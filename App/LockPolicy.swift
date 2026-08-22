// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Pure retry policy for BSSID-lock enforcement.
///
/// Failure counts are one-based: the first transient failure waits 15 seconds.
/// Ordinary association keeps retrying at the capped delay; strict association
/// pauses when its fifth consecutive attempt fails.
struct LockRetryPolicy: Equatable {
  static let standard = LockRetryPolicy(
    delays: [15, 30, 60, 120, 300],
    strictCircuitBreakerFailureCount: 5
  )

  let delays: [TimeInterval]
  let strictCircuitBreakerFailureCount: Int

  init(delays: [TimeInterval], strictCircuitBreakerFailureCount: Int) {
    precondition(!delays.isEmpty, "A lock retry policy needs at least one delay.")
    precondition(
      delays.allSatisfy { $0 >= 0 && $0.isFinite },
      "Lock retry delays must be finite and nonnegative.")
    precondition(
      strictCircuitBreakerFailureCount > 0,
      "The strict lock circuit breaker must allow at least one failure.")
    self.delays = delays
    self.strictCircuitBreakerFailureCount = strictCircuitBreakerFailureCount
  }

  func decision(
    afterConsecutiveFailure failureCount: Int,
    strictBSSID: Bool
  ) -> LockRetryDecision {
    precondition(failureCount > 0, "Failure counts are one-based.")
    if strictBSSID && failureCount >= strictCircuitBreakerFailureCount {
      return .pauseAtCircuitBreaker(failureCount: failureCount)
    }
    let delayIndex = min(failureCount - 1, delays.count - 1)
    return .retry(after: delays[delayIndex])
  }
}

enum LockRetryDecision: Equatable {
  case retry(after: TimeInterval)
  case pauseAtCircuitBreaker(failureCount: Int)
}

/// A token captured when asynchronous lock work starts. Results carrying an
/// older token must not mutate a newer target or enforcement policy.
struct LockGeneration: RawRepresentable, Equatable, Hashable {
  let rawValue: UInt64
}

/// Tracks the one user-initiated enable operation that has not yet proved the
/// selected BSSID is active. A generation token prevents a late asynchronous
/// result from committing or rejecting a newer lock configuration.
struct LockActivationTracker: Equatable {
  private(set) var pendingGeneration: LockGeneration?

  mutating func begin(_ generation: LockGeneration) {
    pendingGeneration = generation
  }

  func isPending(_ generation: LockGeneration) -> Bool {
    pendingGeneration == generation
  }

  @discardableResult
  mutating func establish(_ generation: LockGeneration) -> Bool {
    consume(generation)
  }

  @discardableResult
  mutating func fail(_ generation: LockGeneration) -> Bool {
    consume(generation)
  }

  mutating func cancel() {
    pendingGeneration = nil
  }

  private mutating func consume(_ generation: LockGeneration) -> Bool {
    guard pendingGeneration == generation else { return false }
    pendingGeneration = nil
    return true
  }
}

enum LockPause: Equatable {
  case permanent(errorDescription: String)
  case strictCircuitBreaker(failureCount: Int, lastErrorDescription: String)
}

enum LockRuntimePhase: Equatable {
  case ready
  case retryScheduled(at: Date, delay: TimeInterval, lastErrorDescription: String)
  case paused(LockPause)
}

/// Transient, non-persisted lock state. All time-dependent operations accept
/// their clock value as an argument so the policy remains deterministic and
/// unit-testable.
struct LockRuntimeState: Equatable {
  private(set) var generation = LockGeneration(rawValue: 0)
  private(set) var consecutiveFailureCount = 0
  private(set) var phase: LockRuntimePhase = .ready

  var token: LockGeneration { generation }

  func accepts(_ token: LockGeneration) -> Bool {
    token == generation
  }

  func canAttempt(at date: Date) -> Bool {
    switch phase {
    case .ready:
      return true
    case .retryScheduled(let nextAttempt, _, _):
      return date >= nextAttempt
    case .paused:
      return false
    }
  }

  /// Whole seconds remaining before a scheduled retry. Rounding upward keeps
  /// a newly scheduled 15-second delay at 15 until a full second has elapsed.
  func retrySecondsRemaining(at date: Date) -> Int? {
    guard case .retryScheduled(let nextAttempt, _, _) = phase else { return nil }
    let remaining = max(0, ceil(nextAttempt.timeIntervalSince(date)))
    return remaining >= Double(Int.max) ? Int.max : Int(remaining)
  }

  /// Invalidates outstanding asynchronous work after the persisted target or
  /// association mode changes, and starts the new policy in a ready state.
  @discardableResult
  mutating func resetForConfigurationChange() -> LockGeneration {
    advanceGeneration()
    resetProgress()
    return generation
  }

  /// Clears backoff after a successful current-BSSID check or association.
  mutating func recordSuccess() {
    resetProgress()
  }

  mutating func recordPermanentFailure(_ errorDescription: String) {
    phase = .paused(.permanent(errorDescription: errorDescription))
  }

  @discardableResult
  mutating func recordTransientFailure(
    _ errorDescription: String,
    strictBSSID: Bool,
    at date: Date,
    policy: LockRetryPolicy = .standard
  ) -> LockRetryDecision {
    if consecutiveFailureCount < Int.max {
      consecutiveFailureCount += 1
    }
    let decision = policy.decision(
      afterConsecutiveFailure: consecutiveFailureCount,
      strictBSSID: strictBSSID
    )
    switch decision {
    case .retry(let delay):
      phase = .retryScheduled(
        at: date.addingTimeInterval(delay),
        delay: delay,
        lastErrorDescription: errorDescription
      )
    case .pauseAtCircuitBreaker(let failureCount):
      phase = .paused(
        .strictCircuitBreaker(
          failureCount: failureCount,
          lastErrorDescription: errorDescription
        ))
    }
    return decision
  }

  /// Implements “Retry Lock Now”: stale callbacks are invalidated and both a
  /// permanent pause and transient backoff are cleared before the new check.
  @discardableResult
  mutating func prepareManualRetry() -> LockGeneration {
    advanceGeneration()
    resetProgress()
    return generation
  }

  private mutating func resetProgress() {
    consecutiveFailureCount = 0
    phase = .ready
  }

  private mutating func advanceGeneration() {
    generation = LockGeneration(rawValue: generation.rawValue &+ 1)
  }
}
