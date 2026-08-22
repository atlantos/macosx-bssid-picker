// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Session-scoped, bounded, sanitized history for the scanner and diagnostics
/// UI. Credential observations are typed, bounded, and secret-free.
final class ConnectionHistory {
  private let capacity: Int
  private(set) var events: [ConnectionEvent] = []
  private(set) var lastError: String?
  private(set) var lastErrorTrigger: ConnectionEventTrigger?

  init(capacity: Int = 200) {
    precondition(capacity > 0)
    self.capacity = capacity
  }

  func recordStart(
    id: UUID,
    target: NetworkTarget,
    trigger: ConnectionEventTrigger,
    mode: AssociationMode,
    credentialRequirement: CredentialRequirement = .unknown,
    credentialConsentScope: CredentialConsentScope = .none,
    at date: Date = Date()
  ) {
    guard !events.contains(where: { $0.id == id }) else { return }
    events.append(
      ConnectionEvent(
        id: id,
        startedAt: date,
        completedAt: nil,
        trigger: trigger,
        mode: mode,
        requestedTarget: target,
        observedBSSID: nil,
        state: .started,
        message: nil,
        verificationSamples: [],
        credentialDiagnostics: CredentialDiagnostics(
          requirement: credentialRequirement,
          consentScope: credentialConsentScope
        )
      ))
    if events.count > capacity {
      events.removeFirst(events.count - capacity)
    }
  }

  func recordCredential(id: UUID, record: CredentialAccessRecord) {
    guard let index = events.lastIndex(where: { $0.id == id }) else { return }
    events[index].credentialDiagnostics.append(record)
  }

  func recordCredentialRequirement(id: UUID, requirement: CredentialRequirement) {
    guard let index = events.lastIndex(where: { $0.id == id }) else { return }
    events[index].credentialDiagnostics.setRequirement(requirement)
  }

  func recordCredentialConsent(id: UUID, scope: CredentialConsentScope) {
    guard let index = events.lastIndex(where: { $0.id == id }) else { return }
    events[index].credentialDiagnostics.setConsentScope(scope)
  }

  func recordSuccess(
    id: UUID,
    observedBSSID: BSSID?,
    verificationSamples: [BSSIDVerificationSample],
    at date: Date = Date()
  ) {
    lastError = nil
    lastErrorTrigger = nil
    complete(
      id: id,
      state: .succeeded,
      observedBSSID: observedBSSID,
      message: nil,
      verificationSamples: verificationSamples,
      at: date
    )
  }

  func recordFailure(id: UUID, error: Error, at date: Date = Date()) {
    let details = Self.verificationDetails(from: error)
    let message = Self.sanitizedMessage(for: error)
    lastError = message
    lastErrorTrigger = events.last(where: { $0.id == id })?.trigger
    complete(
      id: id,
      state: .failed,
      observedBSSID: details.observedBSSID,
      message: message,
      verificationSamples: details.samples,
      at: date
    )
  }

  func recordCancellation(id: UUID, message: String, at date: Date = Date()) {
    complete(
      id: id,
      state: .cancelled,
      observedBSSID: nil,
      message: message,
      verificationSamples: [],
      at: date
    )
  }

  /// Clears only the transient presentation of the latest failure. The
  /// immutable event remains available in the scanner's session history.
  func clearActiveError() {
    lastError = nil
    lastErrorTrigger = nil
  }

  /// A failed request is considered externally recovered only when a later
  /// association observation matches that request's exact raw SSID and BSSID.
  func clearActiveErrorIfResolved(by association: CurrentAssociation) {
    guard let event = events.last(where: { $0.state == .failed }),
      event.requestedTarget.ssid == association.ssid,
      event.requestedTarget.bssid == association.bssid
    else {
      return
    }
    clearActiveError()
  }

  static func sanitizedMessage(for error: Error) -> String {
    guard let operationError = error as? WiFiOperationError else {
      return "The Wi-Fi operation failed (system error code \((error as NSError).code))."
    }
    switch operationError {
    case .systemKeychainConsentRequired:
      return "A saved Wi-Fi credential was unavailable."
    case .credentialReadFailed(let source, let status, _):
      return
        "A saved Wi-Fi credential could not be read from the \(source.rawValue) (OSStatus \(status))."
    case .emptyCredential:
      return "The saved Wi-Fi credential was empty."
    case .strictCredentialDelegationUnavailable:
      return "Strict BSSID could not use the saved Wi-Fi credential for this network."
    case .strictBackendUnavailable:
      return "Experimental Strict BSSID is unavailable on this macOS release."
    case .strictAssociationFailed:
      return
        "The experimental Strict BSSID association failed without falling back to another access point."
    case .noInterface, .notConnected, .invalidSSIDData, .enterpriseUnsupported,
      .unknownSecurity, .strictWEPUnsupported, .targetNotFound,
      .currentSSIDChanged, .wrongBSSID, .strictVerificationFailed:
      return operationError.localizedDescription
    }
  }

  private func complete(
    id: UUID,
    state: ConnectionEventState,
    observedBSSID: BSSID?,
    message: String?,
    verificationSamples: [BSSIDVerificationSample],
    at date: Date
  ) {
    guard let index = events.lastIndex(where: { $0.id == id }) else { return }
    events[index].completedAt = date
    events[index].observedBSSID = observedBSSID
    events[index].state = state
    events[index].message = message
    events[index].verificationSamples = verificationSamples
  }

  private static func verificationDetails(from error: Error) -> (
    observedBSSID: BSSID?, samples: [BSSIDVerificationSample]
  ) {
    guard let operationError = error as? WiFiOperationError else { return (nil, []) }
    switch operationError {
    case .wrongBSSID(_, let actual):
      return (actual, [])
    case .strictVerificationFailed(_, let samples):
      return (samples.last?.bssid, samples)
    default:
      return (nil, [])
    }
  }
}
