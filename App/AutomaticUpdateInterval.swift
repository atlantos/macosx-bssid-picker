// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Shared validation and presentation for user-entered automatic-update
/// intervals. Values are nonnegative whole seconds. Zero has one consistent
/// meaning throughout the app: perform no recurring work.
enum AutomaticUpdateInterval {
  private static let asciiDigitRange: ClosedRange<UInt8> = 0x30...0x39

  static func validated(_ interval: Int) -> Int? {
    interval >= 0 ? interval : nil
  }

  /// Accept exact integral values written by the short-lived decimal interval
  /// implementation without accepting fractions as current input.
  static func migratedLegacyValue(_ interval: TimeInterval) -> Int? {
    guard
      interval.isFinite,
      interval >= 0,
      interval.rounded() == interval,
      interval < Double(Int.max)
    else {
      return nil
    }
    return Int(interval)
  }

  static func parse(_ input: String) -> Int? {
    let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty, trimmed.utf8.allSatisfy(asciiDigitRange.contains),
      let interval = Int(trimmed)
    else { return nil }
    return validated(interval)
  }

  static func format(_ interval: Int) -> String {
    String(validated(interval) ?? 0)
  }
}
