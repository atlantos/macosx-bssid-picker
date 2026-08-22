// SPDX-License-Identifier: GPL-3.0-only

import CoreWLAN
import Darwin
import Foundation
import Security

/// Performs short-lived Wi-Fi credential lookups. Passwords are passed directly
/// to a caller-supplied closure and are never stored on the service object.
final class CredentialProvider {
  private static let interruptedStatus = OSStatus(NSXPCConnectionInterrupted)
  private static let maximumAttempts = 3
  private static let retryDelayMicroseconds: useconds_t = 200_000

  func withSavedPassword<Result>(
    for ssid: RawSSID,
    policy: CredentialPolicy,
    record: (CredentialAccessRecord) -> Void,
    perform: (String, CredentialSource) throws -> Result
  ) throws -> Result {
    try autoreleasepool {
      var password: NSString?
      defer { password = nil }

      let userLookup = findPassword(in: .user, for: ssid, password: &password)
      let userStatus = userLookup.status
      if userStatus == errSecSuccess {
        guard let password else {
          record(
            accessRecord(
              stage: .userKeychainLookup,
              result: .emptyCredential,
              lookup: userLookup
            ))
          throw WiFiOperationError.emptyCredential(source: .user)
        }
        record(
          accessRecord(
            stage: .userKeychainLookup,
            result: .succeeded,
            lookup: userLookup,
            secretHandling: .appHandledEphemerally
          ))
        return try perform(password as String, .user)
      }

      record(
        accessRecord(
          stage: .userKeychainLookup,
          result: accessResult(for: userStatus),
          lookup: userLookup
        ))

      let userLookupInterrupted = userStatus == Self.interruptedStatus
      guard userStatus == errSecItemNotFound || userLookupInterrupted else {
        throw readError(status: userStatus, source: .user)
      }
      guard policy == .includeSystemKeychain else {
        record(
          CredentialAccessRecord(
            stage: .systemKeychainConsent,
            result: .consentRequired,
            secretHandling: .notExposedToApp
          ))
        throw WiFiOperationError.systemKeychainConsentRequired(
          userLookupInterrupted: userLookupInterrupted
        )
      }

      password = nil
      let systemLookup = findPassword(in: .system, for: ssid, password: &password)
      let systemStatus = systemLookup.status
      guard systemStatus == errSecSuccess else {
        record(
          accessRecord(
            stage: .systemKeychainLookup,
            result: accessResult(for: systemStatus),
            lookup: systemLookup
          ))
        throw readError(status: systemStatus, source: .system)
      }
      guard let password else {
        record(
          accessRecord(
            stage: .systemKeychainLookup,
            result: .emptyCredential,
            lookup: systemLookup
          ))
        throw WiFiOperationError.emptyCredential(source: .system)
      }
      record(
        accessRecord(
          stage: .systemKeychainLookup,
          result: .succeeded,
          lookup: systemLookup,
          secretHandling: .appHandledEphemerally
        ))
      return try perform(password as String, .system)
    }
  }

  private typealias Lookup = (status: OSStatus, attempts: Int)

  private func findPassword(
    in domain: CWKeychainDomain,
    for ssid: RawSSID,
    password: inout NSString?
  ) -> Lookup {
    for attempt in 0..<Self.maximumAttempts {
      password = nil
      let status = CWKeychainFindWiFiPassword(domain, ssid.data, &password)
      guard status == Self.interruptedStatus,
        attempt + 1 < Self.maximumAttempts
      else {
        return (status, attempt + 1)
      }
      usleep(Self.retryDelayMicroseconds)
    }
    return (Self.interruptedStatus, Self.maximumAttempts)
  }

  private func accessRecord(
    stage: CredentialAccessStage,
    result: CredentialAccessResult,
    lookup: Lookup,
    secretHandling: CredentialSecretHandling = .notExposedToApp
  ) -> CredentialAccessRecord {
    CredentialAccessRecord(
      stage: stage,
      result: result,
      attempts: lookup.attempts,
      osStatus: lookup.status,
      secretHandling: secretHandling
    )
  }

  private func accessResult(for status: OSStatus) -> CredentialAccessResult {
    switch status {
    case errSecSuccess: return .succeeded
    case errSecItemNotFound: return .itemNotFound
    case Self.interruptedStatus: return .serviceInterrupted
    case errSecUserCanceled: return .cancelled
    case errSecNoAccessForItem: return .accessDenied
    case errSecAuthFailed: return .authenticationFailed
    case errSecInteractionNotAllowed: return .interactionNotAllowed
    default: return .failed
    }
  }

  private func readError(status: OSStatus, source: CredentialSource) -> WiFiOperationError {
    .credentialReadFailed(source: source, status: status, detail: nil)
  }
}
