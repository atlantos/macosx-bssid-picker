// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// The association implementation selected by the user.
enum AssociationMode: String, Codable, CaseIterable, Equatable {
  case standard = "Standard CoreWLAN"
  case strict = "Strict BSSID (Experimental)"
}

enum AppOperation: String, Codable, Equatable {
  case idle = "Idle"
  case scanningCurrentNetwork = "Scanning current network"
  case checkingLock = "Checking BSSID lock"
  case checkingStrictAvailability = "Checking Strict BSSID availability"
  case connecting = "Connecting"
  case awaitingConsent = "Awaiting user consent"
  case presentingDialog = "Presenting a dialog"
}

enum LockDiagnosticState: String, Codable, Equatable {
  case disabled = "Disabled"
  case active = "Active"
  case waitingForSSID = "Waiting for SSID"
  case checking = "Checking"
  case restoring = "Restoring target"
  case retryScheduled = "Retry scheduled"
  case paused = "Paused"
}

struct LockDiagnostics: Codable, Equatable {
  let state: LockDiagnosticState
  let target: NetworkTarget?
  let displaySSID: String?
  let failureCount: Int
  let nextRetryAt: Date?
  let retryDelay: TimeInterval?
  let lastError: String?

  static let disabled = LockDiagnostics(
    state: .disabled,
    target: nil,
    displaySSID: nil,
    failureCount: 0,
    nextRetryAt: nil,
    retryDelay: nil,
    lastError: nil
  )
}

enum LocationDiagnosticState: String, Codable, Equatable {
  case notDetermined = "Not determined"
  case allowed = "Allowed"
  case denied = "Denied or restricted"
  case unavailable = "Unavailable"
}

enum StrictBackendDiagnosticState: String, Codable, Equatable {
  case notChecked = "Not checked"
  case checking = "Checking"
  case available = "Available"
  case unavailable = "Unavailable"
}

struct StrictBackendDiagnostics: Codable, Equatable {
  let state: StrictBackendDiagnosticState
  let message: String?

  static let notChecked = StrictBackendDiagnostics(state: .notChecked, message: nil)
}

/// Consent recorded by BSSID Picker to attempt a System Keychain fallback.
/// This is not evidence that an item exists or that macOS granted item access.
struct SystemKeychainConsentDiagnostics: Codable, Equatable {
  let sessionSSID: RawSSID?
  let persistedLockSSID: RawSSID?

  static let none = SystemKeychainConsentDiagnostics(
    sessionSSID: nil,
    persistedLockSSID: nil
  )

  func scope(for ssid: RawSSID) -> CredentialConsentScope {
    if persistedLockSSID == ssid { return .persistedLock }
    if sessionSSID == ssid { return .session }
    return .none
  }
}

struct AppEnvironmentDiagnostics: Codable, Equatable {
  let macOSVersion: String
  let appVersion: String
  let appBuild: String
  let bundleIdentifier: String
  let locationAuthorization: LocationDiagnosticState
  let strictBackend: StrictBackendDiagnostics

  static let unavailable = AppEnvironmentDiagnostics(
    macOSVersion: "Unavailable",
    appVersion: "Unavailable",
    appBuild: "Unavailable",
    bundleIdentifier: "Unavailable",
    locationAuthorization: .unavailable,
    strictBackend: .notChecked
  )
}

struct ClientWiFiState: Codable, Equatable {
  /// Time at which the current association was actually observed. `nil`
  /// means no association observation is available; rendering code must not
  /// substitute its own current time for missing data.
  let capturedAt: Date?
  let displaySSID: String?
  let rawSSID: RawSSID?
  let currentBSSID: BSSID?
  let associationMode: AssociationMode
  let operation: AppOperation
  let lock: LockDiagnostics
  let lastConnectionError: String?
  let systemKeychainConsent: SystemKeychainConsentDiagnostics
}

enum ConnectionEventTrigger: String, Codable, Equatable {
  case userSelection = "User selection"
  case lockRecovery = "BSSID lock recovery"
}

enum ConnectionEventState: String, Codable, Equatable {
  case started = "Started"
  case succeeded = "Succeeded"
  case failed = "Failed"
  case cancelled = "Cancelled"
}

enum CredentialRequirement: String, Codable, Equatable {
  case unknown = "Unknown"
  case notRequired = "Not required"
  case personalPassword = "Personal-network password"
  case legacyWEPPassword = "Legacy WEP password"
  case enterpriseUnsupported = "Enterprise authentication unsupported"
  case unknownUnsupported = "Unknown authentication unsupported"
}

extension NetworkAuthentication {
  var credentialRequirement: CredentialRequirement {
    switch self {
    case .passwordless: return .notRequired
    case .personal: return .personalPassword
    case .legacyWEP: return .legacyWEPPassword
    case .enterprise: return .enterpriseUnsupported
    case .unknown: return .unknownUnsupported
    }
  }
}

enum CredentialAccessStage: String, Codable, Equatable {
  case noCredential = "No credential"
  case userKeychainLookup = "Login or iCloud Keychain lookup"
  case systemKeychainConsent = "System Keychain consent"
  case systemKeychainLookup = "System Keychain lookup"
  case airportdDelegation = "Strict macOS credential delegation"
  case unsupportedAuthentication = "Unsupported authentication"
}

enum CredentialAccessResult: String, Codable, Equatable {
  case pending = "Pending"
  case notRequired = "Not required"
  case succeeded = "Succeeded"
  case itemNotFound = "Item not found"
  case serviceInterrupted = "Credential service interrupted"
  case consentRequired = "Consent required"
  case consentGranted = "Consent granted"
  case consentDeclined = "Consent declined"
  case accessDenied = "Access denied"
  case authenticationFailed = "Authentication failed"
  case interactionNotAllowed = "Interaction not allowed"
  case emptyCredential = "Empty credential"
  case delegated = "Delegated"
  case failed = "Failed"
  case unsupported = "Unsupported"
  case cancelled = "Cancelled"
}

enum CredentialSecretHandling: String, Codable, Equatable {
  case unknown = "Unknown"
  case notNeeded = "Not needed"
  case appHandledEphemerally = "Handled ephemerally by BSSID Picker"
  case notExposedToApp = "Not exposed to BSSID Picker"
}

enum CredentialConsentScope: String, Codable, Equatable {
  case notApplicable = "Not applicable"
  case none = "Not granted"
  case session = "This app session"
  case provisionalLock = "Pending BSSID lock activation"
  case persistedLock = "Saved BSSID lock"
}

/// A secret-free observation made while resolving a credential. It contains
/// neither a credential nor a Keychain item identifier.
struct CredentialAccessRecord: Codable, Equatable {
  let observedAt: Date
  let stage: CredentialAccessStage
  let result: CredentialAccessResult
  let attempts: Int?
  let osStatus: Int32?
  let secretHandling: CredentialSecretHandling

  init(
    observedAt: Date = Date(),
    stage: CredentialAccessStage,
    result: CredentialAccessResult,
    attempts: Int? = nil,
    osStatus: Int32? = nil,
    secretHandling: CredentialSecretHandling = .unknown
  ) {
    self.observedAt = observedAt
    self.stage = stage
    self.result = result
    self.attempts = attempts
    self.osStatus = osStatus
    self.secretHandling = secretHandling
  }
}

/// Bounded, typed credential diagnostics. Only the access route and outcome
/// are retained; password contents and Keychain item metadata cannot be
/// represented by this model.
struct CredentialDiagnostics: Codable, Equatable {
  static let maximumRecordCount = 16

  private(set) var requirement: CredentialRequirement
  private(set) var consentScope: CredentialConsentScope
  private(set) var records: [CredentialAccessRecord]

  init(
    requirement: CredentialRequirement = .unknown,
    consentScope: CredentialConsentScope = .none,
    records: [CredentialAccessRecord] = []
  ) {
    self.requirement = requirement
    self.consentScope = consentScope
    self.records = Array(records.suffix(Self.maximumRecordCount))
  }

  var sourceDisplayName: String {
    for record in records.reversed() where record.result == .succeeded {
      switch record.stage {
      case .userKeychainLookup: return "Login or iCloud Keychain"
      case .systemKeychainLookup: return "System Keychain"
      case .noCredential, .systemKeychainConsent, .airportdDelegation,
        .unsupportedAuthentication:
        continue
      }
    }
    if let delegation = records.last(where: { $0.stage == .airportdDelegation }) {
      switch delegation.result {
      case .delegated:
        return "Delegated to macOS (source unavailable)"
      case .pending:
        return "Delegation pending (source unavailable)"
      default:
        return "Unavailable (strict path)"
      }
    }
    if records.contains(where: { $0.stage == .noCredential }) {
      return "No credential required"
    }
    if records.contains(where: { $0.stage == .unsupportedAuthentication }) {
      return "No credential lookup"
    }
    return records.isEmpty ? "Not attempted" : "Unresolved"
  }

  var resultDisplayName: String {
    records.last?.result.rawValue ?? "Not attempted"
  }

  var passwordHandlingDisplayName: String {
    if records.contains(where: { $0.secretHandling == .appHandledEphemerally }) {
      return CredentialSecretHandling.appHandledEphemerally.rawValue
    }
    if records.contains(where: { $0.secretHandling == .notExposedToApp }) {
      return CredentialSecretHandling.notExposedToApp.rawValue
    }
    if records.contains(where: { $0.secretHandling == .notNeeded }) {
      return CredentialSecretHandling.notNeeded.rawValue
    }
    return CredentialSecretHandling.unknown.rawValue
  }

  mutating func append(_ record: CredentialAccessRecord) {
    records.append(record)
    if records.count > Self.maximumRecordCount {
      records.removeFirst(records.count - Self.maximumRecordCount)
    }
  }

  mutating func setRequirement(_ requirement: CredentialRequirement) {
    self.requirement = requirement
  }

  mutating func setConsentScope(_ scope: CredentialConsentScope) {
    consentScope = scope
  }

  private enum CodingKeys: String, CodingKey {
    case requirement
    case consentScope
    case records
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    requirement = try container.decode(CredentialRequirement.self, forKey: .requirement)
    consentScope = try container.decode(CredentialConsentScope.self, forKey: .consentScope)
    let decodedRecords = try container.decode([CredentialAccessRecord].self, forKey: .records)
    records = Array(decodedRecords.suffix(Self.maximumRecordCount))
  }
}

/// A sanitized association history record. Passwords, Keychain item
/// identifiers, profile metadata, and ACL details must never be added here.
struct ConnectionEvent: Codable, Identifiable, Equatable {
  let id: UUID
  let startedAt: Date
  var completedAt: Date?
  let trigger: ConnectionEventTrigger
  let mode: AssociationMode
  let requestedTarget: NetworkTarget
  var observedBSSID: BSSID?
  var state: ConnectionEventState
  var message: String?
  var verificationSamples: [BSSIDVerificationSample]
  var credentialDiagnostics: CredentialDiagnostics
}

struct ScannerContextSnapshot: Codable, Equatable {
  let client: ClientWiFiState
  let connectionEvents: [ConnectionEvent]
  let environment: AppEnvironmentDiagnostics
  let interface: WiFiInterfaceSnapshot?

  init(
    client: ClientWiFiState,
    connectionEvents: [ConnectionEvent],
    environment: AppEnvironmentDiagnostics = .unavailable,
    interface: WiFiInterfaceSnapshot? = nil
  ) {
    self.client = client
    self.connectionEvents = connectionEvents
    self.environment = environment
    self.interface = interface
  }

  func withInterface(_ interface: WiFiInterfaceSnapshot?) -> ScannerContextSnapshot {
    ScannerContextSnapshot(
      client: client,
      connectionEvents: connectionEvents,
      environment: environment,
      interface: interface
    )
  }
}
