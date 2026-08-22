// SPDX-License-Identifier: GPL-3.0-only

import CoreFoundation
import Foundation

/// One atomic persisted record represents an enabled lock. There is no
/// separate `lockEnabled` flag that can disagree with its target.
struct LockConfiguration: Codable, Equatable {
  static let currentSchemaVersion = 1

  let schemaVersion: Int
  let target: NetworkTarget
  let displaySSID: String?

  /// Consent is scoped by being stored in the same immutable record as its
  /// target. Replacing the target requires constructing a new configuration,
  /// whose default is no System Keychain access.
  let systemKeychainConsentGranted: Bool

  init(
    target: NetworkTarget,
    displaySSID: String?,
    systemKeychainConsentGranted: Bool = false
  ) {
    schemaVersion = Self.currentSchemaVersion
    self.target = target
    self.displaySSID = displaySSID
    self.systemKeychainConsentGranted = systemKeychainConsentGranted
  }

  func withSystemKeychainConsent(_ granted: Bool) -> LockConfiguration {
    LockConfiguration(
      target: target,
      displaySSID: displaySSID,
      systemKeychainConsentGranted: granted
    )
  }

  private enum CodingKeys: String, CodingKey {
    case schemaVersion
    case target
    case displaySSID
    case systemKeychainConsentGranted
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let decodedVersion = try container.decode(Int.self, forKey: .schemaVersion)
    guard decodedVersion == Self.currentSchemaVersion else {
      throw DecodingError.dataCorruptedError(
        forKey: .schemaVersion,
        in: container,
        debugDescription: "Unsupported lock-configuration schema version \(decodedVersion)."
      )
    }

    schemaVersion = decodedVersion
    target = try container.decode(NetworkTarget.self, forKey: .target)
    displaySSID = try container.decodeIfPresent(String.self, forKey: .displaySSID)
    // Missing consent is safely interpreted as denial. This permits a
    // schema-v1 record written before the field existed to fail closed.
    systemKeychainConsentGranted =
      try container.decodeIfPresent(
        Bool.self,
        forKey: .systemKeychainConsentGranted
      ) ?? false
  }
}

enum SettingsStoreError: LocalizedError {
  case invalidLockConfiguration(underlying: Error)
  case lockConfigurationEncodingFailed(underlying: Error)

  var errorDescription: String? {
    switch self {
    case .invalidLockConfiguration(let underlying):
      return "The saved BSSID lock configuration is invalid. \(underlying.localizedDescription)"
    case .lockConfigurationEncodingFailed(let underlying):
      return "The BSSID lock configuration could not be saved. \(underlying.localizedDescription)"
    }
  }
}

/// Typed persistence for lock configuration and independent association-mode
/// preferences. A single encoded value makes the target, display label, and
/// target-scoped Keychain consent visible together or not at all.
final class SettingsStore {
  static let defaultStrictBSSIDEnabled = true
  static let defaultMainMenuRefreshInterval = 10
  static let defaultLockMonitorInterval = 300

  private enum Key {
    static let lockConfiguration = "LockConfiguration"
    static let migrationVersion = "LockConfigurationMigrationVersion"
    static let strictBSSIDEnabled = "StrictBSSIDEnabled"
    static let mainMenuRefreshInterval = "MainMenuRefreshIntervalSeconds"
    static let lockMonitorInterval = "LockMonitorIntervalSeconds"

    static let legacySelectedSSID = "SelectedSSID"
    static let legacySelectedSSIDData = "SelectedSSIDData"
    static let legacySelectedBSSID = "SelectedBSSID"
    static let legacyLockEnabled = "LockEnabled"
    static let legacySystemCredentialConsent = "SystemKeychainConsent"
    static let legacySystemCredentialConsentSSIDData = "SystemKeychainConsentSSIDData"

    static let legacyLockPreferenceNames = [
      legacySelectedSSID,
      legacySelectedSSIDData,
      legacySelectedBSSID,
      legacyLockEnabled,
      legacySystemCredentialConsent,
      legacySystemCredentialConsentSSIDData,
    ]
  }

  private static let currentMigrationVersion = 1

  private let defaults: UserDefaults
  private let encoder: PropertyListEncoder
  private let decoder = PropertyListDecoder()
  private let criticalSection = NSLock()

  init(defaults: UserDefaults = .standard) {
    self.defaults = defaults
    defaults.register(defaults: [
      Key.strictBSSIDEnabled: Self.defaultStrictBSSIDEnabled
    ])
    let encoder = PropertyListEncoder()
    encoder.outputFormat = .binary
    self.encoder = encoder
  }

  /// Returns `nil` when locking is disabled. Invalid or unsupported records
  /// throw instead of being treated as a partially usable lock target.
  func loadLock() throws -> LockConfiguration? {
    try synchronized {
      try migrateLegacyLockIfNeeded()
      guard let data = defaults.data(forKey: Key.lockConfiguration) else { return nil }
      do {
        return try decoder.decode(LockConfiguration.self, from: data)
      } catch {
        throw SettingsStoreError.invalidLockConfiguration(underlying: error)
      }
    }
  }

  /// Atomically enables or replaces the lock by writing its complete record
  /// under one UserDefaults key.
  func saveLock(_ configuration: LockConfiguration) throws {
    try synchronized {
      try migrateLegacyLockIfNeeded()
      do {
        defaults.set(try encoder.encode(configuration), forKey: Key.lockConfiguration)
      } catch {
        throw SettingsStoreError.lockConfigurationEncodingFailed(underlying: error)
      }
    }
  }

  /// Disables locking and prevents a stale legacy target from being migrated
  /// back into existence on the next launch.
  func clearLock() {
    synchronized {
      defaults.removeObject(forKey: Key.lockConfiguration)
      removeLegacyLockKeys()
      defaults.set(Self.currentMigrationVersion, forKey: Key.migrationVersion)
    }
  }

  /// Restores every app-owned persisted setting managed by this store. Write
  /// the migration marker last so obsolete lock keys cannot be resurrected on
  /// a later launch if an older build left them behind.
  func resetToDefaults() {
    synchronized {
      defaults.removeObject(forKey: Key.lockConfiguration)
      defaults.removeObject(forKey: Key.strictBSSIDEnabled)
      defaults.removeObject(forKey: Key.mainMenuRefreshInterval)
      defaults.removeObject(forKey: Key.lockMonitorInterval)
      removeLegacyLockKeys()
      defaults.set(Self.currentMigrationVersion, forKey: Key.migrationVersion)
    }
  }

  /// Strict/private association is an independent preference, not part of
  /// the invariant that determines whether a lock exists.
  var strictBSSIDEnabled: Bool {
    get {
      synchronized { defaults.bool(forKey: Key.strictBSSIDEnabled) }
    }
    set {
      synchronized { defaults.set(newValue, forKey: Key.strictBSSIDEnabled) }
    }
  }

  /// How often the status-menu access-point list is refreshed while open.
  /// Zero disables automatic menu scans. Missing, nonnumeric, nonfinite, or
  /// negative persisted values safely use the established ten-second default.
  /// Existing integer values written by earlier versions remain valid.
  var mainMenuRefreshInterval: Int {
    get {
      synchronized {
        interval(
          forKey: Key.mainMenuRefreshInterval,
          defaultValue: Self.defaultMainMenuRefreshInterval
        )
      }
    }
    set {
      synchronized {
        persistInterval(
          newValue,
          forKey: Key.mainMenuRefreshInterval,
          defaultValue: Self.defaultMainMenuRefreshInterval
        )
      }
    }
  }

  /// How often an enabled BSSID lock verifies the current association.
  /// Zero disables routine checks; the retry backoff after a failed
  /// association remains a separate policy.
  var lockMonitorInterval: Int {
    get {
      synchronized {
        interval(
          forKey: Key.lockMonitorInterval,
          defaultValue: Self.defaultLockMonitorInterval
        )
      }
    }
    set {
      synchronized {
        persistInterval(
          newValue,
          forKey: Key.lockMonitorInterval,
          defaultValue: Self.defaultLockMonitorInterval
        )
      }
    }
  }

  private func migrateLegacyLockIfNeeded() throws {
    guard defaults.integer(forKey: Key.migrationVersion) < Self.currentMigrationVersion else {
      return
    }

    // Never replace a record already written by the new store. It may be a
    // newer schema that this executable correctly refuses to reinterpret.
    if defaults.object(forKey: Key.lockConfiguration) != nil {
      finishLegacyMigration()
      return
    }

    var migratedConfiguration: LockConfiguration?
    if defaults.bool(forKey: Key.legacyLockEnabled),
      let legacySSIDData = defaults.data(forKey: Key.legacySelectedSSIDData),
      let ssid = RawSSID(data: legacySSIDData),
      let legacyBSSID = defaults.string(forKey: Key.legacySelectedBSSID),
      let bssid = BSSID(legacyBSSID)
    {
      let consentMatchesTarget =
        defaults.bool(forKey: Key.legacySystemCredentialConsent)
        && defaults.data(forKey: Key.legacySystemCredentialConsentSSIDData) == legacySSIDData
      migratedConfiguration = LockConfiguration(
        target: NetworkTarget(ssid: ssid, bssid: bssid),
        displaySSID: defaults.string(forKey: Key.legacySelectedSSID),
        systemKeychainConsentGranted: consentMatchesTarget
      )
    }

    // A text-only legacy SSID is deliberately not migrated. Raw bytes are
    // the security and identity boundary for a same-SSID BSSID lock.
    if let migratedConfiguration {
      do {
        defaults.set(
          try encoder.encode(migratedConfiguration),
          forKey: Key.lockConfiguration)
      } catch {
        // Keep the legacy keys and migration marker untouched so a
        // later launch can retry rather than silently disabling lock.
        throw SettingsStoreError.lockConfigurationEncodingFailed(underlying: error)
      }
    }
    finishLegacyMigration()
  }

  private func finishLegacyMigration() {
    removeLegacyLockKeys()
    // Write this last. If the process stops earlier, migration safely runs
    // again; an already-written new record is never replaced.
    defaults.set(Self.currentMigrationVersion, forKey: Key.migrationVersion)
  }

  private func removeLegacyLockKeys() {
    for key in Key.legacyLockPreferenceNames {
      defaults.removeObject(forKey: key)
    }
  }

  private func interval(
    forKey key: String,
    defaultValue: Int
  ) -> Int {
    guard
      let storedValue = defaults.object(forKey: key) as? NSNumber,
      CFGetTypeID(storedValue) != CFBooleanGetTypeID()
    else {
      return defaultValue
    }
    if let interval = AutomaticUpdateInterval.parse(storedValue.stringValue) {
      return interval
    }
    return AutomaticUpdateInterval.migratedLegacyValue(storedValue.doubleValue) ?? defaultValue
  }

  private func persistInterval(
    _ interval: Int,
    forKey key: String,
    defaultValue: Int
  ) {
    let validatedInterval = AutomaticUpdateInterval.validated(interval) ?? defaultValue
    defaults.set(validatedInterval, forKey: key)
  }

  private func synchronized<T>(_ body: () throws -> T) rethrows -> T {
    criticalSection.lock()
    defer { criticalSection.unlock() }
    return try body()
  }
}
