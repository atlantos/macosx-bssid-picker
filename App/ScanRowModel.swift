// SPDX-License-Identifier: GPL-3.0-only

import Foundation

enum ScanRowIdentity: Hashable {
  case target(NetworkTarget)
  case reported(rawSSID: RawSSID?, bssid: String)
}

struct ScanAssociationObservation: Equatable {
  let capturedAt: Date
  let ssid: RawSSID?
  let bssid: BSSID?
}

struct ScanClientStatePresentation {
  let contextAvailable: Bool
  let associationObservation: ScanAssociationObservation?
  let associated: Bool?
  let lockTarget: Bool?
  let savedProfiles: [WiFiSavedNetworkProfile]?
  let systemKeychainConsentScope: CredentialConsentScope?
  let lastConnectionEvent: ConnectionEvent?

  static let unavailable = ScanClientStatePresentation(
    contextAvailable: false,
    associationObservation: nil,
    associated: nil,
    lockTarget: nil,
    savedProfiles: nil,
    systemKeychainConsentScope: nil,
    lastConnectionEvent: nil
  )

  init(
    accessPoint: AccessPoint,
    context: ScannerContextSnapshot?,
    associationObservation: ScanAssociationObservation?,
    interfaceSnapshot: WiFiInterfaceSnapshot?
  ) {
    let contextAssociationObservation = context.flatMap { context in
      context.client.capturedAt.map {
        ScanAssociationObservation(
          capturedAt: $0,
          ssid: context.client.rawSSID,
          bssid: context.client.currentBSSID
        )
      }
    }
    let effectiveAssociationObservation: ScanAssociationObservation?
    switch (associationObservation, contextAssociationObservation) {
    case (let scan?, let app?):
      effectiveAssociationObservation = app.capturedAt > scan.capturedAt ? app : scan
    case (let scan?, nil):
      effectiveAssociationObservation = scan
    case (nil, let app?):
      effectiveAssociationObservation = app
    case (nil, nil):
      effectiveAssociationObservation = nil
    }
    self.associationObservation = effectiveAssociationObservation
    contextAvailable = context != nil
    associated = effectiveAssociationObservation.flatMap { observation in
      guard let accessPointBSSID = accessPoint.bssid,
        let observedBSSID = observation.bssid
      else { return nil }
      guard observedBSSID == accessPointBSSID else { return false }
      guard let observedSSID = observation.ssid,
        let accessPointSSID = accessPoint.rawSSID
      else { return nil }
      return accessPointSSID == observedSSID
    }
    lockTarget = context.flatMap { context in
      guard let target = accessPoint.target else { return nil }
      return target == context.client.lock.target
    }
    savedProfiles = interfaceSnapshot?.configuration.flatMap { configuration in
      guard let rawSSID = accessPoint.rawSSID else { return nil }
      return configuration.matchingProfiles.filter { $0.rawSSID == rawSSID }
    }
    systemKeychainConsentScope = context.flatMap { context in
      guard let rawSSID = accessPoint.rawSSID else { return nil }
      switch accessPoint.authentication {
      case .personal, .legacyWEP:
        return context.client.systemKeychainConsent.scope(for: rawSSID)
      case .passwordless, .enterprise, .unknown:
        return .notApplicable
      }
    }
    lastConnectionEvent = context?.connectionEvents
      .filter { event in
        accessPoint.target == event.requestedTarget
      }
      .max { $0.startedAt < $1.startedAt }
  }

  private init(
    contextAvailable: Bool,
    associationObservation: ScanAssociationObservation?,
    associated: Bool?,
    lockTarget: Bool?,
    savedProfiles: [WiFiSavedNetworkProfile]?,
    systemKeychainConsentScope: CredentialConsentScope?,
    lastConnectionEvent: ConnectionEvent?
  ) {
    self.contextAvailable = contextAvailable
    self.associationObservation = associationObservation
    self.associated = associated
    self.lockTarget = lockTarget
    self.savedProfiles = savedProfiles
    self.systemKeychainConsentScope = systemKeychainConsentScope
    self.lastConnectionEvent = lastConnectionEvent
  }

  /// A retained scan row's saved-profile value belongs to the scan that last
  /// observed that access point. A newer interface snapshot is intentionally
  /// scoped to SSIDs in the newer scan, so its omission of a retained SSID is
  /// not evidence that the saved profile was removed.
  func preservingSavedProfiles(
    _ savedProfiles: [WiFiSavedNetworkProfile]?
  ) -> ScanClientStatePresentation {
    ScanClientStatePresentation(
      contextAvailable: contextAvailable,
      associationObservation: associationObservation,
      associated: associated,
      lockTarget: lockTarget,
      savedProfiles: savedProfiles,
      systemKeychainConsentScope: systemKeychainConsentScope,
      lastConnectionEvent: lastConnectionEvent
    )
  }

  var associatedDisplayName: String {
    guard associationObservation != nil else { return "Unavailable" }
    return associated.map { $0 ? "Yes" : "No" } ?? "Unknown"
  }

  /// The global client-association sample is relevant to a table row only
  /// when that row is the exact observed SSID+BSSID. Keeping this projection
  /// sparse avoids presenting the active network's timestamp and identity as
  /// though they belonged to every scanned access point.
  var activeAssociationObservation: ScanAssociationObservation? {
    associated == true ? associationObservation : nil
  }

  var associationObservedAtDisplayName: String {
    activeAssociationObservation.map { ScanFormatting.timestamp.string(from: $0.capturedAt) }
      ?? ""
  }

  var lockTargetDisplayName: String {
    guard contextAvailable else { return "Unavailable" }
    return lockTarget.map { $0 ? "Yes" : "No" } ?? "Unknown"
  }

  var savedProfileDisplayName: String {
    savedProfiles.map { $0.isEmpty ? "No" : "Yes" } ?? "Unavailable"
  }

  var lastConnectionResult: String {
    guard contextAvailable else { return "Unavailable" }
    return lastConnectionEvent?.state.rawValue ?? "No Attempt"
  }

  var lastAttemptDisplayName: String {
    guard contextAvailable else { return "Unavailable" }
    return lastConnectionEvent.map { ScanFormatting.timestamp.string(from: $0.startedAt) }
      ?? "No Attempt"
  }

  var lastConnectionModeDisplayName: String {
    guard contextAvailable else { return "Unavailable" }
    return lastConnectionEvent?.mode.rawValue ?? "No Attempt"
  }

  var credentialSourceDisplayName: String {
    guard contextAvailable else { return "Unavailable" }
    return lastConnectionEvent?.credentialDiagnostics.sourceDisplayName ?? "No Attempt"
  }

  var credentialResultDisplayName: String {
    guard contextAvailable else { return "Unavailable" }
    return lastConnectionEvent?.credentialDiagnostics.resultDisplayName ?? "No Attempt"
  }

  var systemFallbackDisplayName: String {
    systemKeychainConsentScope?.rawValue ?? "Unavailable"
  }

  var appReadPassword: Bool? {
    guard let records = lastConnectionEvent?.credentialDiagnostics.records else { return nil }
    if records.contains(where: { $0.secretHandling == .appHandledEphemerally }) { return true }
    if records.contains(where: {
      $0.secretHandling == .notExposedToApp || $0.secretHandling == .notNeeded
    }) {
      return false
    }
    return nil
  }

  var appReadPasswordDisplayName: String {
    guard contextAvailable else { return "Unavailable" }
    guard lastConnectionEvent != nil else { return "No Attempt" }
    return appReadPassword.map { $0 ? "Yes" : "No" } ?? "Unknown"
  }

  var lastConnectionErrorDisplayName: String {
    guard contextAvailable else { return "Unavailable" }
    guard let event = lastConnectionEvent else { return "No Attempt" }
    return event.message ?? "None"
  }
}

struct ScanRow {
  let accessPoint: AccessPoint
  let identity: ScanRowIdentity
  let standards: ScanStandardsPresentation
  private(set) var macAttribution: MACAddressAttribution?
  private(set) var lastSeenAt: Date
  private(set) var presentInLatestSuccessfulScan: Bool
  private(set) var scanAssociationObservation: ScanAssociationObservation?
  private(set) var clientState: ScanClientStatePresentation
  /// Cached once per row-state change so interactive search does not rebuild
  /// every column and information-element summary for every keystroke.
  private(set) var searchableText: String
  private(set) var foldedSearchableText: String

  init(
    accessPoint: AccessPoint,
    lastSeenAt: Date,
    macAttribution: MACAddressAttribution? = nil
  ) {
    self.accessPoint = accessPoint
    if let target = accessPoint.target {
      identity = .target(target)
    } else {
      identity = .reported(rawSSID: accessPoint.rawSSID, bssid: accessPoint.reportedBSSID)
    }
    standards = ScanStandardsPresentation.decode(accessPoint.informationElements)
    self.macAttribution = macAttribution
    self.lastSeenAt = lastSeenAt
    presentInLatestSuccessfulScan = true
    scanAssociationObservation = nil
    clientState = .unavailable
    searchableText = ""
    foldedSearchableText = ""
    refreshSearchableText()
  }

  /// Re-enriches a row after the local registry database changes without
  /// performing another Wi-Fi scan. Cached observations keep all of their
  /// original radio and timing data.
  func applyingMACAttribution(_ attribution: MACAddressAttribution?) -> ScanRow {
    var updated = self
    updated.macAttribution = attribution
    updated.refreshSearchableText()
    return updated
  }

  func applyingClientContext(
    _ context: ScannerContextSnapshot?,
    interfaceSnapshot: WiFiInterfaceSnapshot? = nil
  ) -> ScanRow {
    var updated = self
    let priorSavedProfiles = clientState.savedProfiles
    var updatedClientState = ScanClientStatePresentation(
      accessPoint: accessPoint,
      context: context,
      associationObservation: scanAssociationObservation,
      interfaceSnapshot: interfaceSnapshot ?? context?.interface
    )
    if !presentInLatestSuccessfulScan {
      updatedClientState = updatedClientState.preservingSavedProfiles(priorSavedProfiles)
    }
    updated.clientState = updatedClientState
    updated.refreshSearchableText()
    return updated
  }

  func applyingScannerState(
    context: ScannerContextSnapshot?,
    associationObservation: ScanAssociationObservation?,
    interfaceSnapshot: WiFiInterfaceSnapshot? = nil,
    presentInLatestSuccessfulScan: Bool = true
  ) -> ScanRow {
    var updated = self
    let priorSavedProfiles = clientState.savedProfiles
    updated.presentInLatestSuccessfulScan = presentInLatestSuccessfulScan
    updated.scanAssociationObservation = associationObservation
    var updatedClientState = ScanClientStatePresentation(
      accessPoint: accessPoint,
      context: context,
      associationObservation: associationObservation,
      interfaceSnapshot: interfaceSnapshot ?? context?.interface
    )
    if !presentInLatestSuccessfulScan {
      updatedClientState = updatedClientState.preservingSavedProfiles(priorSavedProfiles)
    }
    updated.clientState = updatedClientState
    updated.refreshSearchableText()
    return updated
  }

  var displaySSID: String {
    switch accessPoint.displaySSID {
    case "<hidden>", "<hidden SSID>": return "<hidden SSID>"
    case "<non-text SSID>": return "Non-text SSID"
    default: return accessPoint.displaySSID
    }
  }

  var signalToNoiseRatio: Int? {
    accessPoint.noise < 0 ? accessPoint.rssi - accessPoint.noise : nil
  }

  var phyStandardsSummary: String {
    var standards = Set(
      accessPoint.phyModes.split(separator: ",").map {
        $0.trimmingCharacters(in: .whitespacesAndNewlines)
      }.filter { !$0.isEmpty }
    )
    if let report = self.standards.decodedReport {
      // Infer a PHY only from a structurally complete capabilities element.
      // Merely seeing an element ID is insufficient because CoreWLAN can
      // expose truncated or otherwise malformed frame data.
      if report.elements(with: 45).contains(where: { $0.payload.count == 26 }) {
        standards.insert("802.11n")
      }
      if report.elements(with: 191).contains(where: { $0.payload.count == 12 }) {
        standards.insert("802.11ac")
      }
      if report.elements(with: .elementIDExtension).contains(where: {
        $0.payload.first == 35 && $0.payload.count >= 22
      }) {
        standards.insert("802.11ax")
      }
      if report.elements(with: .elementIDExtension).contains(where: {
        $0.payload.first == 108 && $0.payload.count >= 12
      }) {
        standards.insert("802.11be")
      }
    }
    let preferredOrder = [
      "802.11b", "802.11a", "802.11g", "802.11n", "802.11ac", "802.11ax", "802.11be",
    ]
    let known = preferredOrder.filter(standards.contains)
    let additional = standards.subtracting(known).sorted()
    let values = known + additional
    return values.isEmpty ? "Unknown" : values.joined(separator: ", ")
  }

  var informationElementCount: Int { standards.decodedReport?.elements.count ?? 0 }
  var informationElementBytes: Int { accessPoint.informationElements?.count ?? 0 }

  func stringValue(for column: ScanColumnID) -> String {
    switch column {
    case .observationStatus:
      return presentInLatestSuccessfulScan ? "Seen in latest scan" : "Previous observation"
    case .lastSeen:
      return ScanFormatting.timestamp.string(from: lastSeenAt)
    case .ssid: return displaySSID
    case .ssidHex: return accessPoint.ssidHex.isEmpty ? "Unavailable" : accessPoint.ssidHex
    case .bssid:
      return accessPoint.reportedBSSID == "<unavailable>"
        ? "Unavailable" : accessPoint.reportedBSSID
    case .macRegistrant:
      return macAttribution?.registrantDisplayName ?? "—"
    case .clientAssociated: return clientState.associatedDisplayName
    case .clientLockTarget: return clientState.lockTargetDisplayName
    case .clientLastConnectionResult: return clientState.lastConnectionResult
    case .clientLastAttempt: return clientState.lastAttemptDisplayName
    case .clientAssociationObservedAt: return clientState.associationObservedAtDisplayName
    case .clientSavedProfile: return clientState.savedProfileDisplayName
    case .clientLastConnectionMode: return clientState.lastConnectionModeDisplayName
    case .clientCredentialSource: return clientState.credentialSourceDisplayName
    case .clientCredentialResult: return clientState.credentialResultDisplayName
    case .clientSystemFallback: return clientState.systemFallbackDisplayName
    case .clientAppReadPassword: return clientState.appReadPasswordDisplayName
    case .clientLastConnectionError: return clientState.lastConnectionErrorDisplayName
    case .rssi: return "\(accessPoint.rssi)"
    case .noise: return accessPoint.noise < 0 ? "\(accessPoint.noise)" : "Unavailable"
    case .snr: return signalToNoiseRatio.map(String.init) ?? "Unavailable"
    case .channel: return accessPoint.channelNumber.map(String.init) ?? "Unavailable"
    case .band: return accessPoint.band == "?" ? "Unknown" : accessPoint.band
    case .channelWidth:
      return accessPoint.channelWidth == "?" ? "Unknown" : accessPoint.channelWidth
    case .bssStationCount: return standards.decodedFields.bssStationCount.displayName
    case .bssChannelUtilization:
      return standards.decodedFields.bssChannelUtilization.displayName
    case .bssAdmissionCapacity:
      return standards.decodedFields.bssAdmissionCapacity.displayName
    case .security: return accessPoint.security
    case .rsn: return standards.rsnSummary
    case .protectedManagementFrames: return standards.protectedManagementFramesSummary
    case .phyModes: return phyStandardsSummary
    case .country: return accessPoint.countryCode == "?" ? "Unknown" : accessPoint.countryCode
    case .beaconInterval: return "\(accessPoint.beaconInterval) ms"
    case .dtimCount: return standards.decodedFields.dtimCount.displayName
    case .dtimPeriod: return standards.decodedFields.dtimPeriod.displayName
    case .networkType: return accessPoint.isIBSS ? "IBSS" : "Infrastructure"
    case .radioMeasurement: return standards.radioMeasurementState.displayName
    case .bssTransition: return standards.bssTransitionState.displayName
    case .fastTransition: return standards.fastTransitionState.displayName
    case .fastTransitionMobilityDomain:
      return standards.decodedFields.fastTransitionMobilityDomain.displayName
    case .fastTransitionOverDS:
      return standards.decodedFields.fastTransitionOverDS.displayName
    case .interworking: return standards.decodedFields.interworking.displayName
    case .apChannelReports: return standards.decodedFields.apChannelReports.displayName
    case .reducedNeighborReport:
      return standards.decodedFields.reducedNeighborReport.displayName
    case .multipleBSSID: return standards.decodedFields.multipleBSSID.displayName
    case .bssMaxIdlePeriod: return standards.decodedFields.bssMaxIdlePeriod.displayName
    case .protectedKeepAlive: return standards.decodedFields.protectedKeepAlive.displayName
    case .roamingConsortium: return standards.decodedFields.roamingConsortium.displayName
    case .informationElementCount: return "\(informationElementCount)"
    case .informationElementBytes: return "\(informationElementBytes)"
    }
  }

  func accessibilityValue(for column: ScanColumnID) -> String {
    switch column {
    case .observationStatus:
      return presentInLatestSuccessfulScan
        ? "Seen in the latest successful scan"
        : "Previous observation; not reported in the latest successful scan"
    case .lastSeen:
      return "Last seen \(ScanFormatting.timestamp.string(from: lastSeenAt))"
    case .macRegistrant:
      guard let attribution = macAttribution else {
        return "Download the MAC registrant database in Settings."
      }
      return attribution.accessibilityDescription
    case .rssi:
      return "\(accessPoint.rssi) decibel-milliwatts"
    case .noise where accessPoint.noise < 0:
      return "\(accessPoint.noise) decibel-milliwatts"
    case .snr:
      return signalToNoiseRatio.map { "\($0) decibels" } ?? "Unavailable"
    case .channelWidth:
      return stringValue(for: column).replacingOccurrences(of: "MHz", with: "megahertz")
    case .clientAssociated:
      guard let associated = clientState.associated else { return stringValue(for: column) }
      return associated ? "Yes, currently associated" : "No, not currently associated"
    case .clientLockTarget:
      guard let lockTarget = clientState.lockTarget else { return stringValue(for: column) }
      return
        lockTarget
        ? "Yes, configured BSSID lock target" : "No, not the configured BSSID lock target"
    case .clientAssociationObservedAt:
      guard let observation = clientState.activeAssociationObservation else {
        return clientState.associated == false
          ? "Not applicable; this access point is not currently associated"
          : "Current association unavailable"
      }
      return
        "Client association observed at \(ScanFormatting.timestamp.string(from: observation.capturedAt))"
    case .clientSavedProfile:
      guard let profiles = clientState.savedProfiles else { return stringValue(for: column) }
      return profiles.isEmpty
        ? "No saved macOS Wi-Fi network profile for this SSID"
        : "Yes, macOS reports \(profiles.count) saved Wi-Fi network profile\(profiles.count == 1 ? "" : "s") for this SSID"
    case .clientSystemFallback:
      guard let scope = clientState.systemKeychainConsentScope else {
        return stringValue(for: column)
      }
      switch scope {
      case .notApplicable:
        return "System Keychain fallback does not apply to this network"
      case .none:
        return "System Keychain fallback is not granted for this SSID"
      case .session:
        return "System Keychain fallback is allowed for this SSID during this app session"
      case .provisionalLock:
        return "System Keychain fallback was granted for this pending BSSID lock activation"
      case .persistedLock:
        return "System Keychain fallback is allowed for this saved BSSID lock"
      }
    case .clientAppReadPassword:
      guard let appReadPassword = clientState.appReadPassword else {
        return stringValue(for: column)
      }
      return appReadPassword
        ? "Yes, BSSID Picker handled the password ephemerally"
        : "No, the password was not exposed to BSSID Picker or was not needed"
    case .beaconInterval:
      return "\(accessPoint.beaconInterval) milliseconds"
    case .bssChannelUtilization:
      guard let rawValue = standards.decodedFields.bssChannelUtilization.value else {
        return stringValue(for: column)
      }
      return "\(stringValue(for: column)), raw utilization \(rawValue) of 255"
    case .bssAdmissionCapacity:
      guard let value = standards.decodedFields.bssAdmissionCapacity.value else {
        return stringValue(for: column)
      }
      return "Available admission capacity \(value), in units of 32 microseconds per second"
    case .bssMaxIdlePeriod:
      guard let value = standards.decodedFields.bssMaxIdlePeriod.value else {
        return stringValue(for: column)
      }
      return "Maximum idle period \(value), in units of one thousand time units"
    case .radioMeasurement:
      return "802.11k radio resource management, \(standards.radioMeasurementState.displayName)"
    case .bssTransition:
      return "802.11v BSS transition management, \(standards.bssTransitionState.displayName)"
    case .fastTransition:
      return "802.11r fast BSS transition, \(standards.fastTransitionState.displayName)"
    default:
      return stringValue(for: column)
    }
  }

  private mutating func refreshSearchableText() {
    var values = ScanColumnID.allCases.map { stringValue(for: $0) }
    if let attribution = macAttribution {
      values.append(
        contentsOf: [
          attribution.addressTypeDisplayName,
          attribution.registeredOrganization,
          attribution.allocationDisplayName,
          attribution.matchedPrefix,
          attribution.registrationSourceDisplayName,
          attribution.databaseAgreementDisplayName,
          attribution.knownAddressRole,
        ].compactMap { $0 })
      values.append(
        contentsOf: attribution.registryClaims.flatMap {
          [$0.organization, $0.source.rawValue]
        })
    }
    values.append(contentsOf: standards.elements.flatMap { [$0.identifier, $0.name, $0.summary] })
    searchableText = values.joined(separator: "\n")
    foldedSearchableText = ScanSearchText.fold(searchableText)
  }
}
