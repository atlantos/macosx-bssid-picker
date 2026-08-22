// SPDX-License-Identifier: GPL-3.0-only

import AppKit

enum ScanColumnGroup: String, CaseIterable {
  case identity = "Identity"
  case clientState = "This Mac & BSSID Picker"
  case radio = "Radio"
  case security = "Security"
  case roaming = "Roaming & Management"
  case timing = "Timing & Topology"
  case raw = "Raw Data"
  case observation = "Scan Observation"
}

enum ScanColumnID: String, CaseIterable, Codable {
  case clientAssociated
  case ssid
  case ssidHex
  case bssid
  case macRegistrant
  case clientLockTarget
  case clientLastConnectionResult
  case clientLastAttempt
  case clientAssociationObservedAt
  case clientSavedProfile
  case clientLastConnectionMode
  case clientCredentialSource
  case clientCredentialResult
  case clientSystemFallback
  case clientAppReadPassword
  case clientLastConnectionError
  case rssi
  case noise
  case snr
  case channel
  case band
  case channelWidth
  case bssStationCount
  case bssChannelUtilization
  case bssAdmissionCapacity
  case security
  case rsn
  case protectedManagementFrames
  case phyModes
  case country
  case beaconInterval
  case dtimCount
  case dtimPeriod
  case networkType
  case radioMeasurement
  case bssTransition
  case fastTransition
  case fastTransitionMobilityDomain
  case fastTransitionOverDS
  case interworking
  case apChannelReports
  case reducedNeighborReport
  case multipleBSSID
  case bssMaxIdlePeriod
  case protectedKeepAlive
  case roamingConsortium
  case informationElementCount
  case informationElementBytes
  case observationStatus
  case lastSeen

  var title: String {
    switch self {
    case .ssid: return "SSID"
    case .ssidHex: return "SSID Bytes"
    case .bssid: return "BSSID"
    case .macRegistrant: return "MAC Registrant"
    case .clientAssociated: return "Active BSSID"
    case .observationStatus: return "Observation"
    case .lastSeen: return "Last Seen"
    case .clientLockTarget: return "BSSID Lock Target"
    case .clientLastConnectionResult: return "Last Connection Result"
    case .clientLastAttempt: return "Last Attempt"
    case .clientAssociationObservedAt: return "Association Observed"
    case .clientSavedProfile: return "Saved Profile"
    case .clientLastConnectionMode: return "Last Mode"
    case .clientCredentialSource: return "Credential Source"
    case .clientCredentialResult: return "Credential Result"
    case .clientSystemFallback: return "System Fallback"
    case .clientAppReadPassword: return "App Read Password"
    case .clientLastConnectionError: return "Last Error"
    case .rssi: return "Signal (dBm)"
    case .noise: return "Noise (dBm)"
    case .snr: return "SNR (dB)"
    case .channel: return "Channel"
    case .band: return "Band"
    case .channelWidth: return "Width"
    case .bssStationCount: return "BSS Stations"
    case .bssChannelUtilization: return "BSS Utilization"
    case .bssAdmissionCapacity: return "BSS Admission Capacity"
    case .security: return "Security"
    case .rsn: return "RSN"
    case .protectedManagementFrames: return "PMF"
    case .phyModes: return "PHY Modes"
    case .country: return "Country"
    case .beaconInterval: return "Beacon Interval"
    case .dtimCount: return "DTIM Count"
    case .dtimPeriod: return "DTIM Period"
    case .networkType: return "Network Type"
    case .radioMeasurement: return "802.11k"
    case .bssTransition: return "802.11v"
    case .fastTransition: return "802.11r"
    case .fastTransitionMobilityDomain: return "FT Mobility Domain"
    case .fastTransitionOverDS: return "FT over DS"
    case .interworking: return "Interworking"
    case .apChannelReports: return "AP Channel Reports"
    case .reducedNeighborReport: return "Reduced Neighbor Report"
    case .multipleBSSID: return "Multiple BSSID"
    case .bssMaxIdlePeriod: return "BSS Max Idle"
    case .protectedKeepAlive: return "Protected Keep-Alive"
    case .roamingConsortium: return "Roaming Consortium"
    case .informationElementCount: return "IE Count"
    case .informationElementBytes: return "IE Bytes"
    }
  }

  var accessibilityTitle: String {
    switch self {
    case .ssid: return "Network name, SSID"
    case .ssidHex: return "Raw SSID bytes"
    case .bssid: return "Access point identifier, BSSID"
    case .macRegistrant:
      return
        "The organization registered for the matching MAC address block. It may differ from the access point manufacturer or brand."
    case .clientAssociated: return "Currently active BSSID"
    case .observationStatus: return "Presence in the latest successful scan"
    case .lastSeen: return "Time this access point was last seen"
    case .clientLockTarget: return "Client state, configured BSSID lock target"
    case .clientLastConnectionResult: return "Client state, last connection result"
    case .clientLastAttempt: return "Client state, last connection attempt time"
    case .clientAssociationObservedAt:
      return "Time the scanner observed the current client association"
    case .clientSavedProfile:
      return "Whether macOS reports a saved Wi-Fi network profile for this SSID"
    case .clientLastConnectionMode:
      return "Association mode used by the last connection attempt"
    case .clientCredentialSource:
      return "Credential source observed during the last connection attempt"
    case .clientCredentialResult:
      return "Credential handling result from the last connection attempt"
    case .clientSystemFallback:
      return "BSSID Picker System Keychain fallback consent for this SSID"
    case .clientAppReadPassword:
      return "Whether BSSID Picker read a Wi-Fi password during the last connection attempt"
    case .clientLastConnectionError:
      return "Error from the last connection attempt"
    case .rssi: return "Signal strength in decibel-milliwatts"
    case .noise: return "Noise in decibel-milliwatts"
    case .snr: return "Signal-to-noise ratio in decibels"
    case .channelWidth: return "Channel width"
    case .bssStationCount: return "Associated station count from the BSS Load element"
    case .bssChannelUtilization: return "Channel utilization from the BSS Load element"
    case .bssAdmissionCapacity:
      return "Available admission capacity from the BSS Load element"
    case .rsn: return "Robust Security Network information"
    case .protectedManagementFrames: return "Protected Management Frames"
    case .phyModes: return "IEEE 802.11 physical modes"
    case .beaconInterval: return "Beacon interval"
    case .dtimCount: return "Delivery Traffic Indication Message count"
    case .dtimPeriod: return "Delivery Traffic Indication Message period"
    case .radioMeasurement: return "802.11k radio resource management"
    case .bssTransition: return "802.11v BSS transition management"
    case .fastTransition: return "802.11r fast BSS transition"
    case .fastTransitionMobilityDomain: return "802.11r mobility domain identifier"
    case .fastTransitionOverDS: return "802.11r fast transition over the distribution system"
    case .interworking: return "802.11 interworking information"
    case .apChannelReports: return "802.11 access point channel reports"
    case .reducedNeighborReport: return "Reduced Neighbor Report"
    case .multipleBSSID: return "Multiple BSSID advertisement"
    case .bssMaxIdlePeriod: return "BSS maximum idle period"
    case .protectedKeepAlive: return "Protected keep-alive requirement"
    case .roamingConsortium: return "Roaming Consortium organization identifiers"
    case .informationElementCount: return "Information element count"
    case .informationElementBytes: return "Information element byte count"
    default: return title
    }
  }

  var group: ScanColumnGroup {
    switch self {
    case .ssid, .ssidHex, .bssid, .macRegistrant:
      return .identity
    case .clientAssociated, .clientLockTarget, .clientLastConnectionResult, .clientLastAttempt,
      .clientAssociationObservedAt, .clientSavedProfile, .clientLastConnectionMode,
      .clientCredentialSource, .clientCredentialResult, .clientSystemFallback,
      .clientAppReadPassword, .clientLastConnectionError:
      return .clientState
    case .rssi, .noise, .snr, .channel, .band, .channelWidth, .bssStationCount,
      .bssChannelUtilization, .bssAdmissionCapacity, .phyModes:
      return .radio
    case .security, .rsn, .protectedManagementFrames:
      return .security
    case .radioMeasurement, .bssTransition, .fastTransition, .fastTransitionMobilityDomain,
      .fastTransitionOverDS, .interworking, .apChannelReports, .reducedNeighborReport,
      .multipleBSSID, .bssMaxIdlePeriod, .protectedKeepAlive, .roamingConsortium:
      return .roaming
    case .country, .beaconInterval, .dtimCount, .dtimPeriod, .networkType:
      return .timing
    case .informationElementCount, .informationElementBytes:
      return .raw
    case .observationStatus, .lastSeen:
      return .observation
    }
  }

  var defaultWidth: CGFloat {
    switch self {
    case .ssid: return 190
    case .ssidHex: return 250
    case .bssid: return 150
    case .macRegistrant: return 210
    case .clientAssociated: return 38
    case .observationStatus: return 160
    case .lastSeen: return 180
    case .clientLockTarget: return 135
    case .clientLastConnectionResult: return 220
    case .clientLastAttempt: return 180
    case .clientAssociationObservedAt: return 180
    case .clientSavedProfile: return 125
    case .clientLastConnectionMode: return 185
    case .clientCredentialSource: return 210
    case .clientCredentialResult: return 190
    case .clientSystemFallback: return 175
    case .clientAppReadPassword: return 145
    case .clientLastConnectionError: return 300
    case .rssi, .noise: return 92
    case .snr: return 78
    case .channel: return 76
    case .band: return 76
    case .channelWidth: return 84
    case .bssStationCount: return 105
    case .bssChannelUtilization: return 115
    case .bssAdmissionCapacity: return 165
    case .security: return 220
    case .rsn: return 310
    case .protectedManagementFrames: return 130
    case .phyModes: return 170
    case .country: return 76
    case .beaconInterval: return 112
    case .dtimCount, .dtimPeriod: return 92
    case .networkType: return 112
    case .radioMeasurement, .bssTransition, .fastTransition: return 122
    case .fastTransitionMobilityDomain: return 145
    case .fastTransitionOverDS: return 110
    case .interworking: return 300
    case .apChannelReports: return 260
    case .reducedNeighborReport: return 280
    case .multipleBSSID: return 220
    case .bssMaxIdlePeriod: return 140
    case .protectedKeepAlive: return 145
    case .roamingConsortium: return 280
    case .informationElementCount, .informationElementBytes: return 86
    }
  }

  var minimumWidth: CGFloat {
    switch self {
    case .ssid: return 100
    case .ssidHex, .rsn: return 140
    case .bssid: return 120
    case .macRegistrant: return 140
    case .clientAssociated: return defaultWidth
    case .observationStatus: return 120
    case .lastSeen: return 140
    case .clientLockTarget: return 125
    case .clientLastConnectionResult, .clientLastAttempt, .clientAssociationObservedAt,
      .clientSavedProfile, .clientLastConnectionMode, .clientCredentialSource,
      .clientCredentialResult, .clientSystemFallback, .clientAppReadPassword,
      .clientLastConnectionError:
      return 120
    default: return 64
    }
  }

  var maximumWidth: CGFloat {
    self == .clientAssociated ? defaultWidth : 1_200
  }

  var isNumeric: Bool {
    switch self {
    case .rssi, .noise, .snr, .channel, .bssStationCount, .bssChannelUtilization,
      .bssAdmissionCapacity, .beaconInterval, .dtimCount, .dtimPeriod,
      .bssMaxIdlePeriod, .informationElementCount, .informationElementBytes:
      return true
    default:
      return false
    }
  }

  var defaultSortAscending: Bool {
    switch self {
    case .rssi, .snr, .clientAssociated, .observationStatus, .lastSeen, .clientLockTarget,
      .clientSavedProfile, .clientAppReadPassword, .clientLastAttempt,
      .clientAssociationObservedAt:
      return false
    default:
      return true
    }
  }
}

enum ScanPreset: String, CaseIterable, Codable {
  case overview = "Overview"
  case thisMac = "This Mac"
  case radio = "Radio"
  case security = "Security"
  case roaming = "Roaming"
  case allFields = "All Fields"
  case custom = "Custom"

  static var selectableCases: [ScanPreset] {
    [.overview, .thisMac, .radio, .security, .roaming, .allFields]
  }

  var columns: [ScanColumnID] {
    switch self {
    case .overview:
      return [
        .clientAssociated, .ssid, .bssid, .macRegistrant, .clientLockTarget, .rssi, .channel,
        .band, .security, .phyModes, .observationStatus, .lastSeen,
      ]
    case .thisMac:
      return [
        .clientAssociated, .ssid, .bssid, .macRegistrant, .clientLockTarget, .clientSavedProfile,
        .clientLastConnectionResult, .clientLastAttempt, .clientLastConnectionMode,
        .clientCredentialSource, .clientCredentialResult, .clientSystemFallback,
        .clientAppReadPassword, .clientLastConnectionError, .observationStatus, .lastSeen,
      ]
    case .radio:
      return [
        .clientAssociated, .ssid, .bssid, .macRegistrant, .rssi, .noise, .snr, .channel, .band,
        .channelWidth, .phyModes, .bssStationCount, .bssChannelUtilization,
        .bssAdmissionCapacity, .country, .beaconInterval, .dtimCount, .dtimPeriod,
        .observationStatus, .lastSeen,
      ]
    case .security:
      return [
        .clientAssociated, .ssid, .bssid, .macRegistrant, .security, .rsn,
        .protectedManagementFrames, .fastTransition, .informationElementBytes,
        .observationStatus, .lastSeen,
      ]
    case .roaming:
      return [
        .clientAssociated, .ssid, .bssid, .macRegistrant, .rssi, .channel, .radioMeasurement,
        .bssTransition, .fastTransition, .fastTransitionMobilityDomain, .fastTransitionOverDS,
        .apChannelReports, .reducedNeighborReport, .multipleBSSID, .bssMaxIdlePeriod,
        .protectedKeepAlive, .roamingConsortium, .interworking, .informationElementCount,
        .observationStatus, .lastSeen,
      ]
    case .allFields, .custom:
      return [.clientAssociated] + ScanColumnID.allCases.filter { $0 != .clientAssociated }
    }
  }
}

enum ScanSecurityFilter: String, CaseIterable {
  case all = "Any Security"
  case open = "Open / OWE"
  case personal = "Personal"
  case enterprise = "Enterprise"
  case wep = "WEP"
  case unknown = "Unknown"
}

enum ScanCapabilityFilter: String, CaseIterable {
  case all = "Any Capability"
  case radioMeasurement = "802.11k Advertised"
  case bssTransition = "802.11v Advertised"
  case fastTransition = "802.11r Advertised"
  case rawInformation = "Raw IEs Present"
}

enum ScanObservationFilter: String, CaseIterable {
  case all = "Any Observation"
  case latestScan = "Seen in Latest Scan"
  case previous = "Previous Observations"
}

enum ScanSearchMode {
  case literal
  case regularExpression
}

enum ScanSearchText {
  static func fold(_ value: String) -> String {
    value.folding(
      options: [.caseInsensitive, .diacriticInsensitive],
      locale: .current
    )
  }
}

struct ScanFilter {
  var query = ""
  var searchMode = ScanSearchMode.literal
  var band: String?
  var security = ScanSecurityFilter.all
  var capability = ScanCapabilityFilter.all
  var observation = ScanObservationFilter.all

  var isActive: Bool {
    !query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || band != nil
      || security != .all || capability != .all || observation != .all
  }

  func prepared() -> PreparedScanFilter {
    PreparedScanFilter(filter: self)
  }
}

struct PreparedScanFilter {
  private let filter: ScanFilter
  private let search: PreparedScanSearch

  fileprivate init(filter: ScanFilter) {
    self.filter = filter
    search = PreparedScanSearch(
      query: filter.query,
      mode: filter.searchMode
    )
  }

  var searchError: String? {
    search.error
  }

  func matches(_ row: ScanRow) -> Bool {
    if let band = filter.band {
      if band == "Unknown" {
        if row.accessPoint.band != "?" { return false }
      } else if row.accessPoint.band != band {
        return false
      }
    }

    switch filter.security {
    case .all:
      break
    case .open:
      if row.accessPoint.authentication != .passwordless { return false }
    case .personal:
      if row.accessPoint.authentication != .personal { return false }
    case .enterprise:
      if row.accessPoint.authentication != .enterprise { return false }
    case .wep:
      if !row.accessPoint.security.lowercased().contains("wep") { return false }
    case .unknown:
      if row.accessPoint.authentication != .unknown { return false }
    }

    switch filter.observation {
    case .all:
      break
    case .latestScan:
      if !row.presentInLatestSuccessfulScan { return false }
    case .previous:
      if row.presentInLatestSuccessfulScan { return false }
    }

    switch filter.capability {
    case .all:
      break
    case .radioMeasurement:
      if row.standards.radioMeasurementState != .advertised { return false }
    case .bssTransition:
      if row.standards.bssTransitionState != .advertised { return false }
    case .fastTransition:
      if row.standards.fastTransitionState != .advertised { return false }
    case .rawInformation:
      if row.accessPoint.informationElements?.isEmpty ?? true { return false }
    }

    return search.matches(row)
  }
}

private enum PreparedScanSearch {
  case none
  case literal(String)
  case regularExpression(NSRegularExpression)
  case invalid(String)

  init(query: String, mode: ScanSearchMode) {
    let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
      self = .none
      return
    }

    switch mode {
    case .literal:
      self = .literal(ScanSearchText.fold(trimmed))
    case .regularExpression:
      do {
        self = .regularExpression(
          try NSRegularExpression(
            pattern: query,
            options: [.caseInsensitive, .anchorsMatchLines]
          )
        )
      } catch {
        self = .invalid(error.localizedDescription)
      }
    }
  }

  var error: String? {
    guard case .invalid(let message) = self else { return nil }
    return message
  }

  func matches(_ row: ScanRow) -> Bool {
    switch self {
    case .none:
      return true
    case .literal(let query):
      return row.foldedSearchableText.contains(query)
    case .regularExpression(let expression):
      let text = row.searchableText
      return expression.firstMatch(
        in: text,
        range: NSRange(location: 0, length: text.utf16.count)
      ) != nil
    case .invalid:
      return false
    }
  }
}
