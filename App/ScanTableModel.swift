// SPDX-License-Identifier: GPL-3.0-only

import Foundation

struct ScanSortRule: Codable, Equatable {
  let column: ScanColumnID
  let ascending: Bool
}

enum ScanSemanticSorter {
  static func sort(_ rows: [ScanRow], using rules: [ScanSortRule]) -> [ScanRow] {
    let effectiveRules =
      rules.isEmpty
      ? [
        ScanSortRule(column: .ssid, ascending: true), ScanSortRule(column: .rssi, ascending: false),
      ]
      : rules
    return rows.sorted { left, right in
      for rule in effectiveRules {
        let leftMissing = isMissing(left, column: rule.column)
        let rightMissing = isMissing(right, column: rule.column)
        if leftMissing != rightMissing {
          return !leftMissing
        }
        let comparison = compare(left, right, column: rule.column)
        if comparison != .orderedSame {
          return rule.ascending ? comparison == .orderedAscending : comparison == .orderedDescending
        }
      }
      return left.accessPoint.reportedBSSID.localizedCaseInsensitiveCompare(
        right.accessPoint.reportedBSSID
      ) == .orderedAscending
    }
  }

  private static func compare(_ left: ScanRow, _ right: ScanRow, column: ScanColumnID)
    -> ComparisonResult
  {
    switch column {
    case .observationStatus:
      return compare(
        left.presentInLatestSuccessfulScan ? 1 : 0,
        right.presentInLatestSuccessfulScan ? 1 : 0
      )
    case .lastSeen:
      return compareOptional(left.lastSeenAt, right.lastSeenAt)
    case .rssi:
      return compare(left.accessPoint.rssi, right.accessPoint.rssi)
    case .noise:
      return compare(left.accessPoint.noise, right.accessPoint.noise)
    case .snr:
      return compareOptional(left.signalToNoiseRatio, right.signalToNoiseRatio)
    case .channel:
      return compareOptional(left.accessPoint.channelNumber, right.accessPoint.channelNumber)
    case .bssStationCount:
      return compareOptional(
        left.standards.decodedFields.bssStationCount.value,
        right.standards.decodedFields.bssStationCount.value
      )
    case .bssChannelUtilization:
      return compareOptional(
        left.standards.decodedFields.bssChannelUtilization.value,
        right.standards.decodedFields.bssChannelUtilization.value
      )
    case .bssAdmissionCapacity:
      return compareOptional(
        left.standards.decodedFields.bssAdmissionCapacity.value,
        right.standards.decodedFields.bssAdmissionCapacity.value
      )
    case .beaconInterval:
      return compare(left.accessPoint.beaconInterval, right.accessPoint.beaconInterval)
    case .dtimCount:
      return compareOptional(
        left.standards.decodedFields.dtimCount.value,
        right.standards.decodedFields.dtimCount.value
      )
    case .dtimPeriod:
      return compareOptional(
        left.standards.decodedFields.dtimPeriod.value,
        right.standards.decodedFields.dtimPeriod.value
      )
    case .bssMaxIdlePeriod:
      return compareOptional(
        left.standards.decodedFields.bssMaxIdlePeriod.value,
        right.standards.decodedFields.bssMaxIdlePeriod.value
      )
    case .protectedKeepAlive:
      return compareOptional(
        left.standards.decodedFields.protectedKeepAlive.sortValue,
        right.standards.decodedFields.protectedKeepAlive.sortValue
      )
    case .informationElementCount:
      return compare(left.informationElementCount, right.informationElementCount)
    case .informationElementBytes:
      return compare(left.informationElementBytes, right.informationElementBytes)
    case .clientAssociated:
      return compare(
        left.clientState.associated == true ? 1 : 0,
        right.clientState.associated == true ? 1 : 0
      )
    case .clientLockTarget:
      return compare(
        left.clientState.lockTarget == true ? 1 : 0,
        right.clientState.lockTarget == true ? 1 : 0
      )
    case .clientSavedProfile:
      return compare(
        left.clientState.savedProfiles?.isEmpty == false ? 1 : 0,
        right.clientState.savedProfiles?.isEmpty == false ? 1 : 0
      )
    case .clientAppReadPassword:
      return compare(
        left.clientState.appReadPassword == true ? 1 : 0,
        right.clientState.appReadPassword == true ? 1 : 0
      )
    case .clientLastConnectionResult:
      let stateComparison = (left.clientState.lastConnectionEvent?.state.rawValue ?? "")
        .localizedStandardCompare(right.clientState.lastConnectionEvent?.state.rawValue ?? "")
      if stateComparison != .orderedSame { return stateComparison }
      return compareOptional(
        left.clientState.lastConnectionEvent?.startedAt,
        right.clientState.lastConnectionEvent?.startedAt
      )
    case .clientLastAttempt:
      return compareOptional(
        left.clientState.lastConnectionEvent?.startedAt,
        right.clientState.lastConnectionEvent?.startedAt
      )
    case .clientLastConnectionMode:
      return compareOptional(
        left.clientState.lastConnectionEvent?.mode.rawValue,
        right.clientState.lastConnectionEvent?.mode.rawValue
      )
    case .clientAssociationObservedAt:
      return compareOptional(
        left.clientState.activeAssociationObservation?.capturedAt,
        right.clientState.activeAssociationObservation?.capturedAt
      )
    case .radioMeasurement:
      return compare(
        left.standards.radioMeasurementState.sortOrder,
        right.standards.radioMeasurementState.sortOrder
      )
    case .bssTransition:
      return compare(
        left.standards.bssTransitionState.sortOrder,
        right.standards.bssTransitionState.sortOrder
      )
    case .fastTransition:
      return compare(
        left.standards.fastTransitionState.sortOrder,
        right.standards.fastTransitionState.sortOrder
      )
    case .fastTransitionOverDS:
      return compare(
        left.standards.decodedFields.fastTransitionOverDS.state.sortOrder,
        right.standards.decodedFields.fastTransitionOverDS.state.sortOrder
      )
    case .fastTransitionMobilityDomain:
      return compareOptional(
        left.standards.decodedFields.fastTransitionMobilityDomain.sortValue,
        right.standards.decodedFields.fastTransitionMobilityDomain.sortValue
      )
    case .interworking:
      return compareOptional(
        left.standards.decodedFields.interworking.sortValue,
        right.standards.decodedFields.interworking.sortValue
      )
    case .apChannelReports:
      return compareOptional(
        left.standards.decodedFields.apChannelReports.sortValue,
        right.standards.decodedFields.apChannelReports.sortValue
      )
    case .reducedNeighborReport:
      return compareOptional(
        left.standards.decodedFields.reducedNeighborReport.sortValue,
        right.standards.decodedFields.reducedNeighborReport.sortValue
      )
    case .multipleBSSID:
      return compareOptional(
        left.standards.decodedFields.multipleBSSID.sortValue,
        right.standards.decodedFields.multipleBSSID.sortValue
      )
    case .roamingConsortium:
      return compareOptional(
        left.standards.decodedFields.roamingConsortium.sortValue,
        right.standards.decodedFields.roamingConsortium.sortValue
      )
    default:
      return left.stringValue(for: column).localizedStandardCompare(right.stringValue(for: column))
    }
  }

  private static func compare<Value: Comparable>(_ left: Value, _ right: Value)
    -> ComparisonResult
  {
    if left < right { return .orderedAscending }
    if left > right { return .orderedDescending }
    return .orderedSame
  }

  private static func compareOptional<Value: Comparable>(_ left: Value?, _ right: Value?)
    -> ComparisonResult
  {
    switch (left, right) {
    case (.some(let left), .some(let right)): return compare(left, right)
    case (.none, .some): return .orderedDescending
    case (.some, .none): return .orderedAscending
    case (.none, .none): return .orderedSame
    }
  }

  private static func compareOptional(_ left: String?, _ right: String?) -> ComparisonResult {
    switch (left, right) {
    case (.some(let left), .some(let right)): return left.localizedStandardCompare(right)
    case (.none, .some): return .orderedDescending
    case (.some, .none): return .orderedAscending
    case (.none, .none): return .orderedSame
    }
  }

  private static func isMissing(_ row: ScanRow, column: ScanColumnID) -> Bool {
    switch column {
    case .ssidHex:
      return row.accessPoint.ssidHex.isEmpty
    case .bssid:
      return row.accessPoint.bssid == nil
    case .macRegistrant:
      guard let attribution = row.macAttribution else { return true }
      return attribution.addressType == .invalidAddress
        || (attribution.addressType == .globallyAdministered
          && attribution.isDatabaseUnavailable)
    case .clientAssociated:
      return row.clientState.associated == nil
    case .clientLockTarget:
      return row.clientState.lockTarget == nil
    case .clientSavedProfile:
      return row.clientState.savedProfiles == nil
    case .clientLastConnectionResult, .clientLastAttempt, .clientLastConnectionMode,
      .clientCredentialSource, .clientCredentialResult, .clientLastConnectionError:
      return row.clientState.lastConnectionEvent == nil
    case .clientSystemFallback:
      return row.clientState.systemKeychainConsentScope == nil
    case .clientAppReadPassword:
      return row.clientState.appReadPassword == nil
    case .clientAssociationObservedAt:
      return row.clientState.activeAssociationObservation == nil
    case .noise:
      return row.accessPoint.noise >= 0
    case .snr:
      return row.signalToNoiseRatio == nil
    case .channel:
      return row.accessPoint.channelNumber == nil
    case .band:
      return row.accessPoint.band == "?"
    case .channelWidth:
      return row.accessPoint.channelWidth == "?"
    case .bssStationCount:
      return row.standards.decodedFields.bssStationCount.value == nil
    case .bssChannelUtilization:
      return row.standards.decodedFields.bssChannelUtilization.value == nil
    case .bssAdmissionCapacity:
      return row.standards.decodedFields.bssAdmissionCapacity.value == nil
    case .country:
      return row.accessPoint.countryCode == "?"
    case .dtimCount:
      return row.standards.decodedFields.dtimCount.value == nil
    case .dtimPeriod:
      return row.standards.decodedFields.dtimPeriod.value == nil
    case .rsn:
      return row.standards.decodedReport?.rsnElements.values.isEmpty ?? true
    case .protectedManagementFrames:
      return row.standards.protectedManagementFramesSummary == "Unknown"
    case .phyModes:
      return row.phyStandardsSummary == "Unknown"
    case .security:
      return row.accessPoint.authentication == .unknown
    case .radioMeasurement:
      return row.standards.radioMeasurementState == .unknown
    case .bssTransition:
      return row.standards.bssTransitionState == .unknown
    case .fastTransition:
      return row.standards.fastTransitionState == .unknown
    case .fastTransitionMobilityDomain:
      return row.standards.decodedFields.fastTransitionMobilityDomain.sortValue == nil
    case .fastTransitionOverDS:
      return row.standards.decodedFields.fastTransitionOverDS.state == .unknown
    case .interworking:
      return row.standards.decodedFields.interworking.sortValue == nil
    case .apChannelReports:
      return row.standards.decodedFields.apChannelReports.sortValue == nil
    case .reducedNeighborReport:
      return row.standards.decodedFields.reducedNeighborReport.sortValue == nil
    case .multipleBSSID:
      return row.standards.decodedFields.multipleBSSID.sortValue == nil
    case .bssMaxIdlePeriod:
      return row.standards.decodedFields.bssMaxIdlePeriod.value == nil
    case .protectedKeepAlive:
      return row.standards.decodedFields.protectedKeepAlive.sortValue == nil
    case .roamingConsortium:
      return row.standards.decodedFields.roamingConsortium.sortValue == nil
    default:
      return false
    }
  }
}

struct ScanRetentionMergePlan {
  let freshRows: [ScanRow]
  let retainedRows: [ScanRow]
  let selectedIdentity: ScanRowIdentity?
}

enum ScanRetentionPolicy {
  static func mergePlan(
    previousRows: [ScanRow],
    freshRows: [ScanRow],
    scannedAt: Date,
    retentionSeconds: Int,
    selectedIdentity: ScanRowIdentity?
  ) -> ScanRetentionMergePlan {
    var seenFreshIdentities = Set<ScanRowIdentity>()
    let uniqueFreshRows = freshRows.filter {
      seenFreshIdentities.insert($0.identity).inserted
    }

    var previousByIdentity: [ScanRowIdentity: ScanRow] = [:]
    for row in previousRows where previousByIdentity[row.identity] == nil {
      previousByIdentity[row.identity] = row
    }
    var unmatchedPreviousIdentities = Set(previousByIdentity.keys)
    var unmatchedFreshIndices: [Int] = []
    for index in uniqueFreshRows.indices {
      if unmatchedPreviousIdentities.remove(uniqueFreshRows[index].identity) == nil {
        unmatchedFreshIndices.append(index)
      }
    }

    var effectiveSelection = selectedIdentity
    reconcileMissingSSIDFallbacks(
      freshRows: uniqueFreshRows,
      unmatchedFreshIndices: unmatchedFreshIndices,
      previousByIdentity: previousByIdentity,
      unmatchedPreviousIdentities: &unmatchedPreviousIdentities,
      selectedIdentity: &effectiveSelection
    )

    let retainedRows: [ScanRow]
    if retentionSeconds > 0 {
      let retention = TimeInterval(retentionSeconds)
      retainedRows = previousRows.filter { row in
        guard unmatchedPreviousIdentities.remove(row.identity) != nil else { return false }
        return scannedAt.timeIntervalSince(row.lastSeenAt) < retention
      }
    } else {
      retainedRows = []
    }

    let survivingIdentities = Set((uniqueFreshRows + retainedRows).map(\.identity))
    if let selection = effectiveSelection, !survivingIdentities.contains(selection) {
      effectiveSelection = nil
    }
    return ScanRetentionMergePlan(
      freshRows: uniqueFreshRows,
      retainedRows: retainedRows,
      selectedIdentity: effectiveSelection
    )
  }

  static func prunedRows(
    _ rows: [ScanRow],
    at date: Date,
    retentionSeconds: Int
  ) -> [ScanRow] {
    let retention = TimeInterval(retentionSeconds)
    return rows.filter { row in
      guard !row.presentInLatestSuccessfulScan else { return true }
      guard retention > 0 else { return false }
      return date.timeIntervalSince(row.lastSeenAt) < retention
    }
  }

  static func earliestExpiry(
    in rows: [ScanRow],
    retentionSeconds: Int
  ) -> Date? {
    guard retentionSeconds > 0 else { return nil }
    let retention = TimeInterval(retentionSeconds)
    return rows.lazy.filter { !$0.presentInLatestSuccessfulScan }.map {
      $0.lastSeenAt.addingTimeInterval(retention)
    }.min()
  }

  private static func reconcileMissingSSIDFallbacks(
    freshRows: [ScanRow],
    unmatchedFreshIndices: [Int],
    previousByIdentity: [ScanRowIdentity: ScanRow],
    unmatchedPreviousIdentities: inout Set<ScanRowIdentity>,
    selectedIdentity: inout ScanRowIdentity?
  ) {
    var freshByBSSID: [BSSID: [Int]] = [:]
    for index in unmatchedFreshIndices {
      guard let bssid = freshRows[index].accessPoint.bssid else { continue }
      freshByBSSID[bssid, default: []].append(index)
    }

    var previousByBSSID: [BSSID: [ScanRowIdentity]] = [:]
    for identity in unmatchedPreviousIdentities {
      guard let row = previousByIdentity[identity], let bssid = row.accessPoint.bssid else {
        continue
      }
      previousByBSSID[bssid, default: []].append(identity)
    }

    for (bssid, freshIndices) in freshByBSSID {
      guard freshIndices.count == 1,
        let previousIdentities = previousByBSSID[bssid],
        previousIdentities.count == 1,
        let freshIndex = freshIndices.first,
        let previousIdentity = previousIdentities.first,
        let previousRow = previousByIdentity[previousIdentity]
      else { continue }
      let freshRow = freshRows[freshIndex]
      guard isMissingSSIDFallback(freshRow) || isMissingSSIDFallback(previousRow) else {
        continue
      }
      unmatchedPreviousIdentities.remove(previousIdentity)
      if selectedIdentity == previousIdentity {
        selectedIdentity = freshRow.identity
      }
    }
  }

  private static func isMissingSSIDFallback(_ row: ScanRow) -> Bool {
    guard row.accessPoint.rawSSID == nil, row.accessPoint.bssid != nil else { return false }
    if case .reported(rawSSID: nil, bssid: _) = row.identity { return true }
    return false
  }
}

struct ScanColumnLayout: Codable {
  let id: ScanColumnID
  var width: Double
  var isVisible: Bool
  var order: Int
}

struct ScanSavedPreferences: Codable {
  private static let legacyAutomaticScanInterval = 10

  var preset: ScanPreset
  var columns: [ScanColumnLayout]
  var sortRules: [ScanSortRule]
  var automaticScanInterval: Int
  var cacheRetentionSeconds: Int
  var rawInspectorExpanded: Bool

  private enum CodingKeys: String, CodingKey {
    case preset
    case columns
    case sortRules
    case liveScanning
    case automaticScanInterval = "liveScanInterval"
    case cacheRetentionSeconds
    case rawInspectorExpanded
  }

  init(
    preset: ScanPreset,
    columns: [ScanColumnLayout],
    sortRules: [ScanSortRule],
    automaticScanInterval: Int,
    cacheRetentionSeconds: Int = 0,
    rawInspectorExpanded: Bool
  ) {
    self.preset = preset
    self.columns = columns
    self.sortRules = sortRules
    self.automaticScanInterval = automaticScanInterval
    self.cacheRetentionSeconds = cacheRetentionSeconds
    self.rawInspectorExpanded = rawInspectorExpanded
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    preset = try container.decode(ScanPreset.self, forKey: .preset)
    columns = try container.decode([ScanColumnLayout].self, forKey: .columns)
    sortRules = try container.decode([ScanSortRule].self, forKey: .sortRules)
    rawInspectorExpanded = try container.decode(Bool.self, forKey: .rawInspectorExpanded)

    let validInterval: Int?
    if let interval = try? container.decode(Int.self, forKey: .automaticScanInterval) {
      validInterval = AutomaticUpdateInterval.validated(interval)
    } else if let legacyInterval = try? container.decode(
      TimeInterval.self, forKey: .automaticScanInterval)
    {
      validInterval = AutomaticUpdateInterval.migratedLegacyValue(legacyInterval)
    } else {
      validInterval = nil
    }
    if let legacyAutomaticScanning = try? container.decode(Bool.self, forKey: .liveScanning) {
      // Older preferences represented automatic scanning with a separate
      // Live/Paused flag. Collapse that state into the interval so zero is the
      // sole, unambiguous representation of disabled automatic scans.
      automaticScanInterval =
        legacyAutomaticScanning ? (validInterval ?? Self.legacyAutomaticScanInterval) : 0
    } else {
      automaticScanInterval = validInterval ?? 0
    }
    cacheRetentionSeconds =
      (try? container.decode(Int.self, forKey: .cacheRetentionSeconds))
      .flatMap(AutomaticUpdateInterval.validated) ?? 0
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(preset, forKey: .preset)
    try container.encode(columns, forKey: .columns)
    try container.encode(sortRules, forKey: .sortRules)
    // Keep the removed flag as a derived compatibility field so an older app
    // can still read the user's table layout after a downgrade.
    try container.encode(automaticScanInterval > 0, forKey: .liveScanning)
    try container.encode(automaticScanInterval, forKey: .automaticScanInterval)
    try container.encode(cacheRetentionSeconds, forKey: .cacheRetentionSeconds)
    try container.encode(rawInspectorExpanded, forKey: .rawInspectorExpanded)
  }

  static let defaults = ScanSavedPreferences(
    preset: .overview,
    columns: ScanPreset.allFields.columns.enumerated().map { index, id in
      ScanColumnLayout(
        id: id,
        width: Double(id.defaultWidth),
        isVisible: ScanPreset.overview.columns.contains(id),
        order: index
      )
    },
    sortRules: [
      ScanSortRule(column: .ssid, ascending: true),
      ScanSortRule(column: .rssi, ascending: false),
    ],
    automaticScanInterval: 0,
    cacheRetentionSeconds: 0,
    rawInspectorExpanded: false
  )
}

final class ScanPreferenceStore {
  private let defaults: UserDefaults
  private let key = "ScanWindow.preferences.v2"

  init(defaults: UserDefaults = .standard) {
    self.defaults = defaults
  }

  func load() -> ScanSavedPreferences {
    guard let data = defaults.data(forKey: key),
      let decoded = try? JSONDecoder().decode(ScanSavedPreferences.self, from: data)
    else {
      return .defaults
    }
    return ScanPreferenceNormalizer.normalize(decoded)
  }

  func save(_ preferences: ScanSavedPreferences) {
    guard let data = try? JSONEncoder().encode(preferences) else { return }
    defaults.set(data, forKey: key)
  }

  func resetToDefaults() {
    defaults.removeObject(forKey: key)
  }
}

enum ScanPreferenceNormalizer {
  static func normalize(_ input: ScanSavedPreferences) -> ScanSavedPreferences {
    var preferences = input
    var seenColumns = Set<ScanColumnID>()
    preferences.columns = preferences.columns
      .sorted { $0.order < $1.order }
      .filter { seenColumns.insert($0.id).inserted }
      .enumerated()
      .map { order, layout in
        var normalized = layout
        normalized.order = order
        let width =
          layout.id == .clientAssociated
          ? Double(layout.id.defaultWidth)
          : (layout.width.isFinite ? layout.width : Double(layout.id.defaultWidth))
        normalized.width = min(
          max(width, Double(layout.id.minimumWidth)),
          Double(layout.id.maximumWidth)
        )
        return normalized
      }

    let present = Set(preferences.columns.map(\.id))
    let addedColumnIDs = Set(ScanColumnID.allCases).subtracting(present)
    var nextOrder = (preferences.columns.map(\.order).max() ?? -1) + 1
    for id in ScanColumnID.allCases where !present.contains(id) {
      preferences.columns.append(
        ScanColumnLayout(
          id: id,
          width: Double(id.defaultWidth),
          isVisible: preferences.preset != .custom && preferences.preset.columns.contains(id),
          order: nextOrder
        )
      )
      nextOrder += 1
    }

    // Keep a newly introduced registrant field adjacent to BSSID even in a
    // saved Custom layout. It remains hidden so existing visibility choices
    // are preserved, and the relative order of every existing column is
    // unchanged.
    if preferences.preset == .custom,
      addedColumnIDs.contains(.macRegistrant),
      let registrantIndex = preferences.columns.firstIndex(where: { $0.id == .macRegistrant }),
      let bssidIndex = preferences.columns.firstIndex(where: { $0.id == .bssid })
    {
      let registrantLayout = preferences.columns.remove(at: registrantIndex)
      let adjustedBSSIDIndex =
        registrantIndex < bssidIndex ? bssidIndex - 1 : bssidIndex
      preferences.columns.insert(registrantLayout, at: adjustedBSSIDIndex + 1)
      for index in preferences.columns.indices {
        preferences.columns[index].order = index
      }
    }

    // Upgrade only the exact legacy Overview visibility set. Custom layouts
    // and user-selected columns remain untouched, while an existing Overview
    // gains the two client-state columns now defined by that preset.
    let legacyOverview: Set<ScanColumnID> = [
      .ssid, .bssid, .rssi, .channel, .band, .security, .phyModes,
    ]
    let visibleColumns = Set(preferences.columns.filter(\.isVisible).map(\.id))
      .subtracting(addedColumnIDs)
    if preferences.preset == .overview, visibleColumns == legacyOverview {
      for index in preferences.columns.indices
      where preferences.columns[index].id == .clientAssociated
        || preferences.columns[index].id == .clientLockTarget
      {
        preferences.columns[index].isVisible = true
      }
    }

    // The active-BSSID marker is a permanent row-status affordance rather than
    // an optional data field. Migrate every saved layout, including Custom, to
    // keep it visible, compact, and leading.
    if let associatedIndex = preferences.columns.firstIndex(where: {
      $0.id == .clientAssociated
    }) {
      var associatedLayout = preferences.columns.remove(at: associatedIndex)
      associatedLayout.isVisible = true
      associatedLayout.order = 0
      preferences.columns.insert(associatedLayout, at: 0)
      for index in preferences.columns.indices {
        preferences.columns[index].order = index
      }
    }

    if !preferences.columns.contains(where: {
      $0.id != .clientAssociated && $0.isVisible
    }) {
      let overview = Set(ScanPreset.overview.columns)
      for index in preferences.columns.indices {
        preferences.columns[index].isVisible = overview.contains(preferences.columns[index].id)
      }
      preferences.preset = .overview
    }

    // Named presets have a canonical visible order; reordering a column
    // changes the saved preset to Custom before preferences are written.
    // Keep Custom ordering untouched, including when new hidden columns are
    // appended, while migrating named presets to their current canonical
    // order.
    if preferences.preset != .custom {
      let canonicalIDs = preferences.preset.columns
      let canonicalIDSet = Set(canonicalIDs)
      let remainingIDs = preferences.columns.map(\.id).filter {
        !canonicalIDSet.contains($0)
      }
      let layoutsByID = Dictionary(
        uniqueKeysWithValues: preferences.columns.map { ($0.id, $0) }
      )
      preferences.columns = (canonicalIDs + remainingIDs).enumerated().compactMap {
        order, id in
        guard var layout = layoutsByID[id] else { return nil }
        layout.order = order
        return layout
      }
    }

    if AutomaticUpdateInterval.validated(preferences.automaticScanInterval) == nil {
      preferences.automaticScanInterval = ScanSavedPreferences.defaults.automaticScanInterval
    }
    if AutomaticUpdateInterval.validated(preferences.cacheRetentionSeconds) == nil {
      preferences.cacheRetentionSeconds = ScanSavedPreferences.defaults.cacheRetentionSeconds
    }

    var seenSortColumns = Set<ScanColumnID>()
    preferences.sortRules = preferences.sortRules.filter {
      seenSortColumns.insert($0.column).inserted
    }
    if preferences.sortRules.isEmpty {
      preferences.sortRules = ScanSavedPreferences.defaults.sortRules
    }
    return preferences
  }
}

enum ScanFormatting {
  static let timestamp: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateStyle = .medium
    formatter.timeStyle = .medium
    return formatter
  }()

  static let timeOnly: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateStyle = .none
    formatter.timeStyle = .medium
    return formatter
  }()

  static func compactHex(_ data: Data) -> String {
    data.map { String(format: "%02X", $0) }.joined(separator: " ")
  }

  static func hexDump(_ data: Data, bytesPerLine: Int = 16) -> String {
    guard !data.isEmpty else { return "No raw information-element data." }
    var lines: [String] = []
    for offset in stride(from: 0, to: data.count, by: bytesPerLine) {
      let end = min(offset + bytesPerLine, data.count)
      let slice = data[offset..<end]
      let hexadecimal = slice.map { String(format: "%02X", $0) }.joined(separator: " ")
      let padding = String(repeating: " ", count: max(0, bytesPerLine * 3 - 1 - hexadecimal.count))
      let ascii = slice.map { byte -> Character in
        guard (32...126).contains(byte), let scalar = UnicodeScalar(Int(byte)) else { return "." }
        return Character(scalar)
      }
      lines.append(String(format: "%04X  %@%@  |%@|", offset, hexadecimal, padding, String(ascii)))
    }
    return lines.joined(separator: "\n")
  }
}
