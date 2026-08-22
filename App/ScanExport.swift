// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import UniformTypeIdentifiers

enum ScanExportFormat: String {
  case json
  case csv

  var filenameExtension: String { rawValue }
  var displayName: String { rawValue.uppercased() }
}

enum ScanExportScope {
  case all
  case filtered

  var filenameComponent: String {
    switch self {
    case .all: return "all"
    case .filtered: return "filtered"
    }
  }
}

/// Stable, explicitly enumerated export of every typed value derived from an
/// information-element stream. `WiFiInformationElementReport` keeps its typed
/// views as computed properties, so encoding that model directly would export
/// only its stored raw fields.
private struct ScanTypedInformationElementExport: Encodable {
  struct ParseInformation: Encodable {
    let status: WiFiInformationElementParseStatus
    let issue: WiFiInformationElementParseIssue?
    let rawByteCount: Int
    let parsedElementCount: Int
    let unparsedByteCount: Int
    let unparsedData: Data
  }

  let parse: ParseInformation
  let radioMeasurement80211k: WiFiRadioMeasurementCapabilities
  let bssTransitionManagement80211v: WiFiBSSTransitionManagementCapabilities
  let fastTransition80211r: WiFiFastTransitionCapabilities
  let robustSecurityNetwork: WiFiDecodedElementCollection<WiFiRSNInformation>
  let protectedManagementFrames80211w: WiFiProtectedManagementFrames
  let countryInformation: WiFiDecodedElementCollection<WiFiCountryInformation>
  let apChannelReports: WiFiDecodedElementCollection<WiFiAPChannelReport>
  let bssLoads: WiFiDecodedElementCollection<WiFiBSSLoad>
  let trafficIndicationMaps: WiFiDecodedElementCollection<WiFiTrafficIndicationMap>
  let bssMaxIdlePeriods: WiFiDecodedElementCollection<WiFiBSSMaxIdlePeriod>
  let interworking: WiFiDecodedElementCollection<WiFiInterworkingInformation>
  let roamingConsortiums: WiFiDecodedElementCollection<WiFiRoamingConsortium>
  let reducedNeighborReports: WiFiDecodedElementCollection<WiFiReducedNeighborReport>
  let multipleBSSIDs: WiFiDecodedElementCollection<WiFiMultipleBSSIDInformation>

  init(_ report: WiFiInformationElementReport) {
    parse = ParseInformation(
      status: report.parseStatus,
      issue: report.parseIssue,
      rawByteCount: report.rawData.count,
      parsedElementCount: report.elements.count,
      unparsedByteCount: report.unparsedData.count,
      unparsedData: report.unparsedData
    )
    radioMeasurement80211k = report.radioMeasurement
    bssTransitionManagement80211v = report.bssTransitionManagement
    fastTransition80211r = report.fastTransition
    robustSecurityNetwork = report.rsnElements
    protectedManagementFrames80211w = report.protectedManagementFrames
    countryInformation = report.countryInformation
    apChannelReports = report.apChannelReports
    bssLoads = report.bssLoads
    trafficIndicationMaps = report.trafficIndicationMaps
    bssMaxIdlePeriods = report.bssMaxIdlePeriods
    interworking = report.interworking
    roamingConsortiums = report.roamingConsortiums
    reducedNeighborReports = report.reducedNeighborReports
    multipleBSSIDs = report.multipleBSSIDs
  }
}

enum ScanExporter {
  static func data(
    format: ScanExportFormat,
    rows: [ScanRow],
    context: ScannerContextSnapshot?,
    scannedAt: Date?,
    scope: ScanExportScope
  ) throws -> Data {
    switch format {
    case .json:
      return try jsonData(rows: rows, context: context, scannedAt: scannedAt, scope: scope)
    case .csv:
      return try csvData(rows: rows, context: context, scannedAt: scannedAt, scope: scope)
    }
  }

  static func suggestedFilename(
    format: ScanExportFormat,
    scope: ScanExportScope,
    at date: Date = Date()
  ) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.dateFormat = "yyyy-MM-dd-HHmmss"
    return
      "wifi-scan-\(scope.filenameComponent)-\(formatter.string(from: date)).\(format.filenameExtension)"
  }

  static func tabSeparatedRow(_ row: ScanRow, columns: [ScanColumnID]) -> String {
    let header = columns.map(\.title).joined(separator: "\t")
    let values = columns.map { tsvField(row.stringValue(for: $0)) }.joined(separator: "\t")
    return "\(header)\n\(values)"
  }

  private static func jsonData(
    rows: [ScanRow],
    context: ScannerContextSnapshot?,
    scannedAt: Date?,
    scope: ScanExportScope
  ) throws -> Data {
    var root: [String: Any] = [
      "schema": "local.bssid-picker.scan",
      "schemaVersion": 7,
      "exportedAt": iso8601(Date()),
      "scope": scope.filenameComponent,
      "accessPointCount": rows.count,
      "accessPoints": try rows.map(jsonObject),
    ]
    if let scannedAt { root["scannedAt"] = iso8601(scannedAt) }
    if let observation = rows.first?.clientState.associationObservation {
      root["associationObservation"] = [
        "capturedAt": iso8601(observation.capturedAt),
        "ssidBytesHex": jsonString(
          observation.ssid.map { ScanFormatting.compactHex($0.data) }
        ),
        "currentBSSID": jsonString(observation.bssid?.rawValue),
      ]
    }
    if let context, let object = try contextJSONObject(context) {
      root["scannerContext"] = object
    }
    return try JSONSerialization.data(
      withJSONObject: root,
      options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    )
  }

  private static func jsonObject(_ row: ScanRow) throws -> [String: Any] {
    let accessPoint = row.accessPoint
    let rawElements = accessPoint.informationElements
    let activeAssociation = row.clientState.activeAssociationObservation
    var result: [String: Any] = [
      "identity": [
        "ssid": row.displaySSID,
        "ssidBytesHex": accessPoint.ssidHex,
        "bssid": accessPoint.reportedBSSID,
      ],
      "macRegistration": macRegistrationJSONObject(row),
      "scanObservation": [
        "presentInLatestSuccessfulScan": row.presentInLatestSuccessfulScan,
        "status":
          row.presentInLatestSuccessfulScan
          ? "Seen in latest scan" : "Previous observation",
        "lastSeenAt": iso8601(row.lastSeenAt),
      ],
      "clientState": [
        "source": "Application client state; not advertised by the access point",
        "contextAvailable": row.clientState.contextAvailable,
        "associated": jsonBoolean(row.clientState.associated),
        "associatedDisplay": row.clientState.associatedDisplayName,
        "associationObservedAt": jsonString(
          activeAssociation.map { iso8601($0.capturedAt) }
        ),
        "associationObservedBSSID": jsonString(
          activeAssociation?.bssid?.rawValue
        ),
        "associationObservedSSIDBytesHex": jsonString(
          activeAssociation?.ssid.map {
            ScanFormatting.compactHex($0.data)
          }
        ),
        "lockTarget": jsonBoolean(row.clientState.lockTarget),
        "lockTargetDisplay": row.clientState.lockTargetDisplayName,
        "savedProfile": row.clientState.savedProfileDisplayName,
        "matchingSavedProfiles": row.clientState.savedProfiles.map { profiles in
          profiles.map { profile in
            [
              "ssid": jsonString(profile.displaySSID),
              "ssidBytesHex": ScanFormatting.compactHex(profile.rawSSID.data),
              "security": profile.security.rawValue,
              "preferenceIndex": profile.preferenceIndex,
            ] as [String: Any]
          }
        } as Any? ?? NSNull(),
        "lastConnectionResult": jsonString(row.clientState.lastConnectionEvent?.state.rawValue),
        "lastConnectionResultDisplay": row.clientState.lastConnectionResult,
        "lastConnectionMode": jsonString(row.clientState.lastConnectionEvent?.mode.rawValue),
        "lastConnectionMessage": jsonString(row.clientState.lastConnectionEvent?.message),
        "lastAttemptAt": jsonString(
          row.clientState.lastConnectionEvent.map { iso8601($0.startedAt) }),
        "lastAttemptDisplay": row.clientState.lastAttemptDisplayName,
        "lastConnectionEventID": jsonString(
          row.clientState.lastConnectionEvent?.id.uuidString.lowercased()
        ),
        "systemKeychainFallbackConsent": jsonString(
          row.clientState.systemKeychainConsentScope?.rawValue
        ),
        "credentialSource": row.clientState.credentialSourceDisplayName,
        "credentialResult": row.clientState.credentialResultDisplayName,
        "appReadPassword": jsonBoolean(row.clientState.appReadPassword),
        "credentialDiagnostics": try row.clientState.lastConnectionEvent.flatMap {
          try codableJSONObject($0.credentialDiagnostics)
        } ?? NSNull(),
      ],
      "radio": [
        "rssiDBm": accessPoint.rssi,
        "noiseDBm": jsonInteger(accessPoint.noise < 0 ? accessPoint.noise : nil),
        "snrDB": jsonInteger(row.signalToNoiseRatio),
        "channel": jsonInteger(accessPoint.channelNumber),
        "band": accessPoint.band,
        "channelWidth": accessPoint.channelWidth,
        "coreWLANPHYModes": accessPoint.phyModes,
        "reportedOrInferredPHYStandards": row.phyStandardsSummary,
        "bssLoad": [
          "stationCount": jsonInteger(row.standards.decodedFields.bssStationCount.value),
          "stationCountDisplay": row.standards.decodedFields.bssStationCount.displayName,
          "channelUtilizationRaw": jsonInteger(
            row.standards.decodedFields.bssChannelUtilization.value
          ),
          "channelUtilizationDisplay":
            row.standards.decodedFields.bssChannelUtilization.displayName,
          "availableAdmissionCapacity": jsonInteger(
            row.standards.decodedFields.bssAdmissionCapacity.value
          ),
          "availableAdmissionCapacityDisplay":
            row.standards.decodedFields.bssAdmissionCapacity.displayName,
        ],
      ],
      "security": [
        "coreWLANSummary": accessPoint.security,
        "rsn": row.standards.rsnSummary,
        "protectedManagementFrames": row.standards.protectedManagementFramesSummary,
      ],
      "roamingAndManagement": [
        "evidenceScope":
          "Derived from one CoreWLAN beacon/probe-response information-element blob; this does not test this Mac's capabilities or prove end-to-end enablement.",
        "radioMeasurement80211k": [
          "state": row.standards.radioMeasurementState.detailedDisplayName,
          "summary": row.standards.radioMeasurementSummary,
        ],
        "bssTransition80211v": [
          "state": row.standards.bssTransitionState.detailedDisplayName,
          "summary": row.standards.bssTransitionSummary,
        ],
        "fastTransition80211r": [
          "state": row.standards.fastTransitionState.detailedDisplayName,
          "summary": row.standards.fastTransitionSummary,
          "mobilityDomainIdentifier":
            row.standards.decodedFields.fastTransitionMobilityDomain.displayName,
          "fastTransitionOverDS": row.standards.decodedFields.fastTransitionOverDS.displayName,
        ],
        "interworking": row.standards.decodedFields.interworking.displayName,
        "apChannelReports": row.standards.decodedFields.apChannelReports.displayName,
        "reducedNeighborReport": row.standards.decodedFields.reducedNeighborReport.displayName,
        "multipleBSSID": row.standards.decodedFields.multipleBSSID.displayName,
        "roamingConsortium": row.standards.decodedFields.roamingConsortium.displayName,
        "bssMaximumIdle": [
          "periodInThousandsOfTU": jsonInteger(
            row.standards.decodedFields.bssMaxIdlePeriod.value
          ),
          "periodDisplay": row.standards.decodedFields.bssMaxIdlePeriod.displayName,
          "protectedKeepAlive": row.standards.decodedFields.protectedKeepAlive.displayName,
        ],
      ],
      "timingAndTopology": [
        "countryCode": accessPoint.countryCode,
        "beaconIntervalMS": accessPoint.beaconInterval,
        "dtimCount": jsonInteger(row.standards.decodedFields.dtimCount.value),
        "dtimCountDisplay": row.standards.decodedFields.dtimCount.displayName,
        "dtimPeriod": jsonInteger(row.standards.decodedFields.dtimPeriod.value),
        "dtimPeriodDisplay": row.standards.decodedFields.dtimPeriod.displayName,
        "networkType": accessPoint.isIBSS ? "IBSS" : "Infrastructure",
      ],
      "informationElements": [
        "parseStatus": row.standards.parseStatus,
        "dataPresent": rawElements != nil,
        "count": row.informationElementCount,
        "byteCount": row.informationElementBytes,
        "rawBase64": jsonString(rawElements?.base64EncodedString()),
        "rawHex": jsonString(rawElements.map(ScanFormatting.compactHex)),
        "decoded": row.standards.elements.map { element in
          [
            "identifier": element.identifier,
            "name": element.name,
            "length": element.length,
            "summary": element.summary,
            "rawHex": element.rawHex,
          ] as [String: Any]
        },
      ],
    ]
    if let report = row.standards.decodedReport,
      let typedReport = try codableJSONObject(ScanTypedInformationElementExport(report))
    {
      var informationElements = result["informationElements"] as? [String: Any] ?? [:]
      informationElements["typedReport"] = typedReport
      result["informationElements"] = informationElements
    }
    return result
  }

  private static func csvData(
    rows: [ScanRow],
    context: ScannerContextSnapshot?,
    scannedAt: Date?,
    scope: ScanExportScope
  ) throws -> Data {
    let columns = ScanColumnID.allCases
    let supplementalTitles = [
      "MAC Address Type",
      "MAC Allocation",
      "MAC Matched Prefix",
      "MAC Registration Source",
      "MAC Database Agreement",
      "Known Address Role",
      "IE Parse Status",
      "IE Data Present",
      "Raw IE Base64",
      "Raw IE Hex",
      "Decoded IE Summary JSON",
      "Typed IE Report JSON",
      "Client Last Attempt ISO 8601",
      "Association Observed ISO 8601",
      "Association Observed SSID Bytes Hex",
      "Association Observed BSSID",
      "Present in Latest Successful Scan",
      "Last Seen ISO 8601",
      "Scanned At",
      "Export Scope",
      "Scanner Context JSON",
    ]
    let header = columns.map(\.title) + supplementalTitles
    var records: [String] = [header.map(csvField).joined(separator: ",")]
    let contextJSON = try context.map(codableJSONString) ?? ""
    let scannedAtValue = scannedAt.map(iso8601) ?? ""
    for row in rows {
      records.append(
        try csvRecord(
          for: row,
          columns: columns,
          contextJSON: contextJSON,
          scannedAtValue: scannedAtValue,
          scope: scope
        )
      )
    }
    // A UTF-8 BOM helps spreadsheet applications recognize non-ASCII SSIDs.
    return Data([0xEF, 0xBB, 0xBF]) + Data(records.joined(separator: "\r\n").utf8)
  }

  private static func csvRecord(
    for row: ScanRow,
    columns: [ScanColumnID],
    contextJSON: String,
    scannedAtValue: String,
    scope: ScanExportScope
  ) throws -> String {
    let rawElements = row.accessPoint.informationElements
    let activeAssociation = row.clientState.activeAssociationObservation
    let decodedElements: [[String: Any]] = row.standards.elements.map { element in
      [
        "identifier": element.identifier,
        "name": element.name,
        "length": element.length,
        "summary": element.summary,
        "rawHex": element.rawHex,
      ]
    }
    let decodedJSON = try jsonString(decodedElements)
    let typedJSON: String
    if let report = row.standards.decodedReport {
      typedJSON = try codableJSONString(ScanTypedInformationElementExport(report))
    } else {
      typedJSON = ""
    }
    let attribution = row.macAttribution
    let registrationSource = attribution.flatMap { attribution -> String? in
      if let source = attribution.registrationSourceDisplayName { return source }
      let claimSources = Set(attribution.registryClaims.map(\.source.rawValue)).sorted()
      return claimSources.isEmpty ? nil : claimSources.joined(separator: ", ")
    }

    var values = columns.map { row.stringValue(for: $0) }
    values.reserveCapacity(values.count + 21)
    values.append(attribution?.addressTypeDisplayName ?? "")
    values.append(attribution?.allocationDisplayName ?? "")
    values.append(attribution?.matchedPrefix ?? "")
    values.append(registrationSource ?? "")
    values.append(attribution?.databaseAgreementDisplayName ?? "")
    values.append(attribution?.knownAddressRole ?? "")
    values.append(row.standards.parseStatus)
    values.append(rawElements == nil ? "false" : "true")
    values.append(rawElements?.base64EncodedString() ?? "")
    values.append(rawElements.map(ScanFormatting.compactHex) ?? "")
    values.append(decodedJSON)
    values.append(typedJSON)
    values.append(row.clientState.lastConnectionEvent.map { iso8601($0.startedAt) } ?? "")
    values.append(activeAssociation.map { iso8601($0.capturedAt) } ?? "")
    values.append(
      activeAssociation?.ssid.map {
        ScanFormatting.compactHex($0.data)
      } ?? ""
    )
    values.append(activeAssociation?.bssid?.rawValue ?? "")
    values.append(row.presentInLatestSuccessfulScan ? "true" : "false")
    values.append(iso8601(row.lastSeenAt))
    values.append(scannedAtValue)
    values.append(scope.filenameComponent)
    values.append(contextJSON)
    return values.map(csvField).joined(separator: ",")
  }

  private static func csvField(_ value: String) -> String {
    let safeValue = neutralizingSpreadsheetFormula(value)
    return "\"\(safeValue.replacingOccurrences(of: "\"", with: "\"\""))\""
  }

  private static func tsvField(_ value: String) -> String {
    neutralizingSpreadsheetFormula(value)
      .replacingOccurrences(of: "\\", with: "\\\\")
      .replacingOccurrences(of: "\t", with: "\\t")
      .replacingOccurrences(of: "\r", with: "\\r")
      .replacingOccurrences(of: "\n", with: "\\n")
  }

  /// Quoting a CSV field does not prevent spreadsheet applications from
  /// evaluating formula-like values. Prefixing an apostrophe preserves the
  /// visible value while forcing a literal cell in common spreadsheet apps.
  private static func neutralizingSpreadsheetFormula(_ value: String) -> String {
    guard let first = value.unicodeScalars.first else { return value }
    switch first.value {
    case 0x00, 0x09, 0x0A, 0x0D, 0x2B, 0x2D, 0x3D, 0x40,
      0xFF0B, 0xFF0D, 0xFF1D, 0xFF20:
      return "'" + value
    default:
      return value
    }
  }

  private static func jsonInteger(_ value: Int?) -> Any {
    value ?? NSNull()
  }

  private static func jsonBoolean(_ value: Bool?) -> Any {
    value ?? NSNull()
  }

  private static func jsonString(_ value: String?) -> Any {
    value ?? NSNull()
  }

  private static func macRegistrationJSONObject(_ row: ScanRow) -> [String: Any] {
    guard let attribution = row.macAttribution else {
      return [
        "addressType": NSNull(),
        "registrantDisplay": "Unavailable",
        "registeredOrganization": NSNull(),
        "allocation": NSNull(),
        "matchedPrefix": NSNull(),
        "registrationSource": NSNull(),
        "databaseAgreement": NSNull(),
        "knownAddressRole": NSNull(),
        "registryClaims": [],
        "evidenceScope":
          "MAC-prefix registration may not identify the access point's brand, manufacturer, owner, or operator.",
      ]
    }
    let registrationSource: String?
    if let source = attribution.registrationSourceDisplayName {
      registrationSource = source
    } else {
      let claimSources = Set(attribution.registryClaims.map(\.source.rawValue)).sorted()
      registrationSource = claimSources.isEmpty ? nil : claimSources.joined(separator: ", ")
    }
    return [
      "addressType": attribution.addressTypeDisplayName,
      "registrantDisplay": attribution.registrantDisplayName,
      "registeredOrganization": jsonString(attribution.registeredOrganization),
      "allocation": jsonString(attribution.allocationDisplayName),
      "matchedPrefix": jsonString(attribution.matchedPrefix),
      "registrationSource": jsonString(registrationSource),
      "databaseAgreement": jsonString(attribution.databaseAgreementDisplayName),
      "knownAddressRole": jsonString(attribution.knownAddressRole),
      "registryClaims": attribution.registryClaims.map {
        [
          "organization": $0.organization,
          "source": $0.source.rawValue,
        ]
      },
      "evidenceScope":
        "MAC-prefix registration may not identify the access point's brand, manufacturer, owner, or operator.",
    ]
  }

  private static func jsonString(_ value: Any) throws -> String {
    let data = try JSONSerialization.data(
      withJSONObject: value,
      options: [.sortedKeys, .withoutEscapingSlashes]
    )
    return String(decoding: data, as: UTF8.self)
  }

  private static func contextJSONObject(_ context: ScannerContextSnapshot) throws -> Any? {
    try codableJSONObject(context)
  }

  private static func codableJSONObject<Value: Encodable>(_ value: Value) throws -> Any? {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    let data = try encoder.encode(value)
    return try JSONSerialization.jsonObject(with: data)
  }

  private static func codableJSONString<Value: Encodable>(_ value: Value) throws -> String {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return String(decoding: try encoder.encode(value), as: UTF8.self)
  }

  private static func iso8601(_ date: Date) -> String {
    ISO8601DateFormatter().string(from: date)
  }
}

enum ScanExportPresenter {
  static func begin(
    format: ScanExportFormat,
    scope: ScanExportScope,
    rows: [ScanRow],
    context: ScannerContextSnapshot?,
    scannedAt: Date?,
    in window: NSWindow,
    completion: @escaping () -> Void
  ) {
    let panel = NSSavePanel()
    panel.title = "Export Wi-Fi Scan"
    panel.prompt = "Export"
    panel.canCreateDirectories = true
    panel.isExtensionHidden = false
    panel.allowedContentTypes = [
      UTType(filenameExtension: format.filenameExtension) ?? .data
    ]
    panel.nameFieldStringValue = ScanExporter.suggestedFilename(format: format, scope: scope)
    panel.beginSheetModal(for: window) { response in
      guard response == .OK, let url = panel.url else { return }
      DispatchQueue.global(qos: .userInitiated).async {
        do {
          let data = try ScanExporter.data(
            format: format,
            rows: rows,
            context: context,
            scannedAt: scannedAt,
            scope: scope
          )
          try data.write(to: url, options: .atomic)
          DispatchQueue.main.async(execute: completion)
        } catch {
          DispatchQueue.main.async {
            present(error: error, in: window)
          }
        }
      }
    }
  }

  private static func present(error: Error, in window: NSWindow) {
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = "Export Failed"
    alert.informativeText = error.localizedDescription
    alert.beginSheetModal(for: window)
  }
}
