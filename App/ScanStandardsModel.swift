// SPDX-License-Identifier: GPL-3.0-only

import Foundation

struct ScanInformationElementPresentation {
  let identifier: String
  let name: String
  let length: Int
  let summary: String
  let rawHex: String
}

struct ScanDecodedNumericPresentation {
  let value: Int?
  let displayName: String
  let state: WiFiAdvertisementState

  static let unavailable = ScanDecodedNumericPresentation(
    value: nil,
    displayName: "Unavailable",
    state: .unknown
  )
}

struct ScanDecodedTextPresentation {
  let sortValue: String?
  let displayName: String
  let state: WiFiAdvertisementState

  static let unavailable = ScanDecodedTextPresentation(
    sortValue: nil,
    displayName: "Unavailable",
    state: .unknown
  )
}

/// Compact, sortable views of typed information elements used by the table
/// and export formats. Raw values remain available in the inspector and typed
/// JSON report, while these fields make common AP/BSS facts directly useful.
struct ScanDecodedFieldsPresentation {
  let dtimCount: ScanDecodedNumericPresentation
  let dtimPeriod: ScanDecodedNumericPresentation
  let bssStationCount: ScanDecodedNumericPresentation
  let bssChannelUtilization: ScanDecodedNumericPresentation
  let bssAdmissionCapacity: ScanDecodedNumericPresentation
  let fastTransitionMobilityDomain: ScanDecodedTextPresentation
  let fastTransitionOverDS: ScanDecodedTextPresentation
  let interworking: ScanDecodedTextPresentation
  let apChannelReports: ScanDecodedTextPresentation
  let reducedNeighborReport: ScanDecodedTextPresentation
  let multipleBSSID: ScanDecodedTextPresentation
  let bssMaxIdlePeriod: ScanDecodedNumericPresentation
  let protectedKeepAlive: ScanDecodedTextPresentation
  let roamingConsortium: ScanDecodedTextPresentation

  static let unavailable = ScanDecodedFieldsPresentation(
    dtimCount: .unavailable,
    dtimPeriod: .unavailable,
    bssStationCount: .unavailable,
    bssChannelUtilization: .unavailable,
    bssAdmissionCapacity: .unavailable,
    fastTransitionMobilityDomain: .unavailable,
    fastTransitionOverDS: .unavailable,
    interworking: .unavailable,
    apChannelReports: .unavailable,
    reducedNeighborReport: .unavailable,
    multipleBSSID: .unavailable,
    bssMaxIdlePeriod: .unavailable,
    protectedKeepAlive: .unavailable,
    roamingConsortium: .unavailable
  )

  static func decode(_ report: WiFiInformationElementReport) -> ScanDecodedFieldsPresentation {
    let trafficIndicationMaps = report.trafficIndicationMaps
    let bssLoads = report.bssLoads
    let fastTransition = report.fastTransition
    let fastTransitionOverDS = fastTransition.fastTransitionOverDS
    let fastTransitionOverDSSortValue: String?
    if fastTransition.mobilityDomains.isEmpty {
      fastTransitionOverDSSortValue = nil
    } else {
      switch fastTransitionOverDS {
      case .advertised: fastTransitionOverDSSortValue = "1"
      case .notAdvertised: fastTransitionOverDSSortValue = "0"
      case .unknown: fastTransitionOverDSSortValue = nil
      }
    }

    return ScanDecodedFieldsPresentation(
      dtimCount: numeric(trafficIndicationMaps, value: { Int($0.dtimCount) }),
      dtimPeriod: numeric(trafficIndicationMaps, value: { Int($0.dtimPeriod) }),
      bssStationCount: numeric(bssLoads, value: { Int($0.stationCount) }),
      bssChannelUtilization: numeric(
        bssLoads,
        value: { Int($0.channelUtilization) },
        format: { rawValue in
          String(format: "%.1f%%", Double(rawValue) / 255.0 * 100.0)
        }
      ),
      bssAdmissionCapacity: numeric(
        bssLoads,
        value: { Int($0.availableAdmissionCapacity) },
        format: { "\($0) × 32 µs/s" }
      ),
      fastTransitionMobilityDomain: mobilityDomain(fastTransition),
      fastTransitionOverDS: ScanDecodedTextPresentation(
        sortValue: fastTransitionOverDSSortValue,
        displayName: fastTransitionOverDS.displayName,
        state: fastTransitionOverDS
      ),
      interworking: text(report.interworking) { value in
        var fields = [
          "type \(value.accessNetworkType)",
          "internet \(yesNo(value.internetAvailable))",
        ]
        if let venueGroup = value.venueGroup, let venueType = value.venueType {
          fields.append("venue \(venueGroup)/\(venueType)")
        }
        if let hessid = value.homogeneousExtendedServiceSetIdentifier {
          fields.append("HESSID \(ScanFormatting.compactHex(hessid))")
        }
        return fields.joined(separator: "; ")
      },
      apChannelReports: text(report.apChannelReports) { value in
        let channels = value.channelNumbers.map(String.init).joined(separator: "/")
        return "class \(value.operatingClass): \(channels.isEmpty ? "no channels" : channels)"
      },
      reducedNeighborReport: text(report.reducedNeighborReports) { value in
        let neighbors = value.neighborAccessPoints
        let channels = neighbors.map { "\($0.operatingClass)/\($0.channelNumber)" }
        var seenChannels = Set<String>()
        let uniqueChannels = channels.filter { seenChannels.insert($0).inserted }
        let channelSummary =
          uniqueChannels.isEmpty ? "" : ": \(uniqueChannels.joined(separator: ", "))"
        return
          "\(neighbors.count) neighbor field\(neighbors.count == 1 ? "" : "s")\(channelSummary)"
      },
      multipleBSSID: text(report.multipleBSSIDs) { value in
        "max indicator \(value.maximumBSSIDIndicator); \(value.subelements.count) subelement\(value.subelements.count == 1 ? "" : "s")"
      },
      bssMaxIdlePeriod: numeric(
        report.bssMaxIdlePeriods,
        value: { Int($0.maximumIdlePeriod) },
        format: { "\($0) × 1,000 TU" }
      ),
      protectedKeepAlive: boolean(
        report.bssMaxIdlePeriods,
        value: \.protectedKeepAliveRequired,
        trueName: "Required",
        falseName: "Not Required"
      ),
      roamingConsortium: text(report.roamingConsortiums) { value in
        let identifiers = value.organizationIdentifiers.map(ScanFormatting.compactHex)
        let identifierSummary = identifiers.isEmpty ? "none" : identifiers.joined(separator: "/")
        return "ANQP OI count \(value.anqpOrganizationIdentifierCount); OIs \(identifierSummary)"
      }
    )
  }

  private static func numeric<Value>(
    _ collection: WiFiDecodedElementCollection<Value>,
    value: (Value) -> Int,
    format: (Int) -> String = String.init
  ) -> ScanDecodedNumericPresentation
  where Value: Codable & Hashable & Sendable {
    let values = Set(collection.values.map(value))
    guard let onlyValue = values.first, values.count == 1 else {
      if values.isEmpty {
        return ScanDecodedNumericPresentation(
          value: nil,
          displayName: collection.advertisement.displayName,
          state: collection.advertisement
        )
      }
      return ScanDecodedNumericPresentation(
        value: nil,
        displayName:
          "Conflicting Values: \(values.sorted().map(String.init).joined(separator: ", "))",
        state: .unknown
      )
    }

    let suffix = collection.advertisement == .unknown ? " (partial)" : ""
    return ScanDecodedNumericPresentation(
      value: onlyValue,
      displayName: format(onlyValue) + suffix,
      state: collection.advertisement
    )
  }

  private static func text<Value>(
    _ collection: WiFiDecodedElementCollection<Value>,
    summarize: (Value) -> String
  ) -> ScanDecodedTextPresentation
  where Value: Codable & Hashable & Sendable {
    let summaries = collection.values.map(summarize)
    guard !summaries.isEmpty else {
      let state = collection.advertisement
      return ScanDecodedTextPresentation(
        sortValue: nil,
        displayName: state.displayName,
        state: state
      )
    }
    let summary = summaries.joined(separator: " | ")
    let suffix = collection.advertisement == .unknown ? " (partial)" : ""
    return ScanDecodedTextPresentation(
      sortValue: summary,
      displayName: summary + suffix,
      state: collection.advertisement
    )
  }

  private static func boolean<Value>(
    _ collection: WiFiDecodedElementCollection<Value>,
    value: (Value) -> Bool,
    trueName: String,
    falseName: String
  ) -> ScanDecodedTextPresentation
  where Value: Codable & Hashable & Sendable {
    let values = Set(collection.values.map(value))
    guard let onlyValue = values.first, values.count == 1 else {
      if values.isEmpty {
        let state = collection.advertisement
        return ScanDecodedTextPresentation(
          sortValue: nil, displayName: state.displayName, state: state)
      }
      return ScanDecodedTextPresentation(
        sortValue: nil,
        displayName: "Conflicting Values",
        state: .unknown
      )
    }
    let displayName = onlyValue ? trueName : falseName
    let suffix = collection.advertisement == .unknown ? " (partial)" : ""
    return ScanDecodedTextPresentation(
      sortValue: onlyValue ? "1" : "0",
      displayName: displayName + suffix,
      state: collection.advertisement
    )
  }

  private static func mobilityDomain(_ value: WiFiFastTransitionCapabilities)
    -> ScanDecodedTextPresentation
  {
    let identifiers = Set(value.mobilityDomains.map(\.mobilityDomainIdentifier))
    guard let identifier = identifiers.first, identifiers.count == 1 else {
      if identifiers.isEmpty {
        let state = value.advertisement
        return ScanDecodedTextPresentation(
          sortValue: nil, displayName: state.displayName, state: state)
      }
      return ScanDecodedTextPresentation(
        sortValue: nil,
        displayName: "Conflicting Mobility Domains",
        state: .unknown
      )
    }
    let summary = ScanFormatting.compactHex(identifier)
    let suffix = value.advertisement == .unknown ? " (partial)" : ""
    return ScanDecodedTextPresentation(
      sortValue: summary,
      displayName: summary + suffix,
      state: value.advertisement
    )
  }

  private static func yesNo(_ value: Bool) -> String { value ? "yes" : "no" }
}

extension WiFiAdvertisementState {
  var sortOrder: Int {
    switch self {
    case .unknown: return 0
    case .notAdvertised: return 1
    case .advertised: return 2
    }
  }

  var displayName: String {
    switch self {
    case .advertised: return "Advertised"
    case .notAdvertised: return "Not Advertised"
    case .unknown: return "Unknown"
    }
  }

  var detailedDisplayName: String {
    switch self {
    case .advertised: return "Advertised in Captured Frame"
    case .notAdvertised: return "Not Advertised in Captured Frame"
    case .unknown: return "Unknown from Captured Frame"
    }
  }
}

struct ScanStandardsPresentation {
  let decodedReport: WiFiInformationElementReport?
  let decodedFields: ScanDecodedFieldsPresentation
  let parseStatus: String
  let radioMeasurementState: WiFiAdvertisementState
  let radioMeasurementSummary: String
  let bssTransitionState: WiFiAdvertisementState
  let bssTransitionSummary: String
  let fastTransitionState: WiFiAdvertisementState
  let fastTransitionSummary: String
  let rsnSummary: String
  let protectedManagementFramesSummary: String
  let elements: [ScanInformationElementPresentation]

  static func decode(_ data: Data?) -> ScanStandardsPresentation {
    guard let data else {
      return ScanStandardsPresentation(
        decodedReport: nil,
        decodedFields: .unavailable,
        parseStatus: "Unavailable — CoreWLAN did not provide information-element data",
        radioMeasurementState: .unknown,
        radioMeasurementSummary: "Unknown",
        bssTransitionState: .unknown,
        bssTransitionSummary: "Unknown",
        fastTransitionState: .unknown,
        fastTransitionSummary: "Unknown",
        rsnSummary: "Unavailable",
        protectedManagementFramesSummary: "Unknown",
        elements: []
      )
    }

    let report = WiFiInformationElementDecoder.decode(data)
    let radioMeasurement = report.radioMeasurement
    let bssTransition = report.bssTransitionManagement
    let fastTransition = report.fastTransition
    var presentedElements = report.elements.map { element in
      ScanInformationElementPresentation(
        identifier: "ID \(element.identifier) @ 0x\(String(format: "%04X", element.offset))",
        name: ScanInformationElementPresenter.name(for: element),
        length: element.length,
        summary: ScanInformationElementPresenter.summary(for: element, report: report),
        rawHex: ScanFormatting.compactHex(element.encodedBytes)
      )
    }
    if !report.unparsedData.isEmpty {
      let offset = report.parseIssue?.offset ?? (data.count - report.unparsedData.count)
      presentedElements.append(
        ScanInformationElementPresentation(
          identifier: "Unparsed @ 0x\(String(format: "%04X", offset))",
          name: "Malformed Trailing Data",
          length: report.unparsedData.count,
          summary: ScanInformationElementPresenter.parseIssueSummary(report.parseIssue),
          rawHex: ScanFormatting.compactHex(report.unparsedData)
        )
      )
    }

    return ScanStandardsPresentation(
      decodedReport: report,
      decodedFields: .decode(report),
      parseStatus: ScanInformationElementPresenter.parseStatus(report),
      radioMeasurementState: radioMeasurement.advertisement,
      radioMeasurementSummary: ScanInformationElementPresenter.radioMeasurementSummary(
        radioMeasurement
      ),
      bssTransitionState: bssTransition.advertisement,
      bssTransitionSummary: ScanInformationElementPresenter.bssTransitionSummary(bssTransition),
      fastTransitionState: fastTransition.advertisement,
      fastTransitionSummary: ScanInformationElementPresenter.fastTransitionSummary(fastTransition),
      rsnSummary: ScanInformationElementPresenter.rsnSummary(report.rsnElements),
      protectedManagementFramesSummary: ScanInformationElementPresenter.pmfSummary(
        report.protectedManagementFrames
      ),
      elements: presentedElements
    )
  }
}

/// Per-access-point application state. These values are derived from the latest
/// client snapshot and are intentionally kept separate from beacon/probe data.
