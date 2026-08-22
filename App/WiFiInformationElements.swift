// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Whether a capability was advertised in the supplied information-element
/// stream. This deliberately does not claim that a feature is supported by the
/// client, negotiated, or enabled end to end.
enum WiFiAdvertisementState: String, Codable, Hashable, Sendable {
  case advertised
  case notAdvertised
  case unknown
}

enum WiFiInformationElementParseStatus: String, Codable, Hashable, Sendable {
  case complete
  case empty
  case malformed
}

enum WiFiInformationElementParseIssueKind: String, Codable, Hashable, Sendable {
  case truncatedHeader
  case truncatedPayload
}

struct WiFiInformationElementParseIssue: Codable, Hashable, Sendable {
  let kind: WiFiInformationElementParseIssueKind
  let offset: Int
  let declaredPayloadLength: Int?
  let availableByteCount: Int
}

/// Element identifiers decoded by this file. Unknown identifiers remain
/// available through `WiFiInformationElement.identifier`.
enum WiFiInformationElementID: UInt8, Codable, Hashable, Sendable {
  case trafficIndicationMap = 5
  case country = 7
  case bssLoad = 11
  case robustSecurityNetwork = 48
  case apChannelReport = 51
  case mobilityDomain = 54
  case radioMeasurementEnabledCapabilities = 70
  case multipleBSSID = 71
  case bssMaxIdlePeriod = 90
  case interworking = 107
  case advertisementProtocol = 108
  case roamingConsortium = 111
  case extendedCapabilities = 127
  case reducedNeighborReport = 201
  case vendorSpecific = 221
  case elementIDExtension = 255
}

/// One syntactically complete IEEE 802.11 information element. Instances stay
/// in wire order, so duplicate and unknown elements are never discarded.
struct WiFiInformationElement: Codable, Hashable, Sendable {
  let offset: Int
  let identifier: UInt8
  let payload: Data

  var knownIdentifier: WiFiInformationElementID? {
    WiFiInformationElementID(rawValue: identifier)
  }

  var length: Int { payload.count }

  var encodedBytes: Data {
    precondition(payload.count <= Int(UInt8.max))
    var bytes = Data([identifier, UInt8(payload.count)])
    bytes.append(payload)
    return bytes
  }
}

/// A typed view of all instances of one element kind. Invalid instances remain
/// in the report's raw `elements` array and are identified here by offset.
struct WiFiDecodedElementCollection<Value>: Codable, Hashable, Sendable
where Value: Codable & Hashable & Sendable {
  let advertisement: WiFiAdvertisementState
  let values: [Value]
  let invalidElementOffsets: [Int]
}

/// The lossless result of decoding a CoreWLAN information-element data blob.
/// Typed properties are derived deterministically from the ordered raw TLVs.
struct WiFiInformationElementReport: Codable, Hashable, Sendable {
  let rawData: Data
  let parseStatus: WiFiInformationElementParseStatus
  let parseIssue: WiFiInformationElementParseIssue?
  let elements: [WiFiInformationElement]
  let unparsedData: Data

  func elements(with identifier: UInt8) -> [WiFiInformationElement] {
    elements.filter { $0.identifier == identifier }
  }

  func elements(with identifier: WiFiInformationElementID) -> [WiFiInformationElement] {
    elements(with: identifier.rawValue)
  }

  var radioMeasurement: WiFiRadioMeasurementCapabilities {
    decodeRadioMeasurementCapabilities()
  }

  var bssTransitionManagement: WiFiBSSTransitionManagementCapabilities {
    decodeBSSTransitionManagement()
  }

  var fastTransition: WiFiFastTransitionCapabilities {
    decodeFastTransitionCapabilities()
  }

  var rsnElements: WiFiDecodedElementCollection<WiFiRSNInformation> {
    decodedCollection(for: .robustSecurityNetwork, decoder: decodeRSN)
  }

  var protectedManagementFrames: WiFiProtectedManagementFrames {
    decodeProtectedManagementFrames()
  }

  var countryInformation: WiFiDecodedElementCollection<WiFiCountryInformation> {
    decodedCollection(for: .country, decoder: decodeCountryInformation)
  }

  var apChannelReports: WiFiDecodedElementCollection<WiFiAPChannelReport> {
    decodedCollection(for: .apChannelReport, decoder: decodeAPChannelReport)
  }

  var bssLoads: WiFiDecodedElementCollection<WiFiBSSLoad> {
    decodedCollection(for: .bssLoad, decoder: decodeBSSLoad)
  }

  var trafficIndicationMaps: WiFiDecodedElementCollection<WiFiTrafficIndicationMap> {
    decodedCollection(for: .trafficIndicationMap, decoder: decodeTrafficIndicationMap)
  }

  var bssMaxIdlePeriods: WiFiDecodedElementCollection<WiFiBSSMaxIdlePeriod> {
    decodedCollection(for: .bssMaxIdlePeriod, decoder: decodeBSSMaxIdlePeriod)
  }

  var interworking: WiFiDecodedElementCollection<WiFiInterworkingInformation> {
    decodedCollection(for: .interworking, decoder: decodeInterworkingInformation)
  }

  var roamingConsortiums: WiFiDecodedElementCollection<WiFiRoamingConsortium> {
    decodedCollection(for: .roamingConsortium, decoder: decodeRoamingConsortium)
  }

  var reducedNeighborReports: WiFiDecodedElementCollection<WiFiReducedNeighborReport> {
    decodedCollection(for: .reducedNeighborReport, decoder: decodeReducedNeighborReport)
  }

  var multipleBSSIDs: WiFiDecodedElementCollection<WiFiMultipleBSSIDInformation> {
    decodedCollection(for: .multipleBSSID, decoder: decodeMultipleBSSIDInformation)
  }

  fileprivate init(
    rawData: Data,
    parseStatus: WiFiInformationElementParseStatus,
    parseIssue: WiFiInformationElementParseIssue?,
    elements: [WiFiInformationElement],
    unparsedData: Data
  ) {
    self.rawData = rawData
    self.parseStatus = parseStatus
    self.parseIssue = parseIssue
    self.elements = elements
    self.unparsedData = unparsedData
  }
}

/// The sole entry point for decoding a raw sequence of IEEE 802.11 information
/// elements, such as `CWNetwork.informationElementData`.
enum WiFiInformationElementDecoder {
  static func decode(_ data: Data) -> WiFiInformationElementReport {
    guard !data.isEmpty else {
      return WiFiInformationElementReport(
        rawData: data,
        parseStatus: .empty,
        parseIssue: nil,
        elements: [],
        unparsedData: data
      )
    }

    let bytes = [UInt8](data)
    var elements: [WiFiInformationElement] = []
    var offset = 0

    while offset < bytes.count {
      let headerBytesAvailable = bytes.count - offset
      guard headerBytesAvailable >= 2 else {
        return malformedReport(
          data: data,
          elements: elements,
          issue: WiFiInformationElementParseIssue(
            kind: .truncatedHeader,
            offset: offset,
            declaredPayloadLength: nil,
            availableByteCount: headerBytesAvailable
          )
        )
      }

      let identifier = bytes[offset]
      let payloadLength = Int(bytes[offset + 1])
      let payloadOffset = offset + 2
      let payloadBytesAvailable = bytes.count - payloadOffset
      guard payloadLength <= payloadBytesAvailable else {
        return malformedReport(
          data: data,
          elements: elements,
          issue: WiFiInformationElementParseIssue(
            kind: .truncatedPayload,
            offset: offset,
            declaredPayloadLength: payloadLength,
            availableByteCount: payloadBytesAvailable
          )
        )
      }

      let payloadEnd = payloadOffset + payloadLength
      elements.append(
        WiFiInformationElement(
          offset: offset,
          identifier: identifier,
          payload: Data(bytes[payloadOffset..<payloadEnd])
        )
      )
      offset = payloadEnd
    }

    return WiFiInformationElementReport(
      rawData: data,
      parseStatus: .complete,
      parseIssue: nil,
      elements: elements,
      unparsedData: Data()
    )
  }

  private static func malformedReport(
    data: Data,
    elements: [WiFiInformationElement],
    issue: WiFiInformationElementParseIssue
  ) -> WiFiInformationElementReport {
    let bytes = [UInt8](data)
    return WiFiInformationElementReport(
      rawData: data,
      parseStatus: .malformed,
      parseIssue: issue,
      elements: elements,
      unparsedData: Data(bytes[issue.offset..<bytes.count])
    )
  }
}

// MARK: - 802.11k Radio Measurement

/// The five-octet RM Enabled Capabilities element (Element ID 70). Boolean
/// fields use IEEE bit numbering, starting with bit 0 at the least-significant
/// bit of payload octet 0.
struct WiFiRadioMeasurementCapabilities: Codable, Hashable, Sendable {
  let advertisement: WiFiAdvertisementState
  let linkMeasurement: WiFiAdvertisementState  // bit 0
  let neighborReport: WiFiAdvertisementState  // bit 1
  let parallelMeasurements: WiFiAdvertisementState  // bit 2
  let repeatedMeasurements: WiFiAdvertisementState  // bit 3
  let passiveBeaconMeasurement: WiFiAdvertisementState  // bit 4
  let activeBeaconMeasurement: WiFiAdvertisementState  // bit 5
  let beaconTableMeasurement: WiFiAdvertisementState  // bit 6
  let beaconMeasurementReportingConditions: WiFiAdvertisementState  // bit 7
  let frameMeasurement: WiFiAdvertisementState  // bit 8
  let channelLoadMeasurement: WiFiAdvertisementState  // bit 9
  let noiseHistogramMeasurement: WiFiAdvertisementState  // bit 10
  let statisticsMeasurement: WiFiAdvertisementState  // bit 11
  let locationConfigurationInformationMeasurement: WiFiAdvertisementState  // bit 12
  let locationConfigurationInformationAzimuth: WiFiAdvertisementState  // bit 13
  let transmitStreamCategoryMeasurement: WiFiAdvertisementState  // bit 14
  let triggeredTransmitStreamCategoryMeasurement: WiFiAdvertisementState  // bit 15
  let apChannelReport: WiFiAdvertisementState  // bit 16
  let radioMeasurementMIB: WiFiAdvertisementState  // bit 17
  let operatingChannelMaxMeasurementDuration: UInt8?  // bits 18...20
  let nonoperatingChannelMaxMeasurementDuration: UInt8?  // bits 21...23
  let measurementPilotCapability: UInt8?  // bits 24...26
  let measurementPilotTransmissionInformation: WiFiAdvertisementState  // bit 27
  let neighborReportTSFOffset: WiFiAdvertisementState  // bit 28
  let receivedChannelPowerIndicatorMeasurement: WiFiAdvertisementState  // bit 29
  let receivedSignalToNoiseIndicatorMeasurement: WiFiAdvertisementState  // bit 30
  let bssAverageAccessDelay: WiFiAdvertisementState  // bit 31
  let bssAvailableAdmissionCapacity: WiFiAdvertisementState  // bit 32
  let antennaInformation: WiFiAdvertisementState  // bit 33
  let fineTimingMeasurementRangeReport: WiFiAdvertisementState  // bit 34
  let civicLocationMeasurement: WiFiAdvertisementState  // bit 35
  let rawCapabilities: [Data]
  let invalidElementOffsets: [Int]
}

// MARK: - 802.11v BSS Transition Management

struct WiFiBSSTransitionManagementCapabilities: Codable, Hashable, Sendable {
  /// Extended Capabilities element bit 19 (payload octet 2, mask 0x08).
  let advertisement: WiFiAdvertisementState
  let rawExtendedCapabilities: [Data]
  let invalidElementOffsets: [Int]
}

// MARK: - 802.11r Fast BSS Transition

struct WiFiMobilityDomainInformation: Codable, Hashable, Sendable {
  let sourceElementOffset: Int
  /// The two MDID octets in wire order. They are kept as bytes to avoid an
  /// artificial host-endian interpretation.
  let mobilityDomainIdentifier: Data
  let fastTransitionOverDS: Bool
  let resourceRequestProtocol: Bool
  let rawCapabilityAndPolicy: UInt8
}

struct WiFiFastTransitionCapabilities: Codable, Hashable, Sendable {
  let advertisement: WiFiAdvertisementState
  let mobilityDomainIdentifier: Data?
  let fastTransitionOverDS: WiFiAdvertisementState
  let resourceRequestProtocol: WiFiAdvertisementState
  let mobilityDomains: [WiFiMobilityDomainInformation]
  let invalidElementOffsets: [Int]
}

// MARK: - Robust Security Network and 802.11w

struct WiFiSuiteSelector: Codable, Hashable, Sendable {
  /// Three-octet OUI or CID in wire order.
  let organizationIdentifier: Data
  let suiteType: UInt8

  var rawValue: Data {
    var value = organizationIdentifier
    value.append(suiteType)
    return value
  }

  /// IEEE 802.11-defined selectors use 00-0F-AC.
  var isIEEE80211Selector: Bool {
    organizationIdentifier == Data([0x00, 0x0f, 0xac])
  }
}

struct WiFiRSNCapabilities: Codable, Hashable, Sendable {
  let rawValue: UInt16

  /// Management Frame Protection Required, RSN Capabilities bit 6.
  var managementFrameProtectionRequired: Bool { rawValue & 0x0040 != 0 }

  /// Management Frame Protection Capable, RSN Capabilities bit 7.
  var managementFrameProtectionCapable: Bool { rawValue & 0x0080 != 0 }
}

struct WiFiRSNInformation: Codable, Hashable, Sendable {
  let sourceElementOffset: Int
  let version: UInt16
  let groupDataCipherSuite: WiFiSuiteSelector?
  /// `nil` means the list was omitted, not that an explicit zero count was
  /// present. Explicit zero counts are rejected as malformed.
  let pairwiseCipherSuites: [WiFiSuiteSelector]?
  let authenticationKeyManagementSuites: [WiFiSuiteSelector]?
  let capabilities: WiFiRSNCapabilities?
  let pairwiseMasterKeyIdentifiers: [Data]?
  let groupManagementCipherSuite: WiFiSuiteSelector?
  let rawPayload: Data
}

enum WiFiProtectedManagementFramesMode: String, Codable, Hashable, Sendable {
  case required
  case capable
  case notAdvertised
  case unknown
}

struct WiFiProtectedManagementFrames: Codable, Hashable, Sendable {
  let advertisement: WiFiAdvertisementState
  let mode: WiFiProtectedManagementFramesMode
}

// MARK: - Other useful information elements

struct WiFiCountryInformation: Codable, Hashable, Sendable {
  let sourceElementOffset: Int
  let countryCode: Data
  let environment: UInt8
  /// Regulatory triplets and any standard padding byte are retained verbatim.
  let regulatoryData: Data
  let rawPayload: Data
}

struct WiFiAPChannelReport: Codable, Hashable, Sendable {
  let sourceElementOffset: Int
  let operatingClass: UInt8
  let channelNumbers: [UInt8]
  let rawPayload: Data
}

struct WiFiBSSLoad: Codable, Hashable, Sendable {
  let sourceElementOffset: Int
  let stationCount: UInt16
  let channelUtilization: UInt8
  let availableAdmissionCapacity: UInt16
  let rawPayload: Data
}

struct WiFiTrafficIndicationMap: Codable, Hashable, Sendable {
  let sourceElementOffset: Int
  let dtimCount: UInt8
  let dtimPeriod: UInt8
  let bitmapControl: UInt8
  let partialVirtualBitmap: Data
  let rawPayload: Data
}

struct WiFiBSSMaxIdlePeriod: Codable, Hashable, Sendable {
  let sourceElementOffset: Int
  /// Maximum idle period in units of 1,000 time units (TUs).
  let maximumIdlePeriod: UInt16
  let protectedKeepAliveRequired: Bool
  let rawIdleOptions: UInt8
  let rawPayload: Data
}

struct WiFiInterworkingInformation: Codable, Hashable, Sendable {
  let sourceElementOffset: Int
  let accessNetworkType: UInt8
  let internetAvailable: Bool
  let additionalStepRequiredForAccess: Bool
  let emergencyServicesReachable: Bool
  let unauthenticatedEmergencyServiceAccessible: Bool
  let venueGroup: UInt8?
  let venueType: UInt8?
  let homogeneousExtendedServiceSetIdentifier: Data?
  let rawPayload: Data
}

struct WiFiRoamingConsortium: Codable, Hashable, Sendable {
  let sourceElementOffset: Int
  let anqpOrganizationIdentifierCount: UInt8
  let organizationIdentifiers: [Data]
  let rawPayload: Data
}

struct WiFiReducedNeighborAccessPointInformation: Codable, Hashable, Sendable {
  let offsetInElementPayload: Int
  let tbttInformationFieldType: UInt8
  let filteredNeighborAccessPoint: Bool
  let rawTBTTInformationHeader: UInt8
  let operatingClass: UInt8
  let channelNumber: UInt8
  let tbttInformationLength: UInt8
  let tbttInformationSets: [Data]
}

struct WiFiReducedNeighborReport: Codable, Hashable, Sendable {
  let sourceElementOffset: Int
  let neighborAccessPoints: [WiFiReducedNeighborAccessPointInformation]
  let rawPayload: Data
}

struct WiFiInformationSubelement: Codable, Hashable, Sendable {
  let offsetInElementPayload: Int
  let identifier: UInt8
  let payload: Data
}

struct WiFiMultipleBSSIDInformation: Codable, Hashable, Sendable {
  let sourceElementOffset: Int
  let maximumBSSIDIndicator: UInt8
  let subelements: [WiFiInformationSubelement]
  let rawPayload: Data
}

// MARK: - Typed derivation

extension WiFiInformationElementReport {
  fileprivate var canInferAbsence: Bool { parseStatus == .complete }

  fileprivate func decodedCollection<Value>(
    for identifier: WiFiInformationElementID,
    decoder: (WiFiInformationElement) -> Value?
  ) -> WiFiDecodedElementCollection<Value>
  where Value: Codable & Hashable & Sendable {
    let rawElements = elements(with: identifier)
    var values: [Value] = []
    var invalidOffsets: [Int] = []
    for element in rawElements {
      if let value = decoder(element) {
        values.append(value)
      } else {
        invalidOffsets.append(element.offset)
      }
    }

    let advertisement: WiFiAdvertisementState
    if !invalidOffsets.isEmpty {
      advertisement = .unknown
    } else if !values.isEmpty {
      // A syntactically valid target element is positive evidence even when
      // an unrelated, later TLV makes the overall stream malformed.
      advertisement = .advertised
    } else {
      advertisement = canInferAbsence ? .notAdvertised : .unknown
    }

    return WiFiDecodedElementCollection(
      advertisement: advertisement,
      values: values,
      invalidElementOffsets: invalidOffsets
    )
  }

  fileprivate func decodeRadioMeasurementCapabilities() -> WiFiRadioMeasurementCapabilities {
    let rawElements = elements(with: .radioMeasurementEnabledCapabilities)
    let validElements = rawElements.filter { $0.payload.count == 5 }
    let invalidOffsets = rawElements.filter { $0.payload.count != 5 }.map(\.offset)
    let rawCapabilities = rawElements.map(\.payload)

    let rawValuesAreConsistent = Set(validElements.map(\.payload)).count <= 1
    let advertisement: WiFiAdvertisementState
    if !invalidOffsets.isEmpty || !rawValuesAreConsistent {
      advertisement = .unknown
    } else if !validElements.isEmpty {
      advertisement = .advertised
    } else {
      advertisement = canInferAbsence ? .notAdvertised : .unknown
    }

    func bit(_ index: Int) -> WiFiAdvertisementState {
      guard invalidOffsets.isEmpty, rawValuesAreConsistent else { return .unknown }
      guard !validElements.isEmpty else {
        return canInferAbsence ? .notAdvertised : .unknown
      }
      let observations = Set(validElements.map { capabilityBit(index, in: $0.payload) })
      guard observations.count == 1, let value = observations.first else { return .unknown }
      return value ? .advertised : .notAdvertised
    }

    func field(_ range: ClosedRange<Int>) -> UInt8? {
      guard invalidOffsets.isEmpty, rawValuesAreConsistent, !validElements.isEmpty else {
        return nil
      }
      let values = Set(validElements.map { capabilityField(range, in: $0.payload) })
      return values.count == 1 ? values.first : nil
    }

    return WiFiRadioMeasurementCapabilities(
      advertisement: advertisement,
      linkMeasurement: bit(0),
      neighborReport: bit(1),
      parallelMeasurements: bit(2),
      repeatedMeasurements: bit(3),
      passiveBeaconMeasurement: bit(4),
      activeBeaconMeasurement: bit(5),
      beaconTableMeasurement: bit(6),
      beaconMeasurementReportingConditions: bit(7),
      frameMeasurement: bit(8),
      channelLoadMeasurement: bit(9),
      noiseHistogramMeasurement: bit(10),
      statisticsMeasurement: bit(11),
      locationConfigurationInformationMeasurement: bit(12),
      locationConfigurationInformationAzimuth: bit(13),
      transmitStreamCategoryMeasurement: bit(14),
      triggeredTransmitStreamCategoryMeasurement: bit(15),
      apChannelReport: bit(16),
      radioMeasurementMIB: bit(17),
      operatingChannelMaxMeasurementDuration: field(18...20),
      nonoperatingChannelMaxMeasurementDuration: field(21...23),
      measurementPilotCapability: field(24...26),
      measurementPilotTransmissionInformation: bit(27),
      neighborReportTSFOffset: bit(28),
      receivedChannelPowerIndicatorMeasurement: bit(29),
      receivedSignalToNoiseIndicatorMeasurement: bit(30),
      bssAverageAccessDelay: bit(31),
      bssAvailableAdmissionCapacity: bit(32),
      antennaInformation: bit(33),
      fineTimingMeasurementRangeReport: bit(34),
      civicLocationMeasurement: bit(35),
      rawCapabilities: rawCapabilities,
      invalidElementOffsets: invalidOffsets
    )
  }

  fileprivate func decodeBSSTransitionManagement() -> WiFiBSSTransitionManagementCapabilities {
    let rawElements = elements(with: .extendedCapabilities)
    // Extended Capabilities may omit trailing zero octets. A payload shorter
    // than three octets therefore advertises bit 19 as clear; it is not a
    // malformed element.
    let invalidOffsets: [Int] = []

    let advertisement: WiFiAdvertisementState
    if !rawElements.isEmpty {
      let observations = Set(rawElements.map { capabilityBit(19, in: $0.payload) })
      if observations.count == 1, let value = observations.first {
        advertisement = value ? .advertised : .notAdvertised
      } else {
        advertisement = .unknown
      }
    } else {
      advertisement = canInferAbsence ? .notAdvertised : .unknown
    }

    return WiFiBSSTransitionManagementCapabilities(
      advertisement: advertisement,
      rawExtendedCapabilities: rawElements.map(\.payload),
      invalidElementOffsets: invalidOffsets
    )
  }

  fileprivate func decodeFastTransitionCapabilities() -> WiFiFastTransitionCapabilities {
    let rawElements = elements(with: .mobilityDomain)
    let invalidOffsets = rawElements.filter { $0.payload.count != 3 }.map(\.offset)
    let mobilityDomains = rawElements.compactMap(decodeMobilityDomain)
    let consistent =
      Set(mobilityDomains.map { $0.mobilityDomainIdentifier + Data([$0.rawCapabilityAndPolicy]) })
      .count <= 1

    let advertisement: WiFiAdvertisementState
    if !invalidOffsets.isEmpty || !consistent {
      advertisement = .unknown
    } else if !mobilityDomains.isEmpty {
      advertisement = .advertised
    } else {
      advertisement = canInferAbsence ? .notAdvertised : .unknown
    }

    func state(_ value: (WiFiMobilityDomainInformation) -> Bool) -> WiFiAdvertisementState {
      guard invalidOffsets.isEmpty, consistent else { return .unknown }
      guard !mobilityDomains.isEmpty else {
        return canInferAbsence ? .notAdvertised : .unknown
      }
      let observations = Set(mobilityDomains.map(value))
      guard observations.count == 1, let observation = observations.first else { return .unknown }
      return observation ? .advertised : .notAdvertised
    }

    let identifiers = Set(mobilityDomains.map(\.mobilityDomainIdentifier))
    let identifier =
      invalidOffsets.isEmpty && consistent && identifiers.count == 1
      ? identifiers.first
      : nil

    return WiFiFastTransitionCapabilities(
      advertisement: advertisement,
      mobilityDomainIdentifier: identifier,
      fastTransitionOverDS: state(\.fastTransitionOverDS),
      resourceRequestProtocol: state(\.resourceRequestProtocol),
      mobilityDomains: mobilityDomains,
      invalidElementOffsets: invalidOffsets
    )
  }

  fileprivate func decodeProtectedManagementFrames() -> WiFiProtectedManagementFrames {
    let decoded = rsnElements
    guard decoded.invalidElementOffsets.isEmpty else {
      return WiFiProtectedManagementFrames(advertisement: .unknown, mode: .unknown)
    }
    guard !decoded.values.isEmpty else {
      let mode: WiFiProtectedManagementFramesMode =
        decoded.advertisement == .notAdvertised ? .notAdvertised : .unknown
      return WiFiProtectedManagementFrames(
        advertisement: decoded.advertisement,
        mode: mode
      )
    }

    let modes = Set(
      decoded.values.map { information -> WiFiProtectedManagementFramesMode in
        // RSN Capabilities is an optional trailing field. When omitted, every
        // capability bit has its specified default value of zero.
        let capabilities = information.capabilities ?? WiFiRSNCapabilities(rawValue: 0)
        let required = capabilities.managementFrameProtectionRequired
        let capable = capabilities.managementFrameProtectionCapable
        switch (capable, required) {
        case (true, true): return .required
        case (true, false): return .capable
        case (false, false): return .notAdvertised
        case (false, true): return .unknown
        }
      })

    guard modes.count == 1, let mode = modes.first, mode != .unknown else {
      return WiFiProtectedManagementFrames(advertisement: .unknown, mode: .unknown)
    }
    let advertisement: WiFiAdvertisementState =
      mode == .notAdvertised
      ? .notAdvertised
      : .advertised
    return WiFiProtectedManagementFrames(advertisement: advertisement, mode: mode)
  }
}

// MARK: - Element decoders

private func decodeMobilityDomain(
  _ element: WiFiInformationElement
) -> WiFiMobilityDomainInformation? {
  let bytes = [UInt8](element.payload)
  guard bytes.count == 3 else { return nil }
  return WiFiMobilityDomainInformation(
    sourceElementOffset: element.offset,
    mobilityDomainIdentifier: Data(bytes[0...1]),
    fastTransitionOverDS: bytes[2] & 0x01 != 0,
    resourceRequestProtocol: bytes[2] & 0x02 != 0,
    rawCapabilityAndPolicy: bytes[2]
  )
}

private func decodeRSN(_ element: WiFiInformationElement) -> WiFiRSNInformation? {
  var cursor = WiFiByteCursor(element.payload)
  guard let version = cursor.readUInt16LittleEndian(), version == 1 else { return nil }

  var groupDataCipherSuite: WiFiSuiteSelector?
  var pairwiseCipherSuites: [WiFiSuiteSelector]?
  var authenticationKeyManagementSuites: [WiFiSuiteSelector]?
  var capabilities: WiFiRSNCapabilities?
  var pairwiseMasterKeyIdentifiers: [Data]?
  var groupManagementCipherSuite: WiFiSuiteSelector?

  if cursor.hasRemainingBytes {
    guard let selector = cursor.readSuiteSelector() else { return nil }
    groupDataCipherSuite = selector
  }
  if cursor.hasRemainingBytes {
    guard let count = cursor.readUInt16LittleEndian(), count > 0,
      let selectors = cursor.readSuiteSelectors(count: Int(count))
    else { return nil }
    pairwiseCipherSuites = selectors
  }
  if cursor.hasRemainingBytes {
    guard let count = cursor.readUInt16LittleEndian(), count > 0,
      let selectors = cursor.readSuiteSelectors(count: Int(count))
    else { return nil }
    authenticationKeyManagementSuites = selectors
  }
  if cursor.hasRemainingBytes {
    guard let rawCapabilities = cursor.readUInt16LittleEndian() else { return nil }
    capabilities = WiFiRSNCapabilities(rawValue: rawCapabilities)
  }
  if cursor.hasRemainingBytes {
    guard let count = cursor.readUInt16LittleEndian(),
      let identifiers = cursor.readDataValues(count: Int(count), width: 16)
    else { return nil }
    pairwiseMasterKeyIdentifiers = identifiers
  }
  if cursor.hasRemainingBytes {
    guard let selector = cursor.readSuiteSelector() else { return nil }
    groupManagementCipherSuite = selector
  }
  guard !cursor.hasRemainingBytes else { return nil }

  return WiFiRSNInformation(
    sourceElementOffset: element.offset,
    version: version,
    groupDataCipherSuite: groupDataCipherSuite,
    pairwiseCipherSuites: pairwiseCipherSuites,
    authenticationKeyManagementSuites: authenticationKeyManagementSuites,
    capabilities: capabilities,
    pairwiseMasterKeyIdentifiers: pairwiseMasterKeyIdentifiers,
    groupManagementCipherSuite: groupManagementCipherSuite,
    rawPayload: element.payload
  )
}

private func decodeCountryInformation(
  _ element: WiFiInformationElement
) -> WiFiCountryInformation? {
  let bytes = [UInt8](element.payload)
  guard bytes.count >= 3 else { return nil }
  return WiFiCountryInformation(
    sourceElementOffset: element.offset,
    countryCode: Data(bytes[0..<2]),
    environment: bytes[2],
    regulatoryData: Data(bytes.dropFirst(3)),
    rawPayload: element.payload
  )
}

private func decodeAPChannelReport(
  _ element: WiFiInformationElement
) -> WiFiAPChannelReport? {
  let bytes = [UInt8](element.payload)
  guard let operatingClass = bytes.first else { return nil }
  return WiFiAPChannelReport(
    sourceElementOffset: element.offset,
    operatingClass: operatingClass,
    channelNumbers: Array(bytes.dropFirst()),
    rawPayload: element.payload
  )
}

private func decodeBSSLoad(_ element: WiFiInformationElement) -> WiFiBSSLoad? {
  let bytes = [UInt8](element.payload)
  guard bytes.count == 5 else { return nil }
  return WiFiBSSLoad(
    sourceElementOffset: element.offset,
    stationCount: littleEndianUInt16(bytes[0], bytes[1]),
    channelUtilization: bytes[2],
    availableAdmissionCapacity: littleEndianUInt16(bytes[3], bytes[4]),
    rawPayload: element.payload
  )
}

private func decodeTrafficIndicationMap(
  _ element: WiFiInformationElement
) -> WiFiTrafficIndicationMap? {
  let bytes = [UInt8](element.payload)
  guard bytes.count >= 4 else { return nil }
  return WiFiTrafficIndicationMap(
    sourceElementOffset: element.offset,
    dtimCount: bytes[0],
    dtimPeriod: bytes[1],
    bitmapControl: bytes[2],
    partialVirtualBitmap: Data(bytes.dropFirst(3)),
    rawPayload: element.payload
  )
}

private func decodeBSSMaxIdlePeriod(
  _ element: WiFiInformationElement
) -> WiFiBSSMaxIdlePeriod? {
  let bytes = [UInt8](element.payload)
  guard bytes.count == 3 else { return nil }
  return WiFiBSSMaxIdlePeriod(
    sourceElementOffset: element.offset,
    maximumIdlePeriod: littleEndianUInt16(bytes[0], bytes[1]),
    protectedKeepAliveRequired: bytes[2] & 0x01 != 0,
    rawIdleOptions: bytes[2],
    rawPayload: element.payload
  )
}

private func decodeInterworkingInformation(
  _ element: WiFiInformationElement
) -> WiFiInterworkingInformation? {
  let bytes = [UInt8](element.payload)
  guard [1, 3, 7, 9].contains(bytes.count), let options = bytes.first else { return nil }

  let venueIsPresent = bytes.count == 3 || bytes.count == 9
  let hessidIsPresent = bytes.count == 7 || bytes.count == 9
  let venueGroup = venueIsPresent ? bytes[1] : nil
  let venueType = venueIsPresent ? bytes[2] : nil
  let hessidOffset = venueIsPresent ? 3 : 1
  let hessid =
    hessidIsPresent
    ? Data(bytes[hessidOffset..<(hessidOffset + 6)])
    : nil

  return WiFiInterworkingInformation(
    sourceElementOffset: element.offset,
    accessNetworkType: options & 0x0f,
    internetAvailable: options & 0x10 != 0,
    additionalStepRequiredForAccess: options & 0x20 != 0,
    emergencyServicesReachable: options & 0x40 != 0,
    unauthenticatedEmergencyServiceAccessible: options & 0x80 != 0,
    venueGroup: venueGroup,
    venueType: venueType,
    homogeneousExtendedServiceSetIdentifier: hessid,
    rawPayload: element.payload
  )
}

private func decodeRoamingConsortium(
  _ element: WiFiInformationElement
) -> WiFiRoamingConsortium? {
  let bytes = [UInt8](element.payload)
  guard bytes.count >= 2 else { return nil }
  let firstLength = Int(bytes[1] & 0x0f)
  let secondLength = Int(bytes[1] >> 4)
  let organizationBytes = bytes.count - 2
  guard firstLength + secondLength <= organizationBytes else { return nil }

  var cursor = 2
  var identifiers: [Data] = []
  if firstLength > 0 {
    identifiers.append(Data(bytes[cursor..<(cursor + firstLength)]))
    cursor += firstLength
  }
  if secondLength > 0 {
    identifiers.append(Data(bytes[cursor..<(cursor + secondLength)]))
    cursor += secondLength
  }
  if cursor < bytes.count {
    identifiers.append(Data(bytes[cursor..<bytes.count]))
  }

  return WiFiRoamingConsortium(
    sourceElementOffset: element.offset,
    anqpOrganizationIdentifierCount: bytes[0],
    organizationIdentifiers: identifiers,
    rawPayload: element.payload
  )
}

private func decodeReducedNeighborReport(
  _ element: WiFiInformationElement
) -> WiFiReducedNeighborReport? {
  let bytes = [UInt8](element.payload)
  guard !bytes.isEmpty else { return nil }
  var offset = 0
  var neighbors: [WiFiReducedNeighborAccessPointInformation] = []

  while offset < bytes.count {
    guard bytes.count - offset >= 4 else { return nil }
    let header = bytes[offset]
    let informationLength = Int(bytes[offset + 1])
    let count = Int(header >> 4) + 1
    guard informationLength > 0, count <= (bytes.count - offset - 4) / informationLength else {
      return nil
    }

    var informationSets: [Data] = []
    var informationOffset = offset + 4
    for _ in 0..<count {
      let informationEnd = informationOffset + informationLength
      informationSets.append(Data(bytes[informationOffset..<informationEnd]))
      informationOffset = informationEnd
    }

    neighbors.append(
      WiFiReducedNeighborAccessPointInformation(
        offsetInElementPayload: offset,
        tbttInformationFieldType: header & 0x03,
        filteredNeighborAccessPoint: header & 0x04 != 0,
        rawTBTTInformationHeader: header,
        operatingClass: bytes[offset + 2],
        channelNumber: bytes[offset + 3],
        tbttInformationLength: UInt8(informationLength),
        tbttInformationSets: informationSets
      )
    )
    offset = informationOffset
  }

  return WiFiReducedNeighborReport(
    sourceElementOffset: element.offset,
    neighborAccessPoints: neighbors,
    rawPayload: element.payload
  )
}

private func decodeMultipleBSSIDInformation(
  _ element: WiFiInformationElement
) -> WiFiMultipleBSSIDInformation? {
  let bytes = [UInt8](element.payload)
  guard let indicator = bytes.first, (1...8).contains(indicator) else { return nil }
  var offset = 1
  var subelements: [WiFiInformationSubelement] = []

  while offset < bytes.count {
    guard bytes.count - offset >= 2 else { return nil }
    let identifier = bytes[offset]
    let length = Int(bytes[offset + 1])
    let payloadOffset = offset + 2
    guard length <= bytes.count - payloadOffset else { return nil }
    let end = payloadOffset + length
    subelements.append(
      WiFiInformationSubelement(
        offsetInElementPayload: offset,
        identifier: identifier,
        payload: Data(bytes[payloadOffset..<end])
      )
    )
    offset = end
  }

  return WiFiMultipleBSSIDInformation(
    sourceElementOffset: element.offset,
    maximumBSSIDIndicator: indicator,
    subelements: subelements,
    rawPayload: element.payload
  )
}

// MARK: - Byte utilities

private struct WiFiByteCursor {
  private let bytes: [UInt8]
  private(set) var offset = 0

  init(_ data: Data) {
    bytes = [UInt8](data)
  }

  var remainingByteCount: Int { bytes.count - offset }
  var hasRemainingBytes: Bool { remainingByteCount > 0 }

  mutating func readUInt16LittleEndian() -> UInt16? {
    guard remainingByteCount >= 2 else { return nil }
    let value = littleEndianUInt16(bytes[offset], bytes[offset + 1])
    offset += 2
    return value
  }

  mutating func readData(count: Int) -> Data? {
    guard count >= 0, count <= remainingByteCount else { return nil }
    let end = offset + count
    let value = Data(bytes[offset..<end])
    offset = end
    return value
  }

  mutating func readSuiteSelector() -> WiFiSuiteSelector? {
    guard let value = readData(count: 4) else { return nil }
    let bytes = [UInt8](value)
    return WiFiSuiteSelector(
      organizationIdentifier: Data(bytes[0..<3]),
      suiteType: bytes[3]
    )
  }

  mutating func readSuiteSelectors(count: Int) -> [WiFiSuiteSelector]? {
    guard count >= 0, count <= remainingByteCount / 4 else { return nil }
    var values: [WiFiSuiteSelector] = []
    values.reserveCapacity(count)
    for _ in 0..<count {
      guard let value = readSuiteSelector() else { return nil }
      values.append(value)
    }
    return values
  }

  mutating func readDataValues(count: Int, width: Int) -> [Data]? {
    guard count >= 0, width > 0, count <= remainingByteCount / width else { return nil }
    var values: [Data] = []
    values.reserveCapacity(count)
    for _ in 0..<count {
      guard let value = readData(count: width) else { return nil }
      values.append(value)
    }
    return values
  }
}

private func capabilityBit(_ bit: Int, in data: Data) -> Bool {
  guard bit >= 0 else { return false }
  let bytes = [UInt8](data)
  let byteIndex = bit / 8
  guard byteIndex < bytes.count else { return false }
  return bytes[byteIndex] & UInt8(1 << (bit % 8)) != 0
}

private func capabilityField(_ range: ClosedRange<Int>, in data: Data) -> UInt8 {
  precondition(range.lowerBound >= 0 && range.count <= 8)
  var value: UInt8 = 0
  for (destinationBit, sourceBit) in range.enumerated() where capabilityBit(sourceBit, in: data) {
    value |= UInt8(1 << destinationBit)
  }
  return value
}

private func littleEndianUInt16(_ low: UInt8, _ high: UInt8) -> UInt16 {
  UInt16(low) | UInt16(high) << 8
}
