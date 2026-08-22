// SPDX-License-Identifier: GPL-3.0-only

import Foundation

enum ScanInformationElementPresenter {
  static func name(for element: WiFiInformationElement) -> String {
    guard let identifier = element.knownIdentifier else {
      return standardName(forRawIdentifier: element.identifier)
        ?? "Unknown Element (ID \(element.identifier))"
    }
    switch identifier {
    case .trafficIndicationMap: return "Traffic Indication Map (TIM)"
    case .country: return "Country"
    case .bssLoad: return "BSS Load"
    case .robustSecurityNetwork: return "Robust Security Network (RSN)"
    case .apChannelReport: return "AP Channel Report"
    case .mobilityDomain: return "Mobility Domain (802.11r)"
    case .radioMeasurementEnabledCapabilities:
      return "RM Enabled Capabilities (802.11k)"
    case .multipleBSSID: return "Multiple BSSID"
    case .bssMaxIdlePeriod: return "BSS Max Idle Period"
    case .interworking: return "Interworking"
    case .advertisementProtocol: return "Advertisement Protocol"
    case .roamingConsortium: return "Roaming Consortium"
    case .extendedCapabilities: return "Extended Capabilities"
    case .reducedNeighborReport: return "Reduced Neighbor Report"
    case .vendorSpecific: return "Vendor Specific"
    case .elementIDExtension:
      guard let extensionID = element.payload.first else { return "Element ID Extension" }
      return extensionName(extensionID) ?? "Element ID Extension \(extensionID)"
    }
  }

  private static func standardName(forRawIdentifier identifier: UInt8) -> String? {
    switch identifier {
    case 0: return "Service Set Identifier (SSID)"
    case 1: return "Supported Rates"
    case 2: return "FH Parameter Set"
    case 3: return "DSSS Parameter Set"
    case 4: return "CF Parameter Set"
    case 6: return "IBSS Parameter Set"
    case 8: return "Hopping Pattern Parameters"
    case 9: return "Hopping Pattern Table"
    case 10: return "Request"
    case 12: return "EDCA Parameter Set"
    case 13: return "Traffic Specification (TSPEC)"
    case 14: return "Traffic Classification (TCLAS)"
    case 15: return "Schedule"
    case 16: return "Challenge Text"
    case 32: return "Power Constraint"
    case 33: return "Power Capability"
    case 34: return "Transmit Power Control Request"
    case 35: return "Transmit Power Control Report"
    case 36: return "Supported Channels"
    case 37: return "Channel Switch Announcement"
    case 38: return "Measurement Request"
    case 39: return "Measurement Report"
    case 40: return "Quiet"
    case 41: return "IBSS Dynamic Frequency Selection"
    case 42: return "ERP Information"
    case 43: return "Traffic Stream Delay"
    case 44: return "Traffic Classification Processing"
    case 45: return "HT Capabilities"
    case 46: return "QoS Capability"
    case 47: return "Reserved / Vendor Element"
    case 49: return "802.15 Coexistence"
    case 50: return "Extended Supported Rates"
    case 52: return "Neighbor Report"
    case 53: return "Received Channel Power Indicator"
    case 55: return "Fast BSS Transition"
    case 56: return "Timeout Interval"
    case 57: return "Resource Information Container Data"
    case 58: return "DSE Registered Location"
    case 59: return "Supported Operating Classes"
    case 60: return "Extended Channel Switch Announcement"
    case 61: return "HT Operation"
    case 62: return "Secondary Channel Offset"
    case 63: return "BSS Average Access Delay"
    case 64: return "Antenna Information"
    case 65: return "Received Signal-to-Noise Indicator"
    case 66: return "Measurement Pilot Transmission Information"
    case 67: return "BSS Available Admission Capacity"
    case 68: return "BSS AC Access Delay"
    case 69: return "Time Advertisement"
    case 72: return "20/40 BSS Coexistence"
    case 73: return "20/40 Intolerant Channel Report"
    case 74: return "Overlapping BSS Scan Parameters"
    case 75: return "Resource Information Container Descriptor"
    case 76: return "Management MIC"
    case 77: return "Association Comeback Time"
    case 78: return "Event Request"
    case 79: return "Event Report"
    case 80: return "Diagnostic Request"
    case 81: return "Diagnostic Report"
    case 82: return "Location Parameters"
    case 83: return "Nontransmitted BSSID Capability"
    case 84: return "SSID List"
    case 85: return "Multiple BSSID Index"
    case 86: return "FMS Descriptor"
    case 87: return "FMS Request"
    case 88: return "FMS Response"
    case 89: return "QoS Traffic Capability"
    case 91: return "Timing Synchronization Function Request"
    case 92: return "Timing Synchronization Function Response"
    case 93: return "WNM Sleep Mode"
    case 94: return "TIM Broadcast Request"
    case 95: return "TIM Broadcast Response"
    case 96: return "Collocated Interference Report"
    case 97: return "Channel Usage"
    case 98: return "Time Zone"
    case 99: return "Directed Multicast Service Request"
    case 100: return "Directed Multicast Service Response"
    case 101: return "Link Identifier"
    case 102: return "Wakeup Schedule"
    case 104: return "Channel Switch Timing"
    case 105: return "Peer Traffic Indication Control"
    case 106: return "Peer Traffic Indication Buffer Status"
    case 109: return "Expedited Bandwidth Request"
    case 110: return "QoS Map Set"
    case 112: return "Emergency Alert Identifier"
    case 113: return "Mesh Configuration"
    case 114: return "Mesh Identifier"
    case 115: return "Mesh Link Metric Report"
    case 116: return "Congestion Notification"
    case 117: return "Mesh Peering Management"
    case 118: return "Mesh Channel Switch Parameters"
    case 119: return "Mesh Awake Window"
    case 120: return "Beacon Timing"
    case 121: return "MCCAOP Setup Request"
    case 122: return "MCCAOP Setup Response"
    case 123: return "MCCAOP Advertisement"
    case 124: return "MCCAOP Teardown"
    case 125: return "Gate Announcement"
    case 126: return "Root Announcement"
    case 130: return "Path Request"
    case 131: return "Path Reply"
    case 132: return "Path Error"
    case 191: return "VHT Capabilities"
    case 192: return "VHT Operation"
    case 193: return "Extended BSS Load"
    case 194: return "Wide Bandwidth Channel Switch"
    case 195: return "Transmit Power Envelope"
    case 196: return "Channel Switch Wrapper"
    case 197: return "Association Identifier (AID)"
    case 198: return "Quiet Channel"
    case 199: return "Operating Mode Notification"
    case 202: return "TVHT Operation"
    case 210: return "Association Identifier Request"
    case 211: return "Association Identifier Response"
    case 213: return "S1G Beacon Compatibility"
    case 214: return "S1G Short Beacon Interval"
    case 216: return "Target Wake Time"
    case 217: return "S1G Capabilities"
    case 222: return "QoS Parameter"
    case 232: return "S1G Operation"
    case 237: return "Change Sequence Number"
    case 239: return "AP Configuration Sequence Number"
    case 240: return "FILS Indication"
    case 241: return "DILS"
    case 242: return "Fragment"
    case 244: return "RSN Extension (RSNXE)"
    default: return nil
    }
  }

  private static func extensionName(_ identifier: UInt8) -> String? {
    switch identifier {
    case 1: return "Association Delay Information"
    case 2: return "FILS Request Parameters"
    case 3: return "FILS Key Confirmation"
    case 4: return "FILS Session"
    case 5: return "FILS HLP Container"
    case 6: return "FILS IP Address Assignment"
    case 7: return "Key Delivery"
    case 8: return "FILS Wrapped Data"
    case 12: return "FILS Public Key"
    case 13: return "FILS Nonce"
    case 14: return "Future Channel Guidance"
    case 32: return "Diffie-Hellman Parameter"
    case 35: return "HE Capabilities"
    case 36: return "HE Operation"
    case 37: return "UORA Parameter Set"
    case 38: return "HE MU EDCA Parameter Set"
    case 39: return "HE Spatial Reuse Parameter Set"
    case 41: return "NDP Feedback Report Parameter Set"
    case 42: return "BSS Color Change Announcement"
    case 43: return "Quiet Time Period Setup"
    case 45: return "ESS Report"
    case 46: return "OPS"
    case 47: return "HE BSS Load"
    case 52: return "Maximum Channel Switch Time"
    case 55: return "Multiple BSSID Configuration"
    case 56: return "Non-Inheritance"
    case 57: return "Known BSSID"
    case 58: return "Short SSID List"
    case 59: return "HE 6 GHz Band Capabilities"
    case 60: return "Uplink MU Power Capabilities"
    case 106: return "EHT Operation"
    case 107: return "Multi-Link"
    case 108: return "EHT Capabilities"
    case 109: return "TID-to-Link Mapping"
    case 135: return "Bandwidth Indication"
    case 136: return "Known STA Identification"
    case 137: return "Non-AP STA Regulatory Connectivity"
    default: return nil
    }
  }

  static func parseStatus(_ report: WiFiInformationElementReport) -> String {
    switch report.parseStatus {
    case .complete:
      return "Complete — \(report.elements.count) elements, \(report.rawData.count) bytes"
    case .empty:
      return "Empty"
    case .malformed:
      return "Malformed — \(parseIssueSummary(report.parseIssue))"
    }
  }

  static func parseIssueSummary(_ issue: WiFiInformationElementParseIssue?) -> String {
    guard let issue else { return "Unknown parse error" }
    switch issue.kind {
    case .truncatedHeader:
      return
        "Truncated element header at byte \(issue.offset); \(issue.availableByteCount) byte(s) remain"
    case .truncatedPayload:
      return
        "Truncated payload at byte \(issue.offset); declared \(issue.declaredPayloadLength ?? 0) bytes, \(issue.availableByteCount) available"
    }
  }

  static func summary(
    for element: WiFiInformationElement,
    report: WiFiInformationElementReport
  ) -> String {
    guard let identifier = element.knownIdentifier else {
      return standardSummary(for: element) ?? payloadPreview(element.payload)
    }
    switch identifier {
    case .trafficIndicationMap:
      let trafficIndicationMaps = report.trafficIndicationMaps
      guard
        let value = trafficIndicationMaps.values.first(where: {
          $0.sourceElementOffset == element.offset
        })
      else { return invalidSummary(trafficIndicationMaps.invalidElementOffsets, element) }
      return
        "DTIM count \(value.dtimCount); DTIM period \(value.dtimPeriod); bitmap control 0x\(String(format: "%02X", value.bitmapControl)); partial virtual bitmap \(value.partialVirtualBitmap.count) bytes"
    case .country:
      let countryInformation = report.countryInformation
      guard
        let value = countryInformation.values.first(where: {
          $0.sourceElementOffset == element.offset
        })
      else { return invalidSummary(countryInformation.invalidElementOffsets, element) }
      var regulatoryBytes = [UInt8](value.regulatoryData)
      let hasPadding = regulatoryBytes.count % 3 == 1 && regulatoryBytes.last == 0
      if hasPadding { regulatoryBytes.removeLast() }
      let tripletByteCount = regulatoryBytes.count - regulatoryBytes.count % 3
      let regulatoryTriplets = stride(from: 0, to: tripletByteCount, by: 3).map { offset in
        ScanFormatting.compactHex(Data(regulatoryBytes[offset..<(offset + 3)]))
      }.joined(separator: ", ")
      let trailingBytes = Data(regulatoryBytes.dropFirst(tripletByteCount))
      let paddingSummary = hasPadding ? "; padding 0x00" : ""
      let trailingSummary =
        trailingBytes.isEmpty
        ? "" : "; trailing regulatory bytes \(ScanFormatting.compactHex(trailingBytes))"
      return
        "Country \(asciiOrHex(value.countryCode)); environment \(printableByte(value.environment)); regulatory triplets \(regulatoryTriplets.isEmpty ? "none" : regulatoryTriplets)\(paddingSummary)\(trailingSummary)"
    case .bssLoad:
      let bssLoads = report.bssLoads
      guard
        let value = bssLoads.values.first(where: {
          $0.sourceElementOffset == element.offset
        })
      else { return invalidSummary(bssLoads.invalidElementOffsets, element) }
      let utilization = Double(value.channelUtilization) / 255.0 * 100.0
      return
        "Stations \(value.stationCount); channel utilization \(String(format: "%.1f", utilization))%; available admission capacity \(value.availableAdmissionCapacity)"
    case .robustSecurityNetwork:
      let rsnElements = report.rsnElements
      guard
        let value = rsnElements.values.first(where: {
          $0.sourceElementOffset == element.offset
        })
      else { return invalidSummary(rsnElements.invalidElementOffsets, element) }
      return rsnValueSummary(value)
    case .apChannelReport:
      let apChannelReports = report.apChannelReports
      guard
        let value = apChannelReports.values.first(where: {
          $0.sourceElementOffset == element.offset
        })
      else { return invalidSummary(apChannelReports.invalidElementOffsets, element) }
      return
        "Operating class \(value.operatingClass); channels \(value.channelNumbers.map(String.init).joined(separator: ", "))"
    case .mobilityDomain:
      let fastTransition = report.fastTransition
      guard
        let value = fastTransition.mobilityDomains.first(where: {
          $0.sourceElementOffset == element.offset
        })
      else {
        return fastTransition.invalidElementOffsets.contains(element.offset)
          ? "Invalid Mobility Domain element"
          : payloadPreview(element.payload)
      }
      return
        "MDID \(ScanFormatting.compactHex(value.mobilityDomainIdentifier)); FT over DS \(yesNo(value.fastTransitionOverDS)); resource request protocol \(yesNo(value.resourceRequestProtocol)); capability/policy 0x\(String(format: "%02X", value.rawCapabilityAndPolicy))"
    case .radioMeasurementEnabledCapabilities:
      return radioMeasurementSummary(report.radioMeasurement)
    case .multipleBSSID:
      let multipleBSSIDs = report.multipleBSSIDs
      guard
        let value = multipleBSSIDs.values.first(where: {
          $0.sourceElementOffset == element.offset
        })
      else { return invalidSummary(multipleBSSIDs.invalidElementOffsets, element) }
      let subelements = value.subelements.map {
        "offset \($0.offsetInElementPayload), ID \($0.identifier), \($0.payload.count) bytes, payload \(ScanFormatting.compactHex($0.payload))"
      }.joined(separator: ", ")
      return
        "Maximum BSSID indicator \(value.maximumBSSIDIndicator); subelements \(value.subelements.count)\(subelements.isEmpty ? "" : ": \(subelements)")"
    case .bssMaxIdlePeriod:
      let bssMaxIdlePeriods = report.bssMaxIdlePeriods
      guard
        let value = bssMaxIdlePeriods.values.first(where: {
          $0.sourceElementOffset == element.offset
        })
      else { return invalidSummary(bssMaxIdlePeriods.invalidElementOffsets, element) }
      return
        "Maximum idle period \(value.maximumIdlePeriod) × 1,000 TU; protected keep-alive required \(yesNo(value.protectedKeepAliveRequired)); options 0x\(String(format: "%02X", value.rawIdleOptions))"
    case .interworking:
      let interworking = report.interworking
      guard
        let value = interworking.values.first(where: {
          $0.sourceElementOffset == element.offset
        })
      else { return invalidSummary(interworking.invalidElementOffsets, element) }
      var values = [
        "access network type \(value.accessNetworkType)",
        "internet \(yesNo(value.internetAvailable))",
        "additional access step \(yesNo(value.additionalStepRequiredForAccess))",
        "emergency services reachable \(yesNo(value.emergencyServicesReachable))",
        "unauthenticated emergency service \(yesNo(value.unauthenticatedEmergencyServiceAccessible))",
      ]
      if let group = value.venueGroup, let type = value.venueType {
        values.append("venue \(group)/\(type)")
      }
      if let hessid = value.homogeneousExtendedServiceSetIdentifier {
        values.append("HESSID \(ScanFormatting.compactHex(hessid))")
      }
      return values.joined(separator: "; ")
    case .advertisementProtocol:
      let bytes = [UInt8](element.payload)
      guard bytes.count.isMultiple(of: 2), !bytes.isEmpty else {
        return "Invalid Advertisement Protocol tuples; \(payloadPreview(element.payload))"
      }
      return stride(from: 0, to: bytes.count, by: 2).map { offset in
        "tuple \(offset / 2 + 1): query-response info 0x\(String(format: "%02X", bytes[offset])), protocol ID \(bytes[offset + 1])"
      }.joined(separator: "; ")
    case .roamingConsortium:
      let roamingConsortiums = report.roamingConsortiums
      guard
        let value = roamingConsortiums.values.first(where: {
          $0.sourceElementOffset == element.offset
        })
      else { return invalidSummary(roamingConsortiums.invalidElementOffsets, element) }
      let identifiers = value.organizationIdentifiers.map(ScanFormatting.compactHex).joined(
        separator: ", "
      )
      return
        "ANQP OI count \(value.anqpOrganizationIdentifierCount); organization identifiers \(value.organizationIdentifiers.count)\(identifiers.isEmpty ? "" : ": \(identifiers)")"
    case .extendedCapabilities:
      return
        "BSS transition management \(advertisementName(report.bssTransitionManagement.advertisement)); \(payloadPreview(element.payload))"
    case .reducedNeighborReport:
      let reducedNeighborReports = report.reducedNeighborReports
      guard
        let value = reducedNeighborReports.values.first(where: {
          $0.sourceElementOffset == element.offset
        })
      else {
        return invalidSummary(reducedNeighborReports.invalidElementOffsets, element)
      }
      let neighbors = value.neighborAccessPoints.map {
        let sets = $0.tbttInformationSets.map(ScanFormatting.compactHex).joined(separator: "/")
        return
          "payload offset \($0.offsetInElementPayload), header 0x\(String(format: "%02X", $0.rawTBTTInformationHeader)), filtered \(yesNo($0.filteredNeighborAccessPoint)), class \($0.operatingClass), channel \($0.channelNumber), TBTT type/length \($0.tbttInformationFieldType)/\($0.tbttInformationLength), sets \(sets.isEmpty ? "none" : sets)"
      }.joined(separator: "; ")
      return
        "Neighbor AP fields \(value.neighborAccessPoints.count)\(neighbors.isEmpty ? "" : ": \(neighbors)")"
    case .vendorSpecific:
      if element.payload.count >= 3 {
        return
          "OUI \(ScanFormatting.compactHex(Data(element.payload.prefix(3)))); vendor payload \(max(0, element.payload.count - 3)) bytes"
      }
      return "Invalid vendor-specific payload; \(payloadPreview(element.payload))"
    case .elementIDExtension:
      guard let extensionID = element.payload.first else { return "Missing extension identifier" }
      let extensionPayload = Data(element.payload.dropFirst())
      let extensionTitle = extensionName(extensionID) ?? "Unknown extension"
      return
        "Extension ID \(extensionID), \(extensionTitle); \(payloadPreview(extensionPayload))"
    }
  }

  private static func standardSummary(for element: WiFiInformationElement) -> String? {
    let bytes = [UInt8](element.payload)
    switch element.identifier {
    case 0:
      if element.payload.isEmpty { return "Wildcard or hidden SSID (zero-length payload)" }
      if let value = String(data: element.payload, encoding: .utf8) {
        return "SSID \(String(reflecting: value)); \(element.payload.count) bytes"
      }
      return "Non-UTF-8 SSID; \(payloadPreview(element.payload))"
    case 1, 50:
      guard !bytes.isEmpty else { return "Empty supported-rates list" }
      let rates = bytes.map { byte -> String in
        let rate = Double(byte & 0x7F) / 2.0
        let formatted = rate.rounded() == rate ? String(Int(rate)) : String(format: "%.1f", rate)
        return "\(formatted) Mb/s\(byte & 0x80 != 0 ? " (basic)" : "")"
      }
      return rates.joined(separator: ", ")
    case 3:
      guard bytes.count == 1 else {
        return "Invalid DSSS Parameter Set; \(payloadPreview(element.payload))"
      }
      return "Current channel \(bytes[0])"
    case 42:
      guard bytes.count == 1 else {
        return "Invalid ERP Information; \(payloadPreview(element.payload))"
      }
      return
        "Non-ERP present \(yesNo(bytes[0] & 0x01 != 0)); protection required \(yesNo(bytes[0] & 0x02 != 0)); Barker preamble mode \(yesNo(bytes[0] & 0x04 != 0)); raw 0x\(String(format: "%02X", bytes[0]))"
    case 45:
      guard bytes.count == 26 else {
        return "Invalid HT Capabilities; \(payloadPreview(element.payload))"
      }
      let capabilities = littleEndianUInt16(bytes, at: 0)
      let spatialMode = (capabilities >> 2) & 0x3
      return
        "Capabilities 0x\(String(format: "%04X", capabilities)); 20/40 MHz \(yesNo(capabilities & 0x0002 != 0)); SM power-save \(spatialMode); short GI 20/40 \(yesNo(capabilities & 0x0020 != 0))/\(yesNo(capabilities & 0x0040 != 0)); TX STBC \(yesNo(capabilities & 0x0080 != 0)); RX STBC \((capabilities >> 8) & 0x3); \(payloadPreview(element.payload))"
    case 52:
      guard bytes.count >= 13 else {
        return "Invalid Neighbor Report; \(payloadPreview(element.payload))"
      }
      let bssid = bytes[0..<6].map { String(format: "%02X", $0) }.joined(separator: ":")
      let bssidInformation = littleEndianUInt32(bytes, at: 6)
      return
        "BSSID \(bssid); BSSID information 0x\(String(format: "%08X", bssidInformation)); operating class \(bytes[10]); channel \(bytes[11]); PHY type \(bytes[12]); subelements \(max(0, bytes.count - 13)) bytes"
    case 61:
      guard bytes.count == 22 else {
        return "Invalid HT Operation; \(payloadPreview(element.payload))"
      }
      let secondaryOffset: String
      switch bytes[1] & 0x03 {
      case 1: secondaryOffset = "above"
      case 3: secondaryOffset = "below"
      default: secondaryOffset = "none"
      }
      return
        "Primary channel \(bytes[0]); secondary channel \(secondaryOffset); any 40 MHz channel width \(yesNo(bytes[1] & 0x04 != 0)); \(payloadPreview(element.payload))"
    case 191:
      guard bytes.count == 12 else {
        return "Invalid VHT Capabilities; \(payloadPreview(element.payload))"
      }
      let capabilities = littleEndianUInt32(bytes, at: 0)
      return
        "Capabilities 0x\(String(format: "%08X", capabilities)); max MPDU code \(capabilities & 0x3); channel-width code \((capabilities >> 2) & 0x3); short GI 80/160 \(yesNo(capabilities & 0x20 != 0))/\(yesNo(capabilities & 0x40 != 0)); TX STBC \(yesNo(capabilities & 0x80 != 0)); RX STBC \((capabilities >> 8) & 0x7); SU beamformer/beamformee \(yesNo(capabilities & 0x800 != 0))/\(yesNo(capabilities & 0x1000 != 0)); \(payloadPreview(element.payload))"
    case 192:
      guard bytes.count == 5 else {
        return "Invalid VHT Operation; \(payloadPreview(element.payload))"
      }
      return
        "Channel-width code \(bytes[0]); center-frequency segments \(bytes[1])/\(bytes[2]); basic VHT MCS/NSS set 0x\(String(format: "%04X", littleEndianUInt16(bytes, at: 3)))"
    case 244:
      return "RSN extension capabilities; \(payloadPreview(element.payload))"
    case 255:
      guard let extensionID = bytes.first else { return "Missing extension identifier" }
      let extensionPayload = Data(bytes.dropFirst())
      return
        "Extension ID \(extensionID), \(extensionName(extensionID) ?? "Unknown extension"); \(payloadPreview(extensionPayload))"
    default:
      return nil
    }
  }

  private static func littleEndianUInt16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
    UInt16(bytes[offset]) | UInt16(bytes[offset + 1]) << 8
  }

  private static func littleEndianUInt32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
    UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8
      | UInt32(bytes[offset + 2]) << 16 | UInt32(bytes[offset + 3]) << 24
  }

  static func radioMeasurementSummary(_ value: WiFiRadioMeasurementCapabilities) -> String {
    guard value.advertisement == .advertised else {
      var parts = [advertisementName(value.advertisement)]
      if !value.invalidElementOffsets.isEmpty {
        parts.append("invalid RM elements at \(offsetList(value.invalidElementOffsets))")
      }
      if Set(value.rawCapabilities).count > 1 {
        parts.append("conflicting RM capability elements")
      } else if value.advertisement == .unknown, !value.rawCapabilities.isEmpty,
        value.invalidElementOffsets.isEmpty
      {
        parts.append("stream incomplete or malformed; raw RM element retained")
      }
      return parts.joined(separator: "; ")
    }
    let capabilities: [(String, WiFiAdvertisementState)] = [
      ("link", value.linkMeasurement),
      ("neighbor report", value.neighborReport),
      ("parallel", value.parallelMeasurements),
      ("repeated", value.repeatedMeasurements),
      ("passive beacon", value.passiveBeaconMeasurement),
      ("active beacon", value.activeBeaconMeasurement),
      ("beacon table", value.beaconTableMeasurement),
      ("beacon reporting conditions", value.beaconMeasurementReportingConditions),
      ("frame", value.frameMeasurement),
      ("channel load", value.channelLoadMeasurement),
      ("noise histogram", value.noiseHistogramMeasurement),
      ("statistics", value.statisticsMeasurement),
      ("LCI", value.locationConfigurationInformationMeasurement),
      ("LCI azimuth", value.locationConfigurationInformationAzimuth),
      ("transmit stream/category", value.transmitStreamCategoryMeasurement),
      ("triggered transmit stream/category", value.triggeredTransmitStreamCategoryMeasurement),
      ("AP channel report", value.apChannelReport),
      ("RM MIB", value.radioMeasurementMIB),
      ("measurement pilot TX info", value.measurementPilotTransmissionInformation),
      ("neighbor report TSF offset", value.neighborReportTSFOffset),
      ("RCPI", value.receivedChannelPowerIndicatorMeasurement),
      ("RSNI", value.receivedSignalToNoiseIndicatorMeasurement),
      ("BSS average access delay", value.bssAverageAccessDelay),
      ("BSS available admission capacity", value.bssAvailableAdmissionCapacity),
      ("antenna information", value.antennaInformation),
      ("FTM range report", value.fineTimingMeasurementRangeReport),
      ("civic location", value.civicLocationMeasurement),
    ]
    var summaries = capabilities.compactMap { name, state in
      state == .advertised ? name : nil
    }
    if let duration = value.operatingChannelMaxMeasurementDuration {
      summaries.append("operating max duration \(duration)")
    }
    if let duration = value.nonoperatingChannelMaxMeasurementDuration {
      summaries.append("nonoperating max duration \(duration)")
    }
    if let pilot = value.measurementPilotCapability {
      summaries.append("measurement pilot \(pilot)")
    }
    return "Advertised\(summaries.isEmpty ? "" : ": \(summaries.joined(separator: ", "))")"
  }

  static func bssTransitionSummary(_ value: WiFiBSSTransitionManagementCapabilities) -> String {
    var parts = [advertisementName(value.advertisement)]
    if !value.invalidElementOffsets.isEmpty {
      parts.append("invalid Extended Capabilities at \(offsetList(value.invalidElementOffsets))")
    } else if value.advertisement == .unknown, !value.rawExtendedCapabilities.isEmpty {
      parts.append("conflicting, incomplete, or malformed Extended Capabilities")
    }
    return parts.joined(separator: "; ")
  }

  static func fastTransitionSummary(_ value: WiFiFastTransitionCapabilities) -> String {
    guard value.advertisement == .advertised else {
      var parts = [advertisementName(value.advertisement)]
      if !value.invalidElementOffsets.isEmpty {
        parts.append(
          "invalid Mobility Domain elements at \(offsetList(value.invalidElementOffsets))")
      } else if value.advertisement == .unknown, !value.mobilityDomains.isEmpty {
        parts.append("conflicting, incomplete, or malformed Mobility Domain elements")
      }
      return parts.joined(separator: "; ")
    }
    var parts = ["Advertised"]
    if let mdid = value.mobilityDomainIdentifier {
      parts.append("MDID \(ScanFormatting.compactHex(mdid))")
    }
    parts.append("FT over DS \(advertisementName(value.fastTransitionOverDS))")
    parts.append("resource request \(advertisementName(value.resourceRequestProtocol))")
    if value.mobilityDomains.count > 1 {
      parts.append("\(value.mobilityDomains.count) Mobility Domain elements")
    }
    return parts.joined(separator: "; ")
  }

  static func rsnSummary(_ collection: WiFiDecodedElementCollection<WiFiRSNInformation>) -> String {
    if collection.values.isEmpty {
      let base = advertisementName(collection.advertisement)
      guard !collection.invalidElementOffsets.isEmpty else { return base }
      return "\(base); invalid RSN elements at \(offsetList(collection.invalidElementOffsets))"
    }
    var values = collection.values.map(rsnValueSummary)
    if collection.advertisement == .unknown {
      values.append("Advertisement state unknown because the stream is incomplete or malformed")
    }
    if !collection.invalidElementOffsets.isEmpty {
      values.append("Invalid RSN elements at \(offsetList(collection.invalidElementOffsets))")
    }
    return values.joined(separator: " | ")
  }

  static func pmfSummary(_ value: WiFiProtectedManagementFrames) -> String {
    switch value.mode {
    case .required: return "Required"
    case .capable: return "Capable, not required"
    case .notAdvertised: return "Not Advertised"
    case .unknown: return "Unknown"
    }
  }

  private static func rsnValueSummary(_ value: WiFiRSNInformation) -> String {
    var fields = ["v\(value.version)"]
    if let group = value.groupDataCipherSuite {
      fields.append("group \(cipherName(group))")
    }
    if let pairwise = value.pairwiseCipherSuites {
      fields.append("pairwise \(pairwise.map(cipherName).joined(separator: "/"))")
    }
    if let authentication = value.authenticationKeyManagementSuites {
      fields.append("AKM \(authentication.map(akmName).joined(separator: "/"))")
    }
    if let capabilities = value.capabilities {
      fields.append("capabilities 0x\(String(format: "%04X", capabilities.rawValue))")
    }
    if let identifiers = value.pairwiseMasterKeyIdentifiers {
      fields.append(
        "PMKIDs \(identifiers.count)\(identifiers.isEmpty ? "" : ": \(identifiers.map(ScanFormatting.compactHex).joined(separator: "/"))")"
      )
    }
    if let management = value.groupManagementCipherSuite {
      fields.append("group management \(cipherName(management))")
    }
    return fields.joined(separator: "; ")
  }

  private static func cipherName(_ selector: WiFiSuiteSelector) -> String {
    guard selector.isIEEE80211Selector else { return suiteRaw(selector) }
    switch selector.suiteType {
    case 0: return "Use Group"
    case 1: return "WEP-40"
    case 2: return "TKIP"
    case 4: return "CCMP-128"
    case 5: return "WEP-104"
    case 6: return "BIP-CMAC-128"
    case 8: return "GCMP-128"
    case 9: return "GCMP-256"
    case 10: return "CCMP-256"
    case 11: return "BIP-GMAC-128"
    case 12: return "BIP-GMAC-256"
    case 13: return "BIP-CMAC-256"
    default: return "IEEE cipher \(selector.suiteType)"
    }
  }

  private static func akmName(_ selector: WiFiSuiteSelector) -> String {
    guard selector.isIEEE80211Selector else { return suiteRaw(selector) }
    switch selector.suiteType {
    case 1: return "802.1X"
    case 2: return "PSK"
    case 3: return "FT/802.1X"
    case 4: return "FT/PSK"
    case 5: return "802.1X SHA-256"
    case 6: return "PSK SHA-256"
    case 8: return "SAE"
    case 9: return "FT/SAE"
    case 11: return "Suite B"
    case 12: return "Suite B 192-bit"
    case 13: return "FT/802.1X SHA-384"
    case 18: return "OWE"
    default: return "IEEE AKM \(selector.suiteType)"
    }
  }

  private static func suiteRaw(_ selector: WiFiSuiteSelector) -> String {
    ScanFormatting.compactHex(selector.rawValue)
  }

  private static func invalidSummary(_ offsets: [Int], _ element: WiFiInformationElement)
    -> String
  {
    offsets.contains(element.offset)
      ? "Invalid \(name(for: element)) payload"
      : payloadPreview(element.payload)
  }

  private static func payloadPreview(_ data: Data) -> String {
    guard !data.isEmpty else { return "Empty payload" }
    let preview = Data(data.prefix(24))
    return
      "Payload \(data.count) bytes: \(ScanFormatting.compactHex(preview))\(data.count > preview.count ? " …" : "")"
  }

  private static func asciiOrHex(_ data: Data) -> String {
    if let value = String(data: data, encoding: .ascii),
      value.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value <= 126 })
    {
      return value
    }
    return ScanFormatting.compactHex(data)
  }

  private static func printableByte(_ byte: UInt8) -> String {
    guard (32...126).contains(byte), let scalar = UnicodeScalar(Int(byte)) else {
      return "0x\(String(format: "%02X", byte))"
    }
    return "\(Character(scalar)) (0x\(String(format: "%02X", byte)))"
  }

  private static func advertisementName(_ state: WiFiAdvertisementState) -> String {
    switch state {
    case .advertised: return "Advertised in Captured Frame"
    case .notAdvertised: return "Not Advertised in Captured Frame"
    case .unknown: return "Unknown from Captured Frame"
    }
  }

  private static func offsetList(_ offsets: [Int]) -> String {
    offsets.map { "0x\(String(format: "%04X", $0))" }.joined(separator: ", ")
  }

  private static func yesNo(_ value: Bool) -> String { value ? "yes" : "no" }
}
