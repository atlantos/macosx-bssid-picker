// SPDX-License-Identifier: GPL-3.0-only

import Foundation

func scanExportTests() -> [RegressionTest] {
  [
    RegressionTest(name: "JSON export exposes the cleaned MAC registration schema") {
      let row = try attributedScanRow()
      let data = try ScanExporter.data(
        format: .json,
        rows: [row],
        context: nil,
        scannedAt: Date(timeIntervalSince1970: 1_700_000_000),
        scope: .all
      )
      let root = try requireDictionary(JSONSerialization.jsonObject(with: data))
      try expectEqual(root["schema"] as? String, "local.bssid-picker.scan")
      try expectEqual(root["schemaVersion"] as? Int, 7)
      let accessPoints = try requireArray(root["accessPoints"])
      try expectEqual(accessPoints.count, 1)
      let accessPoint = try requireDictionary(accessPoints[0])
      let registration = try requireDictionary(accessPoint["macRegistration"])

      try expectEqual(
        Set(registration.keys),
        Set([
          "addressType",
          "registrantDisplay",
          "registeredOrganization",
          "allocation",
          "matchedPrefix",
          "registrationSource",
          "databaseAgreement",
          "knownAddressRole",
          "registryClaims",
          "evidenceScope",
        ])
      )
      try expectEqual(registration["registeredOrganization"] as? String, "Example Corporation")
      try expectEqual(registration["registrationSource"] as? String, "IEEE Registry via Wireshark")
      try expect(registration["wiresharkName"] == nil, "removed Wireshark name key was exported")
    },

    RegressionTest(name: "CSV export exposes the cleaned MAC registration columns") {
      let data = try ScanExporter.data(
        format: .csv,
        rows: [try attributedScanRow()],
        context: nil,
        scannedAt: nil,
        scope: .filtered
      )
      let records = try parseCSV(data)
      try expectEqual(records.count, 2)
      let expectedHeader =
        ScanColumnID.allCases.map(\.title) + [
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
      try expectEqual(records[0], expectedHeader)
      try expectEqual(records[1].count, expectedHeader.count)

      let exportedRow = Dictionary(uniqueKeysWithValues: zip(expectedHeader, records[1]))
      try expectEqual(exportedRow["MAC Address Type"], "Globally Administered")
      try expectEqual(exportedRow["MAC Allocation"], "MA-L")
      try expectEqual(exportedRow["MAC Matched Prefix"], "00:11:22/24")
      try expectEqual(exportedRow["MAC Registration Source"], "IEEE Registry via Wireshark")
      try expectEqual(exportedRow["MAC Database Agreement"], "")
      try expectEqual(exportedRow["Known Address Role"], "")
    },
  ]
}

private func attributedScanRow() throws -> ScanRow {
  guard let rawSSID = RawSSID(data: Data("Regression Network".utf8)),
    let bssid = BSSID("00:11:22:33:44:55")
  else {
    throw RegressionTestFailure(message: "invalid scan-row fixture")
  }
  let target = NetworkTarget(ssid: rawSSID, bssid: bssid)
  let accessPoint = AccessPoint(
    target: target,
    displaySSID: "Regression Network",
    rawSSID: rawSSID,
    bssid: bssid,
    reportedBSSID: bssid.rawValue,
    channelNumber: 36,
    channelWidth: "80 MHz",
    band: "5 GHz",
    rssi: -50,
    noise: -90,
    countryCode: "US",
    beaconInterval: 100,
    isIBSS: false,
    phyModes: "802.11ac",
    security: "WPA2 Personal",
    authentication: .personal,
    informationElements: nil
  )
  let resolver = try MACRegistrantDatabaseParser.resolver(
    manufData: Data("00:11:22\tExample\tExample Corporation".utf8)
  )
  return ScanRow(
    accessPoint: accessPoint,
    lastSeenAt: Date(timeIntervalSince1970: 1_700_000_000),
    macAttribution: resolver.resolve(bssid)
  )
}

private func requireDictionary(_ value: Any?) throws -> [String: Any] {
  guard let dictionary = value as? [String: Any] else {
    throw RegressionTestFailure(message: "expected a JSON object")
  }
  return dictionary
}

private func requireArray(_ value: Any?) throws -> [Any] {
  guard let array = value as? [Any] else {
    throw RegressionTestFailure(message: "expected a JSON array")
  }
  return array
}

private func parseCSV(_ data: Data) throws -> [[String]] {
  var text = String(decoding: data, as: UTF8.self)
  if text.first == "\u{FEFF}" { text.removeFirst() }

  var records: [[String]] = []
  var record: [String] = []
  var field = ""
  var insideQuotedField = false
  var index = text.startIndex

  while index < text.endIndex {
    let character = text[index]
    let next = text.index(after: index)
    if insideQuotedField {
      if character == "\"" {
        if next < text.endIndex, text[next] == "\"" {
          field.append("\"")
          index = text.index(after: next)
        } else {
          insideQuotedField = false
          index = next
        }
      } else {
        field.append(character)
        index = next
      }
      continue
    }

    switch character {
    case "\"":
      insideQuotedField = true
      index = next
    case ",":
      record.append(field)
      field = ""
      index = next
    case "\r", "\n", "\r\n":
      record.append(field)
      records.append(record)
      field = ""
      record = []
      if character == "\r", next < text.endIndex, text[next] == "\n" {
        index = text.index(after: next)
      } else {
        index = next
      }
    default:
      field.append(character)
      index = next
    }
  }

  try expect(!insideQuotedField, "CSV ended inside a quoted field")
  if !field.isEmpty || !record.isEmpty {
    record.append(field)
    records.append(record)
  }
  return records
}
