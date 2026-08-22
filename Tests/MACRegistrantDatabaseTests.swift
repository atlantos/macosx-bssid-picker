// SPDX-License-Identifier: GPL-3.0-only

import Foundation

func macRegistrantDatabaseTests() -> [RegressionTest] {
  [
    RegressionTest(name: "registrant lookup prefers the longest prefix") {
      let resolver = try makeResolver(
        manuf: """
          00:11:22\tShort\tTwenty Four Corporation
          00:11:22:30/28\tMedium\tTwenty Eight Corporation
          00:11:22:33:40/36\tLong\tThirty Six Corporation
          """
      )

      let longest = resolver.resolve(try requireBSSID("00-11-22-33-4A-55"))
      try expectEqual(longest.registeredOrganization, "Thirty Six Corporation")
      try expectEqual(longest.allocation, .maSOrIAB)
      try expectEqual(longest.matchedPrefix, "00:11:22:33:4/36")
      try expectEqual(longest.registrationSource, .ieeeRegistryViaWireshark)
      try expectEqual(longest.registryClaims.count, 1)

      let medium = resolver.resolve(try requireBSSID("00:11:22:3f:aa:bb"))
      try expectEqual(medium.registeredOrganization, "Twenty Eight Corporation")
      try expectEqual(medium.allocation, .maM)
      try expectEqual(medium.matchedPrefix, "00:11:22:3/28")

      let shortest = resolver.resolve(try requireBSSID("00:11:22:ff:aa:bb"))
      try expectEqual(shortest.registeredOrganization, "Twenty Four Corporation")
      try expectEqual(shortest.allocation, .maL)
      try expectEqual(shortest.matchedPrefix, "00:11:22/24")
    },

    RegressionTest(name: "address classification does not invent registrations") {
      let resolver = try makeResolver(
        manuf: "00:11:22\tExample\tExample Corporation",
        wka: "01:00:5E/25\tIPv4 multicast"
      )

      let local = resolver.resolve(try requireBSSID("02:11:22:33:44:55"))
      try expectEqual(local.addressType, .locallyAdministered)
      try expectEqual(local.registrantDisplayName, "Locally Administered")
      try expectEqual(local.registeredOrganization, nil)

      let group = resolver.resolve(try requireBSSID("01:00:5e:10:20:30"))
      try expectEqual(group.addressType, .groupAddress)
      try expectEqual(group.registrantDisplayName, "Group Address")
      try expectEqual(group.knownAddressRole, "IPv4 multicast")
      try expectEqual(group.registeredOrganization, nil)

      let zero = resolver.resolve(try requireBSSID("00:00:00:00:00:00"))
      try expectEqual(zero.addressType, .invalidAddress)
      try expectEqual(zero.registrantDisplayName, "Unavailable")
      try expectEqual(resolver.resolve(nil).addressType, .invalidAddress)

      let unavailable = MACRegistrantResolver.unavailable.resolve(
        try requireBSSID("00:11:22:33:44:55"))
      try expectEqual(unavailable.addressType, .globallyAdministered)
      try expect(unavailable.isDatabaseUnavailable, "missing database was not reported")
      try expectEqual(unavailable.registrantDisplayName, "—")
    },

    RegressionTest(name: "ambiguous and duplicate registry records are deterministic") {
      let resolver = try makeResolver(
        manuf: """
          00:11:22\tFirst\tAcme, Inc.
          00:11:22\tDuplicate\tACMÉ INC
          00:11:22\tSecond\tOther Corporation
          """
      )
      let attribution = resolver.resolve(try requireBSSID("00:11:22:33:44:55"))

      try expectEqual(attribution.registeredOrganization, nil)
      try expectEqual(attribution.registrantDisplayName, "Ambiguous Registration")
      try expectEqual(attribution.databaseAgreement, .ambiguousRegistryRecords)
      try expectEqual(
        attribution.registryClaims.map(\.organization),
        ["Acme, Inc.", "Other Corporation"]
      )
    },

    RegressionTest(name: "known-address roles use the longest prefix and deduplicate") {
      let resolver = try makeResolver(
        manuf: "00:11:22\tExample\tExample Corporation",
        wka: """
          00:11:22/24\tGeneral role
          00:11:22:33/32\tZeta role
          00:11:22:33/32\tAlpha role
          00:11:22:33/32\tAlpha role
          """
      )

      let specific = resolver.resolve(try requireBSSID("00:11:22:33:44:55"))
      try expectEqual(specific.knownAddressRole, "Alpha role; Zeta role")

      let general = resolver.resolve(try requireBSSID("00:11:22:44:55:66"))
      try expectEqual(general.knownAddressRole, "General role")
    },

    RegressionTest(name: "private registrations and abbreviated records are represented") {
      let resolver = try makeResolver(
        manuf: """
          00:11:22\tPrivate\tPrivate Registration
          00:22:33\tShortName
          """
      )

      let privateRecord = resolver.resolve(try requireBSSID("00:11:22:33:44:55"))
      try expect(privateRecord.isPrivateRegistration, "private registration was not identified")
      try expectEqual(privateRecord.registrantDisplayName, "Private Registration")

      let abbreviated = resolver.resolve(try requireBSSID("00:22:33:44:55:66"))
      try expectEqual(abbreviated.registeredOrganization, "ShortName")
    },

    RegressionTest(name: "malformed database records are rejected") {
      do {
        _ = try MACRegistrantDatabaseParser.resolver(manufData: Data([0xFF]))
        throw RegressionTestFailure(message: "invalid UTF-8 was accepted")
      } catch MACRegistrantDatabaseParseError.invalidEncoding(let source) {
        try expectEqual(source, "manufacturer")
      }

      do {
        _ = try makeResolver(manuf: "00:11:22:3F/28\tInvalid\tHost Bits Set")
        throw RegressionTestFailure(message: "a prefix with nonzero host bits was accepted")
      } catch MACRegistrantDatabaseParseError.invalidPrefix(let source, let line) {
        try expectEqual(source, "manufacturer")
        try expectEqual(line, 1)
      }

      do {
        _ = try makeResolver(manuf: "")
        throw RegressionTestFailure(message: "an empty manufacturer database was accepted")
      } catch MACRegistrantDatabaseParseError.invalidRecordCount(let source, let count) {
        try expectEqual(source, "manufacturer")
        try expectEqual(count, 0)
      }
    },

    RegressionTest(name: "database states preserve installed snapshot metadata") {
      let metadata = MACRegistrantDatabaseMetadata(
        updatedAt: Date(timeIntervalSince1970: 1_700_000_000),
        manufacturerRecordCount: 12_345,
        knownAddressRecordCount: 123,
        sources: [
          MACRegistrantDatabase.manufacturerSource,
          MACRegistrantDatabase.knownAddressSource,
        ]
      )
      let states: [MACRegistrantDatabaseState] = [
        .ready(metadata),
        .downloading(previous: metadata),
        .validating(previous: metadata),
        .installing(previous: metadata),
        .updateFailed(message: "fixture", previous: metadata),
      ]
      for state in states {
        try expectEqual(state.databaseMetadata, metadata)
      }
      try expectEqual(MACRegistrantDatabaseState.notDownloaded.databaseMetadata, nil)
      try expectEqual(
        MACRegistrantDatabaseState.downloading(previous: nil).databaseMetadata,
        nil
      )
    },
  ]
}

private func makeResolver(manuf: String, wka: String? = nil) throws -> MACRegistrantResolver {
  try MACRegistrantDatabaseParser.resolver(
    manufData: Data(manuf.utf8),
    wkaData: wka.map { Data($0.utf8) }
  )
}

private func requireBSSID(
  _ value: String,
  file: StaticString = #filePath,
  line: UInt = #line
) throws -> BSSID {
  guard let bssid = BSSID(value) else {
    throw RegressionTestFailure(message: "\(file):\(line): invalid test BSSID \(value)")
  }
  return bssid
}
