// SPDX-License-Identifier: GPL-3.0-only

import CoreWLAN
import Darwin
import Foundation

/// Serializes every CoreWLAN operation, including association verification.
/// CWNetwork objects never leave this queue; callers receive immutable copies.
final class CoreWLANService {
  typealias Completion<Value> = (Result<Value, Error>) -> Void
  typealias CredentialObserver = (CredentialRequirement, CredentialAccessRecord) -> Void

  private let queue = DispatchQueue(label: "local.bssid-picker.wifi", qos: .userInitiated)
  private lazy var client = CWWiFiClient.shared()
  private let credentials = CredentialProvider()
  private let strictBSSID = StrictBSSIDService()

  func scanCurrent(completion: @escaping Completion<CurrentScanSnapshot>) {
    submit(completion: completion) {
      let interface = try self.interface()
      let association = try self.currentAssociation(on: interface)
      let scanned = try interface.scanForNetworks(withSSID: association.ssid.data)
      let accessPoints =
        scanned
        .map(AccessPoint.init(network:))
        .sorted(by: Self.strongestFirst)

      return CurrentScanSnapshot(
        capturedAt: Date(),
        displaySSID: association.displaySSID,
        ssid: association.ssid,
        currentBSSID: association.bssid,
        accessPoints: accessPoints
      )
    }
  }

  func scanAll(completion: @escaping Completion<AllScanSnapshot>) {
    submit(completion: completion) {
      let interface = try self.interface()
      let scanned = try interface.scanForNetworks(withName: nil, includeHidden: true)
      let accessPoints =
        scanned
        .map(AccessPoint.init(network:))
        .sorted(by: Self.displayNameThenSignal)
      let association = try? self.currentAssociation(on: interface)
      let capturedAt = Date()
      let scannedSSIDs = Set(accessPoints.compactMap(\.rawSSID))
      let interfaceSnapshot = self.interfaceSnapshot(
        on: interface,
        capturedAt: capturedAt,
        currentAssociation: association,
        scannedSSIDs: scannedSSIDs
      )
      return AllScanSnapshot(
        capturedAt: capturedAt,
        currentAssociation: association,
        accessPoints: accessPoints,
        interfaceSnapshot: interfaceSnapshot
      )
    }
  }

  func currentAssociation(completion: @escaping Completion<CurrentAssociation>) {
    submit(completion: completion) {
      try self.currentAssociation(on: self.interface())
    }
  }

  func checkStrictAvailability(completion: @escaping Completion<Void>) {
    submit(completion: completion) {
      try self.strictBSSID.requireAvailability()
    }
  }

  func connectPublic(
    to target: NetworkTarget,
    credentialPolicy: CredentialPolicy,
    credentialObserver: @escaping CredentialObserver,
    completion: @escaping Completion<ConnectionOutcome>
  ) {
    submit(completion: completion) {
      let interface = try self.interface()
      try self.requireCurrentSSID(target.ssid, on: interface)
      let network = try self.resolveNetwork(target, on: interface)
      try self.requireCurrentSSID(target.ssid, on: interface)

      let authentication = AccessPoint.authentication(for: network)
      switch authentication {
      case .passwordless:
        self.reportCredential(
          requirement: .notRequired,
          record: CredentialAccessRecord(
            stage: .noCredential,
            result: .notRequired,
            secretHandling: .notNeeded
          ),
          to: credentialObserver
        )
        try interface.associate(to: network, password: nil)
      case .personal, .legacyWEP:
        try self.credentials.withSavedPassword(
          for: target.ssid,
          policy: credentialPolicy,
          record: { record in
            self.reportCredential(
              requirement: authentication.credentialRequirement,
              record: record,
              to: credentialObserver
            )
          }
        ) { password, _ in
          try interface.associate(to: network, password: password)
        }
      case .enterprise:
        self.reportUnsupportedCredential(
          requirement: authentication.credentialRequirement,
          to: credentialObserver
        )
        throw WiFiOperationError.enterpriseUnsupported
      case .unknown:
        self.reportUnsupportedCredential(
          requirement: authentication.credentialRequirement,
          to: credentialObserver
        )
        throw WiFiOperationError.unknownSecurity
      }

      return try self.verifyPublicAssociation(on: interface, expected: target.bssid)
    }
  }

  func connectStrict(
    to target: NetworkTarget,
    credentialObserver: @escaping CredentialObserver,
    completion: @escaping Completion<ConnectionOutcome>
  ) {
    submit(completion: completion) {
      let interface = try self.interface()
      try self.strictBSSID.requireAvailability()
      try self.requireCurrentSSID(target.ssid, on: interface)

      // A fresh, directed scan is mandatory. The private shim receives
      // this exact scan result rather than a remembered network profile.
      let network = try self.resolveNetwork(target, on: interface)
      let authentication = AccessPoint.authentication(for: network)
      switch authentication {
      case .passwordless:
        self.reportCredential(
          requirement: .notRequired,
          record: CredentialAccessRecord(
            stage: .noCredential,
            result: .notRequired,
            secretHandling: .notNeeded
          ),
          to: credentialObserver
        )
      case .personal:
        break
      case .legacyWEP:
        self.reportUnsupportedCredential(
          requirement: authentication.credentialRequirement,
          to: credentialObserver
        )
        throw WiFiOperationError.strictWEPUnsupported
      case .enterprise:
        self.reportUnsupportedCredential(
          requirement: authentication.credentialRequirement,
          to: credentialObserver
        )
        throw WiFiOperationError.enterpriseUnsupported
      case .unknown:
        self.reportUnsupportedCredential(
          requirement: authentication.credentialRequirement,
          to: credentialObserver
        )
        throw WiFiOperationError.unknownSecurity
      }

      // Close the scan/association TOCTOU window as far as the public
      // API permits. The Objective-C boundary repeats this check just
      // before sending the request to airportd.
      try self.requireCurrentSSID(target.ssid, on: interface)
      if authentication == .personal {
        self.reportCredential(
          requirement: .personalPassword,
          record: CredentialAccessRecord(
            stage: .airportdDelegation,
            result: .pending,
            secretHandling: .notExposedToApp
          ),
          to: credentialObserver
        )
      }
      do {
        try self.strictBSSID.associate(
          interface: interface,
          network: network,
          expectedCurrentSSID: target.ssid
        )
      } catch {
        if authentication == .personal {
          self.reportCredential(
            requirement: .personalPassword,
            record: CredentialAccessRecord(
              stage: .airportdDelegation,
              result: .failed,
              secretHandling: .notExposedToApp
            ),
            to: credentialObserver
          )
        }
        throw error
      }
      if authentication == .personal {
        self.reportCredential(
          requirement: .personalPassword,
          record: CredentialAccessRecord(
            stage: .airportdDelegation,
            result: .delegated,
            secretHandling: .notExposedToApp
          ),
          to: credentialObserver
        )
      }
      return try self.verifyStrictAssociation(on: interface, expected: target.bssid)
    }
  }

  private func reportUnsupportedCredential(
    requirement: CredentialRequirement,
    to observer: @escaping CredentialObserver
  ) {
    reportCredential(
      requirement: requirement,
      record: CredentialAccessRecord(
        stage: .unsupportedAuthentication,
        result: .unsupported,
        secretHandling: .notExposedToApp
      ),
      to: observer
    )
  }

  private func reportCredential(
    requirement: CredentialRequirement,
    record: CredentialAccessRecord,
    to observer: @escaping CredentialObserver
  ) {
    DispatchQueue.main.async {
      observer(requirement, record)
    }
  }

  private func interface() throws -> CWInterface {
    guard let interface = client.interface() else {
      throw WiFiOperationError.noInterface
    }
    return interface
  }

  private func currentAssociation(on interface: CWInterface) throws -> CurrentAssociation {
    guard let ssidValue = interface.ssidData() else {
      throw WiFiOperationError.notConnected
    }
    guard let copiedData = ownedData(ssidValue as NSData?),
      let ssid = RawSSID(data: copiedData)
    else {
      throw WiFiOperationError.invalidSSIDData
    }
    return CurrentAssociation(
      displaySSID: interface.ssid() ?? "<non-text SSID>",
      ssid: ssid,
      bssid: interface.bssid().flatMap(BSSID.init)
    )
  }

  private func interfaceSnapshot(
    on interface: CWInterface,
    capturedAt: Date,
    currentAssociation: CurrentAssociation?,
    scannedSSIDs: Set<RawSSID>
  ) -> WiFiInterfaceSnapshot {
    let isPowerOn = interface.powerOn()
    let rssiValue = currentAssociation.map { _ in interface.rssiValue() }
    let noiseValue = currentAssociation.map { _ in interface.noiseMeasurement() }
    let rssi = rssiValue.flatMap { $0 < 0 ? $0 : nil }
    let noise = noiseValue.flatMap { $0 < 0 ? $0 : nil }
    let transmitRate = currentAssociation.map { _ in interface.transmitRate() }.flatMap {
      $0.isFinite && $0 > 0 ? $0 : nil
    }
    let transmitPower = isPowerOn ? interface.transmitPower() : 0

    return WiFiInterfaceSnapshot(
      capturedAt: capturedAt,
      availableInterfaceNames: (client.interfaceNames() ?? [])
        .filter { !$0.isEmpty }
        .reduce(into: Set<String>()) { $0.insert($1) }
        .sorted(),
      interfaceName: Self.nonempty(interface.interfaceName),
      isPowerOn: isPowerOn,
      isServiceActive: interface.serviceActive(),
      interfaceMode: Self.interfaceMode(interface.interfaceMode()),
      hardwareAddress: Self.nonempty(interface.hardwareAddress()),
      countryCode: Self.nonempty(interface.countryCode()),
      activePHYMode: Self.phyMode(interface.activePHYMode()),
      currentChannel: interface.wlanChannel().flatMap(Self.channelSnapshot),
      currentAssociation: currentAssociation,
      rssi: rssi,
      noise: noise,
      snr: rssi.flatMap { signal in noise.map { signal - $0 } },
      security: currentAssociation.map { _ in Self.securityMode(interface.security()) },
      transmitRateMbps: transmitRate,
      transmitPowerMilliwatts: transmitPower > 0 ? transmitPower : nil,
      supportedChannels: (interface.supportedWLANChannels() ?? [])
        .compactMap(Self.channelSnapshot)
        .sorted(by: Self.channelComesBefore),
      configuration: interface.configuration().map {
        Self.configurationSnapshot($0, scannedSSIDs: scannedSSIDs)
      }
    )
  }

  private static func configurationSnapshot(
    _ configuration: CWConfiguration,
    scannedSSIDs: Set<RawSSID>
  ) -> WiFiConfigurationSnapshot {
    let preferredProfiles = configuration.networkProfiles
    var matchingProfiles: [WiFiSavedNetworkProfile] = []
    matchingProfiles.reserveCapacity(min(preferredProfiles.count, scannedSSIDs.count))

    for (index, value) in preferredProfiles.enumerated() {
      guard let profile = value as? CWNetworkProfile,
        let copiedData = ownedData(profile.ssidData as NSData?),
        let rawSSID = RawSSID(data: copiedData),
        scannedSSIDs.contains(rawSSID)
      else {
        continue
      }
      matchingProfiles.append(
        WiFiSavedNetworkProfile(
          rawSSID: rawSSID,
          displaySSID: nonempty(profile.ssid),
          security: securityMode(profile.security),
          preferenceIndex: index
        ))
    }

    return WiFiConfigurationSnapshot(
      rememberJoinedNetworks: configuration.rememberJoinedNetworks,
      requireAdministratorForAssociation: configuration.requireAdministratorForAssociation,
      requireAdministratorForPower: configuration.requireAdministratorForPower,
      requireAdministratorForIBSSMode: configuration.requireAdministratorForIBSSMode,
      preferredProfileCount: preferredProfiles.count,
      matchingProfiles: matchingProfiles
    )
  }

  private static func channelSnapshot(_ channel: CWChannel) -> WiFiChannelSnapshot? {
    let number = Int(channel.channelNumber)
    guard number > 0 else { return nil }
    return WiFiChannelSnapshot(
      number: number,
      band: channelBand(channel.channelBand),
      width: channelWidth(channel.channelWidth)
    )
  }

  private static func channelBand(_ value: CWChannelBand) -> WiFiChannelBand {
    switch value.rawValue {
    case 0: return .unknown
    case 1: return .band2GHz
    case 2: return .band5GHz
    case 3: return .band6GHz
    default: return .other
    }
  }

  private static func channelWidth(_ value: CWChannelWidth) -> WiFiChannelWidth {
    switch value.rawValue {
    case 0: return .unknown
    case 1: return .width20MHz
    case 2: return .width40MHz
    case 3: return .width80MHz
    case 4: return .width160MHz
    default: return .other
    }
  }

  private static func interfaceMode(_ value: CWInterfaceMode) -> WiFiInterfaceMode {
    switch value.rawValue {
    case 0: return .none
    case 1: return .station
    case 2: return .ibss
    case 3: return .hostAP
    default: return .other
    }
  }

  private static func phyMode(_ value: CWPHYMode) -> WiFiPHYMode {
    switch value.rawValue {
    case 0: return .none
    case 1: return .mode11a
    case 2: return .mode11b
    case 3: return .mode11g
    case 4: return .mode11n
    case 5: return .mode11ac
    case 6: return .mode11ax
    case 7: return .mode11be
    default: return .other
    }
  }

  private static func securityMode(_ value: CWSecurity) -> WiFiSecurityMode {
    switch value.rawValue {
    case 0: return .none
    case 1: return .wep
    case 2: return .wpaPersonal
    case 3: return .wpaPersonalMixed
    case 4: return .wpa2Personal
    case 5: return .personal
    case 6: return .dynamicWEP
    case 7: return .wpaEnterprise
    case 8: return .wpaEnterpriseMixed
    case 9: return .wpa2Enterprise
    case 10: return .enterprise
    case 11: return .wpa3Personal
    case 12: return .wpa3Enterprise
    case 13: return .wpa3Transition
    case 14: return .owe
    case 15: return .oweTransition
    case CWSecurity.unknown.rawValue: return .unknown
    default: return .other
    }
  }

  private static func channelComesBefore(
    _ left: WiFiChannelSnapshot,
    _ right: WiFiChannelSnapshot
  ) -> Bool {
    let leftKey = (channelBandSortOrder(left.band), left.number, channelWidthSortOrder(left.width))
    let rightKey =
      (channelBandSortOrder(right.band), right.number, channelWidthSortOrder(right.width))
    return leftKey < rightKey
  }

  private static func channelBandSortOrder(_ band: WiFiChannelBand) -> Int {
    switch band {
    case .band2GHz: return 0
    case .band5GHz: return 1
    case .band6GHz: return 2
    case .unknown: return 3
    case .other: return 4
    }
  }

  private static func channelWidthSortOrder(_ width: WiFiChannelWidth) -> Int {
    switch width {
    case .width20MHz: return 0
    case .width40MHz: return 1
    case .width80MHz: return 2
    case .width160MHz: return 3
    case .unknown: return 4
    case .other: return 5
    }
  }

  private static func nonempty(_ value: String?) -> String? {
    guard let value, !value.isEmpty else { return nil }
    return value
  }

  private func requireCurrentSSID(_ expected: RawSSID, on interface: CWInterface) throws {
    guard let currentValue = interface.ssidData(),
      let currentData = ownedData(currentValue as NSData?),
      let current = RawSSID(data: currentData),
      current == expected
    else {
      throw WiFiOperationError.currentSSIDChanged
    }
  }

  private func resolveNetwork(_ target: NetworkTarget, on interface: CWInterface) throws
    -> CWNetwork
  {
    let scanned = try interface.scanForNetworks(withSSID: target.ssid.data)
    guard let network = scanned.first(where: { NetworkTarget(network: $0) == target }) else {
      throw WiFiOperationError.targetNotFound
    }
    return network
  }

  private func verifyPublicAssociation(
    on interface: CWInterface,
    expected: BSSID
  ) throws -> ConnectionOutcome {
    var actual = interface.bssid().flatMap(BSSID.init)
    for _ in 0..<10 where actual != expected {
      usleep(250_000)
      actual = interface.bssid().flatMap(BSSID.init)
    }
    guard actual == expected else {
      throw WiFiOperationError.wrongBSSID(expected: expected, actual: actual)
    }
    return ConnectionOutcome(currentBSSID: actual)
  }

  private func verifyStrictAssociation(
    on interface: CWInterface,
    expected: BSSID
  ) throws -> ConnectionOutcome {
    let checkpoints: [TimeInterval] = [0.5, 2.0, 10.0]
    var previousCheckpoint: TimeInterval = 0
    var samples: [BSSIDVerificationSample] = []

    for checkpoint in checkpoints {
      Thread.sleep(forTimeInterval: checkpoint - previousCheckpoint)
      previousCheckpoint = checkpoint
      let actual = interface.bssid().flatMap(BSSID.init)
      samples.append(BSSIDVerificationSample(elapsed: checkpoint, bssid: actual))

      // The first observation can still be the stale pre-association
      // state. At two seconds the target must be established, and at ten
      // seconds it must still be the associated access point.
      if checkpoint >= 2.0, actual != expected {
        throw WiFiOperationError.strictVerificationFailed(
          expected: expected,
          samples: samples
        )
      }
    }
    return ConnectionOutcome(
      currentBSSID: samples.last?.bssid,
      verificationSamples: samples
    )
  }

  private func submit<Value>(
    completion: @escaping Completion<Value>,
    operation: @escaping () throws -> Value
  ) {
    queue.async {
      let result = Result(catching: operation)
      DispatchQueue.main.async {
        completion(result)
      }
    }
  }

  private static func strongestFirst(_ left: AccessPoint, _ right: AccessPoint) -> Bool {
    if left.rssi != right.rssi { return left.rssi > right.rssi }
    return left.reportedBSSID.localizedCaseInsensitiveCompare(right.reportedBSSID)
      == .orderedAscending
  }

  private static func displayNameThenSignal(_ left: AccessPoint, _ right: AccessPoint) -> Bool {
    let nameOrder = left.displaySSID.localizedCaseInsensitiveCompare(right.displaySSID)
    if nameOrder != .orderedSame { return nameOrder == .orderedAscending }
    return strongestFirst(left, right)
  }
}
