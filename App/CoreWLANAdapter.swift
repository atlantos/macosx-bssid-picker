// SPDX-License-Identifier: GPL-3.0-only

import CoreWLAN
import Foundation

extension NetworkTarget {
  init?(network: CWNetwork) {
    guard let ssidData = ownedData(network.ssidData as NSData?),
      let ssid = RawSSID(data: ssidData),
      let bssidString = network.bssid,
      let bssid = BSSID(bssidString)
    else {
      return nil
    }
    self.init(ssid: ssid, bssid: bssid)
  }
}

extension AccessPoint {
  init(network: CWNetwork) {
    let copiedSSIDData = ownedData(network.ssidData as NSData?)
    let rawSSID = copiedSSIDData.flatMap(RawSSID.init(data:))
    let bssid = network.bssid.flatMap(BSSID.init)

    self.target = rawSSID.flatMap { ssid in
      bssid.map { NetworkTarget(ssid: ssid, bssid: $0) }
    }
    if copiedSSIDData?.isEmpty == true || network.ssid?.isEmpty == true {
      self.displaySSID = "<hidden SSID>"
    } else if let displaySSID = network.ssid {
      self.displaySSID = displaySSID
    } else {
      self.displaySSID = copiedSSIDData == nil ? "<hidden SSID>" : "<non-text SSID>"
    }
    self.rawSSID = rawSSID
    self.bssid = bssid
    self.reportedBSSID = network.bssid ?? "<unavailable>"
    self.channelNumber = network.wlanChannel.map { Int($0.channelNumber) }

    if let channel = network.wlanChannel {
      switch channel.channelWidth {
      case .widthUnknown: self.channelWidth = "?"
      case .width20MHz: self.channelWidth = "20 MHz"
      case .width40MHz: self.channelWidth = "40 MHz"
      case .width80MHz: self.channelWidth = "80 MHz"
      case .width160MHz: self.channelWidth = "160 MHz"
      @unknown default: self.channelWidth = "Other"
      }

      switch channel.channelBand {
      case .bandUnknown: self.band = "?"
      case .band2GHz: self.band = "2.4 GHz"
      case .band5GHz: self.band = "5 GHz"
      case .band6GHz: self.band = "6 GHz"
      @unknown default: self.band = "Other"
      }
    } else {
      self.channelWidth = "?"
      self.band = "?"
    }

    self.rssi = network.rssiValue
    self.noise = network.noiseMeasurement
    self.countryCode = network.countryCode ?? "?"
    self.beaconInterval = network.beaconInterval
    self.isIBSS = network.ibss
    self.phyModes = Self.phyModeLabels(for: network).joined(separator: ", ")
    self.security = Self.securityLabels(for: network).joined(separator: ", ")
    self.authentication = Self.authentication(for: network)
    self.informationElements = ownedData(network.informationElementData as NSData?)
  }

  private static func phyModeLabels(for network: CWNetwork) -> [String] {
    var modes: [(CWPHYMode, String)] = [
      (.mode11a, "802.11a"),
      (.mode11b, "802.11b"),
      (.mode11g, "802.11g"),
      (.mode11n, "802.11n"),
      (.mode11ac, "802.11ac"),
      (.mode11ax, "802.11ax"),
    ]
    if let mode11be = CWPHYMode(rawValue: 7) {
      modes.append((mode11be, "802.11be"))
    }
    return modes.compactMap { network.supportsPHYMode($0.0) ? $0.1 : nil }
  }

  private static func securityLabels(for network: CWNetwork) -> [String] {
    let securityTypes: [(CWSecurity, String)] = [
      (.none, "Open"),
      (.WEP, "WEP"),
      (.wpaPersonal, "WPA Personal"),
      (.wpaPersonalMixed, "WPA/WPA2 Personal"),
      (.wpa2Personal, "WPA2 Personal"),
      (.personal, "Personal"),
      (.dynamicWEP, "Dynamic WEP"),
      (.wpaEnterprise, "WPA Enterprise"),
      (.wpaEnterpriseMixed, "WPA/WPA2 Enterprise"),
      (.wpa2Enterprise, "WPA2 Enterprise"),
      (.enterprise, "Enterprise"),
      (.wpa3Personal, "WPA3 Personal"),
      (.wpa3Enterprise, "WPA3 Enterprise"),
      (.wpa3Transition, "WPA2/WPA3 Personal"),
      (.OWE, "Enhanced Open (OWE)"),
      (.oweTransition, "Enhanced Open Transition"),
      (.unknown, "Unknown"),
    ]
    let labels = securityTypes.compactMap { security, label in
      network.supportsSecurity(security) ? label : nil
    }
    return labels.isEmpty ? ["Unknown"] : labels
  }

  /// Classifies authentication conservatively. If CoreWLAN reports an
  /// unknown flag or flags spanning more than one credential family, the
  /// result is unknown and association is refused.
  static func authentication(for network: CWNetwork) -> NetworkAuthentication {
    if network.supportsSecurity(.unknown) {
      return .unknown
    }

    let enterpriseTypes: [CWSecurity] = [
      .dynamicWEP,
      .wpaEnterprise,
      .wpaEnterpriseMixed,
      .wpa2Enterprise,
      .enterprise,
      .wpa3Enterprise,
    ]
    let personalTypes: [CWSecurity] = [
      .wpaPersonal,
      .wpaPersonalMixed,
      .wpa2Personal,
      .personal,
      .wpa3Personal,
      .wpa3Transition,
    ]
    let passwordlessTypes: [CWSecurity] = [.none, .OWE, .oweTransition]

    let hasEnterprise = enterpriseTypes.contains { network.supportsSecurity($0) }
    let hasWEP = network.supportsSecurity(.WEP)
    let hasPersonal = personalTypes.contains { network.supportsSecurity($0) }
    let hasPasswordless = passwordlessTypes.contains { network.supportsSecurity($0) }
    let familyCount = [hasEnterprise, hasWEP, hasPersonal, hasPasswordless].filter { $0 }.count

    guard familyCount == 1 else { return .unknown }
    if hasEnterprise { return .enterprise }
    if hasWEP { return .legacyWEP }
    if hasPersonal { return .personal }
    return .passwordless
  }
}

func ownedData(_ source: NSData?) -> Data? {
  guard let source else { return nil }
  return Data(bytes: source.bytes, count: source.length)
}
