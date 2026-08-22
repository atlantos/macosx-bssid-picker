// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// The byte-exact identity of an SSID. Display names are deliberately not used
/// for matching because distinct SSIDs need not have distinct UTF-8 renderings.
struct RawSSID: Hashable, Codable {
  private let storage: Data

  init?(data: Data) {
    guard (1...32).contains(data.count) else { return nil }
    storage = data.withUnsafeBytes { Data($0) }
  }

  var data: Data {
    storage.withUnsafeBytes { Data($0) }
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let data = try container.decode(Data.self)
    guard let value = RawSSID(data: data) else {
      throw DecodingError.dataCorruptedError(
        in: container,
        debugDescription: "An SSID must contain between 1 and 32 bytes."
      )
    }
    self = value
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(storage)
  }
}

/// A validated, canonical IEEE 802 MAC address used as a Wi-Fi BSSID.
struct BSSID: Hashable, Codable, CustomStringConvertible {
  let rawValue: String

  init?(_ value: String) {
    let normalized = value.lowercased().replacingOccurrences(of: "-", with: ":")
    let octets = normalized.split(separator: ":", omittingEmptySubsequences: false)
    guard octets.count == 6,
      octets.allSatisfy({ $0.count == 2 && UInt8($0, radix: 16) != nil })
    else {
      return nil
    }
    rawValue = normalized
  }

  var description: String { rawValue }

  init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    let value = try container.decode(String.self)
    guard let bssid = BSSID(value) else {
      throw DecodingError.dataCorruptedError(
        in: container,
        debugDescription: "A BSSID must contain six hexadecimal octets."
      )
    }
    self = bssid
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(rawValue)
  }
}

struct NetworkTarget: Hashable, Codable {
  let ssid: RawSSID
  let bssid: BSSID
}

enum NetworkAuthentication: String, Codable {
  case passwordless
  case personal
  case legacyWEP
  case enterprise
  case unknown

  var canAssociate: Bool {
    self == .passwordless || self == .personal || self == .legacyWEP
  }

  var associationLimitation: String? {
    switch self {
    case .enterprise:
      return "Enterprise/802.1X association is not supported by this utility."
    case .unknown:
      return "This network's authentication type is unknown or ambiguous."
    case .passwordless, .personal, .legacyWEP:
      return nil
    }
  }
}

/// An immutable copy of everything the UI needs from a transient CWNetwork.
struct AccessPoint {
  let target: NetworkTarget?
  let displaySSID: String
  let rawSSID: RawSSID?
  let bssid: BSSID?
  let reportedBSSID: String
  let channelNumber: Int?
  let channelWidth: String
  let band: String
  let rssi: Int
  let noise: Int
  let countryCode: String
  let beaconInterval: Int
  let isIBSS: Bool
  let phyModes: String
  let security: String
  let authentication: NetworkAuthentication
  let informationElements: Data?

  var channel: String { channelNumber.map(String.init) ?? "?" }
  var ssidHex: String { rawSSID.map { hexString($0.data) } ?? "" }
  var canAssociate: Bool { target != nil && authentication.canAssociate }
  var associationLimitation: String? { authentication.associationLimitation }
}

struct CurrentScanSnapshot {
  let capturedAt: Date
  let displaySSID: String
  let ssid: RawSSID
  let currentBSSID: BSSID?
  let accessPoints: [AccessPoint]
}

enum WiFiChannelBand: String, Codable, Equatable {
  case unknown = "Unknown"
  case band2GHz = "2.4 GHz"
  case band5GHz = "5 GHz"
  case band6GHz = "6 GHz"
  case other = "Other"
}

enum WiFiChannelWidth: String, Codable, Equatable {
  case unknown = "Unknown"
  case width20MHz = "20 MHz"
  case width40MHz = "40 MHz"
  case width80MHz = "80 MHz"
  case width160MHz = "160 MHz"
  case other = "Other"
}

struct WiFiChannelSnapshot: Codable, Equatable {
  let number: Int
  let band: WiFiChannelBand
  let width: WiFiChannelWidth
}

enum WiFiInterfaceMode: String, Codable, Equatable {
  case none = "None"
  case station = "Station"
  case ibss = "IBSS"
  case hostAP = "Host AP"
  case other = "Other"
}

enum WiFiPHYMode: String, Codable, Equatable {
  case none = "None"
  case mode11a = "802.11a"
  case mode11b = "802.11b"
  case mode11g = "802.11g"
  case mode11n = "802.11n"
  case mode11ac = "802.11ac"
  case mode11ax = "802.11ax"
  case mode11be = "802.11be"
  case other = "Other"
}

enum WiFiSecurityMode: String, Codable, Equatable {
  case none = "Open"
  case wep = "WEP"
  case wpaPersonal = "WPA Personal"
  case wpaPersonalMixed = "WPA/WPA2 Personal"
  case wpa2Personal = "WPA2 Personal"
  case personal = "Personal"
  case dynamicWEP = "Dynamic WEP"
  case wpaEnterprise = "WPA Enterprise"
  case wpaEnterpriseMixed = "WPA/WPA2 Enterprise"
  case wpa2Enterprise = "WPA2 Enterprise"
  case enterprise = "Enterprise"
  case wpa3Personal = "WPA3 Personal"
  case wpa3Enterprise = "WPA3 Enterprise"
  case wpa3Transition = "WPA2/WPA3 Personal"
  case owe = "Enhanced Open (OWE)"
  case oweTransition = "Enhanced Open Transition"
  case unknown = "Unknown"
  case other = "Other"
}

/// A preferred-network entry is included only when its exact raw SSID also
/// occurs in the current scan. This prevents scanner diagnostics from exposing
/// the names of unrelated saved networks.
struct WiFiSavedNetworkProfile: Codable, Equatable {
  let rawSSID: RawSSID
  let displaySSID: String?
  let security: WiFiSecurityMode

  /// Zero-based position in CoreWLAN's preferred-network ordering.
  let preferenceIndex: Int
}

struct WiFiConfigurationSnapshot: Codable, Equatable {
  let rememberJoinedNetworks: Bool
  let requireAdministratorForAssociation: Bool
  let requireAdministratorForPower: Bool
  let requireAdministratorForIBSSMode: Bool
  let preferredProfileCount: Int
  let matchingProfiles: [WiFiSavedNetworkProfile]
}

/// Immutable public CoreWLAN state captured immediately after an all-network
/// scan. Nil measurements mean CoreWLAN did not provide a meaningful value;
/// zero-valued association measurements are not presented as real telemetry.
struct WiFiInterfaceSnapshot: Codable, Equatable {
  let capturedAt: Date
  let availableInterfaceNames: [String]
  let interfaceName: String?
  let isPowerOn: Bool
  let isServiceActive: Bool
  let interfaceMode: WiFiInterfaceMode
  let hardwareAddress: String?
  let countryCode: String?
  let activePHYMode: WiFiPHYMode
  let currentChannel: WiFiChannelSnapshot?
  let currentAssociation: CurrentAssociation?
  let rssi: Int?
  let noise: Int?
  let snr: Int?
  let security: WiFiSecurityMode?
  let transmitRateMbps: Double?
  let transmitPowerMilliwatts: Int?
  let supportedChannels: [WiFiChannelSnapshot]
  let configuration: WiFiConfigurationSnapshot?
}

struct AllScanSnapshot {
  let capturedAt: Date
  let currentAssociation: CurrentAssociation?
  let accessPoints: [AccessPoint]
  let interfaceSnapshot: WiFiInterfaceSnapshot
}

struct CurrentAssociation: Codable, Equatable {
  let displaySSID: String
  let ssid: RawSSID
  let bssid: BSSID?
}

struct ConnectionOutcome {
  let currentBSSID: BSSID?
  let verificationSamples: [BSSIDVerificationSample]

  init(currentBSSID: BSSID?, verificationSamples: [BSSIDVerificationSample] = []) {
    self.currentBSSID = currentBSSID
    self.verificationSamples = verificationSamples
  }
}

struct BSSIDVerificationSample: Codable, Equatable {
  let elapsed: TimeInterval
  let bssid: BSSID?
}

enum CredentialPolicy {
  /// Search only the per-user Wi-Fi credential domain. If that cannot supply
  /// a password, the caller must obtain explicit consent before retrying.
  case userKeychainOnly

  /// Search the System Wi-Fi credential domain after the per-user lookup.
  /// The application is responsible for obtaining consent before using this.
  case includeSystemKeychain
}

enum CredentialSource: String {
  case user = "login or iCloud Keychain"
  case system = "System Keychain"
}

enum WiFiOperationError: LocalizedError {
  case noInterface
  case notConnected
  case invalidSSIDData
  case systemKeychainConsentRequired(userLookupInterrupted: Bool)
  case credentialReadFailed(source: CredentialSource, status: Int32, detail: String?)
  case emptyCredential(source: CredentialSource)
  case enterpriseUnsupported
  case unknownSecurity
  case strictWEPUnsupported
  case targetNotFound
  case currentSSIDChanged
  case wrongBSSID(expected: BSSID, actual: BSSID?)
  case strictBackendUnavailable(underlying: Error?)
  case strictCredentialDelegationUnavailable(underlying: Error?)
  case strictAssociationFailed(underlying: Error?)
  case strictVerificationFailed(expected: BSSID, samples: [BSSIDVerificationSample])

  var errorDescription: String? {
    switch self {
    case .noInterface:
      return "No Wi-Fi interface is available."
    case .notConnected:
      return "The Mac is not connected to Wi-Fi."
    case .invalidSSIDData:
      return "The Wi-Fi interface returned invalid raw SSID data."
    case .systemKeychainConsentRequired(let userLookupInterrupted):
      if userLookupInterrupted {
        return "The login or iCloud Wi-Fi credential service was interrupted."
      }
      return "The Wi-Fi password was not found in your login or iCloud Keychain."
    case .credentialReadFailed(let source, let status, let detail):
      let suffix = detail.map { " \($0)" } ?? ""
      return
        "The saved Wi-Fi password could not be read from the \(source.rawValue) (OSStatus \(status)).\(suffix)"
    case .emptyCredential(let source):
      return "The \(source.rawValue) returned an empty Wi-Fi password."
    case .enterpriseUnsupported:
      return "Enterprise/802.1X association is not supported by this utility."
    case .unknownSecurity:
      return "The access point has an unknown or ambiguous security type."
    case .strictWEPUnsupported:
      return
        "Experimental Strict BSSID does not support WEP networks. Use ordinary CoreWLAN mode for this network."
    case .targetNotFound:
      return "The selected BSSID was not found in the latest scan."
    case .currentSSIDChanged:
      return
        "The currently connected raw SSID changed after this target was scanned. Refresh the menu and select a BSSID from the current network."
    case .wrongBSSID(let expected, let actual):
      return
        "macOS joined \(actual?.rawValue ?? "an unknown BSSID") instead of the requested BSSID \(expected.rawValue). CoreWLAN did not honor the selected access point, and its public API provides no stronger BSSID pin."
    case .strictBackendUnavailable(let underlying):
      let detail = underlying.map { " \($0.localizedDescription)" } ?? ""
      return
        "Experimental Strict BSSID is unavailable on this macOS release. The connection was not attempted with ordinary CoreWLAN.\(detail)"
    case .strictCredentialDelegationUnavailable(let underlying):
      let detail = underlying.map { " \($0.localizedDescription)" } ?? ""
      return
        "Experimental Strict BSSID could not delegate this network's saved credential to airportd. BSSID Picker did not request or read the Wi-Fi password.\(detail)"
    case .strictAssociationFailed(let underlying):
      let detail = underlying.map { " \($0.localizedDescription)" } ?? ""
      return
        "The experimental Strict BSSID association failed. The utility did not fall back to another same-SSID access point.\(detail)"
    case .strictVerificationFailed(let expected, let samples):
      let observations = samples.map {
        "\(String(format: "%.1f", $0.elapsed))s=\($0.bssid?.rawValue ?? "not associated")"
      }.joined(separator: ", ")
      return
        "Strict BSSID verification did not remain on \(expected.rawValue) (\(observations)). The result is treated as a failed connection, not a successful same-SSID fallback."
    }
  }
}

private func hexString(_ data: Data) -> String {
  data.map { String(format: "%02X", $0) }.joined(separator: " ")
}
