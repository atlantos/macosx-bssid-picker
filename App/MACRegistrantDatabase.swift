// SPDX-License-Identifier: GPL-3.0-only

import Foundation

// MARK: - Scanner-facing attribution

enum MACAddressType: String, Codable, Equatable {
  case globallyAdministered = "Globally Administered"
  case locallyAdministered = "Locally Administered"
  case groupAddress = "Group Address"
  case invalidAddress = "Invalid Address"
}

enum MACAllocation: String, Codable, Equatable {
  case maL = "MA-L"
  case maM = "MA-M"
  // Wireshark's generated manuf file does not distinguish historical IAB
  // assignments from MA-S assignments. Do not claim more precision than the
  // downloaded source provides.
  case maSOrIAB = "MA-S / IAB"
}

enum MACDatabaseAgreement: String, Codable, Equatable {
  case ambiguousRegistryRecords = "Ambiguous Registry Records"
}

enum MACRegistrationSource: String, Codable, Equatable {
  case ieeeRegistryViaWireshark = "IEEE Registry via Wireshark"
}

struct MACRegistrantClaim: Equatable {
  let organization: String
  let source: MACRegistrationSource
}

/// A complete, presentation-ready result. The Wireshark abbreviation in
/// column two of `manuf` is intentionally not exposed: it is an algorithmic
/// abbreviation, not a second registrant claim.
struct MACAddressAttribution: Equatable {
  let addressType: MACAddressType
  let registeredOrganization: String?
  let allocation: MACAllocation?
  let matchedPrefix: String?
  let registrationSource: MACRegistrationSource?
  let databaseAgreement: MACDatabaseAgreement?
  let knownAddressRole: String?
  let registryClaims: [MACRegistrantClaim]
  let isDatabaseUnavailable: Bool
  let isPrivateRegistration: Bool

  var registrantDisplayName: String {
    switch addressType {
    case .invalidAddress:
      return "Unavailable"
    case .locallyAdministered:
      return "Locally Administered"
    case .groupAddress:
      return "Group Address"
    case .globallyAdministered:
      if isDatabaseUnavailable { return "—" }
      if databaseAgreement == .ambiguousRegistryRecords {
        return "Ambiguous Registration"
      }
      if isPrivateRegistration { return "Private Registration" }
      return registeredOrganization ?? "Not Found"
    }
  }

  var addressTypeDisplayName: String { addressType.rawValue }
  var allocationDisplayName: String? { allocation?.rawValue }
  var registrationSourceDisplayName: String? { registrationSource?.rawValue }
  var databaseAgreementDisplayName: String? { databaseAgreement?.rawValue }

  var accessibilityDescription: String {
    if isDatabaseUnavailable && addressType == .globallyAdministered {
      return "Download the MAC registrant database in Settings."
    }
    var parts = [registrantDisplayName]
    if addressTypeDisplayName != registrantDisplayName {
      parts.append(addressTypeDisplayName)
    }
    if let allocationDisplayName { parts.append(allocationDisplayName) }
    if let matchedPrefix { parts.append("prefix \(matchedPrefix)") }
    if let knownAddressRole { parts.append("known role \(knownAddressRole)") }
    switch databaseAgreement {
    case .ambiguousRegistryRecords:
      parts.append("Multiple registry records disagree for the same MAC prefix")
    case nil:
      break
    }
    return parts.joined(separator: ", ")
  }
}

// MARK: - Immutable resolver

/// A value-semantic lookup snapshot. It contains no mutable service state and
/// is safe to capture for synchronous lookup on a scanner background queue.
struct MACRegistrantResolver {
  fileprivate let registrants: [Int: [UInt64: [RegistrantRecord]]]
  fileprivate let knownAddresses: [Int: [UInt64: [String]]]
  fileprivate let knownAddressPrefixLengths: [Int]
  let metadata: MACRegistrantDatabaseMetadata?

  static let unavailable = MACRegistrantResolver(
    registrants: [:],
    knownAddresses: [:],
    knownAddressPrefixLengths: [],
    metadata: nil
  )

  var isDatabaseAvailable: Bool { metadata != nil }

  fileprivate var manufacturerRecordCount: Int {
    registrants.values.reduce(0) { partial, prefixes in
      partial + prefixes.values.reduce(0) { $0 + $1.count }
    }
  }

  fileprivate var knownAddressRecordCount: Int {
    knownAddresses.values.reduce(0) { partial, prefixes in
      partial + prefixes.values.reduce(0) { $0 + $1.count }
    }
  }

  fileprivate func withMetadata(
    _ metadata: MACRegistrantDatabaseMetadata
  ) -> MACRegistrantResolver {
    MACRegistrantResolver(
      registrants: registrants,
      knownAddresses: knownAddresses,
      knownAddressPrefixLengths: knownAddressPrefixLengths,
      metadata: metadata
    )
  }

  func resolve(_ bssid: BSSID?) -> MACAddressAttribution {
    guard let bssid, let address = MACAddressValue(bssid.rawValue) else {
      return attribution(addressType: .invalidAddress, address: nil)
    }
    return attribution(addressType: address.addressType, address: address)
  }

  private func attribution(
    addressType: MACAddressType,
    address: MACAddressValue?
  ) -> MACAddressAttribution {
    let knownRole = address.flatMap(longestKnownAddressMatch)
    guard addressType == .globallyAdministered else {
      return MACAddressAttribution(
        addressType: addressType,
        registeredOrganization: nil,
        allocation: nil,
        matchedPrefix: nil,
        registrationSource: nil,
        databaseAgreement: nil,
        knownAddressRole: knownRole,
        registryClaims: [],
        isDatabaseUnavailable: !isDatabaseAvailable,
        isPrivateRegistration: false
      )
    }

    guard isDatabaseAvailable, let address else {
      return MACAddressAttribution(
        addressType: addressType,
        registeredOrganization: nil,
        allocation: nil,
        matchedPrefix: nil,
        registrationSource: nil,
        databaseAgreement: nil,
        knownAddressRole: knownRole,
        registryClaims: [],
        isDatabaseUnavailable: true,
        isPrivateRegistration: false
      )
    }

    guard let match = longestRegistrantMatch(address) else {
      return MACAddressAttribution(
        addressType: addressType,
        registeredOrganization: nil,
        allocation: nil,
        matchedPrefix: nil,
        registrationSource: nil,
        databaseAgreement: nil,
        knownAddressRole: knownRole,
        registryClaims: [],
        isDatabaseUnavailable: false,
        isPrivateRegistration: false
      )
    }

    let claims = match.records.map {
      MACRegistrantClaim(
        organization: $0.organization,
        source: .ieeeRegistryViaWireshark
      )
    }
    let ambiguous = claims.count > 1
    let organization = ambiguous ? nil : claims.first?.organization
    return MACAddressAttribution(
      addressType: addressType,
      registeredOrganization: organization,
      allocation: MACAllocation(prefixLength: match.prefix.length),
      matchedPrefix: match.prefix.displayName,
      registrationSource: .ieeeRegistryViaWireshark,
      databaseAgreement: ambiguous ? .ambiguousRegistryRecords : nil,
      knownAddressRole: knownRole,
      registryClaims: claims,
      isDatabaseUnavailable: false,
      isPrivateRegistration: organization.map(Self.isPrivateOrganization) ?? false
    )
  }

  private func longestRegistrantMatch(
    _ address: MACAddressValue
  ) -> (prefix: MACPrefix, records: [RegistrantRecord])? {
    for length in [36, 28, 24] {
      let key = address.value >> UInt64(48 - length)
      guard let records = registrants[length]?[key], !records.isEmpty else { continue }
      return (MACPrefix(key: key, length: length), records)
    }
    return nil
  }

  private func longestKnownAddressMatch(_ address: MACAddressValue) -> String? {
    for length in knownAddressPrefixLengths {
      let key = address.value >> UInt64(48 - length)
      guard let roles = knownAddresses[length]?[key], !roles.isEmpty else { continue }
      return roles.joined(separator: "; ")
    }
    return nil
  }

  private static func isPrivateOrganization(_ organization: String) -> Bool {
    let normalized =
      organization
      .trimmingCharacters(in: .whitespacesAndNewlines)
      .lowercased()
    return normalized == "private" || normalized.hasPrefix("private registration")
  }
}

extension MACAllocation {
  fileprivate init(prefixLength: Int) {
    switch prefixLength {
    case 24: self = .maL
    case 28: self = .maM
    default: self = .maSOrIAB
    }
  }
}

private struct RegistrantRecord: Equatable {
  let organization: String
}

private struct MACPrefix: Hashable {
  let key: UInt64
  let length: Int

  var displayName: String {
    let nibbleCount = (length + 3) / 4
    let padded = String(format: "%012llX", key << UInt64(48 - length))
    let digits = String(padded.prefix(nibbleCount))
    var groups: [String] = []
    var start = digits.startIndex
    while start < digits.endIndex {
      let end = digits.index(start, offsetBy: 2, limitedBy: digits.endIndex) ?? digits.endIndex
      groups.append(String(digits[start..<end]))
      start = end
    }
    return groups.joined(separator: ":") + "/\(length)"
  }
}

private struct MACAddressValue {
  let value: UInt64
  let firstOctet: UInt8

  init?(_ text: String) {
    let pieces = text.split(separator: ":", omittingEmptySubsequences: false)
    guard pieces.count == 6 else { return nil }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(6)
    for piece in pieces {
      guard piece.count == 2, let byte = UInt8(piece, radix: 16) else { return nil }
      bytes.append(byte)
    }
    firstOctet = bytes[0]
    value = bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
  }

  var addressType: MACAddressType {
    if value == 0 { return .invalidAddress }
    if firstOctet & 0x01 != 0 { return .groupAddress }
    if firstOctet & 0x02 != 0 { return .locallyAdministered }
    return .globallyAdministered
  }
}

// MARK: - Parsing and validation

enum MACRegistrantDatabaseParseError: LocalizedError {
  case invalidEncoding(source: String)
  case invalidLine(source: String, line: Int)
  case invalidPrefix(source: String, line: Int)
  case invalidRecordCount(source: String, count: Int)
  case sourceTooLarge(source: String)

  var errorDescription: String? {
    switch self {
    case .invalidEncoding(let source):
      return "The \(source) database is not valid UTF-8 text."
    case .invalidLine(let source, let line):
      return "The \(source) database contains an invalid record at line \(line)."
    case .invalidPrefix(let source, let line):
      return "The \(source) database contains an invalid MAC prefix at line \(line)."
    case .invalidRecordCount(let source, let count):
      return "The \(source) database contains an unexpected number of records (\(count))."
    case .sourceTooLarge(let source):
      return "The \(source) database exceeds the permitted size."
    }
  }
}

enum MACRegistrantDatabaseParser {
  private static let maximumValuesPerPrefix = 64

  /// Builds a resolver from deterministic in-memory regression-test fixtures.
  /// Production downloads use stricter record-count bounds in
  /// `MACRegistrantDatabase`.
  static func resolver(
    manufData: Data,
    wkaData: Data? = nil,
    metadata: MACRegistrantDatabaseMetadata? = nil
  ) throws -> MACRegistrantResolver {
    let effectiveMetadata =
      metadata
      ?? MACRegistrantDatabaseMetadata(
        updatedAt: .distantPast,
        manufacturerRecordCount: 0,
        knownAddressRecordCount: 0,
        sources: []
      )
    return try parse(
      manufData: manufData,
      wkaData: wkaData,
      metadata: effectiveMetadata,
      validation: .permissive
    )
  }

  fileprivate static func parse(
    manufData: Data,
    wkaData: Data?,
    metadata: MACRegistrantDatabaseMetadata?,
    validation: Validation
  ) throws -> MACRegistrantResolver {
    guard manufData.count <= validation.maximumManufBytes else {
      throw MACRegistrantDatabaseParseError.sourceTooLarge(source: "manufacturer")
    }
    let registrants = try parseManuf(manufData)
    let registrantCount = registrants.values.reduce(0) { partial, prefixes in
      partial + prefixes.values.reduce(0) { $0 + $1.count }
    }
    guard validation.manufRecordRange.contains(registrantCount) else {
      throw MACRegistrantDatabaseParseError.invalidRecordCount(
        source: "manufacturer", count: registrantCount)
    }

    var knownAddresses: [Int: [UInt64: [String]]] = [:]
    if let wkaData {
      guard wkaData.count <= validation.maximumWKABytes else {
        throw MACRegistrantDatabaseParseError.sourceTooLarge(source: "well-known-address")
      }
      knownAddresses = try parseWKA(wkaData)
      let count = knownAddresses.values.reduce(0) { partial, prefixes in
        partial + prefixes.values.reduce(0) { $0 + $1.count }
      }
      guard validation.wkaRecordRange.contains(count) else {
        throw MACRegistrantDatabaseParseError.invalidRecordCount(
          source: "well-known-address", count: count)
      }
    }
    return MACRegistrantResolver(
      registrants: registrants,
      knownAddresses: knownAddresses,
      knownAddressPrefixLengths: knownAddresses.keys.sorted(by: >),
      metadata: metadata
    )
  }

  fileprivate struct Validation {
    let maximumManufBytes: Int
    let maximumWKABytes: Int
    let manufRecordRange: ClosedRange<Int>
    let wkaRecordRange: ClosedRange<Int>

    static let permissive = Validation(
      maximumManufBytes: 8 * 1_024 * 1_024,
      maximumWKABytes: 1 * 1_024 * 1_024,
      manufRecordRange: 1...250_000,
      wkaRecordRange: 0...20_000
    )

    static let production = Validation(
      maximumManufBytes: 8 * 1_024 * 1_024,
      maximumWKABytes: 1 * 1_024 * 1_024,
      manufRecordRange: 10_000...250_000,
      wkaRecordRange: 10...20_000
    )
  }

  private static func parseManuf(
    _ data: Data
  ) throws -> [Int: [UInt64: [RegistrantRecord]]] {
    guard let text = String(data: data, encoding: .utf8) else {
      throw MACRegistrantDatabaseParseError.invalidEncoding(source: "manufacturer")
    }
    var result: [Int: [UInt64: [RegistrantRecord]]] = [:]
    try enumerateRecords(in: text, source: "manufacturer") { line, number in
      let fields = tabFields(line, maximum: 3)
      guard fields.count >= 2,
        let prefix = parsePrefix(fields[0], allowedLengths: [24, 28, 36], defaultLength: 24)
      else {
        throw MACRegistrantDatabaseParseError.invalidPrefix(source: "manufacturer", line: number)
      }
      let abbreviation = fields[1]
      let organization = fields.count == 3 ? fields[2] : abbreviation
      guard validLabel(abbreviation), validLabel(organization) else {
        throw MACRegistrantDatabaseParseError.invalidLine(source: "manufacturer", line: number)
      }
      var records = result[prefix.length]?[prefix.key] ?? []
      let record = RegistrantRecord(organization: organization)
      if records.isEmpty {
        records = [record]
      } else {
        let normalized = normalizedOrganization(organization)
        guard !records.contains(where: { normalizedOrganization($0.organization) == normalized })
        else {
          return
        }
        guard records.count < maximumValuesPerPrefix else {
          throw MACRegistrantDatabaseParseError.invalidLine(
            source: "manufacturer", line: number)
        }
        records.append(record)
        records.sort { $0.organization < $1.organization }
      }
      result[prefix.length, default: [:]][prefix.key] = records
    }
    return result
  }

  private static func parseWKA(_ data: Data) throws -> [Int: [UInt64: [String]]] {
    guard let text = String(data: data, encoding: .utf8) else {
      throw MACRegistrantDatabaseParseError.invalidEncoding(source: "well-known-address")
    }
    var result: [Int: [UInt64: [String]]] = [:]
    try enumerateRecords(in: text, source: "well-known-address") { line, number in
      guard let boundary = line.firstIndex(where: { $0 == "\t" || $0 == " " }),
        let prefix = parsePrefix(
          String(line[..<boundary]),
          allowedLengths: Set(1...48),
          defaultLength: nil
        )
      else {
        throw MACRegistrantDatabaseParseError.invalidPrefix(
          source: "well-known-address", line: number)
      }
      let role = String(line[boundary...]).trimmingCharacters(in: .whitespaces)
      guard validLabel(role) else {
        throw MACRegistrantDatabaseParseError.invalidLine(
          source: "well-known-address", line: number)
      }
      var roles = result[prefix.length]?[prefix.key] ?? []
      if !roles.contains(role) {
        guard roles.count < maximumValuesPerPrefix else {
          throw MACRegistrantDatabaseParseError.invalidLine(
            source: "well-known-address", line: number)
        }
        roles.append(role)
        roles.sort()
      }
      result[prefix.length, default: [:]][prefix.key] = roles
    }
    return result
  }

  private static func enumerateRecords(
    in text: String,
    source: String,
    consume: (String, Int) throws -> Void
  ) throws {
    if text.unicodeScalars.contains(where: { $0.value == 0 }) {
      throw MACRegistrantDatabaseParseError.invalidEncoding(source: source)
    }
    for (offset, rawLine) in text.split(
      omittingEmptySubsequences: false,
      whereSeparator: \Character.isNewline
    ).enumerated() {
      let line = rawLine.trimmingCharacters(in: .whitespaces)
      guard !line.isEmpty, !line.hasPrefix("#") else { continue }
      guard line.utf8.count <= 4_096 else {
        throw MACRegistrantDatabaseParseError.invalidLine(source: source, line: offset + 1)
      }
      try consume(line, offset + 1)
    }
  }

  private static func tabFields(_ line: String, maximum: Int) -> [String] {
    let tabSeparated = line.split(separator: "\t", maxSplits: maximum - 1)
      .map { $0.trimmingCharacters(in: .whitespaces) }
    if tabSeparated.count >= 2 { return tabSeparated }
    return line.split(
      maxSplits: maximum - 1,
      whereSeparator: \Character.isWhitespace
    ).map(String.init)
  }

  private static func parsePrefix(
    _ input: String,
    allowedLengths: Set<Int>,
    defaultLength: Int?
  ) -> MACPrefix? {
    let pieces = input.split(separator: "/", omittingEmptySubsequences: false)
    guard pieces.count <= 2 else { return nil }
    let length: Int
    if pieces.count == 2 {
      guard let parsed = Int(pieces[1]), allowedLengths.contains(parsed) else { return nil }
      length = parsed
    } else {
      guard let inferred = defaultLength ?? inferredPrefixLength(from: pieces[0]),
        allowedLengths.contains(inferred)
      else { return nil }
      length = inferred
    }
    let addressPart = pieces[0]
    guard addressPart.allSatisfy({ $0.isHexDigit || $0 == ":" || $0 == "-" || $0 == "." })
    else { return nil }
    let digits = addressPart.filter(\Character.isHexDigit)
    // WKA represents values such as 01-00-5E/25 with the final prefix bit
    // implicitly zero. Require all complete prefix bytes, then zero-fill at
    // most the remaining seven bits.
    let requiredWholeByteNibbles = (length / 8) * 2
    guard digits.count >= requiredWholeByteNibbles, digits.count <= 12,
      let value = UInt64(digits, radix: 16)
    else { return nil }
    let aligned = value << UInt64((12 - digits.count) * 4)
    let hostBits = 48 - length
    let key = aligned >> UInt64(hostBits)
    // Reject a supplied host portion rather than silently changing the record.
    let hostMask = (UInt64(1) << UInt64(hostBits)) - 1
    guard aligned & hostMask == 0 else { return nil }
    return MACPrefix(key: key, length: length)
  }

  private static func inferredPrefixLength(from addressPart: Substring) -> Int? {
    let digitCount = addressPart.filter(\Character.isHexDigit).count
    guard (1...12).contains(digitCount), digitCount.isMultiple(of: 2) else { return nil }
    return digitCount * 4
  }

  private static func validLabel(_ label: String) -> Bool {
    guard !label.isEmpty, label.utf8.count <= 512 else { return false }
    // Registry names contain legitimate Unicode format characters. Reject
    // only ASCII control bytes, which cannot be meaningful presentation text.
    return !label.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7F }
  }

  private static func normalizedOrganization(_ name: String) -> String {
    name.folding(
      options: [.caseInsensitive, .diacriticInsensitive],
      locale: Locale(identifier: "en_US_POSIX")
    )
    .unicodeScalars
    .filter(CharacterSet.alphanumerics.contains)
    .map(String.init)
    .joined()
  }
}

// MARK: - Persistence and updating

struct MACRegistrantDatabaseSourceMetadata: Codable, Equatable {
  let name: String
  let sourceURL: URL
  let purpose: String
  let license: String
  let licenseURL: URL
  let attribution: String
}

struct MACRegistrantDatabaseMetadata: Codable, Equatable {
  let updatedAt: Date
  let manufacturerRecordCount: Int
  let knownAddressRecordCount: Int
  let sources: [MACRegistrantDatabaseSourceMetadata]
}

enum MACRegistrantDatabaseState: Equatable {
  case notDownloaded
  case ready(MACRegistrantDatabaseMetadata)
  case downloading(previous: MACRegistrantDatabaseMetadata?)
  case validating(previous: MACRegistrantDatabaseMetadata?)
  case installing(previous: MACRegistrantDatabaseMetadata?)
  case updateFailed(message: String, previous: MACRegistrantDatabaseMetadata?)

  var databaseMetadata: MACRegistrantDatabaseMetadata? {
    switch self {
    case .ready(let metadata): return metadata
    case .downloading(let previous), .validating(let previous), .installing(let previous),
      .updateFailed(_, let previous):
      return previous
    case .notDownloaded: return nil
    }
  }

  var isBusy: Bool {
    switch self {
    case .downloading, .validating, .installing: return true
    case .notDownloaded, .ready, .updateFailed: return false
    }
  }
}

enum MACRegistrantDatabaseError: LocalizedError {
  case updateAlreadyInProgress
  case updateTooSoon
  case invalidResponse(source: String)
  case downloadFailed(source: String, underlying: Error)
  case persistenceFailed(underlying: Error)
  case parsingFailed(underlying: Error)

  var errorDescription: String? {
    switch self {
    case .updateAlreadyInProgress:
      return "A MAC registrant database update is already in progress."
    case .updateTooSoon:
      return "The MAC registrant database can be updated no more than once per week."
    case .invalidResponse(let source):
      return "The \(source) database server returned an invalid response."
    case .downloadFailed(let source, let underlying):
      return "The \(source) database could not be downloaded. \(underlying.localizedDescription)"
    case .persistenceFailed(let underlying):
      return "The MAC registrant database could not be stored. \(underlying.localizedDescription)"
    case .parsingFailed(let underlying):
      return "The downloaded MAC registrant database is invalid. \(underlying.localizedDescription)"
    }
  }
}

/// URLSession's completion-handler API buffers an arbitrarily large response
/// before the caller can validate it. This delegate enforces the source limit
/// while bytes arrive and cancels immediately when the bound is crossed.
private final class BoundedHTTPSDataDownload: NSObject, URLSessionDataDelegate,
  @unchecked Sendable
{
  private let source: MACRegistrantDatabaseSourceMetadata
  private let maximumBytes: Int
  private let configuration: URLSessionConfiguration
  private var completion: ((Result<Data, Error>) -> Void)?
  private var received = Data()
  private var downloadSession: URLSession?

  init(
    source: MACRegistrantDatabaseSourceMetadata,
    maximumBytes: Int,
    configuration: URLSessionConfiguration,
    completion: @escaping (Result<Data, Error>) -> Void
  ) {
    self.source = source
    self.maximumBytes = maximumBytes
    self.configuration = configuration
    self.completion = completion
  }

  func start() {
    let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
    downloadSession = session
    var request = URLRequest(url: source.sourceURL)
    request.httpMethod = "GET"
    request.cachePolicy = .reloadIgnoringLocalCacheData
    request.timeoutInterval = 60
    request.setValue("text/plain", forHTTPHeaderField: "Accept")
    session.dataTask(with: request).resume()
  }

  func urlSession(
    _ session: URLSession,
    dataTask: URLSessionDataTask,
    didReceive response: URLResponse,
    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
  ) {
    guard let http = response as? HTTPURLResponse,
      http.statusCode == 200,
      http.url?.scheme?.lowercased() == "https",
      http.url?.host?.lowercased() == source.sourceURL.host?.lowercased(),
      response.expectedContentLength <= 0
        || response.expectedContentLength <= Int64(maximumBytes)
    else {
      completionHandler(.cancel)
      finish(.failure(MACRegistrantDatabaseError.invalidResponse(source: source.name)))
      return
    }
    completionHandler(.allow)
  }

  func urlSession(
    _ session: URLSession,
    dataTask: URLSessionDataTask,
    didReceive data: Data
  ) {
    guard completion != nil else { return }
    guard data.count <= maximumBytes - received.count else {
      dataTask.cancel()
      finish(.failure(MACRegistrantDatabaseError.invalidResponse(source: source.name)))
      return
    }
    received.append(data)
  }

  func urlSession(
    _ session: URLSession,
    task: URLSessionTask,
    didCompleteWithError error: Error?
  ) {
    guard completion != nil else { return }
    if let error {
      finish(
        .failure(
          MACRegistrantDatabaseError.downloadFailed(
            source: source.name,
            underlying: error
          )))
    } else if received.isEmpty {
      finish(.failure(MACRegistrantDatabaseError.invalidResponse(source: source.name)))
    } else {
      finish(.success(received))
    }
  }

  private func finish(_ result: Result<Data, Error>) {
    guard let completion else { return }
    self.completion = nil
    completion(result)
    downloadSession?.invalidateAndCancel()
    downloadSession = nil
  }
}

final class MACRegistrantDatabase {
  static let minimumUpdateInterval: TimeInterval = 7 * 24 * 60 * 60

  static let manufacturerSource = MACRegistrantDatabaseSourceMetadata(
    name: "Wireshark Manufacturer Database",
    sourceURL: URL(string: "https://www.wireshark.org/download/automated/data/manuf")!,
    purpose: "MAC prefix registration",
    license: "GPL-2.0-or-later",
    licenseURL: URL(string: "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html")!,
    attribution: "Wireshark Foundation and contributors; generated from public registry data"
  )

  static let knownAddressSource = MACRegistrantDatabaseSourceMetadata(
    name: "Wireshark Well-Known Addresses",
    sourceURL: URL(string: "https://gitlab.com/wireshark/wireshark/-/raw/master/wka")!,
    purpose: "Well-known MAC address roles",
    license: "GPL-2.0-or-later",
    licenseURL: URL(string: "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html")!,
    attribution: "Copyright 1998 Gerald Combs; Wireshark Foundation and contributors"
  )

  private struct InstalledPayload: Codable {
    let metadata: MACRegistrantDatabaseMetadata
    let manufData: Data
    let wkaData: Data
  }

  private struct AttemptRecord: Codable {
    let attemptedAt: Date
  }

  private let fileManager: FileManager
  private let session: URLSession
  private let now: () -> Date
  private let callbackQueue: DispatchQueue
  private let worker = DispatchQueue(
    label: "local.bssid-picker.mac-registrant-database",
    qos: .utility
  )
  private let stateLock = NSLock()
  private var storedSnapshot = MACRegistrantResolver.unavailable
  private var storedState = MACRegistrantDatabaseState.notDownloaded
  private var stateCallback: ((MACRegistrantDatabaseState) -> Void)?

  let storageDirectoryURL: URL
  private var payloadURL: URL { storageDirectoryURL.appendingPathComponent("database.plist") }
  private var attemptURL: URL {
    storageDirectoryURL.appendingPathComponent("last-update-attempt.plist")
  }

  var snapshot: MACRegistrantResolver {
    stateLock.lock()
    defer { stateLock.unlock() }
    return storedSnapshot
  }

  var state: MACRegistrantDatabaseState {
    stateLock.lock()
    defer { stateLock.unlock() }
    return storedState
  }

  var hasInstalledDatabase: Bool { snapshot.isDatabaseAvailable }

  /// Intended for enabling the Settings button. The cooldown date remains an
  /// implementation detail and is deliberately not exposed for presentation.
  var canUpdate: Bool {
    if state.isBusy { return false }
    guard hasInstalledDatabase else { return true }
    guard let data = try? Data(contentsOf: attemptURL),
      let record = try? PropertyListDecoder().decode(AttemptRecord.self, from: data)
    else { return true }
    return now().timeIntervalSince(record.attemptedAt) >= Self.minimumUpdateInterval
  }

  /// Delivered on the main queue by default. Assigning it immediately emits
  /// the current state, making controller setup deterministic.
  var onStateChange: ((MACRegistrantDatabaseState) -> Void)? {
    get {
      stateLock.lock()
      defer { stateLock.unlock() }
      return stateCallback
    }
    set {
      stateLock.lock()
      stateCallback = newValue
      let current = storedState
      stateLock.unlock()
      if let newValue { callbackQueue.async { newValue(current) } }
    }
  }

  init(
    fileManager: FileManager = .default,
    applicationSupportDirectory: URL? = nil,
    session: URLSession = .shared,
    callbackQueue: DispatchQueue = .main,
    now: @escaping () -> Date = Date.init
  ) {
    self.fileManager = fileManager
    self.session = session
    self.callbackQueue = callbackQueue
    self.now = now
    let support =
      applicationSupportDirectory
      ?? fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    storageDirectoryURL =
      support
      .appendingPathComponent("BSSID Picker", isDirectory: true)
      .appendingPathComponent("Vendor Databases", isDirectory: true)
    loadInstalledDatabase()
  }

  func loadInstalledDatabase() {
    do {
      let data = try Data(contentsOf: payloadURL, options: .mappedIfSafe)
      let payload = try PropertyListDecoder().decode(InstalledPayload.self, from: data)
      let resolver = try MACRegistrantDatabaseParser.parse(
        manufData: payload.manufData,
        wkaData: payload.wkaData,
        metadata: payload.metadata,
        validation: .production
      )
      replace(snapshot: resolver, state: .ready(payload.metadata))
    } catch CocoaError.fileReadNoSuchFile {
      replace(snapshot: .unavailable, state: .notDownloaded)
    } catch {
      // A corrupt/incompatible payload is not a usable weekly snapshot. Let
      // the user replace it immediately instead of trapping them behind the
      // cooldown with no database available.
      try? fileManager.removeItem(at: payloadURL)
      try? fileManager.removeItem(at: attemptURL)
      replace(
        snapshot: .unavailable,
        state: .updateFailed(message: error.localizedDescription, previous: nil)
      )
    }
  }

  /// Performs only fixed, full-database HTTPS requests. No scanned address,
  /// SSID, BSSID, or other network observation is sent or logged.
  func update(
    completion: @escaping (Result<MACRegistrantDatabaseMetadata, Error>) -> Void
  ) {
    let previous: MACRegistrantDatabaseMetadata?
    stateLock.lock()
    if storedState.isBusy {
      stateLock.unlock()
      callbackQueue.async {
        completion(.failure(MACRegistrantDatabaseError.updateAlreadyInProgress))
      }
      return
    }
    previous = storedSnapshot.metadata
    storedState = .downloading(previous: previous)
    let callback = stateCallback
    stateLock.unlock()
    callbackQueue.async { callback?(.downloading(previous: previous)) }

    worker.async { [weak self] in
      guard let self else { return }
      do {
        try self.enforceCooldownAndRecordAttempt(hasInstalledDatabase: previous != nil)
      } catch {
        self.finishUpdate(.failure(error), previous: previous, completion: completion)
        return
      }
      self.download(Self.manufacturerSource, maximumBytes: 8 * 1_024 * 1_024) { manufResult in
        switch manufResult {
        case .failure(let error):
          self.finishUpdate(.failure(error), previous: previous, completion: completion)
        case .success(let manufData):
          self.download(Self.knownAddressSource, maximumBytes: 1 * 1_024 * 1_024) { wkaResult in
            switch wkaResult {
            case .failure(let error):
              self.finishUpdate(.failure(error), previous: previous, completion: completion)
            case .success(let wkaData):
              self.transition(to: .validating(previous: previous))
              self.install(
                manufData: manufData,
                wkaData: wkaData,
                previous: previous,
                completion: completion
              )
            }
          }
        }
      }
    }
  }

  func removeDownloadedData() throws {
    guard !state.isBusy else {
      throw MACRegistrantDatabaseError.updateAlreadyInProgress
    }
    do {
      if fileManager.fileExists(atPath: payloadURL.path) {
        try fileManager.removeItem(at: payloadURL)
      }
    } catch {
      throw MACRegistrantDatabaseError.persistenceFailed(underlying: error)
    }
    // The attempt marker has no effect without an installed snapshot, so a
    // failure to remove this tiny advisory file must not resurrect an already
    // deleted database in memory.
    try? fileManager.removeItem(at: attemptURL)
    replace(snapshot: .unavailable, state: .notDownloaded)
  }

  private func enforceCooldownAndRecordAttempt(hasInstalledDatabase: Bool) throws {
    try fileManager.createDirectory(
      at: storageDirectoryURL,
      withIntermediateDirectories: true,
      attributes: nil
    )
    if hasInstalledDatabase,
      let data = try? Data(contentsOf: attemptURL),
      let record = try? PropertyListDecoder().decode(AttemptRecord.self, from: data),
      now().timeIntervalSince(record.attemptedAt) < Self.minimumUpdateInterval
    {
      throw MACRegistrantDatabaseError.updateTooSoon
    }
    do {
      let encoder = PropertyListEncoder()
      encoder.outputFormat = .binary
      let data = try encoder.encode(AttemptRecord(attemptedAt: now()))
      try data.write(to: attemptURL, options: .atomic)
    } catch {
      throw MACRegistrantDatabaseError.persistenceFailed(underlying: error)
    }
  }

  private func download(
    _ source: MACRegistrantDatabaseSourceMetadata,
    maximumBytes: Int,
    completion: @escaping (Result<Data, Error>) -> Void
  ) {
    BoundedHTTPSDataDownload(
      source: source,
      maximumBytes: maximumBytes,
      configuration: session.configuration,
      completion: completion
    ).start()
  }

  private func install(
    manufData: Data,
    wkaData: Data,
    previous: MACRegistrantDatabaseMetadata?,
    completion: @escaping (Result<MACRegistrantDatabaseMetadata, Error>) -> Void
  ) {
    worker.async { [weak self] in
      guard let self else { return }
      do {
        let parsed = try MACRegistrantDatabaseParser.parse(
          manufData: manufData,
          wkaData: wkaData,
          metadata: nil,
          validation: .production
        )
        let metadata = MACRegistrantDatabaseMetadata(
          updatedAt: self.now(),
          manufacturerRecordCount: parsed.manufacturerRecordCount,
          knownAddressRecordCount: parsed.knownAddressRecordCount,
          sources: [Self.manufacturerSource, Self.knownAddressSource]
        )
        let resolver = parsed.withMetadata(metadata)
        self.transition(to: .installing(previous: previous))
        let encoder = PropertyListEncoder()
        encoder.outputFormat = .binary
        let payload = InstalledPayload(
          metadata: metadata,
          manufData: manufData,
          wkaData: wkaData
        )
        let encoded = try encoder.encode(payload)
        try encoded.write(to: self.payloadURL, options: .atomic)
        self.replace(snapshot: resolver, state: .ready(metadata))
        self.callbackQueue.async { completion(.success(metadata)) }
      } catch let error as MACRegistrantDatabaseParseError {
        self.finishUpdate(
          .failure(MACRegistrantDatabaseError.parsingFailed(underlying: error)),
          previous: previous,
          completion: completion
        )
      } catch {
        self.finishUpdate(
          .failure(MACRegistrantDatabaseError.persistenceFailed(underlying: error)),
          previous: previous,
          completion: completion
        )
      }
    }
  }

  private func finishUpdate(
    _ result: Result<MACRegistrantDatabaseMetadata, Error>,
    previous: MACRegistrantDatabaseMetadata?,
    completion: @escaping (Result<MACRegistrantDatabaseMetadata, Error>) -> Void
  ) {
    switch result {
    case .success(let metadata):
      replace(snapshot: snapshot, state: .ready(metadata))
    case .failure(let error):
      if previous == nil {
        // Initial-download failures leave no useful data. Permit a deliberate
        // retry; successful/installed snapshots remain weekly throttled.
        try? fileManager.removeItem(at: attemptURL)
      }
      replace(
        snapshot: snapshot,
        state: .updateFailed(message: error.localizedDescription, previous: previous)
      )
    }
    callbackQueue.async { completion(result) }
  }

  private func replace(
    snapshot: MACRegistrantResolver,
    state: MACRegistrantDatabaseState
  ) {
    stateLock.lock()
    storedSnapshot = snapshot
    storedState = state
    let callback = stateCallback
    stateLock.unlock()
    callbackQueue.async { callback?(state) }
  }

  private func transition(to state: MACRegistrantDatabaseState) {
    stateLock.lock()
    storedState = state
    let callback = stateCallback
    stateLock.unlock()
    callbackQueue.async { callback?(state) }
  }
}
