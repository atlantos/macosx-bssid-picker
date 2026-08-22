// SPDX-License-Identifier: GPL-3.0-only

import AppKit

enum ScanInspectorDocumentBuilder {
  static func make(
    row: ScanRow?,
    context: ScannerContextSnapshot?,
    interfaceSnapshot: WiFiInterfaceSnapshot?,
    rawExpanded: Bool
  ) -> NSAttributedString {
    let renderer = ScanInspectorDocumentRenderer()
    let showsCurrentAssociation = row == nil || row?.clientState.associated == true

    if let row {
      renderer.appendHeader(title: row.displaySSID, subtitle: row.accessPoint.reportedBSSID)
      appendScanObservation(
        row,
        latestSuccessfulScanAt: interfaceSnapshot?.capturedAt,
        to: renderer
      )
      appendAccessPointSections(row, to: renderer)
    } else {
      renderer.appendHeader(title: "No Access Point Selected", subtitle: nil)
      renderer.appendNote(
        "Select a row to inspect every reported radio, security, roaming, timing, and raw information-element field."
      )
    }

    if let context {
      appendClientContext(
        row: row,
        context: context,
        includesCurrentAssociation: showsCurrentAssociation,
        to: renderer
      )
    }
    if let interfaceSnapshot {
      appendInterface(
        interfaceSnapshot,
        includesCurrentAssociation: showsCurrentAssociation,
        to: renderer
      )
      appendConfiguration(interfaceSnapshot.configuration, to: renderer)
    }
    if let row {
      appendCredentialAccess(row, to: renderer)
    }
    if let context {
      appendEnvironment(context.environment, to: renderer)
    }
    if let row {
      appendInformationElements(row, rawExpanded: rawExpanded, to: renderer)
    }
    if let context {
      let events: [ConnectionEvent]
      if let target = row?.accessPoint.target {
        events = context.connectionEvents.filter { $0.requestedTarget == target }
      } else if row != nil {
        events = []
      } else {
        events = context.connectionEvents
      }
      appendConnectionEvents(events, scopedToSelectedBSSID: row != nil, to: renderer)
    }

    return renderer.finish()
  }

  private static func appendScanObservation(
    _ row: ScanRow,
    latestSuccessfulScanAt: Date?,
    to renderer: ScanInspectorDocumentRenderer
  ) {
    renderer.appendSection(
      title: "Scan Observation",
      fields: [
        .init(
          label: "Status",
          value:
            row.presentInLatestSuccessfulScan
            ? "Seen in latest scan" : "Previous observation"
        ),
        .init(
          label: "Last Seen",
          value: ScanFormatting.timestamp.string(from: row.lastSeenAt)
        ),
        .init(
          label: "Latest Successful Scan",
          value: latestSuccessfulScanAt.map {
            ScanFormatting.timestamp.string(from: $0)
          } ?? "Unavailable"
        ),
      ]
    )
    if !row.presentInLatestSuccessfulScan {
      renderer.appendNote(
        "This access point was not reported by the latest successful scan. "
          + "That does not prove it is offline or out of range; the details below are "
          + "from its last observation."
      )
    }
  }

  private static func appendAccessPointSections(
    _ row: ScanRow,
    to renderer: ScanInspectorDocumentRenderer
  ) {
    let decoded = row.standards.decodedFields
    renderer.appendSection(
      title: "Identity",
      fields: [
        .init(label: "SSID", value: row.displaySSID),
        .init(
          label: "SSID Bytes",
          value: row.accessPoint.ssidHex.isEmpty ? "Unavailable" : row.accessPoint.ssidHex,
          monospaced: true
        ),
        .init(label: "BSSID", value: row.accessPoint.reportedBSSID, monospaced: true),
      ]
    )
    appendMACRegistration(row, to: renderer)
    renderer.appendSection(
      title: "Radio",
      fields: [
        .init(label: "Signal", value: "\(row.accessPoint.rssi) dBm"),
        .init(
          label: "Noise",
          value: row.accessPoint.noise < 0 ? "\(row.accessPoint.noise) dBm" : "Unavailable"
        ),
        .init(
          label: "SNR", value: row.signalToNoiseRatio.map { "\($0) dB" } ?? "Unavailable"),
        .init(
          label: "Channel",
          value: row.accessPoint.channelNumber.map(String.init) ?? "Unavailable"
        ),
        .init(label: "Band", value: row.stringValue(for: .band)),
        .init(label: "Channel Width", value: row.stringValue(for: .channelWidth)),
        .init(label: "PHY Modes", value: row.stringValue(for: .phyModes)),
      ]
    )
    renderer.appendSection(
      title: "BSS Load",
      fields: [
        .init(label: "Associated Stations", value: inspectorValue(decoded.bssStationCount)),
        .init(
          label: "Channel Utilization",
          value: inspectorValue(decoded.bssChannelUtilization)
        ),
        .init(
          label: "Available Admission Capacity",
          value: inspectorValue(decoded.bssAdmissionCapacity)
        ),
      ]
    )
    renderer.appendSection(
      title: "Security",
      fields: [
        .init(label: "CoreWLAN", value: row.accessPoint.security),
        .init(label: "RSN", value: row.standards.rsnSummary),
        .init(
          label: "Protected Management Frames",
          value: row.standards.protectedManagementFramesSummary
        ),
      ]
    )
    renderer.appendSection(
      title: "Roaming & Management",
      fields: [
        .init(label: "802.11k Radio Measurement", value: row.standards.radioMeasurementSummary),
        .init(label: "802.11v BSS Transition", value: row.standards.bssTransitionSummary),
        .init(label: "802.11r Fast Transition", value: row.standards.fastTransitionSummary),
        .init(
          label: "FT Mobility Domain",
          value: inspectorValue(decoded.fastTransitionMobilityDomain)
        ),
        .init(label: "FT over DS", value: inspectorValue(decoded.fastTransitionOverDS)),
        .init(label: "BSS Maximum Idle", value: inspectorValue(decoded.bssMaxIdlePeriod)),
        .init(
          label: "Protected Keep-Alive",
          value: inspectorValue(decoded.protectedKeepAlive)
        ),
        .init(
          label: "Evidence Scope",
          value:
            "Derived from one CoreWLAN beacon/probe-response information-element blob. This does not test this Mac’s capabilities or prove end-to-end enablement."
        ),
      ]
    )
    renderer.appendSection(
      title: "Network Discovery & Access",
      fields: [
        .init(label: "Interworking", value: inspectorValue(decoded.interworking)),
        .init(label: "Roaming Consortium", value: inspectorValue(decoded.roamingConsortium)),
        .init(label: "AP Channel Reports", value: inspectorValue(decoded.apChannelReports)),
        .init(
          label: "Reduced Neighbor Report",
          value: inspectorValue(decoded.reducedNeighborReport)
        ),
        .init(label: "Multiple BSSID", value: inspectorValue(decoded.multipleBSSID)),
      ]
    )
    renderer.appendSection(
      title: "Timing & Topology",
      fields: [
        .init(label: "Country", value: row.stringValue(for: .country)),
        .init(label: "Beacon Interval", value: "\(row.accessPoint.beaconInterval) ms"),
        .init(label: "DTIM Count", value: inspectorValue(decoded.dtimCount)),
        .init(label: "DTIM Period", value: inspectorValue(decoded.dtimPeriod)),
        .init(
          label: "Network Type",
          value: row.accessPoint.isIBSS ? "IBSS" : "Infrastructure"
        ),
      ]
    )
  }

  private static func appendMACRegistration(
    _ row: ScanRow,
    to renderer: ScanInspectorDocumentRenderer
  ) {
    guard let attribution = row.macAttribution else {
      renderer.appendSection(
        title: "MAC Registration",
        fields: [
          .init(label: "Address Type", value: "Unavailable"),
          .init(label: "Registered Organization", value: "Unavailable"),
          .init(label: "Allocation", value: "Unavailable"),
          .init(label: "Matched Prefix", value: "Unavailable", monospaced: true),
          .init(label: "Registration Source", value: "Unavailable"),
          .init(label: "Database Agreement", value: "Unavailable"),
          .init(label: "Known Address Role", value: "Unavailable"),
          .init(
            label: "Evidence Scope",
            value:
              "MAC-prefix registration may not identify the access point’s brand, manufacturer, owner, or operator."
          ),
        ]
      )
      return
    }

    let unavailableValue: String
    switch attribution.addressType {
    case .globallyAdministered:
      unavailableValue = attribution.isDatabaseUnavailable ? "Unavailable" : "Not Found"
    case .locallyAdministered, .groupAddress:
      unavailableValue = "Not Applicable"
    case .invalidAddress:
      unavailableValue = "Unavailable"
    }

    let registeredOrganization: String
    if let organization = attribution.registeredOrganization {
      registeredOrganization =
        attribution.isPrivateRegistration ? "Private Registration" : organization
    } else if !attribution.registryClaims.isEmpty {
      registeredOrganization = attribution.registryClaims.map {
        "\($0.organization) — \($0.source.rawValue)"
      }.joined(separator: "\n")
    } else {
      registeredOrganization = unavailableValue
    }
    let registrationSource =
      attribution.registrationSourceDisplayName
      ?? {
        let claimSources = Set(attribution.registryClaims.map(\.source.rawValue)).sorted()
        return claimSources.isEmpty ? unavailableValue : claimSources.joined(separator: ", ")
      }()
    let fields: [ScanInspectorField] = [
      .init(label: "Address Type", value: attribution.addressTypeDisplayName),
      .init(
        label: "Registered Organization",
        value: registeredOrganization
      ),
      .init(label: "Allocation", value: attribution.allocationDisplayName ?? unavailableValue),
      .init(
        label: "Matched Prefix",
        value: attribution.matchedPrefix ?? unavailableValue,
        monospaced: true
      ),
      .init(
        label: "Registration Source",
        value: registrationSource
      ),
      .init(
        label: "Database Agreement",
        value: attribution.databaseAgreementDisplayName
          ?? (attribution.registryClaims.isEmpty ? unavailableValue : "No Conflicting Records")
      ),
      .init(
        label: "Known Address Role",
        value: attribution.knownAddressRole
          ?? (attribution.isDatabaseUnavailable ? "Unavailable" : "Not Found")
      ),
      .init(
        label: "Evidence Scope",
        value:
          "MAC-prefix registration may not identify the access point’s brand, manufacturer, owner, or operator."
      ),
    ]
    renderer.appendSection(title: "MAC Registration", fields: fields)
  }

  private static func appendClientContext(
    row: ScanRow?,
    context: ScannerContextSnapshot,
    includesCurrentAssociation: Bool,
    to renderer: ScanInspectorDocumentRenderer
  ) {
    let client = context.client
    var fields: [ScanInspectorField] = []
    if let row {
      fields.append(
        .init(label: "Selected AP Association", value: row.clientState.associatedDisplayName))
      fields.append(
        .init(
          label: "Selected AP BSSID Lock Target", value: row.clientState.lockTargetDisplayName))
    }
    if includesCurrentAssociation {
      fields.append(contentsOf: [
        .init(
          label: "Association Observed",
          value: client.capturedAt.map { ScanFormatting.timestamp.string(from: $0) }
            ?? "Unavailable"
        ),
        .init(label: "Operation", value: client.operation.rawValue),
        .init(label: "Association Mode", value: client.associationMode.rawValue),
        .init(label: "Current SSID", value: client.displaySSID ?? "Not associated"),
        .init(
          label: "Current BSSID",
          value: client.currentBSSID?.rawValue ?? "Not associated",
          monospaced: true
        ),
        .init(
          label: "Raw SSID",
          value: client.rawSSID.map { ScanFormatting.compactHex($0.data) } ?? "Unavailable",
          monospaced: true
        ),
      ])
    }

    let includesLockRuntime = row == nil || row?.clientState.lockTarget == true
    if includesLockRuntime {
      if !includesCurrentAssociation {
        fields.append(.init(label: "Operation", value: client.operation.rawValue))
        fields.append(.init(label: "Association Mode", value: client.associationMode.rawValue))
      }
      fields.append(.init(label: "BSSID Lock State", value: client.lock.state.rawValue))
      if let displaySSID = client.lock.displaySSID {
        fields.append(.init(label: "BSSID Lock SSID", value: displaySSID))
      }
      if let target = client.lock.target {
        fields.append(
          .init(label: "BSSID Lock Target", value: target.bssid.rawValue, monospaced: true))
        fields.append(
          .init(
            label: "BSSID Lock Target SSID Bytes",
            value: ScanFormatting.compactHex(target.ssid.data),
            monospaced: true
          ))
      }
      if client.lock.failureCount > 0 {
        fields.append(.init(label: "BSSID Lock Failures", value: "\(client.lock.failureCount)"))
      }
      if let retry = client.lock.nextRetryAt {
        fields.append(
          .init(
            label: "Next BSSID Lock Retry", value: ScanFormatting.timestamp.string(from: retry)))
      }
      if let delay = client.lock.retryDelay {
        fields.append(.init(label: "Retry Delay", value: String(format: "%.1f s", delay)))
      }
      if let error = client.lock.lastError {
        fields.append(.init(label: "BSSID Lock Error", value: error))
      }
    }
    if includesCurrentAssociation, let error = client.lastConnectionError {
      fields.append(.init(label: "Connection Error", value: error))
    }
    renderer.appendSection(title: "This Mac & BSSID Picker", fields: fields)
  }

  private static func appendInterface(
    _ snapshot: WiFiInterfaceSnapshot,
    includesCurrentAssociation: Bool,
    to renderer: ScanInspectorDocumentRenderer
  ) {
    let association = snapshot.currentAssociation
    let channel = snapshot.currentChannel.map(channelDescription) ?? "Unavailable"
    let signal = snapshot.rssi.map { "\($0) dBm" } ?? "Unavailable"
    let noise = snapshot.noise.map { "\($0) dBm" } ?? "Unavailable"
    let snr = snapshot.snr.map { "\($0) dB" } ?? "Unavailable"
    let transmitRate =
      snapshot.transmitRateMbps.map { String(format: "%.1f Mb/s", $0) } ?? "Unavailable"
    let transmitPower =
      snapshot.transmitPowerMilliwatts.map { "\($0) mW" } ?? "Unavailable"
    var fields: [ScanInspectorField] = [
      .init(label: "Captured", value: ScanFormatting.timestamp.string(from: snapshot.capturedAt)),
      .init(
        label: "Available Interfaces",
        value: snapshot.availableInterfaceNames.isEmpty
          ? "None reported" : snapshot.availableInterfaceNames.joined(separator: ", "),
        monospaced: true
      ),
      .init(label: "Active Interface", value: snapshot.interfaceName ?? "Unavailable"),
      .init(label: "Power", value: snapshot.isPowerOn ? "On" : "Off"),
      .init(label: "Network Service", value: snapshot.isServiceActive ? "Active" : "Inactive"),
      .init(label: "Interface Mode", value: snapshot.interfaceMode.rawValue),
      .init(
        label: "Hardware Address",
        value: snapshot.hardwareAddress ?? "Unavailable",
        monospaced: true
      ),
      .init(label: "Country", value: snapshot.countryCode ?? "Unavailable"),
    ]
    if includesCurrentAssociation {
      fields.append(contentsOf: [
        .init(label: "Current SSID", value: association?.displaySSID ?? "Not associated"),
        .init(
          label: "Current SSID Bytes",
          value: association.map { ScanFormatting.compactHex($0.ssid.data) } ?? "Unavailable",
          monospaced: true
        ),
        .init(
          label: "Current BSSID",
          value: association?.bssid?.rawValue ?? "Not associated",
          monospaced: true
        ),
        .init(label: "PHY Mode", value: snapshot.activePHYMode.rawValue),
        .init(label: "Security", value: snapshot.security?.rawValue ?? "Unavailable"),
        .init(
          label: "Channel",
          value: channel
        ),
        .init(label: "Signal", value: signal),
        .init(label: "Noise", value: noise),
        .init(label: "SNR", value: snr),
        .init(label: "Transmit Rate", value: transmitRate),
        .init(label: "Transmit Power", value: transmitPower),
      ])
    }
    fields.append(
      .init(
        label: "Supported Channels", value: groupedChannelDescription(snapshot.supportedChannels)))
    renderer.appendSection(title: "Mac Wi-Fi Interface", fields: fields)
  }

  private static func appendConfiguration(
    _ configuration: WiFiConfigurationSnapshot?,
    to renderer: ScanInspectorDocumentRenderer
  ) {
    guard let configuration else {
      renderer.appendSection(
        title: "Mac Wi-Fi Configuration",
        fields: [.init(label: "Status", value: "Unavailable")]
      )
      return
    }
    renderer.appendSection(
      title: "Mac Wi-Fi Configuration",
      fields: [
        .init(
          label: "Remember Joined Networks", value: yesNo(configuration.rememberJoinedNetworks)),
        .init(
          label: "Admin Required to Associate",
          value: yesNo(configuration.requireAdministratorForAssociation)
        ),
        .init(
          label: "Admin Required for Power",
          value: yesNo(configuration.requireAdministratorForPower)
        ),
        .init(
          label: "Admin Required for IBSS",
          value: yesNo(configuration.requireAdministratorForIBSSMode)
        ),
        .init(label: "Preferred Profiles", value: "\(configuration.preferredProfileCount)"),
        .init(
          label: "Profiles Matching This Scan",
          value: "\(configuration.matchingProfiles.count)"
        ),
        .init(
          label: "Profile Scope",
          value: "Only saved profiles whose exact SSID bytes occur in this scan are included."
        ),
      ]
    )
  }

  private static func appendCredentialAccess(
    _ row: ScanRow,
    to renderer: ScanInspectorDocumentRenderer
  ) {
    let diagnostics = row.clientState.lastConnectionEvent?.credentialDiagnostics
    var fields: [ScanInspectorField] = [
      .init(label: "Saved Network Profile", value: row.clientState.savedProfileDisplayName),
      .init(
        label: "Current System Fallback Consent",
        value: row.clientState.systemFallbackDisplayName
      ),
      .init(
        label: "Network Requirement",
        value: row.accessPoint.authentication.credentialRequirement.rawValue
      ),
      .init(label: "Last Connection Result", value: row.clientState.lastConnectionResult),
      .init(label: "Last Attempt At", value: row.clientState.lastAttemptDisplayName),
      .init(label: "Last Connection Mode", value: row.clientState.lastConnectionModeDisplayName),
      .init(
        label: "Last Attempt Requirement",
        value: diagnostics?.requirement.rawValue ?? "No Attempt"
      ),
      .init(
        label: "Last Attempt Consent",
        value: diagnostics?.consentScope.rawValue ?? "No Attempt"
      ),
      .init(label: "Credential Source", value: row.clientState.credentialSourceDisplayName),
      .init(label: "Credential Result", value: row.clientState.credentialResultDisplayName),
      .init(label: "App Read Password", value: row.clientState.appReadPasswordDisplayName),
      .init(
        label: "Password Handling",
        value: diagnostics?.passwordHandlingDisplayName ?? "No Attempt"
      ),
      .init(label: "Last Connection Error", value: row.clientState.lastConnectionErrorDisplayName),
    ]
    if let profiles = row.clientState.savedProfiles, !profiles.isEmpty {
      let summaries = profiles.map { profile in
        let displaySSID = profile.displaySSID.map { " · \($0)" } ?? ""
        return "#\(profile.preferenceIndex + 1)\(displaySSID) · \(profile.security.rawValue)"
      }
      fields.append(.init(label: "Matching Profiles", value: summaries.joined(separator: "\n")))
    }
    fields.append(
      .init(
        label: "Privacy",
        value:
          "Passwords, Keychain item identifiers, and access-control data are never stored in diagnostics or displayed. Selecting a row does not access Keychain."
      ))
    renderer.appendSection(title: "Credential Access", fields: fields)
  }

  private static func appendEnvironment(
    _ environment: AppEnvironmentDiagnostics,
    to renderer: ScanInspectorDocumentRenderer
  ) {
    var fields: [ScanInspectorField] = [
      .init(label: "macOS", value: environment.macOSVersion),
      .init(label: "App Version", value: environment.appVersion),
      .init(label: "App Build", value: environment.appBuild),
      .init(label: "Bundle Identifier", value: environment.bundleIdentifier, monospaced: true),
      .init(label: "Location Access", value: environment.locationAuthorization.rawValue),
      .init(label: "Strict BSSID Backend", value: environment.strictBackend.state.rawValue),
    ]
    if let message = environment.strictBackend.message {
      fields.append(.init(label: "Strict Backend Detail", value: message))
    }
    renderer.appendSection(title: "App & macOS Environment", fields: fields)
  }

  private static func appendInformationElements(
    _ row: ScanRow,
    rawExpanded: Bool,
    to renderer: ScanInspectorDocumentRenderer
  ) {
    renderer.appendSection(
      title: "Information Elements",
      fields: [
        .init(label: "Parse Status", value: row.standards.parseStatus),
        .init(label: "Element Count", value: "\(row.informationElementCount)"),
        .init(label: "Raw Bytes", value: "\(row.informationElementBytes)"),
      ]
    )
    if row.standards.elements.isEmpty {
      renderer.appendNote("No information-element data is available for this access point.")
      return
    }
    for (index, element) in row.standards.elements.enumerated() {
      renderer.appendDetailBlock(
        title: "\(index + 1). \(element.identifier) — \(element.name) (\(element.length) bytes)",
        details: [element.summary],
        rawText: element.rawHex.isEmpty ? nil : element.rawHex
      )
    }
    if rawExpanded,
      let rawData = row.accessPoint.informationElements,
      !rawData.isEmpty
    {
      renderer.appendSectionHeading("Complete Information-Element Hex Dump")
      renderer.appendRawBlock(ScanFormatting.hexDump(rawData))
    }
  }

  private static func appendConnectionEvents(
    _ events: [ConnectionEvent],
    scopedToSelectedBSSID: Bool,
    to renderer: ScanInspectorDocumentRenderer
  ) {
    renderer.appendSectionHeading(
      scopedToSelectedBSSID ? "Connection Events for Selected BSSID" : "Connection Events"
    )
    guard !events.isEmpty else {
      renderer.appendNote(
        scopedToSelectedBSSID
          ? "No connection events have been recorded for this BSSID in the current app session."
          : "No connection events have been recorded in this app session."
      )
      return
    }
    if events.count > 20 {
      renderer.appendNote(
        "Showing the 20 most recent of \(events.count) events. Exports include the complete history."
      )
    }
    for event in events.suffix(20).reversed() {
      var details = [
        "Event ID: \(event.id.uuidString)",
        "Mode: \(event.mode.rawValue)",
        "Requested BSSID: \(event.requestedTarget.bssid.rawValue)",
        "Requested SSID bytes: \(ScanFormatting.compactHex(event.requestedTarget.ssid.data))",
        "Observed: \(event.observedBSSID?.rawValue ?? "Unavailable")",
        "Credential requirement: \(event.credentialDiagnostics.requirement.rawValue)",
        "System fallback: \(event.credentialDiagnostics.consentScope.rawValue)",
        "Credential source: \(event.credentialDiagnostics.sourceDisplayName)",
        "Credential result: \(event.credentialDiagnostics.resultDisplayName)",
        "Password handling: \(event.credentialDiagnostics.passwordHandlingDisplayName)",
      ]
      if let completedAt = event.completedAt {
        details.append(
          "Completed: \(ScanFormatting.timeOnly.string(from: completedAt)) (\(String(format: "%.2f", completedAt.timeIntervalSince(event.startedAt))) s)"
        )
      }
      if !event.verificationSamples.isEmpty {
        let samples = event.verificationSamples.map {
          "\(String(format: "%.1f", $0.elapsed)) s=\($0.bssid?.rawValue ?? "not associated")"
        }.joined(separator: ", ")
        details.append("Verification: \(samples)")
      }
      for (index, record) in event.credentialDiagnostics.records.enumerated() {
        var values = [
          ScanFormatting.timeOnly.string(from: record.observedAt),
          record.stage.rawValue,
          record.result.rawValue,
          record.secretHandling.rawValue,
        ]
        if let attempts = record.attempts { values.append("attempts \(attempts)") }
        if let status = record.osStatus { values.append("OSStatus \(status)") }
        details.append("Credential record \(index + 1): \(values.joined(separator: " · "))")
      }
      if let message = event.message { details.append("Message: \(message)") }
      renderer.appendDetailBlock(
        title:
          "\(event.state.rawValue) · \(event.trigger.rawValue) · \(ScanFormatting.timeOnly.string(from: event.startedAt))",
        details: details,
        rawText: nil
      )
    }
  }

  private static func inspectorValue(_ value: ScanDecodedNumericPresentation) -> String {
    value.displayName == value.state.displayName
      ? value.state.detailedDisplayName
      : value.displayName
  }

  private static func inspectorValue(_ value: ScanDecodedTextPresentation) -> String {
    value.displayName == value.state.displayName
      ? value.state.detailedDisplayName
      : value.displayName
  }

  private static func channelDescription(_ channel: WiFiChannelSnapshot) -> String {
    "\(channel.number) · \(channel.band.rawValue) · \(channel.width.rawValue)"
  }

  private static func groupedChannelDescription(_ channels: [WiFiChannelSnapshot]) -> String {
    guard !channels.isEmpty else { return "None reported" }
    let bandOrder: [WiFiChannelBand] = [.band2GHz, .band5GHz, .band6GHz, .other, .unknown]
    return bandOrder.compactMap { band in
      let matching = channels.filter { $0.band == band }
      guard !matching.isEmpty else { return nil }
      let values = matching.map { "\($0.number) (\($0.width.rawValue))" }.joined(separator: ", ")
      return "\(band.rawValue): \(values)"
    }.joined(separator: "\n")
  }

  private static func yesNo(_ value: Bool) -> String {
    value ? "Yes" : "No"
  }
}

private struct ScanInspectorField {
  let label: String
  let value: String
  let monospaced: Bool

  init(label: String, value: String, monospaced: Bool = false) {
    self.label = label
    self.value = value
    self.monospaced = monospaced
  }
}

private final class ScanInspectorDocumentRenderer {
  private enum Layout {
    static let labelColumnWidth: CGFloat = 176
  }

  private let result = NSMutableAttributedString()
  private var hasContent = false

  func finish() -> NSAttributedString {
    NSAttributedString(attributedString: result)
  }

  func appendHeader(title: String, subtitle: String?) {
    appendParagraph(
      title,
      font: NSFont.systemFont(ofSize: NSFont.systemFontSize + 2, weight: .semibold),
      color: .labelColor,
      paragraphSpacing: 4
    )
    if let subtitle {
      appendParagraph(
        subtitle,
        font: NSFont.monospacedSystemFont(
          ofSize: NSFont.smallSystemFontSize,
          weight: .regular
        ),
        color: .secondaryLabelColor,
        paragraphSpacing: 8
      )
    }
  }

  func appendSection(title: String, fields: [ScanInspectorField]) {
    appendSectionHeading(title)
    guard !fields.isEmpty else { return }
    let table = NSTextTable()
    table.numberOfColumns = 2
    table.layoutAlgorithm = .fixedLayoutAlgorithm
    table.collapsesBorders = true
    table.hidesEmptyCells = false
    table.setContentWidth(100, type: .percentageValueType)
    for (row, field) in fields.enumerated() {
      appendTableCell(
        field.label,
        table: table,
        row: row,
        column: 0,
        width: Layout.labelColumnWidth,
        font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize, weight: .medium),
        color: .secondaryLabelColor,
        alignment: .right
      )
      appendTableCell(
        field.value,
        table: table,
        row: row,
        column: 1,
        width: nil,
        font: field.monospaced
          ? NSFont.monospacedSystemFont(
            ofSize: NSFont.smallSystemFontSize,
            weight: .regular
          )
          : NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
        color: .labelColor,
        alignment: .left
      )
    }
    appendSpacer(4)
  }

  func appendSectionHeading(_ title: String) {
    appendParagraph(
      title,
      font: NSFont.systemFont(ofSize: NSFont.systemFontSize, weight: .semibold),
      color: .labelColor,
      paragraphSpacingBefore: hasContent ? 12 : 0,
      paragraphSpacing: 6
    )
  }

  func appendNote(_ value: String) {
    appendParagraph(
      value,
      font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
      color: .secondaryLabelColor,
      paragraphSpacing: 6
    )
  }

  func appendDetailBlock(title: String, details: [String], rawText: String?) {
    appendIndentedParagraph(
      title,
      font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize, weight: .semibold),
      color: .labelColor,
      paragraphSpacingBefore: 4,
      paragraphSpacing: 2
    )
    for detail in details where !detail.isEmpty {
      appendIndentedParagraph(
        detail,
        font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
        color: .labelColor,
        paragraphSpacing: 2
      )
    }
    if let rawText, !rawText.isEmpty {
      appendIndentedParagraph(
        rawText,
        font: NSFont.monospacedSystemFont(
          ofSize: NSFont.smallSystemFontSize,
          weight: .regular
        ),
        color: .secondaryLabelColor,
        paragraphSpacing: 4
      )
    }
  }

  func appendRawBlock(_ value: String) {
    let block = NSTextBlock()
    block.setContentWidth(100, type: .percentageValueType)
    block.setWidth(6, type: .absoluteValueType, for: .padding)
    block.setWidth(1, type: .absoluteValueType, for: .border)
    block.setBorderColor(.separatorColor)
    block.backgroundColor = .controlBackgroundColor
    let style = NSMutableParagraphStyle()
    style.textBlocks = [block]
    style.paragraphSpacing = 6
    append(
      value + "\n",
      attributes: [
        .font: NSFont.monospacedSystemFont(
          ofSize: NSFont.smallSystemFontSize,
          weight: .regular
        ),
        .foregroundColor: NSColor.labelColor,
        .paragraphStyle: style,
      ]
    )
  }

  private func appendTableCell(
    _ value: String,
    table: NSTextTable,
    row: Int,
    column: Int,
    width: CGFloat?,
    font: NSFont,
    color: NSColor,
    alignment: NSTextAlignment
  ) {
    let block = NSTextTableBlock(
      table: table,
      startingRow: row,
      rowSpan: 1,
      startingColumn: column,
      columnSpan: 1
    )
    if let width {
      block.setValue(width, type: .absoluteValueType, for: .width)
    }
    block.setWidth(2, type: .absoluteValueType, for: .padding, edge: .minY)
    block.setWidth(2, type: .absoluteValueType, for: .padding, edge: .maxY)
    if column == 0 {
      block.setWidth(8, type: .absoluteValueType, for: .padding, edge: .maxX)
    }
    block.verticalAlignment = .topAlignment
    let style = NSMutableParagraphStyle()
    style.textBlocks = [block]
    style.alignment = alignment
    append(
      value + "\n",
      attributes: [
        .font: font,
        .foregroundColor: color,
        .paragraphStyle: style,
      ]
    )
  }

  private func appendParagraph(
    _ value: String,
    font: NSFont,
    color: NSColor,
    paragraphSpacingBefore: CGFloat = 0,
    paragraphSpacing: CGFloat = 0
  ) {
    let style = NSMutableParagraphStyle()
    style.paragraphSpacingBefore = paragraphSpacingBefore
    style.paragraphSpacing = paragraphSpacing
    append(
      value + "\n",
      attributes: [
        .font: font,
        .foregroundColor: color,
        .paragraphStyle: style,
      ]
    )
  }

  private func appendIndentedParagraph(
    _ value: String,
    font: NSFont,
    color: NSColor,
    paragraphSpacingBefore: CGFloat = 0,
    paragraphSpacing: CGFloat = 0
  ) {
    let style = NSMutableParagraphStyle()
    style.firstLineHeadIndent = 8
    style.headIndent = 8
    style.paragraphSpacingBefore = paragraphSpacingBefore
    style.paragraphSpacing = paragraphSpacing
    append(
      value + "\n",
      attributes: [
        .font: font,
        .foregroundColor: color,
        .paragraphStyle: style,
      ]
    )
  }

  private func appendSpacer(_ height: CGFloat) {
    let style = NSMutableParagraphStyle()
    style.minimumLineHeight = height
    style.maximumLineHeight = height
    append("\n", attributes: [.paragraphStyle: style])
  }

  private func append(_ string: String, attributes: [NSAttributedString.Key: Any]) {
    result.append(NSAttributedString(string: string, attributes: attributes))
    hasContent = true
  }
}
