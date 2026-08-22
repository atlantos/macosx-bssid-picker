// SPDX-License-Identifier: GPL-3.0-only

import AppKit

private final class SettingsDocumentView: NSView {
  override var isFlipped: Bool { true }
}

enum MACRegistrantDatabaseViewStatus: Equatable {
  case notDownloaded
  case ready
  case downloading
  case validating
  case installing
  case failed
}

struct MACRegistrantDatabaseViewState {
  let status: MACRegistrantDatabaseViewStatus
  let metadata: MACRegistrantDatabaseMetadata?
  let hasInstalledDatabase: Bool
  let canUpdate: Bool
  let errorMessage: String?

  static let notDownloaded = MACRegistrantDatabaseViewState(
    status: .notDownloaded,
    metadata: nil,
    hasInstalledDatabase: false,
    canUpdate: true,
    errorMessage: nil
  )

  var isBusy: Bool {
    switch status {
    case .downloading, .validating, .installing: return true
    case .notDownloaded, .ready, .failed: return false
    }
  }

  var updatedAt: Date? { metadata?.updatedAt }
}

struct SettingsViewState {
  let locationState: LocationAuthorizationState
  let launchAtLoginStatus: LaunchAtLoginStatus
  let launchAtLoginErrorMessage: String?
  let macRegistrantDatabase: MACRegistrantDatabaseViewState
  let strictBSSIDEnabled: Bool
  let mainMenuRefreshInterval: Int
  let lockMonitorInterval: Int
  let isCheckingStrictAvailability: Bool
  let repairLockSettingsAvailable: Bool
  let resetToDefaultsEnabled: Bool
  let controlsEnabled: Bool
  let statusMessage: String?

  init(
    locationState: LocationAuthorizationState,
    launchAtLoginStatus: LaunchAtLoginStatus = .notRegistered,
    launchAtLoginErrorMessage: String? = nil,
    macRegistrantDatabase: MACRegistrantDatabaseViewState = .notDownloaded,
    strictBSSIDEnabled: Bool,
    mainMenuRefreshInterval: Int = SettingsStore.defaultMainMenuRefreshInterval,
    lockMonitorInterval: Int = SettingsStore.defaultLockMonitorInterval,
    isCheckingStrictAvailability: Bool = false,
    controlsEnabled: Bool = true,
    statusMessage: String? = nil,
    repairLockSettingsAvailable: Bool = false,
    resetToDefaultsEnabled: Bool = false
  ) {
    self.locationState = locationState
    self.launchAtLoginStatus = launchAtLoginStatus
    self.launchAtLoginErrorMessage = launchAtLoginErrorMessage
    self.macRegistrantDatabase = macRegistrantDatabase
    self.strictBSSIDEnabled = strictBSSIDEnabled
    self.mainMenuRefreshInterval = mainMenuRefreshInterval
    self.lockMonitorInterval = lockMonitorInterval
    self.isCheckingStrictAvailability = isCheckingStrictAvailability
    self.repairLockSettingsAvailable = repairLockSettingsAvailable
    self.resetToDefaultsEnabled = resetToDefaultsEnabled
    self.controlsEnabled = controlsEnabled
    self.statusMessage = statusMessage
  }
}

/// Nonmodal preferences window for configuration that is too consequential or
/// verbose for the status-item panel.
final class SettingsWindowController: NSWindowController, NSWindowDelegate, NSTextFieldDelegate {
  var onSetLaunchAtLoginEnabled: ((Bool) -> Void)?
  var onOpenLoginItemsSettings: (() -> Void)?
  var onRefreshLaunchAtLogin: (() -> Void)?
  var onSetStrictEnabled: ((Bool) -> Void)?
  var onSetMainMenuRefreshInterval: ((Int) -> Void)?
  var onSetLockMonitorInterval: ((Int) -> Void)?
  var onUpdateMACRegistrantDatabase: (() -> Void)?
  var onRemoveMACRegistrantDatabase: (() -> Void)?
  var onRequestLocation: (() -> Void)?
  var onOpenLocationSettings: (() -> Void)?
  var onRepairLockSettings: (() -> Void)?
  var onResetToDefaults: (() -> Void)?

  private var state: SettingsViewState
  private let scrollView = NSScrollView()
  private let documentView = SettingsDocumentView()
  private let root = NSStackView()
  private let launchAtLoginToggle = NSButton(
    checkboxWithTitle: "Launch BSSID Picker at login", target: nil, action: nil)
  private let launchAtLoginStatus = NSTextField(wrappingLabelWithString: "")
  private let launchAtLoginStatusRow = NSStackView()
  private let openLoginItemsSettingsButton = NSButton(
    title: "Open Login Items Settings…", target: nil, action: nil)
  private let locationStatus = NSTextField(labelWithString: "")
  private let locationAction = NSButton()
  private let strictToggle = NSButton(
    checkboxWithTitle: "Use Strict BSSID association (Experimental)", target: nil, action: nil)
  private let strictStatus = NSTextField(labelWithString: "")
  private let strictProgress = NSProgressIndicator()
  private let mainMenuRefreshField = NSTextField()
  private let lockMonitorField = NSTextField()
  private let macRegistrantDatabaseStatus = NSTextField(labelWithString: "")
  private let macRegistrantDatabaseUpdated = NSTextField(labelWithString: "")
  private let macRegistrantDatabaseError = NSTextField(wrappingLabelWithString: "")
  private let updateMACRegistrantDatabaseButton = NSButton(
    title: "Download Database", target: nil, action: nil)
  private let showMACRegistrantSourcesButton = NSButton(
    title: "Sources & Licenses…", target: nil, action: nil)
  private let operationStatus = NSTextField(wrappingLabelWithString: "")
  private let operationStatusRow = NSStackView()
  private let repairLockSettingsButton = NSButton(
    title: "Reset Invalid BSSID Lock Settings", target: nil, action: nil)
  private let resetToDefaultsButton = NSButton(
    title: "Reset to Defaults…", target: nil, action: nil)

  init(initialState: SettingsViewState) {
    state = initialState
    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 540, height: 500),
      styleMask: [.titled, .closable, .miniaturizable],
      backing: .buffered,
      defer: false
    )
    super.init(window: window)
    window.title = "BSSID Picker Settings"
    window.isReleasedWhenClosed = false
    window.autorecalculatesKeyViewLoop = true
    window.delegate = self
    buildInterface()
    render(initialState)
    window.center()
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    fatalError("init(coder:) is not supported")
  }

  func show() {
    updateWindowSize()
    showWindow(nil)
    window?.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }

  func render(_ newState: SettingsViewState) {
    state = newState
    guard isWindowLoaded else { return }

    launchAtLoginToggle.state = newState.launchAtLoginStatus.isRegistered ? .on : .off
    launchAtLoginToggle.isEnabled = newState.launchAtLoginStatus.isAvailable
    launchAtLoginStatus.stringValue = launchAtLoginSummary
    launchAtLoginStatus.textColor = launchAtLoginColor
    launchAtLoginStatus.toolTip = launchAtLoginHelp
    launchAtLoginStatus.setAccessibilityValue(launchAtLoginSummary)
    launchAtLoginStatusRow.isHidden =
      newState.launchAtLoginErrorMessage == nil
      && newState.launchAtLoginStatus != .requiresApproval
      && newState.launchAtLoginStatus != .unknown
    openLoginItemsSettingsButton.isHidden =
      newState.launchAtLoginStatus != .requiresApproval
    openLoginItemsSettingsButton.isEnabled =
      newState.launchAtLoginStatus == .requiresApproval

    locationStatus.stringValue = locationSummary
    locationStatus.textColor = locationColor
    locationStatus.toolTip = locationHelp
    locationStatus.setAccessibilityValue(locationSummary)
    locationAction.title = locationActionTitle
    locationAction.isEnabled = newState.controlsEnabled && newState.locationState != .unavailable
    locationAction.toolTip = locationHelp

    synchronizeInterval(newState.mainMenuRefreshInterval, with: mainMenuRefreshField)
    synchronizeInterval(newState.lockMonitorInterval, with: lockMonitorField)
    renderMACRegistrantDatabase(newState.macRegistrantDatabase)

    strictToggle.state = newState.strictBSSIDEnabled ? .on : .off
    strictToggle.isEnabled =
      newState.controlsEnabled && !newState.isCheckingStrictAvailability
    strictProgress.isHidden = !newState.isCheckingStrictAvailability
    if newState.isCheckingStrictAvailability {
      strictProgress.startAnimation(nil)
      strictStatus.stringValue = "Checking whether Strict BSSID is available on this Mac…"
    } else {
      strictProgress.stopAnimation(nil)
      strictStatus.stringValue =
        newState.strictBSSIDEnabled
        ? "Enabled. Every strict connection is verified against the requested BSSID."
        : "Disabled. Connections use Apple's supported CoreWLAN association API."
    }
    strictStatus.toolTip = strictStatus.stringValue

    operationStatus.stringValue = newState.statusMessage ?? ""
    operationStatus.isHidden = newState.statusMessage == nil
    operationStatus.setAccessibilityLabel(newState.statusMessage ?? "")
    repairLockSettingsButton.isHidden = !newState.repairLockSettingsAvailable
    repairLockSettingsButton.isEnabled =
      newState.repairLockSettingsAvailable && newState.controlsEnabled
    operationStatusRow.isHidden =
      newState.statusMessage == nil && !newState.repairLockSettingsAvailable
    resetToDefaultsButton.isEnabled =
      newState.controlsEnabled && newState.resetToDefaultsEnabled
    updateWindowSize()
  }

  private func buildInterface() {
    guard let content = window?.contentView else { return }

    scrollView.borderType = .noBorder
    scrollView.drawsBackground = false
    scrollView.hasHorizontalScroller = false
    scrollView.hasVerticalScroller = true
    scrollView.autohidesScrollers = true
    scrollView.scrollerStyle = .overlay
    scrollView.translatesAutoresizingMaskIntoConstraints = false
    scrollView.documentView = documentView
    content.addSubview(scrollView)
    NSLayoutConstraint.activate([
      scrollView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
      scrollView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
      scrollView.topAnchor.constraint(equalTo: content.topAnchor),
      scrollView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
    ])

    root.orientation = .vertical
    root.alignment = .leading
    root.spacing = 18
    root.edgeInsets = NSEdgeInsets(top: 22, left: 24, bottom: 22, right: 24)
    root.translatesAutoresizingMaskIntoConstraints = false
    documentView.addSubview(root)
    NSLayoutConstraint.activate([
      root.leadingAnchor.constraint(equalTo: documentView.leadingAnchor),
      root.trailingAnchor.constraint(equalTo: documentView.trailingAnchor),
      root.topAnchor.constraint(equalTo: documentView.topAnchor),
    ])

    root.addArrangedSubview(makeLocationSection())
    root.addArrangedSubview(makeSeparator())
    root.addArrangedSubview(makeStartupSection())
    root.addArrangedSubview(makeSeparator())
    root.addArrangedSubview(makeRefreshIntervalsSection())
    root.addArrangedSubview(makeSeparator())
    root.addArrangedSubview(makeMACRegistrantDatabaseSection())
    root.addArrangedSubview(makeSeparator())
    root.addArrangedSubview(makeStrictSection())

    operationStatus.font = .systemFont(ofSize: 12)
    operationStatus.textColor = .systemRed
    operationStatus.maximumNumberOfLines = 3
    operationStatus.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

    repairLockSettingsButton.target = self
    repairLockSettingsButton.action = #selector(repairLockSettings)
    repairLockSettingsButton.bezelStyle = .rounded
    repairLockSettingsButton.setAccessibilityHelp(
      "Remove the malformed saved BSSID lock record so a new lock can be configured."
    )

    operationStatusRow.orientation = .horizontal
    operationStatusRow.alignment = .centerY
    operationStatusRow.spacing = 10
    operationStatusRow.addArrangedSubview(operationStatus)
    operationStatusRow.addArrangedSubview(NSView())
    operationStatusRow.addArrangedSubview(repairLockSettingsButton)
    operationStatusRow.widthAnchor.constraint(equalToConstant: 492).isActive = true
    root.addArrangedSubview(operationStatusRow)

    root.addArrangedSubview(makeSeparator())
    root.addArrangedSubview(makeResetToDefaultsRow())
  }

  private func updateWindowSize() {
    guard let window, let content = window.contentView else { return }
    content.layoutSubtreeIfNeeded()
    let requiredHeight = ceil(root.fittingSize.height)
    guard requiredHeight.isFinite, requiredHeight > 0 else { return }
    let currentWidth = window.contentRect(forFrameRect: window.frame).width
    let requiredFrame = window.frameRect(
      forContentRect: NSRect(x: 0, y: 0, width: currentWidth, height: requiredHeight)
    )
    let maximumFrameHeight =
      (window.screen ?? NSScreen.main).map {
        max(420, $0.visibleFrame.height - 40)
      } ?? requiredFrame.height
    let targetFrameHeight = min(requiredFrame.height, maximumFrameHeight)
    let targetContentHeight = window.contentRect(
      forFrameRect: NSRect(x: 0, y: 0, width: currentWidth, height: targetFrameHeight)
    ).height
    window.setContentSize(NSSize(width: currentWidth, height: targetContentHeight))
    content.layoutSubtreeIfNeeded()
    documentView.frame = NSRect(
      x: 0,
      y: 0,
      width: max(scrollView.contentSize.width, ceil(root.fittingSize.width)),
      height: requiredHeight
    )
    scrollView.reflectScrolledClipView(scrollView.contentView)
    if let screen = window.screen ?? NSScreen.main {
      let visibleFrame = screen.visibleFrame.insetBy(dx: 20, dy: 20)
      var constrainedFrame = window.frame
      if constrainedFrame.maxX > visibleFrame.maxX {
        constrainedFrame.origin.x = visibleFrame.maxX - constrainedFrame.width
      }
      if constrainedFrame.minX < visibleFrame.minX {
        constrainedFrame.origin.x = visibleFrame.minX
      }
      if constrainedFrame.maxY > visibleFrame.maxY {
        constrainedFrame.origin.y = visibleFrame.maxY - constrainedFrame.height
      }
      if constrainedFrame.minY < visibleFrame.minY {
        constrainedFrame.origin.y = visibleFrame.minY
      }
      window.setFrame(constrainedFrame, display: false)
    }
  }

  private func makeLocationSection() -> NSView {
    let title = sectionTitle("Location Access")
    let explanation = NSTextField(
      wrappingLabelWithString:
        "macOS treats nearby Wi-Fi identifiers as location information. BSSID Picker needs Location access to read the current SSID/BSSID and scan access points; it does not request your geographic coordinates."
    )
    explanation.textColor = .secondaryLabelColor
    explanation.maximumNumberOfLines = 4
    explanation.widthAnchor.constraint(equalToConstant: 492).isActive = true

    locationStatus.font = .systemFont(ofSize: 12, weight: .medium)
    locationStatus.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

    locationAction.target = self
    locationAction.action = #selector(performLocationAction)
    locationAction.bezelStyle = .rounded
    locationAction.setAccessibilityLabel("Configure Location access")

    let statusRow = NSStackView(views: [locationStatus, NSView(), locationAction])
    statusRow.orientation = .horizontal
    statusRow.alignment = .centerY
    statusRow.widthAnchor.constraint(equalToConstant: 492).isActive = true

    let section = NSStackView(views: [title, explanation, statusRow])
    section.orientation = .vertical
    section.alignment = .leading
    section.spacing = 8
    return section
  }

  private func makeStartupSection() -> NSView {
    let title = sectionTitle("Startup")
    launchAtLoginToggle.target = self
    launchAtLoginToggle.action = #selector(launchAtLoginChanged)
    launchAtLoginToggle.setAccessibilityHelp(
      "Open BSSID Picker as a menu-bar app when you sign in. This does not open Wi-Fi Scanner."
    )

    launchAtLoginStatus.font = .systemFont(ofSize: 11)
    launchAtLoginStatus.maximumNumberOfLines = 3
    launchAtLoginStatus.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
    launchAtLoginStatus.setAccessibilityLabel("Launch at Login status")

    openLoginItemsSettingsButton.target = self
    openLoginItemsSettingsButton.action = #selector(openLoginItemsSettings)
    openLoginItemsSettingsButton.bezelStyle = .rounded
    openLoginItemsSettingsButton.setAccessibilityHelp(
      "Open General, Login Items & Extensions in System Settings to approve BSSID Picker."
    )

    launchAtLoginStatusRow.addArrangedSubview(launchAtLoginStatus)
    launchAtLoginStatusRow.addArrangedSubview(NSView())
    launchAtLoginStatusRow.addArrangedSubview(openLoginItemsSettingsButton)
    launchAtLoginStatusRow.orientation = .horizontal
    launchAtLoginStatusRow.alignment = .centerY
    launchAtLoginStatusRow.spacing = 10
    launchAtLoginStatusRow.widthAnchor.constraint(equalToConstant: 492).isActive = true

    let section = NSStackView(views: [title, launchAtLoginToggle, launchAtLoginStatusRow])
    section.orientation = .vertical
    section.alignment = .leading
    section.spacing = 8
    return section
  }

  private func makeStrictSection() -> NSView {
    let title = sectionTitle("Association Mode")
    strictToggle.target = self
    strictToggle.action = #selector(strictModeChanged)
    strictToggle.setAccessibilityHelp(
      "Use an undocumented private macOS Wi-Fi API to request the exact scanned access point.")

    let warning = NSTextField(
      wrappingLabelWithString:
        "Strict BSSID uses an undocumented private CoreWiFi interface. Apple may change or remove it in any macOS update. BSSID Picker never silently falls back to ordinary same-SSID association when this mode is enabled."
    )
    warning.textColor = .secondaryLabelColor
    warning.maximumNumberOfLines = 4
    warning.widthAnchor.constraint(equalToConstant: 492).isActive = true

    strictStatus.font = .systemFont(ofSize: 11)
    strictStatus.textColor = .secondaryLabelColor
    strictStatus.lineBreakMode = .byTruncatingTail
    strictStatus.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

    strictProgress.style = .spinning
    strictProgress.controlSize = .small
    strictProgress.isDisplayedWhenStopped = false
    strictProgress.setAccessibilityLabel("Checking Strict BSSID availability")

    let strictStatusRow = NSStackView(views: [strictProgress, strictStatus])
    strictStatusRow.orientation = .horizontal
    strictStatusRow.alignment = .centerY
    strictStatusRow.spacing = 7
    strictStatusRow.widthAnchor.constraint(equalToConstant: 492).isActive = true

    let section = NSStackView(views: [title, strictToggle, warning, strictStatusRow])
    section.orientation = .vertical
    section.alignment = .leading
    section.spacing = 8
    return section
  }

  private func makeRefreshIntervalsSection() -> NSView {
    let title = sectionTitle("Update Frequency")
    let explanation = NSTextField(
      wrappingLabelWithString:
        "Enter a whole number of seconds; 0 disables recurring updates. Opening the menu still performs one scan, and enabling BSSID lock still performs one check. Failed connections use a separate retry backoff. Shorter intervals may use more power."
    )
    explanation.textColor = .secondaryLabelColor
    explanation.maximumNumberOfLines = 4
    explanation.widthAnchor.constraint(equalToConstant: 492).isActive = true

    configureIntervalField(
      mainMenuRefreshField,
      action: #selector(mainMenuRefreshIntervalChanged),
      accessibilityLabel: "Menu scan interval",
      accessibilityHelp: "How often access points are rescanned while the status menu is open."
    )
    configureIntervalField(
      lockMonitorField,
      action: #selector(lockMonitorIntervalChanged),
      accessibilityLabel: "BSSID lock check interval",
      accessibilityHelp: "How often an enabled BSSID lock verifies the current association."
    )

    let menuLabel = formLabel("Menu scan interval:")
    let lockLabel = formLabel("BSSID lock check interval:")
    let menuUnit = formUnitLabel("seconds")
    let lockUnit = formUnitLabel("seconds")
    let grid = NSGridView(views: [
      [menuLabel, mainMenuRefreshField, menuUnit],
      [lockLabel, lockMonitorField, lockUnit],
    ])
    grid.rowSpacing = 8
    grid.columnSpacing = 12
    grid.column(at: 0).xPlacement = .trailing
    grid.column(at: 1).xPlacement = .leading

    let section = NSStackView(views: [title, explanation, grid])
    section.orientation = .vertical
    section.alignment = .leading
    section.spacing = 8
    return section
  }

  private func makeMACRegistrantDatabaseSection() -> NSView {
    let title = sectionTitle("MAC Registrant Database")
    let explanation = NSTextField(
      wrappingLabelWithString:
        "MAC registrants are looked up locally. Updates download the complete database; scanned BSSIDs are never sent."
    )
    explanation.textColor = .secondaryLabelColor
    explanation.maximumNumberOfLines = 3
    explanation.widthAnchor.constraint(equalToConstant: 492).isActive = true

    macRegistrantDatabaseStatus.font = .systemFont(ofSize: 12, weight: .medium)
    macRegistrantDatabaseStatus.setAccessibilityLabel("MAC registrant database status")
    macRegistrantDatabaseUpdated.font = .systemFont(ofSize: 12)
    macRegistrantDatabaseUpdated.textColor = .secondaryLabelColor
    macRegistrantDatabaseUpdated.setAccessibilityLabel("MAC registrant database updated")
    macRegistrantDatabaseError.font = .systemFont(ofSize: 11)
    macRegistrantDatabaseError.textColor = .systemRed
    macRegistrantDatabaseError.maximumNumberOfLines = 3
    macRegistrantDatabaseError.widthAnchor.constraint(equalToConstant: 492).isActive = true
    macRegistrantDatabaseError.setAccessibilityLabel("MAC registrant database update error")

    let statusLabel = formLabel("Database Status:")
    let updatedLabel = formLabel("Database Updated:")
    let grid = NSGridView(views: [
      [statusLabel, macRegistrantDatabaseStatus],
      [updatedLabel, macRegistrantDatabaseUpdated],
    ])
    grid.rowSpacing = 7
    grid.columnSpacing = 12
    grid.column(at: 0).xPlacement = .trailing
    grid.column(at: 1).xPlacement = .leading

    updateMACRegistrantDatabaseButton.target = self
    updateMACRegistrantDatabaseButton.action = #selector(updateMACRegistrantDatabase)
    updateMACRegistrantDatabaseButton.bezelStyle = .rounded
    updateMACRegistrantDatabaseButton.setAccessibilityHelp(
      "Download the complete registrant database for local lookups. No scanned BSSID is transmitted."
    )

    showMACRegistrantSourcesButton.target = self
    showMACRegistrantSourcesButton.action = #selector(showMACRegistrantSources)
    showMACRegistrantSourcesButton.bezelStyle = .rounded
    showMACRegistrantSourcesButton.setAccessibilityHelp(
      "Show the database sources, purposes, versions, and licenses."
    )

    let buttons = NSStackView(views: [
      updateMACRegistrantDatabaseButton, showMACRegistrantSourcesButton,
    ])
    buttons.orientation = .horizontal
    buttons.alignment = .centerY
    buttons.spacing = 8

    let section = NSStackView(views: [
      title, explanation, grid, macRegistrantDatabaseError, buttons,
    ])
    section.orientation = .vertical
    section.alignment = .leading
    section.spacing = 8
    return section
  }

  private func renderMACRegistrantDatabase(_ database: MACRegistrantDatabaseViewState) {
    switch database.status {
    case .notDownloaded:
      macRegistrantDatabaseStatus.stringValue = "Not Downloaded"
      macRegistrantDatabaseStatus.textColor = .secondaryLabelColor
    case .ready:
      macRegistrantDatabaseStatus.stringValue = "Ready"
      macRegistrantDatabaseStatus.textColor = .systemGreen
    case .downloading:
      macRegistrantDatabaseStatus.stringValue = "Downloading…"
      macRegistrantDatabaseStatus.textColor = .secondaryLabelColor
    case .validating:
      macRegistrantDatabaseStatus.stringValue = "Validating…"
      macRegistrantDatabaseStatus.textColor = .secondaryLabelColor
    case .installing:
      macRegistrantDatabaseStatus.stringValue = "Installing…"
      macRegistrantDatabaseStatus.textColor = .secondaryLabelColor
    case .failed:
      macRegistrantDatabaseStatus.stringValue = "Update Failed"
      macRegistrantDatabaseStatus.textColor = .systemRed
    }

    if let updatedAt = database.updatedAt {
      macRegistrantDatabaseUpdated.stringValue = Self.databaseDateFormatter.string(from: updatedAt)
      macRegistrantDatabaseUpdated.toolTip = DateFormatter.localizedString(
        from: updatedAt,
        dateStyle: .full,
        timeStyle: .long
      )
    } else {
      macRegistrantDatabaseUpdated.stringValue = "Never"
      macRegistrantDatabaseUpdated.toolTip = "No MAC registrant database has been installed."
    }

    let statusHelp: String
    if let error = database.errorMessage {
      statusHelp = error
    } else if database.status == .ready {
      statusHelp = "The installed database is available for local MAC-prefix lookups."
    } else if database.isBusy {
      statusHelp = "A complete database update is in progress."
    } else {
      statusHelp = "No MAC registrant database is installed."
    }
    macRegistrantDatabaseStatus.toolTip = statusHelp
    macRegistrantDatabaseStatus.setAccessibilityValue(
      database.errorMessage.map { "\(macRegistrantDatabaseStatus.stringValue). \($0)" }
        ?? macRegistrantDatabaseStatus.stringValue
    )
    macRegistrantDatabaseError.stringValue = database.errorMessage ?? ""
    macRegistrantDatabaseError.isHidden = database.errorMessage == nil

    updateMACRegistrantDatabaseButton.title =
      database.hasInstalledDatabase ? "Update Database" : "Download Database"
    updateMACRegistrantDatabaseButton.isEnabled =
      state.controlsEnabled && database.canUpdate && !database.isBusy
    if !database.canUpdate && !database.isBusy {
      updateMACRegistrantDatabaseButton.toolTip =
        "Wireshark requests that automated database downloads occur no more than once per week."
    } else {
      updateMACRegistrantDatabaseButton.toolTip =
        "Download the complete MAC registrant database without transmitting scanned BSSIDs."
    }
    showMACRegistrantSourcesButton.isEnabled = !database.isBusy
  }

  private static let databaseDateFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateStyle = .long
    formatter.timeStyle = .none
    return formatter
  }()

  private func makeResetToDefaultsRow() -> NSView {
    resetToDefaultsButton.target = self
    resetToDefaultsButton.action = #selector(resetToDefaults)
    resetToDefaultsButton.bezelStyle = .rounded
    resetToDefaultsButton.hasDestructiveAction = true
    resetToDefaultsButton.setAccessibilityLabel("Reset BSSID Picker settings to defaults")
    resetToDefaultsButton.setAccessibilityHelp(
      "Ask for confirmation before restoring BSSID Picker's configurable settings to their defaults."
    )
    resetToDefaultsButton.toolTip =
      "Restore configurable settings to their defaults after confirmation."

    let row = NSStackView(views: [NSView(), resetToDefaultsButton])
    row.orientation = .horizontal
    row.alignment = .centerY
    row.widthAnchor.constraint(equalToConstant: 492).isActive = true
    return row
  }

  private var locationSummary: String {
    switch state.locationState {
    case .allowed: return "Location access: Allowed"
    case .notDetermined: return "Location access: Not requested"
    case .denied: return "Location access: Denied"
    case .unavailable: return "Location access: Unavailable"
    }
  }

  private var launchAtLoginSummary: String {
    if let error = state.launchAtLoginErrorMessage { return error }
    switch state.launchAtLoginStatus {
    case .notRegistered, .notFound:
      return "BSSID Picker will not open automatically when you sign in."
    case .enabled:
      return "BSSID Picker will open as a menu-bar app when you sign in."
    case .requiresApproval:
      return
        "Disabled in System Settings. Approval is required before BSSID Picker can open at login."
    case .unknown:
      return "Launch at Login is unavailable because macOS returned an unsupported service state."
    }
  }

  private var launchAtLoginHelp: String {
    switch state.launchAtLoginStatus {
    case .notRegistered, .notFound:
      return "Launch at Login is off."
    case .enabled:
      return "Launch at Login is enabled. Wi-Fi Scanner will remain closed."
    case .requiresApproval:
      return
        "BSSID Picker is registered but disabled in System Settings. Open Login Items settings to approve it."
    case .unknown:
      return "This version of macOS returned a Launch at Login state the app does not recognize."
    }
  }

  private var launchAtLoginColor: NSColor {
    if state.launchAtLoginErrorMessage != nil { return .systemRed }
    switch state.launchAtLoginStatus {
    case .requiresApproval: return .systemOrange
    case .unknown: return .systemRed
    case .notRegistered, .enabled, .notFound: return .secondaryLabelColor
    }
  }

  private var locationHelp: String {
    switch state.locationState {
    case .allowed:
      return
        "BSSID Picker can read protected Wi-Fi identifiers. Use System Settings to change access."
    case .notDetermined:
      return "Ask macOS to grant BSSID Picker access to protected Wi-Fi identifiers."
    case .denied:
      return
        "Open Privacy & Security in System Settings and allow Location access for BSSID Picker."
    case .unavailable:
      return "Location Services is restricted or unavailable on this Mac."
    }
  }

  private var locationActionTitle: String {
    state.locationState == .notDetermined ? "Request Access…" : "Open System Settings…"
  }

  private var locationColor: NSColor {
    switch state.locationState {
    case .allowed: return .systemGreen
    case .notDetermined: return .secondaryLabelColor
    case .denied, .unavailable: return .systemOrange
    }
  }

  private func sectionTitle(_ text: String) -> NSTextField {
    let label = NSTextField(labelWithString: text)
    label.font = .systemFont(ofSize: 15, weight: .semibold)
    return label
  }

  private func formLabel(_ text: String) -> NSTextField {
    let label = NSTextField(labelWithString: text)
    label.textColor = .secondaryLabelColor
    label.alignment = .right
    return label
  }

  private func formUnitLabel(_ text: String) -> NSTextField {
    let label = NSTextField(labelWithString: text)
    label.textColor = .secondaryLabelColor
    return label
  }

  private func configureIntervalField(
    _ field: NSTextField,
    action: Selector,
    accessibilityLabel: String,
    accessibilityHelp: String
  ) {
    field.alignment = .right
    field.placeholderString = "0"
    field.delegate = self
    field.target = self
    field.action = action
    field.widthAnchor.constraint(equalToConstant: 90).isActive = true
    field.setAccessibilityLabel(accessibilityLabel)
    field.setAccessibilityHelp(
      accessibilityHelp + " Enter a whole number of seconds, or 0 to disable automatic updates."
    )
  }

  private func setInterval(_ interval: Int, in field: NSTextField) {
    field.stringValue = AutomaticUpdateInterval.format(interval)
  }

  private func synchronizeInterval(_ interval: Int, with field: NSTextField) {
    guard field.currentEditor() == nil else { return }
    setInterval(interval, in: field)
  }

  private func makeSeparator() -> NSBox {
    let separator = NSBox()
    separator.boxType = .separator
    separator.widthAnchor.constraint(equalToConstant: 492).isActive = true
    return separator
  }

  @objc private func performLocationAction() {
    switch state.locationState {
    case .notDetermined: onRequestLocation?()
    case .allowed, .denied: onOpenLocationSettings?()
    case .unavailable: break
    }
  }

  @objc private func launchAtLoginChanged() {
    let requested = launchAtLoginToggle.state == .on
    launchAtLoginToggle.state = state.launchAtLoginStatus.isRegistered ? .on : .off
    onSetLaunchAtLoginEnabled?(requested)
  }

  @objc private func openLoginItemsSettings() {
    onOpenLoginItemsSettings?()
  }

  @objc private func strictModeChanged() {
    let requested = strictToggle.state == .on
    // The owner may need an availability check and warning before accepting
    // the change. Keep the rendered value authoritative during that work.
    strictToggle.state = state.strictBSSIDEnabled ? .on : .off
    onSetStrictEnabled?(requested)
  }

  @objc private func mainMenuRefreshIntervalChanged() {
    commitInterval(
      from: mainMenuRefreshField,
      currentValue: state.mainMenuRefreshInterval,
      action: onSetMainMenuRefreshInterval
    )
  }

  @objc private func lockMonitorIntervalChanged() {
    commitInterval(
      from: lockMonitorField,
      currentValue: state.lockMonitorInterval,
      action: onSetLockMonitorInterval
    )
  }

  @objc private func updateMACRegistrantDatabase() {
    guard state.macRegistrantDatabase.canUpdate, !state.macRegistrantDatabase.isBusy else {
      return
    }
    onUpdateMACRegistrantDatabase?()
  }

  @objc private func showMACRegistrantSources() {
    guard let window else { return }
    let metadata = state.macRegistrantDatabase.metadata
    let installedSnapshot =
      (metadata?.updatedAt).map {
        "Installed snapshot downloaded \(Self.databaseDateFormatter.string(from: $0))"
      } ?? "Not downloaded"
    let installedSources = metadata?.sources ?? []
    let sources =
      installedSources.isEmpty
      ? [MACRegistrantDatabase.manufacturerSource, MACRegistrantDatabase.knownAddressSource]
      : installedSources
    let sourceDetails =
      sources
      .map { source in
        """
        \(source.name)
        Purpose: \(source.purpose)
        Source: \(source.sourceURL.absoluteString)
        Version: \(installedSnapshot)
        License: \(source.license) (\(source.licenseURL.absoluteString))
        Attribution: \(source.attribution)
        """
      }
      .joined(separator: "\n\n")
    let recordDetails = metadata.map {
      "Installed records: \($0.manufacturerRecordCount) MAC registrations; \($0.knownAddressRecordCount) known-address roles."
    }
    let alert = NSAlert()
    alert.messageText = "MAC Registrant Database Sources"
    alert.informativeText = """
      \(sourceDetails)

      \(recordDetails ?? "No records installed.")

      Registry names identify a MAC-prefix registrant, which may differ from the access point's brand or manufacturer.
      """
    alert.alertStyle = .informational
    alert.addButton(withTitle: "Close")
    if state.macRegistrantDatabase.hasInstalledDatabase {
      let removeButton = alert.addButton(withTitle: "Remove Downloaded Data…")
      removeButton.hasDestructiveAction = true
    }
    alert.beginSheetModal(for: window) { [weak self] response in
      guard response == .alertSecondButtonReturn else { return }
      self?.confirmRemoveMACRegistrantDatabase()
    }
  }

  private func confirmRemoveMACRegistrantDatabase() {
    guard let window else { return }
    let alert = NSAlert()
    alert.messageText = "Remove Downloaded MAC Registrant Data?"
    alert.informativeText =
      "This removes the local database. Wi-Fi scans and settings are not affected."
    alert.alertStyle = .warning
    let removeButton = alert.addButton(withTitle: "Remove")
    removeButton.hasDestructiveAction = true
    removeButton.keyEquivalent = ""
    let cancelButton = alert.addButton(withTitle: "Cancel")
    cancelButton.keyEquivalent = "\r"
    cancelButton.keyEquivalentModifierMask = []
    alert.beginSheetModal(for: window) { [weak self] response in
      guard response == .alertFirstButtonReturn else { return }
      self?.onRemoveMACRegistrantDatabase?()
    }
  }

  func controlTextDidEndEditing(_ notification: Notification) {
    guard let field = notification.object as? NSTextField else { return }
    if field === mainMenuRefreshField {
      mainMenuRefreshIntervalChanged()
    } else if field === lockMonitorField {
      lockMonitorIntervalChanged()
    }
  }

  private func commitInterval(
    from field: NSTextField,
    currentValue: Int,
    action: ((Int) -> Void)?
  ) {
    guard let interval = AutomaticUpdateInterval.parse(field.stringValue) else {
      setInterval(currentValue, in: field)
      NSSound.beep()
      return
    }

    setInterval(interval, in: field)
    guard interval != currentValue else { return }
    action?(interval)
  }

  @objc private func repairLockSettings() {
    onRepairLockSettings?()
  }

  @objc private func resetToDefaults() {
    guard state.controlsEnabled, state.resetToDefaultsEnabled else { return }
    onResetToDefaults?()
  }

  func windowDidBecomeKey(_ notification: Notification) {
    onRefreshLaunchAtLogin?()
  }

  func windowDidChangeScreen(_ notification: Notification) {
    updateWindowSize()
  }
}
