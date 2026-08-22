// SPDX-License-Identifier: GPL-3.0-only

import AppKit

final class ScanWindowController: NSWindowController {
  private enum Layout {
    static let rootInset: CGFloat = 10
    static let defaultContentSize = NSSize(width: 1440, height: 760)
    static let tableMinimumWidth: CGFloat = 500
    static let inspectorMinimumWidth: CGFloat = 350
    static let inspectorPreferredWidth: CGFloat = 480
    static let tableHoldingPriority = NSLayoutConstraint.Priority.defaultLow
    static let inspectorHoldingPriority = NSLayoutConstraint.Priority(rawValue: 251)
    static let inspectorPreferencePriority = NSLayoutConstraint.Priority(rawValue: 489)
    static let frameAutosaveName = "BSSIDPicker.ScanWindow"
    static let splitAutosaveName = "BSSIDPicker.ScanWindow.Split"
    static let splitAutosaveDefaultsKey =
      "NSSplitView Subview Frames \(splitAutosaveName)"
  }

  private let service: CoreWLANService
  private let preferenceStore: ScanPreferenceStore
  private var macRegistrantResolver: MACRegistrantResolver
  var onScannerOpenStateChanged: ((Bool) -> Void)?
  var preferences: ScanSavedPreferences
  let tableView = ScanTableView()
  private let tableScrollView = NSScrollView()
  private let splitView = NSSplitView()
  private let inspectorView: ScanInspectorView
  private var inspectorWidthPreference: NSLayoutConstraint?
  let statusLabel = NSTextField(labelWithString: "Not Scanned")
  private let progressIndicator = NSProgressIndicator()
  private let emptyView = NSStackView()
  private let emptyTitle = NSTextField(labelWithString: "")
  private let emptyDetail = NSTextField(wrappingLabelWithString: "")
  private lazy var emptyActionButton = NSButton(
    title: "Scan Again",
    target: self,
    action: #selector(scanManually)
  )
  private lazy var scanButton = NSButton(
    title: "Scan",
    target: self,
    action: #selector(scanManually)
  )
  private let automaticScanIntervalLabel = NSTextField(
    labelWithString: "Automatic scan interval:")
  private let automaticScanIntervalField = NSTextField()
  private let automaticScanIntervalUnitLabel = NSTextField(labelWithString: "seconds (0 = off)")
  private let cacheRetentionLabel = NSTextField(labelWithString: "Cache retention:")
  private let cacheRetentionField = NSTextField()
  private let cacheRetentionUnitLabel = NSTextField(labelWithString: "seconds (0 = no cache)")
  let presetPopup = NSPopUpButton()
  let columnsPopup = NSPopUpButton(frame: .zero, pullsDown: true)
  private let observationPopup = NSPopUpButton()
  private let bandPopup = NSPopUpButton()
  private let securityPopup = NSPopUpButton()
  private let capabilityPopup = NSPopUpButton()
  private let searchField = NSSearchField()
  private lazy var regexToggle = NSButton(
    checkboxWithTitle: "Regex",
    target: self,
    action: #selector(regexModeChanged)
  )
  let exportPopup = NSPopUpButton(frame: .zero, pullsDown: true)

  var allRows: [ScanRow] = []
  var displayedRows: [ScanRow] = []
  private var filter = ScanFilter()
  var selectedIdentity: ScanRowIdentity?
  var context: ScannerContextSnapshot?
  var interfaceSnapshot: WiFiInterfaceSnapshot?
  private var scanningAllowed = false
  /// Tracks the user's open/closed scanner session independently of AppKit
  /// visibility. A scanner remains open while its window is hidden with the
  /// app or miniaturized, so automatic scans and cache expiry continue.
  private var isScannerOpen = false
  private var isScanning = false
  private var scanGeneration = 0
  private var activeScanReason = ScanReason.initial
  private var automaticScanTimer: Timer?
  private var cacheExpiryTimer: Timer?
  private var searchDebounceWorkItem: DispatchWorkItem?
  private var searchDebounceGeneration: UInt64 = 0
  private var searchValidationError: String?
  private let tableReloadDeferrer = ScanTableReloadDeferrer()
  var lastScanDate: Date?
  private var lastScanError: String?
  var isApplyingColumnLayout = false
  var isRestoringSelection = false
  private var tableNotificationTokens: [NSObjectProtocol] = []

  init(
    service: CoreWLANService,
    macRegistrantResolver: MACRegistrantResolver = .unavailable,
    preferenceStore: ScanPreferenceStore = ScanPreferenceStore()
  ) {
    self.service = service
    self.macRegistrantResolver = macRegistrantResolver
    self.preferenceStore = preferenceStore
    preferences = preferenceStore.load()
    inspectorView = ScanInspectorView(rawExpanded: preferences.rawInspectorExpanded)

    let window = ScanCommandWindow(
      contentRect: NSRect(origin: .zero, size: Layout.defaultContentSize),
      styleMask: [.titled, .closable, .miniaturizable, .resizable],
      backing: .buffered,
      defer: false
    )
    super.init(window: window)
    window.onScan = { [weak self] in
      guard let self else { return false }
      self.scanManually()
      return true
    }
    window.onFocusSearch = { [weak self] in
      guard let self else { return false }
      self.window?.makeFirstResponder(self.searchField)
      return true
    }
    window.onCopy = { [weak self] in
      guard let self, self.selectedRow != nil else { return false }
      self.copySelectedRow()
      return true
    }
    window.onClose = { [weak self] in
      guard let self else { return false }
      self.window?.performClose(nil)
      return true
    }
    window.delegate = self
    window.title = "Wi-Fi Scanner"
    window.subtitle = "Nearby access points and IEEE 802.11 information"
    window.minSize = NSSize(width: 900, height: 520)
    window.autorecalculatesKeyViewLoop = true
    if !window.setFrameUsingName(Layout.frameAutosaveName) {
      window.center()
    }
    window.setFrameAutosaveName(Layout.frameAutosaveName)

    buildInterface()
    configureControls()
    configureTable()
    applyColumnLayout()
    wireInspectorActions()
    updateAutomaticScanTimer()
    rebuildDisplayedRows()
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    fatalError("init(coder:) is not supported")
  }

  deinit {
    automaticScanTimer?.invalidate()
    cacheExpiryTimer?.invalidate()
    cancelPendingSearchRebuild()
    tableReloadDeferrer.cancel()
    for token in tableNotificationTokens {
      NotificationCenter.default.removeObserver(token)
    }
  }

  func updateContext(_ context: ScannerContextSnapshot) {
    guard scanningAllowed else { return }
    let previousContext = self.context
    guard previousContext != context else { return }
    self.context = context

    let associationObservationChanged =
      previousContext?.client.capturedAt != context.client.capturedAt
      || previousContext?.client.rawSSID != context.client.rawSSID
      || previousContext?.client.currentBSSID != context.client.currentBSSID
    let rowPresentationChanged =
      previousContext == nil
      || previousContext?.client.lock.target != context.client.lock.target
      || previousContext?.client.systemKeychainConsent != context.client.systemKeychainConsent
      || previousContext?.connectionEvents != context.connectionEvents
      || associationObservationChanged

    guard rowPresentationChanged else {
      updateInspector()
      return
    }
    allRows = allRows.map {
      $0.applyingClientContext(context, interfaceSnapshot: interfaceSnapshot)
    }
    rebuildDisplayedRows(revealSelection: false)
  }

  /// Re-enriches current and retained observations from an immutable local
  /// database snapshot. This intentionally performs no CoreWLAN operation.
  func updateMACRegistrantResolver(_ resolver: MACRegistrantResolver) {
    guard macRegistrantResolver.metadata != resolver.metadata else { return }
    macRegistrantResolver = resolver
    allRows = allRows.map { row in
      row.applyingMACAttribution(resolver.resolve(row.accessPoint.bssid))
    }
    rebuildDisplayedRows(revealSelection: false)
  }

  func setScanningAllowed(_ allowed: Bool) {
    guard scanningAllowed != allowed else { return }
    scanningAllowed = allowed
    scanButton.isEnabled = allowed && !isScanning
    updateScanBehaviorAvailability()
    emptyActionButton.isEnabled = allowed
    if allowed {
      updateAutomaticScanTimer()
      rebuildDisplayedRows()
    } else {
      automaticScanTimer?.invalidate()
      automaticScanTimer = nil
      cacheExpiryTimer?.invalidate()
      cacheExpiryTimer = nil
      clearProtectedData()
    }
  }

  /// Removes every value obtained through Location-protected CoreWLAN APIs.
  /// User-selected filters, columns, and live-mode preference are retained.
  func clearProtectedData() {
    tableReloadDeferrer.cancel()
    window?.makeFirstResponder(tableView)
    scanGeneration &+= 1
    isScanning = false
    progressIndicator.stopAnimation(nil)
    cacheExpiryTimer?.invalidate()
    cacheExpiryTimer = nil
    allRows = []
    displayedRows = []
    selectedIdentity = nil
    context = nil
    interfaceSnapshot = nil
    lastScanDate = nil
    lastScanError = nil
    scanButton.isEnabled = scanningAllowed
    rebuildDisplayedRows()
  }

  func showAndScan() {
    if !isScannerOpen {
      isScannerOpen = true
      onScannerOpenStateChanged?(true)
    }
    _ = pruneExpiredRetainedRows(at: Date())
    rebuildDisplayedRows(revealSelection: false, refreshInspector: false)
    showWindow(nil)
    window?.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
    updateAutomaticScanTimer()
    updateCacheExpiryTimer()
    if scanningAllowed {
      requestScan(reason: .initial)
    }
  }

  static func resetPersistedDefaults(defaults: UserDefaults = .standard) {
    ScanPreferenceStore(defaults: defaults).resetToDefaults()
    NSWindow.removeFrame(usingName: Layout.frameAutosaveName)
    defaults.removeObject(forKey: Layout.splitAutosaveDefaultsKey)
  }

  func resetToDefaults() {
    window?.makeFirstResponder(nil)
    tableReloadDeferrer.cancel()
    automaticScanTimer?.invalidate()
    automaticScanTimer = nil
    cacheExpiryTimer?.invalidate()
    cacheExpiryTimer = nil

    Self.resetPersistedDefaults()
    preferences = .defaults
    filter = ScanFilter()
    searchField.stringValue = ""
    regexToggle.state = .off
    updateSearchFieldPresentation()
    observationPopup.selectItem(at: 0)
    bandPopup.selectItem(at: 0)
    securityPopup.selectItem(at: 0)
    capabilityPopup.selectItem(at: 0)
    automaticScanIntervalField.stringValue = AutomaticUpdateInterval.format(
      preferences.automaticScanInterval
    )
    cacheRetentionField.stringValue = AutomaticUpdateInterval.format(
      preferences.cacheRetentionSeconds
    )
    if let customIndex = presetPopup.itemArray.firstIndex(where: {
      ($0.representedObject as? ScanPreset) == .custom
    }) {
      presetPopup.removeItem(at: customIndex)
    }
    selectPresetItem(preferences.preset)
    inspectorView.resetToDefaults()
    applyColumnLayout()

    _ = pruneExpiredRetainedRows(at: Date())
    resetWindowLayout()
    rebuildDisplayedRows(revealSelection: false)
    updateAutomaticScanTimer()
    updateCacheExpiryTimer()
  }

  private func resetWindowLayout() {
    splitView.autosaveName = nil
    inspectorWidthPreference?.constant = Layout.inspectorPreferredWidth
    if let window {
      window.setContentSize(Layout.defaultContentSize)
      window.center()
      window.contentView?.layoutSubtreeIfNeeded()
    }

    let minimumPosition = splitView.bounds.minX + Layout.tableMinimumWidth
    let preferredPosition =
      splitView.bounds.maxX - splitView.dividerThickness - Layout.inspectorPreferredWidth
    if preferredPosition >= minimumPosition {
      splitView.setPosition(preferredPosition, ofDividerAt: 0)
    }
    splitView.autosaveName = Layout.splitAutosaveName
    window?.saveFrame(usingName: Layout.frameAutosaveName)
  }

  private func buildInterface() {
    guard let contentView = window?.contentView else { return }

    let root = NSStackView()
    root.translatesAutoresizingMaskIntoConstraints = false
    root.orientation = .vertical
    root.spacing = 8
    root.edgeInsets = NSEdgeInsets(
      top: Layout.rootInset,
      left: Layout.rootInset,
      bottom: Layout.rootInset,
      right: Layout.rootInset
    )
    contentView.addSubview(root)
    NSLayoutConstraint.activate([
      root.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
      root.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
      root.topAnchor.constraint(equalTo: contentView.topAnchor),
      root.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
    ])

    let commandBar = makeCommandBar()
    root.addArrangedSubview(commandBar)
    commandBar.widthAnchor.constraint(
      equalTo: root.widthAnchor,
      constant: -(Layout.rootInset * 2)
    ).isActive = true

    splitView.translatesAutoresizingMaskIntoConstraints = false
    splitView.isVertical = true
    splitView.dividerStyle = .thin
    splitView.delegate = self

    let tableContainer = makeTableContainer()
    tableContainer.frame.size.width = Layout.tableMinimumWidth
    inspectorView.frame.size.width = Layout.inspectorPreferredWidth
    splitView.addArrangedSubview(tableContainer)
    splitView.addArrangedSubview(inspectorView)
    splitView.setHoldingPriority(Layout.tableHoldingPriority, forSubviewAt: 0)
    splitView.setHoldingPriority(Layout.inspectorHoldingPriority, forSubviewAt: 1)
    tableContainer.widthAnchor.constraint(greaterThanOrEqualToConstant: Layout.tableMinimumWidth)
      .isActive = true
    inspectorView.widthAnchor.constraint(
      greaterThanOrEqualToConstant: Layout.inspectorMinimumWidth
    ).isActive = true
    root.addArrangedSubview(splitView)
    splitView.widthAnchor.constraint(
      equalTo: root.widthAnchor,
      constant: -(Layout.rootInset * 2)
    ).isActive = true
    // Assigning the autosave name after adding both panes lets AppKit restore
    // a user's divider position over the fresh-install seed widths above.
    splitView.autosaveName = Layout.splitAutosaveName
    let restoredInspectorWidth = inspectorView.frame.width
    let preferredInspectorWidth =
      restoredInspectorWidth > 0 ? restoredInspectorWidth : Layout.inspectorPreferredWidth
    let inspectorWidthPreference = inspectorView.widthAnchor.constraint(
      equalToConstant: preferredInspectorWidth
    )
    inspectorWidthPreference.priority = Layout.inspectorPreferencePriority
    inspectorWidthPreference.isActive = true
    self.inspectorWidthPreference = inspectorWidthPreference

    let footer = NSStackView()
    footer.orientation = .horizontal
    footer.alignment = .centerY
    footer.spacing = 7

    progressIndicator.style = .spinning
    progressIndicator.controlSize = .small
    progressIndicator.isDisplayedWhenStopped = false
    progressIndicator.setAccessibilityLabel("Scan progress")
    footer.addArrangedSubview(progressIndicator)

    statusLabel.lineBreakMode = .byTruncatingMiddle
    statusLabel.setContentHuggingPriority(.defaultLow, for: .horizontal)
    statusLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
    statusLabel.setAccessibilityLabel("Scan Status")
    footer.addArrangedSubview(statusLabel)
    root.addArrangedSubview(footer)
    footer.widthAnchor.constraint(equalTo: splitView.widthAnchor).isActive = true
  }

  private func makeCommandBar() -> NSView {
    let commandBar = NSStackView()
    commandBar.orientation = .vertical
    commandBar.alignment = .leading
    commandBar.spacing = 6

    let primaryBar = NSStackView()
    primaryBar.orientation = .horizontal
    primaryBar.alignment = .centerY
    primaryBar.spacing = 8

    let filterBar = NSStackView()
    filterBar.orientation = .horizontal
    filterBar.alignment = .centerY
    filterBar.spacing = 8

    let scanBehaviorBar = NSStackView()
    scanBehaviorBar.orientation = .horizontal
    scanBehaviorBar.alignment = .centerY
    scanBehaviorBar.spacing = 8

    scanButton.bezelStyle = .rounded
    scanButton.keyEquivalent = "r"
    scanButton.keyEquivalentModifierMask = .command
    scanButton.toolTip = "Scan nearby Wi-Fi access points (⌘R)"
    primaryBar.addArrangedSubview(scanButton)

    primaryBar.addArrangedSubview(ScanWindowSupport.verticalSeparator())
    primaryBar.addArrangedSubview(NSTextField(labelWithString: "View:"))
    primaryBar.addArrangedSubview(presetPopup)
    primaryBar.addArrangedSubview(columnsPopup)

    searchField.placeholderString = "Search SSID, BSSID, or capability"
    searchField.sendsSearchStringImmediately = true
    searchField.sendsWholeSearchString = false
    searchField.setAccessibilityLabel("Search Access Points")
    searchField.setContentHuggingPriority(
      NSLayoutConstraint.Priority(rawValue: NSLayoutConstraint.Priority.defaultLow.rawValue - 1),
      for: .horizontal
    )
    searchField.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
    searchField.widthAnchor.constraint(greaterThanOrEqualToConstant: 220).isActive = true
    primaryBar.addArrangedSubview(searchField)
    primaryBar.addArrangedSubview(regexToggle)
    primaryBar.addArrangedSubview(exportPopup)

    let filterLabel = NSTextField(labelWithString: "Filters:")
    filterLabel.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize, weight: .medium)
    filterLabel.textColor = .secondaryLabelColor
    filterBar.addArrangedSubview(filterLabel)
    filterBar.addArrangedSubview(bandPopup)
    filterBar.addArrangedSubview(securityPopup)
    filterBar.addArrangedSubview(capabilityPopup)
    filterBar.addArrangedSubview(observationPopup)
    let clearButton = NSButton(title: "Clear", target: self, action: #selector(clearFilters))
    clearButton.bezelStyle = .inline
    clearButton.toolTip = "Clear the search text and every filter."
    filterBar.addArrangedSubview(clearButton)
    let filterSpacer = NSView()
    filterSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
    filterBar.addArrangedSubview(filterSpacer)

    let scanBehaviorLabel = NSTextField(labelWithString: "Scan behavior:")
    scanBehaviorLabel.font = NSFont.systemFont(
      ofSize: NSFont.smallSystemFontSize,
      weight: .medium
    )
    scanBehaviorLabel.textColor = .secondaryLabelColor
    scanBehaviorBar.addArrangedSubview(scanBehaviorLabel)

    automaticScanIntervalLabel.textColor = .secondaryLabelColor
    scanBehaviorBar.addArrangedSubview(automaticScanIntervalLabel)
    scanBehaviorBar.addArrangedSubview(automaticScanIntervalField)
    scanBehaviorBar.addArrangedSubview(automaticScanIntervalUnitLabel)
    scanBehaviorBar.addArrangedSubview(ScanWindowSupport.verticalSeparator())
    cacheRetentionLabel.textColor = .secondaryLabelColor
    scanBehaviorBar.addArrangedSubview(cacheRetentionLabel)
    scanBehaviorBar.addArrangedSubview(cacheRetentionField)
    scanBehaviorBar.addArrangedSubview(cacheRetentionUnitLabel)
    let scanBehaviorSpacer = NSView()
    scanBehaviorSpacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
    scanBehaviorBar.addArrangedSubview(scanBehaviorSpacer)

    commandBar.addArrangedSubview(primaryBar)
    commandBar.addArrangedSubview(filterBar)
    commandBar.addArrangedSubview(scanBehaviorBar)
    primaryBar.widthAnchor.constraint(equalTo: commandBar.widthAnchor).isActive = true
    filterBar.widthAnchor.constraint(equalTo: commandBar.widthAnchor).isActive = true
    scanBehaviorBar.widthAnchor.constraint(equalTo: commandBar.widthAnchor).isActive = true
    return commandBar
  }

  private func makeTableContainer() -> NSView {
    let container = NSView()
    container.translatesAutoresizingMaskIntoConstraints = false

    tableScrollView.translatesAutoresizingMaskIntoConstraints = false
    tableScrollView.hasVerticalScroller = true
    tableScrollView.hasHorizontalScroller = true
    tableScrollView.autohidesScrollers = true
    tableScrollView.borderType = .bezelBorder
    tableScrollView.documentView = tableView
    container.addSubview(tableScrollView)

    emptyView.translatesAutoresizingMaskIntoConstraints = false
    emptyView.orientation = .vertical
    emptyView.alignment = .centerX
    emptyView.spacing = 8

    let image = NSImageView()
    image.image = NSImage(
      systemSymbolName: "wifi.exclamationmark",
      accessibilityDescription: "Wi-Fi scan status"
    )
    image.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 34, weight: .regular)
    emptyView.addArrangedSubview(image)

    emptyTitle.font = NSFont.systemFont(ofSize: NSFont.systemFontSize + 2, weight: .semibold)
    emptyTitle.alignment = .center
    emptyView.addArrangedSubview(emptyTitle)

    emptyDetail.maximumNumberOfLines = 0
    emptyDetail.alignment = .center
    emptyDetail.textColor = .secondaryLabelColor
    emptyDetail.widthAnchor.constraint(lessThanOrEqualToConstant: 420).isActive = true
    emptyView.addArrangedSubview(emptyDetail)
    emptyView.addArrangedSubview(emptyActionButton)
    container.addSubview(emptyView)

    NSLayoutConstraint.activate([
      tableScrollView.leadingAnchor.constraint(equalTo: container.leadingAnchor),
      tableScrollView.trailingAnchor.constraint(equalTo: container.trailingAnchor),
      tableScrollView.topAnchor.constraint(equalTo: container.topAnchor),
      tableScrollView.bottomAnchor.constraint(equalTo: container.bottomAnchor),
      emptyView.centerXAnchor.constraint(equalTo: container.centerXAnchor),
      emptyView.centerYAnchor.constraint(equalTo: container.centerYAnchor),
      emptyView.leadingAnchor.constraint(
        greaterThanOrEqualTo: container.leadingAnchor, constant: 24),
      emptyView.trailingAnchor.constraint(
        lessThanOrEqualTo: container.trailingAnchor, constant: -24),
    ])
    return container
  }

  private func configureControls() {
    presetPopup.removeAllItems()
    for preset in ScanPreset.selectableCases {
      addPresetItem(preset)
    }
    if preferences.preset == .custom {
      addPresetItem(.custom)
    }
    selectPresetItem(preferences.preset)
    presetPopup.target = self
    presetPopup.action = #selector(presetChanged)
    presetPopup.setAccessibilityLabel("Column Preset")

    configureColumnsMenu()
    configureFilterMenus()
    configureExportMenu()
    configureAutomaticScanIntervalField()
    configureCacheRetentionField()
    searchField.delegate = self
    regexToggle.setAccessibilityLabel("Use Regular Expression")
    regexToggle.setAccessibilityHelp(
      "When selected, interpret the search text as a case-insensitive regular expression."
    )
    regexToggle.toolTip = "Interpret search text as a regular expression."
    updateSearchFieldPresentation()
  }

  private func configureAutomaticScanIntervalField() {
    automaticScanIntervalField.stringValue = AutomaticUpdateInterval.format(
      preferences.automaticScanInterval)
    automaticScanIntervalField.alignment = .right
    automaticScanIntervalField.placeholderString = "0"
    automaticScanIntervalField.target = self
    automaticScanIntervalField.action = #selector(automaticScanIntervalChanged)
    automaticScanIntervalField.delegate = self
    automaticScanIntervalField.widthAnchor.constraint(equalToConstant: 72).isActive = true
    updateScanBehaviorAvailability()
    automaticScanIntervalField.setAccessibilityLabel("Automatic scan interval in whole seconds")
    automaticScanIntervalField.setAccessibilityHelp(
      "Enter a whole number of seconds between automatic scans. Enter zero to turn automatic scanning off."
    )
    automaticScanIntervalField.toolTip =
      "Seconds between automatic scans. Enter 0 to turn automatic scanning off."
  }

  private func configureCacheRetentionField() {
    cacheRetentionField.stringValue = AutomaticUpdateInterval.format(
      preferences.cacheRetentionSeconds
    )
    cacheRetentionField.alignment = .right
    cacheRetentionField.placeholderString = "0"
    cacheRetentionField.target = self
    cacheRetentionField.action = #selector(cacheRetentionChanged)
    cacheRetentionField.delegate = self
    cacheRetentionField.widthAnchor.constraint(equalToConstant: 72).isActive = true
    updateScanBehaviorAvailability()
    cacheRetentionField.setAccessibilityLabel("Scan cache retention in whole seconds")
    cacheRetentionField.setAccessibilityHelp(
      "Enter how long missing access points remain visible. Enter zero to show only the latest successful scan."
    )
    cacheRetentionField.toolTip =
      "Seconds to retain access points missing from a later successful scan. Enter 0 to show only the latest successful scan."
  }

  private func configureFilterMenus() {
    observationPopup.removeAllItems()
    observationPopup.addItems(withTitles: ScanObservationFilter.allCases.map(\.rawValue))
    observationPopup.target = self
    observationPopup.action = #selector(filtersChanged)
    observationPopup.toolTip =
      "Filter by whether an access point appeared in the latest successful scan or is retained from an earlier scan."
    observationPopup.setAccessibilityLabel("Scan Observation Filter")
    observationPopup.setAccessibilityHelp(
      "Show all observations, access points seen in the latest successful scan, or cached observations retained from earlier scans."
    )

    bandPopup.removeAllItems()
    bandPopup.addItems(
      withTitles: ["Any Band", "2.4 GHz", "5 GHz", "6 GHz", "Other", "Unknown"]
    )
    bandPopup.target = self
    bandPopup.action = #selector(filtersChanged)
    bandPopup.setAccessibilityLabel("Band Filter")

    securityPopup.removeAllItems()
    securityPopup.addItems(withTitles: ScanSecurityFilter.allCases.map(\.rawValue))
    securityPopup.target = self
    securityPopup.action = #selector(filtersChanged)
    securityPopup.setAccessibilityLabel("Security Filter")

    capabilityPopup.removeAllItems()
    capabilityPopup.addItems(withTitles: ScanCapabilityFilter.allCases.map(\.rawValue))
    capabilityPopup.target = self
    capabilityPopup.action = #selector(filtersChanged)
    capabilityPopup.setAccessibilityLabel("Capability Filter")
  }

  private func configureExportMenu() {
    let menu = NSMenu()
    menu.autoenablesItems = false
    menu.addItem(NSMenuItem(title: "Export", action: nil, keyEquivalent: ""))
    menu.addItem(exportItem(title: "Export All as JSON…", command: .allJSON))
    menu.addItem(
      exportItem(title: "Export Filtered Rows as JSON…", command: .filteredJSON)
    )
    menu.addItem(.separator())
    menu.addItem(exportItem(title: "Export All as CSV…", command: .allCSV))
    menu.addItem(
      exportItem(title: "Export Filtered Rows as CSV…", command: .filteredCSV)
    )
    exportPopup.menu = menu
    exportPopup.setAccessibilityLabel("Export Scan")
  }

  private func exportItem(title: String, command: ScanExportCommand) -> NSMenuItem {
    let item = NSMenuItem(
      title: title, action: #selector(exportSelectedFormat(_:)), keyEquivalent: "")
    item.target = self
    item.tag = command.rawValue
    return item
  }

  private func configureTable() {
    tableView.dataSource = self
    tableView.delegate = self
    tableView.usesAlternatingRowBackgroundColors = true
    tableView.columnAutoresizingStyle = .noColumnAutoresizing
    tableView.allowsColumnReordering = true
    tableView.allowsColumnResizing = true
    tableView.allowsMultipleSelection = false
    tableView.allowsEmptySelection = true
    tableView.rowSizeStyle = .medium
    tableView.setAccessibilityLabel("Nearby Wi-Fi Access Points")
    tableView.setAccessibilityHelp(
      "A sortable, configurable table of scan observations. Select a row for complete decoded details. Data-cell text can be selected and copied."
    )

    tableView.installContextMenu(
      target: self,
      copyRow: #selector(copySelectedRow),
      copyBSSID: #selector(copySelectedBSSID),
      copyRaw: #selector(copySelectedRawInformationElements)
    )
    tableView.contextualRowProvider = { [weak self] in self?.selectedRow }

    let center = NotificationCenter.default
    tableNotificationTokens.append(
      center.addObserver(
        forName: NSTableView.columnDidResizeNotification,
        object: tableView,
        queue: .main
      ) { [weak self] _ in
        self?.tableColumnsDidChange(changesPreset: false)
      }
    )
    tableNotificationTokens.append(
      center.addObserver(
        forName: NSTableView.columnDidMoveNotification,
        object: tableView,
        queue: .main
      ) { [weak self] _ in
        self?.tableColumnsDidChange(changesPreset: true)
      }
    )
  }

  private func wireInspectorActions() {
    inspectorView.onCopyRow = { [weak self] in self?.copySelectedRow() }
    inspectorView.onCopyBSSID = { [weak self] in self?.copySelectedBSSID() }
    inspectorView.onCopyRawInformationElements = { [weak self] in
      self?.copySelectedRawInformationElements()
    }
    inspectorView.onRawExpansionChanged = { [weak self] expanded in
      guard let self else { return }
      self.preferences.rawInspectorExpanded = expanded
      self.savePreferences()
    }
  }

  // MARK: - Scanning and live updates

  @objc private func scanManually() {
    requestScan(reason: .manual)
  }

  private func requestScan(reason: ScanReason) {
    guard isScannerOpen, scanningAllowed, !isScanning else { return }
    automaticScanTimer?.invalidate()
    automaticScanTimer = nil
    cacheExpiryTimer?.invalidate()
    cacheExpiryTimer = nil
    scanGeneration &+= 1
    let generation = scanGeneration
    isScanning = true
    activeScanReason = reason
    scanButton.isEnabled = false
    progressIndicator.startAnimation(nil)
    updateStatus()
    updateEmptyState()

    service.scanAll { [weak self] result in
      guard let self else { return }
      guard self.scanningAllowed, self.scanGeneration == generation else { return }
      switch result {
      case .success(let snapshot):
        let accessPoints = snapshot.accessPoints
        let macRegistrantResolver = self.macRegistrantResolver
        let macRegistrantDatabaseMetadata = macRegistrantResolver.metadata
        // Preserve a fresh unknown observation when CoreWLAN cannot report an
        // association. It must supersede older application context without
        // claiming that every scanned access point is disconnected.
        let associationObservation = ScanAssociationObservation(
          capturedAt: snapshot.capturedAt,
          ssid: snapshot.currentAssociation?.ssid,
          bssid: snapshot.currentAssociation?.bssid
        )
        DispatchQueue.global(qos: .userInitiated).async {
          let decodedRows = accessPoints.map {
            ScanRow(
              accessPoint: $0,
              lastSeenAt: snapshot.capturedAt,
              macAttribution: macRegistrantResolver.resolve($0.bssid)
            )
          }
          DispatchQueue.main.async { [weak self] in
            guard let self, self.scanningAllowed, self.scanGeneration == generation else { return }
            let currentResolver = self.macRegistrantResolver
            let currentRows =
              currentResolver.metadata == macRegistrantDatabaseMetadata
              ? decodedRows
              : decodedRows.map { row in
                row.applyingMACAttribution(currentResolver.resolve(row.accessPoint.bssid))
              }
            self.completeScan(
              with: currentRows,
              scannedAt: snapshot.capturedAt,
              associationObservation: associationObservation,
              interfaceSnapshot: snapshot.interfaceSnapshot
            )
          }
        }
      case .failure(let error):
        self.failScan(with: error)
      }
    }
  }

  private func completeScan(
    with rows: [ScanRow],
    scannedAt: Date,
    associationObservation: ScanAssociationObservation?,
    interfaceSnapshot: WiFiInterfaceSnapshot
  ) {
    let reason = activeScanReason
    let hadPreviousResults = !allRows.isEmpty
    isScanning = false
    scanButton.isEnabled = scanningAllowed
    progressIndicator.stopAnimation(nil)
    self.interfaceSnapshot = interfaceSnapshot
    allRows = mergeSuccessfulScan(
      rows,
      scannedAt: scannedAt,
      associationObservation: associationObservation,
      interfaceSnapshot: interfaceSnapshot
    )
    if selectedIdentity == nil, !hadPreviousResults {
      selectedIdentity = allRows.first?.identity
    }
    lastScanDate = scannedAt
    lastScanError = nil
    rebuildDisplayedRows()
    updateAutomaticScanTimer()
    updateCacheExpiryTimer()
    if reason.announcesCompletion {
      announce("\(rows.count) access points found.", priority: .low)
    }
  }

  private func failScan(with error: Error) {
    let reason = activeScanReason
    isScanning = false
    scanButton.isEnabled = scanningAllowed
    progressIndicator.stopAnimation(nil)
    lastScanError = error.localizedDescription
    rebuildDisplayedRows()
    updateAutomaticScanTimer()
    updateCacheExpiryTimer()
    if reason.announcesCompletion {
      announce("Wi-Fi scan failed. \(error.localizedDescription)", priority: .medium)
    }
  }

  private func mergeSuccessfulScan(
    _ rows: [ScanRow],
    scannedAt: Date,
    associationObservation: ScanAssociationObservation?,
    interfaceSnapshot: WiFiInterfaceSnapshot
  ) -> [ScanRow] {
    let plan = ScanRetentionPolicy.mergePlan(
      previousRows: allRows,
      freshRows: rows,
      scannedAt: scannedAt,
      retentionSeconds: preferences.cacheRetentionSeconds,
      selectedIdentity: selectedIdentity
    )
    selectedIdentity = plan.selectedIdentity
    let freshRows = plan.freshRows.map {
      $0.applyingScannerState(
        context: context,
        associationObservation: associationObservation,
        interfaceSnapshot: interfaceSnapshot,
        presentInLatestSuccessfulScan: true
      )
    }
    let retainedRows = plan.retainedRows.map {
      $0.applyingScannerState(
        context: context,
        associationObservation: associationObservation,
        interfaceSnapshot: interfaceSnapshot,
        presentInLatestSuccessfulScan: false
      )
    }
    return freshRows + retainedRows
  }

  private func clearSelectionRemovedFrom(previousRows: [ScanRow], newRows: [ScanRow]) {
    guard let selectedIdentity,
      previousRows.contains(where: { $0.identity == selectedIdentity }),
      !newRows.contains(where: { $0.identity == selectedIdentity })
    else { return }
    self.selectedIdentity = nil
  }

  @objc private func automaticScanIntervalChanged() {
    guard let interval = AutomaticUpdateInterval.parse(automaticScanIntervalField.stringValue)
    else {
      automaticScanIntervalField.stringValue = AutomaticUpdateInterval.format(
        preferences.automaticScanInterval)
      NSSound.beep()
      return
    }
    automaticScanIntervalField.stringValue = AutomaticUpdateInterval.format(interval)
    guard interval != preferences.automaticScanInterval else { return }
    preferences.automaticScanInterval = interval
    savePreferences()
    updateAutomaticScanTimer()
    updateStatus()
  }

  @objc private func cacheRetentionChanged() {
    guard let interval = AutomaticUpdateInterval.parse(cacheRetentionField.stringValue) else {
      cacheRetentionField.stringValue = AutomaticUpdateInterval.format(
        preferences.cacheRetentionSeconds
      )
      NSSound.beep()
      return
    }
    cacheRetentionField.stringValue = AutomaticUpdateInterval.format(interval)
    guard interval != preferences.cacheRetentionSeconds else {
      updateCacheExpiryTimer()
      return
    }
    preferences.cacheRetentionSeconds = interval
    savePreferences()
    _ = pruneExpiredRetainedRows(at: Date())
    rebuildDisplayedRows(revealSelection: false)
    updateCacheExpiryTimer()
  }

  private func updateAutomaticScanTimer() {
    automaticScanTimer?.invalidate()
    automaticScanTimer = nil
    let seconds = preferences.automaticScanInterval
    guard isScannerOpen, scanningAllowed, seconds > 0, !isScanning else {
      return
    }
    let interval = TimeInterval(seconds)
    let timer = Timer(timeInterval: interval, repeats: false) {
      [weak self] timer in
      guard let self, self.isScannerOpen, self.automaticScanTimer === timer else { return }
      self.automaticScanTimer = nil
      self.requestScan(reason: .automatic)
    }
    timer.tolerance = min(interval * 0.1, 1)
    RunLoop.main.add(timer, forMode: .common)
    automaticScanTimer = timer
  }

  private func updateScanBehaviorAvailability() {
    automaticScanIntervalLabel.isEnabled = scanningAllowed
    automaticScanIntervalField.isEnabled = scanningAllowed
    automaticScanIntervalUnitLabel.isEnabled = scanningAllowed
    cacheRetentionLabel.isEnabled = scanningAllowed
    cacheRetentionField.isEnabled = scanningAllowed
    cacheRetentionUnitLabel.isEnabled = scanningAllowed
  }

  @discardableResult
  private func pruneExpiredRetainedRows(at date: Date) -> Bool {
    let previousRows = allRows
    allRows = ScanRetentionPolicy.prunedRows(
      previousRows,
      at: date,
      retentionSeconds: preferences.cacheRetentionSeconds
    )
    guard allRows.count != previousRows.count else { return false }
    clearSelectionRemovedFrom(previousRows: previousRows, newRows: allRows)
    return true
  }

  private func updateCacheExpiryTimer() {
    cacheExpiryTimer?.invalidate()
    cacheExpiryTimer = nil
    let retention = preferences.cacheRetentionSeconds
    guard scanningAllowed,
      isScannerOpen,
      retention > 0,
      !isScanning,
      let expiry = ScanRetentionPolicy.earliestExpiry(
        in: allRows,
        retentionSeconds: retention
      )
    else { return }

    let interval = max(0, expiry.timeIntervalSinceNow)
    let timer = Timer(timeInterval: interval, repeats: false) { [weak self] timer in
      guard let self, self.cacheExpiryTimer === timer else { return }
      self.cacheExpiryTimer = nil
      guard self.isScannerOpen, !self.isScanning else { return }
      if self.pruneExpiredRetainedRows(at: Date()) {
        self.rebuildDisplayedRows(revealSelection: false)
      }
      self.updateCacheExpiryTimer()
    }
    timer.tolerance = min(interval * 0.1, 1)
    RunLoop.main.add(timer, forMode: .common)
    cacheExpiryTimer = timer
  }

  private func automaticScanStatus() -> String {
    let interval = preferences.automaticScanInterval
    guard interval > 0 else { return "Automatic scans off" }
    let unit = interval == 1 ? "second" : "seconds"
    return "Automatic scan every \(AutomaticUpdateInterval.format(interval)) \(unit)"
  }

  // MARK: - Filtering, rows, and selection

  @objc private func filtersChanged() {
    filter.observation =
      ScanObservationFilter.allCases[scanSafe: observationPopup.indexOfSelectedItem] ?? .all
    filter.band = bandPopup.indexOfSelectedItem == 0 ? nil : bandPopup.titleOfSelectedItem
    filter.security =
      ScanSecurityFilter.allCases[scanSafe: securityPopup.indexOfSelectedItem] ?? .all
    filter.capability =
      ScanCapabilityFilter.allCases[scanSafe: capabilityPopup.indexOfSelectedItem] ?? .all
    rebuildDisplayedRows(refreshInspector: false)
  }

  @objc private func regexModeChanged() {
    filter.searchMode = regexToggle.state == .on ? .regularExpression : .literal
    updateSearchFieldPresentation()
    rebuildDisplayedRows(refreshInspector: false)
  }

  @objc private func clearFilters() {
    searchField.stringValue = ""
    regexToggle.state = .off
    observationPopup.selectItem(at: 0)
    bandPopup.selectItem(at: 0)
    securityPopup.selectItem(at: 0)
    capabilityPopup.selectItem(at: 0)
    filter = ScanFilter()
    updateSearchFieldPresentation()
    rebuildDisplayedRows(refreshInspector: false)
    window?.makeFirstResponder(searchField)
  }

  @objc private func clearSearch() {
    searchField.stringValue = ""
    filter.query = ""
    rebuildDisplayedRows(refreshInspector: false)
    window?.makeFirstResponder(searchField)
  }

  func rebuildDisplayedRows(
    revealSelection: Bool = true,
    refreshInspector: Bool = true
  ) {
    cancelPendingSearchRebuild()
    let preparedFilter = filter.prepared()
    let previousSearchError = searchValidationError
    searchValidationError = preparedFilter.searchError
    updateSearchFieldPresentation()
    if let searchValidationError, searchValidationError != previousSearchError {
      announce("Invalid regular expression. \(searchValidationError)", priority: .medium)
    }
    let filtered = allRows.filter(preparedFilter.matches)
    let rows = ScanSemanticSorter.sort(filtered, using: preferences.sortRules)
    let deferred = tableReloadDeferrer.perform(
      while: { [weak self] in
        guard let self else { return false }
        return self.window?.isVisible == true && self.tableCellTextSelectionIsActive
      },
      action: { [weak self] in
        self?.applyDisplayedRows(
          rows,
          revealSelection: revealSelection,
          refreshInspector: refreshInspector
        )
      }
    )
    if deferred {
      updateStatus(displayedRowCount: rows.count)
    }
  }

  private func applyDisplayedRows(
    _ rows: [ScanRow],
    revealSelection: Bool,
    refreshInspector: Bool
  ) {
    let selectedWasVisible =
      selectedIdentity.map { identity in
        displayedRows.contains(where: { $0.identity == identity })
      } ?? false
    let selectedWillBeVisible =
      selectedIdentity.map { identity in
        rows.contains(where: { $0.identity == identity })
      } ?? false
    displayedRows = rows
    reloadTableRetainingSelection(revealSelection: revealSelection)
    if refreshInspector || selectedWasVisible != selectedWillBeVisible {
      updateInspector()
    }
    updateStatus()
    updateEmptyState()
    updateExportMenuAvailability()
  }

  private func scheduleSearchRebuild() {
    cancelPendingSearchRebuild()
    let generation = searchDebounceGeneration
    let workItem = DispatchWorkItem { [weak self] in
      guard let self, self.searchDebounceGeneration == generation else { return }
      self.searchDebounceWorkItem = nil
      self.rebuildDisplayedRows(refreshInspector: false)
    }
    searchDebounceWorkItem = workItem
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.12, execute: workItem)
  }

  private func cancelPendingSearchRebuild() {
    searchDebounceGeneration &+= 1
    searchDebounceWorkItem?.cancel()
    searchDebounceWorkItem = nil
  }

  private func updateSearchFieldPresentation() {
    let usesRegularExpression = regexToggle.state == .on
    searchField.placeholderString =
      usesRegularExpression
      ? "Regular expression across scanner fields"
      : "Search SSID, BSSID, or capability"
    searchField.textColor = searchValidationError == nil ? .controlTextColor : .systemRed
    if let searchValidationError {
      let message = "Invalid regular expression: \(searchValidationError)"
      searchField.toolTip = message
      searchField.setAccessibilityHelp(message)
    } else if usesRegularExpression {
      searchField.toolTip = "Search scanner fields with a case-insensitive regular expression."
      searchField.setAccessibilityHelp(
        "Enter a case-insensitive regular expression to search all scanner fields."
      )
    } else {
      searchField.toolTip = "Search SSID, BSSID, or advertised capability."
      searchField.setAccessibilityHelp(
        "Enter text to search SSIDs, BSSIDs, and advertised capabilities."
      )
    }
  }

  private var tableCellTextSelectionIsActive: Bool {
    guard let editor = window?.firstResponder as? NSTextView,
      editor.isFieldEditor,
      editor.selectedRange().length > 0,
      let field = editor.delegate as? NSView,
      field is ScanTableTextField,
      field.isDescendant(of: tableView)
    else { return false }
    return true
  }

  private func reloadTableRetainingSelection(revealSelection: Bool) {
    let identity = selectedIdentity
    isRestoringSelection = true
    defer { isRestoringSelection = false }
    tableView.reloadData()
    selectedIdentity = identity
    guard let identity,
      let index = displayedRows.firstIndex(where: { $0.identity == identity })
    else {
      tableView.deselectAll(nil)
      return
    }
    tableView.selectRowIndexes(IndexSet(integer: index), byExtendingSelection: false)
    if revealSelection {
      tableView.scrollRowToVisible(index)
    }
  }

  var selectedRow: ScanRow? {
    guard displayedRows.indices.contains(tableView.selectedRow) else { return nil }
    return displayedRows[tableView.selectedRow]
  }

  func updateInspector() {
    let row: ScanRow?
    if let selectedIdentity {
      row = displayedRows.first(where: { $0.identity == selectedIdentity })
    } else {
      row = nil
    }
    inspectorView.update(
      row: row,
      context: context,
      interfaceSnapshot: interfaceSnapshot
    )
  }

  func updateStatus(displayedRowCount: Int? = nil) {
    let mode = automaticScanStatus()
    guard scanningAllowed else {
      statusLabel.textColor = .secondaryLabelColor
      statusLabel.stringValue = "Scanning unavailable · Location access is required"
      return
    }
    if let searchValidationError {
      statusLabel.textColor = .systemRed
      statusLabel.stringValue = "Invalid regular expression: \(searchValidationError)"
      return
    }
    if isScanning {
      statusLabel.textColor = .labelColor
      let visibleCount =
        filter.isActive ? "\(displayedRows.count) of \(allRows.count)" : "\(allRows.count)"
      statusLabel.stringValue =
        allRows.isEmpty
        ? "Scanning nearby access points…"
        : "Scanning… showing \(visibleCount) existing results · \(mode)"
      return
    }
    if let error = lastScanError {
      statusLabel.textColor = .systemRed
      if let date = lastScanDate, !allRows.isEmpty {
        statusLabel.stringValue =
          "Scan failed: \(error) · Showing \(allRows.count) results from \(ScanFormatting.timeOnly.string(from: date)) · \(mode)"
      } else {
        statusLabel.stringValue = "Scan failed: \(error) · \(mode)"
      }
      return
    }
    statusLabel.textColor = .secondaryLabelColor
    guard let date = lastScanDate else {
      statusLabel.stringValue = "Not scanned · \(mode)"
      return
    }
    let count =
      filter.isActive
      ? "\(displayedRowCount ?? displayedRows.count) of \(allRows.count) access points"
      : "\(allRows.count) access points"
    statusLabel.stringValue =
      "\(count) · Updated \(ScanFormatting.timeOnly.string(from: date)) · \(mode)"
  }

  private func updateEmptyState() {
    guard displayedRows.isEmpty else {
      emptyView.isHidden = true
      return
    }
    emptyView.isHidden = false
    if !scanningAllowed {
      emptyTitle.stringValue = "Location Access Required"
      emptyDetail.stringValue =
        "Allow Location access in Settings to scan nearby Wi-Fi access points."
      emptyActionButton.isHidden = true
    } else if let searchValidationError {
      emptyTitle.stringValue = "Invalid Regular Expression"
      emptyDetail.stringValue = searchValidationError
      emptyActionButton.title = "Clear Search"
      emptyActionButton.action = #selector(clearSearch)
      emptyActionButton.isHidden = false
    } else if isScanning {
      emptyTitle.stringValue = "Scanning Nearby Access Points"
      emptyDetail.stringValue = "Results appear here as soon as the scan completes."
      emptyActionButton.isHidden = true
    } else if let error = lastScanError {
      emptyTitle.stringValue = "Scan Failed"
      emptyDetail.stringValue =
        filter.isActive && !allRows.isEmpty
        ? "\(error) Existing scan results remain available; clear the filters to inspect them."
        : error
      emptyActionButton.title = "Try Again"
      emptyActionButton.action = #selector(scanManually)
      emptyActionButton.isHidden = false
    } else if filter.observation == .previous, preferences.cacheRetentionSeconds == 0 {
      emptyTitle.stringValue = "No Previous Observations"
      emptyDetail.stringValue =
        "Cache retention is off. Enter a positive cache-retention interval to retain observations from earlier scans."
      emptyActionButton.title = "Clear Filters"
      emptyActionButton.action = #selector(clearFilters)
      emptyActionButton.isHidden = false
    } else if filter.isActive, !allRows.isEmpty {
      emptyTitle.stringValue = "No Matching Access Points"
      switch filter.observation {
      case .previous:
        emptyDetail.stringValue =
          "No previous observations match the current filters. Previous observations are cached access points retained from earlier scans."
      case .latestScan:
        emptyDetail.stringValue =
          "No access points seen in the latest successful scan match the current filters."
      case .all:
        emptyDetail.stringValue =
          "Change the search text or filters to include more scan results."
      }
      emptyActionButton.title = "Clear Filters"
      emptyActionButton.action = #selector(clearFilters)
      emptyActionButton.isHidden = false
    } else if lastScanDate != nil {
      emptyTitle.stringValue = "No Access Points Found"
      emptyDetail.stringValue = "No nearby access points were reported. Try another scan."
      emptyActionButton.title = "Scan Again"
      emptyActionButton.action = #selector(scanManually)
      emptyActionButton.isHidden = false
    } else {
      emptyTitle.stringValue = "Ready to Scan"
      emptyDetail.stringValue =
        "Scan nearby Wi-Fi access points and inspect their reported IEEE 802.11 information."
      emptyActionButton.title = "Scan"
      emptyActionButton.action = #selector(scanManually)
      emptyActionButton.isHidden = false
    }
  }

  func announce(_ value: String, priority: NSAccessibilityPriorityLevel) {
    ScanWindowSupport.announce(value, from: statusLabel, priority: priority)
  }

  func savePreferences() {
    preferenceStore.save(preferences)
  }
}

// MARK: - Search and window lifecycle

extension ScanWindowController: NSSearchFieldDelegate {
  func controlTextDidChange(_ notification: Notification) {
    guard notification.object as? NSSearchField === searchField else { return }
    filter.query = searchField.stringValue
    if filter.query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      rebuildDisplayedRows(refreshInspector: false)
    } else {
      scheduleSearchRebuild()
    }
  }

  func controlTextDidEndEditing(_ notification: Notification) {
    guard let field = notification.object as? NSTextField else { return }
    if field === automaticScanIntervalField {
      automaticScanIntervalChanged()
    } else if field === cacheRetentionField {
      cacheRetentionChanged()
    }
  }
}

extension ScanWindowController: NSSplitViewDelegate {
  func splitView(
    _ splitView: NSSplitView,
    constrainSplitPosition proposedPosition: CGFloat,
    ofSubviewAt dividerIndex: Int
  ) -> CGFloat {
    guard splitView === self.splitView, dividerIndex == 0 else {
      return proposedPosition
    }

    let minimumPosition = splitView.bounds.minX + Layout.tableMinimumWidth
    let maximumPosition =
      splitView.bounds.maxX - splitView.dividerThickness - Layout.inspectorMinimumWidth
    guard minimumPosition <= maximumPosition else {
      return proposedPosition
    }

    let position = min(max(proposedPosition, minimumPosition), maximumPosition)
    inspectorWidthPreference?.constant =
      splitView.bounds.maxX - position - splitView.dividerThickness
    return position
  }
}

extension ScanWindowController: NSWindowDelegate {
  func windowWillClose(_ notification: Notification) {
    let wasScannerOpen = isScannerOpen
    isScannerOpen = false
    window?.makeFirstResponder(nil)
    tableReloadDeferrer.flush()
    automaticScanIntervalChanged()
    cacheRetentionChanged()
    automaticScanTimer?.invalidate()
    automaticScanTimer = nil
    cacheExpiryTimer?.invalidate()
    cacheExpiryTimer = nil
    cancelPendingSearchRebuild()
    if wasScannerOpen {
      onScannerOpenStateChanged?(false)
    }
  }
}
