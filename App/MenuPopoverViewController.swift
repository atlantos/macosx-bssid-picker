// SPDX-License-Identifier: GPL-3.0-only

import AppKit

protocol MenuPopoverViewControllerDelegate: AnyObject {
  func menuPopoverRequestedRefresh()
  func menuPopoverSelected(_ target: NetworkTarget)
  func menuPopoverRequestedLockToggle()
  func menuPopoverRequestedLockRetry()
  func menuPopoverRequestedSettings()
  func menuPopoverRequestedInspector()
  func menuPopoverRequestedAbout()
  func menuPopoverRequestedQuit()
}

final class MenuPopoverViewController: NSViewController {
  private enum Layout {
    static let minimumWidth: CGFloat = 300
    static let maximumWidth: CGFloat = 480
    static let screenMargin: CGFloat = 18
    static let horizontalInset: CGFloat = 14
    static let maximumVisibleAccessPointRows = 7
    static let refreshProgressSize: CGFloat = 14
  }

  weak var delegate: MenuPopoverViewControllerDelegate?

  private var state: MenuBarViewState
  private let rootStack = NSStackView()
  private let headerIcon = NSImageView(image: StatusSymbols.headerWiFi)
  private let headingLabel = NSTextField(labelWithString: "")
  private let bssidLabel = NSTextField(labelWithString: "")
  private let accessPointHeadingLabel = NSTextField(labelWithString: "ACCESS POINTS")
  private let refreshButton = NSButton()
  private let refreshProgress = NSProgressIndicator()
  private let noticeBox = NSBox()
  private let noticeIcon = NSImageView()
  private let noticeTitle = NSTextField(labelWithString: "")
  private let noticeMessage = NSTextField(wrappingLabelWithString: "")
  private let noticeActionButton = NSButton()
  private let accessPointStack = NSStackView()
  private let accessPointScrollView = NSScrollView()
  private let emptyAccessPointLabel = NSTextField(wrappingLabelWithString: "")
  private var accessPointHeightConstraint: NSLayoutConstraint?
  private var emptyAccessPointWidthConstraint: NSLayoutConstraint?
  private var noticeHeightConstraint: NSLayoutConstraint?
  private weak var noticeContentView: NSStackView?
  private let lockToggle = NSButton(
    checkboxWithTitle: "BSSID Lock", target: nil, action: nil)
  private let lockStatus = NSTextField(labelWithString: "")
  private let settingsButton = NSButton()
  private let inspectorButton = NSButton()
  private let aboutButton = NSButton(title: "About…", target: nil, action: nil)
  private let quitButton = NSButton(title: "Quit", target: nil, action: nil)

  init(initialState: MenuBarViewState) {
    state = initialState
    super.init(nibName: nil, bundle: nil)
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    fatalError("init(coder:) is not supported")
  }

  override func loadView() {
    // Height is deliberately unconstrained while the stack is measured. The
    // popover adopts the resulting content size after every state update.
    view = NSView(
      frame: NSRect(x: 0, y: 0, width: Layout.minimumWidth, height: 1)
    )
    buildInterface()
    render(state)
  }

  /// Returns the smallest useful popover size for the current state. The AP
  /// list grows with its rows and becomes scrollable only after reaching the
  /// row or display-height limit.
  func fittingContentSize(on screen: NSScreen?) -> NSSize {
    // Accessing `view` is the macOS 13-compatible way to force loading.
    // `loadViewIfNeeded()` is only available starting in macOS 14.
    _ = view

    let visibleFrame = screen?.visibleFrame ?? NSScreen.main?.visibleFrame
    let screenWidth = visibleFrame.map { max(0, $0.width - (Layout.screenMargin * 2)) }
    let maximumWidth = min(Layout.maximumWidth, screenWidth ?? Layout.maximumWidth)
    let minimumWidth = min(Layout.minimumWidth, maximumWidth)
    let width = min(max(naturalContentWidth, minimumWidth), maximumWidth)

    var frame = view.frame
    frame.size.width = width
    view.frame = frame
    view.layoutSubtreeIfNeeded()
    updateNoticeHeight()
    view.layoutSubtreeIfNeeded()

    let naturalListHeight = accessPointStack.fittingSize.height
    let rowLimitedHeight = visibleAccessPointHeightLimit
    let initialListHeight = min(naturalListHeight, rowLimitedHeight)
    accessPointHeightConstraint?.constant = initialListHeight
    rootStack.layoutSubtreeIfNeeded()

    let screenHeight = visibleFrame.map { max(0, $0.height - (Layout.screenMargin * 2)) }
    if let screenHeight {
      let nonListHeight = max(0, rootStack.fittingSize.height - initialListHeight)
      let screenLimitedListHeight = max(0, screenHeight - nonListHeight)
      accessPointHeightConstraint?.constant = min(initialListHeight, screenLimitedListHeight)
      rootStack.layoutSubtreeIfNeeded()
    }

    let listHeight = accessPointHeightConstraint?.constant ?? 0
    accessPointScrollView.hasVerticalScroller = naturalListHeight > listHeight + 0.5
    let size = NSSize(width: ceil(width), height: ceil(rootStack.fittingSize.height))
    preferredContentSize = size
    return size
  }

  func render(_ newState: MenuBarViewState) {
    state = newState
    guard isViewLoaded else { return }

    headingLabel.stringValue = newState.heading
    headingLabel.toolTip = newState.headingToolTip
    bssidLabel.stringValue =
      newState.currentBSSIDDescription.map { "Current BSSID  \($0)" }
      ?? "Current BSSID unavailable"
    bssidLabel.toolTip = newState.currentBSSIDDescription

    configureRefreshControl()
    reconcileAccessPointRows()
    configureNotice()
    configureLockControls()
    inspectorButton.isEnabled = newState.showAllEnabled
  }

  private func buildInterface() {
    rootStack.orientation = .vertical
    rootStack.alignment = .leading
    rootStack.distribution = .fill
    rootStack.detachesHiddenViews = true
    rootStack.spacing = 11
    rootStack.edgeInsets = NSEdgeInsets(top: 14, left: 14, bottom: 12, right: 14)
    rootStack.translatesAutoresizingMaskIntoConstraints = false
    view.addSubview(rootStack)
    NSLayoutConstraint.activate([
      rootStack.leadingAnchor.constraint(equalTo: view.leadingAnchor),
      rootStack.trailingAnchor.constraint(equalTo: view.trailingAnchor),
      rootStack.topAnchor.constraint(equalTo: view.topAnchor),
    ])

    addFullWidthArrangedSubview(makeHeader())
    addFullWidthArrangedSubview(noticeBox)
    configureNoticeBox()

    addFullWidthArrangedSubview(makeAccessPointHeader())
    addFullWidthArrangedSubview(makeAccessPointScrollView())
    addFullWidthArrangedSubview(makeLockSection())
    addFullWidthArrangedSubview(makeSeparator())
    addFullWidthArrangedSubview(makeFooter())
  }

  private func addFullWidthArrangedSubview(_ arrangedSubview: NSView) {
    rootStack.addArrangedSubview(arrangedSubview)
    arrangedSubview.widthAnchor.constraint(
      equalTo: rootStack.widthAnchor,
      constant: -(Layout.horizontalInset * 2)
    ).isActive = true
  }

  private func makeHeader() -> NSView {
    headerIcon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 20, weight: .medium)
    headerIcon.setAccessibilityLabel("Wi-Fi")

    headingLabel.font = .systemFont(ofSize: 15, weight: .semibold)
    headingLabel.lineBreakMode = .byTruncatingTail
    headingLabel.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
    bssidLabel.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
    bssidLabel.textColor = .secondaryLabelColor

    let labels = NSStackView(views: [headingLabel, bssidLabel])
    labels.orientation = .vertical
    labels.alignment = .leading
    labels.spacing = 2

    let header = NSStackView(views: [headerIcon, labels, NSView()])
    header.orientation = .horizontal
    header.alignment = .centerY
    header.spacing = 9
    return header
  }

  private func makeAccessPointHeader() -> NSView {
    accessPointHeadingLabel.font = .systemFont(ofSize: 10, weight: .semibold)
    accessPointHeadingLabel.textColor = .secondaryLabelColor

    refreshProgress.style = .spinning
    refreshProgress.controlSize = .small
    refreshProgress.isIndeterminate = true
    refreshProgress.isDisplayedWhenStopped = false
    refreshProgress.setAccessibilityLabel("Refreshing access points")
    NSLayoutConstraint.activate([
      refreshProgress.widthAnchor.constraint(equalToConstant: Layout.refreshProgressSize),
      refreshProgress.heightAnchor.constraint(equalToConstant: Layout.refreshProgressSize),
    ])

    refreshButton.title = "Refresh"
    refreshButton.image = StatusSymbols.refresh
    refreshButton.imagePosition = .imageLeading
    refreshButton.target = self
    refreshButton.action = #selector(refresh)
    refreshButton.bezelStyle = .texturedRounded
    refreshButton.keyEquivalent = "r"
    refreshButton.keyEquivalentModifierMask = [.command]
    refreshButton.setAccessibilityLabel("Refresh access points")

    let controls = NSStackView(views: [refreshProgress, refreshButton])
    controls.orientation = .horizontal
    controls.alignment = .centerY
    controls.spacing = 6
    controls.detachesHiddenViews = true

    let header = NSStackView(views: [accessPointHeadingLabel, NSView(), controls])
    header.orientation = .horizontal
    header.alignment = .centerY
    header.spacing = 8
    return header
  }

  private func configureNoticeBox() {
    noticeBox.boxType = .custom
    noticeBox.cornerRadius = 7
    noticeBox.borderWidth = 1
    noticeBox.contentViewMargins = NSSize(width: 9, height: 8)

    noticeIcon.imageScaling = .scaleProportionallyDown
    noticeIcon.widthAnchor.constraint(equalToConstant: 18).isActive = true
    noticeIcon.heightAnchor.constraint(equalToConstant: 18).isActive = true
    noticeTitle.font = .systemFont(ofSize: 12, weight: .semibold)
    noticeMessage.font = .systemFont(ofSize: 11)
    noticeMessage.textColor = .secondaryLabelColor
    noticeMessage.maximumNumberOfLines = 2
    noticeMessage.lineBreakMode = .byWordWrapping
    noticeMessage.cell?.truncatesLastVisibleLine = true

    let text = NSStackView(views: [noticeTitle, noticeMessage])
    text.orientation = .vertical
    text.alignment = .leading
    text.spacing = 2
    text.setContentHuggingPriority(.defaultLow, for: .horizontal)
    text.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

    noticeActionButton.target = self
    noticeActionButton.action = #selector(performNoticeAction)
    noticeActionButton.bezelStyle = .roundRect

    let row = NSStackView(views: [noticeIcon, text, noticeActionButton])
    row.orientation = .horizontal
    row.alignment = .centerY
    row.spacing = 8
    noticeBox.contentView = row
    row.widthAnchor.constraint(
      equalTo: noticeBox.widthAnchor,
      constant: -(noticeBox.contentViewMargins.width * 2)
    ).isActive = true
    noticeContentView = row
    noticeBox.setContentHuggingPriority(.required, for: .vertical)
    let heightConstraint = noticeBox.heightAnchor.constraint(equalToConstant: 47)
    heightConstraint.isActive = true
    noticeHeightConstraint = heightConstraint
  }

  private func makeAccessPointScrollView() -> NSView {
    accessPointStack.orientation = .vertical
    accessPointStack.alignment = .width
    accessPointStack.spacing = 3
    accessPointStack.translatesAutoresizingMaskIntoConstraints = false

    let document = FlippedView()
    document.translatesAutoresizingMaskIntoConstraints = false
    document.addSubview(accessPointStack)
    NSLayoutConstraint.activate([
      accessPointStack.leadingAnchor.constraint(equalTo: document.leadingAnchor),
      accessPointStack.trailingAnchor.constraint(equalTo: document.trailingAnchor),
      accessPointStack.topAnchor.constraint(equalTo: document.topAnchor),
      accessPointStack.bottomAnchor.constraint(equalTo: document.bottomAnchor),
    ])

    emptyAccessPointLabel.textColor = .secondaryLabelColor
    emptyAccessPointLabel.alignment = .center
    emptyAccessPointLabel.font = .systemFont(ofSize: 12)
    emptyAccessPointLabel.heightAnchor.constraint(greaterThanOrEqualToConstant: 42).isActive = true

    accessPointScrollView.documentView = document
    accessPointScrollView.hasVerticalScroller = false
    accessPointScrollView.autohidesScrollers = true
    accessPointScrollView.drawsBackground = false
    accessPointScrollView.borderType = .noBorder
    let heightConstraint = accessPointScrollView.heightAnchor.constraint(equalToConstant: 42)
    heightConstraint.isActive = true
    accessPointHeightConstraint = heightConstraint
    document.widthAnchor.constraint(equalTo: accessPointScrollView.contentView.widthAnchor)
      .isActive =
      true
    return accessPointScrollView
  }

  private func makeLockSection() -> NSView {
    lockToggle.target = self
    lockToggle.action = #selector(toggleLock)
    lockToggle.font = .systemFont(ofSize: 12, weight: .medium)
    lockToggle.setAccessibilityLabel("BSSID Lock")

    lockStatus.font = .systemFont(ofSize: 11)
    lockStatus.textColor = .secondaryLabelColor
    lockStatus.lineBreakMode = .byTruncatingTail
    lockStatus.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
    lockStatus.setAccessibilityLabel("BSSID Lock status")

    let content = NSStackView(views: [lockToggle, lockStatus])
    content.orientation = .vertical
    content.alignment = .leading
    content.spacing = 4
    content.detachesHiddenViews = true
    lockStatus.widthAnchor.constraint(lessThanOrEqualTo: content.widthAnchor).isActive = true
    content.setContentHuggingPriority(.required, for: .vertical)
    content.setContentCompressionResistancePriority(.required, for: .vertical)
    return content
  }

  private func makeFooter() -> NSView {
    configureFooterButton(
      settingsButton,
      title: "Settings…",
      image: StatusSymbols.settings,
      action: #selector(showSettings),
      key: ",",
      help: "Configure Location access and experimental Strict BSSID association.")
    configureFooterButton(
      inspectorButton,
      title: "Wi-Fi Scanner",
      image: StatusSymbols.inspector,
      action: #selector(showInspector),
      key: "i",
      help: "Open the Wi-Fi Scanner.")

    aboutButton.target = self
    aboutButton.action = #selector(showAbout)
    aboutButton.bezelStyle = .inline
    aboutButton.isBordered = false
    aboutButton.setAccessibilityHelp("Show version and application information.")

    quitButton.target = self
    quitButton.action = #selector(quit)
    quitButton.bezelStyle = .inline
    quitButton.isBordered = false
    quitButton.keyEquivalent = "q"
    quitButton.keyEquivalentModifierMask = [.command]
    quitButton.setAccessibilityHelp("Quit BSSID Picker.")

    let actions = NSStackView(views: [settingsButton, inspectorButton])
    actions.orientation = .horizontal
    actions.spacing = 8
    settingsButton.widthAnchor.constraint(equalTo: inspectorButton.widthAnchor).isActive = true

    let secondary = NSStackView(views: [aboutButton, NSView(), quitButton])
    secondary.orientation = .horizontal
    secondary.alignment = .centerY

    let footer = NSStackView(views: [actions, secondary])
    footer.orientation = .vertical
    footer.alignment = .leading
    footer.spacing = 8
    actions.widthAnchor.constraint(equalTo: footer.widthAnchor).isActive = true
    secondary.widthAnchor.constraint(equalTo: footer.widthAnchor).isActive = true
    return footer
  }

  private func configureFooterButton(
    _ button: NSButton,
    title: String,
    image: NSImage,
    action: Selector,
    key: String,
    help: String
  ) {
    button.title = title
    button.image = image
    button.imagePosition = .imageLeading
    button.target = self
    button.action = action
    button.bezelStyle = .rounded
    button.keyEquivalent = key
    button.keyEquivalentModifierMask = [.command]
    button.setAccessibilityHelp(help)
  }

  private func configureRefreshControl() {
    let isRefreshing = state.refreshState == .refreshing
    refreshButton.isEnabled =
      state.refreshState == .ready && state.refreshEnabled && state.controlsEnabled
    refreshProgress.isHidden = !isRefreshing

    if isRefreshing {
      refreshProgress.startAnimation(nil)
    } else {
      refreshProgress.stopAnimation(nil)
    }

    switch state.refreshState {
    case .ready:
      refreshButton.toolTip = "Scan the current Wi-Fi network now (⌘R)."
      refreshButton.setAccessibilityHelp("Scan the current Wi-Fi network now.")
      refreshButton.setAccessibilityValue("Ready")
    case .refreshing:
      refreshButton.toolTip = "Refreshing access points…"
      refreshButton.setAccessibilityHelp("An access-point scan is in progress.")
      refreshButton.setAccessibilityValue("Refreshing")
    case .connecting:
      refreshButton.toolTip = "Refresh is unavailable while connecting."
      refreshButton.setAccessibilityHelp("Wait for the current connection attempt to finish.")
      refreshButton.setAccessibilityValue("Unavailable while connecting")
    }
  }

  private func configureNotice() {
    guard let notice = effectiveNotice else {
      noticeBox.isHidden = true
      return
    }
    noticeBox.isHidden = false
    noticeTitle.stringValue = notice.title
    noticeMessage.stringValue = notice.message
    noticeMessage.toolTip = notice.message
    noticeIcon.image = StatusSymbols.notice(notice.style)
    noticeIcon.contentTintColor = noticeColor(notice.style)
    noticeBox.borderColor = noticeColor(notice.style).withAlphaComponent(0.55)
    noticeBox.fillColor = noticeColor(notice.style).withAlphaComponent(0.08)
    noticeActionButton.title = notice.actionTitle ?? ""
    noticeActionButton.isHidden = notice.actionTitle == nil || notice.action == nil
    let actionHelp: String
    switch notice.action {
    case .refresh:
      noticeActionButton.isEnabled = state.refreshEnabled
      actionHelp = "Retry the current Wi-Fi scan."
    case .retryLock:
      noticeActionButton.isEnabled = state.controlsEnabled
      if let target = state.lockTargetDescription {
        actionHelp = "Clear the retry backoff and try target BSSID \(target) now."
      } else {
        actionHelp = "Clear the retry backoff and try the saved BSSID now."
      }
    case .showSettings:
      noticeActionButton.isEnabled = true
      actionHelp = "Open Settings to resolve this issue."
    case .showInspector:
      noticeActionButton.isEnabled = state.showAllEnabled
      actionHelp = "Open Wi-Fi Scanner for complete diagnostics."
    case nil:
      noticeActionButton.isEnabled = false
      actionHelp = ""
    }
    noticeActionButton.toolTip = actionHelp.isEmpty ? nil : actionHelp
    noticeActionButton.setAccessibilityHelp(actionHelp)
    noticeBox.setAccessibilityLabel("\(notice.title). \(notice.message)")
  }

  private var effectiveNotice: MenuNotice? {
    if let notice = state.notice { return notice }
    if let message = state.headingToolTip {
      return MenuNotice(
        style: .error,
        title: "Wi-Fi scan needs attention",
        message: message,
        actionTitle: "Retry",
        action: .refresh
      )
    }
    return nil
  }

  /// Reuses rows by network identity so asynchronous scans do not discard the
  /// keyboard or VoiceOver focus on every render. Structural changes preserve
  /// the visible scroll origin and restore focus when the same target remains.
  private func reconcileAccessPointRows() {
    var seenTargets: Set<NetworkTarget> = []
    let networks = state.networks.filter { seenTargets.insert($0.target).inserted }
    let existingButtons = accessPointStack.arrangedSubviews.compactMap {
      $0 as? NetworkChoiceButton
    }
    let existingTargets = existingButtons.map { $0.network.target }
    let desiredTargets = networks.map(\.target)

    if networks.isEmpty {
      emptyAccessPointLabel.stringValue = emptyAccessPointText
      guard
        accessPointStack.arrangedSubviews.count != 1
          || accessPointStack.arrangedSubviews.first !== emptyAccessPointLabel
      else { return }
      replaceAccessPointRows(with: [emptyAccessPointLabel], preservingFocusedTarget: nil)
      return
    }

    var available: [NetworkTarget: NetworkChoiceButton] = [:]
    for button in existingButtons where available[button.network.target] == nil {
      available[button.network.target] = button
    }
    let desiredButtons = networks.map { network -> NetworkChoiceButton in
      let button =
        available.removeValue(forKey: network.target) ?? makeNetworkButton(for: network)
      configure(button, with: network)
      return button
    }

    guard
      existingTargets != desiredTargets
        || accessPointStack.arrangedSubviews.count != desiredButtons.count
    else { return }

    let focusedTarget = (view.window?.firstResponder as? NetworkChoiceButton)?.network.target
    replaceAccessPointRows(with: desiredButtons, preservingFocusedTarget: focusedTarget)
  }

  private func makeNetworkButton(for network: MenuNetworkItem) -> NetworkChoiceButton {
    let button = NetworkChoiceButton(network: network)
    button.target = self
    button.action = #selector(selectNetwork(_:))
    button.bezelStyle = .inline
    button.isBordered = false
    button.alignment = .left
    button.imagePosition = .imageLeading
    button.cell?.lineBreakMode = .byTruncatingTail
    button.heightAnchor.constraint(greaterThanOrEqualToConstant: 27).isActive = true
    return button
  }

  private func configure(_ button: NetworkChoiceButton, with network: MenuNetworkItem) {
    button.network = network
    button.title = network.title
    button.font = .monospacedSystemFont(
      ofSize: 11, weight: network.isCurrent ? .semibold : .regular)
    button.image = network.isCurrent ? StatusSymbols.current : StatusSymbols.notCurrent
    button.isEnabled = network.isEnabled && state.controlsEnabled
    button.toolTip =
      network.toolTip
      ?? (network.isCurrent
        ? "Currently associated with this access point."
        : "Connect to \(network.target.bssid.description).")
    button.setAccessibilityLabel(
      "\(network.isCurrent ? "Current access point" : "Access point"), \(network.accessibilityDescription)"
    )
    button.setAccessibilityHelp(button.toolTip ?? "")
  }

  private func replaceAccessPointRows(
    with desiredViews: [NSView],
    preservingFocusedTarget focusedTarget: NetworkTarget?
  ) {
    let scrollOrigin = accessPointScrollView.contentView.bounds.origin
    let desiredIdentities = Set(desiredViews.map(ObjectIdentifier.init))

    for existingView in accessPointStack.arrangedSubviews {
      accessPointStack.removeArrangedSubview(existingView)
      if !desiredIdentities.contains(ObjectIdentifier(existingView)) {
        existingView.removeFromSuperview()
      }
    }
    for desiredView in desiredViews {
      accessPointStack.addArrangedSubview(desiredView)
      constrainAccessPointRowWidth(desiredView)
    }

    accessPointStack.layoutSubtreeIfNeeded()
    accessPointScrollView.contentView.scroll(to: scrollOrigin)
    accessPointScrollView.reflectScrolledClipView(accessPointScrollView.contentView)

    if let focusedTarget,
      let focusedButton = desiredViews.compactMap({ $0 as? NetworkChoiceButton })
        .first(where: { $0.network.target == focusedTarget })
    {
      view.window?.makeFirstResponder(focusedButton)
    }
  }

  private var emptyAccessPointText: String {
    switch state.refreshState {
    case .refreshing: return "Scanning for access points…"
    case .connecting: return "Connecting… cached access points will remain available here."
    case .ready: return "No cached access points. Choose Refresh to scan."
    }
  }

  private func configureLockControls() {
    lockToggle.state = state.lockEnabled ? .on : .off
    let accessibilityStatus = "Status: \(state.lockStatus)"
    if let target = state.lockTargetDescription {
      lockToggle.toolTip =
        state.lockEnabled
        ? "Turn off BSSID Lock for target \(target)."
        : "Turn on BSSID Lock for target \(target)."
      lockToggle.setAccessibilityHelp(
        "BSSID Lock is \(state.lockEnabled ? "on" : "off"). Target BSSID \(target). \(accessibilityStatus)"
      )
    } else {
      lockToggle.toolTip = "Select an access point before turning on BSSID Lock."
      lockToggle.setAccessibilityHelp(
        "Select an access point before turning on BSSID Lock. \(accessibilityStatus)"
      )
    }
    lockToggle.isEnabled = state.lockTargetDescription != nil && state.controlsEnabled
    lockStatus.stringValue = conciseLockStatus
    lockStatus.toolTip = state.lockStatus
    lockStatus.setAccessibilityValue(state.lockStatus)
    lockStatus.isHidden = !state.showsLockStatus
  }

  private var conciseLockStatus: String {
    let text = state.lockStatus
    if text.count <= 68 { return text }
    return String(text.prefix(65)) + "…"
  }

  private var naturalContentWidth: CGFloat {
    let labelWidth = max(textWidth(headingLabel), textWidth(bssidLabel))
    let headerWidth = intrinsicWidth(headerIcon) + labelWidth + (9 * 2)
    // Reserve the spinner width in every state so automatic scans never
    // change the popover width or move the Refresh button.
    let accessPointHeaderWidth =
      textWidth(accessPointHeadingLabel) + Layout.refreshProgressSize
      + buttonWidth(refreshButton) + 22

    let networkWidth = accessPointStack.arrangedSubviews.reduce(CGFloat.zero) { width, view in
      if let button = view as? NSButton {
        return max(width, buttonWidth(button))
      }
      return max(width, textWidth(emptyAccessPointLabel) + 12)
    }

    let noticeWidth: CGFloat
    if noticeBox.isHidden {
      noticeWidth = 0
    } else {
      let actionWidth = noticeActionButton.isHidden ? 0 : buttonWidth(noticeActionButton) + 8
      // Error text wraps at the selected popover width. Letting an arbitrary
      // message choose the width makes the pointer target jump during live
      // updates and normally drives every error state to the maximum width.
      noticeWidth = 18 + textWidth(noticeTitle) + actionWidth + 42
    }

    let statusWidth = lockStatus.isHidden ? 0 : textWidth(lockStatus)
    let lockWidth = max(
      buttonWidth(lockToggle),
      statusWidth
    )
    let footerButtonWidth = max(buttonWidth(settingsButton), buttonWidth(inspectorButton))
    let footerWidth = (footerButtonWidth * 2) + 8
    let contentWidth = max(
      headerWidth,
      accessPointHeaderWidth,
      networkWidth,
      noticeWidth,
      lockWidth,
      footerWidth
    )
    return ceil(contentWidth + (Layout.horizontalInset * 2))
  }

  private var visibleAccessPointHeightLimit: CGFloat {
    let visibleRows = accessPointStack.arrangedSubviews.prefix(
      Layout.maximumVisibleAccessPointRows)
    let rowHeights = visibleRows.map { view -> CGFloat in
      let intrinsicHeight = view.intrinsicContentSize.height
      return max(
        view.fittingSize.height, intrinsicHeight == NSView.noIntrinsicMetric ? 0 : intrinsicHeight)
    }
    guard !rowHeights.isEmpty else { return 0 }
    return rowHeights.reduce(0, +) + accessPointStack.spacing * CGFloat(rowHeights.count - 1)
  }

  private func textWidth(_ field: NSTextField) -> CGFloat {
    guard !field.stringValue.isEmpty else { return 0 }
    return ceil(
      (field.stringValue as NSString).size(
        withAttributes: [.font: field.font ?? NSFont.systemFont(ofSize: NSFont.systemFontSize)]
      ).width)
  }

  private func intrinsicWidth(_ view: NSView) -> CGFloat {
    let width = view.intrinsicContentSize.width
    return width == NSView.noIntrinsicMetric ? view.fittingSize.width : width
  }

  private func buttonWidth(_ button: NSButton) -> CGFloat {
    button.cell?.cellSize.width ?? intrinsicWidth(button)
  }

  private func constrainAccessPointRowWidth(_ row: NSView) {
    if row === emptyAccessPointLabel {
      if emptyAccessPointWidthConstraint?.isActive != true {
        let constraint = row.widthAnchor.constraint(equalTo: accessPointStack.widthAnchor)
        constraint.isActive = true
        emptyAccessPointWidthConstraint = constraint
      }
      return
    }

    guard let button = row as? NetworkChoiceButton,
      button.stackWidthConstraint?.isActive != true
    else { return }
    let constraint = button.widthAnchor.constraint(equalTo: accessPointStack.widthAnchor)
    constraint.isActive = true
    button.stackWidthConstraint = constraint
  }

  private func updateNoticeHeight() {
    if !noticeBox.isHidden, let content = noticeContentView {
      // NSTextField otherwise measures wrapping text as one unbounded line.
      // Feed it the resolved column width before asking the stack for height.
      noticeMessage.preferredMaxLayoutWidth = max(0, noticeMessage.frame.width)
      content.layoutSubtreeIfNeeded()
      noticeHeightConstraint?.constant = ceil(
        content.fittingSize.height + noticeBox.contentViewMargins.height * 2
      )
    }
  }

  private func noticeColor(_ style: MenuNoticeStyle) -> NSColor {
    switch style {
    case .information: return .controlAccentColor
    case .warning: return .systemOrange
    case .error: return .systemRed
    }
  }

  private func makeSeparator() -> NSBox {
    let separator = NSBox()
    separator.boxType = .separator
    return separator
  }

  @objc private func refresh() { delegate?.menuPopoverRequestedRefresh() }
  @objc private func toggleLock() { delegate?.menuPopoverRequestedLockToggle() }
  @objc private func showSettings() { delegate?.menuPopoverRequestedSettings() }
  @objc private func showInspector() { delegate?.menuPopoverRequestedInspector() }
  @objc private func showAbout() { delegate?.menuPopoverRequestedAbout() }
  @objc private func quit() { delegate?.menuPopoverRequestedQuit() }

  @objc private func selectNetwork(_ sender: NetworkChoiceButton) {
    delegate?.menuPopoverSelected(sender.network.target)
  }

  @objc private func performNoticeAction() {
    switch effectiveNotice?.action {
    case .refresh: delegate?.menuPopoverRequestedRefresh()
    case .retryLock: delegate?.menuPopoverRequestedLockRetry()
    case .showSettings: delegate?.menuPopoverRequestedSettings()
    case .showInspector: delegate?.menuPopoverRequestedInspector()
    case nil: break
    }
  }
}

private final class NetworkChoiceButton: NSButton {
  var network: MenuNetworkItem
  var stackWidthConstraint: NSLayoutConstraint?

  init(network: MenuNetworkItem) {
    self.network = network
    super.init(frame: .zero)
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    fatalError("init(coder:) is not supported")
  }
}

private final class FlippedView: NSView {
  override var isFlipped: Bool { true }
}
