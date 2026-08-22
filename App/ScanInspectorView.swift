// SPDX-License-Identifier: GPL-3.0-only

import AppKit

private struct ScanInspectorRowSnapshot: Equatable {
  let identity: ScanRowIdentity
  let columnValues: [String]
  let informationElements: Data?

  init(_ row: ScanRow) {
    identity = row.identity
    columnValues = ScanColumnID.allCases.map { row.stringValue(for: $0) }
    informationElements = row.accessPoint.informationElements
  }
}

private struct ScanInspectorRenderSnapshot: Equatable {
  let row: ScanInspectorRowSnapshot?
  let context: ScannerContextSnapshot?
  let interface: WiFiInterfaceSnapshot?
}

final class ScanInspectorView: NSView {
  var onCopyRow: (() -> Void)?
  var onCopyBSSID: (() -> Void)?
  var onCopyRawInformationElements: (() -> Void)?
  var onRawExpansionChanged: ((Bool) -> Void)?

  private let rootStack = NSStackView()
  private let scrollView = NSScrollView()
  private let textView = NSTextView()
  private let actionContainer = NSView()
  private let actionStack = NSStackView()
  private let copyRowButton = NSButton(title: "Copy Row", target: nil, action: nil)
  private let copyBSSIDButton = NSButton(title: "Copy BSSID", target: nil, action: nil)
  private let copyRawButton = NSButton(title: "Copy Raw IEs", target: nil, action: nil)
  private let rawToggleButton = NSButton(title: "", target: nil, action: nil)

  private var row: ScanRow?
  private var context: ScannerContextSnapshot?
  private var interfaceSnapshot: WiFiInterfaceSnapshot?
  private var rawExpanded: Bool
  private var renderedSnapshot: ScanInspectorRenderSnapshot?
  private var deferredRebuild: DispatchWorkItem?
  private var isSizingTextView = false

  init(rawExpanded: Bool) {
    self.rawExpanded = rawExpanded
    super.init(frame: .zero)
    translatesAutoresizingMaskIntoConstraints = false
    setAccessibilityElement(true)
    setAccessibilityRole(.group)
    setAccessibilityLabel("Access Point Inspector")
    buildInterface()
    rebuild()
    recordRenderedContent()
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    fatalError("init(coder:) is not supported")
  }

  deinit {
    deferredRebuild?.cancel()
  }

  override func layout() {
    super.layout()
    sizeTextViewToContent()
  }

  func update(
    row: ScanRow?,
    context: ScannerContextSnapshot?,
    interfaceSnapshot: WiFiInterfaceSnapshot? = nil
  ) {
    self.row = row
    self.context = context
    self.interfaceSnapshot = interfaceSnapshot ?? context?.interface
    let newSnapshot = renderSnapshot
    guard renderedSnapshot != newSnapshot else { return }

    let preservesInteraction = renderedSnapshot?.row?.identity == row?.identity
    if inspectorTextSelectionIsBeingDragged,
      window?.isVisible == true
    {
      scheduleDeferredRebuild()
      return
    }
    deferredRebuild?.cancel()
    deferredRebuild = nil
    rebuild(
      preservingScrollPosition: preservesInteraction,
      preservingTextSelection: preservesInteraction
    )
    recordRenderedContent()
  }

  func resetToDefaults() {
    guard rawExpanded else { return }
    rawExpanded = false
    deferredRebuild?.cancel()
    deferredRebuild = nil
    rebuild(preservingScrollPosition: true, preservingTextSelection: true)
    recordRenderedContent()
  }

  private func buildInterface() {
    rootStack.translatesAutoresizingMaskIntoConstraints = false
    rootStack.orientation = .vertical
    rootStack.alignment = .leading
    rootStack.spacing = 8
    rootStack.edgeInsets = NSEdgeInsets(top: 0, left: 0, bottom: 10, right: 0)
    rootStack.detachesHiddenViews = true
    addSubview(rootStack)

    scrollView.translatesAutoresizingMaskIntoConstraints = false
    scrollView.hasVerticalScroller = true
    scrollView.hasHorizontalScroller = false
    scrollView.autohidesScrollers = true
    scrollView.drawsBackground = false
    scrollView.setContentHuggingPriority(.defaultLow, for: .vertical)
    scrollView.setContentCompressionResistancePriority(.defaultLow, for: .vertical)
    rootStack.addArrangedSubview(scrollView)

    textView.frame = scrollView.contentView.bounds
    textView.isEditable = false
    textView.isSelectable = true
    textView.isRichText = true
    textView.importsGraphics = false
    textView.usesFindPanel = true
    textView.drawsBackground = false
    textView.isVerticallyResizable = true
    textView.isHorizontallyResizable = false
    textView.autoresizingMask = [.width]
    textView.minSize = .zero
    textView.maxSize = NSSize(
      width: CGFloat.greatestFiniteMagnitude,
      height: CGFloat.greatestFiniteMagnitude
    )
    textView.textContainerInset = NSSize(width: 14, height: 14)
    textView.textContainer?.lineFragmentPadding = 0
    textView.textContainer?.widthTracksTextView = true
    textView.textContainer?.heightTracksTextView = false
    textView.textContainer?.containerSize = NSSize(
      width: max(
        scrollView.contentView.bounds.width - (textView.textContainerInset.width * 2),
        1
      ),
      height: CGFloat.greatestFiniteMagnitude
    )
    textView.identifier = NSUserInterfaceItemIdentifier("scan-inspector-details")
    textView.setAccessibilityLabel("Access Point Inspector Details")
    textView.setAccessibilityHelp(
      "Read-only Wi-Fi details. Select any continuous range of text and press Command-C to copy it."
    )
    scrollView.documentView = textView

    actionContainer.translatesAutoresizingMaskIntoConstraints = false
    actionStack.translatesAutoresizingMaskIntoConstraints = false
    actionStack.orientation = .vertical
    actionStack.alignment = .leading
    actionStack.spacing = 4
    actionStack.detachesHiddenViews = true
    actionContainer.addSubview(actionStack)

    let primaryActions = NSStackView()
    primaryActions.orientation = .horizontal
    primaryActions.alignment = .centerY
    primaryActions.spacing = 8
    primaryActions.addArrangedSubview(copyRowButton)
    primaryActions.addArrangedSubview(copyBSSIDButton)
    primaryActions.addArrangedSubview(copyRawButton)
    actionStack.addArrangedSubview(primaryActions)

    copyRowButton.target = self
    copyRowButton.action = #selector(copyRow)
    copyBSSIDButton.target = self
    copyBSSIDButton.action = #selector(copyBSSID)
    copyRawButton.target = self
    copyRawButton.action = #selector(copyRawInformationElements)
    copyRawButton.toolTip =
      "Copy the raw IEEE 802.11 information-element bytes as hexadecimal."

    rawToggleButton.target = self
    rawToggleButton.action = #selector(toggleRawExpansion)
    rawToggleButton.bezelStyle = .inline
    rawToggleButton.setAccessibilityHelp(
      "Shows or hides the complete information-element hex dump inside the selectable inspector document."
    )
    actionStack.addArrangedSubview(rawToggleButton)
    rootStack.addArrangedSubview(actionContainer)

    NSLayoutConstraint.activate([
      rootStack.leadingAnchor.constraint(equalTo: leadingAnchor),
      rootStack.trailingAnchor.constraint(equalTo: trailingAnchor),
      rootStack.topAnchor.constraint(equalTo: topAnchor),
      rootStack.bottomAnchor.constraint(equalTo: bottomAnchor),
      scrollView.widthAnchor.constraint(equalTo: rootStack.widthAnchor),
      scrollView.heightAnchor.constraint(greaterThanOrEqualToConstant: 100),
      actionContainer.widthAnchor.constraint(equalTo: rootStack.widthAnchor),
      actionStack.leadingAnchor.constraint(equalTo: actionContainer.leadingAnchor, constant: 14),
      actionStack.trailingAnchor.constraint(
        lessThanOrEqualTo: actionContainer.trailingAnchor,
        constant: -14
      ),
      actionStack.topAnchor.constraint(equalTo: actionContainer.topAnchor),
      actionStack.bottomAnchor.constraint(equalTo: actionContainer.bottomAnchor),
    ])
  }

  private func scheduleDeferredRebuild() {
    guard deferredRebuild == nil else { return }
    let workItem = DispatchWorkItem { [weak self] in
      guard let self else { return }
      self.deferredRebuild = nil
      if self.inspectorTextSelectionIsBeingDragged,
        self.window?.isVisible == true
      {
        self.scheduleDeferredRebuild()
        return
      }
      let preservesInteraction = self.renderedSnapshot?.row?.identity == self.row?.identity
      self.rebuild(
        preservingScrollPosition: preservesInteraction,
        preservingTextSelection: preservesInteraction
      )
      self.recordRenderedContent()
    }
    deferredRebuild = workItem
    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5, execute: workItem)
  }

  private var inspectorTextSelectionIsBeingDragged: Bool {
    window?.firstResponder === textView && (NSEvent.pressedMouseButtons & 1) != 0
  }

  private func rebuild(
    preservingScrollPosition: Bool = false,
    preservingTextSelection: Bool = false
  ) {
    let previousOrigin = scrollView.contentView.bounds.origin
    let previousString = textView.string
    let previousSelection = textView.selectedRange()
    if !preservingTextSelection {
      resignInspectorTextInteraction()
    }
    configureActions()
    let document = ScanInspectorDocumentBuilder.make(
      row: row,
      context: context,
      interfaceSnapshot: interfaceSnapshot,
      rawExpanded: rawExpanded
    )
    textView.textStorage?.setAttributedString(document)
    let selection =
      preservingTextSelection
      ? mappedSelection(
        previousSelection,
        from: previousString,
        to: textView.string
      )
      : NSRange(location: 0, length: 0)
    textView.setSelectedRange(selection)
    needsLayout = true
    layoutSubtreeIfNeeded()
    sizeTextViewToContent()

    let origin = preservingScrollPosition ? clampedScrollOrigin(previousOrigin) : .zero
    scrollView.contentView.scroll(to: origin)
    scrollView.reflectScrolledClipView(scrollView.contentView)
  }

  private func configureActions() {
    guard let row else {
      actionContainer.isHidden = true
      return
    }
    actionContainer.isHidden = false
    copyRowButton.isEnabled = true
    copyBSSIDButton.isEnabled = row.accessPoint.bssid != nil
    let hasRawInformationElements = !(row.accessPoint.informationElements?.isEmpty ?? true)
    copyRawButton.isEnabled = hasRawInformationElements
    rawToggleButton.isHidden = !hasRawInformationElements
    rawToggleButton.title = rawExpanded ? "Hide Complete Hex Dump" : "Show Complete Hex Dump"
    rawToggleButton.setAccessibilityValue(rawExpanded ? "Expanded" : "Collapsed")
  }

  private func resignInspectorTextInteraction() {
    if window?.firstResponder === textView {
      window?.makeFirstResponder(nil)
    }
  }

  private func sizeTextViewToContent() {
    guard !isSizingTextView else { return }
    let clipView = scrollView.contentView
    let clipSize = clipView.bounds.size
    guard clipSize.width > 0, clipSize.height > 0 else { return }
    isSizingTextView = true
    defer { isSizingTextView = false }

    let previousOrigin = clipView.bounds.origin
    var size = textView.frame.size
    if abs(size.width - clipSize.width) >= 0.5 {
      size.width = clipSize.width
      textView.setFrameSize(size)
    }
    if let textContainer = textView.textContainer,
      let layoutManager = textView.layoutManager
    {
      let textWidth = max(1, clipSize.width - (textView.textContainerInset.width * 2))
      if abs(textContainer.containerSize.width - textWidth) >= 0.5 {
        textContainer.containerSize = NSSize(
          width: textWidth,
          height: CGFloat.greatestFiniteMagnitude
        )
      }
      layoutManager.ensureLayout(for: textContainer)
      let usedRect = layoutManager.usedRect(for: textContainer)
      let requiredHeight = ceil(usedRect.maxY + (textView.textContainerInset.height * 2))
      let targetHeight = max(clipSize.height, requiredHeight)
      if abs(size.height - targetHeight) >= 0.5 {
        size.height = targetHeight
        textView.setFrameSize(size)
      }
    }
    let origin = clampedScrollOrigin(previousOrigin)
    if abs(clipView.bounds.origin.x - origin.x) >= 0.5
      || abs(clipView.bounds.origin.y - origin.y) >= 0.5
    {
      clipView.scroll(to: origin)
      scrollView.reflectScrolledClipView(clipView)
    }
  }

  private func clampedScrollOrigin(_ proposed: NSPoint) -> NSPoint {
    let clipBounds = scrollView.contentView.bounds
    let maximumY = max(0, textView.frame.height - clipBounds.height)
    return NSPoint(x: 0, y: min(max(0, proposed.y), maximumY))
  }

  private func mappedSelection(
    _ selection: NSRange,
    from previousString: String,
    to newString: String
  ) -> NSRange {
    let newLength = (newString as NSString).length
    guard selection.length > 0 else {
      return NSRange(location: min(selection.location, newLength), length: 0)
    }

    let previous = previousString as NSString
    if NSMaxRange(selection) <= previous.length {
      let selectedText = previous.substring(with: selection)
      let updated = newString as NSString
      if NSMaxRange(selection) <= updated.length,
        updated.substring(with: selection) == selectedText
      {
        return selection
      }
      if let nearestMatch = nearestRange(
        of: selectedText,
        in: updated,
        to: selection.location
      ) {
        return nearestMatch
      }
    }

    let location = min(selection.location, newLength)
    return NSRange(location: location, length: min(selection.length, newLength - location))
  }

  private func nearestRange(
    of value: String,
    in string: NSString,
    to location: Int
  ) -> NSRange? {
    guard !value.isEmpty else { return nil }
    var searchRange = NSRange(location: 0, length: string.length)
    var closest: NSRange?
    while searchRange.length > 0 {
      let match = string.range(of: value, range: searchRange)
      guard match.location != NSNotFound else { break }
      if let currentClosest = closest {
        if abs(match.location - location) < abs(currentClosest.location - location) {
          closest = match
        }
      } else {
        closest = match
      }
      let nextLocation = NSMaxRange(match)
      searchRange = NSRange(location: nextLocation, length: string.length - nextLocation)
    }
    return closest
  }

  private func recordRenderedContent() {
    renderedSnapshot = renderSnapshot
  }

  private var renderSnapshot: ScanInspectorRenderSnapshot {
    ScanInspectorRenderSnapshot(
      row: row.map(ScanInspectorRowSnapshot.init),
      context: context,
      interface: interfaceSnapshot
    )
  }

  @objc private func copyRow() {
    onCopyRow?()
  }

  @objc private func copyBSSID() {
    onCopyBSSID?()
  }

  @objc private func copyRawInformationElements() {
    onCopyRawInformationElements?()
  }

  @objc private func toggleRawExpansion() {
    rawExpanded.toggle()
    onRawExpansionChanged?(rawExpanded)
    deferredRebuild?.cancel()
    deferredRebuild = nil
    rebuild(preservingScrollPosition: true, preservingTextSelection: true)
    recordRenderedContent()
  }
}
