// SPDX-License-Identifier: GPL-3.0-only

import AppKit

enum ScanReason {
  case initial
  case manual
  case automatic

  var announcesCompletion: Bool { self != .automatic }
}

enum ScanExportCommand: Int {
  case allJSON = 1
  case filteredJSON
  case allCSV
  case filteredCSV

  var format: ScanExportFormat {
    switch self {
    case .allJSON, .filteredJSON: return .json
    case .allCSV, .filteredCSV: return .csv
    }
  }

  var scope: ScanExportScope {
    switch self {
    case .allJSON, .allCSV: return .all
    case .filteredJSON, .filteredCSV: return .filtered
    }
  }
}

private enum ScanContextMenuCommand: Int {
  case copySelection = 1
  case copyRow
  case copyBSSID
  case copyRawInformationElements
}

enum ScanWindowSupport {
  static func verticalSeparator() -> NSView {
    let separator = NSBox()
    separator.boxType = .separator
    separator.heightAnchor.constraint(equalToConstant: 20).isActive = true
    return separator
  }

  static func copyToPasteboard(_ value: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(value, forType: .string)
  }

  static func copyTabularToPasteboard(_ value: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(value, forType: .string)
    NSPasteboard.general.setString(value, forType: .tabularText)
  }

  static func announce(
    _ value: String,
    from element: Any,
    priority: NSAccessibilityPriorityLevel
  ) {
    NSAccessibility.post(
      element: element,
      notification: .announcementRequested,
      userInfo: [
        .announcement: value,
        .priority: priority.rawValue,
      ]
    )
  }
}

// MARK: - Scanner columns, sorting, copy, and export

extension ScanWindowController {
  func configureColumnsMenu() {
    let menu = NSMenu()
    menu.autoenablesItems = false
    let title = NSMenuItem(title: "Columns", action: nil, keyEquivalent: "")
    menu.addItem(title)

    for group in ScanColumnGroup.allCases {
      if menu.items.count > 1 { menu.addItem(.separator()) }
      let heading = NSMenuItem(title: group.rawValue, action: nil, keyEquivalent: "")
      heading.isEnabled = false
      menu.addItem(heading)
      for columnID in ScanColumnID.allCases where columnID.group == group {
        let item = NSMenuItem(
          title: columnID.title,
          action: #selector(toggleColumn(_:)),
          keyEquivalent: ""
        )
        item.target = self
        item.representedObject = columnID.rawValue
        item.state = layout(for: columnID).isVisible ? .on : .off
        item.isEnabled = columnID != .clientAssociated
        if columnID == .clientAssociated {
          item.toolTip = "The active-BSSID status column is always shown first."
        }
        item.setAccessibilityLabel(columnID.accessibilityTitle)
        menu.addItem(item)
      }
    }
    columnsPopup.menu = menu
    columnsPopup.setAccessibilityLabel("Choose Table Columns")
  }

  func applyColumnLayout() {
    isApplyingColumnLayout = true
    defer { isApplyingColumnLayout = false }

    for column in tableView.tableColumns {
      tableView.removeTableColumn(column)
    }
    let visibleLayouts = preferences.columns
      .filter(\.isVisible)
      .sorted { $0.order < $1.order }
    for layout in visibleLayouts {
      let identifier = NSUserInterfaceItemIdentifier(layout.id.rawValue)
      let column = NSTableColumn(identifier: identifier)
      column.title = layout.id == .clientAssociated ? "✓" : layout.id.title
      column.headerCell.alignment = layout.id == .clientAssociated ? .center : .left
      column.headerCell.setAccessibilityLabel(layout.id.accessibilityTitle)
      if layout.id == .clientAssociated {
        column.headerToolTip = "Checkmark marks this Mac's currently active BSSID."
      }
      column.width = max(layout.id.minimumWidth, CGFloat(layout.width))
      column.minWidth = layout.id.minimumWidth
      column.maxWidth = layout.id.maximumWidth
      if layout.id == .clientAssociated {
        column.resizingMask = []
      }
      column.sortDescriptorPrototype = NSSortDescriptor(
        key: layout.id.rawValue,
        ascending: layout.id.defaultSortAscending
      )
      tableView.addTableColumn(column)
    }
    restoreSortDescriptors()
    configureColumnsMenu()
  }

  private func restoreSortDescriptors() {
    tableView.sortDescriptors = preferences.sortRules.map {
      NSSortDescriptor(key: $0.column.rawValue, ascending: $0.ascending)
    }
  }

  func tableColumnsDidChange(changesPreset: Bool) {
    guard !isApplyingColumnLayout else { return }
    var byID = Dictionary(uniqueKeysWithValues: preferences.columns.map { ($0.id, $0) })
    let visibleIDs = tableView.tableColumns.compactMap {
      ScanColumnID(rawValue: $0.identifier.rawValue)
    }
    for (index, column) in tableView.tableColumns.enumerated() {
      guard let id = ScanColumnID(rawValue: column.identifier.rawValue),
        var layout = byID[id]
      else { continue }
      layout.width = Double(column.width)
      layout.order = index
      layout.isVisible = true
      byID[id] = layout
    }
    var nextOrder = visibleIDs.count
    for id in ScanColumnID.allCases where !visibleIDs.contains(id) {
      guard var layout = byID[id] else { continue }
      layout.isVisible = false
      layout.order = max(layout.order, nextOrder)
      byID[id] = layout
      nextOrder += 1
    }
    preferences.columns = ScanColumnID.allCases.compactMap { byID[$0] }
    if changesPreset {
      preferences.preset = .custom
      updatePresetPopup()
    }
    savePreferences()
  }

  private func applyPreset(_ preset: ScanPreset) {
    guard preset != .custom else { return }
    let visible = Set(preset.columns)
    var byID = Dictionary(uniqueKeysWithValues: preferences.columns.map { ($0.id, $0) })
    for (index, id) in preset.columns.enumerated() {
      var layout =
        byID[id]
        ?? ScanColumnLayout(
          id: id,
          width: Double(id.defaultWidth),
          isVisible: true,
          order: index
        )
      layout.isVisible = true
      layout.order = index
      byID[id] = layout
    }
    var hiddenOrder = preset.columns.count
    for id in ScanColumnID.allCases where !visible.contains(id) {
      var layout =
        byID[id]
        ?? ScanColumnLayout(
          id: id,
          width: Double(id.defaultWidth),
          isVisible: false,
          order: hiddenOrder
        )
      layout.isVisible = false
      layout.order = hiddenOrder
      byID[id] = layout
      hiddenOrder += 1
    }
    preferences.columns = ScanColumnID.allCases.compactMap { byID[$0] }
    preferences.preset = preset
    applyColumnLayout()
    updatePresetPopup()
    savePreferences()
  }

  private func layout(for id: ScanColumnID) -> ScanColumnLayout {
    preferences.columns.first(where: { $0.id == id })
      ?? ScanColumnLayout(
        id: id,
        width: Double(id.defaultWidth),
        isVisible: false,
        order: ScanColumnID.allCases.firstIndex(of: id) ?? 0
      )
  }

  private func updatePresetPopup() {
    let customItem = presetPopup.itemArray.first {
      ($0.representedObject as? ScanPreset) == .custom
    }
    if preferences.preset == .custom,
      customItem == nil
    {
      addPresetItem(.custom)
    } else if preferences.preset != .custom,
      let customItem,
      let customIndex = presetPopup.itemArray.firstIndex(of: customItem)
    {
      presetPopup.removeItem(at: customIndex)
    }
    selectPresetItem(preferences.preset)
  }

  func addPresetItem(_ preset: ScanPreset) {
    presetPopup.addItem(withTitle: preset.rawValue)
    presetPopup.lastItem?.representedObject = preset
  }

  func selectPresetItem(_ preset: ScanPreset) {
    guard
      let index = presetPopup.itemArray.firstIndex(where: {
        ($0.representedObject as? ScanPreset) == preset
      })
    else { return }
    presetPopup.selectItem(at: index)
  }

  private var visibleColumnIDs: [ScanColumnID] {
    tableView.tableColumns.compactMap { ScanColumnID(rawValue: $0.identifier.rawValue) }
  }

  @objc func presetChanged() {
    guard let preset = presetPopup.selectedItem?.representedObject as? ScanPreset else { return }
    if preset == .custom { return }
    applyPreset(preset)
  }

  @objc private func toggleColumn(_ sender: NSMenuItem) {
    guard let rawValue = sender.representedObject as? String,
      let id = ScanColumnID(rawValue: rawValue),
      id != .clientAssociated,
      let index = preferences.columns.firstIndex(where: { $0.id == id })
    else { return }
    let visibleDataColumns = preferences.columns.filter {
      $0.id != .clientAssociated && $0.isVisible
    }.count
    if preferences.columns[index].isVisible, visibleDataColumns == 1 {
      NSSound.beep()
      return
    }
    preferences.columns[index].isVisible.toggle()
    preferences.preset = .custom
    applyColumnLayout()
    updatePresetPopup()
    savePreferences()
  }

  @objc func copySelectedRow() {
    guard let row = selectedRow else { return }
    ScanWindowSupport.copyTabularToPasteboard(
      ScanExporter.tabSeparatedRow(row, columns: visibleColumnIDs)
    )
    showTransientStatus("Copied selected row.")
  }

  @objc func copySelectedBSSID() {
    guard let bssid = selectedRow?.accessPoint.bssid?.rawValue else { return }
    ScanWindowSupport.copyToPasteboard(bssid)
    showTransientStatus("Copied BSSID \(bssid).")
  }

  @objc func copySelectedRawInformationElements() {
    guard let data = selectedRow?.accessPoint.informationElements, !data.isEmpty else { return }
    ScanWindowSupport.copyToPasteboard(ScanFormatting.compactHex(data))
    showTransientStatus("Copied \(data.count) raw information-element bytes as hexadecimal.")
  }

  private func showTransientStatus(_ message: String) {
    statusLabel.textColor = .labelColor
    statusLabel.stringValue = message
    announce(message, priority: .low)
    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
      self?.updateStatus()
    }
  }

  @objc func exportSelectedFormat(_ sender: NSMenuItem) {
    guard let command = ScanExportCommand(rawValue: sender.tag) else { return }
    let format = command.format
    let scope = command.scope
    let rows = scope == .all ? allRows : displayedRows
    guard !rows.isEmpty, let window else { return }

    ScanExportPresenter.begin(
      format: format,
      scope: scope,
      rows: rows,
      context: context?.withInterface(interfaceSnapshot),
      scannedAt: lastScanDate,
      in: window
    ) { [weak self] in
      self?.showTransientStatus(
        "Exported \(rows.count) access points as \(format.displayName)."
      )
    }
  }

  func updateExportMenuAvailability() {
    for item in exportPopup.menu?.items ?? [] {
      guard let command = ScanExportCommand(rawValue: item.tag) else { continue }
      item.isEnabled = command.scope == .all ? !allRows.isEmpty : !displayedRows.isEmpty
    }
  }
}

// MARK: - Scanner table

extension ScanWindowController: NSTableViewDataSource, NSTableViewDelegate {
  func numberOfRows(in tableView: NSTableView) -> Int {
    displayedRows.count
  }

  func tableView(
    _ tableView: NSTableView,
    viewFor tableColumn: NSTableColumn?,
    row: Int
  ) -> NSView? {
    guard displayedRows.indices.contains(row),
      let rawIdentifier = tableColumn?.identifier.rawValue,
      let columnID = ScanColumnID(rawValue: rawIdentifier)
    else { return nil }

    return ScanTableCellFactory.view(
      in: tableView,
      owner: self,
      row: displayedRows[row],
      column: columnID
    )
  }

  func tableViewSelectionDidChange(_ notification: Notification) {
    guard !isRestoringSelection else { return }
    selectedIdentity = selectedRow?.identity
    updateInspector()
  }

  func tableView(
    _ tableView: NSTableView,
    sortDescriptorsDidChange oldDescriptors: [NSSortDescriptor]
  ) {
    guard !isApplyingColumnLayout else { return }
    let rules = tableView.sortDescriptors.compactMap { descriptor -> ScanSortRule? in
      guard let key = descriptor.key, let column = ScanColumnID(rawValue: key) else { return nil }
      return ScanSortRule(column: column, ascending: descriptor.ascending)
    }
    preferences.sortRules = rules
    savePreferences()
    rebuildDisplayedRows()
  }

  func tableView(
    _ tableView: NSTableView,
    shouldReorderColumn columnIndex: Int,
    toColumn newColumnIndex: Int
  ) -> Bool {
    guard
      let associatedIndex = tableView.tableColumns.firstIndex(where: {
        $0.identifier.rawValue == ScanColumnID.clientAssociated.rawValue
      })
    else { return true }
    return columnIndex != associatedIndex && newColumnIndex != 0
  }
}

/// Handles scanner-specific shortcuts locally as a fallback when the utility
/// is menu-bar-only and for commands not represented in the Scanner's menu.
final class ScanCommandWindow: NSWindow {
  var onScan: (() -> Bool)?
  var onFocusSearch: (() -> Bool)?
  var onCopy: (() -> Bool)?
  var onClose: (() -> Bool)?

  override func performKeyEquivalent(with event: NSEvent) -> Bool {
    let modifiers = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
    let shortcutModifiers = modifiers.intersection([.command, .option, .control, .shift])
    guard shortcutModifiers == .command,
      let key = event.charactersIgnoringModifiers?.lowercased()
    else {
      return super.performKeyEquivalent(with: event)
    }

    if let textView = firstResponder as? NSTextView {
      if key == "a" {
        textView.selectAll(nil)
        return true
      }
      if key == "c", textView.selectedRange().length > 0 {
        textView.copy(nil)
        return true
      }
      if key == "f", textView.usesFindPanel, !textView.isFieldEditor {
        let sender = NSMenuItem()
        sender.tag = Int(NSFindPanelAction.showFindPanel.rawValue)
        textView.performFindPanelAction(sender)
        return true
      }
    }

    let handled: Bool
    switch key {
    case "r":
      handled = onScan?() ?? false
    case "f":
      handled = onFocusSearch?() ?? false
    case "c":
      handled = onCopy?() ?? false
    case "w":
      handled = onClose?() ?? false
    default:
      handled = false
    }
    return handled || super.performKeyEquivalent(with: event)
  }
}

final class ScanTableView: NSTableView {
  var contextualRowProvider: (() -> ScanRow?)?

  func installContextMenu(
    target: AnyObject,
    copyRow: Selector,
    copyBSSID: Selector,
    copyRaw: Selector
  ) {
    let contextualMenu = NSMenu()
    contextualMenu.autoenablesItems = false
    contextualMenu.addItem(
      contextItem(
        title: "Copy Selection",
        command: .copySelection,
        action: #selector(copySelectedCellText),
        target: self
      )
    )
    contextualMenu.addItem(.separator())
    contextualMenu.addItem(
      contextItem(
        title: "Copy Row", command: .copyRow, action: copyRow, target: target)
    )
    contextualMenu.addItem(
      contextItem(
        title: "Copy BSSID", command: .copyBSSID, action: copyBSSID, target: target
      )
    )
    contextualMenu.addItem(
      contextItem(
        title: "Copy Raw Information Elements",
        command: .copyRawInformationElements,
        action: copyRaw,
        target: target
      )
    )
    menu = contextualMenu
  }

  override func menu(for event: NSEvent) -> NSMenu? {
    let location = convert(event.locationInWindow, from: nil)
    let clickedRow = row(at: location)
    guard clickedRow >= 0 else { return nil }
    selectRowIndexes(IndexSet(integer: clickedRow), byExtendingSelection: false)
    let contextualMenu = super.menu(for: event)
    let scanRow = contextualRowProvider?()
    for item in contextualMenu?.items ?? [] {
      switch ScanContextMenuCommand(rawValue: item.tag) {
      case .copySelection:
        item.isEnabled = selectedCellTextEditor != nil
      case .copyRow:
        item.isEnabled = scanRow != nil
      case .copyBSSID:
        item.isEnabled = scanRow?.accessPoint.bssid != nil
      case .copyRawInformationElements:
        item.isEnabled = !(scanRow?.accessPoint.informationElements?.isEmpty ?? true)
      case nil:
        item.isEnabled = false
      }
    }
    return contextualMenu
  }

  @objc private func copySelectedCellText() {
    selectedCellTextEditor?.copy(nil)
  }

  private var selectedCellTextEditor: NSTextView? {
    guard let editor = window?.firstResponder as? NSTextView,
      editor.isFieldEditor,
      editor.selectedRange().length > 0,
      let field = editor.delegate as? NSView,
      field is ScanTableTextField,
      field.isDescendant(of: self)
    else { return nil }
    return editor
  }

  private func contextItem(
    title: String,
    command: ScanContextMenuCommand,
    action: Selector,
    target: AnyObject
  ) -> NSMenuItem {
    let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
    item.tag = command.rawValue
    item.target = target
    return item
  }
}

/// A read-only table value that retains native AppKit substring selection.
/// Selecting text must not prevent the row from driving the inspector, and a
/// secondary click must continue to expose the scanner's row context menu.
final class ScanTableTextField: NSTextField {
  weak var scanTableView: ScanTableView?

  override func mouseDown(with event: NSEvent) {
    selectContainingRow()
    super.mouseDown(with: event)
  }

  override func menu(for event: NSEvent) -> NSMenu? {
    selectContainingRow()
    return scanTableView?.menu(for: event) ?? super.menu(for: event)
  }

  @discardableResult
  func selectContainingRow() -> Bool {
    guard let tableView = scanTableView else { return false }
    let row = tableView.row(for: self)
    guard row >= 0 else { return false }
    if !tableView.selectedRowIndexes.contains(row) {
      tableView.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
    }
    return true
  }
}

/// Coalesces presentation-only table refreshes while AppKit's shared field
/// editor owns a selected substring. The data source and its visible rows stay
/// in sync until the latest pending presentation can be applied safely.
final class ScanTableReloadDeferrer {
  private let retryDelay: TimeInterval
  private var pendingAction: (() -> Void)?
  private var interactionIsActive: (() -> Bool)?
  private var workItem: DispatchWorkItem?

  init(retryDelay: TimeInterval = 0.25) {
    self.retryDelay = retryDelay
  }

  deinit {
    cancel()
  }

  /// Returns `true` when the action was deferred. A newer deferred action
  /// replaces the older one so rapidly arriving scan results never replay.
  @discardableResult
  func perform(
    while interactionIsActive: @escaping () -> Bool,
    action: @escaping () -> Void
  ) -> Bool {
    guard interactionIsActive() else {
      cancel()
      action()
      return false
    }
    pendingAction = action
    self.interactionIsActive = interactionIsActive
    scheduleIfNeeded()
    return true
  }

  func flush() {
    workItem?.cancel()
    workItem = nil
    interactionIsActive = nil
    let action = pendingAction
    pendingAction = nil
    action?()
  }

  func cancel() {
    workItem?.cancel()
    workItem = nil
    interactionIsActive = nil
    pendingAction = nil
  }

  private func scheduleIfNeeded() {
    guard workItem == nil else { return }
    let item = DispatchWorkItem { [weak self] in
      guard let self else { return }
      self.workItem = nil
      guard self.pendingAction != nil else { return }
      if self.interactionIsActive?() == true {
        self.scheduleIfNeeded()
      } else {
        self.flush()
      }
    }
    workItem = item
    DispatchQueue.main.asyncAfter(deadline: .now() + retryDelay, execute: item)
  }
}

enum ScanTableCellFactory {
  static func view(
    in tableView: NSTableView,
    owner: Any?,
    row: ScanRow,
    column: ScanColumnID
  ) -> NSView {
    let identifier = NSUserInterfaceItemIdentifier("ScanCell.\(column.rawValue)")
    let cell: NSTableCellView
    let textField: ScanTableTextField
    if let reused = tableView.makeView(withIdentifier: identifier, owner: owner)
      as? NSTableCellView,
      let reusedText = reused.textField as? ScanTableTextField
    {
      cell = reused
      textField = reusedText
    } else {
      cell = NSTableCellView()
      cell.identifier = identifier
      textField = ScanTableTextField(labelWithString: "")
      textField.translatesAutoresizingMaskIntoConstraints = false
      textField.lineBreakMode = .byTruncatingTail
      textField.maximumNumberOfLines = 1
      cell.textField = textField
      cell.addSubview(textField)
      if column == .observationStatus {
        let imageView = NSImageView()
        imageView.translatesAutoresizingMaskIntoConstraints = false
        imageView.imageScaling = .scaleProportionallyDown
        imageView.setAccessibilityElement(false)
        cell.imageView = imageView
        cell.addSubview(imageView)
        NSLayoutConstraint.activate([
          imageView.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 5),
          imageView.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
          imageView.widthAnchor.constraint(equalToConstant: 14),
          imageView.heightAnchor.constraint(equalToConstant: 14),
          textField.leadingAnchor.constraint(equalTo: imageView.trailingAnchor, constant: 5),
          textField.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -5),
          textField.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
        ])
      } else {
        NSLayoutConstraint.activate([
          textField.leadingAnchor.constraint(equalTo: cell.leadingAnchor, constant: 5),
          textField.trailingAnchor.constraint(equalTo: cell.trailingAnchor, constant: -5),
          textField.centerYAnchor.constraint(equalTo: cell.centerYAnchor),
        ])
      }
    }

    textField.scanTableView = tableView as? ScanTableView
    textField.isEditable = false
    textField.isSelectable = column != .clientAssociated

    let value: String
    if column == .clientAssociated {
      switch row.clientState.associated {
      case true: value = "✓"
      case false: value = ""
      case nil: value = ""
      }
    } else {
      value = row.stringValue(for: column)
    }
    textField.stringValue = value
    let isPreviousObservation = !row.presentInLatestSuccessfulScan
    textField.textColor = isPreviousObservation ? .secondaryLabelColor : .labelColor
    textField.alignment =
      column == .clientAssociated ? .center : (column.isNumeric ? .right : .left)
    if column == .bssid || column == .ssidHex {
      textField.font = NSFont.monospacedSystemFont(
        ofSize: NSFont.systemFontSize,
        weight: .regular
      )
    } else if column.isNumeric {
      textField.font = NSFont.monospacedDigitSystemFont(
        ofSize: NSFont.systemFontSize,
        weight: .regular
      )
    } else if column == .clientAssociated {
      textField.font = NSFont.systemFont(ofSize: NSFont.systemFontSize, weight: .semibold)
    } else {
      textField.font = NSFont.systemFont(ofSize: NSFont.systemFontSize)
    }
    let observationDescription =
      row.presentInLatestSuccessfulScan
      ? "Seen in the latest successful scan"
      : "Previous observation; not reported in the latest successful scan"
    let lastSeenDescription =
      "Last seen \(ScanFormatting.timestamp.string(from: row.lastSeenAt))"
    let baseAccessibilityValue = row.accessibilityValue(for: column)
    let baseToolTip =
      column == .clientAssociated || column == .macRegistrant
      ? baseAccessibilityValue : value
    if column == .observationStatus || column == .lastSeen {
      textField.toolTip = "\(observationDescription). \(lastSeenDescription)."
      textField.setAccessibilityValue("\(observationDescription). \(lastSeenDescription).")
    } else if isPreviousObservation {
      textField.toolTip =
        "\(observationDescription). \(lastSeenDescription). \(baseToolTip)"
      textField.setAccessibilityValue(
        "\(observationDescription). \(lastSeenDescription). \(baseAccessibilityValue)"
      )
    } else {
      textField.toolTip = baseToolTip
      textField.setAccessibilityValue(baseAccessibilityValue)
    }
    if column == .observationStatus, let imageView = cell.imageView {
      let symbolName = isPreviousObservation ? "clock" : "circle.fill"
      imageView.image = NSImage(systemSymbolName: symbolName, accessibilityDescription: nil)
      imageView.contentTintColor = .secondaryLabelColor
      imageView.toolTip = "\(observationDescription). \(lastSeenDescription)."
    }
    textField.setAccessibilityLabel(column.accessibilityTitle)
    return cell
  }
}

extension Collection {
  subscript(scanSafe index: Index) -> Element? {
    indices.contains(index) ? self[index] : nil
  }
}
