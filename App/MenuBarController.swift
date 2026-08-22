// SPDX-License-Identifier: GPL-3.0-only

import AppKit

enum MenuRefreshState: Equatable {
  case ready
  case refreshing
  case connecting

  var title: String {
    switch self {
    case .ready: return "Refresh"
    case .refreshing: return "Refreshing…"
    case .connecting: return "Connecting…"
    }
  }
}

struct MenuNetworkItem {
  let target: NetworkTarget
  let title: String
  let accessibilityDescription: String
  let isCurrent: Bool
  let isEnabled: Bool
  let toolTip: String?

  init(
    target: NetworkTarget,
    title: String,
    accessibilityDescription: String? = nil,
    isCurrent: Bool,
    isEnabled: Bool,
    toolTip: String?
  ) {
    self.target = target
    self.title = title
    self.accessibilityDescription = accessibilityDescription ?? title
    self.isCurrent = isCurrent
    self.isEnabled = isEnabled
    self.toolTip = toolTip
  }
}

enum MenuNoticeStyle {
  case information
  case warning
  case error
}

enum MenuNoticeAction {
  case refresh
  case retryLock
  case showSettings
  case showInspector
}

struct MenuNotice {
  let style: MenuNoticeStyle
  let title: String
  let message: String
  let actionTitle: String?
  let action: MenuNoticeAction?

  init(
    style: MenuNoticeStyle,
    title: String,
    message: String,
    actionTitle: String? = nil,
    action: MenuNoticeAction? = nil
  ) {
    self.style = style
    self.title = title
    self.message = message
    self.actionTitle = actionTitle
    self.action = action
  }
}

struct MenuBarViewState {
  let heading: String
  let headingToolTip: String?
  let currentBSSIDDescription: String?
  let refreshState: MenuRefreshState
  let refreshEnabled: Bool
  let networks: [MenuNetworkItem]
  let controlsEnabled: Bool
  let lockTargetDescription: String?
  let lockEnabled: Bool
  let lockStatus: String
  let showsLockStatus: Bool
  let showAllEnabled: Bool
  let notice: MenuNotice?

  init(
    heading: String,
    headingToolTip: String?,
    currentBSSIDDescription: String?,
    refreshState: MenuRefreshState,
    refreshEnabled: Bool,
    networks: [MenuNetworkItem],
    controlsEnabled: Bool,
    lockTargetDescription: String?,
    lockEnabled: Bool,
    lockStatus: String,
    showsLockStatus: Bool,
    showAllEnabled: Bool,
    notice: MenuNotice? = nil
  ) {
    self.heading = heading
    self.headingToolTip = headingToolTip
    self.currentBSSIDDescription = currentBSSIDDescription
    self.refreshState = refreshState
    self.refreshEnabled = refreshEnabled
    self.networks = networks
    self.controlsEnabled = controlsEnabled
    self.lockTargetDescription = lockTargetDescription
    self.lockEnabled = lockEnabled
    self.lockStatus = lockStatus
    self.showsLockStatus = showsLockStatus
    self.showAllEnabled = showAllEnabled
    self.notice = notice
  }
}

/// Owns the status item and a single, retained popover. Unlike a tracking
/// NSMenu, the popover can safely replace AP rows while an asynchronous scan is
/// running, so first-open results appear without closing and reopening it.
final class MenuBarController: NSObject, NSPopoverDelegate {
  var onMenuOpen: (() -> Void)?
  var onMenuClose: (() -> Void)?
  var onRefresh: (() -> Void)?
  var onSelectNetwork: ((NetworkTarget) -> Void)?
  var onToggleLock: (() -> Void)?
  var onRetryLock: (() -> Void)?
  var onShowSettings: (() -> Void)?
  var onShowAllNetworks: (() -> Void)?
  var onShowAbout: (() -> Void)?

  private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
  private let popover = NSPopover()
  private let contentController: MenuPopoverViewController
  private var state: MenuBarViewState

  private(set) var isTracking = false

  init(initialState: MenuBarViewState) {
    state = initialState
    contentController = MenuPopoverViewController(initialState: initialState)
    super.init()

    contentController.delegate = self
    popover.contentViewController = contentController
    popover.behavior = .transient
    popover.animates = true
    popover.delegate = self

    if let button = statusItem.button {
      button.target = self
      button.action = #selector(togglePopover(_:))
      button.sendAction(on: [.leftMouseUp])
      button.setAccessibilityRole(.button)
    }
    render(initialState)
  }

  func render(_ newState: MenuBarViewState, synchronizeSize: Bool = true) {
    precondition(Thread.isMainThread, "Menu-bar state must be rendered on the main thread.")
    state = newState
    contentController.render(newState)
    if synchronizeSize {
      synchronizePopoverSize()
    }
    updateStatusItem()
  }

  func popoverWillShow(_ notification: Notification) {
    synchronizePopoverSize()
  }

  func popoverDidShow(_ notification: Notification) {
    // The popover window now has its final display assignment. Reconcile once
    // more in case the menu bar moved between displays while it was closed.
    synchronizePopoverSize()
  }

  func popoverDidClose(_ notification: Notification) {
    guard isTracking else { return }
    isTracking = false
    onMenuClose?()
    updateStatusItem()
  }

  private func updateStatusItem() {
    guard let button = statusItem.button else { return }
    button.image = StatusSymbols.statusImage(locked: state.lockEnabled)

    var parts = [state.heading]
    if let currentBSSID = state.currentBSSIDDescription { parts.append(currentBSSID) }
    if state.lockEnabled, state.notice == nil { parts.append(state.lockStatus) }
    if state.refreshState != .ready { parts.append(state.refreshState.title) }
    if let notice = state.notice {
      parts.append("\(notice.title): \(notice.message)")
    } else if let headingError = state.headingToolTip {
      parts.append("Wi-Fi scan error: \(headingError)")
    }
    let summary = parts.joined(separator: " — ")
    button.toolTip = summary
    button.setAccessibilityLabel("BSSID Picker")
    button.setAccessibilityHelp(summary)
    button.setAccessibilityValue(summary)
  }

  @objc private func togglePopover(_ sender: NSStatusBarButton) {
    if popover.isShown {
      popover.performClose(sender)
      return
    }
    isTracking = true
    onMenuOpen?()
    synchronizePopoverSize()
    popover.show(relativeTo: sender.bounds, of: sender, preferredEdge: .minY)
    popover.contentViewController?.view.window?.makeKey()
    updateStatusItem()
  }

  private func synchronizePopoverSize() {
    let screen =
      statusItem.button?.window?.screen ?? popover.contentViewController?.view.window?.screen
    let size = contentController.fittingContentSize(on: screen)
    guard
      abs(popover.contentSize.width - size.width) > 0.5
        || abs(popover.contentSize.height - size.height) > 0.5
    else { return }
    popover.contentSize = size
  }
}

extension MenuBarController: MenuPopoverViewControllerDelegate {
  func menuPopoverRequestedRefresh() { onRefresh?() }
  func menuPopoverSelected(_ target: NetworkTarget) { onSelectNetwork?(target) }
  func menuPopoverRequestedLockToggle() { onToggleLock?() }
  func menuPopoverRequestedLockRetry() { onRetryLock?() }
  func menuPopoverRequestedSettings() { closePopover(then: onShowSettings) }
  func menuPopoverRequestedInspector() { closePopover(then: onShowAllNetworks) }
  func menuPopoverRequestedAbout() { closePopover(then: onShowAbout) }
  func menuPopoverRequestedQuit() { closePopover { NSApp.terminate(nil) } }

  private func closePopover(then action: (() -> Void)?) {
    if isTracking {
      isTracking = false
      onMenuClose?()
      updateStatusItem()
    }
    popover.performClose(nil)
    action?()
  }
}
