// SPDX-License-Identifier: GPL-3.0-only

import AppKit

/// Presents the conventional macOS application UI only while the Wi-Fi
/// Scanner has an open window session. The status-item utility otherwise
/// remains an accessory app without a Dock icon or application menu.
final class ApplicationMenuController: NSObject {
  private let onShowAbout: () -> Void
  private let onShowSettings: () -> Void
  private let metadata: AppMetadata
  private var installedMainMenu: NSMenu?

  init(
    metadata: AppMetadata = AppMetadata(),
    onShowAbout: @escaping () -> Void,
    onShowSettings: @escaping () -> Void
  ) {
    self.metadata = metadata
    self.onShowAbout = onShowAbout
    self.onShowSettings = onShowSettings
  }

  func setScannerOpen(_ isOpen: Bool) {
    precondition(Thread.isMainThread, "Application presentation must change on the main thread.")

    let policy: NSApplication.ActivationPolicy = isOpen ? .regular : .accessory
    if isOpen {
      installMainMenu()
    }
    guard NSApp.activationPolicy() != policy else { return }
    if !NSApp.setActivationPolicy(policy) {
      let policyName = isOpen ? "regular" : "accessory"
      NSLog("BSSID Picker could not change its activation policy to %@.", policyName)
    }
  }

  private func installMainMenu() {
    if installedMainMenu == nil {
      installedMainMenu = makeMainMenu()
    }
    NSApp.mainMenu = installedMainMenu
  }

  private func makeMainMenu() -> NSMenu {
    let mainMenu = NSMenu()
    mainMenu.addItem(rootItem(title: applicationName, submenu: makeApplicationMenu()))
    mainMenu.addItem(rootItem(title: "File", submenu: makeFileMenu()))
    mainMenu.addItem(rootItem(title: "Edit", submenu: makeEditMenu()))

    let windowMenu = makeWindowMenu()
    mainMenu.addItem(rootItem(title: "Window", submenu: windowMenu))
    NSApp.windowsMenu = windowMenu
    return mainMenu
  }

  private func makeApplicationMenu() -> NSMenu {
    let name = applicationName
    let menu = NSMenu(title: name)
    menu.addItem(
      item(
        title: "About \(name)",
        action: #selector(showAbout(_:)),
        target: self
      )
    )
    menu.addItem(.separator())
    menu.addItem(
      item(
        title: "Settings…",
        action: #selector(showSettings(_:)),
        keyEquivalent: ",",
        target: self
      )
    )
    menu.addItem(.separator())

    let servicesMenu = NSMenu(title: "Services")
    let servicesItem = NSMenuItem(title: "Services", action: nil, keyEquivalent: "")
    servicesItem.submenu = servicesMenu
    menu.addItem(servicesItem)
    NSApp.servicesMenu = servicesMenu

    menu.addItem(.separator())
    menu.addItem(
      item(
        title: "Hide \(name)",
        action: #selector(NSApplication.hide(_:)),
        keyEquivalent: "h",
        target: NSApp
      )
    )
    menu.addItem(
      item(
        title: "Hide Others",
        action: #selector(NSApplication.hideOtherApplications(_:)),
        keyEquivalent: "h",
        modifiers: [.command, .option],
        target: NSApp
      )
    )
    menu.addItem(
      item(
        title: "Show All",
        action: #selector(NSApplication.unhideAllApplications(_:)),
        target: NSApp
      )
    )
    menu.addItem(.separator())
    menu.addItem(
      item(
        title: "Quit \(name)",
        action: #selector(NSApplication.terminate(_:)),
        keyEquivalent: "q",
        target: NSApp
      )
    )
    return menu
  }

  private func makeFileMenu() -> NSMenu {
    let menu = NSMenu(title: "File")
    menu.addItem(
      item(
        title: "Close",
        action: #selector(NSWindow.performClose(_:)),
        keyEquivalent: "w"
      )
    )
    return menu
  }

  private func makeEditMenu() -> NSMenu {
    let menu = NSMenu(title: "Edit")
    menu.addItem(item(title: "Undo", action: Selector(("undo:")), keyEquivalent: "z"))
    menu.addItem(
      item(
        title: "Redo",
        action: Selector(("redo:")),
        keyEquivalent: "z",
        modifiers: [.command, .shift]
      )
    )
    menu.addItem(.separator())
    menu.addItem(item(title: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x"))
    menu.addItem(item(title: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c"))
    menu.addItem(item(title: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v"))
    menu.addItem(item(title: "Delete", action: #selector(NSText.delete(_:))))
    menu.addItem(.separator())
    menu.addItem(
      item(title: "Select All", action: #selector(NSResponder.selectAll(_:)), keyEquivalent: "a")
    )
    return menu
  }

  private func makeWindowMenu() -> NSMenu {
    let menu = NSMenu(title: "Window")
    menu.addItem(
      item(
        title: "Minimize",
        action: #selector(NSWindow.performMiniaturize(_:)),
        keyEquivalent: "m"
      )
    )
    menu.addItem(item(title: "Zoom", action: #selector(NSWindow.performZoom(_:))))
    menu.addItem(.separator())
    menu.addItem(
      item(
        title: "Bring All to Front",
        action: #selector(NSApplication.arrangeInFront(_:)),
        target: NSApp
      )
    )
    return menu
  }

  private func rootItem(title: String, submenu: NSMenu) -> NSMenuItem {
    let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
    item.submenu = submenu
    return item
  }

  private func item(
    title: String,
    action: Selector,
    keyEquivalent: String = "",
    modifiers: NSEvent.ModifierFlags = .command,
    target: AnyObject? = nil
  ) -> NSMenuItem {
    let item = NSMenuItem(title: title, action: action, keyEquivalent: keyEquivalent)
    item.keyEquivalentModifierMask = modifiers
    item.target = target
    return item
  }

  private var applicationName: String {
    metadata.name
  }

  @objc private func showAbout(_ sender: Any?) {
    onShowAbout()
  }

  @objc private func showSettings(_ sender: Any?) {
    onShowSettings()
  }
}
