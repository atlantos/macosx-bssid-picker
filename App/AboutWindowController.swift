// SPDX-License-Identifier: GPL-3.0-only

import AppKit

/// Lightweight, retained About window shared by the status-item popover and
/// the conventional application menu shown while the Scanner is open.
final class AboutWindowController: NSWindowController {
  init(bundle: Bundle = .main, metadata: AppMetadata? = nil) {
    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 420, height: 320),
      styleMask: [.titled, .closable],
      backing: .buffered,
      defer: false
    )
    super.init(window: window)
    window.title = "About BSSID Picker"
    window.isReleasedWhenClosed = false
    window.center()
    buildInterface(bundle: bundle, metadata: metadata ?? AppMetadata(bundle: bundle))
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) {
    fatalError("init(coder:) is not supported")
  }

  func show() {
    showWindow(nil)
    window?.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }

  private func buildInterface(bundle: Bundle, metadata: AppMetadata) {
    guard let content = window?.contentView else { return }
    let icon = NSImageView()
    icon.image =
      bundle.image(forResource: "AppIcon")
      ?? NSImage(systemSymbolName: "wifi.circle", accessibilityDescription: "BSSID Picker")
    icon.imageScaling = .scaleProportionallyUpOrDown
    icon.widthAnchor.constraint(equalToConstant: 72).isActive = true
    icon.heightAnchor.constraint(equalToConstant: 72).isActive = true

    let name = NSTextField(labelWithString: metadata.name)
    name.font = .systemFont(ofSize: 22, weight: .semibold)
    name.alignment = .center

    let version = NSTextField(labelWithString: "Version \(metadata.version ?? "Unknown")")
    version.textColor = .secondaryLabelColor
    version.alignment = .center

    let license = NSTextField(labelWithString: "GNU General Public License v3.0 only")
    license.font = .systemFont(ofSize: 11)
    license.textColor = .secondaryLabelColor
    license.alignment = .center

    let summary = NSTextField(
      wrappingLabelWithString:
        "Connect to a specific Wi-Fi access point, inspect nearby networks, and optionally use BSSID Lock."
    )
    summary.alignment = .center
    summary.maximumNumberOfLines = 3
    summary.widthAnchor.constraint(equalToConstant: 340).isActive = true

    let note = NSTextField(
      wrappingLabelWithString:
        "Exact-BSSID association is ultimately controlled by macOS. Experimental Strict BSSID uses an undocumented private interface and may change after an OS update."
    )
    note.font = .systemFont(ofSize: 11)
    note.textColor = .secondaryLabelColor
    note.alignment = .center
    note.maximumNumberOfLines = 4
    note.widthAnchor.constraint(equalToConstant: 340).isActive = true

    let stack = NSStackView(views: [icon, name, version, license, summary, note])
    stack.orientation = .vertical
    stack.alignment = .centerX
    stack.spacing = 9
    stack.translatesAutoresizingMaskIntoConstraints = false
    content.addSubview(stack)
    NSLayoutConstraint.activate([
      stack.centerXAnchor.constraint(equalTo: content.centerXAnchor),
      stack.centerYAnchor.constraint(equalTo: content.centerYAnchor),
      stack.leadingAnchor.constraint(greaterThanOrEqualTo: content.leadingAnchor, constant: 24),
      stack.trailingAnchor.constraint(lessThanOrEqualTo: content.trailingAnchor, constant: -24),
    ])
  }

}
