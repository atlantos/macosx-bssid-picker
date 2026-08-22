// SPDX-License-Identifier: GPL-3.0-only

import AppKit

enum StatusSymbols {
  static let statusUnlocked = symbol("wifi.circle", fallback: "NSNetwork")
  static let statusLocked = symbol("wifi.circle.fill", fallback: "NSNetwork")
  static let headerWiFi = symbol("wifi", fallback: "NSNetwork")
  static let refresh = symbol("arrow.clockwise", fallback: "NSRefreshTemplate")
  static let current = symbol("checkmark.circle.fill", fallback: "NSMenuOnStateTemplate")
  static let notCurrent = symbol("circle", fallback: "NSMenuOffStateTemplate")
  static let settings = symbol("gearshape", fallback: "NSPreferencesGeneral")
  static let inspector = symbol("tablecells", fallback: "NSInfo")
  static let information = symbol("info.circle.fill", fallback: "NSInfo")
  static let warning = symbol("exclamationmark.triangle.fill", fallback: "NSCaution")
  static let error = symbol("xmark.octagon.fill", fallback: "NSCaution")

  /// Keep the circular Wi-Fi silhouette stable. Transient state belongs in
  /// descriptive text and the popover; swapping in a generic Wi-Fi or warning
  /// glyph makes the item look like another menu-bar utility.
  static func statusImage(locked: Bool) -> NSImage {
    return locked ? statusLocked : statusUnlocked
  }

  static func notice(_ style: MenuNoticeStyle) -> NSImage {
    switch style {
    case .information: return information
    case .warning: return warning
    case .error: return error
    }
  }

  private static func symbol(_ name: String, fallback: String) -> NSImage {
    let image =
      NSImage(systemSymbolName: name, accessibilityDescription: nil)
      ?? NSImage(named: NSImage.Name(fallback))
      ?? NSImage(size: NSSize(width: 16, height: 16))
    image.isTemplate = true
    return image
  }
}
