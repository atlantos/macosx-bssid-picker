// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Immutable bundle metadata shared by application chrome and diagnostics.
/// Keeping the raw optional values lets each presentation choose an
/// appropriate fallback without querying `Bundle` repeatedly.
struct AppMetadata {
  let name: String
  let version: String?
  let build: String?
  let bundleIdentifier: String?

  init(bundle: Bundle = .main) {
    name =
      (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
      ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
      ?? "BSSID Picker"
    version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
    build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String
    bundleIdentifier = bundle.bundleIdentifier
  }
}
