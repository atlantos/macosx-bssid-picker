// SPDX-License-Identifier: GPL-3.0-only

import ServiceManagement

/// Authoritative macOS registration state for launching the main app when the
/// current user signs in. This is intentionally not mirrored in UserDefaults.
enum LaunchAtLoginStatus: Equatable {
  case notRegistered
  case enabled
  case requiresApproval
  case notFound
  case unknown

  var isRegistered: Bool {
    switch self {
    case .enabled, .requiresApproval: return true
    case .notRegistered, .notFound, .unknown: return false
    }
  }

  var isAvailable: Bool { self != .unknown }

}

protocol LaunchAtLoginServicing {
  var status: LaunchAtLoginStatus { get }
  func register() throws
  func unregister() throws
  func openSystemSettings()
}

/// Narrow boundary around ServiceManagement so orchestration and Settings UI
/// can be tested without mutating the current user's real Login Items.
final class LaunchAtLoginService: LaunchAtLoginServicing {
  private let service: SMAppService

  init(service: SMAppService = .mainApp) {
    self.service = service
  }

  var status: LaunchAtLoginStatus {
    switch service.status {
    case .notRegistered: return .notRegistered
    case .enabled: return .enabled
    case .requiresApproval: return .requiresApproval
    case .notFound: return .notFound
    @unknown default: return .unknown
    }
  }

  func register() throws {
    try service.register()
  }

  func unregister() throws {
    try service.unregister()
  }

  func openSystemSettings() {
    SMAppService.openSystemSettingsLoginItems()
  }
}
