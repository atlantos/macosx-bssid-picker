// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import CoreLocation

enum LocationAuthorizationState: Equatable {
  case notDetermined
  case allowed
  case denied
  case unavailable
}

final class LocationAuthorizationController: NSObject, CLLocationManagerDelegate {
  private let manager = CLLocationManager()

  var onStateChange: ((LocationAuthorizationState) -> Void)?

  override init() {
    super.init()
    manager.delegate = self
  }

  var state: LocationAuthorizationState {
    switch manager.authorizationStatus {
    case .notDetermined:
      return .notDetermined
    case .authorized, .authorizedAlways, .authorizedWhenInUse:
      return .allowed
    case .denied, .restricted:
      return .denied
    @unknown default:
      return .unavailable
    }
  }

  var isAllowed: Bool { state == .allowed }

  /// Location access is requested only from a direct menu interaction. An
  /// enabled lock may use existing authorization at launch, but never opens
  /// the system prompt on its own.
  func requestFromUserAction() {
    guard state == .notDetermined else { return }
    NSApp.activate(ignoringOtherApps: true)
    manager.requestWhenInUseAuthorization()
  }

  func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
    DispatchQueue.main.async { [weak self] in
      guard let self else { return }
      self.onStateChange?(self.state)
    }
  }
}
