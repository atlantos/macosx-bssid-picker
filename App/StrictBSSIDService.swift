// SPDX-License-Identifier: GPL-3.0-only

import CoreWLAN
import Foundation

/// The only Swift boundary to the dynamically loaded private CoreWiFi shim.
/// It never accepts a password and never falls back to public association.
final class StrictBSSIDService {
  func requireAvailability() throws {
    var error: NSError?
    guard BPPrivateBackendAvailable(&error) else {
      throw WiFiOperationError.strictBackendUnavailable(underlying: error)
    }
  }

  func associate(
    interface: CWInterface,
    network: CWNetwork,
    expectedCurrentSSID: RawSSID
  ) throws {
    var error: NSError?
    guard BPAssociateForcedBSSID(interface, network, expectedCurrentSSID.data, &error) else {
      if BPIsCredentialDelegationUnavailableError(error) {
        throw WiFiOperationError.strictCredentialDelegationUnavailable(underlying: error)
      }
      if BPIsUnsupportedAuthenticationError(error) {
        throw WiFiOperationError.unknownSecurity
      }
      if BPIsSSIDInvariantViolationError(error) {
        throw WiFiOperationError.currentSSIDChanged
      }
      throw WiFiOperationError.strictAssociationFailed(underlying: error)
    }
  }
}
