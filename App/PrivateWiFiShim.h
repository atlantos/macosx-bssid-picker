// SPDX-License-Identifier: GPL-3.0-only

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class CWInterface;
@class CWNetwork;

FOUNDATION_EXPORT NSErrorDomain const BPPrivateWiFiErrorDomain;

typedef NS_ERROR_ENUM(BPPrivateWiFiErrorDomain, BPPrivateWiFiErrorCode) {
    BPPrivateWiFiErrorUnsupported = 1,
    BPPrivateWiFiErrorInvalidArgument = 2,
    BPPrivateWiFiErrorUnexpectedService = 3,
    BPPrivateWiFiErrorMissingScanResult = 4,
    BPPrivateWiFiErrorAssociationFailed = 5,
    BPPrivateWiFiErrorRuntimeException = 6,
    BPPrivateWiFiErrorCredentialDelegationUnavailable = 7,
    BPPrivateWiFiErrorUnsupportedAuthentication = 8,
    BPPrivateWiFiErrorSSIDInvariantViolation = 9,
};

/// Returns whether `error` represents the stable credential-delegation
/// failure category exposed by this shim.
FOUNDATION_EXPORT BOOL BPIsCredentialDelegationUnavailableError(
    NSError *_Nullable error);

/// Returns whether `error` means that strict association rejected the
/// selected network's authentication family.
FOUNDATION_EXPORT BOOL BPIsUnsupportedAuthenticationError(
    NSError *_Nullable error);

/// Returns whether `error` means that the current, selected, or copied raw
/// SSID no longer matches the caller's expected current SSID.
FOUNDATION_EXPORT BOOL BPIsSSIDInvariantViolationError(
    NSError *_Nullable error);

/// Verifies that the private CoreWiFi runtime surface used for strict BSSID
/// association is present and has the expected Objective-C ABI.
FOUNDATION_EXPORT BOOL BPPrivateBackendAvailable(
    NSError *__autoreleasing _Nullable *_Nullable error);

/// Attempts one association to the exact scan result represented by `network`.
/// `expectedCurrentSSIDData` must be a nonempty snapshot of the raw SSID to
/// which `interface` is connected and must exactly match `network.ssidData`.
/// For a PSK Personal network, a request-local system-mode profile tells
/// airportd to resolve the saved System Keychain credential without exposing
/// it to this process. Passwordless networks do not require a profile. The
/// association is not added to the remembered-network list. This function
/// does not fall back to CoreWLAN's non-strict association API.
FOUNDATION_EXPORT BOOL BPAssociateForcedBSSID(
    CWInterface *interface,
    CWNetwork *network,
    NSData *expectedCurrentSSIDData,
    NSError *__autoreleasing _Nullable *_Nullable error);

NS_ASSUME_NONNULL_END
