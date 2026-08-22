# Architecture

This document is for contributors who need to understand the source layout,
runtime boundaries, and persisted state. User workflows belong in the
[User Guide](USER-GUIDE.md), build and signing procedures belong in
[Installation and Local Signing](INSTALLATION.md), and the CoreWLAN/CoreWiFi
association analysis belongs in
[BSSID Association on macOS](BSSID-ASSOCIATION.md).

## Build model

BSSID Picker is a native AppKit application. It does not use an Xcode project,
Swift Package Manager, or third-party dependencies. `BuildTools/build-app.sh`
contains an explicit source manifest and compiles the Swift, Objective-C, and C
sources for the host Mac's native architecture with a macOS 13 deployment
target.

The build script:

1. validates required inputs, the project license, plist settings,
   entitlements, and its exhaustive Swift source manifest;
2. resolves the SDK, native target, and signing identity;
3. creates private staging and module-cache directories and assembles the
   bundle resources, including the license copy shipped with the app;
4. compiles the Objective-C private Wi-Fi shim, Swift application, and separate
   C atomic-install helper;
5. signs and verifies the staged app with its App Sandbox, Location,
   outbound-network, and user-selected-file entitlements; and
6. uses the helper to atomically replace `build/BSSID Picker.app` only after
   validation succeeds.

Local-signing setup and supported build overrides are documented in
[Installation and Local Signing](INSTALLATION.md).

## Application lifecycle

`AppDelegate` owns the application lifetime. `ApplicationController` is the
main coordinator for permissions, scans, connections, BSSID Lock, Settings,
and presentation state.

The app normally runs as an accessory menu-bar application:

- `MenuBarController` owns the status item and popover.
- `MenuPopoverViewController` renders current-network access points and inline
  recovery actions.
- `SettingsWindowController` and `AboutWindowController` own their respective
  windows.
- `ApplicationMenuController` temporarily installs the conventional Dock and
  application-menu presentation while the Wi-Fi Scanner session is open.

Closing the Scanner returns the process to menu-bar-only presentation. This is
presentation state rather than process termination; an established BSSID Lock
can continue its configured checks while all windows are closed.

## Wi-Fi service boundary

`CoreWLANService` serializes all public CoreWLAN work on one private queue.
Scans, association requests, credential callbacks, and verification therefore
do not race one another inside the app. Transient CoreWLAN objects remain on
that queue; immutable app models cross back to the UI.

`WiFiModels.swift` defines validated raw-SSID and BSSID identities plus the
immutable scan and interface snapshots. `CoreWLANAdapter.swift` converts
CoreWLAN objects into those models and classifies authentication fail-closed.

The two association implementations have separate boundaries:

- `CredentialProvider` is used by the public CoreWLAN path when an SSID-scoped
  saved credential is required.
- `StrictBSSIDService` is the narrow Swift interface to `PrivateWiFiShim.m`.
  The shim loads private CoreWiFi dynamically, validates every required runtime
  selector and type encoding, and fails closed. The app does not link CoreWiFi
  directly and never silently falls back from Strict to Standard mode.

The exact request construction, credential boundaries, verification behavior,
historical evidence, and support limitations are intentionally documented only
in [BSSID Association on macOS](BSSID-ASSOCIATION.md).

## Permissions and protected data

BSSID Picker runs inside App Sandbox. It uses only four sandbox capabilities:

- App Sandbox containment;
- Location-protected SSID/BSSID access;
- outgoing client networking for user-initiated downloads of the two complete
  MAC registrant source files; and
- read/write access to the single JSON or CSV destination selected through an
  `NSSavePanel`.

It has no incoming-network, arbitrary-home-directory, Downloads-folder,
Apple Events, app-group, or Keychain-sharing entitlement. Public CoreWLAN work
uses interfaces vended by `CWWiFiClient`, which is Apple's
[documented sandbox-compatible boundary][apple-corewlan-sandbox].
Container-owned preferences and Application Support files need no additional
file entitlement.

`LocationAuthorizationController` is the gate for protected SSID/BSSID access.
When Location permission is lost, the application invalidates in-flight work
and clears protected scan and association presentation state.

Credential material is never part of scanner rows, diagnostics, or exports.
The public connection path releases its app-held password reference after the
attempt. The Strict saved-PSK path delegates credential resolution to macOS and
does not expose the password to the Swift application.

`ConnectionHistory` stores a bounded, secret-free session history.
`AppDiagnostics` defines the typed sanitized snapshots used by the Scanner and
exports.

## MAC registrant database

MAC registrant enrichment is separate from CoreWLAN acquisition. The database
service downloads complete, fixed upstream data files, validates and compiles a
candidate snapshot away from the UI, and publishes an immutable resolver only
after the complete snapshot has been installed atomically. A failed update
therefore leaves the last known-good snapshot available. Removing the snapshot
does not alter scan observations or preferences.

Lookups are local and side-effect free: no BSSID or derived MAC prefix is sent
to an upstream service, placed in a download URL, or written to update logs.
Rows retain structured registration provenance so the table, inspector, search,
and exporters share one resolution. Replacing or removing the snapshot
re-enriches in-session rows without initiating a CoreWLAN scan.

The installed data lives under the app container at
`~/Library/Containers/local.bssid-picker.app/Data/Library/Application Support/BSSID Picker/Vendor Databases/`.
`database.plist` is one atomically replaced payload containing both raw source
files and their metadata. `last-update-attempt.plist` persists the weekly
download throttle while a usable snapshot is installed; removal deletes both
files. A failed first download, or a corrupt/incompatible payload that cannot
be used, does not leave the user behind that throttle and may be retried
immediately. With a usable snapshot installed, successful and failed update
attempts both start the seven-day interval, and a failed update retains the
installed snapshot. The directory is resolved from Foundation's
**Application Support** location through `FileManager`, not constructed from
the user's home directory.

The app does not request access to or import data from an earlier unsandboxed
copy. Any registrant database left in the former Application Support location
is ignored and can be downloaded again from Settings. `SMAppService`
login-item registration, Location consent, and Keychain access decisions remain
macOS-owned state rather than files managed by the app container.

Input files are untrusted. The service applies transfer and entry limits,
strict prefix validation, production record-count bounds, deterministic
duplicate handling, and source provenance before installation. Both sources
must download and validate before `database.plist` is replaced. The resolution
policy prefers the longest matching address block. Identical normalized records
are deduplicated; different organization records for the same prefix remain an
ambiguous result rather than being selected by input order. It does not
reinterpret a registry organization as proof of the access point's
manufacturer, brand, owner, or operator. Source and license details are
maintained in
[MAC Registrant Data Sources and Licenses](MAC-REGISTRANT-DATA.md).

## BSSID Lock state

`SettingsStore` owns the atomic, versioned lock record plus the persisted
association mode and menu/lock interval settings. The record identifies a
target by raw SSID bytes and canonical BSSID; display text is not used as
identity.

`LockRetryPolicy` and `LockRuntimeState` contain retry scheduling, phases,
circuit breaking, and generation checks that prevent stale asynchronous
completions from mutating newer state. `ApplicationController` classifies
operation failures and orchestrates provisional activation: persistence happens
only after exact-target verification succeeds.

`LaunchAtLoginService` is a small ServiceManagement boundary. The
`SMAppService` status is authoritative; the app does not maintain a duplicate
Boolean preference.

## Wi-Fi Scanner pipeline

The Scanner pipeline keeps acquisition, decoding, presentation, and export
separate:

1. `CoreWLANService` produces immutable access-point and interface snapshots.
2. The MAC registrant resolver enriches validated BSSIDs from one immutable
   local database snapshot.
3. `WiFiInformationElementDecoder` parses the raw IEEE 802.11
   information-element byte stream without discarding unknown or malformed
   elements.
4. `ScanStandardsPresentation` projects decoded standards and capability state.
5. `ScanRow` combines one access point with registration, scan-observation, and
   application context.
6. `ScanColumnID`, `ScanPreset`, and `ScanFilter` define columns, prepared
   search, filters, and presets.
7. `ScanSemanticSorter` sorts typed values, while `ScanPreferenceStore` owns
   persisted Scanner preferences.
8. `ScanWindowController` coordinates scans, the session-only retention cache,
   table selection, filters, and window lifecycle.
9. `ScanInspectorDocumentBuilder` creates the single selectable attributed-text
   document rendered by `ScanInspectorView`.
10. `ScanExporter` and `ScanExportPresenter` create and save the JSON and CSV
   representations from the same typed snapshots.

The Scanner cache contains observations only for the current app session.
`ScanPreferenceStore` persists Scanner preferences, while AppKit autosave stores
window and split geometry. Captured access-point rows are not persisted.

## Regression tests

`BuildTools/run-tests.sh` compiles and runs the deterministic regression tests
under `Tests/` with the same native target and macOS 13 deployment target as the
application. The tests exercise MAC-prefix parsing and longest-prefix
resolution, address classification, duplicate and ambiguous records,
known-address matching, and the versioned JSON and CSV MAC-registration export
contracts.

The test executable uses only in-memory fixtures. It does not launch the app,
scan or modify Wi-Fi, access Keychain or Location data, contact database
servers, or read and write application preferences. CI runs it before building
the signed application bundle.

## Source map

The main source groups are:

- `ApplicationController.swift`, `AppDelegate.swift`, and `main.swift` — app
  orchestration and lifecycle.
- `MenuBarController.swift`, `MenuPopoverViewController.swift`,
  `SettingsWindowController.swift`, `AboutWindowController.swift`, and
  `ApplicationMenuController.swift` — AppKit presentation.
- `CoreWLANService.swift`, `CoreWLANAdapter.swift`, `CredentialProvider.swift`,
  and `WiFiModels.swift` — supported Wi-Fi operations and immutable models.
- `StrictBSSIDService.swift` and `PrivateWiFiShim.m` — isolated experimental
  private association path.
- `SettingsStore.swift`, `LockPolicy.swift`, and
  `AutomaticUpdateInterval.swift` — persistence and policy.
- `MACRegistrantDatabase.swift` — complete-source downloading, validation,
  atomic Application Support storage, local prefix resolution, and provenance.
- `BSSIDPicker.entitlements` — sandbox capabilities.
- `WiFiInformationElements.swift` and `Scan*.swift` — Scanner decoding, model,
  table, inspector, search, and export.
- `AppDiagnostics.swift` and `ConnectionHistory.swift` — typed sanitized
  diagnostics.
- `Tests/` — deterministic parser, resolver, and export-contract regression
  coverage.
- `BuildTools/` — regression-test execution, local signing, compilation, bundle
  assembly, and verification.

## Design constraints

Changes should preserve these boundaries:

- keep CoreWLAN operations serialized and CoreWLAN objects queue-confined;
- use raw SSID bytes plus canonical BSSID for target identity;
- classify unsupported or ambiguous authentication fail-closed;
- keep passwords and private profile objects out of diagnostics and exports;
- keep the private CoreWiFi surface isolated, runtime-validated, and optional;
- verify observed association results instead of treating an API return value
  as an exact-BSSID postcondition; and
- avoid background polling when a one-shot timer or explicit lifecycle event is
  sufficient.

[apple-corewlan-sandbox]: https://developer.apple.com/documentation/corewlan
