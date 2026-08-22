// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import Foundation

private enum ConnectionPurpose {
  case direct
  case lock(LockGeneration)

  var isLock: Bool {
    if case .lock = self { return true }
    return false
  }

  var lockGeneration: LockGeneration? {
    guard case .lock(let generation) = self else { return nil }
    return generation
  }
}

private enum ConnectionStrategy {
  case publicCoreWLAN(CredentialPolicy)
  case strict

  var usesStrictBSSID: Bool {
    if case .strict = self { return true }
    return false
  }
}

private enum LockUpdatePolicy {
  case unchanged
  case moveOnSuccess
}

private struct ConnectionRequest {
  let id: UUID
  let target: NetworkTarget
  let purpose: ConnectionPurpose
  let strategy: ConnectionStrategy
  let userInitiated: Bool
  let lockUpdatePolicy: LockUpdatePolicy
  let privacyGeneration: UInt64

  func allowingSystemKeychain() -> ConnectionRequest {
    ConnectionRequest(
      id: id,
      target: target,
      purpose: purpose,
      strategy: .publicCoreWLAN(.includeSystemKeychain),
      userInitiated: userInitiated,
      lockUpdatePolicy: lockUpdatePolicy,
      privacyGeneration: privacyGeneration
    )
  }
}

/// The latest association fact returned by CoreWLAN. This is intentionally
/// independent of the scan cache: a lock check can observe an association
/// without producing a fresh access-point scan.
private struct AssociationObservation {
  let capturedAt: Date
  let displaySSID: String
  let ssid: RawSSID
  let bssid: BSSID?
}

private enum AppActivity {
  case idle
  case scanning(UUID)
  case checkingLock(UUID, LockGeneration)
  case checkingStrictAvailability(UUID)
  case connecting(ConnectionRequest)
  case awaitingSystemConsent(ConnectionRequest)
  case presentingModal(UUID)

  var isIdle: Bool {
    if case .idle = self { return true }
    return false
  }

  var isLockOperation: Bool {
    switch self {
    case .checkingLock:
      return true
    case .connecting(let request), .awaitingSystemConsent(let request):
      return request.purpose.isLock
    case .idle, .scanning, .checkingStrictAvailability, .presentingModal:
      return false
    }
  }

  /// The scanner is read-only navigation. It may open while the menu's
  /// current-network scan is using the serialized CoreWLAN service, but not
  /// while an association, consent flow, or modal operation is in progress.
  var allowsScannerNavigation: Bool {
    switch self {
    case .idle, .scanning:
      return true
    case .checkingLock, .checkingStrictAvailability, .connecting, .awaitingSystemConsent,
      .presentingModal:
      return false
    }
  }

  var refreshState: MenuRefreshState {
    switch self {
    case .scanning:
      return .refreshing
    case .connecting, .awaitingSystemConsent:
      return .connecting
    default:
      return .ready
    }
  }
}

/// Owns application state and orchestrates UI-independent services. UI
/// controllers render immutable view state and report user intent through
/// closures; they do not read CoreWLAN, Keychain, or UserDefaults directly.
final class ApplicationController {
  private let wifi: CoreWLANService
  private let settings: SettingsStore
  private let location: LocationAuthorizationController
  private let connectionHistory: ConnectionHistory
  private let launchAtLoginService: LaunchAtLoginServicing
  private let macRegistrantDatabase: MACRegistrantDatabase
  private let appMetadata: AppMetadata
  private lazy var applicationMenu = ApplicationMenuController(
    metadata: appMetadata,
    onShowAbout: { [weak self] in self?.showAbout() },
    onShowSettings: { [weak self] in self?.showSettings() }
  )
  private lazy var menuBar = MenuBarController(initialState: makeMenuState())

  private var scanWindow: ScanWindowController?
  private var settingsWindow: SettingsWindowController?
  private var aboutWindow: AboutWindowController?
  private var menuScanTimer: Timer?
  private var lockMonitorTimer: Timer?
  private var lockRetryTimer: Timer?
  private var lockCountdownTimer: Timer?
  private var scheduledLockRetryAt: Date?
  private var pendingLockRetry = false

  private var activity: AppActivity = .idle
  private var currentScan: CurrentScanSnapshot?
  private var latestAssociation: AssociationObservation?
  private var selectedTarget: NetworkTarget?
  private var lastScanError: String?
  private var lockSettingsStatusMessage: String?
  private var strictStatusMessage: String?
  private var launchAtLoginErrorMessage: String?
  private var macRegistrantDatabaseOperationError: String?
  private var strictBackendDiagnostics = StrictBackendDiagnostics.notChecked
  private var lockSettingsNeedRepair = false
  private var pendingMenuScan = false
  private var privacyGeneration: UInt64 = 0

  private var lockConfiguration: LockConfiguration?
  private var lockRuntime = LockRuntimeState()
  private var lockActivation = LockActivationTracker()
  private var lockActivationFailureMessage: String?
  private var lockWaitingMessage: String?
  private var lockPausedForLocation = false
  private var sessionSystemKeychainConsentSSID: RawSSID?

  init(
    wifi: CoreWLANService = CoreWLANService(),
    settings: SettingsStore = SettingsStore(),
    location: LocationAuthorizationController = LocationAuthorizationController(),
    connectionHistory: ConnectionHistory = ConnectionHistory(),
    launchAtLoginService: LaunchAtLoginServicing = LaunchAtLoginService(),
    macRegistrantDatabase: MACRegistrantDatabase = MACRegistrantDatabase(),
    appMetadata: AppMetadata = AppMetadata()
  ) {
    self.wifi = wifi
    self.settings = settings
    self.location = location
    self.connectionHistory = connectionHistory
    self.launchAtLoginService = launchAtLoginService
    self.macRegistrantDatabase = macRegistrantDatabase
    self.appMetadata = appMetadata
  }

  func start() {
    loadSettings()
    macRegistrantDatabase.onStateChange = { [weak self] state in
      self?.macRegistrantDatabaseStateChanged(state)
    }
    location.onStateChange = { [weak self] state in
      self?.locationStateChanged(state)
    }

    wireMenuActions()
    if lockConfiguration != nil, !location.isAllowed {
      let message =
        location.state == .notDetermined
        ? "Open Settings to grant Location access"
        : "Location access required"
      pauseLockForLocation(message)
    }
    render()

    restartLockMonitorTimer()

    if lockConfiguration != nil, location.isAllowed {
      attemptLock()
    }
  }

  func stop() {
    menuScanTimer?.invalidate()
    lockMonitorTimer?.invalidate()
    lockMonitorTimer = nil
    cancelScheduledLockRetry()
  }

  private func restartLockMonitorTimer() {
    lockMonitorTimer?.invalidate()
    lockMonitorTimer = nil
    guard lockConfiguration != nil,
      lockActivation.pendingGeneration == nil,
      location.isAllowed
    else { return }

    let seconds = settings.lockMonitorInterval
    guard seconds > 0 else { return }
    let interval = TimeInterval(seconds)
    let timer = Timer(timeInterval: interval, repeats: true) { [weak self] _ in
      self?.attemptLock()
    }
    timer.tolerance = min(interval * 0.1, 1)
    RunLoop.main.add(timer, forMode: .common)
    lockMonitorTimer = timer
  }

  private func loadSettings() {
    do {
      lockConfiguration = try settings.loadLock()
    } catch {
      lockConfiguration = nil
      lockSettingsStatusMessage = error.localizedDescription
      lockSettingsNeedRepair = true
    }
  }

  private func wireMenuActions() {
    menuBar.onMenuOpen = { [weak self] in self?.menuOpened() }
    menuBar.onMenuClose = { [weak self] in self?.menuClosed() }
    menuBar.onRefresh = { [weak self] in self?.requestMenuScan() }
    menuBar.onSelectNetwork = { [weak self] target in self?.selectNetwork(target) }
    menuBar.onToggleLock = { [weak self] in self?.toggleLock() }
    menuBar.onRetryLock = { [weak self] in self?.retryLockNow() }
    menuBar.onShowSettings = { [weak self] in self?.showSettings() }
    menuBar.onShowAllNetworks = { [weak self] in self?.showAllNetworks() }
    menuBar.onShowAbout = { [weak self] in self?.showAbout() }
  }

  // MARK: - Location and scans

  private func menuOpened() {
    if location.isAllowed {
      requestMenuScan()
    } else {
      render()
    }
  }

  private func menuClosed() {
    pendingMenuScan = false
    menuScanTimer?.invalidate()
    menuScanTimer = nil
    if lockActivationFailureMessage != nil {
      lockActivationFailureMessage = nil
      render()
    }
  }

  private func locationStateChanged(_ state: LocationAuthorizationState) {
    switch state {
    case .allowed:
      if lockPausedForLocation {
        lockPausedForLocation = false
        lockRuntime.prepareManualRetry()
        lockWaitingMessage = nil
      }
      if menuBar.isTracking { requestMenuScan() }
      if lockConfiguration != nil { attemptLock() }
    case .denied:
      clearProtectedWiFiState()
      pauseLockForLocation("Location access required")
    case .unavailable:
      clearProtectedWiFiState()
      pauseLockForLocation("Location authorization is unavailable")
    case .notDetermined:
      clearProtectedWiFiState()
      pauseLockForLocation("Open Settings to grant Location access")
    }
    restartLockMonitorTimer()
    render()
  }

  private func clearProtectedWiFiState() {
    privacyGeneration &+= 1
    switch activity {
    case .connecting(let request), .awaitingSystemConsent(let request):
      connectionHistory.recordCancellation(
        id: request.id,
        message: "Location authorization changed before the operation completed."
      )
    default:
      break
    }
    activity = .idle
    currentScan = nil
    latestAssociation = nil
    selectedTarget = nil
    lastScanError = nil
    pendingMenuScan = false
    menuScanTimer?.invalidate()
    menuScanTimer = nil
    scanWindow?.clearProtectedData()
  }

  private func pauseLockForLocation(_ message: String) {
    guard lockConfiguration != nil else { return }
    if let generation = lockActivation.pendingGeneration {
      failPendingLockActivation(generation, message: message)
      return
    }
    if !lockPausedForLocation {
      // Location changes can arrive while a check or physical association is
      // in flight. Invalidate that result before recording the new pause.
      lockRuntime.resetForConfigurationChange()
    }
    lockPausedForLocation = true
    lockRuntime.recordPermanentFailure(message)
  }

  private func requestMenuScan() {
    guard menuBar.isTracking else { return }
    guard location.isAllowed else {
      render()
      return
    }
    guard activity.isIdle else {
      pendingMenuScan = true
      return
    }

    menuScanTimer?.invalidate()
    menuScanTimer = nil
    let requestID = UUID()
    let requestPrivacyGeneration = privacyGeneration
    activity = .scanning(requestID)
    render()

    wifi.scanCurrent { [weak self] result in
      guard let self,
        case .scanning(let activeID) = self.activity,
        activeID == requestID,
        self.privacyGeneration == requestPrivacyGeneration
      else { return }
      self.activity = .idle
      guard self.location.isAllowed else {
        self.render()
        self.finishForegroundOperation()
        return
      }
      switch result {
      case .success(let snapshot):
        self.currentScan = snapshot
        self.recordAssociation(
          CurrentAssociation(
            displaySSID: snapshot.displaySSID,
            ssid: snapshot.ssid,
            bssid: snapshot.currentBSSID
          ),
          at: snapshot.capturedAt
        )
        if self.selectedTarget?.ssid != snapshot.ssid {
          self.selectedTarget = nil
        }
        self.lastScanError = nil
      case .failure(let error):
        if self.errorProvesAssociationUnavailable(error) {
          self.clearObservedWiFiState()
        }
        self.lastScanError = error.localizedDescription
      }
      self.render()
      self.finishForegroundOperation()
    }
  }

  private func scheduleMenuScan() {
    menuScanTimer?.invalidate()
    menuScanTimer = nil
    guard menuBar.isTracking else {
      return
    }
    guard activity.isIdle else { return }
    let seconds = settings.mainMenuRefreshInterval
    guard seconds > 0 else { return }
    let interval = TimeInterval(seconds)
    let timer = Timer(timeInterval: interval, repeats: false) { [weak self] _ in
      self?.requestMenuScan()
    }
    timer.tolerance = min(interval * 0.1, 1)
    RunLoop.main.add(timer, forMode: .common)
    menuScanTimer = timer
  }

  private func finishForegroundOperation() {
    if pendingLockRetry {
      pendingLockRetry = false
      if attemptLock() { return }
    }
    if pendingMenuScan, menuBar.isTracking {
      pendingMenuScan = false
      requestMenuScan()
    } else if menuBar.isTracking {
      scheduleMenuScan()
    } else {
      pendingMenuScan = false
    }
  }

  // MARK: - Direct connection

  private func selectNetwork(_ target: NetworkTarget) {
    guard activity.isIdle,
      location.isAllowed,
      latestAssociation == nil || latestAssociation?.ssid == target.ssid,
      currentScan?.accessPoints.contains(where: { $0.target == target && $0.canAssociate }) == true
    else {
      return
    }
    lockActivationFailureMessage = nil
    if let configuration = lockConfiguration, configuration.target != target {
      confirmConnectionWhileLocked(target, existing: configuration)
    } else {
      selectedTarget = target
      startConnection(
        target: target,
        purpose: .direct,
        userInitiated: true,
        lockUpdatePolicy: .unchanged
      )
    }
  }

  private func confirmConnectionWhileLocked(
    _ target: NetworkTarget,
    existing configuration: LockConfiguration
  ) {
    let dialogID = UUID()
    activity = .presentingModal(dialogID)
    render()
    NSApp.activate(ignoringOtherApps: true)

    let alert = NSAlert()
    alert.messageText = "Move the BSSID Lock?"
    let connectOnceExplanation =
      configuration.target.ssid == target.ssid
      ? "connect once and let BSSID Lock restore the existing BSSID."
      : "connect once and leave BSSID Lock waiting until its Wi-Fi network is joined again."
    alert.informativeText =
      "BSSID Lock currently targets \(configuration.target.bssid). You selected \(target.bssid). Move BSSID Lock after a successful connection, or \(connectOnceExplanation)"
    alert.addButton(withTitle: "Connect and Move BSSID Lock")
    alert.addButton(withTitle: "Connect Once")
    alert.addButton(withTitle: "Cancel")
    let response = alert.runModal()

    guard case .presentingModal(let activeID) = activity, activeID == dialogID else { return }
    activity = .idle
    guard response == .alertFirstButtonReturn || response == .alertSecondButtonReturn else {
      render()
      finishForegroundOperation()
      return
    }

    selectedTarget = target
    startConnection(
      target: target,
      purpose: .direct,
      userInitiated: true,
      lockUpdatePolicy: response == .alertFirstButtonReturn ? .moveOnSuccess : .unchanged
    )
  }

  private func startConnection(
    target: NetworkTarget,
    purpose: ConnectionPurpose,
    userInitiated: Bool,
    lockUpdatePolicy: LockUpdatePolicy = .unchanged
  ) {
    guard activity.isIdle else {
      if let generation = purpose.lockGeneration {
        failPendingLockActivation(
          generation,
          message: "Another Wi-Fi operation prevented the initial BSSID Lock connection."
        )
        render()
      }
      return
    }
    guard location.isAllowed else {
      if let generation = purpose.lockGeneration {
        failPendingLockActivation(generation, message: "Location access is required.")
      }
      render()
      finishForegroundOperation()
      return
    }
    let strategy: ConnectionStrategy
    if settings.strictBSSIDEnabled {
      strategy = .strict
    } else {
      let hasConsent = hasSystemKeychainConsent(for: target.ssid)
      strategy = .publicCoreWLAN(hasConsent ? .includeSystemKeychain : .userKeychainOnly)
    }
    performConnection(
      ConnectionRequest(
        id: UUID(),
        target: target,
        purpose: purpose,
        strategy: strategy,
        userInitiated: userInitiated,
        lockUpdatePolicy: lockUpdatePolicy,
        privacyGeneration: privacyGeneration
      ))
  }

  private func performConnection(_ request: ConnectionRequest) {
    connectionHistory.recordStart(
      id: request.id,
      target: request.target,
      trigger: request.purpose.isLock ? .lockRecovery : .userSelection,
      mode: request.strategy.usesStrictBSSID ? .strict : .standard,
      credentialRequirement: credentialRequirement(for: request.target),
      credentialConsentScope: credentialConsentScope(for: request)
    )
    activity = .connecting(request)
    render()

    let completion: CoreWLANService.Completion<ConnectionOutcome> = { [weak self] result in
      self?.connectionFinished(request, result: result)
    }
    let credentialObserver: CoreWLANService.CredentialObserver = {
      [weak self] requirement, record in
      guard let self,
        self.location.isAllowed,
        request.privacyGeneration == self.privacyGeneration,
        self.connectionRequestIsCurrent(request)
      else {
        return
      }
      self.connectionHistory.recordCredentialRequirement(
        id: request.id,
        requirement: requirement
      )
      self.connectionHistory.recordCredential(id: request.id, record: record)
      if request.strategy.usesStrictBSSID
        || requirement == .notRequired
        || requirement == .enterpriseUnsupported
        || requirement == .unknownUnsupported
      {
        self.connectionHistory.recordCredentialConsent(id: request.id, scope: .notApplicable)
      }
      self.render()
    }
    switch request.strategy {
    case .publicCoreWLAN(let policy):
      wifi.connectPublic(
        to: request.target,
        credentialPolicy: policy,
        credentialObserver: credentialObserver,
        completion: completion
      )
    case .strict:
      wifi.connectStrict(
        to: request.target,
        credentialObserver: credentialObserver,
        completion: completion
      )
    }
  }

  private func connectionFinished(
    _ request: ConnectionRequest,
    result: Result<ConnectionOutcome, Error>
  ) {
    guard case .connecting(let activeRequest) = activity,
      activeRequest.id == request.id
    else {
      return
    }
    guard location.isAllowed else {
      connectionHistory.recordCancellation(
        id: request.id,
        message: "Location access changed before the association result was received."
      )
      activity = .idle
      if let generation = request.purpose.lockGeneration {
        failPendingLockActivation(
          generation,
          message: "Location access changed before BSSID Lock activation completed."
        )
      }
      render()
      finishForegroundOperation()
      return
    }
    guard connectionRequestIsCurrent(request) else {
      connectionHistory.recordCancellation(
        id: request.id,
        message:
          "The BSSID Lock target, association mode, or Location authorization changed before completion."
      )
      activity = .idle
      if let generation = request.purpose.lockGeneration {
        failPendingLockActivation(
          generation,
          message: "The BSSID Lock target or authorization changed before activation completed."
        )
      }
      render()
      finishForegroundOperation()
      return
    }

    if request.strategy.usesStrictBSSID {
      switch result {
      case .success:
        strictBackendDiagnostics = StrictBackendDiagnostics(state: .available, message: nil)
      case .failure(let error):
        if case WiFiOperationError.strictBackendUnavailable = error {
          strictBackendDiagnostics = StrictBackendDiagnostics(
            state: .unavailable,
            message: ConnectionHistory.sanitizedMessage(for: error)
          )
        } else {
          strictBackendDiagnostics = StrictBackendDiagnostics(state: .available, message: nil)
        }
      }
    }

    switch result {
    case .success(let outcome):
      activity = .idle
      connectionSucceeded(request, outcome: outcome)
      render()
      finishForegroundOperation()
    case .failure(let error):
      if case WiFiOperationError.systemKeychainConsentRequired(let interrupted) = error,
        case .publicCoreWLAN = request.strategy
      {
        handleSystemKeychainConsentNeeded(request, interrupted: interrupted)
        return
      }
      activity = .idle
      connectionFailed(request, error: error)
      render()
      finishForegroundOperation()
    }
  }

  private func connectionRequestIsCurrent(_ request: ConnectionRequest) -> Bool {
    guard location.isAllowed, request.privacyGeneration == privacyGeneration else { return false }
    guard case .lock(let generation) = request.purpose else { return true }
    return lockConfiguration?.target == request.target && lockRuntime.accepts(generation)
  }

  private func connectionSucceeded(_ request: ConnectionRequest, outcome: ConnectionOutcome) {
    connectionHistory.recordSuccess(
      id: request.id,
      observedBSSID: outcome.currentBSSID,
      verificationSamples: outcome.verificationSamples
    )
    let displaySSID = displaySSID(for: request.target)
    recordAssociation(
      CurrentAssociation(
        displaySSID: displaySSID,
        ssid: request.target.ssid,
        bssid: outcome.currentBSSID
      ))
    switch request.purpose {
    case .lock(let generation):
      lockWaitingMessage = nil
      let activationWasPending = lockActivation.isPending(generation)
      recordLockSuccess(generation)
      if activationWasPending,
        !lockActivation.isPending(generation),
        lockConfiguration?.systemKeychainConsentGranted == true
      {
        connectionHistory.recordCredentialConsent(id: request.id, scope: .persistedLock)
      }
    case .direct:
      guard request.lockUpdatePolicy == .moveOnSuccess,
        let existingLock = lockConfiguration
      else { return }
      let displaySSID =
        currentScan?.accessPoints.first(where: { $0.target == request.target })?.displaySSID
        ?? currentScan?.displaySSID
        ?? existingLock.displaySSID
      let consent: Bool
      switch request.strategy {
      case .strict:
        consent =
          existingLock.target.ssid == request.target.ssid
          && existingLock.systemKeychainConsentGranted
      case .publicCoreWLAN(let policy):
        consent = policy == .includeSystemKeychain
      }
      let replacement = LockConfiguration(
        target: request.target,
        displaySSID: displaySSID,
        systemKeychainConsentGranted: consent
      )
      if persistLock(replacement) {
        lockRuntime.resetForConfigurationChange()
        lockRuntime.recordSuccess()
        lockWaitingMessage = nil
      }
    }
  }

  private func connectionFailed(_ request: ConnectionRequest, error: Error) {
    connectionHistory.recordFailure(id: request.id, error: error)
    switch error as? WiFiOperationError {
    case .wrongBSSID(_, let observedBSSID):
      if let observedBSSID {
        recordAssociation(
          CurrentAssociation(
            displaySSID: displaySSID(for: request.target),
            ssid: request.target.ssid,
            bssid: observedBSSID
          ),
          clearResolvedError: false
        )
      } else {
        clearObservedWiFiState()
      }
    case .strictVerificationFailed(_, let samples):
      if let observedBSSID = samples.last?.bssid {
        recordAssociation(
          CurrentAssociation(
            displaySSID: displaySSID(for: request.target),
            ssid: request.target.ssid,
            bssid: observedBSSID
          ),
          clearResolvedError: false
        )
      } else {
        clearObservedWiFiState()
      }
    default:
      break
    }
    if request.purpose.isLock {
      recordLockFailure(
        error,
        permanent: isPermanentLockError(error),
        strictBSSID: request.strategy.usesStrictBSSID,
        generation: request.purpose.lockGeneration
      )
    }
  }

  private func displaySSID(for target: NetworkTarget) -> String {
    currentScan?.accessPoints.first(where: { $0.target == target })?.displaySSID
      ?? (currentScan?.ssid == target.ssid ? currentScan?.displaySSID : nil)
      ?? (lockConfiguration?.target.ssid == target.ssid ? lockConfiguration?.displaySSID : nil)
      ?? "<non-text SSID>"
  }

  private func recordAssociation(
    _ association: CurrentAssociation,
    at capturedAt: Date = Date(),
    clearResolvedError: Bool = true
  ) {
    latestAssociation = AssociationObservation(
      capturedAt: capturedAt,
      displaySSID: association.displaySSID,
      ssid: association.ssid,
      bssid: association.bssid
    )
    if clearResolvedError {
      connectionHistory.clearActiveErrorIfResolved(by: association)
    }
    guard let scan = currentScan, scan.ssid == association.ssid else { return }
    currentScan = CurrentScanSnapshot(
      capturedAt: scan.capturedAt,
      displaySSID: scan.displaySSID,
      ssid: scan.ssid,
      currentBSSID: association.bssid,
      accessPoints: scan.accessPoints
    )
  }

  // MARK: - Explicit System Keychain consent

  private func handleSystemKeychainConsentNeeded(
    _ request: ConnectionRequest,
    interrupted: Bool
  ) {
    guard request.userInitiated else {
      activity = .idle
      let error = WiFiOperationError.systemKeychainConsentRequired(
        userLookupInterrupted: interrupted)
      connectionHistory.recordFailure(id: request.id, error: error)
      recordLockFailure(
        error,
        permanent: true,
        strictBSSID: false,
        generation: request.purpose.lockGeneration
      )
      render()
      finishForegroundOperation()
      return
    }

    activity = .awaitingSystemConsent(request)
    render()
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.messageText = "Read Saved Wi-Fi Password?"
    let userDomainResult =
      interrupted
      ? "CoreWLAN's login or iCloud credential service remained unavailable after retrying."
      : "The credential was not found in your login or iCloud Keychain."
    alert.informativeText =
      "\(userDomainResult) BSSID Picker can ask macOS for this SSID's credential from the System Keychain. macOS may display its own authorization prompt."
    alert.addButton(withTitle: "Continue")
    alert.addButton(withTitle: "Cancel")
    let response = alert.runModal()

    guard case .awaitingSystemConsent(let activeRequest) = activity,
      activeRequest.id == request.id
    else {
      return
    }
    guard connectionRequestIsCurrent(request) else {
      connectionHistory.recordCancellation(
        id: request.id,
        message:
          "The BSSID Lock target, association mode, or Location authorization changed before consent was completed."
      )
      activity = .idle
      if let generation = request.purpose.lockGeneration {
        failPendingLockActivation(
          generation,
          message: "The BSSID Lock target or authorization changed before activation completed."
        )
      }
      render()
      finishForegroundOperation()
      return
    }

    guard location.isAllowed else {
      connectionHistory.recordCancellation(
        id: request.id,
        message: "Location access changed before credential consent was completed."
      )
      activity = .idle
      if let generation = request.purpose.lockGeneration {
        failPendingLockActivation(
          generation,
          message: "Location access changed before BSSID Lock activation completed."
        )
      }
      render()
      finishForegroundOperation()
      return
    }

    if response == .alertFirstButtonReturn {
      guard recordSystemKeychainConsent(for: request) else {
        connectionHistory.recordCancellation(
          id: request.id,
          message:
            "Consent could not be recorded because the BSSID Lock target changed or the BSSID Lock settings could not be saved."
        )
        activity = .idle
        if let generation = request.purpose.lockGeneration {
          failPendingLockActivation(
            generation,
            message: "System Keychain consent could not be recorded."
          )
        }
        render()
        finishForegroundOperation()
        return
      }
      let scope = credentialConsentScope(for: request.allowingSystemKeychain())
      connectionHistory.recordCredentialConsent(id: request.id, scope: scope)
      connectionHistory.recordCredential(
        id: request.id,
        record: CredentialAccessRecord(
          stage: .systemKeychainConsent,
          result: .consentGranted,
          secretHandling: .notExposedToApp
        )
      )
      performConnection(request.allowingSystemKeychain())
    } else {
      activity = .idle
      connectionHistory.recordCredential(
        id: request.id,
        record: CredentialAccessRecord(
          stage: .systemKeychainConsent,
          result: .consentDeclined,
          secretHandling: .notExposedToApp
        )
      )
      connectionHistory.recordCancellation(
        id: request.id,
        message: "Credential access was cancelled."
      )
      if request.purpose.isLock {
        recordLockFailure(
          WiFiOperationError.systemKeychainConsentRequired(userLookupInterrupted: interrupted),
          permanent: true,
          strictBSSID: false,
          generation: request.purpose.lockGeneration
        )
      }
      render()
      finishForegroundOperation()
    }
  }

  private func hasSystemKeychainConsent(for ssid: RawSSID) -> Bool {
    sessionSystemKeychainConsentSSID == ssid
      || (lockConfiguration?.target.ssid == ssid
        && lockConfiguration?.systemKeychainConsentGranted == true)
  }

  private var systemKeychainConsentDiagnostics: SystemKeychainConsentDiagnostics {
    SystemKeychainConsentDiagnostics(
      sessionSSID: sessionSystemKeychainConsentSSID,
      persistedLockSSID: lockConfiguration.flatMap { configuration in
        configuration.systemKeychainConsentGranted
          && lockActivation.pendingGeneration == nil
          ? configuration.target.ssid : nil
      }
    )
  }

  private func credentialConsentScope(for request: ConnectionRequest) -> CredentialConsentScope {
    guard !request.strategy.usesStrictBSSID else { return .notApplicable }
    if let generation = request.purpose.lockGeneration,
      lockActivation.isPending(generation),
      lockConfiguration?.target.ssid == request.target.ssid,
      lockConfiguration?.systemKeychainConsentGranted == true
    {
      return .provisionalLock
    }
    return systemKeychainConsentDiagnostics.scope(for: request.target.ssid)
  }

  private func credentialRequirement(for target: NetworkTarget) -> CredentialRequirement {
    guard
      let authentication = currentScan?.accessPoints.first(where: { $0.target == target })?
        .authentication
    else {
      return .unknown
    }
    return authentication.credentialRequirement
  }

  private func recordSystemKeychainConsent(for request: ConnectionRequest) -> Bool {
    switch request.purpose {
    case .direct:
      sessionSystemKeychainConsentSSID = request.target.ssid
      return true
    case .lock(let generation):
      guard let configuration = lockConfiguration,
        configuration.target == request.target
      else {
        return false
      }
      let updated = configuration.withSystemKeychainConsent(true)
      if lockActivation.isPending(generation) {
        // Consent belongs to the provisional transaction and must not create
        // a persisted lock before exact-BSSID activation succeeds.
        lockConfiguration = updated
        return true
      }
      return persistLock(updated)
    }
  }

  // MARK: - Lock enforcement

  private func synchronizeScheduledLockRetry(at now: Date) {
    guard lockConfiguration != nil,
      lockWaitingMessage == nil,
      !activity.isLockOperation,
      case .retryScheduled(let deadline, _, _) = lockRuntime.phase
    else {
      cancelScheduledLockRetry()
      return
    }

    if scheduledLockRetryAt == deadline,
      lockCountdownTimer?.isValid == true,
      pendingLockRetry || lockRetryTimer?.isValid == true || now >= deadline
    {
      return
    }

    cancelScheduledLockRetry()
    scheduledLockRetryAt = deadline

    let retryTimer = Timer(
      timeInterval: max(0.001, deadline.timeIntervalSince(now)),
      repeats: false
    ) { [weak self] _ in
      self?.scheduledLockRetryReached(deadline)
    }
    RunLoop.main.add(retryTimer, forMode: .common)
    lockRetryTimer = retryTimer

    let countdownTimer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
      self?.lockCountdownTimerFired(deadline)
    }
    countdownTimer.tolerance = 0.1
    RunLoop.main.add(countdownTimer, forMode: .common)
    lockCountdownTimer = countdownTimer
  }

  private func scheduledLockRetryReached(_ expectedDeadline: Date) {
    guard
      case .retryScheduled(let deadline, _, _) = lockRuntime.phase,
      deadline == expectedDeadline,
      scheduledLockRetryAt == expectedDeadline
    else {
      return
    }

    let now = Date()
    guard now >= deadline else {
      lockRetryTimer = nil
      synchronizeScheduledLockRetry(at: now)
      return
    }

    lockRetryTimer?.invalidate()
    lockRetryTimer = nil
    if activity.isLockOperation {
      pendingLockRetry = false
    } else if activity.isIdle {
      pendingLockRetry = false
      if attemptLock() { return }
    } else {
      pendingLockRetry = true
    }
    renderLockPresentation(at: now)
  }

  private func lockCountdownTimerFired(_ expectedDeadline: Date) {
    guard
      case .retryScheduled(let deadline, _, _) = lockRuntime.phase,
      deadline == expectedDeadline,
      scheduledLockRetryAt == expectedDeadline
    else {
      return
    }

    let now = Date()
    if now >= deadline {
      scheduledLockRetryReached(expectedDeadline)
    } else {
      renderLockPresentation(at: now)
    }
  }

  private func cancelScheduledLockRetry() {
    lockRetryTimer?.invalidate()
    lockRetryTimer = nil
    lockCountdownTimer?.invalidate()
    lockCountdownTimer = nil
    scheduledLockRetryAt = nil
    pendingLockRetry = false
  }

  private func toggleLock() {
    guard activity.isIdle else { return }
    if lockConfiguration != nil {
      settings.clearLock()
      lockConfiguration = nil
      lockActivation.cancel()
      lockActivationFailureMessage = nil
      if connectionHistory.lastErrorTrigger == .lockRecovery {
        connectionHistory.clearActiveError()
      }
      lockSettingsStatusMessage = nil
      lockSettingsNeedRepair = false
      lockRuntime.resetForConfigurationChange()
      lockWaitingMessage = nil
      lockPausedForLocation = false
      restartLockMonitorTimer()
      render()
      return
    }

    guard let target = candidateLockTarget(), target.ssid == currentScan?.ssid else { return }
    let displaySSID =
      currentScan?.accessPoints.first(where: { $0.target == target })?.displaySSID
      ?? currentScan?.displaySSID
    let configuration = LockConfiguration(target: target, displaySSID: displaySSID)
    if lockSettingsNeedRepair {
      settings.clearLock()
      lockSettingsStatusMessage = nil
      lockSettingsNeedRepair = false
    }
    lockConfiguration = configuration
    lockActivationFailureMessage = nil
    connectionHistory.clearActiveError()
    let generation = lockRuntime.resetForConfigurationChange()
    lockActivation.begin(generation)
    lockWaitingMessage = nil
    lockPausedForLocation = false
    restartLockMonitorTimer()
    if location.isAllowed {
      guard attemptLock(userInitiated: true) else {
        failPendingLockActivation(
          generation,
          message: "The initial BSSID check could not be started."
        )
        render()
        return
      }
    } else {
      failPendingLockActivation(generation, message: "Location access is required.")
      render()
    }
  }

  private func retryLockNow() {
    guard lockConfiguration != nil, activity.isIdle else { return }
    lockRuntime.prepareManualRetry()
    lockWaitingMessage = nil
    guard location.isAllowed else {
      pauseLockForLocation("Location access required")
      render()
      return
    }
    lockPausedForLocation = false
    attemptLock(userInitiated: true)
  }

  @discardableResult
  private func attemptLock(userInitiated: Bool = false) -> Bool {
    guard let configuration = lockConfiguration,
      location.isAllowed,
      activity.isIdle,
      userInitiated || lockRuntime.canAttempt(at: Date())
    else {
      return false
    }
    if connectionHistory.lastErrorTrigger == .lockRecovery {
      connectionHistory.clearActiveError()
    }
    let requestID = UUID()
    let generation = lockRuntime.token
    activity = .checkingLock(requestID, generation)
    render()

    wifi.currentAssociation { [weak self] result in
      guard let self,
        case .checkingLock(let activeID, let activeGeneration) = self.activity,
        activeID == requestID,
        activeGeneration == generation
      else {
        return
      }
      self.activity = .idle
      guard self.lockRuntime.accepts(generation),
        self.lockConfiguration?.target == configuration.target
      else {
        self.render()
        self.finishForegroundOperation()
        return
      }
      switch result {
      case .success(let association):
        self.recordAssociation(association)
        guard association.ssid == configuration.target.ssid else {
          if self.failPendingLockActivation(
            generation,
            message: "The Wi-Fi network changed before the selected BSSID could be verified."
          ) {
            self.currentScan = nil
            self.selectedTarget = nil
            self.render()
            self.finishForegroundOperation()
            return
          }
          self.lockWaitingMessage =
            "BSSID Lock waiting for \(configuration.displaySSID ?? "selected SSID")"
          self.render()
          self.finishForegroundOperation()
          return
        }
        self.lockWaitingMessage = nil
        if association.bssid == configuration.target.bssid {
          self.recordLockSuccess(generation)
          self.render()
          self.finishForegroundOperation()
        } else {
          self.startConnection(
            target: configuration.target,
            purpose: .lock(generation),
            userInitiated: userInitiated
          )
        }
      case .failure(let error):
        if self.errorProvesAssociationUnavailable(error) {
          self.clearObservedWiFiState()
        }
        self.recordLockFailure(
          error,
          permanent: false,
          strictBSSID: settings.strictBSSIDEnabled,
          generation: generation
        )
        self.render()
        self.finishForegroundOperation()
      }
    }
    return true
  }

  private func recordLockFailure(
    _ error: Error,
    permanent: Bool,
    strictBSSID: Bool,
    generation: LockGeneration? = nil
  ) {
    lockWaitingMessage = nil
    let message = ConnectionHistory.sanitizedMessage(for: error)
    if let generation, failPendingLockActivation(generation, message: message) {
      return
    }
    if permanent {
      lockRuntime.recordPermanentFailure(message)
    } else {
      lockRuntime.recordTransientFailure(
        message,
        strictBSSID: strictBSSID,
        at: Date()
      )
    }
  }

  /// Commits a user-requested lock only after CoreWLAN has proved that its
  /// exact BSSID is active. Locks loaded from preferences have no pending
  /// activation and retain the established retry behavior.
  private func recordLockSuccess(_ generation: LockGeneration) {
    guard lockRuntime.accepts(generation) else { return }
    guard lockActivation.isPending(generation) else {
      lockRuntime.recordSuccess()
      return
    }
    guard let configuration = lockConfiguration else {
      failPendingLockActivation(
        generation,
        message: "The provisional BSSID Lock configuration was no longer available."
      )
      return
    }
    guard persistLock(configuration) else {
      let message = lockSettingsStatusMessage ?? "The BSSID Lock settings could not be saved."
      failPendingLockActivation(generation, message: message)
      return
    }
    guard lockActivation.establish(generation) else { return }
    lockActivationFailureMessage = nil
    lockRuntime.recordSuccess()
    restartLockMonitorTimer()
  }

  /// Rejects only the matching provisional enable operation. A later failure
  /// of an established or restored lock must preserve its saved target so it
  /// can retry or be recovered explicitly.
  @discardableResult
  private func failPendingLockActivation(
    _ generation: LockGeneration,
    message: String
  ) -> Bool {
    guard lockActivation.fail(generation) else { return false }
    let targetBSSID = lockConfiguration?.target.bssid.description
    settings.clearLock()
    lockConfiguration = nil
    lockSettingsStatusMessage = nil
    lockSettingsNeedRepair = false
    lockRuntime.resetForConfigurationChange()
    lockWaitingMessage = nil
    lockPausedForLocation = false
    lockActivationFailureMessage = targetBSSID.map { "Target BSSID \($0): \(message)" } ?? message
    cancelScheduledLockRetry()
    restartLockMonitorTimer()
    return true
  }

  private func errorProvesAssociationUnavailable(_ error: Error) -> Bool {
    guard let operationError = error as? WiFiOperationError else { return false }
    switch operationError {
    case .noInterface, .notConnected, .invalidSSIDData:
      return true
    default:
      return false
    }
  }

  private func clearObservedWiFiState() {
    currentScan = nil
    latestAssociation = nil
    selectedTarget = nil
  }

  private func isPermanentLockError(_ error: Error) -> Bool {
    guard let operationError = error as? WiFiOperationError else {
      return (error as NSError).domain == NSOSStatusErrorDomain
    }
    switch operationError {
    case .invalidSSIDData, .systemKeychainConsentRequired, .credentialReadFailed,
      .emptyCredential, .enterpriseUnsupported, .unknownSecurity, .wrongBSSID,
      .strictWEPUnsupported, .currentSSIDChanged, .strictBackendUnavailable,
      .strictCredentialDelegationUnavailable:
      return true
    case .noInterface, .notConnected, .targetNotFound,
      .strictAssociationFailed, .strictVerificationFailed:
      return false
    }
  }

  private func candidateLockTarget() -> NetworkTarget? {
    if let lockConfiguration { return lockConfiguration.target }
    if let selectedTarget,
      currentScan?.ssid == selectedTarget.ssid,
      latestAssociation == nil || latestAssociation?.ssid == selectedTarget.ssid
    {
      return selectedTarget
    }
    guard let scan = currentScan, let bssid = associatedBSSID(for: scan.ssid) else { return nil }
    return NetworkTarget(ssid: scan.ssid, bssid: bssid)
  }

  private func associatedBSSID(for ssid: RawSSID) -> BSSID? {
    if let association = latestAssociation, association.ssid == ssid {
      return association.bssid
    }
    guard currentScan?.ssid == ssid else { return nil }
    return currentScan?.currentBSSID
  }

  @discardableResult
  private func persistLock(_ configuration: LockConfiguration) -> Bool {
    do {
      try settings.saveLock(configuration)
      lockConfiguration = configuration
      lockSettingsStatusMessage = nil
      lockSettingsNeedRepair = false
      return true
    } catch {
      lockSettingsStatusMessage = error.localizedDescription
      return false
    }
  }

  // MARK: - Strict mode

  private func toggleStrictBSSID() {
    guard activity.isIdle else { return }
    if settings.strictBSSIDEnabled {
      settings.strictBSSIDEnabled = false
      lockRuntime.resetForConfigurationChange()
      lockWaitingMessage = nil
      render()
      if lockConfiguration != nil, location.isAllowed { attemptLock(userInitiated: true) }
      return
    }

    let requestID = UUID()
    activity = .checkingStrictAvailability(requestID)
    strictBackendDiagnostics = StrictBackendDiagnostics(state: .checking, message: nil)
    render()
    wifi.checkStrictAvailability { [weak self] result in
      guard let self,
        case .checkingStrictAvailability(let activeID) = self.activity,
        activeID == requestID
      else {
        return
      }
      switch result {
      case .failure(let error):
        self.activity = .idle
        self.strictStatusMessage = error.localizedDescription
        self.strictBackendDiagnostics = StrictBackendDiagnostics(
          state: .unavailable,
          message: ConnectionHistory.sanitizedMessage(for: error)
        )
        self.render()
        self.finishForegroundOperation()
      case .success:
        self.strictBackendDiagnostics = StrictBackendDiagnostics(state: .available, message: nil)
        self.presentStrictWarning(requestID: requestID)
      }
    }
  }

  private func presentStrictWarning(requestID: UUID) {
    guard case .checkingStrictAvailability(let activeID) = activity,
      activeID == requestID
    else { return }
    activity = .presentingModal(requestID)
    render()
    NSApp.activate(ignoringOtherApps: true)
    let alert = NSAlert()
    alert.messageText = "Enable Experimental Strict BSSID?"
    alert.informativeText =
      "This mode uses an undocumented private macOS Wi-Fi API. It may stop working after an OS update. For the currently connected saved Personal PSK network, airportd resolves the credential; BSSID Picker does not read the Wi-Fi password. A strict attempt never falls back silently to ordinary same-SSID association."
    alert.addButton(withTitle: "Enable")
    alert.addButton(withTitle: "Cancel")
    let response = alert.runModal()
    guard case .presentingModal(let activeID) = activity,
      activeID == requestID
    else { return }
    activity = .idle
    if response == .alertFirstButtonReturn {
      settings.strictBSSIDEnabled = true
      strictStatusMessage = nil
      lockRuntime.resetForConfigurationChange()
      lockWaitingMessage = nil
    }
    render()
    if response == .alertFirstButtonReturn,
      lockConfiguration != nil,
      location.isAllowed
    {
      attemptLock(userInitiated: true)
    } else {
      finishForegroundOperation()
    }
  }

  // MARK: - Auxiliary UI

  private func showAllNetworks() {
    guard location.isAllowed else {
      showSettings()
      return
    }
    guard activity.allowsScannerNavigation else {
      render()
      return
    }
    if scanWindow == nil {
      let controller = ScanWindowController(
        service: wifi,
        macRegistrantResolver: macRegistrantDatabase.snapshot
      )
      controller.onScannerOpenStateChanged = { [weak self] isOpen in
        self?.applicationMenu.setScannerOpen(isOpen)
      }
      scanWindow = controller
    }
    scanWindow?.setScanningAllowed(true)
    scanWindow?.updateContext(scannerContextSnapshot)
    scanWindow?.showAndScan()
  }

  private func openLocationSettings() {
    guard
      let url = URL(
        string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices"
      )
    else { return }
    NSWorkspace.shared.open(url)
  }

  private func requestLocationAccess() {
    location.requestFromUserAction()
    render()
  }

  private func showSettings() {
    if settingsWindow == nil {
      let controller = SettingsWindowController(initialState: settingsViewState)
      controller.onSetLaunchAtLoginEnabled = { [weak self] enabled in
        self?.setLaunchAtLoginEnabled(enabled)
      }
      controller.onOpenLoginItemsSettings = { [weak self] in
        self?.openLoginItemsSettings()
      }
      controller.onRefreshLaunchAtLogin = { [weak self] in
        self?.refreshLaunchAtLoginStatus()
      }
      controller.onSetStrictEnabled = { [weak self] enabled in
        self?.setStrictBSSIDEnabled(enabled)
      }
      controller.onSetMainMenuRefreshInterval = { [weak self] interval in
        self?.setMainMenuRefreshInterval(interval)
      }
      controller.onSetLockMonitorInterval = { [weak self] interval in
        self?.setLockMonitorInterval(interval)
      }
      controller.onUpdateMACRegistrantDatabase = { [weak self] in
        self?.updateMACRegistrantDatabase()
      }
      controller.onRemoveMACRegistrantDatabase = { [weak self] in
        self?.removeMACRegistrantDatabase()
      }
      controller.onRequestLocation = { [weak self] in self?.requestLocationAccess() }
      controller.onOpenLocationSettings = { [weak self] in self?.openLocationSettings() }
      controller.onRepairLockSettings = { [weak self] in self?.repairInvalidLockSettings() }
      controller.onResetToDefaults = { [weak self] in self?.confirmResetToDefaults() }
      settingsWindow = controller
    }
    settingsWindow?.render(settingsViewState)
    settingsWindow?.show()
  }

  private func updateMACRegistrantDatabase() {
    guard !macRegistrantDatabase.state.isBusy else { return }
    macRegistrantDatabaseOperationError = nil
    macRegistrantDatabase.update { _ in }
    settingsWindow?.render(settingsViewState)
  }

  private func removeMACRegistrantDatabase() {
    guard !macRegistrantDatabase.state.isBusy else { return }
    do {
      try macRegistrantDatabase.removeDownloadedData()
      macRegistrantDatabaseOperationError = nil
    } catch {
      macRegistrantDatabaseOperationError = error.localizedDescription
      settingsWindow?.render(settingsViewState)
    }
  }

  private func macRegistrantDatabaseStateChanged(_ state: MACRegistrantDatabaseState) {
    if case .updateFailed = state {
      // The database state already carries the update error.
    } else {
      macRegistrantDatabaseOperationError = nil
    }
    scanWindow?.updateMACRegistrantResolver(macRegistrantDatabase.snapshot)
    settingsWindow?.render(settingsViewState)
  }

  private func setLaunchAtLoginEnabled(_ enabled: Bool) {
    launchAtLoginErrorMessage = nil
    let initialStatus = launchAtLoginService.status

    if enabled {
      switch initialStatus {
      case .enabled:
        render()
        return
      case .requiresApproval:
        launchAtLoginService.openSystemSettings()
        render()
        return
      case .unknown:
        render()
        return
      case .notRegistered, .notFound:
        break
      }
    } else if !initialStatus.isRegistered {
      render()
      return
    }

    do {
      if enabled {
        try launchAtLoginService.register()
      } else {
        try launchAtLoginService.unregister()
      }
    } catch {
      let reconciledStatus = launchAtLoginService.status
      let requestedStateWasApplied =
        enabled ? reconciledStatus.isRegistered : !reconciledStatus.isRegistered
      if !requestedStateWasApplied {
        launchAtLoginErrorMessage =
          "Launch at Login could not be changed. \(error.localizedDescription)"
      }
    }

    let finalStatus = launchAtLoginService.status
    let requestedStateWasApplied = enabled ? finalStatus.isRegistered : !finalStatus.isRegistered
    if !requestedStateWasApplied, launchAtLoginErrorMessage == nil {
      launchAtLoginErrorMessage = "macOS did not apply the Launch at Login change."
    }
    render()
  }

  private func openLoginItemsSettings() {
    launchAtLoginErrorMessage = nil
    launchAtLoginService.openSystemSettings()
    settingsWindow?.render(settingsViewState)
  }

  private func refreshLaunchAtLoginStatus() {
    launchAtLoginErrorMessage = nil
    settingsWindow?.render(settingsViewState)
  }

  private func setStrictBSSIDEnabled(_ enabled: Bool) {
    guard activity.isIdle, enabled != settings.strictBSSIDEnabled else { return }
    strictStatusMessage = nil
    toggleStrictBSSID()
  }

  private func setMainMenuRefreshInterval(_ interval: Int) {
    guard interval >= 0, interval != settings.mainMenuRefreshInterval else {
      return
    }
    settings.mainMenuRefreshInterval = interval
    if menuBar.isTracking {
      scheduleMenuScan()
    }
    render()
  }

  private func setLockMonitorInterval(_ interval: Int) {
    guard interval >= 0, interval != settings.lockMonitorInterval else {
      return
    }
    settings.lockMonitorInterval = interval
    restartLockMonitorTimer()
    render()
  }

  private func repairInvalidLockSettings() {
    guard activity.isIdle, lockSettingsNeedRepair else { return }
    settings.clearLock()
    lockConfiguration = nil
    lockActivation.cancel()
    lockActivationFailureMessage = nil
    lockRuntime.resetForConfigurationChange()
    lockWaitingMessage = nil
    restartLockMonitorTimer()
    lockSettingsStatusMessage = nil
    lockSettingsNeedRepair = false
    render()
  }

  private func confirmResetToDefaults() {
    guard activity.isIdle, let settingsWindow = settingsWindow?.window else { return }
    let requestID = UUID()
    activity = .presentingModal(requestID)
    render()

    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = "Restore Default Settings?"
    alert.informativeText =
      "This turns off Launch at Login, disables and removes the saved BSSID lock, including its BSSID Picker consent to try System Keychain fallback, restores Experimental Strict BSSID to enabled, restores menu scanning to 10 seconds and BSSID Lock checks to 300 seconds, and resets Wi-Fi Scanner columns, sorting, automatic scanning, cache retention, inspector layout, and window placement. Location permission, the downloaded MAC registrant database, saved Wi-Fi networks and passwords, macOS Keychain items and access decisions, and exported files are not changed."
    let resetButton = alert.addButton(withTitle: "Reset")
    resetButton.hasDestructiveAction = true
    resetButton.keyEquivalent = ""
    let cancelButton = alert.addButton(withTitle: "Cancel")
    cancelButton.keyEquivalent = "\r"
    cancelButton.keyEquivalentModifierMask = []

    alert.beginSheetModal(for: settingsWindow) { [weak self] response in
      guard let self,
        case .presentingModal(let activeID) = self.activity,
        activeID == requestID
      else { return }
      if response == .alertFirstButtonReturn {
        self.resetToDefaults()
      } else {
        self.activity = .idle
        self.render()
        self.finishForegroundOperation()
      }
    }
  }

  private func resetToDefaults() {
    let launchAtLoginResetError = resetLaunchAtLogin()
    settings.resetToDefaults()
    lockConfiguration = nil
    lockActivation.cancel()
    lockRuntime.resetForConfigurationChange()
    lockActivationFailureMessage = nil
    lockWaitingMessage = nil
    lockPausedForLocation = false
    lockSettingsStatusMessage = nil
    strictStatusMessage = nil
    launchAtLoginErrorMessage = launchAtLoginResetError
    strictBackendDiagnostics = .notChecked
    lockSettingsNeedRepair = false
    sessionSystemKeychainConsentSSID = nil
    selectedTarget = nil
    cancelScheduledLockRetry()
    if connectionHistory.lastErrorTrigger == .lockRecovery {
      connectionHistory.clearActiveError()
    }

    lockMonitorTimer?.invalidate()
    lockMonitorTimer = nil
    menuScanTimer?.invalidate()
    menuScanTimer = nil
    pendingMenuScan = false
    if let scanWindow {
      scanWindow.resetToDefaults()
    } else {
      ScanWindowController.resetPersistedDefaults()
    }

    activity = .idle
    restartLockMonitorTimer()
    if menuBar.isTracking {
      scheduleMenuScan()
    }
    render()
  }

  private func resetLaunchAtLogin() -> String? {
    guard launchAtLoginService.status.isRegistered else { return nil }
    do {
      try launchAtLoginService.unregister()
    } catch {
      guard launchAtLoginService.status.isRegistered else { return nil }
      return "Launch at Login could not be reset. \(error.localizedDescription)"
    }
    return launchAtLoginService.status.isRegistered
      ? "macOS did not turn off Launch at Login."
      : nil
  }

  private func showAbout() {
    if aboutWindow == nil { aboutWindow = AboutWindowController(metadata: appMetadata) }
    aboutWindow?.show()
  }

  // MARK: - View state

  private func render() {
    let now = Date()
    synchronizeScheduledLockRetry(at: now)
    menuBar.render(makeMenuState(at: now))
    scanWindow?.setScanningAllowed(location.isAllowed)
    if location.isAllowed {
      scanWindow?.updateContext(scannerContextSnapshot)
    }
    settingsWindow?.render(settingsViewState)
  }

  private func renderLockPresentation(at now: Date) {
    menuBar.render(makeMenuState(at: now), synchronizeSize: false)
  }

  private var settingsViewState: SettingsViewState {
    SettingsViewState(
      locationState: location.state,
      launchAtLoginStatus: launchAtLoginService.status,
      launchAtLoginErrorMessage: launchAtLoginErrorMessage,
      macRegistrantDatabase: macRegistrantDatabaseViewState,
      strictBSSIDEnabled: settings.strictBSSIDEnabled,
      mainMenuRefreshInterval: settings.mainMenuRefreshInterval,
      lockMonitorInterval: settings.lockMonitorInterval,
      isCheckingStrictAvailability: {
        if case .checkingStrictAvailability = activity { return true }
        return false
      }(),
      controlsEnabled: activity.isIdle,
      statusMessage: lockSettingsNeedRepair
        ? lockSettingsStatusMessage
        : (strictStatusMessage ?? lockSettingsStatusMessage),
      repairLockSettingsAvailable: lockSettingsNeedRepair,
      resetToDefaultsEnabled: true
    )
  }

  private var macRegistrantDatabaseViewState: MACRegistrantDatabaseViewState {
    let databaseState = macRegistrantDatabase.state
    let status: MACRegistrantDatabaseViewStatus
    let stateError: String?
    switch databaseState {
    case .notDownloaded:
      status = .notDownloaded
      stateError = nil
    case .ready:
      status = .ready
      stateError = nil
    case .downloading:
      status = .downloading
      stateError = nil
    case .validating:
      status = .validating
      stateError = nil
    case .installing:
      status = .installing
      stateError = nil
    case .updateFailed(let message, _):
      status = .failed
      stateError = message
    }
    return MACRegistrantDatabaseViewState(
      status: status,
      metadata: databaseState.databaseMetadata,
      hasInstalledDatabase: macRegistrantDatabase.hasInstalledDatabase,
      canUpdate: macRegistrantDatabase.canUpdate,
      errorMessage: macRegistrantDatabaseOperationError ?? stateError
    )
  }

  // MARK: - Sanitized diagnostics

  private var associationMode: AssociationMode {
    settings.strictBSSIDEnabled ? .strict : .standard
  }

  private var scannerContextSnapshot: ScannerContextSnapshot {
    ScannerContextSnapshot(
      client: ClientWiFiState(
        capturedAt: latestAssociation?.capturedAt,
        displaySSID: latestAssociation?.displaySSID,
        rawSSID: latestAssociation?.ssid,
        currentBSSID: latestAssociation?.bssid,
        associationMode: associationMode,
        operation: diagnosticOperation,
        lock: lockDiagnostics,
        lastConnectionError: connectionHistory.lastError,
        systemKeychainConsent: systemKeychainConsentDiagnostics
      ),
      connectionEvents: connectionHistory.events,
      environment: appEnvironmentDiagnostics,
      interface: nil
    )
  }

  private var appEnvironmentDiagnostics: AppEnvironmentDiagnostics {
    return AppEnvironmentDiagnostics(
      macOSVersion: ProcessInfo.processInfo.operatingSystemVersionString,
      appVersion: appMetadata.version ?? "Unavailable",
      appBuild: appMetadata.build ?? "Unavailable",
      bundleIdentifier: appMetadata.bundleIdentifier ?? "Unavailable",
      locationAuthorization: locationDiagnosticState,
      strictBackend: strictBackendDiagnostics
    )
  }

  private var locationDiagnosticState: LocationDiagnosticState {
    switch location.state {
    case .notDetermined: return .notDetermined
    case .allowed: return .allowed
    case .denied: return .denied
    case .unavailable: return .unavailable
    }
  }

  private var diagnosticOperation: AppOperation {
    switch activity {
    case .idle: return .idle
    case .scanning: return .scanningCurrentNetwork
    case .checkingLock: return .checkingLock
    case .checkingStrictAvailability: return .checkingStrictAvailability
    case .connecting: return .connecting
    case .awaitingSystemConsent: return .awaitingConsent
    case .presentingModal: return .presentingDialog
    }
  }

  private var lockDiagnostics: LockDiagnostics {
    guard let configuration = lockConfiguration else { return .disabled }
    let state: LockDiagnosticState
    var nextRetryAt: Date?
    var retryDelay: TimeInterval?
    var lastError: String?

    if lockWaitingMessage != nil {
      state = .waitingForSSID
    } else if case .checkingLock = activity {
      state = .checking
    } else if case .connecting(let request) = activity, request.purpose.isLock {
      state = .restoring
    } else if case .awaitingSystemConsent(let request) = activity, request.purpose.isLock {
      state = .restoring
    } else {
      switch lockRuntime.phase {
      case .ready:
        state = .active
      case .retryScheduled(let date, let delay, let message):
        state = .retryScheduled
        nextRetryAt = date
        retryDelay = delay
        lastError = message
      case .paused(.permanent(let message)):
        state = .paused
        lastError = message
      case .paused(.strictCircuitBreaker(_, let message)):
        state = .paused
        lastError = message
      }
    }

    return LockDiagnostics(
      state: state,
      target: configuration.target,
      displaySSID: configuration.displaySSID,
      failureCount: lockRuntime.consecutiveFailureCount,
      nextRetryAt: nextRetryAt,
      retryDelay: retryDelay,
      lastError: lastError ?? lockWaitingMessage
    )
  }

  private func makeMenuState(at now: Date = Date()) -> MenuBarViewState {
    let controlsEnabled = activity.isIdle
    let heading: String
    if let displaySSID = latestAssociation?.displaySSID {
      heading = displaySSID
    } else if !location.isAllowed {
      heading = "BSSID Picker"
    } else if activity.refreshState == .refreshing {
      heading = "Scanning Wi-Fi…"
    } else {
      heading = "Open to scan Wi-Fi"
    }
    let networks = uniqueAccessPoints().compactMap { accessPoint -> MenuNetworkItem? in
      guard let target = accessPoint.target else { return nil }
      let channel = accessPoint.channel
      let channelColumn = rightAlignedMenuColumn(channel, width: 3)
      let signalColumn = rightAlignedMenuColumn(String(accessPoint.rssi), width: 4)
      let channelDescription = accessPoint.channelNumber.map(String.init) ?? "unavailable"
      return MenuNetworkItem(
        target: target,
        title:
          "\(target.bssid.description)   CH \(channelColumn)   \(signalColumn) dBm",
        accessibilityDescription:
          "BSSID \(target.bssid.description), channel \(channelDescription), signal \(accessPoint.rssi) decibel-milliwatts",
        isCurrent: accessPoint.bssid == associatedBSSID(for: target.ssid),
        isEnabled: location.isAllowed && accessPoint.canAssociate,
        toolTip: accessPoint.associationLimitation
      )
    }
    let lockTarget = candidateLockTarget()?.bssid.description
    return MenuBarViewState(
      heading: heading,
      headingToolTip: lastScanError,
      currentBSSIDDescription: latestAssociation?.bssid?.description,
      refreshState: activity.refreshState,
      refreshEnabled: location.isAllowed && controlsEnabled,
      networks: networks,
      controlsEnabled: controlsEnabled,
      lockTargetDescription: lockTarget,
      lockEnabled: lockConfiguration != nil,
      lockStatus: lockStatusText(at: now),
      showsLockStatus: showsLockStatusInMenu,
      showAllEnabled: location.isAllowed && activity.allowsScannerNavigation,
      notice: menuNotice(at: now)
    )
  }

  private func rightAlignedMenuColumn(_ value: String, width: Int) -> String {
    guard value.count < width else { return value }
    return String(repeating: " ", count: width - value.count) + value
  }

  private func menuNotice(at now: Date) -> MenuNotice? {
    switch location.state {
    case .notDetermined:
      return MenuNotice(
        style: .information,
        title: "Location access is required",
        message:
          "macOS protects SSIDs and BSSIDs as location data. Configure access to scan nearby access points.",
        actionTitle: "Settings",
        action: .showSettings
      )
    case .denied:
      return MenuNotice(
        style: .warning,
        title: "Location access is denied",
        message: "Allow BSSID Picker in Privacy & Security to scan Wi-Fi identifiers.",
        actionTitle: "Settings",
        action: .showSettings
      )
    case .unavailable:
      return MenuNotice(
        style: .error,
        title: "Location access is unavailable",
        message: "Location Services is restricted or unavailable on this Mac.",
        actionTitle: "Settings",
        action: .showSettings
      )
    case .allowed:
      break
    }

    if let lockActivationFailureMessage {
      return MenuNotice(
        style: .error,
        title: "BSSID lock was not enabled",
        message: lockActivationFailureMessage
      )
    }

    if let notice = lockAttentionNotice(at: now) {
      return notice
    }

    if let lastConnectionError = connectionHistory.lastError {
      return connectionFailureNotice(lastConnectionError)
    }
    if let settingsStatusMessage = lockSettingsStatusMessage ?? strictStatusMessage {
      return MenuNotice(
        style: .error,
        title: "Settings need attention",
        message: settingsStatusMessage,
        actionTitle: "Settings",
        action: .showSettings
      )
    }
    if let lastScanError {
      return MenuNotice(
        style: .error,
        title: "Wi-Fi scan failed",
        message: lastScanError,
        actionTitle: "Retry",
        action: .refresh
      )
    }
    return nil
  }

  private func connectionFailureNotice(_ message: String) -> MenuNotice {
    MenuNotice(
      style: .error,
      title: "Connection failed",
      message: message,
      actionTitle: "Wi-Fi Scanner",
      action: .showInspector
    )
  }

  private func lockAttentionNotice(at now: Date) -> MenuNotice? {
    guard let configuration = lockConfiguration else { return nil }
    guard !activity.isLockOperation else { return nil }
    let targetBSSID = configuration.target.bssid.description
    if lockWaitingMessage != nil {
      let network = configuration.displaySSID ?? "the saved Wi-Fi network"
      return MenuNotice(
        style: .warning,
        title: "BSSID lock is waiting",
        message: "Join \(network) to resume monitoring target BSSID \(targetBSSID)."
      )
    }
    let message = "Target BSSID \(targetBSSID). \(lockStatusText(at: now))"
    switch lockRuntime.phase {
    case .ready:
      return nil
    case .retryScheduled:
      return MenuNotice(
        style: .warning,
        title: "BSSID lock will retry",
        message: message,
        actionTitle: "Retry Now",
        action: .retryLock
      )
    case .paused:
      return MenuNotice(
        style: .error,
        title: "BSSID lock is paused",
        message: message,
        actionTitle: "Retry Now",
        action: .retryLock
      )
    }
  }

  private func uniqueAccessPoints() -> [AccessPoint] {
    guard location.isAllowed,
      latestAssociation == nil || currentScan?.ssid == latestAssociation?.ssid
    else {
      return []
    }
    var seen: Set<NetworkTarget> = []
    return currentScan?.accessPoints.filter { accessPoint in
      guard let target = accessPoint.target else { return false }
      return seen.insert(target).inserted
    } ?? []
  }

  private func lockStatusText(at now: Date) -> String {
    guard lockConfiguration != nil else {
      if let lockActivationFailureMessage {
        return "BSSID Lock was not enabled. \(lockActivationFailureMessage)"
      }
      return "BSSID Lock disabled"
    }
    if let lockWaitingMessage { return lockWaitingMessage }
    let targetBSSID = lockConfiguration?.target.bssid.description ?? "saved BSSID"
    if case .checkingLock = activity { return "Checking target \(targetBSSID)…" }
    if case .connecting(let request) = activity, request.purpose.isLock {
      return "Restoring target \(targetBSSID)…"
    }
    if case .awaitingSystemConsent(let request) = activity, request.purpose.isLock {
      return "Waiting for credential permission for target \(targetBSSID)…"
    }
    switch lockRuntime.phase {
    case .ready:
      return "BSSID Lock active"
    case .retryScheduled(_, _, let message):
      let seconds = lockRuntime.retrySecondsRemaining(at: now) ?? 0
      if seconds > 0 {
        return "BSSID Lock retry in \(seconds)s: \(message)"
      }
      return activity.isIdle
        ? "BSSID Lock retry due now: \(message)"
        : "BSSID Lock retry pending: \(message)"
    case .paused(.permanent(let message)):
      return "BSSID Lock paused: \(message)"
    case .paused(.strictCircuitBreaker(let count, let message)):
      return "BSSID Lock paused after \(count) failed Strict BSSID attempts: \(message)"
    }
  }

  private var showsLockStatusInMenu: Bool {
    guard lockConfiguration != nil else { return false }
    if case .checkingLock = activity { return true }
    if case .connecting(let request) = activity, request.purpose.isLock { return true }
    if case .awaitingSystemConsent(let request) = activity, request.purpose.isLock { return true }
    return false
  }
}
