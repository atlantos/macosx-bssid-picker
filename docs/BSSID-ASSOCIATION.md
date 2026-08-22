# BSSID Association on macOS: CoreWLAN and CoreWiFi

Last verified: August 20, 2026

This note records why selecting an exact BSSID through public CoreWLAN can
disconnect and reconnect a Mac without leaving it on the requested access
point, how BSSID Picker handles that limitation, what its experimental private
CoreWiFi path changes, and what the historical evidence does and does not
establish.

`CoreWLAN` is Apple's public framework. `CoreWiFi` is an undocumented private
framework used internally by macOS. They are different interfaces with very
different support and compatibility guarantees.

## Conclusions

- BSSID Picker passes the exact freshly scanned `CWNetwork` selected by raw
  SSID bytes and canonical BSSID to public CoreWLAN. No app-side target mix-up
  or concurrent CoreWLAN operation was found.
- Public `CWInterface.associate(to:password:)` does not document an exact-BSSID
  postcondition, a roaming lock, or a way to disable macOS candidate selection.
  Supplying a `CWNetwork` whose `bssid` is the desired AP is therefore a request,
  not a supported hard pin.
- Reverse-engineering of a current macOS CoreWLAN implementation shows that the
  public wrapper calls an internal association method with `forceBSSID` set to
  `false`. The downstream implementation then sends an XPC request that has no
  force-BSSID parameter. This is implementation evidence, not a stable API
  contract for every macOS release.
- Keychain access only supplies an SSID-scoped credential. It does not select a
  BSSID. If BSSID Picker reports `wrongBSSID`, any required credential lookup
  and the public association call completed, but the target was not observed
  within the verification window. The actual BSSID can be absent or different;
  a different value means macOS selected or roamed to another access point.
- The behavior is not limited to one recent macOS release. Matching
  public-CoreWLAN reports exist from at least OS X Yosemite/El Capitan through
  High Sierra and Mojave. The evidence does **not** prove that every older
  release and hardware combination always ignored the selected BSSID; some
  reports describe initial success followed by immediate roaming, and some
  users reported success.
- Experimental Strict BSSID uses a separate private CoreWiFi request with an
  exact private scan result, `forceBSSID = true`, and a request to disable
  automatic candidate search. It verifies the resulting association and never
  silently falls back to public CoreWLAN. This is still unsupported, can break
  after any macOS update, and cannot be presented as a permanent
  platform-supported roaming lock.

## Public and experimental paths at a glance

| Property | Standard mode | Experimental Strict BSSID |
| --- | --- | --- |
| Framework | Public CoreWLAN | Private CoreWiFi, loaded at runtime |
| Apple-supported API | Yes | No |
| Target | Fresh `CWNetwork` matched by raw SSID and BSSID | Exact private scan result derived from that `CWNetwork` |
| BSSID-force control | None in the public API | Private `forceBSSID = true` parameter |
| Candidate search | Controlled by macOS | Requests private `findAndJoinNetwork = false` |
| Credential | Passwordless, or app reads an SSID-scoped saved password and passes it to CoreWLAN | Passwordless, or `airportd` is asked to resolve a saved Personal PSK credential; no password enters the app |
| Supported authentication in this app | Open/OWE, Personal PSK, legacy WEP | Open/OWE and Personal PSK only |
| Verification | Exact observed BSSID, polled for up to about 2.5 seconds | Samples at about 0.5, 2, and 10 seconds; target required at 2 and 10 seconds |
| Result on wrong BSSID | Failure; an established lock pauses to avoid a reconnect loop | Failure; an established lock uses bounded retry and a circuit breaker |
| Durable exact-BSSID guarantee | No | No supported guarantee; private best-effort force plus verification |

## What public CoreWLAN promises

Apple documents [`CWInterface.associate(to:password:)`][apple-associate] as an
operation that associates to a supplied `CWNetwork`. A scanned `CWNetwork` has
a readable [`bssid`][apple-bssid], so selecting the object with the desired
BSSID is a reasonable request. The documented method nevertheless does not say
that:

- the resulting interface BSSID must equal `network.bssid`;
- other same-SSID candidates are excluded;
- auto-join or client roaming is disabled; or
- the association remains on that BSSID after the call returns.

Public `CWNetworkProfile` configuration is network/SSID-oriented and provides
no public BSSID pin. No public CoreWLAN header in the current SDK exposes a
force-BSSID association option or a control that disables roaming.

There is also an Apple documentation inconsistency that should not be mistaken
for an association guarantee. Apple's current web documentation for
[`CWNetwork.isEqual(to:)`][apple-network-equality] describes equality in terms
of SSID data, security type, and network type, while installed recent SDK
headers describe `CWNetwork` equality using SSID data and BSSID. Either rule is
object-comparison behavior, not a promised association postcondition.

Apple's [Wi-Fi roaming documentation][apple-roaming] states that the client
device decides when and where to roam. It evaluates same-ESS candidates using
RSSI, band and PHY capabilities, channel utilization, associated-client count,
and roaming-assistance information. A clean public association followed by a
different same-SSID BSSID is consistent with that client-side policy.

An Apple DTS engineer also noted in 2025 that macOS Wi-Fi infrastructure has
changed substantially and that CoreWLAN has not kept pace. That discussion was
about using saved credentials rather than exact BSSID selection, so it is
context for the framework's current limitations, not direct proof of this
specific behavior. See the [DTS CoreWLAN discussion][dts-corewlan].

## What BSSID Picker's standard path actually does

All CoreWLAN operations run on one serial queue. A `CWNetwork` never crosses
that queue; UI and history receive immutable app models. That rules out a menu
scan, Scanner scan, or lock check concurrently replacing the network object
during association.

The public connection sequence in
[`CoreWLANService.connectPublic`][source-public-connect] is:

1. Obtain the current Wi-Fi interface.
2. Require the interface's current raw SSID bytes to equal the selected target.
3. Perform a fresh directed scan for those exact SSID bytes.
4. Resolve the scanned `CWNetwork` whose raw SSID and canonical BSSID both equal
   the selected `NetworkTarget`.
5. Recheck the current raw SSID to reduce the scan/association race.
6. Classify the network's authentication family fail-closed.
7. For a passwordless network, pass `nil`; for Personal PSK or WEP, obtain the
   SSID-scoped saved password and pass it directly to CoreWLAN. Enterprise and
   ambiguous/unknown authentication are refused.
8. Call `CWInterface.associate(to:password:)` with that exact `CWNetwork`.
9. Independently read `interface.bssid()` and accept success only when it equals
   the requested BSSID.

Target resolution is byte-exact, not based on a display name. See
[`NetworkTarget`][source-network-target],
[`CWNetwork` conversion][source-corewlan-adapter], and
[`resolveNetwork`][source-resolve-network].

BSSID Picker does not call `disassociate()` anywhere. The visible disconnect
and reconnect occur inside Apple's public association operation. A successful
return means the association request completed; it does not establish the
exact-BSSID postcondition that the app checks afterward.

### Public verification boundary

The standard verifier reads the current BSSID immediately, then polls every
250 milliseconds for at most ten iterations. It succeeds on the first target
observation and otherwise throws `wrongBSSID` after roughly 2.5 seconds. See
[`verifyPublicAssociation`][source-public-verify].

This verifier detects the observed mismatch but does not retain a complete
sample timeline. It therefore cannot currently distinguish these two platform
behaviors:

1. macOS never joins the requested BSSID and selects another same-SSID AP from
   the outset; or
2. macOS joins the target briefly and immediately roams to another AP.

The historical evidence contains examples of both. The short verifier can also
accept a target that macOS leaves later. These are diagnostic and durability
limits, not evidence that the app passed the wrong target.

For an established BSSID Lock, public `wrongBSSID` is treated as a permanent
automatic-recovery failure. This avoids repeatedly disconnecting and
reconnecting the Mac when the public API cannot enforce the requested AP.

## Why Keychain access is unrelated to BSSID choice

The public CoreWLAN credential function
[`CWKeychainFindWiFiPassword`][apple-keychain] takes a Keychain domain and SSID
data. It has no BSSID argument. In BSSID Picker's standard path:

- Open and OWE networks require no Keychain access.
- Personal PSK and legacy WEP first check the user/Login-or-iCloud domain.
- The System Keychain is checked only after explicit, exact-SSID-scoped user
  consent.
- Only an interrupted user-domain CoreWLAN credential XPC connection is retried:
  at most three attempts, 200 milliseconds apart. Cancellation, denial,
  authentication failure, interaction-not-allowed, and other OSStatus results
  are surfaced rather than silently bypassed.
- The resulting password is passed to the already resolved exact `CWNetwork`.
  The app does not log or persist it and releases its reference after the
  attempt. Swift and `NSString` do not provide a deterministic memory-zeroing
  guarantee, so the accurate claim is ephemeral handling, not provable
  zeroization.

Consent for a direct connection is session- and exact-SSID-scoped. For a new
BSSID Lock, target-scoped System fallback consent is saved only after exact
BSSID activation succeeds; a failed provisional activation does not persist
that consent. Scanning, Scanner presentation/export, and healthy current-BSSID
checks never perform a Keychain lookup.

The credential lookup is SSID-scoped because Apple's API is SSID-scoped. It
cannot distinguish two unrelated networks that deliberately use identical raw
SSID bytes but different passwords. Ordinary multi-AP deployments normally use
the same credential throughout one ESS.

A missing, denied, or unreadable credential fails before BSSID verification.
Consequently, a reported `wrongBSSID` is not a Keychain-selection problem: the
password lookup completed when one was required, CoreWLAN accepted the
association request, and the target was not observed. The reported actual BSSID
may be another value or unavailable.

Saved CoreWLAN profile metadata also does not prove that a readable Keychain
credential exists. Scanner views intentionally report profiles and credential
events as separate facts.

## Current macOS implementation evidence

The system CoreWLAN image was inspected with Apple's `/usr/bin/dyld_info`.
Function starts identified these implementation methods:

```text
-[CWInterface associateToNetwork:password:error:]
-[CWInterface(Private) associateToNetwork:password:forceBSSID:remember:possiblyHidden:error:]
-[CWInterface(Private) associateToNetwork:password:forceBSSID:remember:error:]
```

The public wrapper supplies `false` for the force-BSSID Boolean before calling
the private selector. The Objective-C runtime encoding independently confirms
that selector's argument layout.

The five-argument private wrapper forwards to a longer private implementation.
In that implementation the incoming force argument is not read before the XPC
call. The XPC selector is:

```text
associateToWiFiNetwork:password:remember:possiblyHidden:
  interfaceName:token:priority:authorization:reply:
```

It has no force-BSSID argument. This explains how CoreWLAN can receive the exact
`CWNetwork`, perform a disruptive reassociation, and still leave final candidate
selection to the system.

The inspection can be repeated with:

```sh
/usr/bin/dyld_info -function_starts \
  /System/Library/Frameworks/CoreWLAN.framework/Versions/A/CoreWLAN

/usr/bin/dyld_info -disassemble \
  /System/Library/Frameworks/CoreWLAN.framework/Versions/A/CoreWLAN
```

These selector chains and private implementations are version-specific and can
change in any update. The supported conclusion is narrower: public CoreWLAN
exposes no hard-pin contract. The disassembly adds evidence that the inspected
implementation does not request a force-BSSID association through this public
method.

The private CoreWLAN selector visible in that public call chain is not BSSID
Picker's Strict implementation. Strict mode instead bridges to private
`CWFInterface` and supplies a `CWFAssocParameters` object, described below.

## Historical evidence

The historical record is mixed, but it clearly rules out a recent-only issue.

| Date / system | Evidence | What it establishes | Limitation |
| --- | --- | --- | --- |
| OS X 10.7 API, visible in the 10.9 SDK | The public method already had the same broad “associate to a network” wording. | The reviewed public contracts do not state an exact-BSSID or no-roam postcondition. | A header contract does not prove runtime behavior. |
| 2013 | [`airport-bssid` source][airport-bssid-source] scans networks, matches `network.bssid`, and passes that exact object to public `associateToNetwork`. | An early public-CoreWLAN implementation used the same basic strategy as BSSID Picker. | The tool prints the requested BSSID after success without rereading the interface, so its success message is not proof of the resulting BSSID. |
| 2014 | Google's [`macops` private selector declaration][macops-force-selector] includes a separate `forceBSSID` Boolean. | A distinct private force choice existed by the Yosemite era. | It is reverse-engineered/private API evidence, not a public guarantee. |
| 2015, Yosemite-era | A developer [reported][yosemite-report] selecting the exact `CWNetwork` by BSSID but observing another same-SSID BSSID after association. | The same failure pattern predates El Capitan and current macOS releases. | Community report; network steering and timing were not fully controlled. |
| 2016, El Capitan | [`airport-bssid` issue #3][el-capitan-report] reports successful network association without respecting the target BSSID. | Exact public-path failure on El Capitan. | Community report; forcing the radio channel changed the outcome. |
| 2016 | A separate [CoreWLAN reproduction][corewlan-2016] scans and selects a target, disassociates, and calls public association, but reports the target was not selected. | Independent reproduction with the public API. | The extra channel/disassociation operations differ from BSSID Picker. |
| 2017 | A follow-up [experiment][corewlan-2017] reports initial association to the chosen 2.4 GHz AP followed by an immediate move to the same-SSID 5 GHz AP. | Strong evidence for “target briefly honored, then client roamed” as one failure mode. | It does not prove every mismatch follows that sequence. |
| 2018, High Sierra; later Mojave comments | [`airport-bssid` issue #7][high-sierra-report] and [Ask Different reports][ask-different] describe the requested BSSID being ignored or the command merely triggering a move to the system's preferred same-SSID AP. | Continued failure reports across later releases. | [Contradictory reports][contradictory-reports] say the tool worked on El Capitan and High Sierra. |
| 2018 runtime headers | [macOS 10.13.5 runtime-derived headers][high-sierra-private-header] contain both the public method and a separate private force-BSSID selector. | The public/private control distinction predates current macOS. | Presence of a selector does not show how each implementation used it. |

Older `airport` private-command behavior is even less conclusive. An
[Ask Different timeline][ask-different] reports a BSSID option on much older OS
X versions and says it stopped working around 10.6, while later answers and
comments disagree about which replacements worked. This is useful historical
context, not a reliable release boundary.

Measurement also caused disagreement. One High Sierra report warns that the
Option-click Wi-Fi menu can show a cached BSSID after a switch and recommends a
fresh `airport -I` reading instead. BSSID Picker avoids that particular UI cache
by reading `CWInterface.bssid()` repeatedly, but old community observations may
not all have measured the same post-association state.

The defensible version conclusion is therefore:

- exact public-CoreWLAN failures are documented by at least the
  Yosemite/El Capitan era and continue through current macOS;
- a private force-BSSID distinction existed by that era;
- some combinations may have honored the target initially or appeared to work;
  and
- the available evidence cannot prove that public CoreWLAN literally always
  ignored BSSID on every OS X/macOS release.

Reports where `CWNetwork.bssid` is `nil` or redacted because Location permission
is missing are a separate issue. They concern access to protected Wi-Fi
identifiers, not whether an association request enforces a visible target.

## Experimental private CoreWiFi path

BSSID Picker's Strict BSSID implementation is intentionally separate from the
public path. The Swift boundary accepts no password and never falls back to
public association. See [`StrictBSSIDService`][source-strict-service] and the
runtime shim [`PrivateWiFiShim.m`][source-private-shim].

### Runtime and ABI validation

The app does not link CoreWiFi as a supported framework. It dynamically loads:

```text
/System/Library/PrivateFrameworks/CoreWiFi.framework/CoreWiFi
```

Before enabling strict association, the shim validates the required classes,
selectors, return types, argument counts and encodings, `NSCopying` conformance,
the CoreWLAN-to-CoreWiFi bridge, and the expected private interface service
type. An unavailable class, selector, changed ABI, unexpected service, Objective-C
exception, or invalid object causes a failure. It does not guess at a changed
private ABI.

“Available” means only that the expected runtime surface and bridge are present.
It does not perform a real association, retrieve a credential, test the driver,
or prove that CoreWiFi policy will authorize its private request. The
association path separately asks its XPC connection whether the private request
type is allowed; the availability probe does not exercise that policy check.

### Exact request construction

Strict mode repeats the raw-SSID invariant and uses a fresh directed CoreWLAN
scan. From the selected `CWNetwork`, it obtains the corresponding private
`CWFScanResult` and verifies:

- exact raw SSID bytes;
- exact canonical BSSID;
- authentication family; and
- nonempty, consistent private security metadata.

It then constructs request-local `CWFAssocParameters` with:

```text
scanResult                         = exact selected private scan result
password                           = nil
forceBSSID                         = true
findAndJoinNetwork                 = false
rememberUponSuccessfulAssociation = false
```

After setting them, the shim reads the values back from the request-owned
object and revalidates the copied scan result, profile, security metadata, and
all three Boolean controls before calling private
`associateWithParameters:error:`.

Passwordless networks need no profile. For a currently connected saved
Personal PSK network, the private scan result supplies profile metadata. The
shim copies that profile, marks only the request-local copy as system mode, and
passes no password. This asks `airportd` to resolve the saved credential using
its system access; BSSID Picker does not receive or read the Wi-Fi password.
The shim does not mutate the shared scan result and verifies that the original
profile's system-mode state remains unchanged.

`rememberUponSuccessfulAssociation = false` asks the outer strict request not
to add or update a remembered network. In the inspected implementation, the
passwordless branch observes that non-remembering choice. The Personal PSK
system-Keychain branch instead manages an already saved network internally and
does not consult the outer flag in the same way; no promise should be made that
macOS leaves all saved-profile metadata untouched. That branch still cannot
create a usable PSK entry from nothing because BSSID Picker supplies no password
and the daemon must find a saved System credential.

Strict mode deliberately rejects WEP, Enterprise/802.1X, and unknown or mixed
authentication. Missing compatible profile metadata or failed `airportd`
credential delegation is a strict failure, not a prompt for a password or a
fallback to standard mode.

### CoreWiFi and `airportd` implementation evidence

Additional disassembly confirms that the strict fields are not merely inert
Objective-C properties in the inspected implementation:

- Private `-[CWFInterface associateWithParameters:error:]` passes the same
  `CWFAssocParameters` over its synchronous XPC proxy using
  `associateWithParameters:requestParams:reply:`.
- `airportd`'s private association handler extracts the exact scan record. When
  `forceBSSID` is true, it writes a `FORCE_BSSID` property into that record
  before constructing its internal network object.
- On the Personal PSK system-mode-profile branch, `airportd` calls its
  system-Keychain association path. That path obtains the exact SSID data,
  invokes `CWKeychainFindWiFiPassword` with the System domain, and passes the
  returned password internally to the lower-level association operation. The
  secret does not cross back into BSSID Picker.

The CoreWiFi and daemon portions can be inspected with:

```sh
/usr/bin/dyld_info -function_starts \
  /System/Library/PrivateFrameworks/CoreWiFi.framework/CoreWiFi

/usr/bin/dyld_info -disassemble \
  /System/Library/PrivateFrameworks/CoreWiFi.framework/CoreWiFi

/usr/bin/dyld_info -disassemble /usr/libexec/airportd
```

This confirms that the inspected private CoreWiFi path propagates a material
force-BSSID signal to `airportd`, while the inspected public CoreWLAN path
supplies false and propagates no force signal. It also confirms the daemon-side
credential lookup in that implementation. It does not document an
Apple-supported contract, identify a specific Keychain item, or predict the
same implementation on another release. The shim also requests
`findAndJoinNetwork = false`, but the audit did not establish where the current
`airportd` binary consumes that field, so this document does not treat it as a
demonstrated system guarantee.

The private `associateWithParameters:error:` Boolean means that its synchronous
XPC operation reported no error. It is not itself an exact-BSSID postcondition,
which is why the app still performs independent public BSSID observations.

### Verification and support boundary

After the private request returns, strict mode samples the active BSSID at
approximately 0.5, 2, and 10 seconds. The first sample is diagnostic because it
can still reflect pre-association state. The target must be present at two
seconds and remain present at ten seconds. All samples are retained in the
connection event. See [`verifyStrictAssociation`][source-strict-verify].

This is stronger evidence than the standard short verifier, but it is still a
finite observation. It does not create a supported permanent roaming lock.
CoreWiFi is private, its request fields and credential behavior can change,
macOS can entitlement-gate it, and the Wi-Fi stack or AP infrastructure can
still change the association later. Strict BSSID should be considered an
experimental, fail-closed force attempt followed by verification—not a stable
Apple API. Private-API use is also incompatible with the Mac App Store's
[public-API requirement][app-review-private-api]; local code signing does not
make the interface supported.

The application runs inside App Sandbox. The Standard path obtains every
`CWInterface` from `CWWiFiClient`, which is Apple's
[documented sandbox-safe CoreWLAN boundary][apple-corewlan-sandbox]. The private
CoreWiFi request has no supported App Sandbox contract: loading the framework,
passing the structural availability check, or having outbound-network
permission does not guarantee that macOS will authorize the private operation.
Strict mode therefore keeps its runtime validation and fails closed rather than
falling back to Standard association.

Both association paths are state-changing and can interrupt the existing link.
A failed request or verification mismatch is reported, but the operation is not
an atomic transaction that restores the previous BSSID. BSSID Picker does not
call `disassociate()` itself; the daemon and driver can leave the Mac
disconnected or associated with another AP after a failure.

## Secondary limitations found during the audit

- **Public credential timing:** Standard mode checks the current SSID after its
  directed scan, then may wait for a Keychain prompt or lookup before calling
  `associate`. A network change during that interval can stale the scan object.
  Another pre-association check could narrow this race, but it would not create
  the missing public force-BSSID semantics.
- **Verification duration:** Standard mode does not preserve a timestamped
  sequence and watches for only about 2.5 seconds. Strict mode records three
  observations through ten seconds. Neither proves indefinite residence.
- **Raw SSID versus display SSID:** The app correctly uses raw bytes. This
  avoids display-name collisions but cannot solve the underlying public API
  policy.
- **Serialized work:** Menu, Scanner, lock, and association operations share
  one CoreWLAN queue, so concurrent app scans are not the cause of target
  substitution.
- **Lock health checks:** A healthy periodic BSSID Lock check only reads current
  SSID/BSSID. It scans and associates only after detecting the same SSID with a
  different BSSID. The lock itself is not continuously scanning.

## Practical recommendations

For supported and predictable behavior:

1. Treat Standard mode as **request and verify**, not enforce and guarantee.
2. Do not retry a public wrong-BSSID result in a tight loop. Repeated public
   association can repeatedly interrupt connectivity without changing macOS's
   candidate choice.
3. Use Strict BSSID only with its experimental warning and only when temporary
   incompatibility after an OS update is acceptable.
4. For a reliable deployment, solve selection on the network side: use unique
   SSIDs where feasible, disable or make the undesirable AP unavailable to the
   client, tune AP placement/power, or use controller/AP client policy if the
   infrastructure supports it.
5. To distinguish initial wrong selection from immediate roaming, capture a
   timestamped target/actual-BSSID sequence and collect a sysdiagnose immediately
   after a reliable reproduction. Apple's [Wi-Fi bug-report guidance][wifi-bug]
   asks for a reproducible case, a Wi-Fi debug profile, a rough timestamp, logs,
   and—when useful—a Wi-Fi packet trace.

No supported client-only CoreWLAN fallback discovered in this investigation can
guarantee an exact BSSID while multiple candidates advertise the same SSID.

## Source links

### Apple documentation and guidance

- [`CWInterface.associate(to:password:)`][apple-associate]
- [`CWNetwork.bssid`][apple-bssid]
- [`CWNetwork.isEqual(to:)`][apple-network-equality]
- [`CWKeychainFindWiFiPassword`][apple-keychain]
- [Wi-Fi roaming support in Apple devices][apple-roaming]
- [Apple DTS discussion of current CoreWLAN limitations][dts-corewlan]
- [Filing a Wi-Fi Bug Report][wifi-bug]
- [App Review Guidelines: public API requirement][app-review-private-api]
- [CoreWLAN App Sandbox guidance][apple-corewlan-sandbox]

### Historical code and reports

- [OS X 10.9 CoreWLAN header mirror][corewlan-10-9-header]
- [`airport-bssid` public-CoreWLAN implementation][airport-bssid-source]
- [Google `macops` private force-BSSID selector declaration][macops-force-selector]
- [macOS 10.13.5 runtime-derived CoreWLAN header][high-sierra-private-header]
- [Yosemite-era exact-BSSID report][yosemite-report]
- [El Capitan report][el-capitan-report]
- [2016 CoreWLAN experiment][corewlan-2016]
- [2017 initial-association-then-roam experiment][corewlan-2017]
- [High Sierra report][high-sierra-report]
- [Contradictory El Capitan/High Sierra reports and measurement warning][contradictory-reports]
- [Ask Different historical discussion][ask-different]

[apple-associate]: https://developer.apple.com/documentation/corewlan/cwinterface/associate(to:password:)
[apple-bssid]: https://developer.apple.com/documentation/corewlan/cwnetwork/bssid
[apple-network-equality]: https://developer.apple.com/documentation/corewlan/cwnetwork/isequal(to:)
[apple-keychain]: https://developer.apple.com/documentation/corewlan/cwkeychainfindwifipassword(_:_:_:)
[apple-roaming]: https://support.apple.com/guide/deployment/wi-fi-roaming-support-dep98f116c0f/web
[dts-corewlan]: https://developer.apple.com/forums/thread/799718
[wifi-bug]: https://developer.apple.com/forums/thread/819141
[app-review-private-api]: https://developer.apple.com/app-store/review/guidelines/#software-requirements
[apple-corewlan-sandbox]: https://developer.apple.com/documentation/corewlan
[corewlan-10-9-header]: https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX10.9.sdk/System/Library/Frameworks/CoreWLAN.framework/Versions/A/Headers/CWInterface.h#L323-L332
[airport-bssid-source]: https://github.com/qpSHiNqp/airport-bssid/blob/master/airport-bssid/main.m#L76-L110
[macops-force-selector]: https://github.com/google/macops/blob/3248145c6ed7a30d02f608d1ba0104f2dfe13f91/gmacpyutil/gmacpyutil/airport.py#L19-L36
[high-sierra-private-header]: https://github.com/LeoNatan/Apple-Runtime-Headers/blob/ce13efd905dcf4df94136d55554cda32b1e4c538/macOS/Frameworks/CoreWLAN.framework/CWInterface.h#L65-L140
[yosemite-report]: https://www.reddit.com/r/OSXTweaks/comments/2rceuj/connect_to_a_wifi_network_by_bssid_instead_of/
[el-capitan-report]: https://github.com/qpSHiNqp/airport-bssid/issues/3
[corewlan-2016]: https://takuya-1st.hatenablog.jp/entry/2016/03/08/173651
[corewlan-2017]: https://takuya-1st.hatenablog.jp/entry/2017/12/08/180807
[high-sierra-report]: https://github.com/qpSHiNqp/airport-bssid/issues/7
[contradictory-reports]: https://github.com/qpSHiNqp/airport-bssid/issues/6
[ask-different]: https://apple.stackexchange.com/questions/6958/can-i-connect-to-a-specific-access-point-by-bssid
[source-public-connect]: ../App/CoreWLANService.swift#L76-L131
[source-network-target]: ../App/WiFiModels.swift#L5-L75
[source-corewlan-adapter]: ../App/CoreWLANAdapter.swift#L6-L27
[source-resolve-network]: ../App/CoreWLANService.swift#L483-L491
[source-public-verify]: ../App/CoreWLANService.swift#L493-L506
[source-strict-service]: ../App/StrictBSSIDService.swift#L6-L35
[source-private-shim]: ../App/PrivateWiFiShim.m
[source-strict-verify]: ../App/CoreWLANService.swift#L508-L535
