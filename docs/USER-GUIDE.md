# User Guide

This guide covers the menu-bar workflow, BSSID Lock, Settings, permissions, and
background behavior. See the separate [Wi-Fi Scanner guide](WIFI-SCANNER.md) for
the scanner window.

## First launch

1. Open **Settings…** from the status-item popover.
2. In **Location Access**, request permission when prompted.
3. Optionally enable **Launch BSSID Picker at login**.
4. Close Settings and open the Wi-Fi target icon in the menu bar.

macOS classifies nearby Wi-Fi SSIDs and BSSIDs as location information. BSSID
Picker requests Location permission only after the explicit Settings action.
Without it, the app cannot reliably read the current network or scan BSSIDs.

Launch at Login registers the signed main application with macOS. A login launch
opens only the menu-bar utility; it does not open Wi-Fi Scanner or show a Dock
icon. Settings reads the authoritative macOS Login Items state. If approval is
required, it links to **System Settings → General → Login Items & Extensions**.

## Main menu

Opening the status-item popover:

1. Reads the raw SSID and BSSID currently associated with the Mac.
2. Scans access points advertising that same SSID.
3. Lists their BSSIDs, channels, and signal strengths.
4. Marks the currently connected BSSID with a checkmark.
5. Lets you request association with another listed BSSID.
6. Verifies and reports the BSSID macOS actually joined.

The first scan begins when the popover opens. Results remain visible while a
refresh is running. Scan, connection, permission, and lock-recovery problems
appear as inline notices with the relevant action.

Selecting an access point requests a connection; it does not automatically
enable BSSID Lock. The selected target remains available for the optional lock
checkbox.

## Association modes

### Standard

Standard mode uses Apple's public CoreWLAN API. It passes the freshly scanned
network for the selected BSSID and verifies the result. The public API does not
provide a supported durable BSSID pin or a no-roam control, so macOS may choose
or later roam to another access point advertising the same SSID.

Standard mode supports:

- Open and Enhanced Open (OWE) without a password;
- Personal WEP/WPA/WPA2/WPA3 using a saved SSID-scoped password; and
- explicit System Keychain fallback only after user consent.

Enterprise/802.1X and unknown or ambiguous authentication are shown but are not
associated through an inappropriate credential flow.

### Strict BSSID (Experimental)

**Strict BSSID (Experimental)** is enabled by default under
**Settings → Association Mode**. It uses an undocumented private macOS Wi-Fi
path to request the exact BSSID and verifies the observed result. Turn it off
to use Standard CoreWLAN association. Strict mode supports passwordless
networks and compatible saved Personal PSK networks.

Strict mode never silently falls back to Standard mode. If its private backend,
credential delegation, authentication family, request, or verification is not
usable, the connection fails. Apple may change or remove the private interface
in any macOS update. Do not rely on Strict mode for safety-critical
connectivity.

The exact public/private request paths and historical macOS behavior are
documented in [BSSID Association on macOS](BSSID-ASSOCIATION.md).

## BSSID Lock

**BSSID Lock** is optional and off by default. To enable it:

1. Select a BSSID in the main menu.
2. Turn on **BSSID Lock**.
3. Wait for the immediate association check to finish.

The app saves the raw SSID and BSSID only after it verifies the exact target.
If initial activation cannot confirm the target, the checkbox returns to off
and no lock record is saved.

After a lock is established:

- a healthy check reads the current SSID/BSSID without scanning all networks;
- a different current SSID places the lock in a waiting state;
- the same SSID with a different BSSID starts recovery with a fresh directed
  scan and association attempt; and
- later outages retain the saved lock so Retry and recovery remain available.

Turning BSSID Lock off removes the saved target. Selecting another BSSID while
a lock exists asks whether to move the persistent lock after a successful
connection or make a one-time connection while retaining the existing lock. It
is never changed silently.

### Retry behavior

Transient established-lock failures use increasing retry delays. Credential,
permission, unsupported-security, and unavailable-private-backend errors pause
automatic retries. A Standard-mode wrong-BSSID result also pauses to avoid an
endless disconnect/reconnect loop.

Strict association or verification failures use bounded increasing delays.
Five consecutive failed Strict attempts trip a circuit breaker and pause the
lock. **Retry Now** clears that strict failure count and starts one new sequence.
The same action makes one explicit attempt after another paused failure.

## Update frequency

Settings accepts nonnegative whole seconds. `0` disables the corresponding
recurring timer; it does not disable explicit operations.

### Main-menu refresh

- Default: 10 seconds.
- Runs only while the status popover is open.
- Opening the popover still performs one scan when the interval is `0`.
- Closing the popover stops future menu scans; one already in progress may
  finish.

### BSSID lock check

- Default: 300 seconds.
- Runs whenever an established BSSID Lock exists, even with all windows closed.
- A healthy check reads the current association and does not perform a Wi-Fi
  scan.
- Setting it to `0` disables routine checks, but enabling the lock still performs
  its immediate activation check and an established failure may still use the
  separate retry policy.

Wi-Fi Scanner has independent automatic-scan and cache settings described in
the [Scanner guide](WIFI-SCANNER.md).

## Settings and Reset to Defaults

Settings controls:

- Location access;
- Launch at Login;
- main-menu and BSSID-lock intervals;
- the downloaded MAC registrant database;
- Standard versus Experimental Strict association; and
- recovery of a malformed saved lock record.

### MAC Registrant Database

The optional database adds local registrant information to Wi-Fi Scanner. It is
not required for scanning, association, or BSSID Lock.

- **Database Status** reports **Not Downloaded**, **Ready**,
  **Downloading…**, **Validating…**, **Installing…**, or **Update Failed**.
- **Database Updated** reports when the installed snapshot was downloaded, or
  **Never** when none is installed. It is not an assignment or company-change
  date.
- **Download Database** installs the first snapshot. After installation, the
  same action is named **Update Database**.
- **Sources & Licenses…** opens **MAC Registrant Database Sources**. For each
  source it shows **Purpose**, **Source**, **Version**, **License**, and
  **Attribution**. Version is either the installed snapshot's download time or
  **Not downloaded**. The sheet also reports the installed registration and
  known-address record counts, or **No records installed**. When a snapshot is
  installed, it offers **Remove Downloaded Data…**.

An update downloads the complete source databases and performs every BSSID
lookup locally. A scanned BSSID or MAC prefix is never submitted to an online
lookup service. Database downloads are user-initiated; the app does not schedule
periodic database updates. It honors Wireshark's request not to download its
database more than once per week. If no database is installed and the first
download fails, **Download Database** remains available for an immediate manual
retry. Once a valid snapshot is installed, every later update attempt starts a
seven-day wait, whether that attempt succeeds or fails. A failed update retains
the previously installed valid snapshot.

Removing downloaded data does not affect Wi-Fi scans, settings, saved networks,
or BSSID Lock. **Remove Downloaded Data…** opens the **Remove Downloaded MAC
Registrant Data?** confirmation with **Remove** and **Cancel** actions. Scanner
registrant fields remain unavailable until another snapshot is downloaded. See
[MAC Registrant Data Sources and Licenses](MAC-REGISTRANT-DATA.md) for source
provenance and the limits of prefix-based identification.

**Reset to Defaults…** requests confirmation, then:

- turns off Launch at Login;
- removes the saved BSSID Lock and its target-scoped System Keychain fallback
  consent;
- restores Experimental Strict BSSID to enabled;
- restores menu and lock-check intervals; and
- resets Wi-Fi Scanner columns, sorting, filters, automatic scanning, cache
  retention, inspector expansion, window placement, and split-panel size.

Reset does not change Location authorization, macOS saved Wi-Fi networks or
credentials, Keychain items or macOS access-control decisions, or exported
files. It also does not remove the downloaded MAC registrant database; use
**Sources & Licenses… → Remove Downloaded Data…** for that separate action.

## Permissions, credentials, and privacy

Scanning, viewing Wi-Fi Scanner, healthy BSSID checks, and passwordless
association do not read Wi-Fi passwords.

In Standard mode, a protected Personal or WEP connection can require a saved
password. BSSID Picker asks for permission before trying the System Keychain
fallback. Authentication failure, denial, and cancellation are reported rather
than bypassed. The app does not log or persist the password.

For a compatible saved Personal PSK network, Strict mode asks macOS to resolve
the credential without exposing the password to BSSID Picker. This is an
undocumented implementation path and can fail without offering a Standard-mode
fallback.

The credential lookup and association boundaries are documented in
[BSSID Association on macOS](BSSID-ASSOCIATION.md).

Wi-Fi Scanner and exports never include passwords, password-derived values,
Keychain account names, item labels, persistent references, access groups,
ACLs, or private profile dumps. See the [Scanner privacy and export
section](WIFI-SCANNER.md#copying-export-and-privacy) for details.
