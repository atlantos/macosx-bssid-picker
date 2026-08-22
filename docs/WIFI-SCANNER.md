# Wi-Fi Scanner

Wi-Fi Scanner shows nearby access points, decoded Wi-Fi advertisement data, and
the Mac/BSSID Picker context associated with the current session. It is a
diagnostic and export surface; opening, scanning, selecting, sorting, copying,
or exporting does not connect to a network or read a Wi-Fi password.

## Opening and closing

Choose **Wi-Fi Scanner** from the status-item popover. Opening the window starts
one scan even when automatic scanning is disabled.

While the Scanner session is open:

- BSSID Picker appears in the Dock;
- a conventional application menu provides About, Settings, File, Edit, Window,
  and Quit commands; and
- configured automatic scans and cache expiration continue while the window is
  miniaturized or the app is hidden.

Closing the Scanner window removes its Dock icon, returns the app to menu-bar-
only mode, and stops future Scanner and cache-expiry timers. A CoreWLAN scan
already in progress may finish and update the session cache, but it cannot
schedule another scan while the Scanner remains closed.

## Scan controls

The Scanner window has independent controls for:

- automatic scan interval;
- cache retention;
- search and optional regular-expression mode;
- band, security, capability, and observation filters;
- column preset and individual column visibility; and
- export scope and format.

Intervals are nonnegative whole seconds.

### Automatic scan interval

- Default: `0`, which disables recurring Scanner scans.
- Opening the Scanner still performs one scan.
- A positive value schedules the next scan after the preceding scan finishes,
  preventing overlapping Scanner scans.
- Automatic scans continue while the Scanner is hidden or miniaturized and stop
  when the Scanner window is closed.

### Cache retention

- Default: `0`, which shows only results from the latest successful scan.
- A positive value retains an access point omitted by a later successful scan
  until that many seconds have elapsed since **Last Seen**.
- A failed or in-progress scan does not reclassify prior observations as
  missing.
- Retention expiration removes rows but never initiates a Wi-Fi scan.
- Retained observations survive closing and reopening the Scanner during the
  same app session.
- The cache is not stored across app launches and is cleared if Location access
  is lost.

`0` therefore means no historical retention, not infinite retention. Use a high
positive value when a long in-session history is desired.

## Table and column presets

The left panel is a dense, sortable table. Built-in presets include:

- **Overview**;
- **This Mac**;
- **Radio**;
- **Security**;
- **Roaming**; and
- **All Fields**.

Columns can also be shown individually. Visibility, order, widths, sorting,
automatic scan interval, cache retention, and inspector expansion persist
between launches. A Custom column arrangement retains its explicit order when
other preset defaults evolve.

The permanent leading checkmark identifies the row whose exact raw SSID and
BSSID match the Mac's latest association observation. It is not a generic
“active network” indicator.

The **MAC Registrant** column appears after **BSSID** and is visible in every
named preset. An existing Custom layout gains the column in that position but
keeps it hidden until explicitly enabled, preserving the user's visibility
choices. The value comes from the optional local database managed in Settings;
the app can still classify a valid address as **Locally Administered** or a
**Group Address** without that database. An em dash for a globally administered
address means the database is unavailable. **Not Found**, **Private
Registration**, and **Ambiguous Registration** are explicit lookup results. A
named organization identifies the registrant for a matching MAC-address block;
it is not proof of the access point's brand, manufacturer, owner, or operator.

Default-visible **Observation** and **Last Seen** columns appear after the other
network fields. **Observation** distinguishes:

- **Seen in Latest Scan**; and
- **Previous Observation** retained from an earlier successful scan.

A previous observation means only that the access point was not reported by
the latest successful scan. It does not prove that the AP is offline, out of
range, or unavailable.

## Search and filters

Search uses a cached per-row index and coalesces rapid typing before rebuilding
the table. It covers all scanner fields plus decoded information-element names
and summaries. When local MAC attribution is available, search also covers its
organization names, address type, allocation, matched prefix, source, database
agreement, and known-address role.

With **Regex** off, search is literal, case-insensitive, and
diacritic-insensitive. With **Regex** on, the query is interpreted as a
case-insensitive regular expression. Invalid expressions are reported and
produce no matches until corrected or Regex is disabled.

Search combines with all popup filters:

- **Any Band** or a specific band;
- **Any Security** or a specific security class;
- **Any Capability** or an advertised roaming capability; and
- **Any Observation**, **Seen in Latest Scan**, or **Previous Observations**.

**Clear Filters** restores the unfiltered session view. If cache retention is
`0`, **Previous Observations** correctly has no matching rows.

Sorting uses typed numeric and date values rather than formatted display text.
**MAC Registrant** sorts by its displayed name using locale-aware comparison,
with unavailable values treated as missing. The selected row remains selected
across updates while its identity remains in the displayed result set.

## Selecting and copying text

Text in every table data cell is read-only but selectable. Selecting text in a
cell also selects its row so the inspector remains synchronized.

The right inspector is one continuous read-only text document. A selection can
span field values, labels, and entire sections rather than being limited to one
control. Command-A selects the inspector document when it owns keyboard focus.

Command-C copies an arbitrary selected substring when one exists. Otherwise it
copies the selected table row. Context and inspector actions also provide:

- **Copy Row**;
- **Copy BSSID**; and
- **Copy Raw IEs**.

## Inspector contents

The right panel shows every concise access-point field available to the scanner
and then the complete decoded information-element list. Its sections include:

- scan observation and last-seen state;
- identity and raw SSID bytes;
- MAC registration and known-address attribution;
- radio, signal, noise, SNR, channel, band, channel width, and PHY modes;
- BSS load, including station count, channel utilization, and available
  admission capacity;
- security, RSN suites, and Protected Management Frames;
- 802.11k, 802.11v, and 802.11r roaming and management advertisements;
- interworking, roaming consortium, AP channel reports, Reduced Neighbor
  Reports, and Multiple BSSID;
- DTIM, BSS Max Idle, protected keep-alive, timing, and topology; and
- known extended and vendor information elements, malformed tails, per-element
  raw bytes, and an optional complete hex dump.

Capability states distinguish **Advertised**, **Not Advertised in Captured
Frame**, and **Unknown from Captured Frame**. They describe one captured beacon
or probe-response information-element blob. They do not test the Mac's own
capability or prove that a feature works end to end.

### MAC Registration

For a selected row, **MAC Registration** always shows all of these local lookup
fields:

- **Address Type**;
- **Registered Organization**, including every preserved organization and
  source when one prefix has ambiguous registry records;
- **Allocation** and **Matched Prefix**;
- **Registration Source**;
- **Database Agreement**;
- **Known Address Role** from Wireshark's supplemental data; and
- **Evidence Scope**.

Unavailable attribution shows **Unavailable** for the lookup fields. For a
locally administered or group address, registration-only fields show **Not
Applicable**. A globally administered address with no matching record shows
**Not Found**. An ordinary registry match reports **No Conflicting Records**
for **Database Agreement**.
**Known Address Role** independently shows its matched role, **Not Found**, or
**Unavailable**. **Evidence Scope** always explains that prefix registration is
not proof of the access point's brand, manufacturer, owner, or operator.

The resolver uses the most-specific matching prefix. More-specific MA-S or IAB
and MA-M matches take precedence over a broader MA-L/OUI match. When source
data contains genuinely different full organization names for the same prefix,
the result is **Ambiguous Registration** and the database agreement reports
**Ambiguous Registry Records** rather than selecting a company by file order.
A known-address role describes a special use of an address and is not a
registrant.

All of these values come from the installed local snapshot. Selecting a row or
opening the inspector never performs an Internet lookup. See
[MAC Registrant Data Sources and Licenses](MAC-REGISTRANT-DATA.md) for source,
license, update, and interpretation details.

### Current-Mac context

Current association/channel/PHY/security, signal/noise/SNR, transmit rate, and
transmit power appear only for the exact active BSSID or in the no-selection
global dashboard. They are not repeated on unrelated rows.

Global interface context includes interface identity, power and service state,
mode, hardware address, country, supported channels, relevant public CoreWLAN
configuration flags, and preferred-profile counts. Saved-profile details are
scoped to exact raw SSIDs present in the current scan; a saved profile is not
evidence that a readable Keychain credential exists.

The same inspector reports observed session state for:

- current and requested BSSID;
- BSSID Lock target and state;
- Standard versus Experimental Strict association mode;
- failure count, retry state, last result, and sanitized error;
- post-association verification observations; and
- bounded connection-event history.

Credential diagnostics are secret-free. They can show whether a credential was
required, which lookup stage was attempted, result and attempt count, numeric
OSStatus, consent scope, and whether the app handled a password ephemerally.
Strict mode is identified as a macOS-managed handoff; the UI does not claim
which Keychain item macOS used.

## Copying, export, and privacy

The Export menu supports:

- all rows or the currently filtered rows;
- JSON; and
- CSV.

JSON export uses schema version 7. Exports include the typed scan, observation,
system, lock, connection, and credential diagnostics already held for the
current app session. Each access point's `macRegistration` object contains
`addressType`, `registrantDisplay`, `registeredOrganization`, `allocation`,
`matchedPrefix`, `registrationSource`, `databaseAgreement`,
`knownAddressRole`, `registryClaims`, and `evidenceScope`. Each entry in
`registryClaims` contains `organization` and `source`. Optional structured
values with no source evidence are `null`, while `registryClaims` is an empty
array when there are no claims. Inspector-only explanatory fallbacks such as
**No Conflicting Records** are therefore not exported as if they were source
records.

CSV includes every Scanner column, including **MAC Registrant**, plus the exact
supplemental columns **MAC Address Type**, **MAC Allocation**, **MAC Matched
Prefix**, **MAC Registration Source**, **MAC Database Agreement**, and **Known
Address Role**. It also retains the raw observation fields needed to distinguish
current and retained rows. These supplemental columns export the underlying
structured values, so a field with no source value is empty even when the
inspector supplies explanatory fallback text.
Exporting uses the attribution already attached to each row and does not
perform a network lookup or database update.

Exports contain scan results and decoded advertisement data—not captured
packets or PCAP frames. Nearby SSIDs, BSSIDs, hardware addresses, and raw Wi-Fi
advertisements can still be sensitive; review exported files before sharing
them.

Scanner presentation and export never include:

- Wi-Fi passwords or password-derived values;
- Keychain account names, item identifiers, labels, or persistent references;
- Keychain paths, access groups, or ACLs; or
- private Wi-Fi profile dumps.

Opening, refreshing, filtering, selecting, copying, and exporting never trigger
a Keychain lookup or the private Strict association path. Connection history can
only display sanitized events produced by an association attempt made elsewhere
in the app.
