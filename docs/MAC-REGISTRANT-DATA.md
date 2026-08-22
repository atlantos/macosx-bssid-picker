# MAC Registrant Data Sources and Licenses

BSSID Picker can enrich a scanned BSSID with information about its matching MAC
address registration. This document records what that result means, where the
downloaded data comes from, how updates protect scan privacy, and which licenses
apply.

## What a registration identifies

A MAC-address block is registered to an organization. That registrant may be a
component supplier, contract manufacturer, former company name, parent company,
or organization operating a special address range. It is not necessarily the
access point's current manufacturer, product brand, owner, or network operator.

The resolver uses the most-specific matching prefix. A 36-bit MA-S or IAB match
therefore takes precedence over a 28-bit MA-M match, which takes precedence over
a 24-bit MA-L/OUI match. More-specific and less-specific registrations are not
treated as contradictory.

The current implementation does not combine independent IEEE and Wireshark
registration downloads. Wireshark's `manuf` file already contains
registry-derived full organization names. Its shortened name column is an
algorithmic Wireshark abbreviation, not a second organization claim.

Identical organization names for one prefix are deduplicated after conservative
normalization. If the source contains genuinely different full organization
names for the same prefix, the result is **Ambiguous Registration** with
**Ambiguous Registry Records** rather than an arbitrary selection based on file
order. The inspector lists the preserved claims and JSON export includes them
in `registryClaims`. A database's download date does not establish when an
assignment or organization name became valid.

Locally administered or randomized addresses do not reliably encode a hardware
manufacturer. A well-known-address match describes an address role, not a MAC
registrant, and remains distinct from registration information.

## Wireshark Manufacturer Database

- Purpose: MAC-prefix registration names for MA-L, MA-M, MA-S, and legacy IAB
  address blocks.
- Download: [Wireshark automated `manuf` data][wireshark-manuf].
- Upstream project: [Wireshark][wireshark-project].
- Attribution: Wireshark Foundation and contributors; generated from public
  registry data.
- License: [`GPL-2.0-or-later`][gpl-2-or-later].

Wireshark generates this data substantially from the IEEE Registration
Authority's public listings and also maintains name-resolution data used by
Wireshark. It is therefore not wholly independent of IEEE; differences can
reflect normalization, historical names, curation, or source update timing.
Because BSSID Picker consumes this combined file, there is no separate
“IEEE-versus-Wireshark” precedence decision for a matching prefix.

The downloaded file states that its data is updated once a week and asks clients
not to download it more frequently. Once a valid snapshot is installed, BSSID
Picker persists a seven-day interval after every later update attempt, including
a failed attempt, to honor that policy. A failed first download leaves no usable
snapshot and may be retried immediately.

## Wireshark Well-Known Addresses

- Purpose: supplemental roles for exact or masked well-known MAC addresses.
- Download: [Wireshark `wka` data][wireshark-wka].
- Upstream project: [Wireshark][wireshark-project].
- Attribution: Copyright 1998 Gerald Combs; Wireshark Foundation and
  contributors.
- License: [`GPL-2.0-or-later`][gpl-2-or-later].

The `wka` file identifies protocol, multicast, virtual, and other specially used
addresses. A role from this file is displayed separately and does not override a
registration claim as though it were a manufacturer.

## IEEE derivation and attribution

The IEEE Registration Authority defines the public assignment classes consumed
by Wireshark, including:

- [MA-L, formerly called OUI][ieee-ma-l] — a 24-bit assignment used to form
  extended identifiers;
- MA-M — a 28-bit MAC address block;
- MA-S — a 36-bit MAC address block; and
- legacy Individual Address Blocks (IABs), also represented by a 36-bit match.

IEEE is the assignment authority. Wireshark supplies the downloadable,
GPL-2.0-or-later-formatted data used by this feature. BSSID Picker preserves the
Wireshark attribution and license information in the application and source
distribution.

## Download, storage, and privacy

**Download Database** and **Update Database** fetch the complete `manuf` and
`wka` files from fixed HTTPS locations. The app does not query an upstream
service for an observed BSSID, OUI, or other derived prefix. Upstream servers
therefore receive an ordinary full-file request, not the nearby hardware
addresses found in a scan. Downloads occur only after either button is chosen;
there is no periodic database updater.

The app validates both complete sources and compiles a candidate resolver before
replacing the local payload. An interrupted, rejected, or failed update leaves
the previously installed valid snapshot in use. The payload is stored inside
the App Sandbox container under
`~/Library/Containers/local.bssid-picker.app/Data/Library/Application Support/BSSID Picker/Vendor Databases/`.
`database.plist` is the atomically replaced payload containing both raw sources
and their metadata. `last-update-attempt.plist` records the installed-database
update throttle. Removing downloaded data deletes both files. The app does not
read or import a database left in the former unsandboxed Application Support
location; download a fresh copy from Settings instead. This is app support data
rather than a preference, so
**Reset to Defaults…** retains it; use
**Sources & Licenses… → Remove Downloaded Data…** to delete it.

The **Database Updated** value is the snapshot's successful download time. It is
not an upstream release version or an effective date for individual registry
records. The **MAC Registrant Database Sources** sheet reports the same value as
**Version** for both files, or **Not downloaded** when no snapshot is installed;
it also lists each source's purpose, URL, attribution, and
`GPL-2.0-or-later` license URL. For an installed snapshot it reports the
validated MAC-registration and known-address record counts stored with that
snapshot.

[ieee-ma-l]: https://standards.ieee.org/products-programs/regauth/oui/
[gpl-2-or-later]: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
[wireshark-manuf]: https://www.wireshark.org/download/automated/data/manuf
[wireshark-project]: https://gitlab.com/wireshark/wireshark/
[wireshark-wka]: https://gitlab.com/wireshark/wireshark/-/raw/master/wka
