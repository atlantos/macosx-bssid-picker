# Installation and Local Signing

BSSID Picker is built locally from source. A persistent code-signing identity
keeps macOS Location Services and Keychain decisions stable across rebuilds.
An Apple Developer Program membership is not required for personal use on the
Mac where the app is built.

## Requirements

- macOS 13 or later.
- Xcode or Xcode Command Line Tools providing `swiftc`, `clang`, `codesign`,
  `xcrun`, and a macOS SDK.
- An unlocked login Keychain.
- A normal user account. Do not run the signing setup with `sudo`.

If neither Xcode nor the Command Line Tools are installed, request the latter
with:

```sh
xcode-select --install
```

## Build and launch

Run these commands from the repository root:

```sh
./BuildTools/setup-local-signing.sh
./BuildTools/build-app.sh
open "build/BSSID Picker.app"
```

The signing setup is normally needed once per Mac. Later rebuilds require only:

```sh
./BuildTools/build-app.sh
```

The signed application is created at `build/BSSID Picker.app`. It can run from
that location. For a stable installed location, copy the finished app to
**Applications** before enabling **Launch BSSID Picker at login**, then launch
that copy. Recopy the bundle after rebuilding when you want to update the
installed copy.

## App Sandbox

The built application runs inside Apple's App Sandbox. Its entitlements allow
Location-protected Wi-Fi access, outgoing connections for the explicit MAC
registrant database download, and read/write access to a JSON or CSV destination
chosen in the system Save dialog. It has no unrestricted access to the user's
home directory.

The application does not request access to or import data from an earlier
unsandboxed copy. A previously downloaded MAC registrant database is ignored;
download a fresh copy from Settings. Location and Keychain decisions and
**Launch BSSID Picker at login** registration remain system-managed.

Do not delete the container as an ordinary troubleshooting step: doing so
removes the current sandboxed preferences and downloaded database.

## Expected setup prompts

During a fresh signing setup, macOS normally presents two approvals:

1. Apple's `security` tool asks in Terminal for the **login Keychain password**
   before changing the new private key's partition list. Input is hidden and is
   read directly by Apple's tool; BSSID Picker's script does not receive, store,
   or put the password in process arguments.
2. macOS presents native authentication before adding per-user Code Signing
   trust for the new certificate.

Approve both prompts. A verified rerun of the setup script should require no
prompts. If the login Keychain is manually locked, macOS must unlock it before
`codesign` or any other process can use its private keys.

The first build signed with the new identity has a different code identity from
older ad-hoc builds. macOS will therefore request Location access again and may
request relevant Keychain approval when Standard association later needs a
saved System credential. Subsequent builds retain the same identity and those
decisions.

## Why persistent signing is needed

macOS associates protected-data permissions with an app's code identity. An
ad-hoc signature changes when the executable changes, which can make each
rebuild appear to be a new app. The setup script creates one local identity
named `BSSID Picker Local Signing` and the build script uses it by default.

The generated identity is intended for local development and personal use. It
provides identity continuity across rebuilds; it is not a substitute for
Developer ID signing and notarization for public distribution.

## What the setup script creates

The setup script replaces the manual Certificate Assistant workflow. It:

- creates an RSA-3072/SHA-256 self-signed Code Signing certificate;
- imports its private key into the login Keychain as non-extractable;
- limits the private-key ACL to Apple's `/usr/bin/codesign`;
- installs only the `apple-tool:` and `apple:` partition entries required for
  non-interactive signing;
- adds Code Signing-only per-user trust;
- verifies the certificate/private-key binding, unique key selector, ACL,
  partition list, trust, and signing capability before declaring success; and
- protects temporary key material and helper output with owner-only permissions
  and removes them on exit.

The script does not modify `authorizationdb`, the system-wide trust store,
unrelated Keychain items, or unrelated private-key ACLs. It does not grant every
application access to the key.

The setup-only Security.framework helper identifies the private-key record from
the certificate's public-key hash and verifies that the system-assigned key
label uniquely selects the same key. It does not need a separate item-access
approval to read the new private key.

## Rerunning or replacing the identity

The normal setup command is idempotent after it verifies the complete expected
configuration:

```sh
./BuildTools/setup-local-signing.sh
```

It reuses only one fully valid identity with the exact expected name. It refuses
ambiguous duplicates, certificate-only states, and ordinary identities that do
not match its security policy.

To intentionally replace the exact managed identity and its per-user trust:

```sh
./BuildTools/setup-local-signing.sh --recreate
```

Recreation changes the app's code identity. Location and applicable Keychain
permissions will be requested again after the next build. On macOS 14 or later,
the system can also ask whether the replacement identity may access the existing
App Sandbox container; denying that request can prevent the app from launching.
With an unlocked login Keychain, recreation normally requires three setup
approvals: removal of the old certificate's trust, the Terminal partition-list
password, and trust for the replacement certificate. Runtime privacy and
container prompts are separate.

## Interrupted setup recovery

If authentication is cancelled or setup stops after importing a complete
identity, the script records that exact certificate fingerprint in an
owner-only pending-state file. Run the normal setup command to resume it:

```sh
./BuildTools/setup-local-signing.sh
```

Do not use `--recreate` merely to resume an interrupted setup. To remove only
the fingerprint-matched pending identity and its per-user trust, run:

```sh
./BuildTools/setup-local-signing.sh --reset-pending
```

If macOS itself stops during PKCS#12 import and leaves only a certificate or
only a private key, the script fails closed rather than guessing which item to
delete. Resolve that rare partial item in Keychain Access, then rerun setup. A
certificate fingerprint cannot safely identify a private-key-only orphan after
its certificate has disappeared.

Keep the valid identity and its private key in the login Keychain. Because the
generated key is deliberately non-extractable, deleting it requires creating a
new identity and reapproving protected-data access.

## Build overrides

To select a specific installed macOS SDK, provide its directory explicitly:

```sh
BSSID_PICKER_SDK_PATH="/path/to/MacOSX.sdk" ./BuildTools/build-app.sh
```

The path must identify a complete macOS SDK compatible with the active Swift
and Clang toolchain.

To use another uniquely named installed Code Signing identity:

```sh
BSSID_PICKER_SIGNING_IDENTITY="identity name" ./BuildTools/build-app.sh
```

For compilation diagnostics only, an explicit `-` selects ad-hoc signing:

```sh
BSSID_PICKER_SIGNING_IDENTITY=- ./BuildTools/build-app.sh
```

Do not use ad-hoc signing for the normal installed copy. Permissions can be
requested again after every rebuild because the app's code identity changes,
and macOS can refuse or repeatedly prompt for access to an existing sandbox
container owned by the stable identity.

## Security boundary

The local identity protects continuity, not isolation from other processes
running as the same macOS user. Such a process can invoke Apple's `codesign`
tool and ask it to use Code Signing identities available to that user.

For public distribution, use Developer ID signing and notarization instead of
the local self-signed identity. Apple documents both
[creating self-signed certificates][self-signed] and the purpose of stable code
identity in its [Code Signing Guide][code-signing].

Publish any binary release from an immutable source tag and keep the exact
tagged Corresponding Source available with it, including the build and signing
scripts and project-owned assets. The build embeds the repository's GPLv3
license as `Contents/Resources/LICENSE.txt`; do not remove that copy from a
distributed bundle.

Build-system implementation details are documented in
[Architecture](ARCHITECTURE.md).

[self-signed]: https://support.apple.com/guide/keychain-access/create-self-signed-certificates-kyca8916/mac
[code-signing]: https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html
