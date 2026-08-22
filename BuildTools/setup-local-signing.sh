#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail

umask 077

readonly identity_name="BSSID Picker Local Signing"
mode="setup"
script_dir="$(cd -P "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
readonly helper_source="$script_dir/signing-key-helper.c"

user_id=""
user_temp=""
login_keychain=""
state_dir=""
pending_marker=""
marker_temp=""
work_dir=""
private_key=""
certificate=""
signing_helper=""
probe_binary=""
probe_log=""
pending_hash=""
all_hashes=""
all_count=0
valid_hashes=""
valid_count=0
identity_hash=""

usage() {
  /bin/cat <<EOF
Usage: ./BuildTools/setup-local-signing.sh [--recreate | --reset-pending]

Creates the local, persistent code-signing identity used by BSSID Picker.
The identity is stored in your login Keychain and is trusted only for code
signing. macOS requires a native authentication dialog before changing your
per-user certificate trust settings.

  --recreate       Remove the one exact-name identity and its per-user trust by
                   certificate fingerprint, then create a correctly configured
                   replacement. Earlier app permissions will be requested again.
  --reset-pending  Remove only the exact identity recorded by an interrupted
                   setup, including its per-user trust, then exit.
EOF
}

parse_arguments() {
  if [[ "$#" -gt 1 ]]; then
    usage >&2
    exit 2
  fi

  case "${1:-}" in
    "") ;;
    --recreate) mode="recreate" ;;
    --reset-pending) mode="reset" ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
}

validate_prerequisites() {
  local tool

  if [[ "$(/usr/bin/id -u)" -eq 0 ]]; then
    echo "Run this script as your normal macOS user, not with sudo." >&2
    return 1
  fi

  for tool in \
      /bin/chmod \
      /bin/cat \
      /bin/cp \
      /bin/mkdir \
      /bin/mv \
      /bin/rm \
      /usr/bin/awk \
      /usr/bin/codesign \
      /usr/bin/dirname \
      /usr/bin/getconf \
      /usr/bin/id \
      /usr/bin/lockf \
      /usr/bin/mktemp \
      /usr/bin/openssl \
      /usr/bin/security \
      /usr/bin/sed \
      /usr/bin/stat \
      /usr/bin/tr \
      /usr/bin/xcrun; do
    if [[ ! -x "$tool" ]]; then
      echo "Required macOS tool not found: $tool" >&2
      return 1
    fi
  done

  if [[ ! -f "$helper_source" ]]; then
    echo "Signing-key helper source not found: $helper_source" >&2
    return 1
  fi
}

acquire_setup_lock() {
  local lock_file="${user_temp%/}/bssid-picker-local-signing.lock"

  # Keep descriptor 9 open until process exit. This prevents two setup runs
  # from creating identities after both observe an empty Keychain.
  exec 9>"$lock_file"
  if ! /usr/bin/lockf -s -t 0 9; then
    echo "Another BSSID Picker signing setup is already running." >&2
    return 1
  fi
}

locate_login_keychain() {
  if ! login_keychain="$(/usr/bin/security login-keychain 2>/dev/null |
      /usr/bin/sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//')"; then
    echo "The login Keychain could not be queried. Log in normally, then retry." >&2
    return 1
  fi
  if [[ -z "$login_keychain" || ! -f "$login_keychain" ]]; then
    echo "The login Keychain could not be located. Log in normally, then retry." >&2
    return 1
  fi
}

prepare_state_directory() {
  if [[ -z "${HOME:-}" || ! -d "$HOME" ]]; then
    echo "Your home directory could not be located." >&2
    return 1
  fi

  state_dir="$HOME/Library/Application Support/local.bssid-picker.app"
  if [[ -L "$state_dir" || ( -e "$state_dir" && ! -d "$state_dir" ) ]]; then
    echo "The signing state path is not a normal directory: $state_dir" >&2
    return 1
  fi
  /bin/mkdir -p "$state_dir"
  if [[ "$(/usr/bin/stat -f '%u' "$state_dir")" != "$user_id" ]]; then
    echo "The signing state directory is not owned by the current user." >&2
    return 1
  fi
  /bin/chmod 700 "$state_dir"

  pending_marker="$state_dir/pending-signing-sha1"
  marker_temp="$state_dir/.pending-signing-sha1.$$"
  if [[ -L "$pending_marker" ||
      ( -e "$pending_marker" && ! -f "$pending_marker" ) ]]; then
    echo "The pending-signing marker is not a normal file." >&2
    return 1
  fi
  if [[ -f "$pending_marker" &&
      "$(/usr/bin/stat -f '%u' "$pending_marker")" != "$user_id" ]]; then
    echo "The pending-signing marker is not owned by the current user." >&2
    return 1
  fi
}

prepare_workspace() {
  work_dir="$(/usr/bin/mktemp -d "${user_temp%/}/bssid-picker-signing.XXXXXX")"
  private_key="$work_dir/identity.key.pem"
  certificate="$work_dir/identity.cert.pem"
  signing_helper="$work_dir/signing-key-helper"
  probe_binary="$work_dir/signing-probe"
  probe_log="$work_dir/signing-probe.log"
}

cleanup() {
  local exit_status=$?
  local retained_hash=""

  trap - EXIT
  /bin/rm -f "$marker_temp"
  /bin/rm -rf "$work_dir"
  if [[ "$exit_status" -ne 0 && -f "$pending_marker" ]]; then
    retained_hash="$(/usr/bin/tr -d '[:space:]' <"$pending_marker" 2>/dev/null || true)"
    /bin/cat >&2 <<EOF

Setup did not complete. An identity, per-user Code Signing trust, or its
private-key ACL may already have been retained for fingerprint:

  $retained_hash

Run ./BuildTools/setup-local-signing.sh again to resume that exact fingerprint.
To remove only this interrupted setup state, run:

  ./BuildTools/setup-local-signing.sh --reset-pending
EOF
  fi
  exit "$exit_status"
}

compile_signing_helper() {
  if ! /usr/bin/xcrun --sdk macosx clang \
      -std=c11 \
      -O2 \
      -Wall \
      -Wextra \
      -Werror \
      -Wno-deprecated-declarations \
      -framework CoreFoundation \
      -framework Security \
      "$helper_source" \
      -o "$signing_helper"; then
    echo "The signing-key helper could not be compiled." >&2
    return 1
  fi
}

initialize_environment() {
  validate_prerequisites

  user_id="$(/usr/bin/id -u)"
  user_temp="$(/usr/bin/getconf DARWIN_USER_TEMP_DIR)"
  if [[ ! -d "$user_temp" ||
      "$(/usr/bin/stat -f '%u' "$user_temp")" != "$user_id" ]]; then
    echo "The private per-user temporary directory could not be validated." >&2
    return 1
  fi

  acquire_setup_lock
  locate_login_keychain
  prepare_state_directory
  prepare_workspace

  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  compile_signing_helper
}

identity_hashes() {
  local valid_only="$1"
  local listing
  if [[ "$valid_only" == "yes" ]]; then
    if ! listing="$(/usr/bin/security find-identity -v -p codesigning \
        "$login_keychain" 2>/dev/null)"; then
      echo "The login Keychain could not be searched for valid identities." >&2
      return 1
    fi
  else
    # The basic policy includes an imported self-signed identity before it is
    # trusted; the Code Signing policy does not.
    if ! listing="$(/usr/bin/security find-identity "$login_keychain" 2>/dev/null)"; then
      echo "The login Keychain could not be searched for identities." >&2
      return 1
    fi
  fi
  printf '%s\n' "$listing" |
    /usr/bin/awk -F '"' -v wanted="$identity_name" '
      $2 == wanted {
        value = $1
        sub(/^[[:space:]]*[0-9]+\)[[:space:]]*/, "", value)
        sub(/[[:space:]].*$/, "", value)
        value = toupper(value)
        if (!seen[value]++) {
          print value
        }
      }
    '
}

line_count() {
  /usr/bin/awk 'NF { count++ } END { print count + 0 }'
}

first_line() {
  /usr/bin/awk 'NF { print; exit }'
}

named_certificate_count() {
  local output_file="$work_dir/certificate-matches.txt"
  if ! /usr/bin/security find-certificate -a -c "$identity_name" -Z "$login_keychain" \
      >"$output_file" 2>/dev/null; then
    echo "The login Keychain certificate inventory could not be queried." >&2
    return 1
  fi
  /usr/bin/awk '/SHA-1 hash:/ { count++ } END { print count + 0 }' "$output_file"
}

named_certificate_hashes() {
  local output_file="$work_dir/certificate-matches.txt"
  if ! /usr/bin/security find-certificate -a -c "$identity_name" -Z "$login_keychain" \
      >"$output_file" 2>/dev/null; then
    echo "The login Keychain certificate inventory could not be queried." >&2
    return 1
  fi
  /usr/bin/awk '
    /SHA-1 hash:/ {
      value = $0
      sub(/^.*SHA-1 hash:[[:space:]]*/, "", value)
      print toupper(value)
    }
  ' "$output_file"
}

certificate_hash() {
  /usr/bin/openssl x509 -in "$1" -noout -fingerprint -sha1 2>/dev/null |
    /usr/bin/sed -e 's/^.*=//' -e 's/://g' |
    /usr/bin/tr '[:lower:]' '[:upper:]'
}

key_label_for_hash() {
  printf '%s Key %s\n' "$identity_name" "$1"
}

require_key_label_absent() {
  local key_label="$1"
  local query_status
  if "$signing_helper" label-exists "$login_keychain" "$key_label" \
      >/dev/null 2>&1; then
    /bin/cat >&2 <<EOF
The private key selected before identity deletion is still present. The pending
marker was retained. Resolve the orphaned key in Keychain Access, then retry.
EOF
    return 1
  else
    query_status=$?
  fi
  if [[ "$query_status" -eq 2 ]]; then
    return 0
  fi
  echo "The login Keychain private-key inventory could not be queried." >&2
  return 1
}

refuse_unresolvable_pending_marker() {
  /bin/cat >&2 <<EOF
The interrupted fingerprint has no matching certificate, so the script cannot
prove whether PKCS#12 import left a private-key-only orphan. The marker was
retained and nothing was changed. Resolve any orphaned BSSID Picker signing key
in Keychain Access before retrying.
EOF
  return 1
}

read_pending_hash() {
  local value=""
  if [[ -f "$pending_marker" ]]; then
    value="$(/usr/bin/tr -d '[:space:]' <"$pending_marker" |
      /usr/bin/tr '[:lower:]' '[:upper:]')"
    if [[ ! "$value" =~ ^[0-9A-F]{40}$ ]]; then
      echo "The pending-signing marker is malformed; refusing to use it." >&2
      return 1
    fi
  fi
  printf '%s\n' "$value"
}

write_pending_hash() {
  local value="$1"
  printf '%s\n' "$value" >"$marker_temp"
  /bin/chmod 600 "$marker_temp"
  /bin/mv -f "$marker_temp" "$pending_marker"
}

export_existing_certificate() {
  local expected_hash="$1"
  if ! /usr/bin/security find-certificate -c "$identity_name" -p "$login_keychain" \
      >"$certificate" 2>/dev/null; then
    echo "The existing identity's certificate could not be exported." >&2
    return 1
  fi
  local exported_hash
  exported_hash="$(certificate_hash "$certificate")"
  if [[ "$exported_hash" != "$expected_hash" ]]; then
    /bin/cat >&2 <<EOF
The login Keychain contains ambiguous certificates named "$identity_name".
Nothing was changed. Resolve the duplicate certificates before retrying.
EOF
    return 1
  fi
}

trust_certificate() {
  echo "macOS will ask you to authorize per-user Code Signing trust."
  /usr/bin/security add-trusted-cert \
    -r trustRoot \
    -p codeSign \
    -k "$login_keychain" \
    "$certificate"
}

configure_private_key() {
  local identity_hash="$1"
  local key_label

  # Do not request a live private-key reference until its partition ACL has
  # been installed. This selects the imported key through certificate/public-
  # key metadata, then proves its system-assigned text label is unique for the
  # exact selector accepted by Apple's security tool.
  key_label="$("$signing_helper" select-label "$login_keychain" "$identity_hash")"

  /bin/cat <<EOF
macOS will now ask once in this Terminal for your login Keychain password.
The password is read securely by Apple's security tool and is not stored by
BSSID Picker. It authorizes the exact private-key partition-list change.
EOF
  /usr/bin/security set-key-partition-list \
    -S "apple-tool:,apple:" \
    -t private \
    -s \
    -l "$key_label" \
    "$login_keychain"

  "$signing_helper" verify "$login_keychain" "$identity_hash" "$key_label"
}

verify_private_key() {
  local identity_hash="$1"
  local key_label
  key_label="$("$signing_helper" select-label "$login_keychain" "$identity_hash")"
  "$signing_helper" verify "$login_keychain" "$identity_hash" "$key_label"
}

verify_code_signing_only_trust() {
  local identity_hash="$1"
  "$signing_helper" verify-trust "$login_keychain" "$identity_hash"
}

resume_private_key() {
  local identity_hash="$1"
  # Verification has Keychain UI disabled inside the helper, so it either
  # confirms an already completed ACL without prompting or fails cleanly. Only
  # an incomplete ACL needs the intentional partition-list password request.
  if verify_private_key "$identity_hash" >/dev/null 2>&1; then
    echo "Existing signing private-key ACL is already configured."
    return 0
  fi
  configure_private_key "$identity_hash"
}

signing_probe() {
  local identity_hash="$1"
  /bin/cp /usr/bin/true "$probe_binary"
  if ! /usr/bin/codesign \
      --force \
      --sign "$identity_hash" \
      --keychain "$login_keychain" \
      --timestamp=none \
      "$probe_binary" >"$probe_log" 2>&1; then
    return 1
  fi
  /usr/bin/codesign --verify --strict --verbose=2 "$probe_binary" >>"$probe_log" 2>&1
}

load_identity_inventory() {
  pending_hash="$(read_pending_hash)"
  all_hashes="$(identity_hashes no)"
  all_count="$(printf '%s\n' "$all_hashes" | line_count)"
  valid_hashes="$(identity_hashes yes)"
  valid_count="$(printf '%s\n' "$valid_hashes" | line_count)"

  if [[ "$all_count" -gt 1 || "$valid_count" -gt 1 ]]; then
    /bin/cat >&2 <<EOF
More than one identity is named "$identity_name".
Nothing was changed. Remove or rename the unintended duplicate, then retry.
EOF
    printf '%s\n' "$all_hashes" >&2
    return 1
  fi
}

reset_interrupted_setup() {
  local certificate_count
  local reset_hash
  local reset_certificate_hashes
  local reset_certificate_count
  local reset_key_label
  local remaining_identity_hashes
  local remaining_certificate_count

  # This mode deliberately terminates the workflow after handling the marker.
  # main returns immediately instead of creating or validating an identity.
  if [[ -z "$pending_hash" ]]; then
    echo "There is no interrupted BSSID Picker signing setup to reset."
    return 0
  fi
  if [[ "$all_count" -eq 0 ]]; then
    certificate_count="$(named_certificate_count)"
    if [[ "$certificate_count" -ne 0 ]]; then
      echo "A matching certificate remains without an enumerable identity; refusing automatic deletion." >&2
      exit 1
    fi
    refuse_unresolvable_pending_marker
  fi

  reset_hash="$(printf '%s\n' "$all_hashes" | first_line)"
  if [[ "$reset_hash" != "$pending_hash" ]]; then
    echo "The pending fingerprint does not match the existing identity; nothing was deleted." >&2
    exit 1
  fi
  reset_certificate_hashes="$(named_certificate_hashes)"
  reset_certificate_count="$(printf '%s\n' "$reset_certificate_hashes" | line_count)"
  if [[ "$reset_certificate_count" -ne 1 ||
      "$(printf '%s\n' "$reset_certificate_hashes" | first_line)" != "$reset_hash" ]]; then
    /bin/cat >&2 <<EOF
The exact-name certificate inventory is ambiguous or does not match the
interrupted identity. Nothing was deleted. Resolve duplicate or orphaned
certificates in Keychain Access, then retry.
EOF
    exit 1
  fi
  reset_key_label="$("$signing_helper" select-label "$login_keychain" "$reset_hash")"
  echo "Removing interrupted identity and its per-user trust: $pending_hash"
  /usr/bin/security delete-identity -Z "$pending_hash" -t "$login_keychain"
  remaining_identity_hashes="$(identity_hashes no)"
  remaining_certificate_count="$(named_certificate_count)"
  if [[ -n "$remaining_identity_hashes" || "$remaining_certificate_count" -ne 0 ]]; then
    echo "The interrupted identity was not completely deleted; its marker was retained." >&2
    exit 1
  fi
  require_key_label_absent "$reset_key_label"
  /bin/rm -f "$pending_marker"
  /bin/cat <<EOF
Interrupted setup state was removed. Start again with:

  ./BuildTools/setup-local-signing.sh
EOF
}

recreate_existing_identity() {
  local recreate_hash
  local recreate_certificate_hashes
  local recreate_certificate_count
  local recreate_key_label
  local remaining_identity_hashes
  local remaining_certificate_count

  if [[ "$all_count" -eq 1 ]]; then
    recreate_hash="$(printf '%s\n' "$all_hashes" | first_line)"
    if [[ -n "$pending_hash" && "$pending_hash" != "$recreate_hash" ]]; then
      echo "The pending fingerprint does not match the identity to recreate; nothing was deleted." >&2
      exit 1
    fi
    recreate_certificate_hashes="$(named_certificate_hashes)"
    recreate_certificate_count="$(printf '%s\n' "$recreate_certificate_hashes" | line_count)"
    if [[ "$recreate_certificate_count" -ne 1 ||
        "$(printf '%s\n' "$recreate_certificate_hashes" | first_line)" != "$recreate_hash" ]]; then
      /bin/cat >&2 <<EOF
The exact-name certificate inventory is ambiguous or does not match the one
identity selected for recreation. Nothing was deleted. Resolve duplicate or
orphaned certificates in Keychain Access, then retry.
EOF
      exit 1
    fi
    recreate_key_label="$("$signing_helper" select-label \
      "$login_keychain" "$recreate_hash")"
    # Record the exact identity before the first destructive operation. If
    # macOS or the script stops during deletion, a later plain setup run will
    # refuse to guess about the interrupted fingerprint.
    write_pending_hash "$recreate_hash"
    /bin/cat <<EOF
Removing the existing local identity and its per-user trust by fingerprint:

  $recreate_hash

This intentionally changes the app's signing identity. macOS will request the
app's privacy and Keychain permissions again after the next build.

macOS will first ask you to authorize removal of the old certificate's
per-user Code Signing trust.
EOF
    /usr/bin/security delete-identity -Z "$recreate_hash" -t "$login_keychain"
    remaining_identity_hashes="$(identity_hashes no)"
    if [[ -n "$remaining_identity_hashes" ]]; then
      echo "The exact identity still exists after deletion; refusing to continue." >&2
      exit 1
    fi
    remaining_certificate_count="$(named_certificate_count)"
    if [[ "$remaining_certificate_count" -ne 0 ]]; then
      echo "A matching certificate remains after exact identity deletion; refusing to continue." >&2
      exit 1
    fi
    require_key_label_absent "$recreate_key_label"
    /bin/rm -f "$pending_marker"
    pending_hash=""
    all_hashes=""
    all_count=0
    valid_hashes=""
    valid_count=0
  else
    recreate_certificate_count="$(named_certificate_count)"
    if [[ "$recreate_certificate_count" -ne 0 ]]; then
      /bin/cat >&2 <<EOF
The login Keychain contains a certificate named "$identity_name" without an
enumerable matching identity. Even --recreate will not guess which orphaned
item is safe to delete. Resolve it in Keychain Access, then retry.
EOF
      exit 1
    fi
    if [[ -n "$pending_hash" ]]; then
      refuse_unresolvable_pending_marker
    fi
  fi
}

use_existing_identity() {
  local valid_hash

  identity_hash="$(printf '%s\n' "$all_hashes" | first_line)"
  if [[ "$valid_count" -eq 1 ]]; then
    valid_hash="$(printf '%s\n' "$valid_hashes" | first_line)"
    if [[ "$valid_hash" != "$identity_hash" ]]; then
      echo "The basic and Code Signing identity searches disagree; nothing was changed." >&2
      exit 1
    fi
    if [[ -n "$pending_hash" && "$pending_hash" != "$identity_hash" ]]; then
      echo "The pending fingerprint does not match the valid identity; nothing was changed." >&2
      exit 1
    fi
    if [[ -n "$pending_hash" ]]; then
      echo "Resuming interrupted private-key setup for fingerprint: $identity_hash"
      resume_private_key "$identity_hash"
      if ! verify_code_signing_only_trust "$identity_hash" >/dev/null 2>&1; then
        export_existing_certificate "$identity_hash"
        trust_certificate
      fi
    else
      if ! verify_private_key "$identity_hash" ||
          ! verify_code_signing_only_trust "$identity_hash"; then
        /bin/cat >&2 <<EOF
The existing identity does not have this setup script's exact private-key
label, /usr/bin/codesign ACL, apple-tool:/apple: partition list, and
Code Signing-only per-user trust. Nothing was changed. Replace this legacy or
incomplete identity explicitly with:

  ./BuildTools/setup-local-signing.sh --recreate
EOF
        exit 1
      fi
      echo "Reusing verified signing identity: $identity_hash"
    fi
  else
    if [[ -z "$pending_hash" || "$pending_hash" != "$identity_hash" ]]; then
      /bin/cat >&2 <<EOF
An invalid or untrusted identity is named "$identity_name", but it was not
created by a resumable run of this script. It will not be modified or trusted
automatically. Replace it explicitly with:

  ./BuildTools/setup-local-signing.sh --recreate
EOF
      exit 1
    fi
    export_existing_certificate "$identity_hash"
    if ! /usr/bin/openssl x509 -checkend 0 -noout -in "$certificate"; then
      echo "The pending signing certificate is expired or otherwise unusable." >&2
      exit 1
    fi
    echo "Resuming interrupted setup for fingerprint: $identity_hash"
    resume_private_key "$identity_hash"
    trust_certificate
  fi
}

create_identity() {
  local certificate_count
  local serial
  local key_label
  local identity_archive
  local archive_password

  certificate_count="$(named_certificate_count)"
  if [[ "$certificate_count" -ne 0 ]]; then
    /bin/cat >&2 <<EOF
The login Keychain contains a certificate named "$identity_name" without an
enumerable matching identity. Nothing was changed. Resolve that orphaned item
in Keychain Access before retrying; --recreate will not guess which item to
delete.
EOF
    exit 1
  fi
  if [[ -n "$pending_hash" ]]; then
    refuse_unresolvable_pending_marker
  fi

  echo "Creating local code-signing identity: $identity_name"
  serial="$(/usr/bin/openssl rand -hex 16)"
  /usr/bin/openssl req \
    -x509 \
    -newkey rsa:3072 \
    -sha256 \
    -nodes \
    -days 7300 \
    -set_serial "0x$serial" \
    -subj "/CN=$identity_name/O=BSSID Picker Local" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,digitalSignature,keyCertSign" \
    -addext "extendedKeyUsage=critical,codeSigning" \
    -addext "subjectKeyIdentifier=hash" \
    -addext "authorityKeyIdentifier=keyid:always" \
    -keyout "$private_key" \
    -out "$certificate" >/dev/null 2>&1

  identity_hash="$(certificate_hash "$certificate")"
  write_pending_hash "$identity_hash"
  key_label="$(key_label_for_hash "$identity_hash")"
  identity_archive="$work_dir/$key_label.p12"

  archive_password="$(/usr/bin/openssl rand -hex 32)"
  /usr/bin/openssl pkcs12 \
    -export \
    -name "$key_label" \
    -inkey "$private_key" \
    -in "$certificate" \
    -out "$identity_archive" \
    -keypbe PBE-SHA1-3DES \
    -certpbe PBE-SHA1-3DES \
    -macalg sha1 \
    -passout "pass:$archive_password"

  /usr/bin/security import "$identity_archive" \
    -k "$login_keychain" \
    -f pkcs12 \
    -P "$archive_password" \
    -x \
    -T /usr/bin/codesign >/dev/null
  archive_password=""

  configure_private_key "$identity_hash"
  trust_certificate
}

verify_completed_setup() {
  if ! verify_code_signing_only_trust "$identity_hash"; then
    /bin/cat >&2 <<EOF
The certificate does not have exactly the Code Signing-only per-user trust
installed by this setup script. Nothing was deleted; rerun this script to
resume the recorded fingerprint or use --reset-pending to remove it.
EOF
    return 1
  fi

  valid_hashes="$(identity_hashes yes)"
  valid_count="$(printf '%s\n' "$valid_hashes" | line_count)"
  if [[ "$valid_count" -ne 1 ||
      "$(printf '%s\n' "$valid_hashes" | first_line)" != "$identity_hash" ]]; then
    /bin/cat >&2 <<EOF
macOS does not report the fingerprint as one unique, valid Code Signing
identity. Nothing was deleted; rerun this script to resume the recorded
fingerprint or use --reset-pending to remove it.
EOF
    return 1
  fi

  if ! signing_probe "$identity_hash"; then
    /bin/cat >&2 <<EOF
The identity is valid, but /usr/bin/codesign could not use its private key.
The exact private-key ACL and partition list passed inspection, so this may be
a locked-Keychain or macOS security-service error. Signing test output:
EOF
    /bin/cat "$probe_log" >&2
    return 1
  fi
}

print_success() {
  /bin/rm -f "$pending_marker"
  /bin/cat <<EOF
Local signing setup is complete.

Identity: $identity_name
SHA-1:    $identity_hash
Keychain: $login_keychain

Build normally with:

  ./BuildTools/build-app.sh
EOF
}

main() {
  parse_arguments "$@"
  initialize_environment
  load_identity_inventory

  if [[ "$mode" == "reset" ]]; then
    reset_interrupted_setup
    return
  fi
  if [[ "$mode" == "recreate" ]]; then
    recreate_existing_identity
  fi

  if [[ "$all_count" -eq 1 ]]; then
    use_existing_identity
  else
    create_identity
  fi

  verify_completed_setup
  print_success
}

main "$@"
