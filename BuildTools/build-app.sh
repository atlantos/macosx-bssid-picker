#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail

umask 077

script_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
project_dir="$(cd "$script_dir/.." && pwd -P)"
readonly project_dir
readonly app_name="BSSID Picker.app"
readonly executable_name="BSSIDPicker"
readonly icon_name="AppIcon.png"
readonly license_name="LICENSE.txt"
readonly bundle_identifier="local.bssid-picker.app"
readonly default_signing_identity="BSSID Picker Local Signing"
readonly deployment_target="13.0"
readonly build_dir="$project_dir/build"
readonly app_dir="$build_dir/$app_name"
readonly entitlements_path="$project_dir/App/BSSIDPicker.entitlements"
readonly required_boolean_entitlements=(
  "com.apple.security.app-sandbox"
  "com.apple.security.files.user-selected.read-write"
  "com.apple.security.network.client"
  "com.apple.security.personal-information.location"
)

signing_identity="${BSSID_PICKER_SIGNING_IDENTITY:-$default_signing_identity}"
resolved_signing_identity="$signing_identity"
signing_keychain=""
sdk_path=""
target=""
stage_root=""
module_cache=""

readonly swift_sources=(
  "$project_dir/App/WiFiModels.swift"
  "$project_dir/App/AppMetadata.swift"
  "$project_dir/App/MACRegistrantDatabase.swift"
  "$project_dir/App/LaunchAtLoginService.swift"
  "$project_dir/App/WiFiInformationElements.swift"
  "$project_dir/App/AppDiagnostics.swift"
  "$project_dir/App/ConnectionHistory.swift"
  "$project_dir/App/CoreWLANAdapter.swift"
  "$project_dir/App/CredentialProvider.swift"
  "$project_dir/App/StrictBSSIDService.swift"
  "$project_dir/App/CoreWLANService.swift"
  "$project_dir/App/AutomaticUpdateInterval.swift"
  "$project_dir/App/SettingsStore.swift"
  "$project_dir/App/LockPolicy.swift"
  "$project_dir/App/LocationAuthorizationController.swift"
  "$project_dir/App/StatusSymbols.swift"
  "$project_dir/App/ApplicationMenuController.swift"
  "$project_dir/App/MenuBarController.swift"
  "$project_dir/App/MenuPopoverViewController.swift"
  "$project_dir/App/SettingsWindowController.swift"
  "$project_dir/App/AboutWindowController.swift"
  "$project_dir/App/ScanColumnModel.swift"
  "$project_dir/App/ScanInformationElementPresenter.swift"
  "$project_dir/App/ScanStandardsModel.swift"
  "$project_dir/App/ScanRowModel.swift"
  "$project_dir/App/ScanTableModel.swift"
  "$project_dir/App/ScanInspectorDocument.swift"
  "$project_dir/App/ScanInspectorView.swift"
  "$project_dir/App/ScanExport.swift"
  "$project_dir/App/ScanWindowSupport.swift"
  "$project_dir/App/ScanWindowController.swift"
  "$project_dir/App/ApplicationController.swift"
  "$project_dir/App/AppDelegate.swift"
  "$project_dir/App/main.swift"
)

die() {
  printf 'build-app: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local exit_status=$?
  trap - EXIT
  if [[ -n "$stage_root" ]]; then
    /bin/rm -rf "$stage_root"
  fi
  if [[ -n "$module_cache" ]]; then
    /bin/rm -rf "$module_cache"
  fi
  exit "$exit_status"
}

validate_arguments() {
  if [[ "$#" -ne 0 ]]; then
    die "this command does not accept positional arguments"
  fi
  if [[ -z "$signing_identity" || "$signing_identity" == *$'\n'* ||
      "$signing_identity" == *$'\r'* ]]; then
    die "BSSID_PICKER_SIGNING_IDENTITY must be a nonempty, single-line value"
  fi
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || die "required source file not found: $path"
}

require_boolean_entitlement() {
  local plist="$1"
  local key="$2"
  local value
  if ! value="$(/usr/libexec/PlistBuddy -c "Print :$key" "$plist" 2>/dev/null)" ||
      [[ "$value" != "true" ]]; then
    die "required entitlement must be present and enabled: $key"
  fi
}

validate_entitlements() {
  local entitlement_count
  local key

  for key in "${required_boolean_entitlements[@]}"; do
    require_boolean_entitlement "$entitlements_path" "$key"
  done

  # Keep the sandbox profile auditable. Adding a capability must be an explicit
  # build-system change rather than an unnoticed edit to the plist.
  entitlement_count="$(/usr/libexec/PlistBuddy -c Print "$entitlements_path" |
    /usr/bin/awk -F ' = ' 'NF == 2 { count++ } END { print count + 0 }')"
  [[ "$entitlement_count" -eq "${#required_boolean_entitlements[@]}" ]] ||
    die "the entitlement file must contain only the required sandbox capabilities"
}

validate_inputs() {
  local configured_bundle_identifier
  local configured_deployment_target
  local configured_executable
  local configured_icon
  local configured_package_type
  local occurrence_count
  local candidate
  local source
  require_file "$project_dir/App/Info.plist"
  require_file "$project_dir/App/$icon_name"
  require_file "$project_dir/App/PrivateWiFiShim.h"
  require_file "$project_dir/App/PrivateWiFiShim.m"
  require_file "$project_dir/LICENSE"
  require_file "$script_dir/atomic-install.c"
  require_file "$entitlements_path"
  for source in "${swift_sources[@]}"; do
    require_file "$source"
  done
  for candidate in "$project_dir"/App/*.swift; do
    occurrence_count=0
    for source in "${swift_sources[@]}"; do
      if [[ "$source" == "$candidate" ]]; then
        ((occurrence_count += 1))
      fi
    done
    [[ "$occurrence_count" -eq 1 ]] ||
      die "Swift source must appear exactly once in swift_sources: $candidate"
  done
  /usr/bin/plutil -lint \
    "$project_dir/App/Info.plist" \
    "$entitlements_path" >/dev/null
  validate_entitlements

  configured_bundle_identifier="$(/usr/libexec/PlistBuddy \
    -c 'Print :CFBundleIdentifier' "$project_dir/App/Info.plist")"
  [[ "$configured_bundle_identifier" == "$bundle_identifier" ]] ||
    die "CFBundleIdentifier must be $bundle_identifier"

  configured_deployment_target="$(/usr/libexec/PlistBuddy \
    -c 'Print :LSMinimumSystemVersion' "$project_dir/App/Info.plist")"
  [[ "$configured_deployment_target" == "$deployment_target" ]] ||
    die "LSMinimumSystemVersion must match build target $deployment_target"

  configured_executable="$(/usr/libexec/PlistBuddy \
    -c 'Print :CFBundleExecutable' "$project_dir/App/Info.plist")"
  [[ "$configured_executable" == "$executable_name" ]] ||
    die "CFBundleExecutable must be $executable_name"

  configured_package_type="$(/usr/libexec/PlistBuddy \
    -c 'Print :CFBundlePackageType' "$project_dir/App/Info.plist")"
  [[ "$configured_package_type" == "APPL" ]] ||
    die "CFBundlePackageType must be APPL"

  configured_icon="$(/usr/libexec/PlistBuddy \
    -c 'Print :CFBundleIconFile' "$project_dir/App/Info.plist")"
  [[ "$configured_icon" == "$icon_name" ]] ||
    die "CFBundleIconFile must be $icon_name"
}

resolve_sdk() {
  if [[ -n "${BSSID_PICKER_SDK_PATH:-}" ]]; then
    sdk_path="$BSSID_PICKER_SDK_PATH"
  elif [[ -d /Library/Developer/CommandLineTools/SDKs/MacOSX15.sdk ]]; then
    # The app intentionally uses only public SDK-15-era APIs at compile time;
    # its newer/private Wi-Fi path is resolved dynamically. A versioned SDK
    # also avoids a transient Command Line Tools state where MacOSX.sdk and
    # swiftc come from different point releases and cannot import SwiftShims.
    sdk_path=/Library/Developer/CommandLineTools/SDKs/MacOSX15.sdk
  elif ! sdk_path="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"; then
    die "the active macOS SDK could not be located"
  fi
  [[ -d "$sdk_path" ]] || die "SDK not found: $sdk_path"
}

resolve_target() {
  local architecture
  architecture="$(/usr/bin/uname -m)"
  case "$architecture" in
    arm64|x86_64) target="$architecture-apple-macosx$deployment_target" ;;
    *) die "unsupported build architecture: $architecture" ;;
  esac
}

resolve_login_keychain() {
  local output
  if ! output="$(/usr/bin/security login-keychain 2>/dev/null)"; then
    die "the login Keychain could not be queried"
  fi
  signing_keychain="$(printf '%s\n' "$output" |
    /usr/bin/sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//')"
  if [[ -z "$signing_keychain" || ! -f "$signing_keychain" ]]; then
    die "the login Keychain containing the local signing identity was not found"
  fi
}

identity_hashes_named() {
  local listing="$1"
  printf '%s\n' "$listing" |
    /usr/bin/awk -F '"' -v wanted="$signing_identity" '
      $2 == wanted {
        value = $1
        sub(/^[[:space:]]*[0-9]+\)[[:space:]]*/, "", value)
        sub(/[[:space:]].*$/, "", value)
        value = toupper(value)
        if (!seen[value]++) print value
      }
    '
}

resolve_signing_identity() {
  local identity_listing
  local identity_matches
  local identity_count

  if [[ "$signing_identity" == "-" ]]; then
    printf '%s\n' \
      "Warning: using an ad-hoc signature; privacy and Keychain approvals may reset after rebuilding." >&2
    return
  fi

  if [[ "$signing_identity" == "$default_signing_identity" ]]; then
    resolve_login_keychain
  fi

  if [[ -n "$signing_keychain" ]]; then
    if ! identity_listing="$(/usr/bin/security find-identity -v -p codesigning \
        "$signing_keychain" 2>/dev/null)"; then
      die "the signing Keychain could not be searched for identities"
    fi
  elif ! identity_listing="$(/usr/bin/security find-identity -v -p codesigning \
      2>/dev/null)"; then
    die "the signing Keychain search list could not be searched for identities"
  fi

  identity_matches="$(identity_hashes_named "$identity_listing")"
  identity_count="$(printf '%s\n' "$identity_matches" |
    /usr/bin/awk 'NF { count++ } END { print count + 0 }')"

  if [[ "$identity_count" -eq 0 ]]; then
    /bin/cat >&2 <<EOF
Code-signing identity not found: $signing_identity

Run the automated local-signing setup described in README.md, or select
another installed identity for this build:

  ./BuildTools/setup-local-signing.sh

  BSSID_PICKER_SIGNING_IDENTITY="identity name" ./BuildTools/build-app.sh

Ad-hoc signing is used by CI and automated GitHub release builds, and is also
available for diagnostics. It will not preserve Location Services or Keychain
approvals across rebuilds:

  BSSID_PICKER_SIGNING_IDENTITY=- ./BuildTools/build-app.sh
EOF
    exit 1
  fi

  if [[ "$identity_count" -ne 1 ]]; then
    /bin/cat >&2 <<EOF
More than one valid code-signing identity has the exact name:

  $signing_identity

Refusing to choose one ambiguously. Remove or rename the unintended duplicate,
or select a unique identity name with BSSID_PICKER_SIGNING_IDENTITY.
EOF
    printf '%s\n' "$identity_matches" >&2
    exit 1
  fi

  resolved_signing_identity="$(printf '%s\n' "$identity_matches" |
    /usr/bin/awk 'NF { print; exit }')"
}

prepare_staging_area() {
  local cache_parent="${TMPDIR:-/tmp}"
  [[ -d "$cache_parent" ]] || die "temporary directory not found: $cache_parent"
  /bin/mkdir -p -m 755 "$build_dir"
  stage_root="$(/usr/bin/mktemp -d "$build_dir/.bssid-picker-stage.XXXXXX")"
  module_cache="$(/usr/bin/mktemp -d "${cache_parent%/}/bssid-picker-module-cache.XXXXXX")"
}

assemble_bundle() {
  local contents_dir="$stage_root/$app_name/Contents"
  local resources_dir="$contents_dir/Resources"
  /bin/mkdir -p "$contents_dir/MacOS" "$resources_dir"
  /bin/cp "$project_dir/App/Info.plist" "$contents_dir/Info.plist"
  /bin/cp "$project_dir/App/$icon_name" "$resources_dir/$icon_name"
  /bin/cp "$project_dir/LICENSE" "$resources_dir/$license_name"
}

compile_application() {
  local staged_app="$stage_root/$app_name"
  local executable="$staged_app/Contents/MacOS/$executable_name"
  local shim_object="$stage_root/PrivateWiFiShim.o"

  /usr/bin/xcrun clang \
    -fobjc-arc \
    -fmodules \
    -fmodules-cache-path="$module_cache/clang" \
    -Wall \
    -Wextra \
    -Werror \
    -target "$target" \
    -isysroot "$sdk_path" \
    -c "$project_dir/App/PrivateWiFiShim.m" \
    -o "$shim_object"

  /usr/bin/xcrun swiftc \
    -swift-version 5 \
    -target "$target" \
    -sdk "$sdk_path" \
    -module-cache-path "$module_cache" \
    -import-objc-header "$project_dir/App/PrivateWiFiShim.h" \
    -warnings-as-errors \
    -O \
    -framework AppKit \
    -framework CoreLocation \
    -framework CoreWLAN \
    -framework Foundation \
    -framework ServiceManagement \
    "${swift_sources[@]}" \
    "$shim_object" \
    -o "$executable"
}

compile_atomic_installer() {
  /usr/bin/xcrun clang \
    -std=c11 \
    -Wall \
    -Wextra \
    -Werror \
    -target "$target" \
    -isysroot "$sdk_path" \
    "$script_dir/atomic-install.c" \
    -o "$stage_root/atomic-install"
}

sign_bundle() {
  local staged_app="$stage_root/$app_name"
  local entitlement_report
  local key
  local -a arguments=(
    --force
    --sign "$resolved_signing_identity"
    --identifier "$bundle_identifier"
    --options runtime
    --timestamp=none
    --generate-entitlement-der
    --entitlements "$entitlements_path"
  )
  if [[ -n "$signing_keychain" ]]; then
    arguments+=(--keychain "$signing_keychain")
  fi
  /usr/bin/codesign "${arguments[@]}" "$staged_app"
  /usr/bin/codesign --verify --deep --strict --verbose=2 "$staged_app"

  if ! entitlement_report="$(/usr/bin/codesign \
      --display --entitlements - "$staged_app" 2>&1)"; then
    die "the signed app's entitlements could not be inspected"
  fi
  for key in "${required_boolean_entitlements[@]}"; do
    if ! printf '%s\n' "$entitlement_report" | /usr/bin/awk -v expected="$key" '
      /^[[:space:]]*\[Key\][[:space:]]/ {
        current = $0
        sub(/^[[:space:]]*\[Key\][[:space:]]*/, "", current)
        next
      }
      /<key>[^<]+<\/key>/ {
        current = $0
        sub(/^.*<key>/, "", current)
        sub(/<\/key>.*$/, "", current)
        next
      }
      current == expected &&
        ($0 ~ /^[[:space:]]*\[Bool\][[:space:]]+true[[:space:]]*$/ ||
         $0 ~ /<true[[:space:]]*\/>/) { found = 1 }
      END { exit found ? 0 : 1 }
    '; then
      die "signed app is missing required enabled entitlement: $key"
    fi
  done
}

install_bundle() {
  "$stage_root/atomic-install" "$stage_root/$app_name" "$app_dir"
}

print_summary() {
  printf 'Built and signed: %s\n' "$app_dir"
  if [[ "$signing_identity" == "-" ]]; then
    printf 'Signing identity: ad hoc\n'
  else
    printf 'Signing identity: %s (%s)\n' \
      "$signing_identity" "$resolved_signing_identity"
  fi
}

main() {
  validate_arguments "$@"
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  validate_inputs
  resolve_sdk
  resolve_target
  resolve_signing_identity
  prepare_staging_area
  # Staging/cache roots are created under the process-private umask above.
  # Bundle contents use conventional read/execute modes rather than inheriting
  # the process-private staging umask.
  umask 022
  assemble_bundle
  compile_application
  compile_atomic_installer
  sign_bundle
  install_bundle
  print_summary
}

main "$@"
