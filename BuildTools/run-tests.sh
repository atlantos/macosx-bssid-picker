#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail

umask 077

script_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
project_dir="$(cd "$script_dir/.." && pwd -P)"
readonly project_dir
readonly deployment_target="13.0"
readonly release_test_script="$project_dir/Tests/create-release-tests.sh"

sdk_path=""
target=""
test_root=""

die() {
  printf 'run-tests: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local exit_status=$?
  trap - EXIT
  if [[ -n "$test_root" ]]; then
    /bin/rm -rf "$test_root"
  fi
  exit "$exit_status"
}

resolve_sdk() {
  if [[ -n "${BSSID_PICKER_SDK_PATH:-}" ]]; then
    sdk_path="$BSSID_PICKER_SDK_PATH"
  elif [[ -d /Library/Developer/CommandLineTools/SDKs/MacOSX15.sdk ]]; then
    sdk_path=/Library/Developer/CommandLineTools/SDKs/MacOSX15.sdk
  elif ! sdk_path="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"; then
    die "the active macOS SDK could not be located"
  fi
  [[ -d "$sdk_path" ]] || die "SDK not found: $sdk_path"
}

resolve_target() {
  case "$(/usr/bin/uname -m)" in
    arm64) target="arm64-apple-macosx$deployment_target" ;;
    x86_64) target="x86_64-apple-macosx$deployment_target" ;;
    *) die "unsupported build architecture" ;;
  esac
}

main() {
  [[ "$#" -eq 0 ]] || die "this command does not accept positional arguments"
  [[ -x "$release_test_script" ]] ||
    die "release-helper test script not found or not executable: $release_test_script"
  resolve_sdk
  resolve_target

  local temporary_parent="${TMPDIR:-/tmp}"
  [[ -d "$temporary_parent" ]] || die "temporary directory not found: $temporary_parent"
  test_root="$(/usr/bin/mktemp -d "${temporary_parent%/}/bssid-picker-tests.XXXXXX")"
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  local -a app_sources=(
    "$project_dir/App/WiFiModels.swift"
    "$project_dir/App/MACRegistrantDatabase.swift"
    "$project_dir/App/AutomaticUpdateInterval.swift"
    "$project_dir/App/WiFiInformationElements.swift"
    "$project_dir/App/AppDiagnostics.swift"
    "$project_dir/App/ScanColumnModel.swift"
    "$project_dir/App/ScanInformationElementPresenter.swift"
    "$project_dir/App/ScanStandardsModel.swift"
    "$project_dir/App/ScanRowModel.swift"
    "$project_dir/App/ScanTableModel.swift"
    "$project_dir/App/ScanExport.swift"
  )
  local -a test_sources=(
    "$project_dir/Tests/TestSupport.swift"
    "$project_dir/Tests/MACRegistrantDatabaseTests.swift"
    "$project_dir/Tests/ScanExportTests.swift"
  )
  local candidate
  local occurrence_count
  local source
  for source in "${app_sources[@]}" "${test_sources[@]}"; do
    [[ -f "$source" ]] || die "required source file not found: $source"
  done
  for candidate in "$project_dir"/Tests/*.swift; do
    occurrence_count=0
    for source in "${test_sources[@]}"; do
      if [[ "$source" == "$candidate" ]]; then
        ((occurrence_count += 1))
      fi
    done
    [[ "$occurrence_count" -eq 1 ]] ||
      die "test source must appear exactly once in test_sources: $candidate"
  done

  /usr/bin/xcrun swiftc \
    -swift-version 5 \
    -parse-as-library \
    -target "$target" \
    -sdk "$sdk_path" \
    -module-cache-path "$test_root/module-cache" \
    -warnings-as-errors \
    -Onone \
    -framework AppKit \
    -framework Foundation \
    -framework UniformTypeIdentifiers \
    "${app_sources[@]}" \
    "${test_sources[@]}" \
    -o "$test_root/regression-tests"

  "$test_root/regression-tests"
  "$release_test_script"
}

main "$@"
