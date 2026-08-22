#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail

umask 077

# The test script doubles as the fake GitHub CLI through a temporary symlink.
# Keeping the mock here avoids executing any generated shell source.
mock_gh() {
  {
    printf 'gh'
    printf ' %q' "$@"
    printf '\n'
  } >>"${MOCK_GH_LOG:?}"

  case "${1:-} ${2:-}" in
    "api repos/atlantos/macosx-bssid-picker/immutable-releases")
      printf '%s\n' "${MOCK_RELEASE_IMMUTABLE:-true}"
      ;;
    "run list")
      case "${MOCK_CI_RESULT:-success}" in
        success | mutate)
          if [[ "${MOCK_CI_RESULT:-success}" == mutate &&
            ! -e "${MOCK_MUTATION_MARKER:?}" ]]; then
            /usr/bin/touch "${MOCK_WORK_DIR:?}/changed-during-validation"
            /usr/bin/touch "$MOCK_MUTATION_MARKER"
          fi
          printf 'completed|success|%s|https://example.invalid/ci\n' \
            "${MOCK_CI_HEAD_SHA:?}"
          ;;
        failure)
          printf 'completed|failure|%s|https://example.invalid/ci\n' \
            "${MOCK_CI_HEAD_SHA:?}"
          ;;
        missing)
          ;;
        error)
          exit 1
          ;;
        *)
          printf 'mock gh: unsupported CI result\n' >&2
          exit 2
          ;;
      esac
      ;;
    *)
      printf 'mock gh: unexpected invocation: %s\n' "$*" >&2
      exit 2
      ;;
  esac
}

mock_ssh() {
  local argument
  local host_seen=false
  local service=""

  for argument in "$@"; do
    if [[ "$argument" == git@github.com ]]; then
      host_seen=true
    fi
    case "$argument" in
      "git-upload-pack 'atlantos/macosx-bssid-picker.git'")
        service=upload
        ;;
      "git-receive-pack 'atlantos/macosx-bssid-picker.git'")
        service=receive
        ;;
    esac
  done
  [[ "$host_seen" == true && -n "$service" ]] || {
    printf 'mock ssh: unexpected invocation: %s\n' "$*" >&2
    exit 2
  }

  case "$service" in
    upload) exec /usr/bin/git-upload-pack "${MOCK_ORIGIN_DIR:?}" ;;
    receive) exec /usr/bin/git-receive-pack "${MOCK_ORIGIN_DIR:?}" ;;
  esac
}

case "${0##*/}" in
  gh)
    mock_gh "$@"
    exit
    ;;
  ssh)
    mock_ssh "$@"
    exit
    ;;
esac

script_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
project_dir="$(cd "$script_dir/.." && pwd -P)"
readonly project_dir
readonly source_helper="$project_dir/BuildTools/create-release.sh"
readonly source_plist="$project_dir/App/Info.plist"
readonly source_workflow="$project_dir/.github/workflows/release.yml"

test_root=""
case_root=""
work_dir=""
origin_dir=""
gh_log=""
helper_output=""
test_count=0

die() {
  printf 'create-release-tests: %s\n' "$*" >&2
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

new_repository() {
  test_count=$((test_count + 1))
  case_root="$test_root/case-$test_count"
  work_dir="$case_root/work"
  origin_dir="$case_root/origin.git"
  gh_log="$case_root/gh.log"
  export MOCK_GH_LOG="$gh_log"
  export MOCK_ORIGIN_DIR="$origin_dir"
  export MOCK_WORK_DIR="$work_dir"
  export MOCK_MUTATION_MARKER="$case_root/mutation-complete"

  /bin/mkdir -p \
    "$work_dir/App" \
    "$work_dir/BuildTools" \
    "$work_dir/.github/workflows"
  /usr/bin/touch "$gh_log"
  /usr/bin/git init --quiet --bare "$origin_dir"
  /usr/bin/git init --quiet "$work_dir"
  /usr/bin/git -C "$work_dir" symbolic-ref HEAD refs/heads/main

  /bin/cp "$source_helper" "$work_dir/BuildTools/create-release.sh"
  /bin/cp "$source_plist" "$work_dir/App/Info.plist"
  /bin/cp "$source_workflow" "$work_dir/.github/workflows/release.yml"
  /bin/chmod 700 "$work_dir/BuildTools/create-release.sh"
  /usr/libexec/PlistBuddy \
    -c 'Set :CFBundleShortVersionString 0.1.0' \
    -c 'Set :CFBundleVersion 1' \
    "$work_dir/App/Info.plist"

  /usr/bin/git -C "$work_dir" add .
  /usr/bin/git -C "$work_dir" commit --quiet -m 'Initial test release'
  /usr/bin/git -C "$work_dir" remote add origin \
    git@github.com:atlantos/macosx-bssid-picker.git
  /usr/bin/git -C "$work_dir" push --quiet --set-upstream origin main
}

run_helper_success() {
  local ci_result="$1"
  shift
  local output_file="$case_root/helper-output"
  local ci_head_sha
  ci_head_sha="${MOCK_CI_HEAD_OVERRIDE:-$(
    /usr/bin/git -C "$work_dir" rev-parse HEAD
  )}"

  if ! (
    cd "$work_dir"
    MOCK_CI_HEAD_SHA="$ci_head_sha" MOCK_CI_RESULT="$ci_result" \
      ./BuildTools/create-release.sh --yes "$@"
  ) >"$output_file" 2>&1; then
    helper_output="$(<"$output_file")"
    die "helper unexpectedly failed: $helper_output"
  fi
  helper_output="$(<"$output_file")"
  assert_no_temporary_refs
}

run_helper_failure() {
  local expected="$1"
  local ci_result="$2"
  shift 2
  local output_file="$case_root/helper-output"
  local ci_head_sha
  ci_head_sha="${MOCK_CI_HEAD_OVERRIDE:-$(
    /usr/bin/git -C "$work_dir" rev-parse HEAD
  )}"

  if (
    cd "$work_dir"
    MOCK_CI_HEAD_SHA="$ci_head_sha" MOCK_CI_RESULT="$ci_result" \
      ./BuildTools/create-release.sh --yes "$@"
  ) >"$output_file" 2>&1; then
    die "helper unexpectedly succeeded"
  fi
  helper_output="$(<"$output_file")"
  [[ "$helper_output" == *"$expected"* ]] ||
    die "expected failure containing '$expected'; got: $helper_output"
  assert_no_temporary_refs
}

assert_no_temporary_refs() {
  local refs
  refs="$(/usr/bin/git -C "$work_dir" for-each-ref \
    --format='%(refname)' refs/bssid-picker/create-release-)"
  [[ -z "$refs" ]] || die "temporary release refs were not cleaned up: $refs"
}

assert_tag_absent() {
  local tag="$1"
  if /usr/bin/git -C "$work_dir" show-ref --verify --quiet "refs/tags/$tag"; then
    die "unexpected local tag: $tag"
  fi
  if /usr/bin/git --git-dir="$origin_dir" \
    show-ref --verify --quiet "refs/tags/$tag"; then
    die "unexpected origin tag: $tag"
  fi
}

pass() {
  printf 'PASS %s\n' "$1"
}

test_dry_run() {
  new_repository
  run_helper_success success --dry-run 0.1.0
  [[ "$helper_output" == *"Dry run passed"* ]] ||
    die "dry-run success was not reported"
  assert_tag_absent v0.1.0
  pass "dry run has no tag side effects"
}

test_successful_release() {
  local head_commit
  local local_target
  local remote_target
  local tag_count
  local tag_subject

  new_repository
  /usr/bin/git -C "$work_dir" tag -a v999.0.0 -m 'Local-only tag'
  /usr/bin/git -C "$work_dir" config tag.gpgSign true
  /usr/bin/git -C "$work_dir" config push.gpgSign true
  /usr/bin/git -C "$work_dir" config push.followTags true
  head_commit="$(/usr/bin/git -C "$work_dir" rev-parse HEAD)"
  run_helper_success success 0.1.0

  [[ "$(/usr/bin/git -C "$work_dir" cat-file -t refs/tags/v0.1.0)" == tag ]] ||
    die "the local release ref is not an annotated tag"
  [[ "$(/usr/bin/git --git-dir="$origin_dir" \
    cat-file -t refs/tags/v0.1.0)" == tag ]] ||
    die "the origin release ref is not an annotated tag"
  local_target="$(/usr/bin/git -C "$work_dir" rev-parse 'refs/tags/v0.1.0^{commit}')"
  remote_target="$(/usr/bin/git --git-dir="$origin_dir" \
    rev-parse 'refs/tags/v0.1.0^{commit}')"
  [[ "$local_target" == "$head_commit" && "$remote_target" == "$head_commit" ]] ||
    die "the release tag does not target the validated HEAD"
  tag_subject="$(/usr/bin/git -C "$work_dir" for-each-ref \
    --format='%(contents:subject)' refs/tags/v0.1.0)"
  [[ "$tag_subject" == 'Release v0.1.0' ]] ||
    die "unexpected annotated-tag message: $tag_subject"
  tag_count="$(/usr/bin/git --git-dir="$origin_dir" for-each-ref \
    --format='%(refname)' refs/tags | /usr/bin/wc -l | /usr/bin/tr -d '[:space:]')"
  [[ "$tag_count" == 1 ]] || die "the push created unexpected tag refs"
  /usr/bin/grep -F -- "--commit $head_commit" "$gh_log" >/dev/null ||
    die "CI was not checked for the exact release commit"
  /usr/bin/grep -F -- "--branch main" "$gh_log" >/dev/null ||
    die "CI was not restricted to the release branch"
  pass "release ignores local tags and overrides signing/follow-tag config"
}

test_dirty_tree() {
  new_repository
  /usr/bin/touch "$work_dir/untracked-file"
  run_helper_failure "worktree must be clean" success 0.1.0
  assert_tag_absent v0.1.0
  [[ ! -s "$gh_log" ]] || die "dirty-tree rejection contacted GitHub"
  pass "dirty worktree is rejected before remote checks"
}

test_multiple_push_urls() {
  new_repository
  /usr/bin/git -C "$work_dir" remote set-url --add --push origin \
    git@github.com:atlantos/macosx-bssid-picker.git
  /usr/bin/git -C "$work_dir" remote set-url --add --push origin \
    git@github.com:atlantos/macosx-bssid-picker.git
  run_helper_failure "exactly one canonical push URL" success 0.1.0
  assert_tag_absent v0.1.0
  pass "multiple push destinations are rejected"
}

test_version_mismatch() {
  new_repository
  run_helper_failure \
    "does not match CFBundleShortVersionString 0.1.0" success 0.1.1
  assert_tag_absent v0.1.1
  pass "version mismatch is rejected"
}

test_ci_failure() {
  local head_commit

  new_repository
  head_commit="$(/usr/bin/git -C "$work_dir" rev-parse HEAD)"
  run_helper_failure "CI did not succeed for HEAD" failure 0.1.0
  assert_tag_absent v0.1.0
  /usr/bin/grep -F -- "--commit $head_commit" "$gh_log" >/dev/null ||
    die "failed CI was not checked for the exact release commit"
  pass "failed CI prevents tag creation"
}

test_wrong_ci_commit() {
  new_repository
  MOCK_CI_HEAD_OVERRIDE=0000000000000000000000000000000000000000 \
    run_helper_failure "unexpected commit" success 0.1.0
  assert_tag_absent v0.1.0
  pass "CI result for another commit is rejected"
}

test_state_change_during_validation() {
  new_repository
  run_helper_failure "worktree must be clean" mutate 0.1.0
  assert_tag_absent v0.1.0
  pass "state changes between validation passes prevent release"
}

test_slash_tag_is_not_a_release() {
  new_repository
  /usr/bin/git -C "$work_dir" tag -a vexperimental/v999.0.0 \
    -m 'Non-release namespaced tag'
  /usr/bin/git -C "$work_dir" push --quiet origin \
    refs/tags/vexperimental/v999.0.0:refs/tags/vexperimental/v999.0.0
  run_helper_success success --dry-run 0.1.0
  assert_tag_absent v0.1.0
  pass "slash-containing v tags do not become release baselines"
}

test_build_monotonicity() {
  new_repository
  /usr/bin/git -C "$work_dir" tag -a v0.1.0 -m 'Release v0.1.0'
  /usr/bin/git -C "$work_dir" push --quiet origin \
    refs/tags/v0.1.0:refs/tags/v0.1.0

  /usr/libexec/PlistBuddy \
    -c 'Set :CFBundleShortVersionString 0.2.0' \
    "$work_dir/App/Info.plist"
  /usr/bin/git -C "$work_dir" add App/Info.plist
  /usr/bin/git -C "$work_dir" commit --quiet -m 'Bump version without build'
  /usr/bin/git -C "$work_dir" push --quiet origin main
  run_helper_failure "CFBundleVersion 1 must exceed 1 from v0.1.0" success 0.2.0
  assert_tag_absent v0.2.0

  /usr/libexec/PlistBuddy -c 'Set :CFBundleVersion 2' \
    "$work_dir/App/Info.plist"
  /usr/bin/git -C "$work_dir" add App/Info.plist
  /usr/bin/git -C "$work_dir" commit --quiet -m 'Increment build number'
  /usr/bin/git -C "$work_dir" push --quiet origin main
  run_helper_success success --dry-run 0.2.0
  assert_tag_absent v0.2.0
  pass "build number must increase across releases"
}

test_large_version_components() {
  local next_build=1000000000000000000000000000000000000000
  local next_version=100000000000000000000.0.0
  local previous_build=999999999999999999999999999999999999999
  local previous_version=99999999999999999999.0.0

  new_repository
  /usr/libexec/PlistBuddy \
    -c "Set :CFBundleShortVersionString $previous_version" \
    -c "Set :CFBundleVersion $previous_build" \
    "$work_dir/App/Info.plist"
  /usr/bin/git -C "$work_dir" add App/Info.plist
  /usr/bin/git -C "$work_dir" commit --quiet -m 'Set large prior version'
  /usr/bin/git -C "$work_dir" push --quiet origin main
  /usr/bin/git -C "$work_dir" tag -a "v$previous_version" \
    -m "Release v$previous_version"
  /usr/bin/git -C "$work_dir" push --quiet origin \
    "refs/tags/v$previous_version:refs/tags/v$previous_version"

  /usr/libexec/PlistBuddy \
    -c "Set :CFBundleShortVersionString $next_version" \
    -c "Set :CFBundleVersion $next_build" \
    "$work_dir/App/Info.plist"
  /usr/bin/git -C "$work_dir" add App/Info.plist
  /usr/bin/git -C "$work_dir" commit --quiet -m 'Set larger release metadata'
  /usr/bin/git -C "$work_dir" push --quiet origin main
  run_helper_success success --dry-run "$next_version"
  assert_tag_absent "v$next_version"
  pass "large version and build numbers compare without integer overflow"
}

main() {
  [[ "$#" -eq 0 ]] || die "this command does not accept positional arguments"
  [[ -f "$source_helper" ]] || die "release helper not found: $source_helper"
  [[ -f "$source_plist" ]] || die "Info.plist not found: $source_plist"
  [[ -f "$source_workflow" ]] || die "release workflow not found: $source_workflow"
  /bin/bash -n "$source_helper"

  local temporary_parent="${TMPDIR:-/tmp}"
  [[ -d "$temporary_parent" ]] ||
    die "temporary directory not found: $temporary_parent"
  test_root="$(/usr/bin/mktemp -d \
    "${temporary_parent%/}/bssid-picker-release-tests.XXXXXX")"
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  /bin/mkdir -p "$test_root/fake-bin" "$test_root/home" "$test_root/gh-config"
  /bin/ln -s "$script_dir/create-release-tests.sh" "$test_root/fake-bin/gh"
  /bin/ln -s "$script_dir/create-release-tests.sh" "$test_root/fake-bin/ssh"

  export PATH="$test_root/fake-bin:/usr/bin:/bin"
  export HOME="$test_root/home"
  export GH_CONFIG_DIR="$test_root/gh-config"
  export GH_PROMPT_DISABLED=1
  export GIT_CONFIG_NOSYSTEM=1
  export GIT_CONFIG_GLOBAL=/dev/null
  export GIT_TERMINAL_PROMPT=0
  export GIT_SSH="$test_root/fake-bin/ssh"
  export GIT_SSH_VARIANT=ssh
  export GIT_AUTHOR_NAME='Release Test'
  export GIT_AUTHOR_EMAIL='release-test@example.invalid'
  export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME"
  export GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"

  test_dry_run
  test_successful_release
  test_dirty_tree
  test_multiple_push_urls
  test_version_mismatch
  test_ci_failure
  test_wrong_ci_commit
  test_state_change_during_validation
  test_slash_tag_is_not_a_release
  test_build_monotonicity
  test_large_version_components
  printf 'Executed %d release-helper tests; 0 failed.\n' "$test_count"
}

main "$@"
