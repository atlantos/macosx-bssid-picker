#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-only

set -euo pipefail

export LC_ALL=C
umask 077

script_dir="$(cd "$(/usr/bin/dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly script_dir
project_dir="$(cd "$script_dir/.." && pwd -P)"
readonly project_dir
readonly repository="atlantos/macosx-bssid-picker"
readonly release_branch="main"
readonly origin_name="origin"
readonly info_plist="$project_dir/App/Info.plist"
readonly temporary_ref_namespace="refs/bssid-picker/create-release-$$"

dry_run=false
assume_yes=false
version=""
gh_path=""
release_commit=""

die() {
  printf 'create-release: %s\n' "$*" >&2
  exit 1
}

usage() {
  /bin/cat <<'EOF'
Usage: ./BuildTools/create-release.sh [--dry-run] [--yes] VERSION

Validate and publish the annotated Git tag that triggers a GitHub Release.
VERSION must be a stable semantic version without a leading "v", for example:

  ./BuildTools/create-release.sh --dry-run 0.1.0
  ./BuildTools/create-release.sh 0.1.0

Options:
  --dry-run  Run every check, but do not create or push the tag.
  --yes      Skip the final interactive confirmation.
  -h, --help Show this help text.
EOF
}

parse_arguments() {
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --dry-run)
        dry_run=true
        ;;
      --yes)
        assume_yes=true
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      --*)
        die "unknown option: $1"
        ;;
      *)
        [[ -z "$version" ]] || die "only one VERSION may be supplied"
        version="$1"
        ;;
    esac
    shift
  done

  [[ -n "$version" ]] || {
    usage >&2
    die "VERSION is required"
  }
  if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    die "VERSION must use MAJOR.MINOR.PATCH without a leading v"
  fi
}

resolve_tools() {
  [[ -x /usr/bin/git ]] || die "Apple's git command was not found"
  [[ -x /usr/bin/plutil ]] || die "Apple's plutil command was not found"
  [[ -x /usr/libexec/PlistBuddy ]] || die "Apple's PlistBuddy command was not found"
  if ! gh_path="$(command -v gh)" || [[ -z "$gh_path" || ! -x "$gh_path" ]]; then
    die "GitHub CLI is required; install and authenticate gh before releasing"
  fi
  readonly gh_path
}

clear_temporary_refs() {
  local ref

  while IFS= read -r ref; do
    [[ -n "$ref" ]] || continue
    /usr/bin/git update-ref -d "$ref" >/dev/null
  done < <(
    /usr/bin/git for-each-ref --format='%(refname)' "$temporary_ref_namespace/"
  )
}

cleanup() {
  local exit_status=$?
  trap - EXIT
  clear_temporary_refs || true
  exit "$exit_status"
}

require_clean_main() {
  local branch
  local worktree_status

  branch="$(/usr/bin/git branch --show-current)"
  [[ "$branch" == "$release_branch" ]] ||
    die "releases must be created from the $release_branch branch"

  worktree_status="$(/usr/bin/git status --porcelain=v1 --untracked-files=normal)"
  [[ -z "$worktree_status" ]] ||
    die "the worktree must be clean before creating a release"

  /usr/bin/git remote get-url "$origin_name" >/dev/null 2>&1 ||
    die "the repository must have an $origin_name remote"
}

is_canonical_origin_url() {
  case "$1" in
    "git@github.com:$repository" | \
      "git@github.com:$repository.git" | \
      "ssh://git@github.com/$repository" | \
      "ssh://git@github.com/$repository.git" | \
      "https://github.com/$repository" | \
      "https://github.com/$repository.git")
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

require_canonical_origin() {
  local fetch_url
  local fetch_url_count=0
  local push_url
  local push_url_count=0

  while IFS= read -r fetch_url; do
    [[ -n "$fetch_url" ]] || continue
    ((fetch_url_count += 1))
    is_canonical_origin_url "$fetch_url" ||
      die "$origin_name fetch URL is not the canonical GitHub $repository repository"
  done < <(/usr/bin/git remote get-url --all "$origin_name")
  [[ "$fetch_url_count" -eq 1 ]] ||
    die "$origin_name must have exactly one canonical fetch URL"

  while IFS= read -r push_url; do
    [[ -n "$push_url" ]] || continue
    ((push_url_count += 1))
    is_canonical_origin_url "$push_url" ||
      die "$origin_name push URL is not the canonical GitHub $repository repository"
  done < <(/usr/bin/git remote get-url --push --all "$origin_name")
  [[ "$push_url_count" -eq 1 ]] ||
    die "$origin_name must have exactly one canonical push URL"

}

fetch_release_state() {
  clear_temporary_refs
  if ! /usr/bin/git fetch --no-tags "$origin_name" \
    "+refs/heads/$release_branch:refs/remotes/$origin_name/$release_branch" \
    "+refs/tags/v*:$(printf '%s' "$temporary_ref_namespace")/tags/v*"; then
    die "$origin_name/$release_branch and release tags could not be fetched"
  fi
}

capture_release_commit() {
  local remote_commit

  release_commit="$(/usr/bin/git rev-parse HEAD)"
  remote_commit="$(/usr/bin/git rev-parse \
    "refs/remotes/$origin_name/$release_branch")"
  [[ "$release_commit" == "$remote_commit" ]] ||
    die "HEAD must exactly match $origin_name/$release_branch before releasing"

  /usr/bin/git cat-file -e \
    "${release_commit}:.github/workflows/release.yml" ||
    die "the release workflow is not committed at HEAD"
  /usr/bin/git cat-file -e \
    "${release_commit}:BuildTools/create-release.sh" ||
    die "the release helper is not committed at HEAD"
  readonly release_commit
}

require_unchanged_release_commit() {
  local current_commit
  local remote_commit

  current_commit="$(/usr/bin/git rev-parse HEAD)"
  [[ "$current_commit" == "$release_commit" ]] ||
    die "HEAD changed after release validation; start again"

  remote_commit="$(/usr/bin/git rev-parse \
    "refs/remotes/$origin_name/$release_branch")"
  [[ "$remote_commit" == "$release_commit" ]] ||
    die "$origin_name/$release_branch changed after release validation; start again"
}

plist_type_at_revision() {
  local revision="$1"
  local key="$2"

  /usr/bin/git show "${revision}:App/Info.plist" |
    /usr/bin/plutil -type "$key" -o - -
}

plist_value_at_revision() {
  local revision="$1"
  local key="$2"

  /usr/bin/git show "${revision}:App/Info.plist" |
    /usr/bin/plutil -extract "$key" raw -o - -
}

compare_decimal() {
  local left="$1"
  local right="$2"

  if [[ "${#left}" -lt "${#right}" ]]; then
    printf '%s\n' -1
  elif [[ "${#left}" -gt "${#right}" ]]; then
    printf '%s\n' 1
  elif [[ "$left" == "$right" ]]; then
    printf '%s\n' 0
  elif [[ "$left" < "$right" ]]; then
    printf '%s\n' -1
  else
    printf '%s\n' 1
  fi
}

compare_semver() {
  local left="$1"
  local right="$2"
  local left_major left_minor left_patch
  local right_major right_minor right_patch
  local result

  IFS=. read -r left_major left_minor left_patch <<<"$left"
  IFS=. read -r right_major right_minor right_patch <<<"$right"
  for result in \
    "$(compare_decimal "$left_major" "$right_major")" \
    "$(compare_decimal "$left_minor" "$right_minor")" \
    "$(compare_decimal "$left_patch" "$right_patch")"; do
    if [[ "$result" != 0 ]]; then
      printf '%s\n' "$result"
      return
    fi
  done
  printf '%s\n' 0
}

require_version_metadata() {
  local configured_build
  local configured_version
  local highest_build="0"
  local highest_build_tag=""
  local highest_version=""
  local previous_build
  local previous_commit
  local previous_version
  local release_ref
  local release_tag
  local release_tag_version
  local value_type

  value_type="$(/usr/bin/plutil -type CFBundleShortVersionString "$info_plist")"
  [[ "$value_type" == string ]] ||
    die "CFBundleShortVersionString must be a plist string"
  configured_version="$(/usr/libexec/PlistBuddy \
    -c 'Print :CFBundleShortVersionString' "$info_plist")"
  [[ "$configured_version" == "$version" ]] ||
    die "VERSION $version does not match CFBundleShortVersionString $configured_version"

  value_type="$(/usr/bin/plutil -type CFBundleVersion "$info_plist")"
  [[ "$value_type" == string ]] || die "CFBundleVersion must be a plist string"
  configured_build="$(/usr/libexec/PlistBuddy \
    -c 'Print :CFBundleVersion' "$info_plist")"
  [[ "$configured_build" =~ ^[1-9][0-9]*$ ]] ||
    die "CFBundleVersion must be a positive integer"

  while IFS= read -r release_ref; do
    [[ -n "$release_ref" ]] || continue
    release_tag="${release_ref#"$temporary_ref_namespace/tags/"}"
    release_tag_version="${release_tag#v}"
    if [[ ! "$release_tag_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
      continue
    fi
    [[ "$(/usr/bin/git cat-file -t "$release_ref")" == tag ]] ||
      die "remote release tag $release_tag is not annotated"
    previous_commit="$(/usr/bin/git rev-parse "${release_ref}^{commit}")"
    /usr/bin/git merge-base --is-ancestor "$previous_commit" \
      "refs/remotes/$origin_name/$release_branch" ||
      die "remote release tag $release_tag is not on $origin_name/$release_branch"

    value_type="$(plist_type_at_revision "$previous_commit" \
      CFBundleShortVersionString)" ||
      die "CFBundleShortVersionString could not be read from release tag $release_tag"
    [[ "$value_type" == string ]] ||
      die "release tag $release_tag has a non-string CFBundleShortVersionString"
    previous_version="$(plist_value_at_revision "$previous_commit" \
      CFBundleShortVersionString)" ||
      die "CFBundleShortVersionString could not be read from release tag $release_tag"
    [[ "$previous_version" == "$release_tag_version" ]] ||
      die "release tag $release_tag does not match its Info.plist version $previous_version"

    value_type="$(plist_type_at_revision "$previous_commit" CFBundleVersion)" ||
      die "CFBundleVersion could not be read from release tag $release_tag"
    [[ "$value_type" == string ]] ||
      die "release tag $release_tag has a non-string CFBundleVersion"
    previous_build="$(plist_value_at_revision "$previous_commit" CFBundleVersion)" ||
      die "CFBundleVersion could not be read from release tag $release_tag"
    [[ "$previous_build" =~ ^[1-9][0-9]*$ ]] ||
      die "release tag $release_tag has a nonnumeric CFBundleVersion"

    if [[ -z "$highest_version" ||
      "$(compare_semver "$release_tag_version" "$highest_version")" == 1 ]]; then
      highest_version="$release_tag_version"
    fi
    if [[ "$(compare_decimal "$previous_build" "$highest_build")" == 1 ]]; then
      highest_build="$previous_build"
      highest_build_tag="$release_tag"
    fi
  done < <(
    /usr/bin/git for-each-ref --format='%(refname)' \
      "$temporary_ref_namespace/tags/"
  )

  if [[ -n "$highest_version" &&
    "$(compare_semver "$version" "$highest_version")" != 1 ]]; then
    die "VERSION $version must be newer than existing release $highest_version"
  fi
  if [[ "$(compare_decimal "$configured_build" "$highest_build")" != 1 ]]; then
    die "CFBundleVersion $configured_build must exceed $highest_build from $highest_build_tag"
  fi
}

remote_tag_state() {
  local tag="$1"

  /usr/bin/git ls-remote --tags "$origin_name" \
    "refs/tags/$tag" "refs/tags/$tag^{}"
}

require_new_tag() {
  local remote_output
  local tag="v$version"

  if /usr/bin/git show-ref --verify --quiet "refs/tags/$tag"; then
    die "tag $tag already exists locally"
  fi
  if ! remote_output="$(remote_tag_state "$tag")"; then
    die "$origin_name could not be checked for tag $tag"
  fi
  [[ -z "$remote_output" ]] || die "tag $tag already exists on $origin_name"
}

require_release_immutability() {
  local immutable

  if ! immutable="$({
    /usr/bin/env -u GH_HOST -u GH_REPO "$gh_path" api \
      "repos/$repository/immutable-releases" --jq .enabled
  })"; then
    die "GitHub release immutability could not be checked"
  fi
  [[ "$immutable" == true ]] ||
    die "enable GitHub release immutability before publishing"
}

require_successful_ci() {
  local ci_conclusion
  local ci_head
  local ci_record
  local ci_status
  local ci_url

  if ! ci_record="$({
    /usr/bin/env -u GH_HOST -u GH_REPO "$gh_path" run list \
      --repo "$repository" \
      --workflow ci.yml \
      --branch "$release_branch" \
      --commit "$release_commit" \
      --event push \
      --limit 1 \
      --json status,conclusion,headSha,url \
      --jq 'if length == 0 then empty else .[0] | [.status, (.conclusion // ""), .headSha, .url] | join("|") end'
  })"; then
    die "GitHub CI status could not be read"
  fi
  [[ -n "$ci_record" ]] ||
    die "no CI push run exists for HEAD $release_commit on $release_branch"

  IFS='|' read -r ci_status ci_conclusion ci_head ci_url <<<"$ci_record"
  [[ "$ci_head" == "$release_commit" ]] ||
    die "GitHub returned CI for an unexpected commit: $ci_head"
  [[ "$ci_status" == completed ]] ||
    die "CI has not completed for HEAD: $ci_url"
  [[ "$ci_conclusion" == success ]] ||
    die "CI did not succeed for HEAD: $ci_url"
}

confirm_release() {
  local reply

  if [[ "$dry_run" == true || "$assume_yes" == true ]]; then
    return
  fi
  [[ -t 0 ]] ||
    die "interactive confirmation requires a terminal; use --yes to proceed"

  printf 'Create and push immutable release tag v%s from %s? [y/N] ' \
    "$version" "${release_commit:0:12}"
  IFS= read -r reply
  case "$reply" in
    y | Y | yes | YES) ;;
    *) die "release cancelled" ;;
  esac
}

revalidate_before_publish() {
  require_release_immutability
  require_successful_ci
  require_clean_main
  require_canonical_origin
  [[ "$(/usr/bin/git rev-parse HEAD)" == "$release_commit" ]] ||
    die "HEAD changed after release validation; start again"
  fetch_release_state
  require_unchanged_release_commit
  require_version_metadata
  require_new_tag
}

inspect_remote_tag() {
  local output="$1"
  local expected_tag_object="$2"
  local expected_commit="$3"
  local tag="$4"
  local object=""
  local peeled=""
  local oid ref

  while IFS=$'\t' read -r oid ref; do
    case "$ref" in
      "refs/tags/$tag")
        [[ -z "$object" ]] || return 1
        object="$oid"
        ;;
      "refs/tags/$tag^{}")
        [[ -z "$peeled" ]] || return 1
        peeled="$oid"
        ;;
      "") ;;
      *) return 1 ;;
    esac
  done <<<"$output"

  [[ "$object" == "$expected_tag_object" && "$peeled" == "$expected_commit" ]]
}

create_and_push_tag() {
  local push_succeeded=false
  local remote_output
  local tag="v$version"
  local tag_object

  if [[ "$dry_run" == true ]]; then
    printf 'Dry run passed: would create annotated tag %s at %s and push it to %s.\n' \
      "$tag" "$release_commit" "$origin_name"
    return
  fi

  /usr/bin/git tag --no-sign -a "$tag" -m "Release $tag" "$release_commit"
  [[ "$(/usr/bin/git cat-file -t "refs/tags/$tag")" == tag ]] ||
    die "local release ref is not an annotated tag: $tag"
  [[ "$(/usr/bin/git rev-parse "refs/tags/$tag^{commit}")" == "$release_commit" ]] ||
    die "local release tag does not target the validated commit"
  tag_object="$(/usr/bin/git rev-parse "refs/tags/$tag")"

  if /usr/bin/git push --no-follow-tags --no-signed "$origin_name" \
    "refs/tags/$tag:refs/tags/$tag"; then
    push_succeeded=true
  fi

  if ! remote_output="$(remote_tag_state "$tag")"; then
    die "the tag push result is uncertain because $origin_name could not be queried; do not delete or move $tag until its remote state is verified"
  fi
  if inspect_remote_tag "$remote_output" "$tag_object" "$release_commit" "$tag"; then
    if [[ "$push_succeeded" != true ]]; then
      printf 'The push reported an error, but %s contains the exact expected tag.\n' \
        "$origin_name" >&2
    fi
    printf 'Pushed %s. Follow the release workflow at:\n' "$tag"
    printf 'https://github.com/%s/actions/workflows/release.yml\n' "$repository"
    return
  fi

  if [[ -z "$remote_output" ]]; then
    die "the tag push failed and $origin_name has no $tag; the local tag remains—after resolving the push problem, delete only that local tag with: git tag -d $tag"
  fi
  die "$origin_name contains $tag, but its tag object or target differs from the validated local tag; do not delete or move either tag until investigated"
}

main() {
  parse_arguments "$@"
  resolve_tools
  cd "$project_dir"
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  require_clean_main
  require_canonical_origin
  fetch_release_state
  capture_release_commit
  require_version_metadata
  require_new_tag
  require_release_immutability
  require_successful_ci
  confirm_release
  if [[ "$dry_run" != true ]]; then
    revalidate_before_publish
  fi
  create_and_push_tag
}

main "$@"
