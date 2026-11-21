#!/usr/bin/env bash
# Download only the requested source commit; never run anything from the checkout.
set -euo pipefail
umask 077
export LC_ALL=C

usage() {
  printf '%s\n' 'Usage: bash tools/stage_release.sh COMMIT NEW_DIRECTORY' \
    'COMMIT must be a full 40-digit Git SHA. The parent directory must exist.' \
    'The new checkout is private. If staging fails, use a different new directory.'
}

if [[ $# == 1 && $1 == --help ]]; then
  usage
  exit 0
fi
if [[ $# != 2 ]] || ! [[ $1 =~ ^[a-fA-F0-9]{40}$ ]] || [[ -z $2 ]]; then
  usage >&2
  exit 2
fi

commit=$(printf '%s' "$1" | tr A-F a-f)
destination=$2
origin='https://github.com/ipsc-gummy/team-relay-toolkit.git'

git_clean() {
  # No inherited Git environment, redirects, user/system config, or credential prompts.
  env -i PATH="$PATH" LC_ALL=C NETRC=/dev/null \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/false \
    git -c core.hooksPath=/dev/null -c credential.helper= \
    -c protocol.allow=never -c protocol.https.allow=always \
    -c http.sslVerify=true -c http.followRedirects=false -c 'http.extraHeader=Authorization:' \
    -c http.lowSpeedLimit=1 -c http.lowSpeedTime=30 "$@"
}

fail() {
  printf 'STAGING_FAILED: %s\n' "$1" >&2
  exit 1
}

# mkdir is exclusive, including against existing symlinks. Do not reuse or remove a path.
mkdir -m 0700 -- "$destination" 2>/dev/null || fail 'destination must be a new directory with an existing parent'
git_clean -C "$destination" init --quiet --object-format=sha1 --template= \
  </dev/null 2>/dev/null || fail 'could not initialize the private checkout'
git_clean -C "$destination" fetch --quiet --no-tags --depth=1 --no-recurse-submodules "$origin" "$commit" \
  </dev/null 2>/dev/null || fail 'could not fetch the pinned commit from the project origin'

fetched=$(git_clean -C "$destination" rev-parse --verify 'FETCH_HEAD^{commit}' 2>/dev/null) || \
  fail 'fetched object is not a commit'
[[ $fetched == "$commit" ]] || fail 'fetched commit differs from the requested SHA'
git_clean -C "$destination" checkout --quiet --detach --no-recurse-submodules "$commit" -- \
  </dev/null 2>/dev/null || fail 'could not check out the pinned commit'
resolved=$(git_clean -C "$destination" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || \
  fail 'could not resolve the checkout HEAD'
[[ $resolved == "$commit" ]] || fail 'checkout HEAD differs from the requested SHA'
if git_clean -C "$destination" symbolic-ref -q HEAD >/dev/null 2>&1; then
  fail 'checkout HEAD is not detached'
else
  [[ $? == 1 ]] || fail 'could not verify detached HEAD'
fi

printf 'STAGED_COMMIT=%s\n' "$resolved"
