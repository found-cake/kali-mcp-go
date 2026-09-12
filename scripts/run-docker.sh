#!/usr/bin/env bash

set -euo pipefail

readonly profile_sha256="cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849"
readonly profile_url="https://raw.githubusercontent.com/found-cake/kali-mcp-go/8184dde5d042919d42da7fb2204624d4984f6321/chromium-seccomp.json"
readonly script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly bundled_profile="$script_dir/../chromium-seccomp.json"
readonly cache_root="${XDG_CACHE_HOME:-${HOME}/.cache}"
readonly profile_dir="$cache_root/kali-mcp"
readonly profile_path="$profile_dir/chromium-seccomp.json"
readonly image_name="${KALI_MCP_DOCKER_IMAGE:-ghcr.io/found-cake/kali-mcp-go:latest}"
readonly pull_policy="${KALI_MCP_DOCKER_PULL:-always}"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi
  printf '%s\n' "run-docker: sha256sum or shasum is required" >&2
  return 1
}

profile_is_valid() {
  test -f "$1" && test "$(sha256_file "$1")" = "$profile_sha256"
}

install_profile() {
  mkdir -p "$profile_dir"
  local temporary_profile
  temporary_profile=$(mktemp "$profile_dir/chromium-seccomp.XXXXXX")
  trap 'rm -f "$temporary_profile"' RETURN

  if profile_is_valid "$bundled_profile"; then
    cp "$bundled_profile" "$temporary_profile"
  else
    command -v curl >/dev/null 2>&1 || {
      printf '%s\n' "run-docker: curl is required to download the Chromium seccomp profile" >&2
      return 1
    }
    curl --fail --silent --show-error --location \
      --proto '=https' --tlsv1.2 \
      "$profile_url" \
      --output "$temporary_profile"
  fi

  if ! profile_is_valid "$temporary_profile"; then
    printf '%s\n' "run-docker: Chromium seccomp profile checksum mismatch" >&2
    return 1
  fi
  chmod 0600 "$temporary_profile"
  mv "$temporary_profile" "$profile_path"
  trap - RETURN
}

command -v docker >/dev/null 2>&1 || {
  printf '%s\n' "run-docker: docker is required" >&2
  exit 1
}

if ! profile_is_valid "$profile_path"; then
  install_profile
fi

if test "${1:-}" = "--print-seccomp-profile"; then
  printf '%s\n' "$profile_path"
  exit 0
fi

exec docker run \
  --pull="$pull_policy" \
  --rm \
  -i \
  --add-host host.docker.internal:host-gateway \
  --ipc=host \
  --security-opt "seccomp=$profile_path" \
  "$image_name" \
  "$@"
