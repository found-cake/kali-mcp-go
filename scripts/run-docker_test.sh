#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/kali-mcp-run-docker.XXXXXX")
trap 'rm -rf "$test_root"' EXIT

fake_bin="$test_root/bin"
capture_file="$test_root/docker-args"
cache_root="$test_root/cache"
mkdir -p "$fake_bin"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'printf "%s\\n" "$@" > "$KALI_MCP_DOCKER_CAPTURE"' \
  > "$fake_bin/docker"
chmod +x "$fake_bin/docker"

PATH="$fake_bin:$PATH" \
  XDG_CACHE_HOME="$cache_root" \
  KALI_MCP_DOCKER_CAPTURE="$capture_file" \
  KALI_MCP_DOCKER_IMAGE="example.invalid/kali-mcp:test" \
  bash "$repo_root/scripts/run-docker.sh" --timeout 42

profile_path="$cache_root/kali-mcp/chromium-seccomp.json"
test -f "$profile_path"
cmp "$repo_root/chromium-seccomp.json" "$profile_path"

printf '%s\n' \
  run \
  --pull=always \
  --rm \
  -i \
  --add-host \
  host.docker.internal:host-gateway \
  --ipc=host \
  --security-opt \
  "seccomp=$profile_path" \
  example.invalid/kali-mcp:test \
  --timeout \
  42 \
  > "$test_root/want-docker-args"

diff -u "$test_root/want-docker-args" "$capture_file"

reported_profile=$(PATH="$fake_bin:$PATH" \
  XDG_CACHE_HOME="$cache_root" \
  KALI_MCP_DOCKER_CAPTURE="$capture_file" \
  bash "$repo_root/scripts/run-docker.sh" --print-seccomp-profile)
test "$reported_profile" = "$profile_path"
