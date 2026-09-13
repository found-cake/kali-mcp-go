#!/bin/sh

set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/kali-mcp-run-docker.XXXXXX")
cleanup() {
  status=$?
  trap - 0
  rm -rf "$test_root"
  exit "$status"
}
trap cleanup 0

fake_bin="$test_root/bin"
capture_file="$test_root/docker-args"
cache_root="$test_root/cache"
installer_output="$test_root/output"
mkdir -p "$fake_bin"

cat > "$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = "container" ] && [ "${2:-}" = "inspect" ]; then
  if [ "${KALI_MCP_TEST_CONTAINER_EXISTS:-}" = "true" ]; then
    exit 0
  fi
  exit 1
fi
if [ "${1:-}" = "inspect" ]; then
  case "${3:-}" in
    *Config.Labels*) printf '%s\n' true ;;
    *State.Running*) printf '%s\n' true ;;
    *) exit 1 ;;
  esac
  exit 0
fi
if [ "${1:-}" = "run" ]; then
  printf '%s\n' "$@" > "$KALI_MCP_DOCKER_CAPTURE"
  printf '%s\n' fake-container-id
  exit 0
fi
if [ "${1:-}" = "exec" ]; then
  exit 0
fi
printf '%s\n' "unexpected docker command: $*" >&2
exit 1
EOF

cat > "$fake_bin/curl" <<'EOF'
#!/bin/sh
set -eu
output=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output" ]; then
    shift
    output=$1
  fi
  shift
done
test -n "$output"
cp "$KALI_MCP_TEST_PROFILE_SOURCE" "$output"
EOF

cat > "$fake_bin/openssl" <<'EOF'
#!/bin/sh
set -eu
test "$*" = "rand -hex 32"
printf '%s\n' test-api-token
EOF

chmod +x "$fake_bin/docker" "$fake_bin/curl" "$fake_bin/openssl"

PATH="$fake_bin:$PATH" \
  XDG_CACHE_HOME="$cache_root" \
  KALI_MCP_DOCKER_CAPTURE="$capture_file" \
  KALI_MCP_TEST_PROFILE_SOURCE="$repo_root/chromium-seccomp.json" \
  KALI_MCP_DOCKER_IMAGE="example.invalid/kali-mcp:test" \
  sh < "$repo_root/scripts/run-docker.sh" > "$installer_output"

profile_path="$cache_root/kali-mcp/chromium-seccomp.json"
test -f "$profile_path"
cmp "$repo_root/chromium-seccomp.json" "$profile_path"

cat > "$test_root/want-docker-args" <<EOF
run
--pull=always
-d
--name
kali-mcp
--restart
unless-stopped
--init
--add-host
host.docker.internal:host-gateway
--ipc=host
--security-opt
seccomp=$profile_path
--label
io.github.found-cake.kali-mcp.managed=true
-e
KALI_MCP_API_TOKEN=test-api-token
--entrypoint
kali-server
example.invalid/kali-mcp:test
--ip
127.0.0.1
--port
5000
EOF

diff -u "$test_root/want-docker-args" "$capture_file"
grep -F 'docker exec -i kali-mcp mcp-client' "$installer_output" >/dev/null
if grep -Eq -- '--rm|kali-mcp-docker' "$installer_output"; then
  printf '%s\n' "installer output still advertises the removed transient launcher" >&2
  exit 1
fi

cp "$capture_file" "$test_root/first-docker-args"
PATH="$fake_bin:$PATH" \
  XDG_CACHE_HOME="$cache_root" \
  KALI_MCP_DOCKER_CAPTURE="$capture_file" \
  KALI_MCP_TEST_CONTAINER_EXISTS=true \
  sh < "$repo_root/scripts/run-docker.sh" > "$test_root/existing-output"
diff -u "$test_root/first-docker-args" "$capture_file"
grep -F 'docker exec -i kali-mcp mcp-client' "$test_root/existing-output" >/dev/null
