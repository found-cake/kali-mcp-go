#!/bin/sh

set -eu

readonly profile_sha256="cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849"
readonly profile_url="https://raw.githubusercontent.com/found-cake/kali-mcp-go/refs/heads/master/chromium-seccomp.json"
readonly cache_root="${XDG_CACHE_HOME:-${HOME}/.cache}"
readonly profile_dir="$cache_root/kali-mcp"
readonly profile_path="$profile_dir/chromium-seccomp.json"
readonly image_name="${KALI_MCP_DOCKER_IMAGE:-ghcr.io/found-cake/kali-mcp-go:latest}"
readonly pull_policy="${KALI_MCP_DOCKER_PULL:-always}"
readonly container_name="${KALI_MCP_CONTAINER_NAME:-kali-mcp}"
readonly managed_label="io.github.found-cake.kali-mcp.managed=true"

temporary_profile=""
run_pull_policy="$pull_policy"

cleanup() {
  status=$?
  trap - 0
  if test -n "$temporary_profile" && test -f "$temporary_profile"; then
    rm -f "$temporary_profile"
  fi
  exit "$status"
}

trap cleanup 0

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
    return
  fi
  printf '%s\n' "kali-mcp installer: sha256sum or shasum is required" >&2
  return 1
}

profile_is_valid() {
  test -f "$1" && test "$(sha256_file "$1")" = "$profile_sha256"
}

install_profile() {
  mkdir -p "$profile_dir"
  temporary_profile=$(mktemp "$profile_dir/chromium-seccomp.XXXXXX")
  curl --fail --silent --show-error --location \
    --proto '=https' --tlsv1.2 \
    "$profile_url" \
    --output "$temporary_profile"

  if ! profile_is_valid "$temporary_profile"; then
    printf '%s\n' "kali-mcp installer: Chromium seccomp profile checksum mismatch" >&2
    return 1
  fi
  chmod 0600 "$temporary_profile"
  mv "$temporary_profile" "$profile_path"
  temporary_profile=""
}

print_registration() {
  cat <<EOF
Kali MCP container '$container_name' is ready.

Register it with Codex:
  codex mcp add kali-mcp -- docker exec -i $container_name mcp-client --server http://127.0.0.1:5000 --timeout 3600

The MCP launcher command for other clients is:
  docker exec -i $container_name mcp-client --server http://127.0.0.1:5000 --timeout 3600
EOF
}

wait_for_health() {
  attempts=0
  while test "$attempts" -lt 100; do
    if docker exec "$container_name" curl -fsS --max-time 1 http://127.0.0.1:5000/health >/dev/null 2>&1; then
      return 0
    fi
    attempts=$((attempts + 1))
    sleep 0.1
  done
  return 1
}

command -v docker >/dev/null 2>&1 || {
  printf '%s\n' "kali-mcp installer: docker is required" >&2
  exit 1
}

if docker container inspect "$container_name" >/dev/null 2>&1; then
  existing_label=$(docker inspect --format '{{ index .Config.Labels "io.github.found-cake.kali-mcp.managed" }}' "$container_name" 2>/dev/null || true)
  if test "$existing_label" != "true"; then
    printf '%s\n' "kali-mcp installer: container '$container_name' already exists and is not managed by this installer" >&2
    exit 1
  fi
  reuse_existing=true
  if test "$pull_policy" = "always"; then
    docker pull "$image_name" >/dev/null
    existing_image_id=$(docker inspect --format '{{ .Image }}' "$container_name")
    desired_image_id=$(docker image inspect --format '{{ .Id }}' "$image_name")
    if test "$existing_image_id" != "$desired_image_id"; then
      docker rm -f "$container_name" >/dev/null
      reuse_existing=false
      run_pull_policy=never
    fi
  fi
  if test "$reuse_existing" = "true"; then
    if test "$(docker inspect --format '{{ .State.Running }}' "$container_name")" != "true"; then
      docker start "$container_name" >/dev/null
    fi
    if ! wait_for_health; then
      printf '%s\n' "kali-mcp installer: existing container '$container_name' failed its health check" >&2
      exit 1
    fi
    print_registration
    exit 0
  fi
fi

command -v curl >/dev/null 2>&1 || {
  printf '%s\n' "kali-mcp installer: curl is required" >&2
  exit 1
}
command -v openssl >/dev/null 2>&1 || {
  printf '%s\n' "kali-mcp installer: openssl is required" >&2
  exit 1
}

if ! profile_is_valid "$profile_path"; then
  install_profile
fi

api_token=$(openssl rand -hex 32)
test -n "$api_token"

docker run \
  --pull="$run_pull_policy" \
  -d \
  --name "$container_name" \
  --restart unless-stopped \
  --init \
  --add-host host.docker.internal:host-gateway \
  --shm-size=512m \
  --security-opt "seccomp=$profile_path" \
  --label "$managed_label" \
  -e "KALI_MCP_API_TOKEN=$api_token" \
  --entrypoint kali-server \
  "$image_name" \
  --ip 127.0.0.1 --port 5000 >/dev/null

if ! wait_for_health; then
  docker logs --tail 100 "$container_name" >&2 || true
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  printf '%s\n' "kali-mcp installer: new container failed its health check and was removed" >&2
  exit 1
fi

print_registration
