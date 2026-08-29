#!/usr/bin/env bash

set -eu

readonly server_url="http://127.0.0.1:5000"
server_pid=""
client_pid=""

stop_process() {
    local pid="$1"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    stop_process "$client_pid"
    stop_process "$server_pid"
    wait "$client_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    exit "$status"
}

forward_signal() {
    stop_process "$client_pid"
    stop_process "$server_pid"
}

trap forward_signal INT TERM
trap cleanup EXIT

if [[ -z "${KALI_MCP_API_TOKEN:-}" ]]; then
    KALI_MCP_API_TOKEN="$(openssl rand -hex 32)"
    export KALI_MCP_API_TOKEN
fi

/usr/local/bin/kali-server --ip 127.0.0.1 --port 5000 &
server_pid=$!

server_ready=false
for ((attempt = 0; attempt < 100; attempt++)); do
    if curl -fs --max-time 1 "$server_url/health" >/dev/null 2>&1; then
        server_ready=true
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        wait "$server_pid"
        exit 1
    fi
    sleep 0.1
done

if [[ "$server_ready" != true ]]; then
    echo "kali-server did not become ready" >&2
    exit 1
fi

/usr/local/bin/mcp-client --server "$server_url" "$@" <&0 &
client_pid=$!
wait "$client_pid"
