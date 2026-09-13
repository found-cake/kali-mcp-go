#!/usr/bin/env bash

set -eu

readonly browser_user="kali-browser"
readonly browser_home="/home/${browser_user}"
readonly chromium_path="${CHROMIUM_PATH:-/usr/bin/chromium}"
readonly executable_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

browser_environment=(
    env -i
    "HOME=${browser_home}"
    "PATH=${executable_path}"
    "LANG=C.UTF-8"
    "CHROMIUM_PATH=${chromium_path}"
)

for proxy_name in HTTP_PROXY HTTPS_PROXY NO_PROXY http_proxy https_proxy no_proxy; do
    if [[ -n "${!proxy_name:-}" ]]; then
        browser_environment+=("${proxy_name}=${!proxy_name}")
    fi
done

browser_command=(node /usr/local/lib/kali-mcp/browser-check.cjs "$@")
if [[ "$(id -u)" -eq 0 ]]; then
    exec runuser -u "${browser_user}" -- "${browser_environment[@]}" "${browser_command[@]}"
fi
exec "${browser_environment[@]}" "${browser_command[@]}"
