#!/usr/bin/env sh

set -eu

jwt_home="$(mktemp -d)"
cleanup() {
    rm -rf "$jwt_home"
}
trap cleanup EXIT INT TERM

export HOME="$jwt_home"
cp -a /opt/jwt_tool-seed/. "$jwt_home"/
cd /opt/jwt_tool
set +e
/opt/jwt_tool/.venv/bin/python /opt/jwt_tool/jwt_tool.py "$@"
jwt_status=$?
set -e

if [ "$jwt_status" -eq 1 ]; then
    exit 0
fi
exit "$jwt_status"
