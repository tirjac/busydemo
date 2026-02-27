#!/usr/bin/env bash
set -euo pipefail

export SRCDIR=$(dirname $(cd ${0%/*} 2>>/dev/null ; echo `pwd`/${0##*/}))
ROOT_DIR="${SRCDIR}/.."

CONF_PATH="${1:-$ROOT_DIR/example/oldserver.conf}"

if [[ ! -f "$CONF_PATH" ]]; then
  echo "Config not found: $CONF_PATH" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "$CONF_PATH"

BIN="$ROOT_DIR/build/bin/oldserver"

if [[ ! -x "$BIN" ]]; then
  echo "Binary not found or not executable: $BIN" >&2
  echo "Build first: cmake -S . -B build && cmake --build build" >&2
  exit 1
fi

exec "$BIN" "$PORT" \
  "$SERVER_CERT" \
  "$SERVER_KEY" \
  "$LOCAL_CA" \
  "$USER_FILE" \
  "$DB_PATH" \
  "$REMOTE_HOST" "$REMOTE_PORT" \
  "$REMOTE_CA" \
  "$REMOTE_CLIENT_CERT" \
  "$REMOTE_CLIENT_KEY" \
  "${REMOTE_SERVER_CA:-}"
