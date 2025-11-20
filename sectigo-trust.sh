#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Try to source the same env as sectigo.sh if present
if [[ -f "$HERE/sectigo.env" ]]; then
  # shellcheck source=/dev/null
  source "$HERE/sectigo.env"
fi

usage() {
  cat <<'USAGE'
sectigo-trust.sh — utilities to manage CA trust for Splunk TLS

Subcommands:

  le-trust [--out-dir DIR]
    Fetch/refresh Let's Encrypt R3 and ISRG Root X1 and build a small bundle.

  compose-trust [--chain PATH] [--certs-dir DIR] [--out-dir DIR] [--no-fetch]
    Compose a combined trust bundle: Sectigo chain + Let's Encrypt bundle.

Environment (with defaults):

  LE_R3_URL="https://letsencrypt.org/certs/lets-encrypt-r3.pem"
  LE_ISRG_ROOT_URL="https://letsencrypt.org/certs/isrgrootx1.pem"
  SECTIGO_TRUST_OUT_DIR="$HERE/certs"
  SECTIGO_LE_BUNDLE_NAME="le-ca-bundle.pem"
  SECTIGO_COMPOSED_TRUST_NAME="sectigo_and_le_roots.pem"
  SECTIGO_CERTS_DIR="$HERE/certs"

Examples:
  ./sectigo-trust.sh le-trust --out-dir /fullPathTo/sectigo/certs
  ./sectigo-trust.sh compose-trust --certs-dir /fullPathTo/sectigo/certs --out-dir /fullPathTo/sectigo/certs
USAGE
}

le_trust() {
  local OUT_DIR="${SECTIGO_TRUST_OUT_DIR:-$HERE/certs}"
  local R3_URL="${LE_R3_URL:-https://letsencrypt.org/certs/lets-encrypt-r3.pem}"
  local ISRG_URL="${LE_ISRG_ROOT_URL:-https://letsencrypt.org/certs/isrgrootx1.pem}"
  local BUNDLE="${SECTIGO_LE_BUNDLE_NAME:-le-ca-bundle.pem}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out-dir) OUT_DIR="${2:?}"; shift 2;;
      *) echo "Unknown arg to le-trust: $1" >&2; return 2;;
    esac
  done

  mkdir -p "$OUT_DIR"
  local r3="$OUT_DIR/lets-encrypt-r3.pem"
  local isrg="$OUT_DIR/isrgrootx1.pem"
  curl -fsS --connect-timeout "${CURL_CONNECT_TIMEOUT:-10}" --max-time "${CURL_MAX_TIME:-120}" -o "$r3" "$R3_URL"
  curl -fsS --connect-timeout "${CURL_CONNECT_TIMEOUT:-10}" --max-time "${CURL_MAX_TIME:-120}" -o "$isrg" "$ISRG_URL"
  cat "$r3" "$isrg" > "$OUT_DIR/$BUNDLE"
  chmod 0644 "$OUT_DIR/$BUNDLE"
  echo "wrote $OUT_DIR/$BUNDLE"
}

compose_trust() {
  local CERTS_DIR="${SECTIGO_CERTS_DIR:-$HERE/certs}"
  local OUT_DIR="${SECTIGO_TRUST_OUT_DIR:-$HERE/certs}"
  local CHAIN_PATH=""
  local BUNDLE="${SECTIGO_LE_BUNDLE_NAME:-le-ca-bundle.pem}"
  local COMPOSED="${SECTIGO_COMPOSED_TRUST_NAME:-sectigo_and_le_roots.pem}"
  local NO_FETCH=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --chain) CHAIN_PATH="${2:?}"; shift 2;;
      --certs-dir) CERTS_DIR="${2:?}"; shift 2;;
      --out-dir) OUT_DIR="${2:?}"; shift 2;;
      --no-fetch) NO_FETCH=1; shift;;
      *) echo "Unknown arg to compose-trust: $1" >&2; return 2;;
    esac
  done

  mkdir -p "$OUT_DIR"
  [[ -n "$CHAIN_PATH" ]] || CHAIN_PATH="$CERTS_DIR/chain.pem"
  [[ -s "$CHAIN_PATH" ]] || { echo "chain not found or empty: $CHAIN_PATH" >&2; return 2; }

  if [[ ! -s "$OUT_DIR/$BUNDLE" ]]; then
    if (( NO_FETCH == 1 )); then
      echo "LE bundle missing and --no-fetch specified: $OUT_DIR/$BUNDLE" >&2
      return 2
    fi
    "$HERE/sectigo-trust.sh" le-trust --out-dir "$OUT_DIR"
  fi

  cat "$CHAIN_PATH" "$OUT_DIR/$BUNDLE" > "$OUT_DIR/$COMPOSED"
  chmod 0644 "$OUT_DIR/$COMPOSED"
  echo "wrote $OUT_DIR/$COMPOSED"
}

case "${1:-}" in
  le-trust) shift; le_trust "$@";;
  compose-trust) shift; compose_trust "$@";;
  ""|-h|--help) usage;;
  *) echo "Unknown command: ${1:-}" >&2; usage; exit 2;;
esac
