#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$HERE/sectigo.env"

usage() {
  cat <<'USAGE'
Usage:
  sectigo-token.sh [--json] [--payload]

No flags: prints the access token (JWT) to stdout (for piping).
  --json     Print full token endpoint JSON (to stdout)
  --payload  Print decoded JWT payload JSON (to stdout)
USAGE
}

want_json=false
want_payload=false
for a in "${@:-}"; do
  case "$a" in
    --json) want_json=true ;;
    --payload) want_payload=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown flag: $a" >&2; usage; exit 2 ;;
  esac
done

resp="$(curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
  -X POST "$SECTIGO_AUTH_URL" \
  -d grant_type=client_credentials \
  -d "client_id=$SECTIGO_ENROLL_CLIENT_ID" \
  -d "client_secret=$SECTIGO_ENROLL_CLIENT_SECRET")"

token="$(jq -r '.access_token // empty' <<<"$resp")"
[[ -n "$token" ]] || { echo "$resp" | jq . >&2 || echo "$resp" >&2; exit 1; }

# Default behavior: print the token for piping
if ! $want_json && ! $want_payload; then
  echo "$token"
  exit 0
fi

$want_json && echo "$resp" | jq .
if $want_payload; then
  payload="$(cut -d. -f2 <<<"$token" | tr '_-' '/+' | base64 -d 2>/dev/null || true)"
  echo "$payload" | jq .
fi

