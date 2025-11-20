#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$HERE/sectigo.env"
# shellcheck source=/dev/null
source "$HERE/sectigo-api.sh"

usage() {
  cat <<'USAGE'
sectigo.sh — Single-run Enrollment flow for Splunk forwarder certs (reuse existing key)

One-shot forwarder issuance (cron-safe; reuses existing private key):
  forwarder-issue \
    --cn FQDN | (use CSR_CN_DEFAULT from sectigo.env) \
    --key PATH_TO_EXISTING_KEY \
    --out-dir DIR \
    [--sans DNS:alt1,DNS:alt2] \
    [--org "Example Org"] [--ou "IT"] [--country US] [--state "CA"] [--locality "San Diego"] [--email user@domain] \
    [--quiet] [--lock]
USAGE
}

with_lock() {
  local enabled="$1"; shift
  if [[ "$enabled" == "1" ]]; then
    exec 200>"$SECTIGO_LOCK_FILE"
    flock -n 200 || { echo "Another run is in progress (lock: $SECTIGO_LOCK_FILE)" >&2; exit 75; }
  fi
  "$@"
}

forwarder_issue() {
  # Parse args (all locals are valid here)
  local CN="" KEY="" OUT_DIR="" SANS="" QUIET=0 LOCK=0 EMAIL=""
  local C="" ST="" L="" O="" OU=""
  local ORDER_COMMENT="${SECTIGO_ORDER_COMMENT:-}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --cn) CN="${2:?}"; shift 2;;
      --key) KEY="${2:?}"; shift 2;;
      --out-dir) OUT_DIR="${2:?}"; shift 2;;
      --sans) SANS="${2:?}"; shift 2;;
      --country) C="${2:?}"; shift 2;;
      --state) ST="${2:?}"; shift 2;;
      --locality) L="${2:?}"; shift 2;;
      --org) O="${2:?}"; shift 2;;
      --ou) OU="${2:?}"; shift 2;;
      --email) EMAIL="${2:?}"; shift 2;;
      --comment) ORDER_COMMENT="${2:?}"; shift 2;;
      --quiet) QUIET=1; shift;;
      --lock) LOCK=1; shift;;
      *) echo "Unknown flag: $1" >&2; usage; return 2;;
    esac
  done

  # Allow CN to fall back to env default
  if [[ -z "$CN" && -n "${CSR_CN_DEFAULT:-}" ]]; then
    CN="$CSR_CN_DEFAULT"
  fi

  [[ -n "$CN" && -n "$KEY" && -n "$OUT_DIR" ]] || { echo "--cn (or CSR_CN_DEFAULT), --key, and --out-dir are required" >&2; return 2; }
  [[ -s "$KEY" ]] || { echo "Key not found or empty: $KEY" >&2; return 2; }

  local run_flow
  run_flow() {
    mkdir -p "$OUT_DIR"
    local CSR="$OUT_DIR/forwarder.csr"

    # Generate CSR from existing key, fully non-interactive (values from flags/env)
    make_csr_from_key \
      --key "$KEY" \
      --csr-out "$CSR" \
      --cn "$CN" \
      ${SANS:+--sans "$SANS"} \
      ${C:+--country "$C"} \
      ${ST:+--state "$ST"} \
      ${L:+--locality "$L"} \
      ${O:+--org "$O"} \
      ${OU:+--ou "$OU"} \
      ${EMAIL:+--email "$EMAIL"} \
      >/dev/null

    (( QUIET==1 )) || echo "CSR created at $CSR"

    # Enroll
    local enroll; enroll="$(SECTIGO_ORDER_COMMENT="$ORDER_COMMENT" enroll_ssl "$CSR")" || { echo "Enroll failed" >&2; return 1; }
    local CERT_ID; CERT_ID="$(jq -r '.certId // .id // empty' <<<"$enroll")"
    [[ -n "$CERT_ID" ]] || { echo "Could not parse certId" >&2; echo "$enroll" | jq . >&2; return 1; }
    (( QUIET==1 )) || echo "Enrolled certId: $CERT_ID"

    # Wait for issuance
    wait_until_issued "$CERT_ID" >/dev/null || { echo "Issuance wait failed" >&2; return 1; }
    (( QUIET==1 )) || echo "Issued."

    # Collect & assemble forwarder.pem with the SAME existing key
    collect_cert_materials "$CERT_ID" --out "$OUT_DIR" --key "$KEY" >/dev/null || {
      echo "Collect failed" >&2; return 1; }
    (( QUIET==1 )) || echo "Artifacts written to $OUT_DIR (cert.pem, chain.pem, forwarder.pem using existing key)"
  }

  with_lock "$LOCK" run_flow
}


# Cron-friendly renewal: checks *.crt and renews those expiring within DAYS.
cron_renew() {
  local CERTS_DIR="${SECTIGO_CERTS_DIR:-$HERE/certs}"
  local KEYS_DIR="${SECTIGO_KEYS_DIR:-$HERE/keys}"
  local DAYS="${SECTIGO_RENEW_DAYS:-5}" QUIET=1 LOCK=0 AUTO_COMMENT=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --certs-dir) CERTS_DIR="${2:?}"; shift 2;;
      --keys-dir)  KEYS_DIR="${2:?}"; shift 2;;
      --days)      DAYS="${2:?}"; shift 2;;
      --quiet)     QUIET=1; shift;;
      --verbose)   QUIET=0; shift;;
      --lock)      LOCK=1; shift;;
      --auto-comment) AUTO_COMMENT=1; shift;;
      *) echo "Unknown arg to cron_renew: $1" >&2; return 2;;
    esac
  done
  [[ -d "$CERTS_DIR" ]] || { echo "Missing certs dir: $CERTS_DIR" >&2; return 2; }
  [[ -d "$KEYS_DIR"  ]] || { echo "Missing keys dir:  $KEYS_DIR"  >&2; return 2; }

  local now; now="$(date -u +%s)"
  local cutoff=$(( DAYS * 86400 ))

  _scan() {
    shopt -s nullglob
    local crt base key_path na notafter delta cn sans_line comment
    for crt in "$CERTS_DIR"/*.crt; do
      [[ -s "$crt" ]] || continue
      base="${crt##*/}"; base="${base%.crt}"
      key_path="$KEYS_DIR/${base}.pem"
      [[ -s "$key_path" ]] || { (( QUIET==0 )) && echo "Skip (no key): $crt" >&2; continue; }

      na="$(openssl x509 -in "$crt" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')"
      [[ -n "$na" ]] || { echo "WARN: could not read expiry for $crt" >&2; continue; }
      notafter="$(date -u -d "$na" +%s 2>/dev/null || true)"
      [[ -n "$notafter" ]] || { echo "WARN: bad date for $crt: $na" >&2; continue; }
      delta=$(( notafter - now ))
      (( delta <= cutoff )) || { (( QUIET==0 )) && echo "OK (> ${DAYS}d): $crt" >&2; continue; }

      # Extract CN (RFC2253, fallback legacy)
      cn="$(openssl x509 -in "$crt" -noout -subject -nameopt RFC2253 2>/dev/null | sed -n 's/.*CN=\([^,]*\).*/\1/p')"
      if [[ -z "$cn" ]]; then
        cn="$(openssl x509 -in "$crt" -noout -subject 2>/dev/null | sed -n 's/^subject=.*CN[ =]*\([^,/]*\).*/\1/p')"
      fi
      [[ -n "$cn" ]] || { echo "WARN: CN parse failed for $crt; skipping" >&2; continue; }

      sans_line="$(openssl x509 -in "$crt" -noout -ext subjectAltName 2>/dev/null | grep -Eo 'DNS:[^,]+' | paste -sd, -)"
      [[ -n "$sans_line" ]] || sans_line="DNS:${cn}"

      comment=""
      if (( AUTO_COMMENT==1 )); then
        comment="Auto-renew via cron on $(date -u +%F) host=$(hostname -f) CN=${cn} SANs=$(echo "$sans_line" | tr -d '
')"
      fi

      (( QUIET==0 )) && echo "Renewing: $crt  CN=${cn}" >&2
      if [[ -n "$comment" ]]; then
        "$HERE/sectigo.sh" forwarder-issue \
          --key "$key_path" --cn "$cn" --sans "$sans_line" \
          --out-dir "$CERTS_DIR" ${QUIET:+--quiet} ${LOCK:+--lock} \
          --comment "$comment"
      else
        "$HERE/sectigo.sh" forwarder-issue \
          --key "$key_path" --cn "$cn" --sans "$sans_line" \
          --out-dir "$CERTS_DIR" ${QUIET:+--quiet} ${LOCK:+--lock}
      fi
    done
  }

  if (( LOCK==1 )); then
    with_lock "$SECTIGO_LOCK_FILE" _scan
  else
    _scan
  fi
}

case "${1:-}" in
  forwarder-issue) shift; forwarder_issue "${@}";;
  cron-renew) shift; cron_renew "${@}";;
  ""|-h|--help) usage;;
  *) echo "Unknown command: ${1:-}" >&2; usage; exit 2;;
esac

