#!/usr/bin/env bash
# shellcheck shell=bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$HERE/sectigo.env"

_jq() { jq -r "$@"; }
log() { printf '%s %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" | tee -a "$SECTIGO_LOG_FILE" >&2; }

# -------- Enrollment token helper --------
get_enroll_token() {
  local resp token
  resp="$(curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    -X POST "$SECTIGO_AUTH_URL" \
    -d grant_type=client_credentials \
    -d "client_id=$SECTIGO_ENROLL_CLIENT_ID" \
    -d "client_secret=$SECTIGO_ENROLL_CLIENT_SECRET")"
  token="$(_jq '.access_token // empty' <<<"$resp")"
  [[ -n "$token" ]] || { echo "ERROR: Unable to obtain Enrollment token." >&2; echo "$resp" | jq . >&2 || echo "$resp" >&2; return 1; }
  echo "$token"
}

# -------- Enrollment API helpers (Bearer) --------
_enroll_get() {
  local path="$1" token="${2:-}"
  [[ -z "$token" ]] && token="$(get_enroll_token)"
  curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    -H "Authorization: Bearer $token" \
    "$SECTIGO_ENROLL_BASE$path"
}

_enroll_post() {
  local path="$1" body="$2" token="${3:-}"
  [[ -z "$token" ]] && token="$(get_enroll_token)"
  curl -sS --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" \
    -X POST "$SECTIGO_ENROLL_BASE$path" \
    -d "$body"
}

# -------- CSR helpers --------
normalize_csr() {
  awk 'BEGIN{p=0}
       /-----BEGIN CERTIFICATE REQUEST-----/ {p=1}
       p {print}
       /-----END CERTIFICATE REQUEST-----/ {p=0}' "${1:?}"
}

make_csr_openssl_cfg() {
  # $1=CN, $2=SANS (comma-separated "DNS:a.example,DNS:b.example")
  # Optional subject via env: C, ST, L, O, OU
  local cn="$1"; local sans="$2"
  cat <<CFG
[ req ]
default_bits       = 3072
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
CN = ${cn}
$( [[ -n "${C:-}"  ]] && echo "C = ${C}" )
$( [[ -n "${ST:-}" ]] && echo "ST = ${ST}" )
$( [[ -n "${L:-}"  ]] && echo "L = ${L}" )
$( [[ -n "${O:-}"  ]] && echo "O = ${O}" )
$( [[ -n "${OU:-}" ]] && echo "OU = ${OU}" )

[ req_ext ]
$( [[ -n "$sans" ]] && echo "subjectAltName = ${sans}" )
CFG
}

# New: build a CSR from an existing private key (non-interactive; values from env or flags)
make_csr_from_key() {
  # Args:
  #   --key PATH (required, existing key)
  #   --csr-out PATH (required)
  #   [--cn FQDN] [--sans "DNS:a.example,DNS:b.example"]
  #   [--country C] [--state ST] [--locality L] [--org O] [--ou OU] [--email addr]
  local KEY="" CSR_OUT="" CN="" SANS="" C="" ST="" L="" O="" OU="" EMAIL=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --key)      KEY="${2:?}"; shift 2;;
      --csr-out)  CSR_OUT="${2:?}"; shift 2;;
      --cn)       CN="${2:?}"; shift 2;;
      --sans)     SANS="${2:?}"; shift 2;;
      --country)  C="${2:?}"; shift 2;;
      --state)    ST="${2:?}"; shift 2;;
      --locality) L="${2:?}"; shift 2;;
      --org)      O="${2:?}"; shift 2;;
      --ou)       OU="${2:?}"; shift 2;;
      --email)    EMAIL="${2:?}"; shift 2;;
      *) echo "Unknown arg: $1" >&2; return 2;;
    esac
  done

  [[ -f "$KEY" && -n "$CSR_OUT" ]] || { echo "make_csr_from_key: --key and --csr-out required" >&2; return 2; }

  # Fall back to env defaults if flags not provided
  : "${CN:=${CSR_CN_DEFAULT:-}}"
  : "${C:=${CSR_COUNTRY:-}}"
  : "${ST:=${CSR_STATE:-}}"
  : "${L:=${CSR_LOCALITY:-}}"
  : "${O:=${CSR_ORG:-}}"
  : "${OU:=${CSR_OU:-}}"
  : "${EMAIL:=${CSR_EMAIL:-}}"
  : "${SANS:=${CSR_SANS_DEFAULT:-}}"

  [[ -n "$CN" ]] || { echo "Common Name (CN) not provided and CSR_CN_DEFAULT is empty" >&2; return 2; }

  # Build -subj string (only include components that are non-empty)
  subj="/CN=$CN"
  [[ -n "$C"     ]] && subj="/C=$C$subj"
  [[ -n "$ST"    ]] && subj="/ST=$ST$subj"
  [[ -n "$L"     ]] && subj="/L=$L$subj"
  [[ -n "$O"     ]] && subj="/O=$O$subj"
  [[ -n "$OU"    ]] && subj="/OU=$OU$subj"
  [[ -n "$EMAIL" ]] && subj="/emailAddress=$EMAIL$subj"

  umask 177

  # Compose args for SANs
  # OpenSSL 1.1.1+ supports -addext; it safely omits “extra attributes”.
  if [[ -n "$SANS" ]]; then
    openssl req -new -key "$KEY" -out "$CSR_OUT" -subj "$subj" -addext "subjectAltName=$SANS" >/dev/null 2>&1
  else
    openssl req -new -key "$KEY" -out "$CSR_OUT" -subj "$subj" >/dev/null 2>&1
  fi

  echo "$CSR_OUT"
}


# -------- ENROLL: POST /api/v1/certificates (SSL) --------
enroll_ssl() {
  local csr_file="${1:?usage: enroll_ssl <CSR_FILE> [json_overrides]}"
  local overrides_input="${2-}"
  local csr; csr="$(normalize_csr "$csr_file")"
  local body; local base='{"csr": $csr}'
  if [[ -n "${overrides_input:-}" ]] && echo "$overrides_input" | jq -e . >/dev/null 2>&1; then
    body="$(jq -n --arg csr "$csr" --argjson o "$overrides_input" \
            "$base + ( ( $o | type == \"object\" ) ? $o : {} )")"
  else
    body="$(jq -n --arg csr "$csr" "$base")"
  fi
  _enroll_post "/api/v1/certificates" "$body"
}

# -------- Item endpoints --------
get_cert()        { local id="${1:?cert_id required}"; _enroll_get  "/api/v1/certificates/$id"; }
get_cert_status() { local id="${1:?cert_id required}"; _enroll_get  "/api/v1/certificates/$id/status"; }
renew_cert()      { local id="${1:?cert_id required}"; local body="${2:-{}}"; _enroll_post "/api/v1/certificates/$id/renew"   "$body"; }
replace_cert()    {
  local id="${1:?cert_id required}"; local csr_file="${2:?usage: replace_cert <cert_id> <CSR_FILE> [json_overrides]}"; local ov="${3:-{}}"
  local csr; csr="$(normalize_csr "$csr_file")"
  local body; body="$(jq -n --arg csr "$csr" --argjson o "$ov" '{csr:$csr} + ( ( $o | type=="object") ? $o : {} )')"
  _enroll_post "/api/v1/certificates/$id/replace" "$body"
}

# -------- Poller --------

# -------- Poller: waits until issued/ready (case-insensitive) --------
wait_until_issued() {
  local id="${1:?cert_id required}"
  local start now waited=0 backoff="$SECTIGO_POLL_BACKOFF_MIN"
  start="$(date +%s)"
  while :; do
    local resp status status_upper
    resp="$(get_cert_status "$id")"
    # Try a few common fields; adjust as needed for your tenant’s schema
    status="$(jq -r '.status // .state // .certificateStatus // empty' <<<"$resp")"
    status_upper="$(printf '%s' "$status" | tr '[:lower:]' '[:upper:]')"

    log "status($id) => ${status:-unknown}"

    case "$status_upper" in
      ISSUED|READY|COLLECTABLE|COLLECTED)
        # Emit the final status JSON and return success
        jq . <<<"$resp"
        return 0
        ;;
      *)
        # keep polling
        ;;
    esac

    now="$(date +%s)"; waited=$(( now - start ))
    if (( waited >= SECTIGO_POLL_MAX_WAIT )); then
      echo "ERROR: Timed out after $waited s" >&2
      jq . <<<"$resp"
      return 1
    fi
    sleep "$backoff"
    backoff=$(( backoff * 2 ))
    (( backoff > SECTIGO_POLL_BACKOFF_MAX )) && backoff="$SECTIGO_POLL_BACKOFF_MAX"
  done
}


# -------- Collect & assemble Splunk forwarder.pem --------
# -------- Collect & assemble Splunk forwarder.pem (JSON or PEM response) --------
collect_cert_materials() {
  local id="${1:?usage: collect_cert_materials <cert_id> --out DIR --key PATH }"
  shift || true
  local out_dir="" key_path=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --out) out_dir="${2:?}"; shift 2;;
      --key) key_path="${2:?}"; shift 2;;
      *) echo "Unknown arg: $1" >&2; return 2;;
    esac
  done
  [[ -n "$out_dir" && -n "$key_path" ]] || { echo "--out and --key are required" >&2; return 2; }
  mkdir -p "$out_dir"
# Compute leaf filename based on the private key name:
# e.g., /path/keys/example1-private.pem -> example1-private.crt
local key_base leaf_filename leaf_path
key_base="$(basename "$key_path")"
key_base="${key_base%.*}"                 # strip .pem or any extension
leaf_filename="${key_base}.crt"
leaf_path="$out_dir/$leaf_filename"

# Helper to write leaf to both the requested .crt path and maintain legacy cert.pem
write_leaf_files() {
  local leaf_content="$1"
  printf '%s\n' "$leaf_content" > "$leaf_path"; log "wrote $leaf_path"
  # Maintain backward compatibility: also write/overwrite cert.pem (symlink if possible)
  # Try to create a symlink; if it fails (e.g., FS restrictions), fall back to copy.
  rm -f "$leaf_path" 2>/dev/null || true
  ln -s "$leaf_filename" "$leaf_path" 2>/dev/null || { printf '%s\n' "$leaf_content" > "$leaf_path"; }
  [[ -s "$leaf_path" ]] && log "updated $out_dir/cert.pem -> $leaf_filename"
}


  # Fetch the item; some tenants return JSON, others return PEM directly.
  local resp
  resp="$(get_cert "$id" 2>/dev/null || true)"

  # Heuristic: JSON if first non-space char is '{', else treat as PEM.
  local first_char
  first_char="$(printf '%s' "$resp" | sed -n 's/^[[:space:]]*\(.\).*$/\1/p' | head -1)"

  umask 177
  if [[ "$first_char" == "{" ]]; then
    # JSON mode: try known fields
    local leaf chain
    leaf="$(jq -r '.certificate // .cert // .pem // empty' <<<"$resp" 2>/dev/null || true)"
    chain="$(jq -r '.caCertificate // .chain // .chainPem // empty' <<<"$resp" 2>/dev/null || true)"

    if [[ -z "$leaf" ]]; then
      echo "No certificate found in JSON response" >&2
      echo "$resp" | jq . >&2 || printf '%s\n' "$resp" >&2
      return 1
    fi

    write_leaf_files "$leaf"
    if [[ -n "$chain" ]]; then
      printf '%s\n' "$chain" > "$out_dir/chain.pem"; log "wrote $out_dir/chain.pem"
    fi

  else
    # PEM mode: response is one or more concatenated certs.
    # Write full body, then split first cert (leaf) vs remainder (chain).
    if ! grep -q "BEGIN CERTIFICATE" <<<"$resp"; then
      echo "Unexpected non-JSON, non-PEM response from get_cert" >&2
      printf '%s\n' "$resp" >&2
      return 1
    fi

    # Normalize line endings and ensure proper PEM formatting
    local fullpem="$out_dir/fullchain.tmp.pem"
    printf '%s\n' "$resp" | sed 's/\r$//' > "$fullpem"

    # Extract first cert block as leaf
    awk '
      BEGIN{found=0; block=0}
      /-----BEGIN CERTIFICATE-----/ {
        block++
        if (block==1) found=1
      }
      found {print}
      /-----END CERTIFICATE-----/ {
        if (block==1) exit
      }
    ' "$fullpem" > "$leaf_path"

    # Extract any remaining certs as chain
    awk '
      BEGIN{block=0; out=0}
      /-----BEGIN CERTIFICATE-----/ {block++}
      { if (block>=2) print }
    ' "$fullpem" > "$out_dir/chain.pem"

    # Clean up chain.pem if empty
    if [[ ! -s "$out_dir/chain.pem" ]]; then rm -f "$out_dir/chain.pem"; fi

    log "wrote $out_dir/cert.pem"
    [[ -s "$out_dir/chain.pem" ]] && log "wrote $out_dir/chain.pem"
    rm -f "$fullpem"
  fi

  # Build Splunk forwarder.pem: private key -> leaf -> chain (if present)
  if [[ ! -s "$leaf_path" ]]; then
    echo "Leaf certificate file missing after collection." >&2
    return 1
  fi
  if [[ ! -s "$key_path" ]]; then
    echo "Private key not found: $key_path" >&2
    return 2
  fi

  if [[ -s "$out_dir/chain.pem" ]]; then
    cat "$key_path" "$leaf_path" "$out_dir/chain.pem" > "$out_dir/forwarder.pem"
  else
    cat "$key_path" "$leaf_path" > "$out_dir/forwarder.pem"
  fi
  chmod 0600 "$out_dir/forwarder.pem"
  log "wrote $out_dir/forwarder.pem"

  # Emit raw JSON only when it was JSON; for PEM, just print a tiny summary
  if [[ "$first_char" == "{" ]]; then
    printf '%s\n' "$resp"
  else
    printf '{"result":"ok","mode":"pem","leaf":"%s","chain":"%s"}\n' \
      "$leaf_path" \
      "$( [[ -s "$out_dir/chain.pem" ]] && echo "$out_dir/chain.pem" || echo "" )"
  fi
}

