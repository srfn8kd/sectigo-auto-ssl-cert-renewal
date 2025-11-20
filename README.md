
Sectigo SSL Issuance + Auto-Renew + Trust Utilities (README)
=======================================================

Overview
--------
This toolkit is currently coded Splunk Forwarder specific but can be easily
adjusted to fit any scenario.  As configured it automates Sectigo certificate
enrollment and renewal, and provides small helpers for building a trust bundle
to validate servers using Let’s Encrypt (e.g., Splunk indexers utilizing
Lets Encrypt for SSL certs).

I created it because there was no easy way to manage Windows SSL certificates
so the purpose as written here is for use on a Splunk Deployment Server, which
will handle all the cert generations and renewals and then the Windows Forwarders
will pick them up as needed.

Components
----------
- sectigo.sh          : User-facing CLI with two subcommands:
                        • forwarder-issue  – one-shot CSR/issue/retrieval
                        • cron-renew       – scan certs and renew if expiring
- sectigo-api.sh      : API helpers for Sectigo (enroll/poll/download/assemble)
- sectigo-token.sh    : Token helper (sourced by the API flow)
- sectigo.env         : Configuration (editable; sourced by all scripts)
- sectigo-trust.sh    : Trust helpers for Let’s Encrypt bundles
                        • le-trust         – fetch LE R3 + ISRG Root X1
                        • compose-trust    – compose Sectigo chain + LE bundle

What it does
------------
1) One-shot issuance: Generates a CSR (reusing the given private key), submits
   to Sectigo, polls for issuance, and writes:
   - <key-basename>.crt     (leaf; filename matches the private key basename)
   - chain.pem              (Sectigo intermediates)
   - cert.pem               (symlink/copy of the leaf for compatibility)
   - forwarder.pem          (key + leaf + chain; suitable for many clients)

2) Auto-renew (cron-safe): Scans a cert directory for *.crt, checks NotAfter,
   and renews certificates within the configured threshold. It reuses the
   matching private key automatically and preserves CN/SANs.

3) Trust utilities (optional): Builds a small Let’s Encrypt trust bundle and a
   composed trust (Sectigo chain + LE bundle) for clients that must trust
   LE-signed servers (e.g., Splunk indexers). This does NOT change the
   presented client chain (which remains Sectigo-only).

Prerequisites
-------------
- bash 4+  | openssl  | curl  | jq  | awk | sed | date (GNU coreutils)
- Network egress to Sectigo / cert-manager.com and letsencrypt.org (if using
  trust helpers).
- Ensure directories specified in sectigo.env exist and are writable.

Installation & Layout
---------------------
Place all files in the same directory, e.g. /fullPathTo/sectigo, and ensure:
  chmod +x sectigo.sh sectigo-api.sh sectigo-token.sh sectigo-trust.sh
Edit and source "sectigo.env" in your shell or let the scripts source it.

Security Notes
--------------
- Keep private keys (keys/*.pem) 0400/0600 and accessible only to the account
  that runs the issuer/renewal.
- "forwarder.pem" contains the private key; it is written 0600.
- Treat sectigo.env as sensitive if it contains credentials/tokens.

===============================================================================
USAGE
===============================================================================

A) One-shot issuance (forwarder-issue)
--------------------------------------
Example:
  ./sectigo.sh forwarder-issue \
    --key /fullPathTo/sectigo/keys/example-private.pem \
    --cn  example1.example.com \
    --sans "DNS:example2.example.com,DNS:example3.example.com" \
    --out-dir /fullPathTo/sectigo/certs \
    --quiet --lock \
    --comment "Requested by $(hostname -f) on $(date -u +%F)"

Required flags:
  --key PATH                 Path to existing private key (PEM)
  --cn FQDN                  Certificate Common Name
  --sans "DNS:a,DNS:b,..."   Comma-separated SANs (prefix each with DNS:)
  --out-dir DIR              Output directory for cert artifacts

Optional flags:
  --comment "TEXT"           Stores an order comment with Sectigo
  --quiet                    Less console output
  --lock                     Use the lock file defined in sectigo.env

Outputs (in --out-dir):
  <key-basename>.crt   (leaf certificate)
  chain.pem            (Sectigo intermediates)
  cert.pem             (symlink or copy of the leaf for compatibility)
  forwarder.pem        (key + leaf + chain; mode 0600)

B) Auto-Renew (cron-renew)
--------------------------
Purpose: Renew any *.crt in a directory that expire within N days.
Suitable for running daily by cron

Example (manual run):
  ./sectigo.sh cron-renew \
    --certs-dir /fullPathTo/sectigo/certs \
    --keys-dir  /fullPathTo/sectigo/keys \
    --days 5 \
    --lock \
    --auto-comment \
    --verbose

Flags:
  --certs-dir DIR            Directory containing *.crt (default: $HERE/certs)
  --keys-dir  DIR            Directory with matching private keys (*.pem)
  --days N                   Renew if NotAfter <= N days (default: env)
  --no-lock                  Disable lock usage
  --verbose                  Chatty output (default quiet)
  --dry-run                  Show what would renew; do not change anything
  --force                    Renew regardless of NotAfter threshold
  --jitter SECONDS           Random start delay (default from env)
  --auto-comment             Attach an informative comment automatically

Behavior highlights:
  - Matches key by basename: e.g., foo.crt → keys/foo.pem
  - Extracts CN + SANs from the existing cert for renewal reuse
  - Uses a simple throttle (env-configurable) to avoid repeating renewals too
    frequently for the same cert (unless --force is used).
  - Safe for cron; supports locking and jitter.

Cron example (daily at 02:30 with 60s jitter):
  30 2 * * * /fullPathTo/sectigo/sectigo.sh cron-renew \
    --certs-dir /fullPathTo/sectigo/certs \
    --keys-dir  /fullPathTo/sectigo/keys \
    --days 5 --lock --jitter 60 --quiet >> /fullPathTo/sectigo/logs/cron-renew.log 2>&1

C) Trust Helpers (Let’s Encrypt) – optional
-------------------------------------------
Keep the client’s presented chain Sectigo-only. If your servers (e.g. Splunk
indexers) use Let’s Encrypt, you can add LE CA certs to the trust bundle used
to verify servers.

1) Build/refresh the LE bundle:
   ./sectigo-trust.sh le-trust --out-dir /fullPathTo/sectigo/certs
   Outputs:
     lets-encrypt-r3.pem, isrgrootx1.pem, le-ca-bundle.pem

2) Compose a combined trust (Sectigo chain + LE bundle):
   ./sectigo-trust.sh compose-trust \
     --certs-dir /fullPathTo/sectigo/certs \
     --out-dir  /fullPathTo/sectigo/certs
   Output:
     sectigo_and_le_roots.pem   # CA certs only, suitable for trust/verification

Splunk example (outputs.conf):
  [tcpout:primary]
  server = indexer1.example.com:9998,indexer2.example.com:9998
  sslCertPath     = /fullPathTo/sectigo/certs/forwarder.pem
  sslRootCAPath   = /fullPathTo/sectigo/certs/sectigo_and_le_roots.pem
  sslVerifyServerCert = true

===============================================================================
CONFIGURATION (sectigo.env)
===============================================================================
You can set/override defaults here; scripts source this file automatically.

Renewal thresholds & jitter:
  export SECTIGO_RENEW_DAYS=5                 # default for cron-renew --days
  export SECTIGO_CRON_JITTER_MAX=60           # default jitter seconds
  export SECTIGO_RENEW_MIN_INTERVAL_HOURS=24  # throttle repeat renewals
  export SECTIGO_STATE_DIR="$HERE/state"      # throttle stamps location

Notifications (optional):
  export SECTIGO_NOTIFY_CMD="logger -t sectigo-renew"
  # The command is invoked as: $SECTIGO_NOTIFY_CMD <level> <message>

Trust defaults (optional):
  export LE_R3_URL="https://letsencrypt.org/certs/lets-encrypt-r3.pem"
  export LE_ISRG_ROOT_URL="https://letsencrypt.org/certs/isrgrootx1.pem"
  export SECTIGO_TRUST_OUT_DIR="$HERE/certs"
  export SECTIGO_LE_BUNDLE_NAME="le-ca-bundle.pem"
  export SECTIGO_COMPOSED_TRUST_NAME="sectigo_and_le_roots.pem"

Order comments (optional):
  export SECTIGO_ORDER_COMMENT="Routine renewal via automation"

Locking:
  export SECTIGO_LOCK_FILE="$HERE/.sectigo.lock"

===============================================================================
TROUBLESHOOTING
===============================================================================
- "parameter null or not set": a required option’s value was empty. Ensure you
  passed non-empty values for flags like --cn/--key/--sans/--out-dir.
- "CN parse failed" during cron-renew: the certificate subject was unusual.
  Consider forcing renewal with explicit --cn/--sans via forwarder-issue, or
  verify the current cert’s subject formatting with:
    openssl x509 -in /path/to/cert.crt -noout -subject -nameopt RFC2253
- Permission denied writing output: ensure --out-dir exists and is writable.
- Missing jq/curl/openssl: install prerequisites via your package manager.

===============================================================================
LICENSE / WARRANTY
===============================================================================
This automation is provided as-is with no warranty. Validate outputs and test
in a non-production environment before widespread deployment.

