#!/usr/bin/env bash
# Starts the compose stack with secrets generated on first use and kept outside the repo (mode 600).
# Reruns reuse them, so the database in an existing volume still accepts its password.
set -euo pipefail
cd "$(dirname "$0")/.."
ENV_FILE=${SENTINEL_ENV_FILE:-$HOME/.config/sentinel-stream/compose.env}
if [[ ! -f $ENV_FILE ]]; then
  mkdir -p "$(dirname "$ENV_FILE")"
  umask 077
  {
    for name in SENTINEL_DB_PASSWORD SENTINEL_REDIS_PASSWORD SENTINEL_S3_SECRET_KEY SENTINEL_WEBHOOK_SECRET; do
      echo "$name=$(openssl rand -hex 24)"
    done
    echo "SENTINEL_S3_ACCESS_KEY=sentinel$(openssl rand -hex 6)"
    # Ed25519 PKCS#8 key as one line of base64 DER; the app accepts it with or without PEM armour.
    echo "SENTINEL_AUDIT_SIGNING_KEY=$(openssl genpkey -algorithm ed25519 -outform DER | base64 -w0)"
  } > "$ENV_FILE"
  echo "wrote new secrets to $ENV_FILE"
fi
exec docker compose --env-file "$ENV_FILE" up -d --wait --wait-timeout "${WAIT:-300}" "$@"
