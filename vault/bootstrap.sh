#!/bin/sh
# Runs Vault with persistent file storage (vault/config.hcl), so keys survive restarts.
#  - First start: initializes Vault and saves the unseal key and root token to /vault/keys/init.json
#    (a Docker volume, never the project folder).
#  - Every start: unseals Vault automatically, then makes sure the secrets engines, Transit keys,
#    the "bintalk-api" policy (vault/policy.hcl) and the API's token exist. The token is written
#    to /vault/app-token/token (a volume the API mounts read-only); it is limited to that policy
#    and renewed by the API, so no root token is handed to the application.
#
# DEVELOPMENT ONLY: keeping the unseal key next to the data is convenient but means anyone with
# access to the Docker volumes can unseal Vault. Production should use auto-unseal (cloud KMS/HSM)
# and must back up the vault_data volume: losing it makes all encrypted data unreadable.
set -eu

export VAULT_ADDR="http://127.0.0.1:8200"
KEYS_FILE=/vault/keys/init.json
APP_TOKEN_FILE=/vault/app-token/token
APP_POLICY=bintalk-api
# Earlier versions gave the API this fixed token with the root policy; it is revoked below.
LEGACY_TOKEN=ROOT_TOKEN_DEV_ONLY

mkdir -p /vault/keys /vault/app-token
chmod 700 /vault/keys
chmod 755 /vault/app-token

vault server -config=/vault/config/config.hcl &
VAULT_PID=$!
trap 'kill -TERM "$VAULT_PID" 2>/dev/null; wait "$VAULT_PID"' TERM INT

# `vault status` exits 0 when unsealed, 2 when sealed/uninitialized, 1 when unreachable.
until status=0; vault status >/dev/null 2>&1 || status=$?; [ "$status" -ne 1 ]; do
  sleep 1
done

json_value() { # json_value <file> <key>: first string value of key (single-line JSON or arrays)
  tr -d '\n ' < "$1" | sed -n "s/.*\"$2\":\[\{0,1\}\"\([^\"]*\)\".*/\1/p"
}

if vault status -format=json 2>/dev/null | tr -d '\n ' | grep -q '"initialized":false'; then
  echo "bootstrap: initializing Vault (first start)"
  vault operator init -key-shares=1 -key-threshold=1 -format=json > "$KEYS_FILE.tmp"
  mv "$KEYS_FILE.tmp" "$KEYS_FILE"
  chmod 600 "$KEYS_FILE"
fi

if [ ! -s "$KEYS_FILE" ]; then
  echo "bootstrap: Vault is initialized but $KEYS_FILE is missing; unseal it manually" >&2
  wait "$VAULT_PID"
  exit 1
fi

if vault status >/dev/null 2>&1; then
  echo "bootstrap: Vault already unsealed"
else
  vault operator unseal "$(json_value "$KEYS_FILE" unseal_keys_b64)" >/dev/null
  echo "bootstrap: Vault unsealed"
fi

VAULT_TOKEN="$(json_value "$KEYS_FILE" root_token)"
export VAULT_TOKEN

vault secrets list -format=json | tr -d '\n ' | grep -q '"secret/"' \
  || vault secrets enable -path=secret -version=2 kv
vault secrets list -format=json | tr -d '\n ' | grep -q '"transit/"' \
  || vault secrets enable transit
for key in api-header-encryption database-encryption; do
  vault read "transit/keys/$key" >/dev/null 2>&1 \
    || vault write -f "transit/keys/$key" type=aes256-gcm96 >/dev/null
done

vault policy write "$APP_POLICY" /vault/policy.hcl >/dev/null

# The API's token: limited to the bintalk-api policy, periodic (the API renews it), and orphan so
# it survives the revocation of whoever created it. Reissued if missing or no longer valid.
if [ -s "$APP_TOKEN_FILE" ] \
  && vault token lookup -format=json "$(cat "$APP_TOKEN_FILE")" 2>/dev/null | tr -d '\n ' | grep -q "\"$APP_POLICY\""; then
  echo "bootstrap: API token is valid"
else
  vault token create -policy="$APP_POLICY" -period=168h -orphan -display-name=bintalk-api \
    -field=token > "$APP_TOKEN_FILE.tmp"
  mv "$APP_TOKEN_FILE.tmp" "$APP_TOKEN_FILE"
  echo "bootstrap: issued a new API token (policy $APP_POLICY)"
fi
# Readable by the API container's non-root user; the volume is only mounted into vault and api.
chmod 644 "$APP_TOKEN_FILE"

if vault token lookup "$LEGACY_TOKEN" >/dev/null 2>&1; then
  vault token revoke "$LEGACY_TOKEN" >/dev/null
  echo "bootstrap: revoked the legacy root-policy development token"
fi

echo "bootstrap: Vault ready (persistent storage at /vault/data)"
wait "$VAULT_PID"
