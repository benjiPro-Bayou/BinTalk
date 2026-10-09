#!/bin/bash
set -e

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-ROOT_TOKEN_DEV_ONLY}"

echo "Initializing Vault..."

# Wait for Vault to be ready
until curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null; do
    echo "Waiting for Vault to be ready..."
    sleep 2
done

echo "Vault is ready"

# Enable KV v2 secret engine
curl -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -d '{"type": "kv", "options": {"version": "2"}}' \
    "$VAULT_ADDR/v1/sys/mounts/secret" || true

# Enable Transit engine for encryption
curl -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -d '{"type": "transit"}' \
    "$VAULT_ADDR/v1/sys/mounts/transit" || true

# Create encryption key for API headers
curl -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ADDR/v1/transit/keys/api-header-encryption" \
    -d '{
        "type": "aes256-gcm96",
        "exportable": false
    }' || true

# Create encryption key for database fields
curl -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ADDR/v1/transit/keys/database-encryption" \
    -d '{
        "type": "aes256-gcm96",
        "exportable": false
    }' || true

# Store API encryption key
curl -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ADDR/v1/secret/data/bintalk/api/encryption-key" \
    -d '{
        "data": {
            "key": "'$(openssl rand -base64 32)'",
            "algorithm": "AES-256-GCM"
        }
    }' || true

# Store JWT signing key
JWT_SECRET=$(openssl rand -base64 64)
curl -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ADDR/v1/secret/data/bintalk/jwt/signing-key" \
    -d '{
        "data": {
            "secret": "'$JWT_SECRET'"
        }
    }' || true

# Store database encryption key
curl -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ADDR/v1/secret/data/bintalk/database/encryption-key" \
    -d '{
        "data": {
            "key": "'$(openssl rand -base64 32)'",
            "algorithm": "AES-256-GCM"
        }
    }' || true

# Store Redis password
curl -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ADDR/v1/secret/data/bintalk/redis/credentials" \
    -d '{
        "data": {
            "password": "redis_password_123"
        }
    }' || true

# Create Vault policy for BinTalk application
curl -X PUT \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    "$VAULT_ADDR/v1/sys/policy/bintalk" \
    -d '{
        "policy": "path \"secret/data/bintalk/*\" {\n  capabilities = [\"read\", \"list\"]\n}\npath \"transit/encrypt/api-header-encryption\" {\n  capabilities = [\"update\"]\n}\npath \"transit/decrypt/api-header-encryption\" {\n  capabilities = [\"update\"]\n}\npath \"transit/encrypt/database-encryption\" {\n  capabilities = [\"update\"]\n}\npath \"transit/decrypt/database-encryption\" {\n  capabilities = [\"update\"]\n}\npath \"transit/keys/api-header-encryption\" {\n  capabilities = [\"read\"]\n}\npath \"transit/keys/database-encryption\" {\n  capabilities = [\"read\"]\n}\npath \"sys/leases/renew\" {\n  capabilities = [\"update\"]\n}"
    }' || true

echo "Vault initialization complete"
echo "Vault is available at $VAULT_ADDR"
echo "Token: $VAULT_TOKEN"
