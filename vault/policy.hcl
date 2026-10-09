# Vault policy "bintalk-api": exactly what the BinTalk API server (and its rotate-keys command)
# uses. vault/bootstrap.sh installs it and issues the API's token with it. The secrets engines
# and Transit keys are created by the bootstrap, so the API needs no sys/mounts write access.

# Startup check that the KV and Transit engines are mounted.
path "sys/mounts" {
  capabilities = ["read"]
}

# The RSA key pair for header/response encryption (created on first start, then read).
path "secret/data/bintalk/*" {
  capabilities = ["create", "read", "update"]
}

# Transit: wrap/unwrap data keys and serve the encryption endpoints.
path "transit/encrypt/database-encryption" {
  capabilities = ["update"]
}
path "transit/decrypt/database-encryption" {
  capabilities = ["update"]
}
path "transit/encrypt/api-header-encryption" {
  capabilities = ["update"]
}
path "transit/decrypt/api-header-encryption" {
  capabilities = ["update"]
}

# Key metadata for startup checks and the admin encryption status page.
path "transit/keys" {
  capabilities = ["list"]
}
path "transit/keys/database-encryption" {
  capabilities = ["read"]
}
path "transit/keys/api-header-encryption" {
  capabilities = ["read"]
}

# `api-server rotate-keys`: rotate the data-key wrapping key and re-wrap stored data keys.
# Remove these two if rotation should need a separate operator token.
path "transit/keys/database-encryption/rotate" {
  capabilities = ["update"]
}
path "transit/rewrap/database-encryption" {
  capabilities = ["update"]
}
