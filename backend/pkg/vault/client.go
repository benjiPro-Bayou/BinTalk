package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
)

const (
	kvMount         = "secret"
	transitMount    = "transit"
	connectAttempts = 15
)

// ErrNotFound is returned when a KV secret does not exist.
var ErrNotFound = errors.New("vault: secret not found")

// VaultConfig holds the settings needed to reach Vault.
type VaultConfig struct {
	Address string
	Token   string
}

// VaultClient wraps the Vault API with the KV v2 and Transit operations BinTalk uses.
type VaultClient struct {
	client  *api.Client
	address string
	logger  *logrus.Logger
	stop    chan struct{}
}

// NewVaultClient connects to Vault and verifies it is initialized and unsealed.
func NewVaultClient(cfg *VaultConfig, logger *logrus.Logger) (*VaultClient, error) {
	if cfg.Token == "" {
		return nil, errors.New("VAULT_TOKEN is not set")
	}

	apiConfig := api.DefaultConfig()
	if cfg.Address != "" {
		apiConfig.Address = cfg.Address
	}
	apiConfig.Timeout = 10 * time.Second

	client, err := api.NewClient(apiConfig)
	if err != nil {
		return nil, fmt.Errorf("create vault client: %w", err)
	}
	client.SetToken(cfg.Token)

	v := &VaultClient{client: client, address: apiConfig.Address, logger: logger, stop: make(chan struct{})}

	for attempt := 1; ; attempt++ {
		health, err := v.Health(context.Background())
		if err == nil && health.Initialized && !health.Sealed {
			break
		}
		if err == nil {
			err = fmt.Errorf("initialized=%t sealed=%t", health.Initialized, health.Sealed)
		}
		if attempt == connectAttempts {
			return nil, fmt.Errorf("vault at %s is not ready: %w", v.address, err)
		}
		logger.Warnf("Vault not ready (attempt %d/%d): %v", attempt, connectAttempts, err)
		time.Sleep(2 * time.Second)
	}

	// Fail fast on a bad token rather than on the first request.
	self, err := client.Auth().Token().LookupSelfWithContext(context.Background())
	if err != nil {
		return nil, fmt.Errorf("vault token rejected: %w", err)
	}
	if policies, _ := self.TokenPolicies(); containsString(policies, "root") {
		logger.Warn("The Vault token has the root policy. Use a token limited to the bintalk-api policy " +
			"(vault/policy.hcl); a leaked root token exposes every key.")
	}
	if renewable, _ := self.TokenIsRenewable(); renewable {
		go v.renewLoop()
	}

	return v, nil
}

// renewLoop keeps a periodic (renewable) token alive by renewing it every 12 hours.
func (v *VaultClient) renewLoop() {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-v.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if _, err := v.client.Auth().Token().RenewSelfWithContext(ctx, 0); err != nil {
				v.logger.WithError(err).Error("Failed to renew the Vault token")
			}
			cancel()
		}
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// Close stops the token renewal loop.
func (v *VaultClient) Close() {
	select {
	case <-v.stop:
	default:
		close(v.stop)
	}
}

// Address returns the Vault server address.
func (v *VaultClient) Address() string {
	return v.address
}

// Health returns Vault's health status.
func (v *VaultClient) Health(ctx context.Context) (*api.HealthResponse, error) {
	return v.client.Sys().HealthWithContext(ctx)
}

// EnsureEngines mounts the KV v2 and Transit secrets engines if they are missing.
func (v *VaultClient) EnsureEngines(ctx context.Context) error {
	mounts, err := v.client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return fmt.Errorf("list mounts: %w", err)
	}

	if _, ok := mounts[kvMount+"/"]; !ok {
		input := &api.MountInput{Type: "kv", Options: map[string]string{"version": "2"}}
		if err := v.client.Sys().MountWithContext(ctx, kvMount, input); err != nil {
			return fmt.Errorf("mount %s: %w", kvMount, err)
		}
		v.logger.Infof("Mounted Vault KV v2 engine at %s/", kvMount)
	}

	if _, ok := mounts[transitMount+"/"]; !ok {
		if err := v.client.Sys().MountWithContext(ctx, transitMount, &api.MountInput{Type: "transit"}); err != nil {
			return fmt.Errorf("mount %s: %w", transitMount, err)
		}
		v.logger.Infof("Mounted Vault Transit engine at %s/", transitMount)
	}

	return nil
}

// EnsureTransitKey creates an aes256-gcm96 Transit key if it does not exist.
func (v *VaultClient) EnsureTransitKey(ctx context.Context, name string) error {
	existing, err := v.client.Logical().ReadWithContext(ctx, transitMount+"/keys/"+name)
	if err != nil {
		return fmt.Errorf("read transit key %s: %w", name, err)
	}
	if existing != nil {
		return nil
	}

	_, err = v.client.Logical().WriteWithContext(ctx, transitMount+"/keys/"+name, map[string]interface{}{
		"type":       "aes256-gcm96",
		"exportable": false,
	})
	if err != nil {
		return fmt.Errorf("create transit key %s: %w", name, err)
	}
	v.logger.Infof("Created Vault Transit key %s", name)
	return nil
}

// ListTransitKeys returns the names of all Transit keys.
func (v *VaultClient) ListTransitKeys(ctx context.Context) ([]string, error) {
	secret, err := v.client.Logical().ListWithContext(ctx, transitMount+"/keys")
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return []string{}, nil
	}

	raw, _ := secret.Data["keys"].([]interface{})
	keys := make([]string, 0, len(raw))
	for _, k := range raw {
		if name, ok := k.(string); ok {
			keys = append(keys, name)
		}
	}
	return keys, nil
}

// TransitEncrypt encrypts plaintext with the named Transit key and returns Vault's ciphertext ("vault:v1:...").
func (v *VaultClient) TransitEncrypt(ctx context.Context, key string, plaintext []byte) (string, error) {
	secret, err := v.client.Logical().WriteWithContext(ctx, transitMount+"/encrypt/"+key, map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", errors.New("vault returned no data")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", errors.New("vault response missing ciphertext")
	}
	return ciphertext, nil
}

// TransitDecrypt decrypts Vault ciphertext with the named Transit key.
func (v *VaultClient) TransitDecrypt(ctx context.Context, key, ciphertext string) ([]byte, error) {
	secret, err := v.client.Logical().WriteWithContext(ctx, transitMount+"/decrypt/"+key, map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, errors.New("vault returned no data")
	}

	encoded, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, errors.New("vault response missing plaintext")
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// TransitRotate creates a new version of a Transit key. Older versions remain available for
// decryption, so data encrypted before the rotation stays readable.
func (v *VaultClient) TransitRotate(ctx context.Context, key string) error {
	_, err := v.client.Logical().WriteWithContext(ctx, transitMount+"/keys/"+key+"/rotate", nil)
	return err
}

// TransitRewrap re-encrypts Vault ciphertext with the latest version of the key without
// exposing the plaintext.
func (v *VaultClient) TransitRewrap(ctx context.Context, key, ciphertext string) (string, error) {
	secret, err := v.client.Logical().WriteWithContext(ctx, transitMount+"/rewrap/"+key, map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", errors.New("vault returned no data")
	}
	rewrapped, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", errors.New("vault response missing ciphertext")
	}
	return rewrapped, nil
}

// TransitKeyVersion returns the latest version of a Transit key.
func (v *VaultClient) TransitKeyVersion(ctx context.Context, key string) (int, error) {
	secret, err := v.client.Logical().ReadWithContext(ctx, transitMount+"/keys/"+key)
	if err != nil {
		return 0, err
	}
	if secret == nil {
		return 0, ErrNotFound
	}
	switch latest := secret.Data["latest_version"].(type) {
	case json.Number:
		n, err := latest.Int64()
		return int(n), err
	case float64:
		return int(latest), nil
	}
	return 0, errors.New("vault response missing latest_version")
}

// StorageType returns Vault's storage backend ("inmem" in dev mode, "file", "raft", ...).
func (v *VaultClient) StorageType(ctx context.Context) (string, error) {
	status, err := v.client.Sys().SealStatusWithContext(ctx)
	if err != nil {
		return "", err
	}
	return status.StorageType, nil
}

// KVGet reads a KV v2 secret. It returns ErrNotFound if the secret does not exist.
func (v *VaultClient) KVGet(ctx context.Context, path string) (map[string]interface{}, error) {
	secret, err := v.client.KVv2(kvMount).Get(ctx, path)
	if errors.Is(err, api.ErrSecretNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return secret.Data, nil
}

// KVPut writes a KV v2 secret.
func (v *VaultClient) KVPut(ctx context.Context, path string, data map[string]interface{}) error {
	_, err := v.client.KVv2(kvMount).Put(ctx, path, data)
	return err
}

// KVCreate writes a KV v2 secret only if it does not exist yet (check-and-set 0), so two
// instances starting at once cannot both create it.
func (v *VaultClient) KVCreate(ctx context.Context, path string, data map[string]interface{}) error {
	_, err := v.client.KVv2(kvMount).Put(ctx, path, data, api.WithCheckAndSet(0))
	return err
}
