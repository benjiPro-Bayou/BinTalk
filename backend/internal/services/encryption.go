package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/bintalk/bintalk-clone/pkg/vault"
)

const (
	// Vault Transit keys
	HeaderTransitKey = "api-header-encryption"
	DataTransitKey   = "database-encryption"

	// Vault KV paths
	rsaKeyPath = "bintalk/api/rsa-keypair"
	// legacyDataKeyPath held the single plaintext data key used before versioned keys.
	// It is imported once as data key version 1.
	legacyDataKeyPath = "bintalk/database/encryption-key"

	// dataKeyName identifies BinTalk's data keys in encryption_key_versions.
	dataKeyName = "message-data-key"

	rsaKeyBits      = 3072
	gcmTagSize      = 16
	gcmNonceSize    = 12
	keyRefreshEvery = time.Minute
)

// blobMagic prefixes encrypted blobs (files, thumbnails): magic(4) | key version(4) | nonce | ciphertext+tag.
// Blobs without it predate versioned keys and were encrypted with version 1.
var blobMagic = []byte("BTK\x01")

var (
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrUnknownKey       = errors.New("data key version is not available")
)

// EncryptionService provides the encryption primitives used across the API:
//   - RSA-OAEP (SHA-256) private key for decrypting values clients encrypt with the published public key
//   - versioned AES-256-GCM data keys for message content, phone numbers and files at rest
//   - Vault Transit for encryption-as-a-service endpoints
//
// Data keys are envelope-encrypted: each version is stored in Postgres wrapped by the Vault
// Transit key "database-encryption". Vault keeps every Transit key version, so rotating the
// Transit key or creating a new data key never makes existing data unreadable. Data is only
// lost if Vault's own storage is lost (e.g. Vault running in dev/in-memory mode).
type EncryptionService struct {
	vault        *vault.VaultClient
	db           *sql.DB
	logger       *logrus.Logger
	privateKey   *rsa.PrivateKey
	publicKeyPEM string
	fingerprint  string
	startedAt    time.Time

	mu            sync.RWMutex
	dataKeys      map[int][]byte
	activeVersion int
	failedKeys    map[int]string // versions that could not be unwrapped, with the reason
	rotationDays  int

	missMu     sync.Mutex
	lastMissAt map[int]time.Time // unknown versions recently looked up, to avoid a reload per decryption
	stop       chan struct{}
}

// missRetryAfter is how long keyFor waits before reloading keys again for the same unknown version.
const missRetryAfter = time.Minute

// DataKeyInfo describes one data key version (never the key itself).
type DataKeyInfo struct {
	Version          int        `json:"version"`
	Active           bool       `json:"active"`
	Available        bool       `json:"available"`
	CreatedAt        time.Time  `json:"created_at"`
	NextRotationDate *time.Time `json:"next_rotation_date,omitempty"`
	Error            string     `json:"error,omitempty"`
}

// EncryptionStatus describes the health of the encryption subsystem.
type EncryptionStatus struct {
	Status               string            `json:"status"`
	Vault                VaultStatus       `json:"vault"`
	TransitKeys          []string          `json:"transit_keys"`
	Algorithms           map[string]string `json:"algorithms"`
	PublicKeyFingerprint string            `json:"public_key_fingerprint"`
	DataKeyVersion       int               `json:"data_key_version"`
	DataKeys             []DataKeyInfo     `json:"data_keys"`
	CheckedAt            time.Time         `json:"checked_at"`
	UptimeSeconds        int64             `json:"uptime_seconds"`
}

// VaultStatus describes the Vault connection.
type VaultStatus struct {
	Reachable         bool   `json:"reachable"`
	Initialized       bool   `json:"initialized"`
	Sealed            bool   `json:"sealed"`
	Version           string `json:"version,omitempty"`
	StorageType       string `json:"storage_type,omitempty"`
	Persistent        bool   `json:"persistent"`
	TransitKeyVersion int    `json:"transit_key_version,omitempty"`
	Error             string `json:"error,omitempty"`
}

// NewEncryptionService prepares Vault (engines and keys) and loads the key material.
// It exits the process if the keys cannot be loaded, since the API cannot run without them.
func NewEncryptionService(vaultClient *vault.VaultClient, database *sql.DB, logger *logrus.Logger) *EncryptionService {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s := &EncryptionService{
		vault:        vaultClient,
		db:           database,
		logger:       logger,
		startedAt:    time.Now(),
		rotationDays: 90,
		lastMissAt:   map[int]time.Time{},
		stop:         make(chan struct{}),
	}
	if days, err := strconv.Atoi(os.Getenv("KEY_ROTATION_INTERVAL")); err == nil && days > 0 {
		s.rotationDays = days
	}

	if storage, err := vaultClient.StorageType(ctx); err == nil && storage == "inmem" {
		logger.Warn("Vault is running in dev (in-memory) mode: all keys are lost when Vault restarts " +
			"and every message encrypted until then becomes unreadable. Use persistent Vault storage.")
	}
	if err := vaultClient.EnsureEngines(ctx); err != nil {
		logger.Fatalf("Failed to prepare Vault secrets engines: %v", err)
	}
	for _, key := range []string{HeaderTransitKey, DataTransitKey} {
		if err := vaultClient.EnsureTransitKey(ctx, key); err != nil {
			logger.Fatalf("Failed to prepare Vault Transit key: %v", err)
		}
	}
	if err := s.loadRSAKey(ctx); err != nil {
		logger.Fatalf("Failed to load RSA key pair: %v", err)
	}
	if err := s.loadDataKeys(ctx); err != nil {
		logger.Fatalf("Failed to load data encryption keys: %v", err)
	}
	if err := s.rotateIfDue(ctx); err != nil {
		logger.WithError(err).Error("Scheduled data key rotation failed; continuing with the current key")
	}

	go s.refreshLoop()
	return s
}

func (s *EncryptionService) loadRSAKey(ctx context.Context) error {
	data, err := s.vault.KVGet(ctx, rsaKeyPath)
	switch {
	case err == nil:
		encoded, _ := data["private_key"].(string)
		block, _ := pem.Decode([]byte(encoded))
		if block == nil {
			return fmt.Errorf("%s does not contain a PEM private key", rsaKeyPath)
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}
		s.privateKey = key
	case errors.Is(err, vault.ErrNotFound):
		key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
		if err != nil {
			return fmt.Errorf("generate RSA key: %w", err)
		}
		privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		if err := s.vault.KVCreate(ctx, rsaKeyPath, map[string]interface{}{
			"private_key": string(privatePEM),
			"algorithm":   "RSA-OAEP-SHA256",
			"created_at":  time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			// Another instance may have created it first: use the stored key, so every instance
			// shares one key pair.
			if _, getErr := s.vault.KVGet(ctx, rsaKeyPath); getErr == nil {
				return s.loadRSAKey(ctx)
			}
			return fmt.Errorf("store RSA key: %w", err)
		}
		s.privateKey = key
		s.logger.Info("Generated new RSA key pair and stored it in Vault")
	default:
		return err
	}

	publicDER, err := x509.MarshalPKIXPublicKey(&s.privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("encode public key: %w", err)
	}
	s.publicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	sum := sha256.Sum256(publicDER)
	s.fingerprint = "SHA256:" + hex.EncodeToString(sum[:])
	return nil
}

type storedKey struct {
	version      int
	wrapped      string
	active       bool
	createdAt    time.Time
	nextRotation *time.Time
}

func (s *EncryptionService) storedKeys(ctx context.Context) ([]storedKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT key_version, wrapped_key, COALESCE(is_active, false), rotation_date, next_rotation_date
		FROM encryption_key_versions
		WHERE key_name = $1 AND wrapped_key IS NOT NULL
		ORDER BY key_version`, dataKeyName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []storedKey
	for rows.Next() {
		var k storedKey
		if err := rows.Scan(&k.version, &k.wrapped, &k.active, &k.createdAt, &k.nextRotation); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// loadDataKeys unwraps every stored data key version. On first start it imports the legacy
// plaintext key from Vault KV (if any) as version 1, so data encrypted with it stays readable.
func (s *EncryptionService) loadDataKeys(ctx context.Context) error {
	keys, err := s.storedKeys(ctx)
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		key, source, err := s.initialDataKey(ctx)
		if err != nil {
			return err
		}
		if err := s.storeDataKey(ctx, 1, key); err != nil {
			return err
		}
		s.logger.Infof("Created data key version 1 (%s), wrapped by Vault Transit key %q", source, DataTransitKey)
		if keys, err = s.storedKeys(ctx); err != nil {
			return err
		}
	}

	unwrapped := make(map[int][]byte, len(keys))
	failed := map[int]string{}
	active := 0
	for _, k := range keys {
		key, err := s.vault.TransitDecrypt(ctx, DataTransitKey, k.wrapped)
		if err != nil || len(key) != 32 {
			reason := "Vault could not unwrap this key"
			if err != nil {
				reason += ": " + err.Error()
			}
			failed[k.version] = reason
			s.logger.Errorf("Data key version %d is unavailable (%s). Data encrypted with it cannot be "+
				"decrypted until Vault's Transit key %q is restored.", k.version, reason, DataTransitKey)
			continue
		}
		unwrapped[k.version] = key
		if k.active {
			active = k.version
		}
	}

	s.mu.Lock()
	s.dataKeys = unwrapped
	s.failedKeys = failed
	s.activeVersion = active
	s.mu.Unlock()

	if active == 0 {
		// No usable active key (e.g. Vault was reset): start a new version so new data can be stored.
		// Older data stays undecryptable unless the original Vault data is restored.
		s.logger.Error("No usable active data key; creating a new version")
		_, err := s.RotateDataKey(ctx)
		return err
	}
	return nil
}

func (s *EncryptionService) initialDataKey(ctx context.Context) ([]byte, string, error) {
	data, err := s.vault.KVGet(ctx, legacyDataKeyPath)
	if err == nil {
		encoded, _ := data["key"].(string)
		key, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(key) != 32 {
			return nil, "", fmt.Errorf("%s must hold a base64-encoded 32-byte key", legacyDataKeyPath)
		}
		return key, "imported from " + legacyDataKeyPath, nil
	}
	if !errors.Is(err, vault.ErrNotFound) {
		return nil, "", err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, "", err
	}
	return key, "newly generated", nil
}

// storeDataKey wraps key with Vault Transit and saves it as the active version.
func (s *EncryptionService) storeDataKey(ctx context.Context, version int, key []byte) error {
	wrapped, err := s.vault.TransitEncrypt(ctx, DataTransitKey, key)
	if err != nil {
		return fmt.Errorf("wrap data key: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`UPDATE encryption_key_versions SET is_active = false WHERE key_name = $1`, dataKeyName); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO encryption_key_versions
			(key_name, key_version, algorithm, is_active, rotation_date, next_rotation_date, vault_key_id, wrapped_key)
		VALUES ($1, $2, 'AES-256-GCM', true, NOW(), NOW() + make_interval(days => $3), $4, $5)`,
		dataKeyName, version, s.rotationDays, "transit/keys/"+DataTransitKey, wrapped); err != nil {
		return err
	}
	return tx.Commit()
}

// RotateDataKey creates a new data key version and makes it active for new data.
// Existing versions remain available for decryption.
func (s *EncryptionService) RotateDataKey(ctx context.Context) (int, error) {
	var latest int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(key_version), 0) FROM encryption_key_versions WHERE key_name = $1`, dataKeyName,
	).Scan(&latest); err != nil {
		return 0, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return 0, err
	}
	version := latest + 1
	if err := s.storeDataKey(ctx, version, key); err != nil {
		return 0, err
	}

	s.mu.Lock()
	if s.dataKeys == nil {
		s.dataKeys = map[int][]byte{}
	}
	s.dataKeys[version] = key
	s.activeVersion = version
	s.mu.Unlock()

	s.logger.Infof("Rotated data key: version %d is now active", version)
	return version, nil
}

// RewrapDataKeys re-encrypts every stored data key with the latest Transit key version
// (useful after rotating the Transit key so old Transit versions can eventually be retired).
func (s *EncryptionService) RewrapDataKeys(ctx context.Context) (int, error) {
	keys, err := s.storedKeys(ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, k := range keys {
		rewrapped, err := s.vault.TransitRewrap(ctx, DataTransitKey, k.wrapped)
		if err != nil {
			return count, fmt.Errorf("rewrap data key version %d: %w", k.version, err)
		}
		if rewrapped == k.wrapped {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `
			UPDATE encryption_key_versions SET wrapped_key = $3
			WHERE key_name = $1 AND key_version = $2`, dataKeyName, k.version, rewrapped); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (s *EncryptionService) rotateIfDue(ctx context.Context) error {
	keys, err := s.storedKeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if k.active && k.nextRotation != nil && time.Now().After(*k.nextRotation) {
			_, err := s.RotateDataKey(ctx)
			return err
		}
	}
	return nil
}

// refreshLoop picks up key versions created by other instances or the rotate-keys command,
// and performs scheduled rotations.
func (s *EncryptionService) refreshLoop() {
	ticker := time.NewTicker(keyRefreshEvery)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := s.reloadKeys(ctx); err != nil {
			s.logger.WithError(err).Warn("Failed to refresh data keys")
		}
		if err := s.rotateIfDue(ctx); err != nil {
			s.logger.WithError(err).Warn("Scheduled data key rotation failed")
		}
		cancel()
	}
}

// reloadKeys unwraps versions that are new (or previously failed) and updates the active version.
func (s *EncryptionService) reloadKeys(ctx context.Context) error {
	keys, err := s.storedKeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		s.mu.RLock()
		_, known := s.dataKeys[k.version]
		s.mu.RUnlock()
		if !known {
			key, err := s.vault.TransitDecrypt(ctx, DataTransitKey, k.wrapped)
			if err != nil || len(key) != 32 {
				continue
			}
			s.mu.Lock()
			s.dataKeys[k.version] = key
			delete(s.failedKeys, k.version)
			s.mu.Unlock()
		}
		if k.active {
			s.mu.Lock()
			if _, ok := s.dataKeys[k.version]; ok {
				s.activeVersion = k.version
			}
			s.mu.Unlock()
		}
	}
	return nil
}

func (s *EncryptionService) activeKey() (int, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.dataKeys[s.activeVersion]
	if !ok {
		return 0, nil, ErrUnknownKey
	}
	return s.activeVersion, key, nil
}

func (s *EncryptionService) keyFor(version int) ([]byte, error) {
	s.mu.RLock()
	key, ok := s.dataKeys[version]
	s.mu.RUnlock()
	if ok {
		return key, nil
	}
	if s.db == nil {
		return nil, ErrUnknownKey
	}
	// A version created moments ago by another instance: try loading it, but at most once a
	// minute per version, so a version that cannot be unwrapped does not cost a reload per message.
	s.missMu.Lock()
	if last, ok := s.lastMissAt[version]; ok && time.Since(last) < missRetryAfter {
		s.missMu.Unlock()
		return nil, ErrUnknownKey
	}
	s.lastMissAt[version] = time.Now()
	s.missMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.reloadKeys(ctx); err == nil {
		s.mu.RLock()
		key, ok = s.dataKeys[version]
		s.mu.RUnlock()
		if ok {
			return key, nil
		}
	}
	return nil, ErrUnknownKey
}

// Close stops the background key refresh.
func (s *EncryptionService) Close() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

// Ready reports an error if no data key is available for new data.
func (s *EncryptionService) Ready() error {
	_, _, err := s.activeKey()
	return err
}

// ActiveKeyVersion returns the data key version used for new data.
func (s *EncryptionService) ActiveKeyVersion() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeVersion
}

// PublicKeyPEM returns the server's RSA public key in PEM (PKIX) format.
func (s *EncryptionService) PublicKeyPEM() string {
	return s.publicKeyPEM
}

// PublicKeyFingerprint returns the SHA-256 fingerprint of the public key.
func (s *EncryptionService) PublicKeyFingerprint() string {
	return s.fingerprint
}

// PublicKeySize returns the RSA modulus size in bits.
func (s *EncryptionService) PublicKeySize() int {
	return s.privateKey.N.BitLen()
}

// DecryptWithPrivateKey decrypts a base64-encoded RSA-OAEP (SHA-256) ciphertext.
func (s *EncryptionService) DecryptWithPrivateKey(encoded string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), nil, s.privateKey, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

// EncryptField encrypts a value with the active data key, returning ciphertext, IV and GCM tag
// separately (matching the *_encrypted / *_iv / *_tag database columns) plus the key version,
// which must be stored alongside so the value can be decrypted after key rotation.
func (s *EncryptionService) EncryptField(plaintext []byte) (ciphertext, iv, tag []byte, version int, err error) {
	version, key, err := s.activeKey()
	if err != nil {
		return nil, nil, nil, 0, err
	}
	sealed, iv, err := SealAESGCM(key, plaintext)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	split := len(sealed) - gcmTagSize
	return sealed[:split], iv, sealed[split:], version, nil
}

// DecryptField reverses EncryptField. An empty tag means it is appended to ciphertext.
func (s *EncryptionService) DecryptField(ciphertext, iv, tag []byte, version int) ([]byte, error) {
	key, err := s.keyFor(version)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(append(sealed, ciphertext...), tag...)
	return OpenAESGCM(key, iv, sealed)
}

// EncryptBlob encrypts data with the active data key. The result records the key version.
func (s *EncryptionService) EncryptBlob(plaintext []byte) ([]byte, error) {
	version, key, err := s.activeKey()
	if err != nil {
		return nil, err
	}
	sealed, iv, err := SealAESGCM(key, plaintext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(blobMagic)+4+len(iv)+len(sealed))
	out = append(out, blobMagic...)
	out = binary.BigEndian.AppendUint32(out, uint32(version)) // #nosec G115 -- versions are small positive integers from the database
	out = append(out, iv...)
	return append(out, sealed...), nil
}

// DecryptBlob reverses EncryptBlob, using whichever key version the blob was encrypted with.
func (s *EncryptionService) DecryptBlob(blob []byte) ([]byte, error) {
	version := 1
	if len(blob) >= len(blobMagic)+4 && string(blob[:len(blobMagic)]) == string(blobMagic) {
		version = int(binary.BigEndian.Uint32(blob[len(blobMagic):]))
		blob = blob[len(blobMagic)+4:]
	}
	if len(blob) < gcmNonceSize+gcmTagSize {
		return nil, ErrDecryptionFailed
	}
	key, err := s.keyFor(version)
	if err != nil {
		return nil, err
	}
	return OpenAESGCM(key, blob[:gcmNonceSize], blob[gcmNonceSize:])
}

// TransitEncrypt encrypts plaintext with Vault Transit.
func (s *EncryptionService) TransitEncrypt(ctx context.Context, plaintext []byte) (string, error) {
	return s.vault.TransitEncrypt(ctx, DataTransitKey, plaintext)
}

// TransitDecrypt decrypts Vault Transit ciphertext.
func (s *EncryptionService) TransitDecrypt(ctx context.Context, ciphertext string) ([]byte, error) {
	return s.vault.TransitDecrypt(ctx, DataTransitKey, ciphertext)
}

// Status reports Vault connectivity, storage persistence and the data key versions.
func (s *EncryptionService) Status(ctx context.Context) *EncryptionStatus {
	status := &EncryptionStatus{
		Status:      "operational",
		TransitKeys: []string{},
		Algorithms: map[string]string{
			"transport":           "TLS 1.3",
			"header_encryption":   "RSA-OAEP-SHA256",
			"response_encryption": "AES-256-GCM",
			"data_at_rest":        "AES-256-GCM (versioned data keys wrapped by Vault Transit)",
			"vault_transit":       "aes256-gcm96",
		},
		PublicKeyFingerprint: s.fingerprint,
		DataKeyVersion:       s.ActiveKeyVersion(),
		DataKeys:             []DataKeyInfo{},
		CheckedAt:            time.Now().UTC(),
		UptimeSeconds:        int64(time.Since(s.startedAt).Seconds()),
	}

	keys, err := s.storedKeys(ctx)
	if err != nil {
		status.Status = "degraded"
	} else {
		s.mu.RLock()
		for _, k := range keys {
			_, available := s.dataKeys[k.version]
			info := DataKeyInfo{
				Version: k.version, Active: k.active, Available: available,
				CreatedAt: k.createdAt, NextRotationDate: k.nextRotation, Error: s.failedKeys[k.version],
			}
			if !available {
				status.Status = "degraded"
			}
			status.DataKeys = append(status.DataKeys, info)
		}
		s.mu.RUnlock()
		sort.Slice(status.DataKeys, func(i, j int) bool { return status.DataKeys[i].Version > status.DataKeys[j].Version })
	}

	health, err := s.vault.Health(ctx)
	if err != nil {
		status.Status = "degraded"
		status.Vault.Error = err.Error()
		return status
	}
	status.Vault.Reachable = true
	status.Vault.Initialized = health.Initialized
	status.Vault.Sealed = health.Sealed
	status.Vault.Version = health.Version
	if health.Sealed || !health.Initialized {
		status.Status = "degraded"
	}
	if storage, err := s.vault.StorageType(ctx); err == nil {
		status.Vault.StorageType = storage
		status.Vault.Persistent = storage != "inmem"
	}
	if version, err := s.vault.TransitKeyVersion(ctx, DataTransitKey); err == nil {
		status.Vault.TransitKeyVersion = version
	}

	if keys, err := s.vault.ListTransitKeys(ctx); err == nil {
		status.TransitKeys = keys
	} else {
		status.Status = "degraded"
		status.Vault.Error = err.Error()
	}

	return status
}

// SealAESGCM encrypts plaintext with AES-256-GCM using a random 96-bit nonce.
// The returned ciphertext has the 16-byte tag appended.
func SealAESGCM(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nonce, nil
}

// OpenAESGCM decrypts ciphertext (with appended tag) produced by SealAESGCM.
func OpenAESGCM(key, nonce, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrDecryptionFailed
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
