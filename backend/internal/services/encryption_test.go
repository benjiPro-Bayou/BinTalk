package services

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func newTestKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestOldKeyVersionsStayReadableAfterRotation(t *testing.T) {
	s := &EncryptionService{dataKeys: map[int][]byte{1: newTestKey(t)}, activeVersion: 1}

	ct, iv, tag, version, err := s.EncryptField([]byte("before rotation"))
	if err != nil || version != 1 {
		t.Fatalf("encrypt: version=%d err=%v", version, err)
	}
	oldBlob, err := s.EncryptBlob([]byte("old file"))
	if err != nil {
		t.Fatal(err)
	}

	// Rotate: version 2 becomes active, version 1 is kept.
	s.dataKeys[2] = newTestKey(t)
	s.activeVersion = 2

	_, _, _, newVersion, err := s.EncryptField([]byte("after rotation"))
	if err != nil || newVersion != 2 {
		t.Fatalf("new data should use version 2, got %d (%v)", newVersion, err)
	}
	if got, err := s.DecryptField(ct, iv, tag, version); err != nil || string(got) != "before rotation" {
		t.Fatalf("old message unreadable after rotation: %q %v", got, err)
	}
	if got, err := s.DecryptBlob(oldBlob); err != nil || string(got) != "old file" {
		t.Fatalf("old file unreadable after rotation: %q %v", got, err)
	}
	if _, err := s.DecryptField(ct, iv, tag, 2); err == nil {
		t.Fatal("decrypting with the wrong key version must fail")
	}
}

func TestLegacyBlobsUseVersionOne(t *testing.T) {
	v1 := newTestKey(t)
	s := &EncryptionService{dataKeys: map[int][]byte{1: v1, 2: newTestKey(t)}, activeVersion: 2}

	// Format written before versioned keys: nonce | ciphertext+tag, no header.
	sealed, nonce, err := SealAESGCM(v1, []byte("legacy file"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.DecryptBlob(append(nonce, sealed...))
	if err != nil || string(got) != "legacy file" {
		t.Fatalf("legacy blob: %q %v", got, err)
	}

	blob, err := s.EncryptBlob([]byte("new file"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob, blobMagic) {
		t.Fatal("new blobs must carry the version header")
	}
}

func TestUnknownKeyVersionFailsCleanly(t *testing.T) {
	s := &EncryptionService{dataKeys: map[int][]byte{1: newTestKey(t)}, activeVersion: 1}
	ct, iv, tag, _, err := s.EncryptField([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecryptField(ct, iv, tag, 7); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("got %v, want ErrUnknownKey", err)
	}
}
