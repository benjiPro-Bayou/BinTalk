package handlers

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/bintalk/bintalk-clone/internal/middleware"
	"github.com/bintalk/bintalk-clone/internal/services"
)

const maxTransitPlaintext = 64 << 10

// EncryptionHandler exposes the server public key, Vault-backed encryption and status.
type EncryptionHandler struct {
	encryption *services.EncryptionService
}

// NewEncryptionHandler creates an EncryptionHandler.
func NewEncryptionHandler(encryption *services.EncryptionService) *EncryptionHandler {
	return &EncryptionHandler{encryption: encryption}
}

// GetPublicKey returns the RSA public key clients use to encrypt headers and response keys.
func (h *EncryptionHandler) GetPublicKey(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"public_key":  h.encryption.PublicKeyPEM(),
		"algorithm":   "RSA-OAEP",
		"hash":        "SHA-256",
		"key_size":    h.encryption.PublicKeySize(),
		"fingerprint": h.encryption.PublicKeyFingerprint(),
	})
}

// EncryptData encrypts {"plaintext": "..."} with Vault Transit. The ciphertext is bound to
// the caller, so only the same user can decrypt it.
func (h *EncryptionHandler) EncryptData(c *gin.Context) {
	var req struct {
		Plaintext string `json:"plaintext" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if len(req.Plaintext) > maxTransitPlaintext {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "plaintext must be at most 64 KiB"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	owner := middleware.GetUserID(c).String()
	ciphertext, err := h.encryption.TransitEncrypt(ctx, []byte(owner+":"+req.Plaintext))
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "encryption service unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ciphertext": ciphertext, "key": services.DataTransitKey})
}

// DecryptData decrypts {"ciphertext": "vault:v1:..."} produced by EncryptData for the same user.
func (h *EncryptionHandler) DecryptData(c *gin.Context) {
	var req struct {
		Ciphertext string `json:"ciphertext" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, err)
		return
	}
	if !strings.HasPrefix(req.Ciphertext, "vault:v") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ciphertext must be in vault:v<N>:... format"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	plaintext, err := h.encryption.TransitDecrypt(ctx, req.Ciphertext)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not decrypt ciphertext"})
		return
	}

	prefix := []byte(middleware.GetUserID(c).String() + ":")
	if !bytes.HasPrefix(plaintext, prefix) {
		c.JSON(http.StatusForbidden, gin.H{"error": "ciphertext was encrypted by a different user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"plaintext": string(plaintext[len(prefix):])})
}

// GetEncryptionSummary gives any signed-in user the overall encryption health and algorithms,
// without Vault internals (version, storage, key names and versions, raw errors).
func (h *EncryptionHandler) GetEncryptionSummary(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	status := h.encryption.Status(ctx)
	c.JSON(http.StatusOK, gin.H{"status": status.Status, "algorithms": status.Algorithms})
}

// GetEncryptionStatus reports Vault connectivity and the encryption configuration (admins only).
// It responds 503 when the encryption subsystem is degraded.
func (h *EncryptionHandler) GetEncryptionStatus(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	status := h.encryption.Status(ctx)
	code := http.StatusOK
	if status.Status != "operational" {
		code = http.StatusServiceUnavailable
	}
	c.JSON(code, status)
}
