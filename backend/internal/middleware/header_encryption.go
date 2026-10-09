package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/bintalk/bintalk-clone/internal/services"
	"github.com/bintalk/bintalk-clone/pkg/vault"
)

const (
	// Clients send sensitive headers as "X-Encrypted-<Name>: base64(RSA-OAEP-SHA256(value))",
	// encrypted with the key from GET /api/v1/encryption/public-key. The middleware
	// decrypts them and exposes the plain "<Name>" header to the rest of the stack.
	encryptedHeaderPrefix = "X-Encrypted-"

	// To receive an encrypted response, clients send a random 32-byte AES key encrypted
	// the same way. The response body is then AES-256-GCM encrypted with that key.
	responseKeyHeader       = "X-Response-Key"
	responseEncryptedHeader = "X-Response-Encrypted"
)

// decryptableHeaders lists the headers clients may send encrypted. Anything else is rejected:
// decrypted values replace headers set by the gateway, so allowing arbitrary names would let a
// client forge X-Forwarded-For, X-Real-IP, Host and the like.
var decryptableHeaders = map[string]bool{
	"Authorization": true,
}

// HeaderEncryptionMiddleware decrypts encrypted request headers and optionally encrypts responses.
type HeaderEncryptionMiddleware struct {
	encryption *services.EncryptionService
	vault      *vault.VaultClient
	logger     *logrus.Logger
}

// NewHeaderEncryptionMiddleware creates the header/response encryption middleware.
func NewHeaderEncryptionMiddleware(
	encryption *services.EncryptionService,
	vaultClient *vault.VaultClient,
	logger *logrus.Logger,
) *HeaderEncryptionMiddleware {
	return &HeaderEncryptionMiddleware{encryption: encryption, vault: vaultClient, logger: logger}
}

// DecryptHeaders replaces every X-Encrypted-<Name> header with its decrypted <Name> header.
// Requests carrying an encrypted header that cannot be decrypted, or whose <Name> is not in
// decryptableHeaders, are rejected.
func (m *HeaderEncryptionMiddleware) DecryptHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		var names []string // collected first: the loop below changes the header map
		for name, values := range c.Request.Header {
			if strings.HasPrefix(name, encryptedHeaderPrefix) && len(values) > 0 {
				names = append(names, name)
			}
		}
		for _, name := range names {
			values := c.Request.Header.Values(name)
			target := http.CanonicalHeaderKey(strings.TrimPrefix(name, encryptedHeaderPrefix))
			if !decryptableHeaders[target] {
				m.logger.WithField("header", name).Warn("Rejected request with a disallowed encrypted header")
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error":  "this header cannot be sent encrypted",
					"header": name,
				})
				return
			}

			plaintext, err := m.encryption.DecryptWithPrivateKey(values[0])
			if err != nil {
				m.logger.WithField("header", name).Warn("Rejected request with undecryptable header")
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
					"error":  "could not decrypt header",
					"header": name,
				})
				return
			}

			c.Request.Header.Del(name)
			c.Request.Header.Set(target, string(plaintext))
		}
		c.Next()
	}
}

// EncryptResponse encrypts the response body when the client supplies an X-Response-Key.
// The body becomes {"encrypted":true,"algorithm":"AES-256-GCM","iv":...,"ciphertext":...},
// where ciphertext includes the 16-byte GCM tag. Requests without the header are untouched.
func (m *HeaderEncryptionMiddleware) EncryptResponse() gin.HandlerFunc {
	return func(c *gin.Context) {
		encryptedKey := c.GetHeader(responseKeyHeader)
		if encryptedKey == "" || strings.EqualFold(c.GetHeader("Upgrade"), "websocket") {
			c.Next()
			return
		}

		key, err := m.encryption.DecryptWithPrivateKey(encryptedKey)
		if err != nil || len(key) != 32 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "X-Response-Key must be a 32-byte AES key encrypted with the server public key",
			})
			return
		}

		original := c.Writer
		buffered := &bufferedWriter{ResponseWriter: original, status: http.StatusOK}
		c.Writer = buffered
		defer func() { c.Writer = original }()

		c.Next()

		ciphertext, iv, err := services.SealAESGCM(key, buffered.body.Bytes())
		if err != nil {
			m.logger.Errorf("Failed to encrypt response: %v", err)
			original.Header().Set("Content-Type", "application/json")
			original.WriteHeader(http.StatusInternalServerError)
			_, _ = original.Write([]byte(`{"error":"internal server error"}`))
			return
		}

		payload, _ := json.Marshal(gin.H{
			"encrypted":    true,
			"algorithm":    "AES-256-GCM",
			"content_type": original.Header().Get("Content-Type"),
			"iv":           base64.StdEncoding.EncodeToString(iv),
			"ciphertext":   base64.StdEncoding.EncodeToString(ciphertext),
		})

		h := original.Header()
		h.Del("Content-Length")
		h.Del("Content-Disposition")
		h.Set("Content-Type", "application/json; charset=utf-8")
		h.Set(responseEncryptedHeader, "true")
		original.WriteHeader(buffered.status)
		_, _ = original.Write(payload)
	}
}

// bufferedWriter captures the status and body so they can be encrypted before sending.
type bufferedWriter struct {
	gin.ResponseWriter
	body    bytes.Buffer
	status  int
	written bool
}

func (w *bufferedWriter) WriteHeader(code int) {
	if !w.written {
		w.status = code
	}
}

func (w *bufferedWriter) WriteHeaderNow() {
	w.written = true
}

func (w *bufferedWriter) Write(data []byte) (int, error) {
	w.written = true
	return w.body.Write(data)
}

func (w *bufferedWriter) WriteString(s string) (int, error) {
	w.written = true
	return w.body.WriteString(s)
}

func (w *bufferedWriter) Status() int {
	return w.status
}

func (w *bufferedWriter) Size() int {
	if !w.written {
		return -1
	}
	return w.body.Len()
}

func (w *bufferedWriter) Written() bool {
	return w.written
}
