package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func init() { gin.SetMode(gin.TestMode) }

func TestSessionValueRoundTrip(t *testing.T) {
	id := uuid.New()
	for _, tc := range []struct {
		value string
		want  Session
	}{
		{SessionValue(id, 7, false), Session{UserID: id, Generation: 7}},
		{SessionValue(id, 0, true), Session{UserID: id, MustChangePassword: true}},
		// Values written before session generations existed.
		{id.String(), Session{UserID: id}},
		{id.String() + ":pwchange", Session{UserID: id, MustChangePassword: true}},
	} {
		got, ok := parseSessionValue(tc.value)
		if !ok || got != tc.want {
			t.Errorf("parseSessionValue(%q) = %+v, %v; want %+v", tc.value, got, ok, tc.want)
		}
	}
	for _, bad := range []string{"", "not-a-uuid", id.String() + ":gX", id.String() + ":admin"} {
		if _, ok := parseSessionValue(bad); ok {
			t.Errorf("parseSessionValue(%q) accepted an invalid value", bad)
		}
	}
}

// SEC-012: only allowlisted headers may be sent encrypted; others could overwrite headers set by
// the gateway, such as the client IP.
func TestDecryptHeadersRejectsDisallowedTargets(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	m := &HeaderEncryptionMiddleware{logger: logger}
	router := gin.New()
	router.Use(m.DecryptHeaders())
	router.GET("/", func(c *gin.Context) { c.String(http.StatusOK, c.ClientIP()) })

	for _, name := range []string{"X-Encrypted-X-Forwarded-For", "X-Encrypted-X-Real-Ip", "X-Encrypted-Host", "x-encrypted-forwarded"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set(name, "anything")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, rec.Code)
		}
	}
}

func TestBodyLimit(t *testing.T) {
	router := gin.New()
	router.Use(BodyLimitMiddleware(16, "/upload"))
	read := func(c *gin.Context) {
		var body struct{ A string }
		if err := c.ShouldBindJSON(&body); err != nil {
			c.Status(http.StatusRequestEntityTooLarge)
			return
		}
		c.Status(http.StatusOK)
	}
	router.POST("/json", read)
	router.POST("/upload", read)

	big := `{"A":"` + strings.Repeat("x", 100) + `"}`
	for _, tc := range []struct {
		path string
		want int
	}{{"/json", http.StatusRequestEntityTooLarge}, {"/upload", http.StatusOK}} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(big)))
		if rec.Code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.path, rec.Code, tc.want)
		}
	}
}
