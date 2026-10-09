package config

import (
	"strings"
	"testing"
)

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{
		"10": 10 << 20, "10M": 10 << 20, "10MB": 10 << 20, "512k": 512 << 10, "1G": 1 << 30,
	} {
		if got, err := ParseSize(in, 1<<20); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "M", "-5", "ten"} {
		if _, err := ParseSize(bad, 1<<20); err == nil {
			t.Errorf("ParseSize(%q) accepted an invalid size", bad)
		}
	}
}

func TestLoadRejectsUnsafeValues(t *testing.T) {
	t.Setenv("JWT_EXPIRATION", "0")
	t.Setenv("APP_BASE_URL", "localhost")
	t.Setenv("TRUSTED_PROXIES", "not-an-ip")
	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted invalid configuration")
	}
	for _, want := range []string{"never expire", "APP_BASE_URL", "TRUSTED_PROXIES"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestLoadAcceptsDocumentedSizes(t *testing.T) {
	t.Setenv("MAX_REQUEST_SIZE", "10M") // as in .env.example; used to be silently ignored
	t.Setenv("SESSION_TTL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Security.MaxRequestSize != 10<<20 {
		t.Errorf("MaxRequestSize = %d", cfg.Security.MaxRequestSize)
	}
}
