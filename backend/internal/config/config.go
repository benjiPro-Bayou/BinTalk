// Package config loads and validates the API server's configuration from the environment.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment string
	LogLevel    string
	Port        string

	Database DatabaseConfig
	Redis    RedisConfig
	Kafka    KafkaConfig
	Session  SessionConfig
	Vault    VaultConfig
	TLS      TLSConfig
	Security SecurityConfig
	CORS     CORSConfig
	Email    EmailConfig
	Billing  BillingConfig
}

type DatabaseConfig struct {
	Host            string
	Port            string
	User            string
	Password        string
	Name            string
	SSLMode         string
	MaxConnections  int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

type RedisConfig struct {
	Host      string
	Port      string
	Password  string
	DB        int
	PoolSize  int
	TLSEnable bool
}

type KafkaConfig struct {
	Brokers []string
	Topic   string
}

// SessionConfig holds the lifetimes of the opaque access and refresh tokens.
type SessionConfig struct {
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

type VaultConfig struct {
	Address string
	Token   string
}

type TLSConfig struct {
	CertFile string
	KeyFile  string
}

type SecurityConfig struct {
	RateLimitRequests int
	RateLimitWindow   time.Duration
	// MaxRequestSize is the largest file upload, in bytes.
	MaxRequestSize int64
	// MaxJSONBodySize is the largest request body for every other route, in bytes.
	MaxJSONBodySize int64
	// StorageQuotaPerUser caps the total size of a user's files, in bytes (0 = unlimited).
	StorageQuotaPerUser int64
	// TrustedProxies are the addresses (IPs or CIDRs) of reverse proxies whose X-Forwarded-For
	// header is believed when determining the client IP.
	TrustedProxies []string
}

type CORSConfig struct {
	AllowedOrigins []string
	AllowedMethods string
}

type EmailConfig struct {
	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string
	FromAddr string
}

// BillingConfig controls company subscriptions and Chapa payments.
type BillingConfig struct {
	// AppBaseURL is the public address of the web app (payment return and callback URLs).
	AppBaseURL         string
	ChapaBaseURL       string
	ChapaSecretKey     string
	ChapaWebhookSecret string
	// RequireApproval: a company that has paid waits for a platform admin's approval instead of
	// being activated automatically.
	RequireApproval bool
	// GracePeriod is how long a company keeps working after its paid period ends.
	GracePeriod time.Duration
}

// IsProduction reports whether ENVIRONMENT is "production".
func (c *Config) IsProduction() bool {
	return c.Environment == "production"
}

// Load reads the configuration from the environment and validates it.
func Load() (*Config, error) {
	var errs []error
	durationSeconds := func(names []string, fallback int64) time.Duration {
		for _, name := range names {
			if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
				n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s must be a number of seconds, got %q", name, v))
					return 0
				}
				return time.Duration(n) * time.Second
			}
		}
		return time.Duration(fallback) * time.Second
	}

	maxUpload, err := ParseSize(getEnv("MAX_REQUEST_SIZE", "10"), 1<<20)
	if err != nil {
		errs = append(errs, fmt.Errorf("MAX_REQUEST_SIZE: %w", err))
	}
	maxJSON, err := ParseSize(getEnv("MAX_JSON_BODY_SIZE", "1M"), 1)
	if err != nil {
		errs = append(errs, fmt.Errorf("MAX_JSON_BODY_SIZE: %w", err))
	}
	quota := int64(0)
	if v := strings.TrimSpace(getEnv("STORAGE_QUOTA_PER_USER", "5G")); v != "0" {
		if quota, err = ParseSize(v, 1<<20); err != nil {
			errs = append(errs, fmt.Errorf("STORAGE_QUOTA_PER_USER: %w", err))
		}
	}
	window, err := time.ParseDuration(getEnv("RATE_LIMIT_WINDOW", "1m"))
	if err != nil {
		errs = append(errs, fmt.Errorf("RATE_LIMIT_WINDOW must be a duration such as 1m: %w", err))
	}

	cfg := &Config{
		Environment: getEnv("ENVIRONMENT", "development"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		Port:        getEnv("PORT", "8000"),

		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnv("DB_PORT", "5432"),
			User:            getEnv("DB_USER", "bintalk"),
			Password:        getEnv("DB_PASSWORD", ""),
			Name:            getEnv("DB_NAME", "bintalk_db"),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxConnections:  getEnvInt("DB_MAX_CONNECTIONS", 50),
			ConnMaxLifetime: 5 * time.Minute,
			ConnMaxIdleTime: 2 * time.Minute,
		},

		Redis: RedisConfig{
			Host:      getEnv("REDIS_HOST", "localhost"),
			Port:      getEnv("REDIS_PORT", "6379"),
			Password:  getEnv("REDIS_PASSWORD", ""),
			DB:        getEnvInt("REDIS_DB", 0),
			PoolSize:  getEnvInt("REDIS_POOL_SIZE", 20),
			TLSEnable: getEnvBool("REDIS_TLS", false),
		},

		Kafka: KafkaConfig{
			Brokers: splitList(getEnv("KAFKA_BROKERS", "localhost:9092")),
			Topic:   getEnv("KAFKA_TOPIC", "bintalk-events"),
		},

		// SESSION_* replace the misleadingly named JWT_* variables (tokens are opaque, not JWTs);
		// the old names are still accepted.
		Session: SessionConfig{
			AccessTTL:  durationSeconds([]string{"SESSION_TTL", "JWT_EXPIRATION"}, 900),
			RefreshTTL: durationSeconds([]string{"SESSION_REFRESH_TTL", "JWT_REFRESH_EXPIRATION"}, 86400),
		},

		Vault: VaultConfig{
			Address: getEnv("VAULT_ADDR", "http://localhost:8200"),
			Token:   vaultToken(&errs),
		},

		TLS: TLSConfig{
			CertFile: getEnv("TLS_CERT_FILE", "certs/server.crt"),
			KeyFile:  getEnv("TLS_KEY_FILE", "certs/server.key"),
		},

		Security: SecurityConfig{
			RateLimitRequests:   getEnvInt("RATE_LIMIT_REQUESTS", 100),
			RateLimitWindow:     window,
			MaxRequestSize:      maxUpload,
			MaxJSONBodySize:     maxJSON,
			StorageQuotaPerUser: quota,
			TrustedProxies:      splitList(getEnv("TRUSTED_PROXIES", "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")),
		},

		CORS: CORSConfig{
			AllowedOrigins: splitList(getEnv("CORS_ALLOWED_ORIGINS", "*")),
			AllowedMethods: getEnv("CORS_ALLOWED_METHODS", "GET,POST,PUT,DELETE,OPTIONS"),
		},

		Email: EmailConfig{
			SMTPHost: getEnv("SMTP_HOST", "smtp.gmail.com"),
			SMTPPort: getEnvInt("SMTP_PORT", 587),
			SMTPUser: getEnv("SMTP_USER", ""),
			SMTPPass: getEnv("SMTP_PASSWORD", ""),
			FromAddr: getEnv("SMTP_FROM", "noreply@bintalk.com"),
		},

		Billing: BillingConfig{
			AppBaseURL:         strings.TrimRight(getEnv("APP_BASE_URL", "https://localhost"), "/"),
			ChapaBaseURL:       getEnv("CHAPA_BASE_URL", ""),
			ChapaSecretKey:     getEnv("CHAPA_SECRET_KEY", ""),
			ChapaWebhookSecret: getEnv("CHAPA_WEBHOOK_SECRET", ""),
			RequireApproval:    getEnvBool("COMPANY_REQUIRE_APPROVAL", false),
			GracePeriod:        time.Duration(getEnvInt("SUBSCRIPTION_GRACE_DAYS", 3)) * 24 * time.Hour,
		},
	}

	errs = append(errs, cfg.validate()...)
	return cfg, errors.Join(errs...)
}

func (c *Config) validate() []error {
	var errs []error
	if c.Session.AccessTTL <= 0 {
		errs = append(errs, errors.New("SESSION_TTL (JWT_EXPIRATION) must be positive; 0 would create sessions that never expire"))
	}
	if c.Session.RefreshTTL < c.Session.AccessTTL {
		errs = append(errs, errors.New("SESSION_REFRESH_TTL (JWT_REFRESH_EXPIRATION) must be at least SESSION_TTL"))
	}
	if c.Security.MaxRequestSize <= 0 || c.Security.MaxJSONBodySize <= 0 {
		errs = append(errs, errors.New("MAX_REQUEST_SIZE and MAX_JSON_BODY_SIZE must be positive"))
	}
	if c.Security.RateLimitRequests <= 0 || c.Security.RateLimitWindow <= 0 {
		errs = append(errs, errors.New("RATE_LIMIT_REQUESTS and RATE_LIMIT_WINDOW must be positive"))
	}
	for _, proxy := range c.Security.TrustedProxies {
		if net.ParseIP(proxy) == nil {
			if _, _, err := net.ParseCIDR(proxy); err != nil {
				errs = append(errs, fmt.Errorf("TRUSTED_PROXIES: %q is not an IP address or CIDR", proxy))
			}
		}
	}
	if !strings.HasPrefix(c.Billing.AppBaseURL, "https://") && !strings.HasPrefix(c.Billing.AppBaseURL, "http://") {
		errs = append(errs, errors.New("APP_BASE_URL must start with https:// or http://"))
	}
	if c.Billing.GracePeriod < 0 {
		errs = append(errs, errors.New("SUBSCRIPTION_GRACE_DAYS must not be negative"))
	}
	if c.IsProduction() {
		for _, origin := range c.CORS.AllowedOrigins {
			if origin == "*" {
				errs = append(errs, errors.New("CORS_ALLOWED_ORIGINS must list explicit origins in production"))
			}
		}
		if c.Database.Password == "" || c.Redis.Password == "" || c.Vault.Token == "" {
			errs = append(errs, errors.New("DB_PASSWORD, REDIS_PASSWORD and VAULT_TOKEN must be set in production"))
		}
	}
	return errs
}

// vaultToken returns VAULT_TOKEN, or the contents of VAULT_TOKEN_FILE (a token written by
// vault/bootstrap.sh, so it never has to appear in an environment file).
func vaultToken(errs *[]error) string {
	if token := getEnv("VAULT_TOKEN", ""); token != "" {
		return token
	}
	path := getEnv("VAULT_TOKEN_FILE", "")
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("VAULT_TOKEN_FILE: %w", err))
		return ""
	}
	return strings.TrimSpace(string(data))
}

// ParseSize parses a size such as "50", "512K", "10M", "10MB" or "1G". A bare number is
// multiplied by unit (e.g. 1<<20 to read it as megabytes).
func ParseSize(value string, unit int64) (int64, error) {
	v := strings.ToUpper(strings.TrimSpace(value))
	v = strings.TrimSuffix(v, "B")
	multiplier := unit
	if v != "" {
		switch v[len(v)-1] {
		case 'K':
			multiplier, v = 1<<10, v[:len(v)-1]
		case 'M':
			multiplier, v = 1<<20, v[:len(v)-1]
		case 'G':
			multiplier, v = 1<<30, v[:len(v)-1]
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid size %q (use e.g. 10M)", value)
	}
	return n * multiplier, nil
}

func splitList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		return value == "true" || value == "1" || value == "yes"
	}
	return defaultValue
}
