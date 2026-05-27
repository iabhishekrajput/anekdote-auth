package config

import (
	"bufio"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port                   string
	AppURL                 string
	DBDsn                  string
	RedisDSN               string
	RSAPrivateKey          string
	RSAPublicKey           string
	SessionSecret          string
	SMTPHost               string
	SMTPPort               string
	SMTPUsername           string
	SMTPPassword           string
	SMTPFrom               string
	SMTPInsecureSkipVerify bool

	AppEnv             string
	CORSAllowedOrigins string

	// RedisEncryptionKey is a 32-byte AES key used to encrypt sensitive values
	// in Redis (e.g. OAuth2 client secret flash). Set REDIS_ENCRYPTION_KEY to
	// 64 lowercase hex characters (32 bytes). In production the server refuses
	// to start if this is not set to a valid key.
	RedisEncryptionKey []byte

	// AuditRetentionDays is how many days to keep admin audit log entries.
	// Entries older than this are deleted on startup and daily thereafter.
	// Default: 90. Set AUDIT_RETENTION_DAYS to override.
	AuditRetentionDays int

	// ManagementAudience is the expected `aud` claim for Management API tokens
	// (e.g. https://auth.example.com/api/v1/). Tokens without this exact audience
	// are rejected by the Management API. Defaults to AppURL+"/api/v1/".
	// Set MANAGEMENT_AUDIENCE to override.
	ManagementAudience string
}

func Load() *Config {
	if err := loadDotEnv(".env"); err != nil {
		slog.Warn("Failed to load .env file", "error", err)
	}

	port := getEnvOrDefault("PORT", "8080")
	dbDsn := getEnvOrDefault("DB_DSN", "postgres://authuser:authpassword@localhost:5432/authdb?sslmode=disable")
	redisDsn := getEnvOrDefault("REDIS_URL", "redis://localhost:6379/0")
	rsaPrivate := getEnvOrDefault("RSA_PRIVATE_KEY_PATH", "certs/private.pem")
	rsaPublic := getEnvOrDefault("RSA_PUBLIC_KEY_PATH", "certs/public.pem")
	sessionSecret := getEnvOrDefault("SESSION_SECRET", "super-secret-session-key-change-in-prod")

	smtpHost := getEnvOrDefault("SMTP_HOST", "localhost")
	smtpPort := getEnvOrDefault("SMTP_PORT", "1025")
	smtpUser := getEnvOrDefault("SMTP_USERNAME", "test")
	smtpPass := getEnvOrDefault("SMTP_PASSWORD", "test")
	smtpFrom := getEnvOrDefault("SMTP_FROM", "noreply@anekdoteauth.local")
	smtpInsecureSkipVerify := getEnvOrDefault("SMTP_INSECURE_SKIP_VERIFY", "false") == "true"

	appEnv := getEnvOrDefault("APP_ENV", "development")
	appURL := getEnvOrDefault("APP_URL", "http://localhost:"+port)
	corsAllowed := getEnvOrDefault("CORS_ALLOWED_ORIGINS", "http://localhost:8080")

	encKey := parseHexKey(getEnvOrDefault("REDIS_ENCRYPTION_KEY", ""))
	if encKey == nil && appEnv != "production" {
		// Insecure dev-only key; logged so it's impossible to miss.
		slog.Warn("REDIS_ENCRYPTION_KEY not set — using insecure dev key; never run this in production")
		encKey = []byte("dev-insecure-key-do-not-use-prod")
	}

	retentionDays := 90
	if v, _ := strconv.Atoi(os.Getenv("AUDIT_RETENTION_DAYS")); v > 0 {
		retentionDays = v
	}

	mgmtAudience := getEnvOrDefault("MANAGEMENT_AUDIENCE", appURL+"/api/v1/")

	slog.Info("Configuration loaded", "port", port, "env", appEnv)

	return &Config{
		Port:                   port,
		AppURL:                 appURL,
		DBDsn:                  dbDsn,
		RedisDSN:               redisDsn,
		RSAPrivateKey:          rsaPrivate,
		RSAPublicKey:           rsaPublic,
		SessionSecret:          sessionSecret,
		SMTPHost:               smtpHost,
		SMTPPort:               smtpPort,
		SMTPUsername:           smtpUser,
		SMTPPassword:           smtpPass,
		SMTPFrom:               smtpFrom,
		SMTPInsecureSkipVerify: smtpInsecureSkipVerify,
		AppEnv:                 appEnv,
		CORSAllowedOrigins:     corsAllowed,
		RedisEncryptionKey:     encKey,
		AuditRetentionDays:     retentionDays,
		ManagementAudience:     mgmtAudience,
	}
}

const defaultSessionSecret = "super-secret-session-key-change-in-prod"

func Validate(cfg *Config) error {
	if cfg.AppEnv == "production" {
		if cfg.SessionSecret == defaultSessionSecret || cfg.SessionSecret == "" {
			return errors.New("SESSION_SECRET is set to an insecure value; set a random 32+ byte secret before running in production")
		}
		if len(cfg.RedisEncryptionKey) != 32 {
			return errors.New("REDIS_ENCRYPTION_KEY must be set to 64 hex chars (32 bytes) in production")
		}
	}
	return nil
}

// parseHexKey decodes a 64-char hex string to a 32-byte key. Returns nil on error.
func parseHexKey(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil
	}
	return b
}

// loadDotEnv reads KEY=VALUE pairs from path and sets them as environment
// variables. It is a no-op if the file does not exist. Existing variables
// are never overridden, so shell exports and container-injected vars always win.
// Lines starting with # and empty lines are ignored. Inline # comments are stripped.
func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		// Strip inline comment (e.g. VALUE   # comment)
		if idx := strings.Index(v, " #"); idx >= 0 {
			v = v[:idx]
		}
		v = strings.TrimSpace(v)
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
	return scanner.Err()
}

func getEnvOrDefault(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
