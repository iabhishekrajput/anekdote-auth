package config

import (
	"log/slog"
	"os"
)

type Config struct {
	Port                   string
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
}

func Load() *Config {
	port := getEnvOrDefault("PORT", "8080")
	dbDsn := getEnvOrDefault("DB_DSN", "postgres://authuser:authpassword@localhost:5432/authdb?sslmode=disable")
	redisDsn := getEnvOrDefault("REDIS_URL", "redis://localhost:6379/0")
	rsaPrivate := getEnvOrDefault("RSA_PRIVATE_KEY_PATH", "certs/private.pem")
	rsaPublic := getEnvOrDefault("RSA_PUBLIC_KEY_PATH", "certs/public.pem")
	sessionSecret := getEnvOrDefault("SESSION_SECRET", "super-secret-session-key-change-in-prod")

	smtpHost := getEnvOrDefault("SMTP_HOST", "smtp.example.com")
	smtpPort := getEnvOrDefault("SMTP_PORT", "587")
	smtpUser := getEnvOrDefault("SMTP_USERNAME", "")
	smtpPass := getEnvOrDefault("SMTP_PASSWORD", "")
	smtpFrom := getEnvOrDefault("SMTP_FROM", "noreply@anekdoteauth.local")
	smtpInsecureSkipVerify := getEnvOrDefault("SMTP_INSECURE_SKIP_VERIFY", "false") == "true"

	slog.Info("Configuration loaded", "port", port)

	return &Config{
		Port:                   port,
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
	}
}

func getEnvOrDefault(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
