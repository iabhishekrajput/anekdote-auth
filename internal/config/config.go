package config

import (
	"errors"
	"log/slog"
	"os"
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

	AdminEmails []string
}

func Load() *Config {
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

	var adminEmails []string
	for _, e := range strings.Split(getEnvOrDefault("ADMIN_EMAILS", ""), ",") {
		if e = strings.ToLower(strings.TrimSpace(e)); e != "" {
			adminEmails = append(adminEmails, e)
		}
	}

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
		AdminEmails:            adminEmails,
	}
}

const defaultSessionSecret = "super-secret-session-key-change-in-prod"

func Validate(cfg *Config) error {
	if cfg.AppEnv == "production" && (cfg.SessionSecret == defaultSessionSecret || cfg.SessionSecret == "") {
		return errors.New("SESSION_SECRET is set to an insecure value; set a random 32+ byte secret before running in production")
	}
	if len(cfg.AdminEmails) == 0 {
		slog.Warn("ADMIN_EMAILS is not set; the /admin panel will be inaccessible")
	}
	return nil
}

func getEnvOrDefault(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
