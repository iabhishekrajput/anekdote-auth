package config

import (
	"os"
	"testing"
)

func TestValidate_ProductionDefaultSecret(t *testing.T) {
	cfg := &Config{AppEnv: "production", SessionSecret: defaultSessionSecret}
	if err := Validate(cfg); err == nil {
		t.Error("expected error for production with default session secret, got nil")
	}
}

func TestValidate_ProductionEmptySecret(t *testing.T) {
	cfg := &Config{AppEnv: "production", SessionSecret: ""}
	if err := Validate(cfg); err == nil {
		t.Error("expected error for production with empty session secret, got nil")
	}
}

func TestValidate_ProductionCustomSecret(t *testing.T) {
	key := make([]byte, 32)
	cfg := &Config{AppEnv: "production", SessionSecret: "a-very-secure-random-secret-value", RedisEncryptionKey: key}
	if err := Validate(cfg); err != nil {
		t.Errorf("expected nil for production with custom session secret and encryption key, got %v", err)
	}
}

func TestValidate_ProductionMissingEncryptionKey(t *testing.T) {
	cfg := &Config{AppEnv: "production", SessionSecret: "a-very-secure-random-secret-value"}
	if err := Validate(cfg); err == nil {
		t.Error("expected error for production without REDIS_ENCRYPTION_KEY, got nil")
	}
}

func TestValidate_DevelopmentDefaultSecret(t *testing.T) {
	cfg := &Config{AppEnv: "development", SessionSecret: defaultSessionSecret}
	if err := Validate(cfg); err != nil {
		t.Errorf("expected nil for development with default session secret, got %v", err)
	}
}

func TestLoad_DefaultValues(t *testing.T) {
	// Clear environments logically to ensure defaults
	os.Clearenv()

	cfg := Load()

	if cfg.Port != "8080" {
		t.Errorf("expected 8080 default port, got %s", cfg.Port)
	}
	if cfg.AppEnv != "development" {
		t.Errorf("expected development default env, got %s", cfg.AppEnv)
	}
	if cfg.SMTPHost != "localhost" {
		t.Errorf("expected localhost default smtp host, got %s", cfg.SMTPHost)
	}
	if cfg.SMTPInsecureSkipVerify != false {
		t.Errorf("expected false default insecure skip verify, got %v", cfg.SMTPInsecureSkipVerify)
	}
}

func TestLoad_EnvValues(t *testing.T) {
	t.Setenv("PORT", "9000")
	t.Setenv("APP_ENV", "production")
	t.Setenv("SMTP_INSECURE_SKIP_VERIFY", "true")

	cfg := Load()

	if cfg.Port != "9000" {
		t.Errorf("expected 9000 port, got %s", cfg.Port)
	}
	if cfg.AppEnv != "production" {
		t.Errorf("expected production env, got %s", cfg.AppEnv)
	}
	if cfg.SMTPInsecureSkipVerify != true {
		t.Errorf("expected true insecure skip verify, got %v", cfg.SMTPInsecureSkipVerify)
	}
}
