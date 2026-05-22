package config

import (
	"os"
	"path/filepath"
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

// --- loadDotEnv tests ---

func writeTempEnv(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadDotEnv_FileNotFound(t *testing.T) {
	if err := loadDotEnv("/tmp/does-not-exist-anekdote.env"); err != nil {
		t.Errorf("expected nil for missing file, got %v", err)
	}
}

func TestLoadDotEnv_SetsValues(t *testing.T) {
	t.Setenv("ANEKDOTE_TEST_PORT", "")
	os.Unsetenv("ANEKDOTE_TEST_PORT")

	path := writeTempEnv(t, "ANEKDOTE_TEST_PORT=9999\n")
	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("ANEKDOTE_TEST_PORT"); v != "9999" {
		t.Errorf("expected 9999, got %q", v)
	}
	os.Unsetenv("ANEKDOTE_TEST_PORT")
}

func TestLoadDotEnv_SkipsComments(t *testing.T) {
	os.Unsetenv("ANEKDOTE_TEST_COMMENT")
	path := writeTempEnv(t, "# this is a comment\n# ANEKDOTE_TEST_COMMENT=should-not-set\n")
	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("ANEKDOTE_TEST_COMMENT"); v != "" {
		t.Errorf("comment line should not set env var, got %q", v)
	}
}

func TestLoadDotEnv_InlineComment(t *testing.T) {
	os.Unsetenv("ANEKDOTE_TEST_INLINE")
	path := writeTempEnv(t, "ANEKDOTE_TEST_INLINE=hello   # this is inline\n")
	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("ANEKDOTE_TEST_INLINE"); v != "hello" {
		t.Errorf("expected 'hello' without inline comment, got %q", v)
	}
	os.Unsetenv("ANEKDOTE_TEST_INLINE")
}

func TestLoadDotEnv_DoesNotOverride(t *testing.T) {
	t.Setenv("ANEKDOTE_TEST_OVERRIDE", "original")
	path := writeTempEnv(t, "ANEKDOTE_TEST_OVERRIDE=from-dotenv\n")
	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("ANEKDOTE_TEST_OVERRIDE"); v != "original" {
		t.Errorf("expected 'original' (not overridden), got %q", v)
	}
}

func TestLoadDotEnv_MalformedLine(t *testing.T) {
	os.Unsetenv("ANEKDOTE_TEST_MALFORMED")
	path := writeTempEnv(t, "no-equals-sign\nANEKDOTE_TEST_MALFORMED=ok\n")
	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("ANEKDOTE_TEST_MALFORMED"); v != "ok" {
		t.Errorf("expected 'ok' after malformed line, got %q", v)
	}
	os.Unsetenv("ANEKDOTE_TEST_MALFORMED")
}

func TestLoad_AuditRetentionDays(t *testing.T) {
	t.Setenv("AUDIT_RETENTION_DAYS", "30")
	cfg := Load()
	if cfg.AuditRetentionDays != 30 {
		t.Errorf("expected 30, got %d", cfg.AuditRetentionDays)
	}
}

func TestLoadDotEnv_EmptyLines(t *testing.T) {
	os.Unsetenv("ANEKDOTE_TEST_EMPTY")
	path := writeTempEnv(t, "\n\n\nANEKDOTE_TEST_EMPTY=set\n\n\n")
	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if v := os.Getenv("ANEKDOTE_TEST_EMPTY"); v != "set" {
		t.Errorf("expected 'set', got %q", v)
	}
	os.Unsetenv("ANEKDOTE_TEST_EMPTY")
}
