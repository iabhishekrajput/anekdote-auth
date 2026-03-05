package mailer

import (
	"context"
	"testing"

	"github.com/iabhishekrajput/anekdote-auth/internal/config"
)

func TestNewMailer_DefaultPorts(t *testing.T) {
	cfg := &config.Config{
		SMTPHost:               "localhost",
		SMTPPort:               "invalid", // Forces fallback to 587
		SMTPUsername:           "user",
		SMTPPassword:           "pass",
		SMTPInsecureSkipVerify: true,
	}

	mailer, err := NewMailer(cfg)
	if err != nil {
		t.Fatalf("expected successful mailer creation, got error: %v", err)
	}
	if mailer == nil {
		t.Fatalf("expected non-nil mailer")
	}
}

func TestNewMailer_Success(t *testing.T) {
	cfg := &config.Config{
		SMTPHost:               "localhost",
		SMTPPort:               "1025",
		SMTPUsername:           "user",
		SMTPPassword:           "pass",
		SMTPInsecureSkipVerify: false,
	}

	mailer, err := NewMailer(cfg)
	if err != nil {
		t.Fatalf("expected successful mailer creation, got error: %v", err)
	}
	if mailer == nil {
		t.Fatalf("expected non-nil mailer")
	}
}

func TestSendPasswordReset_InvalidFrom(t *testing.T) {
	cfg := &config.Config{
		SMTPHost: "localhost",
		SMTPPort: "1025",
		SMTPFrom: "invalid-email-format",
	}

	mailer, _ := NewMailer(cfg)

	err := mailer.SendPasswordReset(context.Background(), "to@example.com", "http://reset")
	if err == nil {
		t.Errorf("expected error due to invalid FROM address")
	}
}

func TestSendPasswordReset_InvalidTo(t *testing.T) {
	cfg := &config.Config{
		SMTPHost: "localhost",
		SMTPPort: "1025",
		SMTPFrom: "valid@example.com",
	}

	mailer, _ := NewMailer(cfg)

	err := mailer.SendPasswordReset(context.Background(), "invalid-to-email", "http://reset")
	if err == nil {
		t.Errorf("expected error due to invalid TO address")
	}
}

func TestSendOTP_InvalidFrom(t *testing.T) {
	cfg := &config.Config{
		SMTPHost: "localhost",
		SMTPPort: "1025",
		SMTPFrom: "invalid-email-format",
	}

	mailer, _ := NewMailer(cfg)

	err := mailer.SendOTP(context.Background(), "to@example.com", "123456")
	if err == nil {
		t.Errorf("expected error due to invalid FROM address")
	}
}

func TestSendOTP_InvalidTo(t *testing.T) {
	cfg := &config.Config{
		SMTPHost: "localhost",
		SMTPPort: "1025",
		SMTPFrom: "valid@example.com",
	}

	mailer, _ := NewMailer(cfg)

	err := mailer.SendOTP(context.Background(), "invalid-to-email", "123456")
	if err == nil {
		t.Errorf("expected error due to invalid TO address")
	}
}
