package email_test

import (
	"context"
	"strings"
	"testing"

	"github.com/iabhishekrajput/anekdote-auth/web/ui/email"
)

func TestResetPasswordEmailComponent(t *testing.T) {
	comp := email.PasswordResetEmail("http://localhost:8080/reset?token=123")

	var sb strings.Builder
	if err := comp.Render(context.Background(), &sb); err != nil {
		t.Fatalf("Failed to render PasswordResetEmail: %v", err)
	}

	html := sb.String()
	if !strings.Contains(html, "http://localhost:8080/reset?token=123") {
		t.Errorf("expected reset link in HTML")
	}
}

func TestVerifyEmailOTPEmailComponent(t *testing.T) {
	comp := email.VerifyEmailOTPEmail("123456")

	var sb strings.Builder
	if err := comp.Render(context.Background(), &sb); err != nil {
		t.Fatalf("Failed to render VerifyEmailOTPEmail: %v", err)
	}

	html := sb.String()
	if !strings.Contains(html, "123456") {
		t.Errorf("expected OTP code in HTML")
	}
}

func TestOrgInviteEmailComponent(t *testing.T) {
	comp := email.OrgInviteEmail("Acme Corp", "alice@example.com", "http://localhost:8080/join?token=abc")

	var sb strings.Builder
	if err := comp.Render(context.Background(), &sb); err != nil {
		t.Fatalf("Failed to render OrgInviteEmail: %v", err)
	}

	html := sb.String()
	if !strings.Contains(html, "Acme Corp") {
		t.Errorf("expected org name in HTML")
	}
	if !strings.Contains(html, "http://localhost:8080/join?token=abc") {
		t.Errorf("expected accept URL in HTML")
	}
}
