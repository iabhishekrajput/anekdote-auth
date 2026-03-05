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
	err := comp.Render(context.Background(), &sb)
	if err != nil {
		t.Fatalf("Failed to render PasswordResetEmail component: %v", err)
	}

	html := sb.String()
	if !strings.Contains(html, "http://localhost:8080/reset?token=123") {
		t.Errorf("Expected HTML to contain reset link, got: %s", html)
	}
}
