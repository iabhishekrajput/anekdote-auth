package ui_test

import (
	"context"
	"strings"
	"testing"

	"github.com/iabhishekrajput/anekdote-auth/web/ui"
)

func TestLoginComponent(t *testing.T) {
	comp := ui.LoginPage("csrf-token-123", "", "", "")

	var sb strings.Builder
	err := comp.Render(context.Background(), &sb)
	if err != nil {
		t.Fatalf("Failed to render Login component: %v", err)
	}

	html := sb.String()
	if !strings.Contains(html, "csrf-token-123") {
		t.Errorf("Expected HTML to contain CSRF token, got: %s", html)
	}
}
