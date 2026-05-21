package ui_test

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
	"github.com/google/uuid"
	"github.com/iabhishekrajput/anekdote-auth/internal/models"
	"github.com/iabhishekrajput/anekdote-auth/internal/store/postgres"
	"github.com/iabhishekrajput/anekdote-auth/web/ui"
)

func renderComp(t *testing.T, name string, comp templ.Component) string {
	t.Helper()
	var sb strings.Builder
	if err := comp.Render(context.Background(), &sb); err != nil {
		t.Fatalf("%s: render error: %v", name, err)
	}
	return sb.String()
}

func TestLoginPage(t *testing.T) {
	html := renderComp(t, "LoginPage", ui.LoginPage("csrf-token-123", "", "", "", ""))
	if !strings.Contains(html, "csrf-token-123") {
		t.Error("expected CSRF token in output")
	}
	if !strings.Contains(html, "Welcome back.") {
		t.Error("expected heading in output")
	}
}

func TestRegisterPage(t *testing.T) {
	html := renderComp(t, "RegisterPage", ui.RegisterPage("csrf-xyz", "", "", "", ""))
	if !strings.Contains(html, "Create your account") {
		t.Error("expected heading in output")
	}
}

func TestForgotPasswordPage(t *testing.T) {
	html := renderComp(t, "ForgotPasswordPage", ui.ForgotPasswordPage("csrf-xyz", "", ""))
	if !strings.Contains(html, "Forgot your password?") {
		t.Error("expected heading in output")
	}
}

func TestResetPasswordPage(t *testing.T) {
	html := renderComp(t, "ResetPasswordPage", ui.ResetPasswordPage("csrf-xyz", "reset-token-abc", "", ""))
	if !strings.Contains(html, "Set a new password") {
		t.Error("expected heading in output")
	}
	if !strings.Contains(html, "reset-token-abc") {
		t.Error("expected reset token in output")
	}
}

func TestVerifyEmailPage(t *testing.T) {
	html := renderComp(t, "VerifyEmailPage", ui.VerifyEmailPage("csrf-xyz", "user-id-123", "", ""))
	if !strings.Contains(html, "Check your inbox.") {
		t.Error("expected heading in output")
	}
}

func TestConsentPage(t *testing.T) {
	html := renderComp(t, "ConsentPage", ui.ConsentPage("TestApp", "testapp.example.com", []string{"openid", "email"}, "csrf-xyz", "", "", ""))
	if !strings.Contains(html, "TestApp") {
		t.Error("expected client name in output")
	}
	if !strings.Contains(html, "testapp.example.com") {
		t.Error("expected domain in output")
	}
	if !strings.Contains(html, "Read your email address") {
		t.Error("expected scope description in output")
	}
}

func TestAccountPage(t *testing.T) {
	user := &models.User{
		ID:    uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		Name:  "Jane Doe",
		Email: "jane@example.com",
	}
	html := renderComp(t, "AccountPage", ui.AccountPage("csrf-xyz", user, "", ""))
	if !strings.Contains(html, "Jane Doe") {
		t.Error("expected user name in output")
	}
}

func TestOrgListPage(t *testing.T) {
	html := renderComp(t, "OrgListPage", ui.OrgListPage("csrf-xyz", []postgres.OrgListItem{}, []ui.OrgPendingInvite{}, "", ""))
	if !strings.Contains(html, "Organizations") {
		t.Error("expected heading in output")
	}
}

func TestOrgListPageWithOrgs(t *testing.T) {
	items := []postgres.OrgListItem{
		{Org: models.Org{Slug: "acme", DisplayName: "Acme Corp"}, Role: "owner", MemberCount: 3},
	}
	html := renderComp(t, "OrgListPage with orgs", ui.OrgListPage("csrf-xyz", items, []ui.OrgPendingInvite{}, "", ""))
	if !strings.Contains(html, "Acme Corp") {
		t.Error("expected org name in output")
	}
	if !strings.Contains(html, "owner") {
		t.Error("expected role in output")
	}
}

func TestOrgDetailPage(t *testing.T) {
	org := &models.Org{Slug: "acme", DisplayName: "Acme Corp"}
	html := renderComp(t, "OrgDetailPage", ui.OrgDetailPage("csrf-xyz", org, []*models.OrgMembership{}, []ui.OrgPendingMember{}, "user-123", true, "", ""))
	if !strings.Contains(html, "Acme Corp") {
		t.Error("expected org name in output")
	}
}

func TestOrgClientsPage(t *testing.T) {
	org := &models.Org{Slug: "acme", DisplayName: "Acme Corp"}
	html := renderComp(t, "OrgClientsPage", ui.OrgClientsPage("csrf-xyz", org, true, nil, "", "", "", ""))
	if !strings.Contains(html, "Acme Corp") {
		t.Error("expected org name in output")
	}
}

func TestOrgClientsPageWithSecret(t *testing.T) {
	org := &models.Org{Slug: "acme", DisplayName: "Acme Corp"}
	html := renderComp(t, "OrgClientsPageWithSecret", ui.OrgClientsPage("csrf-xyz", org, true, nil, "client-id-123", "key_abc123", "", ""))
	if !strings.Contains(html, "Save your client secret") {
		t.Error("expected secret modal in output")
	}
	if !strings.Contains(html, "key_abc123") {
		t.Error("expected secret value in output")
	}
}

func TestOrgClientsPageNonAdmin(t *testing.T) {
	org := &models.Org{Slug: "acme", DisplayName: "Acme Corp"}
	html := renderComp(t, "OrgClientsPageNonAdmin", ui.OrgClientsPage("csrf-xyz", org, false, nil, "", "", "", ""))
	if strings.Contains(html, "Register client") {
		t.Error("non-admin should not see register button")
	}
}

func TestAlertVariants(t *testing.T) {
	for _, kind := range []string{"error", "success", "info", "warning"} {
		comp := ui.Alert(kind, "Test message for "+kind)
		var sb strings.Builder
		if err := comp.Render(context.Background(), &sb); err != nil {
			t.Errorf("Alert(%q): render error: %v", kind, err)
		}
		if !strings.Contains(sb.String(), "Test message for "+kind) {
			t.Errorf("Alert(%q): expected message in output", kind)
		}
	}
}

func TestAlertEmpty(t *testing.T) {
	var sb strings.Builder
	if err := ui.Alert("error", "").Render(context.Background(), &sb); err != nil {
		t.Fatalf("Alert with empty message: render error: %v", err)
	}
	if sb.String() != "" {
		t.Error("Alert with empty message should render nothing")
	}
}
