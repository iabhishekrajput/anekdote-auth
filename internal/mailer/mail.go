package mailer

import (
	"bytes"
	"context"
	"strconv"

	"github.com/iabhishekrajput/anekdote-auth/internal/config"
	uiemail "github.com/iabhishekrajput/anekdote-auth/web/ui/email"
	"github.com/wneessen/go-mail"
)

type Mailer struct {
	config *config.Config
	client *mail.Client
}

func NewMailer(cfg *config.Config) (*Mailer, error) {
	port, err := strconv.Atoi(cfg.SMTPPort)
	if err != nil {
		port = 587
	}

	opts := []mail.Option{
		mail.WithPort(port),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(cfg.SMTPUsername),
		mail.WithPassword(cfg.SMTPPassword),
	}

	switch {
	case cfg.SMTPInsecureSkipVerify:
		// Local dev (e.g. Mailpit): plain SMTP, no TLS negotiation.
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	case port == 465:
		// SMTPS: implicit SSL/TLS on port 465 (e.g. Resend, SendGrid).
		opts = append(opts, mail.WithSSL())
	default:
		// STARTTLS: explicit TLS upgrade (e.g. port 587).
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}

	client, err := mail.NewClient(cfg.SMTPHost, opts...)
	if err != nil {
		return nil, err
	}

	return &Mailer{
		config: cfg,
		client: client,
	}, nil
}

func (m *Mailer) SendPasswordReset(ctx context.Context, toEmail, resetLink string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.config.SMTPFrom); err != nil {
		return err
	}
	if err := msg.To(toEmail); err != nil {
		return err
	}

	msg.Subject("Password Reset - anekdote")

	var body bytes.Buffer
	if err := uiemail.PasswordResetEmail(resetLink).Render(ctx, &body); err != nil {
		return err
	}

	msg.SetBodyString(mail.TypeTextHTML, body.String())

	return m.client.DialAndSendWithContext(ctx, msg)
}

func (m *Mailer) SendOrgInvite(ctx context.Context, toEmail, orgName, inviterEmail, acceptURL string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.config.SMTPFrom); err != nil {
		return err
	}
	if err := msg.To(toEmail); err != nil {
		return err
	}
	msg.Subject("You're invited to " + orgName + " - anekdote")

	var body bytes.Buffer
	if err := uiemail.OrgInviteEmail(orgName, inviterEmail, acceptURL).Render(ctx, &body); err != nil {
		return err
	}
	msg.SetBodyString(mail.TypeTextHTML, body.String())
	return m.client.DialAndSendWithContext(ctx, msg)
}

func (m *Mailer) SendOwnershipTransfer(ctx context.Context, toEmail, orgName, orgSlug, appURL string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.config.SMTPFrom); err != nil {
		return err
	}
	if err := msg.To(toEmail); err != nil {
		return err
	}
	msg.Subject("You are now the owner of " + orgName + " - anekdote")

	orgURL := appURL + "/account/orgs/" + orgSlug
	var body bytes.Buffer
	if err := uiemail.OwnershipTransferEmail(orgName, orgURL).Render(ctx, &body); err != nil {
		return err
	}
	msg.SetBodyString(mail.TypeTextHTML, body.String())
	return m.client.DialAndSendWithContext(ctx, msg)
}

func (m *Mailer) SendClientGrantRequest(ctx context.Context, toEmails []string, clientName, requesterOrgName, requestsURL string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.config.SMTPFrom); err != nil {
		return err
	}
	if err := msg.To(toEmails...); err != nil {
		return err
	}
	msg.Subject(requesterOrgName + " is requesting access to " + clientName + " - anekdote")

	var body bytes.Buffer
	if err := uiemail.ClientGrantRequestEmail(clientName, requesterOrgName, requestsURL).Render(ctx, &body); err != nil {
		return err
	}
	msg.SetBodyString(mail.TypeTextHTML, body.String())
	return m.client.DialAndSendWithContext(ctx, msg)
}

func (m *Mailer) SendGrantApproved(ctx context.Context, toEmails []string, clientName, requesterOrgName, clientsURL string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.config.SMTPFrom); err != nil {
		return err
	}
	if err := msg.To(toEmails...); err != nil {
		return err
	}
	msg.Subject("Access to " + clientName + " approved - anekdote")
	var body bytes.Buffer
	if err := uiemail.GrantApprovedEmail(clientName, requesterOrgName, clientsURL).Render(ctx, &body); err != nil {
		return err
	}
	msg.SetBodyString(mail.TypeTextHTML, body.String())
	return m.client.DialAndSendWithContext(ctx, msg)
}

func (m *Mailer) SendGrantDenied(ctx context.Context, toEmails []string, clientName, requesterOrgName string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.config.SMTPFrom); err != nil {
		return err
	}
	if err := msg.To(toEmails...); err != nil {
		return err
	}
	msg.Subject("Access request for " + clientName + " denied - anekdote")
	var body bytes.Buffer
	if err := uiemail.GrantDeniedEmail(clientName, requesterOrgName).Render(ctx, &body); err != nil {
		return err
	}
	msg.SetBodyString(mail.TypeTextHTML, body.String())
	return m.client.DialAndSendWithContext(ctx, msg)
}

func (m *Mailer) SendGrantRevoked(ctx context.Context, toEmails []string, clientName, orgName string, adminRevoke bool, reason string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.config.SMTPFrom); err != nil {
		return err
	}
	if err := msg.To(toEmails...); err != nil {
		return err
	}
	msg.Subject(orgName + "'s access to " + clientName + " removed - anekdote")
	var body bytes.Buffer
	if err := uiemail.GrantRevokedEmail(clientName, orgName, adminRevoke, reason).Render(ctx, &body); err != nil {
		return err
	}
	msg.SetBodyString(mail.TypeTextHTML, body.String())
	return m.client.DialAndSendWithContext(ctx, msg)
}

func (m *Mailer) SendSecretRotated(ctx context.Context, toEmails []string, clientName, orgName string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.config.SMTPFrom); err != nil {
		return err
	}
	if err := msg.To(toEmails...); err != nil {
		return err
	}
	msg.Subject("Client secret rotated for " + clientName + " - anekdote")
	var body bytes.Buffer
	if err := uiemail.SecretRotatedEmail(clientName, orgName).Render(ctx, &body); err != nil {
		return err
	}
	msg.SetBodyString(mail.TypeTextHTML, body.String())
	return m.client.DialAndSendWithContext(ctx, msg)
}

func (m *Mailer) SendOTP(ctx context.Context, toEmail, otp string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.config.SMTPFrom); err != nil {
		return err
	}
	if err := msg.To(toEmail); err != nil {
		return err
	}

	msg.Subject("Verify Your Email - anekdote")

	var body bytes.Buffer
	if err := uiemail.VerifyEmailOTPEmail(otp).Render(ctx, &body); err != nil {
		return err
	}

	msg.SetBodyString(mail.TypeTextHTML, body.String())

	return m.client.DialAndSendWithContext(ctx, msg)
}
