package mailer

import (
	"bytes"
	"context"
	"crypto/tls"
	"html/template"
	"strconv"

	"github.com/iabhishekrajput/anekdote-auth/internal/config"
	"github.com/wneessen/go-mail"
)

type Mailer struct {
	config *config.Config
	client *mail.Client
	tmpl   *template.Template
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

	if cfg.SMTPInsecureSkipVerify {
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
		opts = append(opts, mail.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	}

	client, err := mail.NewClient(cfg.SMTPHost, opts...)
	if err != nil {
		return nil, err
	}

	tmpl, err := template.ParseFiles(
		"web/templates/email/reset_password.tmpl",
		"web/templates/email/verify_email.tmpl",
	)
	if err != nil {
		return nil, err
	}

	return &Mailer{
		config: cfg,
		client: client,
		tmpl:   tmpl,
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

	msg.Subject("Password Reset - Anekdote Auth")

	var body bytes.Buffer
	err := m.tmpl.ExecuteTemplate(&body, "reset_password.tmpl", map[string]string{
		"ResetLink": resetLink,
	})
	if err != nil {
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

	msg.Subject("Verify Your Email - Anekdote Auth")

	var body bytes.Buffer
	err := m.tmpl.ExecuteTemplate(&body, "verify_email.tmpl", map[string]string{
		"OTP": otp,
	})
	if err != nil {
		return err
	}

	msg.SetBodyString(mail.TypeTextHTML, body.String())

	return m.client.DialAndSendWithContext(ctx, msg)
}
