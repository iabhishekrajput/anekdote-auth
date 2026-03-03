package mailer

import (
	"bytes"
	"context"
	"crypto/tls"
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

	if cfg.SMTPInsecureSkipVerify {
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
		opts = append(opts, mail.WithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
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
