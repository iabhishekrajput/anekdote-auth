package mailer

import (
	"context"
	"fmt"
	"strconv"

	"github.com/iabhishekrajput/anekdote-auth/internal/config"
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

	msg.Subject("Password Reset - Anekdote Auth")

	body := fmt.Sprintf(`
		<h2>Password Reset Request</h2>
		<p>You have requested to reset your password. Click the link below to securely create a new password:</p>
		<p><a href="%s">%s</a></p>
		<p>If you did not request this, please ignore this email.</p>
	`, resetLink, resetLink)

	msg.SetBodyString(mail.TypeTextHTML, body)

	return m.client.DialAndSendWithContext(ctx, msg)
}
