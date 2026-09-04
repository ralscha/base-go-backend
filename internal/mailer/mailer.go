package mailer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"sort"
	"strings"

	"base/internal/config"
	"base/internal/store/sqlc"
)

type Mailer struct {
	logger *slog.Logger
	cfg    config.MailerConfig
}

func New(logger *slog.Logger, cfg config.MailerConfig) *Mailer {
	return &Mailer{logger: logger, cfg: cfg}
}

func (m *Mailer) Enabled() bool {
	return m.cfg.Enabled
}

func (m *Mailer) Send(ctx context.Context, email sqlc.EmailOutbox) error {
	body, err := renderBody(email)
	if err != nil {
		return err
	}

	if !m.cfg.Enabled {
		m.logger.Info("mailer disabled; leaving email in outbox",
			slog.Int64("email_id", email.ID),
			slog.String("recipient", email.Recipient),
		)
		return fmt.Errorf("mailer disabled")
	}

	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	msg := buildMessage(m.cfg.From, email.Recipient, email.Subject, body)

	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}

	return m.sendSMTP(ctx, addr, auth, email.Recipient, msg)
}

func (m *Mailer) sendSMTP(ctx context.Context, addr string, auth smtp.Auth, recipient string, msg []byte) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial smtp: %w", err)
	}
	stopClosing := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClosing()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return fmt.Errorf("set smtp deadline: %w", err)
		}
	}

	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("create smtp client: %w", err)
	}
	defer func() { _ = client.Close() }()

	tlsCfg := &tls.Config{
		ServerName: m.cfg.Host,
		MinVersion: tls.VersionTLS12,
	}
	if m.cfg.RequireTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp server does not support STARTTLS")
		}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp STARTTLS: %w", err)
		}
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(m.cfg.From); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := client.Rcpt(recipient); err != nil {
		return fmt.Errorf("smtp rcpt to: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("smtp quit: %w", err)
	}
	return nil
}

func buildMessage(from, to, subject, body string) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", to)
	fmt.Fprintf(&buf, "Subject: %s\r\n", subject)
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	buf.WriteString(body)
	return buf.Bytes()
}

func renderBody(email sqlc.EmailOutbox) (string, error) {
	var payload map[string]any
	if len(email.Payload) > 0 {
		if err := json.Unmarshal(email.Payload, &payload); err != nil {
			return "", fmt.Errorf("decode email payload: %w", err)
		}
	}

	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var builder strings.Builder
	fmt.Fprintf(&builder, "Template: %s\n\n", email.Template)
	for _, key := range keys {
		fmt.Fprintf(&builder, "%s: %v\n", key, payload[key])
	}

	return builder.String(), nil
}
