package mailer

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"base/internal/config"
	"base/internal/store/dbtype"
	"base/internal/store/sqlc"
)

func TestNewAndEnabled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mailer := New(logger, config.MailerConfig{Enabled: true})
	if mailer == nil {
		t.Fatal("New() = nil, want mailer")
	}
	if !mailer.Enabled() {
		t.Fatal("Enabled() = false, want true")
	}
}

func TestBuildMessage(t *testing.T) {
	message := string(buildMessage("from@example.com", "to@example.com", "Subject Line", "Hello world"))

	for _, fragment := range []string{
		"From: from@example.com\r\n",
		"To: to@example.com\r\n",
		"Subject: Subject Line\r\n",
		"MIME-Version: 1.0\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n\r\n",
		"Hello world",
	} {
		if !strings.Contains(message, fragment) {
			t.Fatalf("buildMessage() missing fragment %q in %q", fragment, message)
		}
	}
}

func TestRenderBodySortsPayloadKeys(t *testing.T) {
	body, err := renderBody(sqlc.EmailOutbox{
		Template: "welcome",
		Payload:  dbtype.RawMessage(`{"zeta":1,"alpha":"two"}`),
	})
	if err != nil {
		t.Fatalf("renderBody() error = %v", err)
	}

	if !strings.HasPrefix(body, "Template: welcome\n\n") {
		t.Fatalf("renderBody() = %q, want template prefix", body)
	}
	alphaIndex := strings.Index(body, "alpha: two\n")
	zetaIndex := strings.Index(body, "zeta: 1\n")
	if alphaIndex == -1 || zetaIndex == -1 {
		t.Fatalf("renderBody() = %q, want both payload lines", body)
	}
	if alphaIndex > zetaIndex {
		t.Fatalf("renderBody() = %q, want keys sorted alphabetically", body)
	}
}

func TestRenderBodyRejectsInvalidPayload(t *testing.T) {
	if _, err := renderBody(sqlc.EmailOutbox{Payload: dbtype.RawMessage(`{"broken":`)}); err == nil {
		t.Fatal("renderBody() error = nil, want JSON decode error")
	}
}

func TestRenderBodyWithoutPayloadIncludesTemplate(t *testing.T) {
	body, err := renderBody(sqlc.EmailOutbox{Template: "verify-email"})
	if err != nil {
		t.Fatalf("renderBody() error = %v", err)
	}
	if body != "Template: verify-email\n\n" {
		t.Fatalf("renderBody() = %q, want template-only body", body)
	}
}

func TestSendReturnsErrorWhenMailerDisabled(t *testing.T) {
	mailer := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.MailerConfig{
		Enabled: false,
		From:    "from@example.com",
		Host:    "localhost",
		Port:    2525,
	})

	err := mailer.Send(context.Background(), sqlc.EmailOutbox{
		ID:        1,
		Template:  "welcome",
		Recipient: "to@example.com",
		Subject:   "Hello",
		Payload:   dbtype.RawMessage(`{"name":"alice"}`),
	})
	if err == nil || !strings.Contains(err.Error(), "mailer disabled") {
		t.Fatalf("Send() error = %v, want mailer disabled error", err)
	}
}

func TestSendRejectsInvalidPayloadBeforeSMTP(t *testing.T) {
	mailer := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.MailerConfig{
		Enabled: true,
		From:    "from@example.com",
		Host:    "127.0.0.1",
		Port:    1,
	})

	err := mailer.Send(context.Background(), sqlc.EmailOutbox{
		ID:        2,
		Template:  "welcome",
		Recipient: "to@example.com",
		Subject:   "Hello",
		Payload:   dbtype.RawMessage(`{"broken":`),
	})
	if err == nil || !strings.Contains(err.Error(), "decode email payload") {
		t.Fatalf("Send() error = %v, want payload decode error", err)
	}
}

func TestSendTLSDialError(t *testing.T) {
	mailer := New(slog.New(slog.NewTextHandler(io.Discard, nil)), config.MailerConfig{
		Enabled:    true,
		From:       "from@example.com",
		Host:       "127.0.0.1",
		Port:       1,
		RequireTLS: true,
	})

	err := mailer.Send(context.Background(), sqlc.EmailOutbox{
		ID:        3,
		Template:  "welcome",
		Recipient: "to@example.com",
		Subject:   "Hello",
		Payload:   dbtype.RawMessage(`{"name":"alice"}`),
	})
	if err == nil || !strings.Contains(err.Error(), "tls dial smtp") {
		t.Fatalf("Send() error = %v, want TLS dial error", err)
	}
}
