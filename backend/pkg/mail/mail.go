// Package mail sends transactional email over SMTP.
package mail

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bintalk/bintalk-clone/internal/config"
)

const sendTimeout = 30 * time.Second

// Mailer sends plain-text email through any SMTP provider (Gmail, Outlook/Office 365, SendGrid,
// Brevo, Mailgun, Amazon SES, ...).
//
//   - Port 465 uses TLS from the start (implicit TLS).
//   - Other ports upgrade with STARTTLS when the server offers it.
//   - Credentials are never sent over an unencrypted connection; without SMTP_USER no login is
//     attempted (e.g. the local Mailpit development server).
type Mailer struct {
	host, port, user, pass, from string
}

// New creates a Mailer from the email configuration.
func New(cfg config.EmailConfig) *Mailer {
	return &Mailer{
		host: strings.TrimSpace(cfg.SMTPHost), port: strconv.Itoa(cfg.SMTPPort),
		user: strings.TrimSpace(cfg.SMTPUser), pass: cfg.SMTPPass, from: strings.TrimSpace(cfg.FromAddr),
	}
}

// Status describes where email goes, for the admin console (never includes credentials).
type Status struct {
	Host string `json:"host"`
	Port string `json:"port"`
	From string `json:"from"`
	// Kind is "mailpit" (caught locally, never delivered), "local" (the bundled Postfix server
	// delivering directly to recipients' mail servers) or "external" (an SMTP provider).
	Kind        string `json:"kind"`
	Development bool   `json:"development"` // true for "mailpit"
}

// Status reports the active email configuration.
func (m *Mailer) Status() Status {
	kind := "external"
	switch m.host {
	case "mailpit", "localhost":
		kind = "mailpit"
	case "postfix":
		kind = "local"
	}
	return Status{Host: m.host, Port: m.port, From: m.from, Kind: kind, Development: kind == "mailpit"}
}

// Send delivers a plain-text message to one recipient.
func (m *Mailer) Send(to, subject, body string) error {
	if strings.ContainsAny(to+subject, "\r\n") {
		return errors.New("invalid header value")
	}
	if m.host == "" || m.from == "" {
		return errors.New("email is not configured (set SMTP_HOST and SMTP_FROM)")
	}

	msg := strings.Join([]string{
		"From: BinTalk <" + m.from + ">",
		"To: " + to,
		"Subject: " + subject,
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: <" + uuid.NewString() + "@" + domainOf(m.from) + ">",
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"",
		strings.ReplaceAll(body, "\n", "\r\n"),
	}, "\r\n")

	addr := net.JoinHostPort(m.host, m.port)
	tlsConfig := &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	var conn net.Conn
	var err error
	if m.port == "465" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(sendTimeout))

	client, err := smtp.NewClient(conn, m.host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SMTP greeting from %s: %w", addr, err)
	}
	defer client.Close()

	encrypted := m.port == "465"
	if !encrypted {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("STARTTLS with %s: %w", addr, err)
			}
			encrypted = true
		}
	}
	if m.user != "" {
		if !encrypted {
			return fmt.Errorf("%s does not support encryption; refusing to send the SMTP password in plain text", addr)
		}
		if err := client.Auth(smtp.PlainAuth("", m.user, m.pass, m.host)); err != nil {
			return fmt.Errorf("SMTP login as %s failed (check SMTP_USER/SMTP_PASSWORD; Gmail and Outlook need an app password): %w", m.user, err)
		}
	}
	if err := client.Mail(m.from); err != nil {
		return fmt.Errorf("sender %s rejected (SMTP_FROM usually must be your SMTP account or a verified sender): %w", m.from, err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("recipient %s rejected: %w", to, err)
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("message rejected: %w", err)
	}
	return client.Quit()
}

func domainOf(address string) string {
	if at := strings.LastIndex(address, "@"); at >= 0 && at < len(address)-1 {
		return address[at+1:]
	}
	return "bintalk"
}
