package mail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	stdsmtp "net/smtp"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"golang.org/x/crypto/bcrypt"

	"hostit/shared/emailcfg"
)

func startFakeOutboundSMTPServer(t *testing.T) (string, <-chan []byte) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	msgCh := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		writef := func(format string, args ...any) error {
			if _, err := fmt.Fprintf(rw, format, args...); err != nil {
				return err
			}
			return rw.Flush()
		}

		if err := writef("220 mx.test ESMTP\r\n"); err != nil {
			return
		}

		var data bytes.Buffer
		inData := false
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			trimmed := strings.TrimRight(line, "\r\n")
			if inData {
				if trimmed == "." {
					msgCh <- append([]byte(nil), data.Bytes()...)
					if err := writef("250 2.0.0 queued\r\n"); err != nil {
						return
					}
					inData = false
					continue
				}
				if strings.HasPrefix(trimmed, "..") {
					trimmed = trimmed[1:]
				}
				data.WriteString(trimmed)
				data.WriteString("\r\n")
				continue
			}

			switch upper := strings.ToUpper(trimmed); {
			case strings.HasPrefix(upper, "EHLO "):
				if err := writef("250-mx.test\r\n250 SIZE 1048576\r\n"); err != nil {
					return
				}
			case strings.HasPrefix(upper, "HELO "):
				if err := writef("250 mx.test\r\n"); err != nil {
					return
				}
			case strings.HasPrefix(upper, "MAIL FROM:"):
				if err := writef("250 2.1.0 ok\r\n"); err != nil {
					return
				}
			case strings.HasPrefix(upper, "RCPT TO:"):
				if err := writef("250 2.1.5 ok\r\n"); err != nil {
					return
				}
			case upper == "DATA":
				data.Reset()
				inData = true
				if err := writef("354 end with <CRLF>.<CRLF>\r\n"); err != nil {
					return
				}
			case upper == "QUIT":
				_ = writef("221 2.0.0 bye\r\n")
				return
			default:
				if err := writef("250 ok\r\n"); err != nil {
					return
				}
			}
		}
	}()

	return ln.Addr().String(), msgCh
}

func TestServiceApplyConfigAuthenticateAndDeliverLocal(t *testing.T) {
	t.Parallel()

	svc, err := NewService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := emailcfg.Config{
		Enabled:           true,
		Domain:            "example.com",
		SubmissionAddr:    "127.0.0.1:0",
		SubmissionTLSAddr: "127.0.0.1:0",
		IMAPAddr:          "127.0.0.1:0",
		IMAPTLSAddr:       "127.0.0.1:0",
		Accounts: []emailcfg.Account{{
			Username:     "test",
			PasswordHash: string(hash),
			PasswordSet:  true,
			Enabled:      true,
		}},
	}
	if err := svc.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := svc.Status()
	if !st.TLSReady {
		t.Fatal("Status().TLSReady = false, want true")
	}
	if st.TLSCertSource != "self-signed" {
		t.Fatalf("Status().TLSCertSource = %q, want self-signed", st.TLSCertSource)
	}
	if !st.DKIMReady {
		t.Fatal("Status().DKIMReady = false, want true")
	}
	if st.DKIMDNSName != "hostit._domainkey.example.com" {
		t.Fatalf("Status().DKIMDNSName = %q, want hostit._domainkey.example.com", st.DKIMDNSName)
	}
	if st.DKIMTXTValue == "" {
		t.Fatal("Status().DKIMTXTValue = empty, want TXT record value")
	}
	if st.MaxMessageBytes != 25<<20 {
		t.Fatalf("Status().MaxMessageBytes = %d, want %d", st.MaxMessageBytes, 25<<20)
	}
	if st.MaxRecipients != 100 {
		t.Fatalf("Status().MaxRecipients = %d, want 100", st.MaxRecipients)
	}
	if !st.StorageUnlimited {
		t.Fatal("Status().StorageUnlimited = false, want true")
	}
	if _, err := os.Stat(filepath.Join(svc.dataDir, "tls", "mail.crt")); err != nil {
		t.Fatalf("expected generated mail cert: %v", err)
	}
	if _, err := os.Stat(filepath.Join(svc.dataDir, "dkim", "hostit.pem")); err != nil {
		t.Fatalf("expected generated DKIM key: %v", err)
	}

	rec, err := svc.authenticate("test@example.com", "Password123")
	if err != nil {
		t.Fatalf("authenticate() error = %v", err)
	}
	if rec.Address != "test@example.com" {
		t.Fatalf("authenticate() address = %q, want test@example.com", rec.Address)
	}

	raw := []byte("From: sender@example.net\r\nTo: test@example.com\r\nSubject: hello\r\n\r\nworld\r\n")
	if err := svc.deliverLocal("test@example.com", "INBOX", raw); err != nil {
		t.Fatal(err)
	}

	msgs, err := svc.listMessages("test")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("listMessages() len = %d, want 1", len(msgs))
	}
	if msgs[0].Mailbox != "INBOX" {
		t.Fatalf("message mailbox = %q, want INBOX", msgs[0].Mailbox)
	}

	user, err := svc.buildIMAPUser(rec, "Password123")
	if err != nil {
		t.Fatal(err)
	}
	if err := user.Login("test@example.com", "Password123"); err != nil {
		t.Fatalf("imap login failed: %v", err)
	}
	status, err := user.Status("INBOX", &imap.StatusOptions{NumMessages: true})
	if err != nil {
		t.Fatal(err)
	}
	if status.NumMessages == nil || *status.NumMessages != 1 {
		t.Fatalf("INBOX message count = %v, want 1", status.NumMessages)
	}
}

func TestServiceAutoTLSSetsLetsEncryptSource(t *testing.T) {
	t.Parallel()

	svc, err := NewService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := emailcfg.Config{
		Enabled:           true,
		Domain:            "example.com",
		MailHost:          "mail.example.com",
		AutoTLS:           true,
		ACMEEmail:         "admin@example.com",
		ACMEHTTPAddr:      "127.0.0.1:0",
		SubmissionAddr:    "127.0.0.1:0",
		SubmissionTLSAddr: "127.0.0.1:0",
		IMAPAddr:          "127.0.0.1:0",
		IMAPTLSAddr:       "127.0.0.1:0",
		Accounts: []emailcfg.Account{{
			Username:     "test",
			PasswordHash: string(hash),
			PasswordSet:  true,
			Enabled:      true,
		}},
	}
	if err := svc.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := svc.Status()
	if st.TLSCertSource != "lets-encrypt" {
		t.Fatalf("Status().TLSCertSource = %q, want lets-encrypt", st.TLSCertSource)
	}
	if svc.acmeHTTPLn == nil {
		t.Fatal("expected ACME HTTP listener to be running")
	}
}

func TestServiceImplicitTLSListenersAcceptConnections(t *testing.T) {
	t.Parallel()

	svc, err := NewService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := emailcfg.Config{
		Enabled:           true,
		Domain:            "example.com",
		SubmissionAddr:    "127.0.0.1:0",
		SubmissionTLSAddr: "127.0.0.1:0",
		IMAPAddr:          "127.0.0.1:0",
		IMAPTLSAddr:       "127.0.0.1:0",
		Accounts: []emailcfg.Account{{
			Username:     "test",
			PasswordHash: string(hash),
			PasswordSet:  true,
			Enabled:      true,
		}},
	}
	if err := svc.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if svc.submissionTLSLn == nil {
		t.Fatal("expected SMTPS listener to be running")
	}
	if svc.imapTLSLn == nil {
		t.Fatal("expected IMAPS listener to be running")
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	smtpConn, err := tls.Dial("tcp", svc.submissionTLSLn.Addr().String(), tlsCfg)
	if err != nil {
		t.Fatalf("tls dial SMTPS failed: %v", err)
	}
	b := make([]byte, 256)
	n, err := smtpConn.Read(b)
	if err != nil {
		t.Fatalf("read SMTPS banner failed: %v", err)
	}
	if !strings.Contains(string(b[:n]), "220 ") {
		t.Fatalf("SMTPS banner = %q, want SMTP greeting", string(b[:n]))
	}
	_ = smtpConn.Close()

	imapConn, err := tls.Dial("tcp", svc.imapTLSLn.Addr().String(), tlsCfg)
	if err != nil {
		t.Fatalf("tls dial IMAPS failed: %v", err)
	}
	n, err = imapConn.Read(b)
	if err != nil {
		t.Fatalf("read IMAPS banner failed: %v", err)
	}
	if !strings.Contains(string(b[:n]), "* OK") {
		t.Fatalf("IMAPS banner = %q, want IMAP greeting", string(b[:n]))
	}
	_ = imapConn.Close()
}

func TestListInboxSortsNewestFirst(t *testing.T) {
	t.Parallel()

	svc, err := NewService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApplyConfig(emailcfg.Config{
		Enabled:           true,
		Domain:            "example.com",
		SubmissionAddr:    "127.0.0.1:0",
		SubmissionTLSAddr: "127.0.0.1:0",
		IMAPAddr:          "127.0.0.1:0",
		IMAPTLSAddr:       "127.0.0.1:0",
		Accounts: []emailcfg.Account{{
			Username:     "test",
			PasswordHash: string(hash),
			PasswordSet:  true,
			Enabled:      true,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	older := []byte("From: old@example.net\r\nTo: test@example.com\r\nSubject: older\r\n\r\nold\r\n")
	newer := []byte("From: new@example.net\r\nTo: test@example.com\r\nSubject: newer\r\n\r\nnew\r\n")
	if err := svc.deliverLocal("test@example.com", "INBOX", older); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := svc.deliverLocal("test@example.com", "INBOX", newer); err != nil {
		t.Fatal(err)
	}

	msgs, err := svc.ListInbox("test")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("ListInbox() len = %d, want 2", len(msgs))
	}
	if msgs[0].Subject != "newer" || msgs[1].Subject != "older" {
		t.Fatalf("ListInbox() subjects = [%q, %q], want [newer, older]", msgs[0].Subject, msgs[1].Subject)
	}
}

func TestSMTPPlainAuthAcceptsUsernameOrIdentity(t *testing.T) {
	t.Parallel()

	svc, err := NewService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ApplyConfig(emailcfg.Config{
		Enabled:           true,
		Domain:            "example.com",
		SubmissionAddr:    "127.0.0.1:0",
		SubmissionTLSAddr: "127.0.0.1:0",
		IMAPAddr:          "127.0.0.1:0",
		IMAPTLSAddr:       "127.0.0.1:0",
		Accounts: []emailcfg.Account{{
			Username:     "test",
			PasswordHash: string(hash),
			PasswordSet:  true,
			Enabled:      true,
		}},
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("authcid", func(t *testing.T) {
		sess := &smtpSession{svc: svc, submission: true}
		if err := sess.authenticatePlain("", "test@example.com", "Password123"); err != nil {
			t.Fatalf("authenticatePlain(authcid) error = %v, want nil", err)
		}
		if !sess.authenticated {
			t.Fatal("session not marked authenticated")
		}
		if sess.authAddress != "test@example.com" {
			t.Fatalf("auth address = %q, want test@example.com", sess.authAddress)
		}
	})

	t.Run("authzid fallback", func(t *testing.T) {
		sess := &smtpSession{svc: svc, submission: true}
		if err := sess.authenticatePlain("test@example.com", "", "Password123"); err != nil {
			t.Fatalf("authenticatePlain(authzid fallback) error = %v, want nil", err)
		}
		if !sess.authenticated {
			t.Fatal("session not marked authenticated")
		}
		if sess.authAddress != "test@example.com" {
			t.Fatalf("auth address = %q, want test@example.com", sess.authAddress)
		}
	})
}

func TestServiceAutoTLSFailureStillPublishesDKIM(t *testing.T) {
	t.Parallel()

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	svc, err := NewService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := emailcfg.Config{
		Enabled:           true,
		Domain:            "example.com",
		MailHost:          "mail.example.com",
		AutoTLS:           true,
		ACMEEmail:         "admin@example.com",
		ACMEHTTPAddr:      occupied.Addr().String(),
		SubmissionAddr:    "127.0.0.1:0",
		SubmissionTLSAddr: "127.0.0.1:0",
		IMAPAddr:          "127.0.0.1:0",
		IMAPTLSAddr:       "127.0.0.1:0",
		Accounts: []emailcfg.Account{{
			Username:     "test",
			PasswordHash: string(hash),
			PasswordSet:  true,
			Enabled:      true,
		}},
	}
	if err := svc.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := svc.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v, want service to continue with warning", err)
	}
	st := svc.Status()
	if !st.DKIMReady {
		t.Fatal("Status().DKIMReady = false, want true even after ACME startup failure")
	}
	if st.DKIMDNSName != "hostit._domainkey.example.com" {
		t.Fatalf("Status().DKIMDNSName = %q, want hostit._domainkey.example.com", st.DKIMDNSName)
	}
	if st.DKIMTXTValue == "" {
		t.Fatal("Status().DKIMTXTValue = empty, want TXT record value")
	}
	if st.LastError == "" {
		t.Fatal("Status().LastError = empty, want ACME bind failure")
	}
	if svc.submissionLn == nil {
		t.Fatal("expected submission listener to keep running when ACME bind fails")
	}
	if svc.imapLn == nil {
		t.Fatal("expected IMAP listener to keep running when ACME bind fails")
	}
}

func TestServiceStorageLimitRejectsOverflow(t *testing.T) {
	t.Parallel()

	svc, err := NewService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("A", 700)
	raw := []byte("From: sender@example.net\r\nTo: test@example.com\r\nSubject: hello\r\n\r\n" + body + "\r\n")
	limit := int64(1024)
	cfg := emailcfg.Config{
		Enabled:           true,
		Domain:            "example.com",
		SubmissionAddr:    "127.0.0.1:0",
		SubmissionTLSAddr: "127.0.0.1:0",
		IMAPAddr:          "127.0.0.1:0",
		IMAPTLSAddr:       "127.0.0.1:0",
		StorageLimitBytes: limit,
		Accounts: []emailcfg.Account{{
			Username:     "test",
			PasswordHash: string(hash),
			PasswordSet:  true,
			Enabled:      true,
		}},
	}
	if err := svc.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := svc.deliverLocal("test@example.com", "INBOX", raw); err != nil {
		t.Fatalf("first deliverLocal() error = %v, want nil", err)
	}
	if err := svc.deliverLocal("test@example.com", "INBOX", raw); err == nil {
		t.Fatal("second deliverLocal() error = nil, want storage limit exceeded")
	}
	st := svc.Status()
	if st.StorageUnlimited {
		t.Fatal("Status().StorageUnlimited = true, want false")
	}
	if st.StorageLimitBytes != limit {
		t.Fatalf("Status().StorageLimitBytes = %d, want %d", st.StorageLimitBytes, limit)
	}
}

func TestSendOutboundSMTPToTargetTimesOutStalledServer(t *testing.T) {
	t.Parallel()

	svc, err := NewService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		select {
		case accepted <- struct{}{}:
		default:
		}
		time.Sleep(2 * time.Second)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = svc.sendOutboundSMTPToTarget(ctx, ln.Addr().String(), "sender@example.com", []string{"rcpt@example.net"}, []byte("Subject: test\r\n\r\nbody\r\n"))
	if err == nil {
		t.Fatal("sendOutboundSMTPToTarget() error = nil, want timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("sendOutboundSMTPToTarget() error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("sendOutboundSMTPToTarget() took %v, want under 1s", elapsed)
	}

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("stalled server never accepted the outbound SMTP connection")
	}
}

func TestServiceImplicitTLSSubmissionAuthAndExternalDelivery(t *testing.T) {
	t.Parallel()

	svc, err := NewService(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	hash, err := bcrypt.GenerateFromPassword([]byte("Password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := emailcfg.Config{
		Enabled:           true,
		Domain:            "example.com",
		SubmissionAddr:    "127.0.0.1:0",
		SubmissionTLSAddr: "127.0.0.1:0",
		IMAPAddr:          "127.0.0.1:0",
		IMAPTLSAddr:       "127.0.0.1:0",
		Accounts: []emailcfg.Account{{
			Username:     "test",
			PasswordHash: string(hash),
			PasswordSet:  true,
			Enabled:      true,
		}},
	}
	if err := svc.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}

	outboundAddr, outboundMsgCh := startFakeOutboundSMTPServer(t)
	svc.mxLookup = func(name string) ([]*net.MX, error) {
		if strings.EqualFold(strings.TrimSpace(name), "remote.test") {
			return []*net.MX{{Host: "mx.remote.test.", Pref: 0}}, nil
		}
		return nil, fmt.Errorf("unexpected mx lookup for %q", name)
	}
	svc.outboundDialer = func(ctx context.Context, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, "tcp", outboundAddr)
	}

	if err := svc.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	tlsConn, err := tls.Dial("tcp", svc.submissionTLSLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls dial SMTPS failed: %v", err)
	}
	defer tlsConn.Close()

	host, _, err := net.SplitHostPort(svc.submissionTLSLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := stdsmtp.NewClient(tlsConn, host)
	if err != nil {
		t.Fatalf("smtp.NewClient() error = %v", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("AUTH"); !ok {
		t.Fatal("AUTH extension not advertised on implicit TLS submission")
	}
	if err := client.Auth(stdsmtp.PlainAuth("", "test@example.com", "Password123", host)); err != nil {
		t.Fatalf("smtp AUTH failed: %v", err)
	}
	if err := client.Mail("test@example.com"); err != nil {
		t.Fatalf("smtp MAIL FROM failed: %v", err)
	}
	if err := client.Rcpt("friend@remote.test"); err != nil {
		t.Fatalf("smtp RCPT TO failed: %v", err)
	}
	wc, err := client.Data()
	if err != nil {
		t.Fatalf("smtp DATA failed: %v", err)
	}
	raw := []byte("From: Test User <test@example.com>\r\nTo: Friend <friend@remote.test>\r\nSubject: hello\r\n\r\nworld\r\n")
	if _, err := wc.Write(raw); err != nil {
		t.Fatalf("smtp DATA write failed: %v", err)
	}
	if err := wc.Close(); err != nil {
		t.Fatalf("smtp DATA close failed: %v", err)
	}
	if err := client.Quit(); err != nil {
		t.Fatalf("smtp QUIT failed: %v", err)
	}

	select {
	case got := <-outboundMsgCh:
		if !bytes.Contains(got, []byte("Subject: hello")) {
			t.Fatalf("outbound message missing subject header: %q", string(got))
		}
		if !bytes.Contains(got, []byte("From: Test User <test@example.com>")) {
			t.Fatalf("outbound message missing From header: %q", string(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for outbound SMTP message")
	}

	msgs, err := svc.listMessages("test")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("listMessages() len = %d, want 1 sent message", len(msgs))
	}
	if msgs[0].Mailbox != "Sent" {
		t.Fatalf("sent mailbox = %q, want Sent", msgs[0].Mailbox)
	}
}
