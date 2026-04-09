package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"hostit/shared/emailcfg"
)

func TestEmailDNSCheckerDetectsSwappedDMARCAndDKIM(t *testing.T) {
	t.Parallel()

	checker := emailDNSChecker{
		lookupMX: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{{Host: "mail.example.com.", Pref: 10}}, nil
		},
		lookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.IPv4(203, 0, 113, 10)}}, nil
		},
		lookupTXT: func(_ context.Context, name string) ([]string, error) {
			switch name {
			case "example.com":
				return []string{"v=spf1 mx a:mail.example.com -all"}, nil
			case "_dmarc.example.com":
				return []string{"v=DKIM1; k=rsa; p=abc123"}, nil
			case "hostit._domainkey.example.com":
				return []string{"v=DMARC1; p=quarantine"}, nil
			default:
				return nil, nil
			}
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			return stubNetConn{}, nil
		},
	}

	report := checker.Run(context.Background(), emailcfg.Config{
		Enabled:      true,
		Domain:       "example.com",
		MailHost:     "mail.example.com",
		InboundSMTP:  true,
		DKIMSelector: "hostit",
	})

	dmarc := findEmailCheck(report.Checks, "dmarc")
	if dmarc.Status != emailCheckFail {
		t.Fatalf("DMARC status = %q, want fail", dmarc.Status)
	}
	if !strings.Contains(strings.ToLower(dmarc.Fix), "move the dkim key") {
		t.Fatalf("DMARC fix = %q, want swap guidance", dmarc.Fix)
	}
	dkim := findEmailCheck(report.Checks, "dkim")
	if dkim.Status != emailCheckFail {
		t.Fatalf("DKIM status = %q, want fail", dkim.Status)
	}
	if !strings.Contains(strings.ToLower(dkim.Fix), "move the dmarc policy") {
		t.Fatalf("DKIM fix = %q, want swap guidance", dkim.Fix)
	}
}

func TestEmailDNSCheckerReportsClosedSMTPPort(t *testing.T) {
	t.Parallel()

	checker := emailDNSChecker{
		lookupMX: func(context.Context, string) ([]*net.MX, error) {
			return []*net.MX{{Host: "mail.example.com.", Pref: 10}}, nil
		},
		lookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.IPv4(203, 0, 113, 10)}}, nil
		},
		lookupTXT: func(_ context.Context, name string) ([]string, error) {
			switch name {
			case "example.com":
				return []string{"v=spf1 mx a:mail.example.com -all"}, nil
			case "_dmarc.example.com":
				return []string{"v=DMARC1; p=quarantine"}, nil
			case "hostit._domainkey.example.com":
				return []string{"v=DKIM1; k=rsa; p=abc123"}, nil
			default:
				return nil, nil
			}
		},
		dial: func(_ context.Context, _, address string) (net.Conn, error) {
			if strings.HasSuffix(address, ":25") {
				return nil, errors.New("connection refused")
			}
			return stubNetConn{}, nil
		},
	}

	report := checker.Run(context.Background(), emailcfg.Config{
		Enabled:      true,
		Domain:       "example.com",
		MailHost:     "mail.example.com",
		InboundSMTP:  true,
		AutoTLS:      true,
		DKIMSelector: "hostit",
	})

	smtp := findEmailCheck(report.Checks, "smtp_port_25")
	if smtp.Status != emailCheckFail {
		t.Fatalf("SMTP port 25 status = %q, want fail", smtp.Status)
	}
	if !strings.Contains(strings.ToLower(smtp.Fix), "open or forward public tcp 25") {
		t.Fatalf("SMTP port 25 fix = %q, want inbound fix guidance", smtp.Fix)
	}
}

func findEmailCheck(checks []emailCheckResult, code string) emailCheckResult {
	for _, ch := range checks {
		if ch.Code == code {
			return ch
		}
	}
	return emailCheckResult{}
}

type stubNetConn struct{}

func (stubNetConn) Read([]byte) (int, error)           { return 0, nil }
func (stubNetConn) Write(b []byte) (int, error)        { return len(b), nil }
func (stubNetConn) Close() error                       { return nil }
func (stubNetConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (stubNetConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (stubNetConn) SetDeadline(_ time.Time) error      { return nil }
func (stubNetConn) SetReadDeadline(_ time.Time) error  { return nil }
func (stubNetConn) SetWriteDeadline(_ time.Time) error { return nil }
