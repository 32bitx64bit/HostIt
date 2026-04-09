package mail

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"hostit/shared/emailcfg"
)

type stubAddr string

func (a stubAddr) Network() string { return "tcp" }
func (a stubAddr) String() string  { return string(a) }

type stubConn struct {
	remote net.Addr
}

func (c stubConn) Read(_ []byte) (int, error)         { return 0, nil }
func (c stubConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c stubConn) Close() error                       { return nil }
func (c stubConn) LocalAddr() net.Addr                { return stubAddr("127.0.0.1:587") }
func (c stubConn) RemoteAddr() net.Addr               { return c.remote }
func (c stubConn) SetDeadline(_ time.Time) error      { return nil }
func (c stubConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c stubConn) SetWriteDeadline(_ time.Time) error { return nil }

func TestEnsureMailTLSConfigAutoTLSFallsBackForLoopback(t *testing.T) {
	t.Parallel()

	setup, err := ensureMailTLSConfig(t.TempDir(), emailcfg.Config{
		Enabled:      true,
		Domain:       "example.com",
		MailHost:     "mail.example.com",
		AutoTLS:      true,
		ACMEEmail:    "admin@example.com",
		ACMEHTTPAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("ensureMailTLSConfig() error = %v", err)
	}
	if setup.Config == nil || setup.Config.GetCertificate == nil {
		t.Fatal("expected AutoTLS config with GetCertificate")
	}

	cert, err := setup.Config.GetCertificate(&tls.ClientHelloInfo{
		Conn:       stubConn{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}},
		ServerName: "",
	})
	if err != nil {
		t.Fatalf("GetCertificate(loopback) error = %v, want nil", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("GetCertificate(loopback) returned empty certificate")
	}
}

func TestShouldUseLocalMailTLSFallback_UsesMailHostSNIOnLoopback(t *testing.T) {
	t.Parallel()

	if shouldUseLocalMailTLSFallback(&tls.ClientHelloInfo{
		Conn:       stubConn{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}},
		ServerName: "mail.example.com",
	}) {
		t.Fatal("shouldUseLocalMailTLSFallback(loopback mail host SNI) = true, want false")
	}

	if !shouldUseLocalMailTLSFallback(&tls.ClientHelloInfo{
		Conn:       stubConn{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}},
		ServerName: "localhost",
	}) {
		t.Fatal("shouldUseLocalMailTLSFallback(localhost SNI) = false, want true")
	}
}

func TestShouldUseLocalMailTLSFallback_DoesNotUseLocalFallbackForRemoteMissingSNI(t *testing.T) {
	t.Parallel()

	if shouldUseLocalMailTLSFallback(&tls.ClientHelloInfo{
		Conn:       stubConn{remote: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 12345}},
		ServerName: "",
	}) {
		t.Fatal("shouldUseLocalMailTLSFallback(remote missing SNI) = true, want false")
	}
}

func TestEffectiveMailClientHello_UsesConfiguredHostForMissingSNI(t *testing.T) {
	t.Parallel()

	hello := effectiveMailClientHello(&tls.ClientHelloInfo{ServerName: ""}, "mail.example.com")
	if hello == nil {
		t.Fatal("effectiveMailClientHello() = nil, want hello")
	}
	if got := hello.ServerName; got != "mail.example.com" {
		t.Fatalf("effectiveMailClientHello().ServerName = %q, want mail.example.com", got)
	}
}
