package mail

import (
	"bytes"
	"testing"

	"github.com/emersion/go-msgauth/dkim"

	"hostit/shared/emailcfg"
)

func TestSignOutboundMessageProducesVerifiableDKIM(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := emailcfg.Normalize(emailcfg.Config{Enabled: true, Domain: "example.com", DKIMSelector: "hostit"})
	signer, dnsName, txtValue, source, err := ensureDKIMSigner(dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if source != "self-generated" {
		t.Fatalf("source = %q, want self-generated", source)
	}
	if dnsName != "hostit._domainkey.example.com" {
		t.Fatalf("dnsName = %q", dnsName)
	}
	raw := []byte("From: test@example.com\r\nTo: user@example.net\r\nSubject: hello\r\nDate: Tue, 08 Apr 2026 12:00:00 +0000\r\nMessage-ID: <abc@example.com>\r\n\r\nbody\r\n")
	signed, err := signOutboundMessage(raw, cfg, signer, "test@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(signed, []byte("DKIM-Signature:")) {
		t.Fatal("signed message missing DKIM-Signature header")
	}
	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(signed), &dkim.VerifyOptions{
		LookupTXT: func(domain string) ([]string, error) {
			if domain != dnsName {
				t.Fatalf("LookupTXT domain = %q, want %q", domain, dnsName)
			}
			return []string{txtValue}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(verifications) != 1 || verifications[0].Err != nil {
		t.Fatalf("verification failed: %+v", verifications)
	}
}