package netutil

import "testing"

func TestValidateAgentLocalHost(t *testing.T) {
	ok := []string{"", "localhost", "LOCALHOST", "127.0.0.1", "::1", "0.0.0.0", "::", "10.0.0.5", "192.168.1.10", "172.16.0.1", "fd12::1"}
	for _, h := range ok {
		if err := ValidateAgentLocalHost(h); err != nil {
			t.Fatalf("ValidateAgentLocalHost(%q) = %v, want nil", h, err)
		}
	}
	bad := []string{"169.254.169.254", "8.8.8.8", "1.1.1.1", "metadata.google.internal", "example.com", "fe80::1"}
	for _, h := range bad {
		if err := ValidateAgentLocalHost(h); err == nil {
			t.Fatalf("ValidateAgentLocalHost(%q) = nil, want error", h)
		}
	}
}

func TestValidateAgentLocalAddr(t *testing.T) {
	if err := ValidateAgentLocalAddr("127.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAgentLocalAddr("169.254.169.254:80"); err == nil {
		t.Fatal("expected reject for metadata IP")
	}
	if err := ValidateAgentLocalAddr("[::1]:443"); err != nil {
		t.Fatal(err)
	}
}
