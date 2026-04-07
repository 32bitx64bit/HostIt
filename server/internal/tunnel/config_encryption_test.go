package tunnel

import (
	"strings"
	"testing"
)

func TestServerConfigValidate_RequiresEncryptionAlgorithmForEncryptedRoutes(t *testing.T) {
	encrypted := true
	cfg := ServerConfig{
		ControlAddr: ":7000",
		DataAddr:    ":7001",
		Token:       "test-token",
		DisableTLS:  true,
		Routes: []RouteConfig{{
			Name:       "game",
			Proto:      "tcp",
			PublicAddr: ":47984",
			Encrypted:  &encrypted,
		}},
	}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "encryption_algorithm is required") {
		t.Fatalf("Validate() error = %v, want encryption algorithm validation failure", err)
	}
}
