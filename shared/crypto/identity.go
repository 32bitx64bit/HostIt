package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// Agent identity is an Ed25519 keypair generated once per install. The agent
// proves possession of the private key by signing the server's auth nonce, so
// only the real agent can re-assume a registered Agent ID (trust-on-first-use).
const (
	AgentPublicKeyLen      = ed25519.PublicKeySize
	identityChallengeLabel = "hostit-agent-identity-v1"
)

// GenerateAgentIdentity returns a fresh Ed25519 keypair for an agent install.
func GenerateAgentIdentity() (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate agent identity: %w", err)
	}
	return pub, priv, nil
}

// SignIdentityChallenge signs the (domain-separated) server nonce.
func SignIdentityChallenge(priv ed25519.PrivateKey, challenge []byte) []byte {
	return ed25519.Sign(priv, identityMessage(challenge))
}

// VerifyIdentityChallenge reports whether sig is pub's signature over challenge.
func VerifyIdentityChallenge(pub, challenge, sig []byte) bool {
	if len(pub) != AgentPublicKeyLen {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), identityMessage(challenge), sig)
}

func identityMessage(challenge []byte) []byte {
	msg := make([]byte, 0, len(identityChallengeLabel)+len(challenge))
	msg = append(msg, identityChallengeLabel...)
	msg = append(msg, challenge...)
	return msg
}
