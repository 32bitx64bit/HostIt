package protocol

import (
	"fmt"
	"sort"

	"hostit/shared/version"
)

// VersionPayload is sent during version negotiation after auth. Error is set
// when the server rejects the peer so the agent can report the reason.
//
// Identity (agent->server): PublicKey is the agent's Ed25519 identity key and
// IdentitySig is its signature over the auth server-nonce, proving possession.
// (server->agent): AssignedAgentID is the authoritative ID the agent must adopt
// (claim confirmation or operator override); Conflict means the proposed ID
// belongs to a different agent and the agent must pick a new one.
type VersionPayload struct {
	Version         string   `json:"version"`
	AgentID         string   `json:"agent_id,omitempty"`
	Features        []string `json:"features,omitempty"`
	Error           string   `json:"error,omitempty"`
	PublicKey       []byte   `json:"public_key,omitempty"`
	IdentitySig     []byte   `json:"identity_sig,omitempty"`
	AssignedAgentID string   `json:"assigned_agent_id,omitempty"`
	Conflict        bool     `json:"conflict,omitempty"`
}

// DefaultAgentID is assumed when an agent or route declares no ID.
const DefaultAgentID = "default"

// ProtocolVersion is the tunnel wire-protocol version (major gates compatibility).
const ProtocolVersion = "2.0.0"

var ProtocolVersionParsed = version.MustParse(ProtocolVersion)

// SupportedFeatures are optional capabilities negotiated per connection.
var SupportedFeatures = []string{}

func IsCompatibleWith(local, peer version.Version) bool {
	return local.Major == peer.Major
}

func IncompatibleVersionError(local, peer version.Version) string {
	return fmt.Sprintf("protocol version %s is incompatible with %s: major versions must match (update the older side)", peer, local)
}

// NegotiateFeatures returns the sorted intersection of local and peer features.
func NegotiateFeatures(local, peer []string) []string {
	if len(local) == 0 || len(peer) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(local))
	for _, f := range local {
		set[f] = struct{}{}
	}
	var shared []string
	for _, f := range peer {
		if _, ok := set[f]; ok {
			shared = append(shared, f)
			delete(set, f) // dedupe
		}
	}
	sort.Strings(shared)
	return shared
}
