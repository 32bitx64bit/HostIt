package protocol

import (
	"fmt"

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
	Version         string `json:"version"`
	AgentID         string `json:"agent_id,omitempty"`
	Error           string `json:"error,omitempty"`
	PublicKey       []byte `json:"public_key,omitempty"`
	IdentitySig     []byte `json:"identity_sig,omitempty"`
	AssignedAgentID string `json:"assigned_agent_id,omitempty"`
	Conflict        bool   `json:"conflict,omitempty"`
}

// DefaultAgentID is assumed when an agent or route declares no ID.
const DefaultAgentID = "default"

// ProtocolVersion is the tunnel wire-protocol version (major gates compatibility).
// Version 3 requires identity- and control-generation-bound UDP registration.
const ProtocolVersion = "3.0.0"

var ProtocolVersionParsed = version.MustParse(ProtocolVersion)

func IsCompatibleWith(local, peer version.Version) bool {
	return local.Major == peer.Major
}

func IncompatibleVersionError(local, peer version.Version) string {
	return fmt.Sprintf("protocol version %s is incompatible with %s: major versions must match (update the older side)", peer, local)
}
