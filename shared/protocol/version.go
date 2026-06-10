package protocol

import (
	"fmt"
	"sort"

	"hostit/shared/version"
)

// VersionPayload is sent during version negotiation after auth.
// Error is set when the server rejects the peer so the agent
// can report the reason.
type VersionPayload struct {
	Version  string   `json:"version"`
	Features []string `json:"features,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// ProtocolVersion is the tunnel wire-protocol version.
const ProtocolVersion = "1.0.0"

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
