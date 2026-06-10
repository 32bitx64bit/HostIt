package protocol

import "hostit/shared/version"

type VersionPayload struct {
	Version string `json:"version"`
}

const ProtocolVersion = "1.0.0"

var ProtocolVersionParsed = version.MustParse(ProtocolVersion)

// IsCompatibleWith returns true if the peer version is compatible with the
// local version. Major versions must match exactly. The peer's minor version
// must be >= the local minor version. Patch is informational and ignored.
func IsCompatibleWith(local, peer version.Version) bool {
	if local.Major != peer.Major {
		return false
	}
	if peer.Minor < local.Minor {
		return false
	}
	return true
}
