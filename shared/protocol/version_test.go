package protocol

import (
	"reflect"
	"testing"

	"hostit/shared/version"
)

func v(s string) version.Version { return version.MustParse(s) }

// TestIsCompatibleWith pins the compatibility contract: same major
// interoperates in BOTH directions regardless of minor/patch; different
// majors never do. (The old rule required peer.Minor >= local.Minor on both
// sides, which collapsed to "minors must be equal" and made every minor
// bump a hard break.)
func TestIsCompatibleWith(t *testing.T) {
	cases := []struct {
		local, peer string
		want        bool
	}{
		{"2.0.0", "2.0.0", true},
		{"2.0.0", "2.1.0", true}, // older local, newer peer minor
		{"2.1.0", "2.0.0", true}, // newer local, older peer minor
		{"2.0.0", "2.0.9", true},
		{"2.5.3", "2.0.0", true},
		{"2.0.0", "1.9.9", false},
		{"1.0.0", "2.0.0", false},
		{"2.0.0", "3.0.0", false},
	}
	for _, c := range cases {
		if got := IsCompatibleWith(v(c.local), v(c.peer)); got != c.want {
			t.Errorf("IsCompatibleWith(%s, %s) = %v, want %v", c.local, c.peer, got, c.want)
		}
		// Compatibility must be symmetric: both ends run this check.
		if got := IsCompatibleWith(v(c.peer), v(c.local)); got != c.want {
			t.Errorf("IsCompatibleWith(%s, %s) = %v, want %v (asymmetric rule)", c.peer, c.local, got, c.want)
		}
	}
}

func TestNegotiateFeatures(t *testing.T) {
	cases := []struct {
		local, peer, want []string
	}{
		{nil, nil, nil},
		{[]string{"a"}, nil, nil},
		{nil, []string{"a"}, nil},
		{[]string{"a", "b"}, []string{"b", "c"}, []string{"b"}},
		{[]string{"b", "a"}, []string{"a", "b"}, []string{"a", "b"}},
		{[]string{"a"}, []string{"a", "a"}, []string{"a"}},
	}
	for _, c := range cases {
		if got := NegotiateFeatures(c.local, c.peer); !reflect.DeepEqual(got, c.want) {
			t.Errorf("NegotiateFeatures(%v, %v) = %v, want %v", c.local, c.peer, got, c.want)
		}
	}
}

func TestIncompatibleVersionErrorMentionsBothVersions(t *testing.T) {
	msg := IncompatibleVersionError(v("2.0.0"), v("1.0.0"))
	if msg == "" {
		t.Fatal("empty rejection reason")
	}
	for _, want := range []string{"1.0.0", "2.0.0"} {
		if !contains(msg, want) {
			t.Errorf("rejection reason %q does not mention %s", msg, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
