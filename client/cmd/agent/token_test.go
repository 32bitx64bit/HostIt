package main

import "testing"

func TestMergeToken(t *testing.T) {
	const existing = "0123456789abcdef0123456789abcdef"
	const fresh = "fedcba9876543210fedcba9876543210"

	cases := []struct {
		name      string
		oldToken  string
		submitted string
		want      string
	}{
		{name: "blank keeps existing", oldToken: existing, submitted: "", want: existing},
		{name: "whitespace keeps existing", oldToken: existing, submitted: "   ", want: existing},
		{name: "stale masked placeholder keeps existing", oldToken: existing, submitted: "****cdef", want: existing},
		{name: "new value replaces", oldToken: existing, submitted: fresh, want: fresh},
		{name: "new value trimmed", oldToken: existing, submitted: "  " + fresh + "  ", want: fresh},
		{name: "blank with no existing stays empty", oldToken: "", submitted: "", want: ""},
		{name: "first token set from empty", oldToken: "", submitted: fresh, want: fresh},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mergeToken(tc.oldToken, tc.submitted); got != tc.want {
				t.Fatalf("mergeToken(%q, %q) = %q, want %q", tc.oldToken, tc.submitted, got, tc.want)
			}
		})
	}
}

func TestMaskTokenNeverLooksLikeRealToken(t *testing.T) {
	// A real (hex) token never begins with "****", so masked output can be used
	// as a safe sentinel for "unchanged" without colliding with a genuine token.
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: "****"},
		{in: "abcd", want: "****"},
		{in: "0123456789abcdef", want: "****cdef"},
	}
	for _, tc := range cases {
		if got := maskToken(tc.in); got != tc.want {
			t.Fatalf("maskToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
