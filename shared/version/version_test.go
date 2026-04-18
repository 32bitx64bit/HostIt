package version

import (
	"testing"
)

func TestParseValid(t *testing.T) {
	cases := []struct {
		input string
		want  Version
	}{
		{"1.2.3", Version{Major: 1, Minor: 2, Patch: 3}},
		{"2.0.0", Version{Major: 2, Minor: 0, Patch: 0}},
		{"0.1.0", Version{Major: 0, Minor: 1, Patch: 0}},
		{"v1.2.3", Version{Major: 1, Minor: 2, Patch: 3}},
		{"V2.0.0", Version{Major: 2, Minor: 0, Patch: 0}},
		{"1.2", Version{Major: 1, Minor: 2, Patch: 0}},
		{" 1.2.3 ", Version{Major: 1, Minor: 2, Patch: 3}},
	}
	for _, tc := range cases {
		got, ok := Parse(tc.input)
		if !ok {
			t.Fatalf("Parse(%q) failed, expected success", tc.input)
		}
		if got != tc.want {
			t.Fatalf("Parse(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	cases := []string{"", "a.b.c", "1..3", "-1.0.0", "1.2.3.4"}
	for _, input := range cases {
		if _, ok := Parse(input); ok {
			t.Fatalf("Parse(%q) succeeded, expected failure", input)
		}
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.0", "1.3.0", -1},
		{"1.3.0", "1.2.0", 1},
		{"1.0.1", "1.0.2", -1},
		{"1.0.2", "1.0.1", 1},
		{"0.1.0", "1.0.0", -1},
	}
	for _, tc := range cases {
		a := MustParse(tc.a)
		b := MustParse(tc.b)
		got := a.Compare(b)
		if got != tc.want {
			t.Fatalf("Compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestMustParse(t *testing.T) {
	v := MustParse("3.1.4")
	if v != (Version{Major: 3, Minor: 1, Patch: 4}) {
		t.Fatalf("MustParse = %v, want {3 1 4}", v)
	}
}

func TestMustParsePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("MustParse with invalid version should panic")
		}
	}()
	MustParse("invalid")
}

func TestVersionString(t *testing.T) {
	v := Version{Major: 1, Minor: 2, Patch: 3}
	if got := v.String(); got != "1.2.3" {
		t.Fatalf("Version.String() = %q, want %q", got, "1.2.3")
	}
}
