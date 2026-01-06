package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Current is the currently running HostIt/Playit-prototype version.
// Keep this in sync with your GitHub release tags.
const Current = "1.5"

type Version struct {
	Major int
	Minor int
	Patch int
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v Version) Compare(o Version) int {
	if v.Major != o.Major {
		if v.Major < o.Major {
			return -1
		}
		return 1
	}
	if v.Minor != o.Minor {
		if v.Minor < o.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != o.Patch {
		if v.Patch < o.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// Parse parses versions like "1", "1.2", "1.2.3", with optional "v" prefix.
func Parse(s string) (Version, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, false
	}
	if strings.HasPrefix(s, "v") || strings.HasPrefix(s, "V") {
		s = strings.TrimSpace(s[1:])
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return Version{}, false
	}
	vals := [3]int{0, 0, 0}
	for i := 0; i < len(parts); i++ {
		p := strings.TrimSpace(parts[i])
		if p == "" {
			return Version{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, false
		}
		vals[i] = n
	}
	return Version{Major: vals[0], Minor: vals[1], Patch: vals[2]}, true
}

func MustParse(s string) Version {
	v, ok := Parse(s)
	if !ok {
		panic("invalid version: " + s)
	}
	return v
}

var CurrentParsed = MustParse(Current)
