package pack

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var strictSemverRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$`)

type semver struct {
	core       [3]int
	prerelease []string
}

func parseSemver(value string) (semver, error) {
	match := strictSemverRE.FindStringSubmatch(value)
	if match == nil {
		return semver{}, fmt.Errorf("invalid strict SemVer: %q", value)
	}
	var parsed semver
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(match[i+1])
		if err != nil {
			return semver{}, fmt.Errorf("invalid strict SemVer: %q", value)
		}
		parsed.core[i] = n
	}
	if match[4] != "" {
		parsed.prerelease = strings.Split(match[4], ".")
		for _, token := range parsed.prerelease {
			if token == "" {
				return semver{}, fmt.Errorf("invalid strict SemVer prerelease: %q", value)
			}
			if _, err := strconv.Atoi(token); err == nil && len(token) > 1 && token[0] == '0' {
				return semver{}, fmt.Errorf("numeric prerelease identifier has leading zero: %q", value)
			}
		}
	}
	return parsed, nil
}

func compareSemver(left, right string) (int, error) {
	l, err := parseSemver(left)
	if err != nil {
		return 0, err
	}
	r, err := parseSemver(right)
	if err != nil {
		return 0, err
	}
	for i := 0; i < 3; i++ {
		switch {
		case l.core[i] < r.core[i]:
			return -1, nil
		case l.core[i] > r.core[i]:
			return 1, nil
		}
	}
	if len(l.prerelease) == 0 && len(r.prerelease) == 0 {
		return 0, nil
	}
	if len(l.prerelease) == 0 {
		return 1, nil
	}
	if len(r.prerelease) == 0 {
		return -1, nil
	}
	limit := len(l.prerelease)
	if len(r.prerelease) < limit {
		limit = len(r.prerelease)
	}
	for i := 0; i < limit; i++ {
		lt, rt := l.prerelease[i], r.prerelease[i]
		if lt == rt {
			continue
		}
		ln, lerr := strconv.Atoi(lt)
		rn, rerr := strconv.Atoi(rt)
		lnum, rnum := lerr == nil, rerr == nil
		switch {
		case lnum && rnum:
			if ln < rn {
				return -1, nil
			}
			return 1, nil
		case lnum != rnum:
			if lnum {
				return -1, nil
			}
			return 1, nil
		default:
			if lt < rt {
				return -1, nil
			}
			return 1, nil
		}
	}
	switch {
	case len(l.prerelease) < len(r.prerelease):
		return -1, nil
	case len(l.prerelease) > len(r.prerelease):
		return 1, nil
	default:
		return 0, nil
	}
}

func requireRuntimeCompatible(minimumRuntime, currentRuntime string) error {
	order, err := compareSemver(currentRuntime, minimumRuntime)
	if err != nil {
		return err
	}
	if order < 0 {
		return fmt.Errorf("runtime %s is below pack minimum %s", currentRuntime, minimumRuntime)
	}
	return nil
}
