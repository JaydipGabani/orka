package provenance

import (
	"errors"
	"regexp"
	"strings"
)

var (
	commandVariable = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)
	commandEval     = regexp.MustCompile(`\beval\b`)
)

func buildCommandLocation(location []string) bool {
	if len(location) == 6 && location[0] == "targets" {
		location = location[2:]
	}
	return len(location) == 4 && location[0] == "build" && location[1] == "steps" &&
		location[2] == "[]" && location[3] == "command"
}

// This is a bounded syntax check, never shell evaluation. Runtime variables
// are preserved; dynamic evaluation and unbound builder-platform inputs remain
// outside the supported recipe subset.
func validateBuildCommand(value string) error {
	if strings.ContainsRune(value, '`') || commandEval.MatchString(value) {
		return errors.New("provenance build commands do not support dynamic shell evaluation")
	}
	for {
		_, rest, found := strings.Cut(value, "$")
		if !found {
			return nil
		}
		braced := strings.HasPrefix(rest, "{")
		if braced {
			rest = rest[1:]
		}
		name := commandVariable.FindString(rest)
		if name == "" {
			return errors.New("provenance build commands require simple shell variables")
		}
		rest = rest[len(name):]
		if braced {
			if !strings.HasPrefix(rest, "}") {
				return errors.New("provenance build commands do not support shell parameter operators")
			}
			rest = rest[1:]
		}
		switch name {
		case "BUILDOS", "BUILDARCH", "BUILDPLATFORM", "BUILDVARIANT", "TARGETVARIANT":
			return errors.New("provenance build commands cannot depend on an unbound builder platform")
		}
		value = rest
	}
}
