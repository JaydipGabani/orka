package investigate

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/orka-agents/orka/internal/remediation/source"
)

const (
	testContextBudget            = "adjacent_test_context_budget"
	testContextUnavailable       = "adjacent_test_context_unavailable"
	testContextEncodedBudget     = "adjacent_test_context_encoded_budget"
	testContextOmittedLimitation = "Optional adjacent test context was omitted due to bounds or content policy; unselected files are not authorized patch targets."
)

func testContextFits(entries []source.Entry, paths []string, config Config) bool {
	return len(paths) <= config.MaxFiles && inventoryContains(entries, paths, false) &&
		selectionBytes(entries, paths) <= int64(config.MaxPlanJSONBytes)
}

func omitAddedTestContext(state State, reason string) State {
	_, tests := selectedPathsWithTests(state.Inventory, state.UnverifiedSelection.Paths, true)
	state.OmittedTestPaths = tests
	state.SelectedPaths = slices.Clone(state.UnverifiedSelection.Paths)
	state.AddedTestPaths = nil
	state.TestContextOmission = reason
	return state
}

func boundedTestContext(entries []source.Entry, required []string, config Config) ([]string, []string, []string) {
	_, tests := selectedPathsWithTests(entries, required, config.IncludeAdjacentGoTests)
	sizes := make(map[string]int64, len(entries))
	for _, entry := range entries {
		sizes[entry.Path] = entry.Size
	}
	ordered := slices.Clone(tests)
	slices.SortStableFunc(ordered, func(a, b string) int {
		if sizes[a] < sizes[b] {
			return -1
		}
		if sizes[a] > sizes[b] {
			return 1
		}
		return 0
	})
	paths := slices.Clone(required)
	var omitted []string
	for _, name := range ordered {
		proposed := append(slices.Clone(paths), name)
		if testContextFits(entries, proposed, config) {
			paths = proposed
		} else {
			omitted = append(omitted, name)
		}
	}
	return partitionTestContext(required, tests, omitted)
}

func partitionTestContext(required, tests, omitted []string) ([]string, []string, []string) {
	paths := slices.Clone(required)
	var added, canonicalOmitted []string
	for _, name := range tests {
		if slices.Contains(omitted, name) {
			canonicalOmitted = append(canonicalOmitted, name)
		} else {
			paths = append(paths, name)
			added = append(added, name)
		}
	}
	return paths, added, canonicalOmitted
}

func dropLargestAddedTest(state State, packet source.Packet) (State, source.Packet, error) {
	name, maximum := "", -1
	for _, file := range packet.Files {
		if !slices.Contains(state.AddedTestPaths, file.Path) {
			continue
		}
		raw, err := json.Marshal(file)
		if err != nil {
			return state, packet, ErrState
		}
		if len(raw) > maximum {
			name, maximum = file.Path, len(raw)
		}
	}
	if name == "" {
		return state, packet, ErrState
	}
	_, tests := selectedPathsWithTests(state.Inventory, state.UnverifiedSelection.Paths, true)
	omitted := append(slices.Clone(state.OmittedTestPaths), name)
	state.SelectedPaths, state.AddedTestPaths, state.OmittedTestPaths = partitionTestContext(state.UnverifiedSelection.Paths, tests, omitted)
	state.TestContextOmission = testContextEncodedBudget
	packet.Files = slices.DeleteFunc(slices.Clone(packet.Files), func(file source.PacketFile) bool {
		return !slices.Contains(state.SelectedPaths, file.Path)
	})
	return state, packet, nil
}

func selectedPathsWithTests(entries []source.Entry, selected []string, includeTests bool) ([]string, []string) {
	paths := slices.Clone(selected)
	if !includeTests {
		return paths, nil
	}
	index := make(map[string]source.Entry, len(entries))
	for _, entry := range entries {
		index[entry.Path] = entry
	}
	var added []string
	for _, name := range selected {
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		test := strings.TrimSuffix(name, ".go") + "_test.go"
		if entry, found := index[test]; found && (entry.Mode == "100644" || entry.Mode == "100755") &&
			!slices.Contains(paths, test) {
			paths = append(paths, test)
			added = append(added, test)
		}
	}
	return paths, added
}

func validTestContextBounds(state State, config Config) bool {
	if len(state.AddedTestPaths) > config.MaxFiles || len(state.OmittedTestPaths) > config.MaxFiles ||
		!validPaths(state.AddedTestPaths) || !validPaths(state.OmittedTestPaths) {
		return false
	}
	if !config.IncludeAdjacentGoTests {
		return len(state.AddedTestPaths)+len(state.OmittedTestPaths) == 0 && state.TestContextOmission == ""
	}
	return state.TestContextOmission == "" || state.TestContextOmission == testContextBudget ||
		state.TestContextOmission == testContextUnavailable || state.TestContextOmission == testContextEncodedBudget
}
