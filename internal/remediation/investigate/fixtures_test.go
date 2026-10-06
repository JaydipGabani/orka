package investigate

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	pv "github.com/orka-agents/orka/internal/patchverification"
	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/intake"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/stretchr/testify/require"
)

type syntheticSource struct {
	target       source.Target
	entries      []source.Entry
	files        []source.PacketFile
	operations   []Stage
	resolveError error
	packetError  error
	packetMutate func(*source.Packet)
}

func (fixture *syntheticSource) Resolve(ctx context.Context, repository, ref string) (source.Target, error) {
	fixture.operations = append(fixture.operations, Resolving)
	if err := ctx.Err(); err != nil {
		return source.Target{}, err
	}
	if canonicalRepository(repository) != fixture.target.Repository.URL || ref != fixture.target.Ref {
		return source.Target{}, fmt.Errorf("unexpected synthetic resolution")
	}
	return fixture.target, fixture.resolveError
}

func (fixture *syntheticSource) Inventory(ctx context.Context, target source.Target) ([]source.Entry, error) {
	fixture.operations = append(fixture.operations, Inventory)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if target != fixture.target {
		return nil, fmt.Errorf("unexpected synthetic target")
	}
	return fixture.entries, nil
}

func (fixture *syntheticSource) Packet(ctx context.Context, target source.Target, paths []string) (source.Packet, error) {
	fixture.operations = append(fixture.operations, Packet)
	if err := ctx.Err(); err != nil {
		return source.Packet{}, err
	}
	if target != fixture.target {
		return source.Packet{}, fmt.Errorf("unexpected synthetic target")
	}
	packet := source.Packet{Version: 1, Target: target, Files: make([]source.PacketFile, 0, len(paths))}
	for _, name := range paths {
		for _, file := range fixture.files {
			if name == file.Path {
				packet.Files = append(packet.Files, file)
			}
		}
	}
	if fixture.packetMutate != nil {
		fixture.packetMutate(&packet)
	}
	return packet, fixture.packetError
}

type syntheticGenerator struct {
	requests []modelagent.Request
	outputs  []string
	generate func(modelagent.Request) (modelagent.Result, error)
}

func (generator *syntheticGenerator) Generate(ctx context.Context, request modelagent.Request) (modelagent.Result, error) {
	generator.requests = append(generator.requests, request)
	if err := ctx.Err(); err != nil {
		return modelagent.Result{}, err
	}
	if generator.generate != nil {
		return generator.generate(request)
	}
	index := len(generator.requests) - 1
	if index >= len(generator.outputs) {
		return modelagent.Result{}, fmt.Errorf("unexpected synthetic model call")
	}
	return modelagent.Result{
		TaskName: request.TaskName, TaskUID: "uid-" + request.TaskName, Output: generator.outputs[index],
	}, nil
}

func fixtureJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	require.NoError(t, err)
	return string(data)
}

func fixtureReport(t *testing.T) intake.Report {
	t.Helper()
	report, err := intake.Parse([]byte(`{"title":"Synthetic request parser error",` +
		`"description":"A malformed request is accepted; it should be rejected before any state change.",` +
		`"versions":["1.2.3"],"restricted":false}`))
	require.NoError(t, err)
	require.Empty(t, report.Repositories, "automatic discovery needs no report repository")
	return report
}

func fixtureProposal(repository string) Proposal {
	return Proposal{
		Problem: "Malformed synthetic input is accepted.", Trigger: "Send the reported malformed request.",
		ExpectedBehavior: "Reject it before a state change.",
		Targets:          []TargetSuggestion{{Repository: repository, Ref: "v1.2.3", Reason: "Synthetic parser evidence matches this allowed project."}},
		Requirements:     []pv.EnvironmentRequirement{{Kind: "process", Name: "parser"}},
		Missing:          []string{}, Limitations: []string{}, LanguageHints: []string{"Go"}, BuildHints: []string{"Go module metadata"},
		Scope: "upstream-source", VersionStatus: "single",
	}
}

func fixtureSelection(paths ...string) Selection {
	return Selection{Paths: paths, Expand: []string{}, Missing: []string{}, Limitations: []string{}}
}

func fixtureSource(repository, name string) *syntheticSource {
	parts := strings.Split(strings.TrimPrefix(repository, "https://github.com/"), "/")
	target := source.Target{
		Repository: source.Repository{URL: repository, Owner: parts[0], Name: parts[1], DefaultBranch: "main"},
		Ref:        "v1.2.3", Commit: strings.Repeat("c", 40), Tree: strings.Repeat("d", 40),
	}
	content := "package synthetic\n"
	object := fmt.Appendf(nil, "blob %d\x00%s", len(content), content)
	blob := sha1.Sum(object)
	sum := sha256.Sum256([]byte(content))
	file := source.PacketFile{
		Path: name, Content: content, BlobSHA: hex.EncodeToString(blob[:]), SHA256: hex.EncodeToString(sum[:]),
	}
	return &syntheticSource{
		target: target, files: []source.PacketFile{file},
		entries: []source.Entry{{Path: name, Mode: "100644", Size: int64(len(content)), BlobSHA: file.BlobSHA}},
	}
}

func fixtureConfig() Config {
	return Config{AllowedRepositoryRoots: []string{
		"https://github.com/synthetic-source/parser", "https://github.com/another-source/engine",
	}}
}

func taskConfig(state State, config Config) Config {
	config.RequestTaskName, config.ExpectedTaskUID = "", ""
	if last := len(state.ModelTasks) - 1; last >= 0 && !state.ModelTasks[last].Completed {
		config.RequestTaskName, config.ExpectedTaskUID = state.ModelTasks[last].TaskName, state.ModelTasks[last].TaskUID
	} else {
		switch state.Stage {
		case "", Identifying:
			config.RequestTaskName = fmt.Sprintf("identify-%d", state.DiscoveryRounds+1)
		case Selecting:
			config.RequestTaskName = fmt.Sprintf("select-%d", state.SelectionRounds+1)
		}
	}
	return config
}

func stepFixture(t *testing.T, engine Engine, state State, report intake.Report, config Config) State {
	t.Helper()
	before := fixtureJSON(t, state)
	next, err := engine.Step(t.Context(), state, report, taskConfig(state, config))
	require.NoError(t, err)
	require.Equal(t, before, fixtureJSON(t, state), "Step must not mutate caller-owned durable state")
	var persisted State
	require.NoError(t, json.Unmarshal([]byte(fixtureJSON(t, next)), &persisted))
	return persisted
}
