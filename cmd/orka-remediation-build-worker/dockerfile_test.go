package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerfileIncludesLocalGoDependencies(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	recipe, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	var inputs []string
	for line := range strings.SplitSeq(string(recipe), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "COPY" || strings.HasPrefix(fields[1], "--") {
			continue
		}
		for _, source := range fields[1 : len(fields)-1] {
			if strings.HasSuffix(source, "/") || source == "." {
				inputs = append(inputs, strings.TrimSuffix(source, "/"))
			}
		}
	}
	const module = "github.com/orka-agents/orka"
	template := `{{if .Module}}{{if eq .Module.Path "` + module + `"}}{{.ImportPath}}{{end}}{{end}}`
	command := exec.CommandContext(
		t.Context(), "go", "list", "-deps", "-f", template, "./cmd/orka-remediation-build-worker",
	)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatal("could not inspect the worker dependency graph", err)
	}
	found := 0
	for path := range strings.SplitSeq(string(output), "\n") {
		if path == "" {
			continue
		}
		found++
		relative := strings.TrimPrefix(path, module+"/")
		included := false
		for _, source := range inputs {
			if source == "." || relative == source || strings.HasPrefix(relative, source+"/") {
				included = true
				break
			}
		}
		if !included {
			t.Errorf("Dockerfile does not copy local dependency %s", relative)
		}
	}
	if found == 0 {
		t.Fatal("worker dependency graph was empty")
	}
}
