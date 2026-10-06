package service

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/orka-agents/orka/internal/remediation/source"
)

type testFailureContext struct {
	Path     string `json:"path"`
	TestName string `json:"testName"`
	Original string `json:"original"`
}

func focusedTestFailureContext(packet source.Packet, feedback json.RawMessage) []testFailureContext {
	var failure candidateRejected
	if json.Unmarshal(feedback, &failure) != nil {
		return nil
	}
	names := make(map[string]bool)
	for _, diagnostic := range failure.Diagnostics {
		if diagnostic.Code == "go-test-failure" && diagnostic.Identifier != "" {
			names[diagnostic.Identifier] = true
		}
	}
	if len(names) == 0 {
		return nil
	}
	var contexts []testFailureContext
	total := 0
	for _, file := range packet.Files {
		if !strings.HasSuffix(file.Path, "_test.go") {
			continue
		}
		positions := token.NewFileSet()
		syntax, err := parser.ParseFile(positions, file.Path, file.Content, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		for _, declaration := range syntax.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !names[function.Name.Name] {
				continue
			}
			start, end := positions.Position(function.Pos()).Offset, positions.Position(function.End()).Offset
			if start < 0 || end > len(file.Content) || end < start || end-start > 8<<10 || total+end-start > 16<<10 {
				continue
			}
			contexts = append(contexts, testFailureContext{
				Path: file.Path, TestName: function.Name.Name, Original: file.Content[start:end],
			})
			total += end - start
			if len(contexts) == 8 {
				return contexts
			}
		}
	}
	return contexts
}
