package buildjob

import (
	"bytes"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxDiagnosticLineBytes = 4096

var (
	buildProgressPattern  = regexp.MustCompile(`^(#[0-9]{1,8}) [0-9]{1,8}(?:\.[0-9]{1,9})? `)
	goTestNamePattern     = regexp.MustCompile(`^Test(?:[A-Z_][a-zA-Z0-9_]{0,59})?$`)
	goTestFailurePattern  = regexp.MustCompile(`^--- FAIL: (Test[a-zA-Z0-9_]*) \(([0-9]{1,8}(?:\.[0-9]{1,9})?s)\)$`)
	goTestTimeoutPattern  = regexp.MustCompile(`^panic: test timed out after ([0-9hms.]{1,32})$`)
	goRunningTestPattern  = regexp.MustCompile(`^(Test[a-zA-Z0-9_]*) \(([0-9hms.]{1,32})\)$`)
	goTestLocationPattern = regexp.MustCompile(
		`^([a-zA-Z0-9_./+-]{1,512}):([1-9][0-9]{0,7})(?::(?: .*)?|(?: \+0x[0-9a-fA-F]{1,16})?)$`)
	credentialNamePattern = regexp.MustCompile(`(?i)(secret|token|password|passwd|credential|bearer|authorization|api_?key|private_?key|gh[pousr]_|github_pat_)`)
)

// SafeTestName accepts only short top-level identifiers, never dynamic subtest
// labels. It does not attest that a test exists or authorize source disclosure.
func SafeTestName(name string) bool {
	return goTestNamePattern.MatchString(name) && !credentialNamePattern.MatchString(name) &&
		!secretPattern.MatchString(name)
}

func safeDiagnosticPath(name string) bool {
	if SourcePath(name) != nil || secretPattern.MatchString(name) {
		return false
	}
	for part := range strings.SplitSeq(name, "/") {
		switch strings.ToLower(part) {
		case "secret", "secrets", "credential", "password", "passwd", "tokens":
			return false
		}
	}
	return true
}

type capturedDiagnostics struct {
	compiler    []Diagnostic
	tests       []Diagnostic
	testFailure bool
	truncated   bool
}

// diagnosticCapture retains bounded metadata independently of the log tail.
// An oversized line is discarded in full, including across Write boundaries.
type diagnosticCapture struct {
	mu        sync.Mutex
	paths     map[string]bool
	basenames map[string]string
	line      []byte
	dropping  bool
	capturedDiagnostics
	stream       string
	testName     string
	testBlock    bool
	timeout      bool
	runningTests bool
}

func newDiagnosticCapture(paths map[string]bool) *diagnosticCapture {
	c := &diagnosticCapture{
		paths: make(map[string]bool), basenames: make(map[string]string),
		line: make([]byte, 0, maxDiagnosticLineBytes),
	}
	for name, allowed := range paths {
		if !allowed || !safeDiagnosticPath(name) {
			continue
		}
		c.paths[name] = true
		if strings.HasSuffix(name, ".go") {
			base := path.Base(name)
			if _, exists := c.basenames[base]; exists {
				c.basenames[base] = ""
			} else {
				c.basenames[base] = name
			}
		}
	}
	return c
}

func (c *diagnosticCapture) Write(body []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	size := len(body)
	for len(body) > 0 {
		end := bytes.IndexByte(body, '\n')
		part := body
		if end >= 0 {
			part = body[:end]
		}
		if !c.dropping {
			if len(c.line)+len(part) > maxDiagnosticLineBytes {
				c.dropping, c.truncated = true, true
				c.line = c.line[:0]
				c.clearContext()
			} else {
				c.line = append(c.line, part...)
			}
		}
		if end < 0 {
			break
		}
		if !c.dropping {
			c.consume(c.line)
		}
		c.line, c.dropping = c.line[:0], false
		body = body[end+1:]
	}
	return size, nil
}

func (c *diagnosticCapture) snapshot() capturedDiagnostics {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dropping && len(c.line) > 0 {
		c.consume(c.line)
		c.line = c.line[:0]
	}
	return capturedDiagnostics{
		compiler: slices.Clone(c.compiler), tests: slices.Clone(c.tests),
		testFailure: c.testFailure, truncated: c.truncated,
	}
}

func (c *diagnosticCapture) clearContext() {
	c.testName, c.testBlock, c.timeout, c.runningTests = "", false, false, false
}

func (c *diagnosticCapture) consume(body []byte) {
	line := strings.TrimSuffix(string(body), "\r")
	if strings.ContainsFunc(line, func(r rune) bool { return (r < ' ' && r != '\t') || r == 127 }) ||
		secretPattern.MatchString(line) {
		c.clearContext()
		return
	}
	for _, diagnostic := range compilerDiagnostics(body, c.paths) {
		c.add(&c.compiler, diagnostic)
	}
	stream := ""
	if prefix := buildProgressPattern.FindStringSubmatch(line); prefix != nil {
		stream, line = prefix[1], line[len(prefix[0]):]
	}
	if stream != c.stream {
		c.clearContext()
		c.stream = strings.Clone(stream)
	}
	line = strings.TrimLeft(line, " \t")
	if match := goTestFailurePattern.FindStringSubmatch(line); match != nil &&
		goTestNamePattern.MatchString(match[1]) {
		c.clearContext()
		c.testFailure, c.testBlock = true, true
		if SafeTestName(match[1]) {
			c.testName = strings.Clone(match[1])
			c.add(&c.tests, Diagnostic{TestName: c.testName})
		}
		return
	}
	if match := goTestTimeoutPattern.FindStringSubmatch(line); match != nil && positiveDuration(match[1]) {
		c.clearContext()
		c.testFailure, c.timeout = true, true
		return
	}
	if c.timeout && line == "running tests:" {
		c.runningTests = true
		return
	}
	if c.runningTests {
		if match := goRunningTestPattern.FindStringSubmatch(line); match != nil {
			elapsed, err := time.ParseDuration(match[2])
			if err == nil && elapsed >= 0 && SafeTestName(match[1]) {
				c.add(&c.tests, Diagnostic{TestName: strings.Clone(match[1])})
			}
			return
		}
		c.runningTests = false
	}
	if c.testBlock || c.timeout {
		if match := goTestLocationPattern.FindStringSubmatch(line); match != nil {
			name := c.goPath(match[1])
			lineNumber, _ := strconv.Atoi(match[2])
			if name != "" && lineNumber >= 1 && lineNumber <= 10000000 {
				c.add(&c.tests, Diagnostic{Path: name, Line: lineNumber, TestName: c.testName})
			}
			return
		}
	}
	if !c.timeout {
		c.clearContext()
	}
}

func positiveDuration(raw string) bool {
	value, err := time.ParseDuration(raw)
	return err == nil && value > 0
}

func (c *diagnosticCapture) goPath(raw string) string {
	if !strings.HasSuffix(raw, ".go") {
		return ""
	}
	// Only Dalec's fixed build root is recognized. The package component is
	// discarded only after validation; the remaining path must match exactly.
	if relative, ok := strings.CutPrefix(raw, "/build/top/BUILD/"); ok {
		pkg, name, found := strings.Cut(relative, "/")
		if found && safeDiagnosticPath(pkg) && safeDiagnosticPath(name) && c.paths[name] {
			return strings.Clone(name)
		}
		return ""
	}
	name := strings.TrimPrefix(raw, "./")
	if !safeDiagnosticPath(name) {
		return ""
	}
	if !strings.Contains(name, "/") {
		return c.basenames[name]
	}
	if c.paths[name] {
		return strings.Clone(name)
	}
	return ""
}

func (c *diagnosticCapture) add(target *[]Diagnostic, item Diagnostic) {
	for i, existing := range *target {
		if existing == item {
			return
		}
		if item.Path == "" && item.TestName != "" && existing.TestName == item.TestName {
			return
		}
		if item.Path != "" && item.TestName != "" && existing.Path == "" && existing.TestName == item.TestName {
			(*target)[i] = item
			return
		}
	}
	if len(*target) >= MaxDiagnostics {
		c.truncated = true
		return
	}
	*target = append(*target, item)
}
