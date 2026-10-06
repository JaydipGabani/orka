package icm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	maxResponseBytes = 16 << 20
	maxPages         = 10
	pageSize         = 100
	endpoint         = "https://icm-mcp-prod.azure-api.net/v1/"
	detailsTool      = "get_incident_details_by_id"
	discussionTool   = "get_incident_discussion_entries_and_insights"
)

var (
	ErrCapture = errors.New("IcM capture failed; inspect the private receipt")
	ErrChanged = errors.New("IcM changed during capture; create a new snapshot")
	idPattern  = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
)

type Exporter struct {
	Binary string
	Auth   string
	Tenant string
	run    func(context.Context, []string) ([]byte, error)
}

type Artifact struct {
	Digest string `json:"digest"`
	Bytes  int    `json:"bytes"`
}

type Receipt struct {
	Version    int                 `json:"version"`
	IncidentID string              `json:"incidentID"`
	StartedAt  time.Time           `json:"startedAt"`
	FinishedAt time.Time           `json:"finishedAt"`
	State      string              `json:"state"`
	Entries    int                 `json:"entries"`
	Artifacts  map[string]Artifact `json:"artifacts"`
}

func IncidentID(input string) (string, error) {
	if idPattern.MatchString(input) {
		if _, err := strconv.ParseInt(input, 10, 64); err == nil {
			return input, nil
		}
	}
	u, err := url.Parse(input)
	if err != nil || u.Scheme != "https" || u.Host != "portal.microsofticm.com" ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return "", errors.New("expected an IcM incident ID or canonical HTTPS incident URL")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 6 || strings.Join(parts[:4], "/") != "imp/v5/incidents/details" ||
		parts[5] != "summary" || !idPattern.MatchString(parts[4]) {
		return "", errors.New("expected an IcM incident ID or canonical HTTPS incident URL")
	}
	if _, err := strconv.ParseInt(parts[4], 10, 64); err != nil {
		return "", errors.New("IcM incident ID exceeds its supported range")
	}
	return parts[4], nil
}

func digest(raw []byte) string {
	value := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(value[:])
}

// Capture creates a new immutable export directory. Failed captures retain their
// raw responses and an incomplete receipt, never a success-shaped input bundle.
func (e Exporter) Capture(ctx context.Context, incident, directory string) (receipt Receipt, resultErr error) {
	id, err := IncidentID(incident)
	if err != nil {
		return receipt, err
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return receipt, errors.New("export directory must be an absolute clean path")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(directory))
	if err != nil || parent != filepath.Dir(directory) {
		return receipt, errors.New("export parent must exist without symlink aliases")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return receipt, errors.New("export directory must be new and writable")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return receipt, err
	}
	receipt = Receipt{Version: 1, IncidentID: id, StartedAt: time.Now().UTC(),
		State: "incomplete", Artifacts: make(map[string]Artifact)}
	defer func() {
		receipt.FinishedAt = time.Now().UTC()
		raw, err := json.MarshalIndent(receipt, "", "  ")
		if err == nil {
			err = writePrivate(filepath.Join(directory, "receipt.json"), append(raw, '\n'))
		}
		resultErr = errors.Join(resultErr, err)
	}()
	operation, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	capture := func(name string, args ...string) ([]byte, error) {
		raw, err := e.invoke(operation, args)
		if len(raw) > maxResponseBytes {
			return nil, ErrCapture
		}
		if len(raw) != 0 {
			if writeErr := writePrivate(filepath.Join(directory, name), raw); writeErr != nil {
				return nil, writeErr
			}
			receipt.Artifacts[name] = Artifact{Digest: digest(raw), Bytes: len(raw)}
		}
		if err != nil {
			return nil, ErrCapture
		}
		return raw, nil
	}
	tools, err := capture("tools.json", "api", "tools")
	if err != nil || !readOnlyTools(tools) {
		return receipt, ErrCapture
	}
	before, err := capture("details.json", "incidents", "get", "--incident-id", id)
	if err != nil {
		return receipt, err
	}
	modified, err := detailsIdentity(before, id)
	if err != nil {
		return receipt, err
	}
	entries, total, err := captureDiscussion(id, receipt.StartedAt, capture)
	if err != nil {
		return receipt, err
	}
	after, err := capture("details-after.json", "incidents", "get", "--incident-id", id)
	if err != nil {
		return receipt, err
	}
	latest, err := detailsIdentity(after, id)
	if err != nil || latest != modified {
		return receipt, ErrChanged
	}
	bundle := struct {
		Details    json.RawMessage `json:"details"`
		Discussion struct {
			IncidentID json.Number `json:"incidentId"`
			Results    struct {
				Data    []json.RawMessage `json:"Data"`
				HasMore bool              `json:"HasMoreData"`
				Total   int               `json:"TotalCount"`
			} `json:"aggregatedDiagnosticResults"`
		} `json:"discussion"`
	}{Details: before}
	bundle.Discussion.IncidentID = json.Number(id)
	bundle.Discussion.Results.Data, bundle.Discussion.Results.Total = entries, total
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil || len(raw) > maxResponseBytes {
		return receipt, ErrCapture
	}
	if err := writePrivate(filepath.Join(directory, "input.json"), raw); err != nil {
		return receipt, err
	}
	receipt.Artifacts["input.json"] = Artifact{Digest: digest(raw), Bytes: len(raw)}
	receipt.State, receipt.Entries = "complete", len(entries)
	return receipt, nil
}

func readOnlyTools(raw []byte) bool {
	var inventory struct {
		Tools []struct {
			Name        string `json:"name"`
			Annotations struct {
				ReadOnly bool `json:"readOnlyHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}
	if json.Unmarshal(raw, &inventory) != nil {
		return false
	}
	found := make(map[string]bool)
	for _, tool := range inventory.Tools {
		if tool.Name == detailsTool || tool.Name == discussionTool {
			if found[tool.Name] || !tool.Annotations.ReadOnly {
				return false
			}
			found[tool.Name] = true
		}
	}
	return found[detailsTool] && found[discussionTool]
}

func detailsIdentity(raw []byte, expected string) (string, error) {
	var details struct {
		ID       json.Number `json:"id"`
		Modified string      `json:"lastModifiedDate"`
	}
	if json.Unmarshal(raw, &details) != nil || details.ID.String() != expected || details.Modified == "" {
		return "", ErrCapture
	}
	if _, err := time.Parse(time.RFC3339Nano, details.Modified); err != nil {
		return "", ErrCapture
	}
	return details.Modified, nil
}

func writePrivate(name string, raw []byte) (resultErr error) {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("private export artifact could not be created")
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	return file.Sync()
}

func (e Exporter) invoke(ctx context.Context, args []string) ([]byte, error) {
	if e.run != nil {
		return e.run(ctx, args)
	}
	binary := e.Binary
	if binary == "" {
		binary = "icm-cli"
	}
	auth := e.Auth
	if auth == "" {
		auth = "azcli"
	}
	if auth != "azcli" && auth != "env" {
		return nil, errors.New("IcM export requires explicit azcli or env authentication")
	}
	options := []string{"--auth", auth, "--url", endpoint, "--timeout", "90s", "--output", "json"}
	if e.Tenant != "" {
		options = append(options, "--tenant", e.Tenant)
	}
	operation, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	command := exec.CommandContext(operation, binary, append(options, args...)...)
	command.WaitDelay = time.Second
	var output boundedOutput
	command.Stdout, command.Stderr = &output, io.Discard
	err := command.Run()
	if err != nil {
		return output.Bytes(), ErrCapture
	}
	return output.Bytes(), nil
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > maxResponseBytes-b.Len() {
		return 0, ErrCapture
	}
	return b.Buffer.Write(data)
}
