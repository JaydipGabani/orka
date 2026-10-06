package icm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIncidentID(t *testing.T) {
	for _, input := range []string{"12345", "https://portal.microsofticm.com/imp/v5/incidents/details/12345/summary"} {
		id, err := IncidentID(input)
		if err != nil || id != "12345" {
			t.Fatalf("unexpected incident identity: %q, %v", id, err)
		}
	}
	for _, input := range []string{"", "0", "-1", "123;echo", "https://elsewhere.test/12345",
		"https://user:pass@portal.microsofticm.com/imp/v5/incidents/details/12345/summary",
		"https://portal.microsofticm.com/imp/v5/incidents/details/12345/summary?token=private",
		"https://portal.microsofticm.com/imp/v5/incidents/details/12345/summary#extra",
		"9999999999999999999"} {
		if _, err := IncidentID(input); err == nil {
			t.Fatalf("accepted an invalid identifier: %q", input)
		}
	}
}

func fixtureExporter(t *testing.T, mutate func(int, []string, []byte) []byte) (Exporter, *int) {
	t.Helper()
	calls := new(int)
	exporter := Exporter{run: func(_ context.Context, args []string) ([]byte, error) {
		*calls++
		var data []byte
		switch {
		case len(args) == 2 && args[0] == "api" && args[1] == "tools":
			data = []byte(`{"tools":[{"name":"get_incident_details_by_id","annotations":{"readOnlyHint":true}},{"name":"get_incident_discussion_entries_and_insights","annotations":{"readOnlyHint":true}}]}`)
		case len(args) == 4 && args[0] == "incidents" && args[1] == "get" && args[2] == "--incident-id" && args[3] == "12345":
			data = []byte(`{"id":12345,"lastModifiedDate":"2026-09-01T12:00:00Z","title":"Synthetic report"}`)
		case len(args) == 6 && args[0] == "api" && args[1] == "call" && args[3] == discussionTool:
			var request struct {
				Request struct {
					ID    int    `json:"incidentId"`
					Skip  int    `json:"skipToken"`
					Order string `json:"sortingOrder"`
				} `json:"request"`
			}
			if err := json.Unmarshal([]byte(args[5]), &request); err != nil || request.Request.ID != 12345 || request.Request.Order != "asc" {
				t.Fatal("unexpected read request")
			}
			data = []byte(fmt.Sprintf(`{"incidentId":12345,"aggregatedDiagnosticResults":{"Data":[{"Content":"Synthetic item %d"}],"HasMoreData":%t,"TotalCount":2}}`, request.Request.Skip, request.Request.Skip == 0))
		default:
			t.Fatal("unexpected or mutating IcM command")
		}
		if mutate != nil {
			data = mutate(*calls, args, data)
		}
		return data, nil
	}}
	return exporter, calls
}

func TestCaptureCompletePrivateSnapshot(t *testing.T) {
	exporter, calls := fixtureExporter(t, nil)
	directory := filepath.Join(t.TempDir(), "new-export")
	receipt, err := exporter.Capture(t.Context(), "12345", directory)
	if err != nil || receipt.State != "complete" || receipt.Entries != 2 || *calls != 5 {
		t.Fatalf("capture failed: state=%s entries=%d calls=%d error=%v", receipt.State, receipt.Entries, *calls, err)
	}
	for name, artifact := range receipt.Artifacts {
		raw, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || digest(raw) != artifact.Digest || len(raw) != artifact.Bytes {
			t.Fatalf("artifact identity mismatch: %s", name)
		}
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("artifact not private: %s", name)
		}
	}
	info, err := os.Stat(directory)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("capture directory is not private")
	}
	raw, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted Receipt
	if err := json.Unmarshal(raw, &persisted); err != nil || persisted.State != "complete" || persisted.FinishedAt.IsZero() {
		t.Fatal("final receipt is not complete")
	}
	if _, err := exporter.Capture(t.Context(), "12345", directory); err == nil || *calls != 5 {
		t.Fatal("an existing snapshot was overwritten")
	}
}

func TestCaptureRejectsIncompleteAndChangedEvidence(t *testing.T) {
	for _, scenario := range []string{"changed", "wrong-id", "wrong-tool", "duplicate", "total-change", "missing-hasmore", "error"} {
		t.Run(scenario, func(t *testing.T) {
			exporter, _ := fixtureExporter(t, func(call int, args []string, data []byte) []byte {
				switch scenario {
				case "changed":
					if call == 5 {
						return []byte(strings.ReplaceAll(string(data), "12:00:00Z", "13:00:00Z"))
					}
				case "wrong-id":
					if call == 3 {
						return []byte(strings.ReplaceAll(string(data), `"incidentId":12345`, `"incidentId":54321`))
					}
				case "wrong-tool":
					if call == 1 {
						return []byte(strings.ReplaceAll(string(data), `"readOnlyHint":true`, `"readOnlyHint":false`))
					}
				case "duplicate":
					return []byte(strings.ReplaceAll(string(data), "Synthetic item 1", "Synthetic item 0"))
				case "total-change":
					if call == 4 {
						return []byte(strings.ReplaceAll(string(data), `"TotalCount":2`, `"TotalCount":3`))
					}
				case "missing-hasmore":
					return []byte(strings.ReplaceAll(string(data), `"HasMoreData":true,`, ""))
				case "error":
					return []byte(`{"error":"private details must not escape"}`)
				}
				return data
			})
			dir := filepath.Join(t.TempDir(), "snapshot")
			receipt, err := exporter.Capture(t.Context(), "12345", dir)
			if err == nil || receipt.State != "incomplete" || strings.Contains(err.Error(), "private details") {
				t.Fatalf("invalid capture accepted or leaked error: state=%s, error=%v", receipt.State, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "input.json")); !os.IsNotExist(err) {
				t.Fatal("invalid capture produced a success-shaped input bundle")
			}
			if _, err := os.Stat(filepath.Join(dir, "receipt.json")); err != nil {
				t.Fatal("failed capture was not retained")
			}
		})
	}
}

func TestCaptureCancellationAndSymlinkParent(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "alias")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	exporter, calls := fixtureExporter(t, nil)
	if _, err := exporter.Capture(t.Context(), "12345", filepath.Join(link, "export")); err == nil || *calls != 0 {
		t.Fatal("symlinked capture directory was accepted")
	}
	exporter.run = func(ctx context.Context, _ []string) ([]byte, error) {
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	receipt, err := exporter.Capture(ctx, "12345", filepath.Join(root, "cancelled"))
	if !errors.Is(err, ErrCapture) || receipt.State != "incomplete" {
		t.Fatalf("cancellation was not retained as incomplete: %v", err)
	}
}
