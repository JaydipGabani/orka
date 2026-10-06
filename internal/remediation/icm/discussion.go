package icm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

func captureDiscussion(id string, startedAt time.Time, capture func(string, ...string) ([]byte, error)) ([]json.RawMessage, int, error) {
	var entries []json.RawMessage
	total := -1
	for page := range maxPages {
		args := struct {
			Request struct {
				IncidentID   json.Number `json:"incidentId"`
				Skip         int         `json:"skipToken"`
				Top          int         `json:"top"`
				SortingOrder string      `json:"sortingOrder"`
				EndDate      time.Time   `json:"endDate"`
			} `json:"request"`
		}{}
		args.Request.IncidentID, args.Request.Skip, args.Request.Top = json.Number(id), len(entries), pageSize
		args.Request.SortingOrder, args.Request.EndDate = "asc", startedAt
		argBytes, err := json.Marshal(args)
		if err != nil {
			return nil, 0, err
		}
		raw, err := capture(fmt.Sprintf("discussion-%04d.json", page+1),
			"api", "call", "--tool", discussionTool, "--args", string(argBytes))
		if err != nil {
			return nil, 0, err
		}
		var response struct {
			IncidentID json.Number `json:"incidentId"`
			Results    struct {
				Data    []json.RawMessage `json:"Data"`
				HasMore *bool             `json:"HasMoreData"`
				Total   *int              `json:"TotalCount"`
			} `json:"aggregatedDiagnosticResults"`
		}
		if json.Unmarshal(raw, &response) != nil || response.IncidentID.String() != id ||
			response.Results.HasMore == nil || response.Results.Total == nil ||
			*response.Results.Total < 0 || *response.Results.Total > maxPages*pageSize ||
			(total >= 0 && total != *response.Results.Total) {
			return nil, 0, ErrCapture
		}
		total = *response.Results.Total
		if len(response.Results.Data) > pageSize || (*response.Results.HasMore && len(response.Results.Data) == 0) {
			return nil, 0, ErrCapture
		}
		for _, entry := range response.Results.Data {
			for _, previous := range entries {
				if bytes.Equal(bytes.TrimSpace(previous), bytes.TrimSpace(entry)) {
					return nil, 0, ErrCapture
				}
			}
			entries = append(entries, entry)
		}
		if len(entries) > total {
			return nil, 0, ErrCapture
		}
		if !*response.Results.HasMore {
			if len(entries) != total {
				return nil, 0, ErrCapture
			}
			return entries, total, nil
		}
	}
	return nil, 0, ErrCapture
}
