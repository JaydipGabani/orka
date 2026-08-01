package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

func newMemoryOperationCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "operation", Short: "Inspect and manage durable memory operations"}
	cmd.AddCommand(newMemoryOperationListCmd())
	cmd.AddCommand(newMemoryOperationGetCmd())
	cmd.AddCommand(newMemoryOperationActionCmd("retry"))
	cmd.AddCommand(newMemoryOperationActionCmd("abandon"))
	return cmd
}

func newMemoryOperationListCmd() *cobra.Command {
	var state string
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List memory operations",
		RunE: func(cmd *cobra.Command, _ []string) error {
			query := map[string]string{"limit": strconv.Itoa(limit)}
			if strings.TrimSpace(state) != "" {
				query["state"] = strings.TrimSpace(state)
			}
			result, err := newClientFromCmd(cmd).DoJSON(cmd.Context(), http.MethodGet, "/api/v1/memory-operations", query, nil)
			if err != nil {
				return err
			}
			return printStructured(cmd, result)
		},
	}
	cmd.Flags().StringVar(&state, "state", "", "Filter by operation state")
	cmd.Flags().IntVar(&limit, "limit", 100, "Maximum number of operations")
	addOutputFlag(cmd, outputTable)
	return cmd
}

func newMemoryOperationGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Get a memory operation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := newClientFromCmd(cmd).DoJSON(
				cmd.Context(),
				http.MethodGet,
				"/api/v1/memory-operations/"+url.PathEscape(args[0]),
				nil,
				nil,
			)
			if err != nil {
				return err
			}
			return printStructured(cmd, result)
		},
	}
	addOutputFlag(cmd, outputJSON)
	return cmd
}

func newMemoryOperationActionCmd(action string) *cobra.Command {
	var reason string
	var yes bool
	cmd := &cobra.Command{
		Use:   action + " <id>",
		Short: titleName(action) + " a memory operation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("--reason is required")
			}
			if !yes {
				return fmt.Errorf("--yes is required for memory operation %s", action)
			}
			body, err := json.Marshal(map[string]any{"reason": strings.TrimSpace(reason)})
			if err != nil {
				return err
			}
			path := "/api/v1/memory-operations/" + url.PathEscape(args[0]) + "/" + action
			response, err := newClientFromCmd(cmd).DoJSONWithHeaders(cmd.Context(), http.MethodPost, path, nil, body, nil)
			if err != nil {
				return err
			}
			return printMemoryMutationOutcome(cmd, "Memory operation "+action, args[0], response)
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Required audit reason")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm the operation")
	return cmd
}
