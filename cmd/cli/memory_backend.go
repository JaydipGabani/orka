package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"
)

const memoryBackendStatusCommand = "status"

func newMemoryBackendCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "backend", Short: "Manage the namespace memory backend"}
	cmd.AddCommand(newMemoryBackendListCmd())
	cmd.AddCommand(newMemoryBackendGetCmd(false))
	cmd.AddCommand(newMemoryBackendGetCmd(true))
	cmd.AddCommand(newMemoryBackendCreateCmd())
	cmd.AddCommand(newMemoryBackendUpdateCmd())
	cmd.AddCommand(newMemoryBackendDeleteCmd())
	cmd.AddCommand(newMemoryBackendCheckpointCmd())
	for _, action := range []string{"activate", "decommission", "force-orphan", "restore-legacy"} {
		cmd.AddCommand(newMemoryBackendActionCmd(action))
	}
	return cmd
}

func newMemoryBackendCheckpointCmd() *cobra.Command {
	var manifestDigest, reason string
	var maximumOperationSequence int64
	var yes bool
	cmd := &cobra.Command{
		Use:   "checkpoint",
		Short: "Record a matched activation recovery receipt or runtime checkpoint",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(manifestDigest) == "" {
				return fmt.Errorf("--manifest-digest is required")
			}
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("--reason is required")
			}
			if !yes {
				return fmt.Errorf("--yes is required for memory backend checkpoint")
			}
			if maximumOperationSequence < 0 {
				return fmt.Errorf("--max-sequence cannot be negative")
			}
			body, err := json.Marshal(map[string]any{
				"manifestDigest":           strings.TrimSpace(manifestDigest),
				"maximumOperationSequence": maximumOperationSequence,
				"reason":                   strings.TrimSpace(reason),
			})
			if err != nil {
				return err
			}
			result, err := newClientFromCmd(cmd).DoJSON(
				cmd.Context(), http.MethodPost, "/api/v1/memory-backends/default/checkpoints", nil, body,
			)
			if err != nil {
				return err
			}
			return printStructured(cmd, result)
		},
	}
	cmd.Flags().StringVar(&manifestDigest, "manifest-digest", "", "SHA-256 digest of the matched recovery manifest")
	cmd.Flags().Int64Var(
		&maximumOperationSequence,
		"max-sequence",
		0,
		"Maximum committed operation sequence covered by the checkpoint",
	)
	cmd.Flags().StringVar(&reason, "reason", "", "Required audit reason")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm the checkpoint receipt")
	addOutputFlag(cmd, outputJSON)
	return cmd
}

func newMemoryBackendListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List memory backends",
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := newClientFromCmd(cmd).DoJSON(cmd.Context(), http.MethodGet, "/api/v1/memory-backends", nil, nil)
			if err != nil {
				return err
			}
			return printStructured(cmd, result)
		},
	}
	addOutputFlag(cmd, outputTable)
	return cmd
}

func newMemoryBackendGetCmd(status bool) *cobra.Command {
	use := "get"
	short := "Get the memory backend"
	path := "/api/v1/memory-backends/default"
	if status {
		use = memoryBackendStatusCommand
		short = "Get effective memory backend status"
		path += "/status"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := newClientFromCmd(cmd).DoJSON(cmd.Context(), http.MethodGet, path, nil, nil)
			if err != nil {
				return err
			}
			return printStructured(cmd, result)
		},
	}
	addOutputFlag(cmd, outputJSON)
	return cmd
}

func newMemoryBackendCreateCmd() *cobra.Command {
	var file, endpoint, secretName, secretKey, storeName, reason string
	var yes bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a staged memory backend",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("--reason is required")
			}
			if !yes {
				return fmt.Errorf("--yes is required for memory backend creation")
			}
			client := newClientFromCmd(cmd)
			var body []byte
			var err error
			if file != "" {
				body, err = manifestWithNamespaceJSON(cmd, file, client.Namespace)
			} else {
				if strings.TrimSpace(endpoint) == "" || strings.TrimSpace(secretName) == "" || strings.TrimSpace(storeName) == "" {
					return fmt.Errorf("--file or --endpoint, --secret, and --store are required")
				}
				body, err = json.Marshal(map[string]any{
					"apiVersion": "core.orka.ai/v1alpha1",
					"kind":       "MemoryBackend",
					"metadata": map[string]any{
						"name":      "default",
						"namespace": client.Namespace,
					},
					"spec": map[string]any{
						"protocol":       map[string]any{"omsVersion": "0.1", "profile": "orka.oms.v0alpha1"},
						"deployment":     map[string]any{"mode": "external-endpoint", "endpoint": endpoint},
						"clientAuth":     map[string]any{"bearerTokenSecretRef": map[string]any{"name": secretName, "key": secretKey}},
						"store":          map[string]any{"name": storeName},
						"lifecycleState": "Staged",
					},
				})
			}
			if err != nil {
				return err
			}
			result, err := client.DoJSON(
				cmd.Context(),
				http.MethodPost,
				"/api/v1/memory-backends",
				map[string]string{"reason": strings.TrimSpace(reason)},
				body,
			)
			if err != nil {
				return err
			}
			return printStructured(cmd, result)
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to MemoryBackend JSON/YAML")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "External HTTPS OMS adapter endpoint")
	cmd.Flags().StringVar(&secretName, "secret", "", "Bearer token Secret name")
	cmd.Flags().StringVar(&secretKey, "secret-key", "token", "Bearer token Secret key")
	cmd.Flags().StringVar(&storeName, "store", "", "Pre-created provider store name")
	cmd.Flags().StringVar(&reason, "reason", "", "Required audit reason")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm backend creation")
	addOutputFlag(cmd, outputJSON)
	return cmd
}

func newMemoryBackendUpdateCmd() *cobra.Command {
	var file, reason string
	var yes bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the requested memory backend lifecycle or endpoint configuration",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(file) == "" {
				return fmt.Errorf("--file is required")
			}
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("--reason is required")
			}
			if !yes {
				return fmt.Errorf("--yes is required for memory backend update")
			}
			client := newClientFromCmd(cmd)
			body, err := manifestWithNamespaceJSON(cmd, file, client.Namespace)
			if err != nil {
				return err
			}
			result, err := client.DoJSON(
				cmd.Context(),
				http.MethodPut,
				"/api/v1/memory-backends/default",
				map[string]string{"reason": strings.TrimSpace(reason)},
				body,
			)
			if err != nil {
				return err
			}
			return printStructured(cmd, result)
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to MemoryBackend JSON/YAML")
	cmd.Flags().StringVar(&reason, "reason", "", "Required audit reason")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm backend update")
	addOutputFlag(cmd, outputJSON)
	return cmd
}

func newMemoryBackendDeleteCmd() *cobra.Command {
	var reason string
	var yes bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a decommissioned or never-activated memory backend",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("--reason is required")
			}
			if !yes {
				return fmt.Errorf("--yes is required for memory backend deletion")
			}
			body, _ := json.Marshal(map[string]string{"reason": strings.TrimSpace(reason)})
			_, err := newClientFromCmd(cmd).DoJSON(
				cmd.Context(),
				http.MethodDelete,
				"/api/v1/memory-backends/default",
				nil,
				body,
			)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "Memory backend deletion requested: default")
			return err
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Required audit reason")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm deletion")
	return cmd
}

func newMemoryBackendActionCmd(action string) *cobra.Command {
	var reason string
	var yes, dryRun bool
	cmd := &cobra.Command{
		Use:   action,
		Short: titleName(action) + " the namespace memory backend",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("--reason is required")
			}
			if !dryRun && !yes {
				return fmt.Errorf("--yes is required for memory backend %s", action)
			}
			body, err := json.Marshal(map[string]any{"reason": strings.TrimSpace(reason), "dryRun": dryRun})
			if err != nil {
				return err
			}
			path := "/api/v1/memory-backends/default/" + action
			result, err := newClientFromCmd(cmd).DoJSON(cmd.Context(), http.MethodPost, path, nil, body)
			if err != nil {
				return err
			}
			return printStructured(cmd, result)
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "Required audit reason")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm the operation")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview the operation without changing state")
	addOutputFlag(cmd, outputJSON)
	return cmd
}
