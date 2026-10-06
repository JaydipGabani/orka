package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"

	"github.com/orka-agents/orka/internal/cli/client"
	"github.com/orka-agents/orka/internal/remediation/icm"
	"github.com/orka-agents/orka/internal/remediation/intake"
	remediationservice "github.com/orka-agents/orka/internal/remediation/service"
	"github.com/orka-agents/orka/internal/store"
)

const (
	remediationStatusLimit   = 1 << 20
	remediationRemotePath    = "/api/v1/remediations"
	remediationListOperation = "list"
	remediationLimitQuery    = "limit"
)

type remediationStartOptions struct {
	incident, input, mode, patch, policy, requestID string
	icmCLI, icmAuth                                 string
	wait                                            bool
}

type remediationCaptureHooks struct {
	cacheRoot func() (string, error)
	capture   func(context.Context, icm.Exporter, string, string) (icm.Receipt, error)
}

func newRemediationStartCmd() *cobra.Command {
	return newRemediationStartCmdWithCapture(remediationCaptureHooks{
		cacheRoot: remediationIncidentCacheRoot,
		capture: func(ctx context.Context, exporter icm.Exporter, incident, directory string) (icm.Receipt, error) {
			return exporter.Capture(ctx, incident, directory)
		},
	})
}

func newRemediationStartCmdWithCapture(hooks remediationCaptureHooks) *cobra.Command {
	var options remediationStartOptions
	command := &cobra.Command{
		Use:   "start",
		Short: "Submit one private incident or report to the server-managed remediation service",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			request, payload, err := prepareRemediationSubmission(options)
			if err != nil {
				return err
			}
			remote, err := newRemediationRemoteClient(cmd)
			if err != nil {
				return err
			}
			defer remote.api.HTTPClient.CloseIdleConnections()
			// This receipt survives a lost acknowledgement. Never retry a POST
			// automatically or replace its request ID after a transport error.
			if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "requestID=%s\n", request.RequestID); err != nil {
				return errors.New("could not write the remediation request ID")
			}
			if request.Incident != "" {
				report, err := captureRemediationIncident(cmd.Context(), hooks, options, request)
				if err != nil {
					return err
				}
				request.Incident, request.Report = "", report
				request, payload, err = encodeRemediationSubmission(request)
				if err != nil {
					return errors.New("captured incident cannot fit a valid 8 MiB submission; private capture was retained")
				}
			}
			status, err := remote.statusRequest(cmd.Context(), http.MethodPost, "", payload, http.StatusAccepted)
			if err != nil {
				return err
			}
			if status.RequestID != request.RequestID || status.Mode != request.Mode {
				return errors.New("remediation acknowledgement does not match the submission")
			}
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(status); err != nil {
				return err
			}
			if !options.wait {
				return nil
			}
			final, waitErr := remote.wait(cmd.Context(), status)
			if final.Revision != status.Revision || final.Phase != status.Phase {
				if err := json.NewEncoder(cmd.OutOrStdout()).Encode(final); err != nil {
					return err
				}
			}
			return waitErr
		},
	}
	command.Flags().StringVar(&options.incident, "incident", "", "one incident ID or URL, captured read-only using local credentials before submission")
	command.Flags().StringVar(&options.input, "input", "", "private JSON report file, at most 8 MiB")
	command.Flags().StringVar(&options.mode, "mode", string(remediationservice.Generate), "generate, validate, or verify")
	command.Flags().StringVar(&options.patch, "patch", "", "private patch file; required only for verify")
	command.Flags().StringVar(&options.policy, "policy", "", "server-configured remediation policy name")
	command.Flags().StringVar(&options.requestID, "request-id", "", "stable request ID for an identical retry; generated and printed before submission if omitted")
	command.Flags().BoolVar(&options.wait, "wait", false, "wait for a terminal or paused status; stopping the CLI does not cancel the remote run")
	command.Flags().StringVar(&options.icmCLI, "icm-cli", "icm-cli", "installed read-only IcM CLI executable")
	command.Flags().StringVar(&options.icmAuth, "icm-auth", "azcli", "existing local IcM authentication: azcli or env; never logs in automatically")
	addRemediationRemoteTokenFlag(command)
	return command
}

func prepareRemediationSubmission(options remediationStartOptions) (remediationservice.Request, []byte, error) {
	var request remediationservice.Request
	if (options.incident == "") == (options.input == "") {
		return request, nil, errors.New("exactly one of --incident or --input is required")
	}
	if options.incident != "" && options.icmAuth != "" && options.icmAuth != "azcli" && options.icmAuth != "env" {
		return request, nil, errors.New("--icm-auth must be azcli or env")
	}
	request = remediationservice.Request{
		RequestID: options.requestID, Incident: options.incident,
		Mode: remediationservice.Mode(options.mode), Policy: options.policy,
	}
	if request.Mode == "" {
		request.Mode = remediationservice.Generate
	}
	if options.input != "" {
		raw, err := readRemediationFile(options.input, remediationservice.MaxRequestBytes, true)
		if err != nil {
			return request, nil, err
		}
		request.Report = raw
	}
	if options.patch != "" {
		raw, err := readRemediationFile(options.patch, remediationservice.MaxPatchBytes, true)
		if err != nil {
			return request, nil, err
		}
		if !utf8.Valid(raw) {
			return request, nil, errors.New("patch must contain valid UTF-8 text")
		}
		request.Patch = string(raw)
	}
	if request.RequestID == "" {
		var entropy [16]byte
		if _, err := rand.Read(entropy[:]); err != nil {
			return request, nil, errors.New("could not generate a remediation request ID")
		}
		request.RequestID = "request-" + hex.EncodeToString(entropy[:])
	}
	return encodeRemediationSubmission(request)
}

func encodeRemediationSubmission(request remediationservice.Request) (remediationservice.Request, []byte, error) {
	payload, err := json.Marshal(request)
	if err != nil || len(payload) > remediationservice.MaxRequestBytes {
		return request, nil, errors.New("invalid remediation request or request exceeds 8 MiB")
	}
	request, err = remediationservice.DecodeRequest(payload)
	if err != nil {
		return request, nil, errors.New("invalid remediation request; check mode, policy, request ID, incident/report, and patch")
	}
	payload, err = json.Marshal(request)
	if err != nil || len(payload) > remediationservice.MaxRequestBytes {
		return request, nil, errors.New("invalid remediation request or request exceeds 8 MiB")
	}
	return request, payload, nil
}

type remediationCaptureIntent struct {
	Version    int    `json:"version"`
	RequestID  string `json:"requestID"`
	IncidentID string `json:"incidentID"`
}

type remediationCaptureSeal struct {
	Version       int    `json:"version"`
	ReceiptDigest string `json:"receiptDigest"`
	InputDigest   string `json:"inputDigest"`
}

func remediationIncidentCacheRoot() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil || !filepath.IsAbs(cache) || filepath.Clean(cache) != cache {
		return "", errors.New("a canonical absolute user cache directory is required for incident capture")
	}
	root := filepath.Join(cache, "orka", "remediation")
	for parent := root; ; parent = filepath.Dir(parent) {
		_, err := os.Lstat(filepath.Join(parent, ".git"))
		if err == nil || !errors.Is(err, os.ErrNotExist) || filepath.Base(parent) == ".git" {
			return "", errors.New("incident capture cache must be outside Git checkouts")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return root, nil
}

func captureRemediationIncident(ctx context.Context, hooks remediationCaptureHooks, options remediationStartOptions, request remediationservice.Request) ([]byte, error) {
	if hooks.cacheRoot == nil || hooks.capture == nil {
		return nil, errors.New("local incident capture is unavailable")
	}
	cache, err := hooks.cacheRoot()
	if err != nil {
		return nil, err
	}
	root, err := openRemediationCaptureCache(cache)
	if err != nil {
		return nil, err
	}
	defer root.Close() //nolint:errcheck
	created := true
	if err := root.Mkdir(request.RequestID, 0o700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return nil, errors.New("private incident capture directory could not be created")
		}
		created = false
	}
	run, err := openPrivateRemediationRoot(root, request.RequestID)
	if err != nil {
		return nil, err
	}
	defer run.Close() //nolint:errcheck
	intent := remediationCaptureIntent{Version: 1, RequestID: request.RequestID, IncidentID: request.Incident}
	if created {
		if err := writeRemediationCaptureJSON(run, "intent.json", intent); err != nil {
			return nil, err
		}
		exporter := icm.Exporter{Binary: options.icmCLI, Auth: options.icmAuth}
		if _, err := hooks.capture(ctx, exporter, request.Incident, filepath.Join(cache, request.RequestID, "export")); err != nil {
			return nil, errors.New("local IcM capture failed; partial capture was retained privately under the request ID")
		}
	} else {
		var saved remediationCaptureIntent
		if err := readRemediationCaptureJSON(run, "intent.json", &saved); err != nil || saved != intent {
			return nil, errors.New("request ID already has a different or invalid local incident capture")
		}
	}
	export, err := openPrivateRemediationRoot(run, "export")
	if err != nil {
		return nil, errors.New("local incident capture is incomplete; retained privately; use a new request ID for a new capture")
	}
	defer export.Close() //nolint:errcheck
	input, seal, err := verifyRemediationCapture(export, request.Incident)
	if err != nil {
		return nil, err
	}
	if _, err := run.Lstat("capture.json"); errors.Is(err, os.ErrNotExist) {
		if err := writeRemediationCaptureJSON(run, "capture.json", seal); err != nil {
			return nil, err
		}
	} else {
		var saved remediationCaptureSeal
		if err := readRemediationCaptureJSON(run, "capture.json", &saved); err != nil || saved != seal {
			return nil, errors.New("private incident capture receipt or input digest changed")
		}
	}
	return input, nil
}

func openRemediationCaptureCache(directory string) (*os.Root, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("incident capture cache path is invalid")
	}
	for parent := directory; ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil && !errors.Is(err, os.ErrNotExist) || err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
			return nil, errors.New("incident capture cache must not contain symlinks")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, errors.New("private incident capture cache could not be created")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("incident capture cache is not private")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("private incident capture cache could not be opened")
	}
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(info, current) {
		_ = root.Close()
		return nil, errors.New("incident capture cache changed while opening")
	}
	return root, nil
}

func openPrivateRemediationRoot(parent *os.Root, name string) (*os.Root, error) {
	info, err := parent.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private incident capture directory is unavailable")
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, errors.New("private incident capture directory could not be opened")
	}
	current, err := root.Stat(".")
	if err != nil || !os.SameFile(info, current) {
		_ = root.Close()
		return nil, errors.New("private incident capture directory changed while opening")
	}
	return root, nil
}

func readRemediationCaptureFile(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > limit {
		return nil, errors.New("private incident capture artifact is unavailable or exceeds its limit")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errors.New("private incident capture artifact could not be opened")
	}
	defer file.Close() //nolint:errcheck
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) {
		return nil, errors.New("private incident capture artifact changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("private incident capture artifact could not be read within its limit")
	}
	return raw, nil
}

func readRemediationCaptureJSON(root *os.Root, name string, value any) error {
	raw, err := readRemediationCaptureFile(root, name, 64<<10)
	if err != nil {
		return err
	}
	return decodeRemediationCaptureJSON(raw, value)
}

func decodeRemediationCaptureJSON(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid private incident capture metadata")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("invalid private incident capture metadata")
	}
	return nil
}

func writeRemediationCaptureJSON(root *os.Root, name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return errors.New("private incident capture metadata could not be encoded")
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("private incident capture metadata already exists or could not be created")
	}
	_, writeErr := file.Write(append(raw, '\n'))
	syncErr, closeErr := file.Sync(), file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("private incident capture metadata could not be persisted")
	}
	return nil
}

func verifyRemediationCapture(root *os.Root, incident string) ([]byte, remediationCaptureSeal, error) {
	var seal remediationCaptureSeal
	receiptBytes, err := readRemediationCaptureFile(root, "receipt.json", 64<<10)
	if err != nil {
		return nil, seal, err
	}
	var receipt icm.Receipt
	if decodeRemediationCaptureJSON(receiptBytes, &receipt) != nil || receipt.Version != 1 ||
		receipt.State != "complete" || receipt.IncidentID != incident ||
		receipt.StartedAt.IsZero() || receipt.FinishedAt.Before(receipt.StartedAt) ||
		receipt.Entries < 0 || receipt.Entries > 1000 || len(receipt.Artifacts) > 14 {
		return nil, seal, errors.New("local incident capture is incomplete or invalid; private snapshot was retained")
	}
	for _, required := range []string{"tools.json", "details.json", "details-after.json", "discussion-0001.json", "input.json"} {
		if _, ok := receipt.Artifacts[required]; !ok {
			return nil, seal, errors.New("private incident capture is missing required evidence")
		}
	}
	var input []byte
	for name, artifact := range receipt.Artifacts {
		if !remediationRemoteArtifactName(name) || filepath.Ext(name) != ".json" ||
			artifact.Bytes < 1 || artifact.Bytes > 16<<20 || !remediationRemoteDigest(artifact.Digest) {
			return nil, seal, errors.New("private incident capture contains invalid artifact metadata")
		}
		raw, err := readRemediationCaptureFile(root, name, 16<<20)
		if err != nil || len(raw) != artifact.Bytes || remediationservice.Digest(raw) != artifact.Digest {
			return nil, seal, errors.New("private incident capture artifact failed its size or SHA-256 integrity check")
		}
		if name == "input.json" {
			input = raw
		}
	}
	if len(input) > remediationservice.MaxRequestBytes {
		return nil, seal, errors.New("captured incident exceeds the 8 MiB submission limit; private snapshot was retained")
	}
	report, err := intake.Parse(input)
	if err != nil || report.SourceKind != "icm-export-bundle" || report.SourceID != incident {
		return nil, seal, errors.New("private incident capture does not contain a valid matching report")
	}
	seal = remediationCaptureSeal{
		Version: 1, ReceiptDigest: remediationservice.Digest(receiptBytes), InputDigest: remediationservice.Digest(input),
	}
	return input, seal, nil
}

func newRemediationApproveCmd() *cobra.Command {
	var digest string
	command := &cobra.Command{
		Use:   "approve RUN_ID",
		Short: "Approve the exact pending server-generated plan",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !strings.HasPrefix(digest, "sha256:") {
				digest = "sha256:" + digest
			}
			if !remediationRemoteDigest(digest) {
				return errors.New("--plan-digest must be a SHA-256 digest")
			}
			body, err := json.Marshal(struct {
				PlanDigest string `json:"planDigest"`
			}{digest})
			if err != nil {
				return err
			}
			return remediationRemoteAction(cmd, args[0], "/approve", body)
		},
	}
	command.Flags().StringVar(&digest, "plan-digest", "", "exact pending sha256:hex digest (or 64 lowercase hex characters)")
	addRemediationRemoteTokenFlag(command)
	return command
}

func newRemediationCancelCmd() *cobra.Command {
	command := &cobra.Command{
		Use:   "cancel RUN_ID",
		Short: "Request durable cancellation without deleting the remote run or its evidence",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return remediationRemoteAction(cmd, args[0], "/cancel", nil)
		},
	}
	addRemediationRemoteTokenFlag(command)
	return command
}

func newRemediationOperatorCommands() []*cobra.Command {
	return []*cobra.Command{newRemediationListCmd(), newRemediationDrainCmd(), newRemediationReconcileCmd()}
}

func newRemediationListCmd() *cobra.Command {
	var limit int
	var continuation string
	command := &cobra.Command{
		Use: remediationListOperation, Short: "List one bounded page of remediation metadata without private inputs or artifacts", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 1 || limit > store.RemediationMaxListLimit ||
				(continuation != "" && !remediationRemoteID(continuation)) {
				return errors.New("list requires a limit from 1 to 100 and a valid continuation run ID")
			}
			remote, err := newRemediationRemoteClient(cmd)
			if err != nil {
				return err
			}
			defer remote.api.HTTPClient.CloseIdleConnections()
			query := url.Values{remediationLimitQuery: {strconv.Itoa(limit)}}
			if continuation != "" {
				query.Set("continue", continuation)
			}
			raw, _, err := remote.request(cmd.Context(), http.MethodGet, "?"+query.Encode(), nil, remediationStatusLimit, http.StatusOK)
			if err != nil {
				return err
			}
			var page remediationservice.RunList
			if decodeRemediationRemoteMetadata(raw, &page) != nil || len(page.Items) > limit ||
				(page.Continue != "" && (len(page.Items) == 0 || page.Continue != page.Items[len(page.Items)-1].ID)) {
				return errors.New("invalid remediation list response")
			}
			seen := make(map[string]bool)
			for _, run := range page.Items {
				if !remediationRemoteID(run.ID) || run.Namespace != remote.api.Namespace || run.Revision == 0 || seen[run.ID] ||
					!remediationKnownPhase(run.Phase) || (run.Mode != string(remediationservice.Generate) && run.Mode != string(remediationservice.Validate) && run.Mode != string(remediationservice.Verify)) {
					return errors.New("invalid remediation list identity or state")
				}
				seen[run.ID] = true
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(page)
		},
	}
	command.Flags().IntVar(&limit, remediationLimitQuery, store.RemediationMaxListLimit, "maximum metadata rows to return, from 1 to 100")
	command.Flags().StringVar(&continuation, "continue", "", "continue after the run ID returned in the preceding page")
	addRemediationRemoteTokenFlag(command)
	return command
}

func newRemediationDrainCmd() *cobra.Command {
	command := &cobra.Command{
		Use: "drain", Short: "Read full-namespace cleanup and intake-retention counts; does not cancel work", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			remote, err := newRemediationRemoteClient(cmd)
			if err != nil {
				return err
			}
			defer remote.api.HTTPClient.CloseIdleConnections()
			raw, _, err := remote.request(cmd.Context(), http.MethodGet, "/drain", nil, remediationStatusLimit, http.StatusOK)
			if err != nil {
				return err
			}
			var status remediationservice.DrainStatus
			if decodeRemediationRemoteMetadata(raw, &status) != nil || status.Namespace != remote.api.Namespace ||
				status.Active < 0 || status.Quarantined < 0 || status.RetainedIntakes < 0 ||
				status.Complete != (status.Active == 0 && status.Quarantined == 0) || status.IntakeDrained != (status.RetainedIntakes == 0) {
				return errors.New("invalid remediation drain response")
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(status)
		},
	}
	addRemediationRemoteTokenFlag(command)
	return command
}

func newRemediationReconcileCmd() *cobra.Command {
	var revision uint64
	command := &cobra.Command{
		Use: "reconcile RUN_ID", Short: "Audit and re-drive only quarantined cleanup at an exact observed revision", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !remediationRemoteID(args[0]) || revision == 0 || revision >= math.MaxInt64 {
				return errors.New("cleanup reconciliation requires a valid run ID and positive --revision")
			}
			remote, err := newRemediationRemoteClient(cmd)
			if err != nil {
				return err
			}
			defer remote.api.HTTPClient.CloseIdleConnections()
			body, err := json.Marshal(struct {
				ExpectedRevision uint64 `json:"expectedRevision"`
			}{revision})
			if err != nil {
				return errors.New("could not encode cleanup reconciliation")
			}
			status, err := remote.statusRequest(cmd.Context(), http.MethodPost, "/"+args[0]+"/reconcile", body, http.StatusAccepted)
			if err != nil {
				return err
			}
			if status.ID != args[0] || status.Revision <= revision || status.Phase != store.RemediationPhaseCancelling ||
				status.Reason == store.RemediationReasonCleanupQuarantined {
				return errors.New("cleanup reconciliation response does not match the requested action")
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(status)
		},
	}
	command.Flags().Uint64Var(&revision, "revision", 0, "exact current run revision; stale actions fail without changing work")
	addRemediationRemoteTokenFlag(command)
	return command
}

func decodeRemediationRemoteMetadata(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid remediation metadata")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("invalid remediation metadata")
	}
	return nil
}

func remediationRemoteAction(cmd *cobra.Command, id, action string, body []byte) error {
	if !remediationRemoteID(id) {
		return errors.New("invalid remediation run ID")
	}
	remote, err := newRemediationRemoteClient(cmd)
	if err != nil {
		return err
	}
	defer remote.api.HTTPClient.CloseIdleConnections()
	status, err := remote.statusRequest(cmd.Context(), http.MethodPost, "/"+id+action, body, http.StatusAccepted)
	if err != nil {
		return err
	}
	if status.ID != id {
		return errors.New("remediation response does not match the requested run")
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(status)
}

func remediationRemoteStatus(cmd *cobra.Command, id string) error {
	remote, err := newRemediationRemoteClient(cmd)
	if err != nil {
		return err
	}
	defer remote.api.HTTPClient.CloseIdleConnections()
	status, err := remote.get(cmd.Context(), id)
	if err != nil {
		return err
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(status)
}

func addRemediationRemoteTokenFlag(command *cobra.Command) {
	command.Flags().String("token-file", "", "private bearer-token file; values are never printed")
}

type remediationRemoteClient struct {
	api *client.Client
}

func newRemediationRemoteClient(cmd *cobra.Command) (*remediationRemoteClient, error) {
	filename, _ := cmd.Flags().GetString("token-file")
	var bearer []byte
	if filename != "" {
		var err error
		bearer, err = readRemediationFile(filename, 16<<10, true)
		if err != nil {
			return nil, errors.New("authentication file is unavailable, not private, or exceeds its size limit")
		}
		if len(bytes.TrimSpace(bearer)) == 0 {
			return nil, errors.New("authentication file is empty")
		}
	}
	api := newClientFromCmd(cmd)
	if filename != "" {
		api.Token = strings.TrimSpace(string(bearer))
	}
	base, err := url.Parse(api.BaseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" ||
		base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("invalid remediation server URL")
	}
	if len(kubevalidation.IsDNS1123Label(api.Namespace)) != 0 {
		return nil, errors.New("invalid remediation namespace")
	}
	for _, credential := range []string{api.Token, api.TxnToken} {
		if len(credential) > 16<<10 || strings.ContainsAny(credential, "\r\n") {
			return nil, errors.New("invalid remediation authentication material")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.ResponseHeaderTimeout = 30 * time.Second
	api.HTTPClient = &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &remediationRemoteClient{api: api}, nil
}

func (r *remediationRemoteClient) get(ctx context.Context, id string) (remediationservice.Status, error) {
	if !remediationRemoteID(id) {
		return remediationservice.Status{}, errors.New("invalid remediation run ID")
	}
	status, err := r.statusRequest(ctx, http.MethodGet, "/"+id, nil, http.StatusOK)
	if err == nil && status.ID != id {
		err = errors.New("remediation response does not match the requested run")
	}
	return status, err
}

func (r *remediationRemoteClient) statusRequest(ctx context.Context, method, path string, body []byte, code int) (remediationservice.Status, error) {
	var status remediationservice.Status
	raw, _, err := r.request(ctx, method, path, body, remediationStatusLimit, code)
	if err != nil {
		return status, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		return status, errors.New("invalid remediation status response")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return status, errors.New("invalid remediation status response")
	}
	if !remediationRemoteID(status.ID) || status.Namespace != r.api.Namespace ||
		!remediationRemoteID(status.RequestID) || status.Revision == 0 ||
		(status.Mode != remediationservice.Generate && status.Mode != remediationservice.Validate && status.Mode != remediationservice.Verify) ||
		!remediationKnownPhase(status.Phase) || len(status.Artifacts) > store.RemediationMaxArtifacts {
		return status, errors.New("invalid remediation status identity or state")
	}
	if status.Phase != store.RemediationPhaseSucceeded {
		visible := status.Artifacts[:0]
		for _, artifact := range status.Artifacts {
			if !remediationservice.IsFinalResultArtifact(artifact.Name) {
				visible = append(visible, artifact)
			}
		}
		status.Artifacts = visible
	}
	return status, nil
}

func (r *remediationRemoteClient) request(ctx context.Context, method, path string, body []byte, limit int64, wantCode int) ([]byte, http.Header, error) {
	target, err := url.Parse(strings.TrimRight(r.api.BaseURL, "/") + remediationRemotePath + path)
	if err != nil {
		return nil, nil, errors.New("invalid remediation server URL")
	}
	query := target.Query()
	query.Set("namespace", r.api.Namespace)
	target.RawQuery = query.Encode()
	attempts := 1
	if method == http.MethodGet {
		attempts = 3
	}
	for attempt := range attempts {
		if attempt != 0 {
			if err := remediationPause(ctx, time.Duration(attempt)*100*time.Millisecond); err != nil {
				return nil, nil, err
			}
		}
		raw, header, retry, err := r.requestOnce(ctx, method, target.String(), body, limit, wantCode)
		if err == nil || !retry || attempt+1 == attempts {
			return raw, header, err
		}
	}
	return nil, nil, errors.New("remediation request failed")
}

func (r *remediationRemoteClient) requestOnce(ctx context.Context, method, target string, body []byte, limit int64, wantCode int) ([]byte, http.Header, bool, error) {
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, nil, false, errors.New("could not construct remediation request")
	}
	request.Header.Set("Accept", "application/json, application/octet-stream")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if r.api.Token != "" {
		request.Header.Set("Authorization", "Bearer "+r.api.Token)
	}
	if r.api.TxnToken != "" {
		request.Header.Set("Txn-Token", r.api.TxnToken)
	}
	response, err := r.api.HTTPClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, false, errors.New("remediation request stopped; the remote run was not cancelled")
		}
		return nil, nil, true, errors.New("remediation request failed; retry a submission only with the same --request-id")
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode != wantCode {
		retry := response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= http.StatusInternalServerError
		return nil, nil, retry, fmt.Errorf("remediation API returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, nil, false, errors.New("remediation response exceeds its size limit")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, nil, false, errors.New("remediation response is incomplete or exceeds its size limit")
	}
	return raw, response.Header, false, nil
}

func (r *remediationRemoteClient) wait(ctx context.Context, status remediationservice.Status) (remediationservice.Status, error) {
	for {
		if status.Phase == store.RemediationPhaseCancelling && status.Reason == "cleanup-quarantined" {
			return status, errors.New("remediation cleanup is quarantined; reconcile the recorded resources before a new run")
		}
		switch status.Phase {
		case store.RemediationPhaseSucceeded:
			return status, nil
		case store.RemediationPhaseNeedsInput, store.RemediationPhaseNeedsAdapter, store.RemediationPhaseNeedsApproval:
			return status, fmt.Errorf("remediation paused (%s); this is not a verified result", status.Phase)
		case store.RemediationPhaseFailed, store.RemediationPhaseCancelled, store.RemediationPhaseTimedOut:
			return status, fmt.Errorf("remediation ended without success (%s)", status.Phase)
		}
		if err := remediationPause(ctx, time.Second); err != nil {
			return status, err
		}
		next, err := r.get(ctx, status.ID)
		if err != nil {
			return status, err
		}
		status = next
	}
}

func remediationPause(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return errors.New("remediation wait stopped; the remote run was not cancelled")
	case <-timer.C:
		return nil
	}
}

func remediationKnownPhase(phase string) bool {
	switch phase {
	case store.RemediationPhaseQueued, store.RemediationPhaseRunning, store.RemediationPhaseCancelling,
		store.RemediationPhaseNeedsInput, store.RemediationPhaseNeedsAdapter, store.RemediationPhaseNeedsApproval,
		store.RemediationPhaseSucceeded, store.RemediationPhaseFailed, store.RemediationPhaseCancelled, store.RemediationPhaseTimedOut:
		return true
	default:
		return false
	}
}

func remediationRemoteID(id string) bool {
	return len(id) <= 96 && len(kubevalidation.IsDNS1123Subdomain(id)) == 0
}

func remediationRemoteDigest(digest string) bool {
	if len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") || strings.ToLower(digest) != digest {
		return false
	}
	_, err := hex.DecodeString(digest[7:])
	return err == nil
}

func newRemediationDownloadCmd() *cobra.Command {
	var output string
	command := &cobra.Command{
		Use:   "download RUN_ID",
		Short: "Download digest-verified evidence into a new private directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !filepath.IsAbs(output) || filepath.Clean(output) != output {
				return errors.New("--output-dir must be a new absolute private directory")
			}
			remote, err := newRemediationRemoteClient(cmd)
			if err != nil {
				return err
			}
			defer remote.api.HTTPClient.CloseIdleConnections()
			status, err := remote.get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			artifacts, err := downloadableRemediationArtifacts(status)
			if err != nil {
				return err
			}
			content := make([][]byte, len(artifacts))
			for i, artifact := range artifacts {
				content[i], err = remote.artifact(cmd.Context(), status.ID, artifact)
				if err != nil {
					return err
				}
			}
			if err := writeRemediationArtifacts(output, artifacts, content); err != nil {
				return err
			}
			status.Artifacts = artifacts
			return json.NewEncoder(cmd.OutOrStdout()).Encode(status)
		},
	}
	command.Flags().StringVar(&output, "output-dir", "", "new absolute directory, created 0700; files are 0600 and never overwritten")
	addRemediationRemoteTokenFlag(command)
	return command
}

func downloadableRemediationArtifacts(status remediationservice.Status) ([]store.RemediationArtifact, error) {
	var selected []store.RemediationArtifact
	names := make(map[string]bool, len(status.Artifacts))
	var total int64
	var patch bool
	for _, artifact := range status.Artifacts {
		key := strings.ToLower(artifact.Name)
		if !remediationRemoteArtifactName(artifact.Name) || names[key] ||
			!remediationRemoteDigest(artifact.Digest) || artifact.Size < 0 || artifact.Size > store.RemediationMaxArtifactBytes {
			return nil, errors.New("invalid remediation artifact metadata")
		}
		names[key] = true
		total += artifact.Size
		if total > store.RemediationMaxArtifactTotalBytes {
			return nil, errors.New("remediation artifacts exceed their total size limit")
		}
		extension := strings.ToLower(filepath.Ext(artifact.Name))
		mediaType, _, err := mime.ParseMediaType(artifact.MediaType)
		if err != nil || !remediationDownloadType(extension, mediaType) {
			return nil, errors.New("unsupported remediation artifact type")
		}
		if status.Phase != store.RemediationPhaseSucceeded && remediationservice.IsFinalResultArtifact(artifact.Name) {
			continue
		}
		if extension == ".patch" || extension == ".diff" {
			if status.Phase != store.RemediationPhaseSucceeded {
				continue
			}
			if artifact.Size == 0 {
				return nil, errors.New("no verified patch bytes are available")
			}
			patch = true
		}
		selected = append(selected, artifact)
	}
	if status.Phase == store.RemediationPhaseSucceeded && status.Mode != remediationservice.Validate && !patch {
		return nil, errors.New("no verified patch artifact is available")
	}
	if len(selected) == 0 {
		return nil, errors.New("no downloadable remediation evidence is available")
	}
	return selected, nil
}

func remediationRemoteArtifactName(name string) bool {
	if len(name) == 0 || len(name) > 255 || strings.HasSuffix(name, ".") {
		return false
	}
	for i, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			continue
		}
		if i == 0 || (r != '.' && r != '_' && r != '-') {
			return false
		}
	}
	return true
}

func remediationDownloadType(extension, mediaType string) bool {
	switch extension {
	case ".json":
		return mediaType == "application/json"
	case ".txt", ".log":
		return mediaType == "text/plain"
	case ".patch", ".diff":
		return mediaType == "text/plain" || mediaType == "text/x-patch" || mediaType == "text/x-diff"
	default:
		return false
	}
}

func (r *remediationRemoteClient) artifact(ctx context.Context, id string, artifact store.RemediationArtifact) ([]byte, error) {
	raw, header, err := r.request(ctx, http.MethodGet, "/"+id+"/artifacts/"+artifact.Name, nil, store.RemediationMaxArtifactBytes, http.StatusOK)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	if artifact.Size != int64(len(raw)) || artifact.Digest != "sha256:"+hex.EncodeToString(digest[:]) ||
		header.Get("Digest") != "sha-256="+base64.StdEncoding.EncodeToString(digest[:]) {
		return nil, errors.New("remediation artifact failed its size or SHA-256 integrity check")
	}
	return raw, nil
}

func writeRemediationArtifacts(directory string, artifacts []store.RemediationArtifact, content [][]byte) error {
	parent, base := filepath.Dir(directory), filepath.Base(directory)
	for path := parent; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("output parent is unavailable or contains a symlink")
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return errors.New("output parent is unavailable")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return errors.New("output parent could not be opened")
	}
	defer root.Close() //nolint:errcheck
	openedParent, err := root.Stat(".")
	if err != nil || !os.SameFile(parentInfo, openedParent) {
		return errors.New("output parent changed while opening")
	}
	if err := root.Mkdir(base, 0o700); err != nil {
		return errors.New("output directory already exists or could not be created")
	}
	info, err := root.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("output directory is not private")
	}
	output, err := root.OpenRoot(base)
	if err != nil {
		return errors.New("output directory could not be opened")
	}
	defer output.Close() //nolint:errcheck
	opened, err := output.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("output directory changed while opening")
	}
	for i, artifact := range artifacts {
		file, err := output.OpenFile(artifact.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return errors.New("artifact file already exists or could not be created")
		}
		_, writeErr := file.Write(content[i])
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || syncErr != nil || closeErr != nil {
			return errors.New("artifact file could not be persisted")
		}
	}
	return nil
}
