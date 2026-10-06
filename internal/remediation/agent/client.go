package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/cli/client"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"github.com/orka-agents/orka/internal/security"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	defaultMaxTurns     = 50
	defaultPollInterval = time.Second
	maxPollInterval     = 30 * time.Second
	taskTimeout         = 15 * time.Minute
	generateTimeout     = 20 * time.Minute
	maxPromptBytes      = 256 << 10
	emptyProposalOutput = "Prompt completed without textual output."
)

type Request struct {
	TaskName        string
	ExpectedTaskUID string
	Prompt          string
	Repository      string
	Commit          string
	MaxTurns        int32
	// Native-controller requests can bind a saved plan and recover an uncertain
	// create without authorizing another Task. The HTTP adapter is unchanged.
	ExpectedIdentity string
	RequireExisting  bool
	RunID            string
}

type Result struct {
	TaskName string `json:"taskName"`
	TaskUID  string `json:"taskUID"`
	Output   string `json:"output"`
}

type Client struct {
	API          *client.Client
	AgentName    string
	TaskType     string
	PollInterval time.Duration
}

// The CLI DTO lacks the canonical top-level workspace field. Its transport also
// reads unbounded bodies and includes remote bodies in errors, so only its DTO
// and client configuration are reused here.
type createTaskRequest struct {
	client.CreateTaskRequest
	Workspace   *corev1alpha1.WorkspaceConfig `json:"workspace,omitempty"`
	requestedBy *corev1alpha1.RequestedBy
}

type taskResponse struct {
	corev1alpha1.Task
	Plan json.RawMessage `json:"plan,omitempty"`
}

// Generate creates or resumes one exactly matching named Task. Errors retain
// TaskName and the supplied or verified Task UID, but never return partial output.
func (c Client) Generate(ctx context.Context, request Request) (Result, error) {
	result := Result{TaskName: request.TaskName, TaskUID: request.ExpectedTaskUID}
	if ctx == nil {
		return result, errors.New("proposal context is required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	wire, payload, err := c.prepare(request)
	if err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(ctx, generateTimeout)
	defer cancel()

	if payload.Type == string(corev1alpha1.TaskTypeAI) {
		payload.requestedBy, err = wire.getRequester(ctx)
		if err != nil {
			return result, err
		}
	}
	task, err := wire.getTask(ctx, request.TaskName, false)
	if isHTTPStatus(err, http.StatusNotFound) {
		if request.ExpectedTaskUID != "" {
			return result, fmt.Errorf("saved proposal Task is missing; refusing to recreate: %w", err)
		}
		task, err = wire.createOrRecover(ctx, payload)
	}
	if err != nil {
		return result, err
	}

	for {
		if err := matchTask(task, payload, &result); err != nil {
			return result, err
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		switch task.Status.Phase {
		case corev1alpha1.TaskPhaseSucceeded:
			output, err := wire.getResult(ctx, request.TaskName)
			if err != nil {
				return result, err
			}
			// Results contain no UID. Fence both sides of the result read rather
			// than attributing a same-name replacement's output to this Task.
			task, err = wire.getTask(ctx, request.TaskName, false)
			if err != nil {
				return result, err
			}
			if err := matchTask(task, payload, &result); err != nil {
				return result, err
			}
			if task.Status.Phase != corev1alpha1.TaskPhaseSucceeded {
				return result, errors.New("proposal Task completion changed while reading its result")
			}
			if err := ctx.Err(); err != nil {
				return result, err
			}
			result.Output = output
			return result, nil
		case corev1alpha1.TaskPhaseFailed:
			return result, errors.New("proposal Task failed")
		case corev1alpha1.TaskPhaseCancelled:
			return result, errors.New("proposal Task was cancelled")
		case "", corev1alpha1.TaskPhasePending, corev1alpha1.TaskPhaseRunning, corev1alpha1.TaskPhaseFinalizing:
			// A newly created Task can have no status until its first reconcile.
		default:
			return result, errors.New("proposal Task has an unexpected phase")
		}
		if err := wait(ctx, wire.pollInterval); err != nil {
			return result, err
		}
		task, err = wire.getTask(ctx, request.TaskName, false)
		if err != nil {
			return result, err
		}
	}
}

func (c Client) prepare(request Request) (*transport, createTaskRequest, error) {
	var payload createTaskRequest
	if c.API == nil {
		return nil, payload, errors.New("proposal API client is required")
	}
	taskType := c.TaskType
	if taskType == "" {
		taskType = string(corev1alpha1.TaskTypeAgent)
	}
	if taskType != string(corev1alpha1.TaskTypeAgent) && taskType != string(corev1alpha1.TaskTypeAI) {
		return nil, payload, errors.New("proposal Task type must be agent or ai")
	}
	if taskType == string(corev1alpha1.TaskTypeAI) && (request.Repository != "" || request.Commit != "") {
		return nil, payload, errors.New("native AI proposals require source content in the prompt, not a repository or commit")
	}
	api := *c.API
	if len(validation.IsDNS1123Label(api.Namespace)) != 0 {
		return nil, payload, errors.New("proposal API namespace must be an explicit canonical Kubernetes namespace")
	}
	if len(validation.IsDNS1123Subdomain(request.TaskName)) != 0 {
		return nil, payload, errors.New("proposal Task name must be a deterministic Kubernetes name")
	}
	if len(validation.IsDNS1123Subdomain(c.AgentName)) != 0 {
		return nil, payload, errors.New("proposal Agent name must be a Kubernetes name")
	}
	if len(request.Prompt) > maxPromptBytes || !utf8.ValidString(request.Prompt) || strings.TrimSpace(request.Prompt) == "" {
		return nil, payload, errors.New("proposal prompt must be nonempty UTF-8 and at most 256 KiB")
	}
	if request.MaxTurns == 0 {
		request.MaxTurns = defaultMaxTurns
	}
	if request.MaxTurns < harnessv2.MinAgentMaxTurns || request.MaxTurns > harnessv2.MaxAgentMaxTurns {
		return nil, payload, errors.New("proposal max turns must be in the range 1..1000")
	}
	if c.PollInterval == 0 {
		c.PollInterval = defaultPollInterval
	}
	if c.PollInterval < 0 || c.PollInterval > maxPollInterval {
		return nil, payload, errors.New("proposal polling interval must be positive and at most 30 seconds")
	}
	baseURL, err := canonicalProposalAPIBaseURL(api.BaseURL)
	if err != nil {
		return nil, payload, err
	}
	api.BaseURL = baseURL

	allowedTools := []string{}
	if request.Repository != "" {
		if !validRepository(request.Repository) {
			return nil, payload, errors.New("proposal source must be a credential-free HTTPS GitHub repository root")
		}
		if !validCommit(request.Commit) {
			return nil, payload, errors.New("proposal source requires an exact full lowercase commit SHA")
		}
		payload.Workspace = &corev1alpha1.WorkspaceConfig{
			GitRepo: request.Repository,
			Ref:     request.Commit,
			Intent:  corev1alpha1.WorkspaceIntentRead,
		}
		allowedTools = []string{"Read", "Glob", "Grep"}
	} else if request.Commit != "" {
		return nil, payload, errors.New("proposal commit requires a source repository")
	}
	payload.CreateTaskRequest = client.CreateTaskRequest{
		Name:      request.TaskName,
		Namespace: api.Namespace,
		Type:      taskType,
		Prompt:    request.Prompt,
		Timeout:   taskTimeout.String(),
		AgentRef: &struct {
			Name string `json:"name"`
		}{Name: c.AgentName},
	}
	if taskType == string(corev1alpha1.TaskTypeAgent) {
		allowBash := false
		payload.AgentRuntime = &corev1alpha1.AgentRuntimeSpec{
			MaxTurns:     &request.MaxTurns,
			AllowedTools: allowedTools,
			AllowBash:    &allowBash,
		}
	}
	httpClient := *http.DefaultClient
	if api.HTTPClient != nil {
		httpClient = *api.HTTPClient
	}
	if httpClient.Timeout <= 0 || httpClient.Timeout > requestTimeout {
		httpClient.Timeout = requestTimeout
	}
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &transport{api: api, http: httpClient, pollInterval: c.PollInterval}, payload, nil
}

func canonicalProposalAPIBaseURL(raw string) (string, error) {
	base, err := url.Parse(raw)
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") ||
		base.User != nil || base.Opaque != "" || base.RawQuery != "" || base.ForceQuery ||
		base.Fragment != "" || strings.Contains(raw, "#") || base.RawPath != "" {
		return "", errors.New("proposal API base URL must be HTTP(S) without credentials, query, or fragment")
	}
	return strings.TrimRight(base.String(), "/"), nil
}

func validRepository(raw string) bool {
	if len(raw) > 2048 || strings.ContainsAny(raw, "%?#\\") || raw != strings.TrimSpace(raw) {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.Opaque != "" {
		return false
	}
	owner, repository, err := security.ParseGitHubRepositoryURL(raw)
	if err != nil || len(owner) > 39 || strings.ContainsAny(owner, "._") ||
		strings.HasPrefix(owner, "-") || strings.HasSuffix(owner, "-") || len(repository) > 100 {
		return false
	}
	canonicalPath := "/" + owner + "/" + repository
	return parsed.Path == canonicalPath || parsed.Path == canonicalPath+".git"
}

func validCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	nonzero := false
	for _, char := range []byte(value) {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
		nonzero = nonzero || char != '0'
	}
	return nonzero
}

func matchTask(task *taskResponse, expected createTaskRequest, result *Result) error {
	if task.Name != expected.Name || task.Namespace != expected.Namespace || task.UID == "" {
		return errors.New("proposal Task response has a different or missing identity")
	}
	if (task.Kind != "" && task.Kind != "Task") ||
		(task.APIVersion != "" && task.APIVersion != corev1alpha1.GroupVersion.String()) {
		return errors.New("proposal API returned a different resource type")
	}
	if result.TaskUID != "" && result.TaskUID != string(task.UID) {
		return errors.New("proposal Task UID changed")
	}
	if task.DeletionTimestamp != nil {
		return errors.New("proposal Task is being deleted")
	}
	spec := &task.Spec
	if expected.Type == string(corev1alpha1.TaskTypeAI) && !reflect.DeepEqual(spec.RequestedBy, expected.requestedBy) {
		return errors.New("proposal Task requester does not match the authenticated identity")
	}
	if spec.Type != corev1alpha1.TaskType(expected.Type) || spec.Prompt != expected.Prompt ||
		spec.AgentRef == nil || spec.AgentRef.Name != expected.AgentRef.Name || spec.AgentRef.Namespace != "" ||
		!reflect.DeepEqual(spec.Workspace, expected.Workspace) ||
		!reflect.DeepEqual(spec.AgentRuntime, expected.AgentRuntime) ||
		spec.Timeout == nil || spec.Timeout.Duration != taskTimeout {
		return errors.New("proposal Task name is occupied by a different request or read-only policy")
	}
	if err := validateTaskExecutionSettings(spec); err != nil {
		return err
	}
	result.TaskUID = string(task.UID)
	return nil
}

func validateTaskExecutionSettings(spec *corev1alpha1.TaskSpec) error {
	if spec.SessionRef != nil || spec.PriorTaskRef != nil || spec.Execution != nil || spec.SecretRef != nil ||
		spec.AI != nil || spec.Image != "" || len(spec.Command) != 0 || len(spec.Args) != 0 ||
		len(spec.Env) != 0 || spec.WebhookURL != "" || spec.Schedule != "" ||
		(spec.Suspend != nil && *spec.Suspend) || (spec.RetryPolicy != nil && spec.RetryPolicy.MaxRetries != 0) {
		return errors.New("proposal Task contains execution settings not requested by the caller")
	}
	return nil
}

func (w *transport) createOrRecover(ctx context.Context, request createTaskRequest) (*taskResponse, error) {
	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, errors.New("cannot encode proposal Task request")
	}
	body, err := w.request(ctx, http.MethodPost, "/api/v1/tasks", encoded, http.StatusCreated)
	if err == nil {
		var task taskResponse
		if err = decodeResponse(body, &task); err == nil {
			return &task, nil
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// A conflict, lost acknowledgement, or invalid acknowledgement cannot
	// justify another POST. Only an observed matching Task can recover it.
	task, readErr := w.getTask(ctx, request.Name, true)
	if readErr != nil {
		return nil, errors.Join(
			fmt.Errorf("proposal Task create was not acknowledged: %w", err),
			fmt.Errorf("proposal Task outcome is unresolved; resume the same name: %w", readErr),
		)
	}
	return task, nil
}

func (w *transport) getTask(ctx context.Context, name string, reconcileCreate bool) (*taskResponse, error) {
	body, err := w.read(ctx, "/api/v1/tasks/"+url.PathEscape(name), reconcileCreate)
	if err != nil {
		return nil, fmt.Errorf("read proposal Task: %w", err)
	}
	var task taskResponse
	if err := decodeResponse(body, &task); err != nil {
		return nil, err
	}
	return &task, nil
}

func (w *transport) getResult(ctx context.Context, name string) (string, error) {
	body, err := w.read(ctx, "/api/v1/tasks/"+url.PathEscape(name)+"/result", false)
	if err != nil {
		return "", fmt.Errorf("read proposal result: %w", err)
	}
	return decodeResult(body)
}
