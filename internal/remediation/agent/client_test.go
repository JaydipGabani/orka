package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/cli/client"
)

type responseStep struct {
	method string
	result bool
	whoami bool
	status int
	body   string
	serve  func(http.ResponseWriter, *http.Request)
}

func syntheticRequest() Request {
	return Request{
		TaskName:   "proposal-fixed-name",
		Prompt:     "Propose a check for this synthetic report; do not modify source.",
		Repository: "https://github.com/example/project",
		Commit:     strings.Repeat("a", 40),
		MaxTurns:   7,
	}
}

func syntheticTask(request Request, phase corev1alpha1.TaskPhase) corev1alpha1.Task {
	maxTurns := request.MaxTurns
	if maxTurns == 0 {
		maxTurns = 50
	}
	allowBash := false
	task := corev1alpha1.Task{
		TypeMeta: metav1.TypeMeta{APIVersion: "core.orka.ai/v1alpha1", Kind: "Task"},
		ObjectMeta: metav1.ObjectMeta{
			Name: request.TaskName, Namespace: "remediation-tests", UID: types.UID("original-task-uid"),
		},
		Spec: corev1alpha1.TaskSpec{
			Type:     corev1alpha1.TaskTypeAgent,
			Prompt:   request.Prompt,
			AgentRef: &corev1alpha1.AgentReference{Name: "proposal-agent"},
			Timeout:  &metav1.Duration{Duration: 15 * time.Minute},
			AgentRuntime: &corev1alpha1.AgentRuntimeSpec{
				MaxTurns: &maxTurns, AllowBash: &allowBash, AllowedTools: []string{},
			},
		},
		Status: corev1alpha1.TaskStatus{Phase: phase},
	}
	if request.Repository != "" {
		task.Spec.Workspace = &corev1alpha1.WorkspaceConfig{
			GitRepo: request.Repository, Ref: request.Commit, Intent: corev1alpha1.WorkspaceIntentRead,
		}
		task.Spec.AgentRuntime.AllowedTools = []string{"Read", "Glob", "Grep"}
	}
	if phase == corev1alpha1.TaskPhaseSucceeded {
		task.Status.ResultRef = &corev1alpha1.ResultReference{Available: true}
	}
	return task
}

func encodeFixture(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("cannot encode synthetic fixture")
	}
	return string(data)
}

func taskStep(t *testing.T, task corev1alpha1.Task) responseStep {
	t.Helper()
	return responseStep{method: http.MethodGet, status: http.StatusOK, body: encodeFixture(t, task)}
}

func resultStep(status int, body string) responseStep {
	return responseStep{method: http.MethodGet, result: true, status: status, body: body}
}

func scriptedClient(t *testing.T, steps ...responseStep) Client {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := int(calls.Add(1)) - 1
		if index >= len(steps) {
			t.Error("unexpected extra API request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		step := steps[index]
		path := "/api/v1/tasks"
		if step.method != http.MethodPost {
			path += "/" + syntheticRequest().TaskName
		}
		if step.result {
			path += "/result"
		}
		if step.whoami {
			path = "/api/v1/auth/whoami"
		}
		if r.Method != step.method || r.URL.Path != path {
			t.Errorf("unexpected API operation at step %d", index)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodGet && r.URL.Query().Get("namespace") != "remediation-tests" {
			t.Error("GET did not carry the canonical client namespace")
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Error("request did not ask for JSON")
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-api-value" || r.Header.Get("Txn-Token") != "synthetic-transaction-value" {
			t.Error("request did not preserve explicit API authentication")
		}
		if step.serve != nil {
			step.serve(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(step.status)
		if _, err := io.WriteString(w, step.body); err != nil && r.Context().Err() == nil {
			t.Error("cannot write synthetic response")
		}
	}))
	t.Cleanup(func() {
		server.Close()
		if int(calls.Load()) != len(steps) {
			t.Errorf("API calls = %d, want %d", calls.Load(), len(steps))
		}
	})
	api := client.NewWithNamespace(server.URL, "synthetic-api-value", "remediation-tests")
	api.TxnToken = "synthetic-transaction-value"
	api.HTTPClient = server.Client()
	return Client{API: api, AgentName: "proposal-agent", PollInterval: time.Millisecond}
}

func TestGenerateCreatePollResultAndReadOnlyWirePolicy(t *testing.T) {
	for _, source := range []bool{true, false} {
		name := "repository"
		if !source {
			name = "source-free"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := syntheticRequest()
			if !source {
				request.Repository, request.Commit = "", ""
			}
			created := syntheticTask(request, "")
			running := syntheticTask(request, corev1alpha1.TaskPhaseRunning)
			finalizing := syntheticTask(request, corev1alpha1.TaskPhaseFinalizing)
			succeeded := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
			createdJSON := encodeFixture(t, created)
			c := scriptedClient(t,
				responseStep{method: http.MethodGet, status: http.StatusNotFound},
				responseStep{method: http.MethodPost, serve: func(w http.ResponseWriter, r *http.Request) {
					assertCreateRequest(t, r, request)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(w, createdJSON)
				}},
				taskStep(t, running),
				taskStep(t, finalizing),
				taskStep(t, succeeded),
				resultStep(http.StatusOK, `{"result":"synthetic proposal\nwith a check"}`),
				taskStep(t, succeeded),
			)
			result, err := c.Generate(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			want := Result{TaskName: request.TaskName, TaskUID: string(created.UID), Output: "synthetic proposal\nwith a check"}
			if result != want {
				t.Error("result did not preserve the exact Task identity and output")
			}
			if c.API.HTTPClient.Timeout != 0 || c.API.HTTPClient.CheckRedirect != nil {
				t.Error("adapter mutated the caller's HTTP client")
			}
			encoded := encodeFixture(t, result)
			var fields map[string]json.RawMessage
			if err := json.Unmarshal([]byte(encoded), &fields); err != nil ||
				len(fields) != 3 || fields["taskName"] == nil || fields["taskUID"] == nil || fields["output"] == nil {
				t.Error("Result JSON contract changed")
			}
		})
	}
}

func assertCreateRequestFields(t *testing.T, fields map[string]json.RawMessage, hasRepository bool) {
	t.Helper()
	allowed := map[string]bool{
		"name": true, "namespace": true, "type": true, "prompt": true,
		"timeout": true, "agentRef": true, "agentRuntime": true,
	}
	if hasRepository {
		allowed["workspace"] = true
	}
	if len(fields) != len(allowed) {
		t.Error("create request contains missing or unexpected fields")
	}
	for key := range fields {
		if !allowed[key] {
			t.Errorf("unexpected create field %q", key)
		}
	}
	for field, allowedKeys := range map[string][]string{
		"agentRuntime": {"maxTurns", "allowBash", "allowedTools"},
		"workspace":    {"gitRepo", "ref", "intent"},
	} {
		if field == "workspace" && !hasRepository {
			continue
		}
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(fields[field], &nested); err != nil || len(nested) != len(allowedKeys) {
			t.Errorf("create %s contains missing or unexpected fields", field)
			continue
		}
		for _, key := range allowedKeys {
			if nested[key] == nil {
				t.Errorf("create %s is missing %s", field, key)
			}
		}
	}
}

func assertCreateRequest(t *testing.T, r *http.Request, request Request) {
	t.Helper()
	if r.Header.Get("Content-Type") != "application/json" {
		t.Error("create request did not declare JSON")
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxResponseBytes+1))
	if err != nil {
		t.Error("cannot read synthetic create request")
		return
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Error("create request is not an object")
		return
	}
	assertCreateRequestFields(t, fields, request.Repository != "")
	// Decode the actual flat API request independently of the adapter's DTO.
	var actual struct {
		Name         string                        `json:"name"`
		Namespace    string                        `json:"namespace"`
		Type         string                        `json:"type"`
		Prompt       string                        `json:"prompt"`
		Timeout      string                        `json:"timeout"`
		AgentRef     corev1alpha1.AgentReference   `json:"agentRef"`
		AgentRuntime corev1alpha1.AgentRuntimeSpec `json:"agentRuntime"`
		Workspace    *corev1alpha1.WorkspaceConfig `json:"workspace"`
	}
	if err := json.Unmarshal(data, &actual); err != nil {
		t.Error("create request does not match the flat API wire contract")
		return
	}
	if actual.Name != request.TaskName || actual.Namespace != "remediation-tests" ||
		actual.Type != "agent" || actual.Prompt != request.Prompt || actual.AgentRef.Name != "proposal-agent" {
		t.Error("create request changed the supplied identity or prompt")
	}
	timeout, err := time.ParseDuration(actual.Timeout)
	if err != nil || timeout != 15*time.Minute {
		t.Error("create request has an incorrect timeout")
	}
	if actual.AgentRuntime.MaxTurns == nil || *actual.AgentRuntime.MaxTurns != request.MaxTurns ||
		actual.AgentRuntime.AllowBash == nil || *actual.AgentRuntime.AllowBash || actual.AgentRuntime.Workspace != nil {
		t.Error("create request lacks explicit runtime limits and bash denial")
	}
	if request.Repository == "" {
		if actual.Workspace != nil || actual.AgentRuntime.AllowedTools == nil || len(actual.AgentRuntime.AllowedTools) != 0 {
			t.Error("source-free inference must explicitly deny all tools and omit workspace")
		}
	} else {
		wantWorkspace := &corev1alpha1.WorkspaceConfig{
			GitRepo: request.Repository, Ref: request.Commit, Intent: corev1alpha1.WorkspaceIntentRead,
		}
		if !reflect.DeepEqual(actual.Workspace, wantWorkspace) ||
			!reflect.DeepEqual(actual.AgentRuntime.AllowedTools, []string{"Read", "Glob", "Grep"}) {
			t.Error("repository Task must be pinned, read-only, and credential-free")
		}
	}
}

func TestGenerateResumeFinishedWithoutPOST(t *testing.T) {
	t.Parallel()
	request := syntheticRequest()
	task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
	priority := int32(500)
	task.Spec.Priority = &priority
	task.Spec.ConcurrencyPolicy = corev1alpha1.ForbidConcurrent
	withPlan := struct {
		corev1alpha1.Task
		Plan struct {
			Summary string `json:"summary"`
		} `json:"plan"`
	}{Task: task}
	withPlan.Plan.Summary = "synthetic plan"
	c := scriptedClient(t,
		responseStep{method: http.MethodGet, status: http.StatusOK, body: encodeFixture(t, withPlan)},
		resultStep(http.StatusOK, `{"result":"already completed"}`),
		taskStep(t, task),
	)
	result, err := c.Generate(t.Context(), request)
	if err != nil || result.TaskUID != string(task.UID) || result.Output != "already completed" {
		t.Fatalf("finished Task was not resumed: %v", err)
	}
}

func TestGenerateExpectedTaskUIDFence(t *testing.T) {
	for _, taskType := range []string{"agent", "ai"} {
		for _, outcome := range []string{
			"missing", "replacement", "missing-uid", "different-request",
			"lookup-error", "poll-replacement", "missing-result", "completed",
		} {
			t.Run(taskType+"/"+outcome, func(t *testing.T) {
				t.Parallel()
				request := syntheticRequest()
				task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
				if taskType == "ai" {
					request = syntheticAIRequest()
					task = syntheticAITask(request, corev1alpha1.TaskPhaseSucceeded)
				}
				request.ExpectedTaskUID = string(task.UID)
				var steps []responseStep
				switch outcome {
				case "missing":
					steps = append(steps, responseStep{method: http.MethodGet, status: http.StatusNotFound})
				case "replacement":
					task.UID = "replacement-task-uid"
					steps = append(steps, taskStep(t, task))
				case "missing-uid":
					task.UID = ""
					steps = append(steps, taskStep(t, task))
				case "different-request":
					task.Spec.Prompt = "another synthetic request"
					steps = append(steps, taskStep(t, task))
				case "lookup-error":
					for range 3 {
						steps = append(steps, responseStep{method: http.MethodGet, status: http.StatusInternalServerError})
					}
				case "poll-replacement":
					task.Status.Phase = corev1alpha1.TaskPhasePending
					steps = append(steps, taskStep(t, task))
					task.UID = "replacement-task-uid"
					steps = append(steps, taskStep(t, task))
				case "missing-result":
					steps = append(steps, taskStep(t, task), resultStep(http.StatusNotFound, ""))
				case "completed":
					steps = append(steps, taskStep(t, task), resultStep(http.StatusOK, `{"result":"{\"synthetic\":true}"}`), taskStep(t, task))
				}
				var c Client
				if taskType == "ai" {
					c = scriptedNativeClient(t, steps...)
				} else {
					c = scriptedClient(t, steps...)
					c.TaskType = taskType
				}
				result, err := c.Generate(t.Context(), request)
				want := Result{TaskName: request.TaskName, TaskUID: request.ExpectedTaskUID}
				if outcome == "completed" {
					want.Output = `{"synthetic":true}`
					if err != nil {
						t.Fatalf("matching saved Task could not be resumed: %v", err)
					}
				} else if err == nil {
					t.Fatal("saved Task fence must fail without creating or adopting a replacement")
				}
				if result != want {
					t.Fatal("saved Task fence did not preserve the expected identity and withhold unverified output")
				}
			})
		}
	}
}

func TestGenerateExpectedTaskUIDPreservedBeforeLookup(t *testing.T) {
	for _, taskType := range []string{"agent", "ai"} {
		t.Run(taskType, func(t *testing.T) {
			t.Parallel()
			request := syntheticAIRequest()
			request.ExpectedTaskUID = "previously-saved-task-uid"
			c := scriptedClient(t)
			c.TaskType = taskType
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			result, err := c.Generate(ctx, request)
			if !errors.Is(err, context.Canceled) ||
				result != (Result{TaskName: request.TaskName, TaskUID: request.ExpectedTaskUID}) {
				t.Fatal("a cancelled resume must preserve the supplied UID without any API call")
			}
		})
	}
}

func TestGenerateReturnsProposalStringUnchanged(t *testing.T) {
	for _, test := range []struct {
		name     string
		proposal string
	}{
		{
			name: "encoded-object",
			proposal: `
  {
    "summary": "synthetic proposal",
    "checks": ["line one\nline two", "quoted \"synthetic\" value"],
    "patch": null
  }
`,
		},
		{name: "caller-rejects-malformed-proposal", proposal: `{"synthetic":`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := syntheticRequest()
			task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
			body := encodeFixture(t, struct {
				Result string `json:"result"`
			}{Result: test.proposal})
			c := scriptedClient(t, taskStep(t, task), resultStep(http.StatusOK, body), taskStep(t, task))
			result, err := c.Generate(t.Context(), request)
			if err != nil {
				t.Fatal(err)
			}
			if result.Output != test.proposal || result.TaskName != request.TaskName || result.TaskUID != string(task.UID) {
				t.Error("adapter must return the exact result string and Task identity without parsing the proposal")
			}
		})
	}
}

func TestGenerateNameCollision(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*corev1alpha1.Task)
	}{
		{"prompt", func(task *corev1alpha1.Task) { task.Spec.Prompt = "different synthetic prompt" }},
		{"agent", func(task *corev1alpha1.Task) { task.Spec.AgentRef.Name = "other-agent" }},
		{"agent-namespace", func(task *corev1alpha1.Task) { task.Spec.AgentRef.Namespace = "foreign-namespace" }},
		{"type", func(task *corev1alpha1.Task) { task.Spec.Type = corev1alpha1.TaskTypeAI }},
		{"kind", func(task *corev1alpha1.Task) { task.Kind = "NotATask" }},
		{"api-version", func(task *corev1alpha1.Task) { task.APIVersion = "foreign.example/v1" }},
		{"namespace", func(task *corev1alpha1.Task) { task.Namespace = "foreign-namespace" }},
		{"name", func(task *corev1alpha1.Task) { task.Name = "foreign-name" }},
		{"uid-missing", func(task *corev1alpha1.Task) { task.UID = "" }},
		{"workspace", func(task *corev1alpha1.Task) { task.Spec.Workspace = nil }},
		{"repository", func(task *corev1alpha1.Task) { task.Spec.Workspace.GitRepo = "https://github.com/other/project" }},
		{"ref", func(task *corev1alpha1.Task) { task.Spec.Workspace.Ref = strings.Repeat("b", 40) }},
		{"intent", func(task *corev1alpha1.Task) { task.Spec.Workspace.Intent = corev1alpha1.WorkspaceIntentWrite }},
		{"implicit-intent", func(task *corev1alpha1.Task) { task.Spec.Workspace.Intent = "" }},
		{"branch", func(task *corev1alpha1.Task) { task.Spec.Workspace.Branch = "different" }},
		{"subpath", func(task *corev1alpha1.Task) { task.Spec.Workspace.SubPath = "nested" }},
		{"read-credential", func(task *corev1alpha1.Task) {
			task.Spec.Workspace.ReadCredentialRef = &corev1alpha1.WorkspaceCredentialReference{Name: "not-allowed"}
		}},
		{"publication-credential", func(task *corev1alpha1.Task) {
			task.Spec.Workspace.PublicationCredentialRef = &corev1alpha1.WorkspaceCredentialReference{Name: "not-allowed"}
		}},
		{"publication", func(task *corev1alpha1.Task) { task.Spec.Workspace.CreatePR = true }},
		{"bash", func(task *corev1alpha1.Task) { *task.Spec.AgentRuntime.AllowBash = true }},
		{"implicit-bash", func(task *corev1alpha1.Task) { task.Spec.AgentRuntime.AllowBash = nil }},
		{"tools", func(task *corev1alpha1.Task) {
			task.Spec.AgentRuntime.AllowedTools = append(task.Spec.AgentRuntime.AllowedTools, "Write")
		}},
		{"turns", func(task *corev1alpha1.Task) { *task.Spec.AgentRuntime.MaxTurns++ }},
		{"timeout", func(task *corev1alpha1.Task) { task.Spec.Timeout.Duration = time.Hour }},
		{"session", func(task *corev1alpha1.Task) {
			task.Spec.SessionRef = &corev1alpha1.SessionReference{Name: "other-session"}
		}},
		{"execution", func(task *corev1alpha1.Task) { task.Spec.Execution = &corev1alpha1.ExecutionSpec{} }},
		{"secret", func(task *corev1alpha1.Task) {
			task.Spec.SecretRef = &corev1alpha1.SecretReference{Name: "not-allowed"}
		}},
		{"env", func(task *corev1alpha1.Task) {
			task.Spec.Env = []corev1.EnvVar{{Name: "UNREQUESTED", Value: "synthetic"}}
		}},
		{"webhook", func(task *corev1alpha1.Task) { task.Spec.WebhookURL = "https://example.invalid/hook" }},
		{"schedule", func(task *corev1alpha1.Task) { task.Spec.Schedule = "* * * * *" }},
		{"retry", func(task *corev1alpha1.Task) { task.Spec.RetryPolicy = &corev1alpha1.RetryPolicy{MaxRetries: 1} }},
		{"deleting", func(task *corev1alpha1.Task) { timestamp := metav1.Now(); task.DeletionTimestamp = &timestamp }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := syntheticRequest()
			task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
			test.mutate(&task)
			c := scriptedClient(t, taskStep(t, task))
			result, err := c.Generate(t.Context(), request)
			if err == nil || result.TaskName != request.TaskName || result.TaskUID != "" || result.Output != "" {
				t.Error("collision must fail without adopting or replaying the foreign Task")
			}
		})
	}
}

func TestGenerateRejectsInheritedToolsWithoutSource(t *testing.T) {
	t.Parallel()
	request := syntheticRequest()
	request.Repository, request.Commit = "", ""
	task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
	task.Spec.AgentRuntime.AllowedTools = nil
	c := scriptedClient(t, taskStep(t, task))
	if _, err := c.Generate(t.Context(), request); err == nil {
		t.Fatal("an absent allowlist must not be treated as an explicit deny-all policy")
	}
}

func TestGenerateCreateAcknowledgementRecovery(t *testing.T) {
	for _, acknowledgement := range []string{"conflict", "server-error", "connection-lost", "malformed", "oversized"} {
		t.Run(acknowledgement, func(t *testing.T) {
			t.Parallel()
			request := syntheticRequest()
			task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
			post := responseStep{method: http.MethodPost}
			switch acknowledgement {
			case "conflict":
				post.status = http.StatusConflict
			case "server-error":
				post.status, post.body = http.StatusInternalServerError, "synthetic content that must not appear in an error"
			case "connection-lost":
				post.serve = func(w http.ResponseWriter, _ *http.Request) {
					hijacker, ok := w.(http.Hijacker)
					if !ok {
						t.Error("httptest server did not support hijacking")
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					connection, _, err := hijacker.Hijack()
					if err != nil {
						t.Error("cannot simulate lost acknowledgement")
						return
					}
					_ = connection.Close()
				}
			case "malformed":
				post.status, post.body = http.StatusCreated, `{"metadata":`
			case "oversized":
				post.status, post.body = http.StatusCreated, strings.Repeat(" ", maxResponseBytes+1)
			}
			c := scriptedClient(t,
				responseStep{method: http.MethodGet, status: http.StatusNotFound},
				post,
				taskStep(t, task),
				resultStep(http.StatusOK, `{"result":"recovered"}`),
				taskStep(t, task),
			)
			result, err := c.Generate(t.Context(), request)
			if err != nil || result.TaskUID != string(task.UID) || result.Output != "recovered" {
				t.Fatalf("matching Task did not recover the acknowledgement: %v", err)
			}
		})
	}
}

func TestGenerateConflictDoesNotAdoptDifferentTask(t *testing.T) {
	t.Parallel()
	request := syntheticRequest()
	task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
	task.Spec.Prompt = "another synthetic request"
	c := scriptedClient(t,
		responseStep{method: http.MethodGet, status: http.StatusNotFound},
		responseStep{method: http.MethodPost, status: http.StatusConflict},
		taskStep(t, task),
	)
	result, err := c.Generate(t.Context(), request)
	if err == nil || result.TaskUID != "" || result.Output != "" {
		t.Fatal("409 reconciliation adopted a different Task")
	}
}

func TestGenerateDoesNotCreateAfterAmbiguousLookup(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusInternalServerError, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			attempts := 1
			if status == http.StatusInternalServerError || status == http.StatusTooManyRequests {
				attempts = 3
			}
			steps := make([]responseStep, 0, attempts)
			for range attempts {
				steps = append(steps, responseStep{method: http.MethodGet, status: status, body: "synthetic-private-error"})
			}
			c := scriptedClient(t, steps...)
			result, err := c.Generate(t.Context(), syntheticRequest())
			if err == nil || result.TaskName != syntheticRequest().TaskName || result.TaskUID != "" {
				t.Fatal("ambiguous lookup was not returned as an error")
			}
			if strings.Contains(err.Error(), "synthetic-private-error") {
				t.Error("HTTP error leaked remote response content")
			}
		})
	}
}

func TestGenerateUnresolvedPOSTNeverReposts(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			steps := make([]responseStep, 0, 5)
			steps = append(steps,
				responseStep{method: http.MethodGet, status: http.StatusNotFound},
				responseStep{method: http.MethodPost, status: http.StatusInternalServerError, body: "synthetic-private-create-body"},
			)
			for range 3 {
				steps = append(steps, responseStep{method: http.MethodGet, status: status, body: "synthetic-private-lookup-body"})
			}
			c := scriptedClient(t, steps...)
			result, err := c.Generate(t.Context(), syntheticRequest())
			if err == nil || result.TaskName != syntheticRequest().TaskName || result.TaskUID != "" || result.Output != "" {
				t.Fatal("unresolved POST must fail with its original name")
			}
			for _, private := range []string{"synthetic-private-create-body", "synthetic-private-lookup-body", syntheticRequest().Prompt} {
				if strings.Contains(err.Error(), private) {
					t.Error("unresolved creation error leaked remote content")
				}
			}
		})
	}
}

func TestGenerateRecoversDelayedVisibilityWithoutPOSTRetry(t *testing.T) {
	t.Parallel()
	request := syntheticRequest()
	task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
	c := scriptedClient(t,
		responseStep{method: http.MethodGet, status: http.StatusNotFound},
		responseStep{method: http.MethodPost, status: http.StatusGatewayTimeout},
		responseStep{method: http.MethodGet, status: http.StatusNotFound},
		responseStep{method: http.MethodGet, status: http.StatusServiceUnavailable},
		taskStep(t, task),
		resultStep(http.StatusOK, `{"result":"observed"}`),
		taskStep(t, task),
	)
	if _, err := c.Generate(t.Context(), request); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratePendingCancellationPreservesIdentityForResume(t *testing.T) {
	t.Parallel()
	request := syntheticRequest()
	pending := syntheticTask(request, corev1alpha1.TaskPhasePending)
	finished := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := scriptedClient(t,
		responseStep{method: http.MethodGet, status: http.StatusNotFound},
		responseStep{method: http.MethodPost, status: http.StatusCreated, body: encodeFixture(t, pending)},
		responseStep{method: http.MethodGet, serve: func(_ http.ResponseWriter, r *http.Request) {
			cancel()
			<-r.Context().Done()
		}},
		taskStep(t, finished),
		resultStep(http.StatusOK, `{"result":"resumed after cancellation"}`),
		taskStep(t, finished),
	)
	result, err := c.Generate(ctx, request)
	if !errors.Is(err, context.Canceled) || result.TaskName != request.TaskName ||
		result.TaskUID != string(pending.UID) || result.Output != "" {
		t.Fatalf("cancellation did not preserve verified identity: %v", err)
	}
	resumed, err := c.Generate(t.Context(), request)
	if err != nil || resumed.TaskUID != result.TaskUID || resumed.Output != "resumed after cancellation" {
		t.Fatalf("cancelled wait could not resume the same Task: %v", err)
	}
}

func TestGenerateCancellationDuringPOSTDoesNotReplaceTask(t *testing.T) {
	t.Parallel()
	request := syntheticRequest()
	task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := scriptedClient(t,
		responseStep{method: http.MethodGet, status: http.StatusNotFound},
		responseStep{method: http.MethodPost, serve: func(_ http.ResponseWriter, r *http.Request) {
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				t.Error("cannot read synthetic POST before cancellation")
				return
			}
			cancel()
			<-r.Context().Done()
		}},
		taskStep(t, task),
		resultStep(http.StatusOK, `{"result":"same named Task"}`),
		taskStep(t, task),
	)
	result, err := c.Generate(ctx, request)
	if !errors.Is(err, context.Canceled) || result.TaskName != request.TaskName || result.Output != "" {
		t.Fatalf("cancelled POST did not preserve its deterministic name: %v", err)
	}
	if resumed, err := c.Generate(t.Context(), request); err != nil || resumed.TaskUID != string(task.UID) {
		t.Fatalf("cancelled acknowledgement did not resume: %v", err)
	}
}

func TestGenerateAlreadyCancelledMakesNoRequests(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	c := scriptedClient(t)
	result, err := c.Generate(ctx, syntheticRequest())
	if !errors.Is(err, context.Canceled) || result.TaskName != syntheticRequest().TaskName {
		t.Fatal("pre-cancelled call must retain its name without any request")
	}
}

func TestGenerateTaskTerminalFailures(t *testing.T) {
	for _, phase := range []corev1alpha1.TaskPhase{corev1alpha1.TaskPhaseFailed, corev1alpha1.TaskPhaseCancelled, corev1alpha1.TaskPhaseScheduled, "Success"} {
		t.Run(string(phase), func(t *testing.T) {
			t.Parallel()
			request := syntheticRequest()
			task := syntheticTask(request, phase)
			task.Status.Message = "synthetic-private-failure-detail"
			c := scriptedClient(t, taskStep(t, task))
			result, err := c.Generate(t.Context(), request)
			if err == nil || result.TaskUID != string(task.UID) || result.Output != "" {
				t.Fatal("failed or unexpected phase must fail without reading output or replaying")
			}
			if strings.Contains(err.Error(), request.Prompt) || strings.Contains(err.Error(), task.Status.Message) {
				t.Error("Task error included prompt or remote status content")
			}
		})
	}
}

func TestGenerateIdentityMustRemainStable(t *testing.T) {
	for _, stage := range []string{"poll-uid", "poll-namespace", "result-uid", "result-namespace", "result-phase"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			request := syntheticRequest()
			task := syntheticTask(request, corev1alpha1.TaskPhaseRunning)
			var steps []responseStep
			if strings.HasPrefix(stage, "result-") {
				task.Status.Phase = corev1alpha1.TaskPhaseSucceeded
				steps = append(steps, taskStep(t, task), resultStep(http.StatusOK, `{"result":"must not escape"}`))
			} else {
				steps = append(steps, taskStep(t, task))
			}
			changed := task.DeepCopy()
			switch {
			case strings.HasSuffix(stage, "-uid"):
				changed.UID = "replacement-task-uid"
			case strings.HasSuffix(stage, "-namespace"):
				changed.Namespace = "foreign-namespace"
			default:
				changed.Status.Phase = corev1alpha1.TaskPhaseFailed
			}
			steps = append(steps, taskStep(t, *changed))
			c := scriptedClient(t, steps...)
			result, err := c.Generate(t.Context(), request)
			if err == nil || result.TaskUID != string(task.UID) || result.TaskName != request.TaskName || result.Output != "" {
				t.Error("identity change must fail while preserving the original identity and withholding output")
			}
		})
	}
}

func TestGenerateMissingAndMalformedResults(t *testing.T) {
	for _, body := range []string{
		`{}`, `null`, `[]`, `{"result":null}`, `{"result":""}`, `{"result":" \n\t"}`,
		`{"result":false}`, `{"result":23}`, `{"result":{}}`, `{"output":"not the API format"}`,
		`{"result":"ok","unrecognized":true}`, `{"result":"ok"}{}`, `{"result":`,
		`{"result":"first","result":"second"}`, `{"Result":"not the API field"}`,
		`{"result":"Prompt completed without textual output."}`,
		`{"result":"  Prompt completed without textual output.\n"}`,
		"{\"result\":\"\xff\"}",
	} {
		t.Run("invalid-shape", func(t *testing.T) {
			t.Parallel()
			request := syntheticRequest()
			task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
			c := scriptedClient(t, taskStep(t, task), resultStep(http.StatusOK, body))
			result, err := c.Generate(t.Context(), request)
			if err == nil || result.TaskUID != string(task.UID) || result.Output != "" {
				t.Fatal("invalid result must fail even when Task status is Succeeded")
			}
		})
	}
}

func TestGenerateMissingResultEndpoint(t *testing.T) {
	t.Parallel()
	request := syntheticRequest()
	task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
	c := scriptedClient(t, taskStep(t, task), resultStep(http.StatusNotFound, "synthetic-private-body"))
	result, err := c.Generate(t.Context(), request)
	if err == nil || result.TaskUID != string(task.UID) || result.Output != "" {
		t.Fatal("Succeeded without a result endpoint must fail")
	}
	if strings.Contains(err.Error(), "synthetic-private-body") {
		t.Error("missing result error leaked remote body")
	}
}

func TestGenerateResultEncodedByteLimit(t *testing.T) {
	for _, difference := range []int{-1, 0, 1} {
		name := "at-limit"
		if difference < 0 {
			name = "below-limit"
		} else if difference > 0 {
			name = "above-limit"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := syntheticRequest()
			task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
			output := strings.Repeat("x", maxResponseBytes-len(`{"result":""}`)+difference)
			body := `{"result":"` + output + `"}`
			if len(body) != maxResponseBytes+difference {
				t.Fatal("incorrect byte-boundary fixture")
			}
			steps := []responseStep{taskStep(t, task), resultStep(http.StatusOK, body)}
			if difference <= 0 {
				steps = append(steps, taskStep(t, task))
			}
			c := scriptedClient(t, steps...)
			result, err := c.Generate(t.Context(), request)
			if difference > 0 {
				if err == nil || result.Output != "" || result.TaskUID != string(task.UID) {
					t.Error("oversized encoded result was not rejected")
				}
			} else if err != nil || result.Output != output {
				t.Errorf("bounded result was rejected: %v", err)
			}
		})
	}
}

func TestGenerateRejectsMalformedAndOversizedTasks(t *testing.T) {
	for _, body := range []string{
		`null`, `{}`, `[]`, `{"metadata":{"name":3}}`, `{"task":{"metadata":{}}}`, `{"status":{"phase":true}}`,
		strings.Repeat(" ", maxResponseBytes+1),
	} {
		t.Run("invalid-task", func(t *testing.T) {
			t.Parallel()
			c := scriptedClient(t, responseStep{method: http.MethodGet, status: http.StatusOK, body: body})
			result, err := c.Generate(t.Context(), syntheticRequest())
			if err == nil || result.TaskUID != "" || result.Output != "" {
				t.Error("invalid Task response was accepted")
			}
		})
	}
}

func TestGenerateRequestValidationBeforeHTTP(t *testing.T) {
	type requestValidationCase struct {
		name   string
		mutate func(*Client, *Request)
	}
	tests := make([]requestValidationCase, 0, 47)
	tests = append(tests, []requestValidationCase{
		{"nil-api", func(c *Client, _ *Request) { c.API = nil }},
		{"namespace-missing", func(c *Client, _ *Request) { c.API.Namespace = "" }},
		{"namespace-space", func(c *Client, _ *Request) { c.API.Namespace = " remediation-tests" }},
		{"namespace-case", func(c *Client, _ *Request) { c.API.Namespace = "Remediation" }},
		{"namespace-path", func(c *Client, _ *Request) { c.API.Namespace = "one/other" }},
		{"name-missing", func(_ *Client, r *Request) { r.TaskName = "" }},
		{"name-generate-prefix", func(_ *Client, r *Request) { r.TaskName = "proposal-" }},
		{"name-path", func(_ *Client, r *Request) { r.TaskName = "../different" }},
		{"agent-missing", func(c *Client, _ *Request) { c.AgentName = "" }},
		{"prompt-missing", func(_ *Client, r *Request) { r.Prompt = "" }},
		{"prompt-blank", func(_ *Client, r *Request) { r.Prompt = " \n\t" }},
		{"prompt-oversized", func(_ *Client, r *Request) { r.Prompt = strings.Repeat("x", maxPromptBytes+1) }},
		{"prompt-invalid-utf8", func(_ *Client, r *Request) { r.Prompt = "\xff" }},
		{"negative-turns", func(_ *Client, r *Request) { r.MaxTurns = -1 }},
		{"excess-turns", func(_ *Client, r *Request) { r.MaxTurns = 1001 }},
		{"negative-interval", func(c *Client, _ *Request) { c.PollInterval = -time.Second }},
		{"excess-interval", func(c *Client, _ *Request) { c.PollInterval = 31 * time.Second }},
		{"commit-without-source", func(_ *Client, r *Request) { r.Repository = "" }},
		{"source-without-commit", func(_ *Client, r *Request) { r.Commit = "" }},
		{"abbreviated-commit", func(_ *Client, r *Request) { r.Commit = "abcdef0" }},
		{"branch-ref", func(_ *Client, r *Request) { r.Commit = "main" }},
		{"upper-commit", func(_ *Client, r *Request) { r.Commit = strings.Repeat("A", 40) }},
		{"zero-commit", func(_ *Client, r *Request) { r.Commit = strings.Repeat("0", 40) }},
		{"invalid-commit", func(_ *Client, r *Request) { r.Commit = strings.Repeat("g", 40) }},
		{"api-query", func(c *Client, _ *Request) { c.API.BaseURL += "?token=synthetic-private-value" }},
		{"api-userinfo", func(c *Client, _ *Request) { c.API.BaseURL = "https://synthetic-private-value@example.invalid" }},
		{"api-fragment", func(c *Client, _ *Request) { c.API.BaseURL += "#" }},
		{"api-invalid", func(c *Client, _ *Request) { c.API.BaseURL = "://synthetic-private-value" }},
	}...)
	for _, repository := range []string{
		"http://github.com/example/project", "git@github.com:example/project",
		"https://github.com.evil.invalid/example/project", "https://example.invalid/example/project",
		"https://synthetic-private-value@github.com/example/project", "https://github.com:443/example/project",
		"https://github.com/example/project?", "https://github.com/example/project#",
		"https://github.com/example/project?token=synthetic-private-value", "https://github.com/example/project#main",
		"https://github.com/example/project/tree/main", "https://github.com/example/project/",
		"https://github.com/example/../project", "https://github.com/example/%70roject",
		"https://github.com/example/.", "https://github.com/example/..", "https://github.com/example",
		" https://github.com/example/project", "https://github.com/example/project ",
	} {
		tests = append(tests, requestValidationCase{"invalid-repository", func(_ *Client, r *Request) { r.Repository = repository }})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			c := scriptedClient(t)
			request := syntheticRequest()
			test.mutate(&c, &request)
			result, err := c.Generate(t.Context(), request)
			if err == nil || result.TaskName != request.TaskName || result.Output != "" {
				t.Fatal("invalid input must fail before making any request")
			}
			if strings.Contains(err.Error(), "synthetic-private-value") || strings.Contains(err.Error(), syntheticRequest().Prompt) {
				t.Error("validation error exposed input content")
			}
		})
	}
}

func TestGenerateAcceptsContractBoundaries(t *testing.T) {
	for _, turns := range []int32{0, 1, 1000} {
		t.Run("max-turns", func(t *testing.T) {
			t.Parallel()
			request := syntheticRequest()
			request.MaxTurns = turns
			request.Repository += ".git"
			request.Commit = strings.Repeat("b", 64)
			request.Prompt = strings.Repeat("x", maxPromptBytes)
			task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
			c := scriptedClient(t, taskStep(t, task), resultStep(http.StatusOK, `{"result":"bounded"}`), taskStep(t, task))
			if _, err := c.Generate(t.Context(), request); err != nil {
				t.Fatal(err)
			}
		})
	}
}
