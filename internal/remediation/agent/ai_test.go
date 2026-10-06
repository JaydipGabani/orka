package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/cli/client"
	"github.com/orka-agents/orka/internal/controller"
	"github.com/orka-agents/orka/internal/workerenv"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func syntheticAIRequest() Request {
	request := syntheticRequest()
	request.Repository, request.Commit = "", ""
	return request
}

func syntheticAITask(request Request, phase corev1alpha1.TaskPhase) corev1alpha1.Task {
	task := syntheticTask(request, phase)
	task.Spec.Type = corev1alpha1.TaskTypeAI
	task.Spec.AgentRuntime = nil
	return task
}

func scriptedNativeClient(t *testing.T, steps ...responseStep) Client {
	t.Helper()
	identity := responseStep{
		method: http.MethodGet, whoami: true, status: http.StatusOK,
		body: `{"authenticated":true,"authType":"tokenReview","username":"system:serviceaccount:remediation-tests:synthetic-caller","uid":"synthetic-caller-uid","namespace":"remediation-tests","subject":"","issuer":"","email":"","groups":["system:authenticated"],"roles":null}`,
	}
	c := scriptedClient(t, append([]responseStep{identity}, steps...)...)
	c.TaskType = "ai"
	return c
}

func TestGenerateNativeAIWireAndWorkerConfiguration(t *testing.T) {
	t.Parallel()
	request := syntheticAIRequest()
	request.Prompt = "Propose JSON using only this synthetic pinned source packet: commit " +
		strings.Repeat("a", 40) + ", file example.txt: synthetic contents."
	created := syntheticAITask(request, "")
	running := syntheticAITask(request, corev1alpha1.TaskPhaseRunning)
	finished := syntheticAITask(request, corev1alpha1.TaskPhaseSucceeded)
	output := `{"summary":"` + strings.Repeat("synthetic ", 1024) + `","checks":[]}`
	createdBody := encodeFixture(t, created)
	requestBody := make(chan []byte, 1)
	c := scriptedNativeClient(t,
		responseStep{method: http.MethodGet, status: http.StatusNotFound},
		responseStep{method: http.MethodPost, serve: func(w http.ResponseWriter, r *http.Request) {
			data, err := io.ReadAll(io.LimitReader(r.Body, maxResponseBytes+1))
			if err != nil {
				t.Error("cannot read synthetic native AI request")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("native AI request did not declare JSON")
			}
			requestBody <- data
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, createdBody)
		}},
		taskStep(t, running),
		taskStep(t, finished),
		resultStep(http.StatusOK, encodeFixture(t, client.TaskResultResponse{Result: output})),
		taskStep(t, finished),
	)
	result, err := c.Generate(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result != (Result{TaskName: request.TaskName, TaskUID: string(created.UID), Output: output}) {
		t.Fatal("native AI did not preserve the Task identity and complete result string")
	}

	data := <-requestBody
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal("native AI request is not valid JSON")
	}
	want := map[string]json.RawMessage{
		"name":      json.RawMessage(encodeFixture(t, request.TaskName)),
		"namespace": json.RawMessage(`"remediation-tests"`),
		"type":      json.RawMessage(`"ai"`),
		"prompt":    json.RawMessage(encodeFixture(t, request.Prompt)),
		"timeout":   json.RawMessage(`"15m0s"`),
		"agentRef":  json.RawMessage(`{"name":"proposal-agent"}`),
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatal("native AI wire request must contain only name, namespace, type, prompt, timeout, and AgentRef")
	}

	// Exercise the existing native worker renderer with the actual emitted
	// request, without starting a worker, reading source, or calling a provider.
	task := &corev1alpha1.Task{ObjectMeta: created.ObjectMeta}
	if err := json.Unmarshal(data, &task.Spec); err != nil {
		t.Fatal("native AI request does not decode into the production Task spec")
	}
	maxTokens := int32(8192)
	provider := &corev1alpha1.Provider{
		ObjectMeta: metav1.ObjectMeta{Name: "synthetic-provider", Namespace: task.Namespace},
		Spec: corev1alpha1.ProviderSpec{
			Type: corev1alpha1.ProviderTypeOpenAI, DefaultModel: "synthetic-provider-default",
			BaseURL: "http://127.0.0.1/synthetic-native-provider",
		},
	}
	registered := &corev1alpha1.Agent{
		ObjectMeta: metav1.ObjectMeta{Name: c.AgentName, Namespace: task.Namespace},
		Spec: corev1alpha1.AgentSpec{
			ProviderRef: &corev1alpha1.ProviderReference{Name: provider.Name},
			Model:       &corev1alpha1.ModelConfig{Name: "synthetic-json-model", MaxTokens: &maxTokens},
		},
	}
	scheme := runtime.NewScheme()
	if err := corev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	builder := controller.NewJobBuilder(fake.NewClientBuilder().WithScheme(scheme).Build())
	builder.AIWorkerImage = "example.invalid/synthetic-native-worker"
	builder.ControllerURL = "http://127.0.0.1/synthetic-controller"
	job, err := builder.Build(t.Context(), task, registered, provider)
	if err != nil {
		t.Fatalf("native worker renderer rejected the AI request: %v", err)
	}
	if len(job.Spec.Template.Spec.Containers) != 1 || len(job.Spec.Template.Spec.InitContainers) != 0 {
		t.Fatal("source-free native AI must render exactly one worker and no source initializer")
	}
	worker := job.Spec.Template.Spec.Containers[0]
	if worker.Image != builder.AIWorkerImage || !reflect.DeepEqual(worker.Command, []string{"/worker"}) ||
		!reflect.DeepEqual(worker.Args, []string{"--mode=ai"}) {
		t.Fatal("native AI request did not select the existing native worker")
	}
	env := make(map[string]string, len(worker.Env))
	for _, variable := range worker.Env {
		env[variable.Name] = variable.Value
	}
	for key, value := range map[string]string{
		workerenv.AIProvider: string(provider.Spec.Type), workerenv.AIBaseURL: provider.Spec.BaseURL,
		workerenv.AIModel: registered.Spec.Model.Name, workerenv.AIMaxTokens: "8192",
		workerenv.AIPrompt: request.Prompt, workerenv.TaskUID: string(task.UID),
		workerenv.ControllerURL: builder.ControllerURL,
		workerenv.AITools:       "", workerenv.CoordinationEnabled: "", workerenv.AIFallbackCount: "",
	} {
		if env[key] != value {
			t.Errorf("native worker configuration mismatch for %s", key)
		}
	}
	if len(worker.EnvFrom) != 0 || job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 0 ||
		job.Spec.ActiveDeadlineSeconds == nil || *job.Spec.ActiveDeadlineSeconds != 900 {
		t.Fatal("native worker unexpectedly inherited credentials, retries, or an unbounded execution deadline")
	}
}

func TestGenerateNativeAIResumeAndLostAcknowledgement(t *testing.T) {
	for _, acknowledgement := range []string{"existing", "conflict", "ambiguous"} {
		t.Run(acknowledgement, func(t *testing.T) {
			t.Parallel()
			request := syntheticAIRequest()
			task := syntheticAITask(request, corev1alpha1.TaskPhaseSucceeded)
			var steps []responseStep
			if acknowledgement != "existing" {
				status := http.StatusConflict
				if acknowledgement == "ambiguous" {
					status = http.StatusInternalServerError
				}
				steps = append(steps,
					responseStep{method: http.MethodGet, status: http.StatusNotFound},
					responseStep{method: http.MethodPost, status: status},
				)
			}
			steps = append(steps, taskStep(t, task), resultStep(http.StatusOK, `{"result":"{\"synthetic\":true}"}`), taskStep(t, task))
			c := scriptedNativeClient(t, steps...)
			result, err := c.Generate(t.Context(), request)
			if err != nil || result.TaskUID != string(task.UID) || result.Output != `{"synthetic":true}` {
				t.Fatalf("native AI could not resume its exact deterministic Task: %v", err)
			}
		})
	}
}

func TestGenerateRejectsUnknownTypeAndNativeAISource(t *testing.T) {
	tests := []struct {
		name       string
		taskType   string
		repository string
		commit     string
	}{
		{name: "unknown", taskType: "container"},
		{name: "uppercase", taskType: "AI"},
		{name: "whitespace", taskType: " ai"},
		{name: "repository", taskType: "ai", repository: syntheticRequest().Repository},
		{name: "commit", taskType: "ai", commit: syntheticRequest().Commit},
		{name: "source", taskType: "ai", repository: syntheticRequest().Repository, commit: syntheticRequest().Commit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := syntheticAIRequest()
			request.Repository, request.Commit = test.repository, test.commit
			c := scriptedClient(t)
			c.TaskType = test.taskType
			result, err := c.Generate(t.Context(), request)
			if err == nil || result.TaskName != request.TaskName || result.TaskUID != "" || result.Output != "" {
				t.Fatal("invalid mode or native source input must fail before any API request")
			}
		})
	}
}

func TestGenerateNativeAIRejectsDifferentTask(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*corev1alpha1.Task)
	}{
		{"type", func(task *corev1alpha1.Task) { task.Spec.Type = corev1alpha1.TaskTypeAgent }},
		{"prompt", func(task *corev1alpha1.Task) { task.Spec.Prompt = "different synthetic packet" }},
		{"agent", func(task *corev1alpha1.Task) { task.Spec.AgentRef.Name = "different-agent" }},
		{"agent-namespace", func(task *corev1alpha1.Task) { task.Spec.AgentRef.Namespace = "foreign-namespace" }},
		{"namespace", func(task *corev1alpha1.Task) { task.Namespace = "foreign-namespace" }},
		{"workspace", func(task *corev1alpha1.Task) {
			task.Spec.Workspace = &corev1alpha1.WorkspaceConfig{Intent: corev1alpha1.WorkspaceIntentRead}
		}},
		{"runtime", func(task *corev1alpha1.Task) { task.Spec.AgentRuntime = &corev1alpha1.AgentRuntimeSpec{} }},
		{"runtime-tools", func(task *corev1alpha1.Task) {
			allowBash := true
			task.Spec.AgentRuntime = &corev1alpha1.AgentRuntimeSpec{AllowedTools: []string{"Bash", "Write"}, AllowBash: &allowBash}
		}},
		{"ai-override", func(task *corev1alpha1.Task) { task.Spec.AI = &corev1alpha1.AISpec{Model: "unrequested-model"} }},
		{"tools", func(task *corev1alpha1.Task) { task.Spec.AI = &corev1alpha1.AISpec{Tools: []string{"code_exec"}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := syntheticAIRequest()
			task := syntheticAITask(request, corev1alpha1.TaskPhaseSucceeded)
			test.mutate(&task)
			c := scriptedNativeClient(t, taskStep(t, task))
			result, err := c.Generate(t.Context(), request)
			if err == nil || result.TaskUID != "" || result.Output != "" {
				t.Fatal("native AI must not adopt a Task with different identity, mode, source or overrides")
			}
		})
	}
}

func TestGenerateAgentSelectionRemainsExplicit(t *testing.T) {
	for _, selection := range []string{"", "agent"} {
		t.Run("default-or-explicit-agent", func(t *testing.T) {
			t.Parallel()
			request := syntheticAIRequest()
			native := syntheticAITask(request, corev1alpha1.TaskPhaseSucceeded)
			c := scriptedClient(t, taskStep(t, native))
			c.TaskType = selection
			if _, err := c.Generate(t.Context(), request); err == nil {
				t.Fatal("agent mode must not silently adopt a native AI Task")
			}
		})
	}
}

func TestGenerateNativeAIPreservesUIDOnChangeAndCancellation(t *testing.T) {
	for _, failure := range []string{"uid-change", "namespace-change", "cancelled"} {
		t.Run(failure, func(t *testing.T) {
			t.Parallel()
			request := syntheticAIRequest()
			task := syntheticAITask(request, corev1alpha1.TaskPhasePending)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			next := task.DeepCopy()
			next.UID = "different-task-uid"
			if failure == "namespace-change" {
				next.UID = task.UID
				next.Namespace = "foreign-namespace"
			}
			step := taskStep(t, *next)
			if failure == "cancelled" {
				step = responseStep{method: http.MethodGet, serve: func(_ http.ResponseWriter, r *http.Request) {
					cancel()
					<-r.Context().Done()
				}}
			}
			c := scriptedNativeClient(t, taskStep(t, task), step)
			result, err := c.Generate(ctx, request)
			if err == nil || result.TaskUID != string(task.UID) || result.TaskName != request.TaskName || result.Output != "" {
				t.Fatal("native AI failure must retain its original identity without creating a replacement")
			}
			if failure == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatal("native AI cancellation did not preserve the context error")
			}
		})
	}
}

func TestGenerateNativeAIRequiresRealResult(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{"missing-endpoint", http.StatusNotFound, ""},
		{"missing-result", http.StatusOK, `{}`},
		{"empty-result", http.StatusOK, `{"result":""}`},
		{"malformed-result", http.StatusOK, `{"result":{}}`},
		{"no-text-placeholder", http.StatusOK, `{"result":"Prompt completed without textual output."}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := syntheticAIRequest()
			task := syntheticAITask(request, corev1alpha1.TaskPhaseSucceeded)
			c := scriptedNativeClient(t, taskStep(t, task), resultStep(test.status, test.body))
			result, err := c.Generate(t.Context(), request)
			if err == nil || result.TaskUID != string(task.UID) || result.TaskName != request.TaskName || result.Output != "" {
				t.Fatal("native AI must fail for absent output without changing mode or supplying substitute output")
			}
		})
	}
}

func TestPrepareNativeAILimitsDoNotChangeAgentMode(t *testing.T) {
	t.Parallel()
	c := scriptedClient(t)
	request := syntheticAIRequest()
	_, implicit, err := c.prepare(request)
	if err != nil {
		t.Fatal(err)
	}
	c.TaskType = "agent"
	_, explicit, err := c.prepare(request)
	if err != nil || !reflect.DeepEqual(implicit, explicit) {
		t.Fatal("explicit agent selection differs from the default")
	}
	c.TaskType = "ai"
	_, native, err := c.prepare(request)
	if err != nil || native.AgentRuntime != nil || native.AI != nil || native.Workspace != nil {
		t.Fatal("native AI must not encode agent-runtime or provider overrides")
	}
	timeout, err := time.ParseDuration(native.Timeout)
	if err != nil || timeout != 15*time.Minute {
		t.Fatal("native AI lost the bounded Task timeout")
	}
}

func syntheticRequester() *corev1alpha1.RequestedBy {
	return &corev1alpha1.RequestedBy{
		Subject: "synthetic-subject", Issuer: "https://issuer.example.invalid",
		Username: "synthetic-user", Email: "synthetic-user@example.invalid",
		Groups: []string{"synthetic-group"}, Roles: []string{"synthetic-role"},
	}
}

func requesterStep(t *testing.T, authType string, requester *corev1alpha1.RequestedBy) responseStep {
	t.Helper()
	identity := map[string]any{
		"authenticated": true, "authType": authType, "uid": "synthetic-caller-uid", "namespace": "remediation-tests",
		"subject": requester.Subject, "issuer": requester.Issuer, "username": requester.Username,
		"email": requester.Email, "groups": requester.Groups, "roles": requester.Roles,
	}
	if authType == "contextToken" {
		identity["transaction"] = map[string]any{
			"profile": "synthetic", "type": "synthetic-context", "id": "synthetic-transaction",
			"issuer": requester.Issuer, "subject": requester.Subject, "audience": []string{"synthetic-api"},
			"scope": "synthetic-scope", "scopes": []string{"synthetic-scope"}, "requestingWorkload": "synthetic-workload",
		}
	}
	return responseStep{method: http.MethodGet, whoami: true, status: http.StatusOK, body: encodeFixture(t, identity)}
}

func TestGenerateNativeAIMatchesServerOwnedRequester(t *testing.T) {
	for _, authType := range []string{"oidc", "contextToken"} {
		t.Run(authType, func(t *testing.T) {
			t.Parallel()
			request := syntheticAIRequest()
			caller := syntheticRequester()
			caller.Groups, caller.Roles = []string{}, nil
			pending := syntheticAITask(request, corev1alpha1.TaskPhasePending)
			pending.Spec.RequestedBy = caller
			finished := pending.DeepCopy()
			finished.Status.Phase = corev1alpha1.TaskPhaseSucceeded
			finished.Status.ResultRef = &corev1alpha1.ResultReference{Available: true}
			createdBody := encodeFixture(t, pending)
			c := scriptedClient(t,
				requesterStep(t, authType, caller),
				responseStep{method: http.MethodGet, status: http.StatusNotFound},
				responseStep{method: http.MethodPost, serve: func(w http.ResponseWriter, r *http.Request) {
					var body map[string]json.RawMessage
					if err := json.NewDecoder(io.LimitReader(r.Body, maxResponseBytes+1)).Decode(&body); err != nil {
						t.Error("cannot decode synthetic native AI request")
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					if len(body) != 6 || body["requestedBy"] != nil || body["spec"] != nil ||
						body["agentRuntime"] != nil || body["ai"] != nil || body["workspace"] != nil {
						t.Error("native AI create leaked server-owned identity or executable configuration")
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusCreated)
					_, _ = io.WriteString(w, createdBody)
				}},
				taskStep(t, *finished),
				resultStep(http.StatusOK, `{"result":"{\"synthetic\":true}"}`),
				taskStep(t, *finished),
			)
			c.TaskType = "ai"
			result, err := c.Generate(t.Context(), request)
			if err != nil || result.TaskUID != string(pending.UID) || result.Output != `{"synthetic":true}` {
				t.Fatalf("native AI did not preserve the server-owned requester through completion: %v", err)
			}
		})
	}
}

func TestGenerateNativeAIRejectsRequesterMismatch(t *testing.T) {
	for _, stage := range []string{"existing", "poll", "result"} {
		for _, field := range []string{"subject", "issuer", "username", "email", "groups", "roles", "missing"} {
			t.Run(stage+"/"+field, func(t *testing.T) {
				t.Parallel()
				request := syntheticAIRequest()
				caller := syntheticRequester()
				task := syntheticAITask(request, corev1alpha1.TaskPhaseSucceeded)
				task.Spec.RequestedBy = caller
				changed := task.DeepCopy()
				switch field {
				case "subject":
					changed.Spec.RequestedBy.Subject = "other-subject"
				case "issuer":
					changed.Spec.RequestedBy.Issuer = "https://other-issuer.example.invalid"
				case "username":
					changed.Spec.RequestedBy.Username = "other-user"
				case "email":
					changed.Spec.RequestedBy.Email = "other-user@example.invalid"
				case "groups":
					changed.Spec.RequestedBy.Groups = []string{"other-group"}
				case "roles":
					changed.Spec.RequestedBy.Roles = []string{"other-role"}
				default:
					changed.Spec.RequestedBy = nil
				}
				steps := []responseStep{requesterStep(t, "oidc", caller)}
				wantUID := ""
				switch stage {
				case "poll":
					task.Status.Phase = corev1alpha1.TaskPhasePending
					steps = append(steps, taskStep(t, task))
					wantUID = string(task.UID)
				case "result":
					steps = append(steps, taskStep(t, task), resultStep(http.StatusOK, `{"result":"must not escape"}`))
					wantUID = string(task.UID)
				}
				steps = append(steps, taskStep(t, *changed))
				c := scriptedClient(t, steps...)
				c.TaskType = "ai"
				result, err := c.Generate(t.Context(), request)
				if err == nil || result.TaskName != request.TaskName || result.TaskUID != wantUID || result.Output != "" {
					t.Fatal("requester mismatch must fail without adopting or publishing another caller's Task")
				}
				if strings.Contains(err.Error(), caller.Subject) || strings.Contains(err.Error(), caller.Email) {
					t.Error("requester mismatch error exposed identity details")
				}
			})
		}
	}
}

func TestGenerateNativeAIRejectsUnverifiedRequester(t *testing.T) {
	for _, body := range []string{
		`null`, `{}`, `{"authenticated":false}`,
		`{"authenticated":true,"authType":"unsupported"}`,
		`{"authenticated":true,"authType":"oidc","subject":"synthetic"}`,
		`{"authenticated":true,"authType":"contextToken","issuer":"synthetic"}`,
		`{"authenticated":true,"authType":"tokenReview","username":""}`,
		`{"authenticated":true,"authType":"tokenReview","username":42}`,
	} {
		t.Run("identity-shape", func(t *testing.T) {
			t.Parallel()
			c := scriptedClient(t, responseStep{method: http.MethodGet, whoami: true, status: http.StatusOK, body: body})
			c.TaskType = "ai"
			result, err := c.Generate(t.Context(), syntheticAIRequest())
			if err == nil || result.TaskUID != "" || result.Output != "" {
				t.Fatal("unverified requester must not reach Task lookup or creation")
			}
		})
	}
	t.Run("identity-unavailable", func(t *testing.T) {
		t.Parallel()
		c := scriptedClient(t, responseStep{
			method: http.MethodGet, whoami: true, status: http.StatusUnauthorized, body: "synthetic-remote-detail",
		})
		c.TaskType = "ai"
		_, err := c.Generate(t.Context(), syntheticAIRequest())
		if err == nil || strings.Contains(err.Error(), "synthetic-remote-detail") {
			t.Fatal("identity lookup failure must fail closed without exposing the remote body")
		}
	})
	t.Run("token-review-cannot-adopt-oidc-requester", func(t *testing.T) {
		t.Parallel()
		request := syntheticAIRequest()
		task := syntheticAITask(request, corev1alpha1.TaskPhaseSucceeded)
		task.Spec.RequestedBy = syntheticRequester()
		c := scriptedNativeClient(t, taskStep(t, task))
		if _, err := c.Generate(t.Context(), request); err == nil {
			t.Fatal("TokenReview must not adopt a Task attributed to an OIDC or context-token requester")
		}
	})
}
