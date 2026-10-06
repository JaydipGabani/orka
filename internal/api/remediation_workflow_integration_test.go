package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubefake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	remediationservice "github.com/orka-agents/orka/internal/remediation/service"
	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/store/sqlite"
)

const (
	workflowNamespace = "remediation-fixture"
	workflowUsername  = "system:serviceaccount:remediation-fixture:operator"
	workflowOriginal  = "enabled=false\n"
	workflowCorrected = "enabled=true\n"
	workflowPatch     = "--- a/fixture.txt\n+++ b/fixture.txt\n@@ -1 +1 @@\n-enabled=false\n+enabled=true\n"
	workflowReport    = `{"title":"Synthetic integration fixture","problem":"A fixture flag is disabled","restricted":false}`
)

// This is a synthetic Processor, not the production Pipeline or a claim of real
// remediation. Only HTTP, CLI, authorization wiring, and durable service/storage
// behavior are under test. No fixture uses a cluster, model, or source network.
type workflowSource struct{ reads atomic.Int32 }

func (s *workflowSource) snapshot() []byte {
	s.reads.Add(1)
	return []byte(workflowOriginal)
}

type workflowModel struct {
	calls   atomic.Int32
	invalid bool
}

func (m *workflowModel) propose(original []byte) ([]byte, error) {
	m.calls.Add(1)
	if string(original) != workflowOriginal {
		return nil, errors.New("synthetic source identity changed")
	}
	if m.invalid {
		return []byte(`{"unexpected":"not a patch"}`), nil
	}
	return []byte(workflowPatch), nil
}

type workflowExecution struct{ calls atomic.Int32 }

func (e *workflowExecution) check(source []byte) bool {
	e.calls.Add(1)
	return string(source) == workflowCorrected
}

type workflowProcessor struct {
	source          workflowSource
	model           workflowModel
	execution       workflowExecution
	requireApproval bool
	pause           error
	prepared        chan struct{}
	holdPrepared    bool
	executing       chan struct{}
	release         chan struct{}
	lateSuccess     chan error
	cleaned         atomic.Int32
}

type workflowState struct {
	Stage      string `json:"stage"`
	PlanDigest string `json:"planDigest"`
}

func newWorkflowProcessor() *workflowProcessor {
	return &workflowProcessor{
		requireApproval: true, prepared: make(chan struct{}, 1),
		executing: make(chan struct{}, 1),
	}
}

func (p *workflowProcessor) Run(ctx context.Context, session *remediationservice.Session) error {
	current, err := session.Current(ctx)
	if err != nil {
		return err
	}
	var state workflowState
	if err := json.Unmarshal(current.StateJSON, &state); err != nil {
		return err
	}
	if state.Stage == "" {
		state, err = p.prepare(ctx, session, current)
		if err != nil {
			return err
		}
		if p.holdPrepared {
			<-ctx.Done()
			return ctx.Err()
		}
	}
	if state.Stage != "fixture-plan" {
		return errors.New("unknown synthetic processor stage")
	}
	if p.pause != nil {
		return p.pause
	}
	if p.requireApproval && current.ApprovedDigest != state.PlanDigest {
		if err := session.Checkpoint(ctx, store.RemediationPhaseNeedsApproval, "synthetic-plan-approval", nil, state.PlanDigest); err != nil {
			return err
		}
		return remediationservice.ErrAwaitApproval
	}
	return p.execute(ctx, session)
}

func (p *workflowProcessor) prepare(ctx context.Context, session *remediationservice.Session, current *store.RemediationRun) (workflowState, error) {
	var request remediationservice.StoredRequest
	if err := json.Unmarshal(current.RequestJSON, &request); err != nil {
		return workflowState{}, err
	}
	if request.Report == nil || request.Report.Title != "Synthetic integration fixture" {
		return workflowState{}, errors.New("unexpected synthetic report")
	}
	original, err := session.Put(ctx, "fixture-source.txt", "text/plain", p.source.snapshot())
	if err != nil {
		return workflowState{}, err
	}
	plan, err := json.Marshal(struct {
		Synthetic    bool   `json:"synthetic"`
		SourceDigest string `json:"sourceDigest"`
	}{true, original.Digest})
	if err != nil {
		return workflowState{}, err
	}
	artifact, err := session.Put(ctx, "fixture-plan.json", "application/json", plan)
	if err != nil {
		return workflowState{}, err
	}
	state := workflowState{Stage: "fixture-plan", PlanDigest: artifact.Digest}
	raw, err := json.Marshal(state)
	if err != nil {
		return workflowState{}, err
	}
	if err := session.Checkpoint(ctx, store.RemediationPhaseRunning, "", raw, ""); err != nil {
		return workflowState{}, err
	}
	p.prepared <- struct{}{}
	return state, nil
}

func (p *workflowProcessor) execute(ctx context.Context, session *remediationservice.Session) error {
	_, original, err := session.Read(ctx, "fixture-source.txt")
	if err != nil {
		return err
	}
	patch, err := p.model.propose(original)
	if err != nil {
		return err
	}
	if string(patch) != workflowPatch {
		return errors.New("invalid synthetic model output")
	}
	if p.execution.check(original) || !p.execution.check([]byte(workflowCorrected)) {
		return errors.New("synthetic checks lack a discriminating baseline and control")
	}
	p.executing <- struct{}{}
	if p.release != nil {
		select {
		case <-p.release:
		case <-ctx.Done():
		}
		// Simulate a successful external result arriving after cancellation,
		// even if the monitor notices cancellation before the CLI returns.
		err := session.Checkpoint(context.WithoutCancel(ctx), store.RemediationPhaseSucceeded, "", nil, "")
		p.lateSuccess <- err
		return err
	}
	if !p.execution.check([]byte(workflowCorrected)) {
		return errors.New("synthetic candidate failed")
	}
	for _, artifact := range []struct {
		name, mediaType string
		content         []byte
	}{
		{"result.patch", "text/x-patch", patch},
		{"fixture-bytes.txt", "text/plain", workflowBinary()},
		{"evidence.json", "application/json", []byte(`{"synthetic":true,"baseline":false,"control":true,"candidate":true,"realWorldVerified":false}`)},
	} {
		if _, err := session.Put(ctx, artifact.name, artifact.mediaType, artifact.content); err != nil {
			return err
		}
	}
	return session.Checkpoint(ctx, store.RemediationPhaseSucceeded, "", json.RawMessage(`{"stage":"fixture-complete"}`), "")
}

func (p *workflowProcessor) Cancel(context.Context, *remediationservice.Session) error {
	p.cleaned.Add(1)
	return nil
}

func workflowBinary() []byte {
	return []byte{'f', 'i', 'x', 't', 'u', 'r', 'e', 0, 0xc3, 0xa9, '\r', '\n'}
}

type workflowHTTPRecord struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Namespace string `json:"namespace"`
	Code      int    `json:"code"`
}

type workflowCLIRecord struct {
	Arguments []string                    `json:"arguments"`
	ExitCode  int                         `json:"exitCode"`
	Statuses  []remediationservice.Status `json:"statuses,omitempty"`
}

type workflowFixture struct {
	t          *testing.T
	directory  string
	binary     string
	database   *sql.DB
	storage    *sqlite.Store
	service    *remediationservice.Service
	processor  *workflowProcessor
	server     *Server
	proxy      *httptest.Server
	endpoint   string
	serveDone  chan error
	workerEnd  chan error
	cancel     context.CancelFunc
	kube       client.Client
	clientset  *kubefake.Clientset
	mu         sync.Mutex
	actors     map[string]authenticationv1.UserInfo
	reviews    []authorizationv1.SubjectAccessReviewSpec
	http       []workflowHTTPRecord
	commands   []workflowCLIRecord
	unexpected atomic.Int32
}

func newWorkflowFixture(t *testing.T, processor *workflowProcessor) *workflowFixture {
	t.Helper()
	binary := os.Getenv("ORKA_REMEDIATION_CLI")
	if binary == "" {
		var err error
		binary, err = filepath.Abs("../../bin/orka-autonomous")
		require.NoError(t, err)
		if _, err := os.Stat(binary); errors.Is(err, os.ErrNotExist) {
			t.Skip("build bin/orka-autonomous with go build -o bin/orka-autonomous ./cmd/cli, or set ORKA_REMEDIATION_CLI")
		}
	}
	require.True(t, filepath.IsAbs(binary), "ORKA_REMEDIATION_CLI must be absolute")
	require.FileExists(t, binary)
	// Do not inherit TMPDIR/HOME from the runner: reports and synthetic tokens
	// must remain outside the checkout and never touch a real kubeconfig.
	directory, err := os.MkdirTemp("/tmp", "orka-api-workflow-")
	require.NoError(t, err)
	f := &workflowFixture{t: t, binary: binary, directory: directory, actors: make(map[string]authenticationv1.UserInfo)}
	t.Cleanup(func() {
		f.stop()
		f.writeEvidence()
		require.NoError(t, os.RemoveAll(directory))
		require.Zero(t, f.unexpected.Load(), "fixture attempted an unexpected Kubernetes operation")
	})
	f.configureAuthorization()
	f.open(processor)
	return f
}

func (f *workflowFixture) configureAuthorization() {
	scheme := runtime.NewScheme()
	require.NoError(f.t, authenticationv1.AddToScheme(scheme))
	f.kube = fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, object client.Object, _ ...client.CreateOption) error {
			review, ok := object.(*authenticationv1.TokenReview)
			if !ok {
				f.unexpected.Add(1)
				return errors.New("only synthetic TokenReviews are allowed")
			}
			f.mu.Lock()
			actor, found := f.actors[review.Spec.Token]
			f.mu.Unlock()
			review.Status = authenticationv1.TokenReviewStatus{Authenticated: found, User: actor}
			return nil
		},
	}).Build()
	f.clientset = kubefake.NewClientset(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "operator", Namespace: workflowNamespace, UID: "uid-1"},
	})
	f.clientset.PrependReactor("*", "*", func(action k8stesting.Action) (bool, runtime.Object, error) {
		if action.GetVerb() == "get" && action.GetResource().Resource == "serviceaccounts" && action.GetNamespace() == workflowNamespace {
			return false, nil, nil
		}
		created, ok := action.(k8stesting.CreateAction)
		if !ok || action.GetResource().Resource != "subjectaccessreviews" {
			f.unexpected.Add(1)
			return true, nil, errors.New("only synthetic authorization operations are allowed")
		}
		review, ok := created.GetObject().(*authorizationv1.SubjectAccessReview)
		if !ok {
			return true, nil, errors.New("invalid synthetic authorization object")
		}
		f.mu.Lock()
		f.reviews = append(f.reviews, *review.Spec.DeepCopy())
		f.mu.Unlock()
		attributes := review.Spec.ResourceAttributes
		if attributes != nil && attributes.Namespace == workflowNamespace && attributes.Group == "core.orka.ai" &&
			review.Spec.User == workflowUsername && review.Spec.UID != "" &&
			slices.Contains(review.Spec.Groups, "fixture:operators") {
			switch attributes.Resource {
			case "remediations":
				review.Status.Allowed = attributes.Verb == "create" || attributes.Verb == "get" || attributes.Verb == "update"
				if attributes.Subresource == "artifacts" && slices.Contains(review.Spec.Groups, "fixture:no-artifacts") {
					review.Status.Allowed = false
				}
			case "remediationpolicies":
				review.Status.Allowed = attributes.Verb == "use" && attributes.Name == "synthetic"
			}
		}
		return true, review, nil
	})
}

func (f *workflowFixture) open(processor *workflowProcessor) {
	f.t.Helper()
	f.processor = processor
	path := filepath.Join(f.directory, "service.db")
	var err error
	f.database, err = sqlite.NewDB(path)
	require.NoError(f.t, err)
	f.storage = sqlite.NewStore(f.database, path)
	cipher, err := sqlite.NewAgentExecutionSnapshotCipher(bytes.Repeat([]byte{'s'}, 32))
	require.NoError(f.t, err)
	require.NoError(f.t, f.storage.SetAgentExecutionSnapshotCipher(cipher))
	f.service, err = remediationservice.New(f.t.Context(), remediationservice.Config{
		Namespace: workflowNamespace, Store: f.storage, Processor: processor,
		Interval: 20 * time.Millisecond, Lease: 900 * time.Millisecond, Workers: 1,
		Authorize: remediationservice.KubernetesAuthorizer(f.clientset),
		Policies: []remediationservice.Policy{{
			Version: 1, Name: "synthetic", Namespace: workflowNamespace, AgentName: "fixture-only",
			Repositories: []string{"https://github.com/example/synthetic-fixture"},
			Adapters: []remediationservice.AdapterPolicy{{
				Name: "synthetic", Kind: "http-workload",
				Repositories:  []string{"https://github.com/example/synthetic-fixture"},
				Configuration: json.RawMessage(`{"synthetic":true}`),
			}},
			MaxDurationSeconds: 120, MaxCandidates: 1, MaxModelCalls: 3,
			RequirePlanApproval: processor.requireApproval,
		}},
	})
	require.NoError(f.t, err)
	f.server = NewServer(f.kube, nil, ServerConfig{
		WatchNamespace: workflowNamespace, EnforceNamespaceIsolation: true,
		Clientset: f.clientset, APIReader: f.kube, RemediationService: f.service,
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(f.t, err)
	f.serveDone = make(chan error, 1)
	go func() {
		f.serveDone <- f.server.app.Listener(listener, fiber.ListenConfig{DisableStartupMessage: true})
	}()
	target, err := url.Parse("http://" + listener.Addr().String())
	require.NoError(f.t, err)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(response *http.Response) error {
		f.mu.Lock()
		f.http = append(f.http, workflowHTTPRecord{
			Method: response.Request.Method, Path: response.Request.URL.Path,
			Namespace: response.Request.URL.Query().Get("namespace"), Code: response.StatusCode,
		})
		f.mu.Unlock()
		return nil
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "synthetic loopback transport failed", http.StatusBadGateway)
	}
	f.proxy = httptest.NewServer(proxy)
	f.endpoint = f.proxy.URL
	httpClient := &http.Client{Timeout: time.Second}
	require.Eventually(f.t, func() bool {
		response, err := httpClient.Get(f.endpoint + "/healthz")
		if err != nil {
			return false
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		return response.StatusCode == http.StatusOK && readErr == nil && closeErr == nil
	}, 5*time.Second, 20*time.Millisecond, "real HTTP listener did not become healthy")
	httpClient.CloseIdleConnections()
}

func (f *workflowFixture) startWorker() {
	f.t.Helper()
	require.Nil(f.t, f.cancel)
	ctx, cancel := context.WithCancel(f.t.Context())
	f.cancel = cancel
	f.workerEnd = make(chan error, 1)
	go func() { f.workerEnd <- f.service.Start(ctx) }()
}

func (f *workflowFixture) stop() {
	f.t.Helper()
	if f.cancel != nil {
		f.cancel()
		select {
		case err := <-f.workerEnd:
			require.NoError(f.t, err)
		case <-time.After(5 * time.Second):
			f.t.Fatal("synthetic service worker did not stop")
		}
		f.cancel = nil
	}
	if f.proxy != nil {
		f.proxy.Close()
		f.proxy = nil
	}
	if f.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := f.server.app.ShutdownWithContext(ctx)
		cancel()
		require.NoError(f.t, err)
		require.NoError(f.t, <-f.serveDone)
		f.server = nil
	}
	if f.database != nil {
		require.NoError(f.t, f.database.Close())
		f.database = nil
	}
}

func (f *workflowFixture) writeEvidence() {
	directory := os.Getenv("ORKA_REMEDIATION_EVIDENCE_DIR")
	if directory == "" {
		return
	}
	require.True(f.t, filepath.IsAbs(directory))
	info, err := os.Stat(directory)
	require.NoError(f.t, err)
	require.Equal(f.t, os.FileMode(0o700), info.Mode().Perm())
	binary, err := os.ReadFile(f.binary)
	require.NoError(f.t, err)
	hash := sha256.Sum256(binary)
	f.mu.Lock()
	data, err := json.MarshalIndent(struct {
		Test      string                                    `json:"test"`
		Failed    bool                                      `json:"failed"`
		Synthetic bool                                      `json:"synthetic"`
		CLI       string                                    `json:"cli"`
		CLISHA256 string                                    `json:"cliSHA256"`
		Commands  []workflowCLIRecord                       `json:"commands"`
		HTTP      []workflowHTTPRecord                      `json:"http"`
		Reviews   []authorizationv1.SubjectAccessReviewSpec `json:"syntheticReviews"`
	}{f.t.Name(), f.t.Failed(), true, f.binary, hex.EncodeToString(hash[:]), f.commands, f.http, f.reviews}, "", "  ")
	f.mu.Unlock()
	require.NoError(f.t, err)
	name := strings.ReplaceAll(f.t.Name(), "/", "-") + ".json"
	require.NoError(f.t, os.WriteFile(filepath.Join(directory, name), data, 0o600))
}

type workflowActor struct {
	fixture   *workflowFixture
	directory string
	tokenFile string
	token     string
	report    string
}

func (f *workflowFixture) actor(uid string, groups ...string) *workflowActor {
	f.t.Helper()
	directory, err := os.MkdirTemp(f.directory, "client-")
	require.NoError(f.t, err)
	entropy := make([]byte, 32)
	_, err = rand.Read(entropy)
	require.NoError(f.t, err)
	actor := &workflowActor{fixture: f, directory: directory, token: hex.EncodeToString(entropy)}
	actor.tokenFile = filepath.Join(directory, "synthetic-token")
	actor.report = filepath.Join(directory, "report.json")
	require.NoError(f.t, os.WriteFile(actor.tokenFile, []byte(actor.token), 0o600))
	require.NoError(f.t, os.WriteFile(actor.report, []byte(workflowReport), 0o600))
	require.NoError(f.t, os.WriteFile(filepath.Join(directory, "kubeconfig"), []byte("apiVersion: v1\nkind: Config\n"), 0o600))
	f.mu.Lock()
	f.actors[actor.token] = authenticationv1.UserInfo{Username: workflowUsername, UID: uid, Groups: slices.Clone(groups)}
	f.mu.Unlock()
	return actor
}

type workflowCLIResult struct {
	out, stderr string
	err         error
	statuses    []remediationservice.Status
}

func (a *workflowActor) cli(namespace string, arguments ...string) workflowCLIResult {
	a.fixture.t.Helper()
	ctx, cancel := context.WithTimeout(a.fixture.t.Context(), 15*time.Second)
	defer cancel()
	flags := make([]string, 0, 9+len(arguments))
	flags = append(flags, "--server", a.fixture.endpoint, "--namespace", namespace, "--kubeconfig", filepath.Join(a.directory, "kubeconfig"),
		"remediate")
	flags = append(flags, arguments...)
	flags = append(flags, "--token-file", a.tokenFile)
	command := exec.CommandContext(ctx, a.fixture.binary, flags...)
	command.Dir = a.directory
	command.Env = []string{
		"HOME=" + a.directory, "XDG_CONFIG_HOME=" + a.directory, "XDG_CACHE_HOME=" + a.directory,
		"KUBECONFIG=" + filepath.Join(a.directory, "kubeconfig"), "TMPDIR=" + a.directory,
		"PATH=" + a.directory, "NO_PROXY=127.0.0.1,localhost",
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	require.NoError(a.fixture.t, ctx.Err(), "CLI exceeded bounded execution time")
	require.False(a.fixture.t, bytes.Contains(stdout.Bytes(), []byte(a.token)), "CLI exposed synthetic authentication")
	require.False(a.fixture.t, bytes.Contains(stderr.Bytes(), []byte(a.token)), "CLI exposed synthetic authentication")
	result := workflowCLIResult{out: stdout.String(), stderr: stderr.String(), err: err}
	decoder := json.NewDecoder(&stdout)
	for {
		var status remediationservice.Status
		decodeErr := decoder.Decode(&status)
		if errors.Is(decodeErr, io.EOF) {
			break
		}
		require.NoError(a.fixture.t, decodeErr, "CLI stdout must be status JSON, never report/source content")
		require.NotEmpty(a.fixture.t, status.ID)
		require.Equal(a.fixture.t, namespace, status.Namespace)
		require.Positive(a.fixture.t, status.Revision)
		result.statuses = append(result.statuses, status)
	}
	require.NotNil(a.fixture.t, command.ProcessState, "CLI could not start")
	a.fixture.mu.Lock()
	a.fixture.commands = append(a.fixture.commands, workflowCLIRecord{
		Arguments: flags, ExitCode: command.ProcessState.ExitCode(), Statuses: result.statuses,
	})
	a.fixture.mu.Unlock()
	return result
}

func (r workflowCLIResult) success(t *testing.T) remediationservice.Status {
	t.Helper()
	require.NoError(t, r.err, r.stderr)
	require.Len(t, r.statuses, 1)
	return r.statuses[0]
}

func (a *workflowActor) start(requestID string, extra ...string) workflowCLIResult {
	return a.cli(workflowNamespace, append([]string{"start", "--input", a.report, "--request-id", requestID}, extra...)...)
}

func (a *workflowActor) status(id string) remediationservice.Status {
	return a.cli(workflowNamespace, "status", id).success(a.fixture.t)
}

func (a *workflowActor) await(id, phase string) remediationservice.Status {
	a.fixture.t.Helper()
	var status remediationservice.Status
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		status = a.status(id)
		if status.Phase == phase {
			return status
		}
		require.False(a.fixture.t, store.IsRemediationTerminalPhase(status.Phase), "unexpected terminal phase: %s", status.Phase)
		time.Sleep(30 * time.Millisecond)
	}
	a.fixture.t.Fatalf("run did not reach %s; last phase %s", phase, status.Phase)
	return status
}

func (a *workflowActor) getArtifact(id, name, namespace string) (int, http.Header, []byte) {
	a.fixture.t.Helper()
	request, err := http.NewRequestWithContext(a.fixture.t.Context(), http.MethodGet,
		a.fixture.endpoint+"/api/v1/remediations/"+id+"/artifacts/"+name+"?namespace="+url.QueryEscape(namespace), nil)
	require.NoError(a.fixture.t, err)
	request.Header.Set("Authorization", "Bearer "+a.token)
	httpClient := &http.Client{Timeout: 5 * time.Second}
	defer httpClient.CloseIdleConnections()
	response, err := httpClient.Do(request)
	require.NoError(a.fixture.t, err)
	content, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	require.NoError(a.fixture.t, readErr)
	require.NoError(a.fixture.t, closeErr)
	require.False(a.fixture.t, bytes.Contains(content, []byte(a.token)), "HTTP exposed synthetic authentication")
	return response.StatusCode, response.Header, content
}

func (f *workflowFixture) requireHTTP(method, path string, code int) {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.True(f.t, slices.ContainsFunc(f.http, func(record workflowHTTPRecord) bool {
		return record.Method == method && record.Path == path && record.Code == code
	}), "missing observed HTTP %s %s -> %d", method, path, code)
}

func TestRemediationWorkflowCLIRecoveryApprovalAndDownload(t *testing.T) {
	before := newWorkflowProcessor()
	before.holdPrepared = true
	f := newWorkflowFixture(t, before)
	actor := f.actor("uid-1", "fixture:operators", "system:authenticated")
	queued := actor.start("disconnect-restart").success(t)
	require.Equal(t, store.RemediationPhaseQueued, queued.Phase)
	require.EqualValues(t, 1, queued.Revision)
	f.requireHTTP(http.MethodPost, "/api/v1/remediations", http.StatusAccepted)

	// The start subprocess is already gone before any worker exists.
	f.startWorker()
	select {
	case <-before.prepared:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not persist its first stage after the CLI exited")
	}
	running := actor.status(queued.ID)
	require.Equal(t, store.RemediationPhaseRunning, running.Phase)
	require.Equal(t, "fixture-plan", running.Stage)
	require.Greater(t, running.Revision, queued.Revision)
	f.requireHTTP(http.MethodGet, "/api/v1/remediations/"+queued.ID, http.StatusOK)
	oldRun, err := f.storage.GetRemediationRun(t.Context(), workflowNamespace, queued.ID)
	require.NoError(t, err)
	require.NotEmpty(t, oldRun.ClaimOwner)
	require.Positive(t, oldRun.ClaimEpoch)
	f.stop()
	after := newWorkflowProcessor()
	f.open(after)
	f.startWorker()
	paused := actor.await(queued.ID, store.RemediationPhaseNeedsApproval)
	require.Equal(t, running.Artifacts, paused.Artifacts)
	require.Greater(t, paused.Revision, running.Revision)
	require.EqualValues(t, 1, before.source.reads.Load())
	require.Zero(t, after.source.reads.Load(), "restart repeated the durable source stage")
	require.Zero(t, after.model.calls.Load(), "model ran before approval")
	recovered, err := f.storage.GetRemediationRun(t.Context(), workflowNamespace, queued.ID)
	require.NoError(t, err)
	require.Greater(t, recovered.ClaimEpoch, oldRun.ClaimEpoch)
	require.False(t, recovered.CancelRequested)

	replay := actor.start("disconnect-restart").success(t)
	require.Equal(t, paused.ID, replay.ID)
	require.Equal(t, paused.Revision, replay.Revision)
	require.Equal(t, store.RemediationPhaseNeedsApproval, replay.Phase)
	require.NoError(t, os.WriteFile(actor.report, []byte(strings.Replace(workflowReport, "disabled", "changed", 1)), 0o600))
	conflict := actor.start("disconnect-restart")
	require.Error(t, conflict.err)
	require.Empty(t, conflict.statuses)
	f.requireHTTP(http.MethodPost, "/api/v1/remediations", http.StatusConflict)
	require.Equal(t, replay.Revision, actor.status(queued.ID).Revision)

	wrong := actor.cli(workflowNamespace, "approve", queued.ID, "--plan-digest", remediationservice.Digest([]byte("wrong synthetic plan")))
	require.Error(t, wrong.err)
	f.requireHTTP(http.MethodPost, "/api/v1/remediations/"+queued.ID+"/approve", http.StatusConflict)
	require.Equal(t, paused.Revision, actor.status(queued.ID).Revision)
	approved := actor.cli(workflowNamespace, "approve", queued.ID, "--plan-digest", paused.ApprovalDigest).success(t)
	require.Greater(t, approved.Revision, paused.Revision)
	complete := actor.await(queued.ID, store.RemediationPhaseSucceeded)
	require.EqualValues(t, 1, after.model.calls.Load())
	require.EqualValues(t, 3, after.execution.calls.Load())
	require.Greater(t, complete.Revision, paused.Revision)
	f.requireHTTP(http.MethodPost, "/api/v1/remediations/"+queued.ID+"/approve", http.StatusAccepted)
	verifyWorkflowDownload(t, actor, complete)
	verifyWorkflowDownloadPaths(t, actor, complete)
	verifyWorkflowArtifactAuthorization(t, f, actor, complete)
}

func verifyWorkflowDownload(t *testing.T, actor *workflowActor, status remediationservice.Status) {
	t.Helper()
	output := filepath.Join(actor.directory, "download")
	downloaded := actor.cli(workflowNamespace, "download", status.ID, "--output-dir", output).success(t)
	require.Equal(t, status.Revision, downloaded.Revision)
	require.Equal(t, status.Artifacts, downloaded.Artifacts)
	info, err := os.Stat(output)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	for _, artifact := range downloaded.Artifacts {
		content, err := os.ReadFile(filepath.Join(output, artifact.Name))
		require.NoError(t, err)
		info, err := os.Stat(filepath.Join(output, artifact.Name))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		digest := sha256.Sum256(content)
		require.Equal(t, artifact.Digest, "sha256:"+hex.EncodeToString(digest[:]))
		require.Equal(t, artifact.Size, int64(len(content)))
	}
	binary, err := os.ReadFile(filepath.Join(output, "fixture-bytes.txt"))
	require.NoError(t, err)
	require.Equal(t, workflowBinary(), binary)
	patch, err := os.ReadFile(filepath.Join(output, "result.patch"))
	require.NoError(t, err)
	require.Equal(t, workflowPatch, string(patch))
	code, headers, body := actor.getArtifact(status.ID, "fixture-bytes.txt", workflowNamespace)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, workflowBinary(), body)
	hash := sha256.Sum256(body)
	require.Equal(t, "sha-256="+base64.StdEncoding.EncodeToString(hash[:]), headers.Get("Digest"))
	require.Equal(t, strconv.Itoa(len(body)), headers.Get("Content-Length"))
	require.Equal(t, "private, no-store", headers.Get("Cache-Control"))
	require.Equal(t, "nosniff", headers.Get("X-Content-Type-Options"))
	code, _, body = actor.getArtifact(status.ID, "result.patch", workflowNamespace)
	require.Equal(t, http.StatusOK, code)
	require.Equal(t, workflowPatch, string(body))
}

func verifyWorkflowDownloadPaths(t *testing.T, actor *workflowActor, status remediationservice.Status) {
	t.Helper()
	target := filepath.Join(actor.directory, "outside")
	require.NoError(t, os.Mkdir(target, 0o700))
	symlink := filepath.Join(actor.directory, "symlink")
	require.NoError(t, os.Symlink(target, symlink))
	existing := filepath.Join(actor.directory, "download")
	for _, output := range []string{
		symlink, filepath.Join(symlink, "child"), actor.directory + "/../escaped",
		filepath.Join(actor.directory, "unused") + "/../escaped", existing,
	} {
		result := actor.cli(workflowNamespace, "download", status.ID, "--output-dir", output)
		require.Error(t, result.err, "unsafe output path accepted")
		require.Empty(t, result.statuses)
	}
	files, err := os.ReadDir(target)
	require.NoError(t, err)
	require.Empty(t, files, "symlink target was modified")
	require.NoDirExists(t, filepath.Join(actor.directory, "escaped"))
	require.NoDirExists(t, filepath.Join(filepath.Dir(actor.directory), "escaped"))
	content, err := os.ReadFile(filepath.Join(existing, "fixture-bytes.txt"))
	require.NoError(t, err)
	require.Equal(t, workflowBinary(), content, "existing download was overwritten")
}

func verifyWorkflowArtifactAuthorization(t *testing.T, f *workflowFixture, actor *workflowActor, status remediationservice.Status) {
	t.Helper()
	foreign := actor.cli("other-namespace", "status", status.ID)
	require.Error(t, foreign.err)
	require.Empty(t, foreign.statuses)
	code, _, body := actor.getArtifact(status.ID, "fixture-bytes.txt", "other-namespace")
	require.Equal(t, http.StatusForbidden, code)
	require.NotContains(t, string(body), string(workflowBinary()))
	reader := f.actor("uid-1", "fixture:operators", "fixture:no-artifacts")
	require.Equal(t, status.ID, reader.status(status.ID).ID, "metadata read must remain allowed")
	code, _, body = reader.getArtifact(status.ID, "fixture-bytes.txt", workflowNamespace)
	require.Equal(t, http.StatusForbidden, code)
	require.NotContains(t, string(body), string(workflowBinary()))
	output := filepath.Join(reader.directory, "forbidden")
	denied := reader.cli(workflowNamespace, "download", status.ID, "--output-dir", output)
	require.Error(t, denied.err)
	require.Empty(t, denied.statuses)
	require.NoDirExists(t, output)
	f.mu.Lock()
	defer f.mu.Unlock()
	require.True(t, slices.ContainsFunc(f.reviews, func(review authorizationv1.SubjectAccessReviewSpec) bool {
		return review.User == workflowUsername && review.UID == "uid-1" &&
			slices.Contains(review.Groups, "fixture:no-artifacts") && review.ResourceAttributes != nil &&
			review.ResourceAttributes.Namespace == workflowNamespace && review.ResourceAttributes.Resource == "remediations" &&
			review.ResourceAttributes.Subresource == "artifacts" && review.ResourceAttributes.Name == status.ID
	}), "artifact authorization did not retain the client's UID, groups, namespace, and run ID")
}

func TestRemediationWorkflowCLIRequestIdentityScope(t *testing.T) {
	f := newWorkflowFixture(t, newWorkflowProcessor())
	first := f.actor("uid-1", "fixture:operators", "fixture:group-a")
	reordered := f.actor("uid-1", "fixture:group-a", "fixture:operators", "fixture:operators")
	changedUID := f.actor("uid-2", "fixture:operators", "fixture:group-a")
	changedGroups := f.actor("uid-1", "fixture:operators", "fixture:group-b")
	original := first.start("identity-scope").success(t)
	require.Equal(t, original.ID, first.start("identity-scope").success(t).ID)
	require.Equal(t, original.ID, reordered.start("identity-scope").success(t).ID)
	groupConflict := changedGroups.start("identity-scope")
	require.Error(t, groupConflict.err)
	require.Empty(t, groupConflict.statuses)
	f.requireHTTP(http.MethodPost, "/api/v1/remediations", http.StatusConflict)
	require.Equal(t, original.Revision, first.status(original.ID).Revision)
	require.Error(t, changedGroups.start("new-group-scope").err, "a fresh request key must not duplicate active source work")
	require.NoError(t, os.WriteFile(changedGroups.report, []byte(strings.Replace(workflowReport, "disabled", "changed for group", 1)), 0o600))
	require.NotEqual(t, original.ID, changedGroups.start("new-group-scope").success(t).ID)
	staleUID := changedUID.start("identity-scope")
	require.Error(t, staleUID.err)
	require.Empty(t, staleUID.statuses)
	f.requireHTTP(http.MethodPost, "/api/v1/remediations", http.StatusForbidden)
	// The fake TokenReview and fake live ServiceAccount must agree. Rotate
	// only the in-memory fixture object to simulate a recreated account.
	require.NoError(t, f.clientset.Tracker().Update(corev1.SchemeGroupVersion.WithResource("serviceaccounts"), &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "operator", Namespace: workflowNamespace, UID: "uid-2"},
	}, workflowNamespace))
	require.Error(t, changedUID.start("identity-scope").err, "an identity rotation must not duplicate active source work")
	require.NoError(t, os.WriteFile(changedUID.report, []byte(strings.Replace(workflowReport, "disabled", "changed for identity", 1)), 0o600))
	require.NotEqual(t, original.ID, changedUID.start("identity-scope").success(t).ID)
	runs, err := f.storage.ListRemediationRuns(t.Context(), workflowNamespace, 10)
	require.NoError(t, err)
	require.Len(t, runs, 3)
	run, err := f.storage.GetRemediationRun(t.Context(), workflowNamespace, original.ID)
	require.NoError(t, err)
	var request remediationservice.StoredRequest
	require.NoError(t, json.Unmarshal(run.RequestJSON, &request))
	require.Equal(t, remediationservice.ActorIdentity{
		Username: workflowUsername, UID: "uid-1", Groups: []string{"fixture:group-a", "fixture:operators"},
	}, request.Actor)
}

func TestRemediationWorkflowCLIWaitPausedNotSuccess(t *testing.T) {
	for _, test := range []struct {
		phase string
		err   error
	}{
		{store.RemediationPhaseNeedsApproval, nil},
		{store.RemediationPhaseNeedsInput, remediationservice.ErrNeedsInput},
		{store.RemediationPhaseNeedsAdapter, remediationservice.ErrNeedsAdapter},
	} {
		t.Run(test.phase, func(t *testing.T) {
			processor := newWorkflowProcessor()
			processor.pause = test.err
			f := newWorkflowFixture(t, processor)
			actor := f.actor("uid-1", "fixture:operators")
			f.startWorker()
			result := actor.start("paused-wait", "--wait")
			require.Error(t, result.err)
			require.NotEmpty(t, result.statuses)
			last := result.statuses[len(result.statuses)-1]
			require.Equal(t, test.phase, last.Phase)
			require.Contains(t, result.stderr, "not a verified result")
			for _, status := range result.statuses {
				require.NotEqual(t, store.RemediationPhaseSucceeded, status.Phase)
			}
			require.Zero(t, processor.model.calls.Load())
		})
	}
}

func TestRemediationWorkflowCLICancellationFencesLateSuccess(t *testing.T) {
	processor := newWorkflowProcessor()
	processor.requireApproval = false
	processor.release = make(chan struct{})
	processor.lateSuccess = make(chan error, 1)
	f := newWorkflowFixture(t, processor)
	actor := f.actor("uid-1", "fixture:operators")
	started := actor.start("cancel-late-success").success(t)
	f.startWorker()
	select {
	case <-processor.executing:
	case <-time.After(5 * time.Second):
		t.Fatal("synthetic execution did not begin")
	}
	cancelled := actor.cli(workflowNamespace, "cancel", started.ID).success(t)
	require.True(t, cancelled.CancelRequested)
	require.Contains(t, []string{store.RemediationPhaseCancelling, store.RemediationPhaseCancelled}, cancelled.Phase)
	close(processor.release)
	select {
	case err := <-processor.lateSuccess:
		require.ErrorIs(t, err, store.ErrConflict, "late success bypassed durable cancellation")
	case <-time.After(5 * time.Second):
		t.Fatal("late success was not attempted")
	}
	settled := actor.await(started.ID, store.RemediationPhaseCancelled)
	require.True(t, settled.CancelRequested)
	require.GreaterOrEqual(t, settled.Revision, cancelled.Revision)
	require.Greater(t, settled.Revision, started.Revision)
	require.EqualValues(t, 1, processor.cleaned.Load())
	repeated := actor.cli(workflowNamespace, "cancel", started.ID).success(t)
	require.Equal(t, settled.Revision, repeated.Revision)
	require.Equal(t, store.RemediationPhaseCancelled, repeated.Phase)
	for _, artifact := range settled.Artifacts {
		require.NotEqual(t, "result.patch", artifact.Name)
	}
	f.requireHTTP(http.MethodPost, "/api/v1/remediations/"+started.ID+"/cancel", http.StatusAccepted)
}

func TestRemediationWorkflowCLIInvalidModelFailsClosed(t *testing.T) {
	processor := newWorkflowProcessor()
	processor.requireApproval = false
	processor.model.invalid = true
	f := newWorkflowFixture(t, processor)
	actor := f.actor("uid-1", "fixture:operators")
	f.startWorker()
	result := actor.start("invalid-model", "--wait")
	require.Error(t, result.err)
	require.NotEmpty(t, result.statuses)
	status := result.statuses[len(result.statuses)-1]
	require.Equal(t, store.RemediationPhaseFailed, status.Phase)
	require.Equal(t, "execution-failed", status.Reason)
	require.Contains(t, result.stderr, "without success (Failed)")
	require.EqualValues(t, 1, processor.model.calls.Load())
	require.Zero(t, processor.execution.calls.Load())
	output := filepath.Join(actor.directory, "unverified-evidence")
	downloaded := actor.cli(workflowNamespace, "download", status.ID, "--output-dir", output).success(t)
	require.Equal(t, store.RemediationPhaseFailed, downloaded.Phase)
	require.NoFileExists(t, filepath.Join(output, "result.patch"))
	require.NoFileExists(t, filepath.Join(output, "evidence.json"))
}

func TestRemediationWorkflowCLIArtifactTampering(t *testing.T) {
	processor := newWorkflowProcessor()
	processor.requireApproval = false
	f := newWorkflowFixture(t, processor)
	actor := f.actor("uid-1", "fixture:operators")
	started := actor.start("artifact-tampering").success(t)
	f.startWorker()
	complete := actor.await(started.ID, store.RemediationPhaseSucceeded)
	for _, mutation := range []string{"bytes", "size", "digest"} {
		t.Run(mutation, func(t *testing.T) {
			verifyWorkflowTransportTampering(t, actor, complete, mutation)
		})
	}
	result, err := f.database.ExecContext(t.Context(), `UPDATE remediation_artifacts SET data = ?
		WHERE namespace = ? AND run_id = ? AND name = ?`, bytes.Repeat([]byte("x"), len(workflowBinary())),
		workflowNamespace, started.ID, "fixture-bytes.txt")
	require.NoError(t, err)
	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.EqualValues(t, 1, rows, "corruption injection must hit the actual SQLite artifact")
	code, _, body := actor.getArtifact(started.ID, "fixture-bytes.txt", workflowNamespace)
	require.Equal(t, http.StatusInternalServerError, code)
	require.Contains(t, string(body), "remediation operation failed")
	require.NotContains(t, string(body), "xxxx")
	output := filepath.Join(actor.directory, "corrupt")
	rejected := actor.cli(workflowNamespace, "download", complete.ID, "--output-dir", output)
	require.Error(t, rejected.err)
	require.Empty(t, rejected.statuses)
	require.NoDirExists(t, output, "corrupt artifact must not leave a partial download")
}

func verifyWorkflowTransportTampering(t *testing.T, actor *workflowActor, status remediationservice.Status, mutation string) {
	t.Helper()
	f := actor.fixture
	originalEndpoint := f.endpoint
	target, err := url.Parse(originalEndpoint)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(target)
	var modified atomic.Int32
	proxy.ModifyResponse = func(response *http.Response) error {
		if !strings.HasSuffix(response.Request.URL.Path, "/artifacts/fixture-bytes.txt") {
			return nil
		}
		original, err := io.ReadAll(response.Body)
		if err != nil {
			return err
		}
		if err := response.Body.Close(); err != nil {
			return err
		}
		switch mutation {
		case "bytes":
			original[0] ^= 0xff
		case "size":
			original = append(original, 0)
		case "digest":
			response.Header.Set("Digest", "sha-256="+base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)))
		default:
			return fmt.Errorf("unknown synthetic mutation %q", mutation)
		}
		response.Body = io.NopCloser(bytes.NewReader(original))
		response.ContentLength = int64(len(original))
		response.Header.Set("Content-Length", strconv.Itoa(len(original)))
		modified.Add(1)
		return nil
	}
	server := httptest.NewServer(proxy)
	defer server.Close()
	f.endpoint = server.URL
	defer func() { f.endpoint = originalEndpoint }()
	output := filepath.Join(actor.directory, "tampered-"+mutation)
	rejected := actor.cli(workflowNamespace, "download", status.ID, "--output-dir", output)
	require.Error(t, rejected.err)
	require.Contains(t, rejected.stderr, "size or SHA-256 integrity check")
	require.Empty(t, rejected.statuses)
	require.EqualValues(t, 1, modified.Load(), "test did not corrupt an actual production artifact response")
	require.NoDirExists(t, output)
}
