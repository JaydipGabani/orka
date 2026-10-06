package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"github.com/orka-agents/orka/internal/store"
	storekube "github.com/orka-agents/orka/internal/store/kube"
	"github.com/orka-agents/orka/internal/store/sqlite"
	appsv1 "k8s.io/api/apps/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestACPDispatcherRestartRetiresOldEpochWithoutPromptReplay(t *testing.T) {
	for _, scenario := range []string{"terminal", "deleting-terminal", "deleting-accepted", "new-pool-generation", "running-runtime"} {
		t.Run(scenario, func(t *testing.T) {
			f := newACPRuntimePoolRestartFixture(t, scenario == "deleting-terminal")
			if scenario == "deleting-accepted" {
				if err := f.pools.Delete(f.ctx, f.task); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "new-pool-generation" {
				pool := runtimePoolTestGetPool(t, f.pools, f.pool)
				pool.Generation++
				pool.Spec.Capacity.MaxResidentSessions++
				if err := f.pools.Update(f.ctx, &pool); err != nil {
					t.Fatal(err)
				}
				runtimePoolReconcile(t, f.pools, f.pool)
			}
			if scenario == "running-runtime" {
				f.runtime.mu.Lock()
				f.runtime.probe.Status.Sessions[0].State = harnessv2.RuntimeSessionStatePromptRunning
				f.runtime.probe.Status.Sessions[0].ActivePromptID = f.runtime.promptID
				f.runtime.probe.Status.ActivePrompts = []harnessv2.ActivePromptStatus{{
					RuntimeSessionUID: f.runtime.sessionUID, SessionGeneration: 1, TaskUID: f.runtime.taskUID,
					TaskAttempt: 1, PromptID: f.runtime.promptID, LeaseExpiresAt: time.Now().UTC().Add(time.Minute),
					FrameSequence: 1, StartedAt: time.Now().UTC(),
				}}
				f.runtime.probe.Status.Pressure.ActivePrompts = 1
				f.runtime.mu.Unlock()
			}
			f.start(t)
			f.await(t, func() bool {
				f.runtime.mu.Lock()
				defer f.runtime.mu.Unlock()
				return f.runtime.deleteCalls > 0
			}, "startup recovery never reached the old-epoch runtime cleanup")
			task := f.currentTask(t)
			if task.Status.Execution.RuntimeSessionCleanupDigest != "" {
				t.Fatal("failed descendant cleanup minted a Task cleanup receipt")
			}
			if ready, err := f.taskReconciler().acpTaskDeletionReady(f.ctx, task); err != nil || ready {
				t.Fatalf("finalizer before runtime proof: ready=%t error=%v", ready, err)
			}
			deployment := runtimePoolTestDeployment(t, f.pools, f.pool.Namespace, f.deployment.Name)
			if ptr.Deref(deployment.Spec.Replicas, 0) != 1 ||
				deployment.Spec.Template.Annotations[runtimePoolTemplateRevisionAnnotation] != f.deployment.Spec.Template.Annotations[runtimePoolTemplateRevisionAnnotation] {
				t.Fatal("rollout replaced the old runtime before cleanup was proven")
			}
			f.runtime.mu.Lock()
			f.runtime.blockCleanup = false
			f.runtime.mu.Unlock()
			f.await(t, func() bool { return taskScopedRuntimeSessionCleanupComplete(f.currentTask(t)) },
				"periodic startup recovery did not retry the blocked retirement")

			projector := &ACPOutboxProjector{
				Client: f.pools.Client, Store: f.control, Epochs: f.dispatcher.Epochs,
				WorkerID: "restart-recovery-projector", MaxAttempts: 3,
			}
			if err := projector.projectOnce(f.ctx); err != nil {
				t.Fatal(err)
			}
			owner, err := f.dispatcher.Epochs.CurrentFence(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			f.await(t, func() bool { return f.currentTask(t).Status.Execution.ControllerEpoch == owner.Epoch },
				"settled retirement never advanced the Task's controller epoch")
			task = f.currentTask(t)
			if task.UID != f.task.UID || task.Status.Execution.PromptID != f.task.Status.Execution.PromptID ||
				task.Status.Execution.Attempt != 1 || task.Status.Execution.State != corev1alpha1.TaskExecutionStateOutcomeUnknown ||
				task.Status.Execution.Outcome != corev1alpha1.TaskExecutionOutcomeOutcomeUnknown ||
				task.Status.Phase != corev1alpha1.TaskPhaseFailed || task.Status.Execution.Reason != "RuntimeLost" {
				t.Fatal("restart changed the accepted identity or replayed its outcome")
			}
			if ready, err := f.taskReconciler().acpTaskDeletionReady(f.ctx, task); err != nil || !ready {
				t.Fatalf("finalizer after exact cleanup and terminal projection: ready=%t error=%v", ready, err)
			}
			f.runtime.mu.Lock()
			promptCalls, wrongFences := f.runtime.promptCalls, f.runtime.wrongFences
			f.runtime.mu.Unlock()
			if promptCalls != 0 || wrongFences != 0 {
				t.Fatalf("restart replayed prompts or changed runtime fences: prompts=%d mismatches=%d", promptCalls, wrongFences)
			}
			runtimePoolReconcile(t, f.pools, f.pool)
			runtimePoolReconcile(t, f.pools, f.pool)
			deployment = runtimePoolTestDeployment(t, f.pools, f.pool.Namespace, f.deployment.Name)
			if ptr.Deref(deployment.Spec.Replicas, 1) != 0 {
				t.Fatal("authenticated retirement did not unblock the rollout stop barrier")
			}
			pool := runtimePoolTestGetPool(t, f.pools, f.pool)
			if pool.Status.AdmissionState == corev1alpha1.RuntimePoolAdmissionAccepting {
				t.Fatal("old-epoch recovery reopened admission")
			}
			if _, _, _, _, err := f.dispatcher.runtimePoolClient(f.ctx, &pool); err == nil {
				t.Fatal("retirement authority relaxed the normal runtime admission epoch")
			}
		})
	}
}

func TestRuntimePoolControllerRestartRendersEpochScopedRollout(t *testing.T) {
	f := newACPRuntimePoolRestartFixture(t, false)
	pool := runtimePoolTestGetPool(t, f.pools, f.pool)
	cfg, err := f.pools.runtimePoolConfig(&pool)
	if err != nil {
		t.Fatal(err)
	}
	previous := cfg
	previous.controllerEpoch = pool.Status.ActiveInstance.ControllerEpoch
	authName := runtimePoolTestVolume(f.deployment.Spec.Template.Spec.Volumes, runtimePoolAuthVolume).Secret.SecretName
	providerName := runtimePoolTestVolume(f.deployment.Spec.Template.Spec.Volumes, runtimePoolProviderCapabilityVolume).Secret.SecretName
	unchanged := f.pools.runtimePoolPodTemplate(&pool, previous, f.deployment.Spec.Selector.MatchLabels, authName, providerName)
	if runtimePoolDeploymentNeedsRollout(f.deployment, unchanged) {
		t.Fatal("rendering identical startup inputs spuriously changed the runtime template")
	}
	auth, provider, err := f.pools.ensureRuntimePoolSecrets(f.ctx, &pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	rotated := f.pools.runtimePoolPodTemplate(&pool, cfg, f.deployment.Spec.Selector.MatchLabels, auth.Name, provider.Name)
	if cfg.controllerEpoch == previous.controllerEpoch || auth.Name == authName || provider.Name == providerName ||
		!runtimePoolDeploymentNeedsRollout(f.deployment, rotated) {
		t.Fatal("durable epoch rotation did not change the rendered epoch and both credential references")
	}
}

//nolint:gocyclo // Exercise each authority boundary against the same initialized controller and runtime fixture.
func TestACPPreviousEpochCleanupRejectsChangedAuthority(t *testing.T) {
	for _, change := range []string{
		"unsettled attempt", "missing pool", "missing pod", "missing active instance", "replacement pod", "pod image",
		"task UID", "binding digest", "reopened admission", "credential version", "controller takeover", "status fence",
	} {
		t.Run(change, func(t *testing.T) {
			f := newACPRuntimePoolRestartFixture(t, false)
			if change != "unsettled attempt" {
				if err := f.dispatcher.recoverStaleAttempts(f.ctx); err != nil {
					t.Fatal(err)
				}
			}
			task := f.currentTask(t)
			f.runtime.mu.Lock()
			f.runtime.blockCleanup = false
			f.runtime.statusReads = 0
			f.runtime.mu.Unlock()
			switch change {
			case "missing pool", "missing pod", "task UID":
				f.dispatcher.APIReader = interceptor.NewClient(f.pools.Client.(client.WithWatch), interceptor.Funcs{
					Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if _, ok := obj.(*corev1alpha1.RuntimePool); ok && change == "missing pool" {
							return apierrors.NewNotFound(schema.GroupResource{Group: corev1alpha1.GroupVersion.Group, Resource: "runtimepools"}, key.Name)
						}
						if _, ok := obj.(*corev1.Pod); ok && change == "missing pod" {
							return apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, key.Name)
						}
						if err := c.Get(ctx, key, obj, opts...); err != nil {
							return err
						}
						if actual, ok := obj.(*corev1alpha1.Task); ok && change == "task UID" {
							actual.UID = "replacement-task-uid"
						}
						return nil
					},
				})
			case "missing active instance", "reopened admission":
				pool := runtimePoolTestGetPool(t, f.pools, f.pool)
				if change == "missing active instance" {
					pool.Status.ActiveInstance = nil
				} else {
					pool.Status.AdmissionState = corev1alpha1.RuntimePoolAdmissionAccepting
				}
				if err := f.pools.Status().Update(f.ctx, &pool); err != nil {
					t.Fatal(err)
				}
			case "replacement pod", "pod image":
				pod := f.pod.DeepCopy()
				if change == "replacement pod" {
					pod.UID = "replacement-pod-uid"
				} else {
					pod.Spec.Containers[0].Image = "example.invalid/changed@sha256:" + strings.Repeat("c", 64)
				}
				if err := f.pools.Update(f.ctx, pod); err != nil {
					t.Fatal(err)
				}
			case "binding digest":
				task.Status.AgentExecutionBinding.BindingDigest = store.CanonicalBytesDigest([]byte("other-binding"))
				if err := f.pools.Status().Update(f.ctx, task); err != nil {
					t.Fatal(err)
				}
			case "credential version", "controller takeover", "status fence":
				f.runtime.mu.Lock()
				f.runtime.statusHook = func(read int) {
					if read != 3 {
						return
					}
					switch change {
					case "credential version":
						secret := &corev1.Secret{}
						if err := f.pools.Get(f.ctx, client.ObjectKeyFromObject(f.runtime.auth), secret); err != nil {
							t.Error(err)
							return
						}
						secret.Annotations = map[string]string{"test.orka.ai/version": "changed"}
						if err := f.pools.Update(f.ctx, secret); err != nil {
							t.Error(err)
						}
					case "controller takeover":
						current, err := f.control.GetControllerEpoch(f.ctx, store.DefaultControllerEpochName)
						if err != nil {
							t.Error(err)
							return
						}
						_, err = f.control.CompareAndSwapControllerEpoch(f.ctx, store.ControllerEpochCAS{
							Name: current.Name, ExpectedEpoch: current.Epoch, ExpectedVersion: current.Version,
							NewEpoch: current.Epoch + 1, HolderID: "another-controller",
							RequestDigest: store.CanonicalBytesDigest([]byte("takeover")), UpdatedAt: time.Now().UTC(),
						})
						if err != nil {
							t.Error(err)
						}
					case "status fence":
						f.runtime.probe.Status.Fence.SupervisorBootID = "different-boot"
					}
				}
				f.runtime.mu.Unlock()
			}
			complete, _ := f.dispatcher.cleanupRecoveredTaskScopedRuntimeSession(f.ctx, task)
			if complete || f.currentTask(t).Status.Execution.RuntimeSessionCleanupDigest != "" {
				t.Fatal("changed authority or absent workload minted retirement proof")
			}
			f.runtime.mu.Lock()
			deletes := f.runtime.deleteCalls
			f.runtime.mu.Unlock()
			if deletes != 0 {
				t.Fatalf("changed authority reached runtime DELETE %d times", deletes)
			}
		})
	}
}

func TestACPPreviousEpochCleanupRequiresPostDeleteProof(t *testing.T) {
	for _, code := range []int{http.StatusNotFound, http.StatusGone} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			f := newACPRuntimePoolRestartFixture(t, false)
			if err := f.dispatcher.recoverStaleAttempts(f.ctx); err != nil {
				t.Fatal(err)
			}
			f.runtime.mu.Lock()
			f.runtime.deleteStatus = code
			f.runtime.mu.Unlock()
			complete, err := f.dispatcher.cleanupRecoveredTaskScopedRuntimeSession(f.ctx, f.currentTask(t))
			if err != nil || complete || f.currentTask(t).Status.Execution.RuntimeSessionCleanupDigest != "" {
				t.Fatalf("HTTP deletion response without authenticated absence: complete=%t error=%v", complete, err)
			}
			f.runtime.mu.Lock()
			deletes := f.runtime.deleteCalls
			f.runtime.mu.Unlock()
			if deletes != 1 {
				t.Fatalf("expected one exact deletion probe, got %d", deletes)
			}
		})
	}
}

func TestACPRuntimeCleanupReceiptRejectsReplacedTaskUID(t *testing.T) {
	f := newACPRuntimePoolRestartFixture(t, false)
	replacement := f.currentTask(t)
	replacement.UID = "replacement-task-uid"
	if err := f.pools.Update(f.ctx, replacement); err != nil {
		t.Fatal(err)
	}
	e := f.task.Status.Execution
	err := f.dispatcher.markTaskScopedRuntimeSessionCleanupComplete(f.ctx, f.task, f.task.UID,
		e.RuntimeInstanceID, e.RuntimeSessionUID, e.RuntimeSessionGeneration)
	if !errors.Is(err, store.ErrConflict) || f.currentTask(t).Status.Execution.RuntimeSessionCleanupDigest != "" {
		t.Fatalf("cleanup proof crossed Task incarnation: %v", err)
	}
}

type acpRestartRuntime struct {
	mu                  sync.Mutex
	probe               RuntimePoolProbeResult
	auth                *corev1.Secret
	blockCleanup        bool
	deleteCalls         int
	promptCalls         int
	wrongFences         int
	statusReads         int
	statusHook          func(int)
	deleteStatus        int
	sessionUID          harnessv2.RuntimeSessionUID
	taskUID             harnessv2.TaskUID
	promptID            harnessv2.PromptID
	mutationCalls       int
	finalizePublication func(http.ResponseWriter, *http.Request)
}

type acpRestartSupervisorClient struct {
	RuntimePoolSupervisorClient
	endpoint string
}

func (c *acpRestartSupervisorClient) Probe(ctx context.Context, _, token string, secret []byte) (RuntimePoolProbeResult, error) {
	return c.RuntimePoolSupervisorClient.Probe(ctx, c.endpoint, token, secret)
}

func (c *acpRestartSupervisorClient) RequestDrain(ctx context.Context, _, token string, secret []byte, status harnessv2.StatusResponse, reason string) error {
	return c.RuntimePoolSupervisorClient.RequestDrain(ctx, c.endpoint, token, secret, status, reason)
}

func (s *acpRestartRuntime) serve(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.mutationCalls++
	}
	if r.URL.Path == harnessv2.CapabilitiesPath {
		writeDispatcherJSON(w, s.probe.Capabilities)
		return
	}
	if s.auth == nil || r.Header.Get("Authorization") != "Bearer "+string(s.auth.Data[runtimePoolControllerTokenKey]) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == harnessv2.StatusPath {
		binding := harnessv2.StatusCapabilityBinding{
			RuntimeProfileDigest: s.probe.Status.Fence.RuntimeProfileDigest, RuntimeInstanceID: s.probe.Status.Fence.RuntimeInstanceID,
		}
		if _, err := harnessv2.VerifyStatusCapability(s.auth.Data[runtimePoolCapabilitySecretKey],
			r.Header.Get(runtimePoolOperationHeader), binding, time.Now().UTC()); err != nil {
			t.Errorf("status request lacked exact old runtime authentication: %v", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		s.statusReads++
		if s.statusHook != nil {
			s.statusHook(s.statusReads)
		}
		s.probe.Status.Timestamp = time.Now().UTC()
		writeDispatcherJSON(w, s.probe.Status)
		return
	}
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/publication-finalization") && s.finalizePublication != nil {
		s.finalizePublication(w, r)
		return
	}
	var wire struct {
		Protocol                 string                     `json:"protocol"`
		Metadata                 harnessv2.MutationMetadata `json:"metadata"`
		Reason                   string                     `json:"reason"`
		AbandonUnvalidatedPrompt bool                       `json:"abandonUnvalidatedPrompt"`
	}
	if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
		t.Error("runtime received a malformed mutation")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	expected := s.probe.Status.Fence
	if r.Method == http.MethodDelete {
		expected.RuntimeSessionUID, expected.RuntimeSessionGeneration = s.sessionUID, 1
		if wire.Metadata.TaskUID != s.taskUID || wire.Metadata.TaskAttempt != 1 ||
			(wire.AbandonUnvalidatedPrompt && wire.Metadata.PromptID != s.promptID) {
			s.wrongFences++
			w.WriteHeader(http.StatusConflict)
			return
		}
	}
	if harnessv2.CompareFence(expected, wire.Metadata.Fence, r.Method == http.MethodDelete) != harnessv2.FenceMatch {
		s.wrongFences++
		w.WriteHeader(http.StatusGone)
		return
	}
	if err := harnessv2.VerifyOperationCapability(s.auth.Data[runtimePoolCapabilitySecretKey],
		r.Header.Get(runtimePoolOperationHeader), wire.Metadata, r.Method == http.MethodDelete, time.Now().UTC()); err != nil {
		t.Errorf("runtime mutation lacked operation authentication: %v", err)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	switch {
	case r.URL.Path == harnessv2.DrainPath:
		s.probe.Status.Lifecycle = harnessv2.SupervisorLifecycleDraining
		s.probe.Status.Drain = harnessv2.DrainStatus{Requested: true, Reason: wire.Reason, RequestedAt: time.Now().UTC()}
		writeDispatcherJSON(w, harnessv2.DrainResponse{
			Protocol:       harnessv2.ProtocolVersion,
			Classification: harnessv2.Classification{Class: harnessv2.RequestClassificationFresh},
			Drain:          s.probe.Status.Drain,
		})
	case r.Method == http.MethodDelete:
		s.deleteCalls++
		if s.deleteStatus != 0 {
			writeDispatcherJSONStatus(w, s.deleteStatus, harnessv2.ErrorResponse{
				Protocol: harnessv2.ProtocolVersion, Code: harnessv2.ErrorCodeStaleFence, Message: "deletion not proven",
			})
			return
		}
		if len(s.probe.Status.ActivePrompts) > 0 {
			if wire.AbandonUnvalidatedPrompt {
				t.Error("unsettled prompt bypassed cancellation")
			}
			s.probe.Status.Sessions[0].State = harnessv2.RuntimeSessionStateValidating
			s.probe.Status.Sessions[0].ActivePromptID = ""
			s.probe.Status.ActivePrompts = nil
			s.probe.Status.Pressure.ActivePrompts = 0
			writeDispatcherJSONStatus(w, http.StatusConflict, harnessv2.ErrorResponse{
				Protocol: harnessv2.ProtocolVersion, Code: harnessv2.ErrorCodeAlreadyAccepted,
				Message: "cancellation must settle before deletion", Retryable: true,
			})
			return
		}
		if !wire.AbandonUnvalidatedPrompt || wire.Metadata.PromptID == "" {
			t.Error("recovery did not explicitly authorize abandonment of the exact settled prompt")
			w.WriteHeader(http.StatusConflict)
			return
		}
		if s.blockCleanup {
			writeDispatcherJSONStatus(w, http.StatusInternalServerError, harnessv2.ErrorResponse{
				Protocol: harnessv2.ProtocolVersion, Code: harnessv2.ErrorCodeSessionPoisoned,
				Message: "runtime descendant cleanup could not be proven",
			})
			return
		}
		request := harnessv2.DeleteRuntimeSessionRequest{Protocol: wire.Protocol, Metadata: wire.Metadata, Reason: wire.Reason}
		s.probe.Status.Sessions = nil
		s.probe.Status.Pressure = harnessv2.PressureMetadata{}
		writeDispatcherJSON(w, harnessv2.DeleteRuntimeSessionResponse{
			Protocol:       harnessv2.ProtocolVersion,
			Classification: harnessv2.Classification{Class: harnessv2.RequestClassificationFresh},
			State:          harnessv2.RuntimeSessionStateDeleted, Tombstone: testDeleteTombstone(request, time.Now().UTC()),
		})
	default:
		if strings.Contains(r.URL.Path, "/prompts/") {
			s.promptCalls++
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

type acpRuntimePoolRestartFixture struct {
	ctx        context.Context
	control    *storekube.Store
	pools      *RuntimePoolReconciler
	pool       *corev1alpha1.RuntimePool
	pod        *corev1.Pod
	deployment *appsv1.Deployment
	task       *corev1alpha1.Task
	dispatcher *ACPDispatcher
	runtime    *acpRestartRuntime
}

func newACPRuntimePoolRestartFixture(t *testing.T, deleting bool) *acpRuntimePoolRestartFixture {
	t.Helper()
	return newACPRuntimePoolCleanupFixture(t, deleting, true)
}

func newACPRuntimePoolCleanupFixture(t *testing.T, deleting, restart bool) *acpRuntimePoolRestartFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	db, err := sqlite.NewDB(filepath.Join(t.TempDir(), "restart.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	persistence := sqlite.NewStore(db, "restart-recovery")
	pool := runtimePoolTestObject(1)
	scheme := runtimePoolTestScheme(t)
	if err := coordinationv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	pools := runtimePoolTestReconciler(t, scheme, nil)
	pools.Client = withControllerEpochLeaseUIDs(t, fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&corev1alpha1.RuntimePool{}, &corev1alpha1.Task{}, &appsv1.Deployment{}, &corev1.Pod{},
			&corev1alpha1.ControllerEpoch{}, &corev1alpha1.PromptAttempt{}, &corev1alpha1.RuntimeSessionControl{},
			&corev1alpha1.BranchClaim{}, &corev1alpha1.Publication{}, &corev1alpha1.ExternalEffect{}).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
				if secret, ok := obj.(*corev1.Secret); ok && secret.UID == "" {
					secret.UID = types.UID("test-uid-" + secret.Name)
				}
				return c.Create(ctx, obj, opts...)
			},
		}).WithObjects(pool).Build())
	control, err := storekube.NewComposite(pools.Client, pool.Namespace, persistence, storekube.WithAPIReader(pools.Client))
	if err != nil {
		t.Fatal(err)
	}
	oldEpochs, stopOldOnce := startACPRuntimePoolRestartEpoch(t, ctx, control, persistence, "old-controller")
	oldFence, err := oldEpochs.CurrentFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pools.ControllerEpoch, pools.Epochs, pools.Now = 0, oldEpochs, time.Now
	runtimePoolReconcile(t, pools, pool)
	deployment := runtimePoolTestDeployment(t, pools, pool.Namespace, runtimePoolResourceName(pool.Namespace, pool.Name))
	runtimeState := &acpRestartRuntime{blockCleanup: true}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { runtimeState.serve(t, w, r) }))
	t.Cleanup(server.Close)
	pools.SupervisorClient = &acpRestartSupervisorClient{RuntimePoolSupervisorClient: pools.supervisorClient(), endpoint: server.URL}
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	pod := runtimePoolReadyPodForDeployment(pool, deployment, "restart-runtime", "restart-runtime-uid", endpoint.Host)
	pod.Spec = *deployment.Spec.Template.Spec.DeepCopy()
	runtimePoolTestCreatePod(t, pools, &pod)
	authName := runtimePoolTestVolume(pod.Spec.Volumes, runtimePoolAuthVolume).Secret.SecretName
	auth := &corev1.Secret{}
	if err := pools.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: authName}, auth); err != nil {
		t.Fatal(err)
	}
	runtimeState.auth = auth
	runtimeState.probe = runtimePoolValidProbe(pool, &pod, "original-boot", false)
	runtimeState.probe.Status.Fence.ControllerEpoch = uint64(oldFence.Epoch)
	runtimePoolReconcile(t, pools, pool)
	currentPool := runtimePoolTestGetPool(t, pools, pool)
	if currentPool.Status.ActiveInstance == nil {
		t.Fatal("initial production RuntimePool reconciliation did not admit its authenticated boot")
	}
	task := runtimePoolRetirementTask(t, &currentPool, "restart-task")
	task.Spec.SessionRef = nil
	task.Status.Phase, task.Status.Attempts = corev1alpha1.TaskPhaseRunning, 1
	task.Status.Execution.State, task.Status.Execution.Outcome = corev1alpha1.TaskExecutionStateRunning, ""
	task.Status.Execution.ControllerEpoch = oldFence.Epoch
	task.Status.Execution.RuntimeSessionUID = taskRuntimeSessionUID(task)
	task.Status.Delivery = nil
	if err := pools.Create(ctx, task); err != nil {
		t.Fatal(err)
	}
	key := store.PromptAttemptKey{Namespace: task.Namespace, TaskUID: string(task.UID), Attempt: 1, PromptID: task.Status.Execution.PromptID}
	attempt, err := control.CreatePromptAttempt(ctx, &store.PromptAttempt{
		Key: key, RequestDigest: task.Status.Execution.RequestDigest,
		BindingDigest: task.Status.AgentExecutionBinding.BindingDigest, SnapshotDigest: task.Status.AgentExecutionBinding.Snapshot.Digest,
	}, oldFence)
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []store.PromptExecutionState{
		store.PromptExecutionReserved, store.PromptExecutionSessionStarting, store.PromptExecutionPlanned,
		store.PromptExecutionSubmitting, store.PromptExecutionAccepted, store.PromptExecutionRunning,
	} {
		attempt, err = control.TransitionPromptAttemptExecution(ctx, store.PromptAttemptExecutionTransition{
			ID: attempt.ID, Fence: oldFence, ExpectedVersion: attempt.Version, ExpectedState: attempt.ExecutionState,
			NewState: next, OperationID: "initial-" + string(next),
			OperationDigest: store.CanonicalBytesDigest([]byte(next)), UpdatedAt: time.Now().UTC(),
			RuntimeInstanceID: task.Status.Execution.RuntimeInstanceID,
			SessionUID:        task.Status.Execution.RuntimeSessionUID, SessionLeaseGeneration: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	runtimeState.mu.Lock()
	runtimeState.sessionUID = harnessv2.RuntimeSessionUID(task.Status.Execution.RuntimeSessionUID)
	runtimeState.taskUID = harnessv2.TaskUID(task.UID)
	runtimeState.promptID = harnessv2.PromptID(task.Status.Execution.PromptID)
	runtimeState.probe.Status.Sessions = []harnessv2.RuntimeSessionStatus{{
		RuntimeSessionID:  harnessv2.RuntimeSessionID("runtime-" + task.Status.Execution.RuntimeSessionUID + "-g1"),
		RuntimeSessionUID: harnessv2.RuntimeSessionUID(task.Status.Execution.RuntimeSessionUID), Generation: 1,
		State: harnessv2.RuntimeSessionStateValidating, LiveDescendantCount: 1, LastTransitionAt: time.Now().UTC(),
	}}
	runtimeState.probe.Status.Pressure = harnessv2.PressureMetadata{ResidentSessions: 1, LiveDescendants: 1}
	runtimeState.mu.Unlock()
	epochs := oldEpochs
	if restart {
		stopOldOnce()
		epochs, _ = startACPRuntimePoolRestartEpoch(t, ctx, control, persistence, "restarted-controller")
	}
	pools.Epochs = epochs
	runtimePoolReconcile(t, pools, pool)
	currentPool = runtimePoolTestGetPool(t, pools, pool)
	if restart && (currentPool.Status.AdmissionState == corev1alpha1.RuntimePoolAdmissionAccepting ||
		currentPool.Status.ActiveInstance.ControllerEpoch != oldFence.Epoch) {
		t.Fatal("epoch rotation did not preserve the old boot behind closed admission")
	}
	// A prior recovery pass may already have settled the prompt before Task
	// deletion. Startup must still discover its missing runtime receipt.
	if deleting {
		dispatcher := &ACPDispatcher{Client: pools.Client, APIReader: pools.Client, Store: control, ResultStore: persistence, Epochs: epochs}
		if err := dispatcher.recoverStaleAttempts(ctx); err != nil {
			t.Fatal(err)
		}
		if err := pools.Delete(ctx, task); err != nil {
			t.Fatal(err)
		}
	}
	gate := NewACPAdmissionGate()
	gate.Close("controller recovery", time.Now().UTC())
	return &acpRuntimePoolRestartFixture{
		ctx: ctx, control: control, pools: pools, pool: pool, pod: &pod, deployment: deployment, task: task, runtime: runtimeState,
		dispatcher: &ACPDispatcher{
			Client: pools.Client, APIReader: pools.Client, Store: control, ResultStore: persistence, EventStore: persistence,
			PlanStore: persistence, Snapshots: persistence, Epochs: epochs, AdmissionGate: gate, Interval: 5 * time.Millisecond,
		},
	}
}

func startACPRuntimePoolRestartEpoch(
	t *testing.T, ctx context.Context, control *storekube.Store, persistence *sqlite.Store, holder string,
) (*ControllerEpochManager, func()) {
	t.Helper()
	epochs := NewControllerEpochManager(control, holder).WithMirror(persistence)
	epochCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- epochs.Start(epochCtx) }()
	stop := sync.OnceFunc(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("controller epoch stopped with error: %v", err)
		}
	})
	t.Cleanup(stop)
	if _, err := epochs.CurrentFence(ctx); err != nil {
		t.Fatal(err)
	}
	return epochs, stop
}

func (f *acpRuntimePoolRestartFixture) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { done <- f.dispatcher.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("dispatcher stopped with error: %v", err)
		}
	})
}

func (f *acpRuntimePoolRestartFixture) currentTask(t *testing.T) *corev1alpha1.Task {
	t.Helper()
	task := &corev1alpha1.Task{}
	if err := f.pools.Get(f.ctx, client.ObjectKeyFromObject(f.task), task); err != nil {
		t.Fatal(err)
	}
	return task
}

func (f *acpRuntimePoolRestartFixture) taskReconciler() *TaskReconciler {
	return &TaskReconciler{Client: f.pools.Client, DurableControlStore: f.control}
}

func (f *acpRuntimePoolRestartFixture) await(t *testing.T, condition func() bool, failure string) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for !condition() {
		select {
		case <-deadline.C:
			t.Fatal(failure)
		case <-f.ctx.Done():
			t.Fatal(f.ctx.Err())
		case <-ticker.C:
		}
	}
}
