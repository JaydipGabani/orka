/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	types "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/store"
	"github.com/orka-agents/orka/internal/store/sqlite"
)

func coexistenceTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := coordinationv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

func legacyLease(namespace, holder string, renewed time.Time) *coordinationv1.Lease {
	renewTime := metav1.NewMicroTime(renewed)
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: corev1alpha1.AgentExecutionLegacyLeaseName},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity: new(holder), RenewTime: &renewTime,
			LeaseDurationSeconds: new(int32(30)),
		},
	}
}

func coexistenceSnapshotStore(t *testing.T) *sqlite.Store {
	t.Helper()
	db, err := sqlite.NewDB(filepath.Join(t.TempDir(), "classifier.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlite.NewStore(db, "test")
	cipher, err := sqlite.NewAgentExecutionSnapshotCipher(bytes.Repeat([]byte{0x11}, sqlite.AgentExecutionSnapshotKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	s.SetAgentExecutionSnapshotCipher(cipher)
	return s
}

func classifierTask(name string, mutate func(*corev1alpha1.Task)) *corev1alpha1.Task {
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default", Name: name, UID: types.UID("uid-" + name), Generation: 1,
		},
		Spec: corev1alpha1.TaskSpec{
			Type: corev1alpha1.TaskTypeAgent, Prompt: "p",
			AgentRef: &corev1alpha1.AgentReference{Name: "agent"},
		},
		Status: corev1alpha1.TaskStatus{Phase: corev1alpha1.TaskPhaseRunning},
	}
	if mutate != nil {
		mutate(task)
	}
	return task
}

func TestAgentExecutionClassifierAdoptsQuarantinesAndRecordsNoExecution(t *testing.T) {
	ctx := context.Background()
	scheme := coexistenceTestScheme(t)
	agent := &corev1alpha1.Agent{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "agent", UID: types.UID("agent-uid"), Generation: 2},
		Spec: corev1alpha1.AgentSpec{Runtime: &corev1alpha1.AgentCLIRuntime{
			Type: corev1alpha1.AgentRuntimeCodex, ContractVersion: ptr.To(corev1alpha1.AgentRuntimeContractHarnessV2),
		}},
	}
	namespace := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default", UID: types.UID("ns-uid")}}

	v2Task := classifierTask("v2-evidence", func(task *corev1alpha1.Task) {
		task.Status.Execution = &corev1alpha1.TaskExecutionStatus{State: corev1alpha1.TaskExecutionStateRunning}
	})
	v1Task := classifierTask("v1-evidence", func(task *corev1alpha1.Task) {
		task.Status.HarnessRuntime = &corev1alpha1.HarnessRuntimeStatus{ContractVersion: "orka.harness.v1", RuntimeName: "wrapper"}
	})
	mixedTask := classifierTask("mixed-evidence", func(task *corev1alpha1.Task) {
		task.Status.Execution = &corev1alpha1.TaskExecutionStatus{State: corev1alpha1.TaskExecutionStateRunning}
		task.Status.HarnessRuntime = &corev1alpha1.HarnessRuntimeStatus{ContractVersion: "orka.harness.v1"}
	})
	annotatedTask := classifierTask("annotations-only", func(task *corev1alpha1.Task) {
		task.Annotations = map[string]string{harnessWrapperTurnIDAnnotation: "turn-1"}
	})
	deletingTask := classifierTask("deleting-no-evidence", func(task *corev1alpha1.Task) {
		task.Finalizers = []string{"orka.ai/cleanup"}
	})
	terminalTask := classifierTask("terminal", func(task *corev1alpha1.Task) {
		task.Status.Phase = corev1alpha1.TaskPhaseSucceeded
	})
	freshTask := classifierTask("fresh-unbound", nil)

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&corev1alpha1.Task{}).
		WithObjects(agent, namespace, v2Task, v1Task, mixedTask, annotatedTask, deletingTask, terminalTask, freshTask).
		Build()
	if err := kubeClient.Delete(ctx, deletingTask.DeepCopy()); err != nil {
		t.Fatal(err)
	}

	classifier := &AgentExecutionClassifier{
		Client: kubeClient, Reader: kubeClient,
		Snapshots: coexistenceSnapshotStore(t), Recorder: record.NewFakeRecorder(20),
		InventoryID: "coexistence-test",
	}
	if err := classifier.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	get := func(name string) *corev1alpha1.Task {
		task := &corev1alpha1.Task{}
		if err := kubeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: name}, task); err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		return task
	}

	adopted := get("v2-evidence")
	if binding := adopted.Status.AgentExecutionBinding; binding == nil ||
		binding.ContractVersion != corev1alpha1.AgentRuntimeContractHarnessV2 ||
		binding.Backend != corev1alpha1.AgentExecutionBackendRuntimePool ||
		binding.Provenance != corev1alpha1.AgentExecutionProvenanceLegacyAdopted {
		t.Fatalf("v2 adoption binding = %+v", adopted.Status.AgentExecutionBinding)
	}
	snapshotKey := store.AgentExecutionSnapshotKey{
		TaskUID: string(adopted.UID), Digest: adopted.Status.AgentExecutionBinding.Snapshot.Digest,
	}
	if _, err := classifier.Snapshots.GetAgentExecutionSnapshot(ctx, snapshotKey); err != nil {
		t.Fatalf("adoption snapshot missing: %v", err)
	}

	adoptedV1 := get("v1-evidence")
	if binding := adoptedV1.Status.AgentExecutionBinding; binding == nil ||
		binding.ContractVersion != corev1alpha1.AgentRuntimeContractHarnessV1 ||
		binding.Backend != corev1alpha1.AgentExecutionBackendHarnessWrapper {
		t.Fatalf("v1 adoption binding = %+v", adoptedV1.Status.AgentExecutionBinding)
	}

	mixed := get("mixed-evidence")
	if quarantine := mixed.Status.AgentExecutionQuarantine; quarantine == nil ||
		quarantine.Reason != corev1alpha1.AgentExecutionQuarantineMixedEvidence ||
		quarantine.V1EvidenceDigest == "" || quarantine.V2EvidenceDigest == "" {
		t.Fatalf("mixed quarantine = %+v", mixed.Status.AgentExecutionQuarantine)
	}
	if mixed.Status.AgentExecutionBinding != nil {
		t.Fatal("quarantined task must not receive a binding")
	}

	annotated := get("annotations-only")
	if quarantine := annotated.Status.AgentExecutionQuarantine; quarantine == nil ||
		quarantine.Reason != corev1alpha1.AgentExecutionQuarantineAmbiguousLegacyEvidence {
		t.Fatalf("annotation-only quarantine = %+v", annotated.Status.AgentExecutionQuarantine)
	}

	deleting := get("deleting-no-evidence")
	if disposition := deleting.Status.AgentExecutionNoExecution; disposition == nil ||
		disposition.State != corev1alpha1.AgentExecutionNoExecutionUnbound {
		t.Fatalf("no-execution disposition = %+v", deleting.Status.AgentExecutionNoExecution)
	}

	if terminal := get("terminal"); terminal.Status.AgentExecutionBinding != nil ||
		terminal.Status.AgentExecutionQuarantine != nil {
		t.Fatal("historical terminal tasks are not classified")
	}
	if fresh := get("fresh-unbound"); fresh.Status.AgentExecutionBinding != nil ||
		fresh.Status.AgentExecutionQuarantine != nil || fresh.Status.AgentExecutionNoExecution != nil {
		t.Fatal("fresh unbound tasks are left to the normal binding stage")
	}
}

func coexistenceControl() *corev1alpha1.AgentExecutionControl {
	return &corev1alpha1.AgentExecutionControl{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: corev1alpha1.AgentExecutionControlNamespace,
			Name:      corev1alpha1.AgentExecutionControlName,
			UID:       types.UID("control-uid"), Generation: 1,
		},
		Spec: corev1alpha1.AgentExecutionControlSpec{Backends: corev1alpha1.AgentExecutionBackendsSpec{
			V1: corev1alpha1.AgentExecutionBackendSpec{DesiredMode: corev1alpha1.AgentExecutionModeDisabled},
			V2: corev1alpha1.AgentExecutionBackendSpec{DesiredMode: corev1alpha1.AgentExecutionModeEnabled},
		}},
	}
}

func TestAgentExecutionControlClosingBarrierProvesCutoff(t *testing.T) {
	ctx := context.Background()
	scheme := coexistenceTestScheme(t)
	control := coexistenceControl()
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&corev1alpha1.AgentExecutionControl{}, &corev1alpha1.Task{}).
		WithObjects(control).Build()
	reconciler := &AgentExecutionControlReconciler{
		Client: kubeClient, APIReader: kubeClient, Recorder: record.NewFakeRecorder(20),
		ClosurePasses: 2, ClosureInterval: time.Millisecond,
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{
		Namespace: control.Namespace, Name: control.Name,
	}}

	reconcileUntilStable := func(limit int) {
		t.Helper()
		for range limit {
			if _, err := reconciler.Reconcile(ctx, request); err != nil {
				t.Fatalf("reconcile: %v", err)
			}
		}
	}

	reconcileUntilStable(3)
	current := &corev1alpha1.AgentExecutionControl{}
	if err := kubeClient.Get(ctx, request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	if current.Status.Backends == nil ||
		current.Status.Backends.V2.EffectiveMode != corev1alpha1.AgentExecutionEffectiveModeEnabled ||
		current.Status.Backends.V1.EffectiveMode != corev1alpha1.AgentExecutionEffectiveModeDisabled {
		t.Fatalf("bootstrap modes = %+v", current.Status.Backends)
	}
	enabledRevision := current.Status.Backends.V2.ModeRevision

	// Request the drain: enabled must pass through the closing barrier and
	// prove the cutoff before drain-only is recorded.
	current.Spec.Backends.V2.DesiredMode = corev1alpha1.AgentExecutionModeDrainOnly
	if err := kubeClient.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	reconcileUntilStable(6)
	if err := kubeClient.Get(ctx, request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	v2 := current.Status.Backends.V2
	if v2.EffectiveMode != corev1alpha1.AgentExecutionEffectiveModeDrainOnly {
		t.Fatalf("v2 effective mode = %s", v2.EffectiveMode)
	}
	if v2.ModeRevision < enabledRevision+2 {
		t.Fatalf("closing barrier must consume revisions: %d -> %d", enabledRevision, v2.ModeRevision)
	}
	if v2.AdmissionClosedAt == nil || !strings.HasPrefix(v2.CutoffInventoryDigest, "sha256:") {
		t.Fatalf("cutoff proof missing: %+v", v2)
	}
}

func TestAgentExecutionControlClosureBlockedByUnsettledWork(t *testing.T) {
	ctx := context.Background()
	scheme := coexistenceTestScheme(t)
	control := coexistenceControl()
	unsettled := classifierTask("unsettled-v2", func(task *corev1alpha1.Task) {
		task.Status.AgentExecutionBinding = &corev1alpha1.AgentExecutionBinding{
			SchemaVersion: 1, Mode: corev1alpha1.AgentExecutionBindingModeExecute,
			ContractVersion: corev1alpha1.AgentRuntimeContractHarnessV2,
			Backend:         corev1alpha1.AgentExecutionBackendRuntimePool,
			Provenance:      corev1alpha1.AgentExecutionProvenanceNewlyBound,
			BindingDigest:   "sha256:" + strings.Repeat("a", 64),
			Task:            corev1alpha1.AgentExecutionBindingTaskRef{NamespaceUID: "ns", UID: task.UID, BoundSpecGeneration: 1},
			Snapshot: corev1alpha1.AgentExecutionSnapshotRef{
				ID:     string(task.UID) + "/sha256:" + strings.Repeat("a", 64),
				Digest: "sha256:" + strings.Repeat("a", 64), SchemaVersion: 1,
			},
			BoundAt: metav1.Now(),
		}
	})
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&corev1alpha1.AgentExecutionControl{}, &corev1alpha1.Task{}).
		WithObjects(control, unsettled).Build()
	reconciler := &AgentExecutionControlReconciler{
		Client: kubeClient, APIReader: kubeClient, Recorder: record.NewFakeRecorder(20),
		ClosurePasses: 2, ClosureInterval: time.Millisecond,
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: control.Namespace, Name: control.Name}}
	for range 3 {
		if _, err := reconciler.Reconcile(ctx, request); err != nil {
			t.Fatal(err)
		}
	}
	current := &corev1alpha1.AgentExecutionControl{}
	if err := kubeClient.Get(ctx, request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	current.Spec.Backends.V2.DesiredMode = corev1alpha1.AgentExecutionModeDrainOnly
	if err := kubeClient.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	for range 6 {
		if _, err := reconciler.Reconcile(ctx, request); err != nil {
			t.Fatal(err)
		}
	}
	if err := kubeClient.Get(ctx, request.NamespacedName, current); err != nil {
		t.Fatal(err)
	}
	if current.Status.Backends.V2.EffectiveMode != corev1alpha1.AgentExecutionEffectiveModeClosing {
		t.Fatalf("closure must stay blocked by unsettled pre-cutoff work, got %s", current.Status.Backends.V2.EffectiveMode)
	}
	if current.Status.Backends.V2.AdmissionClosedAt != nil {
		t.Fatal("cutoff must not be recorded while work is unsettled")
	}
}

func TestAgentExecutionAdjudicationAppliesOnceAndFencesSubject(t *testing.T) {
	ctx := context.Background()
	scheme := coexistenceTestScheme(t)
	quarantine := &corev1alpha1.AgentExecutionQuarantine{
		SchemaVersion: 1, Reason: corev1alpha1.AgentExecutionQuarantineMixedEvidence,
		MigrationInventoryID: "inv-1", RecordedAt: metav1.NewTime(time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)),
	}
	task := classifierTask("quarantined", func(task *corev1alpha1.Task) {
		task.Status.AgentExecutionQuarantine = quarantine
	})
	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&corev1alpha1.Task{}, &corev1alpha1.AgentExecutionAdjudication{}).
		WithObjects(task).Build()

	live := &corev1alpha1.Task{}
	if err := kubeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "quarantined"}, live); err != nil {
		t.Fatal(err)
	}
	quarantineDigest, err := acpDomainDigest("quarantine-record", live.Status.AgentExecutionQuarantine)
	if err != nil {
		t.Fatal(err)
	}
	watermark := "sha256:" + strings.Repeat("b", 64)
	adjudication := &corev1alpha1.AgentExecutionAdjudication{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "resolve-quarantined", UID: types.UID("adj-uid")},
		Spec: corev1alpha1.AgentExecutionAdjudicationSpec{
			TaskRef:          corev1alpha1.AgentExecutionSubjectReference{Name: live.Name, UID: live.UID},
			ExpectedState:    corev1alpha1.AgentExecutionExpectedSubjectState{SubjectResourceVersion: live.ResourceVersion, EvidenceClosureWatermark: watermark},
			QuarantineDigest: quarantineDigest,
			Action:           corev1alpha1.AgentExecutionAdjudicationCleanupBoth,
			EvidenceDigests:  []string{watermark},
			Justification:    "verified",
			RequestedBy:      "admin@example.com",
		},
	}
	if err := kubeClient.Create(ctx, adjudication); err != nil {
		t.Fatal(err)
	}
	reconciler := &AgentExecutionAdjudicationReconciler{
		Client: kubeClient, APIReader: kubeClient, Recorder: record.NewFakeRecorder(20),
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "resolve-quarantined"}}
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}

	applied := &corev1alpha1.AgentExecutionAdjudication{}
	if err := kubeClient.Get(ctx, request.NamespacedName, applied); err != nil {
		t.Fatal(err)
	}
	if applied.Status.State != corev1alpha1.AgentExecutionAdjudicationApplied ||
		applied.Status.ResolutionRefDigest == "" || applied.Status.OperationDigest == "" {
		t.Fatalf("adjudication status = %+v", applied.Status)
	}
	resolved := &corev1alpha1.Task{}
	if err := kubeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "quarantined"}, resolved); err != nil {
		t.Fatal(err)
	}
	resolution := resolved.Status.AgentExecutionResolutionRef
	if resolution == nil || resolution.AdjudicationUID != adjudication.UID ||
		resolution.Action != corev1alpha1.AgentExecutionAdjudicationCleanupBoth ||
		resolution.ResolutionDigest != applied.Status.ResolutionRefDigest {
		t.Fatalf("subject resolution = %+v", resolution)
	}
	if resolved.Status.AgentExecutionQuarantine == nil {
		t.Fatal("original quarantine evidence must never be cleared")
	}

	// Idempotent reconvergence.
	if _, err := reconciler.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}

	// A conflicting adjudication against the resolved subject is rejected.
	conflicting := adjudication.DeepCopy()
	conflicting.ObjectMeta = metav1.ObjectMeta{Namespace: "default", Name: "conflicting", UID: types.UID("adj-uid-2")}
	conflicting.Spec.ExpectedState.SubjectResourceVersion = resolved.ResourceVersion
	conflicting.Status = corev1alpha1.AgentExecutionAdjudicationStatus{}
	if err := kubeClient.Create(ctx, conflicting); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "conflicting"}}); err != nil {
		t.Fatal(err)
	}
	rejected := &corev1alpha1.AgentExecutionAdjudication{}
	if err := kubeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "conflicting"}, rejected); err != nil {
		t.Fatal(err)
	}
	if rejected.Status.State != corev1alpha1.AgentExecutionAdjudicationRejected {
		t.Fatalf("conflicting adjudication state = %s", rejected.Status.State)
	}

	// A stale subject version supersedes.
	stale := adjudication.DeepCopy()
	stale.ObjectMeta = metav1.ObjectMeta{Namespace: "default", Name: "stale", UID: types.UID("adj-uid-3")}
	stale.Spec.ExpectedState.SubjectResourceVersion = "1"
	stale.Status = corev1alpha1.AgentExecutionAdjudicationStatus{}
	if err := kubeClient.Create(ctx, stale); err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: "stale"}}); err != nil {
		t.Fatal(err)
	}
	superseded := &corev1alpha1.AgentExecutionAdjudication{}
	if err := kubeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "stale"}, superseded); err != nil {
		t.Fatal(err)
	}
	if superseded.Status.State != corev1alpha1.AgentExecutionAdjudicationSuperseded {
		t.Fatalf("stale adjudication state = %s", superseded.Status.State)
	}
}

func TestAgentExecutionOwnershipFencesLegacyLeases(t *testing.T) {
	ctx := context.Background()
	scheme := coexistenceTestScheme(t)
	ownership := func(objects ...client.Object) (*AgentExecutionOwnership, client.Client) {
		kubeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
		return &AgentExecutionOwnership{
			Client: kubeClient, Reader: kubeClient, Identity: "orka-coexistence",
			LeaseNamespace: corev1alpha1.AgentExecutionControlNamespace,
			LeaseName:      corev1alpha1.AgentExecutionOwnershipLeaseName,
			LeaseDuration:  30 * time.Second,
		}, kubeClient
	}

	// A stale legacy holder is fenced and readiness opens.
	staleLease := legacyLease("legacy-orka", "old-controller", time.Now().Add(-10*time.Minute))
	fenced, kubeClient := ownership(staleLease)
	if err := fenced.renewOnce(ctx); err != nil {
		t.Fatalf("renewOnce: %v", err)
	}
	if err := fenced.Healthy(); err != nil {
		t.Fatalf("ownership must be healthy after fencing: %v", err)
	}
	fences := fenced.Fences()
	if len(fences) != 2 || !fenceExists(fences, "legacy-orka", corev1alpha1.AgentExecutionLegacyLeaseName) ||
		!fenceExists(fences, corev1alpha1.AgentExecutionControlNamespace, corev1alpha1.AgentExecutionLegacyLeaseName) {
		t.Fatalf("fence set = %+v", fences)
	}
	updated := staleLease.DeepCopy()
	if err := kubeClient.Get(ctx, types.NamespacedName{Namespace: "legacy-orka", Name: staleLease.Name}, updated); err != nil {
		t.Fatal(err)
	}
	if updated.Spec.HolderIdentity == nil || *updated.Spec.HolderIdentity != "orka-coexistence" {
		t.Fatalf("legacy lease holder = %v", updated.Spec.HolderIdentity)
	}

	// A live foreign holder closes readiness: a legacy controller must be
	// stopped before ownership begins.
	liveLease := legacyLease("legacy-orka", "old-controller", time.Now())
	blocked, _ := ownership(liveLease)
	if err := blocked.renewOnce(ctx); err == nil {
		t.Fatal("live legacy holder must block the fence")
	}
	blocked.setUnhealthy("live holder")
	if err := blocked.Healthy(); err == nil {
		t.Fatal("readiness must fail while the fence is not held")
	}
}
