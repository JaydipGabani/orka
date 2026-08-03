package controller

import (
	"context"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/security"
	"github.com/orka-agents/orka/internal/store"
	sqlitestore "github.com/orka-agents/orka/internal/store/sqlite"
)

func TestCreateOrValidateSecurityTaskRejectsForgedExistingTask(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	scan := &corev1alpha1.RepositoryScan{
		TypeMeta:   metav1.TypeMeta{APIVersion: corev1alpha1.GroupVersion.String(), Kind: "RepositoryScan"},
		ObjectMeta: metav1.ObjectMeta{Name: "repo", Namespace: "ns", UID: types.UID("scan-uid")},
	}
	expected := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{Name: "security-task", Namespace: "ns", Labels: map[string]string{
			labels.LabelSecurityTarget: "repo", labels.LabelSecurityScanID: "scan-1", labels.LabelSecurityStage: "mapper",
		}},
		Spec: corev1alpha1.TaskSpec{Type: corev1alpha1.TaskTypeContainer, Command: []string{"--security-mapper"}},
	}
	if err := controllerutil.SetControllerReference(scan, expected, scheme); err != nil {
		t.Fatal(err)
	}
	forged := expected.DeepCopy()
	forged.OwnerReferences = nil
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(scan, forged).Build()
	reconciler := &RepositoryScanReconciler{Client: client, Scheme: scheme}

	err := reconciler.createOrValidateSecurityTask(context.Background(), scan, expected.DeepCopy())
	if err == nil || !strings.Contains(err.Error(), "not controlled") {
		t.Fatalf("createOrValidateSecurityTask() error = %v, want owner rejection", err)
	}
}

func TestCreateOrValidateSecurityTaskRejectsUnexpectedProtectedMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*corev1alpha1.Task)
	}{
		{
			name: "harness attempt annotation",
			mutate: func(task *corev1alpha1.Task) {
				if task.Annotations == nil {
					task.Annotations = map[string]string{}
				}
				task.Annotations["orka.ai/harness-wrapper-attempt"] = "9"
			},
		},
		{
			name: "extra security label",
			mutate: func(task *corev1alpha1.Task) {
				task.Labels[labels.LabelSecurityOccurrenceID] = "occ_forged"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := corev1alpha1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			scan := &corev1alpha1.RepositoryScan{
				TypeMeta:   metav1.TypeMeta{APIVersion: corev1alpha1.GroupVersion.String(), Kind: "RepositoryScan"},
				ObjectMeta: metav1.ObjectMeta{Name: "repo", Namespace: "ns", UID: types.UID("scan-uid")},
			}
			expected := &corev1alpha1.Task{
				ObjectMeta: metav1.ObjectMeta{Name: "security-task", Namespace: "ns", Labels: map[string]string{
					labels.LabelSecurityTarget: "repo", labels.LabelSecurityScanID: "scan-1", labels.LabelSecurityStage: "mapper",
				}},
				Spec: corev1alpha1.TaskSpec{Type: corev1alpha1.TaskTypeContainer, Command: []string{"--security-mapper"}},
			}
			if err := controllerutil.SetControllerReference(scan, expected, scheme); err != nil {
				t.Fatal(err)
			}
			existing := expected.DeepCopy()
			tt.mutate(existing)
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(scan, existing).Build()
			reconciler := &RepositoryScanReconciler{Client: client, Scheme: scheme}
			err := reconciler.createOrValidateSecurityTask(context.Background(), scan, expected.DeepCopy())
			if err == nil || !strings.Contains(err.Error(), "unexpected protected") {
				t.Fatalf("createOrValidateSecurityTask() error = %v, want protected metadata rejection", err)
			}
		})
	}
}

func TestImmutableRunThreatModelDoesNotUseMutableLatestModel(t *testing.T) {
	db, err := sqlitestore.NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlitestore.NewStore(db, ":memory:")
	run := &store.ScanRun{
		ID: "scan-1", RunUID: "run_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Namespace: "ns", RepositoryScan: "repo", TaskName: "task", Mode: "manual", Phase: "running",
		StartedAt: time.Now().UTC(), Quality: store.LegacyScanQuality(),
	}
	if err := s.CreateScanRun(context.Background(), run); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveSecurityRunThreatModel(context.Background(), &store.SecurityRunThreatModel{
		RunUID: run.RunUID, Namespace: run.Namespace, RepositoryScan: run.RepositoryScan, ScanRunID: run.ID,
		Version: 1, Content: "immutable model",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveThreatModel(context.Background(), &store.ThreatModel{
		Namespace: "ns", RepositoryScan: "repo", Content: "later edited model", Source: "edited",
	}); err != nil {
		t.Fatal(err)
	}
	reconciler := &RepositoryScanReconciler{SecurityStore: s, RunThreatModelStore: s}
	got, err := reconciler.immutableRunThreatModel(context.Background(), run)
	if err != nil {
		t.Fatalf("immutableRunThreatModel() error = %v", err)
	}
	if got != "immutable model" {
		t.Fatalf("immutableRunThreatModel() = %q, want immutable model", got)
	}
}

func TestImmutableRunThreatModelRejectsMalformedNonEmptyRunUID(t *testing.T) {
	db, err := sqlitestore.NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlitestore.NewStore(db, ":memory:")
	run := &store.ScanRun{
		ID: "scan-malformed", RunUID: "legacy-but-nonempty",
		Namespace: "ns", RepositoryScan: "repo", TaskName: "task", Mode: "manual", Phase: "running",
		StartedAt: time.Now().UTC(), Quality: store.LegacyScanQuality(),
	}
	if err := s.SaveThreatModel(context.Background(), &store.ThreatModel{
		Namespace: "ns", RepositoryScan: "repo", Content: "mutable fallback", Source: "generated",
		GeneratedByScan: run.ID,
	}); err != nil {
		t.Fatal(err)
	}
	reconciler := &RepositoryScanReconciler{SecurityStore: s, RunThreatModelStore: s}
	got, err := reconciler.immutableRunThreatModel(context.Background(), run)
	if err == nil || !strings.Contains(err.Error(), "valid non-empty run UID") {
		t.Fatalf("immutableRunThreatModel() = %q, error = %v, want malformed RunUID rejection", got, err)
	}
}

func TestImmutableRunThreatModelAllowsExplicitLegacyEmptyRunUID(t *testing.T) {
	db, err := sqlitestore.NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlitestore.NewStore(db, ":memory:")
	run := &store.ScanRun{
		ID: "scan-legacy", RunUID: "",
		Namespace: "ns", RepositoryScan: "repo", TaskName: "task", Mode: "manual", Phase: "running",
		StartedAt: time.Now().UTC(), Quality: store.LegacyScanQuality(),
	}
	if err := s.SaveThreatModel(context.Background(), &store.ThreatModel{
		Namespace: "ns", RepositoryScan: "repo", Content: "legacy model", Source: "generated",
		GeneratedByScan: run.ID,
	}); err != nil {
		t.Fatal(err)
	}
	reconciler := &RepositoryScanReconciler{SecurityStore: s, RunThreatModelStore: s}
	got, err := reconciler.immutableRunThreatModel(context.Background(), run)
	if err != nil {
		t.Fatalf("immutableRunThreatModel() error = %v", err)
	}
	if got != "legacy model" {
		t.Fatalf("immutableRunThreatModel() = %q, want legacy model", got)
	}
}

func TestAppendStageReceiptRejectsMixedArtifactGeneration(t *testing.T) {
	db, err := sqlitestore.NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlitestore.NewStore(db, ":memory:")
	const taskUID = "task-uid-1"
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name: "review-task", Namespace: "ns", UID: types.UID(taskUID), CreationTimestamp: metav1.Now(),
			Labels: map[string]string{labels.LabelSecurityStage: "review", labels.LabelSecuritySliceID: "slice-1"},
		},
		Status: corev1alpha1.TaskStatus{Phase: corev1alpha1.TaskPhaseSucceeded, Attempts: 1},
	}
	run := &store.ScanRun{
		ID: "scan-1", RunUID: "run_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Namespace: "ns", RepositoryScan: "repo", TaskName: task.Name, Mode: "manual", Phase: "running",
		StartedAt: time.Now().UTC(), Quality: store.LegacyScanQuality(),
	}
	if err := s.SaveBoundArtifact(context.Background(), &store.BoundArtifact{
		Namespace: "ns", TaskName: task.Name, Filename: "security-findings.v2.json", ContentType: "application/json",
		Data: []byte(`{"version":"new"}`),
		Provenance: store.OutputProvenance{
			TaskUID: taskUID, TaskAttempt: 1, ProducerKind: store.OutputProducerController,
			SubmissionNonceDigest: "writer-binding-1",
		},
	}); err != nil {
		t.Fatal(err)
	}
	reconciler := &RepositoryScanReconciler{IntegrityStore: s, ArtifactStore: s}
	err = reconciler.appendStageReceipt(
		context.Background(), task, run, "security-findings.v2.json",
		[]byte(`{"version":"parsed"}`), []byte(`{"version":"normalized"}`),
		store.StageReceiptAccepted, "", "",
	)
	if err == nil || !strings.Contains(err.Error(), "changed after parsing") {
		t.Fatalf("appendStageReceipt() error = %v, want mixed-generation rejection", err)
	}
}

func TestAppendStageReceiptPreservesRawArtifactBytes(t *testing.T) {
	db, err := sqlitestore.NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlitestore.NewStore(db, ":memory:")
	const taskUID = "task-uid-raw"
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name: "threat-task", Namespace: "ns", UID: types.UID(taskUID), CreationTimestamp: metav1.Now(),
			Labels: map[string]string{labels.LabelSecurityStage: "threat-model"},
		},
		Status: corev1alpha1.TaskStatus{Phase: corev1alpha1.TaskPhaseSucceeded, Attempts: 1},
	}
	run := &store.ScanRun{
		ID: "scan-raw", RunUID: "run_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Namespace: "ns", RepositoryScan: "repo", TaskName: task.Name, Mode: "manual", Phase: "running",
		StartedAt: time.Now().UTC(), Quality: store.LegacyScanQuality(),
	}
	raw := []byte("# Threat model\n")
	if err := s.SaveBoundArtifact(context.Background(), &store.BoundArtifact{
		Namespace: "ns", TaskName: task.Name, Filename: "security-threat-model.md", ContentType: "text/markdown",
		Data: raw,
		Provenance: store.OutputProvenance{
			TaskUID: taskUID, TaskAttempt: 1, ProducerKind: store.OutputProducerController,
			SubmissionNonceDigest: "writer-binding-raw",
		},
	}); err != nil {
		t.Fatal(err)
	}
	reconciler := &RepositoryScanReconciler{IntegrityStore: s, ArtifactStore: s}
	if err := reconciler.appendStageReceipt(
		context.Background(), task, run, "security-threat-model.md", raw, []byte("# Threat model"),
		store.StageReceiptAccepted, "", "",
	); err != nil {
		t.Fatalf("appendStageReceipt() error = %v", err)
	}
	receipts, _, err := s.ListStageReceipts(context.Background(), store.StageReceiptFilter{
		Namespace: "ns", ScanRunID: run.ID, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 || receipts[0].SourceArtifactSize != int64(len(raw)) ||
		receipts[0].SourceArtifactDigest != securityDigest(raw) {
		t.Fatalf("receipt raw binding = %#v", receipts)
	}
}

func TestSaveControllerArtifactHonorsBindingOff(t *testing.T) {
	db, err := sqlitestore.NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlitestore.NewStore(db, ":memory:")
	task := &corev1alpha1.Task{ObjectMeta: metav1.ObjectMeta{
		Name: "security-task", Namespace: "ns", UID: types.UID("security-task-uid"),
		Labels: map[string]string{labels.LabelCreatedBy: repositorySecurityCreatedBy},
	}}
	reconciler := &RepositoryScanReconciler{
		ArtifactStore:   s,
		IntegrityConfig: security.IntegrityConfig{WorkerOutputBindingMode: security.WorkerOutputBindingOff},
	}
	if err := reconciler.saveControllerArtifact(
		context.Background(), task, "diagnostic.json", "application/json", []byte(`{"ok":true}`),
	); err != nil {
		t.Fatal(err)
	}
	data, _, err := s.GetArtifact(context.Background(), task.Namespace, task.Name, "diagnostic.json")
	if err != nil || string(data) != `{"ok":true}` {
		t.Fatalf("legacy controller artifact = %q, %v", data, err)
	}
}
