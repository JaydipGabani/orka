package tools

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/labels"
	"github.com/orka-agents/orka/internal/store"
	sqlitestore "github.com/orka-agents/orka/internal/store/sqlite"
)

func TestToolTaskResultUsesLiveBoundAttempt(t *testing.T) {
	db, err := sqlitestore.NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlitestore.NewStore(db, ":memory:")
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name: "security-task", Namespace: "ns", UID: types.UID("task-uid"),
			Labels: map[string]string{labels.LabelCreatedBy: repositorySecurityCreatedBy},
		},
		Status: corev1alpha1.TaskStatus{Phase: corev1alpha1.TaskPhaseSucceeded, Attempts: 2},
	}
	ctx := context.Background()
	if err := s.SaveBoundResult(ctx, &store.BoundResult{
		Namespace: task.Namespace, TaskName: task.Name, Data: []byte("old"),
		Provenance: store.OutputProvenance{
			TaskUID: string(task.UID), TaskAttempt: 1, ProducerKind: store.OutputProducerController,
			SubmissionNonceDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}); err != nil {
		t.Fatal(err)
	}
	stale, err := s.GetBoundResult(ctx, task.Namespace, task.Name, string(task.UID), 1)
	if err != nil || string(stale.Data) != "old" {
		t.Fatalf("GetBoundResult(attempt 1) = %#v, %v", stale, err)
	}
	toolCtx := &ToolContext{ResultStore: s}
	if _, err := toolTaskResult(ctx, toolCtx, task); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("toolTaskResult(stale attempt) error = %v, want ErrNotFound", err)
	}
	if err := s.SaveBoundResult(ctx, &store.BoundResult{
		Namespace: task.Namespace, TaskName: task.Name, Data: []byte("current"),
		Provenance: store.OutputProvenance{
			TaskUID: string(task.UID), TaskAttempt: 2, ProducerKind: store.OutputProducerController,
			SubmissionNonceDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		},
	}); err != nil {
		t.Fatal(err)
	}
	data, err := toolTaskResult(ctx, toolCtx, task)
	if err != nil || string(data) != "current" {
		t.Fatalf("toolTaskResult(current) = %q, %v", data, err)
	}
}

func TestToolTaskResultOwnerBindingCannotFallBackToLegacyOutput(t *testing.T) {
	db, err := sqlitestore.NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlitestore.NewStore(db, ":memory:")
	controller := true
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name: "security-task", Namespace: "ns", UID: types.UID("current-task-uid"),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: corev1alpha1.GroupVersion.String(), Kind: "RepositoryScan", Name: "repo",
				UID: types.UID("repository-scan-uid"), Controller: &controller,
			}},
		},
		Status: corev1alpha1.TaskStatus{Phase: corev1alpha1.TaskPhaseSucceeded, Attempts: 1},
	}
	if err := s.SaveResult(context.Background(), task.Namespace, task.Name, []byte("stale legacy output")); err != nil {
		t.Fatal(err)
	}
	_, err = toolTaskResult(context.Background(), &ToolContext{ResultStore: s}, task)
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("toolTaskResult() error = %v, want bound-output conflict", err)
	}
}

func TestToolTaskResultUsesOwnerBoundOutputWithoutMutableLabel(t *testing.T) {
	db, err := sqlitestore.NewDB(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sqlitestore.NewStore(db, ":memory:")
	controller := true
	task := &corev1alpha1.Task{
		ObjectMeta: metav1.ObjectMeta{
			Name: "security-task", Namespace: "ns", UID: types.UID("current-task-uid"),
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: corev1alpha1.GroupVersion.String(), Kind: "RepositoryScan", Name: "repo",
				UID: types.UID("repository-scan-uid"), Controller: &controller,
			}},
		},
		Status: corev1alpha1.TaskStatus{Phase: corev1alpha1.TaskPhaseSucceeded, Attempts: 1},
	}
	if err := s.SaveBoundResult(context.Background(), &store.BoundResult{
		Namespace: task.Namespace, TaskName: task.Name, Data: []byte("current"),
		Provenance: store.OutputProvenance{
			TaskUID: string(task.UID), TaskAttempt: 1, ProducerKind: store.OutputProducerController,
			SubmissionNonceDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		},
	}); err != nil {
		t.Fatal(err)
	}
	data, err := toolTaskResult(context.Background(), &ToolContext{ResultStore: s}, task)
	if err != nil || string(data) != "current" {
		t.Fatalf("toolTaskResult() = %q, %v", data, err)
	}
}
