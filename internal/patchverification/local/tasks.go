package local

import (
	"context"
	"encoding/json"
	"errors"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	orkav1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	pv "github.com/orka-agents/orka/internal/patchverification"
)

const TaskNamespace = "local-patch-verification"

func Tasks(record *pv.Record) []orkav1alpha1.Task {
	if record == nil {
		return nil
	}
	tasks := make([]orkav1alpha1.Task, 0, 2)
	for _, side := range pv.ActionSides(record.Manifest.Action) {
		identity, source := record.Binding.OriginalTaskID, record.Manifest.Sources.Original
		if side == pv.Patched {
			identity, source = record.Binding.PatchedTaskID, record.Manifest.Sources.Patched
		}
		tasks = append(tasks, orkav1alpha1.Task{
			TypeMeta: metav1.TypeMeta{APIVersion: orkav1alpha1.GroupVersion.String(), Kind: "Task"},
			ObjectMeta: metav1.ObjectMeta{Name: "pv-" + identity + "-" + side, Namespace: TaskNamespace, UID: types.UID(identity), Annotations: map[string]string{
				"patchverification.orka.ai/run": record.Binding.RunID, "patchverification.orka.ai/side": side,
				"patchverification.orka.ai/backend": ExecutionBackend, "patchverification.orka.ai/manifest": record.Binding.ManifestDigest,
				"patchverification.orka.ai/source-tree": source.Tree,
				"patchverification.orka.ai/action":      string(pv.ActionOrDefault(record.Manifest.Action)),
				"patchverification.orka.ai/report":      record.Manifest.ReportDigest,
			}},
			Spec: orkav1alpha1.TaskSpec{Type: orkav1alpha1.TaskTypeContainer, Image: record.Manifest.Environment.Image,
				Command: []string{"/bin/sh", "-c", "exit 125"}, RetryPolicy: &orkav1alpha1.RetryPolicy{MaxRetries: 0},
				Workspace: &orkav1alpha1.WorkspaceConfig{Intent: orkav1alpha1.WorkspaceIntentRead, Ref: source.Commit},
			},
			Status: orkav1alpha1.TaskStatus{Phase: armPhase(record, side), Attempts: 1, Message: "Local Docker orchestration projection only; not reconciled by Kubernetes. Read the dedicated verification record for the conclusion."},
		})
	}
	return tasks
}

func armPhase(record *pv.Record, side string) orkav1alpha1.TaskPhase {
	if record.State == pv.RunCancelled {
		return orkav1alpha1.TaskPhaseCancelled
	}
	if record.State == pv.RunInterrupted || record.State == pv.RunInvalid {
		return orkav1alpha1.TaskPhaseFailed
	}
	count, failed := 0, false
	for _, entry := range record.Evidence {
		observation := entry.Observation
		if observation.Side != side {
			continue
		}
		count++
		failed = failed || entry.Rejection != "" || !observation.Executed || observation.SetupError != "" || observation.TimedOut || observation.Skipped || observation.OutputTruncated
	}
	if record.State == pv.RunFinalized {
		if failed || count != len(record.Manifest.Checks) {
			return orkav1alpha1.TaskPhaseFailed
		}
		return orkav1alpha1.TaskPhaseSucceeded
	}
	if count == 0 {
		return orkav1alpha1.TaskPhasePending
	}
	return orkav1alpha1.TaskPhaseRunning
}

func (service *Service) saveAuxiliary(ctx context.Context, record *pv.Record) error {
	if record == nil {
		return errors.New("record is unavailable")
	}
	result, err := json.Marshal(summarize(record))
	if err != nil {
		return err
	}
	for _, task := range Tasks(record) {
		content, err := json.Marshal(task)
		if err != nil {
			return err
		}
		if err := service.storage.SaveArtifact(ctx, task.Namespace, task.Name, "task.json", "application/json", content); err != nil {
			return err
		}
		if err := service.storage.SaveResult(ctx, task.Namespace, task.Name, result); err != nil {
			return err
		}
	}
	return nil
}
