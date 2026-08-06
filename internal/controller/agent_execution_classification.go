/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	"github.com/orka-agents/orka/internal/store"
)

// harnessWrapperTurnIDAnnotation is the historical v1 wrapper turn identity
// annotation. Annotations alone are never sufficient adoption evidence.
const harnessWrapperTurnIDAnnotation = "orka.ai/harness-wrapper-turn-id"

type classificationOutcome string

const (
	classificationAdopted     classificationOutcome = "adopted"
	classificationQuarantined classificationOutcome = "quarantined"
	classificationNoExecution classificationOutcome = "no-execution"
)

// AgentExecutionClassifier runs the sealed legacy-adoption sweep: every
// pre-existing execution- or cleanup-relevant agent Task is bound, recorded as
// proven no-execution, or quarantined from authoritative evidence before the
// dispatchers admit new work. It is a bounded migration operation, not a
// permanent inference rule: Tasks created after the binding stage is enabled
// receive bindings through the normal reservation-backed path.
type AgentExecutionClassifier struct {
	Client      client.Client
	Reader      client.Reader
	Snapshots   store.AgentExecutionSnapshotStore
	Recorder    record.EventRecorder
	InventoryID string
}

// NeedLeaderElection restricts the sweep to the elected controller.
func (c *AgentExecutionClassifier) NeedLeaderElection() bool { return true }

// Start runs one sweep and returns; the manager keeps other runnables alive.
func (c *AgentExecutionClassifier) Start(ctx context.Context) error {
	if c.Snapshots == nil {
		logf.FromContext(ctx).Info("agent execution classification sweep skipped: binding stage is disabled")
		return nil
	}
	if err := c.Sweep(ctx); err != nil {
		// The sweep is idempotent and re-runs on the next election; classification
		// failure must not kill the manager, but it is loud.
		logf.FromContext(ctx).Error(err, "agent execution classification sweep failed; unclassified pre-existing Tasks stay fail-closed")
	}
	return nil
}

// Sweep classifies every pre-existing agent Task exactly once.
func (c *AgentExecutionClassifier) Sweep(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("agent-execution-classifier")
	reader := c.Reader
	if reader == nil {
		reader = c.Client
	}
	inventoryID := c.InventoryID
	if inventoryID == "" {
		inventoryID = "coexistence-" + time.Now().UTC().Format("2006-01-02")
	}

	tasks := &corev1alpha1.TaskList{}
	if err := reader.List(ctx, tasks); err != nil {
		return fmt.Errorf("list tasks for classification: %w", err)
	}
	var classified, quarantined, noExecution int
	quarantineByReason := map[string]int{}
	for i := range tasks.Items {
		task := &tasks.Items[i]
		if task.Spec.Type != corev1alpha1.TaskTypeAgent || task.Spec.Schedule != "" {
			continue
		}
		if quarantine := task.Status.AgentExecutionQuarantine; quarantine != nil {
			quarantineByReason[string(quarantine.Reason)]++
		}
		if task.Status.AgentExecutionBinding != nil || task.Status.AgentExecutionQuarantine != nil ||
			task.Status.AgentExecutionNoExecution != nil {
			continue
		}
		if taskPhaseTerminal(task.Status.Phase) && task.DeletionTimestamp.IsZero() {
			// Historical terminal Tasks retain their fields until retention
			// completes; they need no execution or cleanup ownership.
			continue
		}
		outcome, err := c.classifyTask(ctx, reader, task, inventoryID)
		if err != nil {
			log.Error(err, "classify task", "namespace", task.Namespace, "task", task.Name)
			continue
		}
		switch outcome {
		case classificationAdopted:
			classified++
		case classificationQuarantined:
			quarantined++
		case classificationNoExecution:
			noExecution++
		}
	}
	agentExecutionQuarantinedActive.Reset()
	for reason, count := range quarantineByReason {
		agentExecutionQuarantinedActive.WithLabelValues(reason).Set(float64(count))
	}
	log.Info("agent execution classification sweep complete",
		"inventoryID", inventoryID, "adopted", classified, "quarantined", quarantined, "noExecution", noExecution)
	return nil
}

func taskPhaseTerminal(phase corev1alpha1.TaskPhase) bool {
	switch phase {
	case corev1alpha1.TaskPhaseSucceeded, corev1alpha1.TaskPhaseFailed, corev1alpha1.TaskPhaseCancelled:
		return true
	default:
		return false
	}
}

// classifyTask queries authoritative evidence in the plan's order: v2
// authoritative records first, durable v1 records second, task-local
// configuration last. Mixed evidence quarantines; a deleting Task without any
// route-specific state records the immutable no-execution disposition.
func (c *AgentExecutionClassifier) classifyTask(
	ctx context.Context,
	reader client.Reader,
	task *corev1alpha1.Task,
	inventoryID string,
) (classificationOutcome, error) {
	v2Evidence, v2Digest, err := c.gatherV2Evidence(ctx, reader, task)
	if err != nil {
		return "", err
	}
	v1Evidence, v1Digest := gatherV1Evidence(task)

	switch {
	case v2Evidence && v1Evidence:
		return classificationQuarantined, c.recordQuarantine(ctx, task, corev1alpha1.AgentExecutionQuarantine{
			SchemaVersion: 1, Reason: corev1alpha1.AgentExecutionQuarantineMixedEvidence,
			MigrationInventoryID: inventoryID, V1EvidenceDigest: v1Digest, V2EvidenceDigest: v2Digest,
			RecordedAt: metav1.Now(),
		})
	case v2Evidence:
		return classificationAdopted, c.adoptBinding(ctx, task, corev1alpha1.AgentRuntimeContractHarnessV2,
			corev1alpha1.AgentExecutionBackendRuntimePool, v2Digest, inventoryID)
	case v1Evidence:
		return classificationAdopted, c.adoptBinding(ctx, task, corev1alpha1.AgentRuntimeContractHarnessV1,
			corev1alpha1.AgentExecutionBackendHarnessWrapper, v1Digest, inventoryID)
	case hasUncorroboratedLegacyAnnotations(task):
		// Annotations alone are never sufficient adoption evidence.
		return classificationQuarantined, c.recordQuarantine(ctx, task, corev1alpha1.AgentExecutionQuarantine{
			SchemaVersion: 1, Reason: corev1alpha1.AgentExecutionQuarantineAmbiguousLegacyEvidence,
			MigrationInventoryID: inventoryID, RecordedAt: metav1.Now(),
		})
	case !task.DeletionTimestamp.IsZero():
		evidenceDigest, digestErr := acpDomainDigest("no-execution-evidence", map[string]string{
			"taskUID": string(task.UID), "inventory": inventoryID,
		})
		if digestErr != nil {
			return "", digestErr
		}
		return classificationNoExecution, c.recordNoExecution(ctx, task, corev1alpha1.AgentExecutionNoExecution{
			SchemaVersion: 1, State: corev1alpha1.AgentExecutionNoExecutionUnbound,
			MigrationInventoryID: inventoryID, EvidenceDigest: evidenceDigest, RecordedAt: metav1.Now(),
		})
	default:
		// No executor-specific state: the normal reservation-backed binding
		// stage classifies this Task when its Agent carries an explicit
		// selector; until then execution admission stays fail-closed.
		return "", nil
	}
}

// gatherV2Evidence consults every v2 authoritative surface keyed to the Task
// UID: durable execution/delivery status and PromptAttempt control records.
func (c *AgentExecutionClassifier) gatherV2Evidence(
	ctx context.Context,
	reader client.Reader,
	task *corev1alpha1.Task,
) (bool, string, error) {
	summary := map[string]string{}
	if task.Status.Execution != nil {
		summary["execution"] = string(task.Status.Execution.State)
	}
	if task.Status.Delivery != nil {
		summary["delivery"] = string(task.Status.Delivery.State)
	}
	attempts := &corev1alpha1.PromptAttemptList{}
	if err := reader.List(ctx, attempts, client.InNamespace(task.Namespace),
		client.MatchingLabels{corev1alpha1.ControlRecordTaskUIDLabel: string(task.UID)}); err != nil {
		return false, "", fmt.Errorf("list prompt attempts for %s: %w", task.UID, err)
	}
	for i := range attempts.Items {
		if attempts.Items[i].Spec.TaskUID == string(task.UID) {
			summary["promptAttempt/"+attempts.Items[i].Spec.ID] = string(attempts.Items[i].Status.ExecutionState)
		}
	}
	if len(summary) == 0 {
		return false, "", nil
	}
	digest, err := acpDomainDigest("v2-adoption-evidence", summary)
	if err != nil {
		return false, "", err
	}
	return true, digest, nil
}

// gatherV1Evidence accepts only durable controller-owned v1 state. The
// historical wrapper annotations are corroboration targets, not evidence.
func gatherV1Evidence(task *corev1alpha1.Task) (bool, string) {
	if task.Status.HarnessRuntime == nil {
		return false, ""
	}
	digest, err := acpDomainDigest("v1-adoption-evidence", task.Status.HarnessRuntime)
	if err != nil {
		return false, ""
	}
	return true, digest
}

func hasUncorroboratedLegacyAnnotations(task *corev1alpha1.Task) bool {
	return strings.TrimSpace(task.Annotations[harnessWrapperTurnIDAnnotation]) != ""
}

// adoptBinding writes a legacy-adopted binding referencing an adoption
// snapshot built from the durable evidence itself, never from mutable live
// configuration.
func (c *AgentExecutionClassifier) adoptBinding(
	ctx context.Context,
	task *corev1alpha1.Task,
	contract corev1alpha1.AgentRuntimeContractVersion,
	backend corev1alpha1.AgentExecutionBackend,
	evidenceDigest string,
	inventoryID string,
) error {
	mode := corev1alpha1.AgentExecutionBindingModeExecute
	provenance := corev1alpha1.AgentExecutionProvenanceLegacyAdopted
	agentRef, agentComplete := c.resolveAdoptionAgentRef(ctx, task)
	if !agentComplete {
		// Incomplete identity evidence: the record may be observed, cancelled,
		// or settled, but never retried, continued, or satisfied by a
		// recreated runtime.
		mode = corev1alpha1.AgentExecutionBindingModeCleanupOnly
		provenance = corev1alpha1.AgentExecutionProvenanceLegacyCleanupOnly
	}

	namespace := &corev1.Namespace{}
	if err := c.Reader.Get(ctx, types.NamespacedName{Name: task.Namespace}, namespace); err != nil {
		return fmt.Errorf("resolve namespace identity for adoption: %w", err)
	}

	body := fmt.Appendf(nil,
		`{"schemaVersion":1,"adoption":true,"inventoryID":%q,"taskUID":%q,"contract":%q,"evidenceDigest":%q}`,
		inventoryID, task.UID, contract, evidenceDigest,
	)
	snapshotDigest := store.CanonicalAgentExecutionSnapshotDigest(body)
	if err := c.Snapshots.PersistAgentExecutionSnapshot(ctx, store.AgentExecutionSnapshot{
		TaskUID: string(task.UID), Digest: snapshotDigest,
		SchemaVersion: store.AgentExecutionSnapshotSchemaVersion, Body: body,
	}); err != nil {
		return fmt.Errorf("persist adoption snapshot: %w", err)
	}

	binding := corev1alpha1.AgentExecutionBinding{
		SchemaVersion: 1, Mode: mode, ContractVersion: contract, Backend: backend, Provenance: provenance,
		Task: corev1alpha1.AgentExecutionBindingTaskRef{
			NamespaceUID: namespace.UID, UID: task.UID, BoundSpecGeneration: max(task.Generation, 1),
		},
		Agent: agentRef,
		Snapshot: corev1alpha1.AgentExecutionSnapshotRef{
			ID: string(task.UID) + "/" + snapshotDigest, Digest: snapshotDigest,
			SchemaVersion: store.AgentExecutionSnapshotSchemaVersion,
		},
	}
	if task.Spec.AgentRef != nil {
		if agent, ok := c.adoptionAgent(ctx, task); ok && agent.Spec.Runtime != nil {
			binding.RuntimeType = agent.Spec.Runtime.Type
		}
	}
	digest, err := canonicalAgentExecutionBindingDigest(binding)
	if err != nil {
		return err
	}
	binding.BindingDigest = digest
	binding.BoundAt = metav1.Now()
	return c.patchClassification(ctx, task, func(status *corev1alpha1.TaskStatus) {
		status.AgentExecutionBinding = binding.DeepCopy()
	})
}

func (c *AgentExecutionClassifier) adoptionAgent(ctx context.Context, task *corev1alpha1.Task) (*corev1alpha1.Agent, bool) {
	if task.Spec.AgentRef == nil {
		return nil, false
	}
	namespace := task.Spec.AgentRef.Namespace
	if namespace == "" {
		namespace = task.Namespace
	}
	agent := &corev1alpha1.Agent{}
	if err := c.Reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: task.Spec.AgentRef.Name}, agent); err != nil {
		return nil, false
	}
	return agent, true
}

// resolveAdoptionAgentRef pins the current Agent identity only when the live
// object still exists; a historical Agent UID is never inferred from a
// same-name recreation, so a missing Agent downgrades to cleanup-only.
func (c *AgentExecutionClassifier) resolveAdoptionAgentRef(
	ctx context.Context,
	task *corev1alpha1.Task,
) (*corev1alpha1.AgentExecutionAgentRef, bool) {
	agent, ok := c.adoptionAgent(ctx, task)
	if !ok {
		return nil, false
	}
	return &corev1alpha1.AgentExecutionAgentRef{
		Namespace: agent.Namespace, Name: agent.Name, UID: agent.UID, Generation: max(agent.Generation, 1),
	}, true
}

func (c *AgentExecutionClassifier) recordQuarantine(ctx context.Context, task *corev1alpha1.Task, quarantine corev1alpha1.AgentExecutionQuarantine) error {
	if c.Recorder != nil {
		c.Recorder.Eventf(task, corev1.EventTypeWarning, "AgentExecutionQuarantined",
			"mixed or unprovable route evidence (%s); execution admission is blocked until adjudication", quarantine.Reason)
	}
	return c.patchClassification(ctx, task, func(status *corev1alpha1.TaskStatus) {
		status.AgentExecutionQuarantine = quarantine.DeepCopy()
	})
}

func (c *AgentExecutionClassifier) recordNoExecution(ctx context.Context, task *corev1alpha1.Task, disposition corev1alpha1.AgentExecutionNoExecution) error {
	return c.patchClassification(ctx, task, func(status *corev1alpha1.TaskStatus) {
		status.AgentExecutionNoExecution = disposition.DeepCopy()
	})
}

func (c *AgentExecutionClassifier) patchClassification(ctx context.Context, task *corev1alpha1.Task, mutate func(*corev1alpha1.TaskStatus)) error {
	current := &corev1alpha1.Task{}
	reader := c.Reader
	if reader == nil {
		reader = c.Client
	}
	if err := reader.Get(ctx, types.NamespacedName{Namespace: task.Namespace, Name: task.Name}, current); err != nil {
		return err
	}
	if current.UID != task.UID {
		return fmt.Errorf("task UID changed during classification; skipping")
	}
	if current.Status.AgentExecutionBinding != nil || current.Status.AgentExecutionQuarantine != nil ||
		current.Status.AgentExecutionNoExecution != nil {
		return nil
	}
	base := current.DeepCopy()
	mutate(&current.Status)
	return c.Client.Status().Patch(ctx, current, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{}))
}
