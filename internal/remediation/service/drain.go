package service

import (
	"context"
	"time"

	"github.com/orka-agents/orka/internal/store"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type DrainStatus struct {
	Namespace       string `json:"namespace"`
	Complete        bool   `json:"complete"`
	Active          int64  `json:"active"`
	Quarantined     int64  `json:"quarantined"`
	RetainedIntakes int64  `json:"retainedIntakes"`
	IntakeDrained   bool   `json:"intakeDrained"`
}

// Drain counts all runs without reading private payloads or treating a page of
// recently completed runs as proof that older resources have settled.
func (s *Service) Drain(ctx context.Context) (DrainStatus, error) {
	counts, err := s.config.Store.CountRemediationRuns(ctx, s.config.Namespace)
	if err != nil {
		return DrainStatus{}, err
	}
	return DrainStatus{
		Namespace: s.config.Namespace,
		Active:    counts.Active, Quarantined: counts.Quarantined,
		Complete:        counts.Active == 0 && counts.Quarantined == 0,
		RetainedIntakes: counts.RetainedIntakes, IntakeDrained: counts.RetainedIntakes == 0,
	}, nil
}

type RunSummary struct {
	ID              string                    `json:"id"`
	Namespace       string                    `json:"namespace"`
	Mode            string                    `json:"mode"`
	Phase           string                    `json:"phase"`
	Reason          string                    `json:"reason,omitempty"`
	Revision        uint64                    `json:"revision"`
	CancelRequested bool                      `json:"cancelRequested"`
	CreatedAt       time.Time                 `json:"createdAt"`
	UpdatedAt       time.Time                 `json:"updatedAt"`
	Deadline        time.Time                 `json:"deadline"`
	Cleanup         *store.RemediationCleanup `json:"cleanup,omitempty"`
}

type RunList struct {
	Items    []RunSummary `json:"items"`
	Continue string       `json:"continue,omitempty"`
}

func (s *Service) List(ctx context.Context, namespace string, limit int, beforeID string) (RunList, error) {
	if s == nil || namespace != s.config.Namespace {
		return RunList{}, store.ErrNotFound
	}
	page, err := s.config.Store.ListRemediationRunsPage(ctx, namespace, limit, beforeID)
	if err != nil {
		return RunList{}, err
	}
	result := RunList{Items: make([]RunSummary, 0, len(page.Items)), Continue: page.Continue}
	for _, run := range page.Items {
		result.Items = append(result.Items, RunSummary{
			ID: run.ID, Namespace: run.Namespace, Mode: run.Mode, Phase: run.Phase, Reason: run.Reason,
			Revision: run.Revision, CancelRequested: run.CancelRequested, CreatedAt: run.CreatedAt,
			UpdatedAt: run.UpdatedAt, Deadline: run.Deadline, Cleanup: run.Cleanup,
		})
	}
	return result, nil
}

func (s *Service) DrainNamespace(ctx context.Context, namespace string) (DrainStatus, error) {
	if s == nil || namespace != s.config.Namespace {
		return DrainStatus{}, store.ErrNotFound
	}
	return s.Drain(ctx)
}

func (s *Service) ReconcileCleanup(ctx context.Context, namespace, id, actor string, expectedRevision uint64) (Status, error) {
	if s == nil || namespace != s.config.Namespace {
		return Status{}, store.ErrNotFound
	}
	run, err := s.config.Store.ReconcileRemediationCleanup(ctx, namespace, id, actor, expectedRevision, time.Now().UTC())
	if err != nil {
		return Status{}, err
	}
	log.FromContext(ctx).Info("remediation cleanup reconciliation authorized and recorded",
		"namespace", namespace, "runID", id, "actor", actor, "expectedRevision", expectedRevision, "revision", run.Revision)
	return statusOf(run)
}

func (s *Service) retainIntake(ctx context.Context) {
	ticker := time.NewTicker(s.config.IntakeRetentionInterval)
	defer ticker.Stop()
	for {
		_, err := s.config.Store.PruneRemediationIntake(ctx, s.config.Namespace,
			time.Now().UTC().Add(-s.config.IntakeRetention), store.RemediationMaxListLimit)
		if err != nil && ctx.Err() == nil {
			log.FromContext(ctx).Error(ErrRetryable, "remediation intake retention requires reconciliation",
				"namespace", s.config.Namespace)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
