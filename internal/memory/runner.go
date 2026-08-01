package memory

import (
	"context"
	"errors"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/orka-agents/orka/internal/store"
)

// Runner polls safe binding metadata and fairly attempts at most one operation
// per namespace per pass. It is suitable for controller-runtime manager.Add.
type Runner struct {
	Dispatcher *Dispatcher
	Store      store.GovernedMemoryStore
	Interval   time.Duration
}

// Start runs until manager shutdown.
func (r *Runner) Start(ctx context.Context) error {
	if r == nil || r.Dispatcher == nil || r.Store == nil {
		return nil
	}
	interval := r.Interval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := r.runPass(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.FromContext(ctx).Info("memory dispatcher pass deferred", "reason", boundedRunnerReason(err))
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (r *Runner) runPass(ctx context.Context) error {
	return forEachMemoryBackendBinding(ctx, r.Store, store.MemoryBackendBindingFilter{
		Modes:  []store.MemoryBackendMode{store.MemoryBackendModeRemote},
		States: []store.MemoryBackendBindingState{store.MemoryBackendBindingAccepting, store.MemoryBackendBindingDraining},
	}, func(binding store.MemoryBackendBinding) error {
		_, dispatchErr := r.Dispatcher.DispatchOne(ctx, binding.Namespace)
		if dispatchErr != nil && !errors.Is(dispatchErr, store.ErrNotFound) && !errors.Is(dispatchErr, store.ErrNotReady) {
			log.FromContext(ctx).Info("memory operation dispatch deferred", "reason", boundedRunnerReason(dispatchErr))
		}
		return ctx.Err()
	})
}

func boundedRunnerReason(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		return "not_found"
	case errors.Is(err, store.ErrNotReady):
		return "not_ready"
	case errors.Is(err, store.ErrConflict):
		return "conflict"
	case errors.Is(err, store.ErrCapacity):
		return "capacity"
	default:
		return "dependency_error"
	}
}
