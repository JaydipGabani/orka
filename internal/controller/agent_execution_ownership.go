/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

// AgentExecutionOwnership continuously acquires and renews the legacy
// 03b49a10.orka.ai leader-election Leases as a migration fence. A legacy
// controller cannot win election while the fence set is held; loss of any
// fenced Lease or discovery of a new unclassified holder closes readiness so
// every mutating runnable stops with it. The global orka-agent-execution Lease
// itself is held by controller-runtime leader election; this runnable holds
// only the legacy fence set and publishes the complete ownership state.
type AgentExecutionOwnership struct {
	Client   client.Client
	Reader   client.Reader
	Identity string
	// LeaseNamespace/LeaseName are the fixed global election Lease coordinates.
	LeaseNamespace string
	LeaseName      string
	// RenewInterval defaults to 10s; legacy lease duration defaults to 30s.
	RenewInterval time.Duration
	LeaseDuration time.Duration

	mu      sync.RWMutex
	healthy bool
	fences  []corev1alpha1.AgentExecutionLegacyLeaseFence
	reason  string
}

// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update

// NeedLeaderElection binds the fence set to the elected controller.
func (o *AgentExecutionOwnership) NeedLeaderElection() bool { return true }

// Healthy implements a readiness check: readiness fails until the complete
// legacy fence set is held and stays failed if any fence is lost.
func (o *AgentExecutionOwnership) Healthy() error {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if !o.healthy {
		return fmt.Errorf("agent execution ownership fence is not held: %s", o.reason)
	}
	return nil
}

// Fences returns the currently held legacy fence set.
func (o *AgentExecutionOwnership) Fences() []corev1alpha1.AgentExecutionLegacyLeaseFence {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return append([]corev1alpha1.AgentExecutionLegacyLeaseFence(nil), o.fences...)
}

// Start acquires the legacy fence set and renews it until ctx ends.
func (o *AgentExecutionOwnership) Start(ctx context.Context) error {
	log := logf.FromContext(ctx).WithName("agent-execution-ownership")
	renew := o.RenewInterval
	if renew <= 0 {
		renew = 10 * time.Second
	}
	if o.LeaseDuration <= 0 {
		o.LeaseDuration = 30 * time.Second
	}
	ticker := time.NewTicker(renew)
	defer ticker.Stop()
	for {
		if err := o.renewOnce(ctx); err != nil {
			o.setUnhealthy(err.Error())
			log.Error(err, "legacy lease fence renewal failed; readiness is closed and mutating runnables must stop")
		}
		select {
		case <-ctx.Done():
			o.setUnhealthy("ownership runnable stopped")
			return nil
		case <-ticker.C:
		}
	}
}

func (o *AgentExecutionOwnership) setUnhealthy(reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.healthy = false
	o.reason = reason
}

// renewOnce discovers every legacy Lease, acquires or renews each in
// deterministic namespace/name order, and refuses ownership while another
// live holder exists.
func (o *AgentExecutionOwnership) renewOnce(ctx context.Context) error {
	reader := o.Reader
	if reader == nil {
		reader = o.Client
	}
	leases := &coordinationv1.LeaseList{}
	if err := reader.List(ctx, leases); err != nil {
		return fmt.Errorf("enumerate legacy controller leases: %w", err)
	}
	now := metav1.NewMicroTime(time.Now())
	fences := make([]corev1alpha1.AgentExecutionLegacyLeaseFence, 0, len(leases.Items))
	for i := range leases.Items {
		lease := &leases.Items[i]
		if lease.Name != corev1alpha1.AgentExecutionLegacyLeaseName {
			continue
		}
		holder := ""
		if lease.Spec.HolderIdentity != nil {
			holder = *lease.Spec.HolderIdentity
		}
		if holder != "" && holder != o.Identity && leaseStillLive(lease, time.Now()) {
			return fmt.Errorf("legacy lease %s/%s is held by live holder %q; a legacy controller must be stopped before ownership begins",
				lease.Namespace, lease.Name, holder)
		}
		lease.Spec.HolderIdentity = new(o.Identity)
		lease.Spec.RenewTime = &now
		if lease.Spec.AcquireTime == nil || holder != o.Identity {
			lease.Spec.AcquireTime = &now
			transitions := int32(1)
			if lease.Spec.LeaseTransitions != nil {
				transitions = *lease.Spec.LeaseTransitions + 1
			}
			lease.Spec.LeaseTransitions = &transitions
		}
		lease.Spec.LeaseDurationSeconds = new(int32(o.LeaseDuration.Seconds()))
		if err := o.Client.Update(ctx, lease); err != nil {
			if apierrors.IsConflict(err) {
				return fmt.Errorf("legacy lease %s/%s was concurrently modified; a legacy controller may still be running", lease.Namespace, lease.Name)
			}
			return fmt.Errorf("fence legacy lease %s/%s: %w", lease.Namespace, lease.Name, err)
		}
		fences = append(fences, corev1alpha1.AgentExecutionLegacyLeaseFence{
			Namespace: lease.Namespace, Name: lease.Name, UID: lease.UID, ResourceVersion: lease.ResourceVersion,
		})
	}
	// Ensure a fence exists in the fixed ownership namespace even on clusters
	// that never ran a legacy controller, so a later legacy install cannot
	// elect itself there.
	if !fenceExists(fences, o.LeaseNamespace, corev1alpha1.AgentExecutionLegacyLeaseName) {
		fence, err := o.ensureTombstoneFence(ctx, now)
		if err != nil {
			return err
		}
		if fence != nil {
			fences = append(fences, *fence)
		}
	}
	o.mu.Lock()
	o.healthy = true
	o.reason = ""
	o.fences = fences
	o.mu.Unlock()
	return nil
}

func (o *AgentExecutionOwnership) ensureTombstoneFence(ctx context.Context, now metav1.MicroTime) (*corev1alpha1.AgentExecutionLegacyLeaseFence, error) {
	lease := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: o.LeaseNamespace,
			Name:      corev1alpha1.AgentExecutionLegacyLeaseName,
			Annotations: map[string]string{
				"orka.ai/agent-execution-fence": "held as a migration fence by the coexistence controller",
			},
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       new(o.Identity),
			AcquireTime:          &now,
			RenewTime:            &now,
			LeaseDurationSeconds: new(int32(o.LeaseDuration.Seconds())),
			LeaseTransitions:     new(int32(0)),
		},
	}
	if err := o.Client.Create(ctx, lease); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// The list will pick it up on the next renewal pass.
			return nil, nil
		}
		return nil, fmt.Errorf("create legacy fence tombstone: %w", err)
	}
	created := &coordinationv1.Lease{}
	if err := o.Client.Get(ctx, types.NamespacedName{Namespace: o.LeaseNamespace, Name: lease.Name}, created); err != nil {
		return nil, err
	}
	return &corev1alpha1.AgentExecutionLegacyLeaseFence{
		Namespace: created.Namespace, Name: created.Name, UID: created.UID, ResourceVersion: created.ResourceVersion,
	}, nil
}

func leaseStillLive(lease *coordinationv1.Lease, now time.Time) bool {
	if lease.Spec.RenewTime == nil {
		return false
	}
	duration := 30 * time.Second
	if lease.Spec.LeaseDurationSeconds != nil {
		duration = time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second
	}
	return now.Sub(lease.Spec.RenewTime.Time) <= duration
}

func fenceExists(fences []corev1alpha1.AgentExecutionLegacyLeaseFence, namespace, name string) bool {
	for _, fence := range fences {
		if fence.Namespace == namespace && fence.Name == name {
			return true
		}
	}
	return false
}
