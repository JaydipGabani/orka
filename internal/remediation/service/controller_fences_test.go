package service

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestControllerRejectsChangedPlacementProofBeforeSubjectCreation(t *testing.T) {
	for _, mutation := range []string{"policy-revision", "policy-spec", "node-uid", "cluster-uid", "forged-proof", "forged-state"} {
		t.Run(mutation, func(t *testing.T) {
			t.Parallel()
			fixture := newControllerFixture(t)
			run := fixture.submit(Validate)
			var once atomic.Bool
			if mutation == "forged-proof" || mutation == "forged-state" {
				fixture.beforeState = func(next *controllerlab.State) {
					if next.Phase == controllerlab.InstallingController && next.Placement != nil && once.CompareAndSwap(false, true) {
						if mutation == "forged-proof" {
							placement := *next.Placement
							placement.ProofDigest = strings.Repeat("0", 64)
							next.Placement = &placement
						} else {
							next.PlanDigest = strings.Repeat("0", 64)
						}
					}
				}
			} else {
				fixture.afterState = func(ctx context.Context, next controllerlab.State) error {
					if next.Phase != controllerlab.InstallingController || next.Placement == nil || !once.CompareAndSwap(false, true) {
						return nil
					}
					switch mutation {
					case "policy-revision", "policy-spec":
						policy, err := fixture.kube.NetworkingV1().NetworkPolicies(next.Namespaces[0]).Get(ctx, "controller-egress", metav1.GetOptions{})
						require.NoError(t, err)
						if mutation == "policy-spec" {
							policy.Spec.Egress = nil
						} else {
							policy.ResourceVersion += "-changed"
						}
						_, err = fixture.kube.NetworkingV1().NetworkPolicies(next.Namespaces[0]).Update(ctx, policy, metav1.UpdateOptions{})
						require.NoError(t, err)
					case "node-uid":
						node, err := fixture.kube.CoreV1().Nodes().Get(ctx, next.Placement.NodeName, metav1.GetOptions{})
						require.NoError(t, err)
						node.UID = "replacement-node"
						_, err = fixture.kube.CoreV1().Nodes().Update(ctx, node, metav1.UpdateOptions{})
						require.NoError(t, err)
					case "cluster-uid":
						namespace, err := fixture.kube.CoreV1().Namespaces().Get(ctx, "kube-system", metav1.GetOptions{})
						require.NoError(t, err)
						namespace.UID = "replacement-cluster"
						_, err = fixture.kube.CoreV1().Namespaces().Update(ctx, namespace, metav1.UpdateOptions{})
						require.NoError(t, err)
					}
					return nil
				}
			}
			require.NoError(t, fixture.service.RunOnce(t.Context()))
			current, err := fixture.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
			require.NoError(t, err)
			var saved pipelineState
			require.NoError(t, json.Unmarshal(current.StateJSON, &saved))
			failure := ""
			if saved.Original.Controller != nil && saved.Original.Controller.Isolation != nil {
				failure = saved.Original.Controller.Isolation.FailureCode
			}
			require.True(t, once.Load(), "test never reached proof fence: phase=%s reason=%s isolation=%s", current.Phase, current.Reason, failure)
			require.NotEqual(t, store.RemediationPhaseSucceeded, current.Phase)
			for _, action := range fixture.kube.Actions() {
				require.False(t, action.GetVerb() == "create" && action.GetResource().Resource == "deployments",
					"subject was created using invalid placement evidence")
			}
		})
	}
}

func TestControllerCancellationSettlesBuildBeforeTerminal(t *testing.T) {
	t.Parallel()
	fixture := newControllerFixture(t)
	fixture.builder.blockBuild = make(chan struct{})
	run := fixture.submit(Validate)
	done := make(chan error, 1)
	go func() { done <- fixture.service.RunOnce(t.Context()) }()
	select {
	case <-fixture.builder.blockBuild:
	case <-time.After(30 * time.Second):
		// This includes original-arm setup; the cancellation bound below is separate.
		t.Fatal("rebuilt control did not enter build")
	}
	status, err := fixture.service.Cancel(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseCancelling, status.Phase)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled build did not settle")
	}
	require.Positive(t, fixture.builder.cancelled.Load())
	current, err := fixture.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseCancelled, current.Phase, current.Reason)
	var state pipelineState
	require.NoError(t, json.Unmarshal(current.StateJSON, &state))
	require.True(t, state.Control.Cleaned, "terminal state lost the build settlement receipt")
}

func TestControllerExitCannotBecomeReproductionOrProtection(t *testing.T) {
	t.Parallel()
	fixture := newControllerFixture(t)
	run := fixture.submit(Validate)
	var stopped atomic.Bool
	fixture.afterState = func(ctx context.Context, next controllerlab.State) error {
		if next.Phase != controllerlab.ObservingInitial || !stopped.CompareAndSwap(false, true) {
			return nil
		}
		deployment, err := fixture.kube.AppsV1().Deployments(next.Namespaces[0]).Get(ctx, "controller", metav1.GetOptions{})
		require.NoError(t, err)
		deployment.Status.ReadyReplicas, deployment.Status.AvailableReplicas = 0, 0
		_, err = fixture.kube.AppsV1().Deployments(next.Namespaces[0]).UpdateStatus(ctx, deployment, metav1.UpdateOptions{})
		require.NoError(t, err)
		return nil
	}
	require.NoError(t, fixture.service.RunOnce(t.Context()))
	current, err := fixture.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.True(t, stopped.Load())
	require.NotEqual(t, store.RemediationPhaseSucceeded, current.Phase)
	var state pipelineState
	require.NoError(t, json.Unmarshal(current.StateJSON, &state))
	require.Nil(t, state.Original.Observation)
}
