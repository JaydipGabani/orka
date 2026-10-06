package controllerlab

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestControllerCannotLaunchWithoutTrustedPlacement(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, WaitingPlacement)
	require.Nil(t, s.Placement)
	_, err := l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))
	_, err = l.kube.NetworkingV1().NetworkPolicies(s.Namespaces[0]).Get(context.Background(), "controller-egress", metav1.GetOptions{})
	require.NoError(t, err)
	before := createCount(l.kube.Actions())
	next, err := l.adapter.Step(context.Background(), s, r)
	require.NoError(t, err)
	require.Equal(t, WaitingPlacement, next.Phase)
	require.Equal(t, s.Revision, next.Revision)
	require.Equal(t, before, createCount(l.kube.Actions()))
	pods, err := l.kube.CoreV1().Pods(s.Namespaces[0]).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Empty(t, pods.Items)
	r.Cancel = true
	final := l.until(t, next, r, State.Terminal)
	require.Equal(t, Cancelled, final.Outcome)
}

func TestPlacementIsParentAuthorizedDurableAndRenderedBeforeCreate(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, WaitingPlacement)
	r.Placement = syntheticPlacement(s)
	l.journal.reject = "bind-placement"
	_, err := l.adapter.Step(context.Background(), s, r)
	require.Error(t, err)
	require.Nil(t, l.journal.load(r).Placement)
	l.journal.reject = ""
	next, err := l.adapter.Step(context.Background(), s, r)
	require.NoError(t, err)
	require.Equal(t, InstallingController, next.Phase)
	require.Equal(t, r.Placement, l.journal.load(r).Placement)
	require.False(t, next.SubjectStartedAt.IsZero())
	require.True(t, next.Deadline.After(s.Deadline))
	_, err = l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))
	boundNode := r.Placement.NodeName
	r.Placement.NodeName = "modified-by-caller"
	require.Equal(t, boundNode, next.Placement.NodeName)
	r.Placement = nil
	next, err = l.step(next, r)
	require.NoError(t, err)
	deployment, err := l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, boundNode, deployment.Spec.Template.Spec.NodeName)
	require.Equal(t, boundNode, l.journal.load(r).Placement.NodeName)
	approved := false
	for _, mutation := range l.journal.mutations {
		if mutation.Action == "bind-placement" {
			require.Equal(t, syntheticPlacement(s), mutation.Placement)
			require.Equal(t, ref(deployments, s.Namespaces[0], controllerName), mutation.Object)
			approved = true
		}
	}
	require.True(t, approved)
}

func TestPlacementRejectsCrossOperationInvalidNodeAndMissingProof(t *testing.T) {
	t.Parallel()
	for _, variant := range []string{"operation", "node", "proof"} {
		t.Run(variant, func(t *testing.T) {
			t.Parallel()
			l := newTestLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, WaitingPlacement)
			r.Placement = syntheticPlacement(s)
			switch variant {
			case "operation":
				r.Placement.OperationDigest = strings.Repeat("f", 64)
			case "node":
				r.Placement.NodeName = "not/a/node"
			case "proof":
				r.Placement.ProofDigest = ""
			}
			_, err := l.adapter.Step(context.Background(), s, r)
			require.Error(t, err)
			require.Nil(t, l.journal.load(r).Placement)
			require.Nil(t, receiptFor(l.journal.load(r), ref(deployments, s.Namespaces[0], controllerName)))
		})
	}
}

func TestPlacementCannotBeReboundOrChangedInDeployedTemplate(t *testing.T) {
	t.Parallel()
	l := newTestLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, WaitingRuntime)
	r.Placement = clonePlacement(s.Placement)
	r.Placement.NodeName = "different-node"
	_, err := l.adapter.Step(context.Background(), s, r)
	require.Error(t, err)
	r.Placement = nil
	deployment, err := l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
	require.NoError(t, err)
	deployment.Spec.Template.Spec.NodeName = "different-node"
	require.NoError(t, l.kube.Tracker().Update(deployments, deployment, deployment.Namespace))
	s, err = l.adapter.Step(context.Background(), s, r)
	require.Error(t, err)
	require.Equal(t, Quarantined, s.Phase)
	require.Equal(t, Inconclusive, s.Outcome)
}

func TestPlacementIsNotModelPlanInput(t *testing.T) {
	t.Parallel()
	_, err := DecodePlan(strings.NewReader(`{"version":1,"placement":{"nodeName":"chosen-by-model"}}`))
	require.Error(t, err)
	l := newTestLab(t)
	r := l.request(Candidate)
	r.Placement = &SubjectPlacement{NodeName: "early-node", OperationDigest: strings.Repeat("a", 64), ProofDigest: strings.Repeat("b", 64)}
	_, err = l.adapter.Step(context.Background(), State{}, r)
	require.Error(t, err)
	require.Empty(t, l.kube.Actions())
}
