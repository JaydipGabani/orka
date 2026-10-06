package controllerlab

import (
	"context"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

func clonePlacement(p *SubjectPlacement) *SubjectPlacement {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}

func (a *Adapter) checkPlacementRuntime(ctx context.Context, s State) error {
	target := ref(deployments, s.Namespaces[0], controllerName)
	if receiptFor(s, target) == nil {
		return nil
	}
	value, err := a.exact(ctx, s, target)
	if err != nil {
		return err
	}
	deployment := value.(*appsv1.Deployment)
	if !validPlacement(s.Placement, s.OperationDigest) || deployment.Spec.Template.Spec.NodeName != s.Placement.NodeName ||
		len(deployment.Spec.Template.Spec.Containers) != 1 ||
		imageContentDigest(deployment.Spec.Template.Spec.Containers[0].Image) != s.ImageDigest {
		if publishing(s) {
			return failure(Infrastructure, "subject-node-or-image-binding-changed")
		}
		return failure(OwnershipLost, "subject-node-or-image-binding-changed")
	}
	if publishing(s) {
		receipt := receiptFor(s, target)
		expected := a.controller(s, metadata(s, target, receipt.IntentDigest), deployment.Spec.Template.Spec.Containers[0].Image)
		if !publishingPodEnvelope(deployment.Spec.Template.Spec) || !desiredMatches(expected, deployment) {
			return failure(Infrastructure, "publishing-controller-template-changed")
		}
	}
	return nil
}

func validPlacement(p *SubjectPlacement, operation string) bool {
	return p != nil && p.OperationDigest == operation && digestPattern.MatchString(p.OperationDigest) &&
		p.NodeName != "" && len(validation.IsDNS1123Subdomain(p.NodeName)) == 0 && digestPattern.MatchString(p.ProofDigest)
}

func validatePlacementState(s State, requested *SubjectPlacement) error {
	if requested != nil && (!validPlacement(requested, s.OperationDigest) ||
		(s.Placement != nil && *requested != *s.Placement)) {
		return failure(InvalidState, "trusted-placement-binding-changed")
	}
	if s.Placement != nil {
		if !validPlacement(s.Placement, s.OperationDigest) || s.SubjectStartedAt.IsZero() {
			return failure(InvalidState, "invalid-persisted-placement")
		}
		return nil
	}
	if !s.SubjectStartedAt.IsZero() || !slices.Contains([]Phase{
		Preflight, Preparing, WaitingObserver, InstallingController, WaitingPlacement, Cleaning, Complete, Quarantined,
	}, s.Phase) {
		return failure(InvalidState, "trusted-subject-placement-required")
	}
	return nil
}

func (a *Adapter) bindPlacement(ctx context.Context, s State, placement *SubjectPlacement) (State, error) {
	if placement == nil {
		return s, nil
	}
	if s.Placement != nil || !validPlacement(placement, s.OperationDigest) {
		return s, failure(InvalidState, "invalid-trusted-subject-placement")
	}
	next := cloneState(s)
	next.Placement = clonePlacement(placement)
	if err := a.accept(ctx, next, "bind-placement", ref(deployments, s.Namespaces[0], controllerName)); err != nil {
		return s, err
	}
	next.SubjectStartedAt = a.now().UTC()
	next.Deadline = a.now().Add(2*a.config.StartupTimeout + a.config.ObservationWindow + a.config.TailWindow)
	next.Phase, next.Cursor = InstallingController, 1
	return a.save(ctx, next)
}
