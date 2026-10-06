package controllerlab

import (
	"slices"
	"time"
)

func normalControlsComplete(s State, final bool) bool {
	http := s.Evidence.InitialNormal
	if final {
		http = s.Evidence.FinalNormal
	}
	if http != [2]bool{true, true} {
		return false
	}
	if !publishing(s) {
		return true
	}
	p := s.Evidence.Publishing
	if p == nil {
		return false
	}
	if final {
		return p.FinalHTTPS == [2]bool{true, true} && p.FinalClusterHTTP == [2]bool{true, true}
	}
	return p.InitialHTTPS == [2]bool{true, true} && p.InitialClusterHTTP == [2]bool{true, true}
}

func validatePublishingRequest(h HTTPObservation) error {
	switch h.Route {
	case gridARoute, gridBRoute:
		if !h.TLSDataIngress || !h.SyntheticCredentialObserved || len(h.CloudEvents) == 0 {
			return failure(Infrastructure, "authenticated-tls-publishing-evidence-required")
		}
	case gridCredentialAttackRoute:
		if !h.TLSDataIngress || !h.SyntheticCredentialObserved {
			return failure(Infrastructure, "credential-attack-transport-evidence-required")
		}
	case httpARoute, httpBRoute, clusterHTTPRoute:
		if h.TLSDataIngress || h.SyntheticCredentialObserved {
			return failure(Infrastructure, "unexpected-http-publishing-transport-or-credential")
		}
	case metricRoute:
	default:
		return failure(Infrastructure, "unexpected-publishing-route")
	}
	return nil
}

func incorporatePublishingRequest(s *State, h HTTPObservation) error {
	if err := validatePublishingRequest(h); err != nil {
		return err
	}
	if h.Route == gridCredentialAttackRoute {
		s.Evidence.Publishing.CredentialAttack.Observed = true
	}
	return nil
}

func incorporatePublishingEvent(s *State, route string, index int, final bool) {
	e, p := &s.Evidence, s.Evidence.Publishing
	switch route {
	case httpARoute, httpBRoute:
		if route != []string{httpARoute, httpBRoute}[index] {
			p.HTTPCrossObserved, e.CrossObserved = true, true
		} else if final {
			e.FinalNormal[index] = true
		} else {
			e.InitialNormal[index] = true
		}
	case gridARoute, gridBRoute:
		if route != []string{gridARoute, gridBRoute}[index] {
			p.HTTPSCrossObserved, e.CrossObserved = true, true
		} else if final {
			p.FinalHTTPS[index] = true
		} else {
			p.InitialHTTPS[index] = true
		}
	case gridCredentialAttackRoute:
		if index == 1 {
			if final {
				p.CredentialAttack.FinalObserved = true
			} else {
				p.CredentialAttack.InitialObserved = true
			}
		}
	case clusterHTTPRoute:
		if final {
			p.FinalClusterHTTP[index] = true
		} else {
			p.InitialClusterHTTP[index] = true
		}
	}
}

func validatePublishingState(s State, capability Capability) error {
	if capability != KEDAEventPublishing {
		if s.Capability != "" || s.Evidence.Publishing != nil || s.RuntimePod != nil || s.FinalMarkerNonce != "" {
			return failure(InvalidState, "http-only-state-contract-changed")
		}
		return nil
	}
	if !publishing(s) || s.Evidence.Publishing == nil || !digestPattern.MatchString(s.FinalMarkerNonce) {
		return failure(InvalidState, "publishing-state-contract-required")
	}
	attack := s.Evidence.Publishing.CredentialAttack
	if (attack.InitialObserved || attack.FinalObserved) && !attack.Observed {
		return failure(InvalidState, "credential-attack-evidence-inconsistent")
	}
	if s.RuntimePod != nil && (s.RuntimePod.Resource != pods || s.RuntimePod.Namespace != s.Namespaces[0] ||
		s.RuntimePod.Name == "" || s.RuntimePod.UID == "") {
		return failure(InvalidState, "invalid-runtime-pod-pin")
	}
	if s.RuntimePod == nil && !slices.Contains([]Phase{
		Preflight, Preparing, WaitingObserver, InstallingController, WaitingPlacement, WaitingRuntime, Cleaning, Complete, Quarantined,
	}, s.Phase) {
		return failure(InvalidState, "runtime-pod-pin-required")
	}
	objects := allObjects(s)
	for index, receipt := range s.Receipts {
		if index >= len(objects) || !sameRef(receipt.Object, objects[index]) {
			return failure(InvalidState, "publishing-receipt-sequence-changed")
		}
	}
	expected := publishingReceiptCount(s)
	if expected >= 0 && len(s.Receipts) != expected {
		return failure(InvalidState, "publishing-step-or-receipt-omitted")
	}
	return nil
}

func publishingReceiptCount(s State) int {
	prepared := len(preparation(s))
	controller := prepared + len(controllerObjects(s))
	sources := controller + len(sourceObjects(s))
	initial := sources + len(fixtureObjects(s, false))
	switch s.Phase {
	case Preflight:
		return 0
	case Preparing:
		return s.Cursor
	case WaitingObserver:
		return prepared
	case InstallingController:
		return prepared + s.Cursor
	case WaitingPlacement:
		return prepared + 1
	case WaitingRuntime:
		return controller
	case InstallingSources:
		return controller + s.Cursor
	case WaitingSources:
		return sources
	case InstallingInitial:
		return sources + s.Cursor
	case ObservingInitial, ObservingWindow:
		return initial
	case InstallingFinal:
		return initial + s.Cursor
	case ObservingFinal, Settling:
		return len(allObjects(s))
	default:
		return -1
	}
}

func completedPublishingEvidence(s State) error {
	if !publishing(s) {
		if s.Capability != "" || s.Evidence.Publishing != nil || s.RuntimePod != nil || s.FinalMarkerNonce != "" {
			return failure(InvalidState, "comparison-capability-evidence-mismatch")
		}
		return nil
	}
	if err := validatePublishingState(s, KEDAEventPublishing); err != nil {
		return err
	}
	if err := validateReceipts(s); err != nil {
		return err
	}
	if s.RuntimePod == nil || s.Intent != nil || !s.ControllerStopped ||
		len(s.Receipts) != len(allObjects(s)) || !completedPublishingControls(s) {
		return failure(InvalidState, "comparison-publishing-controls-incomplete")
	}
	for _, receipt := range s.Receipts {
		if receipt.Object.UID == "" || !receipt.Deleted || !receipt.DeleteRequested {
			return failure(InvalidState, "comparison-publishing-cleanup-incomplete")
		}
		if fixtureBinding(receipt.Object.Resource) && !digestPattern.MatchString(receipt.BindingDigest) {
			return failure(InvalidState, "comparison-fixture-bindings-incomplete")
		}
		if receipt.FinalizerRemoval != nil && !receipt.FinalizerRemoval.Completed {
			return failure(InvalidState, "comparison-finalizer-cleanup-incomplete")
		}
	}
	p := s.Evidence.Publishing
	if s.Role == Candidate {
		if s.Outcome != Protected || s.Evidence.CrossObserved || p.HTTPCrossObserved || p.HTTPSCrossObserved ||
			p.CredentialAttack != (CredentialAttackEvidence{}) {
			return failure(InvalidState, "comparison-publishing-boundary-not-protected")
		}
	} else if s.Outcome != Reproduced || !s.Evidence.CrossObserved || !publishingAttacksReproduced(*p) {
		return failure(InvalidState, "comparison-publishing-reproduction-incomplete")
	}
	return nil
}

func publishingAttacksReproduced(p PublishingEvidence) bool {
	return p.HTTPCrossObserved && p.HTTPSCrossObserved && p.CredentialAttack.Observed &&
		p.CredentialAttack.InitialObserved && p.CredentialAttack.FinalObserved
}

func completedPublishingControls(s State) bool {
	return normalControlsComplete(s, false) && normalControlsComplete(s, true) &&
		s.Evidence.Generation == 1 && s.Evidence.HTTPCount > 0 &&
		digestPattern.MatchString(s.ImageDigest) && digestPattern.MatchString(s.Evidence.HTTPDigest) &&
		digestPattern.MatchString(s.Evidence.StateDigest) && digestPattern.MatchString(s.Evidence.BindingsDigest) &&
		!s.WindowStartedAt.IsZero() &&
		!s.TailStartedAt.IsZero() && s.TailStartedAt.Sub(s.WindowStartedAt) >= 10*time.Second
}
