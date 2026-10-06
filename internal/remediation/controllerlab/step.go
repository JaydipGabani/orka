package controllerlab

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
)

// Step performs at most one persistent Kubernetes mutation and at most
// MaxStepClientOperations bounded client operations, including read-only
// authorization reviews and production observer port-forward checks.
// It does not sleep. The parent serializes durable revisions, schedules polls,
// retains terminal tombstones, and invokes Cancel with a fresh live context.
func (a *Adapter) Step(ctx context.Context, input State, request Request) (State, error) {
	ctx, cancel := context.WithTimeout(ctx, a.config.OperationTimeout)
	defer cancel()
	if ctx.Err() != nil {
		return input, failure(Infrastructure, "step-context-ended")
	}
	binding, err := a.validateRequest(request)
	if err != nil {
		return input, err
	}
	s := cloneState(input)
	operation := a.operationDigest(request, binding)
	if s.Version == 0 {
		if !reflectEmpty(s) {
			return s, failure(InvalidState, "nonempty-initial-state")
		}
		if request.Placement != nil {
			return input, failure(InvalidState, "placement-requires-prepared-environment")
		}
		now := a.now().UTC()
		s = State{
			Version: Version, RunID: request.RunID, OperationID: request.OperationID,
			OperationDigest: operation, ConfigDigest: a.digest, PlanDigest: PlanDigest(request.Plan),
			Role: binding.Role, ImageDigest: imageContentDigest(binding.Image), Phase: Preflight,
			Namespaces: a.namespaceNames(operation), ObserverNamespace: a.observerNamespaceName(operation), StartedAt: now,
			Deadline: now.Add(2*a.config.StartupTimeout + a.config.ObservationWindow + a.config.TailWindow),
			Receipts: []Receipt{},
		}
		if request.Plan.Capability == KEDAEventPublishing {
			nonce, err := freshValue()
			if err != nil {
				return input, err
			}
			s.Capability = KEDAEventPublishing
			s.FinalMarkerNonce = string(nonce)
			clear(nonce)
			s.Evidence.Publishing = &PublishingEvidence{}
		}
		if err := a.accept(ctx, s, "start", ObjectRef{}); err != nil {
			return input, err
		}
		if request.Cancel {
			s.Phase, s.Outcome, s.Reason = Complete, Cancelled, "cancelled-before-start"
		}
		return a.save(ctx, s)
	}
	if err := a.validateState(s, request, binding); err != nil {
		return input, err
	}
	if s.Terminal() {
		return s, failure(TerminalRun, "run-cannot-be-replayed")
	}
	if request.Cancel && s.Outcome != Cancelled {
		s.Phase, s.Cursor, s.Outcome, s.Reason = Cleaning, 0, Cancelled, "cancelled"
		s.Deadline = a.now().Add(2 * a.config.StartupTimeout)
		return a.save(ctx, s)
	}
	if !a.now().Before(s.Deadline) {
		if s.Phase == Cleaning {
			s.Phase, s.Outcome, s.Reason = Quarantined, Inconclusive, "cleanup-deadline-exceeded"
			return a.save(ctx, s)
		}
		return a.finish(ctx, s, Inconclusive, "observation-deadline-exceeded")
	}
	if s.Phase == Preflight {
		if err := a.preflight(ctx); err != nil {
			return a.stop(ctx, s, err)
		}
		s.Phase = Preparing
		return a.save(ctx, s)
	}
	return a.advance(ctx, s, binding, request.Placement)
}

func (a *Adapter) advance(ctx context.Context, s State, binding ImageBinding, placement *SubjectPlacement) (State, error) {
	if s.Phase == Cleaning {
		if err := a.checkCleanupAnchors(ctx, s); err != nil {
			var safe *Error
			if errors.As(err, &safe) && safe.Kind == OwnershipLost {
				return a.stop(ctx, s, err)
			}
			return s, err
		}
		return a.cleanup(ctx, s, binding)
	}
	if err := a.checkAnchors(ctx, s); err != nil {
		return a.stop(ctx, s, err)
	}
	if err := a.checkClusterRole(ctx); err != nil {
		return a.stop(ctx, s, err)
	}
	if publishing(s) {
		if err := a.checkPublishingGlobals(ctx, s); err != nil {
			return a.stop(ctx, s, err)
		}
	}
	if s.ObserverPodIP != "" {
		if err := a.checkObserverPin(ctx, s); err != nil {
			return a.stop(ctx, s, err)
		}
	}
	if err := a.checkPlacementRuntime(ctx, s); err != nil {
		return a.stop(ctx, s, err)
	}
	if objects := phaseObjects(s); objects != nil {
		if s.Cursor == len(objects) {
			switch s.Phase {
			case Preparing:
				s.Phase = WaitingObserver
			case InstallingController:
				s.Phase = WaitingRuntime
			case InstallingSources:
				s.Phase = WaitingSources
			case InstallingInitial:
				s.Phase = ObservingInitial
			case InstallingFinal:
				s.Phase = ObservingFinal
			}
			s.Cursor = 0
			return a.save(ctx, s)
		}
		if objects[s.Cursor].Resource == deployments && s.Placement == nil {
			s.Phase, s.Cursor = WaitingPlacement, 0
			s.Deadline = a.now().Add(a.config.StartupTimeout)
			return a.save(ctx, s)
		}
		return a.ensure(ctx, s, binding, objects[s.Cursor])
	}
	switch s.Phase {
	case WaitingObserver:
		return a.pinObserver(ctx, s)
	case WaitingPlacement:
		return a.bindPlacement(ctx, s, placement)
	case WaitingRuntime:
		return a.waitForRuntime(ctx, s)
	case WaitingSources:
		ready, err := a.sourcesReady(ctx, s)
		if err != nil {
			return a.stop(ctx, s, err)
		}
		if ready {
			s.Phase = InstallingInitial
		}
		return a.save(ctx, s)
	case ObservingInitial, ObservingWindow, ObservingFinal, Settling:
		return a.observe(ctx, s)
	default:
		return s, failure(InvalidState, "unknown-phase")
	}
}

func (a *Adapter) waitForRuntime(ctx context.Context, s State) (State, error) {
	if a.now().Sub(s.SubjectStartedAt) >= a.config.StartupTimeout {
		return a.finish(ctx, s, Inconclusive, "runtime-readiness-deadline")
	}
	ready, err := a.runtimeReady(ctx, s)
	if err != nil {
		return a.stop(ctx, s, err)
	}
	if !ready {
		return a.save(ctx, s)
	}
	if publishing(s) {
		pod, err := a.livePublishingRuntime(ctx, s)
		if err != nil {
			return a.stop(ctx, s, err)
		}
		if pod == nil {
			return a.save(ctx, s)
		}
		s.RuntimePod = pod
	}
	if _, err := a.snapshot(ctx, s); err != nil {
		return a.stop(ctx, s, err)
	}
	s.Phase = InstallingSources
	return a.save(ctx, s)
}

func reflectEmpty(s State) bool {
	return digest(s) == digest(State{})
}

func cloneState(s State) State {
	data, _ := json.Marshal(s)
	var clone State
	_ = json.Unmarshal(data, &clone)
	return clone
}

func (a *Adapter) operationDigest(r Request, binding ImageBinding) string {
	return digest(struct {
		Domain, Config, Plan, Run, Operation string
		Binding                              ImageBinding
	}{"orka.controllerlab.operation.v1", a.digest, PlanDigest(r.Plan), r.RunID, r.OperationID, binding})
}

func (a *Adapter) namespaceNames(operation string) [2]string {
	base := a.config.NamespacePrefix + "-" + operation[:24]
	return [2]string{base + "-a", base + "-b"}
}

func (a *Adapter) observerNamespaceName(operation string) string {
	return a.config.NamespacePrefix + "-" + operation[:24] + "-observer"
}

func (a *Adapter) validateState(s State, r Request, binding ImageBinding) error {
	operation := a.operationDigest(r, binding)
	if s.Version != Version || s.Revision == 0 || s.OperationDigest != operation ||
		s.ConfigDigest != a.digest || s.PlanDigest != PlanDigest(r.Plan) ||
		s.RunID != r.RunID || s.OperationID != r.OperationID || s.Role != binding.Role ||
		s.ImageDigest != imageContentDigest(binding.Image) || s.Namespaces != a.namespaceNames(operation) ||
		s.ObserverNamespace != a.observerNamespaceName(operation) ||
		s.StartedAt.IsZero() || s.Deadline.IsZero() || len(s.Receipts) > len(allObjects(s)) ||
		s.Evidence.HTTPCount < 0 || s.Evidence.HTTPCount > 256 || s.Evidence.RESPCount < 0 || s.Evidence.RESPCount > 256 {
		return failure(InvalidState, "state-binding-changed")
	}
	if !slices.Contains([]Phase{Preflight, Preparing, WaitingObserver, InstallingController, WaitingPlacement, WaitingRuntime, InstallingSources, WaitingSources,
		InstallingInitial, ObservingInitial, ObservingWindow, InstallingFinal, ObservingFinal, Settling, Cleaning, Complete, Quarantined}, s.Phase) {
		return failure(InvalidState, "unknown-phase")
	}
	if s.Cursor < 0 || s.Cursor > len(phaseObjects(s)) {
		return failure(InvalidState, "invalid-phase-cursor")
	}
	if err := a.validateEndpointState(s); err != nil {
		return err
	}
	if err := validatePlacementState(s, r.Placement); err != nil {
		return err
	}
	if err := validatePublishingState(s, r.Plan.Capability); err != nil {
		return err
	}
	if publishing(s) && s.Phase == Complete && (s.Outcome == Protected || s.Outcome == Reproduced) {
		if err := completedPublishingEvidence(s); err != nil {
			return err
		}
	}
	return validateReceipts(s)
}

func (a *Adapter) validateEndpointState(s State) error {
	if s.ObserverPodIP == "" {
		if s.ObserverImageDigest != "" || !slices.Contains([]Phase{Preflight, Preparing, WaitingObserver, Cleaning, Complete, Quarantined}, s.Phase) {
			return failure(InvalidState, "observer-endpoint-pin-required")
		}
		return nil
	}
	if !validObserverPin(s, a.config.ObserverImage) {
		return failure(InvalidState, "observer-endpoint-pin-changed")
	}
	return nil
}

func validateReceipts(s State) error {
	if err := validateCleanupReceipts(s); err != nil {
		return err
	}
	seen := map[ObjectRef]bool{}
	for _, receipt := range s.Receipts {
		r := receipt.Object
		r.UID = ""
		if seen[r] || receipt.Object.UID == "" || !knownRef(s, r) || !digestPattern.MatchString(receipt.IntentDigest) ||
			(receipt.Deleted && !receipt.DeleteRequested) ||
			(receipt.BindingDigest != "" && !digestPattern.MatchString(receipt.BindingDigest)) {
			return failure(InvalidState, "invalid-ownership-receipt")
		}
		seen[r] = true
	}
	if s.Intent != nil && (s.Intent.Object.UID != "" || !knownRef(s, s.Intent.Object) ||
		seen[s.Intent.Object] || !digestPattern.MatchString(s.Intent.Digest)) {
		return failure(InvalidState, "invalid-durable-intent")
	}
	if objects := phaseObjects(s); s.Intent != nil && s.Phase != Cleaning && s.Phase != Quarantined &&
		(s.Cursor >= len(objects) || !sameRef(s.Intent.Object, objects[s.Cursor])) {
		return failure(InvalidState, "intent-phase-mismatch")
	}
	return nil
}

func (a *Adapter) save(ctx context.Context, s State) (State, error) {
	expected := s.Revision
	s.Revision++
	if err := a.hooks.PersistState(ctx, expected, cloneState(s)); err != nil {
		// The write may have committed before its acknowledgement was lost.
		// Reload from durable storage after ANY StoreRejected error.
		return s, failure(StoreRejected, "state-cas-not-acknowledged")
	}
	return s, nil
}

func (a *Adapter) accept(ctx context.Context, s State, action string, object ObjectRef) error {
	if err := a.hooks.Acceptance(ctx, Mutation{
		RunID: s.RunID, OperationID: s.OperationID, OperationDigest: s.OperationDigest,
		Action: action, Object: object,
		Placement: clonePlacement(s.Placement),
	}); err != nil {
		return failure(StoreRejected, "operation-not-accepted")
	}
	return nil
}

func (a *Adapter) ensure(ctx context.Context, s State, binding ImageBinding, object ObjectRef) (State, error) {
	if receiptFor(s, object) != nil {
		return a.stop(ctx, s, failure(InvalidState, "creation-cursor-replayed"))
	}
	if sameRef(object, ref(secrets, s.ObserverNamespace, adminSecretName)) ||
		sameRef(object, ref(deployments, s.Namespaces[0], controllerName)) {
		if err := a.checkObserverBoundary(ctx, s); err != nil {
			return a.stop(ctx, s, err)
		}
	}
	current, err := a.get(ctx, object)
	if err != nil && !apierrors.IsNotFound(err) {
		return s, failure(Infrastructure, "resource-read-unavailable")
	}
	if err == nil {
		if s.Intent == nil || !sameRef(s.Intent.Object, object) {
			return a.stop(ctx, s, failure(OwnershipLost, "preexisting-object-not-adoptable"))
		}
		return a.adopt(ctx, s, binding, current, false)
	}
	if s.Intent == nil {
		nonce, err := freshValue()
		if err != nil {
			return s, err
		}
		s.Intent = &Intent{Object: object, Digest: bytesDigest(nonce)}
		clear(nonce)
	}
	if err := a.accept(ctx, s, createVerb, object); err != nil {
		return s, err
	}
	s, err = a.save(ctx, s)
	if err != nil {
		return s, err
	}
	value, err := a.build(ctx, s, binding, *s.Intent, nil)
	if err != nil {
		return a.stop(ctx, s, err)
	}
	created, err := a.create(ctx, value)
	if err != nil {
		// Even a failed request can have created the object. Keep the durable
		// intent and reconcile it on the next bounded Step, never blind rollback.
		return s, failure(Infrastructure, "create-acknowledgement-unavailable")
	}
	return a.adopt(ctx, s, binding, created, false)
}

func (a *Adapter) adopt(ctx context.Context, s State, binding ImageBinding, object runtime.Object, cleaning bool) (State, error) {
	if s.Intent == nil {
		return s, failure(InvalidState, "adoption-requires-intent")
	}
	m, err := objectMetadata(object)
	if err != nil || !owns(s, s.Intent.Object, s.Intent.Digest, m) || m.GetDeletionTimestamp() != nil {
		return a.stop(ctx, s, failure(OwnershipLost, "object-intent-or-uid-mismatch"))
	}
	expected, err := a.build(ctx, s, binding, *s.Intent, object)
	if err != nil || !desiredMatches(expected, object) {
		return a.stop(ctx, s, failure(OwnershipLost, "object-template-mismatch"))
	}
	if publishing(s) && kedaFixture(s.Intent.Object.Resource) && !exactKEDATemplate(expected, object) {
		return a.stop(ctx, s, failure(OwnershipLost, "unexpected-keda-fixture-fields"))
	}
	r := Receipt{Object: s.Intent.Object, IntentDigest: s.Intent.Digest}
	r.Object.UID = m.GetUID()
	if publishing(s) && fixtureBinding(r.Object.Resource) {
		r.BindingDigest, err = resourceBindingDigest(object)
		if err != nil {
			return a.stop(ctx, s, err)
		}
	}
	s.Receipts = append(s.Receipts, r)
	s.Intent = nil
	if !cleaning {
		s.Cursor++
	}
	return a.save(ctx, s)
}

func (a *Adapter) stop(ctx context.Context, s State, cause error) (State, error) {
	code := "lab-operation-unavailable"
	if safe, ok := errors.AsType[*Error](cause); ok {
		code = safe.Code
		if safe.Kind == OwnershipLost || safe.Kind == InvalidState {
			s.Phase, s.Cursor, s.Outcome, s.Reason = Quarantined, 0, Inconclusive, code
			result, err := a.save(ctx, s)
			if err != nil {
				return result, err
			}
			return result, cause
		}
	}
	result, err := a.finish(ctx, s, Inconclusive, code)
	if err != nil {
		return result, err
	}
	return result, cause
}

func (a *Adapter) finish(ctx context.Context, s State, outcome Outcome, reason string) (State, error) {
	s.Phase, s.Cursor, s.Outcome, s.Reason = Cleaning, 0, outcome, reason
	s.Deadline = a.now().Add(2 * a.config.StartupTimeout)
	return a.save(ctx, s)
}

func (a *Adapter) exact(ctx context.Context, s State, object ObjectRef) (runtime.Object, error) {
	receipt := receiptFor(s, object)
	if receipt == nil || receipt.Deleted {
		return nil, failure(OwnershipLost, "runtime-receipt-required")
	}
	value, err := a.get(ctx, object)
	if err != nil {
		return nil, failure(Infrastructure, "owned-runtime-unavailable")
	}
	m, err := objectMetadata(value)
	if err != nil || m.GetUID() != receipt.Object.UID {
		return nil, failure(OwnershipLost, "owned-runtime-identity-changed")
	}
	if !owns(s, object, receipt.IntentDigest, m) || m.GetDeletionTimestamp() != nil {
		return nil, failure(Infrastructure, "owned-runtime-metadata-changed")
	}
	return value, nil
}

func (a *Adapter) runtimeReady(ctx context.Context, s State) (bool, error) {
	observer, err := a.exact(ctx, s, ref(pods, s.ObserverNamespace, serviceName))
	if err != nil {
		return false, err
	}
	pod := observer.(*corev1.Pod)
	if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded ||
		(len(pod.Status.ContainerStatuses) > 0 && pod.Status.ContainerStatuses[0].RestartCount != 0) {
		return false, failure(Infrastructure, "observer-exited-or-restarted")
	}
	if !observerReady(pod) {
		return false, nil
	}
	controller, err := a.exact(ctx, s, ref(deployments, s.Namespaces[0], controllerName))
	if err != nil {
		return false, err
	}
	d := controller.(*appsv1.Deployment)
	return d.Status.ObservedGeneration >= d.Generation && d.Status.AvailableReplicas == 1 &&
		d.Status.ReadyReplicas == 1 && d.Status.Replicas == 1, nil
}

func (a *Adapter) sourcesReady(ctx context.Context, s State) (bool, error) {
	if err := a.ValidateRuntime(ctx, s); err != nil {
		return false, err
	}
	// CR Active status is not the publisher readiness signal in the pinned
	// KEDA implementation. This gate only permits creating the bounded stimulus.
	for _, source := range sourceObjects(s) {
		receipt := receiptFor(s, source)
		if receipt == nil || receipt.Deleted || receipt.DeleteRequested {
			return false, failure(OwnershipLost, "source-receipt-required")
		}
		if publishing(s) {
			continue
		}
		value, err := a.exact(ctx, s, source)
		if err != nil {
			return false, err
		}
		expected, err := a.build(ctx, s, ImageBinding{}, Intent{Object: source, Digest: receipt.IntentDigest}, value)
		if err != nil {
			return false, err
		}
		if !exactKEDATemplate(expected, value) {
			return false, failure(Infrastructure, "source-contract-changed")
		}
	}
	if publishing(s) {
		if _, err := a.validateFixtureBindings(ctx, s); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (a *Adapter) snapshot(ctx context.Context, s State) (Observation, error) {
	if err := a.checkObserverBoundary(ctx, s); err != nil {
		return Observation{}, err
	}
	podObject := ref(pods, s.ObserverNamespace, serviceName)
	pod := receiptFor(s, podObject)
	credentials := receiptFor(s, ref(secrets, s.ObserverNamespace, adminSecretName))
	namespace := receiptFor(s, ref(namespaces, "", s.ObserverNamespace))
	if pod == nil || credentials == nil || namespace == nil {
		return Observation{}, failure(OwnershipLost, "observer-receipts-required")
	}
	// Also enforce the exact Pod boundary for injected observers. Fake evidence
	// cannot turn a missing/restarted Pod into a healthy observation.
	live, err := a.exact(ctx, s, podObject)
	if err != nil || !observerExecutionMatches(live.(*corev1.Pod), a.config.ObserverImage, s.ObserverPodIP) {
		return Observation{}, failure(Infrastructure, "observer-pod-unavailable")
	}
	o, err := a.observer.Snapshot(ctx, ObserverTarget{
		Pod: pod.Object, Credentials: credentials.Object, NamespaceUID: namespace.Object.UID,
		PodIntentDigest: pod.IntentDigest, CredentialsIntentDigest: credentials.IntentDigest,
		OperationDigest: s.OperationDigest, TLSServerName: observerDNS(s),
		PodIP: s.ObserverPodIP, Image: a.config.ObserverImage,
	})
	if err != nil {
		return Observation{}, failure(Infrastructure, "observer-state-unavailable")
	}
	if err := validateObservation(o, s.OperationDigest); err != nil {
		return Observation{}, err
	}
	return o, nil
}

func (a *Adapter) observe(ctx context.Context, s State) (State, error) {
	if publishing(s) {
		if err := a.validatePublishingRuntime(ctx, s); err != nil {
			return a.stop(ctx, s, err)
		}
	} else {
		if err := a.checkNoGlobalSources(ctx); err != nil {
			return a.stop(ctx, s, err)
		}
	}
	o, err := a.snapshot(ctx, s)
	if err != nil {
		return a.stop(ctx, s, err)
	}
	if publishing(s) {
		s.Evidence.BindingsDigest, err = a.validateFixtureBindings(ctx, s)
		if err != nil {
			return a.stop(ctx, s, err)
		}
	}
	if err := incorporate(&s, o); err != nil {
		return a.stop(ctx, s, err)
	}
	if publishing(s) && s.Role == Candidate && s.Evidence.Publishing.CredentialAttack.Observed {
		return a.finish(ctx, s, StillExposed, "undelegated-cluster-credential-observed")
	}
	if s.Evidence.CrossObserved {
		if s.Role == Candidate {
			return a.finish(ctx, s, StillExposed, "cross-namespace-event-observed")
		}
		if !publishing(s) && s.Evidence.InitialNormal == [2]bool{true, true} {
			return a.finish(ctx, s, Reproduced, "cross-namespace-event-and-normal-controls-observed")
		}
	}
	now := a.now().UTC()
	switch s.Phase {
	case ObservingInitial:
		if normalControlsComplete(s, false) {
			s.Phase, s.WindowStartedAt = ObservingWindow, now
		}
	case ObservingWindow:
		if now.Sub(s.WindowStartedAt) >= a.config.ObservationWindow {
			s.Phase = InstallingFinal
		}
	case ObservingFinal:
		if normalControlsComplete(s, true) {
			s.Phase, s.TailStartedAt = Settling, now
		}
	case Settling:
		if now.Sub(s.TailStartedAt) >= a.config.TailWindow {
			if publishing(s) && s.Role != Candidate && publishingAttacksReproduced(*s.Evidence.Publishing) {
				return a.finish(ctx, s, Reproduced, "event-scope-and-undelegated-credential-attacks-observed")
			}
			if s.Role == Candidate {
				return a.finish(ctx, s, Protected, "bounded-isolation-with-fresh-normal-controls")
			}
			return a.finish(ctx, s, NotReproduced, "positive-original-reproduction-not-observed")
		}
	}
	return a.save(ctx, s)
}

func incorporate(s *State, o Observation) error {
	e := &s.Evidence
	if publishing(*s) && e.Publishing == nil {
		return failure(InvalidState, "publishing-evidence-required")
	}
	if len(o.RESP) != 0 || len(o.HTTP) < e.HTTPCount || len(o.RESP) < e.RESPCount || o.DuplicateHTTP < e.DuplicateHTTP ||
		(e.Generation != 0 && e.Generation != o.Generation) {
		return failure(Infrastructure, "observer-generation-or-history-changed")
	}
	if e.Generation != 0 && (digest(o.HTTP[:e.HTTPCount]) != e.HTTPDigest || digest(o.RESP[:e.RESPCount]) != e.RESPDigest) {
		return failure(Infrastructure, "observer-evidence-prefix-changed")
	}
	expectedSource := bytesDigest([]byte("/orka-controllerlab/" + s.Namespaces[0] + "/keda"))
	observations := o.HTTP
	if publishing(*s) {
		observations = observations[e.HTTPCount:]
	}
	for _, observation := range observations {
		if publishing(*s) {
			if err := incorporatePublishingRequest(s, observation); err != nil {
				return err
			}
		} else if !slices.Contains([]string{httpARoute, httpBRoute, metricRoute}, observation.Route) {
			return failure(Infrastructure, "unexpected-http-only-fixture-route")
		}
		if observation.Route == metricRoute {
			continue
		}
		for _, event := range observation.CloudEvents {
			if event.Subject == nil || event.Source == nil || event.Source.SHA256 != expectedSource {
				continue
			}
			for _, final := range []bool{false, true} {
				for index, route := range []string{httpARoute, httpBRoute} {
					if event.Subject.SHA256 != bytesDigest([]byte(subject(*s, index, final))) ||
						!slices.Contains(event.Subject.MarkerIDs, eventMarkerID(*s, index, final)) {
						continue
					}
					if publishing(*s) {
						if receiptFor(*s, fixtureObjects(*s, final)[index]) == nil {
							continue
						}
						incorporatePublishingEvent(s, observation.Route, index, final)
						continue
					}
					if route != observation.Route {
						e.CrossObserved = true
					} else if final {
						e.FinalNormal[index] = true
					} else {
						e.InitialNormal[index] = true
					}
				}
			}
		}
	}
	e.Generation, e.HTTPCount, e.RESPCount = o.Generation, len(o.HTTP), len(o.RESP)
	e.DuplicateHTTP = o.DuplicateHTTP
	e.HTTPDigest, e.RESPDigest, e.StateDigest = digest(o.HTTP), digest(o.RESP), digest(o)
	return nil
}
