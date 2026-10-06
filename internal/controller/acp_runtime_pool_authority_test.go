package controller

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"github.com/orka-agents/orka/internal/store"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestACPPreviousEpochRuntimePoolClientRejectsNewWork(t *testing.T) {
	f := newACPRuntimePoolRestartFixture(t, false)
	if err := f.dispatcher.recoverStaleAttempts(f.ctx); err != nil {
		t.Fatal(err)
	}
	runtimeClient, authority := previousEpochAuthorityTestClient(t, f)
	task, fence := authority.task, authority.fence
	sessionID := harnessv2.RuntimeSessionID(runtimeSessionID(fence))
	profile, configuration := previousEpochAuthorityTestProfile(t)
	baseline, workspace, err := emptyRuntimeWorkspace(task, "")
	if err != nil {
		t.Fatal(err)
	}
	f.runtime.mu.Lock()
	limits, before := f.runtime.probe.Capabilities.Limits, f.runtime.mutationCalls
	f.runtime.mu.Unlock()
	now := time.Now().UTC()
	create := harnessv2.CreateRuntimeSessionRequest{
		Protocol: harnessv2.ProtocolVersion, Metadata: mutationMetadata(fence, task, "retirement-create", false, now.Add(45*time.Second)),
		RuntimeSessionID: sessionID, Profile: profile, MCPConfiguration: configuration, Workspace: workspace,
	}
	// The rollout fixture has opaque policy digests. Admission still needs a
	// canonical profile/policy pair so schema validation cannot hide a missing guard.
	create.Metadata.Fence.RuntimeProfileDigest, err = harnessv2.CanonicalProfileDigest(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := sealMutation(&create.Metadata.RequestDigest, create); err != nil {
		t.Fatal(err)
	}
	prompt, err := f.dispatcher.buildPromptRequest(task, fence, profile, configuration, "", "must not execute", limits, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := sealMutation(&prompt.Metadata.RequestDigest, prompt); err != nil {
		t.Fatal(err)
	}
	delta := harnessv2.CreateWorkspaceDeltaRequest{
		Protocol: harnessv2.ProtocolVersion, Metadata: mutationMetadata(fence, task, "retirement-delta", true, now.Add(45*time.Second)),
		DeltaID: "retirement-delta", Intent: harnessv2.WorkspaceIntentRead, VerifiedBaseline: baseline,
		PromptSettlementDigest: testControlDigestForDispatcher("retirement-settlement"),
		Limits:                 harnessv2.WorkspaceDeltaLimits{MaxBytes: 1024, MaxEntries: 1},
	}
	if err := sealMutation(&delta.Metadata.RequestDigest, delta); err != nil {
		t.Fatal(err)
	}
	drainFence := fence
	drainFence.RuntimeSessionUID, drainFence.RuntimeSessionGeneration = "", 0
	drain := harnessv2.DrainRequest{
		Protocol: harnessv2.ProtocolVersion, Reason: "retirement-only client cannot drain the pool",
		Metadata: harnessv2.MutationMetadata{
			Fence: drainFence, OperationID: "retirement-drain", RequestDigestSchemaVersion: harnessv2.RequestDigestSchemaVersion,
			ExpiresAt: now.Add(45 * time.Second),
		},
	}
	if err := sealMutation(&drain.Metadata.RequestDigest, drain); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		operation string
		request   any
		validate  func(time.Time) error
		call      func() error
	}{
		{
			operation: "start_prompt", request: prompt,
			validate: func(now time.Time) error {
				return prompt.ValidateAt(now, time.Duration(limits.MinPromptLeaseMillis)*time.Millisecond,
					time.Duration(limits.MaxPromptLeaseMillis)*time.Millisecond)
			},
			call: func() error {
				stream, callErr := runtimeClient.StartPrompt(f.ctx, sessionID, prompt)
				if stream != nil {
					if err := stream.Close(); err != nil {
						t.Error(err)
					}
				}
				return callErr
			},
		},
		{
			operation: "create_runtime_session", request: create, validate: create.ValidateAt,
			call: func() error { _, err := runtimeClient.CreateRuntimeSession(f.ctx, create); return err },
		},
		{
			operation: "create_workspace_delta", request: delta, validate: delta.ValidateAt,
			call: func() error { _, err := runtimeClient.CreateWorkspaceDelta(f.ctx, sessionID, delta); return err },
		},
		{
			operation: "drain", request: drain, validate: drain.ValidateAt,
			call: func() error { _, err := runtimeClient.Drain(f.ctx, drain); return err },
		},
	} {
		t.Run(test.operation, func(t *testing.T) {
			if err := test.validate(time.Now().UTC()); err != nil {
				t.Fatalf("request must be valid independently of the retirement gate: %v", err)
			}
			encoded, err := json.Marshal(test.request)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) > limits.MaxRequestBytes {
				t.Fatalf("request is %d bytes, exceeding negotiated limit %d", len(encoded), limits.MaxRequestBytes)
			}
			err = test.call()
			assertPreviousEpochAuthorityRejection(t, err, test.operation, "RuntimePool client permits retirement only")
			assertPreviousEpochMutationCount(t, f, before)
		})
	}
}

func TestACPPreviousEpochRuntimePoolClientFinalizesPreparedPublication(t *testing.T) {
	for _, drift := range []string{"none", "task binding", "credential version", "controller takeover", "status fence"} {
		t.Run(drift, func(t *testing.T) {
			f := newACPRuntimePoolRestartFixture(t, false)
			publication, attempt := preparePreviousEpochAuthorityPublication(t, f)
			runtimeClient, authority := previousEpochAuthorityTestClient(t, f)
			if authority.fence.ControllerEpoch >= uint64(authority.controller.Epoch) || authority.abandon {
				t.Fatal("publication cleanup did not retain the successful attempt's historical authority")
			}
			finalization, err := f.dispatcher.runtimeSessionPublicationFinalization(
				f.ctx, publication.ID, harnessv2.WorkspaceDeltaID("delta-"+attempt.Key.PromptID),
			)
			if err != nil {
				t.Fatal(err)
			}
			request := harnessv2.FinalizeRuntimeSessionPublicationRequest{
				Protocol:         harnessv2.ProtocolVersion,
				Metadata:         mutationMetadata(authority.fence, authority.task, "retirement-finalize", true, time.Now().UTC().Add(45*time.Second)),
				WorkspaceDeltaID: finalization.WorkspaceDeltaID, PublicationID: finalization.PublicationID,
				PublicationGeneration: finalization.PublicationGeneration, PublicationVersion: finalization.PublicationVersion,
				TerminalState: finalization.TerminalState, TerminalReceiptDigest: finalization.TerminalReceiptDigest,
			}
			if err := sealMutation(&request.Metadata.RequestDigest, request); err != nil {
				t.Fatal(err)
			}
			if err := request.ValidateAt(time.Now().UTC()); err != nil {
				t.Fatalf("prepared publication finalization is not valid: %v", err)
			}
			if request.Metadata.TaskUID != harnessv2.TaskUID(attempt.Key.TaskUID) ||
				request.Metadata.TaskAttempt != uint32(attempt.Key.Attempt) || request.Metadata.PromptID != harnessv2.PromptID(attempt.Key.PromptID) ||
				request.PublicationID != publication.ID || request.PublicationGeneration != uint64(publication.Generation) ||
				request.PublicationVersion != uint64(publication.Version) || request.TerminalState != harnessv2.PublicationTerminalVerifiedExact {
				t.Fatal("finalization is not bound to the existing terminal attempt and publication")
			}
			servePreviousEpochPublicationFinalization(t, f, request)
			f.runtime.mu.Lock()
			before, statusBefore := f.runtime.mutationCalls, f.runtime.statusReads
			f.runtime.mu.Unlock()
			changePreviousEpochPublicationAuthority(t, f, drift)
			ownerBefore, err := f.control.GetControllerEpoch(f.ctx, store.DefaultControllerEpochName)
			if err != nil {
				t.Fatal(err)
			}
			response, err := runtimeClient.FinalizeRuntimeSessionPublication(
				f.ctx, harnessv2.RuntimeSessionID(runtimeSessionID(authority.fence)), request,
			)
			if drift != "none" {
				assertPreviousEpochAuthorityRejection(t, err, runtimePoolFinalizePublicationOperation, "pre-mutation authority check")
				if response != nil {
					t.Fatal("authority drift returned a publication finalization response")
				}
				assertPreviousEpochMutationCount(t, f, before)
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if response == nil || response.Finalization.TerminalReceiptDigest != request.TerminalReceiptDigest ||
					response.Session.State != harnessv2.RuntimeSessionStateFinalizing {
					t.Fatal("historical client did not return the exact terminal publication finalization")
				}
				assertPreviousEpochMutationCount(t, f, before+1)
				f.runtime.mu.Lock()
				statusReads, runtimeFence := f.runtime.statusReads, f.runtime.probe.Status.Fence
				f.runtime.mu.Unlock()
				if statusReads != statusBefore+1 || runtimeFence.ControllerEpoch != authority.fence.ControllerEpoch {
					t.Fatal("finalization skipped authenticated revalidation or advanced the surviving runtime epoch")
				}
			}
			assertPreviousEpochPublicationUnchanged(t, f, publication, attempt, ownerBefore)
		})
	}
}

func previousEpochAuthorityTestClient(t *testing.T, f *acpRuntimePoolRestartFixture) (*harnessv2.Client, *runtimePoolCleanupAuthority) {
	t.Helper()
	task := f.currentTask(t)
	if task.Spec.SessionRef != nil {
		t.Fatal("previous-epoch authority fixture must remain a standalone Task")
	}
	pool := runtimePoolTestGetPool(t, f.pools, f.pool)
	owner, err := f.dispatcher.Epochs.CurrentFence(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	runtimeClient, authority, err := f.dispatcher.runtimePoolRetirementClient(f.ctx, task, task.UID, &pool, owner)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeClient == nil || authority == nil {
		t.Fatal("previous-epoch cleanup did not return its real client and frozen authority")
	}
	return runtimeClient, authority
}

func previousEpochAuthorityTestProfile(t *testing.T) (harnessv2.RuntimeProfile, harnessv2.MCPPolicyConfiguration) {
	t.Helper()
	configuration := harnessv2.MCPPolicyConfiguration{}
	var err error
	configuration.ToolPolicy.DescriptorDigest, err = harnessv2.CanonicalMCPToolDescriptorDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ToolPolicyDigest, err = harnessv2.CanonicalRuntimeToolPolicyDigest(nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ApprovalPolicyDigest, err = harnessv2.CanonicalMCPApprovalPolicyDigest(configuration.ApprovalPolicy)
	if err != nil {
		t.Fatal(err)
	}
	configuration.MCPConfigurationDigest, err = harnessv2.CanonicalMCPConfigurationDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := harnessProfileForTest()
	profile.ToolPolicyDigest = configuration.ToolPolicyDigest
	profile.ApprovalPolicyDigest = configuration.ApprovalPolicyDigest
	profile.MCPConfigurationDigest = configuration.MCPConfigurationDigest
	return profile, configuration
}

func assertPreviousEpochAuthorityRejection(t *testing.T, err error, operation, message string) {
	t.Helper()
	var rejected *harnessv2.ClientError
	if !errors.As(err, &rejected) || rejected.Kind != harnessv2.ClientErrorValidation ||
		rejected.Operation != operation || rejected.StatusCode != 0 ||
		!strings.Contains(rejected.Message, "pre-mutation authority check") || !strings.Contains(rejected.Message, message) ||
		rejected.WriteEvidence != (harnessv2.RequestWriteEvidence{State: harnessv2.RequestWriteZeroBytes}) {
		t.Fatalf("%s did not fail at the authority hook before any HTTP write: %v", operation, err)
	}
}

func assertPreviousEpochMutationCount(t *testing.T, f *acpRuntimePoolRestartFixture, want int) {
	t.Helper()
	f.runtime.mu.Lock()
	calls := f.runtime.mutationCalls
	f.runtime.mu.Unlock()
	if calls != want {
		t.Fatalf("runtime received %d mutating HTTP requests, want %d", calls, want)
	}
}

func preparePreviousEpochAuthorityPublication(t *testing.T, f *acpRuntimePoolRestartFixture) (*store.Publication, *store.PromptAttempt) {
	t.Helper()
	task := f.currentTask(t)
	owner, err := f.dispatcher.Epochs.CurrentFence(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	id, err := promptAttemptIDFromTaskUID(task, task.UID)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := f.control.GetPromptAttempt(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []store.PromptExecutionState{store.PromptExecutionSettling, store.PromptExecutionSucceeded} {
		attempt, err = f.control.TransitionPromptAttemptExecution(f.ctx, store.PromptAttemptExecutionTransition{
			ID: id, Fence: owner, ExpectedVersion: attempt.Version, ExpectedState: attempt.ExecutionState, NewState: next,
			OperationID: "publication-" + string(next), OperationDigest: testControlDigestForDispatcher(string(next)), UpdatedAt: time.Now().UTC(),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	publication, _ := createStandaloneBranchClaimPublication(t, f.control, owner, task, store.PublicationPreparing)
	now := time.Now().UTC()
	publication.SourceRepositoryID, publication.SourceRef, publication.SourceBaselineSHA = "github.com/orka/source", "refs/heads/main", strings.Repeat("1", 40)
	publication.ArtifactID, publication.ArtifactDigest, publication.ArtifactSizeBytes = "prepared-delta", testControlDigestForDispatcher("delta"), 1
	publication.ArtifactMediaType = "application/vnd.orka.workspace-delta.v1+tar"
	publication.PublicationCredentialRef = "secret/tenant-a/publisher#token"
	publication.CommitIdentity, publication.CommitMessage, publication.CommitTimestamp = "Orka <orka@example.invalid>", "prepared fixture", now
	publication.RequestDigest = testControlDigestForDispatcher("prepared-publication")
	publication, err = f.control.CreatePublication(f.ctx, publication, owner)
	if err != nil {
		t.Fatal(err)
	}
	prepared := &store.PreparedPublicationReceipt{
		OperationID: "prepare", RequestDigest: testControlDigestForDispatcher("prepare"),
		TreeSHA: strings.Repeat("2", 40), CommitSHA: strings.Repeat("3", 40),
		ManifestDigest: testControlDigestForDispatcher("manifest"), RelativeRoot: ".",
		BundleArtifactID: "prepared-bundle", BundleDigest: testControlDigestForDispatcher("bundle"),
		BundleSizeBytes: 1, BundleMediaType: store.PreparedBundleMediaType,
		BundleRef: "refs/orka/publications/" + strings.Repeat("4", 64), PreparedAt: now,
	}
	for _, transition := range []store.PublicationTransition{
		{NewState: store.PublicationPrepared, OperationID: "prepare", PreparedReceipt: prepared},
		{NewState: store.PublicationPublishing, OperationID: "publishing"},
		{NewState: store.PublicationVerifying, OperationID: "publish", PublishReceipt: &store.PublishOperationReceipt{
			OperationID: "publish", RequestDigest: testControlDigestForDispatcher("publish"),
			TargetRepositoryID: publication.TargetRepositoryID, TargetRef: publication.TargetRef,
			RemoteBefore: publication.Baseline, ExpectedCommitSHA: prepared.CommitSHA, PublishedAt: now,
		}},
		{NewState: store.PublicationVerifiedExact, OperationID: "verify", VerificationReceipt: &store.PublicationVerificationReceipt{
			OperationID: "verify", RequestDigest: testControlDigestForDispatcher("verify"), Outcome: store.PublicationVerifiedExact,
			ExpectedCommitSHA: prepared.CommitSHA, ObservedRemote: store.RemoteRefState{SHA: prepared.CommitSHA}, VerifiedAt: now,
		}},
	} {
		transition.ID, transition.Fence = publication.ID, owner
		transition.ExpectedVersion, transition.ExpectedGeneration, transition.ExpectedState = publication.Version, publication.Generation, publication.State
		transition.OperationDigest, transition.UpdatedAt = testControlDigestForDispatcher(transition.OperationID), now
		publication, err = f.control.TransitionPublication(f.ctx, transition)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, next := range []store.PromptDeliveryState{
		store.PromptDeliveryValidating, store.PromptDeliveryPreparing, store.PromptDeliveryPrepared,
		store.PromptDeliveryPublishing, store.PromptDeliveryVerifying, store.PromptDeliveryVerifiedExact,
	} {
		attempt, err = f.control.TransitionPromptAttemptDelivery(f.ctx, store.PromptAttemptDeliveryTransition{
			ID: id, Fence: owner, ExpectedVersion: attempt.Version, ExpectedState: attempt.DeliveryState, NewState: next,
			OperationID: "delivery-" + string(next), OperationDigest: testControlDigestForDispatcher("delivery-" + string(next)), UpdatedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	task.Status.Phase, task.Status.Execution.State, task.Status.Execution.Outcome = corev1alpha1.TaskPhaseSucceeded,
		corev1alpha1.TaskExecutionStateSucceeded, corev1alpha1.TaskExecutionOutcomeSucceeded
	task.Status.Delivery = &corev1alpha1.TaskDeliveryStatus{State: corev1alpha1.TaskDeliveryStateVerifiedExact}
	if err := f.pools.Status().Update(f.ctx, task); err != nil {
		t.Fatal(err)
	}
	f.runtime.mu.Lock()
	f.runtime.probe.Status.Sessions[0].State = harnessv2.RuntimeSessionStatePublicationPrepared
	f.runtime.mu.Unlock()
	return publication, attempt
}

func servePreviousEpochPublicationFinalization(t *testing.T, f *acpRuntimePoolRestartFixture, want harnessv2.FinalizeRuntimeSessionPublicationRequest) {
	t.Helper()
	path, err := harnessv2.RuntimeSessionPublicationFinalizationPath(harnessv2.RuntimeSessionID(runtimeSessionID(want.Metadata.Fence)))
	if err != nil {
		t.Fatal(err)
	}
	baseline, _, err := emptyRuntimeWorkspace(f.currentTask(t), "")
	if err != nil {
		t.Fatal(err)
	}
	f.runtime.mu.Lock()
	defer f.runtime.mu.Unlock()
	f.runtime.finalizePublication = func(w http.ResponseWriter, r *http.Request) {
		var request harnessv2.FinalizeRuntimeSessionPublicationRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode publication finalization: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Path != path || !reflect.DeepEqual(request, want) {
			t.Error("publication finalization changed the exact request, path, or historical fence")
			w.WriteHeader(http.StatusConflict)
			return
		}
		if err := request.ValidateAt(time.Now().UTC()); err != nil {
			t.Errorf("invalid finalization on the wire: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := harnessv2.VerifyOperationCapability(f.runtime.auth.Data[runtimePoolCapabilitySecretKey],
			r.Header.Get(harnessv2.OperationCapabilityHeader), request.Metadata, true, time.Now().UTC()); err != nil {
			t.Errorf("finalization lacked its exact operation capability: %v", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		now := time.Now().UTC()
		fence := request.Metadata.Fence
		f.runtime.probe.Status.Sessions[0].State = harnessv2.RuntimeSessionStateFinalizing
		writeDispatcherJSON(w, harnessv2.FinalizeRuntimeSessionPublicationResponse{
			Protocol: harnessv2.ProtocolVersion, Classification: harnessv2.Classification{Class: harnessv2.RequestClassificationFresh},
			Session: harnessv2.RuntimeSessionDescriptor{
				RuntimeSessionID: harnessv2.RuntimeSessionID(runtimeSessionID(fence)), RuntimeSessionUID: fence.RuntimeSessionUID,
				Generation: fence.RuntimeSessionGeneration, RuntimeInstanceID: fence.RuntimeInstanceID, SupervisorBootID: fence.SupervisorBootID,
				RuntimeProfileDigest: fence.RuntimeProfileDigest, State: harnessv2.RuntimeSessionStateFinalizing,
				ProviderSessionID: "publication-provider-session", WorkspaceBaseline: baseline, CreatedAt: now, LastTransitionAt: now,
			},
			Finalization: harnessv2.PublicationFinalizationReceipt{
				WorkspaceDeltaID: want.WorkspaceDeltaID, PublicationID: want.PublicationID,
				PublicationGeneration: want.PublicationGeneration, PublicationVersion: want.PublicationVersion,
				TerminalState: want.TerminalState, TerminalReceiptDigest: want.TerminalReceiptDigest, AppliedAt: now,
			},
		})
	}
}

func changePreviousEpochPublicationAuthority(t *testing.T, f *acpRuntimePoolRestartFixture, drift string) {
	t.Helper()
	switch drift {
	case "none":
	case "task binding":
		task := f.currentTask(t)
		task.Status.AgentExecutionBinding.BindingDigest = testControlDigestForDispatcher("changed-binding")
		if err := f.pools.Status().Update(f.ctx, task); err != nil {
			t.Fatal(err)
		}
	case "credential version":
		secret := &corev1.Secret{}
		if err := f.pools.Get(f.ctx, client.ObjectKeyFromObject(f.runtime.auth), secret); err != nil {
			t.Fatal(err)
		}
		secret.Annotations = map[string]string{"test.orka.ai/version": "changed"}
		if err := f.pools.Update(f.ctx, secret); err != nil {
			t.Fatal(err)
		}
	case "controller takeover":
		current, err := f.control.GetControllerEpoch(f.ctx, store.DefaultControllerEpochName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.control.CompareAndSwapControllerEpoch(f.ctx, store.ControllerEpochCAS{
			Name: current.Name, ExpectedEpoch: current.Epoch, ExpectedVersion: current.Version,
			NewEpoch: current.Epoch + 1, HolderID: "another-controller",
			RequestDigest: testControlDigestForDispatcher("takeover"), UpdatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	case "status fence":
		f.runtime.mu.Lock()
		f.runtime.probe.Status.Fence.SupervisorBootID = "different-boot"
		f.runtime.mu.Unlock()
	default:
		t.Fatalf("unknown authority drift %q", drift)
	}
}

func assertPreviousEpochPublicationUnchanged(
	t *testing.T, f *acpRuntimePoolRestartFixture, publication *store.Publication, attempt *store.PromptAttempt, owner *store.ControllerEpoch,
) {
	t.Helper()
	currentPublication, err := f.control.GetPublication(f.ctx, publication.ID)
	if err != nil {
		t.Fatal(err)
	}
	currentAttempt, err := f.control.GetPromptAttempt(f.ctx, attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	currentOwner, err := f.control.GetControllerEpoch(f.ctx, store.DefaultControllerEpochName)
	if err != nil {
		t.Fatal(err)
	}
	publications := &corev1alpha1.PublicationList{}
	if err := f.pools.List(f.ctx, publications, client.InNamespace(f.task.Namespace)); err != nil {
		t.Fatal(err)
	}
	if len(publications.Items) != 1 || !reflect.DeepEqual(currentPublication, publication) ||
		!reflect.DeepEqual(currentAttempt, attempt) || !reflect.DeepEqual(currentOwner, owner) {
		t.Fatal("retirement minted or changed a publication, attempt, or controller authority")
	}
}
