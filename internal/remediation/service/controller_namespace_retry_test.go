package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ktesting "k8s.io/client-go/testing"
)

func controllerNamespaceFixture(t *testing.T) (*controllerTestFixture, *Session, *pipelineState) {
	t.Helper()
	fixture, session, state := controllerSessionFixture(t)
	state.Original.Controller.State = controllerlab.State{
		Version: 1, Revision: 1, RunID: session.run.ID, OperationID: state.Original.ID,
		OperationDigest: strings.Repeat("a", 64), Phase: controllerlab.WaitingPlacement,
		Namespaces: [2]string{"fixture-controller-a", "fixture-controller-b"}, ObserverNamespace: "fixture-observer",
	}
	require.NoError(t, fixture.pipeline.save(t.Context(), session, state, state.Stage))
	return fixture, session, state
}

func TestControllerNamespaceDefiniteRejectionCanRetryOrCancel(t *testing.T) {
	rejections := map[string]error{
		"throttled": apierrors.NewTooManyRequests("synthetic throttling", 1),
		"forbidden": apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "fixture", errors.New("synthetic policy")),
		"invalid": apierrors.NewInvalid(schema.GroupKind{Kind: "Namespace"}, "fixture",
			field.ErrorList{field.Invalid(field.NewPath("metadata", "name"), "fixture", "synthetic admission rejection")}),
		"webhook": &apierrors.StatusError{ErrStatus: metav1.Status{
			Status: metav1.StatusFailure, Code: http.StatusForbidden, Message: "synthetic webhook denied request",
		}},
	}
	for name, rejection := range rejections {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture, session, state := controllerNamespaceFixture(t)
			operation := &state.Original
			creates := 0
			fixture.kube.PrependReactor("create", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
				creates++
				if creates == 1 {
					return true, nil, fmt.Errorf("namespace rejected: %w", rejection)
				}
				return false, nil, nil
			})
			err := fixture.adapter.ensureControllerNamespace(t.Context(), session, state, operation)
			require.ErrorIs(t, err, ErrRetryable)
			require.False(t, operation.Controller.Control.CreateAttempted)
			require.Empty(t, operation.Controller.Control.UID)
			nonce := operation.Controller.Control.IntentDigest
			require.NoError(t, fixture.adapter.ensureControllerNamespace(t.Context(), session, state, operation))
			require.Equal(t, 2, creates)
			require.NotEmpty(t, operation.Controller.Control.UID)
			require.Equal(t, nonce, operation.Controller.Control.IntentDigest)
			require.NoError(t, fixture.adapter.ensureControllerNamespace(t.Context(), session, state, operation))
			require.Equal(t, 2, creates, "an acknowledged namespace must not be recreated")
		})
	}
	t.Run("cancel-definitely-uncreated", func(t *testing.T) {
		t.Parallel()
		fixture, session, state := controllerNamespaceFixture(t)
		fixture.kube.PrependReactor("create", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, rejections["forbidden"]
		})
		operation := &state.Original
		require.ErrorIs(t, fixture.adapter.ensureControllerNamespace(t.Context(), session, state, operation), ErrRetryable)
		require.NoError(t, fixture.adapter.cleanupControllerNamespace(t.Context(), session, state, operation, true))
		require.Nil(t, operation.Controller.Control)
		for _, action := range fixture.kube.Actions() {
			require.NotEqual(t, "delete", action.GetVerb())
		}
	})
}

func TestControllerNamespaceAmbiguousWriteReconcilesWithoutReplay(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		t.Run(fmt.Sprintf("delayed=%t", delayed), func(t *testing.T) {
			t.Parallel()
			fixture, session, state := controllerNamespaceFixture(t)
			operation := &state.Original
			var accepted *corev1.Namespace
			creates := 0
			fixture.kube.PrependReactor("create", "namespaces", func(action ktesting.Action) (bool, runtime.Object, error) {
				creates++
				accepted = action.(ktesting.CreateAction).GetObject().(*corev1.Namespace).DeepCopy()
				accepted.UID, accepted.ResourceVersion = "accepted-proof-namespace", "1"
				accepted.Status.Phase = corev1.NamespaceActive
				if !delayed {
					require.NoError(t, fixture.kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("namespaces"), accepted, ""))
				}
				return true, nil, io.ErrUnexpectedEOF
			})
			require.ErrorIs(t, fixture.adapter.ensureControllerNamespace(t.Context(), session, state, operation), ErrRetryable)
			require.True(t, operation.Controller.Control.CreateAttempted)
			if delayed {
				require.ErrorIs(t, fixture.adapter.ensureControllerNamespace(t.Context(), session, state, operation), ErrRetryable)
				require.Equal(t, 1, creates, "a missing acknowledgement does not permit another Create")
				require.ErrorIs(t, fixture.adapter.cleanupControllerNamespace(t.Context(), session, state, operation, true), ErrUnknown)
				require.NoError(t, fixture.kube.Tracker().Create(corev1.SchemeGroupVersion.WithResource("namespaces"), accepted, ""))
			}
			require.NoError(t, fixture.adapter.ensureControllerNamespace(t.Context(), session, state, operation))
			require.Equal(t, accepted.UID, operation.Controller.Control.UID)
			require.Equal(t, 1, creates)
			require.NoError(t, fixture.adapter.cleanupControllerNamespace(t.Context(), session, state, operation, true))
			require.NoError(t, fixture.adapter.cleanupControllerNamespace(t.Context(), session, state, operation, true))
			require.True(t, operation.Controller.Control.Deleted)
		})
	}
}

func TestControllerNamespaceRecoveryRejectsUnrelatedOrReplacedObjects(t *testing.T) {
	for _, mismatch := range []string{"intent", "operation-label", "replacement-uid"} {
		t.Run(mismatch, func(t *testing.T) {
			t.Parallel()
			fixture, session, state := controllerNamespaceFixture(t)
			operation := &state.Original
			if mismatch == "replacement-uid" {
				require.NoError(t, fixture.adapter.ensureControllerNamespace(t.Context(), session, state, operation))
			} else {
				fixture.kube.PrependReactor("create", "namespaces", func(action ktesting.Action) (bool, runtime.Object, error) {
					namespace := action.(ktesting.CreateAction).GetObject().(*corev1.Namespace).DeepCopy()
					namespace.UID = "ambiguous-namespace"
					require.NoError(t, fixture.kube.Tracker().Create(action.GetResource(), namespace, ""))
					return true, nil, apierrors.NewTimeoutError("synthetic acknowledgement lost", 1)
				})
				require.ErrorIs(t, fixture.adapter.ensureControllerNamespace(t.Context(), session, state, operation), ErrRetryable)
			}
			namespace, err := fixture.kube.CoreV1().Namespaces().Get(t.Context(), operation.Controller.Control.Name, metav1.GetOptions{})
			require.NoError(t, err)
			switch mismatch {
			case "intent":
				namespace.Annotations[controllerControlIntent] = strings.Repeat("b", 64)
			case "operation-label":
				namespace.Labels[controllerControlLabel] = strings.Repeat("b", 40)
			case "replacement-uid":
				namespace.UID = "replacement-namespace"
			}
			require.NoError(t, fixture.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("namespaces"), namespace, ""))
			require.ErrorIs(t, fixture.adapter.ensureControllerNamespace(t.Context(), session, state, operation), ErrUnknown)
			require.ErrorIs(t, fixture.adapter.cleanupControllerNamespace(t.Context(), session, state, operation, true), ErrUnknown)
			for _, action := range fixture.kube.Actions() {
				require.NotEqual(t, "delete", action.GetVerb())
			}
		})
	}
}

func TestControllerNamespaceThrottleResumesPipeline(t *testing.T) {
	t.Parallel()
	fixture := newControllerFixture(t)
	var proofCreates atomic.Int32
	fixture.kube.PrependReactor("create", "namespaces", func(action ktesting.Action) (bool, runtime.Object, error) {
		namespace := action.(ktesting.CreateAction).GetObject().(*corev1.Namespace)
		if strings.HasSuffix(namespace.Name, "-proof") && proofCreates.Add(1) == 1 {
			return true, nil, apierrors.NewTooManyRequests("synthetic throttling", 1)
		}
		return false, nil, nil
	})
	run := fixture.submit(Validate)
	require.NoError(t, fixture.service.RunOnce(t.Context()))
	current, err := fixture.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseRunning, current.Phase)
	require.Equal(t, "waiting-for-infrastructure", current.Reason)
	var state pipelineState
	require.NoError(t, json.Unmarshal(current.StateJSON, &state))
	require.False(t, state.Original.Controller.Control.CreateAttempted)
	timer := time.NewTimer(time.Until(current.ClaimUntil) + 20*time.Millisecond)
	defer timer.Stop()
	select {
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	case <-timer.C:
	}
	require.NoError(t, fixture.service.RunOnce(t.Context()))
	current, err = fixture.store.GetRemediationRun(t.Context(), run.Namespace, run.ID)
	require.NoError(t, err)
	require.Equal(t, store.RemediationPhaseSucceeded, current.Phase, current.Reason)
	require.Equal(t, int32(3), proofCreates.Load(), "one rejected attempt and one namespace per completed arm")
}

func TestControllerNamespaceDefiniteRejectionCheckpointSurvivesCancellation(t *testing.T) {
	t.Parallel()
	fixture, session, state := controllerNamespaceFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	fixture.kube.PrependReactor("create", "namespaces", func(ktesting.Action) (bool, runtime.Object, error) {
		_, err := session.store.CancelRemediationRun(t.Context(), session.run.Namespace, session.run.ID, time.Now())
		require.NoError(t, err)
		cancel()
		return true, nil, apierrors.NewTooManyRequests("synthetic throttling", 1)
	})
	require.ErrorIs(t, fixture.adapter.ensureControllerNamespace(ctx, session, state, &state.Original), ErrRetryable)
	require.False(t, state.Original.Controller.Control.CreateAttempted)
}

func TestControllerNamespaceAmbiguousStatusesAreNotDefiniteRejections(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		io.ErrUnexpectedEOF,
		context.DeadlineExceeded,
		apierrors.NewAlreadyExists(schema.GroupResource{Resource: "namespaces"}, "fixture"),
		apierrors.NewTimeoutError("synthetic timeout", 1),
		apierrors.NewInternalError(errors.New("synthetic server failure")),
	} {
		require.False(t, definitiveControllerNamespaceRejection(fmt.Errorf("wrapped: %w", err)))
	}
}
