package controllerlab

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func requireInconclusiveCleanup(t *testing.T, l *publishingLab, r Request, s State, cause error) {
	t.Helper()
	var safe *Error
	require.ErrorAs(t, cause, &safe)
	require.Equal(t, Infrastructure, safe.Kind)
	require.Equal(t, Cleaning, s.Phase)
	require.Equal(t, Inconclusive, s.Outcome)
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Complete, s.Phase)
	require.Equal(t, Inconclusive, s.Outcome)
	require.True(t, s.ControllerStopped)
	require.Nil(t, s.Intent)
	for _, receipt := range s.Receipts {
		require.True(t, receipt.Deleted && receipt.DeleteRequested)
	}
	_, err := l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))
	pods, err := l.kube.CoreV1().Pods(s.Namespaces[0]).List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Empty(t, pods.Items)
	for _, resource := range []ObjectRef{
		ref(clusterAuthentications, "", globalAuthName(s)), ref(clusterEventSources, "", globalSourceName(s)),
	} {
		objects, err := l.custom.Resource(resource.Resource).List(context.Background(), metav1.ListOptions{})
		require.NoError(t, err)
		require.Empty(t, objects.Items)
	}
}

func TestNamespaceReadFailuresAreInconclusiveAndFullyCleaned(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		cause error
	}{
		{"429", apierrors.NewTooManyRequests("synthetic throttling", 1)},
		{"500", apierrors.NewInternalError(errors.New("synthetic server error"))},
		{"503", apierrors.NewServiceUnavailable("synthetic service unavailable")},
		{"api-timeout", apierrors.NewTimeoutError("synthetic timeout", 1)},
		{"wrapped-timeout", fmt.Errorf("synthetic transport: %w", context.DeadlineExceeded)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			emulateKEDAFinalizers(t, l, r)
			s := l.phase(t, r, ObservingWindow)
			failed := false
			l.kube.PrependReactor("get", "namespaces", func(action ktesting.Action) (bool, runtime.Object, error) {
				if failed || action.(ktesting.GetAction).GetName() != s.Namespaces[0] {
					return false, nil, nil
				}
				failed = true
				return true, nil, tc.cause
			})
			next, err := l.step(s, r)
			require.True(t, failed)
			requireInconclusiveCleanup(t, l, r, next, err)
		})
	}
}

func TestNamespaceAbsenceAndUIDMismatchRemainOwnershipFailures(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"not-found", "uid-mismatch"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, ObservingWindow)
			if mode == "not-found" {
				l.kube.PrependReactor("get", "namespaces", func(action ktesting.Action) (bool, runtime.Object, error) {
					if action.(ktesting.GetAction).GetName() != s.Namespaces[0] {
						return false, nil, nil
					}
					return true, nil, apierrors.NewNotFound(namespaces.GroupResource(), s.Namespaces[0])
				})
			} else {
				raw, err := l.kube.Tracker().Get(namespaces, "", s.Namespaces[0])
				require.NoError(t, err)
				namespace := raw.(*corev1.Namespace)
				namespace.UID = "foreign-namespace-uid"
				require.NoError(t, l.kube.Tracker().Update(namespaces, namespace, ""))
			}
			next, err := l.step(s, r)
			var safe *Error
			require.ErrorAs(t, err, &safe)
			require.Equal(t, OwnershipLost, safe.Kind)
			require.Equal(t, Quarantined, next.Phase)
			require.Equal(t, Inconclusive, next.Outcome)
		})
	}
}

func TestObserverReadinessFailuresAreInconclusiveAndFullyCleaned(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"not-ready", "restart", "pending", "exited", "missing-status", "missing-ip", "missing-image-id"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			emulateKEDAFinalizers(t, l, r)
			s := l.phase(t, r, ObservingWindow)
			raw, err := l.kube.Tracker().Get(pods, s.ObserverNamespace, serviceName)
			require.NoError(t, err)
			pod := raw.(*corev1.Pod)
			switch mode {
			case "not-ready":
				pod.Status.ContainerStatuses[0].Ready = false
			case "restart":
				pod.Status.ContainerStatuses[0].RestartCount = 1
			case "pending":
				pod.Status.Phase = corev1.PodPending
			case "exited":
				pod.Status.Phase = corev1.PodSucceeded
				pod.Status.ContainerStatuses[0].State = corev1.ContainerState{
					Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
				}
			case "missing-status":
				pod.Status.ContainerStatuses = nil
			case "missing-ip":
				pod.Status.PodIP = ""
			case "missing-image-id":
				pod.Status.ContainerStatuses[0].ImageID = ""
			}
			require.NoError(t, l.kube.Tracker().Update(pods, pod, pod.Namespace))
			next, err := l.step(s, r)
			requireInconclusiveCleanup(t, l, r, next, err)
		})
	}
}

func TestObserverIdentityDriftStillQuarantinesWhenNotReady(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"ip", "image-spec", "image-id", "uid"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, ObservingWindow)
			raw, err := l.kube.Tracker().Get(pods, s.ObserverNamespace, serviceName)
			require.NoError(t, err)
			pod := raw.(*corev1.Pod)
			pod.Status.ContainerStatuses[0].Ready = false
			switch mode {
			case "ip":
				pod.Status.PodIP = "10.244.0.99"
			case "image-spec":
				pod.Spec.Containers[0].Image = "registry.invalid/replacement@sha256:" + strings.Repeat("f", 64)
			case "image-id":
				pod.Status.ContainerStatuses[0].ImageID = "sha256:" + strings.Repeat("f", 64)
			case "uid":
				pod.UID = "foreign-observer-uid"
			}
			require.NoError(t, l.kube.Tracker().Update(pods, pod, pod.Namespace))
			next, err := l.step(s, r)
			var safe *Error
			require.ErrorAs(t, err, &safe)
			require.Equal(t, OwnershipLost, safe.Kind)
			require.Equal(t, Quarantined, next.Phase)
			require.Equal(t, s.ObserverPodIP, next.ObserverPodIP)
		})
	}
}

func TestReceiptedGlobalGCIsInconclusiveAndFullyCleaned(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"authentication", "event-source"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			emulateKEDAFinalizers(t, l, r)
			s := l.phase(t, r, ObservingWindow)
			target := ref(clusterAuthentications, "", globalAuthName(s))
			if kind == "event-source" {
				target = ref(clusterEventSources, "", globalSourceName(s))
			}
			require.NotNil(t, receiptFor(s, target))
			raw, err := l.custom.Tracker().Get(target.Resource, "", target.Name)
			require.NoError(t, err)
			object := raw.(*unstructured.Unstructured)
			object.SetOwnerReferences([]metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Namespace", Name: "foreign", UID: "foreign",
			}})
			object.SetFinalizers(nil)
			require.NoError(t, l.custom.Tracker().Update(target.Resource, object, ""))
			require.NoError(t, l.custom.Tracker().Delete(target.Resource, "", target.Name))
			next, err := l.step(s, r)
			requireInconclusiveCleanup(t, l, r, next, err)
		})
	}
}

func TestForeignGlobalsAreOutsideScopeAndPreservedDuringOwnedCleanup(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"multiple", "continued-list", "different-name", "unreceipted-foreign-name"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			phase := ObservingWindow
			if mode == "unreceipted-foreign-name" {
				phase = InstallingSources
			}
			s := l.phase(t, r, phase)
			foreign := publishingEventSource(s, metav1.ObjectMeta{
				Name: "unowned-global-source", UID: "foreign-global-uid", ResourceVersion: "foreign-version",
			})
			require.Empty(t, foreign.GetOwnerReferences(), "foreign fixture must not be a dependent of our namespace")
			require.NoError(t, l.custom.Tracker().Create(clusterEventSources, foreign, ""))
			if mode == "different-name" {
				require.NoError(t, l.custom.Tracker().Delete(clusterEventSources, "", globalSourceName(s)))
			}
			if mode == "continued-list" {
				first := true
				l.custom.PrependReactor("list", clusterEventSources.Resource, func(ktesting.Action) (bool, runtime.Object, error) {
					if !first {
						return false, nil, nil
					}
					first = false
					page := &unstructured.UnstructuredList{Items: []unstructured.Unstructured{*foreign.DeepCopy()}}
					page.SetContinue("synthetic-next-page")
					return true, page, nil
				})
			}
			next, err := l.step(s, r)
			var safe *Error
			require.ErrorAs(t, err, &safe)
			require.Equal(t, OutsideScope, safe.Kind)
			require.Equal(t, Cleaning, next.Phase)
			require.Equal(t, Inconclusive, next.Outcome)
			next = l.until(t, next, r, State.Terminal)
			require.Equal(t, Complete, next.Phase)
			require.Equal(t, Inconclusive, next.Outcome)
			require.True(t, next.ControllerStopped)
			for _, receipt := range next.Receipts {
				require.True(t, receipt.Deleted && receipt.DeleteRequested)
			}
			_, err = l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err))
			pods, err := l.kube.CoreV1().Pods(s.Namespaces[0]).List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)
			require.Empty(t, pods.Items)
			_, err = l.custom.Resource(clusterEventSources).Get(context.Background(), globalSourceName(s), metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err))
			_, err = l.custom.Resource(clusterAuthentications).Get(context.Background(), globalAuthName(s), metav1.GetOptions{})
			require.True(t, apierrors.IsNotFound(err))
			preserved, err := l.custom.Resource(clusterEventSources).Get(context.Background(), foreign.GetName(), metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, foreign.Object, preserved.Object)
			globals, err := l.custom.Resource(clusterEventSources).List(context.Background(), metav1.ListOptions{})
			require.NoError(t, err)
			require.Len(t, globals.Items, 1)
			require.Equal(t, foreign.GetUID(), globals.Items[0].GetUID())
		})
	}
}

func TestReceiptedUIDReplacementAndReservedNameWithoutIntentStillQuarantine(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"replaced-uid", "reserved-name-without-intent"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			phase := ObservingWindow
			if mode == "reserved-name-without-intent" {
				phase = InstallingSources
			}
			s := l.phase(t, r, phase)
			if mode == "replaced-uid" {
				raw, err := l.custom.Tracker().Get(clusterEventSources, "", globalSourceName(s))
				require.NoError(t, err)
				object := raw.(*unstructured.Unstructured)
				object.SetUID("foreign-global-uid")
				require.NoError(t, l.custom.Tracker().Update(clusterEventSources, object, ""))
			} else {
				object := publishingEventSource(s, metav1.ObjectMeta{Name: globalSourceName(s), UID: "foreign-global-uid"})
				require.NoError(t, l.custom.Tracker().Create(clusterEventSources, object, ""))
			}
			next, err := l.step(s, r)
			var safe *Error
			require.ErrorAs(t, err, &safe)
			require.Equal(t, OwnershipLost, safe.Kind)
			require.Equal(t, Quarantined, next.Phase)
			require.Equal(t, Inconclusive, next.Outcome)
		})
	}
}
