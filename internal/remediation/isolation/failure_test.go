package isolation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/remediation/isolation/probe"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestAbsentCNIAndMissingPositiveCannotPass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		role   string
		result probe.Result
	}{
		{"no-enforcement", negativeRole, probe.Result{Reachable: true, NonceMatched: true, FailureClass: probe.None}},
		{"positive-before-missing", beforeRole, probe.Result{FailureClass: probe.DialTimeout}},
		{"positive-after-missing", afterRole, probe.Result{FailureClass: probe.DialTimeout}},
		{"connection-refused-is-not-deny", negativeRole, probe.Result{FailureClass: probe.ConnectionRefused}},
		{"route-unreachable-is-not-deny", negativeRole, probe.Result{FailureClass: probe.Unreachable}},
		{"read-timeout-is-not-deny", negativeRole, probe.Result{Reachable: true, FailureClass: probe.ExchangeFailed}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			f.results[test.role] = test.result
			receipt := f.start()
			var err error
			for range 40 {
				receipt, err = f.step(receipt)
				if err != nil {
					break
				}
			}
			require.ErrorContains(t, err, "needs-adapter")
			require.Equal(t, Failed, receipt.Phase)
			require.False(t, receipt.Proof.Verified)
			_, err = ExportProof(receipt)
			require.Error(t, err)
			receipt = f.clean(receipt)
			require.Equal(t, Rejected, receipt.Outcome)
			require.True(t, receipt.CleanupComplete)
			f.noLeaks()
		})
	}
}

func TestForgedTerminationCannotPass(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*corev1.Pod)
	}{
		{"false-success", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.Message =
				`{"reachable":true,"nonceMatched":true,"failureClass":"none"}`
		}},
		{"missing-field", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.Message = `{"failureClass":"dial-timeout"}`
		}},
		{"duplicate-field", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.Message =
				`{"reachable":false,"reachable":false,"nonceMatched":false,"failureClass":"dial-timeout"}`
		}},
		{"oversized-message", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.Message = strings.Repeat(" ", probe.MaxMessageBytes+1)
		}},
		{"exit-code-mismatch", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State.Terminated.ExitCode = 1 }},
		{"signal-mismatch", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State.Terminated.Signal = 9 }},
		{"restart", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 }},
		{"image-id-mismatch", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].ImageID = "containerd://sha256:" + strings.Repeat("c", 64)
		}},
		{"instant-timeout", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.FinishedAt = p.Status.ContainerStatuses[0].State.Terminated.StartedAt
		}},
		{"different-node", func(p *corev1.Pod) { p.Spec.NodeName = "other-node" }},
		{"different-selector", func(p *corev1.Pod) { p.Labels["component"] = "not-the-subject" }},
		{"injected-credentials", func(p *corev1.Pod) {
			p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "UNEXPECTED", Value: "synthetic"}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			receipt := f.until(f.start(), func(r Receipt) bool {
				return r.Phase == Negative && r.Objects[roleIndex(r, negativeRole)].UID != ""
			})
			f.drivePods(receipt)
			object := receipt.Objects[roleIndex(receipt, negativeRole)]
			pod, err := f.kube.CoreV1().Pods(object.Namespace).Get(context.Background(), object.Name, metav1.GetOptions{})
			require.NoError(t, err)
			test.mutate(pod)
			_, err = f.kube.CoreV1().Pods(object.Namespace).Update(context.Background(), pod, metav1.UpdateOptions{})
			require.NoError(t, err)
			receipt, err = f.adapter().Observe(context.Background(), receipt, f.store.persist)
			require.ErrorContains(t, err, "needs-adapter")
			require.False(t, receipt.Proof.Verified)
			receipt = f.clean(receipt)
			require.True(t, receipt.CleanupComplete)
			f.noLeaks()
		})
	}
}

func TestPolicyObjectPresenceAndReadinessAreInsufficient(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.start()
	var err error
	for range 8 {
		receipt, err = f.adapter().Observe(context.Background(), receipt, f.store.persist)
		require.NoError(t, err)
	}
	require.Equal(t, WaitingCanary, receipt.Phase)
	require.Empty(t, receipt.Proof.Observations)
	require.False(t, receipt.Proof.Verified)
	f.clock = receipt.Deadline.Add(time.Second)
	receipt, err = f.adapter().Observe(context.Background(), receipt, f.store.persist)
	require.ErrorContains(t, err, "proof-deadline-exceeded")
	require.Equal(t, Failed, receipt.Phase)
	receipt = f.clean(receipt)
	require.True(t, receipt.CleanupComplete)
	f.noLeaks()
}

func TestPolicyAndEndpointFences(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, *fixture, Receipt)
	}{
		{"policy-resource-version", func(t *testing.T, f *fixture, _ Receipt) {
			policy, err := f.kube.NetworkingV1().NetworkPolicies(f.subject.Name).Get(context.Background(), f.policy.Name, metav1.GetOptions{})
			require.NoError(t, err)
			policy.ResourceVersion = "changed"
			_, err = f.kube.NetworkingV1().NetworkPolicies(f.subject.Name).Update(context.Background(), policy, metav1.UpdateOptions{})
			require.NoError(t, err)
		}},
		{"policy-digest", func(t *testing.T, f *fixture, _ Receipt) {
			policy, err := f.kube.NetworkingV1().NetworkPolicies(f.subject.Name).Get(context.Background(), f.policy.Name, metav1.GetOptions{})
			require.NoError(t, err)
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{}}
			_, err = f.kube.NetworkingV1().NetworkPolicies(f.subject.Name).Update(context.Background(), policy, metav1.UpdateOptions{})
			require.NoError(t, err)
		}},
		{"additional-policy", func(t *testing.T, f *fixture, _ Receipt) {
			_, err := f.kube.NetworkingV1().NetworkPolicies(f.subject.Name).Create(context.Background(), &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "unexpected", Namespace: f.subject.Name},
			}, metav1.CreateOptions{})
			require.NoError(t, err)
		}},
		{"canary-ip", func(t *testing.T, f *fixture, r Receipt) {
			object := r.Objects[roleIndex(r, serverRole)]
			pod, err := f.kube.CoreV1().Pods(object.Namespace).Get(context.Background(), object.Name, metav1.GetOptions{})
			require.NoError(t, err)
			pod.Status.PodIP = "10.23.42.8"
			_, err = f.kube.CoreV1().Pods(object.Namespace).UpdateStatus(context.Background(), pod, metav1.UpdateOptions{})
			require.NoError(t, err)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			receipt := f.until(f.start(), func(r Receipt) bool { return r.Phase == Negative })
			test.mutate(t, f, receipt)
			receipt, err := f.adapter().Observe(context.Background(), receipt, f.store.persist)
			require.ErrorContains(t, err, "needs-adapter")
			require.False(t, receipt.Proof.Verified)
			require.Equal(t, 2, podCreates(f.kube))
			receipt = f.clean(receipt)
			require.True(t, receipt.CleanupComplete)
			f.noLeaks()
		})
	}
}

func TestPrivateReceiptRoundTripAndExportCannotBeBooleanOnly(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	receipt := f.until(f.start(), func(r Receipt) bool { return r.CleanupComplete })
	encoded, err := json.Marshal(receipt)
	require.NoError(t, err)
	var roundTrip Receipt
	require.NoError(t, json.Unmarshal(encoded, &roundTrip))
	_, err = ExportProof(roundTrip)
	require.NoError(t, err)
	roundTrip.Proof.Observations = nil
	roundTrip.Proof.Verified = true
	_, err = ExportProof(roundTrip)
	require.Error(t, err)
}
