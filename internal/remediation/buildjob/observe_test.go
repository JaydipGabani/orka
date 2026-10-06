package buildjob

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kubetesting "k8s.io/client-go/testing"
)

func TestObserveRejectsUntrustedResultAndExecutionIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*corev1.Pod)
	}{
		{"wrong-input", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.Message = strings.ReplaceAll(
				p.Status.ContainerStatuses[0].State.Terminated.Message, `"inputDigest":"sha256:`, `"inputDigest":"sha512:`)
		}},
		{"model-success-field", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.Message = `{"success":true,"image":"registry/output:latest"}`
		}},
		{"duplicate-result-keys", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.Message = strings.Replace(
				p.Status.ContainerStatuses[0].State.Terminated.Message, `"version":1`, `"version":1,"version":1`, 1)
		}},
		{"oversized-message", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.Message += strings.Repeat(" ", MaxTerminationBytes)
		}},
		{"nonzero-success-exit", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State.Terminated.ExitCode = 1 }},
		{"untrusted-runtime-image", func(p *corev1.Pod) {
			p.Status.ContainerStatuses[0].ImageID = "docker-pullable://" + testImage("other", "f")
		}},
		{"missing-runtime-image-id", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].ImageID = "" }},
		{"restarted-container", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 }},
		{"replaced-container", func(p *corev1.Pod) { p.Status.ContainerStatuses[0].State.Terminated.ContainerID = "another" }},
		{"wrong-owner", func(p *corev1.Pod) { p.OwnerReferences[0].UID = "unowned" }},
		{"wrong-namespace-marker", func(p *corev1.Pod) { p.Annotations[namespaceAnnotation] = "other-namespace" }},
		{"wrong-task-label", func(p *corev1.Pod) { p.Labels[inputLabel] = "another-digest" }},
		{"mutated-entrypoint", func(p *corev1.Pod) { p.Spec.Containers[0].Command = []string{"/bin/sh", "-c", "true"} }},
		{"injected-auth", func(p *corev1.Pod) {
			p.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "DOCKER_CONFIG", Value: "/untrusted"}}
		}},
		{"injected-sidecar", func(p *corev1.Pod) {
			p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "unexpected", Image: testImage("other", "f")})
		}},
		{"mutable-token-mount", func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = new(true) }},
		{"host-network", func(p *corev1.Pod) { p.Spec.HostNetwork = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t)
			r := f.start(t)
			pod := f.pod(t, r, goodResult(r))
			test.change(pod)
			require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod, r.Namespace))
			result, err := f.backend.Observe(context.Background(), r)
			require.ErrorIs(t, err, ErrIdentity)
			require.False(t, result.Done)
			require.Empty(t, result.Image)
		})
	}
}

func TestObserveFencesPodReplacementAndAdditionalPods(t *testing.T) {
	for _, multiple := range []bool{false, true} {
		t.Run(map[bool]string{false: "replacement", true: "additional"}[multiple], func(t *testing.T) {
			f := newFixture(t)
			r := f.start(t)
			pod := f.pod(t, r, nil)
			waiting, err := f.backend.Observe(context.Background(), r)
			require.NoError(t, err)
			require.False(t, waiting.Done)
			resource := corev1.SchemeGroupVersion.WithResource("pods")
			if !multiple {
				require.NoError(t, f.kube.Tracker().Delete(resource, r.Namespace, pod.Name))
			} else {
				pod.Name += "-another"
			}
			pod.UID = "new-pod"
			require.NoError(t, f.kube.Tracker().Create(resource, pod, r.Namespace))
			result, err := f.backend.Observe(context.Background(), r)
			require.ErrorIs(t, err, ErrIdentity)
			require.False(t, result.Done)
		})
	}
}

func TestObserveDetectsLostPreviouslyObservedPod(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	pod := f.pod(t, r, nil)
	_, err := f.backend.Observe(context.Background(), r)
	require.NoError(t, err)
	require.NoError(t, f.kube.Tracker().Delete(corev1.SchemeGroupVersion.WithResource("pods"), r.Namespace, pod.Name))
	_, err = f.backend.Observe(context.Background(), r)
	require.ErrorIs(t, err, ErrLost)
}

func TestObserveRevalidatesPodAfterReadingTermination(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	pod := f.pod(t, r, goodResult(r))
	f.kube.PrependReactor("get", "pods", func(kubetesting.Action) (bool, runtime.Object, error) {
		replaced := pod.DeepCopy()
		replaced.UID = "replacement-after-result-read"
		return true, replaced, nil
	})
	result, err := f.backend.Observe(context.Background(), r)
	require.ErrorIs(t, err, ErrIdentity)
	require.False(t, result.Done)
}

func TestObserveRevalidatesJobAndImmutableAnchorBytes(t *testing.T) {
	for _, target := range []string{"job", "input", "ttl"} {
		t.Run(target, func(t *testing.T) {
			f := newFixture(t)
			r := f.start(t)
			f.pod(t, r, goodResult(r))
			if target == "input" {
				anchor, err := f.kube.CoreV1().Secrets(r.Namespace).Get(context.Background(), r.AnchorName, metav1.GetOptions{})
				require.NoError(t, err)
				anchor.Data[archiveKey] = []byte("forged private inputs")
				require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), anchor, r.Namespace))
			} else {
				job, err := f.kube.BatchV1().Jobs(r.Namespace).Get(context.Background(), r.JobName, metav1.GetOptions{})
				require.NoError(t, err)
				if target == "job" {
					job.Spec.Template.Spec.Containers[0].Args = []string{"--forged"}
				} else {
					job.Spec.TTLSecondsAfterFinished = new(int32(1))
				}
				require.NoError(t, f.kube.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), job, r.Namespace))
			}
			result, err := f.backend.Observe(context.Background(), r)
			require.ErrorIs(t, err, ErrIdentity)
			require.False(t, result.Done)
		})
	}
}

func TestCompileFailureAndMeasuredContainerFailureAreNotSuccess(t *testing.T) {
	for _, missingMessage := range []bool{false, true} {
		t.Run(map[bool]string{false: "compile-failure", true: "container-failure"}[missingMessage], func(t *testing.T) {
			f := newFixture(t)
			r := f.start(t)
			pod := f.pod(t, r, &WorkerResult{Version: Version, InputDigest: r.InputDigest, BuildOutcome: CompileFailure,
				Diagnostics: []Diagnostic{{Path: "source/main.go", Line: 7, Column: 3}}})
			if missingMessage {
				pod.Status.ContainerStatuses[0].State.Terminated.Message = ""
				pod.Status.ContainerStatuses[0].State.Terminated.Reason = "OOMKilled"
				require.NoError(t, f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod, r.Namespace))
			}
			result, err := f.backend.Observe(context.Background(), r)
			require.NoError(t, err)
			require.True(t, result.Done)
			require.Empty(t, result.Image)
			require.Empty(t, result.ImmutableImageDigest)
			if missingMessage {
				require.Equal(t, Infrastructure, result.BuildOutcome)
			} else {
				require.Equal(t, CompileFailure, result.BuildOutcome)
				require.Equal(t, "source/main.go", result.Diagnostics[0].Path)
			}
			require.Regexp(t, digestPattern, result.ResultDigest)
		})
	}
}

func TestResultDiagnosticsAreLimitedToKnownSourcePaths(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	for _, diagnostic := range []Diagnostic{
		{Path: "/etc/passwd", Line: 1}, {Path: "unknown/file.go", Line: 1},
		{Path: "source/main.go", Line: -1}, {Path: "source/main.go", Line: 1, Symbol: "raw\nstderr"},
	} {
		wire := WorkerResult{Version: Version, InputDigest: r.InputDigest, BuildOutcome: CompileFailure,
			Diagnostics: []Diagnostic{diagnostic}}
		body, err := json.Marshal(wire)
		require.NoError(t, err)
		_, err = readWorkerResult(&corev1.ContainerStateTerminated{ExitCode: 1, Message: string(body)},
			r.InputDigest, map[string]bool{"source/main.go": true})
		require.ErrorIs(t, err, ErrIdentity)
	}
}

func TestTerminalJobWithoutPodEvidenceDoesNotRemainPending(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	job, err := f.kube.BatchV1().Jobs(r.Namespace).Get(context.Background(), r.JobName, metav1.GetOptions{})
	require.NoError(t, err)
	job.Status.Conditions = []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Reason: "DeadlineExceeded"}}
	require.NoError(t, f.kube.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), job, r.Namespace))
	result, err := f.backend.Observe(context.Background(), r)
	require.ErrorIs(t, err, ErrLost)
	require.False(t, result.Done)
}

func TestObserveRejectsJobEvidenceOfPreviousExecution(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	f.pod(t, r, goodResult(r))
	job, err := f.kube.BatchV1().Jobs(r.Namespace).Get(context.Background(), r.JobName, metav1.GetOptions{})
	require.NoError(t, err)
	job.Status.Succeeded, job.Status.Failed = 1, 1
	require.NoError(t, f.kube.Tracker().Update(batchv1.SchemeGroupVersion.WithResource("jobs"), job, r.Namespace))
	result, err := f.backend.Observe(context.Background(), r)
	require.ErrorIs(t, err, ErrIdentity)
	require.False(t, result.Done)
}
