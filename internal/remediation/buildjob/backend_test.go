package buildjob

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"
)

type fixture struct {
	config  Config
	input   Input
	kube    *fake.Clientset
	backend *Backend
}

func newFixture(t *testing.T, configure ...func(*Config)) *fixture {
	t.Helper()
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "builds", UID: "namespace-1", ResourceVersion: "1"},
		Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
	}
	kube := fake.NewClientset(namespace,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "buildkit-ca-v1", Namespace: "builds", UID: "ca-secret", ResourceVersion: "1"},
			Type:       corev1.SecretTypeOpaque, Immutable: new(true),
			Data: map[string][]byte{"ca.crt": []byte("synthetic-ca-material")},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "buildkit-client-v1", Namespace: "builds", UID: "client-secret", ResourceVersion: "1"},
			Type:       corev1.SecretTypeTLS, Immutable: new(true),
			Data: map[string][]byte{
				corev1.TLSCertKey:       []byte("synthetic-certificate-material"),
				corev1.TLSPrivateKeyKey: []byte("synthetic-key-material"),
			},
		},
	)
	installAPISemantics(kube)
	policy := Policy{
		RecipePath: "recipe.yml", Frontend: testImage("dalec", "a"), Worker: testImage("worker", "b"),
		WorkerArg: "DALEC_CUSTOM_WORKER", Target: "linux/container", Platform: "linux/amd64",
		OutputRepository: "registry.builds.svc:5000/remediation/output",
		SourcePaths:      []string{"source/main.go"},
	}
	config := Config{
		Kube: kube, Namespace: "builds", WorkerImage: testImage("trusted-client", "c"),
		BuildKitAddress: "tcp://buildkit.builds.svc:1234", Policies: []Policy{policy},
		TLS: &TLS{CASecretName: "buildkit-ca-v1", ClientSecretName: "buildkit-client-v1", ServerName: "buildkit.builds.svc"},
		Limits: Limits{BuildTimeout: 5 * time.Second, APITimeout: 2 * time.Second,
			CleanupTimeout: 2 * time.Second, PollInterval: time.Millisecond},
	}
	for _, change := range configure {
		change(&config)
	}
	backend, err := New(config)
	require.NoError(t, err)
	input := Input{
		RunID: "run-one", OperationID: "operation-one", RecipePath: policy.RecipePath,
		Frontend: policy.Frontend, Worker: policy.Worker, WorkerArg: policy.WorkerArg,
		Target: policy.Target, Platform: policy.Platform, OutputRepository: policy.OutputRepository,
		Files: map[string][]byte{
			"recipe.yml":     []byte("name: fixture\nbuild:\n  network_mode: none\n  steps:\n    - command: echo fixture\n"),
			"source/main.go": []byte("package main\nfunc main() {}\n"),
		},
	}
	return &fixture{config: config, input: input, kube: kube, backend: backend}
}

func testImage(name, character string) string {
	return "docker.io/orka/" + name + "@sha256:" + strings.Repeat(character, 64)
}

// The client-go fake stores real API objects but does not assign UIDs, enforce
// resource versions, honor finalizers, or check delete preconditions. Model those
// API mechanics explicitly rather than making the backend's checks no-ops.
func installAPISemantics(kube *fake.Clientset) {
	var sequence atomic.Int64
	sequence.Store(10)
	kube.PrependReactor("create", "*", func(action kubetesting.Action) (bool, runtime.Object, error) {
		obj := action.(kubetesting.CreateAction).GetObject()
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return true, nil, err
		}
		value := sequence.Add(1)
		accessor.SetUID(types.UID(fmt.Sprintf("%s-%d", action.GetResource().Resource, value)))
		accessor.SetResourceVersion(strconv.FormatInt(value, 10))
		return false, nil, nil
	})
	kube.PrependReactor("update", "*", func(action kubetesting.Action) (bool, runtime.Object, error) {
		obj := action.(kubetesting.UpdateAction).GetObject()
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return true, nil, err
		}
		old, err := kube.Tracker().Get(action.GetResource(), action.GetNamespace(), accessor.GetName())
		if err != nil {
			return true, nil, err
		}
		previous, err := meta.Accessor(old)
		if err != nil {
			return true, nil, err
		}
		if accessor.GetUID() != previous.GetUID() || accessor.GetResourceVersion() != previous.GetResourceVersion() {
			return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), accessor.GetName(), errors.New("stale object"))
		}
		if !immutableDataEqual(old, obj) {
			return true, nil, apierrors.NewForbidden(action.GetResource().GroupResource(), accessor.GetName(), errors.New("immutable data"))
		}
		accessor.SetResourceVersion(strconv.FormatInt(sequence.Add(1), 10))
		if accessor.GetDeletionTimestamp() != nil && len(accessor.GetFinalizers()) == 0 {
			err := kube.Tracker().Delete(action.GetResource(), action.GetNamespace(), accessor.GetName())
			return true, obj, err
		}
		return false, nil, nil
	})
	kube.PrependReactor("delete", "*", func(action kubetesting.Action) (bool, runtime.Object, error) {
		remove := action.(kubetesting.DeleteAction)
		obj, err := kube.Tracker().Get(action.GetResource(), action.GetNamespace(), remove.GetName())
		if err != nil {
			return true, nil, err
		}
		accessor, err := meta.Accessor(obj)
		if err != nil {
			return true, nil, err
		}
		options := remove.GetDeleteOptions()
		if options.Preconditions == nil || options.Preconditions.UID == nil || *options.Preconditions.UID != accessor.GetUID() ||
			options.PropagationPolicy == nil || *options.PropagationPolicy != metav1.DeletePropagationForeground {
			return true, nil, apierrors.NewConflict(action.GetResource().GroupResource(), remove.GetName(), errors.New("unfenced delete"))
		}
		if len(accessor.GetFinalizers()) != 0 {
			accessor.SetDeletionTimestamp(new(metav1.Now()))
			return true, nil, kube.Tracker().Update(action.GetResource(), obj, action.GetNamespace())
		}
		return false, nil, nil
	})
}

func immutableDataEqual(before, after runtime.Object) bool {
	switch old := before.(type) {
	case *corev1.Secret:
		next := after.(*corev1.Secret)
		return old.Immutable == nil || !*old.Immutable ||
			(next.Immutable != nil && *next.Immutable && reflect.DeepEqual(old.Data, next.Data))
	case *corev1.ConfigMap:
		next := after.(*corev1.ConfigMap)
		return old.Immutable == nil || !*old.Immutable ||
			(next.Immutable != nil && *next.Immutable && reflect.DeepEqual(old.Data, next.Data) &&
				reflect.DeepEqual(old.BinaryData, next.BinaryData))
	default:
		return true
	}
}

func (f *fixture) start(t *testing.T) Receipt {
	t.Helper()
	r, err := f.backend.Start(context.Background(), f.input)
	require.NoError(t, err)
	require.NotEmpty(t, r.JobUID)
	require.NotEmpty(t, r.AnchorUID)
	require.NotEmpty(t, r.LedgerUID)
	return r
}

func (f *fixture) pod(t *testing.T, r Receipt, wire *WorkerResult) *corev1.Pod {
	t.Helper()
	job, err := f.kube.BatchV1().Jobs(r.Namespace).Get(context.Background(), r.JobName, metav1.GetOptions{})
	require.NoError(t, err)
	pod := &corev1.Pod{
		ObjectMeta: *job.Spec.Template.ObjectMeta.DeepCopy(), Spec: *job.Spec.Template.Spec.DeepCopy(),
	}
	pod.Name, pod.Namespace = r.JobName+"-worker", r.Namespace
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "batch/v1", Kind: "Job", Name: r.JobName, UID: r.JobUID,
		Controller: new(true), BlockOwnerDeletion: new(true),
	}}
	pod.Labels[batchv1.ControllerUidLabel], pod.Labels[batchv1.JobNameLabel] = string(r.JobUID), r.JobName
	pod.Spec.NodeName = "worker-node"
	pod.Status.Phase = corev1.PodRunning
	if wire != nil {
		message, err := json.Marshal(wire)
		require.NoError(t, err)
		exit := int32(0)
		pod.Status.Phase = corev1.PodSucceeded
		if wire.BuildOutcome != Success {
			exit, pod.Status.Phase = 2, corev1.PodFailed
		}
		if wire.BuildOutcome == TestFailure {
			exit = int32(wire.BuildExitCode)
		}
		containerID := "containerd://" + strings.Repeat("d", 64)
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: workerName, Image: f.config.WorkerImage,
			ImageID: "docker-pullable://" + f.config.WorkerImage, ContainerID: containerID,
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				ExitCode: exit, Message: string(message), ContainerID: containerID,
			}},
		}}
	}
	pod, err = f.kube.CoreV1().Pods(r.Namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	require.NoError(t, err)
	return pod
}

func goodResult(r Receipt) *WorkerResult {
	return &WorkerResult{Version: Version, InputDigest: r.InputDigest, BuildOutcome: Success,
		ImmutableImageDigest: "sha256:" + strings.Repeat("e", 64), BuildRef: "fixture-build-ref", DaemonSettled: true}
}

func countActions(kube *fake.Clientset, verb, resource string) int {
	count := 0
	for _, action := range kube.Actions() {
		if action.GetVerb() == verb && action.GetResource().Resource == resource {
			count++
		}
	}
	return count
}

func settlingKubelet(f *fixture, r Receipt, podUID types.UID) {
	f.kube.PrependReactor("delete", "pods", func(action kubetesting.Action) (bool, runtime.Object, error) {
		name := action.(kubetesting.DeleteAction).GetName()
		object, err := f.kube.Tracker().Get(corev1.SchemeGroupVersion.WithResource("pods"), r.Namespace, name)
		if err != nil {
			return true, nil, err
		}
		pod := object.(*corev1.Pod)
		if pod.UID != podUID {
			return true, nil, errors.New("unexpected kubelet fixture identity")
		}
		wire := WorkerResult{Version: Version, InputDigest: r.InputDigest, BuildOutcome: Cancelled,
			BuildRef: "fixture-cancelled-ref", DaemonSettled: true}
		message, err := json.Marshal(wire)
		if err != nil {
			return true, nil, err
		}
		pod.Status.Phase = corev1.PodFailed
		pod.Status.ContainerStatuses = []corev1.ContainerStatus{{
			Name: workerName, Image: f.config.WorkerImage, ImageID: "docker-pullable://" + f.config.WorkerImage,
			ContainerID: "containerd://cancelled-worker",
			State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
				ExitCode: 1, ContainerID: "containerd://cancelled-worker", Message: string(message),
			}},
		}}
		if err := f.kube.Tracker().Update(corev1.SchemeGroupVersion.WithResource("pods"), pod, r.Namespace); err != nil {
			return true, nil, err
		}
		return false, nil, nil
	})
}

func TestDurableStartAndObserveAcrossBackendReconstruction(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	first, err := f.backend.Observe(context.Background(), r)
	require.NoError(t, err)
	require.False(t, first.Done)
	require.Equal(t, r.InputDigest, first.InputDigest)
	pod := f.pod(t, r, goodResult(r))
	original, err := f.backend.Observe(context.Background(), r)
	require.NoError(t, err)
	require.True(t, original.Done)
	require.Equal(t, pod.UID, original.PodUID)
	require.Equal(t, f.input.OutputRepository+"@"+goodResult(r).ImmutableImageDigest, original.Image)
	require.Regexp(t, digestPattern, original.ResultDigest)
	recovered, err := New(f.config)
	require.NoError(t, err)
	again, err := recovered.Start(context.Background(), f.input)
	require.NoError(t, err)
	require.Equal(t, r, again)
	observed, err := recovered.Observe(context.Background(), r)
	require.NoError(t, err)
	require.Equal(t, original, observed)
	require.Equal(t, 1, countActions(f.kube, "create", "jobs"))
	require.Equal(t, 1, countActions(f.kube, "create", "secrets"))
	require.Equal(t, 1, countActions(f.kube, "create", "configmaps"))
	encoded, err := json.Marshal(observed)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"inputDigest"`)
	require.Contains(t, string(encoded), `"version":1`)
}

func TestJobUsesOnlyTrustedFixedClientAndPrivateInput(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	job, err := f.kube.BatchV1().Jobs(r.Namespace).Get(context.Background(), r.JobName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, r.AnchorUID, job.OwnerReferences[0].UID)
	require.Nil(t, job.Spec.TTLSecondsAfterFinished)
	require.EqualValues(t, 0, *job.Spec.BackoffLimit)
	require.EqualValues(t, 1, *job.Spec.Parallelism)
	pod := job.Spec.Template.Spec
	require.False(t, *pod.AutomountServiceAccountToken)
	require.False(t, pod.HostNetwork)
	require.False(t, pod.HostPID)
	require.False(t, pod.HostIPC)
	require.False(t, *pod.EnableServiceLinks)
	require.EqualValues(t, 65532, *pod.SecurityContext.RunAsUser)
	require.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, pod.SecurityContext.SeccompProfile.Type)
	require.Len(t, pod.Containers, 1)
	worker := pod.Containers[0]
	require.Equal(t, f.config.WorkerImage, worker.Image)
	require.Equal(t, []string{"/orka-remediation-build-worker"}, worker.Command)
	require.Equal(t, []string{"--bundle=/bundle", "--workspace=/workspace", "--termination=/dev/termination-log"}, worker.Args)
	require.True(t, *worker.SecurityContext.ReadOnlyRootFilesystem)
	require.Equal(t, []corev1.Capability{"ALL"}, worker.SecurityContext.Capabilities.Drop)
	require.Empty(t, worker.Env)
	require.Empty(t, worker.EnvFrom)
	require.Empty(t, pod.InitContainers)
	require.Empty(t, pod.EphemeralContainers)
	require.Len(t, pod.Volumes, 4)
	require.Nil(t, pod.Volumes[0].HostPath)
	require.Equal(t, r.AnchorName, pod.Volumes[0].Secret.SecretName)
	require.True(t, worker.VolumeMounts[0].ReadOnly)
	anchor, err := f.kube.CoreV1().Secrets(r.Namespace).Get(context.Background(), r.AnchorName, metav1.GetOptions{})
	require.NoError(t, err)
	require.True(t, *anchor.Immutable)
	require.Empty(t, anchor.OwnerReferences)
	require.Equal(t, string(r.JobUID), anchor.Annotations[jobUIDAnnotation])
	m, input, err := unpackBundle(anchor.Data)
	require.NoError(t, err)
	require.Equal(t, r.InputDigest, input.InputDigest)
	require.Equal(t, f.input.Files, input.Files)
	require.Equal(t, f.config.BuildKitAddress, m.BuildKitAddress)
	record, err := f.kube.CoreV1().ConfigMaps(r.Namespace).Get(context.Background(), r.LedgerName, metav1.GetOptions{})
	require.NoError(t, err)
	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "package main")
	require.NotContains(t, string(encoded), "network_mode")
}

func TestLostCreateAcknowledgementRecoversExactJob(t *testing.T) {
	f := newFixture(t)
	f.kube.PrependReactor("create", "jobs", func(action kubetesting.Action) (bool, runtime.Object, error) {
		job := action.(kubetesting.CreateAction).GetObject().(*batchv1.Job).DeepCopy()
		job.UID, job.ResourceVersion = "job-with-lost-ack", "100"
		err := f.kube.Tracker().Create(action.GetResource(), job, job.Namespace)
		if err != nil {
			return true, nil, err
		}
		return true, nil, apierrors.NewTimeoutError("lost acknowledgement", 1)
	})
	r := f.start(t)
	require.Equal(t, types.UID("job-with-lost-ack"), r.JobUID)
	recovered, err := New(f.config)
	require.NoError(t, err)
	r2, err := recovered.Start(context.Background(), f.input)
	require.NoError(t, err)
	require.Equal(t, r, r2)
	require.Equal(t, 1, countActions(f.kube, "create", "jobs"))
}

func TestAcceptedMissingOrReplacedJobNeverReplays(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		t.Run(strconv.FormatBool(replaced), func(t *testing.T) {
			f := newFixture(t)
			r := f.start(t)
			resource := batchv1.SchemeGroupVersion.WithResource("jobs")
			require.NoError(t, f.kube.Tracker().Delete(resource, r.Namespace, r.JobName))
			if replaced {
				job := f.backend.desiredJob(r)
				job.UID, job.ResourceVersion = "replacement", "999"
				require.NoError(t, f.kube.Tracker().Create(resource, job, r.Namespace))
			}
			recovered, err := New(f.config)
			require.NoError(t, err)
			_, err = recovered.Start(context.Background(), f.input)
			require.Error(t, err)
			_, err = recovered.Observe(context.Background(), r)
			require.Error(t, err)
			require.Equal(t, 1, countActions(f.kube, "create", "jobs"))
			if replaced {
				require.ErrorIs(t, recovered.Cancel(context.Background(), r), ErrIdentity)
				job, err := f.kube.BatchV1().Jobs(r.Namespace).Get(context.Background(), r.JobName, metav1.GetOptions{})
				require.NoError(t, err)
				require.Equal(t, types.UID("replacement"), job.UID)
			}
		})
	}
}

func TestRecoveryHintsAndCanonicalInputsFailClosed(t *testing.T) {
	f := newFixture(t)
	existing := f.input
	existing.RequireExisting = true
	_, err := f.backend.Start(context.Background(), existing)
	require.ErrorIs(t, err, ErrLost)
	require.Zero(t, countActions(f.kube, "create", "jobs"))
	r := f.start(t)
	existing.ExpectedJobUID = "wrong-job"
	_, err = f.backend.Start(context.Background(), existing)
	require.ErrorIs(t, err, ErrIdentity)
	existing.ExpectedJobUID = r.JobUID
	same, err := f.backend.Start(context.Background(), existing)
	require.NoError(t, err)
	require.Equal(t, r, same)
	changed := f.input
	changed.Files = map[string][]byte{"recipe.yml": f.input.Files["recipe.yml"], "extra.txt": []byte("different source")}
	_, err = f.backend.Start(context.Background(), changed)
	require.ErrorIs(t, err, ErrIdentity)
	require.Equal(t, 1, countActions(f.kube, "create", "jobs"))
}

func TestPreparedPartialCreateResumesButAmbiguousSubmissionDoesNot(t *testing.T) {
	t.Run("prepared", func(t *testing.T) {
		f := newFixture(t)
		var once atomic.Bool
		f.kube.PrependReactor("update", "secrets", func(action kubetesting.Action) (bool, runtime.Object, error) {
			secret := action.(kubetesting.UpdateAction).GetObject().(*corev1.Secret)
			if secret.Annotations[stateAnnotation] == submittedState && !once.Swap(true) {
				return true, nil, apierrors.NewServiceUnavailable("before intent persistence")
			}
			return false, nil, nil
		})
		r, err := f.backend.Start(context.Background(), f.input)
		require.ErrorIs(t, err, ErrAPI)
		require.NotEmpty(t, r.AnchorUID)
		require.Empty(t, r.JobUID)
		require.Zero(t, countActions(f.kube, "create", "jobs"))
		recovered, err := New(f.config)
		require.NoError(t, err)
		r, err = recovered.Start(context.Background(), f.input)
		require.NoError(t, err)
		require.NotEmpty(t, r.JobUID)
		require.Equal(t, 1, countActions(f.kube, "create", "jobs"))
	})
	t.Run("ambiguous", func(t *testing.T) {
		f := newFixture(t, func(config *Config) { config.Limits.CleanupTimeout = 30 * time.Millisecond })
		f.kube.PrependReactor("create", "jobs", func(kubetesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewTimeoutError("unknown submission", 1)
		})
		r, err := f.backend.Start(context.Background(), f.input)
		require.ErrorIs(t, err, ErrIndeterminate)
		require.NotEmpty(t, r.AnchorUID)
		_, err = f.backend.Start(context.Background(), f.input)
		require.ErrorIs(t, err, ErrIndeterminate)
		proof, err := f.backend.Cleanup(context.Background(), r)
		require.ErrorIs(t, err, ErrCleanup)
		require.False(t, proof.Stopped)
		require.False(t, proof.SubmissionSettled)
		require.Equal(t, 1, countActions(f.kube, "create", "jobs"))
		_, err = f.kube.CoreV1().Secrets(r.Namespace).Get(context.Background(), r.AnchorName, metav1.GetOptions{})
		require.NoError(t, err)
	})
}

func TestCancellationOfCallerDoesNotDeleteDurableBuild(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.kube.PrependReactor("create", "jobs", func(kubetesting.Action) (bool, runtime.Object, error) {
		cancel()
		return false, nil, nil
	})
	r, err := f.backend.Start(ctx, f.input)
	require.ErrorIs(t, err, context.Canceled)
	require.NotEmpty(t, r.JobUID)
	_, err = f.backend.Observe(ctx, r)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, countActions(f.kube, "delete", "jobs"))
	require.Zero(t, countActions(f.kube, "delete", "secrets"))
	recovered, err := New(f.config)
	require.NoError(t, err)
	request := f.input
	request.ExpectedJobUID, request.RequireExisting = r.JobUID, true
	again, err := recovered.Start(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, r.JobUID, again.JobUID)
}

func TestBackendRejectsReplacedNamespaceAnchorAndLedger(t *testing.T) {
	for _, kind := range []string{"namespaces", "secrets", "configmaps"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			r := f.start(t)
			resource := schema.GroupVersionResource{Version: "v1", Resource: kind}
			namespace, name := r.Namespace, r.AnchorName
			switch kind {
			case "namespaces":
				namespace, name = "", r.Namespace
			case "configmaps":
				name = r.LedgerName
			}
			obj, err := f.kube.Tracker().Get(resource, namespace, name)
			require.NoError(t, err)
			accessor, err := meta.Accessor(obj)
			require.NoError(t, err)
			accessor.SetUID("replaced-identity")
			require.NoError(t, f.kube.Tracker().Delete(resource, namespace, name))
			require.NoError(t, f.kube.Tracker().Create(resource, obj, namespace))
			_, err = f.backend.Observe(context.Background(), r)
			require.ErrorIs(t, err, ErrIdentity)
			_, err = f.backend.Start(context.Background(), f.input)
			require.ErrorIs(t, err, ErrIdentity)
			require.Equal(t, 1, countActions(f.kube, "create", "jobs"))
		})
	}
}
