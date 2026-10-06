package buildjob

import (
	"context"
	"maps"
	"reflect"
	"slices"
	"strings"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

const (
	managedLabel         = "app.kubernetes.io/managed-by"
	managedBy            = "orka-remediation-build"
	operationLabel       = "remediation.orka.ai/build-operation"
	runLabel             = "remediation.orka.ai/build-run"
	inputLabel           = "remediation.orka.ai/build-input"
	namespaceAnnotation  = "remediation.orka.ai/build-namespace-uid"
	configAnnotation     = "remediation.orka.ai/build-configuration"
	inputAnnotation      = "remediation.orka.ai/build-input-digest"
	ledgerUIDAnnotation  = "remediation.orka.ai/build-ledger-uid"
	anchorUIDAnnotation  = "remediation.orka.ai/build-anchor-uid"
	cleanupAnnotation    = "remediation.orka.ai/build-cleanup-receipt"
	jobUIDAnnotation     = "remediation.orka.ai/build-job-uid"
	podUIDAnnotation     = "remediation.orka.ai/build-pod-uid"
	stateAnnotation      = "remediation.orka.ai/build-state"
	submissionAnnotation = "remediation.orka.ai/build-submitted"
	anchorFinalizer      = "remediation.orka.ai/build-input-retention"
	jobFinalizer         = "remediation.orka.ai/build-result-retention"
	podFinalizer         = "remediation.orka.ai/build-daemon-settlement"
	preparedState        = "prepared"
	submittedState       = "submitted"
	cleanupState         = "cleanup"
	cleanedState         = "cleaned"
	workerName           = "build-worker"
)

func (b *Backend) baseReceipt(input Input, namespaceUID types.UID) Receipt {
	name := operationName(input.RunID, input.OperationID)
	return Receipt{
		Version: Version, RunID: input.RunID, OperationID: input.OperationID,
		InputDigest: input.InputDigest, ConfigurationDigest: b.digest,
		Namespace: b.config.Namespace, NamespaceUID: namespaceUID,
		LedgerName: name + "-record", AnchorName: name + "-input", JobName: name,
	}
}

func protectedLabels(r Receipt) map[string]string {
	return map[string]string{
		managedLabel:   managedBy,
		operationLabel: strings.TrimPrefix(r.JobName, "rem-build-"),
		runLabel:       strings.TrimPrefix(digest([]byte(r.RunID)), "sha256:")[:40],
		inputLabel:     strings.TrimPrefix(r.InputDigest, "sha256:")[:40],
	}
}

func protectedAnnotations(r Receipt) map[string]string {
	annotations := map[string]string{
		namespaceAnnotation:     string(r.NamespaceUID),
		configAnnotation:        r.ConfigurationDigest,
		inputAnnotation:         r.InputDigest,
		ledgerUIDAnnotation:     string(r.LedgerUID),
		caUIDAnnotation:         string(r.TLSSecrets.CA.UID),
		caVersionAnnotation:     r.TLSSecrets.CA.ResourceVersion,
		clientUIDAnnotation:     string(r.TLSSecrets.Client.UID),
		clientVersionAnnotation: r.TLSSecrets.Client.ResourceVersion,
	}
	if r.RegistrySecret.Name != "" {
		annotations[registryUIDAnnotation] = string(r.RegistrySecret.UID)
		annotations[registryVersionAnnotation] = r.RegistrySecret.ResourceVersion
	}
	return annotations
}

func (b *Backend) desiredAnchor(r Receipt, data map[string][]byte) *corev1.Secret {
	annotations := protectedAnnotations(r)
	annotations[stateAnnotation] = preparedState
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.Namespace, Name: r.AnchorName,
			Labels: protectedLabels(r), Annotations: annotations, Finalizers: []string{anchorFinalizer},
		},
		Type: corev1.SecretTypeOpaque, Immutable: new(true), Data: data,
	}
}

func (b *Backend) desiredJob(r Receipt) *batchv1.Job {
	pod := b.desiredPod(r)
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.Namespace, Name: r.JobName, Labels: protectedLabels(r),
			Annotations: protectedAnnotations(r), Finalizers: []string{jobFinalizer},
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Secret", Name: r.AnchorName, UID: r.AnchorUID,
				Controller: new(true), BlockOwnerDeletion: new(true),
			}},
		},
		Spec: batchv1.JobSpec{
			Completions: new(int32(1)), Parallelism: new(int32(1)), BackoffLimit: new(int32(0)),
			ActiveDeadlineSeconds: new(int64(b.config.Limits.BuildTimeout.Seconds()) + 60),
			PodReplacementPolicy:  ptr.To(batchv1.Failed),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: protectedLabels(r), Annotations: protectedAnnotations(r),
					Finalizers: []string{podFinalizer}},
				Spec: pod,
			},
		},
	}
}

func (b *Backend) desiredPod(r Receipt) corev1.PodSpec {
	resources := corev1.ResourceList{
		corev1.ResourceCPU:              resource.MustParse(b.config.Limits.CPU),
		corev1.ResourceMemory:           resource.MustParse(b.config.Limits.Memory),
		corev1.ResourceEphemeralStorage: resource.MustParse("32Mi"),
	}
	pod := corev1.PodSpec{
		RestartPolicy: corev1.RestartPolicyNever, ServiceAccountName: "default",
		AutomountServiceAccountToken: new(false), EnableServiceLinks: new(false),
		ShareProcessNamespace: new(false), TerminationGracePeriodSeconds: new(int64(40)),
		DNSPolicy: corev1.DNSClusterFirst, SchedulerName: corev1.DefaultSchedulerName,
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: new(true), RunAsUser: new(int64(65532)), RunAsGroup: new(int64(65532)),
			FSGroup: new(int64(65532)), FSGroupChangePolicy: ptr.To(corev1.FSGroupChangeOnRootMismatch),
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Volumes: []corev1.Volume{
			{Name: "input", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
				SecretName: r.AnchorName, DefaultMode: new(int32(0440)),
				Items: []corev1.KeyToPath{{Key: manifestKey, Path: manifestKey}, {Key: archiveKey, Path: archiveKey}},
			}}},
			{Name: "workspace", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{
				SizeLimit: new(resource.MustParse("16Mi")),
			}}},
		},
		Containers: []corev1.Container{{
			Name: workerName, Image: b.config.WorkerImage, ImagePullPolicy: corev1.PullIfNotPresent,
			Command:   []string{"/orka-remediation-build-worker"},
			Args:      []string{"--bundle=/bundle", "--workspace=/workspace", "--termination=/dev/termination-log"},
			Resources: corev1.ResourceRequirements{Limits: resources, Requests: maps.Clone(resources)},
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: new(false), Privileged: new(false),
				ReadOnlyRootFilesystem: new(true),
				Capabilities:           &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			},
			VolumeMounts: []corev1.VolumeMount{
				{Name: "input", MountPath: "/bundle", ReadOnly: true},
				{Name: "workspace", MountPath: "/workspace"},
			},
			TerminationMessagePath: "/dev/termination-log", TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		}},
	}
	if b.config.TLS != nil {
		pod.Volumes = append(pod.Volumes, corev1.Volume{
			Name: "buildkit-ca", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
				SecretName: b.config.TLS.CASecretName, DefaultMode: new(int32(0440)),
				Items: []corev1.KeyToPath{{Key: caCertificateKey, Path: caCertificateKey}},
			}},
		})
		pod.Containers[0].VolumeMounts = append(pod.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name: "buildkit-ca", MountPath: "/buildkit-ca", ReadOnly: true,
		})
		pod.Volumes = append(pod.Volumes, corev1.Volume{
			Name: "builder-client", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
				SecretName: b.config.TLS.ClientSecretName, DefaultMode: new(int32(0440)),
				Items: []corev1.KeyToPath{
					{Key: corev1.TLSCertKey, Path: corev1.TLSCertKey},
					{Key: corev1.TLSPrivateKeyKey, Path: corev1.TLSPrivateKeyKey},
				},
			}},
		})
		pod.Containers[0].VolumeMounts = append(pod.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name: "builder-client", MountPath: "/builder-client", ReadOnly: true,
		})
	}
	if b.config.RegistrySecretName != "" {
		pod.Volumes = append(pod.Volumes, corev1.Volume{
			Name: "registry-auth", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
				SecretName: b.config.RegistrySecretName, DefaultMode: new(int32(0440)),
				Items: []corev1.KeyToPath{{Key: corev1.DockerConfigJsonKey, Path: registryConfigFile}},
			}},
		})
		pod.Containers[0].VolumeMounts = append(pod.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name: "registry-auth", MountPath: registryConfigDirectory, ReadOnly: true,
		})
	}
	return pod
}

func protectedMetadata(meta metav1.ObjectMeta, r Receipt) bool {
	for key, value := range protectedLabels(r) {
		if meta.Labels[key] != value {
			return false
		}
	}
	for key, value := range protectedAnnotations(r) {
		if meta.Annotations[key] != value {
			return false
		}
	}
	return meta.Namespace == r.Namespace
}

func (b *Backend) verifyAnchor(anchor *corev1.Secret, r Receipt, cleaning bool) (manifest, Input, error) {
	if anchor.UID == "" || anchor.ResourceVersion == "" || (r.AnchorUID != "" && anchor.UID != r.AnchorUID) ||
		anchor.Name != r.AnchorName || !protectedMetadata(anchor.ObjectMeta, r) ||
		anchor.Immutable == nil || !*anchor.Immutable || anchor.Type != corev1.SecretTypeOpaque ||
		len(anchor.OwnerReferences) != 0 || (!cleaning && (anchor.DeletionTimestamp != nil ||
		!slices.Contains(anchor.Finalizers, anchorFinalizer))) {
		return manifest{}, Input{}, failure(ErrIdentity, "build-input-anchor-identity-mismatch")
	}
	if state := anchor.Annotations[stateAnnotation]; state != preparedState && state != submittedState &&
		(!cleaning || state != cleanupState) {
		return manifest{}, Input{}, failure(ErrIdentity, "build-input-anchor-state-mismatch")
	}
	m, input, err := unpackBundle(anchor.Data)
	if err != nil {
		return m, input, err
	}
	if m.ConfigurationDigest != b.digest || m.Namespace != r.Namespace ||
		m.BuildKitAddress != b.config.BuildKitAddress || !reflect.DeepEqual(m.TLS, b.config.TLS) ||
		m.RegistrySecretName != b.config.RegistrySecretName ||
		m.Limits != b.config.Limits || input.RunID != r.RunID || input.OperationID != r.OperationID ||
		input.InputDigest != r.InputDigest {
		return m, input, failure(ErrIdentity, "build-input-anchor-configuration-mismatch")
	}
	_, policy, err := b.admit(input)
	if err != nil || !slices.Equal(policy.SourcePaths, m.SourcePaths) {
		return m, input, failure(ErrIdentity, "build-input-anchor-policy-mismatch")
	}
	return m, input, nil
}

func (b *Backend) verifyJob(job *batchv1.Job, r Receipt, cleaning bool) error {
	if job.UID == "" || job.ResourceVersion == "" || (r.JobUID != "" && job.UID != r.JobUID) || job.Name != r.JobName ||
		!protectedMetadata(job.ObjectMeta, r) ||
		(!cleaning && (job.DeletionTimestamp != nil || !slices.Contains(job.Finalizers, jobFinalizer))) {
		return failure(ErrIdentity, "build-job-identity-mismatch")
	}
	if !cleaning && (job.Status.Active > 1 || job.Status.Succeeded > 1 || job.Status.Failed > 1 ||
		(job.Status.Succeeded > 0 && job.Status.Failed > 0)) {
		return failure(ErrIdentity, "build-job-repeated-execution")
	}
	want := b.desiredJob(r)
	if !reflect.DeepEqual(job.OwnerReferences, want.OwnerReferences) {
		return failure(ErrIdentity, "build-job-owner-mismatch")
	}
	actual, expected := job.Spec.DeepCopy(), want.Spec.DeepCopy()
	if actual.Selector != nil {
		if len(actual.Selector.MatchExpressions) != 0 || len(actual.Selector.MatchLabels) != 1 ||
			actual.Selector.MatchLabels[batchv1.ControllerUidLabel] != string(job.UID) {
			return failure(ErrIdentity, "build-job-selector-mismatch")
		}
	}
	actual.Selector = nil
	if actual.ManualSelector != nil && !*actual.ManualSelector {
		actual.ManualSelector = nil
	}
	if actual.CompletionMode != nil && *actual.CompletionMode == batchv1.NonIndexedCompletion {
		actual.CompletionMode = nil
	}
	if actual.Suspend != nil && !*actual.Suspend {
		actual.Suspend = nil
	}
	if !protectedTemplate(actual.Template.ObjectMeta, r, job.UID) {
		return failure(ErrIdentity, "build-job-template-metadata-mismatch")
	}
	if !slices.Equal(actual.Template.Finalizers, expected.Template.Finalizers) {
		return failure(ErrIdentity, "build-job-pod-retention-mismatch")
	}
	actual.Template.ObjectMeta, expected.Template.ObjectMeta = metav1.ObjectMeta{}, metav1.ObjectMeta{}
	normalizePodDefaults(&actual.Template.Spec)
	normalizePodDefaults(&expected.Template.Spec)
	if !equality.Semantic.DeepEqual(actual, expected) {
		return failure(ErrIdentity, "build-job-template-mismatch")
	}
	return nil
}

func protectedTemplate(meta metav1.ObjectMeta, r Receipt, jobUID types.UID) bool {
	meta.Namespace = r.Namespace
	if !protectedMetadata(meta, r) {
		return false
	}
	for _, key := range []string{batchv1.ControllerUidLabel, "controller-uid"} {
		if value := meta.Labels[key]; value != "" && value != string(jobUID) {
			return false
		}
	}
	for _, key := range []string{batchv1.JobNameLabel, "job-name"} {
		if value := meta.Labels[key]; value != "" && value != r.JobName {
			return false
		}
	}
	return true
}

func normalizePodDefaults(pod *corev1.PodSpec) {
	if pod.DeprecatedServiceAccount == "default" {
		pod.DeprecatedServiceAccount = ""
	}
	if pod.PreemptionPolicy != nil && *pod.PreemptionPolicy == corev1.PreemptLowerPriority {
		pod.PreemptionPolicy = nil
	}
	if pod.Priority != nil && *pod.Priority == 0 {
		pod.Priority = nil
	}
}

func (b *Backend) namespace(ctx context.Context, expected types.UID) (types.UID, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	namespace, err := b.config.APIReader.CoreV1().Namespaces().Get(ctx, b.config.Namespace, metav1.GetOptions{})
	if err != nil {
		return "", apiFailure(ctx, err, "build-namespace-unavailable")
	}
	if namespace.UID == "" || namespace.ResourceVersion == "" || (expected != "" && namespace.UID != expected) ||
		namespace.DeletionTimestamp != nil || namespace.Status.Phase == corev1.NamespaceTerminating {
		return "", failure(ErrIdentity, "build-namespace-identity-mismatch")
	}
	return namespace.UID, nil
}

func apiFailure(ctx context.Context, err error, code string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if apierrors.IsNotFound(err) {
		return failure(ErrLost, code)
	}
	if apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err) {
		return failure(ErrIdentity, code)
	}
	return failure(ErrAPI, code)
}
