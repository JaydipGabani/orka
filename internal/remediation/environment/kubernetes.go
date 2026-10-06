package environment

import (
	"context"
	"errors"
	"net"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	namespaceKind       = "Namespace"
	networkPolicyKind   = "NetworkPolicy"
	podKind             = "Pod"
	managedLabel        = "remediation.orka.ai/environment"
	runLabel            = "remediation.orka.ai/run"
	operationLabel      = "remediation.orka.ai/operation"
	configLabel         = "remediation.orka.ai/config"
	operationAnnotation = "remediation.orka.ai/operation-digest"
)

// Intent computes stable names without creating resources. UID fields remain
// unset until Start's API-server acknowledgement. Persist this intent/request
// before Start; an expected UID, once known, is never weakened to a name lookup.
func (a *Adapter) Intent(request Request) (Receipt, error) {
	if err := validateIsolationConfig(a.config); err != nil {
		return Receipt{}, err
	}
	if len(request.Plan.Namespaces) > modelNamespaceLimit(a.config) {
		return Receipt{}, failure(NeedsAdapter, "isolation-namespace-budget")
	}
	if err := a.validateFrozen(request.Plan); err != nil {
		return Receipt{}, err
	}
	if !idPattern.MatchString(request.RunID) || !idPattern.MatchString(request.OperationID) ||
		!immutableImage(request.Subject.Image) || !validRole(request.Subject.Role) {
		return Receipt{}, failure(NeedsAdapter, "invalid-operation-request")
	}
	plan, err := a.FreezePlan(request.Plan)
	if err != nil {
		return Receipt{}, err
	}
	request.Plan = plan
	identity := request
	identity.RequireExisting, identity.Expected = false, nil
	policy := a.operationPolicy()
	configDigest := operationPolicyDigest(policy)
	sum := jsonDigest(struct {
		Domain, Config string
		Request        Request
	}{"orka.remediation.environment.operation.v1", configDigest, identity})
	now := a.now().UTC()
	receipt := Receipt{
		Version: Version, ConfigDigest: configDigest, Policy: policy, OperationDigest: sum, Request: identity,
		StartedAt: now, Deadline: now.Add(a.config.Limits.OperationTimeout),
	}
	for _, ns := range plan.Namespaces {
		name := namespaceName(receipt, ns.Alias)
		receipt.Objects = append(receipt.Objects,
			ObjectIdentity{Kind: namespaceKind, Name: name},
			ObjectIdentity{Kind: networkPolicyKind, Namespace: name, Name: "observer-only"},
		)
	}
	if policy.ProbeImage != "" {
		receipt.Objects = append(receipt.Objects, ObjectIdentity{
			Kind: namespaceKind, Name: isolationControlName(receipt),
		})
	}
	for _, workload := range plan.Resources {
		receipt.Objects = append(receipt.Objects, ObjectIdentity{
			Kind: podKind, Namespace: namespaceName(receipt, workload.Namespace),
			Name: "subject-" + shortDigest([]byte(workload.ID)), Image: request.Subject.Image,
		})
	}
	for _, expected := range request.Expected {
		if expected.UID == "" || !slices.ContainsFunc(receipt.Objects, func(object ObjectIdentity) bool {
			object.UID = expected.UID
			return object == expected
		}) {
			return Receipt{}, failure(Unknown, "invalid-expected-object-identity")
		}
	}
	return receipt, nil
}

func shortDigest(data []byte) string { return strings.TrimPrefix(digest(data), "sha256:")[:24] }

func namespaceName(receipt Receipt, alias string) string {
	return "rem-" + shortDigest([]byte(receipt.Request.RunID))[:12] + "-" +
		shortDigest([]byte(receipt.OperationDigest + ":" + alias))[:24]
}

func ownerLabels(receipt Receipt) map[string]string {
	return map[string]string{
		managedLabel: "v1", runLabel: shortDigest([]byte(receipt.Request.RunID)),
		operationLabel: shortDigest([]byte(receipt.OperationDigest)), configLabel: shortDigest([]byte(receipt.ConfigDigest)),
	}
}

func objectMetadata(receipt Receipt, identity ObjectIdentity) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: identity.Name, Namespace: identity.Namespace, Labels: ownerLabels(receipt),
		Annotations: map[string]string{operationAnnotation: receipt.OperationDigest},
	}
}

func owned(metadata metav1.Object, receipt Receipt, identity ObjectIdentity) bool {
	if metadata.GetUID() == "" || (identity.UID != "" && metadata.GetUID() != identity.UID) ||
		metadata.GetName() != identity.Name || metadata.GetNamespace() != identity.Namespace ||
		metadata.GetAnnotations()[operationAnnotation] != receipt.OperationDigest ||
		len(metadata.GetOwnerReferences()) != 0 {
		return false
	}
	for key, value := range ownerLabels(receipt) {
		if metadata.GetLabels()[key] != value {
			return false
		}
	}
	return true
}

func (a *Adapter) Start(ctx context.Context, request Request) (Receipt, error) {
	if request.RequireExisting {
		return a.recoverRequest(ctx, request)
	}
	intent, err := a.Intent(request)
	if err != nil {
		return Receipt{}, err
	}
	if a.kube == nil || a.config.Kubernetes == nil {
		return Receipt{}, failure(NeedsAdapter, "dedicated-kubernetes-adapter-required")
	}
	state, unlock, err := a.lockRun(ctx, request.RunID, request.Plan.Bind, true)
	if err != nil {
		return Receipt{}, err
	}
	defer unlock()
	if err := a.validateSubject(request, state); err != nil {
		return Receipt{}, err
	}
	if existing, err := findRequestRecord(state, request); err != nil {
		return Receipt{}, err
	} else if existing != nil && existing.Receipt.OperationDigest != intent.OperationDigest {
		return a.recoverRecord(ctx, request, existing, state)
	}
	record := state.Operations[intent.OperationDigest]
	if record == nil {
		if err := a.admitOperation(state, intent.OperationDigest); err != nil {
			return Receipt{}, err
		}
		record = &operationRecord{Receipt: intent, Observation: Observation{Phase: Starting}}
		state.Operations[intent.OperationDigest] = record
		if err := a.saveRun(request.RunID, state); err != nil {
			return Receipt{}, err
		}
	} else if record.Observation.CleanupComplete {
		return record.Receipt, nil
	} else if record.Observation.Phase == Cleaning {
		return record.Receipt, failure(Unknown, "operation-cleanup-in-progress")
	}
	if err := bindExpectedObjects(&record.Receipt, request.Expected); err != nil {
		return record.Receipt, err
	}
	if record.Receipt.Policy.ProbeImage != "" {
		return a.startIsolated(ctx, record, state)
	}
	globalUnlock, err := a.lock(ctx, "namespace-allocation")
	if err != nil {
		return record.Receipt, err
	}
	defer globalUnlock()
	bounded, cancel := context.WithDeadline(ctx, record.Receipt.Deadline)
	defer cancel()
	if err := a.checkCapacity(bounded, record.Receipt); err != nil {
		if bounded.Err() != nil && ctx.Err() == nil {
			a.settleFailedStart(ctx, record, state)
		}
		return record.Receipt, err
	}
	for i := range record.Receipt.Objects {
		if err := a.ensureObject(bounded, &record.Receipt, i, request.RequireExisting); err != nil {
			if persistErr := a.saveRun(request.RunID, state); persistErr != nil {
				return record.Receipt, failure(Unknown, "resource-acknowledgement-not-persisted")
			}
			if bounded.Err() != nil && ctx.Err() == nil {
				a.settleFailedStart(ctx, record, state)
			}
			return record.Receipt, err
		}
		if err := a.saveRun(request.RunID, state); err != nil {
			return record.Receipt, failure(Unknown, "resource-acknowledgement-not-persisted")
		}
	}
	record.Observation.Phase = Running
	if err := a.saveRun(request.RunID, state); err != nil {
		return record.Receipt, err
	}
	return record.Receipt, nil
}

func (a *Adapter) settleFailedStart(ctx context.Context, record *operationRecord, state *runJournal) {
	record.Observation.Phase = Cleaning
	record.Observation.Failure = &Error{Kind: Infrastructure, Code: "start-timed-out-or-cancelled"}
	if a.saveRun(record.Receipt.Request.RunID, state) != nil {
		return
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	_ = a.cleanup(bounded, record, state)
}

func (a *Adapter) checkCapacity(ctx context.Context, receipt Receipt) error {
	maximum := a.config.Limits.MaxActiveRuns * a.config.Limits.MaxNamespaces
	list, err := a.kube.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: managedLabel + "=v1", Limit: int64(maximum + 1),
	})
	if err != nil {
		return failure(Infrastructure, "namespace-capacity-unavailable")
	}
	if list.Continue != "" || len(list.Items) > maximum {
		return failure(Infrastructure, "namespace-capacity-limit")
	}
	runs := map[string]bool{}
	for _, ns := range list.Items {
		run := ns.Labels[runLabel]
		if run == "" {
			return failure(Unknown, "namespace-ownership-ambiguous")
		}
		if run == ownerLabels(receipt)[runLabel] {
			if ns.Labels[operationLabel] != ownerLabels(receipt)[operationLabel] ||
				!slices.ContainsFunc(receipt.Objects, func(object ObjectIdentity) bool {
					return object.Kind == namespaceKind && object.Name == ns.Name
				}) {
				return failure(Unknown, "previous-namespace-cleanup-unsettled")
			}
		}
		runs[run] = true
	}
	if !runs[ownerLabels(receipt)[runLabel]] && len(runs) >= a.config.Limits.MaxActiveRuns {
		return failure(Infrastructure, "active-run-capacity")
	}
	return nil
}

func (a *Adapter) ensureObject(ctx context.Context, receipt *Receipt, index int, requireExisting bool) error {
	identity := &receipt.Objects[index]
	switch identity.Kind {
	case namespaceKind:
		return a.ensureNamespace(ctx, receipt, identity, requireExisting)
	case networkPolicyKind:
		return a.ensureNetworkPolicy(ctx, receipt, identity, requireExisting)
	case podKind:
		return a.ensurePod(ctx, receipt, identity, requireExisting)
	default:
		return failure(NeedsAdapter, "unknown-resource-kind")
	}
}

func (a *Adapter) ensureNamespace(ctx context.Context, receipt *Receipt, identity *ObjectIdentity, requireExisting bool) error {
	current, err := a.kube.CoreV1().Namespaces().Get(ctx, identity.Name, metav1.GetOptions{})
	if err == nil && identity.UID == "" && receipt.Policy.ProbeImage != "" {
		return failure(Unknown, "namespace-create-acknowledgement-required")
	}
	if apierrors.IsNotFound(err) {
		if requireExisting || identity.UID != "" {
			return failure(Unknown, "existing-namespace-not-found")
		}
		namespace := &corev1.Namespace{ObjectMeta: objectMetadata(*receipt, *identity)}
		namespace.Labels["pod-security.kubernetes.io/enforce"] = restrictedPolicy
		namespace.Labels["pod-security.kubernetes.io/enforce-version"] = "latest"
		current, err = a.kube.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) && receipt.Policy.ProbeImage == "" {
			current, err = a.kube.CoreV1().Namespaces().Get(ctx, identity.Name, metav1.GetOptions{})
		}
	}
	if err != nil {
		return failure(Infrastructure, "namespace-operation-failed")
	}
	if !owned(current, *receipt, *identity) {
		return failure(Unknown, "namespace-identity-mismatch")
	}
	acknowledged := identity.UID != ""
	identity.UID = current.UID
	if current.DeletionTimestamp != nil || current.Labels["pod-security.kubernetes.io/enforce"] != restrictedPolicy ||
		current.Labels["pod-security.kubernetes.io/enforce-version"] != "latest" {
		return failure(Unknown, "namespace-identity-mismatch")
	}
	if requireExisting && !acknowledged {
		if current.CreationTimestamp.IsZero() {
			return failure(Unknown, "namespace-creation-time-unavailable")
		}
		if current.CreationTimestamp.Time.Before(receipt.StartedAt) {
			receipt.StartedAt = current.CreationTimestamp.Time
			receipt.Deadline = receipt.StartedAt.Add(a.config.Limits.OperationTimeout)
		}
	}
	identity.UID = current.UID
	return nil
}

func (a *Adapter) ensureNetworkPolicy(ctx context.Context, receipt *Receipt, identity *ObjectIdentity, requireExisting bool) error {
	desired := a.networkPolicy(*receipt, *identity)
	api := a.kube.NetworkingV1().NetworkPolicies(identity.Namespace)
	current, err := api.Get(ctx, identity.Name, metav1.GetOptions{})
	if err == nil && identity.UID == "" && receipt.Policy.ProbeImage != "" {
		return failure(Unknown, "policy-create-acknowledgement-required")
	}
	if apierrors.IsNotFound(err) {
		if requireExisting || identity.UID != "" {
			return failure(Unknown, "existing-network-policy-not-found")
		}
		current, err = api.Create(ctx, desired, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) && receipt.Policy.ProbeImage == "" {
			current, err = api.Get(ctx, identity.Name, metav1.GetOptions{})
		}
	}
	if err != nil {
		return failure(Infrastructure, "network-policy-operation-failed")
	}
	if !owned(current, *receipt, *identity) {
		return failure(Unknown, "network-policy-identity-mismatch")
	}
	identity.UID = current.UID
	if current.DeletionTimestamp != nil || !sameJSON(current.Spec, desired.Spec) {
		return failure(Unknown, "network-policy-identity-mismatch")
	}
	identity.UID = current.UID
	return nil
}

func (a *Adapter) ensurePod(ctx context.Context, receipt *Receipt, identity *ObjectIdentity, requireExisting bool) error {
	if err := a.verifyIsolationBindings(ctx, *receipt); err != nil {
		return err
	}
	desired := a.pod(*receipt, *identity)
	api := a.kube.CoreV1().Pods(identity.Namespace)
	current, err := api.Get(ctx, identity.Name, metav1.GetOptions{})
	if err == nil && identity.UID == "" && receipt.Policy.ProbeImage != "" {
		return failure(Unknown, "workload-create-acknowledgement-required")
	}
	if apierrors.IsNotFound(err) {
		if requireExisting || identity.UID != "" {
			return failure(Unknown, "existing-workload-not-found")
		}
		current, err = api.Create(ctx, desired, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) && receipt.Policy.ProbeImage == "" {
			current, err = api.Get(ctx, identity.Name, metav1.GetOptions{})
		}
	}
	if err != nil {
		return failure(Infrastructure, "workload-operation-failed")
	}
	if !owned(current, *receipt, *identity) {
		return failure(Unknown, "workload-identity-mismatch")
	}
	identity.UID = current.UID
	if current.DeletionTimestamp != nil || !samePodSpec(current.Spec, desired.Spec) {
		return failure(Unknown, "workload-identity-mismatch")
	}
	if receipt.Policy.ProbeImage != "" && !sameJSON(current.Labels, desired.Labels) {
		return failure(Unknown, "workload-isolation-selector-mismatch")
	}
	identity.UID = current.UID
	return nil
}

func (a *Adapter) networkPolicy(receipt Receipt, identity ObjectIdentity) *networkingv1.NetworkPolicy {
	peers := make([]networkingv1.NetworkPolicyPeer, 0, len(a.config.Kubernetes.ObserverCIDRs))
	for _, cidr := range a.config.Kubernetes.ObserverCIDRs {
		peers = append(peers, networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: cidr}})
	}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: objectMetadata(receipt, identity),
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{{From: peers}},
		},
	}
}

func (a *Adapter) pod(receipt Receipt, identity ObjectIdentity) *corev1.Pod {
	var port int32
	var id string
	for _, r := range receipt.Request.Plan.Resources {
		if "subject-"+shortDigest([]byte(r.ID)) == identity.Name {
			port, id = r.HTTP.Port, r.ID
		}
	}
	yes, no := true, false
	uid, gid, grace := int64(65532), int64(65532), int64(1)
	deadline := int64(a.config.Limits.OperationTimeout / time.Second)
	limits := corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse(a.config.Limits.PodCPU),
		corev1.ResourceMemory: resource.MustParse(a.config.Limits.PodMemory),
	}
	return &corev1.Pod{
		ObjectMeta: objectMetadata(receipt, identity),
		Spec: corev1.PodSpec{
			NodeName:      isolationNodeName(receipt, identity.Namespace),
			RestartPolicy: corev1.RestartPolicyNever, ActiveDeadlineSeconds: &deadline,
			AutomountServiceAccountToken: &no, EnableServiceLinks: &no, TerminationGracePeriodSeconds: &grace,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: &yes, RunAsUser: &uid, RunAsGroup: &gid,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name: "subject", Image: identity.Image, ImagePullPolicy: corev1.PullAlways,
				Ports:     []corev1.ContainerPort{{Name: "http", ContainerPort: port, Protocol: corev1.ProtocolTCP}},
				Env:       []corev1.EnvVar{{Name: "ORKA_REMEDIATION_SYNTHETIC", Value: a.synthetic(receipt, id)}},
				Resources: corev1.ResourceRequirements{Limits: limits, Requests: limits.DeepCopy()},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes,
					Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
			}},
		},
	}
}

func (a *Adapter) synthetic(receipt Receipt, resourceID string) string {
	return "synthetic-" + shortDigest([]byte(receipt.Policy.SyntheticScope+":"+receipt.OperationDigest+":"+resourceID))
}

func samePodSpec(actual, desired corev1.PodSpec) bool {
	actual = *actual.DeepCopy()
	if desired.NodeName != "" && actual.NodeName != desired.NodeName {
		return false
	}
	// Normalize only API-server/kubelet defaults and scheduling output. Unknown
	// admission changes (sidecars, volumes, credentials, commands) remain unequal.
	if (actual.ServiceAccountName != "" && actual.ServiceAccountName != "default") ||
		(actual.DeprecatedServiceAccount != "" && actual.DeprecatedServiceAccount != "default") ||
		(actual.SchedulerName != "" && actual.SchedulerName != "default-scheduler") ||
		(actual.DNSPolicy != "" && actual.DNSPolicy != corev1.DNSClusterFirst) ||
		(actual.Priority != nil && *actual.Priority != 0) ||
		(actual.PreemptionPolicy != nil && *actual.PreemptionPolicy != corev1.PreemptLowerPriority) {
		return false
	}
	for _, tolerance := range actual.Tolerations {
		if (tolerance.Key != "node.kubernetes.io/not-ready" && tolerance.Key != "node.kubernetes.io/unreachable") ||
			tolerance.Operator != corev1.TolerationOpExists || tolerance.Value != "" ||
			tolerance.Effect != corev1.TaintEffectNoExecute || tolerance.TolerationSeconds == nil ||
			*tolerance.TolerationSeconds != 300 {
			return false
		}
	}
	if desired.NodeName == "" {
		actual.NodeName = ""
	}
	actual.ServiceAccountName, actual.DeprecatedServiceAccount = "", ""
	actual.SchedulerName, actual.DNSPolicy = "", ""
	actual.Priority, actual.PreemptionPolicy = nil, nil
	actual.Tolerations = nil
	for i := range actual.Containers {
		if (actual.Containers[i].TerminationMessagePath != "" && actual.Containers[i].TerminationMessagePath != "/dev/termination-log") ||
			(actual.Containers[i].TerminationMessagePolicy != "" && actual.Containers[i].TerminationMessagePolicy != corev1.TerminationMessageReadFile) {
			return false
		}
		actual.Containers[i].TerminationMessagePath = ""
		actual.Containers[i].TerminationMessagePolicy = ""
	}
	return equality.Semantic.DeepEqual(actual, desired)
}

func readyPod(pod *corev1.Pod, image string) bool {
	if pod.Status.Phase != corev1.PodRunning || len(pod.Status.ContainerStatuses) != 1 {
		return false
	}
	status := pod.Status.ContainerStatuses[0]
	_, wanted, _ := strings.Cut(image, "@")
	ip := net.ParseIP(pod.Status.PodIP)
	return status.Name == "subject" && status.Ready && status.State.Running != nil &&
		status.RestartCount == 0 && status.ImageID != "" && status.ContainerID != "" &&
		(strings.HasSuffix(status.ImageID, "@"+wanted) || status.ImageID == wanted) &&
		ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
}

func podURL(pod *corev1.Pod, port int32, path string) string {
	return "http://" + net.JoinHostPort(pod.Status.PodIP, strconv.FormatInt(int64(port), 10)) + path
}

func (a *Adapter) validateReceipt(receipt Receipt) error {
	frozen, err := a.forReceipt(receipt)
	if err != nil {
		return err
	}
	intent, err := frozen.Intent(receipt.Request)
	if err != nil {
		return err
	}
	if receipt.Version != Version || receipt.ConfigDigest != intent.ConfigDigest ||
		receipt.OperationDigest != intent.OperationDigest || len(receipt.Objects) != len(intent.Objects) ||
		receipt.StartedAt.IsZero() || !receipt.Deadline.Equal(receipt.StartedAt.Add(receipt.Policy.Limits.OperationTimeout)) {
		return failure(Unknown, "receipt-binding-mismatch")
	}
	for i, object := range receipt.Objects {
		expected := intent.Objects[i]
		expected.UID = object.UID
		if expected != object {
			return failure(Unknown, "receipt-object-mismatch")
		}
	}
	return validateIsolationReceipt(receipt)
}

func (a *Adapter) recordForReceipt(state *runJournal, receipt Receipt) (*operationRecord, error) {
	record := state.Operations[receipt.OperationDigest]
	if record == nil {
		if len(state.Operations)+len(state.Builds) >= 128 {
			return nil, failure(Unknown, "recovery-journal-limit")
		}
		record = &operationRecord{Receipt: receipt, Observation: Observation{Phase: Starting}}
		state.Operations[receipt.OperationDigest] = record
	}
	if a.validateReceipt(record.Receipt) != nil ||
		record.Receipt.OperationDigest != receipt.OperationDigest ||
		!reflect.DeepEqual(record.Receipt.Request, receipt.Request) {
		return nil, failure(Unknown, "durable-operation-not-found")
	}
	for i, object := range receipt.Objects {
		if object.UID != "" && object.UID != record.Receipt.Objects[i].UID {
			return nil, failure(Unknown, "receipt-uid-mismatch")
		}
	}
	if err := compareIsolationReceipts(receipt, record.Receipt); err != nil {
		return nil, err
	}
	return record, nil
}

func safeError(err error) *Error {
	if typed, ok := errors.AsType[*Error](err); ok {
		return typed
	}
	return &Error{Kind: Infrastructure, Code: "operation-failed"}
}

func uidPreconditions(uid types.UID) metav1.DeleteOptions {
	zero := int64(0)
	return metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}, GracePeriodSeconds: &zero}
}
