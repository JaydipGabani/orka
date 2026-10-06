package controllerlab

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ktesting "k8s.io/client-go/testing"
)

type publishingBehavior struct {
	crossHTTP, crossHTTPS                                  bool
	omitHTTP, omitHTTPS, omitFinal                         bool
	omitClusterHTTP                                        bool
	credentialAttack                                       bool
	omitInitialCredential, omitFinalCredential             bool
	credentialOnlyNamespaceA                               bool
	attackMissingHeader, attackWrongHeader, attackPlainTLS bool
	missingHeader, wrongHeader, plainTLS                   bool
	denyAll, unreachable                                   bool
	retries                                                int
}

func (b publishingBehavior) skipCredentialAttack(index int, final bool) bool {
	return !b.credentialAttack || !final && b.omitInitialCredential || final && b.omitFinalCredential ||
		index == 1 && b.credentialOnlyNamespaceA
}

type publishingHistory struct {
	records []HTTPObservation
	seen    map[string]bool
}

type syntheticObserverConfig struct {
	Channels []struct {
		Channel string `json:"channel"`
		SHA256  string `json:"sha256"`
	} `json:"channelCanaries"`
	Markers []struct {
		ID     string `json:"id"`
		Value  string `json:"value"`
		SHA256 string `json:"sha256"`
	} `json:"markers"`
}

type publishingObserver struct {
	mu        sync.Mutex
	lab       *testLab
	behaviors map[Role]publishingBehavior
	histories map[string]*publishingHistory
	mutate    func(*Observation)
	calls     atomic.Int32
}

func (o *publishingObserver) Snapshot(_ context.Context, target ObserverTarget) (Observation, error) {
	o.calls.Add(1)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lab.journal.mu.Lock()
	var state State
	for _, s := range o.lab.journal.states {
		if s.OperationDigest == target.OperationDigest {
			state = cloneState(s)
		}
	}
	o.lab.journal.mu.Unlock()
	behavior := o.behaviors[state.Role]
	if behavior.unreachable {
		return Observation{}, errors.New("synthetic observer unreachable")
	}
	history := o.histories[state.OperationDigest]
	if history == nil {
		history = &publishingHistory{records: []HTTPObservation{}, seen: map[string]bool{}}
		o.histories[state.OperationDigest] = history
	}
	for _, final := range []bool{false, true} {
		for index, fixture := range fixtureObjects(state, final) {
			value, err := o.lab.custom.Tracker().Get(fixture.Resource, fixture.Namespace, fixture.Name)
			if err != nil || behavior.denyAll || final && behavior.omitFinal {
				continue
			}
			for _, source := range sourceObjects(state) {
				if source.Resource != cloudEventSources && source.Resource != clusterEventSources {
					continue
				}
				raw, err := o.lab.custom.Tracker().Get(source.Resource, source.Namespace, source.Name)
				if err != nil {
					continue
				}
				eventSource := raw.(*unstructured.Unstructured)
				identity := string(value.(*unstructured.Unstructured).GetUID()) + "/" + string(eventSource.GetUID())
				if history.seen[identity] {
					continue
				}
				record, emit, err := o.publish(state, behavior, eventSource, index, final)
				if err != nil {
					return Observation{}, err
				}
				if !emit {
					continue
				}
				history.seen[identity] = true
				for range 1 + behavior.retries {
					history.records = append(history.records, record)
				}
			}
		}
	}
	result := Observation{
		SchemaVersion: "v1", RunID: target.OperationDigest, Generation: 1,
		HTTP: append([]HTTPObservation{}, history.records...), RESP: []RESPObservation{},
	}
	if o.mutate != nil {
		o.mutate(&result)
	}
	return result, nil
}

// The synthetic interpreter consumes the compiled CRs and Secret references.
// Behavior switches model namespace filtering, never a patch name or exit code.
func (o *publishingObserver) publish(s State, b publishingBehavior, source *unstructured.Unstructured, index int, final bool) (HTTPObservation, bool, error) {
	u, encrypted, err := syntheticPublishingEndpoint(s, source)
	if err != nil {
		return HTTPObservation{}, false, err
	}
	if b.omitHTTPS && encrypted || b.omitHTTP && !encrypted ||
		b.omitClusterHTTP && source.GetNamespace() == "" {
		return HTTPObservation{}, false, nil
	}
	authKind, _, _ := unstructured.NestedString(source.Object, "spec", "authenticationRef", "kind")
	credentialAttack := authKind == "ClusterTriggerAuthentication"
	if credentialAttack && b.skipCredentialAttack(index, final) {
		return HTTPObservation{}, false, nil
	}
	cross := b.crossHTTP
	if encrypted {
		cross = b.crossHTTPS
	}
	if source.GetNamespace() != "" && source.GetNamespace() != s.Namespaces[index] && !cross {
		return HTTPObservation{}, false, nil
	}
	clusterName, _, err := unstructured.NestedString(source.Object, "spec", "clusterName")
	if err != nil || clusterName != "orka-controllerlab" {
		return HTTPObservation{}, false, errors.New("compiled event identity changed")
	}
	cfg, err := o.fixtureConfig(s)
	if err != nil {
		return HTTPObservation{}, false, err
	}
	record := observedEvent(s, index, final, index)
	record.Route, record.TLSDataIngress = u.Path, encrypted && !b.plainTLS
	record.CloudEvents[0].Subject.MarkerIDs = []string{}
	for _, marker := range cfg.Markers {
		if marker.Value == subject(s, index, final) || marker.SHA256 == record.CloudEvents[0].Subject.SHA256 {
			record.CloudEvents[0].Subject.MarkerIDs = append(record.CloudEvents[0].Subject.MarkerIDs, marker.ID)
		}
	}
	if encrypted {
		matched, err := o.syntheticKeyMatches(s, source, u.Path, cfg)
		if err != nil {
			return HTTPObservation{}, false, err
		}
		record.SyntheticCredentialObserved = matched && !b.missingHeader && !b.wrongHeader
		if credentialAttack {
			record.SyntheticCredentialObserved = record.SyntheticCredentialObserved && !b.attackMissingHeader && !b.attackWrongHeader
			record.TLSDataIngress = record.TLSDataIngress && !b.attackPlainTLS
		}
	}
	return record, true, nil
}

func syntheticPublishingEndpoint(s State, source *unstructured.Unstructured) (*url.URL, bool, error) {
	endpoint, _, _ := unstructured.NestedString(source.Object, "spec", "destination", "http", "uri")
	encrypted := false
	if endpoint == "" {
		endpoint, _, _ = unstructured.NestedString(source.Object, "spec", "destination", "azureEventGridTopic", "endpoint")
		encrypted = true
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Path == "" || encrypted && (u.Scheme != "https" ||
		u.Host != net.JoinHostPort(observerDNS(s), strconv.Itoa(int(observerTLSPort)))) ||
		!encrypted && (u.Scheme != "http" || u.Host != net.JoinHostPort(s.ObserverPodIP, strconv.Itoa(int(observerWorkerPort)))) {
		return nil, false, errors.New("compiled publishing destination is not the fixture")
	}
	return u, encrypted, nil
}

func (o *publishingObserver) syntheticKeyMatches(s State, source *unstructured.Unstructured, route string, cfg syntheticObserverConfig) (bool, error) {
	name, _, _ := unstructured.NestedString(source.Object, "spec", "authenticationRef", "name")
	kind, _, _ := unstructured.NestedString(source.Object, "spec", "authenticationRef", "kind")
	gvr, authNamespace, secretNamespace := triggerAuthentications, source.GetNamespace(), source.GetNamespace()
	if kind == "ClusterTriggerAuthentication" {
		gvr, authNamespace, secretNamespace = clusterAuthentications, "", s.Namespaces[0]
	} else if kind != "TriggerAuthentication" {
		return false, errors.New("compiled authentication kind is not supported")
	}
	raw, err := o.lab.custom.Tracker().Get(gvr, authNamespace, name)
	if err != nil {
		return false, errors.New("compiled authentication object missing")
	}
	auth := raw.(*unstructured.Unstructured)
	if !reflectAuthSpec(auth) {
		return false, errors.New("compiled authentication tuple changed")
	}
	rawSecret, err := o.lab.kube.Tracker().Get(secrets, secretNamespace, canaryName)
	if err != nil {
		return false, errors.New("synthetic Secret missing")
	}
	for _, pin := range cfg.Channels {
		if route == "/events/"+pin.Channel {
			return pin.SHA256 == bytesDigest(rawSecret.(*corev1.Secret).Data["key"]), nil
		}
	}
	return false, errors.New("synthetic channel canary missing")
}

func (o *publishingObserver) fixtureConfig(s State) (syntheticObserverConfig, error) {
	raw, err := o.lab.kube.Tracker().Get(configMaps, s.ObserverNamespace, "observer-config")
	if err != nil {
		return syntheticObserverConfig{}, errors.New("synthetic observer configuration missing")
	}
	var cfg syntheticObserverConfig
	if json.Unmarshal([]byte(raw.(*corev1.ConfigMap).Data["config.json"]), &cfg) != nil {
		return syntheticObserverConfig{}, errors.New("synthetic observer configuration invalid")
	}
	return cfg, nil
}

func reflectAuthSpec(auth *unstructured.Unstructured) bool {
	spec, found, err := unstructured.NestedMap(auth.Object, "spec")
	return err == nil && found && digest(spec) == digest(publishingAuthSpec())
}

type publishingLab struct {
	*testLab
	observer *publishingObserver
}

func newPublishingLab(t *testing.T) *publishingLab {
	t.Helper()
	base := newTestLab(t)
	base.config.EnableEventPublishing = true
	base.config.Template.Source.Commit = kedaPublishingCommit
	for i := range base.config.Bindings {
		base.config.Bindings[i].Source = base.config.Template.Source
	}
	l := &publishingLab{testLab: base}
	l.observer = &publishingObserver{
		lab: base, histories: map[string]*publishingHistory{},
		behaviors: map[Role]publishingBehavior{
			Original: {crossHTTP: true, crossHTTPS: true, credentialAttack: true},
			Control:  {crossHTTP: true, crossHTTPS: true, credentialAttack: true},
		},
	}
	installSyntheticDeploymentController(t, base)
	l.restart(t)
	return l
}

func (l *publishingLab) restart(t *testing.T) {
	t.Helper()
	adapter, err := New(l.config, Clients{Kubernetes: l.kube, CustomResources: l.custom, Observer: l.observer}, l.journal.hooks())
	require.NoError(t, err)
	adapter.now = func() time.Time {
		l.clockMu.Lock()
		defer l.clockMu.Unlock()
		return l.clock
	}
	l.adapter = adapter
}

func (l *publishingLab) request(role Role) Request {
	r := l.testLab.request(role)
	r.Plan.Capability = KEDAEventPublishing
	r.Plan.Expected = []SemanticOutcome{NamespacedEventScope, NamespacedEventCredentialScope, UndelegatedClusterCredentialScope}
	return r
}

func installSyntheticDeploymentController(t *testing.T, l *testLab) {
	t.Helper()
	replicaSets := schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}
	l.kube.PrependReactor("create", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
		d := action.(ktesting.CreateAction).GetObject().(*appsv1.Deployment).DeepCopy()
		d.UID, d.Generation = types.UID("deployment-"+d.Namespace), 1
		d.ResourceVersion = "1"
		d.Status = appsv1.DeploymentStatus{ObservedGeneration: 1, Replicas: 1, ReadyReplicas: 1, AvailableReplicas: 1}
		rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
			Name: "synthetic-controller-rs", Namespace: d.Namespace, UID: types.UID("rs-" + d.Namespace),
			ResourceVersion: "1",
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: d.Name, UID: d.UID, Controller: new(true)}},
		}}
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: "synthetic-controller-pod", Namespace: d.Namespace, UID: types.UID("pod-" + d.Namespace),
			ResourceVersion: "1",
			Labels:          d.Spec.Template.Labels,
			OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: rs.Name, UID: rs.UID, Controller: new(true)}},
		}, Spec: *d.Spec.Template.Spec.DeepCopy(), Status: corev1.PodStatus{
			Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{{
				Name: controllerName, Ready: true, ImageID: d.Spec.Template.Spec.Containers[0].Image,
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
			}},
		}}
		require.NoError(t, l.kube.Tracker().Create(deployments, d, d.Namespace))
		require.NoError(t, l.kube.Tracker().Create(replicaSets, rs, rs.Namespace))
		require.NoError(t, l.kube.Tracker().Create(pods, pod, pod.Namespace))
		return true, d, nil
	})
	l.kube.PrependReactor("delete", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
		deletion := action.(ktesting.DeleteAction)
		raw, err := l.kube.Tracker().Get(deployments, deletion.GetNamespace(), deletion.GetName())
		if apierrors.IsNotFound(err) {
			return false, nil, nil
		}
		require.NoError(t, err)
		d := raw.(*appsv1.Deployment)
		if deletion.GetDeleteOptions().Preconditions == nil ||
			deletion.GetDeleteOptions().Preconditions.UID == nil || *deletion.GetDeleteOptions().Preconditions.UID != d.UID ||
			deletion.GetDeleteOptions().Preconditions.ResourceVersion == nil ||
			*deletion.GetDeleteOptions().Preconditions.ResourceVersion != d.ResourceVersion {
			return false, nil, nil
		}
		for _, child := range []struct {
			gvr  schema.GroupVersionResource
			name string
		}{{pods, "synthetic-controller-pod"}, {replicaSets, "synthetic-controller-rs"}} {
			err := l.kube.Tracker().Delete(child.gvr, d.Namespace, child.name)
			if err != nil && !apierrors.IsNotFound(err) {
				require.NoError(t, err)
			}
		}
		return false, nil, nil
	})
}
