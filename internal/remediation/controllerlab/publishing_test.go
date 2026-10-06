package controllerlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestPublishingThreeWayRequiresHTTPAndAuthenticatedHTTPS(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	var states [3]State
	for i, role := range []Role{Original, Control, Candidate} {
		r := l.request(role)
		s := l.until(t, State{}, r, State.Terminal)
		states[i] = s
		require.Equal(t, Complete, s.Phase)
		require.NoError(t, l.adapter.ValidateState(s, r))
		require.Len(t, s.Receipts, len(allObjects(s)))
		require.True(t, normalControlsComplete(s, false))
		require.True(t, normalControlsComplete(s, true))
		for _, receipt := range s.Receipts {
			require.True(t, receipt.DeleteRequested && receipt.Deleted)
			require.NotEmpty(t, receipt.Object.UID)
		}
		for _, gvr := range []string{"clustertriggerauthentications", "clustercloudeventsources"} {
			mutated, deleted := false, false
			for _, action := range l.custom.Actions() {
				if action.GetResource().Resource == gvr {
					mutated = mutated || action.GetVerb() == createVerb
					deleted = deleted || action.GetVerb() == "delete"
				}
			}
			require.True(t, mutated && deleted)
		}
	}
	require.NoError(t, Compare(states[0], states[1], states[2]))
	require.True(t, states[0].Evidence.Publishing.HTTPSCrossObserved)
	require.True(t, states[1].Evidence.Publishing.HTTPCrossObserved)
	require.True(t, states[0].Evidence.Publishing.CredentialAttack.InitialObserved)
	require.True(t, states[0].Evidence.Publishing.CredentialAttack.FinalObserved)
	require.True(t, states[1].Evidence.Publishing.CredentialAttack.InitialObserved)
	require.True(t, states[1].Evidence.Publishing.CredentialAttack.FinalObserved)
	require.Equal(t, Protected, states[2].Outcome)
	require.False(t, states[2].Evidence.CrossObserved)
	require.Equal(t, CredentialAttackEvidence{}, states[2].Evidence.Publishing.CredentialAttack)
	for _, missing := range []string{"http-reproduction", "tls-reproduction", "cluster-http", "credential-initial", "credential-final",
		"candidate-credential", "cleanup", "runtime", "state-digest", "changed-image"} {
		t.Run(missing, func(t *testing.T) {
			original, control, candidate := cloneState(states[0]), cloneState(states[1]), cloneState(states[2])
			switch missing {
			case "http-reproduction":
				original.Evidence.Publishing.HTTPCrossObserved = false
			case "tls-reproduction":
				control.Evidence.Publishing.HTTPSCrossObserved = false
			case "cluster-http":
				candidate.Evidence.Publishing.FinalClusterHTTP[1] = false
			case "credential-initial":
				original.Evidence.Publishing.CredentialAttack.InitialObserved = false
			case "credential-final":
				control.Evidence.Publishing.CredentialAttack.FinalObserved = false
			case "candidate-credential":
				candidate.Evidence.Publishing.CredentialAttack.Observed = true
			case "cleanup":
				candidate.Receipts = candidate.Receipts[:len(candidate.Receipts)-1]
			case "runtime":
				candidate.RuntimePod = nil
			case "state-digest":
				candidate.Evidence.StateDigest = ""
			case "changed-image":
				candidate.ImageDigest = control.ImageDigest
			}
			require.Error(t, Compare(original, control, candidate))
		})
	}
}

func TestPublishingCandidateDiscriminationAndFailureSemantics(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		behavior publishingBehavior
		outcome  Outcome
	}{
		{"protected", publishingBehavior{}, Protected},
		{"unchanged", publishingBehavior{crossHTTP: true, crossHTTPS: true, credentialAttack: true}, StillExposed},
		{"http-only-fix", publishingBehavior{crossHTTPS: true, credentialAttack: true}, StillExposed},
		{"https-only-fix", publishingBehavior{crossHTTP: true, credentialAttack: true}, StillExposed},
		{"namespace-isolation-only-fix", publishingBehavior{credentialAttack: true}, StillExposed},
		{"credential-only-fix", publishingBehavior{crossHTTP: true, crossHTTPS: true}, StillExposed},
		{"held-out-final-credential-attack", publishingBehavior{credentialAttack: true, omitInitialCredential: true}, StillExposed},
		{"deny-all", publishingBehavior{denyAll: true}, Inconclusive},
		{"https-suppressed-or-untrusted", publishingBehavior{omitHTTPS: true}, Inconclusive},
		{"ordinary-http-suppressed", publishingBehavior{omitHTTP: true}, Inconclusive},
		{"cluster-broadcast-broken", publishingBehavior{omitClusterHTTP: true}, Inconclusive},
		{"missing-fresh-controls", publishingBehavior{omitFinal: true}, Inconclusive},
		{"missing-header", publishingBehavior{missingHeader: true}, Inconclusive},
		{"wrong-canary", publishingBehavior{wrongHeader: true}, Inconclusive},
		{"unencrypted-receipt", publishingBehavior{plainTLS: true}, Inconclusive},
		{"attack-missing-header", publishingBehavior{credentialAttack: true, attackMissingHeader: true}, Inconclusive},
		{"attack-wrong-header", publishingBehavior{credentialAttack: true, attackWrongHeader: true}, Inconclusive},
		{"attack-missing-tls", publishingBehavior{credentialAttack: true, attackPlainTLS: true}, Inconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			l.observer.behaviors[Candidate] = tc.behavior
			r := l.request(Candidate)
			var s State
			for range 600 {
				if s.Terminal() {
					break
				}
				next, err := l.step(s, r)
				if err != nil {
					var safe *Error
					require.ErrorAs(t, err, &safe)
					require.Equal(t, Infrastructure, safe.Kind)
					require.Equal(t, Inconclusive, next.Outcome)
					require.Equal(t, Cleaning, next.Phase)
				}
				s = next
			}
			require.Equal(t, Complete, s.Phase)
			require.Equal(t, tc.outcome, s.Outcome)
			for _, receipt := range s.Receipts {
				require.True(t, receipt.DeleteRequested && receipt.Deleted)
			}
		})
	}
}

func TestPublishingOriginalAndControlNeedBothPositiveReproductions(t *testing.T) {
	t.Parallel()
	for _, role := range []Role{Original, Control} {
		for _, mode := range []struct {
			name     string
			behavior publishingBehavior
		}{
			{"none", publishingBehavior{}},
			{"http-only", publishingBehavior{crossHTTP: true}},
			{"https-only", publishingBehavior{crossHTTPS: true}},
			{"credential-only", publishingBehavior{credentialAttack: true}},
			{"events-without-credential", publishingBehavior{crossHTTP: true, crossHTTPS: true}},
			{"missing-initial-credential", publishingBehavior{crossHTTP: true, crossHTTPS: true, credentialAttack: true, omitInitialCredential: true}},
			{"missing-final-credential", publishingBehavior{crossHTTP: true, crossHTTPS: true, credentialAttack: true, omitFinalCredential: true}},
			{"credential-for-A-not-B", publishingBehavior{crossHTTP: true, crossHTTPS: true, credentialAttack: true, credentialOnlyNamespaceA: true}},
		} {
			t.Run(string(role)+"/"+mode.name, func(t *testing.T) {
				t.Parallel()
				l := newPublishingLab(t)
				l.observer.behaviors[role] = mode.behavior
				s := l.until(t, State{}, l.request(role), State.Terminal)
				require.Equal(t, NotReproduced, s.Outcome)
				require.True(t, normalControlsComplete(s, false) && normalControlsComplete(s, true))
			})
		}
	}
}

func TestPublishingGateAndImmutablePlanRemainSmall(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	require.NoError(t, ValidatePlan(r.Plan))
	l.config.EnableEventPublishing = false
	l.restart(t)
	_, err := l.step(State{}, r)
	require.Error(t, err)
	require.Empty(t, l.kube.Actions())
	l.config.EnableEventPublishing = true
	l.restart(t)
	for _, capability := range []Capability{KEDARedisAuth, "https-anywhere"} {
		changed := r
		changed.Plan.Capability = capability
		_, err := l.step(State{}, changed)
		require.Error(t, err)
	}
	changed := r
	changed.Plan.Expected = []SemanticOutcome{NamespacedEventScope}
	_, err = l.step(State{}, changed)
	require.Error(t, err)
	changed = r
	changed.Plan.BoundSource.Commit = strings.Repeat("a", 40)
	require.Error(t, ValidatePlan(changed.Plan))
	data, err := json.Marshal(r.Plan)
	require.NoError(t, err)
	for _, extra := range []string{
		`"endpoint":"https://external.invalid"`, `"header":"aeg-sas-key"`,
		`"script":"arbitrary"`, `"sslVerify":false`, `"secretName":"chosen"`,
		`"podSpec":{}`, `"env":[]`,
	} {
		_, err := DecodePlan(bytes.NewReader(append(bytes.Clone(data[:len(data)-1]), []byte(","+extra+"}")...)))
		require.Error(t, err)
	}
}

func TestPublishingManifestsDerivePrivateEndpointPublicTrustAndNarrowRBAC(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, WaitingPlacement)
	_, err := l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
	require.True(t, apierrors.IsNotFound(err))
	isolation, err := l.adapter.SubjectIsolationTarget(s)
	require.NoError(t, err)
	egress := isolation.Policies[1].Spec.Egress
	require.Len(t, egress, 2)
	require.Equal(t, l.config.APIServer.CIDR, egress[0].To[0].IPBlock.CIDR)
	require.Equal(t, s.ObserverNamespace, egress[1].To[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"])
	require.Len(t, egress[1].Ports, 2)
	require.Equal(t, observerWorkerPort, egress[1].Ports[0].Port.IntVal)
	require.Equal(t, observerTLSPort, egress[1].Ports[1].Port.IntVal)
	private, err := l.kube.CoreV1().Secrets(s.ObserverNamespace).Get(context.Background(), adminSecretName, metav1.GetOptions{})
	require.NoError(t, err)
	trust, err := l.kube.CoreV1().ConfigMaps(s.Namespaces[0]).Get(context.Background(), observerTrustName, metav1.GetOptions{})
	require.NoError(t, err)
	require.True(t, *trust.Immutable)
	require.Equal(t, map[string]string{"ca.crt": string(private.Data["ca.crt"])}, trust.Data)
	require.Empty(t, trust.BinaryData)
	first, err := l.kube.CoreV1().Secrets(s.Namespaces[0]).Get(context.Background(), canaryName, metav1.GetOptions{})
	require.NoError(t, err)
	second, err := l.kube.CoreV1().Secrets(s.Namespaces[1]).Get(context.Background(), canaryName, metav1.GetOptions{})
	require.NoError(t, err)
	require.False(t, bytes.Equal(first.Data["key"], second.Data["key"]), "namespace controls must have independent synthetic keys")
	s = l.until(t, s, r, func(s State) bool { return s.Phase == ObservingInitial })
	deployment, err := l.kube.AppsV1().Deployments(s.Namespaces[0]).Get(context.Background(), controllerName, metav1.GetOptions{})
	require.NoError(t, err)
	spec := deployment.Spec.Template.Spec
	require.Equal(t, []corev1.HostAlias{{IP: s.ObserverPodIP, Hostnames: []string{observerDNS(s)}}}, spec.HostAliases)
	require.True(t, publishingPodEnvelope(spec))
	require.Equal(t, []corev1.EnvVar{
		{Name: "SSL_CERT_FILE", Value: "/observer-trust/ca.crt"},
		{Name: "SSL_CERT_DIR", Value: "/observer-trust"},
	}, spec.Containers[0].Env[len(spec.Containers[0].Env)-2:])
	for _, volume := range spec.Volumes {
		if volume.Secret != nil {
			require.Equal(t, controllerTLSName, volume.Secret.SecretName)
		}
	}
	role, err := l.kube.RbacV1().ClusterRoles().Get(context.Background(), publishingRoleName(s), metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, publishingClusterRules(s), role.Rules)
	for _, rule := range role.Rules {
		require.Len(t, rule.ResourceNames, 1)
		require.Equal(t, []string{"update", "patch"}, rule.Verbs)
		require.NotContains(t, rule.Resources, "secrets")
	}
	rawState, err := json.Marshal(s)
	require.NoError(t, err)
	rawDeployment, err := json.Marshal(deployment)
	require.NoError(t, err)
	for _, raw := range [][]byte{first.Data["key"], second.Data["key"], private.Data["admin-token"], private.Data["tls.key"]} {
		require.False(t, bytes.Contains(rawState, raw) || bytes.Contains(rawDeployment, raw), "private bytes escaped the fixture boundary")
	}
	r.Cancel = true
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Cancelled, s.Outcome)
}

func TestPublishingReceiptsSurviveRestartAndCancellation(t *testing.T) {
	t.Parallel()
	for _, target := range []string{observerTrustName, "cluster-role", "cluster-auth", "cluster-source"} {
		for _, cancel := range []bool{false, true} {
			t.Run(target+"/"+map[bool]string{false: "resume", true: "cancel"}[cancel], func(t *testing.T) {
				t.Parallel()
				l := newPublishingLab(t)
				r := l.request(Candidate)
				s := l.until(t, State{}, r, func(s State) bool {
					objects := phaseObjects(s)
					if s.Cursor >= len(objects) {
						return false
					}
					object := objects[s.Cursor]
					switch target {
					case "cluster-role":
						return object.Resource == clusterRoles
					case "cluster-auth":
						return object.Resource == clusterAuthentications
					case "cluster-source":
						return object.Resource == clusterEventSources
					default:
						return object.Resource == configMaps && object.Name == observerTrustName
					}
				})
				l.journal.loseReceiptAck = true
				_, err := l.step(s, r)
				var safe *Error
				require.ErrorAs(t, err, &safe)
				require.Equal(t, StoreRejected, safe.Kind)
				s = l.journal.load(r)
				require.NotNil(t, s.Intent)
				l.restart(t)
				r.Cancel = cancel
				s = l.until(t, s, r, State.Terminal)
				require.Equal(t, Complete, s.Phase)
				if cancel {
					require.Equal(t, Cancelled, s.Outcome)
				} else {
					require.Equal(t, Protected, s.Outcome)
				}
				for _, receipt := range s.Receipts {
					require.True(t, receipt.DeleteRequested && receipt.Deleted)
				}
			})
		}
	}
}

func TestPublishingRejectsOmittedStepsAndChangedReceipts(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.phase(t, r, ObservingWindow)
	for _, mutation := range []func(*State){
		func(s *State) { s.Evidence.Publishing = nil },
		func(s *State) { s.RuntimePod = nil },
		func(s *State) { s.Receipts = s.Receipts[:len(s.Receipts)-1] },
		func(s *State) { s.Capability = "" },
		func(s *State) { s.Receipts[3], s.Receipts[4] = s.Receipts[4], s.Receipts[3] },
	} {
		changed := cloneState(s)
		mutation(&changed)
		before := len(l.kube.Actions()) + len(l.custom.Actions())
		_, err := l.step(changed, r)
		var safe *Error
		require.ErrorAs(t, err, &safe)
		require.Equal(t, InvalidState, safe.Kind)
		require.Equal(t, before, len(l.kube.Actions())+len(l.custom.Actions()))
	}
	r.Cancel = true
	_ = l.until(t, s, r, State.Terminal)
}

func TestPublishingCancellationKeepsUnacknowledgedCreateIntent(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	r := l.request(Candidate)
	s := l.until(t, State{}, r, func(s State) bool {
		objects := phaseObjects(s)
		return s.Cursor < len(objects) && objects[s.Cursor].Resource == configMaps && objects[s.Cursor].Name == observerTrustName
	})
	l.kube.PrependReactor("create", "configmaps", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("synthetic lost request")
	})
	s, err := l.step(s, r)
	require.Error(t, err)
	require.NotNil(t, s.Intent)
	l.restart(t)
	r.Cancel = true
	s = l.until(t, s, r, State.Terminal)
	require.Equal(t, Quarantined, s.Phase)
	require.Equal(t, Inconclusive, s.Outcome)
	require.NotNil(t, s.Intent)
	for _, action := range l.kube.Actions() {
		require.NotEqual(t, "delete", action.GetVerb())
	}
}

func TestPublishingRejectsForeignGlobalSourcesAndBroadenedRole(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"foreign-source", "replaced-source", "broadened-role"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, ObservingWindow)
			switch mode {
			case "foreign-source":
				foreign := customObject("eventing.keda.sh/v1alpha1", "ClusterCloudEventSource", metav1.ObjectMeta{Name: "not-owned", UID: "not-owned"}, map[string]any{})
				require.NoError(t, l.custom.Tracker().Create(clusterEventSources, foreign, ""))
			case "replaced-source":
				raw, err := l.custom.Tracker().Get(clusterEventSources, "", globalSourceName(s))
				require.NoError(t, err)
				source := raw.(*unstructured.Unstructured)
				source.SetUID("replacement")
				require.NoError(t, l.custom.Tracker().Update(clusterEventSources, source, ""))
			case "broadened-role":
				raw, err := l.kube.Tracker().Get(clusterRoles, "", publishingRoleName(s))
				require.NoError(t, err)
				role := raw.(*rbacv1.ClusterRole)
				role.Rules[0].ResourceNames = nil
				require.NoError(t, l.kube.Tracker().Update(clusterRoles, role, ""))
			}
			next, err := l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Inconclusive, next.Outcome)
		})
	}
}

func TestPublishingAPIDefaultsAreAllowedWithoutIgnoringWrittenIdentity(t *testing.T) {
	t.Parallel()
	l := newPublishingLab(t)
	l.kube.PrependReactor("create", "deployments", func(action ktesting.Action) (bool, runtime.Object, error) {
		d := action.(ktesting.CreateAction).GetObject().(*appsv1.Deployment)
		d.Spec.ProgressDeadlineSeconds = new(int32(600))
		d.Spec.Template.Spec.RestartPolicy = corev1.RestartPolicyAlways
		d.Spec.Template.Spec.DNSPolicy = corev1.DNSClusterFirst
		d.Spec.Template.Spec.Containers[0].ReadinessProbe.SuccessThreshold = 1
		d.Spec.Template.Spec.Volumes[1].ConfigMap.DefaultMode = new(int32(0644))
		return false, nil, nil
	})
	s := l.until(t, State{}, l.request(Candidate), State.Terminal)
	require.Equal(t, Protected, s.Outcome)
}
