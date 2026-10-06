// Package controllerlab implements a trusted, synthetic controller observation
// lab. It is separate from the HTTP-workload environment adapter and does not
// build images, execute host commands, accept Kubernetes JSON, or contact cloud
// providers. keda-namespace-events-v1 retains its HTTP-only contract.
// keda-event-publishing-v2 adds an opt-in synthetic HTTPS/Event Grid publishing
// and undelegated cluster-credential contract. The previous combined v1
// capability is rejected, not reinterpreted. keda-redis-auth-v1 remains a reserved capability returning
// NeedsAdapter; no Redis authorization scenario is claimed.
//
// # Parent integration contract
//
// The model supplies only Plan: a version, capability, public repository/full
// commit, opaque recipe ID, two typed namespace actors, and the semantic outcome
// namespaced-event-scope. The publishing capability additionally requires
// namespaced-event-credential-scope and undelegated-cluster-credential-scope,
// the same actors, and the pinned source below.
// ValidatePlan checks this exact semantic shape; Step also checks the operator
// gate and immutable binding. DecodePlan rejects oversized, duplicate, and
// unknown fields. The operator supplies Config and independently verified immutable
// ImageBindings. The parent must not manufacture those bindings from model
// output; EvidenceDigest identifies retained external provenance, not a signature
// this package verifies.
// Actor entries constrain synthetic fixture shapes; they do not establish what
// a real tenant may create under production RBAC or managed-cloud admission.
//
// New accepts dedicated kubernetes.Interface and dynamic.Interface clients plus
// a trusted Observer. NewForConfig instead constructs separate clients and an
// exact-Pod port-forward observer from an explicit operator REST config. Neither
// constructor performs a Kubernetes request. There is no management-client or
// in-cluster-credential fallback.
//
// Repeatedly call Adapter.Step with the persisted State and the same Request.
// One Step performs at most one persistent Kubernetes mutation and
// MaxStepClientOperations (64) bounded client operations, including read-only
// authorization reviews, with a configured per-step timeout. Schedule polls;
// Step never sleeps. Run
// Original, Control, and Candidate as distinct operations of the same run and
// use Compare only on their completed, fully cleaned states. A Candidate
// Protected outcome alone is deliberately insufficient.
//
// Hooks.Acceptance must recheck the parent's private authorization immediately
// before creation/deletion and the explicit "remove-finalizer" cleanup action.
// Hooks.PersistState must implement atomic revision
// compare-and-swap keyed by RunID/OperationID, retain terminal tombstones, and
// reject a second initial revision even after cleanup. Reload durable State on
// any StoreRejected error: the store acknowledgement itself can be lost.
// The config-digest domain is v4 for the DNS-free, endpoint-pinned topology and
// mandatory trusted placement binding; earlier prototype receipts cannot resume
// or compare. EnableEventPublishing is omitted when false, preserving the
// existing HTTP-only config digest. Enabling it changes the frozen identity.
// The combined semantic version lives in the capability string, while the Plan
// schema Version remains 1. Old combined-v1 plans and raw results cannot resume
// or compare under v2; retire those operations with their original controller
// before upgrading. Legacy keda-namespace-events-v1 is unchanged.
// State contains identities, intent digests, UID receipts, times, a non-credential
// FinalMarkerNonce for publishing challenges, and digest/count/boolean evidence.
// Neither callback receives raw canaries, observer keys, or admin material.
//
// After the observer is pinned and the complete controller policy exists, Step
// returns WaitingPlacement without creating a controller Deployment. The parent
// must measure CNI enforcement using its reserved, empty control namespace and
// require a verified, fully cleaned proof. It then supplies Request.Placement:
// the exact operation digest, proof Endpoint.NodeName, and retained ProofDigest.
// Acceptance receives "bind-placement" plus that binding and must validate the
// complete proof against the current namespace UID, all effective policy
// UID/resourceVersion/digests, labels, and node. A syntactically valid digest is
// not proof verification by this package.
//
// Placement is persisted before launch and rendered as
// Deployment.spec.template.spec.nodeName; acceptance alone is not scheduling
// enforcement. Rebinding is rejected and subsequent template node/image changes
// fail closed. Placement is never a model Plan field. Parent integration must
// continue fencing its measured policy/label/namespace/node bindings; this
// package's synthetic placement tests do not establish live CNI qualification.
//
// Cleanup first foreground-deletes the exact receipted controller Deployment
// and waits for its deletion plus a namespace-wide, label-independent absence
// of Pods in namespace A. State.ControllerStopped records that API-observed
// barrier; no force-delete or host process access is used. The remaining
// receipts are then cleaned in reverse order. The driver removes only
// finalizer.keda.sh from the compiled KEDA resource kinds, testing the exact UID,
// resourceVersion, and finalizer list in a JSON patch. Receipt.FinalizerRemoval
// retains the guarded resourceVersion and completion state across lost replies.
// Its pending intent is CAS-persisted before Acceptance reads the durable state.
// A failed persistence acknowledgement prevents acceptance and patching; a
// rejected acceptance retains the pending intent for an authorized retry.
// Cleanup has a bound of twice StartupTimeout, not an unbounded finalizer wait.
//
// A receipted UID remains cleanup authority if the subject changes labels,
// annotations, or ownerRefs; the driver never follows those ownerRefs to another
// resource. If GC has already started or finished deleting that UID, cleanup
// records an authorized UID-preconditioned delete before settling the receipt.
// Unknown finalizers and actual UID replacement quarantine for operator
// intervention. Lost creation acknowledgements still require the durable random
// intent, namespace anchors, and compiled object contract: a NotFound without a
// UID receipt cannot prove an in-flight create will never arrive. Complete and
// Quarantined states cannot replay the run. The Pod absence barrier is a
// Kubernetes API observation, not proof of physical termination on a failed or
// force-deleted node.
//
// # Compiled event scenario
//
// Each operation owns two deterministically named event-producing Namespaces and
// a separate, trusted ObserverNamespace, all with exact UID anchors. A fixed KEDA
// Deployment watches ONLY the event-producing namespaces. Each has a namespaced
// CloudEventSource; their HTTP destinations are two channels on the exact
// observed private observer Pod IPv4 address. No Service/DNS resolution is used.
// The observer Pod UID, immutable image spec, actual image content digest, and
// private IP are checked before a durable endpoint pin is recorded. Only then
// may the controller egress policy and Deployment be created. IP/image drift
// fails closed; the adapter never re-resolves or silently follows an endpoint.
// Failed ScaledObjects with
// deliberately absent scale targets generate positive, synthetic failed.v1
// events. There are no support workload images or incident-specific scripts.
//
// WaitingSources checks the live runtime and exact installed source/auth
// bindings, not the CR Active condition. At the pinned KEDA revision, handler
// setup mutates the live status before the merge-patch baseline is captured, so
// its intended Active=True update can leave persisted Active=Unknown. Event
// processing can also change that condition to False independently of delivery.
// The harness therefore installs its bounded initial event fixtures after
// validating prerequisites; only trusted positive observations establish actual
// publisher readiness. It never patches source status or treats Unknown, False,
// or True as reproduction/protection evidence. Passing this installation gate
// does not change evidence, deadlines, or start the isolation window.
//
// https://github.com/kedacore/keda/blob/e615440f24f6abec8b7c69bd88854cb4324e9eaa/pkg/eventemitter/eventemitter.go#L430-L459
// https://github.com/kedacore/keda/blob/e615440f24f6abec8b7c69bd88854cb4324e9eaa/pkg/status/status.go#L199-L217
//
// The initial controls require an actual CloudEvent subject digest AND marker
// on each source's own channel. Source digests also bind the controller namespace.
// Original and rebuilt-control reproduction require positive observation of a
// wrong-namespace event, never an absent response. Candidate protection requires
// a bounded no-cross-event window, newly created final controls observed on
// both correct channels, and a tail observation window. Saturation, history
// truncation/reset/rewrite, observer restart/disappearance, missing controls,
// malformed wire state, and transport errors cannot produce Protected.
//
// The fixed v1alpha1 fields, WATCH_NAMESPACE, certificate filenames, and failed
// ScaledObject event fixture follow the public KEDA API at revision
// e615440f24f6abec8b7c69bd88854cb4324e9eaa (KEDA v2.17.3):
//
// https://github.com/kedacore/keda/tree/e615440f24f6abec8b7c69bd88854cb4324e9eaa
//
// This is not a claim that that revision reproduces a particular defect.
// A selected original image must actually emit the cross-namespace event or the
// operation returns NotReproduced. Other controller families need an adapter;
// managed AKS policy is explicitly OutsideScope.
//
// # Opt-in HTTP and authenticated HTTPS publishing
//
// Config.EnableEventPublishing authorizes only KEDAEventPublishing at that exact
// public source. Plan.Version remains 1, Actors remain NamespaceAEventSource and
// NamespaceBEventSource, and Expected must contain exactly NamespacedEventScope,
// NamespacedEventCredentialScope, and UndelegatedClusterCredentialScope.
// URLs, headers, keys, TLS settings, Secret
// names, cluster controls, Pod specs, and client configuration are never Plan
// fields. The parent owns service/catalog/policy enablement and image builds.
//
// The compiler retains both ordinary HTTP namespace sources and adds:
//
//   - An azureEventGridTopic CloudEventSource in each namespace, with
//     authenticationRef.kind TriggerAuthentication and a local secretTargetRef
//     mapping parameter accessKey to key in that namespace's synthetic Secret.
//     The two namespaces have independent ephemeral canaries.
//   - A namespace-B CloudEventSource explicitly referring to a generated
//     ClusterTriggerAuthentication whose key resides in namespace A. This is an
//     independent credential-exfiltration attack, NOT a normal control: an
//     explicit reference does not delegate the cluster key to a namespace writer
//     or to that writer's endpoint. The pinned API has no delegation mechanism.
//   - A generated ClusterCloudEventSource using ordinary HTTP that must receive
//     events from both namespaces. This intentionally legitimate broadcast must
//     not be confused with a namespaced source receiving another namespace.
//
// The pinned public resolver selects the referenced authentication object and
// resolves a cluster reference's key from the cluster object namespace. That
// resolution behavior is the attack mechanism, not evidence of delegation:
//
// https://github.com/kedacore/keda/blob/e615440f24f6abec8b7c69bd88854cb4324e9eaa/pkg/scaling/resolver/scale_resolvers.go#L237-L274
// https://github.com/kedacore/keda/blob/e615440f24f6abec8b7c69bd88854cb4324e9eaa/pkg/scaling/resolver/scale_resolvers.go#L366-L386
//
// Its empty-namespace guard does not resolve authentication for a
// ClusterCloudEventSource. The cluster event-source control is therefore HTTP;
// cluster-scoped HTTPS event-source authentication is not claimed.
//
// HTTPS destinations use a generated, operation-specific TLS hostname and the
// exact pinned observer Pod IP through one controller-derived hostAliases entry.
// There is no DNS egress. SSL_CERT_FILE and SSL_CERT_DIR point only at the public
// synthetic CA ConfigMap; the observer private key/admin Secret never enters the
// controller Pod. Verification is not disabled. NetworkPolicy permits only the
// existing HTTP worker port 8080 and the HTTPS data port 9443, not admin 8443.
// Parent CNI qualification must bind this exact expanded policy and placement.
//
// Observer config adds ingressHTTPSAddress on 9443 and channelCanaries containing
// only {channel, sha256} for the three HTTPS channels. The expected header is
// fixed to aeg-sas-key. This follows the pinned publisher's shared-key policy:
//
// https://github.com/kedacore/keda/blob/e615440f24f6abec8b7c69bd88854cb4324e9eaa/vendor/github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventgrid/publisher/client_custom.go#L48-L69
//
// The data-only TLS listener cannot read/reset state, even with admin credentials.
// HTTPObservation.TLSDataIngress is derived from the actual TLS listener, never
// a request header. State/reset continue to require the separate admin token.
// Both data listeners share connection/body/evidence quotas and generation
// fences. Markers use {id, sha256}, an exact-field match; legacy {id, value}
// substring markers remain supported. Publishing final subjects contain
// independent challenge suffixes derived from FinalMarkerNonce. Neither the
// seed nor future subject strings appear in observer configuration. Records
// predating their fixture receipt cannot later be recounted as fresh controls.
// The nonce-protected namespace-B final event is also the held-out credential
// attack challenge, with marker credential-final-1. Its legitimate same-namespace
// HTTP/HTTPS and cluster-HTTP copies remain mandatory normal controls; its copy
// on /events/grid-credential-attack carrying the exact namespace-A canary is a
// separate attack observation. The source is named scope-credential-attack-source.
//
// The publishing profile sets httpSetEvidence=true. It retains the first
// occurrence of each route/TLS/canary-match/source/subject/marker tuple, ignoring
// retry-varying body digests, event IDs, and timestamps. The first body digest
// remains unchanged. duplicateHTTP counts later semantic duplicates separately;
// a new wrong-header, cross-namespace, or final-challenge tuple cannot be hidden
// by deduplication. The unique set is bounded at 256 records. Any distinct-record
// drop, connection rejection, reset, rewrite, or counter saturation invalidates
// evidence. Evidence.HTTPCount is the retained distinct count in this profile,
// while Evidence.DuplicateHTTP must be monotonic within its generation.
//
// Two independent administrative connection slots prevent data traffic from
// exhausting state/reset access. The bounded data limit is 256: the public
// failed-ScaledObject cadence (two failed events, two fixtures, six handlers,
// 5ms exponential retry) can have 240 attempts within the five-second read
// deadline. Tests send every modeled request over HTTP/TLS, without client-side
// deduplication, for minimum and maximum observation/tail windows. Legacy
// configurations retain their existing record and connection accounting.
//
// All three arms must complete initial and fresh final HTTP/HTTPS local controls
// using same-namespace TriggerAuthentication, plus both cluster-HTTP broadcast
// controls. Original and Control independently require positive wrong-namespace
// emission on BOTH local transports AND namespace-A credential emission on the
// attack channel for the initial and held-out final namespace-B events.
// Candidate must emit neither cross-namespace events nor credential attack
// traffic, remain live through the observation/tail windows, and use a different
// immutable image. Merely fixing event namespace filtering is insufficient.
// TLS requests without the exact channel's
// canary are Inconclusive, not evidence of a successful auth fix. Missing steps,
// unreachable observers, stale/reset/rewritten history, missing controls, and a
// stopped/restarted/replaced controller cannot produce protection. RuntimePod
// pins the real Pod UID and its ReplicaSet-to-Deployment ownership chain;
// stale Deployment availability alone is insufficient. Unavailable ReplicaSet
// reads and a replaced Pod with the valid Deployment chain are inconclusive and
// enter cleanup. An actual foreign ownership chain remains quarantined.
// Namespace read throttling/server/transport failures, observer readiness loss
// or restart, and a previously receipted global object removed by GC likewise
// enter inconclusive cleanup. A missing namespace anchor, replaced receipted UID,
// actual observer IP/image drift, or our reserved name without an intent remains
// an ownership failure. Unknown foreign global collections or names are instead
// OutsideScope: our run becomes inconclusive and cleans its own receipts while
// leaving foreign resources untouched.
//
// Evidence.Publishing retains local HTTPS and cluster-HTTP normal arrays plus
// event-scope cross-observation flags. Its CredentialAttack value has Observed,
// InitialObserved, and FinalObserved fields instead of the removed v1
// InitialClusterAuth/FinalClusterAuth normal-control fields. Observed records any
// verified attack-channel canary emission; the two qualified flags additionally
// require the exact initial/final B-event source, subject, marker, and receipt.
// Attack traffic is not counted as evidence for the independent HTTP/HTTPS
// cross-event checks. Compare requires the
// complete ordered compiled receipt set and exact-UID cleanup, including the
// generated cluster objects and their narrowly resourceNames-bound writer role.
// Receipt.BindingDigest freezes the actual acknowledged fixture body, including
// specs, reference fields, labels, annotations, immutable Secret/ConfigMap data,
// and ownerRefs. Server-managed metadata/status and the known KEDA finalizer are
// excluded. KEDA recovery additionally requires an exact compiled template,
// not a subset or an annotation claiming a digest. The expected public
// scaledobject.keda.sh/name label is rendered before creation. After every
// observation, all source/auth/ScaledObject and Secret/ConfigMap bindings are
// reread before evidence can advance; Evidence.BindingsDigest records that set.
// Completed publishing evidence lacking binding or controller-stop receipts
// cannot compare successfully; current-contract in-flight receipts remain
// cancellable. Old combined-v1 receipts are not current v2 proof.
//
// The protocol establishes request emission to private synthetic infrastructure
// and the checked event namespace/undelegated credential boundary only. It does not establish Azure
// subscription ownership, Azure-side authorization, managed-cloud policy, or a
// guarantee about arbitrary production credentials, endpoints, or SDK auth modes.
// This is bounded checked behavior, not a black-box oracle against a controller
// deliberately crafted to emit expected traffic or restore mutated fields
// between reads. The parent's independent automated review of the exact patch
// remains a separate required gate. No validating admission policy is installed
// here. A stronger name/UID-bound policy preventing fixture spec/ref/label
// mutation while allowing controller status/finalizer maintenance requires a
// separately agreed operator installation and rollout contract.
//
// # Operator deployment prerequisites
//
// Use a dedicated disposable lab cluster, not the management cluster, a
// production namespace, or an existing shared KEDA installation. Approval is
// pinned to ClusterIdentity(kube-system Namespace UID), checked before creation.
// Install the matching public KEDA CRDs, including the cluster-scope
// informer CRDs, and one exact ClusterRole with KEDAClusterWatchRules. Config
// pins that role's name and UID; every non-cleanup active step rechecks its rules.
// Both global authentication/event source collections must initially be empty.
// HTTP-only runs require them to remain empty and never create cluster sources
// or roles. Publishing runs allow only their exact generated global objects,
// owner/intent/UID-bound and revalidated on every active step; foreign global
// sources fail closed. No mode creates or modifies a CRD or the operator role.
//
// The dedicated lab client needs narrowly operator-approved permission to create
// and UID-delete the compiled namespace, Role/RoleBinding, ClusterRoleBinding,
// NetworkPolicy, ServiceAccount, Secret, ConfigMap, Pod, Deployment, ScaledObject,
// and CloudEventSource objects, read the approved role and cluster identity,
// discover the CRDs, issue SubjectAccessReview authorization queries, and
// port-forward the owned observer Pod. The publishing gate additionally requires
// creation and UID-deletion of its exact ClusterRole, TriggerAuthentication,
// ClusterTriggerAuthentication, and ClusterCloudEventSource, plus Pod/ReplicaSet
// reads for live runtime identity. The trusted cleanup client also requires
// patch on the compiled KEDA resources for UID/RV-guarded known-finalizer removal;
// that permission is never granted as a generic model tool.
// Restrict role creation/binding to the compiled
// writer contract and the approved watcher role. Never expose these privileges
// as model tools. The namespace prefix must be reserved for this
// operator; concurrent users must not mutate its owned objects.
//
// Controller permissions are namespaced and explicit. Secret informers may
// operate in both watched namespaces, so both grant get/list/watch on their
// synthetic Secrets. Observer credentials and TLS keys live ONLY in the third,
// unwatched namespace, where the compiler grants the controller no permissions.
// Before creating private observer material, before launching the controller,
// and before every snapshot, actual SubjectAccessReviews check the exact
// controller ServiceAccount UID and its authenticated/service-account groups.
// All Secret GET/list/watch paths, including named list/watch, must be denied.
// Observer Pod mutation/exec/attach/ephemeral-container and workload-creation
// paths must also be denied, as must creation of privilege-extending bindings.
// A permission grant, changed identity, unavailable authorizer, or evaluation
// error makes the operation inconclusive, never protected. The pinned global
// watcher role is strictly enumerated and cannot grant Secret access or wildcard
// permissions. These checks do not replace the operator's dedicated-cluster and
// least-privilege approval, and the unit suite does not claim live RBAC proof.
//
// Configure an immutable, single-platform trusted observer image whose runtime
// image ID matches its configured digest, bounded resource requirements, and
// exact API-server IP-and-port egress. The current compiled worker listener is
// IPv4-only; other address families require a qualified template. The observer
// must support ingressHTTPAddress on plain HTTP 8080 alongside httpAddress on
// root-pinned HTTPS 8443, and ingressHTTPSAddress on 9443 when publishing is
// enabled. Neither ingress listener may expose state or reset,
// even with valid admin credentials. No workerHTTPAddress alias is emitted.
// Building/rolling out the trusted observer wire/image is parent-owned.
// A NetworkPolicy-enforcing CNI and
// its API-service DNAT behavior must be validated by the operator. All three
// namespaces default-deny ingress/egress. Only the configured API-server literal
// and the owned observer's worker ports are allowed. Config.DNS must be empty;
// unrestricted resolver access is not a safe default and is rejected. There is
// no DNS egress, proxy fallback, or generic outbound URL surface. Namespace/Pod
// selectors additionally prevent an old Pod IP from becoming an authorized
// unrelated endpoint if the address is reused. The controller image must
// support the compiled KEDA entrypoint/flags; its Kubernetes API environment uses
// the configured literal address and HTTP proxying is explicitly bypassed.
//
// Each operation generates fresh synthetic canary/admin values and separate
// observer/controller TLS material. Canaries are stored only in their immutable
// synthetic Secrets and emitted in synthetic publishing requests; observer
// configuration contains only their SHA-256 digests. Only the
// observer mounts its admin Secret. The production observer client sends the
// actual wire header X-Orka-Observer-Token over root-pinned HTTPS inside an exact
// Pod UID port-forward. It never uses API-server pod/proxy, system HTTP proxies,
// redirects, arbitrary endpoints, or a subject-supplied transport.
// The virtual TLS ServerName is checked against the generated certificate but
// is never DNS-resolved: the admin dialer connects to the exact Pod via a fixed
// loopback port-forward and checks its pinned IP/image again before sending a
// bearer token.
//
// Fake-client state-machine tests and real loopback TLS HTTP wire tests validate
// these component contracts, including UID-guarded deletion and crash recovery.
// They do not constitute live Kubernetes, CNI, KEDA-image, managed-cloud, or
// deployment verification. Parent-owned configuration/deployment integration and
// its live qualification remain prerequisites. Global lab use must be serialized
// by the parent; this package does not coordinate independent lab operators.
package controllerlab
