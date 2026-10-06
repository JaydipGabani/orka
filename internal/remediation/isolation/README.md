# Runtime egress proof

This private, opt-in adapter measures a **single concrete canary path**. A
NetworkPolicy object, an operator boolean, a successful Pod, or an unreachable
address is not sufficient evidence.

The trusted parent supplies:

- A dedicated `kubernetes.Interface`; this package loads no credentials.
- An operator-pinned `Config.ProbeImage`.
- Two distinct, parent-owned, active namespaces with exact UIDs. The subject
  namespace must have its final policies installed but no Pods. The control
  namespace must be exclusively reserved and empty of Pods and NetworkPolicies.
  Namespace allocation belongs to the parent's operator-only code, never a
  model-proposed namespace name or manifest.
- The actual subject's complete frozen Pod labels and the API-server-observed
  policy identity (`Name`, `UID`, `ResourceVersion`, `PolicyDigest(policy)`).
- A private durable receipt callback, serialized per operation, performing CAS
  from `receipt.Revision-1` to `receipt.Revision`. Retain terminal tombstones and
  reject a new initial receipt for an already-used run/operation.

```go
adapter, err := isolation.New(dedicatedClient)
// Handle err; persist is the parent's private, durable CAS callback.
receipt, err := adapter.Start(ctx, operatorConfig, runID, operationID,
    isolation.SubjectNamespace{Name: subjectNS.Name, UID: subjectNS.UID},
    frozenSubjectLabels,
    isolation.PolicyIdentity{
        Name: policy.Name, UID: policy.UID, ResourceVersion: policy.ResourceVersion,
        Digest: isolation.PolicyDigest(policy),
    }, persist)
// Handle err and retain receipt. Repeatedly:
receipt, err = adapter.Observe(ctx, receipt, persist)
// Only after successful durable acknowledgement and CleanupComplete:
proof, err := isolation.ExportProof(receipt)
```

`Start` persists the fresh cryptographic **synthetic, non-secret** nonce and
complete intent before any creation. `Observe` advances one bounded step. A
restart uses the persisted receipt with `Observe`, never `Start`. Handle every
error; after an ambiguous persistence failure, reload the canonical journal.
Returned receipts retain acknowledged UIDs even when their persistence failed.
Neither receipts nor proofs, including IPs and nonces, belong in model context,
public status, or logs.

## Measurement

1. Install default-deny ingress/egress in the reserved control namespace, with
   TCP/8080 ingress to the canary permitted from both namespaces and the exact
   subject labels. A canary Pod runs the trusted worker's fixed `serve` command.
2. Wait for the canary's actual TCP readiness, Pod UID, literal PodIP, node, and
   runtime image ID. Install one positive-client TCP/8080 egress allow whose
   single peer combines the exact control namespace selector **and** the
   canary's unique operation-derived Pod label. Use Pod selectors rather than
   `IPBlock`: in-cluster Pod IP matching is CNI-dependent, and identity-based
   implementations such as Cilium need not match those addresses as CIDRs.
   The worker still connects only to the frozen, UID-bound literal PodIP/8080;
   this grants no external CIDR, DNS, Service, or arbitrary-target access.
3. Run **positive-before → negative → positive-after**, sequentially. The three
   one-shot Pods have identical subject labels and run on the canary's node.
   Both positives must connect and receive the exact nonce response. Only a
   two-second **dial timeout** counts as negative evidence. Refusal, route
   failure, a connected-but-silent peer, malformed JSON, or inconsistent exit
   status fail closed with a classified `needs-adapter` error.
4. Freeze and recheck the subject's entire policy set, namespace UIDs/labels,
   cluster `kube-system` UID, canary identity, fixed Pod specs, and image IDs.
   Record the three actual Pod UIDs, image IDs, timestamps, node, endpoint UID,
   and the exact policy identity/digest.
5. Delete only owned proof resources, with UID preconditions. Observe actual
   absence, recheck the parent fences, and durably persist completion before
   `ExportProof` can succeed.

The subsequent real subject **must not run until cleanup is complete**. Its
namespace, complete label set, policy set and **node placement** must remain
identical to the proof (`proof.Endpoint.NodeName`). The parent must not re-use
this measurement for another operation or claim it covers other nodes, ports,
protocols, destinations, policy changes, cluster-wide policy products, or future
CNI changes. This is a point-in-time qualification, not a general CNI
attestation. The parent still owns admission/authorization and all namespace
lifetimes.

Pod intents remain fixed after admission. The three Calico observation
annotations (`containerID`, `podIP`, `podIPs` under `cni.projectcalico.org`) are
tolerated; arbitrary network-attachment/security annotations, sidecars, injected
volumes and environment are not. An incompatible admission policy fails closed.

## Bounds and cleanup

There are exactly four possible Pods, two control NetworkPolicies, two supplied
namespace anchors, no Jobs, and no namespace allocation. The operation deadline
is at most 60 seconds. Each Pod has a frozen active deadline of at most 60
seconds, 100m CPU/32Mi memory limits, a non-root UID, read-only root filesystem,
all capabilities dropped, and RuntimeDefault seccomp. There are no credential,
volume, proxy, DNS, shell, or arbitrary command inputs. Service-account
automounting and service environment links are disabled. The only writable
container path is kubelet's termination-message file.

The worker uses a direct literal-IP `net.DialTimeout` and a two-second total
exchange deadline. `serve --nonce <synthetic>` serves TCP/8080 for at most 60
seconds; `connect --target <literalIP:port> --expect reachable|blocked --nonce
<synthetic>` emits a canonical fixed boolean/classification JSON message, never
raw errors or reflected bytes. The adapter accepts at most 4KiB.

Cancelling a request context never triggers implicit deletion. Explicitly call
`Cancel` with a live context and the durable receipt until `CleanupComplete`.
Failures also need explicit `Cancel`. Cleanup does not delete or modify the
parent's namespaces or subject policies. All proof resources are owner-referenced
to the exact supplied namespace UID. A known UID is never weakened to a name
lookup. An unacknowledged create cannot be adopted for proof; only cleanup may
recover its UID after checking the exact persisted intent and namespace owner.
Missing/replaced anchors or changed ownership require parent/operator
reconciliation rather than deleting by name.

The required client permissions are `get` on the three known namespaces;
`get/list/create/delete` on proof Pods in the two reserved namespaces;
`get/list/create/delete` on NetworkPolicies in the control namespace; and
`get/list` on subject NetworkPolicies. No Secret, RBAC, ServiceAccount, exec,
logs, port-forward, node, or namespace mutation permission is used.

## Verification boundary

Tests use UID-defaulting fake Kubernetes with enforced delete preconditions,
durable JSON/CAS receipts and fresh adapters after every step. They cover the
positive/negative pair, absent-CNI reachable negatives, missing positives,
forged results, replacement/drift, cancelled contexts, ambiguous creation,
cleanup and resource bounds. Separate real localhost TCP tests prove nonce
exchange, refusal, bounded read timeout, and proxy/DNS avoidance.

These tests do **not** certify a CNI. The parent must qualify the pinned image
and actual CNI on its authorized live cluster before using the proof to admit
subjects. No live-cluster or cloud qualification is performed by this package's
unit suite.
