// Package environment executes operator-approved remediation primitives.
//
// Config is an operator trust boundary, not a model tool argument. A model may
// propose a Plan; the caller must FreezePlan and durably save its binding before
// requesting a candidate patch. Build and Start only accept that frozen plan.
// Neither a build log nor a subject container can supply observation results.
// A run's first durable operation freezes the binding; later operations cannot
// alter check IDs, expected bytes, source commit, or recipe under that run ID.
//
// The operator installs a read-only recipe catalog once, not a per-incident source
// checkout. CatalogDirectory separates version contexts under RecipeRoot while
// preserving the recipe's original Path and ordered patch paths. New validates
// approved bytes and derives exact upstream commit mappings; RecipeChoices exposes
// only safe selection metadata. MatchTarget never guesses a version or chooses
// between ambiguous recipes. BindRecipe fills the trusted plan binding from an ID.
// SupportedChecks lists implemented primitives, not cluster or scenario readiness;
// unimplemented capabilities remain in NeedsAdapterChecks.
// PublishedOriginal uses the approved recipe's immutable image directly. External
// control/candidate image bindings identify source/recipe/patch inputs, not a
// per-case ChecksDigest. A new case does not require a new operator image entry.
//
// SourceRoot is optional: the executor never reads or copies it. For each build it
// revalidates and privately stages only approved recipe inputs plus the candidate
// patch; the Dalec frontend acquires the full pinned upstream Git commit remotely.
// Source investigation can therefore fetch exact blobs without materializing large
// vendor trees. An altered catalog entry fails digest validation rather than
// silently changing a previously frozen run.
//
// The initial executable observation capability is a hardened, single-container
// Pod observed over plain HTTP by this process. It does not implement Kubernetes
// controller semantics, cloud policy, TLS renewal, event collection, or arbitrary
// test programs. Requests for those primitives fail with NeedsAdapter. The
// operator must provide network reachability to Pod IPs and a dedicated,
// preapproved Kubernetes context; this package never provisions a cluster.
// Its CNI must enforce NetworkPolicy. Each namespace is restricted by Pod Security
// Admission and an adapter-owned policy admitting only operator-specified
// observer CIDRs, with no subject egress. The cluster must not inject additional
// workloads into these dedicated namespaces. Subject images must support a
// non-root, read-only process listening on the approved unprivileged port.
// Use platform-manifest image digests: an unaccounted runtime image ID (including
// a platform image selected from an index) is not accepted as the requested image.
//
// Persist Intent's complete Receipt and Request in the remediation effects store
// before Start, then persist the returned Receipt. After a
// lost acknowledgement use the same Request with RequireExisting set. Never
// invent another OperationID to recover an uncertain operation. Adapter journals
// require persistent, private storage on the remediation database's PV, not an
// emptyDir or container filesystem. They are an executor recovery cache, not a
// replacement for the coordinator's durable effects/budget authority. If this
// cache is missing, Observe and Cancel reconstruct from the parent's saved Receipt
// and exact resource identities; they never create replacement resources or infer
// lost observation results. The parent can sweep terminal/unknown effects by
// calling Cancel with their persisted receipts, not by deleting label matches.
// A new operation for a run is refused
// until the previous operation's UID-fenced cleanup is observed complete.
// OutputRoot must be shared by replicas of this adapter so the process-shared
// allocation lock enforces capacity. Cancel returns nil only after absence is
// observed, not merely after the delete API acknowledges the request.
// Receipts freeze only per-operation execution settings and the authenticated
// lab-cluster UID. Catalog removal, tighter limits, observer-network changes, or
// credential rotation cannot strand an admitted operation's cleanup. A different
// lab cluster is never substituted. Use a distinct RunID derived from the case ID
// and plan revision because each run freezes one Bind.
//
// Build runs a fixed buildctl command, not incident-specific scripts. The
// operator owns the BuildKit endpoint and its worker-option contract. The daemon
// and frontend are trusted build infrastructure, not remote attestation.
// BuildResult preserves incomplete provenance rather than converting a successful
// build into a claim that dependencies or published-image provenance are verified.
// The frontend's exact worker-image argument and its retained qualification
// evidence are mandatory operator inputs. BuildKit must support anonymous output
// publication at the configured repository or supply its own server-side
// credentials: no ambient client credential discovery is enabled. Missing
// buildctl binaries are explicit prerequisite errors, not a fallback to Docker,
// a shell, a cloud build service, or a tag-only external image.
// Worker/cache isolation and live NetworkPolicy enforcement still require
// independent deployment qualification; this package does not prove them from a
// configured digest, metadata JSON, or successful HTTP response. Interrupted
// builds remain Unknown rather than being replayed without coordinator budget and
// executor-settlement authority. Build retry/heartbeat and live isolation canaries
// are not implemented here.
//
// Reproduction checks declare distinct exact Failure and Healthy status/body
// pairs. Normal checks declare Healthy only, on the same resource/port as their
// reproduction check. HTTPResult.Outcome is healthy, failure, or other; arbitrary
// mismatches (including 404s, 500s, and application "passed" flags) are never
// reproduction evidence. Observation.Failure contains executor/infrastructure
// errors, not assertion outcomes. The coordinator requires failure on original
// and rebuilt-control reproduction checks, healthy on candidate reproduction
// checks, healthy on every normal check, complete provenance for its policy, and
// settled cleanup. This package never declares a patch "verified".
package environment
