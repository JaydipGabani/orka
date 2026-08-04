# KD6 OMS draft v0.1.0 Level 1 compatibility

## Target

Orka targets the KD6 Open Memory Service draft at immutable source revision
`042cff94bf82e92dea3a47f181121fd9cdcbc434` (document version `0.1.0`,
dated May 24, 2026).

The compatibility surface follows the JSON models and HTTP behavior of the KD6
reference server at that revision where the prose specification is incomplete.
A compatibility claim always names this revision; it never follows mutable
`main` implicitly.

## Architecture

The existing `orka.oms.v0alpha1` profile remains the private Orka governance
protocol. Its ownership claims, routing fences, durable operation lookup,
generation/delete fences, and restart-safe pagination are not weakened or
redefined by Level 1 compatibility.

The KD6 adapter exposes an opt-in native OMS Level 1 facade. The facade is a
strict, authenticated reverse proxy to a separately authenticated, HTTPS KD6
OMS endpoint. It forwards only the pinned Level 1 route set and identity headers
and never forwards the caller's bearer token downstream. This keeps the public
interoperability surface separate from the private governance surface while
allowing both to share one deployment and trust boundary.

The facade is disabled by default. Enabling it is an explicit statement that
the configured downstream KD6 service implements the pinned Level 1 contract.
The adapter does not manufacture capabilities that the downstream service does
not provide.

## Level 1 route set

| Method | Path | Requirement |
| --- | --- | --- |
| `GET` | `/health` | Service liveness and version |
| `GET` | `/capabilities` | Provider capability discovery |
| `POST`, `GET` | `/v1/stores` | Create and list tenant stores |
| `GET`, `PATCH`, `DELETE` | `/v1/stores/{store_name}` | Read, update, and delete one immutable-name store |
| `POST`, `GET` | `/v1/stores/{store_name}/memories` | Create/upsert and list memories |
| `GET`, `PATCH`, `DELETE` | `/v1/stores/{store_name}/memories/{memory_id}` | Memory item CRUD |
| `POST` | `/v1/stores/{store_name}/search` | Vector/semantic search with metadata filters |

No lifecycle, inheritance, shared-space, audit, graph, batch, GDPR, or other
Level 2/3 route is included in the Level 1 allowlist.

## Identity and authentication

- Every request to the facade first passes a dedicated Level 1 inbound
  bearer-token authentication realm; the private Orka token is not accepted.
- One facade credential is bound at startup to one canonical tenant and agent
  identity. Caller-supplied identity headers must match that binding exactly.
- Store, memory, and search routes require safe, non-empty `X-Tenant-ID` and
  `X-Agent-ID` values.
- The adapter injects a separately configured downstream KD6 bearer token on
  the native request.
- The inbound `Authorization` value, cookies, forwarding headers, and arbitrary
  caller headers are never relayed downstream.
- Missing or malformed identity fails before any downstream request.
- Tenant isolation is proven by black-box conformance tests showing that a
  credential cannot select a tenant other than its configured binding.

## Required behavior

The black-box Level 1 suite proves at least:

1. authentication is required;
2. tenant and agent identity are required for data routes;
3. store create/get/list/update/delete works and names remain immutable;
4. stores are isolated by tenant;
5. plain string memory create/get/list/update/delete works;
6. `upsert_key` atomically updates the existing logical memory, preserves its
   identifier, and increments its version;
7. semantic/vector search returns scored results;
8. tag and owner filters are applied as part of search selection;
9. capability discovery advertises the features used by the proof; and
10. a successful conformance run verifies that all fixtures are cleaned up.

A transparent facade passes only when the configured downstream KD6 service
passes the same suite. Passing the private `orka.oms.v0alpha1` suite is not
substituted for this proof.

## Non-goals

- Replacing or weakening `orka.oms.v0alpha1`.
- Treating `MemoryBackend` Kubernetes resources as caller-owned OMS stores.
- Forwarding production credentials or raw caller authorization to KD6.
- Claiming Level 2 or Level 3 support.
- Claiming compatibility with an unpinned future KD6 revision.
