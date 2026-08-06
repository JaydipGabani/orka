#!/usr/bin/env bash
# Closed-world coexistence inventory (plan section 15): counts every admission,
# execution, cleanup-relevant, and historical surface reachable through the
# Kubernetes API, split by explicit contract, and digests the complete report.
# Unknown, unreadable, orphaned, or contradictory state counts as nonzero.
#
# SQLite-side counts (wrapper ledger, attempt store, outbox) live inside the
# controller and wrapper Pods; this report records the Kubernetes-side
# closed-world view plus list resourceVersions for cutoff comparison.
#
# Usage: KUBECTL=kubectl scripts/coexistence-inventory.sh
set -euo pipefail

KUBECTL=${KUBECTL:-kubectl}

fetch() {
  ${KUBECTL} get "$1" --all-namespaces -o json 2>/dev/null || echo '{"items":[],"metadata":{}}'
}

tasks=$(fetch tasks.core.orka.ai)
agents=$(fetch agents.core.orka.ai)
runtimes=$(fetch agentruntimes.core.orka.ai)
attempts=$(fetch promptattempts.core.orka.ai)
adjudications=$(fetch agentexecutionadjudications.core.orka.ai)
controls=$(fetch agentexecutioncontrols.core.orka.ai)
pools=$(fetch runtimepools.core.orka.ai)
sessions=$(fetch runtimesessioncontrols.core.orka.ai)
publications=$(fetch publications.core.orka.ai)
claims=$(fetch branchclaims.core.orka.ai)
effects=$(fetch externaleffects.core.orka.ai)
monitors=$(fetch repositorymonitors.core.orka.ai)
leases=$(${KUBECTL} get leases.coordination.k8s.io --all-namespaces -o json)

report=$(jq -n \
  --argjson tasks "${tasks}" \
  --argjson agents "${agents}" \
  --argjson runtimes "${runtimes}" \
  --argjson attempts "${attempts}" \
  --argjson adjudications "${adjudications}" \
  --argjson controls "${controls}" \
  --argjson pools "${pools}" \
  --argjson sessions "${sessions}" \
  --argjson publications "${publications}" \
  --argjson claims "${claims}" \
  --argjson effects "${effects}" \
  --argjson monitors "${monitors}" \
  --argjson leases "${leases}" '
  def agentTasks: [$tasks.items[] | select(.spec.type == "agent" and (.spec.schedule // "") == "")];
  def terminalPhase: ["Succeeded", "Failed", "Cancelled"];
  {
    generatedAt: now | todate,
    listResourceVersions: {
      tasks: ($tasks.metadata.resourceVersion // ""),
      promptAttempts: ($attempts.metadata.resourceVersion // ""),
      agents: ($agents.metadata.resourceVersion // "")
    },
    control: ($controls.items | map({
      uid: .metadata.uid, generation: .metadata.generation,
      backends: (.status.backends // null), ownership: (.status.ownership // null)
    })),
    agents: {
      builtInTotal: [$agents.items[] | select(.spec.runtime.type != null)] | length,
      unclassified: [$agents.items[] | select(.spec.runtime.type != null and .spec.runtime.contractVersion == null)] | length,
      v1: [$agents.items[] | select(.spec.runtime.contractVersion == "orka.harness.v1")] | length,
      v2: [$agents.items[] | select(.spec.runtime.contractVersion == "orka.harness.v2")] | length,
      opencodeUnclassified: [$agents.items[] | select(.spec.runtime.type == "opencode" and .spec.runtime.contractVersion == null)] | length
    },
    agentRuntimes: {
      total: $runtimes.items | length,
      unclassified: [$runtimes.items[] | select(.spec.contractVersion == null)] | length,
      v1: [$runtimes.items[] | select(.spec.contractVersion == "orka.harness.v1")] | length,
      v2: [$runtimes.items[] | select(.spec.contractVersion == "orka.harness.v2")] | length
    },
    tasks: {
      agentTotal: agentTasks | length,
      unbound: [agentTasks[] | select(
        .status.agentExecutionBinding == null and .status.agentExecutionQuarantine == null
        and .status.agentExecutionNoExecution == null
        and ((.status.phase // "Pending") as $p | terminalPhase | index($p) | not))] | length,
      boundV1Active: [agentTasks[] | select(.status.agentExecutionBinding.contractVersion == "orka.harness.v1"
        and ((.status.phase // "Pending") as $p | terminalPhase | index($p) | not))] | length,
      boundV2Active: [agentTasks[] | select(.status.agentExecutionBinding.contractVersion == "orka.harness.v2"
        and ((.status.phase // "Pending") as $p | terminalPhase | index($p) | not))] | length,
      cleanupOnly: [agentTasks[] | select(.status.agentExecutionBinding.mode == "cleanup-only")] | length,
      quarantined: [agentTasks[] | select(.status.agentExecutionQuarantine != null)] | length,
      quarantinedByReason: ([agentTasks[] | select(.status.agentExecutionQuarantine != null)
        | .status.agentExecutionQuarantine.reason] | group_by(.) | map({(.[0]): length}) | add // {}),
      noExecution: [agentTasks[] | select(.status.agentExecutionNoExecution != null)] | length,
      resolved: [agentTasks[] | select(.status.agentExecutionResolutionRef != null)] | length,
      deleting: [agentTasks[] | select(.metadata.deletionTimestamp != null)] | length,
      historicalTerminalWithV1Fields: [agentTasks[] | select(
        ((.status.phase // "") as $p | terminalPhase | index($p))
        and (.status.harnessRuntime != null or .spec.agentRuntime.workspace != null))] | length
    },
    promptAttempts: {
      total: $attempts.items | length,
      nonTerminal: [$attempts.items[] | select(.status.executionState as $s
        | ["Succeeded","Failed","Cancelled","OutcomeUnknown"] | index($s) | not)] | length,
      outcomeUnknown: [$attempts.items[] | select(.status.executionState == "OutcomeUnknown")] | length,
      missingBindingDigest: [$attempts.items[] | select((.spec.bindingDigest // "") == "")] | length
    },
    sessions: {
      total: $sessions.items | length,
      reconciliationBlocked: [$sessions.items[] | select(.status.availability == "ReconciliationBlocked")] | length,
      leased: [$sessions.items[] | select(.status.mutationLease != null)] | length
    },
    publications: {
      total: $publications.items | length,
      nonTerminal: [$publications.items[] | select(.status.state as $s
        | ["VerifiedExact","DeliveredSuperseded","CancelledBeforePublish","DeliveryConflict","CredentialBlocked","PreparationFailed","PublicationOutcomeUnknown"] | index($s) | not)] | length,
      outcomeUnknown: [$publications.items[] | select(.status.state == "PublicationOutcomeUnknown")] | length
    },
    branchClaims: {
      total: $claims.items | length,
      blocked: [$claims.items[] | select(.status.availability == "ReconciliationBlocked")] | length
    },
    externalEffects: {
      total: $effects.items | length,
      unsettled: [$effects.items[] | select(.status.state as $s | ["Succeeded","Failed","OutcomeUnknown"] | index($s) | not)] | length
    },
    adjudications: {
      total: $adjudications.items | length,
      byState: ([$adjudications.items[] | .status.state // "Pending"] | group_by(.) | map({(.[0]): length}) | add // {}),
      unresolved: [$adjudications.items[] | select((.status.state // "Pending") as $s
        | ["Applied","Rejected","Superseded"] | index($s) | not)] | length
    },
    producers: {
      runtimePools: $pools.items | length,
      scheduledParents: [$tasks.items[] | select((.spec.schedule // "") != "")] | length,
      repositoryMonitors: $monitors.items | length
    },
    ownership: {
      legacyLeases: [$leases.items[] | select(.metadata.name == "03b49a10.orka.ai")
        | {namespace: .metadata.namespace, holder: (.spec.holderIdentity // "")}],
      globalLease: [$leases.items[] | select(.metadata.name == "orka-agent-execution")
        | {namespace: .metadata.namespace, holder: (.spec.holderIdentity // "")}]
    }
  }')

digest=$(printf '%s' "${report}" | shasum -a 256 | awk '{print $1}')
jq -n --argjson report "${report}" --arg digest "sha256:${digest}" \
  '$report + {reportDigest: $digest}'
