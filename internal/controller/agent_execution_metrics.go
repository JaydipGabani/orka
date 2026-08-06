/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Coexistence observability: every label is a bounded enum; Task, Session,
// user, repository, endpoint, and Secret identifiers never label metrics.
var (
	agentExecutionBindingFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "orka_agent_binding_failures_total",
		Help: "Agent execution binding stage failures by bounded reason.",
	}, []string{"reason"})

	agentExecutionBindingConflicts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "orka_agent_binding_conflicts_total",
		Help: "Write-once binding conflicts and demand/binding digest mismatches.",
	}, []string{"reason"})

	agentExecutionQuarantinedActive = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "orka_agent_quarantined_active",
		Help: "Quarantined agent Tasks awaiting adjudication by bounded reason.",
	}, []string{"reason"})

	agentExecutionModeRevision = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "orka_agent_mode_revision",
		Help: "Current backend admission mode revision by contract and effective mode.",
	}, []string{"contract_version", "mode"})

	agentExecutionAdjudicationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "orka_agent_adjudications_total",
		Help: "Adjudication applications by action and terminal result.",
	}, []string{"action", "result"})

	agentExecutionLineageConflicts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "orka_agent_session_lineage_conflicts_total",
		Help: "Rejected Session lineage claims by bounded reason.",
	}, []string{"reason"})

	agentExecutionV1Admissions = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "orka_agent_v1_admissions_total",
		Help: "Admitted harness v1 Tasks by bounded runtime class.",
	}, []string{"runtime_class"})
)

func init() {
	metrics.Registry.MustRegister(
		agentExecutionBindingFailures,
		agentExecutionBindingConflicts,
		agentExecutionQuarantinedActive,
		agentExecutionModeRevision,
		agentExecutionAdjudicationsTotal,
		agentExecutionLineageConflicts,
		agentExecutionV1Admissions,
	)
}
