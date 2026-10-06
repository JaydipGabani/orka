package service

import (
	"context"
	"encoding/json"
	"time"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/controllerlab"
	"github.com/orka-agents/orka/internal/remediation/environment"
	"github.com/orka-agents/orka/internal/remediation/intake"
	"github.com/orka-agents/orka/internal/remediation/investigate"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/store"
)

type ProposalClient interface {
	Snapshot(context.Context) (modelagent.PlanIdentity, error)
	Generate(context.Context, modelagent.Request) (modelagent.Result, error)
	Cancel(context.Context, string, string) error
	Retire(context.Context, string, string) error
}

type ProposalFactory func(namespace, name string, accepted func(context.Context, modelagent.Result) error) ProposalClient

type ExecutionAdapter interface {
	FreezePlan(environment.Plan) (environment.Plan, error)
	Build(context.Context, environment.BuildRequest) (environment.BuildResult, error)
	Start(context.Context, environment.Request) (environment.Receipt, error)
	Observe(context.Context, environment.Receipt) (environment.Observation, error)
	Cancel(context.Context, environment.Receipt) error
	CancelBuild(context.Context, string, string, environment.Plan) error
}

type AdapterSelection struct {
	Name                 string              `json:"name"`
	Kind                 string              `json:"kind,omitempty"`
	Capabilities         []string            `json:"capabilities"`
	Binding              environment.Bind    `json:"binding"`
	Original             environment.Subject `json:"original"`
	Requirements         []string            `json:"requirements,omitempty"`
	RequiredCapabilities []string            `json:"requiredCapabilities,omitempty"`
	// ClusterExclusive comes from the whole frozen policy, never a model.
	ClusterExclusive bool `json:"clusterExclusive,omitempty"`
}

// Exactly one observation contract is present; the binding always identifies
// the separately verified immutable build inputs.
type ExecutionPlan struct {
	Binding    environment.Bind    `json:"binding"`
	HTTP       *environment.Plan   `json:"http,omitempty"`
	Controller *controllerlab.Plan `json:"controller,omitempty"`
}

type ExecutionObservation struct {
	HTTP       *environment.Observation `json:"http,omitempty"`
	Controller *controllerlab.State     `json:"controller,omitempty"`
}

type EnvironmentFactory interface {
	Select(context.Context, Policy, investigate.Plan) (AdapterSelection, ExecutionAdapter, error)
	Resume(context.Context, Policy, AdapterSelection) (ExecutionAdapter, error)
}

type Pipeline struct {
	Source       investigate.Source
	Agents       ProposalFactory
	Environments EnvironmentFactory
	Fetch        func(context.Context, string) (intake.Report, error)
	PollInterval time.Duration
}

type modelOperation struct {
	Name         string                     `json:"name"`
	PromptDigest string                     `json:"promptDigest"`
	Expected     modelagent.PlanIdentity    `json:"expected"`
	UID          string                     `json:"uid,omitempty"`
	Intent       bool                       `json:"intent"`
	Output       *store.RemediationArtifact `json:"output,omitempty"`
	Retired      bool                       `json:"retired"`
}

type executionOperation struct {
	ID            string                     `json:"id"`
	Role          environment.Role           `json:"role"`
	BuildIntent   bool                       `json:"buildIntent"`
	BuildNoEffect *buildNoEffect             `json:"buildNoEffect,omitempty"`
	Build         *store.RemediationArtifact `json:"build,omitempty"`
	Subject       *environment.Subject       `json:"subject,omitempty"`
	Intent        bool                       `json:"intent"`
	Receipt       *environment.Receipt       `json:"receipt,omitempty"`
	Observation   *store.RemediationArtifact `json:"observation,omitempty"`
	Cleaned       bool                       `json:"cleaned"`
	Controller    *controllerOperation       `json:"controller,omitempty"`
}

type pipelineAttempt struct {
	Proposal  *store.RemediationArtifact `json:"proposal,omitempty"`
	Patch     *store.RemediationArtifact `json:"patch,omitempty"`
	Feedback  json.RawMessage            `json:"feedback,omitempty"`
	Operation executionOperation         `json:"operation"`
}

type pipelineState struct {
	Version         int                          `json:"version"`
	Stage           string                       `json:"stage"`
	Report          *store.RemediationArtifact   `json:"report,omitempty"`
	Investigation   *store.RemediationArtifact   `json:"investigation,omitempty"`
	SourcePlan      *store.RemediationArtifact   `json:"sourcePlan,omitempty"`
	Selection       *AdapterSelection            `json:"selection,omitempty"`
	ControllerLease *controllerClusterLease      `json:"controllerLease,omitempty"`
	Checks          *store.RemediationArtifact   `json:"checks,omitempty"`
	CheckFailures   int                          `json:"checkFailures"`
	PlanDigest      string                       `json:"planDigest,omitempty"`
	PlanApproved    bool                         `json:"planApproved"`
	ModelCalls      int                          `json:"modelCalls"`
	ModelIdentity   *modelagent.PlanIdentity     `json:"modelIdentity,omitempty"`
	Models          map[string]modelOperation    `json:"models"`
	PatchReviews    map[string]*patchReviewState `json:"patchReviews,omitempty"`
	Original        executionOperation           `json:"original"`
	Control         executionOperation           `json:"control"`
	Attempts        []pipelineAttempt            `json:"attempts"`
}

type executionResult struct {
	Version      int                   `json:"version"`
	Source       source.Target         `json:"source"`
	ChecksDigest string                `json:"checksDigest"`
	Original     ExecutionObservation  `json:"original"`
	Control      ExecutionObservation  `json:"control"`
	Patched      *ExecutionObservation `json:"patched,omitempty"`
	PatchDigest  string                `json:"patchDigest,omitempty"`
	Conclusion   string                `json:"conclusion"`
}
