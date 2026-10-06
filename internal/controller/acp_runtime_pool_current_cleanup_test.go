package controller

import (
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
	harnessv2 "github.com/orka-agents/orka/internal/harness/v2"
	"github.com/stretchr/testify/require"
)

func TestACPCurrentEpochRetiresAbandonedStandalonePrompt(t *testing.T) {
	for _, state := range []harnessv2.RuntimeSessionState{
		harnessv2.RuntimeSessionStateValidating,
		harnessv2.RuntimeSessionStatePromptRunning,
	} {
		t.Run(string(state), func(t *testing.T) {
			f := newACPRuntimePoolCleanupFixture(t, false, false)
			task := f.currentTask(t)
			attemptID, err := promptAttemptIDFromTask(task)
			require.NoError(t, err)
			fence, err := f.dispatcher.Epochs.CurrentFence(f.ctx)
			require.NoError(t, err)
			require.NoError(t, f.dispatcher.persistOutcomeUnknown(f.ctx, attemptID, fence, "Cancelled", "synthetic cancelled prompt"))
			require.NoError(t, f.dispatcher.failTask(f.ctx, task,
				corev1alpha1.TaskExecutionStateOutcomeUnknown, corev1alpha1.TaskExecutionOutcomeOutcomeUnknown,
				"Cancelled", "synthetic cancelled prompt"))
			f.runtime.mu.Lock()
			f.runtime.blockCleanup = false
			if state == harnessv2.RuntimeSessionStatePromptRunning {
				f.runtime.probe.Status.Sessions[0].State = state
				f.runtime.probe.Status.Sessions[0].ActivePromptID = f.runtime.promptID
				f.runtime.probe.Status.ActivePrompts = []harnessv2.ActivePromptStatus{{
					RuntimeSessionUID: f.runtime.sessionUID, SessionGeneration: 1, TaskUID: f.runtime.taskUID,
					TaskAttempt: 1, PromptID: f.runtime.promptID, LeaseExpiresAt: time.Now().UTC().Add(time.Minute),
					FrameSequence: 1, StartedAt: time.Now().UTC(),
				}}
				f.runtime.probe.Status.Pressure.ActivePrompts = 1
			}
			f.runtime.mu.Unlock()
			if state == harnessv2.RuntimeSessionStatePromptRunning {
				complete, err := f.dispatcher.cleanupRecoveredTaskScopedRuntimeSession(f.ctx, f.currentTask(t))
				require.False(t, complete, "active cancellation must settle before retirement")
				require.ErrorContains(t, err, string(harnessv2.ErrorCodeAlreadyAccepted))
				require.Empty(t, f.currentTask(t).Status.Execution.RuntimeSessionCleanupDigest)
			}
			complete, err := f.dispatcher.cleanupRecoveredTaskScopedRuntimeSession(f.ctx, f.currentTask(t))
			require.NoError(t, err)
			require.True(t, complete)
			require.NotEmpty(t, f.currentTask(t).Status.Execution.RuntimeSessionCleanupDigest)
			f.runtime.mu.Lock()
			defer f.runtime.mu.Unlock()
			require.Zero(t, f.runtime.promptCalls)
			require.Zero(t, f.runtime.wrongFences)
			require.Empty(t, f.runtime.probe.Status.Sessions)
			require.Zero(t, f.runtime.probe.Status.Pressure.LiveDescendants)
		})
	}
}

func TestACPCurrentEpochDoesNotAbandonAnUnsettledPrompt(t *testing.T) {
	f := newACPRuntimePoolCleanupFixture(t, false, false)
	complete, err := f.dispatcher.cleanupRecoveredTaskScopedRuntimeSession(f.ctx, f.currentTask(t))
	require.NoError(t, err)
	require.False(t, complete)
	require.Empty(t, f.currentTask(t).Status.Execution.RuntimeSessionCleanupDigest)
	f.runtime.mu.Lock()
	defer f.runtime.mu.Unlock()
	require.Zero(t, f.runtime.deleteCalls)
}

func TestACPCurrentEpochWorkspacePoolKeepsExistingWait(t *testing.T) {
	f := newACPRuntimePoolCleanupFixture(t, false, false)
	task := f.currentTask(t)
	attemptID, err := promptAttemptIDFromTask(task)
	require.NoError(t, err)
	fence, err := f.dispatcher.Epochs.CurrentFence(f.ctx)
	require.NoError(t, err)
	require.NoError(t, f.dispatcher.persistOutcomeUnknown(f.ctx, attemptID, fence, "Cancelled", "synthetic cancelled prompt"))
	require.NoError(t, f.dispatcher.failTask(f.ctx, task,
		corev1alpha1.TaskExecutionStateOutcomeUnknown, corev1alpha1.TaskExecutionOutcomeOutcomeUnknown,
		"Cancelled", "synthetic cancelled prompt"))
	pool := runtimePoolTestGetPool(t, f.pools, f.pool)
	config, err := f.pools.runtimePoolConfig(&pool)
	require.NoError(t, err)
	config.labels[runtimePoolNetworkRoleLabel] = "provider-client"
	pool.Spec.ExecutionWorkspace = &corev1alpha1.RuntimePoolExecutionWorkspaceSpec{
		Provider: corev1alpha1.WorkspaceProviderAgentSandbox, BindingDigest: testControlDigestForDispatcher("workspace"),
		AgentSandbox: &corev1alpha1.RuntimePoolAgentSandboxWorkspaceSpec{},
	}
	require.NoError(t, f.pools.Update(f.ctx, &pool))
	auth, _, err := f.pools.ensureRuntimePoolSecrets(f.ctx, &pool, config)
	require.NoError(t, err)
	f.runtime.mu.Lock()
	f.runtime.auth = auth
	before := f.runtime.mutationCalls
	f.runtime.mu.Unlock()
	complete, err := f.dispatcher.cleanupRecoveredTaskScopedRuntimeSession(f.ctx, f.currentTask(t))
	require.NoError(t, err)
	require.False(t, complete)
	require.Empty(t, f.currentTask(t).Status.Execution.RuntimeSessionCleanupDigest)
	f.runtime.mu.Lock()
	defer f.runtime.mu.Unlock()
	require.Equal(t, before, f.runtime.mutationCalls)
}
