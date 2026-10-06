package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

func TestFinalArtifactsRequireSuccessfulRunEvenWhenAlreadyPersisted(t *testing.T) {
	for _, tt := range []struct {
		name    string
		failure error
		phase   string
	}{
		{"successful", nil, store.RemediationPhaseSucceeded},
		{"running", ErrRetryable, store.RemediationPhaseRunning},
		{"needs-input", ErrNeedsInput, store.RemediationPhaseNeedsInput},
		{"failed", ErrAttemptFailed, store.RemediationPhaseFailed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			final := map[string][]byte{
				"candidate.patch":                  []byte("synthetic candidate"),
				"verification-0123456789abcd.json": []byte(`{"conclusion":"Verified for these checks"}`),
			}
			service, storage := testService(t, processorFunc{
				run: func(ctx context.Context, session *Session) error {
					for name, content := range final {
						mediaType := "application/json"
						if name == "candidate.patch" {
							mediaType = "text/x-diff"
						}
						_, err := session.Put(ctx, name, mediaType, content)
						require.NoError(t, err)
					}
					_, err := session.Put(ctx, "candidate-0-failure.json", "application/json", []byte(`{"code":"candidate-build-failed"}`))
					require.NoError(t, err)
					if tt.failure != nil {
						return tt.failure
					}
					return session.Checkpoint(ctx, store.RemediationPhaseSucceeded, "", json.RawMessage(`{"stage":"verified"}`), "")
				},
			})
			run, _, err := service.Submit(t.Context(), "testing", "caller", requestFixture())
			require.NoError(t, err)
			require.NoError(t, service.RunOnce(t.Context()))
			status, err := service.Get(t.Context(), "testing", run.ID)
			require.NoError(t, err)
			require.Equal(t, tt.phase, status.Phase)
			names := make([]string, 0, len(status.Artifacts))
			for _, artifact := range status.Artifacts {
				names = append(names, artifact.Name)
			}
			for name, expected := range final {
				_, durable, err := storage.GetRemediationArtifact(t.Context(), "testing", run.ID, name)
				require.NoError(t, err, "the staged artifact must actually exist")
				require.Equal(t, expected, durable)
				_, downloaded, err := service.Artifact(t.Context(), "testing", run.ID, name)
				if tt.phase == store.RemediationPhaseSucceeded {
					require.Contains(t, names, name)
					require.NoError(t, err)
					require.Equal(t, expected, downloaded)
				} else {
					require.NotContains(t, names, name)
					require.ErrorIs(t, err, store.ErrNotFound)
					require.Empty(t, downloaded)
				}
			}
			require.Contains(t, names, "candidate-0-failure.json")
			_, evidence, err := service.Artifact(t.Context(), "testing", run.ID, "candidate-0-failure.json")
			require.NoError(t, err)
			require.NotEmpty(t, evidence)
			_, _, err = service.Artifact(t.Context(), "foreign", run.ID, "candidate.patch")
			require.ErrorIs(t, err, store.ErrNotFound)
		})
	}
}
