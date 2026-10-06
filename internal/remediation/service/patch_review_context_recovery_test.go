package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	modelagent "github.com/orka-agents/orka/internal/remediation/agent"
	"github.com/orka-agents/orka/internal/remediation/source"
	"github.com/orka-agents/orka/internal/store"
	"github.com/stretchr/testify/require"
)

type reviewContextCheckpointFault struct {
	store.RemediationRunStore
	match  func(pipelineState) bool
	commit bool
	fired  bool
	fault  error
}

func (s *reviewContextCheckpointFault) UpdateRemediationRun(ctx context.Context, namespace, id, owner string, epoch, revision uint64,
	update store.RemediationUpdate, now time.Time,
) (*store.RemediationRun, error) {
	var state pipelineState
	if s.fired || json.Unmarshal(update.StateJSON, &state) != nil || !s.match(state) {
		return s.RemediationRunStore.UpdateRemediationRun(ctx, namespace, id, owner, epoch, revision, update, now)
	}
	s.fired = true
	if s.commit {
		if _, err := s.RemediationRunStore.UpdateRemediationRun(ctx, namespace, id, owner, epoch, revision, update, now); err != nil {
			return nil, err
		}
	}
	return nil, s.fault
}

func TestPatchReviewContextRecoversEveryCheckpointBoundary(t *testing.T) {
	for _, stage := range []string{"round", "index", "selection", "packet", "review"} {
		for _, committed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/committed=%v", stage, committed), func(t *testing.T) {
				t.Parallel()
				f := newReviewContextFixture(t)
				fault := &reviewContextCheckpointFault{
					RemediationRunStore: f.session.store, commit: committed, fault: errors.New("synthetic checkpoint interruption"),
					match: func(state pipelineState) bool {
						review := state.PatchReviews[Digest(f.patch)]
						if review == nil || len(review.Context) == 0 {
							return false
						}
						round := review.Context[0]
						switch stage {
						case "round":
							return round.Index == nil
						case "index":
							return round.Index != nil && len(round.Paths) == 0
						case "selection":
							return len(round.Paths) != 0 && round.Packet == nil
						case "packet":
							return round.Packet != nil && round.Review == nil
						case "review":
							return round.Review != nil
						}
						return false
					},
				}
				f.session.store = fault
				_, err := f.run(t.Context())
				require.ErrorIs(t, err, fault.fault)
				require.True(t, fault.fired)
				f.resume()
				ref, err := f.run(t.Context())
				require.NoError(t, err)
				require.NotNil(t, ref)
				require.Len(t, f.models.tasks, 3)
				require.Len(t, f.models.requests, 3, "completed model calls are recovered even if the next checkpoint was lost")
				require.Equal(t, 3, f.state.ModelCalls)
				wantInventory, wantPackets := 1, 1
				if stage == "index" && !committed {
					wantInventory++
				}
				if stage == "packet" && !committed {
					wantPackets++
				}
				require.Equal(t, wantInventory, f.source.inventoryCalls)
				require.Equal(t, wantPackets, f.source.packetCalls)
				for _, operation := range f.state.Models {
					task := f.models.tasks[operation.Name]
					require.Equal(t, task.TaskUID, operation.UID)
					require.NotNil(t, operation.Output)
					require.True(t, operation.Retired)
				}
				f.resume()
				again, err := f.run(t.Context())
				require.NoError(t, err)
				require.Equal(t, ref, again)
				require.Len(t, f.models.requests, 3)
			})
		}
	}
}

func TestPatchReviewContextLostModelReplyKeepsAcceptedUID(t *testing.T) {
	for _, stage := range []string{"initial-review", "selection", "augmented-review"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			f := newReviewContextFixture(t)
			var lost modelagent.Result
			f.models.afterAccepted = func(request modelagent.Request, result modelagent.Result) error {
				isSelection := strings.Contains(request.Prompt, "CONTEXT_SELECTION_DATA:\n")
				isAugmented := strings.Contains(request.Prompt, `"supplementalSource":`)
				if lost.TaskUID == "" && ((stage == "selection" && isSelection) ||
					(stage == "initial-review" && !isSelection && !isAugmented) ||
					(stage == "augmented-review" && !isSelection && isAugmented)) {
					lost = result
					return modelagent.ErrDependencyUnavailable
				}
				return nil
			}
			_, err := f.run(t.Context())
			require.ErrorIs(t, err, ErrRetryable)
			require.NotEmpty(t, lost.TaskUID)
			f.resume()
			accepted := false
			for _, operation := range f.state.Models {
				if operation.Name == lost.TaskName {
					require.Equal(t, lost.TaskUID, operation.UID)
					require.Nil(t, operation.Output)
					accepted = true
				}
			}
			require.True(t, accepted)
			ref, err := f.run(t.Context())
			require.NoError(t, err)
			require.NotNil(t, ref)
			require.Len(t, f.models.tasks, 3, "recovery observes the same Task instead of invoking a new model")
			require.Len(t, f.models.requests, 4)
			require.Equal(t, 3, f.state.ModelCalls)
			observations := 0
			for _, request := range f.models.requests {
				if request.TaskName == lost.TaskName {
					observations++
					if observations == 2 {
						require.True(t, request.RequireExisting)
						require.Equal(t, lost.TaskUID, request.ExpectedTaskUID)
					}
				}
			}
			require.Equal(t, 2, observations)
			require.Equal(t, 1, f.source.inventoryCalls)
			require.Equal(t, 1, f.source.packetCalls)
		})
	}
}

func TestPatchReviewContextWaitsForPersistedSourceRetry(t *testing.T) {
	for _, stage := range []string{"inventory", "packet"} {
		for _, lostCheckpointReply := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/lost-checkpoint-reply=%v", stage, lostCheckpointReply), func(t *testing.T) {
				t.Parallel()
				f := newReviewContextFixture(t)
				until := time.Now().UTC().Add(time.Minute).Truncate(time.Second)
				limited := false
				rateLimit := func() error {
					if !limited {
						limited = true
						return fmt.Errorf("synthetic anonymous source response: %w", &source.RateLimitError{RetryAt: until})
					}
					return nil
				}
				if stage == "inventory" {
					f.source.inventory = func(entries []source.Entry) ([]source.Entry, error) { return entries, rateLimit() }
				} else {
					f.source.packet = func(packet source.Packet) (source.Packet, error) { return packet, rateLimit() }
				}
				var fault *reviewContextCheckpointFault
				if lostCheckpointReply {
					fault = &reviewContextCheckpointFault{
						RemediationRunStore: f.session.store, commit: true, fault: errors.New("synthetic lost rate-limit checkpoint reply"),
						match: func(state pipelineState) bool {
							review := state.PatchReviews[Digest(f.patch)]
							return review != nil && len(review.Context) != 0 && !review.Context[0].RetryAt.IsZero()
						},
					}
					f.session.store = fault
				}
				_, err := f.run(t.Context())
				if lostCheckpointReply {
					require.ErrorIs(t, err, fault.fault)
				} else {
					require.ErrorIs(t, err, ErrRetryable)
				}
				inventories, packets, requests := f.source.inventoryCalls, f.source.packetCalls, len(f.models.requests)
				for range 3 {
					f.resume()
					require.Equal(t, until, f.state.PatchReviews[Digest(f.patch)].Context[0].RetryAt)
					_, err := f.run(t.Context())
					require.ErrorIs(t, err, ErrRetryable)
					require.Equal(t, inventories, f.source.inventoryCalls)
					require.Equal(t, packets, f.source.packetCalls)
					require.Len(t, f.models.requests, requests)
				}
				f.state.PatchReviews[Digest(f.patch)].Context[0].RetryAt = time.Now().UTC().Add(-time.Second)
				require.NoError(t, f.pipeline.save(t.Context(), f.session, f.state, f.state.Stage))
				f.resume()
				ref, err := f.run(t.Context())
				require.NoError(t, err)
				require.NotNil(t, ref)
				require.Len(t, f.models.tasks, 3)
				require.Len(t, f.models.requests, 3)
				require.Equal(t, 3, f.state.ModelCalls)
				if stage == "inventory" {
					require.Equal(t, 2, f.source.inventoryCalls)
					require.Equal(t, 1, f.source.packetCalls)
				} else {
					require.Equal(t, 1, f.source.inventoryCalls)
					require.Equal(t, 2, f.source.packetCalls)
				}
				require.True(t, f.state.PatchReviews[Digest(f.patch)].Context[0].RetryAt.IsZero())
			})
		}
	}
}

func TestPatchReviewContextCachedPacketStillRequiresDisclosure(t *testing.T) {
	t.Parallel()
	f := newReviewContextFixture(t)
	_, err := f.run(t.Context())
	require.NoError(t, err)
	f.resume()
	round := &f.state.PatchReviews[Digest(f.patch)].Context[0]
	var packet source.Packet
	require.NoError(t, readJSON(t.Context(), f.session, round.Packet, &packet))
	packet.Files[0] = contextReviewFile("identifier.go", "package dispatcher\n// https://example.invalid/source?token=example-value\n")
	raw := []byte(contextReviewJSON(t, packet))
	// Simulate an older artifact predating shared disclosure enforcement.
	ref, err := f.session.Put(t.Context(), "legacy-review-context.json", "application/json", raw)
	require.NoError(t, err)
	round.Packet = ref
	f.pipeline.Source = nil
	_, err = f.run(t.Context())
	require.ErrorIs(t, err, ErrNeedsInput)
	require.Len(t, f.models.requests, 3)
	require.Equal(t, 1, f.source.inventoryCalls)
	require.Equal(t, 1, f.source.packetCalls)
	require.NotEmpty(t, f.state.PatchReviews[Digest(f.patch)].StopReason)
}

func TestPatchReviewContextCachedApprovalNeedsNoSourceAccess(t *testing.T) {
	t.Parallel()
	f := newReviewContextFixture(t)
	ref, err := f.run(t.Context())
	require.NoError(t, err)
	f.resume()
	f.pipeline.Source = nil
	again, err := f.run(t.Context())
	require.NoError(t, err)
	require.Equal(t, ref, again)
	require.Len(t, f.models.requests, 3)
	require.Equal(t, 1, f.source.inventoryCalls)
	require.Equal(t, 1, f.source.packetCalls)
}
