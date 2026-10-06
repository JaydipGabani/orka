package controllerlab

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublishingDuplicateCounterAndCapacityFailuresCannotMeanProtection(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"counter-decreased", "counter-saturated", "admin-capacity", "data-capacity"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			l := newPublishingLab(t)
			r := l.request(Candidate)
			s := l.phase(t, r, ObservingWindow)
			l.observer.mutate = func(o *Observation) { o.DuplicateHTTP = 10 }
			next, err := l.step(s, r)
			require.NoError(t, err)
			require.Equal(t, uint64(10), next.Evidence.DuplicateHTTP)
			s = next
			l.observer.mutate = func(o *Observation) {
				o.DuplicateHTTP = 10
				switch mode {
				case "counter-decreased":
					o.DuplicateHTTP = 9
				case "counter-saturated":
					o.DuplicateHTTP = ^uint64(0)
				case "admin-capacity":
					o.RejectedAdminConnections = 1
				case "data-capacity":
					o.RejectedHTTPConnections = 1
				}
			}
			next, err = l.step(s, r)
			require.Error(t, err)
			require.Equal(t, Cleaning, next.Phase)
			require.Equal(t, Inconclusive, next.Outcome)
			next = l.until(t, next, r, State.Terminal)
			require.Equal(t, Complete, next.Phase)
			require.Equal(t, Inconclusive, next.Outcome)
		})
	}
}
