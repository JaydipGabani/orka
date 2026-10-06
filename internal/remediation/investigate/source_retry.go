package investigate

import (
	"errors"
	"time"

	"github.com/orka-agents/orka/internal/remediation/source"
)

var ErrSourceDeferred = errors.New("anonymous source access is awaiting its rate-limit reset")

func deferRateLimitedSource(state State, err error) (State, bool) {
	var limited *source.RateLimitError
	if !errors.As(err, &limited) || limited.RetryAt.IsZero() {
		return state, false
	}
	state.SourceRetryAt = limited.RetryAt.UTC()
	state.SafeError = "source_rate_limited"
	return state, true
}

func validSourceRetry(state State) bool {
	if state.SourceRetryAt.IsZero() {
		return true
	}
	return (state.Stage == Resolving || state.Stage == Inventory || state.Stage == Packet) &&
		!state.SourceRetryAt.After(time.Now().UTC().Add(time.Hour+time.Minute))
}

func selectionBytes(entries []source.Entry, paths []string) int64 {
	selected := make(map[string]bool, len(paths))
	for _, path := range paths {
		selected[path] = true
	}
	var total int64
	for _, entry := range entries {
		if selected[entry.Path] {
			total += entry.Size
		}
	}
	return total
}
