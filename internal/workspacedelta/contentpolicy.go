package workspacedelta

import (
	"context"
	"runtime"
	"sync"

	"golang.org/x/sync/semaphore"
)

// contentPolicyInFlightBytes bounds the file content held in memory for
// queued and running content-policy evaluations. A single file larger than
// the bound is still evaluated, on its own.
const contentPolicyInFlightBytes int64 = 64 << 20

type contentPolicyJob struct {
	path    string
	content []byte
}

type contentPolicyVerdict struct {
	flagged      bool
	fingerprints []string
}

// contentPolicyPool evaluates the capture ContentFlagger and
// ContentFingerprinter on GOMAXPROCS worker goroutines. The heuristics are
// CPU-bound while the workspace walk is I/O-bound, so running them behind the
// walk instead of inline lets a baseline capture use every CPU the runtime is
// allowed. Verdicts are keyed by workspace-relative path and applied to the
// snapshot after the walk, so the snapshot itself never sees the concurrency.
type contentPolicyPool struct {
	options  normalizedOptions
	ctx      context.Context
	cancel   context.CancelFunc
	jobs     chan contentPolicyJob
	inFlight *semaphore.Weighted
	workers  sync.WaitGroup

	mu       sync.Mutex
	verdicts map[string]contentPolicyVerdict
}

func newContentPolicyPool(ctx context.Context, options normalizedOptions) *contentPolicyPool {
	workers := runtime.GOMAXPROCS(0)
	ctx, cancel := context.WithCancel(ctx)
	pool := &contentPolicyPool{
		options:  options,
		ctx:      ctx,
		cancel:   cancel,
		jobs:     make(chan contentPolicyJob, workers),
		inFlight: semaphore.NewWeighted(contentPolicyInFlightBytes),
		verdicts: map[string]contentPolicyVerdict{},
	}
	pool.workers.Add(workers)
	for range workers {
		go pool.work()
	}
	return pool
}

func (p *contentPolicyPool) work() {
	defer p.workers.Done()
	for job := range p.jobs {
		if p.ctx.Err() == nil {
			verdict := evaluateContentPolicy(p.options, job.content)
			p.mu.Lock()
			p.verdicts[job.path] = verdict
			p.mu.Unlock()
		}
		p.inFlight.Release(contentPolicyWeight(job.content))
	}
}

// submit queues content for evaluation. It blocks while the in-flight byte
// budget is exhausted and fails once the capture context is cancelled.
// content must not be modified after submission.
func (p *contentPolicyPool) submit(path string, content []byte) error {
	weight := contentPolicyWeight(content)
	if err := p.inFlight.Acquire(p.ctx, weight); err != nil {
		return err
	}
	select {
	case p.jobs <- contentPolicyJob{path: path, content: content}:
		return nil
	case <-p.ctx.Done():
		p.inFlight.Release(weight)
		return p.ctx.Err()
	}
}

func contentPolicyWeight(content []byte) int64 {
	return min(max(int64(len(content)), 1), contentPolicyInFlightBytes)
}

// close stops accepting work and waits for every queued evaluation. Cancel
// first to discard queued work instead of evaluating it.
func (p *contentPolicyPool) close() map[string]contentPolicyVerdict {
	close(p.jobs)
	p.workers.Wait()
	p.cancel()
	return p.verdicts
}

// evaluateContentPolicy runs the flagger and, only for flagged content, the
// fingerprinter: fingerprints only ever exempt content the baseline already
// flagged, so unflagged files skip the (comparatively expensive) pass.
func evaluateContentPolicy(options normalizedOptions, content []byte) contentPolicyVerdict {
	var verdict contentPolicyVerdict
	if options.contentFlagger != nil {
		verdict.flagged = options.contentFlagger(content)
	}
	if options.contentFingerprinter != nil && (options.contentFlagger == nil || verdict.flagged) {
		verdict.fingerprints = options.contentFingerprinter(content)
	}
	return verdict
}
