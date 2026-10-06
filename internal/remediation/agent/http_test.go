package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	corev1alpha1 "github.com/orka-agents/orka/api/v1alpha1"
)

func TestGenerateBoundsHTTPTimeoutAndDoesNotMutateClient(t *testing.T) {
	for _, timeout := range []time.Duration{0, time.Hour, 10 * time.Second} {
		t.Run("timeout", func(t *testing.T) {
			t.Parallel()
			c := scriptedClient(t)
			c.API.HTTPClient.Timeout = timeout
			var redirected atomic.Bool
			c.API.HTTPClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				redirected.Store(true)
				return nil
			}
			wire, _, err := c.prepare(syntheticRequest())
			if err != nil {
				t.Fatal(err)
			}
			want := 30 * time.Second
			if timeout > 0 && timeout < want {
				want = timeout
			}
			if wire.http.Timeout != want || c.API.HTTPClient.Timeout != timeout {
				t.Error("HTTP timeout is not bounded without mutating caller configuration")
			}
			if err := wire.http.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) || redirected.Load() {
				t.Error("adapter must refuse redirects without invoking the caller's redirect policy")
			}
		})
	}
}

func TestGenerateHTTPTimeoutHasBoundedReadAttempts(t *testing.T) {
	t.Parallel()
	request := syntheticRequest()
	task := syntheticTask(request, corev1alpha1.TaskPhasePending)
	steps := make([]responseStep, 0, 4)
	steps = append(steps, taskStep(t, task))
	for range 3 {
		steps = append(steps, responseStep{method: http.MethodGet, serve: func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}})
	}
	c := scriptedClient(t, steps...)
	c.API.HTTPClient.Timeout = 30 * time.Millisecond
	start := time.Now()
	result, err := c.Generate(t.Context(), request)
	if !errors.Is(err, context.DeadlineExceeded) || result.TaskUID != string(task.UID) || result.Output != "" {
		t.Fatalf("HTTP timeouts did not fail with the known Task identity: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Error("read retry budget did not bound timeout handling")
	}
}

func TestGenerateDoesNotFollowRedirects(t *testing.T) {
	t.Parallel()
	var received atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer target.Close()
	c := scriptedClient(t, responseStep{method: http.MethodGet, serve: func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}})
	result, err := c.Generate(t.Context(), syntheticRequest())
	if err == nil || received.Load() != 0 || result.TaskUID != "" {
		t.Error("API redirect must not forward credentials or create a Task")
	}
}

func TestGenerateResultReadRetryBudget(t *testing.T) {
	for _, recover := range []bool{true, false} {
		t.Run("result-retry", func(t *testing.T) {
			t.Parallel()
			request := syntheticRequest()
			task := syntheticTask(request, corev1alpha1.TaskPhaseSucceeded)
			steps := []responseStep{
				taskStep(t, task),
				resultStep(http.StatusTooManyRequests, "synthetic-private-result"),
				resultStep(http.StatusBadGateway, "synthetic-private-result"),
			}
			if recover {
				steps = append(steps, resultStep(http.StatusOK, `{"result":"eventually available"}`), taskStep(t, task))
			} else {
				steps = append(steps, resultStep(http.StatusInternalServerError, "synthetic-private-result"))
			}
			c := scriptedClient(t, steps...)
			result, err := c.Generate(t.Context(), request)
			if recover {
				if err != nil || result.Output != "eventually available" {
					t.Errorf("read-only result retry did not recover: %v", err)
				}
			} else if err == nil || result.TaskUID != string(task.UID) || result.Output != "" {
				t.Fatal("exhausted result retry budget must fail without losing identity")
			} else if strings.Contains(err.Error(), "synthetic-private-result") {
				t.Error("result retry error leaked remote body")
			}
		})
	}
}

func TestGenerateRejectsOversizedContentLength(t *testing.T) {
	t.Parallel()
	c := scriptedClient(t, responseStep{method: http.MethodGet, serve: func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(maxResponseBytes+1))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}})
	if _, err := c.Generate(t.Context(), syntheticRequest()); err == nil {
		t.Fatal("oversized Content-Length must fail before decoding or polling")
	}
}

func TestGenerateDoesNotReplaceDisappearedTask(t *testing.T) {
	t.Parallel()
	request := syntheticRequest()
	task := syntheticTask(request, corev1alpha1.TaskPhasePending)
	c := scriptedClient(t,
		taskStep(t, task),
		responseStep{method: http.MethodGet, status: http.StatusNotFound},
	)
	result, err := c.Generate(t.Context(), request)
	if err == nil || result.TaskUID != string(task.UID) || result.TaskName != request.TaskName {
		t.Fatal("disappeared Task must not trigger another create")
	}
}

func TestGenerateCancellationInterruptsBackoff(t *testing.T) {
	t.Parallel()
	request := syntheticRequest()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c := scriptedClient(t, responseStep{method: http.MethodGet, serve: func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		cancel()
	}})
	c.PollInterval = 30 * time.Second
	start := time.Now()
	result, err := c.Generate(ctx, request)
	if !errors.Is(err, context.Canceled) || result.TaskName != request.TaskName || time.Since(start) > time.Second {
		t.Fatal("cancelled lookup must stop without waiting for the retry interval")
	}
}
