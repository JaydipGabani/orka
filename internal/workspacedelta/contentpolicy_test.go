package workspacedelta

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCaptureEvaluatesContentPolicyConcurrentlyAndCompletely(t *testing.T) {
	root := t.TempDir()
	const files = 200
	for i := range files {
		content := fmt.Sprintf("file %d\n", i)
		if i%3 == 0 {
			content += "secret marker\n"
		}
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%03d.txt", i)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var inFlight, peak, calls atomic.Int32
	var mu sync.Mutex
	fingerprinted := map[string]struct{}{}
	snapshot, err := Capture(root, Options{
		ContentFlagger: func(content []byte) bool {
			calls.Add(1)
			current := inFlight.Add(1)
			defer inFlight.Add(-1)
			for {
				observed := peak.Load()
				if current <= observed || peak.CompareAndSwap(observed, current) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			return len(content) > len("file 000\n")
		},
		ContentFingerprinter: func(content []byte) []string {
			mu.Lock()
			defer mu.Unlock()
			fingerprinted[string(content)] = struct{}{}
			return []string{"fp:" + string(content)}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != files {
		t.Fatalf("flagger ran %d times, want %d", got, files)
	}
	if workers := int32(runtime.GOMAXPROCS(0)); peak.Load() > workers {
		t.Fatalf("peak concurrent flagger calls = %d, want at most GOMAXPROCS (%d)", peak.Load(), workers)
	} else if workers > 1 && peak.Load() < 2 {
		t.Fatalf("flagger never ran concurrently with GOMAXPROCS=%d", workers)
	}
	for i := range files {
		path := fmt.Sprintf("f%03d.txt", i)
		wantFlagged := i%3 == 0
		if got := snapshot.BaselineContentFlagged(path); got != wantFlagged {
			t.Fatalf("%s flagged = %v, want %v", path, got, wantFlagged)
		}
		content := fmt.Sprintf("file %d\nsecret marker\n", i)
		fingerprints := snapshot.BaselineContentFingerprints(path)
		if wantFlagged && (len(fingerprints) != 1 || fingerprints[0] != "fp:"+content) {
			t.Fatalf("%s fingerprints = %v", path, fingerprints)
		}
		if !wantFlagged && fingerprints != nil {
			t.Fatalf("%s unflagged fingerprints = %v", path, fingerprints)
		}
	}
	if len(fingerprinted) != (files+2)/3 {
		t.Fatalf("fingerprinter ran for %d files, want only the %d flagged ones", len(fingerprinted), (files+2)/3)
	}
}

func TestCaptureContentPolicyStopsOnCancellation(t *testing.T) {
	root := t.TempDir()
	for i := range 50 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%02d.txt", i)), []byte("content\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := CaptureContext(ctx, root, Options{ContentFlagger: func([]byte) bool {
			calls.Add(1)
			cancel()
			return true
		}})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("CaptureContext() error = %v, want context.Canceled", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("capture did not return after cancellation")
	}
	if calls.Load() == 0 {
		t.Fatal("flagger never ran")
	}
}

func TestCaptureContentPolicyDoesNotRunAfterWalkFailure(t *testing.T) {
	root := t.TempDir()
	for i := range 20 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("f%02d.txt", i)), []byte("content\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A reserved path component fails the walk part-way through.
	if err := os.WriteFile(filepath.Join(root, ".orka-artifacts"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	_, err := Capture(root, Options{ContentFlagger: func([]byte) bool {
		calls.Add(1)
		time.Sleep(5 * time.Millisecond)
		return true
	}})
	if !errors.Is(err, ErrReservedPath) {
		t.Fatalf("Capture() error = %v, want ErrReservedPath", err)
	}
	if calls.Load() > int32(runtime.GOMAXPROCS(0))*2 {
		t.Fatalf("flagger kept running after the walk failed: %d calls", calls.Load())
	}
}
