package kd6adapter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/orka-agents/orka/internal/oms/protocol"
)

type instrumentedSearchPageStore struct {
	ContentStore
	delay    time.Duration
	response func(ContentSearchPageRequest) []ContentRecord

	mu       sync.Mutex
	calls    int
	requests [][]ContentDescriptor
}

func (s *instrumentedSearchPageStore) ReadSearchPage(
	ctx context.Context,
	request ContentSearchPageRequest,
) ([]ContentRecord, error) {
	s.mu.Lock()
	s.calls++
	s.requests = append(s.requests, append([]ContentDescriptor(nil), request.Entries...))
	s.mu.Unlock()
	if s.delay > 0 {
		timer := time.NewTimer(s.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.response == nil {
		return []ContentRecord{}, nil
	}
	return cloneContentRecords(s.response(request)), nil
}

func (s *instrumentedSearchPageStore) stats() (int, [][]ContentDescriptor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	requests := make([][]ContentDescriptor, len(s.requests))
	for i := range s.requests {
		requests[i] = append([]ContentDescriptor(nil), s.requests[i]...)
	}
	return s.calls, requests
}

func cloneContentRecords(records []ContentRecord) []ContentRecord {
	cloned := make([]ContentRecord, len(records))
	for i := range records {
		cloned[i] = records[i]
		cloned[i].Tags = append([]string(nil), records[i].Tags...)
		cloned[i].Attributes = cloneStringMap(records[i].Attributes)
	}
	return cloned
}

func providerPageFixtures(count int) (protocol.Binding, []ContentDescriptor, []ContentRecord) {
	binding := protocol.Binding{
		ClusterID: "cluster-a", NamespaceUID: "11111111-1111-4111-8111-111111111111",
		BackendUID: "22222222-2222-4222-8222-222222222222", AuthorityEpoch: 1, RoutingEpoch: 1,
		StoreUUID: "44444444-4444-4444-8444-444444444444",
	}
	binding.TenantID = protocol.DeriveTenantID(binding.ClusterID, binding.NamespaceUID)
	now := time.Date(2026, 8, 1, 20, 0, 0, 0, time.UTC)
	entries := make([]ContentDescriptor, count)
	records := make([]ContentRecord, count)
	for i := range count {
		memoryID := fmt.Sprintf("mem-page-%02d", i)
		content := fmt.Sprintf("content-%02d", i)
		digest := protocol.ContentDigest(content)
		entries[i] = ContentDescriptor{
			UpsertKey: protocol.CanonicalUpsertKey(binding, memoryID), ProviderID: fmt.Sprintf("provider-%02d", i),
			Version: fmt.Sprintf("version-%02d", i), MemoryID: memoryID, Generation: 1,
			ContentDigest: digest, UpdatedAt: now.Add(time.Duration(i) * time.Second), Score: float64(i + 1),
		}
		records[i] = ContentRecord{
			UpsertKey: entries[i].UpsertKey, ProviderID: entries[i].ProviderID, Version: entries[i].Version,
			Text: content, Tags: []string{}, Attributes: map[string]string{},
			Scope:     scopeForMutation(binding, memoryID, entries[i].Generation, digest),
			SourceURI: sourceURI(binding, memoryID), UpdatedAt: entries[i].UpdatedAt,
		}
	}
	return binding, entries, records
}

func TestReadProviderPageBatchesCompleteOrderedSliceOnce(t *testing.T) {
	binding, entries, records := providerPageFixtures(protocol.MaxPageSize)
	const delay = 100 * time.Millisecond
	store := &instrumentedSearchPageStore{
		delay: delay,
		response: func(ContentSearchPageRequest) []ContentRecord {
			return records
		},
	}
	started := time.Now()
	page, err := readProviderPage(context.Background(), store, binding, "provider-store", "snapshot-a", entries)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	calls, requests := store.stats()
	if calls != 1 || len(requests) != 1 || len(requests[0]) != len(entries) {
		t.Fatalf("provider calls/requests/entries = %d/%d/%d, want 1/1/%d", calls, len(requests), len(requests[0]), len(entries))
	}
	for i := range entries {
		if !contentDescriptorIdentityEqual(requests[0][i], entries[i]) || requests[0][i].Score != entries[i].Score {
			t.Fatalf("request entry[%d] = %+v, want %+v", i, requests[0][i], entries[i])
		}
		if page[i].MemoryID != entries[i].MemoryID || page[i].Score != entries[i].Score {
			t.Fatalf("page record[%d] = %+v, want memory %q score %v", i, page[i], entries[i].MemoryID, entries[i].Score)
		}
	}
	if elapsed >= 3*delay {
		t.Fatalf("batched provider page took %s, want less than %s", elapsed, 3*delay)
	}
}

func TestReadProviderPageRejectsCountOrderAndIdentityDivergence(t *testing.T) {
	binding, entries, records := providerPageFixtures(3)
	tests := []struct {
		name string
		code string
		edit func([]ContentRecord) []ContentRecord
	}{
		{name: "missing record", code: kd6CodeIncompleteSearchPage, edit: func(values []ContentRecord) []ContentRecord {
			return values[:len(values)-1]
		}},
		{name: "extra record", code: kd6CodeIncompleteSearchPage, edit: func(values []ContentRecord) []ContentRecord {
			return append(values, values[len(values)-1])
		}},
		{name: "reordered records", code: kd6CodeSearchSnapshotChanged, edit: func(values []ContentRecord) []ContentRecord {
			values[0], values[1] = values[1], values[0]
			return values
		}},
		{name: "identity changed", code: kd6CodeSearchSnapshotChanged, edit: func(values []ContentRecord) []ContentRecord {
			values[1].Version += "-changed"
			return values
		}},
		{name: "content changed", code: kd6CodeSearchSnapshotChanged, edit: func(values []ContentRecord) []ContentRecord {
			values[1].Text = "changed content"
			return values
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &instrumentedSearchPageStore{response: func(ContentSearchPageRequest) []ContentRecord {
				return test.edit(cloneContentRecords(records))
			}}
			page, err := readProviderPage(context.Background(), store, binding, "provider-store", "snapshot-a", entries)
			var storeErr *StoreError
			if page != nil || !errors.As(err, &storeErr) || storeErr.Code != test.code || !errors.Is(err, ErrProviderDiverged) {
				t.Fatalf("readProviderPage() = %#v, %#v; want %s divergence", page, err, test.code)
			}
			if calls, _ := store.stats(); calls != 1 {
				t.Fatalf("provider calls = %d, want 1", calls)
			}
		})
	}
}

func TestReadProviderPageBatchedValidationIsRaceSafe(t *testing.T) {
	binding, entries, records := providerPageFixtures(protocol.MaxPageSize)
	store := &instrumentedSearchPageStore{response: func(ContentSearchPageRequest) []ContentRecord {
		return records
	}}
	const workers = 16
	start := make(chan struct{})
	errs := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Go(func() {
			<-start
			page, err := readProviderPage(context.Background(), store, binding, "provider-store", "snapshot-a", entries)
			if err == nil && len(page) != len(entries) {
				err = fmt.Errorf("page length = %d, want %d", len(page), len(entries))
			}
			errs <- err
		})
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	calls, requests := store.stats()
	if calls != workers || len(requests) != workers {
		t.Fatalf("concurrent provider calls/requests = %d/%d, want %d", calls, len(requests), workers)
	}
	for i := range requests {
		if len(requests[i]) != len(entries) {
			t.Fatalf("request[%d] entries = %d, want %d", i, len(requests[i]), len(entries))
		}
	}
}
