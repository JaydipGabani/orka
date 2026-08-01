/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package kd6adapter

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/orka-agents/orka/internal/oms/protocol"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite" // pure-Go SQLite driver registration
)

const (
	controlSchemaVersion                 = 5
	maxSearchSnapshotBytes               = 1 << 20
	maxActiveSearchSnapshotsPerAuthority = 8
	maxActiveSearchSnapshotsGlobal       = 64
	mutationProviderDispatchTimeout      = defaultProviderTimeout
	mutationRecoveryLease                = defaultProviderTimeout
	mutationIntentPrepared               = "prepared"
	mutationIntentDispatching            = "dispatching"
	mutationIntentRecovering             = "recovering"
	mutationIntentLegacyUnknown          = "legacyUnknown"
	snapshotStateReserved                = "reserved"
	snapshotStateReady                   = "ready"
)

var (
	errIdentityConflict             = errors.New("binding is not the claimed owner")
	errRoutingFenced                = errors.New("routing epoch is below the durable fence")
	errRoutingFenceBlocked          = errors.New("routing fence is blocked by unresolved mutation intent")
	errSnapshotInvalid              = errors.New("pagination snapshot is invalid")
	errSnapshotExpired              = errors.New("pagination snapshot expired")
	errSnapshotCapacity             = errors.New("pagination snapshot exceeds adapter capacity")
	errConformanceProviderCommitGap = errors.New("conformance failpoint: provider committed before local receipt")
)

type controlDatabase struct {
	db       *sql.DB
	lock     *processLock
	holderID string

	activeMu          sync.Mutex
	activeProviderOps map[string]struct{}
}

type processLock struct {
	file *os.File
	info os.FileInfo
}

var processLockRegistry = struct {
	sync.Mutex
	held []os.FileInfo
}{}

type ownershipDecision struct {
	result        string
	claimIdentity string
	maxRouting    uint64
	claimedAt     time.Time
}

type controlRecord struct {
	AuthorityDigest string
	UpsertKey       string
	MemoryID        string
	State           string
	Generation      uint64
	BackendVersion  string
	BackendMemoryID string
	ContentDigest   string
	UpdatedAt       time.Time
}

type mutationIntent struct {
	AuthorityDigest         string
	OperationID             string
	MutationDigest          string
	BindingDigest           string
	ProviderStoreID         string
	UpsertKey               string
	MemoryID                string
	Kind                    string
	Generation              uint64
	ExpectedGeneration      uint64
	ExpectedBackendVersion  string
	ProviderExpectedVersion string
	ContentDigest           string
	CreatedAt               time.Time
	RoutingEpoch            uint64
	DispatchState           string
	DispatchStartedAt       time.Time
	DispatchDeadline        time.Time
}

type searchPage struct {
	snapshotID string
	start      int
	total      int
	actualMode string
	records    []protocol.MemoryRecord
	nextToken  string
	exhausted  bool
	expiresAt  time.Time
}

type snapshotState struct {
	snapshotID       string
	providerSnapshot string
	providerStoreID  string
	actualMode       string
	expiresAt        time.Time
	entryCount       int
}

func openControlDatabase(ctx context.Context, path string) (*controlDatabase, error) {
	path = strings.TrimSpace(path)
	if path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") {
		return nil, errors.New("a plain durable SQLite control database path is required")
	}
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("resolve control database path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0o750); err != nil {
		return nil, fmt.Errorf("create control database directory: %w", err)
	}
	lock, err := acquireProcessLock(ctx, cleanPath)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", cleanPath)
	if err != nil {
		_ = lock.close()
		return nil, fmt.Errorf("open SQLite control database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	for _, statement := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			_ = db.Close()
			_ = lock.close()
			return nil, fmt.Errorf("configure SQLite control database: %w", err)
		}
	}
	result := &controlDatabase{db: db, lock: lock, holderID: uuid.NewString(), activeProviderOps: map[string]struct{}{}}
	if err := result.migrate(ctx); err != nil {
		_ = result.close()
		return nil, err
	}
	return result, nil
}

func acquireProcessLock(ctx context.Context, path string) (*processLock, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open process lock target: %w", err)
	}
	info, err := target.Stat()
	if err != nil {
		_ = target.Close()
		return nil, fmt.Errorf("stat process lock target: %w", err)
	}
	if !reserveProcessLock(info) {
		_ = target.Close()
		return nil, errors.New("adapter control database is already locked by another active process")
	}

	lockFile := target
	if runtime.GOOS != "linux" {
		lockFile, err = openCanonicalProcessLock(info)
		_ = target.Close()
		if err != nil {
			releaseProcessLock(info)
			return nil, err
		}
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		releaseProcessLock(info)
		_ = lockFile.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, fmt.Errorf("adapter control database is already locked by another active process: %w", err)
		}
		return nil, fmt.Errorf("acquire process lock: %w", err)
	}
	if err := ctx.Err(); err != nil {
		_ = unix.Flock(int(lockFile.Fd()), unix.LOCK_UN)
		releaseProcessLock(info)
		_ = lockFile.Close()
		return nil, err
	}
	return &processLock{file: lockFile, info: info}, nil
}

func openCanonicalProcessLock(info os.FileInfo) (*os.File, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("resolve process lock inode identity")
	}
	directory := filepath.Join(os.TempDir(), "orka-oms-process-locks")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create canonical process lock directory: %w", err)
	}
	path := filepath.Join(directory, fmt.Sprintf("%x-%x.lock", stat.Dev, stat.Ino))
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open canonical process lock: %w", err)
	}
	return file, nil
}

func reserveProcessLock(info os.FileInfo) bool {
	processLockRegistry.Lock()
	defer processLockRegistry.Unlock()
	for _, held := range processLockRegistry.held {
		if os.SameFile(info, held) {
			return false
		}
	}
	processLockRegistry.held = append(processLockRegistry.held, info)
	return true
}

func releaseProcessLock(info os.FileInfo) {
	processLockRegistry.Lock()
	defer processLockRegistry.Unlock()
	for i, held := range processLockRegistry.held {
		if os.SameFile(info, held) {
			processLockRegistry.held = append(processLockRegistry.held[:i], processLockRegistry.held[i+1:]...)
			return
		}
	}
}

func (l *processLock) close() error {
	if l == nil || l.file == nil {
		return nil
	}
	var result error
	if err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN); err != nil {
		result = err
	}
	releaseProcessLock(l.info)
	if err := l.file.Close(); err != nil && result == nil {
		result = err
	}
	l.file = nil
	l.info = nil
	return result
}

func (d *controlDatabase) close() error {
	if d == nil {
		return nil
	}
	var result error
	if d.db != nil {
		if err := d.db.Close(); err != nil {
			result = err
		}
	}
	if err := d.lock.close(); err != nil && result == nil {
		result = err
	}
	return result
}

func (d *controlDatabase) migrate(ctx context.Context) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin OMS KD6 control migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	statements := []string{
		`CREATE TABLE IF NOT EXISTS oms_schema (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			version INTEGER NOT NULL
		)`,
		`INSERT INTO oms_schema(id, version) VALUES(1, 1) ON CONFLICT(id) DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS writer_epoch_state (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			writer_epoch INTEGER NOT NULL CHECK (writer_epoch >= 0)
		)`,
		`INSERT INTO writer_epoch_state(id, writer_epoch) VALUES(1, 0) ON CONFLICT(id) DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS store_resolutions (
			tenant_id TEXT NOT NULL,
			store_name TEXT NOT NULL,
			store_uuid TEXT NOT NULL,
			provider_store_id TEXT NOT NULL,
			provider_canonical_id TEXT NOT NULL,
			cluster_id TEXT NOT NULL,
			namespace_uid TEXT NOT NULL,
			created_by_backend_uid TEXT NOT NULL,
			created_at TEXT NOT NULL,
			PRIMARY KEY(tenant_id, store_name),
			UNIQUE(store_uuid)
		)`,
		`CREATE TABLE IF NOT EXISTS ownership_claims (
			claim_scope_digest TEXT PRIMARY KEY,
			authority_digest TEXT NOT NULL,
			cluster_id TEXT NOT NULL,
			namespace_uid TEXT NOT NULL,
			backend_uid TEXT NOT NULL,
			authority_epoch INTEGER NOT NULL,
			tenant_id TEXT NOT NULL,
			store_uuid TEXT NOT NULL,
			max_routing_epoch INTEGER NOT NULL,
			claimed_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS operation_receipts (
			authority_digest TEXT NOT NULL,
			operation_id TEXT NOT NULL,
			mutation_digest TEXT NOT NULL,
			receipt_json BLOB NOT NULL,
			completed_at TEXT NOT NULL,
			PRIMARY KEY(authority_digest, operation_id)
		)`,
		`CREATE TABLE IF NOT EXISTS mutation_intents (
			authority_digest TEXT NOT NULL,
			operation_id TEXT NOT NULL,
			mutation_digest TEXT NOT NULL,
			binding_digest TEXT NOT NULL,
			provider_store_id TEXT NOT NULL,
			upsert_key TEXT NOT NULL,
			memory_id TEXT NOT NULL,
			kind TEXT NOT NULL,
			generation INTEGER NOT NULL CHECK (generation > 0),
			expected_generation INTEGER NOT NULL CHECK (expected_generation >= 0),
			expected_backend_version TEXT NOT NULL,
			provider_expected_version TEXT NOT NULL,
			content_digest TEXT NOT NULL,
			created_at TEXT NOT NULL,
			PRIMARY KEY(authority_digest, operation_id),
			UNIQUE(authority_digest, upsert_key)
		)`,
		`CREATE TABLE IF NOT EXISTS record_controls (
			authority_digest TEXT NOT NULL,
			upsert_key TEXT NOT NULL,
			memory_id TEXT NOT NULL,
			state TEXT NOT NULL,
			generation INTEGER NOT NULL,
			backend_version TEXT NOT NULL,
			backend_memory_id TEXT NOT NULL,
			content_digest TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(authority_digest, upsert_key)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_record_controls_search ON record_controls(authority_digest, state, upsert_key)`,
		`CREATE TABLE IF NOT EXISTS pagination_snapshots (
			snapshot_id TEXT PRIMARY KEY,
			authority_digest TEXT NOT NULL,
			request_fingerprint TEXT NOT NULL,
			provider_snapshot_id TEXT NOT NULL,
			provider_store_id TEXT NOT NULL,
			requested_mode TEXT NOT NULL,
			actual_mode TEXT NOT NULL,
			page_size INTEGER NOT NULL,
			entry_count INTEGER NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS pagination_entries (
			snapshot_id TEXT NOT NULL,
			position INTEGER NOT NULL,
			upsert_key TEXT NOT NULL,
			memory_id TEXT NOT NULL,
			generation INTEGER NOT NULL,
			backend_version TEXT NOT NULL,
			backend_memory_id TEXT NOT NULL,
			content_digest TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			PRIMARY KEY(snapshot_id, position),
			FOREIGN KEY(snapshot_id) REFERENCES pagination_snapshots(snapshot_id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pagination_snapshots_expiry ON pagination_snapshots(expires_at)`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("run OMS KD6 control migration: %w", err)
		}
	}
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT version FROM oms_schema WHERE id = 1`).Scan(&version); err != nil {
		return fmt.Errorf("read OMS KD6 control schema version: %w", err)
	}
	if version == 1 {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE pagination_entries ADD COLUMN score REAL NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("migrate OMS KD6 pagination scores: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE oms_schema SET version = 2 WHERE id = 1`); err != nil {
			return fmt.Errorf("record OMS KD6 control schema version 2: %w", err)
		}
		version = 2
	}
	if version == 2 {
		if _, err := tx.ExecContext(ctx, `UPDATE oms_schema SET version = 3 WHERE id = 1`); err != nil {
			return fmt.Errorf("record OMS KD6 control schema version 3: %w", err)
		}
		version = 3
	}
	if version == 3 {
		for _, statement := range []string{
			`ALTER TABLE mutation_intents ADD COLUMN routing_epoch INTEGER NOT NULL DEFAULT 0 CHECK (routing_epoch >= 0)`,
			`ALTER TABLE mutation_intents ADD COLUMN dispatch_state TEXT NOT NULL DEFAULT 'legacyUnknown'`,
			`ALTER TABLE mutation_intents ADD COLUMN dispatch_started_at TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE mutation_intents ADD COLUMN dispatch_deadline TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE pagination_snapshots ADD COLUMN state TEXT NOT NULL DEFAULT 'ready'`,
			`CREATE INDEX IF NOT EXISTS idx_mutation_intents_route ON mutation_intents(authority_digest, routing_epoch, dispatch_state)`,
			`CREATE INDEX IF NOT EXISTS idx_pagination_snapshots_quota ON pagination_snapshots(authority_digest, state, expires_at)`,
		} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migrate OMS KD6 in-flight control state: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE oms_schema SET version = 4 WHERE id = 1`); err != nil {
			return fmt.Errorf("record OMS KD6 control schema version: %w", err)
		}
		version = 4
	}
	if version == 4 {
		for _, statement := range []string{
			`ALTER TABLE ownership_claims ADD COLUMN writer_epoch INTEGER NOT NULL DEFAULT 0 CHECK (writer_epoch >= 0)`,
			`ALTER TABLE ownership_claims ADD COLUMN writer_holder_id TEXT NOT NULL DEFAULT ''`,
		} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migrate OMS KD6 provider writer fencing: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE oms_schema SET version = ? WHERE id = 1`, controlSchemaVersion); err != nil {
			return fmt.Errorf("record OMS KD6 provider writer fencing schema version: %w", err)
		}
		version = controlSchemaVersion
	}
	if version != controlSchemaVersion {
		return fmt.Errorf("unsupported OMS KD6 control schema version %d", version)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit OMS KD6 control migration: %w", err)
	}
	return nil
}

func (d *controlDatabase) resolveStore(ctx context.Context, binding protocol.StoreResolutionBinding, storeName string, resolved ResolvedStore, now time.Time) (string, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck
	var storeUUID, providerStoreID, providerCanonicalID, clusterID, namespaceUID string
	err = tx.QueryRowContext(ctx, `SELECT store_uuid, provider_store_id, provider_canonical_id, cluster_id, namespace_uid
		FROM store_resolutions WHERE tenant_id = ? AND store_name = ?`, binding.TenantID, storeName).
		Scan(&storeUUID, &providerStoreID, &providerCanonicalID, &clusterID, &namespaceUID)
	if errors.Is(err, sql.ErrNoRows) {
		storeUUID = uuid.NewString()
		_, err = tx.ExecContext(ctx, `INSERT INTO store_resolutions(
			tenant_id, store_name, store_uuid, provider_store_id, provider_canonical_id,
			cluster_id, namespace_uid, created_by_backend_uid, created_at
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`, binding.TenantID, storeName, storeUUID,
			resolved.ProviderStoreID, resolved.CanonicalID, binding.ClusterID, binding.NamespaceUID,
			binding.BackendUID, formatTime(now))
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	} else if providerStoreID != resolved.ProviderStoreID || providerCanonicalID != resolved.CanonicalID || clusterID != binding.ClusterID || namespaceUID != binding.NamespaceUID {
		return "", errIdentityConflict
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return storeUUID, nil
}

func (d *controlDatabase) providerStore(ctx context.Context, binding protocol.Binding) (string, error) {
	var providerStoreID string
	err := d.db.QueryRowContext(ctx, `SELECT provider_store_id FROM store_resolutions
		WHERE tenant_id = ? AND store_uuid = ? AND cluster_id = ? AND namespace_uid = ?`,
		binding.TenantID, binding.StoreUUID, binding.ClusterID, binding.NamespaceUID).Scan(&providerStoreID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errIdentityConflict
	}
	return providerStoreID, err
}

func providerStoreInTx(ctx context.Context, tx *sql.Tx, binding protocol.Binding) (string, error) {
	var providerStoreID string
	err := tx.QueryRowContext(ctx, `SELECT provider_store_id FROM store_resolutions
		WHERE tenant_id = ? AND store_uuid = ? AND cluster_id = ? AND namespace_uid = ?`,
		binding.TenantID, binding.StoreUUID, binding.ClusterID, binding.NamespaceUID).Scan(&providerStoreID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errIdentityConflict
	}
	return providerStoreID, err
}

func (d *controlDatabase) claimOwnership(ctx context.Context, store ContentStore, binding protocol.Binding, now time.Time) (ownershipDecision, error) {
	providerStoreID, decision, allowed, err := d.prepareOwnershipClaim(ctx, binding, now)
	if err != nil || !allowed {
		return decision, err
	}
	writerEpoch, err := d.reserveWriterEpoch(ctx)
	if err != nil {
		return ownershipDecision{}, err
	}
	lease := ContentWriterLease{
		Authority: writerAuthorityForBinding(binding), WriterEpoch: writerEpoch, HolderIdentity: d.holderID,
	}
	claimed, err := store.ClaimWriter(ctx, ContentWriterClaim{
		TenantID: binding.TenantID, ProviderStoreID: providerStoreID, Lease: lease,
	})
	if err != nil {
		if errors.Is(err, ErrProviderWriterFenced) {
			decision.result = protocol.ResultIdentityConflict
			return decision, nil
		}
		return ownershipDecision{}, err
	}
	if claimed != lease {
		return ownershipDecision{}, errors.New("provider writer claim did not echo the exact lease")
	}
	return d.commitOwnershipClaim(ctx, binding, providerStoreID, lease, now)
}

func (d *controlDatabase) prepareOwnershipClaim(ctx context.Context, binding protocol.Binding, now time.Time) (string, ownershipDecision, bool, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return "", ownershipDecision{}, false, err
	}
	defer tx.Rollback() //nolint:errcheck
	providerStoreID, err := providerStoreInTx(ctx, tx, binding)
	if err != nil {
		if errors.Is(err, errIdentityConflict) {
			return "", ownershipDecision{result: protocol.ResultIdentityConflict, claimedAt: now}, false, nil
		}
		return "", ownershipDecision{}, false, err
	}
	scope := protocol.ClaimScopeDigest(binding)
	authority := protocol.AuthorityDigest(binding)
	decision := ownershipDecision{
		result: protocol.ResultApplied, claimIdentity: authority,
		maxRouting: binding.RoutingEpoch, claimedAt: now,
	}
	var existingAuthority, claimedAtRaw string
	var maxRouting int64
	err = tx.QueryRowContext(ctx, `SELECT authority_digest, max_routing_epoch, claimed_at
		FROM ownership_claims WHERE claim_scope_digest = ?`, scope).Scan(&existingAuthority, &maxRouting, &claimedAtRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return providerStoreID, decision, true, nil
	}
	if err != nil {
		return "", ownershipDecision{}, false, err
	}
	claimedAt, err := parseTime(claimedAtRaw)
	if err != nil {
		return "", ownershipDecision{}, false, err
	}
	decision.claimIdentity = existingAuthority
	decision.maxRouting = uint64(maxRouting)
	decision.claimedAt = claimedAt
	if existingAuthority != authority {
		decision.result = protocol.ResultIdentityConflict
		return providerStoreID, decision, false, nil
	}
	return providerStoreID, decision, true, nil
}

func (d *controlDatabase) reserveWriterEpoch(ctx context.Context) (uint64, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	var current int64
	if err := tx.QueryRowContext(ctx, `SELECT writer_epoch FROM writer_epoch_state WHERE id = 1`).Scan(&current); err != nil {
		return 0, err
	}
	if current == math.MaxInt64 {
		return 0, errors.New("provider writer epoch is exhausted")
	}
	next := current + 1
	result, err := tx.ExecContext(ctx, `UPDATE writer_epoch_state SET writer_epoch = ? WHERE id = 1 AND writer_epoch = ?`, next, current)
	if err != nil {
		return 0, err
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		if err != nil {
			return 0, err
		}
		return 0, errors.New("provider writer epoch changed during reservation")
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return uint64(next), nil
}

func (d *controlDatabase) commitOwnershipClaim(
	ctx context.Context,
	binding protocol.Binding,
	providerStoreID string,
	lease ContentWriterLease,
	now time.Time,
) (ownershipDecision, error) {
	if lease.Authority != writerAuthorityForBinding(binding) || lease.WriterEpoch == 0 || lease.HolderIdentity != d.holderID {
		return ownershipDecision{}, errors.New("provider writer lease does not match the local ownership claim")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return ownershipDecision{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	currentProviderStoreID, err := providerStoreInTx(ctx, tx, binding)
	if err != nil {
		return ownershipDecision{}, err
	}
	if currentProviderStoreID != providerStoreID {
		return ownershipDecision{}, errors.New("provider store changed during writer claim")
	}
	scope := protocol.ClaimScopeDigest(binding)
	authority := protocol.AuthorityDigest(binding)
	var existingAuthority, claimedAtRaw string
	var maxRouting int64
	err = tx.QueryRowContext(ctx, `SELECT authority_digest, max_routing_epoch, claimed_at
		FROM ownership_claims WHERE claim_scope_digest = ?`, scope).Scan(&existingAuthority, &maxRouting, &claimedAtRaw)
	if errors.Is(err, sql.ErrNoRows) {
		claimedAtRaw = formatTime(now)
		_, err = tx.ExecContext(ctx, `INSERT INTO ownership_claims(
			claim_scope_digest, authority_digest, cluster_id, namespace_uid, backend_uid, authority_epoch,
			tenant_id, store_uuid, max_routing_epoch, claimed_at, updated_at, writer_epoch, writer_holder_id
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, scope, authority, binding.ClusterID,
			binding.NamespaceUID, binding.BackendUID, binding.AuthorityEpoch, binding.TenantID,
			binding.StoreUUID, binding.RoutingEpoch, claimedAtRaw, claimedAtRaw, lease.WriterEpoch, lease.HolderIdentity)
		if err != nil {
			return ownershipDecision{}, err
		}
		maxRouting = int64(binding.RoutingEpoch)
	} else if err != nil {
		return ownershipDecision{}, err
	} else if existingAuthority != authority {
		claimedAt, parseErr := parseTime(claimedAtRaw)
		if parseErr != nil {
			return ownershipDecision{}, parseErr
		}
		return ownershipDecision{
			result: protocol.ResultIdentityConflict, claimIdentity: existingAuthority,
			maxRouting: uint64(maxRouting), claimedAt: claimedAt,
		}, nil
	} else {
		result, updateErr := tx.ExecContext(ctx, `UPDATE ownership_claims
			SET writer_epoch = ?, writer_holder_id = ?, updated_at = ?
			WHERE claim_scope_digest = ? AND authority_digest = ?`, lease.WriterEpoch, lease.HolderIdentity,
			formatTime(now), scope, authority)
		if updateErr != nil {
			return ownershipDecision{}, updateErr
		}
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil || rows != 1 {
			if rowsErr != nil {
				return ownershipDecision{}, rowsErr
			}
			return ownershipDecision{}, errors.New("ownership claim changed during provider writer commit")
		}
	}
	claimedAt, err := parseTime(claimedAtRaw)
	if err != nil {
		return ownershipDecision{}, err
	}
	if err := tx.Commit(); err != nil {
		return ownershipDecision{}, err
	}
	return ownershipDecision{
		result: protocol.ResultApplied, claimIdentity: authority,
		maxRouting: uint64(maxRouting), claimedAt: claimedAt,
	}, nil
}

//nolint:gocyclo // Fence advancement keeps each durable intent/provider transition in one fail-closed loop.
func (d *controlDatabase) advanceRoutingFence(ctx context.Context, store ContentStore, binding protocol.Binding, now time.Time) (ownershipDecision, error) {
	for {
		tx, err := d.db.BeginTx(ctx, nil)
		if err != nil {
			return ownershipDecision{}, err
		}
		owner, maxRouting, claimedAt, err := ownershipInTx(ctx, tx, binding)
		if err != nil {
			_ = tx.Rollback()
			return ownershipDecision{}, err
		}
		decision := ownershipDecision{
			result: protocol.ResultApplied, claimIdentity: protocol.AuthorityDigest(binding),
			maxRouting: maxRouting, claimedAt: claimedAt,
		}
		if !owner {
			_ = tx.Rollback()
			decision.result = protocol.ResultIdentityConflict
			return decision, nil
		}
		if binding.RoutingEpoch < maxRouting {
			_ = tx.Rollback()
			decision.result = protocol.ResultPreconditionFailed
			return decision, nil
		}
		if binding.RoutingEpoch == maxRouting {
			if err := tx.Commit(); err != nil {
				return ownershipDecision{}, err
			}
			return decision, nil
		}

		blocker, found, err := firstFenceBlockerInTx(ctx, tx, protocol.AuthorityDigest(binding), binding.RoutingEpoch)
		if err != nil {
			_ = tx.Rollback()
			return ownershipDecision{}, err
		}
		if !found {
			_, err = tx.ExecContext(ctx, `UPDATE ownership_claims SET max_routing_epoch = ?, updated_at = ?
				WHERE claim_scope_digest = ?`, binding.RoutingEpoch, formatTime(now), protocol.ClaimScopeDigest(binding))
			if err != nil {
				_ = tx.Rollback()
				return ownershipDecision{}, err
			}
			if err := tx.Commit(); err != nil {
				return ownershipDecision{}, err
			}
			decision.maxRouting = binding.RoutingEpoch
			return decision, nil
		}
		if blocker.RoutingEpoch == 0 {
			blocker.RoutingEpoch = maxRouting
		}
		recoveryBinding := binding
		recoveryBinding.RoutingEpoch = blocker.RoutingEpoch
		if blocker.DispatchState == mutationIntentPrepared {
			if err := deleteMutationIntentInTx(ctx, tx, blocker.AuthorityDigest, blocker.OperationID); err != nil {
				_ = tx.Rollback()
				return ownershipDecision{}, err
			}
			if err := tx.Commit(); err != nil {
				return ownershipDecision{}, err
			}
			continue
		}
		if d.providerOperationActive(blocker) || !blocker.DispatchDeadline.IsZero() && blocker.DispatchDeadline.After(now) {
			_ = tx.Rollback()
			return decision, errRoutingFenceBlocked
		}
		blocker.DispatchState = mutationIntentRecovering
		blocker.DispatchStartedAt = now
		blocker.DispatchDeadline = now.Add(mutationRecoveryLease)
		if err := updateMutationIntentDispatchInTx(ctx, tx, blocker); err != nil {
			_ = tx.Rollback()
			return ownershipDecision{}, err
		}
		if err := tx.Commit(); err != nil {
			return ownershipDecision{}, err
		}
		if !d.beginProviderOperation(blocker) {
			return decision, errRoutingFenceBlocked
		}
		lookup, lookupErr := store.LookupMutation(ctx, ContentOperationLookup{
			TenantID: binding.TenantID, ProviderStoreID: blocker.ProviderStoreID,
			OperationID: blocker.OperationID, MutationDigest: blocker.MutationDigest, Kind: blocker.Kind,
		})
		d.endProviderOperation(blocker)
		if lookupErr != nil {
			if errors.Is(lookupErr, ErrProviderIdempotencyConflict) {
				request, requestErr := mutationRequestForRecovery(recoveryBinding, blocker, ContentMutationResult{})
				if requestErr != nil {
					return ownershipDecision{}, requestErr
				}
				receipt := conflictReceipt(request, protocol.ResultIdempotencyConflict, now)
				if _, persistErr := d.persistIntentReceipt(ctx, request, blocker, receipt); persistErr != nil {
					return ownershipDecision{}, persistErr
				}
				continue
			}
			return ownershipDecision{}, lookupErr
		}
		switch lookup.Status {
		case ContentOperationLookupCompleted:
			if lookup.Result == nil {
				return ownershipDecision{}, invalidOperationLookupError()
			}
			request, err := mutationRequestForRecovery(recoveryBinding, blocker, *lookup.Result)
			if err != nil {
				return ownershipDecision{}, err
			}
			receipt, err := d.finalizeMutationResult(ctx, request, blocker, *lookup.Result, now)
			if err != nil {
				return ownershipDecision{}, err
			}
			if receipt.Result == protocol.ResultRetryableError {
				return decision, errRoutingFenceBlocked
			}
			continue
		case ContentOperationLookupNeverApplied:
			if err := d.deleteRecoveredMutationIntent(ctx, blocker); err != nil {
				return ownershipDecision{}, err
			}
			continue
		case ContentOperationLookupPending, ContentOperationLookupNotFound:
			return decision, errRoutingFenceBlocked
		default:
			return ownershipDecision{}, invalidOperationLookupError()
		}
	}
}

func firstFenceBlockerInTx(ctx context.Context, tx *sql.Tx, authority string, targetRouting uint64) (mutationIntent, bool, error) {
	var operationID string
	err := tx.QueryRowContext(ctx, `SELECT operation_id FROM mutation_intents
		WHERE authority_digest = ? AND (routing_epoch = 0 OR routing_epoch < ?)
		ORDER BY created_at, operation_id LIMIT 1`, authority, targetRouting).Scan(&operationID)
	if errors.Is(err, sql.ErrNoRows) {
		return mutationIntent{}, false, nil
	}
	if err != nil {
		return mutationIntent{}, false, err
	}
	return lookupMutationIntentInTx(ctx, tx, authority, operationID)
}

func mutationRequestForRecovery(binding protocol.Binding, intent mutationIntent, result ContentMutationResult) (*protocol.MutationEnvelope, error) {
	if protocol.BindingDigest(binding) != intent.BindingDigest {
		return nil, errors.New("durable mutation intent binding cannot be reconstructed")
	}
	request := &protocol.MutationEnvelope{
		ProtocolVersion: protocol.Version, OperationID: intent.OperationID, Binding: binding,
		MemoryID: intent.MemoryID, UpsertKey: intent.UpsertKey, Kind: intent.Kind,
		Generation: intent.Generation, ExpectedGeneration: intent.ExpectedGeneration,
		ExpectedBackendVersion: intent.ExpectedBackendVersion, ContentDigest: intent.ContentDigest,
		MutationDigest: intent.MutationDigest,
	}
	if intent.Kind != protocol.MutationKindDelete && result.Record != nil {
		request.State = &protocol.MutationState{
			Content: result.Record.Text, Tags: append([]string(nil), result.Record.Tags...),
			Metadata: cloneStringMap(result.Record.Attributes),
		}
	}
	return request, nil
}

func (d *controlDatabase) deleteRecoveredMutationIntent(ctx context.Context, expected mutationIntent) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	current, found, err := lookupMutationIntentInTx(ctx, tx, expected.AuthorityDigest, expected.OperationID)
	if err != nil {
		return err
	}
	if !found || current != expected {
		return errors.New("durable mutation intent changed during fence recovery")
	}
	if err := deleteMutationIntentInTx(ctx, tx, expected.AuthorityDigest, expected.OperationID); err != nil {
		return err
	}
	return tx.Commit()
}

func providerOperationKey(intent mutationIntent) string {
	return intent.AuthorityDigest + "\x00" + intent.OperationID
}

func (d *controlDatabase) beginProviderOperation(intent mutationIntent) bool {
	d.activeMu.Lock()
	defer d.activeMu.Unlock()
	key := providerOperationKey(intent)
	if _, exists := d.activeProviderOps[key]; exists {
		return false
	}
	d.activeProviderOps[key] = struct{}{}
	return true
}

func (d *controlDatabase) endProviderOperation(intent mutationIntent) {
	d.activeMu.Lock()
	delete(d.activeProviderOps, providerOperationKey(intent))
	d.activeMu.Unlock()
}

func (d *controlDatabase) providerOperationActive(intent mutationIntent) bool {
	d.activeMu.Lock()
	defer d.activeMu.Unlock()
	_, exists := d.activeProviderOps[providerOperationKey(intent)]
	return exists
}

func ownershipInTx(ctx context.Context, tx *sql.Tx, binding protocol.Binding) (bool, uint64, time.Time, error) {
	var authority, claimedAtRaw string
	var maxRouting int64
	err := tx.QueryRowContext(ctx, `SELECT authority_digest, max_routing_epoch, claimed_at
		FROM ownership_claims WHERE claim_scope_digest = ?`, protocol.ClaimScopeDigest(binding)).
		Scan(&authority, &maxRouting, &claimedAtRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, 0, time.Time{}, nil
	}
	if err != nil {
		return false, 0, time.Time{}, err
	}
	claimedAt, err := parseTime(claimedAtRaw)
	if err != nil {
		return false, 0, time.Time{}, err
	}
	return authority == protocol.AuthorityDigest(binding), uint64(maxRouting), claimedAt, nil
}

func (d *controlDatabase) writerLeaseInTx(ctx context.Context, tx *sql.Tx, binding protocol.Binding) (ContentWriterLease, bool, error) {
	var authority, holderIdentity string
	var writerEpoch int64
	err := tx.QueryRowContext(ctx, `SELECT authority_digest, writer_epoch, writer_holder_id
		FROM ownership_claims WHERE claim_scope_digest = ?`, protocol.ClaimScopeDigest(binding)).
		Scan(&authority, &writerEpoch, &holderIdentity)
	if errors.Is(err, sql.ErrNoRows) {
		return ContentWriterLease{}, false, nil
	}
	if err != nil {
		return ContentWriterLease{}, false, err
	}
	if authority != protocol.AuthorityDigest(binding) || writerEpoch <= 0 || holderIdentity != d.holderID {
		return ContentWriterLease{}, false, nil
	}
	return ContentWriterLease{
		Authority: writerAuthorityForBinding(binding), WriterEpoch: uint64(writerEpoch), HolderIdentity: holderIdentity,
	}, true, nil
}

func ensureOwnedInTx(ctx context.Context, tx *sql.Tx, binding protocol.Binding) error {
	owner, maxRouting, _, err := ownershipInTx(ctx, tx, binding)
	if err != nil {
		return err
	}
	if !owner {
		return errIdentityConflict
	}
	if binding.RoutingEpoch < maxRouting {
		return errRoutingFenced
	}
	return nil
}

// applyMutation durably records a content-free intent before any provider side
// effect. A replay first asks the provider for the operation ID and digest, so
// a crash after provider success but before the local receipt commit converges
// without issuing an unsafe second mutation.
func (d *controlDatabase) applyMutation(ctx context.Context, contentStore ContentStore, request *protocol.MutationEnvelope, now time.Time) (protocol.MutationReceipt, error) {
	return d.applyMutationWithFailpoint(ctx, contentStore, request, now, false)
}

func (d *controlDatabase) applyMutationWithFailpoint(
	ctx context.Context,
	contentStore ContentStore,
	request *protocol.MutationEnvelope,
	now time.Time,
	failAfterProviderCommit bool,
) (protocol.MutationReceipt, error) {
	intent, immediate, err := d.prepareMutationIntent(ctx, request, now)
	if err != nil {
		return protocol.MutationReceipt{}, err
	}
	if immediate != nil {
		return *immediate, nil
	}

	lookup, err := contentStore.LookupMutation(ctx, ContentOperationLookup{
		TenantID: request.Binding.TenantID, ProviderStoreID: intent.ProviderStoreID,
		OperationID: request.OperationID, MutationDigest: request.MutationDigest, Kind: request.Kind,
	})
	if err != nil {
		if errors.Is(err, ErrProviderIdempotencyConflict) {
			receipt := conflictReceipt(request, protocol.ResultIdempotencyConflict, now)
			return d.persistIntentReceipt(ctx, request, intent, receipt)
		}
		// A failed lookup says nothing definitive about whether a prior provider
		// attempt committed. Preserve the durable intent and retry the lookup.
		return conflictReceipt(request, protocol.ResultRetryableError, now), nil
	}
	switch lookup.Status {
	case ContentOperationLookupCompleted:
		if lookup.Result == nil {
			return conflictReceipt(request, protocol.ResultRetryableError, now), nil
		}
		return d.finalizeMutationResult(ctx, request, intent, *lookup.Result, now)
	case ContentOperationLookupPending:
		return conflictReceipt(request, protocol.ResultRetryableError, now), nil
	case ContentOperationLookupNotFound:
		if intent.DispatchState != mutationIntentPrepared {
			return conflictReceipt(request, protocol.ResultRetryableError, now), nil
		}
	case ContentOperationLookupNeverApplied:
		intent, err = d.resetMutationIntentAfterNeverApplied(ctx, request, intent)
		if err != nil {
			return protocol.MutationReceipt{}, err
		}
		if intent.DispatchState != mutationIntentPrepared {
			return conflictReceipt(request, protocol.ResultRetryableError, now), nil
		}
	default:
		return conflictReceipt(request, protocol.ResultRetryableError, now), nil
	}

	var writerLease ContentWriterLease
	intent, writerLease, immediate, err = d.beginMutationDispatch(ctx, request, intent, now)
	if err != nil {
		return protocol.MutationReceipt{}, err
	}
	if immediate != nil {
		return *immediate, nil
	}
	if !d.beginProviderOperation(intent) {
		return conflictReceipt(request, protocol.ResultRetryableError, now), nil
	}
	providerContext, cancel := context.WithTimeout(ctx, mutationProviderDispatchTimeout)
	providerResult, err := contentStore.Mutate(providerContext, providerMutationForRequest(request, intent, writerLease))
	cancel()
	d.endProviderOperation(intent)
	if err != nil {
		return d.finishMutationProviderError(ctx, request, intent, err, now)
	}
	if failAfterProviderCommit {
		return protocol.MutationReceipt{}, errConformanceProviderCommitGap
	}
	return d.finalizeMutationResult(ctx, request, intent, providerResult, now)
}

func (d *controlDatabase) resetMutationIntentAfterNeverApplied(
	ctx context.Context,
	request *protocol.MutationEnvelope,
	expected mutationIntent,
) (mutationIntent, error) {
	if expected.DispatchState == mutationIntentPrepared || d.providerOperationActive(expected) {
		return expected, nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return mutationIntent{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	intent, found, err := lookupMutationIntentInTx(ctx, tx, expected.AuthorityDigest, expected.OperationID)
	if err != nil {
		return mutationIntent{}, err
	}
	if !found || !mutationIntentMatches(intent, request) || intent != expected {
		return mutationIntent{}, errors.New("durable mutation intent changed during never-applied recovery")
	}
	if d.providerOperationActive(intent) {
		return intent, nil
	}
	intent.DispatchState = mutationIntentPrepared
	intent.DispatchStartedAt = time.Time{}
	intent.DispatchDeadline = time.Time{}
	if err := updateMutationIntentDispatchInTx(ctx, tx, intent); err != nil {
		return mutationIntent{}, err
	}
	if err := tx.Commit(); err != nil {
		return mutationIntent{}, err
	}
	return intent, nil
}

func (d *controlDatabase) prepareMutationIntent(ctx context.Context, request *protocol.MutationEnvelope, now time.Time) (mutationIntent, *protocol.MutationReceipt, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return mutationIntent{}, nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	authority := protocol.AuthorityDigest(request.Binding)
	if existing, digest, found, lookupErr := lookupReceiptInTx(ctx, tx, authority, request.OperationID); lookupErr != nil {
		return mutationIntent{}, nil, lookupErr
	} else if found {
		if digest == request.MutationDigest {
			return mutationIntent{}, &existing, nil
		}
		receipt := conflictReceipt(request, protocol.ResultIdempotencyConflict, now)
		return mutationIntent{}, &receipt, nil
	}
	if existing, found, lookupErr := lookupMutationIntentInTx(ctx, tx, authority, request.OperationID); lookupErr != nil {
		return mutationIntent{}, nil, lookupErr
	} else if found {
		if !mutationIntentMatches(existing, request) {
			receipt := conflictReceipt(request, protocol.ResultIdempotencyConflict, now)
			return mutationIntent{}, &receipt, nil
		}
		return existing, nil, nil
	}
	if pending, found, lookupErr := lookupMutationIntentForUpsertInTx(ctx, tx, authority, request.UpsertKey); lookupErr != nil {
		return mutationIntent{}, nil, lookupErr
	} else if found && pending.OperationID != request.OperationID {
		receipt := conflictReceipt(request, protocol.ResultRetryableError, now)
		return mutationIntent{}, &receipt, nil
	}

	owner, maxRouting, _, err := ownershipInTx(ctx, tx, request.Binding)
	if err != nil {
		return mutationIntent{}, nil, err
	}
	if !owner {
		receipt := conflictReceipt(request, protocol.ResultIdentityConflict, now)
		if err := persistReceiptInTx(ctx, tx, request, receipt); err != nil {
			return mutationIntent{}, nil, err
		}
		if err := tx.Commit(); err != nil {
			return mutationIntent{}, nil, err
		}
		return mutationIntent{}, &receipt, nil
	}
	if request.Binding.RoutingEpoch > maxRouting {
		receipt := conflictReceipt(request, protocol.ResultRetryableError, now)
		return mutationIntent{}, &receipt, nil
	}
	if request.Binding.RoutingEpoch < maxRouting {
		receipt := conflictReceipt(request, protocol.ResultIdentityConflict, now)
		if err := persistReceiptInTx(ctx, tx, request, receipt); err != nil {
			return mutationIntent{}, nil, err
		}
		if err := tx.Commit(); err != nil {
			return mutationIntent{}, nil, err
		}
		return mutationIntent{}, &receipt, nil
	}
	providerStoreID, err := providerStoreInTx(ctx, tx, request.Binding)
	if err != nil {
		if errors.Is(err, errIdentityConflict) {
			receipt := conflictReceipt(request, protocol.ResultIdentityConflict, now)
			return mutationIntent{}, &receipt, nil
		}
		return mutationIntent{}, nil, err
	}
	if _, current, leaseErr := d.writerLeaseInTx(ctx, tx, request.Binding); leaseErr != nil {
		return mutationIntent{}, nil, leaseErr
	} else if !current {
		receipt := conflictReceipt(request, protocol.ResultRetryableError, now)
		return mutationIntent{}, &receipt, nil
	}
	current, found, err := lookupControlInTx(ctx, tx, authority, request.UpsertKey)
	if err != nil {
		return mutationIntent{}, nil, err
	}
	if !mutationPreconditionSatisfied(request, current, found) {
		receipt := conflictReceipt(request, protocol.ResultPreconditionFailed, now)
		if err := persistReceiptInTx(ctx, tx, request, receipt); err != nil {
			return mutationIntent{}, nil, err
		}
		if err := tx.Commit(); err != nil {
			return mutationIntent{}, nil, err
		}
		return mutationIntent{}, &receipt, nil
	}
	providerExpectedVersion := ""
	if found {
		providerExpectedVersion = current.BackendVersion
	}
	intent := mutationIntentFromRequest(request, authority, providerStoreID, providerExpectedVersion, now)
	if err := insertMutationIntentInTx(ctx, tx, intent); err != nil {
		return mutationIntent{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return mutationIntent{}, nil, err
	}
	return intent, nil, nil
}

func (d *controlDatabase) beginMutationDispatch(
	ctx context.Context,
	request *protocol.MutationEnvelope,
	expected mutationIntent,
	now time.Time,
) (mutationIntent, ContentWriterLease, *protocol.MutationReceipt, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return mutationIntent{}, ContentWriterLease{}, nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	intent, found, err := lookupMutationIntentInTx(ctx, tx, expected.AuthorityDigest, expected.OperationID)
	if err != nil {
		return mutationIntent{}, ContentWriterLease{}, nil, err
	}
	if !found || !mutationIntentMatches(intent, request) || intent != expected {
		return mutationIntent{}, ContentWriterLease{}, nil, errors.New("durable mutation intent changed before provider dispatch")
	}
	if intent.DispatchState != mutationIntentPrepared {
		receipt := conflictReceipt(request, protocol.ResultRetryableError, now)
		return mutationIntent{}, ContentWriterLease{}, &receipt, nil
	}
	if d.providerOperationActive(intent) ||
		(intent.DispatchState == mutationIntentDispatching || intent.DispatchState == mutationIntentRecovering) &&
			!intent.DispatchDeadline.IsZero() && intent.DispatchDeadline.After(now) {
		receipt := conflictReceipt(request, protocol.ResultRetryableError, now)
		return mutationIntent{}, ContentWriterLease{}, &receipt, nil
	}
	owner, maxRouting, _, err := ownershipInTx(ctx, tx, request.Binding)
	if err != nil {
		return mutationIntent{}, ContentWriterLease{}, nil, err
	}
	if !owner || request.Binding.RoutingEpoch != maxRouting {
		receipt := conflictReceipt(request, protocol.ResultIdentityConflict, now)
		committed, commitErr := commitIntentReceipt(ctx, tx, request, receipt)
		return mutationIntent{}, ContentWriterLease{}, committed, commitErr
	}
	writerLease, currentWriter, err := d.writerLeaseInTx(ctx, tx, request.Binding)
	if err != nil {
		return mutationIntent{}, ContentWriterLease{}, nil, err
	}
	if !currentWriter {
		receipt := conflictReceipt(request, protocol.ResultRetryableError, now)
		return mutationIntent{}, ContentWriterLease{}, &receipt, nil
	}
	providerStoreID, err := providerStoreInTx(ctx, tx, request.Binding)
	if err != nil {
		if errors.Is(err, errIdentityConflict) {
			receipt := conflictReceipt(request, protocol.ResultIdentityConflict, now)
			committed, commitErr := commitIntentReceipt(ctx, tx, request, receipt)
			return mutationIntent{}, ContentWriterLease{}, committed, commitErr
		}
		return mutationIntent{}, ContentWriterLease{}, nil, err
	}
	if providerStoreID != intent.ProviderStoreID {
		return mutationIntent{}, ContentWriterLease{}, nil, errors.New("durable mutation intent provider store changed")
	}
	current, currentFound, err := lookupControlInTx(ctx, tx, expected.AuthorityDigest, request.UpsertKey)
	if err != nil {
		return mutationIntent{}, ContentWriterLease{}, nil, err
	}
	if !mutationPreconditionSatisfied(request, current, currentFound) ||
		(currentFound && current.BackendVersion != intent.ProviderExpectedVersion) {
		receipt := conflictReceipt(request, protocol.ResultPreconditionFailed, now)
		committed, commitErr := commitIntentReceipt(ctx, tx, request, receipt)
		return mutationIntent{}, ContentWriterLease{}, committed, commitErr
	}
	intent.RoutingEpoch = request.Binding.RoutingEpoch
	intent.DispatchState = mutationIntentDispatching
	intent.DispatchStartedAt = now
	intent.DispatchDeadline = now.Add(mutationProviderDispatchTimeout)
	if err := updateMutationIntentDispatchInTx(ctx, tx, intent); err != nil {
		return mutationIntent{}, ContentWriterLease{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return mutationIntent{}, ContentWriterLease{}, nil, err
	}
	return intent, writerLease, nil, nil
}

func (d *controlDatabase) finishMutationProviderError(ctx context.Context, request *protocol.MutationEnvelope, intent mutationIntent, providerErr error, now time.Time) (protocol.MutationReceipt, error) {
	if providerFailureNeverApplied(providerErr) {
		if _, err := d.resetMutationIntentAfterNeverApplied(ctx, request, intent); err != nil {
			return protocol.MutationReceipt{}, err
		}
		return conflictReceipt(request, protocol.ResultRetryableError, now), nil
	}
	if !providerFailureDefinitive(providerErr) {
		// Generic provider, transport, context, malformed-response, and
		// non-definitive divergence failures are ambiguous once dispatch starts.
		// Keep the intent so replay can recover the provider decision before
		// another mutation is attempted or a routing fence advances.
		return conflictReceipt(request, protocol.ResultRetryableError, now), nil
	}
	if errors.Is(providerErr, ErrProviderPrecondition) {
		receipt := conflictReceipt(request, protocol.ResultPreconditionFailed, now)
		return d.persistIntentReceipt(ctx, request, intent, receipt)
	}
	if errors.Is(providerErr, ErrProviderIdempotencyConflict) {
		receipt := conflictReceipt(request, protocol.ResultIdempotencyConflict, now)
		return d.persistIntentReceipt(ctx, request, intent, receipt)
	}
	receipt := conflictReceipt(request, protocol.ResultNonRetryableError, now)
	return d.persistIntentReceipt(ctx, request, intent, receipt)
}

//nolint:gocyclo
func (d *controlDatabase) finalizeMutationResult(ctx context.Context, request *protocol.MutationEnvelope, expected mutationIntent, providerResult ContentMutationResult, now time.Time) (protocol.MutationReceipt, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.MutationReceipt{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	if existing, digest, found, lookupErr := lookupReceiptInTx(ctx, tx, expected.AuthorityDigest, request.OperationID); lookupErr != nil {
		return protocol.MutationReceipt{}, lookupErr
	} else if found {
		if digest == request.MutationDigest {
			return existing, nil
		}
		return conflictReceipt(request, protocol.ResultIdempotencyConflict, now), nil
	}
	intent, found, err := lookupMutationIntentInTx(ctx, tx, expected.AuthorityDigest, expected.OperationID)
	if err != nil {
		return protocol.MutationReceipt{}, err
	}
	if !found || !mutationIntentMatches(intent, request) || intent != expected {
		return protocol.MutationReceipt{}, errors.New("durable mutation intent is unavailable for provider result")
	}
	if err := validateProviderMutationResult(providerResult); err != nil {
		return conflictReceipt(request, protocol.ResultRetryableError, now), nil
	}
	if providerResult.Outcome == ContentOutcomePreconditionFailed {
		receipt := conflictReceipt(request, protocol.ResultPreconditionFailed, now)
		committed, err := commitIntentReceipt(ctx, tx, request, receipt)
		return valueOrZero(committed), err
	}
	if providerResult.Outcome != ContentOutcomeApplied && providerResult.Outcome != ContentOutcomeNotFound {
		return conflictReceipt(request, protocol.ResultRetryableError, now), nil
	}
	current, found, err := lookupControlInTx(ctx, tx, expected.AuthorityDigest, request.UpsertKey)
	if err != nil {
		return protocol.MutationReceipt{}, err
	}
	if !mutationPreconditionSatisfied(request, current, found) ||
		(found && current.BackendVersion != intent.ProviderExpectedVersion) {
		return protocol.MutationReceipt{}, errors.New("local mutation precondition changed before provider receipt commit")
	}
	live := found && current.State == protocol.RecordStateLive
	result := protocol.ResultApplied
	control := controlRecord{
		AuthorityDigest: expected.AuthorityDigest, UpsertKey: request.UpsertKey, MemoryID: request.MemoryID,
		Generation: request.Generation, BackendVersion: providerResult.Version,
		BackendMemoryID: providerResult.ProviderID, ContentDigest: request.ContentDigest,
		UpdatedAt: providerResult.UpdatedAt,
	}
	if request.Kind == protocol.MutationKindDelete {
		if live && providerResult.Outcome == ContentOutcomeNotFound {
			return conflictReceipt(request, protocol.ResultRetryableError, now), nil
		}
		if !live {
			result = protocol.ResultNotFound
		}
		control.State = protocol.RecordStateTombstone
		control.ContentDigest = protocol.EmptyContentDigest()
	} else {
		boundRecord, bindErr := bindMutationResultRecord(providerResult)
		if providerResult.Outcome != ContentOutcomeApplied || bindErr != nil || boundRecord == nil ||
			!contentMatchesMutation(*boundRecord, request) {
			return conflictReceipt(request, protocol.ResultRetryableError, now), nil
		}
		control.State = protocol.RecordStateLive
	}
	if control.BackendVersion == "" || control.BackendMemoryID == "" || control.UpdatedAt.IsZero() {
		return conflictReceipt(request, protocol.ResultRetryableError, now), nil
	}
	if err := upsertControlInTx(ctx, tx, control); err != nil {
		return protocol.MutationReceipt{}, err
	}
	receipt := protocol.MutationReceipt{
		ProtocolVersion: protocol.Version, Binding: request.Binding, Result: result,
		OperationID: request.OperationID, BindingDigest: protocol.BindingDigest(request.Binding),
		AppliedGeneration: request.Generation, BackendVersion: control.BackendVersion,
		BackendMemoryID: control.BackendMemoryID, ContentDigest: control.ContentDigest,
		MutationDigest: request.MutationDigest, CompletedAt: now,
	}
	if err := validateReceiptForPersistence(receipt); err != nil {
		return protocol.MutationReceipt{}, err
	}
	committed, err := commitIntentReceipt(ctx, tx, request, receipt)
	return valueOrZero(committed), err
}

func validateProviderMutationResult(result ContentMutationResult) error {
	switch result.Outcome {
	case ContentOutcomePreconditionFailed:
		if result.ProviderID != "" || result.Version != "" || !result.UpdatedAt.IsZero() || result.Record != nil {
			return errors.New("provider precondition result contains durable identity")
		}
		return nil
	case ContentOutcomeApplied, ContentOutcomeNotFound:
	default:
		return errors.New("provider mutation result is unsupported")
	}
	if !safeProviderIdentity(result.ProviderID) || len(result.ProviderID) > protocol.MaxIdentityBytes ||
		!safeProviderIdentity(result.Version) || len(result.Version) > protocol.MaxBackendVersionBytes ||
		!receiptSafeTime(result.UpdatedAt) {
		return errors.New("provider mutation result identity is not receipt-safe")
	}
	if result.Record != nil {
		if !safeProviderIdentity(result.Record.ProviderID) || len(result.Record.ProviderID) > protocol.MaxIdentityBytes ||
			!safeProviderIdentity(result.Record.Version) || len(result.Record.Version) > protocol.MaxBackendVersionBytes ||
			!receiptSafeTime(result.Record.UpdatedAt) {
			return errors.New("provider mutation record identity is not receipt-safe")
		}
	}
	return nil
}

func receiptSafeTime(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	_, err := value.MarshalJSON()
	return err == nil
}

func validateReceiptForPersistence(receipt protocol.MutationReceipt) error {
	if err := protocol.ValidateMutationReceipt(&receipt); err != nil {
		return fmt.Errorf("validate durable mutation receipt: %w", err)
	}
	data, err := protocol.EncodeJSON(receipt)
	if err != nil {
		return err
	}
	if len(data) > protocol.MaxAdapterResponseBytes {
		return errors.New("durable mutation receipt exceeds response limit")
	}
	return nil
}

func (d *controlDatabase) persistIntentReceipt(ctx context.Context, request *protocol.MutationEnvelope, expected mutationIntent, receipt protocol.MutationReceipt) (protocol.MutationReceipt, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.MutationReceipt{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	intent, found, err := lookupMutationIntentInTx(ctx, tx, expected.AuthorityDigest, expected.OperationID)
	if err != nil {
		return protocol.MutationReceipt{}, err
	}
	if !found || !mutationIntentMatches(intent, request) || intent != expected {
		return protocol.MutationReceipt{}, errors.New("durable mutation intent changed before receipt commit")
	}
	committed, err := commitIntentReceipt(ctx, tx, request, receipt)
	return valueOrZero(committed), err
}

func commitIntentReceipt(ctx context.Context, tx *sql.Tx, request *protocol.MutationEnvelope, receipt protocol.MutationReceipt) (*protocol.MutationReceipt, error) {
	if err := persistReceiptInTx(ctx, tx, request, receipt); err != nil {
		return nil, err
	}
	if err := deleteMutationIntentInTx(ctx, tx, protocol.AuthorityDigest(request.Binding), request.OperationID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &receipt, nil
}

func providerMutationForRequest(request *protocol.MutationEnvelope, intent mutationIntent, writerLease ContentWriterLease) ContentMutation {
	mutation := ContentMutation{
		TenantID: request.Binding.TenantID, ProviderStoreID: intent.ProviderStoreID,
		WriterLease: writerLease,
		OperationID: request.OperationID, MutationDigest: request.MutationDigest,
		Kind: request.Kind, UpsertKey: request.UpsertKey, ExpectedVersion: intent.ProviderExpectedVersion,
	}
	if request.Kind != protocol.MutationKindDelete {
		mutation.Record = &ContentRecord{
			UpsertKey: request.UpsertKey, Text: request.State.Content,
			Tags: append([]string(nil), request.State.Tags...), Attributes: cloneStringMap(request.State.Metadata),
			Scope:     scopeForMutation(request.Binding, request.MemoryID, request.Generation, request.ContentDigest),
			SourceURI: sourceURI(request.Binding, request.MemoryID),
		}
	}
	return mutation
}

func mutationPreconditionSatisfied(request *protocol.MutationEnvelope, current controlRecord, found bool) bool {
	live := found && current.State == protocol.RecordStateLive
	currentGeneration, currentVersion := uint64(0), ""
	if found {
		currentGeneration, currentVersion = current.Generation, current.BackendVersion
	}
	switch request.Kind {
	case protocol.MutationKindCreate:
		return !live && request.ExpectedGeneration == currentGeneration && request.Generation > currentGeneration
	case protocol.MutationKindReplace:
		return live && request.ExpectedGeneration == currentGeneration && request.Generation > currentGeneration &&
			(request.ExpectedBackendVersion == "" || request.ExpectedBackendVersion == currentVersion)
	case protocol.MutationKindDelete:
		return request.ExpectedGeneration == currentGeneration && request.Generation > currentGeneration &&
			(request.ExpectedBackendVersion == "" || request.ExpectedBackendVersion == currentVersion)
	default:
		return false
	}
}

func mutationIntentFromRequest(request *protocol.MutationEnvelope, authority, providerStoreID, providerExpectedVersion string, now time.Time) mutationIntent {
	return mutationIntent{
		AuthorityDigest: authority, OperationID: request.OperationID, MutationDigest: request.MutationDigest,
		BindingDigest: protocol.BindingDigest(request.Binding), ProviderStoreID: providerStoreID,
		UpsertKey: request.UpsertKey, MemoryID: request.MemoryID, Kind: request.Kind,
		Generation: request.Generation, ExpectedGeneration: request.ExpectedGeneration,
		ExpectedBackendVersion: request.ExpectedBackendVersion, ProviderExpectedVersion: providerExpectedVersion,
		ContentDigest: request.ContentDigest, CreatedAt: now,
		RoutingEpoch: request.Binding.RoutingEpoch, DispatchState: mutationIntentPrepared,
	}
}

func mutationIntentMatches(intent mutationIntent, request *protocol.MutationEnvelope) bool {
	return intent.AuthorityDigest == protocol.AuthorityDigest(request.Binding) &&
		intent.OperationID == request.OperationID && intent.MutationDigest == request.MutationDigest &&
		intent.BindingDigest == protocol.BindingDigest(request.Binding) && intent.UpsertKey == request.UpsertKey &&
		intent.MemoryID == request.MemoryID && intent.Kind == request.Kind && intent.Generation == request.Generation &&
		intent.ExpectedGeneration == request.ExpectedGeneration &&
		intent.ExpectedBackendVersion == request.ExpectedBackendVersion && intent.ContentDigest == request.ContentDigest &&
		(intent.RoutingEpoch == 0 || intent.RoutingEpoch == request.Binding.RoutingEpoch)
}

func lookupMutationIntentInTx(ctx context.Context, tx *sql.Tx, authority, operationID string) (mutationIntent, bool, error) {
	var intent mutationIntent
	var generation, expectedGeneration int64
	var createdAtRaw, dispatchStartedAtRaw, dispatchDeadlineRaw string
	err := tx.QueryRowContext(ctx, `SELECT mutation_digest, binding_digest, provider_store_id, upsert_key,
		memory_id, kind, generation, expected_generation, expected_backend_version, provider_expected_version,
		content_digest, created_at, routing_epoch, dispatch_state, dispatch_started_at, dispatch_deadline
		FROM mutation_intents WHERE authority_digest = ? AND operation_id = ?`,
		authority, operationID).Scan(&intent.MutationDigest, &intent.BindingDigest, &intent.ProviderStoreID,
		&intent.UpsertKey, &intent.MemoryID, &intent.Kind, &generation, &expectedGeneration,
		&intent.ExpectedBackendVersion, &intent.ProviderExpectedVersion, &intent.ContentDigest, &createdAtRaw,
		&intent.RoutingEpoch, &intent.DispatchState, &dispatchStartedAtRaw, &dispatchDeadlineRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return mutationIntent{}, false, nil
	}
	if err != nil {
		return mutationIntent{}, false, err
	}
	intent.AuthorityDigest, intent.OperationID = authority, operationID
	intent.Generation, intent.ExpectedGeneration = uint64(generation), uint64(expectedGeneration)
	intent.CreatedAt, err = parseTime(createdAtRaw)
	if err != nil {
		return mutationIntent{}, false, err
	}
	if dispatchStartedAtRaw != "" {
		intent.DispatchStartedAt, err = parseTime(dispatchStartedAtRaw)
		if err != nil {
			return mutationIntent{}, false, err
		}
	}
	if dispatchDeadlineRaw != "" {
		intent.DispatchDeadline, err = parseTime(dispatchDeadlineRaw)
		if err != nil {
			return mutationIntent{}, false, err
		}
	}
	return intent, true, nil
}

func lookupMutationIntentForUpsertInTx(ctx context.Context, tx *sql.Tx, authority, upsertKey string) (mutationIntent, bool, error) {
	var operationID string
	err := tx.QueryRowContext(ctx, `SELECT operation_id FROM mutation_intents
		WHERE authority_digest = ? AND upsert_key = ?`, authority, upsertKey).Scan(&operationID)
	if errors.Is(err, sql.ErrNoRows) {
		return mutationIntent{}, false, nil
	}
	if err != nil {
		return mutationIntent{}, false, err
	}
	return lookupMutationIntentInTx(ctx, tx, authority, operationID)
}

func insertMutationIntentInTx(ctx context.Context, tx *sql.Tx, intent mutationIntent) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO mutation_intents(
		authority_digest, operation_id, mutation_digest, binding_digest, provider_store_id, upsert_key,
		memory_id, kind, generation, expected_generation, expected_backend_version, provider_expected_version,
		content_digest, created_at, routing_epoch, dispatch_state, dispatch_started_at, dispatch_deadline)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		intent.AuthorityDigest, intent.OperationID, intent.MutationDigest, intent.BindingDigest,
		intent.ProviderStoreID, intent.UpsertKey, intent.MemoryID, intent.Kind, intent.Generation,
		intent.ExpectedGeneration, intent.ExpectedBackendVersion, intent.ProviderExpectedVersion,
		intent.ContentDigest, formatTime(intent.CreatedAt), intent.RoutingEpoch, intent.DispatchState, "", "")
	return err
}

func updateMutationIntentDispatchInTx(ctx context.Context, tx *sql.Tx, intent mutationIntent) error {
	startedAt, deadline := "", ""
	if !intent.DispatchStartedAt.IsZero() {
		startedAt = formatTime(intent.DispatchStartedAt)
	}
	if !intent.DispatchDeadline.IsZero() {
		deadline = formatTime(intent.DispatchDeadline)
	}
	result, err := tx.ExecContext(ctx, `UPDATE mutation_intents SET routing_epoch = ?, dispatch_state = ?,
		dispatch_started_at = ?, dispatch_deadline = ? WHERE authority_digest = ? AND operation_id = ?`,
		intent.RoutingEpoch, intent.DispatchState, startedAt, deadline, intent.AuthorityDigest, intent.OperationID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("durable mutation intent was not updated")
	}
	return nil
}

func deleteMutationIntentInTx(ctx context.Context, tx *sql.Tx, authority, operationID string) error {
	result, err := tx.ExecContext(ctx, `DELETE FROM mutation_intents WHERE authority_digest = ? AND operation_id = ?`, authority, operationID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("durable mutation intent was not removed")
	}
	return nil
}

func conflictReceipt(request *protocol.MutationEnvelope, result string, now time.Time) protocol.MutationReceipt {
	return protocol.MutationReceipt{
		ProtocolVersion: protocol.Version, Binding: request.Binding, Result: result,
		OperationID: request.OperationID, BindingDigest: protocol.BindingDigest(request.Binding),
		ContentDigest: request.ContentDigest, MutationDigest: request.MutationDigest, CompletedAt: now,
	}
}

func lookupReceiptInTx(ctx context.Context, tx *sql.Tx, authority, operationID string) (protocol.MutationReceipt, string, bool, error) {
	var digest string
	var data []byte
	err := tx.QueryRowContext(ctx, `SELECT mutation_digest, receipt_json FROM operation_receipts
		WHERE authority_digest = ? AND operation_id = ?`, authority, operationID).Scan(&digest, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return protocol.MutationReceipt{}, "", false, nil
	}
	if err != nil {
		return protocol.MutationReceipt{}, "", false, err
	}
	receipt, err := protocol.DecodeMutationReceipt(data)
	return valueOrZero(receipt), digest, true, err
}

func persistReceiptInTx(ctx context.Context, tx *sql.Tx, request *protocol.MutationEnvelope, receipt protocol.MutationReceipt) error {
	if err := validateReceiptForPersistence(receipt); err != nil {
		return err
	}
	data, err := protocol.EncodeJSON(receipt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO operation_receipts(
		authority_digest, operation_id, mutation_digest, receipt_json, completed_at
	) VALUES(?, ?, ?, ?, ?)`, protocol.AuthorityDigest(request.Binding), request.OperationID,
		request.MutationDigest, data, formatTime(receipt.CompletedAt))
	return err
}

func valueOrZero[T any](value *T) T {
	if value == nil {
		var zero T
		return zero
	}
	return *value
}

func lookupControlInTx(ctx context.Context, tx *sql.Tx, authority, upsertKey string) (controlRecord, bool, error) {
	var record controlRecord
	var generation int64
	var updatedAtRaw string
	err := tx.QueryRowContext(ctx, `SELECT memory_id, state, generation, backend_version,
		backend_memory_id, content_digest, updated_at FROM record_controls
		WHERE authority_digest = ? AND upsert_key = ?`, authority, upsertKey).
		Scan(&record.MemoryID, &record.State, &generation, &record.BackendVersion,
			&record.BackendMemoryID, &record.ContentDigest, &updatedAtRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return controlRecord{}, false, nil
	}
	if err != nil {
		return controlRecord{}, false, err
	}
	record.AuthorityDigest, record.UpsertKey, record.Generation = authority, upsertKey, uint64(generation)
	record.UpdatedAt, err = parseTime(updatedAtRaw)
	return record, true, err
}

func upsertControlInTx(ctx context.Context, tx *sql.Tx, record controlRecord) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO record_controls(
		authority_digest, upsert_key, memory_id, state, generation, backend_version,
		backend_memory_id, content_digest, updated_at
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(authority_digest, upsert_key) DO UPDATE SET
		memory_id = excluded.memory_id, state = excluded.state, generation = excluded.generation,
		backend_version = excluded.backend_version, backend_memory_id = excluded.backend_memory_id,
		content_digest = excluded.content_digest, updated_at = excluded.updated_at`,
		record.AuthorityDigest, record.UpsertKey, record.MemoryID, record.State, record.Generation,
		record.BackendVersion, record.BackendMemoryID, record.ContentDigest, formatTime(record.UpdatedAt))
	return err
}

func (d *controlDatabase) lookupOperation(ctx context.Context, binding protocol.Binding, operationID string) (protocol.MutationReceipt, bool, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return protocol.MutationReceipt{}, false, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := ensureOwnedInTx(ctx, tx, binding); err != nil {
		return protocol.MutationReceipt{}, false, err
	}
	receipt, _, found, err := lookupReceiptInTx(ctx, tx, protocol.AuthorityDigest(binding), operationID)
	if err != nil {
		return protocol.MutationReceipt{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return protocol.MutationReceipt{}, false, err
	}
	return receipt, found, nil
}

func (d *controlDatabase) lookupRecord(ctx context.Context, store ContentStore, binding protocol.Binding, upsertKey string) (protocol.MemoryRecord, bool, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return protocol.MemoryRecord{}, false, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := ensureOwnedInTx(ctx, tx, binding); err != nil {
		return protocol.MemoryRecord{}, false, err
	}
	providerStoreID, err := providerStoreInTx(ctx, tx, binding)
	if err != nil {
		return protocol.MemoryRecord{}, false, err
	}
	control, found, err := lookupControlInTx(ctx, tx, protocol.AuthorityDigest(binding), upsertKey)
	if err != nil || !found {
		return protocol.MemoryRecord{}, found, err
	}
	if err := tx.Commit(); err != nil {
		return protocol.MemoryRecord{}, false, err
	}
	if control.State == protocol.RecordStateTombstone {
		return tombstoneFromControl(control), true, nil
	}
	content, err := store.Get(ctx, ContentGetRequest{TenantID: binding.TenantID, ProviderStoreID: providerStoreID, UpsertKey: upsertKey})
	if err != nil {
		return protocol.MemoryRecord{}, false, err
	}
	if content == nil || !contentMatchesControl(*content, control, binding) {
		return protocol.MemoryRecord{}, false, &StoreError{Code: "KD6_CONTENT_DIVERGED", Retryable: true, Kind: ErrProviderDiverged}
	}
	return liveRecordFromContent(control, *content), true, nil
}

//nolint:gocyclo // Snapshot admission combines authority filtering, quotas, persistence, and bounded paging.
func (d *controlDatabase) createSnapshot(
	ctx context.Context,
	store ContentStore,
	request *protocol.SearchRequest,
	now time.Time,
	clock func() time.Time,
	ttl time.Duration,
	maxRecords int,
) (searchPage, error) {
	authority := protocol.AuthorityDigest(request.Binding)
	snapshotID, err := randomSnapshotID()
	if err != nil {
		return searchPage{}, err
	}
	fingerprint := searchFingerprint(request)
	reservationExpiresAt := now.Add(ttl)
	if !reservationExpiresAt.After(now) {
		return searchPage{}, errSnapshotExpired
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return searchPage{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := ensureOwnedInTx(ctx, tx, request.Binding); err != nil {
		return searchPage{}, err
	}
	providerStoreID, err := providerStoreInTx(ctx, tx, request.Binding)
	if err != nil {
		return searchPage{}, err
	}
	if err := deleteExpiredSearchSnapshotsInTx(ctx, tx, now); err != nil {
		return searchPage{}, err
	}
	if err := ensureSearchSnapshotCountCapacityInTx(ctx, tx, authority); err != nil {
		return searchPage{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO pagination_snapshots(
		snapshot_id, authority_digest, request_fingerprint, provider_snapshot_id, provider_store_id,
		requested_mode, actual_mode, page_size, entry_count, created_at, expires_at, state
	) VALUES(?, ?, ?, '', ?, ?, '', ?, 0, ?, ?, ?)`, snapshotID, authority, fingerprint,
		providerStoreID, request.Mode, request.PageSize, formatTime(now), formatTime(reservationExpiresAt), snapshotStateReserved)
	if err != nil {
		return searchPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return searchPage{}, err
	}
	cleanupSnapshot := true
	defer func() {
		if cleanupSnapshot {
			_ = d.releaseSearchSnapshot(context.WithoutCancel(ctx), snapshotID)
		}
	}()

	providerSnapshot, err := store.StartSearch(ctx, ContentSearchRequest{
		TenantID: request.Binding.TenantID, ProviderStoreID: providerStoreID,
		Scope: authorityScopeForBinding(request.Binding),
		Mode:  request.Mode, Query: request.Query, MaxSnapshotRecords: maxRecords,
	})
	if err != nil {
		return searchPage{}, err
	}
	currentNow := time.Now().UTC()
	if clock != nil {
		currentNow = clock().UTC()
	}
	if request.Mode != protocol.SearchModeAuto && request.Mode != providerSnapshot.ActualMode {
		return searchPage{}, &StoreError{Code: "KD6_EXPLICIT_MODE_DOWNGRADED", Kind: ErrProviderDiverged}
	}
	if len(providerSnapshot.Entries) > maxRecords {
		return searchPage{}, errSnapshotCapacity
	}
	if err := validateSearchSnapshotEntries(providerSnapshot.ActualMode, providerSnapshot.Entries); err != nil {
		return searchPage{}, err
	}
	expiresAt := providerSnapshot.ExpiresAt.UTC()
	if expiresAt.After(reservationExpiresAt) {
		expiresAt = reservationExpiresAt
	}
	if !expiresAt.After(currentNow) {
		return searchPage{}, errSnapshotExpired
	}

	tx, err = d.db.BeginTx(ctx, nil)
	if err != nil {
		return searchPage{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := ensureOwnedInTx(ctx, tx, request.Binding); err != nil {
		return searchPage{}, err
	}
	controls, err := liveControlsForEntriesInTx(ctx, tx, authority, providerSnapshot.Entries)
	if err != nil {
		return searchPage{}, err
	}
	entries := make([]ContentDescriptor, 0, len(providerSnapshot.Entries))
	snapshotBytes := 0
	for _, entry := range providerSnapshot.Entries {
		control, ok := controls[entry.UpsertKey]
		if !ok || !descriptorMatchesControl(entry, control) || entry.UpsertKey != protocol.CanonicalUpsertKey(request.Binding, entry.MemoryID) {
			continue
		}
		encoded, encodeErr := protocol.EncodeJSON(entry)
		if encodeErr != nil {
			return searchPage{}, encodeErr
		}
		if len(encoded) > maxSearchSnapshotBytes-snapshotBytes {
			return searchPage{}, errSnapshotCapacity
		}
		snapshotBytes += len(encoded)
		entries = append(entries, entry)
	}
	result, err := tx.ExecContext(ctx, `UPDATE pagination_snapshots SET provider_snapshot_id = ?,
		actual_mode = ?, entry_count = ?, expires_at = ?, state = ?
		WHERE snapshot_id = ? AND authority_digest = ? AND request_fingerprint = ? AND state = ?
		AND julianday(expires_at) > julianday(?)`, providerSnapshot.SnapshotID, providerSnapshot.ActualMode,
		len(entries), formatTime(expiresAt), snapshotStateReady, snapshotID, authority, fingerprint,
		snapshotStateReserved, formatTime(currentNow))
	if err != nil {
		return searchPage{}, err
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return searchPage{}, err
	}
	if updated != 1 {
		return searchPage{}, errSnapshotExpired
	}
	for position, entry := range entries {
		_, err := tx.ExecContext(ctx, `INSERT INTO pagination_entries(
			snapshot_id, position, upsert_key, memory_id, generation, backend_version,
			backend_memory_id, content_digest, updated_at, score
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, snapshotID, position, entry.UpsertKey,
			entry.MemoryID, entry.Generation, entry.Version, entry.ProviderID, entry.ContentDigest,
			formatTime(entry.UpdatedAt), entry.Score)
		if err != nil {
			return searchPage{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return searchPage{}, err
	}
	end := min(request.PageSize, len(entries))
	records, err := readProviderPage(ctx, store, request.Binding, providerStoreID, providerSnapshot.SnapshotID, entries[:end])
	if err != nil {
		return searchPage{}, err
	}
	cleanupSnapshot = false
	return pageFromRecords(snapshotID, 0, end, len(entries), providerSnapshot.ActualMode, expiresAt, records), nil
}

func providerFailureDefinitive(err error) bool {
	var storeErr *StoreError
	return errors.As(err, &storeErr) && storeErr.Definitive && !storeErr.Retryable
}

func providerFailureNeverApplied(err error) bool {
	var storeErr *StoreError
	return errors.As(err, &storeErr) && storeErr.NeverApplied
}

func (d *controlDatabase) releaseSearchSnapshot(ctx context.Context, snapshotID string) error {
	result, err := d.db.ExecContext(ctx, `DELETE FROM pagination_snapshots WHERE snapshot_id = ?`, snapshotID)
	if err != nil {
		return err
	}
	_, err = result.RowsAffected()
	return err
}

func deleteExpiredSearchSnapshotsInTx(ctx context.Context, tx *sql.Tx, now time.Time) error {
	_, err := tx.ExecContext(ctx,
		`DELETE FROM pagination_snapshots WHERE julianday(expires_at) <= julianday(?)`,
		formatTime(now),
	)
	return err
}

func ensureSearchSnapshotCountCapacityInTx(ctx context.Context, tx *sql.Tx, authority string) error {
	var globalCount, authorityCount int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(CASE WHEN authority_digest = ? THEN 1 ELSE 0 END), 0)
		FROM pagination_snapshots`, authority).Scan(&globalCount, &authorityCount)
	if err != nil {
		return err
	}
	if globalCount >= maxActiveSearchSnapshotsGlobal || authorityCount >= maxActiveSearchSnapshotsPerAuthority {
		return errSnapshotCapacity
	}
	return nil
}

func (d *controlDatabase) readSnapshotPage(ctx context.Context, store ContentStore, request *protocol.SearchRequest, now time.Time) (searchPage, error) {
	snapshotID, offset, err := parsePageToken(request.PageToken)
	if err != nil {
		return searchPage{}, errSnapshotInvalid
	}
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return searchPage{}, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := ensureOwnedInTx(ctx, tx, request.Binding); err != nil {
		return searchPage{}, err
	}
	var state snapshotState
	var authority, fingerprint, expiresAtRaw string
	var pageSize int
	err = tx.QueryRowContext(ctx, `SELECT authority_digest, request_fingerprint, provider_snapshot_id,
		provider_store_id, actual_mode, page_size, entry_count, expires_at
		FROM pagination_snapshots WHERE snapshot_id = ? AND state = ?`, snapshotID, snapshotStateReady).
		Scan(&authority, &fingerprint, &state.providerSnapshot, &state.providerStoreID,
			&state.actualMode, &pageSize, &state.entryCount, &expiresAtRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return searchPage{}, errSnapshotInvalid
	}
	if err != nil {
		return searchPage{}, err
	}
	state.snapshotID = snapshotID
	state.expiresAt, err = parseTime(expiresAtRaw)
	if err != nil {
		return searchPage{}, err
	}
	if !state.expiresAt.After(now) {
		return searchPage{}, errSnapshotExpired
	}
	if authority != protocol.AuthorityDigest(request.Binding) || fingerprint != searchFingerprint(request) ||
		pageSize != request.PageSize || offset < 0 || offset > state.entryCount {
		return searchPage{}, errSnapshotInvalid
	}
	end := min(offset+pageSize, state.entryCount)
	entries, err := snapshotEntriesInTx(ctx, tx, snapshotID, offset, end)
	if err != nil {
		return searchPage{}, err
	}
	if err := validateSearchSnapshotEntries(state.actualMode, entries); err != nil {
		return searchPage{}, err
	}
	if err := tx.Commit(); err != nil {
		return searchPage{}, err
	}
	records, err := readProviderPage(ctx, store, request.Binding, state.providerStoreID, state.providerSnapshot, entries)
	if err != nil {
		return searchPage{}, err
	}
	return pageFromRecords(snapshotID, offset, end, state.entryCount, state.actualMode, state.expiresAt, records), nil
}

func liveControlsForEntriesInTx(
	ctx context.Context,
	tx *sql.Tx,
	authority string,
	entries []ContentDescriptor,
) (map[string]controlRecord, error) {
	const batchSize = 200
	result := make(map[string]controlRecord, len(entries))
	keys := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, exists := seen[entry.UpsertKey]; exists {
			continue
		}
		seen[entry.UpsertKey] = struct{}{}
		keys = append(keys, entry.UpsertKey)
	}
	for start := 0; start < len(keys); start += batchSize {
		end := min(start+batchSize, len(keys))
		placeholders := strings.TrimSuffix(strings.Repeat("?,", end-start), ",")
		arguments := make([]any, 0, 2+end-start)
		arguments = append(arguments, authority, protocol.RecordStateLive)
		for _, key := range keys[start:end] {
			arguments = append(arguments, key)
		}
		rows, err := tx.QueryContext(ctx, `SELECT upsert_key, memory_id, generation, backend_version,
			backend_memory_id, content_digest, updated_at FROM record_controls
			WHERE authority_digest = ? AND state = ? AND upsert_key IN (`+placeholders+`)`, arguments...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var record controlRecord
			var generation int64
			var updatedAtRaw string
			if err := rows.Scan(&record.UpsertKey, &record.MemoryID, &generation, &record.BackendVersion,
				&record.BackendMemoryID, &record.ContentDigest, &updatedAtRaw); err != nil {
				_ = rows.Close()
				return nil, err
			}
			record.AuthorityDigest, record.State, record.Generation = authority, protocol.RecordStateLive, uint64(generation)
			record.UpdatedAt, err = parseTime(updatedAtRaw)
			if err != nil {
				_ = rows.Close()
				return nil, err
			}
			result[record.UpsertKey] = record
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func snapshotEntriesInTx(ctx context.Context, tx *sql.Tx, snapshotID string, start, end int) ([]ContentDescriptor, error) {
	rows, err := tx.QueryContext(ctx, `SELECT upsert_key, memory_id, generation, backend_version,
		backend_memory_id, content_digest, updated_at, score FROM pagination_entries
		WHERE snapshot_id = ? AND position >= ? AND position < ? ORDER BY position ASC`, snapshotID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck
	entries := make([]ContentDescriptor, 0, end-start)
	for rows.Next() {
		var entry ContentDescriptor
		var generation int64
		var updatedAtRaw string
		if err := rows.Scan(&entry.UpsertKey, &entry.MemoryID, &generation, &entry.Version,
			&entry.ProviderID, &entry.ContentDigest, &updatedAtRaw, &entry.Score); err != nil {
			return nil, err
		}
		entry.Generation = uint64(generation)
		entry.UpdatedAt, err = parseTime(updatedAtRaw)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func readProviderPage(ctx context.Context, store ContentStore, binding protocol.Binding, providerStoreID, providerSnapshot string, entries []ContentDescriptor) ([]protocol.MemoryRecord, error) {
	if len(entries) == 0 {
		return []protocol.MemoryRecord{}, nil
	}
	records := make([]protocol.MemoryRecord, 0, len(entries))
	scope := authorityScopeForBinding(binding)
	for i := range entries {
		contents, err := store.ReadSearchPage(ctx, ContentSearchPageRequest{
			TenantID: binding.TenantID, ProviderStoreID: providerStoreID, Scope: scope,
			SnapshotID: providerSnapshot, Entries: entries[i : i+1],
		})
		if err != nil {
			return nil, err
		}
		if len(contents) != 1 {
			return nil, &StoreError{Code: "KD6_INCOMPLETE_SEARCH_PAGE", Retryable: true, Kind: ErrProviderDiverged}
		}
		control := controlRecord{
			UpsertKey: entries[i].UpsertKey, MemoryID: entries[i].MemoryID, State: protocol.RecordStateLive,
			Generation: entries[i].Generation, BackendVersion: entries[i].Version,
			BackendMemoryID: entries[i].ProviderID, ContentDigest: entries[i].ContentDigest,
			UpdatedAt: entries[i].UpdatedAt,
		}
		if !contentMatchesControl(contents[0], control, binding) {
			return nil, &StoreError{Code: "KD6_SEARCH_SNAPSHOT_CHANGED", Retryable: true, Kind: ErrProviderDiverged}
		}
		contents[0].Score = entries[i].Score
		records = append(records, liveRecordFromContent(control, contents[0]))
	}
	return records, nil
}

func contentMatchesMutation(content ContentRecord, request *protocol.MutationEnvelope) bool {
	if request == nil || request.State == nil {
		return false
	}
	return content.UpsertKey == request.UpsertKey && content.Text == request.State.Content &&
		equalStringSlices(content.Tags, request.State.Tags) && equalStringMaps(content.Attributes, request.State.Metadata) &&
		content.Scope == scopeForMutation(request.Binding, request.MemoryID, request.Generation, request.ContentDigest) &&
		content.SourceURI == sourceURI(request.Binding, request.MemoryID) &&
		protocol.ContentDigest(content.Text) == request.ContentDigest
}

func contentMatchesControl(content ContentRecord, control controlRecord, binding protocol.Binding) bool {
	return protocol.ContentDigest(content.Text) == control.ContentDigest &&
		contentDescriptorIdentityEqual(descriptorFromRecord(content), descriptorFromControl(control)) &&
		content.Scope == scopeForMutation(binding, control.MemoryID, control.Generation, control.ContentDigest) &&
		content.SourceURI == sourceURI(binding, control.MemoryID)
}

func descriptorMatchesControl(entry ContentDescriptor, control controlRecord) bool {
	return contentDescriptorIdentityEqual(entry, descriptorFromControl(control))
}

func descriptorFromControl(control controlRecord) ContentDescriptor {
	return ContentDescriptor{
		UpsertKey: control.UpsertKey, ProviderID: control.BackendMemoryID, Version: control.BackendVersion,
		MemoryID: control.MemoryID, Generation: control.Generation,
		ContentDigest: control.ContentDigest, UpdatedAt: control.UpdatedAt,
	}
}

func liveRecordFromContent(control controlRecord, content ContentRecord) protocol.MemoryRecord {
	return protocol.MemoryRecord{
		MemoryID: control.MemoryID, UpsertKey: control.UpsertKey, State: protocol.RecordStateLive,
		Generation: control.Generation, BackendVersion: control.BackendVersion,
		BackendMemoryID: control.BackendMemoryID, ContentDigest: control.ContentDigest,
		Content: content.Text, Tags: append([]string(nil), content.Tags...),
		Metadata: cloneStringMap(content.Attributes), UpdatedAt: control.UpdatedAt, Score: content.Score,
	}
}

func tombstoneFromControl(control controlRecord) protocol.MemoryRecord {
	return protocol.MemoryRecord{
		MemoryID: control.MemoryID, UpsertKey: control.UpsertKey, State: protocol.RecordStateTombstone,
		Generation: control.Generation, BackendVersion: control.BackendVersion,
		BackendMemoryID: control.BackendMemoryID, ContentDigest: protocol.EmptyContentDigest(),
		Content: "", Tags: []string{}, Metadata: map[string]string{}, UpdatedAt: control.UpdatedAt,
	}
}

func sourceURI(binding protocol.Binding, memoryID string) string {
	return "orka://memory/" + url.PathEscape(binding.TenantID) + "/" + url.PathEscape(memoryID)
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func pageFromRecords(snapshotID string, start, nextOffset, total int, actualMode string, expiresAt time.Time, records []protocol.MemoryRecord) searchPage {
	exhausted := nextOffset >= total
	next := ""
	if !exhausted {
		next = formatPageToken(snapshotID, nextOffset)
	}
	if records == nil {
		records = []protocol.MemoryRecord{}
	}
	return searchPage{
		snapshotID: snapshotID, start: start, total: total, actualMode: actualMode, records: records,
		nextToken: next, exhausted: exhausted, expiresAt: expiresAt,
	}
}

func searchFingerprint(request *protocol.SearchRequest) string {
	data, _ := protocol.EncodeJSON(struct {
		Authority string `json:"authority"`
		Mode      string `json:"mode"`
		Query     string `json:"query"`
		PageSize  int    `json:"pageSize"`
	}{Authority: protocol.AuthorityDigest(request.Binding), Mode: request.Mode, Query: request.Query, PageSize: request.PageSize})
	return protocol.ContentDigest(string(data))
}

func randomSnapshotID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func formatPageToken(snapshotID string, offset int) string {
	return "oms-page-v1." + snapshotID + "." + strconv.Itoa(offset)
}

func parsePageToken(token string) (string, int, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "oms-page-v1" || len(parts[1]) != 32 {
		return "", 0, errSnapshotInvalid
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return "", 0, errSnapshotInvalid
	}
	offset, err := strconv.Atoi(parts[2])
	if err != nil || offset < 0 {
		return "", 0, errSnapshotInvalid
	}
	return parts[1], offset, nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	result, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse persisted time: %w", err)
	}
	return result.UTC(), nil
}
