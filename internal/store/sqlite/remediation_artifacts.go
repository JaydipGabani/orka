package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/orka-agents/orka/internal/store"
)

const remediationArtifactColumns = `name, digest, media_type, size, created_at`

func (s *Store) PutRemediationArtifact(ctx context.Context, namespace, id, owner string, epoch uint64, name, mediaType string, data []byte, now time.Time) (*store.RemediationArtifact, error) {
	if err := validateRemediationIdentity(namespace, id); err != nil {
		return nil, err
	}
	if err := validateRemediationFence(owner, epoch, now); err != nil {
		return nil, err
	}
	if err := validateRemediationArtifactName(name); err != nil {
		return nil, err
	}
	if err := validateRemediationArtifact(mediaType, data); err != nil {
		return nil, err
	}
	var artifact *store.RemediationArtifact
	err := s.withRemediationTx(ctx, func(tx *sql.Tx) error {
		run, err := getRemediationRunMetadata(ctx, tx, namespace, id)
		if err != nil {
			return err
		}
		if err := requireRemediationClaim(run, owner, epoch, now); err != nil {
			return err
		}
		existing, previousData, err := getRemediationArtifact(ctx, tx, namespace, id, name)
		if err == nil {
			if existing.MediaType != mediaType || !bytes.Equal(previousData, data) {
				return store.ErrConflict
			}
			artifact = existing
			return nil
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := admitRemediationArtifact(ctx, tx, namespace, id, len(data)); err != nil {
			return err
		}
		artifact = &store.RemediationArtifact{
			Name: name, Digest: remediationArtifactDigest(data), MediaType: mediaType,
			Size: int64(len(data)), CreatedAt: now.UTC(),
		}
		if data == nil {
			data = []byte{}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO remediation_artifacts
			(namespace, run_id, name, digest, media_type, size, created_at, data)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			namespace, id, artifact.Name, artifact.Digest, artifact.MediaType, artifact.Size,
			artifact.CreatedAt.UnixNano(), data)
		return err
	})
	if err != nil {
		return nil, err
	}
	return artifact, nil
}

func admitRemediationArtifact(ctx context.Context, tx *sql.Tx, namespace, id string, size int) error {
	var count, total int64
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(length(data)), 0)
		FROM remediation_artifacts WHERE namespace = ? AND run_id = ?`,
		namespace, id).Scan(&count, &total); err != nil {
		return err
	}
	if count >= store.RemediationMaxArtifacts || total+int64(size) > store.RemediationMaxArtifactTotalBytes {
		return store.ErrCapacity
	}
	return requireRemediationNamespaceCapacity(ctx, tx, namespace, int64(size))
}

func remediationArtifactDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (s *Store) GetRemediationArtifact(ctx context.Context, namespace, id, name string) (*store.RemediationArtifact, []byte, error) {
	if err := validateRemediationIdentity(namespace, id); err != nil {
		return nil, nil, err
	}
	if err := validateRemediationArtifactName(name); err != nil {
		return nil, nil, err
	}
	return getRemediationArtifact(ctx, s.db, namespace, id, name)
}

func getRemediationArtifact(ctx context.Context, query queryRower, namespace, id, name string) (*store.RemediationArtifact, []byte, error) {
	var artifact store.RemediationArtifact
	var createdAt int64
	var data []byte
	err := query.QueryRowContext(ctx, `SELECT `+remediationArtifactColumns+`, data
		FROM remediation_artifacts WHERE namespace = ? AND run_id = ? AND name = ?`,
		namespace, id, name).Scan(&artifact.Name, &artifact.Digest, &artifact.MediaType, &artifact.Size, &createdAt, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, store.ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if len(data) > store.RemediationMaxArtifactBytes || int64(len(data)) != artifact.Size ||
		remediationArtifactDigest(data) != artifact.Digest {
		return nil, nil, store.ErrRemediationIntegrity
	}
	artifact.CreatedAt = time.Unix(0, createdAt).UTC()
	return &artifact, data, nil
}

func (s *Store) ListRemediationArtifacts(ctx context.Context, namespace, id string) ([]store.RemediationArtifact, error) {
	if err := validateRemediationIdentity(namespace, id); err != nil {
		return nil, err
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM remediation_runs WHERE namespace = ? AND id = ?
	)`, namespace, id).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, store.ErrNotFound
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+remediationArtifactColumns+`
		FROM remediation_artifacts WHERE namespace = ? AND run_id = ? ORDER BY name LIMIT ?`,
		namespace, id, store.RemediationMaxArtifacts+1)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	artifacts := make([]store.RemediationArtifact, 0)
	for rows.Next() {
		var artifact store.RemediationArtifact
		var createdAt int64
		if err := rows.Scan(&artifact.Name, &artifact.Digest, &artifact.MediaType, &artifact.Size, &createdAt); err != nil {
			return nil, err
		}
		if len(artifacts) == store.RemediationMaxArtifacts {
			return nil, store.ErrRemediationIntegrity
		}
		artifact.CreatedAt = time.Unix(0, createdAt).UTC()
		artifacts = append(artifacts, artifact)
	}
	return artifacts, rows.Err()
}
