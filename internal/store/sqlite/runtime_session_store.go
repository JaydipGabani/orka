/*
Copyright (c) 2026.

MIT License - see LICENSE file for details.
*/

package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/orka-agents/orka/internal/runtimesession"
	"github.com/orka-agents/orka/internal/store"
)

const (
	defaultRuntimeSessionLimit = 50
	maxRuntimeSessionLimit     = 200
)

var _ runtimesession.RuntimeSessionStore = (*Store)(nil)

// CreateRuntimeSession persists a new backend-neutral RuntimeSession.
func (s *Store) CreateRuntimeSession(ctx context.Context, session *runtimesession.RuntimeSession) error {
	normalized, err := normalizeRuntimeSessionForCreate(session)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO runtime_sessions (
			id, namespace, session_name, active_task, agent_name, provider, state, cleanup_policy,
			idle_timeout_ns, max_lifetime_ns, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(normalized.ID), normalized.Owner.Namespace, normalized.Owner.SessionName, normalized.Owner.ActiveTask,
		normalized.Owner.AgentName, string(normalized.Owner.Provider), string(normalized.State), string(normalized.CleanupPolicy),
		int64(normalized.IdleTimeout), int64(normalized.MaxLifetime), normalized.CreatedAt, normalized.UpdatedAt,
	)
	if err != nil {
		if isSQLiteConstraintError(err) {
			return fmt.Errorf("%w: runtime session %s/%s already exists", store.ErrConflict, normalized.Owner.Namespace, normalized.ID)
		}
		return err
	}
	*session = normalized
	return nil
}

// GetRuntimeSession loads a RuntimeSession by namespace and canonical ID.
func (s *Store) GetRuntimeSession(ctx context.Context, namespace string, id runtimesession.RuntimeSessionID) (*runtimesession.RuntimeSession, error) {
	session, err := getRuntimeSessionTx(ctx, s.db, namespace, id)
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// ListRuntimeSessions returns RuntimeSessions matching filter, ordered by most recent update first.
func (s *Store) ListRuntimeSessions(ctx context.Context, filter runtimesession.RuntimeSessionFilter) ([]runtimesession.RuntimeSession, string, error) {
	filter, limit, offset, err := validateRuntimeSessionFilter(filter)
	if err != nil {
		return nil, "", err
	}

	query := strings.Builder{}
	query.WriteString(runtimeSessionSelectSQL())
	clauses := []string{"namespace = ?"}
	args := []any{filter.Namespace}
	addClause := func(clause string, arg any) {
		clauses = append(clauses, clause)
		args = append(args, arg)
	}
	if filter.SessionName != "" {
		addClause("session_name = ?", filter.SessionName)
	}
	if filter.ActiveTask != "" {
		addClause("active_task = ?", filter.ActiveTask)
	}
	if filter.AgentName != "" {
		addClause("agent_name = ?", filter.AgentName)
	}
	if filter.Provider != "" {
		addClause("provider = ?", string(filter.Provider))
	}
	if len(filter.States) > 0 {
		placeholders := make([]string, 0, len(filter.States))
		for _, state := range filter.States {
			placeholders = append(placeholders, "?")
			args = append(args, string(state))
		}
		clauses = append(clauses, "state IN ("+strings.Join(placeholders, ",")+")")
	} else if !filter.IncludeDeleted {
		addClause("state <> ?", string(runtimesession.RuntimeSessionStateDeleted))
	}
	if len(filter.CleanupPolicies) > 0 {
		placeholders := make([]string, 0, len(filter.CleanupPolicies))
		for _, policy := range filter.CleanupPolicies {
			placeholders = append(placeholders, "?")
			args = append(args, string(policy))
		}
		clauses = append(clauses, "cleanup_policy IN ("+strings.Join(placeholders, ",")+")")
	}
	query.WriteString(" WHERE ")
	query.WriteString(strings.Join(clauses, " AND "))
	query.WriteString(" ORDER BY updated_at DESC, id ASC LIMIT ? OFFSET ?")
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close() //nolint:errcheck

	sessions := []runtimesession.RuntimeSession{}
	for rows.Next() {
		session, err := scanRuntimeSession(rows)
		if err != nil {
			return nil, "", err
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return sessions, nextOffsetCursor(offset, len(sessions), limit), nil
}

// TransitionRuntimeSession validates and persists an optimistic RuntimeSession state transition.
func (s *Store) TransitionRuntimeSession(
	ctx context.Context,
	transition runtimesession.RuntimeSessionTransition,
) (*runtimesession.RuntimeSession, error) {
	transition, err := normalizeRuntimeSessionTransition(transition)
	if err != nil {
		return nil, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	session, err := getRuntimeSessionTx(ctx, tx, transition.Namespace, transition.ID)
	if err != nil {
		return nil, err
	}
	if session.State != transition.From {
		return nil, fmt.Errorf(
			"%w: runtime session %s/%s is %s, expected %s",
			store.ErrConflict,
			transition.Namespace,
			transition.ID,
			session.State,
			transition.From,
		)
	}
	activeTask := session.Owner.ActiveTask
	if transition.ActiveTask != nil {
		activeTask = strings.TrimSpace(*transition.ActiveTask)
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE runtime_sessions SET state = ?, active_task = ?, updated_at = ?
		 WHERE namespace = ? AND id = ? AND state = ?`,
		string(transition.To), activeTask, transition.UpdatedAt, transition.Namespace, string(transition.ID), string(transition.From),
	)
	if err != nil {
		return nil, err
	}
	if err := ensureRowsAffected(res); err != nil {
		return nil, err
	}
	session.State = transition.To
	session.Owner.ActiveTask = activeTask
	session.UpdatedAt = transition.UpdatedAt
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &session, nil
}

// DeleteRuntimeSession physically prunes a RuntimeSession after it reaches Deleted.
func (s *Store) DeleteRuntimeSession(ctx context.Context, namespace string, id runtimesession.RuntimeSessionID) error {
	namespace, id, err := normalizeRuntimeSessionKey(namespace, id)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM runtime_sessions WHERE namespace = ? AND id = ? AND state = ?`,
		namespace,
		string(id),
		string(runtimesession.RuntimeSessionStateDeleted),
	)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows > 0 {
		return nil
	}
	session, err := getRuntimeSessionTx(ctx, s.db, namespace, id)
	if err != nil {
		return err
	}
	return store.ValidationErrorf("runtime session %s/%s must be %s before physical deletion (current state: %s)", namespace, id, runtimesession.RuntimeSessionStateDeleted, session.State)
}

func getRuntimeSessionTx(ctx context.Context, db queryRower, namespace string, id runtimesession.RuntimeSessionID) (runtimesession.RuntimeSession, error) {
	namespace, id, err := normalizeRuntimeSessionKey(namespace, id)
	if err != nil {
		return runtimesession.RuntimeSession{}, err
	}
	row := db.QueryRowContext(ctx, runtimeSessionSelectSQL()+` WHERE namespace = ? AND id = ?`, namespace, strings.TrimSpace(string(id)))
	session, err := scanRuntimeSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return runtimesession.RuntimeSession{}, store.ErrNotFound
	}
	if err != nil {
		return runtimesession.RuntimeSession{}, err
	}
	return session, nil
}

func runtimeSessionSelectSQL() string {
	return `SELECT id, namespace, session_name, active_task, agent_name, provider, state, cleanup_policy,
		idle_timeout_ns, max_lifetime_ns, created_at, updated_at FROM runtime_sessions`
}

func scanRuntimeSession(scanner rowScanner) (runtimesession.RuntimeSession, error) {
	var session runtimesession.RuntimeSession
	var provider, state, cleanupPolicy string
	var idleTimeoutNS, maxLifetimeNS int64
	err := scanner.Scan(
		&session.ID,
		&session.Owner.Namespace,
		&session.Owner.SessionName,
		&session.Owner.ActiveTask,
		&session.Owner.AgentName,
		&provider,
		&state,
		&cleanupPolicy,
		&idleTimeoutNS,
		&maxLifetimeNS,
		&session.CreatedAt,
		&session.UpdatedAt,
	)
	if err != nil {
		return runtimesession.RuntimeSession{}, err
	}
	session.Owner.Provider = runtimesession.ProviderKind(provider)
	session.State = runtimesession.RuntimeSessionState(state)
	session.CleanupPolicy = runtimesession.RuntimeCleanupPolicy(cleanupPolicy)
	session.IdleTimeout = time.Duration(idleTimeoutNS)
	session.MaxLifetime = time.Duration(maxLifetimeNS)
	return session, nil
}

func normalizeRuntimeSessionForCreate(session *runtimesession.RuntimeSession) (runtimesession.RuntimeSession, error) {
	if session == nil {
		return runtimesession.RuntimeSession{}, store.ValidationErrorf("runtime session is required")
	}
	normalized := *session
	normalized.ID = runtimesession.RuntimeSessionID(strings.TrimSpace(string(normalized.ID)))
	normalized.Owner.Namespace = strings.TrimSpace(normalized.Owner.Namespace)
	normalized.Owner.SessionName = strings.TrimSpace(normalized.Owner.SessionName)
	normalized.Owner.ActiveTask = strings.TrimSpace(normalized.Owner.ActiveTask)
	normalized.Owner.AgentName = strings.TrimSpace(normalized.Owner.AgentName)
	normalized.Owner.Provider = runtimesession.ProviderKind(strings.TrimSpace(string(normalized.Owner.Provider)))
	if normalized.State == "" {
		normalized.State = runtimesession.RuntimeSessionStatePending
	}
	if normalized.CleanupPolicy == "" {
		normalized.CleanupPolicy = runtimesession.RuntimeCleanupPolicyDelete
	}
	if err := normalized.Validate(); err != nil {
		return runtimesession.RuntimeSession{}, store.ValidationErrorf("invalid runtime session: %v", err)
	}
	now := time.Now().UTC()
	if normalized.CreatedAt.IsZero() {
		normalized.CreatedAt = now
	} else {
		normalized.CreatedAt = normalized.CreatedAt.UTC()
	}
	if normalized.UpdatedAt.IsZero() {
		normalized.UpdatedAt = normalized.CreatedAt
	} else {
		normalized.UpdatedAt = normalized.UpdatedAt.UTC()
	}
	return normalized, nil
}

func normalizeRuntimeSessionTransition(transition runtimesession.RuntimeSessionTransition) (runtimesession.RuntimeSessionTransition, error) {
	namespace, id, err := normalizeRuntimeSessionKey(transition.Namespace, transition.ID)
	if err != nil {
		return runtimesession.RuntimeSessionTransition{}, err
	}
	transition.Namespace = namespace
	transition.ID = id
	if err := runtimesession.ValidateRuntimeSessionTransition(transition.From, transition.To); err != nil {
		return runtimesession.RuntimeSessionTransition{}, store.ValidationErrorf("invalid runtime session transition: %v", err)
	}
	if transition.UpdatedAt.IsZero() {
		transition.UpdatedAt = time.Now().UTC()
	} else {
		transition.UpdatedAt = transition.UpdatedAt.UTC()
	}
	return transition, nil
}

func validateRuntimeSessionFilter(filter runtimesession.RuntimeSessionFilter) (runtimesession.RuntimeSessionFilter, int, int, error) {
	filter.Namespace = strings.TrimSpace(filter.Namespace)
	if filter.Namespace == "" {
		return runtimesession.RuntimeSessionFilter{}, 0, 0, store.ValidationErrorf("runtime session namespace is required")
	}
	filter.SessionName = strings.TrimSpace(filter.SessionName)
	filter.ActiveTask = strings.TrimSpace(filter.ActiveTask)
	filter.AgentName = strings.TrimSpace(filter.AgentName)
	filter.Provider = runtimesession.ProviderKind(strings.TrimSpace(string(filter.Provider)))
	for _, state := range filter.States {
		if !runtimesession.IsKnownRuntimeSessionState(state) {
			return runtimesession.RuntimeSessionFilter{}, 0, 0, store.ValidationErrorf("unsupported runtime session state %q", state)
		}
	}
	for _, policy := range filter.CleanupPolicies {
		if !runtimesession.IsKnownRuntimeCleanupPolicy(policy) {
			return runtimesession.RuntimeSessionFilter{}, 0, 0, store.ValidationErrorf("unsupported runtime cleanup policy %q", policy)
		}
	}
	offset, err := parseOffsetCursor(filter.Cursor)
	if err != nil {
		return runtimesession.RuntimeSessionFilter{}, 0, 0, store.ValidationErrorf("invalid runtime session cursor: %v", err)
	}
	limit := boundedLimit(filter.Limit, defaultRuntimeSessionLimit, maxRuntimeSessionLimit)
	return filter, limit, offset, nil
}

func normalizeRuntimeSessionKey(namespace string, id runtimesession.RuntimeSessionID) (string, runtimesession.RuntimeSessionID, error) {
	namespace = strings.TrimSpace(namespace)
	id = runtimesession.RuntimeSessionID(strings.TrimSpace(string(id)))
	if namespace == "" {
		return "", "", store.ValidationErrorf("runtime session namespace is required")
	}
	if id == "" {
		return "", "", store.ValidationErrorf("runtime session id is required")
	}
	return namespace, id, nil
}
