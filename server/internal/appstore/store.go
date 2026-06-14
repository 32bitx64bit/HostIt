package appstore

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

type Application struct {
	ID         int64
	Label      string
	APIKeyHash string
	Enabled    bool
	CreatedAt  time.Time
	Routes     []AppRoute
}

type AppRoute struct {
	ID            int64
	AppID         int64
	RouteName     string
	Proto         string
	PublicAddr    string
	LocalAddr     string
	AgentID       string
	Encrypted     bool
	Domain        string
	DomainEnabled bool
	Enabled       bool
	CreatedAt     time.Time
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)

	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS applications (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			label TEXT NOT NULL UNIQUE,
			api_key_hash TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS app_routes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			app_id INTEGER NOT NULL,
			route_name TEXT NOT NULL UNIQUE,
			proto TEXT NOT NULL DEFAULT 'tcp',
			public_addr TEXT NOT NULL DEFAULT '',
			local_addr TEXT NOT NULL DEFAULT '',
			agent_id TEXT NOT NULL DEFAULT 'default',
			encrypted INTEGER NOT NULL DEFAULT 0,
			domain TEXT NOT NULL DEFAULT '',
			domain_enabled INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(app_id) REFERENCES applications(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_app_routes_app_id ON app_routes(app_id);`,
		`CREATE INDEX IF NOT EXISTS idx_app_routes_route_name ON app_routes(route_name);`,
		`CREATE TABLE IF NOT EXISTS agents (
			public_key TEXT PRIMARY KEY,
			agent_id   TEXT NOT NULL UNIQUE,
			first_seen INTEGER NOT NULL,
			last_seen  INTEGER NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	// CREATE TABLE IF NOT EXISTS won't add agent_id to a pre-existing app_routes.
	if err := s.addColumnIfMissing(ctx, "app_routes", "agent_id", "TEXT NOT NULL DEFAULT 'default'"); err != nil {
		return err
	}
	return nil
}

func (s *Store) addColumnIfMissing(ctx context.Context, table, column, decl string) error {
	rows, err := s.db.QueryContext(ctx, fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name       string
			ctype      string
			notnull    int
			dfltValue  sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &primaryKey); err != nil {
			return err
		}
		if name == column {
			return rows.Close()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, decl))
	return err
}

func (s *Store) CreateApplication(ctx context.Context, label string, apiKeyHash string) (*Application, error) {
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO applications(label, api_key_hash, enabled, created_at) VALUES(?, ?, 1, ?)`,
		label, apiKeyHash, now)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &Application{
		ID:         id,
		Label:      label,
		APIKeyHash: apiKeyHash,
		Enabled:    true,
		CreatedAt:  time.Unix(now, 0),
	}, nil
}

func (s *Store) GetApplication(ctx context.Context, label string) (*Application, error) {
	var app Application
	var enabled int
	var createdAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, label, api_key_hash, enabled, created_at FROM applications WHERE label = ?`,
		label).Scan(&app.ID, &app.Label, &app.APIKeyHash, &enabled, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	app.Enabled = enabled != 0
	app.CreatedAt = time.Unix(createdAt, 0)
	routes, err := s.loadRoutes(ctx, app.ID)
	if err != nil {
		return nil, err
	}
	app.Routes = routes
	return &app, nil
}

func (s *Store) GetApplicationByID(ctx context.Context, id int64) (*Application, error) {
	var app Application
	var enabled int
	var createdAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, label, api_key_hash, enabled, created_at FROM applications WHERE id = ?`,
		id).Scan(&app.ID, &app.Label, &app.APIKeyHash, &enabled, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	app.Enabled = enabled != 0
	app.CreatedAt = time.Unix(createdAt, 0)
	routes, err := s.loadRoutes(ctx, app.ID)
	if err != nil {
		return nil, err
	}
	app.Routes = routes
	return &app, nil
}

func (s *Store) ListApplications(ctx context.Context) ([]Application, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, label, api_key_hash, enabled, created_at FROM applications ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []Application
	for rows.Next() {
		var app Application
		var enabled int
		var createdAt int64
		if err := rows.Scan(&app.ID, &app.Label, &app.APIKeyHash, &enabled, &createdAt); err != nil {
			return nil, err
		}
		app.Enabled = enabled != 0
		app.CreatedAt = time.Unix(createdAt, 0)
		routes, err := s.loadRoutes(ctx, app.ID)
		if err != nil {
			return nil, err
		}
		app.Routes = routes
		apps = append(apps, app)
	}
	return apps, rows.Err()
}

func (s *Store) SetApplicationEnabled(ctx context.Context, label string, enabled bool) error {
	e := boolToInt(enabled)
	res, err := s.db.ExecContext(ctx,
		`UPDATE applications SET enabled = ? WHERE label = ?`, e, label)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	_, err = s.db.ExecContext(ctx,
		`UPDATE app_routes SET enabled = ? WHERE app_id = (SELECT id FROM applications WHERE label = ?)`,
		e, label)
	return err
}

func (s *Store) DeleteApplication(ctx context.Context, label string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM applications WHERE label = ?`, label)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) AddRoute(ctx context.Context, appID int64, route AppRoute) (*AppRoute, error) {
	now := time.Now().Unix()
	agentID := strings.TrimSpace(route.AgentID)
	if agentID == "" {
		agentID = "default"
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO app_routes(app_id, route_name, proto, public_addr, local_addr, agent_id, encrypted, domain, domain_enabled, enabled, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		appID, route.RouteName, route.Proto, route.PublicAddr, route.LocalAddr, agentID,
		boolToInt(route.Encrypted), route.Domain, boolToInt(route.DomainEnabled), boolToInt(route.Enabled), now)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	route.ID = id
	route.AppID = appID
	route.AgentID = agentID
	route.CreatedAt = time.Unix(now, 0)
	return &route, nil
}

func (s *Store) RemoveRoute(ctx context.Context, routeName string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM app_routes WHERE route_name = ?`, routeName)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) SetRouteEnabled(ctx context.Context, routeName string, enabled bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE app_routes SET enabled = ? WHERE route_name = ?`, boolToInt(enabled), routeName)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) GetRouteByRouteName(ctx context.Context, routeName string) (*AppRoute, error) {
	var r AppRoute
	var encrypted, domainEnabled, enabled int
	var createdAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, app_id, route_name, proto, public_addr, local_addr, agent_id, encrypted, domain, domain_enabled, enabled, created_at
		 FROM app_routes WHERE route_name = ?`, routeName).Scan(
		&r.ID, &r.AppID, &r.RouteName, &r.Proto, &r.PublicAddr, &r.LocalAddr, &r.AgentID,
		&encrypted, &r.Domain, &domainEnabled, &enabled, &createdAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	r.Encrypted = encrypted != 0
	r.DomainEnabled = domainEnabled != 0
	r.Enabled = enabled != 0
	r.CreatedAt = time.Unix(createdAt, 0)
	return &r, nil
}

func (s *Store) ListRoutes(ctx context.Context) ([]AppRoute, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, app_id, route_name, proto, public_addr, local_addr, agent_id, encrypted, domain, domain_enabled, enabled, created_at
		 FROM app_routes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var routes []AppRoute
	for rows.Next() {
		var r AppRoute
		var encrypted, domainEnabled, enabled int
		var createdAt int64
		if err := rows.Scan(&r.ID, &r.AppID, &r.RouteName, &r.Proto, &r.PublicAddr, &r.LocalAddr, &r.AgentID,
			&encrypted, &r.Domain, &domainEnabled, &enabled, &createdAt); err != nil {
			return nil, err
		}
		r.Encrypted = encrypted != 0
		r.DomainEnabled = domainEnabled != 0
		r.Enabled = enabled != 0
		r.CreatedAt = time.Unix(createdAt, 0)
		routes = append(routes, r)
	}
	return routes, rows.Err()
}

func (s *Store) FindApplicationByRouteName(ctx context.Context, routeName string) (*Application, error) {
	var appID int64
	err := s.db.QueryRowContext(ctx,
		`SELECT app_id FROM app_routes WHERE route_name = ?`, routeName).Scan(&appID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return s.GetApplicationByID(ctx, appID)
}

func (s *Store) loadRoutes(ctx context.Context, appID int64) ([]AppRoute, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, app_id, route_name, proto, public_addr, local_addr, agent_id, encrypted, domain, domain_enabled, enabled, created_at
		 FROM app_routes WHERE app_id = ? ORDER BY id`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var routes []AppRoute
	for rows.Next() {
		var r AppRoute
		var encrypted, domainEnabled, enabled int
		var createdAt int64
		if err := rows.Scan(&r.ID, &r.AppID, &r.RouteName, &r.Proto, &r.PublicAddr, &r.LocalAddr, &r.AgentID,
			&encrypted, &r.Domain, &domainEnabled, &enabled, &createdAt); err != nil {
			return nil, err
		}
		r.Encrypted = encrypted != 0
		r.DomainEnabled = domainEnabled != 0
		r.Enabled = enabled != 0
		r.CreatedAt = time.Unix(createdAt, 0)
		routes = append(routes, r)
	}
	return routes, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// AgentRecord is a registered agent identity (its public key bound to an ID).
type AgentRecord struct {
	PublicKey string // base64-encoded Ed25519 public key
	AgentID   string
	FirstSeen time.Time
	LastSeen  time.Time
}

// ResolveAgent maps an agent's public key to its authoritative ID. A known key
// re-assumes its registered ID; an unknown key claims proposedID if free
// (trust-on-first-use), else conflict=true so the agent picks a new ID. Atomic
// so two agents can't both win the same ID.
func (s *Store) ResolveAgent(ctx context.Context, pub []byte, proposedID string) (resolved string, conflict bool, err error) {
	proposedID = strings.TrimSpace(proposedID)
	if proposedID == "" {
		proposedID = "default"
	}
	key := base64.StdEncoding.EncodeToString(pub)
	now := time.Now().Unix()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()

	var existingID string
	err = tx.QueryRowContext(ctx, `SELECT agent_id FROM agents WHERE public_key = ?`, key).Scan(&existingID)
	switch {
	case err == nil:
		if _, err = tx.ExecContext(ctx, `UPDATE agents SET last_seen = ? WHERE public_key = ?`, now, key); err != nil {
			return "", false, err
		}
		return existingID, false, tx.Commit()
	case errors.Is(err, sql.ErrNoRows):
		var taken int
		switch err = tx.QueryRowContext(ctx, `SELECT 1 FROM agents WHERE agent_id = ?`, proposedID).Scan(&taken); {
		case err == nil:
			return "", true, nil
		case !errors.Is(err, sql.ErrNoRows):
			return "", false, err
		}
		if _, err = tx.ExecContext(ctx,
			`INSERT INTO agents(public_key, agent_id, first_seen, last_seen) VALUES(?,?,?,?)`,
			key, proposedID, now, now); err != nil {
			return "", false, err
		}
		return proposedID, false, tx.Commit()
	default:
		return "", false, err
	}
}

// RenameAgent changes an agent's ID (operator override). Fails if newID is
// taken or oldID is unknown.
func (s *Store) RenameAgent(ctx context.Context, oldID, newID string) error {
	oldID = strings.TrimSpace(oldID)
	newID = strings.TrimSpace(newID)
	if newID == "" {
		return fmt.Errorf("new agent id is empty")
	}
	if oldID == newID {
		return nil
	}
	res, err := s.db.ExecContext(ctx, `UPDATE agents SET agent_id = ? WHERE agent_id = ?`, newID, oldID)
	if err != nil {
		if IsUniqueConstraint(err) {
			return fmt.Errorf("agent id %q is already in use", newID)
		}
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// ReassignRoutesAgent moves stored (app) routes from one owner to another,
// returning how many were updated. Used when an agent's ID is overridden.
func (s *Store) ReassignRoutesAgent(ctx context.Context, oldID, newID string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE app_routes SET agent_id = ? WHERE agent_id = ?`,
		strings.TrimSpace(newID), strings.TrimSpace(oldID))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteAgent forgets a registered agent so its ID and key can be reclaimed.
func (s *Store) DeleteAgent(ctx context.Context, agentID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM agents WHERE agent_id = ?`, strings.TrimSpace(agentID))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListAgents(ctx context.Context) ([]AgentRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT public_key, agent_id, first_seen, last_seen FROM agents ORDER BY agent_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentRecord
	for rows.Next() {
		var r AgentRecord
		var fs, ls int64
		if err := rows.Scan(&r.PublicKey, &r.AgentID, &fs, &ls); err != nil {
			return nil, err
		}
		r.FirstSeen = time.Unix(fs, 0)
		r.LastSeen = time.Unix(ls, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

func IsUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	var sqliteErr *sqlite.Error
	if errors.As(err, &sqliteErr) {
		code := sqliteErr.Code()
		return code == sqlite3.SQLITE_CONSTRAINT_UNIQUE || code == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || (strings.Contains(msg, "constraint failed") && strings.Contains(strings.ToUpper(msg), "UNIQUE"))
}
