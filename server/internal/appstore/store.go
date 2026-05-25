package appstore

import (
	"context"
	"database/sql"
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
			encrypted INTEGER NOT NULL DEFAULT 0,
			domain TEXT NOT NULL DEFAULT '',
			domain_enabled INTEGER NOT NULL DEFAULT 0,
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(app_id) REFERENCES applications(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_app_routes_app_id ON app_routes(app_id);`,
		`CREATE INDEX IF NOT EXISTS idx_app_routes_route_name ON app_routes(route_name);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
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
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO app_routes(app_id, route_name, proto, public_addr, local_addr, encrypted, domain, domain_enabled, enabled, created_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		appID, route.RouteName, route.Proto, route.PublicAddr, route.LocalAddr,
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
		`SELECT id, app_id, route_name, proto, public_addr, local_addr, encrypted, domain, domain_enabled, enabled, created_at
		 FROM app_routes WHERE route_name = ?`, routeName).Scan(
		&r.ID, &r.AppID, &r.RouteName, &r.Proto, &r.PublicAddr, &r.LocalAddr,
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
		`SELECT id, app_id, route_name, proto, public_addr, local_addr, encrypted, domain, domain_enabled, enabled, created_at
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
		if err := rows.Scan(&r.ID, &r.AppID, &r.RouteName, &r.Proto, &r.PublicAddr, &r.LocalAddr,
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
		`SELECT id, app_id, route_name, proto, public_addr, local_addr, encrypted, domain, domain_enabled, enabled, created_at
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
		if err := rows.Scan(&r.ID, &r.AppID, &r.RouteName, &r.Proto, &r.PublicAddr, &r.LocalAddr,
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
