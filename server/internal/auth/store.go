package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"golang.org/x/crypto/bcrypt"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// reasonable defaults for a tiny app
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash BLOB NOT NULL,
			created_at INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			created_at INTEGER NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) HasAnyUsers(ctx context.Context) (bool, error) {
	row := s.db.QueryRowContext(ctx, `SELECT 1 FROM users LIMIT 1`)
	var one int
	err := row.Scan(&one)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return false, err
}

func (s *Store) CreateUser(ctx context.Context, username string, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users(username, password_hash, created_at) VALUES(?, ?, ?)`,
		username, hash, time.Now().Unix())
	if err != nil {
		return err
	}
	return nil
}

func (s *Store) Authenticate(ctx context.Context, username string, password string) (int64, bool, error) {
	var id int64
	var hash []byte
	err := s.db.QueryRowContext(ctx, `SELECT id, password_hash FROM users WHERE username = ?`, username).Scan(&id, &hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
		return 0, false, nil
	}
	return id, true, nil
}

func (s *Store) CreateSession(ctx context.Context, userID int64, ttl time.Duration) (string, error) {
	_ = s.deleteExpired(ctx)

	sid, err := randHex(32)
	if err != nil {
		return "", err
	}
	exp := time.Now().Add(ttl).Unix()
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions(id, user_id, expires_at, created_at) VALUES(?, ?, ?, ?)`, sid, userID, exp, time.Now().Unix())
	if err != nil {
		return "", err
	}
	return sid, nil
}

func (s *Store) GetSession(ctx context.Context, sid string) (int64, bool, error) {
	_ = s.deleteExpired(ctx)

	var userID int64
	var expiresAt int64
	err := s.db.QueryRowContext(ctx, `SELECT user_id, expires_at FROM sessions WHERE id = ?`, sid).Scan(&userID, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	if time.Now().Unix() > expiresAt {
		_ = s.DeleteSession(ctx, sid)
		return 0, false, nil
	}
	return userID, true, nil
}

func (s *Store) DeleteSession(ctx context.Context, sid string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, sid)
	return err
}

func (s *Store) deleteExpired(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, time.Now().Unix())
	return err
}

func randHex(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func IsUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	// modernc sqlite returns errors with text including "UNIQUE constraint failed"
	return errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "UNIQUE constraint failed")
}

var ErrBadInput = fmt.Errorf("bad input")
