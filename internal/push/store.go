package push

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrTooManyHandles = errors.New("too many handles")
	ErrTokenChanged   = errors.New("token changed")
)

const schema = `
CREATE TABLE IF NOT EXISTS installations (
	id TEXT PRIMARY KEY,
	owner_token_hash BLOB NOT NULL,
	token TEXT NOT NULL,
	topic TEXT NOT NULL,
	environment TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS installations_token ON installations (token);
CREATE TABLE IF NOT EXISTS handles (
	handle TEXT PRIMARY KEY,
	installation_id TEXT NOT NULL,
	host_key BLOB NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS handles_installation ON handles (installation_id);
CREATE TABLE IF NOT EXISTS enrollments (
	id TEXT PRIMARY KEY,
	token TEXT NOT NULL,
	topic TEXT NOT NULL,
	environment TEXT NOT NULL,
	installation_id TEXT NOT NULL,
	code_hash BLOB NOT NULL,
	attempts INTEGER NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS enrollments_expiry ON enrollments (expires_at);
`

type Installation struct {
	ID             string
	OwnerTokenHash []byte
	Token          string
	Topic          string
	Environment    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Enrollment struct {
	ID             string
	Token          string
	Topic          string
	Environment    string
	InstallationID string
	CodeHash       []byte
	Attempts       int
	ExpiresAt      time.Time
}

type Handle struct {
	Handle         string
	InstallationID string
	HostKey        []byte
}

type Store struct {
	db *sql.DB
}

func OpenStore(path string) (*Store, error) {
	dsn := "file:" + (&url.URL{Path: path}).EscapedPath() + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection serializes writers, which keeps multi-statement
	// transactions free of SQLITE_BUSY at the gateway's request rates.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *Store) CreateEnrollment(ctx context.Context, e Enrollment, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM enrollments WHERE expires_at <= ?`, now.UnixMilli()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO enrollments (id, token, topic, environment, installation_id, code_hash, attempts, expires_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
			e.ID, e.Token, e.Topic, e.Environment, e.InstallationID, e.CodeHash, e.ExpiresAt.UnixMilli())
		return err
	})
}

func (s *Store) Enrollment(ctx context.Context, id string, now time.Time) (Enrollment, error) {
	e := Enrollment{ID: id}
	var expires int64
	err := s.db.QueryRowContext(ctx,
		`SELECT token, topic, environment, installation_id, code_hash, attempts, expires_at FROM enrollments WHERE id = ? AND expires_at > ?`,
		id, now.UnixMilli()).Scan(&e.Token, &e.Topic, &e.Environment, &e.InstallationID, &e.CodeHash, &e.Attempts, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return e, ErrNotFound
	}
	e.ExpiresAt = time.UnixMilli(expires)
	return e, err
}

func (s *Store) DeleteEnrollment(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM enrollments WHERE id = ?`, id)
	return err
}

func (s *Store) FailEnrollment(ctx context.Context, id string, maxAttempts int) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE enrollments SET attempts = attempts + 1 WHERE id = ?`, id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM enrollments WHERE id = ? AND attempts >= ?`, id, maxAttempts)
		return err
	})
}

// ConfirmEnrollment consumes the enrollment and makes its token the active
// token of either the enrollment's installation or fresh, which it inserts.
// Every other installation holding the same token belongs to a previous
// install of the app on the same device and is deleted with its handles.
func (s *Store) ConfirmEnrollment(ctx context.Context, e Enrollment, fresh Installation, now time.Time) (string, error) {
	id := e.InstallationID
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM enrollments WHERE id = ? AND expires_at > ?`, e.ID, now.UnixMilli())
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if id != "" {
			res, err := tx.ExecContext(ctx,
				`UPDATE installations SET token = ?, topic = ?, environment = ?, updated_at = ? WHERE id = ?`,
				e.Token, e.Topic, e.Environment, now.UnixMilli(), id)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		} else {
			id = fresh.ID
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO installations (id, owner_token_hash, token, topic, environment, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				id, fresh.OwnerTokenHash, e.Token, e.Topic, e.Environment, now.UnixMilli(), now.UnixMilli()); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM handles WHERE installation_id IN (SELECT id FROM installations WHERE token = ? AND id != ?)`, e.Token, id); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM installations WHERE token = ? AND id != ?`, e.Token, id)
		return err
	})
	return id, err
}

func (s *Store) Installation(ctx context.Context, id string) (Installation, error) {
	in := Installation{ID: id}
	var created, updated int64
	err := s.db.QueryRowContext(ctx,
		`SELECT owner_token_hash, token, topic, environment, created_at, updated_at FROM installations WHERE id = ?`, id).
		Scan(&in.OwnerTokenHash, &in.Token, &in.Topic, &in.Environment, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return in, ErrNotFound
	}
	in.CreatedAt, in.UpdatedAt = time.UnixMilli(created), time.UnixMilli(updated)
	return in, err
}

func (s *Store) DeleteInstallation(ctx context.Context, id string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM installations WHERE id = ?`, id); err != nil {
			return err
		}
		return deleteChildren(ctx, tx, id)
	})
}

// RetireInstallation deletes the installation only while it still holds
// token, the token APNs rejected. An installation rotated to another token
// since the send read it answers ErrTokenChanged; one already gone is nil.
func (s *Store) RetireInstallation(ctx context.Context, id, token string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM installations WHERE id = ? AND token = ?`, id, token)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var exists bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM installations WHERE id = ?)`, id).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return ErrTokenChanged
			}
		}
		return deleteChildren(ctx, tx, id)
	})
}

func deleteChildren(ctx context.Context, tx *sql.Tx, installationID string) error {
	for _, q := range []string{
		`DELETE FROM handles WHERE installation_id = ?`,
		`DELETE FROM enrollments WHERE installation_id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, installationID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) HandleCount(ctx context.Context, installationID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM handles WHERE installation_id = ?`, installationID).Scan(&n)
	return n, err
}

// CreateHandle answers ErrNotFound when the installation was deleted after
// the caller authorized against it.
func (s *Store) CreateHandle(ctx context.Context, h Handle, limit int, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM installations WHERE id = ?)`, h.InstallationID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM handles WHERE installation_id = ?`, h.InstallationID).Scan(&n); err != nil {
			return err
		}
		if n >= limit {
			return ErrTooManyHandles
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO handles (handle, installation_id, host_key, created_at) VALUES (?, ?, ?, ?)`,
			h.Handle, h.InstallationID, h.HostKey, now.UnixMilli())
		return err
	})
}

func (s *Store) DeleteInstallationHandle(ctx context.Context, installationID, handle string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM handles WHERE handle = ? AND installation_id = ?`, handle, installationID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Target resolves a handle to its installation. A handle whose installation
// is gone resolves to ErrNotFound.
func (s *Store) Target(ctx context.Context, handle string) (Handle, Installation, error) {
	h := Handle{Handle: handle}
	var in Installation
	var created, updated int64
	err := s.db.QueryRowContext(ctx,
		`SELECT h.installation_id, h.host_key, i.owner_token_hash, i.token, i.topic, i.environment, i.created_at, i.updated_at
		FROM handles h JOIN installations i ON i.id = h.installation_id WHERE h.handle = ?`, handle).
		Scan(&h.InstallationID, &h.HostKey, &in.OwnerTokenHash, &in.Token, &in.Topic, &in.Environment, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return h, in, ErrNotFound
	}
	in.ID = h.InstallationID
	in.CreatedAt, in.UpdatedAt = time.UnixMilli(created), time.UnixMilli(updated)
	return h, in, err
}

func (s *Store) DeleteHandle(ctx context.Context, handle string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM handles WHERE handle = ?`, handle)
	return err
}

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
