// Package migrations applies numbered schema migrations (NNN_name.sql) at startup.
// init.sql is the base schema and is applied by the PostgreSQL container on first start.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"regexp"
	"sort"
)

// lockID is the PostgreSQL advisory lock that serializes migrations across instances.
const lockID = 0x62696e74616c6b // "bintalk"

//go:embed *.sql
var files embed.FS

var numbered = regexp.MustCompile(`^\d+_.+\.sql$`)

// Apply runs every numbered migration that has not been applied yet, each in its own transaction.
// It returns the names of the migrations it applied. Instances starting at the same time take
// turns (advisory lock), so a migration never runs twice.
func Apply(db *sql.DB) ([]string, error) {
	ctx := context.Background()
	conn, err := db.Conn(ctx) // the lock belongs to one session, so keep one connection
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockID); err != nil {
		return nil, fmt.Errorf("lock migrations: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, lockID) }()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name VARCHAR(255) PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return nil, fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := files.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if numbered.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var applied []string
	for _, name := range names {
		var done bool
		if err := conn.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name).Scan(&done); err != nil {
			return applied, err
		}
		if done {
			continue
		}

		body, err := files.ReadFile(name)
		if err != nil {
			return applied, err
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return applied, err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return applied, fmt.Errorf("%s: %w", name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
			tx.Rollback()
			return applied, fmt.Errorf("%s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return applied, fmt.Errorf("%s: %w", name, err)
		}
		applied = append(applied, name)
	}
	return applied, nil
}
