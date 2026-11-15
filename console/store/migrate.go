// Package store owns PostgreSQL connectivity and schema initialization.
package store

import (
	"context"
	_ "embed"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var initialSchema string

const schemaBaseline = "pki-console-1"

type schemaQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func requireSchema(ctx context.Context, db schemaQuerier) error {
	var baseline string
	if err := db.QueryRow(ctx, `SELECT baseline FROM public.pki_schema WHERE id=1`).Scan(&baseline); err != nil {
		return fmt.Errorf("database is not initialized; run pki-console migrate on an empty database: %w", err)
	}
	if baseline != schemaBaseline {
		return fmt.Errorf("unsupported database baseline %q; expected %q", baseline, schemaBaseline)
	}
	return nil
}

func (s *Store) RequireCurrentSchema(ctx context.Context) error {
	return requireSchema(ctx, s.pool)
}

// Migrate initializes an empty database. Repeating it on this baseline only
// ensures the current and next audit partitions exist; business data is intact.
// Pre-release databases and other nonempty schemas are deliberately rejected.
func Migrate(ctx context.Context, databaseURL string) error {
	db, err := Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin initialization: %w", err)
	}
	defer tx.Rollback(context.Background())
	// Serialize application initializers before inspecting or creating objects.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(736568630354)`); err != nil {
		return fmt.Errorf("lock initialization: %w", err)
	}
	var initialized bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('public.pki_schema') IS NOT NULL`).Scan(&initialized); err != nil {
		return fmt.Errorf("inspect schema: %w", err)
	}
	if initialized {
		if err := requireSchema(ctx, tx); err != nil {
			return err
		}
	} else {
		var nonempty bool
		if err := tx.QueryRow(ctx, `SELECT
            EXISTS(SELECT 1 FROM pg_class WHERE relnamespace='public'::regnamespace) OR
            EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace='public'::regnamespace) OR
            EXISTS(SELECT 1 FROM pg_type WHERE typnamespace='public'::regnamespace)`).Scan(&nonempty); err != nil {
			return fmt.Errorf("inspect empty schema: %w", err)
		}
		if nonempty {
			return fmt.Errorf("refusing to initialize a nonempty public schema without the %s baseline; use a new empty database", schemaBaseline)
		}
		if _, err := tx.Exec(ctx, initialSchema); err != nil {
			return fmt.Errorf("initialize schema (PostgreSQL 18+ required): %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `SELECT pki_create_audit_partition(date_trunc('month', current_date)::date), pki_create_audit_partition((date_trunc('month', current_date) + interval '1 month')::date)`); err != nil {
		return fmt.Errorf("prepare audit partitions: %w", err)
	}
	return tx.Commit(ctx)
}

func Open(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	config.MaxConns = 20
	config.ConnConfig.RuntimeParams["search_path"] = "public,pg_catalog"
	config.MinConns = 2
	config.MaxConnIdleTime = 5 * time.Minute
	config.MaxConnLifetime = time.Hour
	config.HealthCheckPeriod = 30 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	return pool, nil
}
