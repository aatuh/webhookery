package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func MigrateUp(ctx context.Context, databaseURL, dir string) error {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	files, err := filepath.Glob(filepath.Join(dir, "*.up.sql"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, file := range files {
		// #nosec G304 -- migration files are intentionally read from the operator-selected migration directory.
		body, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		version := strings.TrimSuffix(filepath.Base(file), ".up.sql")
		sum := checksum(body)
		appliedChecksum, err := appliedMigrationChecksum(ctx, pool, version)
		if err != nil {
			if version != "001_init" || !isUndefinedTable(err) {
				return fmt.Errorf("check migration %s: %w", version, err)
			}
		}
		if appliedChecksum != "" {
			if appliedChecksum == sum {
				continue
			}
			return fmt.Errorf("check migration %s: checksum mismatch", version)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version, checksum) VALUES($1, $2)", version, sum); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func appliedMigrationChecksum(ctx context.Context, pool *pgxpool.Pool, version string) (string, error) {
	var appliedChecksum string
	err := pool.QueryRow(ctx, "SELECT checksum FROM schema_migrations WHERE version=$1", version).Scan(&appliedChecksum)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return appliedChecksum, err
}

func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

func checksum(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
