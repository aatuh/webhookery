package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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
		var exists bool
		err = pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1 AND checksum=$2)", version, sum).Scan(&exists)
		if err != nil && version != "001_init" {
			return fmt.Errorf("check migration %s: %w", version, err)
		}
		if exists {
			continue
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version, checksum) VALUES($1, $2) ON CONFLICT (version) DO UPDATE SET checksum = EXCLUDED.checksum, applied_at = now()", version, sum); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

func checksum(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
