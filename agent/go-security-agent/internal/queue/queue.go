// Package queue is the local outbox of the agent: messages that must reach the backend are
// written to SQLite before they are sent and deleted only after the backend acknowledged
// them (docs/03-AGENT-PROTOCOL.md §8). It survives restarts and network outages.
//
// Every item has a unique key chosen by the producer (for example an event id), so
// enqueuing the same message twice is a no-op. The total payload size is capped: when the
// cap is exceeded the oldest items are dropped and the number of dropped items is returned,
// so that the caller can record the loss instead of hiding it.
package queue

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure Go SQLite driver (no cgo, cross-compiles to every target)
)

// DefaultMaxBytes is the default cap of the queued payloads (200 MB).
const DefaultMaxBytes int64 = 200 << 20

// ErrTooLarge is returned for a single payload bigger than the whole queue.
var ErrTooLarge = errors.New("queue: payload larger than the queue capacity")

// Item is one queued message.
type Item struct {
	ID        int64
	Key       string
	Kind      string
	Payload   []byte
	CreatedAt time.Time
	Attempts  int
}

// Queue is a persistent FIFO outbox. It is safe for concurrent use.
type Queue struct {
	db       *sql.DB
	maxBytes int64
	now      func() time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT    NOT NULL UNIQUE,
    kind       TEXT    NOT NULL,
    payload    BLOB    NOT NULL,
    size       INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS outbox_kind_idx ON outbox (kind, id);
PRAGMA user_version = 1;
`

// Open opens (or creates) the queue database at path. maxBytes <= 0 means DefaultMaxBytes.
func Open(path string, maxBytes int64) (*Queue, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("queue: create directory: %w", err)
	}
	// create the file with restrictive permissions before SQLite opens it
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("queue: %w", err)
	}
	f.Close()
	// plain path (not a file: URI, so spaces such as "Application Support" need no escaping)
	// followed by the connection pragmas understood by the driver
	dsn := path + "?" + url.Values{
		"_pragma": {"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)"},
	}.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("queue: open: %w", err)
	}
	// one connection: SQLite serializes writers anyway and this avoids SQLITE_BUSY
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("queue: initialise schema: %w", err)
	}
	return &Queue{db: db, maxBytes: maxBytes, now: time.Now}, nil
}

// Close releases the database.
func (q *Queue) Close() error {
	return q.db.Close()
}

// Enqueue stores a message. A message whose key is already queued is ignored. It returns
// the number of older messages dropped to stay under the capacity.
func (q *Queue) Enqueue(ctx context.Context, kind, key string, payload []byte) (dropped int, err error) {
	if kind == "" || key == "" {
		return 0, errors.New("queue: kind and key are required")
	}
	size := int64(len(payload))
	if size > q.maxBytes {
		return 0, ErrTooLarge
	}
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO outbox (key, kind, payload, size, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT (key) DO NOTHING`,
		key, kind, payload, size, q.now().UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("queue: enqueue: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, tx.Commit()
	}
	for {
		var total int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size), 0) FROM outbox`).Scan(&total); err != nil {
			return 0, err
		}
		if total <= q.maxBytes {
			break
		}
		// drop the oldest message (never the one just written: it is the newest)
		if _, err := tx.ExecContext(ctx, `DELETE FROM outbox WHERE id = (SELECT MIN(id) FROM outbox)`); err != nil {
			return 0, err
		}
		dropped++
	}
	return dropped, tx.Commit()
}

// Peek returns up to limit messages of a kind, oldest first, without removing them.
func (q *Queue) Peek(ctx context.Context, kind string, limit int) ([]Item, error) {
	rows, err := q.db.QueryContext(ctx,
		`SELECT id, key, kind, payload, created_at, attempts FROM outbox WHERE kind = ? ORDER BY id LIMIT ?`,
		kind, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Item
	for rows.Next() {
		var it Item
		var created int64
		if err := rows.Scan(&it.ID, &it.Key, &it.Kind, &it.Payload, &created, &it.Attempts); err != nil {
			return nil, err
		}
		it.CreatedAt = time.UnixMilli(created)
		items = append(items, it)
	}
	return items, rows.Err()
}

// Ack deletes messages the backend acknowledged.
func (q *Queue) Ack(ctx context.Context, ids ...int64) error {
	return q.inTx(ctx, `DELETE FROM outbox WHERE id = ?`, ids)
}

// MarkAttempt counts a failed delivery attempt.
func (q *Queue) MarkAttempt(ctx context.Context, ids ...int64) error {
	return q.inTx(ctx, `UPDATE outbox SET attempts = attempts + 1 WHERE id = ?`, ids)
}

func (q *Queue) inTx(ctx context.Context, statement string, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := q.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, statement)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, id := range ids {
		if _, err := stmt.ExecContext(ctx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Stats returns the number of queued messages and their total payload size.
func (q *Queue) Stats(ctx context.Context) (count int, bytes int64, err error) {
	err = q.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(size), 0) FROM outbox`).Scan(&count, &bytes)
	return count, bytes, err
}

// Purge deletes every queued message (used when the agent is revoked) and returns how many.
func (q *Queue) Purge(ctx context.Context) (int, error) {
	res, err := q.db.ExecContext(ctx, `DELETE FROM outbox`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := q.db.ExecContext(ctx, `VACUUM`); err != nil {
		return int(n), err
	}
	return int(n), nil
}
