package queue

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

func open(t *testing.T, maxBytes int64) (*Queue, string) {
	t.Helper()
	// a space in the path, like "/Library/Application Support" on macOS
	path := filepath.Join(t.TempDir(), "state dir", "queue.db")
	q, err := Open(path, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	return q, path
}

func TestFIFOAckAndIdempotentKeys(t *testing.T) {
	ctx := context.Background()
	q, _ := open(t, 0)
	for i := 1; i <= 3; i++ {
		if _, err := q.Enqueue(ctx, "event", fmt.Sprintf("k%d", i), []byte(fmt.Sprintf("p%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	// same key again: ignored
	if _, err := q.Enqueue(ctx, "event", "k2", []byte("other")); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Enqueue(ctx, "other-kind", "x1", []byte("x")); err != nil {
		t.Fatal(err)
	}
	items, err := q.Peek(ctx, "event", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 || string(items[0].Payload) != "p1" || string(items[1].Payload) != "p2" || items[2].Key != "k3" {
		t.Fatalf("unexpected items %+v", items)
	}
	if err := q.MarkAttempt(ctx, items[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := q.Ack(ctx, items[0].ID, items[1].ID); err != nil {
		t.Fatal(err)
	}
	items, _ = q.Peek(ctx, "event", 10)
	if len(items) != 1 || items[0].Key != "k3" {
		t.Fatalf("after ack: %+v", items)
	}
	count, size, err := q.Stats(ctx)
	if err != nil || count != 2 || size != 3 {
		t.Fatalf("stats = %d, %d, %v", count, size, err)
	}
}

func TestSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	q, path := open(t, 0)
	if _, err := q.Enqueue(ctx, "event", "k1", []byte("kept")); err != nil {
		t.Fatal(err)
	}
	items, _ := q.Peek(ctx, "event", 1)
	if err := q.MarkAttempt(ctx, items[0].ID); err != nil {
		t.Fatal(err)
	}
	q.Close()

	reopened, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	items, err = reopened.Peek(ctx, "event", 10)
	if err != nil || len(items) != 1 || string(items[0].Payload) != "kept" || items[0].Attempts != 1 {
		t.Fatalf("after restart: %+v, %v", items, err)
	}
}

func TestCapacityDropsOldestAndReportsIt(t *testing.T) {
	ctx := context.Background()
	q, _ := open(t, 10)
	for i := 0; i < 3; i++ {
		dropped, err := q.Enqueue(ctx, "event", fmt.Sprintf("k%d", i), bytes.Repeat([]byte{'a'}, 4))
		if err != nil || dropped != 0 && i < 2 {
			t.Fatalf("enqueue %d: dropped %d, %v", i, dropped, err)
		}
		if i == 2 && dropped != 1 {
			t.Fatalf("third message should drop the oldest, dropped %d", dropped)
		}
	}
	items, _ := q.Peek(ctx, "event", 10)
	if len(items) != 2 || items[0].Key != "k1" || items[1].Key != "k2" {
		t.Fatalf("unexpected items after overflow %+v", items)
	}
	if _, err := q.Enqueue(ctx, "event", "huge", bytes.Repeat([]byte{'b'}, 11)); err != ErrTooLarge {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}

func TestPurge(t *testing.T) {
	ctx := context.Background()
	q, _ := open(t, 0)
	for i := 0; i < 5; i++ {
		if _, err := q.Enqueue(ctx, "event", fmt.Sprintf("k%d", i), []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	n, err := q.Purge(ctx)
	if err != nil || n != 5 {
		t.Fatalf("purge = %d, %v", n, err)
	}
	if count, _, _ := q.Stats(ctx); count != 0 {
		t.Fatalf("queue not empty after purge: %d", count)
	}
}

func TestRejectsMissingKey(t *testing.T) {
	q, _ := open(t, 0)
	if _, err := q.Enqueue(context.Background(), "event", "", []byte("x")); err == nil {
		t.Fatal("expected an error for an empty key")
	}
}
