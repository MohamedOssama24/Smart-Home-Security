// Package logging configures the structured log of the agent (log/slog). Messages never
// contain tokens or keys: callers log identifiers, states and error messages only.
//
// Under systemd and launchd the log goes to stderr (journald / log file of the daemon). The
// Windows service has no console, so it writes to <state-dir>\agent.log, rotated at 5 MB
// with one previous file kept.
package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// MaxFileSize is the size after which the log file is rotated.
const MaxFileSize = 5 << 20

// Stderr returns a text logger on stderr.
func Stderr() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// File returns a JSON logger writing to path with size-based rotation.
func File(path string) (*slog.Logger, io.Closer, error) {
	w := &rotatingFile{path: path, max: MaxFileSize}
	if err := w.open(); err != nil {
		return nil, nil, err
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})), w, nil
}

type rotatingFile struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func (w *rotatingFile) open() error {
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.f, w.size = f, info.Size()
	return nil
}

func (w *rotatingFile) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return 0, os.ErrClosed
	}
	if w.size+int64(len(p)) > w.max {
		w.f.Close()
		w.f = nil
		_ = os.Rename(w.path, w.path+".1") // replaces the previous rotated file
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingFile) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}
