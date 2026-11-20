package push

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type revocations struct {
	mu    sync.RWMutex
	now   func() time.Time
	lock  *os.File
	file  *os.File
	until map[string]int64
}

func openRevocations(path string, now func() time.Time) (*revocations, error) {
	lock, err := lockFile(path + ".lock")
	if err != nil {
		return nil, err
	}
	r := &revocations{now: now, lock: lock, until: map[string]int64{}}
	if err := r.open(path); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return r, nil
}

func (r *revocations) open(path string) error {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	r.load(string(data))
	if err := r.rewrite(path); err != nil {
		return err
	}
	r.file, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	return err
}

func (r *revocations) load(data string) {
	now := r.now().Unix()
	for line := range strings.Lines(data) {
		id, until, ok := parseRevocation(line)
		if ok && until > now {
			r.until[id] = max(r.until[id], until)
		}
	}
}

func parseRevocation(line string) (string, int64, bool) {
	line, complete := strings.CutSuffix(line, "\n")
	id, at, found := strings.Cut(line, " ")
	if !complete || !found || len(id) != 32 {
		return "", 0, false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return "", 0, false
	}
	until, err := strconv.ParseInt(at, 10, 64)
	return id, until, err == nil
}

func (r *revocations) rewrite(path string) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for id, until := range r.until {
		fmt.Fprintf(w, "%s %d\n", id, until)
	}
	if err := errors.Join(w.Flush(), f.Sync(), f.Close()); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func (r *revocations) revoked(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.until[id] > r.now().Unix()
}

func (r *revocations) revoke(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.until[id] <= now.Unix() {
		until := now.Add(grantLifetime).Unix()
		// The leading newline isolates a record torn by an earlier failed write.
		if _, err := fmt.Fprintf(r.file, "\n%s %d\n", id, until); err != nil {
			return err
		}
		r.until[id] = until
		for id, until := range r.until {
			if until <= now.Unix() {
				delete(r.until, id)
			}
		}
	}
	return r.file.Sync()
}

// unlessRevoked runs fn under the same lock as revoke, so a grant renewed by fn
// can never expire after a tombstone written concurrently for it.
func (r *revocations) unlessRevoked(id string, fn func(now time.Time) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if r.until[id] > now.Unix() {
		return errEndpointRevoked
	}
	return fn(now)
}

func (r *revocations) size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.until)
}

func (r *revocations) close() error {
	return errors.Join(r.file.Close(), r.lock.Close())
}
