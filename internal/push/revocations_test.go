package push

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRevocationLogDropsTornAndExpiredLines(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "revocations")
	live, expired := strings.Repeat("a", 32), strings.Repeat("b", 32)
	torn := strings.Repeat("c", 32) + " 99999999"
	content := live + " 1800000100\n" + expired + " 1800000000\nnot a line\n" + torn
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := openRevocations(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if !r.revoked(live) || r.revoked(expired) || r.revoked(strings.Repeat("c", 32)) || r.size() != 1 {
		t.Fatalf("loaded %v", r.until)
	}
	if _, err := openRevocations(path, func() time.Time { return now }); err == nil {
		t.Fatal("a second gateway opened the log while the first holds it")
	}
	revoked := strings.Repeat("d", 32)
	if _, err := r.file.WriteString(strings.Repeat("e", 20)); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := r.revoke(revoked); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.close(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if n := strings.Count(string(data), revoked); n != 1 {
		t.Fatalf("revoked grant written %d times:\n%s", n, data)
	}
	reopened, err := openRevocations(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.close()
	if !reopened.revoked(revoked) || !reopened.revoked(live) || reopened.size() != 2 {
		t.Fatalf("after a torn write and restart: %v", reopened.until)
	}
}
