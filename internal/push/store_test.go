package push

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStorePersistsAcrossRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "push.sqlite")
	ctx := t.Context()
	now := testEpoch
	s := openTestStore(t, path)
	e := Enrollment{ID: "e1", Token: token(1), Topic: testTopic, Environment: Sandbox, CodeHash: []byte{1}, ExpiresAt: now.Add(time.Minute)}
	if err := s.CreateEnrollment(ctx, e, now); err != nil {
		t.Fatal(err)
	}
	id, err := s.ConfirmEnrollment(ctx, e, Installation{ID: "i1", OwnerTokenHash: []byte{2}}, now)
	if err != nil || id != "i1" {
		t.Fatalf("confirm = %q, %v", id, err)
	}
	if err := s.CreateHandle(ctx, Handle{Handle: "h1", InstallationID: id, HostKey: []byte{3}}, maxHandles, now); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s = openTestStore(t, path)
	h, in, err := s.Target(ctx, "h1")
	if err != nil || in.Token != token(1) || in.Topic != testTopic || string(h.HostKey) != "\x03" || !in.CreatedAt.Equal(now) {
		t.Fatalf("target after reopen = %+v %+v %v", h, in, err)
	}
}

func TestStoreEnrollmentExpiryAndAttempts(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), "push.sqlite"))
	ctx := t.Context()
	now := testEpoch
	enrollment := func(id string, created time.Time) {
		t.Helper()
		e := Enrollment{ID: id, Token: token(1), Topic: testTopic, Environment: Sandbox, CodeHash: []byte{1}, ExpiresAt: created.Add(time.Minute)}
		if err := s.CreateEnrollment(ctx, e, created); err != nil {
			t.Fatal(err)
		}
	}
	enrollment("stale", now)
	now = now.Add(time.Minute)
	enrollment("live", now)
	if _, err := s.Enrollment(ctx, "stale", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired enrollment: %v", err)
	}
	var rows int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM enrollments`).Scan(&rows)
	if rows != 1 {
		t.Fatalf("creating an enrollment kept %d rows, want the expired one pruned", rows)
	}
	for i := range 3 {
		if err := s.FailEnrollment(ctx, "live", 3); err != nil {
			t.Fatal(err)
		}
		e, err := s.Enrollment(ctx, "live", now)
		if i < 2 && (err != nil || e.Attempts != i+1) {
			t.Fatalf("after %d failures: %+v %v", i+1, e, err)
		}
		if i == 2 && !errors.Is(err, ErrNotFound) {
			t.Fatalf("enrollment survived its last attempt: %v", err)
		}
	}
}

func TestStoreConfirmIsSingleUse(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), "push.sqlite"))
	ctx := t.Context()
	now := testEpoch
	e := Enrollment{ID: "e1", Token: token(1), Topic: testTopic, Environment: Sandbox, CodeHash: []byte{1}, ExpiresAt: now.Add(time.Minute)}
	if err := s.CreateEnrollment(ctx, e, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmEnrollment(ctx, e, Installation{ID: "i1", OwnerTokenHash: []byte{2}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmEnrollment(ctx, e, Installation{ID: "i2", OwnerTokenHash: []byte{2}}, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second confirm: %v", err)
	}
	if _, err := s.Installation(ctx, "i2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second confirm created an installation: %v", err)
	}
}

func TestStoreRotationOfDeletedInstallationKeepsEnrollmentUnused(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), "push.sqlite"))
	ctx := t.Context()
	now := testEpoch
	e := Enrollment{ID: "e1", Token: token(2), Topic: testTopic, Environment: Sandbox, InstallationID: "missing", CodeHash: []byte{1}, ExpiresAt: now.Add(time.Minute)}
	if err := s.CreateEnrollment(ctx, e, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmEnrollment(ctx, e, Installation{}, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rotation of a missing installation: %v", err)
	}
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM installations`).Scan(&n)
	if n != 0 {
		t.Fatalf("rotation of a missing installation created %d installations", n)
	}
}

func TestStoreCreateHandleRequiresInstallation(t *testing.T) {
	s := openTestStore(t, filepath.Join(t.TempDir(), "push.sqlite"))
	err := s.CreateHandle(t.Context(), Handle{Handle: "h1", InstallationID: "gone", HostKey: []byte{1}}, maxHandles, testEpoch)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("create handle for a missing installation = %v", err)
	}
	if _, _, err := s.Target(t.Context(), "h1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("orphan handle was stored: %v", err)
	}
}

func TestStoreRetireInstallationOnlyForItsCurrentToken(t *testing.T) {
	ctx := t.Context()
	now := testEpoch
	s := openTestStore(t, filepath.Join(t.TempDir(), "push.sqlite"))
	e := Enrollment{ID: "e1", Token: token(1), Topic: testTopic, Environment: Sandbox, CodeHash: []byte{1}, ExpiresAt: now.Add(time.Minute)}
	if err := s.CreateEnrollment(ctx, e, now); err != nil {
		t.Fatal(err)
	}
	id, err := s.ConfirmEnrollment(ctx, e, Installation{ID: "i1", OwnerTokenHash: []byte{2}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateHandle(ctx, Handle{Handle: "h1", InstallationID: id, HostKey: []byte{3}}, maxHandles, now); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireInstallation(ctx, id, token(2)); !errors.Is(err, ErrTokenChanged) {
		t.Fatalf("retire with another token = %v", err)
	}
	if _, _, err := s.Target(ctx, "h1"); err != nil {
		t.Fatalf("retiring another token removed the handle: %v", err)
	}
	if err := s.RetireInstallation(ctx, id, token(1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Target(ctx, "h1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("handle survived retirement: %v", err)
	}
	if err := s.RetireInstallation(ctx, id, token(1)); err != nil {
		t.Fatalf("retiring a deleted installation = %v", err)
	}
}
