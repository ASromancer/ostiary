package daemon

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestAcquireLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "daemon.lock")
	rel, err := acquireLock(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireLock(p); !errors.Is(err, ErrLocked) {
		t.Fatalf("second acquire: %v, want ErrLocked", err)
	}
	rel()
	rel2, err := acquireLock(p)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	rel2()
}
