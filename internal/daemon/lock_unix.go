//go:build !windows

package daemon

import (
	"os"
	"syscall"
)

// acquireLock takes an exclusive, non-blocking lock on path. The OS drops it if the process dies.
func acquireLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() { f.Close() }, nil
}
