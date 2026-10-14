//go:build unix

package cache

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile takes an exclusive advisory lock (flock). It blocks until the lock
// is available and is released automatically when the fd is closed or the
// process exits (even on crash), so no stale lock files remain.
func lockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}

func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
