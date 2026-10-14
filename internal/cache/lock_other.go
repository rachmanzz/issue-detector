//go:build !unix

package cache

import "os"

// On non-unix platforms advisory flock is unavailable; locking degrades to the
// in-process Store.mu (best effort). Writes remain atomic via temp+rename.
func lockFile(_ *os.File) error { return nil }

func unlockFile(_ *os.File) error { return nil }
