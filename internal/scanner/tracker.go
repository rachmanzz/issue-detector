package scanner

import (
	"context"
	"sync"
)

// completionTracker knows how many queue messages are still in flight for a
// scan and which message IDs have already settled. The message-ID set makes
// handler retries (queue at-least-once) idempotent.
type completionTracker struct {
	mu        sync.Mutex
	pending   int
	completed map[string]bool
	done      chan struct{}
}

func newCompletionTracker(total int) *completionTracker {
	t := &completionTracker{
		pending:   total,
		completed: make(map[string]bool, total),
		done:      make(chan struct{}),
	}
	if total <= 0 {
		close(t.done)
	}
	return t
}

// complete settles a message once. Returns true only on the first settlement,
// so callers can commit side effects (stats, findings) exactly once.
// Enqueue failures pass a synthetic id to drain the budget without a message.
func (t *completionTracker) complete(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.completed[id] {
		return false
	}
	t.completed[id] = true
	t.pending--
	if t.pending <= 0 {
		select {
		case <-t.done:
		default:
			close(t.done)
		}
	}
	return true
}

// Wait blocks until all messages settled or ctx is done.
func (t *completionTracker) Wait(ctx context.Context) error {
	select {
	case <-t.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
