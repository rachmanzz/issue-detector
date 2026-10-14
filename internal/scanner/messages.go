// Package scanner orchestrates a scan: files are shipped through the in-memory
// queue (gosuite) and executed by the worker engine (PRD §5.3).
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/rachmanzz/gosuite/v3/queue"
	"github.com/rachmanzz/gosuite/v3/worker"
)

// Queue topics used by the scan pipeline.
const (
	TopicScanFile = "issue.scan.file"
)

// fileTask is the payload dispatched for each enumerated file. ScanID ties the
// message to the scan that produced it, so the shared handler can resolve the
// owning scan without being bound to it.
type fileTask struct {
	ScanID  string `json:"scan_id"`
	Path    string `json:"path"`
	RelPath string `json:"rel_path"`
	Size    int64  `json:"size"`
}

// scanStates maps an active scan id to its Scanner. The queue handler looks up
// state per message, so it never holds a reference to a specific scan.
var scanStates sync.Map // scanID (string) -> *Scanner

// queueRuntime is the process-level queue. The worker engine, driver, router and
// consumer are created once and the handler is registered exactly once; scans
// only dispatch into the shared driver (roast v2/v28).
type queueRuntime struct {
	drv *queue.MemoryDriver
}

var (
	queueOnce   sync.Once
	sharedQueue *queueRuntime
)

// getQueue returns the process-level queue runtime, creating it on first use.
// Worker concurrency comes from the first scan: CLI runs one scan per process
// and `serve` uses one config, so a single worker pool is the right ceiling.
func getQueue(jobs, sub int, log *slog.Logger) *queueRuntime {
	queueOnce.Do(func() {
		eng := worker.New(
			worker.WithMaxWorkers(jobs),
			worker.WithSubWorkerLimit(sub),
			worker.WithShutdownTimeout(15*time.Second),
			worker.WithLogger(worker.NewSlogLogger(log)),
		).Start()

		drv := queue.NewMemoryDriver()
		router := queue.NewRouter()
		router.Register(TopicScanFile, handleScanFile) // registered once, lifetime of process

		cons := queue.NewConsumer(drv, router, eng,
			queue.WithLogger(queue.NewSlogLogger(log)),
			queue.WithBatchSize(64),
			queue.WithPollInterval(5*time.Millisecond),
		)
		cons.Start()

		sharedQueue = &queueRuntime{drv: drv}
	})
	return sharedQueue
}

// handleScanFile is the single queue handler. It is not bound to any scan: it
// resolves the owning Scanner from the message's scan id and delegates. Messages
// for a scan that already finished are dropped (return nil) rather than retried.
func handleScanFile(ctx context.Context, msg *queue.Message, pool worker.SubWorkerPool) error {
	var t fileTask
	if err := json.Unmarshal(msg.Payload, &t); err != nil {
		return fmt.Errorf("decode file task: %w", err)
	}
	v, ok := scanStates.Load(t.ScanID)
	if !ok {
		return nil
	}
	return v.(*Scanner).handleFile(ctx, msg.ID, t, pool)
}
