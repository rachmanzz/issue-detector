// Package scanner orchestrates a scan: files are shipped through the in-memory
// queue (fiber-extras) and executed by the worker engine (PRD §5.3).
package scanner

// Queue topics used by the scan pipeline.
const (
	TopicScanFile = "issue.scan.file"
)

// fileTask is the payload dispatched for each enumerated file.
type fileTask struct {
	Path    string `json:"path"`
	RelPath string `json:"rel_path"`
	Size    int64  `json:"size"`
}
