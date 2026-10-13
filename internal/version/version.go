package version

var (
	// Version is the semantic version of the binary. Overridable at build time:
	//   go build -ldflags "-X github.com/rachmanzz/issue-detector/internal/version.Version=0.1.0"
	Version = "0.1.0-dev"

	// Commit is the git SHA the binary was built from (via ldflags).
	Commit = ""

	// Date is the build timestamp (via ldflags).
	Date = ""
)

// ToolName is stable across reports and agent contracts.
const ToolName = "issue-detector"

// SchemaVersion is the version of the JSON report contract. Bump on breaking
// changes to the output shape (see PRD §3.7 & §9).
const SchemaVersion = "1"
