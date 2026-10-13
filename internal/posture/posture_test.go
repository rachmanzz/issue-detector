package posture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rachmanzz/issue-detector/internal/fetcher"
	"github.com/rachmanzz/issue-detector/internal/model"
)

func writeEntries(t *testing.T, files map[string]string) []fetcher.Entry {
	t.Helper()
	dir := t.TempDir()
	var entries []fetcher.Entry
	for rel, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		entries = append(entries, fetcher.Entry{Path: p, RelPath: rel})
	}
	return entries
}

func TestDockerfile(t *testing.T) {
	entries := writeEntries(t, map[string]string{
		"Dockerfile": `FROM ubuntu:latest
RUN curl https://x | sh
ENV API_TOKEN=abc123
ADD https://example.com/f.tgz /f.tgz
`,
	})
	got := ids(Analyze(entries))
	for _, want := range []string{"POSTURE-001", "POSTURE-002", "POSTURE-003", "POSTURE-004", "POSTURE-005"} {
		if got[want] == 0 {
			t.Errorf("missing %s (got %v)", want, got)
		}
	}
}

func TestDockerfileHardened(t *testing.T) {
	entries := writeEntries(t, map[string]string{
		"Dockerfile": `FROM alpine:3.19@sha256:deadbeef
USER app
`,
	})
	if got := ids(Analyze(entries)); len(got) != 0 {
		t.Errorf("hardened Dockerfile should be clean, got %v", got)
	}
}

func TestWorkflow(t *testing.T) {
	entries := writeEntries(t, map[string]string{
		".github/workflows/ci.yml": `on: pull_request_target
permissions: write-all
jobs:
  b:
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.event.pull_request.title }}"
`,
	})
	got := ids(Analyze(entries))
	for _, want := range []string{"POSTURE-020", "POSTURE-021", "POSTURE-022", "POSTURE-023"} {
		if got[want] == 0 {
			t.Errorf("missing %s (got %v)", want, got)
		}
	}
}

func TestK8s(t *testing.T) {
	entries := writeEntries(t, map[string]string{
		"deploy.yaml": `apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
    - image: nginx:latest
      securityContext:
        privileged: true
        runAsUser: 0
      volumeMounts:
  volumes:
    - hostPath:
        path: /etc
`,
	})
	got := ids(Analyze(entries))
	for _, want := range []string{"POSTURE-010", "POSTURE-011", "POSTURE-012", "POSTURE-013", "POSTURE-014"} {
		if got[want] == 0 {
			t.Errorf("missing %s (got %v)", want, got)
		}
	}
}

func TestCompose(t *testing.T) {
	entries := writeEntries(t, map[string]string{
		"docker-compose.yml": `services:
  app:
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`,
	})
	got := ids(Analyze(entries))
	for _, want := range []string{"POSTURE-006", "POSTURE-007", "POSTURE-008"} {
		if got[want] == 0 {
			t.Errorf("missing %s (got %v)", want, got)
		}
	}
}

func ids(fs []model.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.RuleID]++
	}
	return m
}
