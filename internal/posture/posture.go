// Package posture scans build/deploy configuration for insecure defaults
// (PRD §4 & §11 M2): Dockerfiles, docker-compose, Kubernetes manifests and
// GitHub Actions workflows. Compose/K8s/Actions are parsed as YAML (structural,
// so string literals or comments cannot produce false positives); Dockerfiles
// are scanned instruction-wise. Deterministic, best-effort.
package posture

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rachmanzz/issue-detector/internal/fetcher"
	"github.com/rachmanzz/issue-detector/internal/model"
)

const maxRead = 2 << 20 // 2 MiB cap per config file

// Analyze inspects enumerated entries and returns posture findings.
func Analyze(entries []fetcher.Entry) []model.Finding {
	var out []model.Finding
	for _, e := range entries {
		kind := classify(e.RelPath)
		if kind == kindNone {
			continue
		}
		content, err := readCapped(e.Path)
		if err != nil {
			continue
		}
		var fs []model.Finding
		switch kind {
		case kindDockerfile:
			fs = scanDockerfile(e.RelPath, content)
		case kindCompose:
			fs = scanYAML(e.RelPath, content, false, false)
		case kindWorkflow:
			fs = scanYAML(e.RelPath, content, true, false)
		case kindK8s:
			if strings.Contains(content, "apiVersion:") {
				fs = scanYAML(e.RelPath, content, false, true)
			}
		}
		out = append(out, fs...)
	}
	return out
}

type kind int

const (
	kindNone kind = iota
	kindDockerfile
	kindCompose
	kindWorkflow
	kindK8s
)

func classify(rel string) kind {
	base := strings.ToLower(path.Base(rel))
	slashed := filepath.ToSlash(rel)
	switch {
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile"):
		return kindDockerfile
	case base == "docker-compose.yml" || base == "docker-compose.yaml" || base == "compose.yml" || base == "compose.yaml":
		return kindCompose
	case strings.Contains(slashed, ".github/workflows/") && isYAML(base):
		return kindWorkflow
	case isYAML(base):
		return kindK8s // confirmed by content sniff in Analyze
	default:
		return kindNone
	}
}

func isYAML(base string) bool {
	return strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")
}

// readCapped reads up to maxRead bytes (handles short reads).
func readCapped(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxRead))
	return string(data), err
}

func finding(ruleID string, sev model.Severity, title, msg, fix, file string, line int, conf float64) model.Finding {
	return model.Finding{
		RuleID: ruleID, Category: model.CategoryPosture, Severity: sev,
		Title: title, Message: msg, FixHint: fix, File: file, Line: line,
		Confidence: conf, Source: model.SourceRule,
	}
}

// --- scanYAML: structural scan of compose / k8s / GitHub Actions -----------

// scanYAML walks the parsed YAML document and reports insecure constructs.
func scanYAML(rel, content string, workflow bool, k8s bool) []model.Finding {
	var out []model.Finding
	visit := func(key, val *yaml.Node) {
		k := strings.ToLower(strings.TrimSpace(key.Value))
		v := strings.TrimSpace(val.Value)

		add := func(id string, sev model.Severity, title, msg, fix string, line int, conf float64) {
			out = append(out, finding(id, sev, title, msg, fix, rel, line, conf))
		}

		if workflow {
			switch k {
			case "on":
				if strings.Contains(v, "pull_request_target") {
					add("POSTURE-020", model.SeverityMedium,
						"pull_request_target",
						"Trigger ini berjalan dengan token/base repo — berbahaya bila memproses kode PR.",
						"Gunakan `pull_request`; bila terpaksa, jangan checkout head PR dan batasi permissions.",
						val.Line, 0.6)
				}
			case "pull_request_target":
				add("POSTURE-020", model.SeverityMedium,
					"pull_request_target",
					"Trigger ini berjalan dengan token/base repo — berbahaya bila memproses kode PR.",
					"Gunakan `pull_request`; bila terpaksa, jangan checkout head PR dan batasi permissions.",
					key.Line, 0.6)
			case "permissions":
				if v == "write-all" {
					add("POSTURE-022", model.SeverityHigh,
						"permissions: write-all", "Token workflow diberi akses tulis penuh.",
						"Set permissions minimal (mis. contents: read).", key.Line, 0.7)
				}
			case "uses":
				if at := strings.LastIndex(v, "@"); at >= 0 {
					if !ghaSHARe.MatchString(v[at+1:]) {
						add("POSTURE-023", model.SeverityLow,
							"Action tidak di-pin ke SHA",
							"Action pihak ketiga di-pin ke tag/branch — dapat berubah tanpa jejak.",
							"Pin ke commit SHA lengkap.", key.Line, 0.5)
					}
				}
			case "run":
				if hasGHAInjection(v) {
					add("POSTURE-021", model.SeverityHigh,
						"Script injection di workflow",
						"Konteks github.event/head_ref di interpolasi langsung ke shell dapat dieksekusi.",
						"Lewatkan lewat `env:` lalu pakai variabel, jangan interpolasi langsung di `run:`.",
						val.Line, 0.7)
				}
			}
			return
		}

		switch k {
		case "privileged":
			if val.Tag == "!!bool" && val.Value == "true" {
				if k8s {
					add("POSTURE-010", model.SeverityHigh,
						"Pod privileged", "`privileged: true` memberi pod kontrol penuh atas node.",
						"Hapus privileged; gunakan securityContext ketat.", val.Line, 0.8)
				} else {
					add("POSTURE-006", model.SeverityHigh,
						"Container privileged", "`privileged: true` memberi container akses penuh ke host.",
						"Hapus privileged; tambahkan capability spesifik bila perlu.", val.Line, 0.8)
				}
			}
		case "network_mode", "pid", "ipc":
			if strings.EqualFold(v, "host") {
				add("POSTURE-007", model.SeverityMedium,
					"Namespace host dipakai", "`network_mode/pid/ipc: host` menghapus isolasi container.",
					"Hindari mode host kecuali benar-benar diperlukan.", key.Line, 0.6)
			}
		case "hostnetwork", "hostpid", "hostipc":
			if val.Tag == "!!bool" && val.Value == "true" {
				add("POSTURE-011", model.SeverityHigh,
					"Namespace host pada pod", "Host namespace membocorkan isolasi node ke pod.",
					"Matikan hostNetwork/hostPID/hostIPC.", key.Line, 0.7)
			}
		case "hostpath":
			add("POSTURE-012", model.SeverityMedium,
				"Volume hostPath", "hostPath mengekspos filesystem node ke pod.",
				"Gunakan volume CSI/PVC; batasi path bila hostPath tak terhindarkan.", key.Line, 0.6)
		case "runasuser":
			if val.Tag == "!!int" && v == "0" {
				add("POSTURE-013", model.SeverityMedium,
					"runAsUser: 0", "Pod berjalan sebagai root (UID 0).",
					"Set runAsNonRoot: true dan runAsUser non-nol.", key.Line, 0.6)
			}
		case "image":
			if strings.HasSuffix(v, ":latest") {
				add("POSTURE-014", model.SeverityLow,
					"Image :latest", "Tag :latest tidak reprodusibel.",
					"Pin ke versi/digest spesifik.", key.Line, 0.5)
			}
		case "volumes":
			if containsDockerSock(val) {
				add("POSTURE-008", model.SeverityHigh,
					"Mount docker.sock", "Mengaitkan docker.sock memberi akses setara root ke host.",
					"Hindari mount docker.sock; gunakan socket proxy terbatas.", val.Line, 0.8)
			}
		}
	}
	// Decode every document so multi-doc manifests (`---` separated, common for
	// Kubernetes) are all scanned — yaml.Unmarshal reads only the first.
	dec := yaml.NewDecoder(strings.NewReader(content))
	for {
		var doc yaml.Node
		if err := dec.Decode(&doc); err != nil {
			break // io.EOF, or malformed tail: keep findings collected so far
		}
		walkMaps(&doc, visit)
	}
	return out
}

// walkMaps visits every mapping (keyNode, valueNode) pair recursively.
func walkMaps(n *yaml.Node, fn func(key, val *yaml.Node)) {
	walkMapsSeen(n, fn, map[*yaml.Node]bool{})
}

// walkMapsSeen is walkMaps with a visited set for alias targets. Each alias
// target is followed at most once so nested anchors cannot expand
// exponentially (a YAML "billion laughs" DoS) or recurse forever on cycles.
func walkMapsSeen(n *yaml.Node, fn func(key, val *yaml.Node), seen map[*yaml.Node]bool) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			walkMapsSeen(c, fn, seen)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			fn(n.Content[i], n.Content[i+1])
			walkMapsSeen(n.Content[i+1], fn, seen)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			walkMapsSeen(c, fn, seen)
		}
	case yaml.AliasNode:
		if n.Alias != nil && !seen[n.Alias] {
			seen[n.Alias] = true
			walkMapsSeen(n.Alias, fn, seen)
		}
	}
}

func hasGHAInjection(run string) bool {
	return strings.Contains(run, "${{ github.event") ||
		strings.Contains(run, "${{ github.head_ref") ||
		strings.Contains(run, "${{ github.base_ref")
}

// containsDockerSock reports whether any scalar under n mentions docker.sock.
func containsDockerSock(n *yaml.Node) bool {
	found := false
	var visit func(node *yaml.Node)
	visit = func(node *yaml.Node) {
		if node == nil || found {
			return
		}
		if node.Kind == yaml.ScalarNode && strings.Contains(node.Value, "docker.sock") {
			found = true
			return
		}
		for _, c := range node.Content {
			visit(c)
		}
	}
	visit(n)
	return found
}

var ghaSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// --- scanDockerfile: instruction-wise --------------------------------------

var (
	dockerUserRe   = regexp.MustCompile(`(?i)^\s*USER\s+(\S+)`)
	dockerAddRe    = regexp.MustCompile(`(?i)^\s*ADD\s+https?://`)
	dockerPipeRe   = regexp.MustCompile(`(?i)^\s*RUN\s+.*(curl|wget)\b[^|]*\|\s*(sh|bash)\b`)
	dockerSecretRe = regexp.MustCompile(`(?i)^\s*(ENV|ARG)\s+.*(secret|token|password|passwd|api[_-]?key|private[_-]?key)\S*\s*=`)
	yingCommentRe  = regexp.MustCompile(`^\s*#`)
)

// isNonRootBase reports whether a base image reference is known to run as a
// non-root user by default (distroless/ubuntu `:nonroot`, `-unprivileged`).
func isNonRootBase(image string) bool {
	img := strings.ToLower(image)
	return strings.Contains(img, "nonroot") || strings.Contains(img, "unprivileged")
}

func scanDockerfile(rel, content string) []model.Finding {
	var out []model.Finding
	hasUser := false
	firstU := 0
	lastBase := ""
	for i, raw := range linesOf(content) {
		line := strings.TrimSpace(raw)
		if line == "" || yingCommentRe.MatchString(line) {
			continue
		}
		if isFromLine(line) {
			if img, ok := dockerFromImage(line); ok {
				lastBase = img
			}
		}
		if m := dockerUserRe.FindStringSubmatch(line); m != nil {
			hasUser = true
			if i == firstU {
				firstU = i
			}
			if strings.EqualFold(strings.TrimSpace(m[1]), "root") {
				out = append(out, finding("POSTURE-002", model.SeverityMedium,
					"Container berjalan sebagai root", "`USER root` menjalankan proses dengan hak tertinggi.",
					"Tambahkan user non-root dan `USER <user>` sebelum CMD.", rel, i+1, 0.7))
			}
		}
		if dockerAddRe.MatchString(line) {
			out = append(out, finding("POSTURE-003", model.SeverityMedium,
				"ADD dari URL remote", "`ADD` dengan URL mengunduh konten tanpa verifikasi.",
				"Gunakan COPY untuk file lokal; verifikasi checksum bila harus mengunduh.", rel, i+1, 0.6))
		}
		if dockerPipeRe.MatchString(line) {
			out = append(out, finding("POSTURE-004", model.SeverityHigh,
				"Pipe curl|sh di build", "Menjalankan script dari internet saat build adalah jalur supply-chain.",
				"Unduh, verifikasi checksum/signature, baru jalankan.", rel, i+1, 0.7))
		}
		if dockerSecretRe.MatchString(line) {
			out = append(out, finding("POSTURE-005", model.SeverityHigh,
				"Secret di ENV/ARG image", "Secret yang ditulis via ENV/ARG tersimpan di layer image.",
				"Gunakan BuildKit secrets (`--mount=type=secret`) atau runtime env.", rel, i+1, 0.7))
		}
	}
	// A non-root base image (e.g. distroless `:nonroot` / `-unprivileged`) already
	// runs as an unprivileged user, so the missing USER instruction is not a risk.
	if !hasUser && !isNonRootBase(lastBase) {
		out = append(out, finding("POSTURE-002", model.SeverityLow,
			"Container tidak menetapkan USER", "Tanpa instruksi USER, container berjalan sebagai root.",
			"Tambahkan `USER` non-root.", rel, 1, 0.5))
	}

	// FROM :latest / no tag.
	for i, raw := range linesOf(content) {
		line := strings.TrimSpace(raw)
		if !isFromLine(line) {
			continue
		}
		img, ok := dockerFromImage(line)
		if !ok || strings.Contains(img, "@sha256:") {
			continue
		}
		last := img[strings.LastIndex(img, "/")+1:]
		if !strings.Contains(last, ":") || strings.HasSuffix(last, ":latest") {
			out = append(out, finding("POSTURE-001", model.SeverityLow,
				"Base image tanpa tag / :latest",
				"Image dasar tidak di-pin ke digest/tag — build tidak reprodusibel.",
				"Pin ke versi spesifik atau digest (`image:1.2.3@sha256:…`).", rel, i+1, 0.6))
		}
	}
	return out
}

// isFromLine reports whether a trimmed Dockerfile line is a FROM instruction.
func isFromLine(line string) bool {
	return len(line) >= 4 && strings.EqualFold(line[:4], "FROM") &&
		(len(line) == 4 || line[4] == ' ' || line[4] == '\t')
}

// dockerFromImage returns the base image reference of a FROM line, skipping
// instruction flags such as `--platform=…` (e.g.
// `FROM --platform=$BUILDPLATFORM golang:1.22 AS build` → `golang:1.22`).
func dockerFromImage(line string) (string, bool) {
	fields := strings.Fields(line)
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		if strings.HasPrefix(f, "--") {
			if f == "--platform" && i+1 < len(fields) {
				i++ // skip the flag's separate value
			}
			continue
		}
		return f, true
	}
	return "", false
}

func linesOf(content string) []string {
	return strings.Split(content, "\n")
}
