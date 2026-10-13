// Package posture scans build/deploy configuration for insecure defaults
// (PRD §4 & §11 M2): Dockerfiles, docker-compose, Kubernetes manifests and
// GitHub Actions workflows. It is deterministic, line-based and best-effort.
package posture

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

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
			fs = scanCompose(e.RelPath, content)
		case kindWorkflow:
			fs = scanWorkflow(e.RelPath, content)
		case kindK8s:
			if strings.Contains(content, "apiVersion:") {
				fs = scanK8s(e.RelPath, content)
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

func readCapped(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, maxRead)
	n, _ := f.Read(buf)
	return string(buf[:n]), nil
}

// findByLine returns 1-based line numbers where re matches.
func findByLine(content string, re *regexp.Regexp) []int {
	var lines []int
	for i, l := range strings.Split(content, "\n") {
		if re.MatchString(l) {
			lines = append(lines, i+1)
		}
	}
	return lines
}

func finding(ruleID string, sev model.Severity, title, msg, fix, file string, line int, conf float64) model.Finding {
	return model.Finding{
		RuleID: ruleID, Category: model.CategoryPosture, Severity: sev,
		Title: title, Message: msg, FixHint: fix, File: file, Line: line,
		Confidence: conf, Source: model.SourceRule,
	}
}

var (
	dockerLatestRe = regexp.MustCompile(`(?i)^\s*FROM\s+[^\s@]+(?::latest)?\s*$`)
	dockerUserRe   = regexp.MustCompile(`(?im)^\s*USER\s+(\S+)`)
	dockerAddRe    = regexp.MustCompile(`(?i)^\s*ADD\s+https?://`)
	dockerPipeRe   = regexp.MustCompile(`(?i)^\s*RUN\s+.*(curl|wget)\b[^|]*\|\s*(sh|bash)\b`)
	dockerSecretRe = regexp.MustCompile(`(?i)^\s*(ENV|ARG)\s+.*(secret|token|password|passwd|api[_-]?key|private[_-]?key)\S*\s*=`)
)

func scanDockerfile(rel, content string) []model.Finding {
	var out []model.Finding
	if hasFromNoTag(content) {
		line := firstLine(content, dockerLatestRe)
		out = append(out, finding("POSTURE-001", model.SeverityLow,
			"Base image tanpa tag / :latest",
			"Image dasar tidak di-pin ke digest/tag — build tidak reprodusibel dan bisa menyerap kerentanan baru.",
			"Pin ke versi spesifik atau digest (`image:1.2.3@sha256:…`).",
			rel, line, 0.6))
	}
	if u := dockerUserRe.FindStringSubmatch(content); u != nil && strings.EqualFold(strings.TrimSpace(u[1]), "root") {
		line := firstLine(content, regexp.MustCompile(`(?i)^\s*USER\s+root\b`))
		out = append(out, finding("POSTURE-002", model.SeverityMedium,
			"Container berjalan sebagai root",
			"`USER root` menjalankan proses dengan hak tertinggi di dalam container.",
			"Tambahkan user non-root dan `USER <user>` sebelum CMD.",
			rel, line, 0.7))
	} else if !dockerUserRe.MatchString(content) {
		out = append(out, finding("POSTURE-002", model.SeverityLow,
			"Container tidak menetapkan USER",
			"Tanpa instruksi USER, container berjalan sebagai root secara default.",
			"Tambahkan `USER` non-root.",
			rel, 1, 0.5))
	}
	for _, ln := range findByLine(content, dockerAddRe) {
		out = append(out, finding("POSTURE-003", model.SeverityMedium,
			"ADD dari URL remote", "`ADD` dengan URL mengunduh konten tanpa verifikasi.",
			"Gunakan COPY untuk file lokal; verifikasi checksum bila harus mengunduh.",
			rel, ln, 0.6))
	}
	for _, ln := range findByLine(content, dockerPipeRe) {
		out = append(out, finding("POSTURE-004", model.SeverityHigh,
			"Pipe curl|sh di build", "Menjalankan script dari internet saat build adalah jalur supply-chain.",
			"Unduh, verifikasi checksum/signature, baru jalankan.",
			rel, ln, 0.7))
	}
	for _, ln := range findByLine(content, dockerSecretRe) {
		out = append(out, finding("POSTURE-005", model.SeverityHigh,
			"Secret di ENV/ARG image", "Secret yang ditulis via ENV/ARG tersimpan di layer image.",
			"Gunakan BuildKit secrets (`--mount=type=secret`) atau runtime env.",
			rel, ln, 0.7))
	}
	return out
}

var (
	composePrivRe = regexp.MustCompile(`(?im)^\s*-?\s*privileged\s*:\s*true`)
	composeHostRe = regexp.MustCompile(`(?im)^\s*-?\s*(network_mode|pid|ipc)\s*:\s*['"]?host`)
	composeSockRe = regexp.MustCompile(`(?i)docker\.sock`)
)

func scanCompose(rel, content string) []model.Finding {
	var out []model.Finding
	for _, ln := range findByLine(content, composePrivRe) {
		out = append(out, finding("POSTURE-006", model.SeverityHigh,
			"Container privileged", "`privileged: true` memberi container akses penuh ke host.",
			"Hapus privileged; tambahkan capability spesifik bila perlu.",
			rel, ln, 0.8))
	}
	for _, ln := range findByLine(content, composeHostRe) {
		out = append(out, finding("POSTURE-007", model.SeverityMedium,
			"Namespace host dipakai", "`network_mode/pid/ipc: host` menghapus isolasi container.",
			"Hindari mode host kecuali benar-benar diperlukan.",
			rel, ln, 0.6))
	}
	for _, ln := range findByLine(content, composeSockRe) {
		out = append(out, finding("POSTURE-008", model.SeverityHigh,
			"Mount docker.sock", "Mengaitkan docker.sock memberi akses setara root ke host.",
			"Hindari mount docker.sock; gunakan socket proxy terbatas.",
			rel, ln, 0.8))
	}
	return out
}

var (
	k8sPrivRe     = regexp.MustCompile(`(?im)^\s*-?\s*privileged\s*:\s*true`)
	k8sHostRe     = regexp.MustCompile(`(?im)^\s*-?\s*(hostNetwork|hostPID|hostIPC)\s*:\s*true`)
	k8sHostPathRe = regexp.MustCompile(`(?im)^\s*-?\s*hostPath\s*:`)
	k8sRootRe     = regexp.MustCompile(`(?im)^\s*-?\s*runAsUser\s*:\s*0\b`)
	k8sLatestRe   = regexp.MustCompile(`(?im)^\s*-?\s*image\s*:\s*\S+:latest`)
)

func scanK8s(rel, content string) []model.Finding {
	var out []model.Finding
	for _, ln := range findByLine(content, k8sPrivRe) {
		out = append(out, finding("POSTURE-010", model.SeverityHigh,
			"Pod privileged", "`privileged: true` memberi pod kontrol penuh atas node.",
			"Hapus privileged; gunakan securityContext ketat.",
			rel, ln, 0.8))
	}
	for _, ln := range findByLine(content, k8sHostRe) {
		out = append(out, finding("POSTURE-011", model.SeverityHigh,
			"Namespace host pada pod", "Host namespace membocorkan isolasi node ke pod.",
			"Matikan hostNetwork/hostPID/hostIPC.",
			rel, ln, 0.7))
	}
	for _, ln := range findByLine(content, k8sHostPathRe) {
		out = append(out, finding("POSTURE-012", model.SeverityMedium,
			"Volume hostPath", "hostPath mengekspos filesystem node ke pod.",
			"Gunakan volume CSI/PVC; batasi path bila hostPath tak terhindarkan.",
			rel, ln, 0.6))
	}
	for _, ln := range findByLine(content, k8sRootRe) {
		out = append(out, finding("POSTURE-013", model.SeverityMedium,
			"runAsUser: 0", "Pod berjalan sebagai root (UID 0).",
			"Set runAsNonRoot: true dan runAsUser non-nol.",
			rel, ln, 0.6))
	}
	for _, ln := range findByLine(content, k8sLatestRe) {
		out = append(out, finding("POSTURE-014", model.SeverityLow,
			"Image :latest", "Tag :latest tidak reprodusibel.",
			"Pin ke versi/digest spesifik.",
			rel, ln, 0.5))
	}
	return out
}

var (
	ghaPRTargetRe = regexp.MustCompile(`(?m)\bpull_request_target\b`)
	ghaInjectRe   = regexp.MustCompile(`\$\{\{\s*github\.(event|head_ref|base_ref)`)
	ghaUsesRe     = regexp.MustCompile(`(?m)^\s*-?\s*uses\s*:\s*([^\s#]+)`)
	ghaWriteAllRe = regexp.MustCompile(`(?im)^\s*permissions\s*:\s*write-all`)
	ghaSHARe      = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func scanWorkflow(rel, content string) []model.Finding {
	var out []model.Finding
	for _, ln := range findByLine(content, ghaPRTargetRe) {
		out = append(out, finding("POSTURE-020", model.SeverityMedium,
			"pull_request_target", "Trigger ini berjalan dengan token/base repo — berbahaya bila memproses kode PR.",
			"Gunakan `pull_request`; bila terpaksa, jangan checkout head PR dan batasi permissions.",
			rel, ln, 0.6))
	}
	for _, ln := range findByLine(content, ghaInjectRe) {
		out = append(out, finding("POSTURE-021", model.SeverityHigh,
			"Script injection di workflow", "Konteks github.event/head_ref di interpolasi langsung ke shell dapat dieksekusi.",
			"Lewatkan lewat `env:` lalu pakai variabel, jangan interpolasi langsung di `run:`.",
			rel, ln, 0.7))
	}
	for _, ln := range findByLine(content, ghaWriteAllRe) {
		out = append(out, finding("POSTURE-022", model.SeverityHigh,
			"permissions: write-all", "Token workflow diberi akses tulis penuh.",
			"Set permissions minimal (mis. contents: read).",
			rel, ln, 0.7))
	}
	for _, m := range ghaUsesRe.FindAllStringSubmatchIndex(content, -1) {
		ref := content[m[2]:m[3]]
		line := lineOf(content, m[0])
		if at := strings.LastIndex(ref, "@"); at >= 0 {
			version := ref[at+1:]
			if !ghaSHARe.MatchString(version) {
				out = append(out, finding("POSTURE-023", model.SeverityLow,
					"Action tidak di-pin ke SHA", "Action pihak ketiga di-pin ke tag/branch — dapat berubah tanpa jejak.",
					"Pin ke commit SHA lengkap.",
					rel, line, 0.5))
			}
		}
	}
	return out
}

func hasFromNoTag(content string) bool {
	for _, l := range strings.Split(content, "\n") {
		t := strings.TrimSpace(l)
		if len(t) < 5 || !strings.EqualFold(t[:5], "FROM ") {
			continue
		}
		image := strings.TrimSpace(t[5:])
		if i := strings.IndexAny(image, " \t"); i >= 0 {
			image = image[:i] // drop `AS stage` / comments
		}
		if image == "" || strings.Contains(image, "@sha256:") {
			continue
		}
		// A tag is a ':' after the last '/'.
		last := image[strings.LastIndex(image, "/")+1:]
		if !strings.Contains(last, ":") || strings.HasSuffix(last, ":latest") {
			return true
		}
	}
	return false
}

func firstLine(content string, re *regexp.Regexp) int {
	for i, l := range strings.Split(content, "\n") {
		if re.MatchString(l) {
			return i + 1
		}
	}
	return 1
}

func lineOf(content string, off int) int {
	return strings.Count(content[:off], "\n") + 1
}
