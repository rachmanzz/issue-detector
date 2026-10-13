#!/usr/bin/env bash
# Benchmark Mode A (PRD §12): repo sintetis 100k LOC harus < 30 detik.
# Penggunaan:  scripts/bench.sh
set -euo pipefail

cd "$(dirname "$0")/.."

GEN_DIR=$(mktemp -d /tmp/idbench-gen.XXXXXX)
REPO_DIR=$(mktemp -d /tmp/idbench.XXXXXX)
trap 'rm -rf "$GEN_DIR" "$REPO_DIR"' EXIT

# Generate ~100k LOC (1000 file x 100 baris) dengan python3.
python3 - "$GEN_DIR" <<'PY'
import sys, os
out = sys.argv[1]
os.makedirs(out, exist_ok=True)
for i in range(1000):
    lines = ["package p" + str(i), ""]
    for k in range(98):
        lines.append("func f%d(x, y int) int { if x > y { x -= y } }; _ = x + y; return x }" % k)
    open(os.path.join(out, "f%d.go" % i), "w").write("\n".join(lines) + "\n")
PY

LOC=$(find "$GEN_DIR" -name '*.go' -print0 | xargs -0 cat | wc -l)
echo "repositori sintetis: $LOC LOC"

go build -o /tmp/idbench-bin ./cmd/issue-detector

START=$(date +%s%N)
/tmp/idbench-bin scan "$GEN_DIR" --no-git --no-deps --no-adapters --quiet >/dev/null 2>&1
RC=$?
END=$(date +%s%N)
ELAPSED_MS=$(( (END - START) / 1000000 ))

echo "durasi scan: ${ELAPSED_MS} ms"
if [ "$RC" -ne 0 ]; then
    echo "FAIL: scan exit $RC"
    exit 1
fi
if [ "$ELAPSED_MS" -gt 30000 ]; then
    echo "FAIL: melebihi target 30s untuk 100k LOC"
    exit 1
fi
echo "OK: < 30 detik (target PRD §12)"