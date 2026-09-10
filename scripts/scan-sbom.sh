#!/usr/bin/env bash
# Shared fail-closed policy for fresh and historical, signature-verified SBOMs.
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: scripts/scan-sbom.sh SBOM_JSON OUTPUT_DIR' >&2; exit 2; }
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export PATH="$ROOT/.tools/bin:$PATH"
SBOM=$(realpath -- "$1")
mkdir -p -- "$2"
OUT=$(realpath -- "$2")
for variable in ${!GRYPE_@}; do unset "$variable"; done
cat > "$OUT/grype-policy.yaml" <<'EOF'
check-for-app-update: false
only-fixed: false
only-notfixed: false
ignore: []
exclude: []
vex-documents: []
db:
  auto-update: true
  validate-by-hash-on-start: true
  validate-age: true
  max-allowed-built-age: 120h
  require-update-check: true
  max-update-check-frequency: 0s
EOF
set +e
grype "sbom:$SBOM" --config "$OUT/grype-policy.yaml" -o json \
  > "$OUT/grype.json" 2> "$OUT/grype.log"
STATUS=$?
set -e
python3 - "$OUT" "$STATUS" "$ROOT/scripts" <<'PY'
import json, pathlib, sys
sys.path.insert(0, sys.argv[3])
from vulnerability_policy import evaluate, POLICY
out = pathlib.Path(sys.argv[1])
status = {'policy': POLICY, 'scannerExitCode': int(sys.argv[2]), 'passed': False}
try:
    report = json.loads((out / 'grype.json').read_text())
    status = evaluate(report, status['scannerExitCode'])
except (ValueError, KeyError, TypeError) as error:
    status['error'] = str(error)
(out / 'scan-status.json').write_text(json.dumps(status, indent=2) + '\n')
print(json.dumps(status))
sys.exit(0 if status['passed'] else 1)
PY
