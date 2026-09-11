#!/usr/bin/env bash
# Shared fail-closed policy for fresh and historical, signature-verified SBOMs.
set -euo pipefail
[[ $# == 2 ]] || { echo 'Usage: scripts/scan-sbom.sh SBOM_JSON OUTPUT_DIR' >&2; exit 2; }
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export PATH="$ROOT/.tools/bin:$PATH"
SBOM=$(realpath -- "$1")
mkdir -p -- "$2"
OUT=$(realpath -- "$2")
for variable in ${!TRIVY_@}; do unset "$variable"; done
cat > "$OUT/trivy-policy.yaml" <<'EOF'
disable-telemetry: true
skip-version-check: true
scanners: [vuln]
severity: [UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL]
ignore-unfixed: false
ignore-status: []
vex: []
skip-db-update: false
show-suppressed: true
list-all-pkgs: true
exit-code: 0
EOF
# Explicit empty ignore file defeats repository-local .trivyignore files.
printf '' > "$OUT/trivy.ignore"
CACHE="$ROOT/.tools/trivy-cache"
set +e
trivy sbom "$SBOM" --config "$OUT/trivy-policy.yaml" --ignorefile "$OUT/trivy.ignore" \
  --cache-dir "$CACHE" --cache-backend memory --no-progress --format json \
  > "$OUT/trivy.json" 2> "$OUT/trivy.log"
STATUS=$?
set -e
python3 - "$OUT" "$STATUS" "$ROOT/scripts" "$CACHE" "$SBOM" <<'PY'
import hashlib, json, pathlib, sys
sys.path.insert(0, sys.argv[3])
from vulnerability_policy import evaluate, validate_database, POLICY
from inventory_contract import validate_inventory
out = pathlib.Path(sys.argv[1])
status = {'policy': POLICY, 'scannerExitCode': int(sys.argv[2]), 'passed': False}
try:
    report = json.loads((out / 'trivy.json').read_text())
    sbom_path = pathlib.Path(sys.argv[5])
    validate_inventory(json.loads(sbom_path.read_text()),
                       json.loads((sbom_path.parent / 'sbom.trivy.json').read_text()), report)
    db = pathlib.Path(sys.argv[4]) / 'db'
    metadata = json.loads((db / 'metadata.json').read_text())
    with (db / 'trivy.db').open('rb') as stream:
        metadata['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
    (out / 'db-metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
    validate_database(metadata)
    status = evaluate(report, status['scannerExitCode'])
except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
    status['error'] = str(error)
(out / 'scan-status.json').write_text(json.dumps(status, indent=2) + '\n')
print(json.dumps(status))
sys.exit(0 if status['passed'] else 1)
PY
