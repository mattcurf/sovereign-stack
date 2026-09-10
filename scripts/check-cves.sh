#!/usr/bin/env bash
# Scan every required inventory, including empty provenance scopes; never skip missing inputs.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# -le 1 ]] || { echo 'Usage: check-cves.sh [all|runtime|build-tools]' >&2; exit 2; }
mode=${1:-all}
case "$mode" in all|runtime|build-tools) ;; *) echo 'Invalid scan scope' >&2; exit 2 ;; esac
targets=()
if [[ $mode != runtime ]]; then targets+=(evidence/tools); fi
for name in base-container nginx rust python; do
  if [[ $mode != build-tools ]]; then targets+=("evidence/$name"); fi
  if [[ $mode != runtime ]]; then
    targets+=("evidence/$name/build-provenance" "evidence/$name/source"
              "evidence/$name-builder" "evidence/$name-builder/build-provenance" "evidence/$name-builder/source")
  fi
done
status=0
for directory in "${targets[@]}"; do
  bash scripts/scan-sbom.sh "$directory/sbom.syft.json" "$directory" || status=1
done
mkdir -p evidence
python3 - "$mode" "${targets[@]}" <<'PY'
import json, pathlib, sys
mode = sys.argv[1]
rows = [f'# CVE scan: {mode}', '',
        'All findings are retained. Only fixable High/Critical findings block; scan errors also fail.',
        'Counts are matches, not unique CVEs. Ignored matches are reported separately.', '',
        '| Inventory | Matches | Ignored | Blocking | Result |',
        '| --- | ---: | ---: | ---: | --- |']
for directory in sys.argv[2:]:
    try:
        status = json.loads((pathlib.Path(directory) / 'scan-status.json').read_text())
        values = [status.get(key, '—') for key in ('matches', 'ignoredMatches', 'blockingMatches')]
        result = 'PASS' if status.get('passed') is True else 'FAIL'
    except (OSError, ValueError, AttributeError):
        values, result = ['—'] * 3, 'ERROR: missing or invalid scan status'
    rows.append(f'| {directory.removeprefix("evidence/")} | {values[0]} | {values[1]} | {values[2]} | {result} |')
pathlib.Path(f'evidence/cve-{mode}.md').write_text('\n'.join(rows) + '\n')
PY
exit "$status"
