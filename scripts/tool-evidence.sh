#!/usr/bin/env bash
set -euo pipefail
[[ $# == 0 || ( $# == 1 && $1 == --collect-only ) ]] || { echo 'Usage: tool-evidence.sh [--collect-only]' >&2; exit 2; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export PATH="$root/.tools/bin:$PATH"
out="$root/evidence/tools"
mkdir -p "$out"
for variable in ${!TRIVY_@}; do unset "$variable"; done
printf 'disable-telemetry: true\nskip-version-check: true\n' > "$out/inventory-policy.yaml"
# rootfs enables installed binary analyzers; fs is for source/lockfile analysis.
trivy rootfs "$root/.tools/bin" --config "$out/inventory-policy.yaml" --ignorefile /dev/null \
  --cache-backend memory --scanners license --list-all-pkgs --format json \
  --output "$out/sbom.trivy.json" 2> "$out/inventory.log"
python3 - "$root" "$out/sbom.trivy.json" <<'PY'
import hashlib, json, pathlib, sys
root, output = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
lock = json.loads((root / 'tools/lock.json').read_text())
for tool in lock['tools']:
    binary = root / '.tools/bin' / tool['name']
    if binary.is_symlink() or hashlib.sha256(binary.read_bytes()).hexdigest() != tool['binary_sha256']:
        raise SystemExit(f'Tool evidence does not match reviewed binary: {tool["name"]}')
inventory = json.loads(output.read_text())
inventory['sovereignStackTools'] = lock
output.write_text(json.dumps(inventory, indent=2) + '\n')
PY
for format in spdx-json cyclonedx; do
  trivy convert "$out/sbom.trivy.json" --config "$out/inventory-policy.yaml" --ignorefile /dev/null \
    --format "$format" --output "$out/sbom.${format%-json}.json"
done
cp "$root/tools/lock.json" "$out/lock.json"
python3 "$root/scripts/license-report.py" "$out/sbom.trivy.json" "$out"
if [[ ${1:-} == --collect-only ]]; then exit 0; fi
"$root/scripts/scan-sbom.sh" "$out/sbom.cyclonedx.json" "$out"
