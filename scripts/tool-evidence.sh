#!/usr/bin/env bash
set -euo pipefail
[[ $# == 0 || ( $# == 1 && $1 == --collect-only ) ]] || { echo 'Usage: tool-evidence.sh [--collect-only]' >&2; exit 2; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export PATH="$root/.tools/bin:$PATH"
out="$root/evidence/tools"
mkdir -p "$out"
for variable in ${!SYFT_@}; do unset "$variable"; done
printf '{}\n' > "$out/syft-policy.yaml"
SYFT_CHECK_FOR_APP_UPDATE=false SYFT_LICENSE_CONTENT=all \
  syft scan "dir:$root/.tools/bin" --config "$out/syft-policy.yaml" \
  -o "syft-json=$out/sbom.syft.json" -o "spdx-json=$out/sbom.spdx.json" \
  -o "cyclonedx-json=$out/sbom.cyclonedx.json" 2> "$out/syft.log"
cp "$root/tools/lock.json" "$out/lock.json"
python3 "$root/scripts/license-report.py" "$out/sbom.syft.json" "$out"
if [[ ${1:-} == --collect-only ]]; then exit 0; fi
"$root/scripts/scan-sbom.sh" "$out/sbom.syft.json" "$out"
