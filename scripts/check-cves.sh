#!/usr/bin/env bash
# Scan every required inventory, including empty provenance scopes; never skip missing inputs.
set -euo pipefail
cd "$(dirname "$0")/.."
status=0
bash scripts/scan-sbom.sh evidence/tools/sbom.syft.json evidence/tools || status=1
for name in base-container nginx rust python base-container-builder nginx-builder rust-builder python-builder; do
  for scope in '' /build-provenance /source; do
    directory="evidence/$name$scope"
    bash scripts/scan-sbom.sh "$directory/sbom.syft.json" "$directory" || status=1
  done
done
exit "$status"
