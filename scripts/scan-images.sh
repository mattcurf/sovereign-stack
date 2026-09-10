#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
status=0
./scripts/tool-evidence.sh || status=1
for name in base-container nginx rust python base-container-builder nginx-builder rust-builder python-builder; do
  # Continue collecting the other reports, but never turn a failed gate green.
  ./scripts/evidence.sh "docker:sovereign-stack/$name:local" "evidence/$name" || status=1
done
exit "$status"
