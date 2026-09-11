#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
while IFS= read -r -d '' file; do
  bash -n "$file"
done < <(find .agents scripts tools deploy -type f \( -name '*.sh' -o -name setup -o -name resume \) -print0)
actionlint -shellcheck=''
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s tools -v
python3 -m unittest discover -s deploy/tests -v
helm lint deploy/helm/sovereign-stack --strict -f deploy/tests/helm-values.json
printf 'Repository checks passed.\n'
