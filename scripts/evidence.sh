#!/usr/bin/env bash
# Independent evidence generation; no app execution, no signing credentials needed.
set -euo pipefail
[[ $# == 2 || ( $# == 3 && $3 == --collect-only ) ]] || { echo 'Usage: scripts/evidence.sh IMAGE OUTPUT_DIR [--collect-only]' >&2; exit 2; }
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
export PATH="$ROOT/.tools/bin:$PATH"
IMAGE=${1#docker:}
mkdir -p -- "$2"
OUT=$(realpath -- "$2")
SOURCE=${SOURCE_DIR-$ROOT}
if [[ -n $SOURCE ]]; then SOURCE=$(realpath -- "$SOURCE"); fi
# A fresh directory avoids mixing evidence from different images or failed runs.
[[ -z $(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
  echo 'OUTPUT_DIR must be empty' >&2; exit 2;
}
TMP=$(mktemp -d)
CID=''
cleanup() {
  if [[ -n $CID ]]; then docker rm "$CID" >/dev/null || true; fi
  rm -rf -- "$TMP"
}
trap cleanup EXIT
# Do not inherit user configuration or environment suppression rules.
for variable in ${!TRIVY_@}; do unset "$variable"; done
printf 'disable-telemetry: true\nskip-version-check: true\n' > "$TMP/trivy.yaml"
TRIVY_ARGS=(--config "$TMP/trivy.yaml" --ignorefile /dev/null --cache-backend memory)
if ! docker image inspect "$IMAGE" > "$OUT/image-inspect.json" 2> "$OUT/image-pull.log"; then
  docker pull --platform linux/amd64 "$IMAGE" >> "$OUT/image-pull.log" 2>&1
  docker image inspect "$IMAGE" > "$OUT/image-inspect.json"
fi
ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["Id"])' "$OUT/image-inspect.json")
# Freeze a mutable local tag to its content-addressed config ID for both operations.
trivy image "$ID" --image-src docker "${TRIVY_ARGS[@]}" \
  --scanners license --list-all-pkgs --format json \
  --output "$OUT/sbom.complete.trivy.json" 2> "$OUT/inventory.log"
python3 "$ROOT/scripts/partition-sbom.py" "$OUT"
CID=$(docker create --entrypoint /bin/true "$ID")
docker export "$CID" --output "$TMP/image.tar"
for TARGET in "$OUT" "$OUT/build-provenance"; do
  for FORMAT in spdx-json cyclonedx; do
    SUFFIX=${FORMAT%-json}
    trivy convert "$TARGET/sbom.trivy.json" --config "$TMP/trivy.yaml" --ignorefile /dev/null \
      --format "$FORMAT" --output "$TARGET/sbom.$SUFFIX.json"
  done
  python3 "$ROOT/scripts/license-report.py" "$TARGET/sbom.trivy.json" "$TARGET" --image-tar "$TMP/image.tar"
done
if [[ -n $SOURCE ]]; then
mkdir "$OUT/source"
trivy fs "$SOURCE" "${TRIVY_ARGS[@]}" --scanners license --include-dev-deps --list-all-pkgs \
  --file-patterns 'pip:requirements\.lock$' \
  --skip-dirs '**/.git' --skip-dirs '**/.tools' --skip-dirs "$OUT" \
  --skip-dirs '**/evidence' --skip-dirs '**/build' --skip-dirs '**/release' \
  --skip-dirs '**/.amp' --skip-dirs '**/target' --skip-dirs '**/node_modules' \
  --format json --output "$OUT/source/sbom.trivy.json" 2> "$OUT/source/inventory.log"
for FORMAT in spdx-json cyclonedx; do
  trivy convert "$OUT/source/sbom.trivy.json" --config "$TMP/trivy.yaml" --ignorefile /dev/null \
    --format "$FORMAT" --output "$OUT/source/sbom.${FORMAT%-json}.json"
done
python3 "$ROOT/scripts/license-report.py" "$OUT/source/sbom.trivy.json" "$OUT/source" --source-dir "$SOURCE"
python3 - "$SOURCE" "$OUT/source/lockfiles.json" <<'PY'
import hashlib, json, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
records = []
excluded = {'.git', '.tools', 'node_modules', 'target', 'evidence', 'build', 'release', '.amp'}
output = pathlib.Path(sys.argv[2]).parent.parent
for directory, dirs, files in os.walk(root, followlinks=False):
    dirs[:] = sorted(d for d in dirs if d not in excluded and pathlib.Path(directory, d) != output)
    for name in sorted(files):
        path = pathlib.Path(directory, name)
        if not path.is_symlink() and name in {'Cargo.lock', 'Cargo.toml', 'package-lock.json', 'requirements.lock'}:
            data = path.read_bytes()
            records.append({'path': str(path.relative_to(root)), 'sha256': hashlib.sha256(data).hexdigest(),
                            'content': data.decode('utf-8')})
pathlib.Path(sys.argv[2]).write_text(json.dumps(records, indent=2) + '\n')
PY
fi
# Generate notices before CVE scans: failures retain all collected evidence.
if [[ ${3:-} == --collect-only ]]; then exit 0; fi
RESULT=0
TARGETS=("$OUT" "$OUT/build-provenance")
if [[ -n $SOURCE ]]; then TARGETS+=("$OUT/source"); fi
for TARGET in "${TARGETS[@]}"; do
  bash "$ROOT/scripts/scan-sbom.sh" "$TARGET/sbom.cyclonedx.json" "$TARGET" || RESULT=1
done
exit "$RESULT"
