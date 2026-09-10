#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
: "${GITHUB_REPOSITORY:?}" "${GH_TOKEN:?}"
identity="https://github.com/$GITHUB_REPOSITORY/.github/workflows/publish.yml@refs/heads/main"
issuer=https://token.actions.githubusercontent.com
out="$PWD/evidence/nightly"
mkdir -p "$out"
# Pagination is essential: checking only the newest page silently loses history.
gh api --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100" \
  --jq '.[] | select(.tag_name | startswith("stack-")) | .tag_name' > "$out/releases.txt"
if [[ ! -s $out/releases.txt ]]; then
  echo 'No published inventories: lifecycle has not yet produced an auditable release.' | tee "$out/error.txt" >&2
  exit 1
fi
status=0
while IFS= read -r tag; do
  if [[ ! $tag =~ ^stack-[a-f0-9]{40}-[0-9]+-[0-9]+$ ]]; then
    echo "Invalid release inventory tag: $tag" >&2
    status=1
    continue
  fi
  dir="$out/$tag"
  mkdir -p "$dir"
  if ! gh release download "$tag" --repo "$GITHUB_REPOSITORY" --dir "$dir" \
      --pattern inventory.json --pattern inventory.sigstore.json \
      --pattern evidence.tar.gz --pattern evidence.sigstore.json; then
    status=1
    continue
  fi
  if ! cosign verify-blob --bundle "$dir/inventory.sigstore.json" \
      --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$dir/inventory.json" \
      > "$dir/inventory-verification.txt" 2>&1; then
    status=1
    continue
  fi
  if ! cosign verify-blob --bundle "$dir/evidence.sigstore.json" \
      --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$dir/evidence.tar.gz" \
      > "$dir/evidence-verification.txt" 2>&1; then
    status=1
    continue
  fi
  if ! ./deploy/verify-images.sh "$dir/inventory.json" > "$dir/image-verification.txt" 2>&1; then
    status=1
    continue
  fi
  python3 scripts/rescan-recorded.py "$dir/evidence.tar.gz" "$dir/inventory.json" "$dir/recorded" || status=1
  for name in base-container nginx rust python; do
    ref=$(jq -er --arg name "$name" '.[$name]' "$dir/inventory.json")
    SOURCE_DIR='' ./scripts/evidence.sh "$ref" "$dir/$name" || status=1
  done
done < "$out/releases.txt"
if [[ $status != 0 ]]; then
  echo 'Artifact audit failed. Inspect nightly-evidence; do not deploy affected releases.' >&2
fi
exit "$status"
