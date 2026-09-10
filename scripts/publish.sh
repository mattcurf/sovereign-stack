#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PWD/.tools/bin:$PATH"
: "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}" "${GITHUB_ACTOR:?}" "${GH_TOKEN:?}"
identity="https://github.com/$GITHUB_REPOSITORY/.github/workflows/publish.yml@refs/heads/main"
issuer=https://token.actions.githubusercontent.com
if [[ ${GITHUB_EVENT_NAME:-} != push || ${GITHUB_REF:-} != refs/heads/main ||
      ${GITHUB_WORKFLOW_REF:-} != "$GITHUB_REPOSITORY/.github/workflows/publish.yml@refs/heads/main" ]]; then
  echo 'Publishing requires the main-branch publish workflow.' >&2
  exit 1
fi
registry="ghcr.io/${GITHUB_REPOSITORY,,}"
docker load -i build/images.tar
mkdir -p release
python3 scripts/validate-release.py > release/validated-images.json
printf '%s' "$GH_TOKEN" | docker login ghcr.io --username "$GITHUB_ACTOR" --password-stdin
trap 'docker logout ghcr.io >/dev/null' EXIT
# Index the attempt before registry writes so an interrupted publication is
# visible to nightly auditing rather than leaving silently untracked packages.
release_tag="stack-$GITHUB_SHA-${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
gh release create "$release_tag" --repo "$GITHUB_REPOSITORY" --target "$GITHUB_SHA" \
  --prerelease --latest=false --title "INCOMPLETE stack publication $GITHUB_SHA" \
  --notes 'Publication in progress or interrupted. Not deployable until signed inventory and evidence are present.'
printf '{}\n' > release/inventory.json
for name in base-container nginx rust python; do
  tag="$registry/$name:$GITHUB_SHA"
  image_id=$(jq -er --arg name "$name" '.[$name]' release/validated-images.json)
  docker tag "$image_id" "$tag"
  docker push "$tag"
  ref=$(docker inspect "$tag" --format '{{json .RepoDigests}}' |
    jq -er --arg prefix "$registry/$name@sha256:" '.[] | select(startswith($prefix))')
  [[ $ref =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$ ]]
  jq --arg name "$name" --arg ref "$ref" '. + {($name): $ref}' release/inventory.json > release/inventory.next
  mv release/inventory.next release/inventory.json
done
for name in base-container nginx rust python; do
  ref=$(jq -er --arg name "$name" '.[$name]' release/inventory.json)
  if [[ $name == base-container ]]; then
    printf '[]\n' > release/materials.json
  else
    jq '[."base-container" | split("@sha256:") | {uri: .[0], digest: {sha256: .[1]}}]' release/inventory.json > release/materials.json
  fi
  python3 scripts/provenance.py "${ref##*@}" "evidence/$name/provenance.json" \
    --materials release/materials.json --build-metadata evidence/build.json
  # Default keyless signing obtains OIDC/Fulcio certificates and uploads to Rekor.
  cosign sign --yes "$ref"
  cosign attest --yes --type spdxjson --predicate "evidence/$name/sbom.spdx.json" "$ref"
  cosign attest --yes --type slsaprovenance1 --predicate "evidence/$name/provenance.json" "$ref"
done
./deploy/verify-images.sh release/inventory.json
cosign sign-blob --yes --bundle release/inventory.sigstore.json release/inventory.json
cosign verify-blob --bundle release/inventory.sigstore.json \
  --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" release/inventory.json
cp release/inventory.json evidence/inventory.json
tar -czf release/evidence.tar.gz evidence
cosign sign-blob --yes --bundle release/evidence.sigstore.json release/evidence.tar.gz
gh release upload "$release_tag" --repo "$GITHUB_REPOSITORY" \
  release/inventory.json release/inventory.sigstore.json release/evidence.tar.gz release/evidence.sigstore.json
gh release edit "$release_tag" --repo "$GITHUB_REPOSITORY" --prerelease=false \
  --title "Verified stack $GITHUB_SHA (run $GITHUB_RUN_ID/$GITHUB_RUN_ATTEMPT)" \
  --notes 'Digest-only inventory and evidence, keylessly signed by publish.yml on main. Verify the bundles before use. See README.md.'
