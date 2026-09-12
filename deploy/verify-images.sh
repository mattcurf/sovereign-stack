#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 ]] || { echo 'Usage: verify-images.sh INVENTORY.json' >&2; exit 2; }
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
identity=${COSIGN_TRUSTED_IDENTITY:-https://github.com/mattcurf/sovereign-stack/.github/workflows/publish.yml@refs/heads/main}
issuer=${COSIGN_TRUSTED_ISSUER:-https://token.actions.githubusercontent.com}
umask 077
refs=$(mktemp)
trap 'rm -f -- "$refs"' EXIT
# Validate the entire input before making even one verification request.
python3 "$here/inventory.py" "$1" > "$refs"
while IFS= read -r image; do
    cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$image" >/dev/null
    cosign verify-attestation --type spdxjson --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$image" >/dev/null
    cosign verify-attestation --type slsaprovenance1 --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" "$image" >/dev/null
done < "$refs"
