#!/usr/bin/env bash
set -euo pipefail
root=$(dirname "$(dirname "$(realpath "$0")")")
docker=${DOCKER:-docker}
args=(--platform linux/amd64)
if [[ -n ${BUILD_NETWORK:-} ]]; then args+=(--network "$BUILD_NETWORK"); fi
for component in base-container nginx rust python; do
    start=$SECONDS
    "$docker" build "${args[@]}" \
        --build-arg BASE_IMAGE=sovereign-stack/base-container:local \
        --tag "sovereign-stack/$component:local" "$root/$component"
    case "$component" in
        base-container) stage=bootstrap ;;
        nginx) stage=static ;;
        rust) stage=build ;;
        python) stage=dependencies ;;
    esac
    "$docker" build "${args[@]}" --target "$stage" \
        --build-arg BASE_IMAGE=sovereign-stack/base-container:local \
        --tag "sovereign-stack/$component-builder:local" "$root/$component"
    printf '%s built in %ss\n' "$component" "$((SECONDS - start))"
done
