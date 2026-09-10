#!/usr/bin/env bash
set -euo pipefail
docker=${DOCKER:-docker}
containers=()
cleanup() {
    for container in "${containers[@]}"; do "$docker" rm -f "$container" >/dev/null; done
}
trap cleanup EXIT
for component in nginx rust python; do
    image="sovereign-stack/$component:local"
    [[ $("$docker" image inspect --format '{{.Config.User}}' "$image") == 65532:65532 ]]
    network_args=(-p 127.0.0.1::8080)
    # For nested environments with no bridge/NAT support. Containers run serially.
    if [[ ${SMOKE_NETWORK:-bridge} == host ]]; then network_args=(--network host); fi
    container=$("$docker" run -d "${network_args[@]}" \
        --read-only --cap-drop ALL --security-opt no-new-privileges=true \
        --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777 \
        --pids-limit 64 --memory 128m --cpus 1 "$image")
    containers+=("$container")
    port=8080
    if [[ ${SMOKE_NETWORK:-bridge} != host ]]; then
        port=$("$docker" port "$container" 8080/tcp | sed 's/.*://')
    fi
    ready=false
    for attempt in {1..30}; do
        if response=$(curl --fail --silent --max-time 2 "http://127.0.0.1:$port/"); then ready=true; break; fi
        sleep 1
    done
    if [[ $ready != true ]]; then "$docker" logs "$container"; exit 1; fi
    [[ $response == *'Hello, world!'* ]]
    [[ $("$docker" inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$container") == true ]]
    "$docker" exec "$container" sh -ec '
        test "$(id -u)" = 65532; test "$(id -g)" = 65532
        grep -Eq "^CapEff:[[:space:]]+0+$" /proc/1/status
        grep -Eq "^NoNewPrivs:[[:space:]]+1$" /proc/1/status
        if touch /should-not-be-writable 2>/dev/null; then exit 1; fi
        touch /tmp/writable; rm /tmp/writable
        test -s /var/lib/dpkg/status
        test -f /usr/share/doc/base-files/copyright
        for tool in node npm rustc cargo pip pip3 cc; do
            if command -v "$tool"; then exit 1; fi
        done
    '
    printf '%s: HTTP hello-world, UID/GID, zero caps, no-new-privileges, read-only root, writable /tmp, package metadata, no runtime build tools: PASS\n' "$component"
    "$docker" rm -f "$container" >/dev/null
    containers=()
done
