# Sovereign stack

An instructive, Linux/amd64 demonstration of a Debian-based software supply chain:
build → test → inventory → scan → publish → sign → verify → run → rescan.
See [the implementation plan](plan.md) for scope and acceptance criteria.

**Security is a process, not an image label.** Release gates reject High/Critical
findings with available fixes; full reports retain every finding, including unfixed
and lower-severity CVEs. Passing is time- and database-dependent, not CVE freedom. This
project does not promise perpetual CVE freedom, certified SLSA compliance, or
bit-for-bit reproducibility merely because its inputs are pinned.

## Components

| Directory | Purpose |
| --- | --- |
| [base-container](base-container/) | Minimal practical Debian trixie rootfs using mmdebstrap and authenticated snapshots |
| [nginx](nginx/) | NPM-built hello-world static content, served by nginx |
| [rust](rust/) | Locked Rust/Tokio hello-world HTTP server |
| [python](python/) | Hash-locked pip hello-world HTTP server |
| [deploy](deploy/) | Independent, fail-closed Compose and Helm loaders |
| [tools](tools/) | Version- and checksum-pinned security tools and Docker plugins |
| [Evidence guide](docs/evidence.md) | Independent SBOMs, license inventory, notices, and provenance |
| [Operations guide](docs/operations.md) | Trust model, releases, CVE response, mirroring, and reproducibility |

All application images derive from `base-container`, listen internally on 8080,
and run as UID/GID 65532. Loaders expose nginx/Rust/Python on distinct ports
8081/8082/8083 and apply read-only filesystems, dropped capabilities, resource
limits, and no privilege escalation. Node, npm, Cargo, and pip belong to build
stages, not production processes. Exact runtime contents are visible in SBOMs.

## Build and check locally

Prerequisites: Linux/amd64, Bash, Python 3, curl, tar, jq, Git, and a running Docker
daemon. Docker access is effectively host-root access; use an isolated machine.
GitHub CLI is needed only for release/audit operations. The locked installer
provides Syft, Grype, Cosign, Helm, actionlint, Docker userspace, Buildx, and Compose.

```sh
./tools/install.sh
export PATH="$PWD/.tools/bin:$PATH"
./scripts/check.sh
./scripts/build-images.sh
./scripts/smoke-images.sh
./scripts/scan-images.sh
```

The four local image names are `sovereign-stack/<component>:local`. These tags
are local build handles, **not trusted deployment references**. Scan reports go
to ignored `evidence/`; the four runtime images, four builder stages, and installed
tool binaries are inventoried even when another scan fails. Do not turn a failing
scan into success by hiding findings.

Runtime SBOMs distinguish installed software from retained build-tool metadata.
`build-provenance/` holds the latter's inventories and scans; `sbom.complete.syft.json`
preserves the original whole-image inventory. All scopes use the same blocking policy.

Amp orbs run `.agents/setup` to cache the pinned tools. `.agents/resume` remains
fast and reconnects a supervised, Unix-socket-only Docker daemon without installing
dependencies. Container build toolchains live in pinned builder images rather than
an unrelated host npm/pip/Cargo environment. The first container build downloads
application dependencies; subsequent builds reuse Docker layers. Setup does not
start a daemon or prebuild container images. Orb-only login settings use host
networking for nested Docker builds/tests; production loaders retain isolation.

## CI and release lifecycle

- **CI** runs pin/syntax/unit/renderer checks, builds and smoke-tests all images,
  then independently inventories and scans them. It uploads failure evidence.
  Pull requests have read-only repository permissions and no OIDC signing token.
  Its five checks are **Code & Workflow Validation**, **Container Build**,
  **Runtime Security & HTTP Tests**, **SBOM Generation & License Reports**, and
  **CVE Check (Fixable High & Critical)**. Smoke tests and SBOM collection run in
  parallel after the build; CVE checking consumes the generated inventories without
  rebuilding images. A CVE failure does not mark SBOM generation as failed.
- **Publish signed stack** runs only on pushes to `main`. A read-only build job
  gates the images; a separate privileged job uploads them to
  `ghcr.io/mattcurf/sovereign-stack/<component>`, signs immutable digests, attaches
  SPDX and SLSA-format provenance attestations, and verifies all three claims.
  Signing uses GitHub OIDC → Fulcio → Rekor, without a stored signing private key.
- Each successful publication creates a `stack-<commit>-<run>-<attempt>` GitHub
  release containing a **signed inventory**, a **signed evidence archive**, and
  their Sigstore bundles. Commit tags on images are conveniences; loaders use
  only `@sha256:` digests from a verified inventory. An incomplete prerelease
  marker is created before registry writes so interrupted publication is visible.
- **Nightly artifact audit** runs at 09:23 UTC, enumerates all stack releases
  with pagination, verifies their evidence and every image/attestation, and
  rescans with fresh vulnerability data. It fails when there is no initial
  release, evidence is missing, verification fails, or fixable High/Critical findings
  are found. Scanner/database errors also fail closed; all CVEs remain in reports.
  Subscribe to Actions failure notifications; nightly reports are kept 90 days.

Opening a PR does not publish artifacts. On first successful main publication,
an owner may need to set GHCR package visibility/access deliberately; the workflow
does not change registry permissions. Enable branch protection and require all five
named CI checks before merging (replace any old `validate`/`containers` requirements).
Publishing needs Actions package-write, contents-write
(release assets), and OIDC permissions. There are no production deployment secrets.

## Run a published stack

Download `inventory.json` and `inventory.sigstore.json` from a selected stack
release, then verify the inventory before invoking either loader:

```sh
cosign verify-blob --bundle inventory.sigstore.json \
  --certificate-identity 'https://github.com/mattcurf/sovereign-stack/.github/workflows/publish.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' inventory.json

./deploy/compose/load.sh inventory.json
# OR, with an independently administered Kubernetes cluster/current kube-context:
./deploy/helm/load.sh inventory.json
```

The loaders verify image signatures and SBOM/provenance attestations before
starting anything. The trusted signer is operator policy, not an input supplied
by the untrusted inventory. Registry login may be necessary for private packages;
this is separate from Sigstore verification and should use a read-only credential.
See [loader documentation](deploy/README.md) for rendering and trust
boundaries. A Helm preflight is not a cluster admission controller: cluster users
who can bypass the loader need separate admission enforcement.

## License and completeness

First-party demonstration code is MIT-licensed. Dependencies retain their own
licenses. Generated inventories and third-party notices are evidence for review,
not legal certification. Keep Debian copyright metadata, the full evidence bundle,
and corresponding source materials when redistributing. Unknown licenses and
scanner blind spots must be resolved, not silently called compliant.
