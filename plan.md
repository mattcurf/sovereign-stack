# Secure sovereign stack: implementation prompt and plan

Build an instructive demonstration of the complete lifecycle of a sovereign
software stack. Implement the components below, test them, open a pull request,
request an Oracle review, fix its actionable findings, and monitor PR checks.
Use GPT-6 Astra Low subagents for independently owned parallel work where useful.

## Required deliverables

1. `base-container/`: a minimal practical Debian **trixie** base, built with
   standard Debian tools (mmdebstrap), using authenticated, timestamp-pinned
   Debian snapshots. Explain size/security tradeoffs; do not claim a theoretical
   minimum. Retain package identity and copyright evidence for auditing.
2. `nginx/`: NPM-built static hello-world content served by nginx, based on the
   base image. Node/NPM are build tools, not an unnecessary runtime server.
3. `rust/`: a hello-world HTTP server using **Tokio** and locked crates, based on
   the base image; no compiler in its runtime.
4. `python/`: a hello-world HTTP server with pip-installed, hash-locked packages,
   based on the base image; no build tooling in its runtime.
5. `deploy/compose/`: an independent Docker Compose loader for all three apps,
   on different host ports, verifying every immutable image digest with Cosign
   against an exact trusted GitHub Actions OIDC issuer and workflow identity
   before any application starts. Fail closed on verification errors.
6. `deploy/helm/`: an independent Helm loader for the same apps and distinct
   ports, with equivalent verification. Clearly distinguish loader-time checks
   from cluster-wide admission enforcement and document that trust boundary.
7. GitHub CI: build and test all images; inventory and scan with native Trivy; on trusted
   main-branch changes publish to GHCR, keylessly sign image digests using
   Sigstore Fulcio/GitHub OIDC, record signatures in Rekor, and verify them.
   Pull requests must not receive publishing or signing permissions.
8. Independent evidence generation: catalog OS and language packages, runtime
   and build dependencies, SPDX/CycloneDX SBOMs, provenance/materials, license
   inventories, third-party attribution texts, and an explicit unresolved
   license/evidence report. Preserve Debian copyright and package metadata.
   Do not equate scanner discovery with mathematically complete provenance.
9. Nightly CI: enumerate the published artifact inventory, verify signatures and
   attestations, and rescan immutable artifacts using fresh vulnerability data.
   Fail visibly on HIGH/CRITICAL CVEs with nonempty `FixedVersion`, scanner or
   malformed-report errors, stale/failed databases, missing evidence, or invalid
   signatures. Retain reports even on failure; document remediation/alerts.
10. Concise but generous documentation: quick start, theory of operations,
    threat model, trust roots, least privilege, sovereign/offline mirroring,
    source and license obligations, pin updates, vulnerability response,
    reproducibility limitations, and authoritative research references.

## Security and reproducibility contract

- Pin actions to full commit SHAs, container inputs to SHA-256 digests, language
  dependencies to complete lockfiles (pip with hashes), tool downloads to exact
  versions and SHA-256 checksums, and Debian inputs to signed snapshots.
- Use linux/amd64 initially and document this scope. Mutable GitHub-hosted runner
  infrastructure and fresh advisory databases are explicit trust inputs, not
  reproducible build material. Never pretend a runner label is an immutable VM.
- Run apps as a non-root numeric UID, on unprivileged ports, with a read-only
  filesystem, dropped capabilities, no privilege escalation, resource limits,
  and narrowly scoped writable tmpfs volumes where needed.
- Sign and deploy digests, never mutable image tags. Keyless verification trusts
  a public issuer + exact workflow identity, not shared private credentials.
- Gate High/Critical vulnerabilities with available fixes; report every finding,
  including unfixed and lower-severity vulnerabilities. Keep runtime software and
  retained build-tool provenance in distinct inventories and scan both. Scanner,
  database and malformed-report errors still fail closed. Passing is not CVE freedom.
- Permit only explicitly approved tool CVE dispositions bound to executable hash,
  release, platform, dependency and advisory, with evidence and at most 30-day expiry.
  Preserve raw findings and report original/excepted/remaining blocker counts.
  Recompute dispositions and expiry at publication and historical rescan time;
  unknown applicability is not an automatic exception.
- Use official checksum-verified Trivy 0.74.0, not custom binaries; retain native
  whole-image/scope JSON, SPDX, and Trivy-generated CycloneDX. Scan all 25 inventories
  with `trivy sbom` on their CycloneDX; preserve separate source and build provenance.
  Keep notices, license JSON/CSV, unresolved evidence and build metadata. Trivy
  license support proves neither legal compliance nor complete source provenance.
- Use default distro-aware Trivy severity (vendor then fallback), without VEX or
  ignore suppression. Refresh the OCI vulnerability DB when due per its metadata;
  validate maximum age 120 hours, future timestamps and `NextUpdate`, and retain DB
  metadata with reports. Never GitHub-cache vulnerability DBs or security results.
- No historical release exists yet. New signed archives contain Trivy CycloneDX;
  legacy Syft-native archives fail closed and require explicit migration. Do not
  promise identical package or vulnerability counts across scanners.
- Pinning alone is not proof of bit-for-bit reproducibility. Normalize build
  timestamps where supported and explain remaining sources of nondeterminism.
- Do not claim SLSA certification or full sovereignty from using public GitHub,
  GHCR, Debian mirrors, or Sigstore. Document migration/export trust boundaries.
- Use unprivileged PR jobs, explicit permissions, bounded job timeouts, and no
  execution of PR code through `pull_request_target`.

## Parallel implementation boundaries

- Container work owns `base-container/`, `nginx/`, `rust/`, `python/` and the local
  image build/smoke-test scripts. All final application Dockerfiles use a supplied
  `BASE_IMAGE`. The local build produces `sovereign-stack/<name>:local` for
  `base-container`, `nginx`, `rust`, and `python`.
- Loader work owns `deploy/` and verification/loader tests; its inventory is a
  JSON object mapping the four component names to GHCR `@sha256:` references.
  The trusted identity is the repository's `publish.yml@refs/heads/main`.
- Evidence/tooling work owns pinned security-tool installation, SBOM/license
  scripts and their tests. Evidence consumes local Docker image references or
  immutable registry references and writes reports beneath a caller-selected
  output directory.
- The supervising agent integrates workflows, orb setup, top-level docs and
  cross-component tests; reviews all transferred changes and resolves contracts.

## Verification and acceptance

Run syntax/unit/lock-policy checks, render Helm and Compose configurations,
exercise positive and negative signature-verification paths, build and smoke
test all containers, and inspect the rendered nginx hello-world page. Verify
orb setup twice for idempotence after adding actual prerequisites. Do not claim
OIDC signing, GHCR publication, or cluster deployment occurred without evidence.
Publishing workflows run on merge to main; opening a PR alone does not publish.
Oracle review and passing PR checks are required before reporting completion.
Report unresolved external access or vulnerability blockers honestly.

## Initial authoritative references (expand while implementing)

- Debian mmdebstrap: <https://manpages.debian.org/trixie/mmdebstrap/mmdebstrap.1.en.html>
- Debian snapshot archive: <https://snapshot.debian.org/>
- Sigstore verification: <https://docs.sigstore.dev/cosign/verifying/verify/>
- Cosign: <https://github.com/sigstore/cosign>
- Trivy SBOM scanning: <https://trivy.dev/latest/docs/target/sbom/>
- Trivy database configuration: <https://trivy.dev/latest/docs/configuration/db/>
- GitHub Actions security: <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
- SLSA provenance: <https://slsa.dev/spec/v1.1/provenance>
- Kubernetes pod security: <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
