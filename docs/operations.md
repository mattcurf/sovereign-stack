# Theory of operations and sovereign deployment

## What is trusted?

The source commit selects all build recipes and lockfiles. SHA-pinned Actions
execute those recipes on GitHub-hosted Linux workers. Debian verifies signed
Release metadata and package hashes from a fixed snapshot; npm integrity hashes,
Cargo checksums, pip hashes, container digests, and tool checksums bind the other
inputs. mmdebstrap constructs an auditable Debian root filesystem, rather than
assembling an undocumented pile of shared libraries.

The trusted main workflow signs the resulting registry digests with an ephemeral
key certified by Fulcio using GitHub Actions OIDC. Rekor records the signing
event. Verification checks the digest, certificate issuer, exact workflow/ref
identity, and transparency evidence. It proves the trusted workflow signed the
artifact—not that its code is safe or that the workflow was uncompromised.

SPDX SBOM and SLSA-format provenance attestations bind inventory/build claims to
each digest. Independent Syft scans are separate from Docker build attestations.
The provenance is **self-reported by this workflow**, not an independent hardened
builder's guarantee and not a claim of SLSA Build Level 3.

The main trust boundaries are:

1. Maintainers/reviewers and protected source history.
2. GitHub Actions platform, runner VM/kernel, pinned Actions, and Docker daemon.
3. Debian archive signing roots, package registries, compiler/tool distributors.
4. GitHub OIDC, Fulcio, Rekor, and Sigstore TUF trust roots.
5. GHCR storage/access policy and the release inventory index.
6. Deployment operator, Docker host or Kubernetes API/admission policy.

Require reviewed changes for workflows, lockfiles, trust identities, and signing
policy. Use protected main and narrowly scoped registry tokens. Do not permit
unreviewed code to run in privileged main jobs or reuse long-lived build workers
across untrusted PRs and releases. Public Rekor discloses signing metadata: never
put secrets in image labels, build args, SBOM fields, or attestation predicates.

## Reproducibility and updates

Locks are reviewed inputs, not a reason to freeze vulnerable software forever.
Update the snapshot timestamps and matching package sets together; regenerate
npm/Cargo/pip locks with the selected tools; resolve builder manifests by digest;
download new tool assets and verify their upstream checksums/signatures before
recording new hashes. Run full build, smoke, evidence, and loader tests in a PR.
Review the SBOM/license delta and preserve previous released inventories.

Inputs without floating versions:

- Actions: full upstream commit SHA (version comments are informational).
- Base/compiler/build images: registry SHA-256 digest.
- Debian: authenticated timestamped snapshot, which fixes transitive resolution.
- npm/Cargo/pip: committed lockfiles, exact versions and integrity checks.
- Downloaded security/renderer tools: release version plus recorded SHA-256.

GitHub's `ubuntu-24.04` runner label is **not an immutable VM image**. Its kernel,
Docker daemon and platform remain trusted infrastructure, and Bash/Python/system
bootstrap utilities are host prerequisites. Production reproducibility needs an
independently pinned and attested VM/builder image. Advisory databases intentionally
move forward; retain their metadata with scans rather than freezing old knowledge.
Signatures, certificate times, scan timestamps and attestation timestamps naturally
differ across runs. BuildKit output metadata and compiled artifacts may still
differ: compare repeated rootfs/artifact hashes before asserting bit-identical builds.

## Vulnerability response

The release gate rejects all known matches, including unfixed vulnerabilities.
Grype database download, validation, or freshness failures also block a release.
This can legitimately leave the PR red when the newest Debian snapshot has an
unfixed issue. Preserve reports and explain the blocker; do not add a blanket
ignore rule or `continue-on-error` to manufacture a passing build.

For a nightly failure: identify the affected image digest/package/advisory from
the retained report; stop promoting it; update pins or remove the dependency;
rebuild, rescan, sign and deploy a new verified digest. Already published images
are immutable and can become vulnerable without a source change. The historical
audit deliberately stays red while an indexed release remains vulnerable.

If a production deployment permits VEX/risk acceptance, introduce a separate
reviewed, signed, time-bounded policy identifying the exact digest and advisory.
This demo has no such bypass. Scanner detection limits remain: absence of known
matches does not prove absence of vulnerabilities or malicious code.

The nightly job fails visibly, but notification delivery is an operator setting.
Subscribe to repository Actions failures and connect your incident channel.
Release inventories are durable GH release assets; nightly workflow artifacts
expire after 90 days. Mirror release evidence for longer retention. Owners can
delete releases or packages: signatures detect tampering, not deletion of an
entire index entry. An external append-only inventory/retention policy is required
to detect malicious omission and prove an exhaustive historical audit.

Publication creates an incomplete prerelease marker before the first GHCR write.
If signing/uploading fails halfway, nightly sees missing evidence and fails instead
of forgetting those packages. Investigate the failed run and either complete its
evidence or explicitly retire its artifacts under an audited retention policy;
do not remove the marker just to hide a failed publication. Each retry has its own
run-attempt inventory, so it cannot silently replace a previously signed release.

Historical audits verify the signed evidence archive's embedded inventory matches
the selected inventory. They rescan the original build/source/tool SBOMs, not
today's checkout, and independently rescan the published runtime digests. This
also detects regressions in software used only during construction.

## Sovereignty, offline use, and source obligations

Using public services is not complete sovereignty. A sovereign installation
must control retention, network egress, access policy, rebuild capability, and
the legal ability to redistribute its entire stack. Mirror:

- Git history, pinned Actions and tool release assets/checksums.
- Debian signed snapshot metadata, `.deb` files, and corresponding source
  packages (`.dsc`, original tarballs, Debian patches) identified by the inventory.
- npm tarballs, crates (including vendored licenses), Python wheels/sdists, and
  compiler/build images including their sources and license obligations.
- OCI images **and** attached signatures/attestations, signed inventory/evidence
  bundles, trusted-root/TUF metadata, and fresh advisory database snapshots.

Keep the original content digests while mirroring. Source archives must remain
available for the required license retention period; a URL alone is not always
sufficient fulfillment of copyleft obligations. Review SPDX expressions, NOTICE
requirements and Debian copyright files. The generated unresolved evidence report
is a work queue for legal/source-completeness review, not permission to redistribute.

Offline signature verification needs the appropriate bundled transparency evidence
and authenticated trust roots; do not use `--insecure-ignore-tlog` or skip identity
checks. Test your selected Cosign version against exported artifacts before
disconnecting. An internally operated Fulcio/Rekor/TUF service or approved signing
PKI changes the trust policy: configure and review both signers and verifiers,
including certificate identity constraints. Simply mirroring GHCR does not replace
GitHub OIDC or remove public-signing metadata disclosure.

Container images are not a full system boundary. Apply host patching, seccomp,
Pod Security Admission, namespace isolation, network policy, and egress restrictions
appropriate to the target cluster. The sample servers have no authentication or
TLS termination and should sit behind an independently configured TLS ingress.

## Research references

Authoritative references consulted for the design (version pins are in code,
not copied from floating documentation examples):

- [Debian mmdebstrap manual](https://manpages.debian.org/trixie/mmdebstrap/mmdebstrap.1.en.html)
- [Debian snapshot archive](https://snapshot.debian.org/)
- [Debian reproducible builds](https://wiki.debian.org/ReproducibleBuilds)
- [GitHub Actions secure use](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [Sigstore signature verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [Sigstore keyless signing](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)
- [Anchore Syft/Grype documentation](https://oss.anchore.com/docs/)
- [SLSA v1 provenance](https://slsa.dev/spec/v1.1/provenance)
- [SPDX specification](https://spdx.github.io/spdx-spec/v2.3/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Compose services](https://docs.docker.com/reference/compose-file/services/)

Component READMEs explain the implementation-specific choices and remaining gaps.
