# Evidence, tool pins, and their limits

## Install the reviewed tools

```sh
./tools/install.sh
export PATH="$PWD/.tools/bin:$PATH"
# GitHub Actions: affects subsequent steps, not this shell
printf '%s\n' "$PWD/.tools/bin" >> "$GITHUB_PATH"
```

Linux/amd64 only. Python 3.11+, Bash, curl with trusted CA roots, tar support in
Python, and Git are bootstrap/runner trust inputs. The installer writes only
`.tools/bin`, `.tools/cache`, and Docker CLI plugin symlinks under
`${DOCKER_CONFIG:-$HOME/.docker}/cli-plugins`; it never overwrites `/usr/bin`.
Orb setup should put the absolute `.tools/bin` path in its login shell PATH and
explicitly pass that PATH to its supervised Docker daemon. No floating installer
scripts are executed. Do not add a second system-wide security-tool installer.

`tools/lock.json` pins versioned URLs, archive SHA-256, and extracted binary
SHA-256. Installed bytes and any existing cache archives are verified every run.
A valid warm installation makes no network request, even if its download cache
is absent. Corrupt cached bytes fail closed; a modified binary can be restored
from a verified cache. Only explicitly named regular archive members are read;
archives are not extracted into the host filesystem. Docker Engine's eight
binaries reuse one content-addressed archive. Existing unrelated Docker plugin
files are not overwritten. Migration retires only recognized old pinned scanner
binaries after verifying their identity; unrelated or modified files are not
silently removed. The same reviewed lockfile governs source setup, installer and
updater; neither CI nor installation runs the updater automatically.

Pins were resolved from the actual stable releases on 2026-09-10: Cosign 3.1.3,
Trivy 0.74.0, Helm 4.3.0, actionlint 1.7.12, buildx 0.37.0,
Compose 5.5.1, and Docker Engine 29.8.0: 14 pinned binaries in total.
Trivy is the official upstream binary, not a custom build. The first six artifacts were
checked against their release checksum assets (Helm uses get.helm.sh). Binary
hashes were then computed from those verified archives. This is checksum
verification, **not verification of upstream release signatures**: initial trust
includes HTTPS, GitHub/release publishers, and the reviewed lockfile.

Docker's official static distribution does not publish the corresponding
`.sha256` sidecar; its archive and individual binary hashes are measured from the
official HTTPS download, explicitly marked in the lockfile. They protect future
installs against byte changes but do not supply an independent initial publisher
authentication claim. System kernel, iptables, cgroups, host runtime and bootstrap
packages remain runner trust inputs, even with Docker userspace binaries pinned.
Docker daemon/socket access is effectively host-root authority: run only trusted
builds on isolated disposable runners, never expose an unauthenticated daemon,
and do not share a privileged daemon with untrusted tenants. Image scanning does
not start application processes, but still trusts the daemon's image/export view.

Maintainers can run `python3 tools/refresh-lock.py` (requires authenticated `gh`)
to regenerate pins. Review every version/URL/hash change and rerun cold and warm
installation tests. This updater is **not** called by the installer or CI.

## Independent collection and fail-closed scanning

```sh
scripts/evidence.sh docker:sovereign-stack/rust:local evidence/rust
# Plain local references and registry references are also accepted.
scripts/evidence.sh ghcr.io/OWNER/IMAGE@sha256:DIGEST evidence/published
# Historical images: do not incorrectly attach today's source checkout.
SOURCE_DIR='' scripts/evidence.sh ghcr.io/OWNER/IMAGE@sha256:DIGEST evidence/historical
# Rescan Trivy CycloneDX obtained from a verified signed evidence archive.
# Keep its corresponding sbom.trivy.json alongside it for package-preservation checks.
scripts/scan-sbom.sh original/sbom.cyclonedx.json rescans/original
```

`OUTPUT_DIR` for `evidence.sh` must be empty; existing reports are never mixed
with a different run. `SOURCE_DIR` defaults to the repository root, can select
another checkout, or explicitly be empty to omit source evidence. The script
requires installed tools and a working Docker daemon. A missing local image is
pulled for linux/amd64. A local tag is frozen to its image ID before cataloging
and exporting. For publication, use the registry manifest digest, not the local
image configuration ID; both are SHA-256 identifiers but describe different bytes.

Each output contains:

| File | Meaning |
| --- | --- |
| `image-inspect.json` | Docker image/config identity and original references |
| `sbom.trivy.json` | Scope-specific native Trivy inventory and package metadata |
| `sbom.spdx.json` | SPDX JSON, the predicate file for the image SBOM attestation |
| `sbom.cyclonedx.json` | Trivy-generated CycloneDX JSON used by `trivy sbom` |
| `sbom.complete.trivy.json` | Raw native whole-image inventory, including retained build evidence |
| `build-provenance/` | Separate SBOMs, licenses and scan reports for retained build-tool metadata; not installed runtime software |
| `licenses.json`, `licenses.csv` | Per-package identifiers, discovered texts, attribution references, unresolved reasons |
| `THIRD_PARTY_NOTICES` | Package index, deduplicated discovered text with locations, unresolved section |
| `unresolved.json` | Machine-readable evidence gaps; not a fabricated license conclusion |
| `build-metadata.json` | Original retained image build locks, Cargo metadata/manifests, package TSVs and tool-version files with hashes |
| `trivy.json`, `trivy.log` | Full scanner result and diagnostics, including database failures |
| `trivy-policy.yaml`, `scan-status.json` | Exact policy and fail-closed result |
| `db-metadata.json` | Retained vulnerability database metadata for freshness validation and audit |
| `source/` | Separate repository inventory, same SBOM/license/Trivy outputs, plus `lockfiles.json` with source lock contents and hashes |

The initial image collection uses native Trivy over the final merged filesystem,
**not** only the application binary. Debian dpkg
metadata and copyrights remain in the images. `partition-sbom.py` separates only
the repository's reserved build-evidence directories: nginx's retained npm/build-OS
metadata, base bootstrap documentation, and Python build documentation. Packages
discovered there belong to `build-provenance/`, not the top-level runtime SBOM.
Both inventories are scanned and retained; the original whole-image Trivy document
is also retained for audit. Primary package records determine membership when
available; a shared supporting copyright file does not prove runtime installation.
A package with primary records in both scopes appears in both inventories with
the appropriate locations. Unknown locations stay in runtime. No package version,
advisory, or severity controls this partition.
License text collection still preserves all image attribution texts, including
unassociated build notices, in addition to the per-inventory package indexes.

Retained Rust Cargo.lock dependencies are kept as conservative runtime candidates
so static-link dependency metadata is not silently ignored. These declarations
are not proof that every target-specific or build-only crate was linked. Source
inventory uses Trivy filesystem analysis (including lockfile declarations),
independently of runtime. An explicit pip analyzer pattern covers this repository's
`requirements.lock` filename. Installed tool binaries use `trivy rootfs`, not `fs`:
source mode omits compiled Go executables. The separate tool lockfile preserves
all 14 executable hashes, including binaries for which Trivy has no package analyzer.
Tool caches, Git internals, evidence/build/release/.amp/target directories, and
the current output directory are excluded from source scanning to avoid
recataloging generated output. Compiler and build-stage OS
packages require scanning the separately tagged **builder images** as well:
source lockfiles alone cannot reveal all packages installed in a multi-stage
builder. The parent build/scan pipeline collects runtime and builder inventories.

All 25 runtime, retained build-provenance, builder, source and tooling inventories
use `trivy sbom` on their own Trivy-generated CycloneDX documents and the same
`scan-sbom.sh` policy: only **HIGH or CRITICAL** findings with a nonempty
`FixedVersion` block CI/publication/nightly audits.
The shared inventory validator requires Trivy root metadata and valid package
identifiers. CycloneDX library PURLs must exactly match the retained native
inventory and the rescan's package list. Debian OS release and source-package
name/version/epoch/release must also survive conversion and rescanning: retaining
binary package names alone is insufficient for Debian advisory lookups.
Missing or silently skipped packages fail
closed, while genuinely empty provenance scopes remain valid. Keep both native
and CycloneDX inputs together; a producer label alone does not prove completeness.
This means an advisory records an available dependency fix, not necessarily that
a new consuming tool binary has been released. Lower-severity and unfixed findings
remain visible but do not block. `trivy.json` retains **all** findings;
no ignore-unfixed or severity filter is applied to report generation.
`scan-status.json` records the versioned policy, total counts and `blockingMatches`.
No scanner ignore or VEX suppression is allowed. Approved, expiring tool-only
dispositions in `tools/cve-overrides.json` are applied after scanning, bound to
the recorded executable hash, release, platform and dependency version.
`scan-status.json` retains original blockers, excepted matches and reasons, and
remaining blockers. Release validation recomputes both the gate and expiry
from the full report. Trivy's default distro-aware severity selection uses vendor
severity, then fallback when needed; it does not force NVD severity. Scanner and
database differences mean neither package counts nor CVE counts are promised to
match another scanner. Explicit configuration and controlled scanner environment
prevent user settings from weakening this policy.

The [tool CVE applicability review](tool-cve-assessment.md) records root causes,
per-tool dispositions and evidence gaps for the current blocking findings. Only
the explicitly approved platform-proven exception is active; provisional
non-applicability candidates remain blocking. Historical inventories without
recorded tool identities cannot receive an override based on today's binaries.

Each scan validates database metadata: maximum age is 120 hours, timestamps more
than ten minutes in the future are rejected, and `NextUpdate` must be valid and not overdue after refresh. Trivy
refreshes its OCI-distributed database when due according to its metadata; a fresh
database need not be downloaded again for every inventory. Failed refresh,
missing/corrupt or stale database, invalid metadata, malformed report, or scanner
nonzero status fails the gate. Preserve `db-metadata.json` with the report for audit.
No security result or vulnerability database is stored in GitHub Actions caches.
Fresh advisory data is deliberately mutable, not frozen to manufacture a pass.
Every collected scope is scanned even if another scope fails. Notices/SBOMs are
written **before** vulnerability scanning, and failed runs retain evidence.

For nightly historical audits, verify the signed inventory/archive and its
digest binding before using it; extract only expected regular members, not
arbitrary archive paths. Scan the original retained build-provenance, builder and
source Trivy CycloneDX documents with `scan-sbom.sh`; separately rescan each immutable published image
with `SOURCE_DIR=''`. Never label the current checkout as a historical build's
source. Signed inventory enumeration must fail on missing or invalid evidence,
not silently skip an image. A passing gate means only **no fixable High/Critical
matches in the examined inventories and database at that time**. It does not mean
zero CVEs, absence of unfixed severe vulnerabilities, or absence of vulnerabilities.

No historical release has been published yet. Signed archives going forward carry
Trivy-generated CycloneDX. Legacy Syft-native archives are unsupported and fail
closed: any future import requires an explicit reviewed migration, preserving the
original signed bytes and recording newly generated evidence separately. Do not
rename native JSON or assume arbitrary third-party CycloneDX is equivalent: Trivy
relies on its own CycloneDX properties for accurate rescanning.

## Attribution and license review

`scripts/license-report.py TRIVY_JSON OUTPUT_DIR [--image-tar DOCKER_EXPORT_TAR | --source-dir SOURCE]`
uses native Trivy package/license metadata and reads discovered license,
copyright, COPYING, NOTICE and AUTHORS files from the exported image. It also
includes `/usr/share/common-licenses`. Debian documentation symlinks are resolved
inside the archive, never followed on the host. Oversized (>8 MiB), undecodable,
cyclic, or missing text is explicitly unresolved rather than silently omitted.
Text is indexed by its SHA-256 with all locations/package references; exact
Debian package paths and retained Rust crate-name/version directories supply
additional associations. Python notices are associated only within the package's
exact `.dist-info` directory, including `licenses/`. Unassociated texts remain
present and unresolved.
Source notice collection skips generated directories and the current evidence
output; it reports file symlinks as unresolved rather than reading outside the tree.

Rust metadata/text lives under `/usr/share/sovereign-stack/rust`, including
Cargo.lock, Cargo.toml, cargo-metadata.json and `dependencies/NAME-VERSION/`.
NPM build metadata is retained under `/usr/share/sovereign-stack/nginx`; Python
build locks/metadata under `/usr/share/sovereign-stack/python`, with installed
`.dist-info` license texts in the runtime. Unknown/malformed license identifiers,
missing text, and unresolved associations are reported as gaps, never replaced
with a convenient permissive license. The native records are preserved even
where SPDX/CycloneDX conversions represent less detail.

This is an evidence aid, **not legal advice, an SPDX legal conclusion, or a
license-compliance certification**. Identifiers alone do not discharge notice,
copyright, corresponding-source, source-offer, copyleft/relinking, modification,
trademark or patent obligations. Text detection and package association are
incomplete; custom licenses and dual-license choices need review. A package with
discovered text is not marked legally compliant. Before redistribution, review
`unresolved.json`, obtain required original source/texts, verify package versions
and linkage, and maintain human-reviewed obligations separately.

No scanner promises “every bit of software.” Stripped/static binaries without
metadata, handwritten/vendored code, generated/minified bundles, compiler runtime
code, packages absent from registries, firmware, host kernel, dynamically fetched
runtime content and hidden build inputs can evade cataloging. Retained lockfiles
and builder scans reduce these gaps but neither prove complete provenance nor
bit-for-bit reproducibility. Restrict runtime network downloads and keep source,
build logs, manifests, original package sources and license material alongside
release evidence as appropriate.

## Build type v1

`scripts/provenance.py IMAGE_DIGEST OUTPUT_FILE [--materials FILE] [--build-metadata FILE]` emits only the
SLSA v1 **predicate**, not an in-toto statement/envelope. It requires
`GITHUB_REPOSITORY`, `GITHUB_SHA`, `GITHUB_WORKFLOW_REF`, `GITHUB_WORKFLOW_SHA`,
`GITHUB_RUN_ID`, and `GITHUB_RUN_ATTEMPT`; `GITHUB_SERVER_URL` defaults to GitHub.
Missing CI identity fails rather than inventing it for a local run. `IMAGE_DIGEST`
is `sha256:<64 hex>` or a complete immutable reference. Cosign supplies the
authoritative subject when attesting; the predicate extension repeats the digest
for audit and must agree with that subject.

The read-only build job retains these environment fields in `evidence/build.json`.
Publishing passes that file via `--build-metadata`: a publish-only retry continues
to identify the original build attempt rather than claiming the retry rebuilt the
images. Before any publication, `validate-release.py` checks the originating
repository, commits, workflow, run and attempt; every expected clean runtime,
builder, source and tool gate; and the loaded runtime image IDs against both
Docker inspection and Trivy metadata. It also checks Trivy's SPDX `ImageID`
annotation and CycloneDX `aquasecurity:trivy:ImageID` property.
Only the validated immutable image IDs are tagged/pushed. A mismatched image,
swapped SBOM, missing report or failed scan aborts before registry writes.

External parameters are `repository` (HTTPS repository URL) and `workflow`
(GitHub workflow reference). To reproduce the procedure, check out the recorded
source Git commit, inspect the recorded workflow at its own commit, and execute
that workflow's checked-in build scripts with its pinned build inputs. Parameters
do not claim hermeticity; recipe, flags and dependency choices live in the source
tree. Resolved dependencies include the source and workflow commits, SHA-256 of
tracked inputs beneath base-container/nginx/rust/python and tools/lock.json, and
literal digest-pinned builder image references found there. Caller `--materials`
is a JSON array of resource descriptors with `uri` and a nonempty `digest` map;
use it for the actual published base digest and other dynamically resolved inputs.
Recording the Git tree recursively commits the checked-in recipe, but explicit
material entries make investigation easier. These are declared/observed inputs,
not an independently intercepted complete trace of every network fetch.

Example extra material (replace placeholder digest):

```json
[{"uri":"oci://ghcr.io/OWNER/base@sha256:DIGEST","digest":{"sha256":"DIGEST"}}]
```

### Self-reported GitHub Actions builder

The builder ID resolves to this section. It denotes this repository's
tenant-controlled workflow running on GitHub Actions and trusts repository
maintainers, workflow code, GitHub's control plane, runner administrators,
bootstrap software, host kernel, Docker daemon and upstream distribution systems.
All predicate fields are generated by the tenant's script, not an independent
trusted builder. **No SLSA level or certification is claimed.** A signature proves
the selected identity signed those statements, not their truth or completeness.
Started/finished timestamps are omitted because this script does not observe the
actual build boundaries; it does not relabel evidence-generation time as build time.

## Cosign attestation and signed inventory contracts

```sh
cosign attest --yes --type spdxjson --predicate evidence/rust/sbom.spdx.json "$IMAGE_AT_DIGEST"
cosign attest --yes --type slsaprovenance1 --predicate provenance.json "$IMAGE_AT_DIGEST"
cosign sign-blob --yes --bundle inventory.sigstore.json inventory.json
cosign verify-blob --bundle inventory.sigstore.json \
  --certificate-identity 'https://github.com/mattcurf/sovereign-stack/.github/workflows/publish.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' inventory.json
```

**Important version-specific correction:** Cosign 3.1.3's `--type slsaprovenance`
alias is still SLSA **v0.2**. Use `slsaprovenance1` (or the exact URI
`https://slsa.dev/provenance/v1`) for this v1 predicate, including verification.
`spdxjson` embeds the full SPDX document; this intentionally accepts the larger
attestation size. Do not use a path-only SBOM predicate when the workflow expects
the actual SPDX document. Current Cosign supports `sign-blob --bundle` and
`verify-blob --bundle`; keep each release's exact inventory bytes and bundle,
with an equally signed evidence archive or cryptographic archive digest binding.
Do not reserialize JSON between signing and verification. Keyless signing needs
trusted GitHub OIDC permissions; it is not available merely because a local CLI
test passes. Verification must enforce exact issuer, workflow identity, subject
digest, expected predicate type, and expected source/material policy.

## Authoritative references

- [Trivy SBOM scanning](https://trivy.dev/latest/docs/target/sbom/): Trivy-generated CycloneDX retains properties needed for accurate rescanning.
- [Trivy vulnerability severity selection](https://trivy.dev/latest/docs/scanner/vulnerability/): vendor severity and fallback rather than forced NVD severity.
- [Trivy database configuration](https://trivy.dev/latest/docs/configuration/db/) and [license scanning](https://trivy.dev/latest/docs/scanner/license/).
- [SPDX 2.3 package information](https://spdx.github.io/spdx-spec/v2.3/package-information/): distinguish declared/concluded licenses, `NOASSERTION`, copyright and attribution fields.
- [SLSA provenance specification](https://slsa.dev/spec/v1.2/provenance): v1 predicate schema, builder trust boundary and best-effort materials.
- [Sigstore signing other artifact types](https://docs.sigstore.dev/cosign/signing/other_types/) and [verification](https://docs.sigstore.dev/cosign/verifying/verify/).
- [Cosign 3.1.3 predicate aliases](https://github.com/sigstore/cosign/blob/v3.1.3/cmd/cosign/cli/options/predicate.go): the versioned SLSA alias distinction matters.
- [Docker static binaries](https://docs.docker.com/engine/install/binaries/) and [official static archive directory](https://download.docker.com/linux/static/stable/x86_64/).
