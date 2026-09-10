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
files are not overwritten.

Pins were resolved from the actual stable releases on 2026-09-10: Cosign 3.1.3,
Syft 1.51.1, Grype 0.118.0, Helm 4.3.0, actionlint 1.7.12, buildx 0.37.0,
Compose 5.5.1, and Docker Engine 29.8.0. The first seven downloaded artifacts were
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

## Independent collection and strict scanning

```sh
scripts/evidence.sh docker:sovereign-stack/rust:local evidence/rust
# Plain local references and registry references are also accepted.
scripts/evidence.sh ghcr.io/OWNER/IMAGE@sha256:DIGEST evidence/published
# Historical images: do not incorrectly attach today's source checkout.
SOURCE_DIR='' scripts/evidence.sh ghcr.io/OWNER/IMAGE@sha256:DIGEST evidence/historical
# Rescan an original Syft document obtained from a verified signed evidence archive.
scripts/scan-sbom.sh original/sbom.syft.json rescans/original
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
| `sbom.syft.json` | Native Syft inventory and rich package metadata |
| `sbom.spdx.json` | SPDX JSON, the predicate file for the image SBOM attestation |
| `sbom.cyclonedx.json` | CycloneDX JSON representation |
| `licenses.json`, `licenses.csv` | Per-package identifiers, discovered texts, attribution references, unresolved reasons |
| `THIRD_PARTY_NOTICES` | Package index, deduplicated discovered text with locations, unresolved section |
| `unresolved.json` | Machine-readable evidence gaps; not a fabricated license conclusion |
| `build-metadata.json` | Original retained image build locks, Cargo metadata/manifests, package TSVs and tool-version files with hashes |
| `grype.json`, `grype.log` | Scanner result and diagnostics, including database failures |
| `grype-policy.yaml`, `scan-status.json` | Exact policy and fail-closed result |
| `source/` | Separate repository inventory, same SBOM/license/Grype outputs, plus `lockfiles.json` with source lock contents and hashes |

The image scan uses Syft's installed-software/image catalogers over the final
merged filesystem (`squashed`), **not** only the application binary. Debian dpkg
metadata and copyrights remain in the images. The Rust Cargo.lock cataloger is
explicitly added so retained static-link dependency metadata is not silently
ignored. These declared dependencies are a conservative candidate set, not proof
that every target-specific or build-only crate was linked. Source inventory uses
directory catalogers (including lockfile declarations), independently of runtime.
Tool caches, Git internals, evidence/build/release/.amp/target directories, and
the current output directory are excluded from source scanning to avoid
recataloging generated output. Compiler and build-stage OS
packages require scanning the separately tagged **builder images** as well:
source lockfiles alone cannot reveal all packages installed in a multi-stage
builder. The parent build/scan pipeline collects runtime and builder inventories.

Both runtime and source inventories use the same `scan-sbom.sh` policy: any actual
match fails, including unknown/negligible severity and unfixed findings. Ignored
matches also fail. There are no blanket ignore rules, severity-only gates, VEX
suppression, or `only-fixed` exceptions. User `GRYPE_*` settings are cleared and
an explicit configuration prevents a home-directory config from weakening this
policy. Database hash validation and age validation are enabled; maximum build
age is 120 hours; update checks are required on every scan. Failed download,
failed update check, missing/corrupt database, stale database, malformed report,
or scanner nonzero status fails the gate. Fresh advisory databases are deliberately
mutable inputs; archive the report's database metadata for audit, not a stale DB
to make builds pass. A fresh source scan is attempted even when runtime Grype
fails. Notices/SBOMs are written **before** Grype, and failed runs retain evidence.

For nightly historical audits, verify the signed inventory/archive and its
digest binding before using it; extract only expected regular members, not
arbitrary archive paths. Scan the original runtime, builder and source Syft
documents with `scan-sbom.sh`; separately rescan each immutable published image
with `SOURCE_DIR=''`. Never label the current checkout as a historical build's
source. Signed inventory enumeration must fail on missing or invalid evidence,
not silently skip an image. A zero-match scan means only **no known matches in
the examined inventory and database at that time**, not absence of vulnerabilities.

## Attribution and license review

`scripts/license-report.py SYFT_JSON OUTPUT_DIR [--image-tar DOCKER_EXPORT_TAR]`
uses native Syft license strings/text/locations and reads discovered license,
copyright, COPYING, NOTICE and AUTHORS files from the exported image. It also
includes `/usr/share/common-licenses`. Debian documentation symlinks are resolved
inside the archive, never followed on the host. Oversized (>8 MiB), undecodable,
cyclic, or missing text is explicitly unresolved rather than silently omitted.
Text is indexed by its SHA-256 with all locations/package references; exact
Debian package paths and retained Rust crate-name/version directories supply
additional associations. Unassociated texts remain present and unresolved.

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

`scripts/provenance.py IMAGE_DIGEST OUTPUT_FILE [--materials FILE]` emits only the
SLSA v1 **predicate**, not an in-toto statement/envelope. It requires
`GITHUB_REPOSITORY`, `GITHUB_SHA`, `GITHUB_WORKFLOW_REF`, `GITHUB_WORKFLOW_SHA`,
`GITHUB_RUN_ID`, and `GITHUB_RUN_ATTEMPT`; `GITHUB_SERVER_URL` defaults to GitHub.
Missing CI identity fails rather than inventing it for a local run. `IMAGE_DIGEST`
is `sha256:<64 hex>` or a complete immutable reference. Cosign supplies the
authoritative subject when attesting; the predicate extension repeats the digest
for audit and must agree with that subject.

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

- [Syft SBOM documentation](https://oss.anchore.com/docs/) and [cataloger selection](https://oss.anchore.com/docs/sbom/generation/).
- [Syft 1.51.1 native license model](https://github.com/anchore/syft/blob/v1.51.1/syft/format/syftjson/model/package.go): `contents` is plain JSON text, not base64.
- [Grype configuration](https://oss.anchore.com/docs/reference/grype/configuration/): database age/hash/update requirements and suppression defaults; installed `grype config --load=false` confirms the pinned release's settings.
- [SPDX 2.3 package information](https://spdx.github.io/spdx-spec/v2.3/package-information/): distinguish declared/concluded licenses, `NOASSERTION`, copyright and attribution fields.
- [SLSA provenance specification](https://slsa.dev/spec/v1.2/provenance): v1 predicate schema, builder trust boundary and best-effort materials.
- [Sigstore signing other artifact types](https://docs.sigstore.dev/cosign/signing/other_types/) and [verification](https://docs.sigstore.dev/cosign/verifying/verify/).
- [Cosign 3.1.3 predicate aliases](https://github.com/sigstore/cosign/blob/v3.1.3/cmd/cosign/cli/options/predicate.go): the versioned SLSA alias distinction matters.
- [Docker static binaries](https://docs.docker.com/engine/install/binaries/) and [official static archive directory](https://download.docker.com/linux/static/stable/x86_64/).
