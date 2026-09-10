# Debian trixie base

Build all components from the repository root with `scripts/build-images.sh`.
The base is `sovereign-stack/base-container:local`; it has no HTTP service.
Initial support is **linux/amd64**, not a tested multi-architecture image.

## Construction and trust

The digest-pinned official Debian image supplies apt, dpkg, the Debian archive
keyring, and **mmdebstrap 1.5.7-1+deb13u1**. Standard mmdebstrap `minbase` creates
a new trixie rootfs; the final `FROM scratch` copies that rootfs, not the builder.
The documented `--skip=chroot/mount` avoids mounting proc/sys/dev during this
particular package set's maintainer scripts. Ordinary Docker build works: no
privileged builder or host bind mount is required. Future added packages may
require mounts and must be tested, rather than disabling maintainer scripts.

`sources.list` pins actual reachable archive snapshots checked on 2026-09-10:

* Debian: **20260910T082439Z**
* Debian security: **20260909T204253Z**

Both bootstrap installs and the generated rootfs use these sources exclusively.
Direct build packages have explicit versions; all transitive versions are fixed
by the immutable signed snapshot. `signed-by` confines authentication to the
Debian archive keyring. HTTP transport is intentionally usable before TLS is
installed: apt verifies signed Release metadata and package hash chains. HTTP
does not hide traffic or prevent denial of service. Only expiry checking is
disabled for historical snapshots; signature/hash verification is **not**
disabled. Do not introduce `trusted=yes` or `--allow-unauthenticated`.

## Practical size and security tradeoff

This is a practical Debian **minbase**, not a theoretical minimum or distroless
image. It retains essential tools, apt/dpkg, libc, TLS certificates, package
identity (`/var/lib/dpkg`), `/usr/share/doc` copyright and common license texts.
Keeping the package manager supports normal authenticated Debian application
installs without fragile hand-copied shared libraries or invented package
databases. It costs size and potential CVE exposure. No compiler is installed.
Setuid/setgid file bits are removed. `USER 65532:65532` is the default, backed
by an `app` passwd/group entry with nologin shell. Apps use port 8080.

Runtime controls belong to the loader: read-only rootfs, a small writable `/tmp`,
all capabilities dropped, no-new-privileges, PID/memory/CPU limits. The image
alone cannot enforce these controls. `scripts/smoke-images.sh` exercises them.

## Evidence, repeatability and updates

`/usr/share/sovereign-stack/base-container/` retains snapshot source declarations,
runtime/bootstrap package TSVs and bootstrap copyright documents. TSVs are
human-readable evidence, **not** a substitute for scanner package catalogs.
`scripts/build-images.sh` also tags the full `bootstrap` stage as
`sovereign-stack/base-container-builder:local` for independent SBOMs/scans.

`SOURCE_DATE_EPOCH=1789027200` fixes the reference time (2026-09-10 08:00 UTC);
mmdebstrap removes volatile metadata and the script clears logs/host identity.
This does **not** establish bit-identical OCI output: builder versions, Docker
export timestamps, filesystem metadata, package scripts and Python bytecode can
still vary. Warm builds reuse ordinary Docker stage layers, including resolved
apt/npm/Cargo inputs; no additional cache service is required. Keep the Docker
data directory across orb resumes. A warm rebuild of all eight tags took 21s in
the verification orb; cold network/download costs are not covered by that claim.
For nested Docker without working NAT only, use `BUILD_NETWORK=host` and
`SMOKE_NETWORK=host`; default smoke tests use bridge networking with random
loopback-only published ports. Host mode is a test-environment concession,
not the deployment policy.

Update snapshots, direct Debian versions and builder digests together, rebuild
without stale caches, regenerate package evidence, and run the strict known-CVE
gate. Pinned inputs do not auto-update security fixes. An unfixed CVE is a release
blocker, not a reason to remove package metadata or ignore the finding. No claim
of zero CVEs is made here. Source redistribution obligations require keeping
corresponding Debian source packages available; copyright text alone is not
complete compliance. Mirror snapshot metadata/packages and pinned builders for
offline use without bypassing signature checks.

## Authoritative references

* [mmdebstrap trixie manual: variants, modes, hooks, reproducibility](https://manpages.debian.org/trixie/mmdebstrap/mmdebstrap.1.en.html)
* [Debian snapshot semantics and Valid-Until](https://snapshot.debian.org/)
* [Debian repository format and signed metadata](https://wiki.debian.org/DebianRepository/Format)
* [Docker digest pins, multi-stage builds and USER](https://docs.docker.com/build/building/best-practices/)
