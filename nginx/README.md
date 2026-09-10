# npm-built hello world, served by nginx

The digest-pinned Node **24.21.0**, npm **11.19.0** build stage runs `npm ci`
against `package-lock.json`, then `npm run build`. The build script copies the
HTML asset using Node's standard filesystem API: no third-party frontend
dependencies are needed for a static hello world. The empty dependency lock is
intentional, not an unpinned `npm install`. npm's own dependencies are still
build inputs, provided by the pinned builder digest.

The final image derives from `ARG BASE_IMAGE` (default
`sovereign-stack/base-container:local`). Debian nginx **1.26.3-3+deb13u7** and
its dependencies are installed normally from the inherited signed snapshots;
dpkg identity/copyright is preserved. Node/npm executables are not copied into
the runtime. Debian's nginx package dependency set costs more space than copying
only the binary; preserving normal package identity and tested shared-library
resolution is preferable here to fragile minimalism.

nginx listens on **8080**, runs directly as **65532:65532**, emits logs to
stdout/stderr, and uses `/tmp` for its PID and temporary files. No root master,
privileged port, writable `/var`, or chown-at-start entrypoint is needed. `SIGQUIT`
is the graceful stop signal. The loaders must supply read-only rootfs, tmpfs,
dropped capabilities and resource limits; `scripts/smoke-images.sh` verifies the
same application contract locally. `/` serves hello world; unknown files return
404. This deliberately plain page is a container demonstration, not a UI framework.

Evidence in `/usr/share/sovereign-stack/nginx/` includes application manifests,
Node/npm versions, Node's combined LICENSE, npm dependency package manifests and
license/notice texts, plus builder Debian package metadata/docs. npm CLI source
is not copied. The full `static` stage is also tagged
`sovereign-stack/nginx-builder:local` for independent build-tool SBOM/scanning.
License discovery is best-effort evidence, not a blanket license-compliance claim.
See [the base README](../base-container/README.md) for pin update and CVE policy.

References:

* [npm ci: frozen lockfiles and ignore-scripts](https://docs.npmjs.com/cli/v11/commands/npm-ci)
* [nginx core directives: pid, user, daemon and workers](https://nginx.org/en/docs/ngx_core_module.html)
* [nginx HTTP core: root, listen and temporary paths](https://nginx.org/en/docs/http/ngx_http_core_module.html)
* [Docker multi-stage build and digest pin guidance](https://docs.docker.com/build/building/best-practices/)
