# Verified loaders

Prerequisites: Bash, Python 3, a trusted Cosign installation with `verify` and
`verify-attestation`, and **either** Docker with Compose v2+ **or** Helm 3/4 and an
authorized Kubernetes context. These loaders neither install tools nor require
one deployment engine to run the other. No image digest defaults are supplied.

Obtain the release's inventory JSON after publishing. Its top-level object must
map **exactly** `base-container`, `nginx`, `rust`, and `python` to strings in the
form `ghcr.io/OWNER/REPOSITORY@sha256:DIGEST` (64 lowercase hexadecimal characters).
That notation is descriptive, not a deployable example. Tags, duplicate keys,
additional metadata/trust keys, and other registries are rejected.

```sh
bash deploy/verify-images.sh /path/to/images.json
bash deploy/compose/load.sh /path/to/images.json --render
bash deploy/compose/load.sh /path/to/images.json
# Alternatively, independently:
bash deploy/helm/load.sh /path/to/images.json --render
bash deploy/helm/load.sh /path/to/images.json
```

`--render` still verifies real signatures and both attestation types; it never
starts workloads. Compose prints `docker compose config`; Helm prints
`helm template`. Normal mode starts Compose project `sovereign-stack`, or
upgrades/installs Helm release `sovereign-stack` in namespace `sovereign-stack`.
There is deliberately no pass-through for arbitrary engine flags/image overrides.
Each run reads the input once, stores a private snapshot, verifies every entry,
and uses the same parsed values for rendering/deployment. Temporary files are
cleaned on normal exit and verification failure. Host administrator/same-user
process compromise is outside this boundary.

All four images, including the base image (normally non-running), require a signature,
SPDX JSON attestation (`--type spdxjson`), and SLSA v1 provenance attestation
(`--type slsaprovenance1`, predicate `https://slsa.dev/provenance/v1`). The
unversioned `slsaprovenance` alias selects v0.2 in pinned Cosign v3.1.3 and must
not be used for these v1 releases. Any parse, registry, signature, signer, attestation,
or tool failure aborts before either engine is invoked. Cosign performs claim
and signature verification; the loader does not use insecure bypass flags.
Trust is exact, not a regex:

- Identity: `https://github.com/mattcurf/sovereign-stack/.github/workflows/publish.yml@refs/heads/main`
- Issuer: `https://token.actions.githubusercontent.com`

Operators may explicitly set `COSIGN_TRUSTED_IDENTITY` and
`COSIGN_TRUSTED_ISSUER` in their trusted execution environment (for example, an
audited fork). Never derive these variables from release inventory or an
untrusted shell file. Protect PATH, the verifier, chart, and loader as trusted code.

## Runtime contract

The initial target is linux/amd64; Compose selects that platform and Kubernetes
selects Linux amd64 nodes. Each application must support UID/GID 65532, a
read-only root filesystem, and listening on internal port 8080. Writable runtime
state must fit `/tmp` (64 MiB).
Both engines drop ALL capabilities, prohibit privilege escalation, and limit
each application to 0.5 CPU and 128 MiB memory. No host mount or daemon socket is
passed to workloads. The operator-side Compose CLI itself needs Docker daemon
access; this does not grant containers access to the daemon.

| Workload | Compose host binding | Kubernetes ClusterIP service → container |
| --- | --- | --- |
| nginx | 127.0.0.1:8081 → 8080 | 8081 → 8080 |
| rust | 127.0.0.1:8082 → 8080 | 8082 → 8080 |
| python | 127.0.0.1:8083 → 8080 | 8083 → 8080 |

Kubernetes uses memory-backed `emptyDir` for `/tmp`, `RuntimeDefault` seccomp,
and disables service-account token mounting. ClusterIP is cluster-internal, not
loopback isolation or a NetworkPolicy. The chart has no ingress, LoadBalancer,
host ports, or node ports. Adjust limits deliberately with workload evidence;
the current interface does not accept arbitrary override files.

## VM-isolated runtime demonstration (Kata Containers)

`deploy/helm/load.sh inventory.json --kata` selects the **administrator-owned**
RuntimeClass `kata` for every application Pod and runs the verified base image
in a short-lived smoke Job. Each Pod contains one container, so the four runtime
images each execute in a separate VM sandbox. Builder stages are not deployed.
Compose does not support this option; passing it fails rather than silently
running without VM isolation. Omitting it preserves the original runtime behavior.

### Prepare a dedicated cluster

Use Linux/amd64 nodes with hardware virtualization and usable `/dev/kvm` (bare
metal or explicitly supported nested virtualization). Install a reviewed/pinned
[Kata Containers release](https://github.com/kata-containers/kata-containers/releases)
and configure the node CRI runtime using the upstream
[Kata deployment instructions](https://github.com/kata-containers/kata-containers/tree/main/tools/packaging/kata-deploy).
This loader does not install a hypervisor, change containerd, or grant node privileges.

The administrator must provision a Kubernetes
[RuntimeClass](https://kubernetes.io/docs/concepts/containers/runtime-class/)
named `kata`, whose `handler` maps to the installed **Kata VM runtime**, not runc.
Handler names vary by installation (for example, `kata-qemu`); do not assume the
class name establishes this mapping. Configure its `scheduling.nodeSelector`
and tolerations to restrict Pods to Kata-capable nodes, and set `overhead.podFixed`
from the installed hypervisor's measured requirements. The existing 128 MiB
container limits do not budget the guest VM's overhead. Confirm compatibility
with the chart's non-root user, read-only filesystem, and RuntimeDefault seccomp.
Registry pull credentials, if needed, must also be provisioned in the namespace.

### Execute and inspect all four images

First verify the release inventory bundle as shown in the root README. Then:

```sh
kubectl get runtimeclass kata -o yaml
./deploy/helm/load.sh inventory.json --kata --render
./deploy/helm/load.sh inventory.json --kata

kubectl -n sovereign-stack get pods \
  -l app.kubernetes.io/instance=sovereign-stack \
  -o custom-columns=NAME:.metadata.name,RUNTIME:.spec.runtimeClassName,NODE:.spec.nodeName,PHASE:.status.phase
kubectl -n sovereign-stack wait --for=condition=complete \
  job/sovereign-stack-base-smoke --timeout=120s
kubectl -n sovereign-stack logs job/sovereign-stack-base-smoke
```

The loader still verifies all twelve image/signature-attestation claims before
invoking Helm. Helm waits for the three application HTTP readiness probes at `/`
on port 8080, then runs and waits for the base smoke hook. Its expected output is
`base-container smoke passed`; it checks UID 65532 and the Debian OS metadata.
The base Job runs again on each Kata install/upgrade, with no retries and a
120-second deadline. A failed hook makes the command fail, but does not roll back
already-running applications. The prior hook is removed before the next run;
save logs before upgrading. Missing RuntimeClass/handler errors are not retried
with the default runtime. Diagnose failures with `kubectl describe pod` and node
runtime logs, not by removing `runtimeClassName` or weakening the security context.

For an interactive HTTP check, run `kubectl -n sovereign-stack port-forward
service/sovereign-stack-nginx 8081:8081` in a separate local terminal, then
`curl --fail http://127.0.0.1:8081/`. Repeat for `sovereign-stack-rust` with
`8082:8082` and `sovereign-stack-python` with `8083:8083`; each must return its
hello-world response.

**RuntimeClass selection is not proof of VM isolation.** On the assigned nodes,
have the administrator correlate each Pod UID / CRI sandbox ID with Kata's shim
and hypervisor/guest instance using the installed runtime's diagnostics. Record
the runtime version, handler configuration, node evidence, Pod specs, readiness,
and base Job logs. A VM boundary is not confidential computing, remote attestation,
or protection from a compromised host/hypervisor. Cluster policy must prevent
untrusted users from changing RuntimeClasses or bypassing the loader.

Cleanup: run `helm uninstall sovereign-stack -n sovereign-stack`, then
`kubectl -n sovereign-stack delete job sovereign-stack-base-smoke --ignore-not-found`.
Helm hook resources are retained for inspection and are not removed by uninstall.
Delete the retained Job explicitly as well when switching back to ordinary mode.

Offline tests cover rendering and verification gates, not VM execution. End-to-end
validation requires this dedicated cluster and real signed release images; ordinary
Docker CI and environments without KVM do not establish Kata runtime compatibility.

## Theory and enforcement boundary

Digest pinning binds execution to immutable content; tags are mutable pointers.
Signatures bind that digest to an authenticated release identity. Attestations
bind signed claims (an SPDX SBOM and SLSA provenance) to the image. Their presence
and signer are checked, **not** SBOM completeness, vulnerability absence, builder
isolation, source revision approval, or a particular SLSA level. Verifying the
base inventory entry does not by itself prove each application was built from
that base; production provenance policy should check build materials too.

The publishing pipeline uses native Trivy inventories, retaining SPDX for the
SBOM attestation and Trivy-generated CycloneDX for vulnerability rescans. It gates
HIGH/CRITICAL findings with nonempty `FixedVersion` and fails closed on scanner,
database or malformed-report errors; other findings remain reported. The loader
does not itself run Trivy or refresh this security decision. Review the signed
release evidence and current audit results; an accepted signature is not a fresh
vulnerability check or a license-compliance certification.

**Helm preflight is not cluster admission control.** A person can bypass this
script, call Helm directly, skip Helm schema validation, or submit another Pod.
Schema validation checks reference shape, not cryptographic trust. The loader
protects only this invocation; it installs no admission controller or policy.

For production, administrators should separately deploy and operate Sigstore
policy-controller (or an equivalent admission system), configure the protected
namespaces, default-deny unmatched images, require the exact issuer/subject,
and require both attestation predicates with content policies. Configure webhook
failure behavior fail-closed, protect policy/namespace changes with RBAC, cover
all relevant workload paths, and test rejected unsigned/wrong-identity images
and controller outages before claiming enforcement. Restrict runtime privilege
with Pod Security Admission as well; it does not replace signature verification.
This repository intentionally does not pretend those cluster policies are installed.

Authoritative references consulted for this implementation:

- [Cosign attestation verification and fail-closed policy reasoning](https://docs.sigstore.dev/cosign/verifying/attestation/)
- [Cosign verify-attestation CLI, predicate types and identity flags](https://github.com/sigstore/cosign/blob/main/doc/cosign_verify-attestation.md)
- [Sigstore policy-controller: namespace opt-in, no-match behavior, keyless identities and attestations](https://docs.sigstore.dev/policy-controller/overview/)
- [Docker Compose services: read_only, security_opt, tmpfs, resource limits and ports](https://docs.docker.com/reference/compose-file/services/)
- [Kubernetes security contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Kubernetes Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [Helm chart schema validation](https://helm.sh/docs/topics/charts/#schema-files)

## Tests

```sh
python3 -m unittest discover -s deploy/tests -v
helm lint deploy/helm/sovereign-stack --strict -f deploy/tests/helm-values.json
helm template test deploy/helm/sovereign-stack -f deploy/tests/helm-values.json
```

`deploy/tests/helm-values.json` contains distinct synthetic digests only for
renderer testing. It is not a release inventory or an application default.

The offline tests substitute recording engines and a signer-aware Cosign fake,
then assert that malformed inventories, wrong identity/issuer, and each failed
verification stage for each image prevent **all** deployment calls. They also
mutate the original inventory mid-verification to test snapshot isolation.
Synthetic test digests cannot be deployed by the normal verifier. These tests
exercise control flow, not real cryptography or registry availability.

When installed, tests additionally run actual `docker compose config`, `helm lint
--strict`, and `helm template`, check positive output, and ensure invalid chart
digests fail schema validation. Missing renderers are explicitly skipped; no
unpinned binary is installed. End-to-end signature checks and workload smoke
tests require real published/signed images plus a Docker daemon or cluster.
