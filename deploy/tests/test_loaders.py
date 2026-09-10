"""Offline gate tests; real renderer checks run when the corresponding CLI exists."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

DEPLOY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEPLOY))
from load import compose_config

IDENTITY = "https://github.com/mattcurf/sovereign-stack/.github/workflows/publish.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
# These synthetic digests exist only in tests, never in deployable defaults.
IMAGES = json.loads((DEPLOY / "tests" / "helm-values.json").read_text())["images"]
MOCK = '''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
tool = pathlib.Path(sys.argv[0]).name
with open(os.environ['CALLS'], 'a') as log:
    log.write(json.dumps([tool, *args]) + '\\n')
if tool == 'cosign':
    if os.environ.get('MUTATE'):
        pathlib.Path(os.environ['MUTATE']).write_text('{}')
    identity = args[args.index('--certificate-identity') + 1]
    issuer = args[args.index('--certificate-oidc-issuer') + 1]
    if identity != os.environ['SIGNER'] or issuer != os.environ['ISSUER']:
        sys.exit(1)
    stage = args[args.index('--type') + 1] if '--type' in args else 'signature'
    if stage == os.environ.get('FAIL_STAGE') and args[-1] == os.environ.get('FAIL_IMAGE'):
        sys.exit(1)
else:
    flag = '-f' if tool == 'docker' else '--values'
    pathlib.Path(os.environ['CONFIG']).write_text(pathlib.Path(args[args.index(flag) + 1]).read_text())
'''


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inventory = self.root / "images.json"
        self.inventory.write_text(json.dumps(IMAGES))
        self.calls = self.root / "calls"
        self.config = self.root / "config"
        for name in ("cosign", "docker", "helm"):
            script = self.root / name
            script.write_text(MOCK)
            script.chmod(0o755)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("COSIGN_TRUSTED_")}
        self.env.update(PATH=str(self.root) + os.pathsep + os.environ["PATH"],
                        CALLS=str(self.calls), CONFIG=str(self.config), SIGNER=IDENTITY, ISSUER=ISSUER)

    def run_loader(self, engine, *flags, **env):
        self.calls.write_text("")
        result = subprocess.run(["bash", str(DEPLOY / engine / "load.sh"), str(self.inventory), *flags],
                                env={**self.env, **env}, capture_output=True, text=True)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        return result, calls

    def assert_blocked(self, engine, **env):
        result, calls = self.run_loader(engine, **env)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(any(call[0] in ("docker", "helm") for call in calls), calls)
        return calls

    def test_malformed_inventories_never_deploy(self):
        invalid = [[], {}, {**IMAGES, "extra": IMAGES["nginx"]},
                   {key: val for key, val in IMAGES.items() if key != "base-container"}]
        for ref in ("nginx:latest", "ghcr.io/test/nginx:latest", IMAGES["nginx"][:-1],
                    IMAGES["nginx"] + "0", IMAGES["nginx"] + "\n", None,
                    IMAGES["nginx"].replace("ghcr.io", "evil.example"),
                    IMAGES["nginx"].replace("sha256:", "sha512:")):
            invalid.append({**IMAGES, "nginx": ref})
        for engine in ("compose", "helm"):
            for inventory in invalid:
                with self.subTest(engine=engine, inventory=inventory):
                    self.inventory.write_text(json.dumps(inventory))
                    self.assertEqual(self.assert_blocked(engine), [])
            for raw in ('{"nginx": "a", "nginx": "b"}', '{broken'):
                self.inventory.write_text(raw)
                self.assertEqual(self.assert_blocked(engine), [])

    def test_each_verification_failure_blocks_every_deploy(self):
        for engine in ("compose", "helm"):
            for image in IMAGES.values():
                for stage in ("signature", "spdxjson", "slsaprovenance1"):
                    with self.subTest(engine=engine, image=image, stage=stage):
                        self.assert_blocked(engine, FAIL_IMAGE=image, FAIL_STAGE=stage)

    def test_wrong_signer_and_issuer_block(self):
        for engine in ("compose", "helm"):
            self.assert_blocked(engine, SIGNER="https://github.com/attacker/workflow")
            self.assert_blocked(engine, ISSUER="https://attacker.example")

    def test_positive_all_verified_before_exact_config(self):
        for engine in ("compose", "helm"):
            result, calls = self.run_loader(engine)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(calls), 13)
            self.assertTrue(all(call[0] == "cosign" for call in calls[:12]))
            for index, image in enumerate(IMAGES.values()):
                signature, sbom, provenance = calls[index * 3:index * 3 + 3]
                self.assertEqual(signature[1], "verify")
                self.assertEqual(sbom[1:4], ["verify-attestation", "--type", "spdxjson"])
                self.assertEqual(provenance[1:4], ["verify-attestation", "--type", "slsaprovenance1"])
                for call in (signature, sbom, provenance):
                    self.assertEqual(call[-1], image)
                    self.assertIn(IDENTITY, call)
                    self.assertIn(ISSUER, call)
                    self.assertNotIn("--certificate-identity-regexp", call)
            config = json.loads(self.config.read_text())
            if engine == "helm":
                self.assertEqual(config, {"images": IMAGES})
                self.assertEqual(calls[-1][1:3], ["upgrade", "--install"])
            else:
                self.assertEqual(config, compose_config(IMAGES))
                self.assertIn("up", calls[-1])
                self.assert_compose_hardening(config)

    def assert_compose_hardening(self, config):
        self.assertEqual(set(config["services"]), {"nginx", "rust", "python"})
        for i, name in enumerate(("nginx", "rust", "python"), 8081):
            service = config["services"][name]
            self.assertEqual(service["image"], IMAGES[name])
            self.assertEqual(service["user"], "65532:65532")
            self.assertTrue(service["read_only"])
            self.assertEqual(service["cap_drop"], ["ALL"])
            self.assertEqual(service["security_opt"], ["no-new-privileges:true"])
            self.assertEqual(service["ports"], [f"127.0.0.1:{i}:8080"])
            self.assertIn("/tmp:", service["tmpfs"][0])
            self.assertEqual(service["cpus"], 0.5)
            self.assertEqual(service["mem_limit"], "128m")
            self.assertNotIn("volumes", service)

    def test_inventory_replacement_during_verification_cannot_change_deployment(self):
        for engine in ("compose", "helm"):
            self.inventory.write_text(json.dumps(IMAGES))
            result, calls = self.run_loader(engine, MUTATE=str(self.inventory))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(calls), 13)
            config = json.loads(self.config.read_text())
            self.assertEqual(config, compose_config(IMAGES) if engine == "compose" else {"images": IMAGES})

    def test_operator_trust_is_explicit_not_inventory(self):
        result, _ = self.run_loader("compose", COSIGN_TRUSTED_IDENTITY="operator", SIGNER="operator")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.inventory.write_text(json.dumps({**IMAGES, "identity": "operator"}))
        self.assertEqual(self.assert_blocked("compose"), [])

    def test_render_still_verifies_but_does_not_deploy(self):
        for engine in ("compose", "helm"):
            result, calls = self.run_loader(engine, "--render")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(calls), 13)
            self.assertIn("config" if engine == "compose" else "template", calls[-1])
            self.assertNotIn("up", calls[-1])
            self.assertNotIn("upgrade", calls[-1])

    def test_standalone_verifier_contract(self):
        command = [str(DEPLOY / "verify-images.sh"), str(self.inventory)]
        result = subprocess.run(command, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls.read_text().splitlines()), 12)
        self.calls.write_text("")
        self.inventory.write_text("{}")
        result = subprocess.run(command, env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls.read_text(), "")


class RealRendererTests(unittest.TestCase):
    def test_compose_config(self):
        if not shutil.which("docker") or subprocess.run(
                ["docker", "compose", "version"], capture_output=True).returncode:
            self.skipTest("Docker Compose plugin is not installed")
        result = subprocess.run(["docker", "compose", "-f", "-", "config", "--format", "json"],
                                input=json.dumps(compose_config(IMAGES)), text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(result.stdout)
        for name, service in config["services"].items():
            self.assertEqual(service["image"], IMAGES[name])
            self.assertEqual(service["ports"][0]["host_ip"], "127.0.0.1")
            self.assertEqual(service["ports"][0]["target"], 8080)
            self.assertTrue(service["read_only"])

    def test_helm_lint_template_and_schema(self):
        if not shutil.which("helm"):
            self.skipTest("Helm is not installed")
        chart = str(DEPLOY / "helm" / "sovereign-stack")
        with tempfile.TemporaryDirectory() as directory:
            values = Path(directory) / "values.json"
            values.write_text(json.dumps({"images": IMAGES}))
            for command in (["helm", "lint", chart, "--strict"],
                            ["helm", "template", "test", chart]):
                result = subprocess.run([*command, "-f", str(values)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            rendered = result.stdout
            self.assertEqual(rendered.count("kind: Deployment"), 3)
            self.assertEqual(rendered.count("kind: Service"), 3)
            for name in ("nginx", "rust", "python"):
                self.assertIn(IMAGES[name], rendered)
            for field in ("runAsUser: 65532", "runAsGroup: 65532", "readOnlyRootFilesystem: true",
                          "allowPrivilegeEscalation: false", "drop: [ALL]", "containerPort: 8080",
                          "medium: Memory", "mountPath: /tmp", "cpu: 500m", "memory: 128Mi"):
                self.assertEqual(rendered.count(field), 3, field)
            for port in (8081, 8082, 8083):
                self.assertIn(f"port: {port}", rendered)
            self.assertNotIn("hostPath", rendered)
            self.assertNotIn("docker.sock", rendered)
            for images in ({}, {**IMAGES, "nginx": "nginx:latest"},
                           {**IMAGES, "nginx": IMAGES["nginx"][:-1]}):
                values.write_text(json.dumps({"images": images}))
                result = subprocess.run(["helm", "template", "test", chart, "-f", str(values)],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("kind: Deployment", result.stdout)


if __name__ == "__main__":
    unittest.main()
