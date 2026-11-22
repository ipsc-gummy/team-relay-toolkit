#!/usr/bin/env python3
"""Offline tests for rendering a configured per-member archive."""
import ast
import base64
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch
import zipfile


PACKER = Path(__file__).with_name("打包新人两步接入.py")
SPEC = importlib.util.spec_from_file_location("deployment_package_builder", PACKER)
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def constants(source):
    return {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(source).body
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in ("HOST", "HOST_FP", "SSH_PORT", "TARGET", "FINGERPRINTS", "PINNED_HOST_KEY")}


class DeploymentPackageTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.ssh_host = self.root / "host.pub"
        self.member_pub = self.root / "member.pub"
        self.member = "testmember"
        for key in (self.ssh_host, self.member_pub):
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", str(key.with_suffix("")),
                            "-N", "", "-C", "unrelated-public-annotation"], check=True, timeout=5)
        self.sha = self.fingerprint(self.ssh_host)
        self.token = "cpa-" + self.member + "-" + "a" * 64
        self.token_path = self.root / "secret.txt"
        self.token_path.write_text(self.token + "\n")
        self.token_path.chmod(0o600)
        self.ip = "192.0.2.42"
        self.port = 19421

    @staticmethod
    def fingerprint(path):
        return subprocess.run(["ssh-keygen", "-lf", str(path)], check=True, capture_output=True, text=True,
                              timeout=5).stdout.split()[1]

    def test_published_macos_and_windows_archives_are_consistent(self):
        deployment = BUILDER.load_deployment(self.ip, self.ssh_host, self.port, self.sha)
        for platform, entry, directory, installer in (
            ("macos", "接入.command", "程序/", "一键接入.py"),
            ("windows", "接入.cmd", "program/", "install.py"),
        ):
            with self.subTest(platform=platform):
                output = self.root / f"{platform}.zip"
                receipt = BUILDER.pack(output, self.member, self.member_pub, self.token_path, platform,
                                      deployment=deployment)
                self.assertEqual(receipt["files"], 7)
                self.assertNotIn(self.token, repr(receipt))
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                prefix = "Codex团队接入/"
                with zipfile.ZipFile(output) as bundle:
                    self.assertEqual(set(bundle.namelist()), {prefix + p for p in (*BUILDER.DOCS, entry,
                        directory + installer, directory + "切换CodexApp.py", "个人参数.json", "中转访问密钥.txt")})
                    self.assertTrue(all(stat.S_IMODE(f.external_attr >> 16) == (0o700 if f.filename.endswith(".command")
                                        else 0o600) for f in bundle.infolist()))
                    self.assertEqual(bundle.read(prefix + "中转访问密钥.txt").decode().strip(), self.token)
                    self.assertTrue(all(self.token.encode() not in bundle.read(n) for n in bundle.namelist()
                                        if not n.endswith("中转访问密钥.txt")))
                    manifest = json.loads(bundle.read(prefix + "个人参数.json"))
                    self.assertEqual((manifest["host"], manifest["host_fingerprint"], manifest["gateway_port"]),
                                     (self.ip, self.sha, self.port))
                    core = constants(bundle.read(prefix + directory + "切换CodexApp.py"))
                    self.assertEqual(core, {"HOST": self.ip, "HOST_FP": self.sha, "SSH_PORT": 22,
                                            "TARGET": f"127.0.0.1:{self.port}",
                                            "FINGERPRINTS": {self.member: self.fingerprint(self.member_pub)}})
                    public_key = constants(bundle.read(prefix + directory + installer))["PINNED_HOST_KEY"]
                    known_hosts = self.root / f"{platform}-known_hosts"
                    known_hosts.write_text(f"{self.ip} {public_key}\n")
                    self.assertEqual(self.fingerprint(known_hosts), self.sha)
                    self.assertNotIn("unrelated-public-annotation", public_key)
                    instructions = bundle.read(prefix + BUILDER.DOCS[1]).decode()
                    for value in (self.ip, self.sha, core["TARGET"], "127.0.0.1:18318"):
                        self.assertIn(value, instructions)
                    for value in (BUILDER.EXAMPLE_HOST, BUILDER.EXAMPLE_HOST_FP, BUILDER.EXAMPLE_TARGET):
                        self.assertNotIn(value, instructions)
                    if platform == "windows":
                        self.assertIn(f'-L 127.0.0.1:18318:{core["TARGET"]} "$verifiedUser@{self.ip}"', instructions)
                before = output.read_bytes()
                with self.assertRaisesRegex(ValueError, "already exists"):
                    BUILDER.pack(output, self.member, self.member_pub, self.token_path, platform, deployment)
                self.assertEqual(output.read_bytes(), before)

    def test_old_defaults_and_public_archive_are_unchanged(self):
        self.assertIsNone(BUILDER.load_deployment())
        member = BUILDER.build_payload(self.member, self.fingerprint(self.member_pub), self.token)
        docs = BUILDER.ROOT / "新人接入/两步版"
        for name in BUILDER.DOCS:
            self.assertEqual(member["Codex团队接入/" + name], (docs / name).read_bytes())
        manifest = json.loads(member["Codex团队接入/个人参数.json"])
        self.assertEqual(manifest["host"], BUILDER.EXAMPLE_HOST)
        self.assertNotIn("gateway_port", manifest)
        output = self.root / "public.zip"
        BUILDER.pack(output)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
        with zipfile.ZipFile(output) as bundle:
            self.assertEqual(set(bundle.namelist()), {"团队中转_两步说明/" + name for name in BUILDER.DOCS})
        with self.assertRaisesRegex(ValueError, "only for personal"):
            BUILDER.build_payload(deployment=BUILDER.load_deployment(self.ip, self.ssh_host, self.port))

    def test_budget_mac_package_only_activates_and_restores_the_expected_route(self):
        deployment = BUILDER.load_deployment(self.ip, self.ssh_host, self.port, self.sha)
        archive = self.root / "budget-mac.zip"
        receipt = BUILDER.pack(archive, self.member, self.member_pub, self.token_path, deployment=deployment,
                               budget_mac=True)
        self.assertEqual(receipt["files"], 8)
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(self.root)
        package = self.root / "Codex团队接入"
        manifest = json.loads((package / "个人参数.json").read_bytes())
        self.assertEqual(manifest["profile"], "budget-mac")
        self.assertEqual(manifest["local_agent_entry"], "FOR-CODEX.md")
        self.assertTrue((package / "FOR-CODEX.md").is_file())
        self.assertEqual(self.fingerprint(package / "known_hosts"), self.sha)
        spec = importlib.util.spec_from_file_location("fixture_budget_core", package / "程序/切换CodexApp.py")
        core = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(core)
        initialized = self.root / "initialized"
        config = self.root / "config.toml"
        original = b'''model = "personal-model"
web_search = "live"
[features]
multi_agent = true
[mcp_servers.example]
command = "fixture"
[marketplaces.openai-bundled]
last_updated = "2026-10-01T00:00:00Z"
'''
        for state, baseline in ((initialized, original), (self.root / "empty-state", None)):
            with self.subTest(had_config=bool(baseline)):
                if baseline is not None:
                    config.write_bytes(baseline)
                elif config.exists():
                    config.unlink()
                ini = ["init", "--state-dir", str(state), "--config", str(config), "--user", self.member,
                       "--ssh-key", str(self.member_pub.with_suffix("")), "--key-file", str(self.token_path),
                       "--known-hosts", str(package / "known_hosts"), "--personal-verified", "--app-auth-helper-supported"]
                core.main(ini)
                self.assertEqual(config.read_bytes() if config.exists() else None, baseline)
                settings = core.read_settings(state)
                wire = core.ssh_command(settings)
                self.assertIn("GlobalKnownHostsFile=none", wire)
                self.assertIn(f"127.0.0.1:18318:127.0.0.1:{self.port}", wire)
                with patch.object(core, "ensure_tunnel") as tied:
                    core.switch(state, "team")
                    tied.assert_called_once()
                live = config.read_bytes()
                parsed = tomllib.loads(live.decode())
                provider = parsed["model_providers"]["sg_team_budget"]
                self.assertEqual(parsed["model"], manifest["model"])
                self.assertFalse(parsed["features"]["multi_agent"])
                self.assertNotIn("mcp_servers", parsed)
                self.assertEqual(parsed["web_search"], "disabled")
                self.assertEqual([provider[k] for k in ("request_max_retries", "stream_max_retries", "supports_websockets")],
                                 [0, 0, False])
                if baseline:
                    config.write_bytes(live.replace(b"2026-10-01", b"2026-10-02"))
                core.switch(state, "personal")
                self.assertEqual(config.read_bytes() if config.exists() else None, baseline)

    def test_budget_package_cannot_target_legacy_port_or_windows(self):
        fingerprint = self.fingerprint(self.member_pub)
        direct_cpa = BUILDER.load_deployment(self.ip, self.ssh_host, 8317, self.sha)
        with self.assertRaisesRegex(ValueError, "dedicated gateway"):
            BUILDER.build_payload(self.member, fingerprint, self.token, deployment=direct_cpa, budget_mac=True)
        verified = BUILDER.load_deployment(self.ip, self.ssh_host, self.port, self.sha)
        with self.assertRaisesRegex(ValueError, "personal Mac"):
            BUILDER.build_payload(self.member, fingerprint, self.token, "windows", verified, budget_mac=True)

    def test_deployment_tuple_rejects_partial_and_invalid_options(self):
        for values in ((self.ip, None, self.port), (None, self.ssh_host, self.port), (self.ip, self.ssh_host, None),
                       (None, None, None, self.sha), ("::1", self.ssh_host, self.port),
                       (BUILDER.EXAMPLE_HOST, self.ssh_host, self.port), (self.ip, self.ssh_host, 0),
                       (self.ip, self.ssh_host, 65536), (self.ip, self.ssh_host, True)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                BUILDER.load_deployment(*values)
        # Localhost is valid in a synthetic or explicitly local deployment.
        self.assertEqual(BUILDER.load_deployment("127.0.0.1", self.ssh_host, self.port).host, "127.0.0.1")

    def test_rejects_mismatch_malformed_multiline_and_symlink(self):
        with self.assertRaisesRegex(ValueError, "separately verified fingerprint"):
            BUILDER.load_deployment(self.ip, self.ssh_host, self.port, self.fingerprint(self.member_pub))
        symlink = self.root / "link.pub"
        symlink.symlink_to(self.ssh_host)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            BUILDER.load_deployment(self.ip, symlink, self.port)
        invalid = self.root / "invalid.pub"
        for content in (self.ssh_host.read_bytes() * 2, b"ssh-rsa AAAA\n", b"ssh-ed25519 invalid^^\n",
                        b"ssh-ed25519 " + base64.b64encode(BUILDER.ED25519_WIRE_PREFIX + b"x" * 31) + b"\n"):
            invalid.write_bytes(content)
            with self.assertRaises(ValueError):
                BUILDER.load_deployment(self.ip, invalid, self.port)

    def test_cli_errors_leave_destination_missing(self):
        output = self.root / "bad.zip"
        command = [sys.executable, "-B", str(PACKER), "--output", str(output), "--server-ip", self.ip]
        public = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertEqual(public.returncode, 2)
        self.assertIn("only for personal", public.stderr)
        personal = subprocess.run(command + ["--user", self.member, "--public-key", str(self.member_pub),
                                            "--token-file", str(self.token_path)], capture_output=True, text=True, timeout=5)
        self.assertEqual(personal.returncode, 2)
        self.assertNotIn(self.token, personal.stdout + personal.stderr)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
