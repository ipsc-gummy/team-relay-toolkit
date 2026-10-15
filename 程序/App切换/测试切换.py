import argparse
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name("切换CodexApp.py")
spec = importlib.util.spec_from_file_location("sg_switch", SOURCE)
sg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sg)


class SwitchingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="sg-app-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "private state"
        self.config = self.root / "config.toml"
        self.original = b'# Preserve this comment\nmodel = "personal-model" # original model\nmodel_provider = "openai"\nmodel_reasoning_effort = "medium"\n[features]\nweb_search = true\n[mcp_servers.example]\ncommand = "example"\nargs = ["a", "b"]\n'
        self.config.write_bytes(self.original)
        self.auth = self.root / "auth.json"
        self.auth.write_bytes(b'{"fixture":"personal-login-must-not-change"}')
        self.key = "cpa-member-a-" + "1" * 64
        self.keyfile = self.root / "key.txt"
        self.keyfile.write_text(self.key)
        self.privatekey = self.root / "private key"
        self.privatekey.write_text("fixture path only; not a usable private key")
        Path(str(self.privatekey) + ".pub").write_text("public fixture")
        self.args = argparse.Namespace(personal_verified=True, app_auth_helper_supported=True,
            user="member-a", ssh_key=str(self.privatekey), ssh_public_key=None,
            key_file=str(self.keyfile), config=str(self.config), port=18318, model="gpt-6-astra")

    def init(self):
        check = subprocess.CompletedProcess([], 0, "256 " + sg.FINGERPRINTS[self.args.user] + " fixture", "")
        with mock.patch.object(sg.shutil, "which", side_effect=lambda name: "/usr/bin/" + name), mock.patch.object(sg.subprocess, "run", return_value=check), redirect_stdout(io.StringIO()):
            sg.initialize(self.args, self.state)
        return sg.read_settings(self.state)

    def switch(self, mode):
        with mock.patch.object(sg, "ensure_tunnel") as tunnel, redirect_stdout(io.StringIO()):
            sg.switch(self.state, mode)
        return tunnel

    def test_initialization_does_not_change_app_config_or_login(self):
        self.init()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual(self.auth.read_bytes(), b'{"fixture":"personal-login-must-not-change"}')

    def test_team_then_personal_is_byte_exact_round_trip(self):
        self.init()
        tunnel = self.switch("team")
        tunnel.assert_called_once()
        self.assertEqual(tomllib.loads(self.config.read_text())["model_provider"], "sg_team")
        tunnel = self.switch("personal")
        tunnel.assert_not_called()
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_command_auth_contains_no_api_key_or_env_key(self):
        self.init()
        text = (self.state / "team.toml").read_text()
        self.assertNotIn(self.key, text)
        provider = tomllib.loads(text)["model_providers"]["sg_team"]
        self.assertNotIn("env_key", provider)
        self.assertNotIn("requires_openai_auth", provider)
        self.assertEqual(provider["auth"]["args"][1], "_credential")
        self.assertEqual(provider["base_url"], "http://127.0.0.1:18318/v1")

    def test_preserves_unrelated_configuration(self):
        self.init()
        original = tomllib.loads(self.original.decode())
        team = tomllib.loads((self.state / "team.toml").read_text())
        self.assertEqual(original["features"], team["features"])
        self.assertEqual(original["mcp_servers"], team["mcp_servers"])
        self.assertEqual(original["model_reasoning_effort"], team["model_reasoning_effort"])

    def test_repeated_selection_does_not_rewrite_config(self):
        self.init()
        self.switch("team")
        first = self.config.stat().st_mtime_ns
        self.switch("team")
        self.assertEqual(first, self.config.stat().st_mtime_ns)
        self.assertEqual(len(list((self.state / "备份").iterdir())), 1)

    def test_existing_tunnel_is_reused(self):
        settings = self.init()
        with mock.patch.object(sg, "tunnel_running", return_value=True), mock.patch.object(sg, "port_open", return_value=True), mock.patch.object(sg, "api_ready", return_value=True), mock.patch.object(sg.subprocess, "run") as run, mock.patch.object(sg.subprocess, "Popen") as popen:
            sg.ensure_tunnel(self.state, settings)
            run.assert_not_called()
            popen.assert_not_called()

    def test_port_owned_by_other_process_is_not_touched(self):
        settings = self.init()
        with mock.patch.object(sg, "tunnel_running", return_value=False), mock.patch.object(sg, "port_open", return_value=True), mock.patch.object(sg.subprocess, "Popen") as popen:
            with self.assertRaises(sg.SafeError):
                sg.ensure_tunnel(self.state, settings)
            popen.assert_not_called()

    def test_unknown_config_changes_are_not_overwritten(self):
        self.init()
        changed = self.original + b'\n# user edited this\n'
        self.config.write_bytes(changed)
        with mock.patch.object(sg, "ensure_tunnel") as tunnel:
            with self.assertRaises(sg.SafeError):
                sg.switch(self.state, "team")
            tunnel.assert_not_called()
        self.assertEqual(self.config.read_bytes(), changed)

    def test_config_changed_during_network_check_is_preserved(self):
        self.init()
        changed = self.original + b'\n# modified while connecting\n'
        with mock.patch.object(sg, "ensure_tunnel", side_effect=lambda *_: self.config.write_bytes(changed)):
            with self.assertRaises(sg.SafeError):
                sg.switch(self.state, "team")
        self.assertEqual(self.config.read_bytes(), changed)

    def test_network_failure_keeps_personal_config(self):
        self.init()
        with mock.patch.object(sg, "ensure_tunnel", side_effect=sg.SafeError("network not ready")):
            with self.assertRaises(sg.SafeError):
                sg.switch(self.state, "team")
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_corrupt_snapshot_is_rejected(self):
        self.init()
        (self.state / "team.toml").write_text('model_provider="unexpected"')
        with self.assertRaises(sg.SafeError):
            self.switch("personal")

    def test_other_provider_cannot_be_claimed_as_personal_plus(self):
        self.config.write_text('model_provider = "unrelated"\n')
        with self.assertRaises(sg.SafeError):
            self.init()
        self.assertFalse(self.state.exists())

    def test_init_requires_app_and_personal_preflight(self):
        self.args.app_auth_helper_supported = False
        with self.assertRaises(sg.SafeError):
            self.init()
        self.assertFalse(self.state.exists())

    def test_reinitialization_does_not_overwrite_state(self):
        self.init()
        before = (self.state / "personal.toml").read_bytes()
        with self.assertRaises(sg.SafeError):
            self.init()
        self.assertEqual((self.state / "personal.toml").read_bytes(), before)

    def test_only_singapore_and_safe_ssh_options(self):
        settings = self.init()
        command = sg.ssh_command(settings)
        self.assertEqual(command[-1], "member-a@203.0.113.10")
        self.assertIn("127.0.0.1:18318:127.0.0.1:8317", command)
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("BatchMode=yes", command)
        self.assertEqual(command[command.index("-F") + 1], "none")
        self.assertNotIn(self.key, " ".join(command))

    def test_operating_system_lock_blocks_duplicate_owner(self):
        self.init()
        with sg.lock(self.state / "操作.lock"):
            with self.assertRaises(sg.SafeError):
                self.switch("personal")

    def test_helper_secret_is_not_in_status_output(self):
        self.init()
        with redirect_stdout(io.StringIO()) as output:
            sg.main(["status", "--state-dir", str(self.state)])
        self.assertNotIn(self.key, output.getvalue())
        self.assertIn("未由此命令验证", output.getvalue())

    def test_incomplete_initialization_returns_clear_error(self):
        result = subprocess.run([sys.executable, str(SOURCE), "team", "--state-dir", str(self.state)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("尚未首次配置", result.stderr)

    def init_owner(self):
        self.args.user = "owner"
        self.args.baseline = "original"
        self.args.original_verified = True
        self.args.personal_verified = False
        self.original = self.original.replace(b'"openai"', b'"original_api"')
        self.config.write_bytes(self.original)
        self.key = "cpa-owner-" + "2" * 64
        self.keyfile.write_text(self.key)
        return self.init()

    def test_owner_reuses_same_engine_and_original_round_trip(self):
        settings = self.init_owner()
        self.assertEqual(sg.ssh_command(settings)[-1], "owner@203.0.113.10")
        self.assertTrue((self.state / "original.toml").is_file())
        self.assertFalse((self.state / "personal.toml").exists())
        self.switch("team")
        self.switch("original")
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_owner_original_cannot_be_claimed_as_personal(self):
        self.init_owner()
        with self.assertRaises(sg.SafeError):
            self.switch("personal")

    def test_teammate_cannot_bypass_personal_preflight(self):
        self.args.baseline = "original"
        self.args.original_verified = True
        with self.assertRaises(sg.SafeError):
            self.init()
        self.assertFalse(self.state.exists())

    def test_original_requires_explicit_baseline_verification(self):
        self.args.user = "owner"
        self.args.baseline = "original"
        self.args.original_verified = False
        with self.assertRaises(sg.SafeError):
            self.init()

    def test_check_does_not_change_config(self):
        self.init_owner()
        with mock.patch.object(sg, "ensure_tunnel") as tunnel, redirect_stdout(io.StringIO()):
            sg.main(["check", "--state-dir", str(self.state)])
            tunnel.assert_called_once()
        self.assertEqual(self.config.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main(verbosity=2)
