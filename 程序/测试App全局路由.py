#!/usr/bin/env python3
"""隔离验证 App 全局路由控制器；所有状态、配置和备份均为临时模拟文件。

直接运行本文件即可。不会读取真实配置、auth、任务历史或凭据；不会启动
App、SSH、launchctl 或网络请求。这些测试不替代 App 重启后的真实线路验收。
"""
from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import tomllib
from types import SimpleNamespace
import unittest
from unittest import mock


sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().with_name("App全局路由.py")


def import_source(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


route = import_source("isolated_app_global_route", SOURCE)
# Only import definitions from the existing helper; do not invoke any real action.
legacy = import_source(
    "isolated_existing_route_core",
    SOURCE.parent / "App切换/切换CodexApp.py",
)


TEAM_CONFIG = '''# Synthetic fixture: no real credential or user history.
model_provider  =  "sg_team" # retain comment and spacing
model = "gpt-6-astra"
model_reasoning_effort = "high"
approval_policy = "on-request"

[model_providers.custom-api]
# School provider text must be retained byte for byte.
name = 'School fixture'
base_url = "http://127.0.0.1:18317/v1"
wire_api = "responses"
env_key = "FIXTURE_SCHOOL_TOKEN"

[model_providers.sg_team]
name = "Singapore fixture"
base_url = "http://127.0.0.1:18318/v1"
wire_api = "responses"

[model_providers.sg_team.auth]
command = "/fixture/python"
args = ["/fixture/helper.py", "_credential"]
timeout_ms = 5000
refresh_interval_ms = 0

[projects."/fixture/研究目录"]
trust_level = "trusted"

[features]
multi_agent = true

[marketplaces.openai-bundled]
source = "fixture://bundle"
last_updated = 1234

[marketplaces.other]
last_updated = 4567
'''.encode()


class FakeLaunchctl:
    """A stateful launchctl stand-in; unrecognized commands always fail the test."""

    def __init__(self):
        self.value = None
        self.calls = []
        self.fail_set_before = False
        self.fail_set_after = False
        self.after_set = None

    def __call__(self, command, **kwargs):
        command = list(command)
        self.calls.append(command)
        if command[:2] == ["/bin/launchctl", "getenv"] and command[2:] == [route.ENV_KEY]:
            return subprocess.CompletedProcess(command, 0, (self.value or "") + "\n", "")
        if command[:3] == ["/bin/launchctl", "setenv", route.ENV_KEY] and len(command) == 4:
            if self.fail_set_before:
                self.fail_set_before = False
                return subprocess.CompletedProcess(command, 1, b"", b"fixture failure")
            self.value = command[3]
            if self.after_set is not None:
                callback, self.after_set = self.after_set, None
                callback()
            if self.fail_set_after:
                self.fail_set_after = False
                return subprocess.CompletedProcess(command, 1, b"", b"fixture failure after mutation")
            return subprocess.CompletedProcess(command, 0, b"", b"")
        if command == ["/bin/launchctl", "unsetenv", route.ENV_KEY]:
            self.value = None
            return subprocess.CompletedProcess(command, 0, b"", b"")
        raise AssertionError("Unexpected external command in isolated test: " + repr(command))

    @property
    def mutations(self):
        return [call for call in self.calls if call[1] != "getenv"]


class ControllerIsolationTests(unittest.TestCase):
    def patch(self, patcher):
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="codex-app-route-test-", dir=tempfile.gettempdir())
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "部署"
        self.state = self.root / ".连接凭据/App全局路由"
        self.legacy = self.root / ".连接凭据/App切换状态"
        self.config = self.base / "模拟用户/.codex/config.toml"
        self.proxy = self.root / "程序/App全局路由代理.py"
        self.binary = self.base / "模拟App/codex"
        self.asar = self.base / "模拟App/app.asar"
        self.backup = self.root / ".连接凭据/修改前备份-20000101-000000"
        self.entry = self.root / "本人App试用.command"
        self.guide = self.root / "本人Mac使用与切换流程.md"
        for directory in (
            self.root, self.state.parent, self.legacy, self.config.parent,
            self.proxy.parent, self.binary.parent, self.backup,
        ):
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            directory.chmod(0o700)

        self.launchctl = FakeLaunchctl()
        self.core = SimpleNamespace(
            SafeError=legacy.SafeError,
            atomic_write=mock.Mock(side_effect=self.safe_atomic_write),
            lock=legacy.lock,
            read_settings=legacy.read_settings,
            snapshots=legacy.snapshots,
            ensure_tunnel=mock.Mock(),
            tunnel_running=mock.Mock(return_value=True),
            main=mock.Mock(),
        )
        self.patch(mock.patch.multiple(
            route, ROOT=self.root, STATE=self.state, LEGACY=self.legacy,
            CONFIG=self.config, PROXY=self.proxy, BINARY=self.binary,
            ASAR=self.asar, _CORE=self.core,
        ))
        original_read = route.read_file

        def isolated_read(path):
            self.assert_temporary(path)
            return original_read(path)

        self.patch(mock.patch.object(route, "read_file", side_effect=isolated_read))
        self.patch(mock.patch.object(subprocess, "run", side_effect=self.launchctl))
        self.patch(mock.patch.object(subprocess, "Popen", side_effect=AssertionError("No process launch allowed")))
        self.patch(mock.patch.object(socket, "create_connection", side_effect=AssertionError("No network allowed")))
        self.output = io.StringIO()
        self.patch(mock.patch("sys.stdout", self.output))

        self.initial = TEAM_CONFIG.replace(b"last_updated = 1234", b"last_updated = 9876")
        self.school_original = TEAM_CONFIG.replace(b'"sg_team" # retain', b'"custom-api" # retain')
        self.safe_atomic_write(self.config, self.initial)
        self.safe_atomic_write(self.proxy, b"#!/fixture/python\n", 0o700)
        self.safe_atomic_write(self.binary, b"fixture-app-server\n", 0o700)
        self.safe_atomic_write(self.asar, b"fixture-asar\n")
        self.safe_atomic_write(self.entry, b"#!/bin/bash\n# original fixture entry\n", 0o700)
        self.safe_atomic_write(self.guide, "原使用说明，模拟文件。\n".encode())
        self.safe_atomic_write(self.legacy / "original.toml", self.school_original)
        self.safe_atomic_write(self.legacy / "team.toml", TEAM_CONFIG)
        self.safe_atomic_write(self.legacy / "settings.json", json.dumps({
            "schema": 1, "user": "owner", "host": legacy.HOST,
            "target": legacy.TARGET, "port": 18318, "baseline_kind": "original",
            "model": "gpt-6-astra", "config": str(self.config), "python": "/fixture/python",
            "personal_hash": route.digest(self.school_original), "team_hash": route.digest(TEAM_CONFIG),
        }).encode())

        # These are fake local sentinels, not real history, auth or a real database.
        self.sentinels = {
            self.config.parent / "auth.json": b'{"fixture": "do not change"}\n',
            self.config.parent / "fixture-history.jsonl": b'{"thread_id":"fixture","cwd":"/fixture/old","context":["before"],"status":"pending"}\n',
            self.config.parent / "fixture-thread.sqlite": b"Synthetic database sentinel; never opened as SQLite.\n",
            self.legacy / "original.toml": self.school_original,
            self.legacy / "team.toml": TEAM_CONFIG,
        }
        for path, content in self.sentinels.items():
            self.safe_atomic_write(path, content)

        self.backup_files = []
        for i, path in enumerate((self.config, self.entry, self.guide)):
            content = path.read_bytes()
            item = {"path": str(path), "backup": f"file-{i}.bak", "sha256": route.digest(content), "mode": path.stat().st_mode & 0o777}
            self.safe_atomic_write(self.backup / item["backup"], content)
            self.backup_files.append(item)
        self.write_backup_manifest()
        route.prepare(self.backup)
        self.launchctl.calls.clear()
        self.core.atomic_write.reset_mock()

    def assert_temporary(self, path):
        self.assertTrue(Path(path).absolute().is_relative_to(self.base), "Attempt to access non-fixture path")

    def safe_atomic_write(self, path, data, mode=0o600):
        self.assert_temporary(path)
        legacy.atomic_write(path, data, mode)

    def write_backup_manifest(self, old_env=None):
        self.safe_atomic_write(self.backup / "备份清单.json", json.dumps({
            "schema": 1, "files": self.backup_files,
            "launchctl_before": {route.ENV_KEY: old_env},
        }).encode())

    def assert_sentinels(self):
        for path, content in self.sentinels.items():
            self.assertEqual(path.read_bytes(), content, str(path))

    def install_files(self):
        self.safe_atomic_write(self.entry, b"#!/bin/bash\n# installed fixture entry\n", 0o700)
        self.safe_atomic_write(self.guide, "新使用说明，模拟文件。\n".encode())
        route.record_installation()

    def assert_no_mutation(self, before=None):
        self.assertEqual(self.config.read_bytes(), self.initial if before is None else before)
        self.assertIsNone(self.launchctl.value)
        self.assertEqual(self.launchctl.mutations, [])
        self.assertFalse(route.manifest()["enabled"])
        self.assert_sentinels()

    def test_provider_selection_preserves_every_other_byte_and_school_definition(self):
        for newline in (b"\n", b"\r\n"):
            with self.subTest(newline=newline):
                before = TEAM_CONFIG.replace(b"\n", newline)
                expected = before.replace(b'"sg_team" # retain', b'"custom-api" # retain', 1)
                after = route.select_provider(before, "custom-api")
                self.assertEqual(after, expected)
                self.assertEqual(route.select_provider(after, "sg_team"), before)
                parsed_before, parsed_after = tomllib.loads(before.decode()), tomllib.loads(after.decode())
                parsed_before["model_provider"] = "custom-api"
                self.assertEqual(parsed_after, parsed_before)

    def test_user_settings_do_not_determine_route_in_either_mode(self):
        for mode, provider in route.PROVIDERS.items():
            route.switch(mode)
            baseline = self.config.read_bytes()
            for old, new in (
                (b'model_reasoning_effort = "high"', b'model_reasoning_effort = "xhigh"'),
                (b'model_reasoning_effort = "high"', b'model_reasoning_effort = "medium"'),
                (b'model = "gpt-6-astra"', b'model = "another-user-model"'),
                (b'last_updated = 4567', b'last_updated = 4568'),
                (b'"fixture://bundle"', b'"fixture://other"'),
                (b'trust_level = "trusted"', b'trust_level = "untrusted"'),
                (b'multi_agent = true', b'multi_agent = false'),
                (b'approval_policy = "on-request"', b'approval_policy = "never"'),
            ):
                with self.subTest(mode=mode, setting=new):
                    changed = baseline.replace(old, new)
                    self.safe_atomic_write(self.config, changed)
                    self.core.atomic_write.reset_mock()
                    self.assertEqual(route.load_route()["provider"], provider)
                    self.assertEqual(route.manifest()["mode"], mode)
                    self.core.atomic_write.assert_not_called()
                    self.assertEqual(self.config.read_bytes(), changed)
            # Previously unseen UI fields require no controller code changes.
            changed = baseline + b'\n[tui]\nanimations = false\nnew_user_setting = "fixture"\n'
            self.safe_atomic_write(self.config, changed)
            self.assertEqual(route.load_route()["provider"], provider)
            self.safe_atomic_write(self.config, baseline)

    def test_switch_preserves_model_reasoning_and_ui_bytes(self):
        changed = self.initial.replace(b'"high"', b'"xhigh"').replace(b'"gpt-6-astra"', b'"new-model"')
        changed += b'\n[tui]\nanimations = false\n'
        self.safe_atomic_write(self.config, changed)
        for mode in ("team", "original", "team"):
            route.switch(mode)
            self.assertEqual(self.config.read_bytes(), route.select_provider(changed, route.PROVIDERS[mode]))
            self.assertEqual(route.load_route()["provider"], route.PROVIDERS[mode])
            self.assertEqual(route.manifest()["mode"], mode)

    def test_prepare_records_independent_hashes_without_enabling_or_touching_original(self):
        value = route.manifest()
        self.assertEqual(value["schema"], 2)
        self.assertEqual(value["mode"], "team")
        self.assertFalse(value["enabled"])
        self.assertEqual(self.config.read_bytes(), self.initial)
        self.assertEqual((self.state / "team.toml").read_bytes(), self.initial)
        for mode in route.PROVIDERS:
            path = self.state / (mode + ".toml")
            self.assertEqual(value["hashes"][mode], route.digest(path.read_bytes()))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assert_no_mutation()

    def test_unknown_route_changes_fail_closed_before_tunnel_or_environment(self):
        unknown = self.initial.replace(b'http://127.0.0.1:18318/v1', b'https://unknown.invalid/v1')
        self.safe_atomic_write(self.config, unknown)
        with self.assertRaises(route.SafeError):
            route.switch("team")
        self.assert_no_mutation(unknown)
        self.core.ensure_tunnel.assert_not_called()

    def test_provider_definitions_fail_closed_in_both_modes_even_when_inactive(self):
        for mode in route.PROVIDERS:
            route.switch(mode)
            baseline = self.config.read_bytes()
            for old, new in (
                (b'http://127.0.0.1:18318/v1', b'https://unknown.invalid/team'),
                (b'http://127.0.0.1:18317/v1', b'https://unknown.invalid/school'),
                (b'FIXTURE_SCHOOL_TOKEN', b'UNKNOWN_TOKEN'),
                (b'wire_api = "responses"', b'wire_api = "chat"'),
                (b'command = "/fixture/python"', b'command = "/unknown/auth-helper"'),
                (b'name = "Singapore fixture"', b'name = "Singapore fixture"\nenv_key = "UNKNOWN_TOKEN"'),
                (b'name = "Singapore fixture"', b'name = "Singapore fixture"\nhttp_headers = { Authorization = "unknown" }'),
            ):
                with self.subTest(mode=mode, field=old):
                    changed = baseline.replace(old, new)
                    self.safe_atomic_write(self.config, changed)
                    self.core.atomic_write.reset_mock()
                    self.core.ensure_tunnel.reset_mock()
                    self.launchctl.calls.clear()
                    with self.assertRaises(route.ConfigDrift):
                        route.load_route()
                    with self.assertRaises(route.ConfigDrift):
                        route.switch("original" if mode == "team" else "team")
                    self.core.atomic_write.assert_not_called()
                    self.core.ensure_tunnel.assert_not_called()
                    self.assertEqual(self.launchctl.mutations, [])
                    self.assertEqual(self.config.read_bytes(), changed)
                    self.assertEqual(route.manifest()["mode"], mode)
            self.safe_atomic_write(self.config, baseline)

    def test_mode_and_top_level_selector_must_agree_without_inference(self):
        for mode in route.PROVIDERS:
            route.switch(mode)
            baseline = self.config.read_bytes()
            for provider in ("sg_team", "custom-api", "unknown"):
                if provider == route.PROVIDERS[mode]:
                    continue
                with self.subTest(mode=mode, provider=provider):
                    self.safe_atomic_write(self.config, route.select_provider(baseline, provider))
                    with self.assertRaises(route.ConfigDrift):
                        route.load_route()
                    self.assertEqual(route.manifest()["mode"], mode)
            self.safe_atomic_write(self.config, baseline)

    def test_missing_invalid_or_legacy_mode_never_falls_back_to_config(self):
        route.switch("team")
        good = route.manifest()
        for invalid in (dict(good, mode="unknown"), {k:v for k,v in good.items() if k != "mode"},
                        {k:v for k,v in dict(good, schema=1).items() if k != "mode"}):
            with self.subTest(schema=invalid["schema"], mode=invalid.get("mode")):
                route.save_manifest(invalid)
                with self.assertRaises(route.SafeError):
                    route.load_route()
                with self.assertRaises(route.SafeError):
                    route.route_enabled()
        route.save_manifest(good)

    def test_managed_mcp_wrapper_paths_are_allowed_but_unknown_paths_fail_closed(self):
        for mode in route.PROVIDERS:
            route.switch(mode)
            baseline = self.config.read_bytes()
            for server in ("node_repl", "another_server"):
                for path in (str(self.binary), str(self.proxy), "/third-party/codex"):
                    with self.subTest(mode=mode, server=server, path=path):
                        changed = baseline + (f'\n[mcp_servers.{server}.env]\nCODEX_CLI_PATH = ' + json.dumps(path) + '\n').encode()
                        self.safe_atomic_write(self.config, changed)
                        if path == "/third-party/codex":
                            with self.assertRaises(route.ConfigDrift):
                                route.load_route()
                        else:
                            self.assertEqual(route.load_route()["provider"], route.PROVIDERS[mode])
            self.safe_atomic_write(self.config, baseline)

    def test_unknown_launch_wrapper_and_manifest_proxy_fail_closed_on_load(self):
        route.switch("team")
        self.launchctl.value = "/third-party/codex"
        with self.assertRaises(route.SafeError):
            route.load_route()
        self.launchctl.value = str(self.proxy)
        value = route.manifest()
        route.save_manifest(dict(value, proxy="/third-party/codex"))
        with self.assertRaises(route.SafeError):
            route.load_route()

    def test_missing_or_nonexecutable_proxy_fails_closed_on_load(self):
        route.switch("team")
        self.proxy.chmod(0o600)
        with self.assertRaises(route.SafeError):
            route.load_route()
        self.proxy.unlink()
        with self.assertRaises(route.SafeError):
            route.load_route()

    def test_asar_update_fails_closed_on_load_and_switch(self):
        route.switch("team")
        self.safe_atomic_write(self.asar, b"changed fixture asar")
        with self.assertRaises(route.SafeError):
            route.load_route()
        with self.assertRaises(route.SafeError):
            route.switch("original")
        self.assertEqual(route.manifest()["mode"], "team")

    def test_mode_change_during_load_fails_closed(self):
        route.switch("team")
        value = route.manifest()
        with mock.patch.object(route, "manifest", side_effect=[value, dict(value, mode="original")]):
            with self.assertRaises(route.SafeError):
                route.load_route()

    def test_existing_proxy_consumes_real_controller_mode_without_rewriting_context(self):
        spec = importlib.util.spec_from_file_location("isolated_proxy_route_contract", SOURCE.with_name("App全局路由代理.py"))
        proxy = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = proxy
        self.addCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(proxy)
        selection = proxy.RouteState(SOURCE)
        selection.controller = route
        request = b'{"id":1,"method":"thread/resume","params":{"threadId":"synthetic-history","modelProvider":"custom-api","opaque":{"text":"context stays"}}}\n'
        for mode, provider in route.PROVIDERS.items():
            route.switch(mode)
            changed = self.config.read_bytes().replace(b'"high"', b'"xhigh"')
            self.safe_atomic_write(self.config, changed)
            selected = selection.read()
            self.assertEqual(selected["mode"], mode)
            transformed = proxy.transform_request(request, selected["provider"])
            self.assertEqual(transformed, request.replace(b'"modelProvider":"custom-api"', ('"modelProvider":' + json.dumps(provider)).encode()))
        self.safe_atomic_write(self.config, changed.replace(b'18318/v1', b'19999/v1'))
        with self.assertRaises(route.ConfigDrift):
            selection.read()
        self.assert_sentinels()

    def make_legacy_state(self):
        value = route.manifest()
        value["schema"] = 1
        del value["mode"]
        route.save_manifest(value)
        return (self.state / "状态.json").read_bytes()

    def test_explicit_legacy_migration_preserves_config_snapshots_and_enabled_flag(self):
        for mode in route.PROVIDERS:
            route.switch(mode)
            changed = self.config.read_bytes().replace(b'"high"', b'"xhigh"')
            self.safe_atomic_write(self.config, changed)
            old = self.make_legacy_state()
            snapshots = {m:(self.state / (m + ".toml")).read_bytes() for m in route.PROVIDERS}
            self.launchctl.calls.clear()
            self.core.ensure_tunnel.reset_mock()
            route.migrate(mode)
            self.assertEqual(route.load_route()["provider"], route.PROVIDERS[mode])
            self.assertTrue(route.manifest()["enabled"])
            self.assertEqual(self.config.read_bytes(), changed)
            self.assertIn(old, [p.read_bytes() for p in self.state.glob("mode迁移前状态_*.json")])
            for m, content in snapshots.items():
                self.assertEqual((self.state / (m + ".toml")).read_bytes(), content)
            self.assertEqual(self.launchctl.mutations, [])
            self.core.ensure_tunnel.assert_not_called()
            self.assert_sentinels()

    def test_migration_preserves_disabled_flag(self):
        self.make_legacy_state()
        route.migrate("team")
        self.assertEqual(route.manifest()["mode"], "team")
        self.assert_no_mutation()

    def test_migration_rejects_wrong_mode_and_unknown_route_before_writing(self):
        old = self.make_legacy_state()
        for mode, changed in (
            ("original", self.initial),
            ("team", self.initial.replace(b'18318/v1', b'19999/v1')),
            ("team", self.initial + b'\n[mcp_servers.node_repl.env]\nCODEX_CLI_PATH = "/unknown/codex"\n'),
        ):
            with self.subTest(mode=mode, changed=changed[-40:]):
                self.safe_atomic_write(self.config, changed)
                self.core.atomic_write.reset_mock()
                with self.assertRaises(route.SafeError):
                    route.migrate(mode)
                self.assertEqual((self.state / "状态.json").read_bytes(), old)
                self.core.atomic_write.assert_not_called()
                self.core.ensure_tunnel.assert_not_called()
                self.assertEqual(self.launchctl.mutations, [])

    def test_migration_write_failure_keeps_legacy_state_and_config(self):
        old = self.make_legacy_state()
        with mock.patch.object(route, "save_manifest", side_effect=OSError("fixture failure")):
            with self.assertRaises(OSError):
                route.migrate("team")
        self.assertEqual((self.state / "状态.json").read_bytes(), old)
        self.assertEqual(self.config.read_bytes(), self.initial)

    def test_migration_requires_explicit_mode_and_cannot_switch_v2_state(self):
        with self.assertRaises(route.SafeError):
            route.migrate("original")
        self.make_legacy_state()
        old_umask = os.umask(0o077)
        try:
            with self.assertRaises(route.SafeError):
                route.main(["migrate"])
        finally:
            os.umask(old_umask)

    def test_failed_switch_preserves_persisted_mode(self):
        route.switch("team")
        old = (self.state / "状态.json").read_bytes()
        with mock.patch.object(route, "save_manifest", side_effect=OSError("fixture failure")):
            with self.assertRaises(OSError):
                route.switch("original")
        self.assertEqual((self.state / "状态.json").read_bytes(), old)
        self.assertEqual(route.load_route()["provider"], "sg_team")
        self.assertEqual(self.config.read_bytes(), self.initial)

    def test_both_selected_and_nonselected_snapshot_tampering_is_rejected(self):
        for mode in ("team", "original"):
            with self.subTest(mode=mode):
                snapshot = self.state / (mode + ".toml")
                before = snapshot.read_bytes()
                self.safe_atomic_write(snapshot, before + b"# unconfirmed tamper\n")
                with self.assertRaises(route.SafeError):
                    route.switch("team")
                self.safe_atomic_write(snapshot, before)
        self.assert_no_mutation()
        self.core.ensure_tunnel.assert_not_called()

    def test_team_original_team_is_symmetric_and_preserves_current_timestamp(self):
        route.switch("team")
        self.assertEqual(route.load_route()["provider"], "sg_team")
        self.assertEqual(self.core.ensure_tunnel.call_count, 1)
        route.switch("original")
        expected = self.initial.replace(b'"sg_team" # retain', b'"custom-api" # retain', 1)
        self.assertEqual(self.config.read_bytes(), expected)
        self.assertEqual(route.load_route()["provider"], "custom-api")
        self.assertEqual(self.core.ensure_tunnel.call_count, 1, "original must not require any network probe")
        route.switch("team")
        self.assertEqual(self.config.read_bytes(), self.initial)
        self.assertEqual(self.core.ensure_tunnel.call_count, 2)
        self.assertEqual(self.launchctl.value, str(self.proxy))
        self.assert_sentinels()

    def test_personal_uses_builtin_openai_without_tunnel_and_keeps_local_state(self):
        self.core.ensure_tunnel.side_effect = AssertionError("personal must not touch SSH")
        route.switch("personal")
        self.assertEqual(tomllib.loads(self.config.read_text())["model_provider"], "openai")
        self.assertEqual(route.load_route(), {"provider": "openai", "mode": "personal", "state_dir": self.state})
        self.core.ensure_tunnel.assert_not_called()
        self.assert_sentinels()
        route.switch("original")
        self.assertEqual(tomllib.loads(self.config.read_text())["model_provider"], "custom-api")
        self.assert_sentinels()

    def test_original_works_without_any_tunnel_or_school_network(self):
        self.core.ensure_tunnel.side_effect = AssertionError("No network dependency allowed for original")
        route.switch("original")
        self.assertEqual(tomllib.loads(self.config.read_text())["model_provider"], "custom-api")
        self.core.ensure_tunnel.assert_not_called()
        self.assertEqual(self.launchctl.mutations, [["/bin/launchctl", "setenv", route.ENV_KEY, str(self.proxy)]])
        self.assert_sentinels()

    def test_switch_registers_and_verifies_gui_startup_environment(self):
        route.switch("team")
        self.assertEqual(self.launchctl.value, str(self.proxy))
        commands = self.launchctl.calls
        set_index = commands.index(["/bin/launchctl", "setenv", route.ENV_KEY, str(self.proxy)])
        self.assertIn(["/bin/launchctl", "getenv", route.ENV_KEY], commands[set_index + 1:])
        self.assertTrue(route.route_enabled())

    def test_already_selected_mode_keeps_config_inode_and_startup_registration(self):
        route.switch("team")
        self.launchctl.calls.clear()
        before = self.config.stat()
        route.switch("team")
        after = self.config.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        self.assertEqual(self.launchctl.mutations, [])

    def test_unknown_startup_wrapper_is_not_overwritten(self):
        self.launchctl.value = "/fixture/another-user-wrapper"
        with self.assertRaises(route.SafeError):
            route.switch("team")
        self.assertEqual(self.launchctl.value, "/fixture/another-user-wrapper")
        self.assertEqual(self.launchctl.mutations, [])
        self.assertEqual(self.config.read_bytes(), self.initial)
        self.core.ensure_tunnel.assert_not_called()

    def test_team_connection_failure_does_not_change_configuration_or_environment(self):
        self.core.ensure_tunnel.side_effect = legacy.SafeError("fixture tunnel unavailable")
        with self.assertRaises(legacy.SafeError):
            route.switch("team")
        self.assert_no_mutation()

    def test_concurrent_edit_during_tunnel_check_is_preserved(self):
        unknown = self.initial + b"# another process edited during check\n"
        self.core.ensure_tunnel.side_effect = lambda *a: self.safe_atomic_write(self.config, unknown)
        with self.assertRaises(route.SafeError):
            route.switch("team")
        self.assert_no_mutation(unknown)

    def test_environment_registration_failure_before_mutation_is_safe(self):
        self.launchctl.fail_set_before = True
        with self.assertRaises(route.SafeError):
            route.switch("original")
        self.assertIsNone(self.launchctl.value)
        self.assertEqual(self.config.read_bytes(), self.initial)
        self.assertFalse(route.manifest()["enabled"])
        self.assertEqual(route.validated_config()[0], "team")

    def test_environment_registration_failure_after_mutation_restores_previous_value(self):
        self.launchctl.fail_set_after = True
        with self.assertRaises(route.SafeError):
            route.switch("original")
        self.assertIsNone(self.launchctl.value)
        self.assertEqual(self.config.read_bytes(), self.initial)
        self.assertFalse(route.manifest()["enabled"])
        self.assertIn(["/bin/launchctl", "unsetenv", route.ENV_KEY], self.launchctl.mutations)

    def test_failure_saving_state_restores_config_and_prior_startup_environment(self):
        self.launchctl.value = "/fixture/prior-codex-wrapper"
        self.write_backup_manifest(self.launchctl.value)
        with mock.patch.object(route, "save_manifest", side_effect=OSError("fixture write failure")):
            with self.assertRaises(OSError):
                route.switch("original")
        self.assertEqual(self.config.read_bytes(), self.initial)
        self.assertEqual(self.launchctl.value, "/fixture/prior-codex-wrapper")
        self.assertFalse(route.manifest()["enabled"])
        self.assert_sentinels()

    def test_config_write_failure_restores_startup_environment(self):
        def fail_config(path, data, mode=0o600):
            if Path(path) == self.config:
                raise OSError("fixture config write failure")
            self.safe_atomic_write(path, data, mode)

        self.core.atomic_write.side_effect = fail_config
        with self.assertRaises(OSError):
            route.switch("original")
        self.assertEqual(self.config.read_bytes(), self.initial)
        self.assertIsNone(self.launchctl.value)
        self.assertFalse(route.manifest()["enabled"])

    def test_concurrent_edit_after_registration_is_preserved_and_environment_restored(self):
        unknown = self.initial + b"# another process edited while registering\n"
        self.launchctl.after_set = lambda: self.safe_atomic_write(self.config, unknown)
        with self.assertRaises(route.SafeError):
            route.switch("original")
        self.assertEqual(self.config.read_bytes(), unknown)
        self.assertIsNone(self.launchctl.value)
        self.assertFalse(route.manifest()["enabled"])

    def test_switch_backup_contains_exact_previous_config_and_private_permissions(self):
        route.switch("original")
        files = list((self.state / "切换前备份").glob("*.toml"))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].read_bytes(), self.initial)
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)

    def test_backup_content_tampering_prevents_switch_before_network(self):
        target = self.backup / self.backup_files[0]["backup"]
        self.safe_atomic_write(target, target.read_bytes() + b"# corrupted backup\n")
        with self.assertRaises(route.SafeError):
            route.switch("team")
        self.assert_no_mutation()
        self.core.ensure_tunnel.assert_not_called()

    def test_backup_path_traversal_is_rejected(self):
        value = json.loads((self.backup / "备份清单.json").read_bytes())
        value["files"][0]["backup"] = "../outside.toml"
        self.safe_atomic_write(self.backup / "备份清单.json", json.dumps(value).encode())
        with self.assertRaises(route.SafeError):
            route.validate_backup(self.backup)

    def test_app_update_prevents_activation_and_live_route_resolution(self):
        self.safe_atomic_write(self.binary, b"fixture-changed-app-server\n", 0o700)
        with self.assertRaises(route.SafeError):
            route.switch("original")
        self.assert_no_mutation()
        value = route.manifest()
        value["enabled"] = True
        route.save_manifest(value)
        with self.assertRaises(route.SafeError):
            route.load_route()

    def test_disabled_route_cannot_be_used_by_proxy(self):
        with self.assertRaises(route.SafeError):
            route.load_route()
        self.assertFalse(route.route_enabled())

    def test_symlinked_config_and_world_readable_private_state_fail_closed(self):
        saved = self.config.with_name("original-fixture-config.toml")
        self.config.rename(saved)
        self.config.symlink_to(saved)
        with self.assertRaises(route.SafeError):
            route.switch("team")
        self.config.unlink()
        saved.rename(self.config)
        self.state.chmod(0o755)
        with self.assertRaises(route.SafeError):
            route.manifest()
        self.state.chmod(0o700)
        self.assert_no_mutation()

    def test_rollback_restores_exact_backup_files_modes_and_prior_startup_environment(self):
        self.launchctl.value = "/fixture/prior-codex-wrapper"
        self.write_backup_manifest(self.launchctl.value)
        self.install_files()
        route.switch("original")
        before_rollback = self.config.read_bytes()
        route.rollback(self.backup)
        self.assertEqual(self.launchctl.value, "/fixture/prior-codex-wrapper")
        self.assertFalse(route.manifest()["enabled"])
        for item in self.backup_files:
            path = Path(item["path"])
            self.assertEqual(path.read_bytes(), (self.backup / item["backup"]).read_bytes())
            self.assertEqual(path.stat().st_mode & 0o777, item["mode"])
        self.assertEqual((self.state / "回滚前配置.toml").read_bytes(), before_rollback)
        self.assert_sentinels()

    def test_rollback_rejects_unknown_route_changes_without_touching_installed_files(self):
        self.install_files()
        route.switch("team")
        unknown = self.initial.replace(b'18318/v1', b'19999/v1')
        self.safe_atomic_write(self.config, unknown)
        entry_before, guide_before = self.entry.read_bytes(), self.guide.read_bytes()
        self.launchctl.calls.clear()
        with self.assertRaises(route.SafeError):
            route.rollback(self.backup)
        self.assertEqual(self.config.read_bytes(), unknown)
        self.assertEqual(self.entry.read_bytes(), entry_before)
        self.assertEqual(self.guide.read_bytes(), guide_before)
        self.assertEqual(self.launchctl.mutations, [])
        self.assertTrue(route.manifest()["enabled"])

    def test_rollback_accepts_user_settings_and_saves_them_before_restoration(self):
        self.install_files()
        route.switch("original")
        changed = self.config.read_bytes().replace(b'"high"', b'"xhigh"').replace(b'"gpt-6-astra"', b'"new-model"')
        self.safe_atomic_write(self.config, changed)
        route.rollback(self.backup)
        self.assertEqual((self.state / "回滚前配置.toml").read_bytes(), changed)
        self.assertEqual(route.validated_config()[0], "team")
        self.assertFalse(route.route_enabled())
        route.rollback(self.backup)
        self.assertEqual(route.manifest()["mode"], "team")

    def test_rollback_rejects_unknown_entry_changes_without_overwriting_them(self):
        self.install_files()
        route.switch("team")
        unknown = self.entry.read_bytes() + b"# user's later edit\n"
        self.safe_atomic_write(self.entry, unknown, 0o700)
        self.launchctl.calls.clear()
        with self.assertRaises(route.SafeError):
            route.rollback(self.backup)
        self.assertEqual(self.entry.read_bytes(), unknown)
        self.assertEqual(self.config.read_bytes(), self.initial)
        self.assertEqual(self.launchctl.mutations, [])
        self.assertTrue(route.manifest()["enabled"])

    def test_rollback_rejects_unrelated_environment_and_backup_path(self):
        self.install_files()
        route.switch("team")
        self.launchctl.value = "/fixture/unrelated-new-wrapper"
        self.launchctl.calls.clear()
        with self.assertRaises(route.SafeError):
            route.rollback(self.backup)
        with self.assertRaises(route.SafeError):
            route.rollback(self.base / "some-other-backup")
        self.assertEqual(self.launchctl.value, "/fixture/unrelated-new-wrapper")
        self.assertEqual(self.launchctl.mutations, [])
        self.assertTrue(route.manifest()["enabled"])

    def test_status_is_read_only_and_distinguishes_configuration_from_actual_requests(self):
        before = self.config.read_bytes()
        route.status()
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.launchctl.mutations, [])
        self.core.ensure_tunnel.assert_not_called()
        output = self.output.getvalue()
        self.assertIn("sg_team", output)
        self.assertIn("实际请求", output)
        self.assertIn("验收", output)

    def test_status_rejects_corrupted_nonselected_snapshot_instead_of_reporting_drift(self):
        snapshot = self.state / "original.toml"
        self.safe_atomic_write(snapshot, snapshot.read_bytes() + b"# corrupted unused snapshot\n")
        with self.assertRaises(route.SafeError) as raised:
            route.status()
        self.assertNotIsInstance(raised.exception, route.ConfigDrift)
        self.assertIn("哈希", str(raised.exception))
        self.assert_no_mutation()
        self.core.tunnel_running.assert_not_called()
        self.assertEqual(self.launchctl.calls, [])

    def test_check_and_stop_delegate_to_existing_helper_without_switching(self):
        old_umask = os.umask(0o077)
        try:
            for action in ("check", "stop"):
                route.main([action])
                self.core.main.assert_called_with([action, "--state-dir", str(self.legacy)])
        finally:
            os.umask(old_umask)
        self.assert_no_mutation()


if __name__ == "__main__":
    unittest.main(verbosity=2)
