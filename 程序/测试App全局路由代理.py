#!/usr/bin/env python3
"""代理的隔离协议/进程测试：只使用临时目录、假子进程及假控制器。"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock


WRAPPER_PATH = Path(__file__).with_name("App全局路由代理.py")
spec = importlib.util.spec_from_file_location("codex_global_route_proxy_under_test", WRAPPER_PATH)
assert spec is not None and spec.loader is not None
wrapper = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wrapper
spec.loader.exec_module(wrapper)


class FakeApp:
    def __init__(self, *, hang_on_eof: bool = False, keep_loaded: bool = False, descendant: bool = False):
        self.temp = tempfile.TemporaryDirectory(prefix="codex-global-route-proxy-test-")
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.capture = self.root / "received.jsonl"
        self.mode = self.root / "mode"
        self.enabled = self.root / "enabled"
        self.mode.write_text("team")
        self.enabled.write_text("true")
        self.controller = self.root / "controller.py"
        self.controller.write_text(textwrap.dedent(f"""
            from pathlib import Path
            ROOT = Path({str(self.root)!r})
            def route_enabled():
                enabled = (ROOT / 'enabled').read_text()
                if enabled not in ('true', 'false'):
                    raise ValueError('SECRET enabled material must never appear')
                return enabled == 'true'
            def load_route():
                mode = (ROOT / 'mode').read_text()
                providers = {{'team': 'sg_team', 'original': 'custom-api', 'personal': 'openai'}}
                if mode not in providers:
                    raise ValueError('SECRET key material must never appear')
                return {{'mode': mode, 'provider': providers[mode], 'state_dir': ROOT}}
        """))
        self.server = self.root / "fake-codex"
        self.server.write_text(f"#!{sys.executable}\n" + textwrap.dedent(f"""
            import json, os, signal, sys, time
            CAPTURE = {str(self.capture)!r}
            HANG = {hang_on_eof!r}
            KEEP_LOADED = {keep_loaded!r}
            DESCENDANT = {descendant!r}
            if HANG:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            def write(raw):
                sys.stdout.buffer.write(raw)
                sys.stdout.buffer.flush()
            def send(obj):
                write((json.dumps(obj, separators=(',', ':')) + '\\n').encode())
            loaded = {{}}
            descendant_pid = None
            if DESCENDANT:
                descendant_pid = os.fork()
                if descendant_pid == 0:
                    signal.signal(signal.SIGTERM, signal.SIG_IGN)
                    while True:
                        time.sleep(10)
            send({{'method':'ready','params':{{'pid':os.getpid(),'descendantPid':descendant_pid}}}})
            with open(CAPTURE, 'ab', buffering=0) as capture:
                for raw in sys.stdin.buffer:
                    capture.write(raw)
                    try:
                        request = json.loads(raw)
                    except Exception:
                        write(raw)
                        continue
                    method = request.get('method')
                    if method == 'rawecho':
                        write(raw)
                    elif method == 'partial':
                        write(b'{{"method":"partial_event","params":')
                        print('PARTIAL_SENT', file=sys.stderr, flush=True)
                        time.sleep(0.15)
                        write(b'{{"value":1}}}}\\n')
                    elif method == 'server/request':
                        send({{'id':request['id'],'result':{{'ok':True}}}})
                        write(b'{{"id":"server-1","method":"item/commandExecution/requestApproval","params":{{"opaque":[1,"context"]}}}}\\n')
                    elif method in ('thread/start', 'thread/resume', 'thread/fork'):
                        params = request.get('params', {{}})
                        tid = params.get('threadId', 'new-' + str(request['id']))
                        if method == 'thread/fork':
                            tid = 'fork-' + str(request['id'])
                        if params.get('testResponseThreadId'):
                            tid = params['testResponseThreadId']
                        provider = params.get('modelProvider', 'custom-api')
                        if KEEP_LOADED and tid in loaded:
                            provider = loaded[tid]
                        loaded[tid] = provider
                        result = {{'modelProvider':provider, 'thread':{{'id':tid,'modelProvider':'custom-api','cwd':'/old/cwd','turns':[{{'id':'old-turn','opaque':'context'}}]}}}}
                        if params.get('testMissingTopLevel'):
                            del result['modelProvider']
                        send({{'id':request['id'],'result':result}})
                    elif method == 'exit':
                        sys.exit(request['params']['code'])
                    elif method is None:
                        send({{'method':'server_reply_received'}})
                    else:
                        send({{'id':request.get('id'),'result':{{'ok':True}}}})
            if HANG:
                while True:
                    time.sleep(10)
        """))
        self.server.chmod(0o700)
        driver = textwrap.dedent(f"""
            import importlib.util, pathlib, sys
            spec = importlib.util.spec_from_file_location('proxy_integration_child', {str(WRAPPER_PATH)!r})
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            raise SystemExit(module.run_proxy(['-c', 'features.code_mode_host=true', 'app-server', '--analytics-default-enabled'], real_binary={str(self.server)!r}, controller_path=pathlib.Path({str(self.controller)!r}), shutdown_grace=0.25, kill_grace=0.25))
        """)
        env = dict(os.environ)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        self.process = subprocess.Popen([sys.executable, "-B", "-c", driver], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, bufsize=0)
        self.buffer = bytearray()
        ready = self.read()
        assert ready["method"] == "ready", ready
        self.child_pid = ready["params"]["pid"]
        self.descendant_pid = ready["params"]["descendantPid"]

    def write(self, raw: bytes) -> None:
        assert self.process.stdin is not None
        view = memoryview(raw)
        while view:
            count = self.process.stdin.write(view)
            if count is None or count == 0:
                raise RuntimeError("input pipe closed")
            view = view[count:]

    def send(self, value: dict) -> None:
        self.write((json.dumps(value, ensure_ascii=False) + "\n").encode())

    def read_raw(self, timeout: float = 5) -> bytes:
        assert self.process.stdout is not None
        deadline = time.monotonic() + timeout
        while True:
            end = self.buffer.find(b"\n")
            if end >= 0:
                result = bytes(self.buffer[: end + 1])
                del self.buffer[: end + 1]
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("timed out waiting for protocol frame")
            readable, _, _ = select.select([self.process.stdout], [], [], remaining)
            if not readable:
                raise AssertionError("timed out waiting for protocol frame")
            raw = os.read(self.process.stdout.fileno(), 65536)
            if not raw:
                raise AssertionError(f"proxy output EOF, exit={self.process.poll()}")
            self.buffer.extend(raw)

    def read(self, timeout: float = 5) -> dict:
        return json.loads(self.read_raw(timeout))

    def received(self) -> list[dict]:
        return [json.loads(line) for line in self.capture.read_bytes().splitlines()]

    def logs(self) -> list[dict]:
        return [json.loads(line) for line in (self.root / wrapper.LOG_NAME).read_bytes().splitlines()]

    def finish(self, timeout: float = 5) -> int:
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        return self.process.wait(timeout=timeout)

    def close(self) -> None:
        if self.process.poll() is None:
            try:
                self.finish()
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=5)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()
        self.temp.cleanup()

    def __enter__(self) -> "FakeApp":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


class TransformTests(unittest.TestCase):
    def test_only_provider_spelling_changes_and_context_is_exact(self):
        source = b'  { "id" : "escaped\\u0031", "method":"thread/resume", "params" : {"threadId":"old-thread", "modelProvider":null, "cwd":"/old/cwd", "history":[{"number":1.23000e-9999,"opaque":"a\\u0062"}], "config":{"model_provider":"custom-api","other": 90071992547409931234567890123456789}, "approvalPolicy":"never", "sandbox":"workspace-write" }, "future":{"modelProvider":"leave-this"} }\r\n'
        expected = source.replace(b'"modelProvider":null', b'"modelProvider":"sg_team"').replace(b'"model_provider":"custom-api"', b'"model_provider":"sg_team"')
        self.assertEqual(wrapper.transform_request(source, "sg_team"), expected)

    def test_insert_with_whitespace_and_original_symmetry(self):
        raw = b'{"id":4,"method":"thread/resume","params":{"threadId":"old"  }}\n'
        team = wrapper.transform_request(raw, "sg_team")
        self.assertEqual(team, b'{"id":4,"method":"thread/resume","params":{"threadId":"old"  ,"modelProvider":"sg_team"}}\n')
        self.assertEqual(wrapper.transform_request(team, "custom-api"), team.replace(b'"sg_team"', b'"custom-api"'))
        self.assertEqual(wrapper.transform_request(team, "openai"), team.replace(b'"sg_team"', b'"openai"'))

    def test_start_without_params_and_empty_params(self):
        for raw in (b'{"id":1,"method":"thread/start"}\n', b'{"id":1,"method":"thread/start","params":{}}\n'):
            self.assertEqual(json.loads(wrapper.transform_request(raw, "sg_team"))["params"], {"modelProvider": "sg_team"})

    def test_unknown_and_responses_preserved(self):
        cases = [b' {"method":"turn/start","id":1,"params":{"modelProvider":null,"input":["hello"]}}\n', b'{"id":"server-1","result":{"decision":"accept"}}\n', b'{broken json\n', b'\xff\n', b'{"method":"thread/read","params":{"threadId":"old"}}\n']
        for raw in cases:
            self.assertEqual(wrapper.transform_request(raw, "sg_team"), raw)

    def test_ambiguous_route_fields_rejected(self):
        for params in ('null', '[]', '{"modelProvider":"a","modelProvider":"b"}', '{"config":3}', '{"config":{"model_provider":"a","model_provider":"b"}}'):
            with self.assertRaises(wrapper.InvalidRoutedRequest):
                wrapper.transform_request(('{"id":1,"method":"thread/resume","params":' + params + '}\n').encode(), "sg_team")

    def test_error_preserves_id_and_never_leaks_internal_exception(self):
        raw = b'{"jsonrpc":"2.0","id":90071992547409931234567890,"method":"thread/resume","params":{}}\n'
        req = wrapper.parse_routed_request(raw)
        response = wrapper.route_error(req)
        self.assertIn(b'"id":90071992547409931234567890', response)
        self.assertEqual(json.loads(response)["error"]["code"], -32098)
        self.assertLess(len(response), 400)
        notification = wrapper.parse_routed_request(b'{"method":"thread/resume","params":{}}\n')
        self.assertIsNone(wrapper.route_error(notification))

    def test_actual_serve_detection_and_helper_passthrough(self):
        for args in (["app-server"], ["-c", "features.code_mode_host=true", "app-server", "--analytics-default-enabled"], ["--config=x=y", "app-server", "--listen", "stdio://"], ["app-server", "--stdio", "--strict-config", "--code-mode-host", "/path with spaces"]):
            self.assertTrue(wrapper.is_app_server_serve(args), args)
        for args in (["--version"], ["exec", "app-server"], ["-c", "app-server", "exec"], ["app-server", "generate-json-schema"], ["app-server", "generate-ts"], ["app-server", "proxy"], ["app-server", "daemon"], ["app-server", "--help"], ["app-server", "--listen", "ws://127.0.0.1:1234"], ["app-server", "unknown-helper"]):
            self.assertFalse(wrapper.is_app_server_serve(args), args)

    def test_non_server_uses_exec_with_exact_arguments(self):
        args = ["-c", "a=b c", "exec", "literal $() and spaces"]
        with mock.patch.object(wrapper.os, "execv") as execute:
            self.assertEqual(wrapper.main(args), 127)
        execute.assert_called_once_with(wrapper.REAL_CODEX, [wrapper.REAL_CODEX, *args])


class ProtocolTests(unittest.TestCase):
    def test_existing_fork_uses_new_result_thread_id_and_does_not_synthesize_turn(self):
        with FakeApp() as app:
            app.send({"id":1,"method":"thread/fork","params":{"threadId":"source-old","cwd":"/old/cwd","config":{"model_provider":"custom-api"}}})
            result = app.read()["result"]
            self.assertEqual(result["modelProvider"], "sg_team")
            self.assertEqual(result["thread"]["id"], "fork-1")
            self.assertEqual([v["method"] for v in app.received()], ["thread/fork"])
            app.send({"id":2,"method":"turn/start","params":{"threadId":"fork-1","input":["new fork turn"]}})
            self.assertTrue(app.read()["result"]["ok"])
            app.send({"id":3,"method":"turn/start","params":{"threadId":"source-old","input":["source not resumed"]}})
            self.assertEqual(app.read()["error"]["code"], -32099)
            self.assertEqual([v["id"] for v in app.received()], [1, 2])

    def test_resume_uses_authoritative_result_thread_id(self):
        with FakeApp() as app:
            app.send({"id":1,"method":"thread/resume","params":{"threadId":"ignored-source","testResponseThreadId":"path-thread","path":"/opaque/history/path"}})
            self.assertEqual(app.read()["result"]["thread"]["id"], "path-thread")
            app.send({"id":2,"method":"turn/start","params":{"threadId":"path-thread","input":["continue"]}})
            self.assertTrue(app.read()["result"]["ok"])

    def test_resume_no_turn_injection_and_original_team_reloaded(self):
        with FakeApp() as app:
            first = {"id":1,"method":"thread/resume","params":{"threadId":"old","modelProvider":"custom-api","cwd":"/old/cwd","history":[{"opaque":"context"}],"config":{"model_provider":"custom-api","unrelated":4}}}
            app.send(first)
            reply = app.read()
            self.assertEqual(reply["result"]["modelProvider"], "sg_team")
            self.assertEqual(reply["result"]["thread"]["modelProvider"], "custom-api")
            received = app.received()
            self.assertEqual([item["method"] for item in received], ["thread/resume"])
            expected = json.loads(json.dumps(first))
            expected["params"]["modelProvider"] = "sg_team"
            expected["params"]["config"]["model_provider"] = "sg_team"
            self.assertEqual(received, [expected])
            app.mode.write_text("original")
            app.send({"id":2,"method":"thread/start","params":{"cwd":"/new"}})
            self.assertEqual(app.read()["result"]["modelProvider"], "custom-api")
            self.assertEqual(app.finish(), 0)
            self.assertEqual([entry["provider"] for entry in app.logs() if entry["event"] == "route_request"], ["sg_team", "custom-api"])
            self.assertEqual(stat.S_IMODE((app.root / wrapper.LOG_NAME).stat().st_mode), 0o600)

    def test_personal_resume_and_turn_are_forced_to_openai(self):
        with FakeApp() as app:
            app.mode.write_text("personal")
            app.send({"id":1,"method":"thread/resume","params":{"threadId":"old-team","modelProvider":"sg_team"}})
            self.assertEqual(app.read()["result"]["modelProvider"], "openai")
            app.send({"id":2,"method":"turn/start","params":{"threadId":"old-team","input":["continue"]}})
            self.assertTrue(app.read()["result"]["ok"])
            self.assertEqual(app.received()[0]["params"]["modelProvider"], "openai")
            self.assertTrue(any(v["event"] == "turn_forwarded" and v["provider"] == "openai" for v in app.logs()))

    def test_matching_turn_exact_and_live_switch_blocks_before_generation(self):
        with FakeApp(keep_loaded=True) as app:
            app.send({"id":1,"method":"thread/resume","params":{"threadId":"old"}})
            self.assertEqual(app.read()["result"]["modelProvider"], "sg_team")
            raw_turn = b' { "id":2,"method":"turn/start","params":{"threadId":"old","input":[{"type":"text","text":"sensitive prompt stays out of logs"}],"opaque":1.20000} }\n'
            app.write(raw_turn)
            self.assertTrue(app.read()["result"]["ok"])
            self.assertIn(raw_turn, app.capture.read_bytes())
            app.mode.write_text("original")
            app.send({"id":3,"method":"thread/resume","params":{"threadId":"old"}})
            reply = app.read()
            self.assertEqual(reply["result"]["modelProvider"], "sg_team")
            app.send({"id":4,"method":"turn/start","params":{"threadId":"old","input":["must not reach provider"]}})
            self.assertEqual(app.read()["error"]["code"], -32099)
            self.assertEqual([v["id"] for v in app.received()], [1, 2, 3])
            app.finish()
            logs = app.logs()
            self.assertTrue(any(v["event"] == "route_mismatch" for v in logs))
            log_bytes = (app.root / wrapper.LOG_NAME).read_bytes()
            self.assertNotIn(b"sensitive prompt", log_bytes)
            self.assertNotIn(b"must not reach provider", log_bytes)

    def test_historical_nested_provider_cannot_authorize_turn(self):
        with FakeApp() as app:
            app.mode.write_text("original")
            app.send({"id":1,"method":"thread/resume","params":{"threadId":"old","testMissingTopLevel":True}})
            result = app.read()["result"]
            self.assertNotIn("modelProvider", result)
            self.assertEqual(result["thread"]["modelProvider"], "custom-api")
            app.send({"id":2,"method":"turn/start","params":{"threadId":"old"}})
            self.assertEqual(app.read()["error"]["code"], -32099)
            self.assertEqual(len(app.received()), 1)

    def test_disabled_passthrough_and_invalid_state_fails_closed(self):
        with FakeApp() as app:
            app.enabled.write_text("false")
            raw = b'{ "id":1,"method":"thread/resume","params":{"threadId":"old","modelProvider":"custom-api"} }\n'
            app.write(raw)
            self.assertEqual(app.read()["result"]["modelProvider"], "custom-api")
            self.assertEqual(app.capture.read_bytes(), raw)
            app.enabled.write_text("true")
            app.mode.write_text("invalid")
            app.send({"jsonrpc":"2.0","id":2,"method":"thread/resume","params":{"threadId":"old"}})
            error = app.read()
            self.assertEqual(error["jsonrpc"], "2.0")
            self.assertEqual(error["error"]["code"], -32098)
            app.send({"id":3,"method":"initialize","params":{"anything":"preserved"}})
            self.assertTrue(app.read()["result"]["ok"])
            self.assertEqual([v["id"] for v in app.received()], [1, 3])
            app.finish()
            self.assertNotIn("SECRET", json.dumps(app.logs()))

    def test_bidirectional_server_requests_and_unknown_methods(self):
        with FakeApp() as app:
            app.send({"id":1,"method":"server/request","params":{"future":"opaque"}})
            self.assertTrue(app.read()["result"]["ok"])
            request = app.read_raw()
            self.assertEqual(request, b'{"id":"server-1","method":"item/commandExecution/requestApproval","params":{"opaque":[1,"context"]}}\n')
            reply = b' {"id":"server-1", "result":{"decision":"accept","future":[42,"opaque"]}}\n'
            app.write(reply)
            self.assertEqual(app.read()["method"], "server_reply_received")
            self.assertIn(reply, app.capture.read_bytes())

    def test_large_frames_backpressure_stdout_byte_exact(self):
        with FakeApp() as app:
            raw = b'{"id":1,"method":"rawecho","params":{"data":"' + b"x" * (3 * 1024 * 1024 + 117) + b'","number":1.23000e-9999}}\n'
            app.write(raw)
            self.assertEqual(app.read_raw(timeout=15), raw)
            self.assertEqual(app.capture.read_bytes(), raw)
            self.assertEqual(app.finish(), 0)

    def test_partial_child_stdout_and_local_error_never_interleave(self):
        with FakeApp() as app:
            app.send({"id":1,"method":"partial"})
            assert app.process.stderr is not None
            readable, _, _ = select.select([app.process.stderr], [], [], 3)
            self.assertTrue(readable)
            self.assertEqual(app.process.stderr.readline(), b"PARTIAL_SENT\n")
            app.mode.write_text("invalid")
            app.send({"id":2,"method":"thread/resume","params":{"threadId":"old"}})
            frames = [app.read(), app.read()]
            self.assertEqual({frame.get("method", "error") for frame in frames}, {"partial_event", "error"})
            self.assertEqual(next(frame for frame in frames if "error" in frame)["error"]["code"], -32098)
            self.assertEqual(len(app.received()), 1)

    def test_eof_reaps_child_even_when_it_ignores_shutdown(self):
        with FakeApp(hang_on_eof=True) as app:
            self.assertEqual(app.finish(timeout=5), 128 + signal.SIGKILL)
            with self.assertRaises(ProcessLookupError):
                os.kill(app.child_pid, 0)

    def test_eof_stops_owned_descendant_after_direct_child_exits(self):
        with FakeApp(descendant=True) as app:
            self.assertEqual(app.finish(timeout=5), 0)
            with self.assertRaises(ProcessLookupError):
                os.kill(app.child_pid, 0)
            try:
                os.kill(app.descendant_pid, 0)
            except ProcessLookupError:
                pass
            else:
                # PID 1 can briefly retain a killed descendant as a zombie.
                status = subprocess.check_output(["ps", "-o", "stat=", "-p", str(app.descendant_pid)], text=True).strip()
                self.assertTrue(status.startswith("Z"), status)

    def test_signal_forwarding_and_child_exit_status(self):
        with FakeApp() as app:
            app.process.send_signal(signal.SIGTERM)
            self.assertEqual(app.process.wait(timeout=5), 128 + signal.SIGTERM)
            with self.assertRaises(ProcessLookupError):
                os.kill(app.child_pid, 0)
        with FakeApp() as app:
            app.send({"id":1,"method":"exit","params":{"code":7}})
            self.assertEqual(app.process.wait(timeout=5), 7)


class AuditTests(unittest.TestCase):
    def test_symlink_and_hardlink_logs_cannot_overwrite_other_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            target = root / "protected"
            target.write_bytes(b"keep-me")
            target.chmod(0o600)
            log = root / wrapper.LOG_NAME
            log.symlink_to(target)
            wrapper.Audit(root).write("test", provider="sg_team")
            self.assertEqual(target.read_bytes(), b"keep-me")
            log.unlink()
            os.link(target, log)
            wrapper.Audit(root).write("test", provider="sg_team")
            self.assertEqual(target.read_bytes(), b"keep-me")

    def test_private_bounded_log_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            preserved = root / "untouched"
            preserved.write_bytes(b"keep")
            with mock.patch.object(wrapper, "LOG_LIMIT", 1024):
                for _ in range(40):
                    wrapper.Audit(root).write("route_request", provider="sg_team", method="thread/resume", threadId="old")
            log = root / wrapper.LOG_NAME
            self.assertLessEqual(log.stat().st_size, 1024)
            self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
            self.assertEqual(preserved.read_bytes(), b"keep")
            for line in log.read_bytes().splitlines():
                self.assertIsInstance(json.loads(line), dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
