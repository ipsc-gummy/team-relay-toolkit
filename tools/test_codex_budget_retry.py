#!/usr/bin/env python3
"""Opt-in bundled Codex CLI budget/retry test; all inference is a loopback fixture."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.server
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
from typing import NamedTuple


MARKER = "BUDGET_PROBE_COMPLETED"
DENIAL = "Budget probe: member allowance exhausted."
MODEL = "gpt-6-astra"
FAKE_TOKEN = "fake-budget-probe-token"
MAC_SANDBOX = Path("/usr/bin/sandbox-exec")


class Case(NamedTuple):
    name: str
    status: int
    code: str
    calls: int
    no_retries: bool = False
    retry_after: bool = False


# Source version baseline: rust-v0.169.0-alpha.11.1. A newer client's changed
# behavior should fail the matrix instead of silently certifying zero retries.
CASES = (
    Case("success", 200, "", 1),
    Case("budget_403_default", 403, "member_budget_exhausted", 6),
    Case("budget_402_default", 402, "member_budget_exhausted", 6),
    Case("budget_400_native", 400, "budget_reached", 1),
    Case("budget_403_zero", 403, "member_budget_exhausted", 1, True),
    Case("budget_402_zero", 402, "member_budget_exhausted", 1, True),
    Case("rate_429_default", 429, "rate_limit_exceeded", 1),
    Case("rate_429_retry_after", 429, "rate_limit_exceeded", 6, False, True),
    Case("rate_429_zero", 429, "rate_limit_exceeded", 1, True, True),
    Case("service_503_zero", 503, "service_unavailable", 1, True),
)


def success_stream():
    part = {"type": "output_text", "text": MARKER, "annotations": []}
    item = {"id": "msg_probe", "type": "message", "role": "assistant", "status": "completed", "content": [part]}
    response = {"id": "resp_probe", "object": "response", "created_at": 0, "status": "completed", "model": MODEL,
                "output": [item], "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
    events = [
        {"type": "response.created", "response": dict(response, status="in_progress", output=[])},
        {"type": "response.output_item.added", "output_index": 0, "item": dict(item, status="in_progress", content=[])},
        {"type": "response.output_text.delta", "item_id": "msg_probe", "output_index": 0, "content_index": 0,
         "delta": MARKER},
        {"type": "response.output_item.done", "output_index": 0, "item": item},
        {"type": "response.completed", "response": response},
    ]
    return "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events).encode()


def run_case(codex, case):
    counter = {"responses": 0, "bad": 0, "blocked_external": 0}
    lock = threading.Lock()

    class Fixture(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # Never print headers, request bodies, or any user data.

        def reply(self, status, kind, body, extra=None):
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            if extra:
                self.send_header(*extra)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path.split("?", 1)[0] in ("/v1/models", "/v1/models/" + MODEL):
                return self.reply(200, "application/json", json.dumps({"object": "list", "data": [{"id": MODEL}]}).encode())
            if self.path.startswith(("http://", "https://")):
                return self.do_CONNECT()  # Fail closed if a proxy fallback is ever attempted.
            return self.reply(404, "application/json", b"{}")

        def do_CONNECT(self):
            with lock:
                counter["blocked_external"] += 1
            self.reply(403, "application/json", b"{}")

        def do_POST(self):
            if self.path.startswith(("http://", "https://")):
                return self.do_CONNECT()
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 2 * 1024 * 1024:
                    raise ValueError("unexpected length")
                request = json.loads(self.rfile.read(length))
                if (self.path != "/v1/responses" or self.headers.get("Authorization") != "Bearer " + FAKE_TOKEN
                        or request.get("model") != MODEL or request.get("stream") is not True):
                    raise ValueError("unexpected request")
            except (OSError, TypeError, ValueError, AttributeError):
                with lock:
                    counter["bad"] += 1
                return self.reply(400, "application/json", b"{}")
            with lock:
                counter["responses"] += 1
            if case.status == 200:
                return self.reply(200, "text/event-stream", success_stream())
            body = json.dumps({"error": {"message": DENIAL, "type": case.code, "code": case.code}}).encode()
            extra = ("Retry-After", "0") if case.retry_after else None
            return self.reply(case.status, "application/json", body, extra)

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Fixture) as server, \
            tempfile.TemporaryDirectory(prefix="codex-budget-test-") as directory:
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            root = Path(directory)
            home = root / "home"
            codex_home = root / "codex"
            work = root / "work"
            for path in (home, codex_home, work):
                path.mkdir(mode=0o700)
            endpoint = f"http://127.0.0.1:{server.server_port}"
            env = {"HOME": str(home), "CODEX_HOME": str(codex_home), "PATH": os.defpath, "TMPDIR": str(root),
                   "NO_PROXY": "127.0.0.1,localhost", "HTTP_PROXY": endpoint, "HTTPS_PROXY": endpoint,
                   "ALL_PROXY": endpoint, "TERM": "dumb", "BUDGET_PROBE_KEY": FAKE_TOKEN}
            config = ('model_provider = "budget_probe"\nmodel = ' + json.dumps(MODEL) + '\n'
                      'check_for_update_on_startup = false\ncli_auth_credentials_store = "file"\n'
                      'web_search = "disabled"\nchatgpt_base_url = ' + json.dumps(endpoint) + '\n'
                      'openai_base_url = ' + json.dumps(endpoint + "/v1") + '\n'
                      '[analytics]\nenabled = false\n[feedback]\nenabled = false\n'
                      '[model_providers.budget_probe]\nname = "Loopback budget test"\n'
                      'wire_api = "responses"\nrequires_openai_auth = false\nsupports_websockets = false\n'
                      'base_url = ' + json.dumps(endpoint + "/v1") + '\nenv_key = "BUDGET_PROBE_KEY"\n')
            if case.no_retries:
                config += "request_max_retries = 0\nstream_max_retries = 0\n"
            (codex_home / "config.toml").write_text(config, encoding="utf-8")
            cmd = [str(codex), "exec", "--skip-git-repo-check", "--ephemeral", "--sandbox", "read-only",
                   "--json", "--color", "never", "Loopback fixture; reply without tools."]
            network_fence = "linux_loopback_only_namespace_and_rejecting_proxy"
            if sys.platform == "darwin":
                profile = ('(version 1) (allow default) (deny network-outbound) '
                           f'(allow network-outbound (remote ip "localhost:{server.server_port}"))')
                cmd = [str(MAC_SANDBOX), "-p", profile, *cmd]
                network_fence = "macos_loopback_socket_allowlist_and_rejecting_proxy"
            result = subprocess.run(cmd, cwd=work, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, timeout=30, check=False)
        finally:
            server.shutdown()
            thread.join(timeout=2)
    events = []
    for raw in result.stdout.splitlines():
        try:
            parsed = json.loads(raw)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            events.append(parsed)
    event_types = {event.get("type") for event in events}
    if case.status == 200:
        outcome = result.returncode == 0 and "turn.completed" in event_types and any(
            event.get("type") == "item.completed" and event.get("item", {}).get("text") == MARKER for event in events)
    else:
        failures = [json.dumps(event).lower() for event in events if event.get("type") in ("turn.failed", "error")]
        if case.status == 429:
            reported = any(re.search(r"\b429\b", failure) for failure in failures)
        else:
            error_mark = "budget reached" if case.code == "budget_reached" else DENIAL
            reported = any(error_mark.lower() in failure for failure in failures)
        outcome = result.returncode != 0 and "turn.failed" in event_types and reported
    passed = counter["bad"] == 0 and counter["responses"] == case.calls and outcome
    return {"case": case.name, "status": case.status, "calls": counter["responses"], "expected": case.calls,
            "unexpected": counter["bad"], "blocked_external": counter["blocked_external"],
            "network_fence": network_fence, "terminal_event_verified": outcome, "exit": result.returncode,
            "pass": passed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path, required=True, help="Explicit path to the trusted installed Codex binary")
    parser.add_argument("--case", action="append", choices=[case.name for case in CASES], help="Run selected case(s)")
    args = parser.parse_args()
    if sys.platform == "darwin":
        if not os.access(MAC_SANDBOX, os.X_OK):
            parser.error("macOS sandbox-exec is required for the loopback-only test")
    elif (sys.platform != "linux" or {name for _, name in socket.if_nameindex()} != {"lo"}
          or os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net")):
        parser.error("run only on macOS with sandbox-exec or in a separate loopback-only Linux namespace")
    codex = args.codex.resolve(strict=True)
    if not codex.is_file() or not os.access(codex, os.X_OK):
        parser.error("--codex must be an executable file")
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda case: run_case(codex, case),
                                (case for case in CASES if not args.case or case.name in args.case)))
    for result in results:
        print(json.dumps(result), flush=True)
    return 0 if all(result["pass"] for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
