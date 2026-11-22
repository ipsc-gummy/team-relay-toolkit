#!/usr/bin/env python3
"""Opt-in Mac Codex app-server -> generated member helper -> local ledger test."""

import argparse
from contextlib import contextmanager
from email.message import Message
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
from queue import Empty, Queue
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread
import time
import tomllib
from unittest.mock import patch

from member_dollar_cap import MODEL, Policy, make_server
from pilot_budget import PilotBudget
from test_codex_member_flow import (CASE, FIRST, MAC_SANDBOX, MEMBER, PROJECT, RESUME, TOKEN,
                                    has_tool_result, load_script, message, stream, tool_call)


PROVIDER = "sg_team_budget"


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def generated_config(root, home, port):
    packer = load_script("mac_member_probe_packer", PROJECT / "程序" / "打包新人两步接入.py")
    host_key, member_key = (root / key for key in ("fixture_host", "fixture_member"))
    env = {"HOME": str(home), "CODEX_HOME": str(home / ".codex"), "TMPDIR": str(root), "PATH": os.defpath}
    for key in (host_key, member_key):
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                       check=True, timeout=5, env=env)
    deployment = packer.load_deployment("127.0.0.1", host_key.with_suffix(".pub"), port)
    fingerprint = subprocess.check_output(["/usr/bin/ssh-keygen", "-lf", str(member_key.with_suffix(".pub"))],
                                          timeout=5, env=env).decode().split()[1]
    bundle = packer.build_payload(MEMBER, fingerprint, TOKEN, platform="macos",
                                  deployment=deployment, budget_mac=True)
    for relative, data in bundle.items():
        path = root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)
    base = f"http://127.0.0.1:{port}"
    baseline = ('model_context_window = 400000\ncheck_for_update_on_startup = false\n'
                'cli_auth_credentials_store = "file"\n'
                f'chatgpt_base_url = "{base}"\nopenai_base_url = "{base}/v1"\n'
                '[analytics]\nenabled = false\n[feedback]\nenabled = false\n').encode()
    personal = home / ".codex/config.toml"
    personal.parent.mkdir(mode=0o700)
    personal.write_bytes(baseline)
    cmd = [str(MAC_SANDBOX), "-p", "(version 1) (allow default) (deny network-outbound)",
           str(Path(sys.executable).absolute()), "-B", str(root / "Codex团队接入/程序/一键接入.py"),
           "prepare", "--ssh-key", str(member_key)]
    process = subprocess.run(cmd, cwd=root, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    require(process.returncode == 0 and b"MAC_CODEX_BACKEND=" in process.stdout, "packaged Mac prepare failed")
    state = home / ".codex-sg-budget"
    require(personal.read_bytes() == baseline and (state / "personal.toml").read_bytes() == baseline,
            "prepare modified the local temporary personal config")
    config = (state / "team.toml").read_bytes()
    parsed = tomllib.loads(config.decode())
    require(parsed["model_provider"] == PROVIDER and parsed["model"] == MODEL, "unexpected provider or model")
    provider = parsed["model_providers"][PROVIDER]
    require(provider.get("request_max_retries") == provider.get("stream_max_retries") == 0
            and provider.get("supports_websockets") is False and "auth" in provider,
            "budget provider lacks its command credential, zero retries, or HTTP-only transport")
    # The package's SSH listener is deliberately not started in this Mac test. Substitute the fake gateway's local
    # port in the isolated client configuration only; leave prepared state and route/credentials untouched.
    default_base = provider["base_url"]
    require(default_base == "http://127.0.0.1:18318/v1", "unexpected package default local port")
    field = f'base_url = "{default_base}"'.encode()
    require(config.count(field) == 1, "unexpected prepared provider field shape")
    return config.replace(field, f'base_url = "{base}/v1"'.encode())


@contextmanager
def app_server(codex, home, codex_home, work, port):
    base = f"http://127.0.0.1:{port}"
    env = {"HOME": str(home), "CODEX_HOME": str(codex_home), "TMPDIR": str(work), "PATH": os.defpath,
           "NO_PROXY": "127.0.0.1,localhost", "HTTP_PROXY": base, "HTTPS_PROXY": base, "ALL_PROXY": base}
    profile = ('(version 1) (allow default) (deny network-outbound) '
               f'(allow network-outbound (remote ip "localhost:{port}"))')
    runner = subprocess.Popen([str(MAC_SANDBOX), "-p", profile, str(codex), "app-server"], cwd=work, env=env,
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, encoding="utf-8", bufsize=1)
    inbox = Queue()

    def receive():
        try:
            for line in runner.stdout:
                try:
                    msg = json.loads(line)
                except ValueError:
                    continue
                if isinstance(msg, dict):
                    inbox.put(msg)
        finally:
            inbox.put(None)

    def send(msg):
        runner.stdin.write(json.dumps(msg) + "\n")
        runner.stdin.flush()

    notifications = []

    def wait_for(predicate, timeout=12):
        end = time.monotonic() + timeout
        while (remaining := end - time.monotonic()) > 0:
            try:
                msg = inbox.get(timeout=remaining)
            except Empty:
                break
            require(msg is not None, "app-server exited before response")
            if "method" in msg and "id" in msg:
                send({"id": msg["id"], "error": {"code": -32601, "message": "No external tool permitted"}})
            else:
                if "method" in msg:
                    notifications.append(msg)
                if predicate(msg):
                    return msg
        raise RuntimeError("app-server response timed out")

    ids = iter(range(1, 20))

    def call(method, params):
        call_id = next(ids)
        send({"id": call_id, "method": method, "params": params})
        reply = wait_for(lambda msg: msg.get("id") == call_id)
        require("result" in reply, f"app-server rejected {method}")
        return reply["result"]

    reader = Thread(target=receive, daemon=True)
    reader.start()
    try:
        call("initialize", {"clientInfo": {"name": "mac_member_probe", "version": "1.0"}})
        send({"method": "initialized", "params": {}})
        yield call, wait_for, notifications
    finally:
        runner.stdin.close()
        try:
            runner.wait(timeout=3)
        except subprocess.TimeoutExpired:
            runner.terminate()
            try:
                runner.wait(timeout=2)
            except subprocess.TimeoutExpired:
                runner.kill()
                runner.wait(timeout=2)
        reader.join(timeout=2)
        runner.stdout.close()


def run(codex):
    upstream = []
    local = []
    prepare = Policy.prepare

    def trace(policy, payload):
        local.append(1)
        return prepare(policy, payload)

    @contextmanager
    def fixture(payload):
        data = json.loads(payload)
        upstream.append(data)
        n = len(upstream)
        if n == 1:
            item = tool_call(data)
        elif n in (2, 3) and has_tool_result(data["input"]) and CASE in json.dumps(data["input"]):
            item = message(n, FIRST if n == 2 else RESUME)
        else:
            raise ValueError("expected one retained tool result and original prompt")
        response = BytesIO(stream(n, item))
        response.status, response.length, response.headers = 200, 0, Message()
        response.headers["Content-Type"] = "text/event-stream"
        yield response

    def turn(call, wait, notifications, thread_id, prompt, status, marker=None):
        count_before = len(notifications)
        started = call("turn/start", {"threadId": thread_id, "input": [{"type": "text", "text": prompt}]})
        turn_id = started["turn"]["id"]
        done = wait(lambda msg: msg.get("method") == "turn/completed" and
                    msg.get("params", {}).get("turn", {}).get("id") == turn_id)["params"]["turn"]
        require(done.get("status") == status, f"expected {status} turn; gateway={len(local)} upstream={len(upstream)}")
        if marker:
            require(any(event.get("method") == "item/completed"
                        and event.get("params", {}).get("turnId") == turn_id
                        and event.get("params", {}).get("item", {}).get("text") == marker
                        for event in notifications[count_before:]), "expected completed fixture response item")
        if status == "failed":
            errors = json.dumps([done, *notifications[count_before:]]).lower()
            require("budget reached" in errors or "budget_reached" in errors,
                    "the failed turn did not report exhausted budget")

    with TemporaryDirectory(prefix="mac-desktop-member-") as temporary:
        root = Path(temporary).resolve()
        home, codex_home, work = (root / name for name in ("home", "codex", "work"))
        for p in (home, codex_home, work):
            p.mkdir(mode=0o700)
        ledger = PilotBudget.create(root / "budget.sqlite")
        ledger.add_member(MEMBER, 100_000_000_000)
        members = {sha256(TOKEN.encode()).hexdigest(): MEMBER}
        with patch.object(Policy, "prepare", trace), make_server(
            listen_port=0, ledger=ledger, members=members, upstream=fixture,
        ) as server:
            port = server.server_port
            (codex_home / "config.toml").write_bytes(generated_config(root, home, port))
            worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            worker.start()
            try:
                with app_server(codex, home, codex_home, work, port) as (call, wait, notifications):
                    started = call("thread/start", {"model": MODEL, "modelProvider": PROVIDER, "cwd": str(work),
                                                    "approvalPolicy": "never", "sandbox": "read-only"})
                    require(started.get("modelProvider") == PROVIDER, "unexpected provider")
                    thread_id = started["thread"]["id"]
                    turn(call, wait, notifications, thread_id, CASE, "completed", FIRST)
                    require(len(local) == len(upstream) == 2, "expected one admitted tool round trip")
                print("MAC_APP_SERVER_PASS=generated-member-new-thread-and-tool", flush=True)
                with app_server(codex, home, codex_home, work, port) as (call, wait, notifications):
                    resumed = call("thread/resume", {"threadId": thread_id, "modelProvider": PROVIDER,
                                                     "model": MODEL, "approvalPolicy": "never", "sandbox": "read-only"})
                    require(resumed["thread"]["id"] == thread_id and resumed.get("modelProvider") == PROVIDER,
                            "different resumed thread or provider")
                    turn(call, wait, notifications, thread_id, "SYNTHETIC_APP_SERVER_RESUME", "completed", RESUME)
                    require(len(local) == len(upstream) == 3, "expected one successful resumed request")
                    print("MAC_APP_SERVER_PASS=restarted-app-server-resume", flush=True)
                    ledger.reserve(MEMBER, "desktop-fixture-remaining", ledger.balance(MEMBER).available)
                    turn(call, wait, notifications, thread_id, "SYNTHETIC_APP_SERVER_BUDGET_DENIAL", "failed")
                    require(len(local) == 4 and len(upstream) == 3, "cap denial retried or reached upstream")
                    print("MAC_APP_SERVER_PASS=budget-denied-once-with-zero-upstream", flush=True)
            finally:
                server.shutdown()
                worker.join(timeout=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path, required=True)
    args = parser.parse_args()
    if not os.access(MAC_SANDBOX, os.X_OK):
        parser.error("macOS sandbox-exec is required")
    try:
        run(args.codex.resolve(strict=True))
    except RuntimeError as exc:
        parser.exit(1, f"MAC_APP_SERVER_FAIL={exc}\n")
