#!/usr/bin/env python3
"""Opt-in offline installed Codex -> member cap -> fixture integration on macOS."""

import argparse
from contextlib import contextmanager
from email.message import Message
from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread
from unittest.mock import patch

from member_dollar_cap import MODEL, Policy, make_server
from pilot_budget import PilotBudget
from test_codex_budget_retry import MAC_SANDBOX


PROJECT = Path(__file__).resolve().parents[1]
MEMBER = "offline-member"
TOKEN = f"cpa-{MEMBER}-" + "a" * 64
FIRST = "FIRST_CODEX_TURN_COMPLETED"
RESUME = "RESUMED_CODEX_TURN_COMPLETED"
CASE = "SYNTHETIC_FIRST_PROMPT"


def stream(sequence, item):
    response = {"id": f"resp_fixture_{sequence}", "object": "response", "created_at": 0, "model": MODEL,
                "status": "completed", "service_tier": "default", "output": [item],
                "usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}}
    events = [{"type": "response.created", "response": dict(response, status="in_progress", output=[])},
              {"type": "response.output_item.added", "output_index": 0, "item": item},
              {"type": "response.output_item.done", "output_index": 0, "item": item},
              {"type": "response.completed", "response": response}]
    return b"".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode() for event in events)


def tool_call(request):
    names = {tool.get("name") for tool in request.get("tools", []) if tool.get("type") == "function"}
    if "get_goal" not in names:
        raise ValueError("fixture cannot find the read-only local tool")
    return {"id": "fc_fixture", "call_id": "call_fixture", "type": "function_call", "name": "get_goal",
            "arguments": "{}", "status": "completed"}


def message(sequence, text):
    return {"id": f"msg_fixture_{sequence}", "type": "message", "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": text, "annotations": []}]}


def has_tool_result(items):
    for item in items:
        if item.get("type") != "function_call_output" or item.get("call_id") != "call_fixture":
            continue
        value = item.get("output")
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                return False
        return isinstance(value, dict) and "goal" in value and value["goal"] is None
    return False


def load_script(name, path):
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def config(endpoint, state, port):
    # Reuse the files rendered into a real member package, but never use an existing package or client profile.
    packer = load_script("member_flow_packer", PROJECT / "程序" / "打包新人两步接入.py")
    payload = packer.build_payload(MEMBER, packer.EXAMPLE_HOST_FP, TOKEN)
    core_path = state / "切换CodexApp.py"
    for path in (core_path, state / "中转访问密钥.txt"):
        path.write_bytes(payload[f"Codex团队接入/{'程序/' if path == core_path else ''}{path.name}"])
        path.chmod(0o600)
    core = load_script("member_flow_rendered_core", core_path)
    settings = {"schema": 1, "user": MEMBER, "host": core.HOST, "target": core.TARGET,
                "port": port, "model": MODEL, "python": str(Path(sys.executable).absolute())}
    core.atomic_write(state / "settings.json", json.dumps(settings).encode())
    baseline = ('model_context_window = 400000\ncheck_for_update_on_startup = false\n'
                'cli_auth_credentials_store = "file"\nweb_search = "disabled"\n'
                f'chatgpt_base_url = "{endpoint}"\nopenai_base_url = "{endpoint}/v1"\n'
                '[analytics]\nenabled = false\n[feedback]\nenabled = false\n[features]\nmulti_agent = false\n')
    # This opts the temporary member into the budget pilot's HTTP-only, zero-retry settings.
    rendered = core.make_team_config(baseline.encode(), state, settings).decode()
    return rendered.replace('[model_providers.sg_team]\n', '[model_providers.sg_team]\n'
                            'request_max_retries = 0\nstream_max_retries = 0\nsupports_websockets = false\n')


def run(codex):
    received, upstream_calls, details, run_events = [], [], [], []
    original = Policy.prepare

    def trace_policy(policy, raw):
        data = json.loads(raw)
        received.append(data)
        try:
            return original(policy, raw)
        except (ValueError, RecursionError) as exc:
            if exc.__class__.__name__ == "Rejected":
                details.append(str(exc))
            raise

    @contextmanager
    def mock(payload):
        request = json.loads(payload)
        upstream_calls.append(request)
        n = len(upstream_calls)
        if n == 1:
            item = tool_call(request)
        elif n == 2 and has_tool_result(request["input"]):
            item = message(n, FIRST)
        elif n == 3 and has_tool_result(request["input"]) and CASE in json.dumps(request["input"]):
            item = message(n, RESUME)
        else:
            details.append(f"mock:{n}:tool_result:{has_tool_result(request['input'])}")
            for item in request["input"]:
                if item.get("type") == "function_call_output":
                    raw = json.dumps(item.get("output"))
                    details.append(f"tool_output:{sorted(item)}:len={len(raw)}:goal={('goal' in raw)}:"
                                   f"invalid={('invalid' in raw)}")
            raise ValueError("synthetic tool or history not present")
        result = BytesIO(stream(n, item))
        result.status, result.length, result.headers = 200, 0, Message()
        result.headers["Content-Type"] = "text/event-stream"
        yield result

    def assert_flow(condition, phase):
        if condition:
            print(f"CODEX_FLOW_PASS={phase}", flush=True)
            return
        shapes = [{"keys": sorted(req), "input_types": [item.get("type") for item in req.get("input", [])
                   if isinstance(item, dict)], "tools": [{"type": tool.get("type"), "name": tool.get("name"),
                   "keys": sorted(tool), "child_types": [child.get("type") for child in tool.get("tools", [])]}
                   for tool in req.get("tools", [])]}
                  for req in received]
        print(json.dumps({"failed": phase, "local_calls": len(received), "upstream_calls": len(upstream_calls),
                          "shapes": shapes, "policy": details, "run_events": run_events}), flush=True)
        raise SystemExit(1)

    with TemporaryDirectory(prefix="codex-member-flow-") as directory:
        root = Path(directory)
        home, codex_home, work, state = (root / name for name in ("home", "codex", "work", "member"))
        for path in (home, codex_home, work, state):
            path.mkdir(mode=0o700)
        ledger = PilotBudget.create(root / "budget.sqlite")
        ledger.add_member(MEMBER, 100_000_000_000)
        members = {sha256(TOKEN.encode()).hexdigest(): MEMBER}
        with patch.object(Policy, "prepare", trace_policy), make_server(
            listen_port=0, ledger=ledger, members=members, upstream=mock,
        ) as server:
            worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            worker.start()
            endpoint = f"http://127.0.0.1:{server.server_port}"
            env = {"HOME": str(home), "CODEX_HOME": str(codex_home), "PATH": os.defpath, "TMPDIR": str(root),
                   "NO_PROXY": "127.0.0.1,localhost", "HTTP_PROXY": endpoint, "HTTPS_PROXY": endpoint,
                   "ALL_PROXY": endpoint, "TERM": "dumb"}
            (codex_home / "config.toml").write_text(config(endpoint, state, server.server_port), encoding="utf-8")
            profile = ('(version 1) (allow default) (deny network-outbound) '
                       f'(allow network-outbound (remote ip "localhost:{server.server_port}"))')
            cmd = [str(MAC_SANDBOX), "-p", profile, str(codex), "exec", "--skip-git-repo-check", "--sandbox",
                   "read-only", "--json", "--color", "never"]

            def execute(*args):
                proc = subprocess.run([*cmd, *args], cwd=work, env=env, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
                events = [json.loads(line) for line in proc.stdout.splitlines() if line.startswith(b"{")]
                run_events.extend(f"{event.get('type')}:{event.get('item', {}).get('type', '')}:"
                                  f"{event.get('item', {}).get('exit_code', '')}" for event in events)
                return proc.returncode, events

            def complete(code, events, marker):
                return code == 0 and any(event.get("type") == "turn.completed" for event in events) and any(
                    event.get("type") == "item.completed" and event.get("item", {}).get("text") == marker
                    for event in events)

            try:
                code, events = execute(CASE + ": follow the fixture tool and finish.")
                assert_flow(complete(code, events, FIRST) and len(upstream_calls) == 2, "new-turn-and-local-tool")
                ids = [e.get("thread_id") for e in events if e.get("type") == "thread.started"]
                assert_flow(len(ids) == 1 and bool(ids[0]), "thread-created")
                code, events = execute("resume", ids[0], "SYNTHETIC_RESUME_PROMPT: continue.")
                assert_flow(complete(code, events, RESUME) and len(upstream_calls) == 3, "resume-with-same-history")
                # Clean restart restores this consumed balance; no API call should happen after denial.
                ledger.reserve(MEMBER, "budget-fixture-remaining", ledger.balance(MEMBER).available)
                local_before = len(received)
                code, events = execute("resume", ids[0], "SYNTHETIC_BUDGET_DENIAL.")
                assert_flow(code != 0 and any(e.get("type") == "turn.failed" for e in events)
                            and len(received) == local_before + 1 and len(upstream_calls) == 3,
                            "cap-denied-once-zero-upstream")
            finally:
                server.shutdown()
                worker.join(timeout=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", type=Path, required=True)
    args = parser.parse_args()
    if not os.access(MAC_SANDBOX, os.X_OK):
        parser.error("macOS sandbox-exec is required")
    run(args.codex.resolve(strict=True))
