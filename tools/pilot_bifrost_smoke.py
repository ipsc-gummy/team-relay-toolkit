#!/usr/bin/env python3
"""Exercise stock Bifrost member budgets and retry behavior without network access."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
from tempfile import TemporaryDirectory
from threading import Barrier, BrokenBarrierError, Lock, Thread
import time

from pilot_cpa_smoke import fetch


HOST = "127.0.0.1"
MODEL = "gpt-4o-mini"
MARKER = "bifrost-pilot-result"
PIN = "bf2da45a4246605af199a21ba313992864835b16872cc62efbad4e62fe8645b3"


def require(condition, step):
    if not condition:
        raise SystemExit("BIFROST_PILOT_FAIL=" + step)
    print("BIFROST_PILOT_PASS=" + step, flush=True)


@contextmanager
def mock(key):
    calls = []
    lock = Lock()
    pending = Barrier(2, timeout=2)

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, data, media="application/json", retry_after=False):
            if not isinstance(data, bytes):
                data = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(data)))
            if retry_after:
                self.send_header("Retry-After", "0")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/v1/models":
                self.reply(200, {"object": "list", "data": [{"id": MODEL, "object": "model"}]})
            else:
                self.reply(404, {})

        def do_POST(self):
            if self.path != "/v1/responses" or self.headers.get("Authorization") != "Bearer " + key:
                self.reply(401, {})
                return
            size = int(self.headers.get("Content-Length", 0))
            if not 0 < size < 65536:
                self.reply(400, {})
                return
            request = json.loads(self.rfile.read(size))
            mode = json.dumps(request.get("input"))
            mode = next((value for value in ("transient", "limited", "concurrent", "after-cap", "single")
                         if '"' + value + '"' in mode), "other")
            with lock:
                calls.append(mode)
            if mode == "transient":
                self.reply(503, {"error": {"code": "pilot_unavailable", "message": "Transient fixture error"}})
                return
            if mode == "limited":
                self.reply(429, {"error": {"code": "rate_limit_exceeded", "message": "Fixture rate limit"}},
                           retry_after=True)
                return
            if mode == "concurrent":
                try:
                    pending.wait()
                except BrokenBarrierError:
                    pass
            part = {"type": "output_text", "text": MARKER, "annotations": []}
            item = {"id": "msg_pilot", "type": "message", "role": "assistant", "status": "completed", "content": [part]}
            response = {"id": "resp_pilot", "created_at": 1, "object": "response", "status": "completed",
                        "model": MODEL, "output": [item],
                        "usage": {"input_tokens": 100, "output_tokens": 100, "total_tokens": 200}}
            if request.get("stream"):
                events = [
                    {"type": "response.created", "response": dict(response, status="in_progress", output=[])},
                    {"type": "response.output_item.added", "output_index": 0, "item": dict(item, content=[])},
                    {"type": "response.output_text.delta", "item_id": item["id"], "output_index": 0,
                     "content_index": 0, "delta": MARKER},
                    {"type": "response.output_item.done", "output_index": 0, "item": item},
                    {"type": "response.completed", "response": response},
                ]
                self.reply(200, "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n"
                                        for event in events).encode(), "text/event-stream")
            else:
                self.reply(200, response)

    with ThreadingHTTPServer((HOST, 0), Fixture) as fixture:
        worker = Thread(target=fixture.serve_forever, daemon=True)
        worker.start()
        try:
            yield fixture.server_port, calls
        finally:
            fixture.shutdown()
            worker.join(timeout=3)


@contextmanager
def gateway(binary, root, upstream_port, upstream_key, member, limit):
    root.mkdir(mode=0o700)
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        port = sock.getsockname()[1]
    pricing = root / "pricing.json"
    pricing.write_text(json.dumps({MODEL: {"provider": "openai", "mode": "responses",
                                          "input_cost_per_token": 0.000001, "output_cost_per_token": 0.000001}}))
    params = root / "model-params.json"
    params.write_text("{}")
    config = {
        "client": {"enforce_auth_on_inference": True, "enable_logging": False, "initial_pool_size": 4},
        "framework": {"pricing": {"pricing_url": pricing.as_uri(), "model_parameters_url": params.as_uri(),
                                  "mcp_library_sync_interval": 0, "live_models_sync_interval": 0}},
        "config_store": {"enabled": True, "type": "sqlite", "config": {"path": str(root / "config.db")}},
        "logs_store": {"enabled": False},
        "providers": {"openai": {
            "keys": [{"name": "fixture", "value": upstream_key, "weight": 1, "models": [MODEL]}],
            "network_config": {"base_url": f"http://{HOST}:{upstream_port}", "max_retries": 0,
                               "default_request_timeout_in_seconds": 5},
        }},
        "governance": {
            "virtual_keys": [{"id": "vk-pilot", "name": "pilot", "value": member, "is_active": True,
                              "provider_configs": [{"provider": "openai", "weight": 1, "allowed_models": [MODEL],
                                                    "key_ids": ["*"]}]}],
            "budgets": [{"id": "pilot-budget", "virtual_key_id": "vk-pilot", "max_limit": limit,
                         "reset_duration": "1h"}],
        },
    }
    settings = root / "config.json"
    settings.touch(mode=0o600, exist_ok=False)
    settings.write_text(json.dumps(config), encoding="utf-8")
    with (root / "process.log").open("w+") as log, subprocess.Popen(
        [str(binary), "--host", HOST, "--port", str(port), "--app-dir", str(root), "--log-level", "warn"],
        cwd=root, env={"HOME": str(root), "PATH": os.defpath, "TMPDIR": str(root)}, stdin=subprocess.DEVNULL,
        stdout=log, stderr=log,
    ) as service:
        try:
            deadline = time.monotonic() + 20
            while True:
                if service.poll() is not None or time.monotonic() >= deadline:
                    log.seek(0)
                    # A failed run may display startup diagnostics, never even the synthetic keys.
                    print(log.read()[-2500:].replace(member, "[fixture]").replace(upstream_key, "[fixture]"))
                    require(False, "listener-startup")
                try:
                    if fetch(port, "/health")[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(0.1)
            yield port
        finally:
            if service.poll() is None:
                service.terminate()
                try:
                    service.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    service.kill()
                    service.wait(timeout=5)


def post(port, member, mode, stream=False):
    return fetch(port, "/v1/responses", member,
                 {"model": "openai/" + MODEL, "input": mode, "stream": stream})


def smoke(binary):
    if ({name for _, name in socket.if_nameindex()} != {"lo"}
            or os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net")):
        raise SystemExit("A separate Linux network namespace with only lo is required")
    with binary.open("rb") as source:
        require(hashlib.file_digest(source, "sha256").hexdigest() == PIN, "official-sha256")
    member, upstream_key = "sk-bf-" + secrets.token_hex(24), "fixture-" + secrets.token_hex(24)
    with TemporaryDirectory(prefix="bifrost-pilot-") as tmp, mock(upstream_key) as (upstream, calls):
        root = Path(tmp)
        with gateway(binary, root / "allowed", upstream, upstream_key, member, 1) as port:
            status, _, _ = post(port, None, "single")
            require(status in (401, 403) and not calls, f"anonymous-rejected-{status}")
            status, _, _ = post(port, "sk-bf-" + secrets.token_hex(24), "single")
            require(status in (401, 403) and not calls, f"unknown-member-rejected-{status}")
            status, _, body = post(port, member, "single")
            require(status == 200 and MARKER.encode() in body, f"responses-json-{status}")
            status, headers, body = post(port, member, "single", stream=True)
            require(status == 200 and "text/event-stream" in headers.get("Content-Type", "")
                    and b"response.completed" in body and MARKER.encode() in body, f"responses-sse-{status}")
            status, _, _ = post(port, member, "transient")
            require(status == 503 and calls.count("transient") == 1, f"no-upstream-retry-{status}")
            status, _, _ = post(port, member, "limited")
            require(status == 429 and calls.count("limited") == 1, f"no-upstream-retry-{status}")
        # Each 200-token synthetic response costs $0.0002 at the fixture rate.
        # Both are intentionally held before either settles.
        with gateway(binary, root / "race", upstream, upstream_key, member, 0.00002) as port:
            with ThreadPoolExecutor(max_workers=2) as pool:
                statuses = list(pool.map(lambda _: post(port, member, "concurrent")[0], range(2)))
            print(f"STOCK_CONCURRENT_STATUS={statuses} UPSTREAM={calls.count('concurrent')}", flush=True)
            if calls.count("concurrent") == 2 and statuses == [200, 200]:
                print("STOCK_HARD_CAP=NOT_ADMISSION_RESERVED", flush=True)
            else:
                require(False, "concurrency-observation-inconclusive")
            # Allow bounded time for the gateway's documented asynchronous accounting.
            time.sleep(2)
            before = len(calls)
            status, headers, reply = post(port, member, "after-cap")
            print(f"STOCK_CAP_HTTP={status} RETRY_AFTER={bool(headers.get('Retry-After'))}", flush=True)
            require(status == 402 and b"budget" in reply.lower() and len(calls) == before,
                    "spent-member-blocked-before-upstream")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    smoke(parser.parse_args().binary.resolve(strict=True))
