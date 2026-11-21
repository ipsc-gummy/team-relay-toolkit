#!/usr/bin/env python3
"""Smoke-test a pinned official Linux binary against a loopback-only fake upstream."""

import argparse
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tarfile
from tempfile import TemporaryDirectory
from threading import Thread
import time


PIN = "e05f968ae36819aeb771fe0f5c9f4110b2a44d8f549a3fdd44e3cb113c00d1a3"
MODEL = "pilot-model"
MARKER = "isolated-pilot-result"


def fetch(port, path, key=None, body=None):
    conn = HTTPConnection("127.0.0.1", port, timeout=6)
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    try:
        conn.request("POST" if body is not None else "GET", path,
                     json.dumps(body).encode() if body is not None else None, headers)
        response = conn.getresponse()
        return response.status, response.headers, response.read(65537)
    finally:
        conn.close()


def fake_upstream(key, routes):
    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            if self.headers.get("Authorization") != "Bearer " + key:
                self.send_error(401)
                return
            incoming = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            routes.append(self.path)
            if self.path != "/v1/chat/completions":
                self.send_error(404)
                return
            usage = {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}
            base = {"id": "chatcmpl-pilot", "model": MODEL, "created": 1}
            if incoming.get("stream"):
                base["object"] = "chat.completion.chunk"
                chunks = [
                    dict(base, choices=[{"index": 0, "delta": {"role": "assistant", "content": MARKER},
                                         "finish_reason": None}]),
                    dict(base, choices=[{"index": 0, "delta": {}, "finish_reason": "stop"}], usage=usage),
                ]
                body = ("".join(f"data: {json.dumps(chunk)}\n\n" for chunk in chunks)
                        + "data: [DONE]\n\n").encode()
                media = "text/event-stream"
            else:
                body = json.dumps(dict(base, object="chat.completion", choices=[{
                    "index": 0, "message": {"role": "assistant", "content": MARKER},
                    "finish_reason": "stop",
                }], usage=usage)).encode()
                media = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ThreadingHTTPServer(("127.0.0.1", 0), Upstream)


def require(condition, step):
    if not condition:
        raise SystemExit("CPA_PILOT_FAIL=" + step)
    print("CPA_PILOT_PASS=" + step, flush=True)


def smoke(archive):
    # A missing network namespace must not quietly turn this into a live test.
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise SystemExit("Run in a private Linux network namespace with only lo enabled")
    with archive.open("rb") as source, TemporaryDirectory(prefix="cpa-pilot-") as tmp:
        require(hashlib.file_digest(source, "sha256").hexdigest() == PIN, "archive-sha256")
        source.seek(0)
        root = Path(tmp)
        binary = root / "cli-proxy-api"
        with tarfile.open(fileobj=source, mode="r:gz") as package:
            executable = package.getmember("cli-proxy-api")
            require(executable.isfile() and executable.size < 256 * 1024 * 1024, "binary-member")
            with package.extractfile(executable) as content, binary.open("xb") as output:
                shutil.copyfileobj(content, output)
        binary.chmod(0o700)
        (root / "oauth-empty").mkdir(mode=0o700)
        routes = []
        client_key, upstream_key = secrets.token_hex(32), secrets.token_hex(32)
        with fake_upstream(upstream_key, routes) as server:
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                run_binary(root, binary, server.server_port, client_key, upstream_key, routes)
            finally:
                server.shutdown()
                worker.join(timeout=3)


def run_binary(root, binary, upstream_port, client_key, upstream_key, routes):
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        _, port = reserved.getsockname()
    config = {
        "config-version": 8,
        "server": {"host": "127.0.0.1", "port": port, "max-request-body-bytes": 65536},
        "access": {"api-keys": [client_key]},
        "oauth": {"auth-dir": str(root / "oauth-empty")},
        "api-keys": {"openai-compatibility": [{
            "name": "pilot", "base-url": f"http://127.0.0.1:{upstream_port}/v1",
            "keys": [{"api-key": upstream_key}], "models": [{"name": MODEL}], "request-retry": 0,
        }]},
        "routing": {"retry": {"request-retry": 0}},
        "management": {"secret-key": "", "disable-control-panel": True},
        "observability": {"logs": {"request-log": False}},
    }
    cfg = root / "fixture.yaml"
    cfg.touch(mode=0o600, exist_ok=False)
    cfg.write_text(json.dumps(config), encoding="utf-8")
    with subprocess.Popen([str(binary), "--local-model", "--config", str(cfg)], cwd=root,
                          env={"HOME": str(root), "PATH": os.defpath}, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL) as service:
        try:
            deadline = time.monotonic() + 12
            while True:
                if service.poll() is not None or time.monotonic() >= deadline:
                    raise SystemExit("CPA_PILOT_FAIL=listener-startup")
                try:
                    status, _, data = fetch(port, "/v1/models", client_key)
                except (OSError, ConnectionError):
                    time.sleep(0.1)
                    continue
                require(status == 200 and MODEL.encode() in data, "model-catalog")
                break
            status, _, _ = fetch(port, "/v1/models")
            require(status == 401 and not routes, "unauthenticated-rejected")
            body = {"model": MODEL, "input": "synthetic", "stream": False}
            status, _, data = fetch(port, "/v1/responses", client_key, body)
            require(status == 200 and MARKER.encode() in data, "responses-json")
            status, headers, data = fetch(port, "/v1/responses", client_key, dict(body, stream=True))
            require(status == 200 and "text/event-stream" in headers.get("Content-Type", "")
                    and b"response.completed" in data and MARKER.encode() in data, "responses-sse")
            require(routes == ["/v1/chat/completions"] * 2, "synthetic-upstream-only")
        finally:
            service.terminate()
            try:
                service.wait(timeout=5)
            except subprocess.TimeoutExpired:
                service.kill()
                service.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="official v8.0.80 Linux amd64 no-plugin tarball")
    smoke(parser.parse_args().archive)
