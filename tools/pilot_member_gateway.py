#!/usr/bin/env python3
"""Loopback-only synthetic CPA pilot. Never use with a real model or billing.

The fixture accepts only pilot-model/synthetic, reserving six integer credits
against one member's ten-credit cap. Its final cost is a fixture constant, not
a price estimate. Start the CLI inside a Linux network namespace with only lo.
"""

import argparse
from contextlib import closing
import hmac
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import socket
import stat
from uuid import uuid4

from pilot_budget import BudgetBlocked, BudgetError, InsufficientCredits, PilotBudget


HOST = "127.0.0.1"
MODEL = "pilot-model"
CAP = 10
HOLD = 6
MAX_REQUEST = 512
MAX_RESPONSE = 256 * 1024
TOKEN = re.compile(r"[A-Za-z0-9_-]{16,128}")


def _unique_fields(pairs):
    obj = {}
    for name, value in pairs:
        if name in obj:
            raise ValueError("duplicate JSON field")
        obj[name] = value
    return obj


def _json(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields)


class _Completion:
    """Observe fixture terminal events without modifying the forwarded SSE."""

    def __init__(self):
        self.pending = b""
        self.event = b""
        self.data = []
        self.complete = False
        self.failed = False

    def feed(self, block):
        *lines, self.pending = (self.pending + block).split(b"\n")
        for raw in lines:
            line = raw.rstrip(b"\r")
            if not line:
                self._end_event()
            elif line.startswith(b"event:"):
                self.event = line[6:].lstrip(b" ")
            elif line.startswith(b"data:"):
                self.data.append(line[5:].lstrip(b" "))

    def _end_event(self):
        if self.event in (b"response.failed", b"response.incomplete", b"error"):
            self.failed = True
        if self.event == b"response.completed":
            payload = _json(b"\n".join(self.data))
            response = payload.get("response") if isinstance(payload, dict) else None
            self.failed |= (self.complete or not isinstance(response, dict)
                            or response.get("status") != "completed"
                            or payload.get("type") != "response.completed")
            self.complete = not self.failed
        self.event, self.data = b"", []

    def successful(self):
        return self.complete and not self.failed and not (self.pending or self.event or self.data)


def make_server(*, listen_port, cpa_port, member, member_token, cpa_token, ledger, final_cost=3):
    if any(type(port) is not int for port in (listen_port, cpa_port)) or not (
        0 <= listen_port <= 65535 and 1 <= cpa_port <= 65535 and listen_port != cpa_port
    ):
        raise ValueError("expected distinct loopback ports")
    if any(not isinstance(key, str) or not TOKEN.fullmatch(key) for key in (member_token, cpa_token)):
        raise ValueError("expected separate fixture bearer tokens")
    if member_token == cpa_token:
        raise ValueError("fixture bearer tokens must differ")
    if type(final_cost) is not int or not 0 <= final_cost <= HOLD:
        raise ValueError("invalid fixture cost")
    if ledger.balance(member).limit != CAP:
        raise ValueError("member must have the ten-credit fixture cap")

    expected = ("Bearer " + member_token).encode("ascii")

    class Gateway(BaseHTTPRequestHandler):
        timeout = 5
        server_version = "SyntheticPilot"
        sys_version = ""

        def log_message(self, *_):
            pass

        def _headers(self, status, media, size=None):
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-store")
            if size is not None:
                self.send_header("Content-Length", str(size))
            self.end_headers()

        def _send(self, status, payload):
            body = json.dumps(payload, separators=(",", ":")).encode()
            self._headers(status, "application/json", len(body))
            self.wfile.write(body)

        def _error(self, status, code):
            self._send(status, {"error": {"code": code}})

        def _authorized(self):
            values = self.headers.get_all("Authorization", ())
            if len(values) == 1 and hmac.compare_digest(values[0].encode("latin1"), expected):
                return True
            self._error(401, "unauthorized")
            return False

        def do_GET(self):
            if not self._authorized():
                return
            if self.path == "/v1/models":
                self._send(200, {"object": "list", "data": [{"object": "model", "id": MODEL}]})
            else:
                self._error(404, "unsupported_fixture_route")

        def do_POST(self):
            if not self._authorized():
                return
            if self.path != "/v1/responses" or self.headers.get("Upgrade") is not None:
                self._error(404, "unsupported_fixture_route")
                return
            sizes = self.headers.get_all("Content-Length", ())
            if (self.headers.get("Transfer-Encoding") is not None or len(sizes) != 1
                    or not re.fullmatch(r"[0-9]{1,10}", sizes[0])):
                self._error(400, "invalid_body_length")
                return
            size = int(sizes[0])
            if size > MAX_REQUEST:
                self._error(413, "fixture_body_too_large")
                return
            if self.headers.get_content_type() != "application/json":
                self._error(415, "expected_json")
                return
            try:
                raw = self.rfile.read(size)
                body = _json(raw) if len(raw) == size else None
            except (OSError, ValueError, RecursionError):
                body = None
            if (not isinstance(body, dict) or body.keys() != {"model", "input", "stream"}
                    or body["model"] != MODEL or body["input"] != "synthetic"
                    or type(body["stream"]) is not bool):
                self._error(400, "unsupported_fixture_body")
                return
            request_id = uuid4().hex
            try:
                ledger.reserve(member, request_id, HOLD)
            except (BudgetBlocked, InsufficientCredits):
                self._error(429, "fixture_budget_exhausted")
                return
            except BudgetError:
                self._error(503, "fixture_budget_unavailable")
                return
            self._dispatch(body, request_id)

        def _dispatch(self, body, request_id):
            started = False
            try:
                with closing(HTTPConnection(HOST, cpa_port, timeout=5)) as upstream:
                    upstream.request("POST", "/v1/responses", json.dumps(body).encode(), {
                        "Authorization": "Bearer " + cpa_token,
                        "Content-Type": "application/json",
                        "Connection": "close",
                    })
                    with upstream.getresponse() as result:
                        media = "text/event-stream" if body["stream"] else "application/json"
                        if result.status != 200 or result.headers.get_content_type() != media:
                            raise ValueError("unexpected upstream status or content type")
                        if body["stream"]:
                            started = True
                            self._headers(200, media)
                            known = self._stream(result)
                        else:
                            answer = result.read(MAX_RESPONSE + 1)
                            if len(answer) > MAX_RESPONSE or result.length not in (0, None):
                                raise ValueError("invalid fixture response length")
                            payload = _json(answer)
                            if not isinstance(payload, dict) or payload.get("status") != "completed":
                                raise ValueError("fixture did not complete")
                            started = True
                            self._headers(200, media, len(answer))
                            self.wfile.write(answer)
                            known = True
                # If an upstream or downstream failure leaves final cost uncertain,
                # the pending reservation remains intact. No failure path refunds.
                if known:
                    self.wfile.flush()
                    ledger.settle(member, request_id, final_cost)
            except (OSError, HTTPException, ValueError, RecursionError, BudgetError):
                if not started:
                    try:
                        self._error(502, "fixture_upstream_unavailable")
                    except OSError:
                        pass

        def _stream(self, result):
            events, count = _Completion(), 0
            while True:
                block = result.read1(4096)
                if not block:
                    return result.length in (0, None) and events.successful()
                count += len(block)
                if count > MAX_RESPONSE:
                    return False
                events.feed(block)
                self.wfile.write(block)
                self.wfile.flush()

    return ThreadingHTTPServer((HOST, listen_port), Gateway)


def _load_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("fixture configuration must be private and user-owned")
        raw = f.read(4097)
    if len(raw) > 4096:
        raise ValueError("fixture configuration too large")
    config = _json(raw)
    if not isinstance(config, dict) or config.keys() != {
        "listen_port", "cpa_port", "member", "member_token", "cpa_token", "ledger", "final_cost"
    }:
        raise ValueError("unexpected fixture configuration")
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="private JSON fixture configuration")
    args = parser.parse_args()
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        parser.exit(1, "Run in a private Linux network namespace with only lo enabled\n")
    try:
        config = _load_private(args.config)
        config["ledger"] = PilotBudget(config["ledger"])
        with make_server(**config) as server:
            server.serve_forever()
    except (OSError, ValueError, TypeError, BudgetError, RecursionError):
        parser.exit(1, "Synthetic member gateway failed to start\n")


if __name__ == "__main__":
    main()
