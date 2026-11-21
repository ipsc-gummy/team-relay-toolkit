"""Behavior tests using only synthetic tokens, SQLite and loopback sockets."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
from tempfile import TemporaryDirectory
from threading import Event, Thread
import time
import unittest

from pilot_budget import PilotBudget
from pilot_member_gateway import _load_private, make_server, MAX_REQUEST


BODY = {"model": "pilot-model", "input": "synthetic", "stream": False}
ANSWER = b'{"object":"response","status":"completed","model":"pilot-model"}'
DELTA = b'event: response.output_text.delta\ndata: {"delta":"fixture"}\n\n'
DONE = (b'event: response.completed\ndata: {"type":"response.completed",'
        b'"response":{"status":"completed"}}\n\n')


@contextmanager
def background(server):
    with server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            thread.join(timeout=2)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        resources = ExitStack()
        self.addCleanup(resources.close)
        self.root = Path(resources.enter_context(TemporaryDirectory()))
        self.ledger = PilotBudget.create(self.root / "ledger.db")
        self.ledger.add_member("test-a", 10)
        self.ledger.add_member("test-b", 10)
        self.member_token, self.cpa_token = secrets.token_hex(24), secrets.token_hex(24)
        self.routes = []
        self.mode = "normal"
        self.inflight = Event()
        self.released = Event()
        test = self

        class Stub(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                test.routes.append((self.path, self.headers.get("Authorization"), payload))
                if self.headers.get("Authorization") != "Bearer " + test.cpa_token:
                    self.send_error(401)
                    return
                if test.mode == "redirect":
                    self.send_response(302)
                    self.send_header("Location", "/should-not-be-followed")
                    self.end_headers()
                    return
                if payload["stream"]:
                    response = DELTA if test.mode == "missing-final" else DELTA + DONE
                else:
                    response = ANSWER
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream" if payload["stream"] else "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                try:
                    if test.mode in ("blocked", "client-drop"):
                        if payload["stream"]:
                            self.wfile.write(DELTA)
                            self.wfile.flush()
                            response = DONE
                        test.inflight.set()
                        test.released.wait(timeout=3)
                        if test.mode == "client-drop":
                            # No completion after the downstream loss in this fixture.
                            return
                    self.wfile.write(response)
                except OSError:
                    pass

        self.stub_port = resources.enter_context(background(ThreadingHTTPServer(("127.0.0.1", 0), Stub)))
        self.port = resources.enter_context(background(make_server(
            listen_port=0, cpa_port=self.stub_port, member="test-a", member_token=self.member_token,
            cpa_token=self.cpa_token, ledger=self.ledger,
        )))
        resources.callback(self.released.set)

    def fetch(self, path="/v1/responses", body=BODY, *, token=True):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=3)
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + (self.member_token if token is True else token)
        try:
            data = None if body is None else (body if type(body) is bytes else json.dumps(body))
            conn.request("GET" if body is None else "POST", path, data, headers)
            response = conn.getresponse()
            return response.status, response.headers.get_content_type(), response.read()
        finally:
            conn.close()

    def assert_balance(self, expected):
        deadline = time.monotonic() + 2
        while self.ledger.balance("test-a").available != expected and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.ledger.balance("test-a").available, expected)

    def test_auth_catalog_and_restricted_routes(self):
        self.assertEqual(self.fetch("/v1/models", None, token=False)[0], 401)
        self.assertEqual(self.fetch(token=self.cpa_token)[0], 401)
        self.assertIn(b"pilot-model", self.fetch("/v1/models", None)[2])
        self.assertEqual(self.fetch("/v1/responses/compact")[0], 404)
        self.assertEqual(self.fetch(body=dict(BODY, tools=[]))[0], 400)
        self.assertEqual(self.fetch(body=dict(BODY, input="unapproved text"))[0], 400)
        self.assertEqual(self.fetch(body=dict(BODY, stream=1))[0], 400)
        self.assertEqual(self.fetch(body=b"x" * (MAX_REQUEST + 1))[0], 413)
        self.assertEqual(self.routes, [])
        self.assert_balance(10)

    def test_json_sse_and_real_predispatch_rejection(self):
        self.assertEqual(self.fetch(), (200, "application/json", ANSWER))
        self.assert_balance(7)
        self.assertEqual(self.fetch(body=dict(BODY, stream=True)), (200, "text/event-stream", DELTA + DONE))
        self.assert_balance(4)
        self.assertEqual(self.fetch()[0], 429)
        self.assertEqual(self.routes, [
            ("/v1/responses", "Bearer " + self.cpa_token, BODY),
            ("/v1/responses", "Bearer " + self.cpa_token, dict(BODY, stream=True)),
        ])
        self.assertEqual(self.ledger.balance("test-b").available, 10)

    def test_concurrent_response_does_not_spend_unsettled_hold(self):
        self.mode = "blocked"
        with ThreadPoolExecutor() as pool:
            first = pool.submit(self.fetch)
            try:
                self.assertTrue(self.inflight.wait(timeout=2))
                self.assertEqual(self.fetch()[0], 429)
                self.assertEqual(len(self.routes), 1)
                self.assert_balance(4)
            finally:
                self.released.set()
            self.assertEqual(first.result()[0], 200)
        self.assert_balance(7)

    def test_sse_passes_delta_before_completion(self):
        self.mode = "blocked"
        conn = HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            conn.request("POST", "/v1/responses", json.dumps(dict(BODY, stream=True)), {
                "Authorization": "Bearer " + self.member_token, "Content-Type": "application/json",
            })
            response = conn.getresponse()
            self.assertEqual(response.read(len(DELTA)), DELTA)
            self.assertFalse(self.released.is_set())
            self.assertEqual(self.fetch()[0], 429)
            self.released.set()
            self.assertEqual(response.read(), DONE)
        finally:
            self.released.set()
            conn.close()
        self.assert_balance(7)

    def test_missing_terminal_and_client_cancel_retain_hold(self):
        self.mode = "client-drop"
        conn = HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request("POST", "/v1/responses", json.dumps(dict(BODY, stream=True)), {
            "Authorization": "Bearer " + self.member_token, "Content-Type": "application/json",
        })
        with conn.getresponse() as response:
            self.assertEqual(response.read(len(DELTA)), DELTA)
            conn.sock and conn.sock.shutdown(socket.SHUT_RDWR)
        conn.close()
        self.released.set()
        self.assertEqual(self.fetch()[0], 429)
        self.assertEqual(len(self.routes), 1)
        self.assert_balance(4)

    def test_clean_sse_eof_without_terminal_retains_hold(self):
        self.mode = "missing-final"
        self.assertEqual(self.fetch(body=dict(BODY, stream=True)), (200, "text/event-stream", DELTA))
        self.assertEqual(self.fetch()[0], 429)
        self.assertEqual(len(self.routes), 1)
        self.assert_balance(4)

    def test_redirect_not_followed_and_failed_upstream_charged_conservatively(self):
        self.mode = "redirect"
        self.assertEqual(self.fetch()[0], 502)
        self.assertEqual(self.fetch()[0], 429)
        self.assertEqual(len(self.routes), 1)
        self.assert_balance(4)

    def test_unverifiable_ledger_does_not_call_upstream(self):
        with sqlite3.connect(self.ledger.path) as con:
            con.execute("DROP TABLE reservations")
        self.assertEqual(self.fetch()[0], 503)
        self.assertEqual(self.routes, [])

    def test_config_requires_private_regular_file_not_symlink(self):
        path = self.root / "fixture.json"
        values = {"listen_port": self.port, "cpa_port": self.stub_port, "member": "test-a",
                  "member_token": self.member_token, "cpa_token": self.cpa_token,
                  "ledger": str(self.ledger.path), "final_cost": 3}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as config:
            json.dump(values, config)
        self.assertEqual(_load_private(path), values)
        alias = self.root / "alias.json"
        alias.symlink_to(path)
        with self.assertRaises(OSError):
            _load_private(alias)
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            _load_private(path)


if __name__ == "__main__":
    unittest.main()
