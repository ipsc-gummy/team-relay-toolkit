#!/usr/bin/env python3
"""End-to-end budget tests with synthetic members and a loopback OpenAI fixture."""

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager, ExitStack, redirect_stdout
from datetime import datetime, timezone
from email.message import Message
from hashlib import sha256
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO, StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier, Event, Lock, Thread
import time
import unittest
from unittest.mock import patch

from member_dollar_cap import CAP, MODEL, make_server, official_upstream
from pilot_budget import PilotBudget
import smoke_member_dollar_cap_live as live


HOST = "127.0.0.1"
MEMBER = "fake-member"
TOKEN = "synthetic-budget-member-token-0123456789"
OTHER = "synthetic-other-member-token-0123456789"
PRIVATE_UPSTREAM_TOKEN = "synthetic-upstream-only-token-0123456789"
BODY = {"model": MODEL, "input": "Count this synthetic example.", "max_output_tokens": 256, "stream": False}
HOLD = 400_000 * 750 + 256 * 4500
FINAL = 4 * 750 + 3 * 4500
START_SPENT = 99_600_000_000
USAGE = {"input_tokens": 4, "output_tokens": 3, "total_tokens": 7,
         "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 1}}
ANSWER = {"id": "resp_fixture", "object": "response", "status": "completed", "model": MODEL,
          "service_tier": "default", "usage": USAGE,
          "output": [{"type": "message", "role": "assistant", "status": "completed", "id": "msg_fixture",
                      "content": [{"type": "output_text", "text": "synthetic-result", "annotations": []}]}]}


def event(kind, **fields):
    return (f"event: {kind}\ndata: " + json.dumps({"type": kind, **fields}) + "\n\n").encode()


DELTA = event("response.output_text.delta", delta="synthetic-result", item_id="msg_fixture",
              output_index=0, content_index=0)
COMPLETE = event("response.completed", response=ANSWER)


@contextmanager
def running(server):
    with server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield server.server_port
        finally:
            server.shutdown()
            thread.join(timeout=2)


class DollarCapTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.stack = stack
        self.path = Path(stack.enter_context(TemporaryDirectory(prefix="dollar-cap-fixture-"))) / "budget.sqlite"
        self.ledger = PilotBudget.create(self.path)
        self.ledger.add_member(MEMBER, CAP)
        self.ledger.add_member("fake-other-member", CAP)
        self.members = {sha256(TOKEN.encode()).hexdigest(): MEMBER,
                        sha256(OTHER.encode()).hexdigest(): "fake-other-member"}
        self.inflight = Event()
        self.release = Event()
        self.calls = []
        self.lock = Lock()
        self.mode = "success"
        test = self

        class Stub(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with test.lock:
                    test.calls.append((self.path, self.headers.get("Authorization"), request))
                mode = test.mode
                if mode in ("429", "503", "redirect"):
                    self.send_response(302 if mode == "redirect" else int(mode))
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "2")
                    self.send_header("Retry-After", "0")
                    self.send_header("Location", "/must-not-follow")
                    self.end_headers()
                    self.wfile.write(b"{}")
                    return
                if mode == "bad-usage":
                    response = json.dumps(dict(ANSWER, usage=dict(USAGE, total_tokens=99))).encode()
                elif mode == "bad-tier":
                    response = json.dumps(dict(ANSWER, service_tier="priority")).encode()
                elif request["stream"]:
                    response = DELTA if mode in ("partial-eof", "cancel") else DELTA + COMPLETE
                else:
                    response = json.dumps(ANSWER).encode()
                media = "text/event-stream" if request["stream"] else "application/json"
                try:
                    if mode == "park":
                        test.inflight.set()
                        test.release.wait(timeout=5)
                    self.send_response(200)
                    self.send_header("Content-Type", media)
                    self.send_header("Content-Length", str(len(response) + (256 if mode == "cancel" else 0)))
                    self.end_headers()
                    self.wfile.write(response)
                    self.wfile.flush()
                    if mode == "cancel":
                        test.inflight.set()
                        test.release.wait(timeout=5)
                except OSError:
                    pass

        self.stub_port = stack.enter_context(running(ThreadingHTTPServer((HOST, 0), Stub)))
        self.port = self.new_gateway()
        stack.callback(self.release.set)

    def new_gateway(self):
        return self.stack.enter_context(running(make_server(
            listen_port=0, ledger=PilotBudget(self.path), members=self.members, upstream=self.upstream,
        )))

    @contextmanager
    def upstream(self, wire):
        conn = HTTPConnection(HOST, self.stub_port, timeout=6)
        try:
            conn.request("POST", "/v1/responses", wire, {"Content-Type": "application/json",
                                                        "Authorization": "Bearer " + PRIVATE_UPSTREAM_TOKEN})
            with conn.getresponse() as response:
                yield response
        finally:
            conn.close()

    def connect(self, *, port=None, token=TOKEN, path="/v1/responses", body=BODY, headers=None):
        conn = HTTPConnection(HOST, port or self.port, timeout=6)
        request_headers = {"Content-Type": "application/json"} | (headers or {})
        if token is not None:
            request_headers["Authorization"] = "Bearer " + token
        if isinstance(body, dict):
            body = json.dumps(body)
        try:
            conn.request("POST" if body is not None else "GET", path, body, request_headers)
            return conn, conn.getresponse()
        except BaseException:
            conn.close()
            raise

    def fetch(self, **kwargs):
        conn, response = self.connect(**kwargs)
        try:
            return response.status, response.headers, response.read()
        finally:
            conn.close()

    def seed_near_cap(self):
        self.assertEqual(CAP, 100_000_000_000)
        self.ledger.reserve(MEMBER, "historical-settled-fixture", START_SPENT)
        self.ledger.settle(MEMBER, "historical-settled-fixture", START_SPENT)

    def assert_spend(self, amount, *, wait=False):
        if wait:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and self.ledger.balance(MEMBER).committed != amount:
                time.sleep(0.01)
        state = self.ledger.balance(MEMBER)
        self.assertEqual(state.committed, amount)
        self.assertLessEqual(state.committed, CAP)

    def assert_local_budget_error(self, result):
        status, headers, body = result
        self.assertEqual(status, 400)
        self.assertNotIn("Retry-After", headers)
        self.assertEqual(json.loads(body)["error"]["code"], "budget_reached")

    def test_concurrent_near_100_dollars_reserves_only_one_across_two_gateways(self):
        self.seed_near_cap()
        peer_port = self.new_gateway()
        self.mode = "park"
        with ThreadPoolExecutor(max_workers=9) as pool:
            first = pool.submit(self.fetch)
            try:
                self.assertTrue(self.inflight.wait(timeout=3))
                blocked = list(pool.map(lambda i: self.fetch(port=peer_port if i % 2 else self.port), range(8)))
                for reply in blocked:
                    self.assert_local_budget_error(reply)
                self.assertEqual(len(self.calls), 1)
                self.assert_spend(START_SPENT + HOLD)
            finally:
                self.release.set()
            self.assertEqual(first.result()[0], 200)
        self.assert_spend(START_SPENT + FINAL, wait=True)
        self.assertEqual(self.fetch(port=peer_port)[0], 200)
        self.assertEqual(len(self.calls), 2)
        self.assert_spend(START_SPENT + 2 * FINAL, wait=True)
        self.assertEqual(self.ledger.balance("fake-other-member").available, CAP)

    def test_simultaneous_admission_for_exact_remaining_allowance_is_atomic(self):
        spent = CAP - HOLD
        self.ledger.reserve(MEMBER, "historical-at-boundary", spent)
        self.ledger.settle(MEMBER, "historical-at-boundary", spent)
        self.mode = "park"
        peer = self.new_gateway()
        barrier = Barrier(2, timeout=3)

        def race(port):
            barrier.wait()
            return self.fetch(port=port)

        with ThreadPoolExecutor(max_workers=2) as pool:
            try:
                jobs = [pool.submit(race, port) for port in (self.port, peer)]
                self.assertTrue(self.inflight.wait(timeout=3))
                rejected, admitted = wait(jobs, timeout=3, return_when=FIRST_COMPLETED)
                self.assertEqual(len(rejected), 1, "one request must be rejected before upstream is allowed to answer")
                self.assertEqual(len(admitted), 1)
                self.assert_local_budget_error(rejected.pop().result())
                self.assertEqual(len(self.calls), 1)
                self.assert_spend(CAP)
            finally:
                self.release.set()
            self.assertEqual(admitted.pop().result()[0], 200)
        self.assert_spend(spent + FINAL, wait=True)

    def test_anonymous_and_unbounded_features_fail_before_upstream(self):
        for token in (None, "synthetic-unknown-0123456789"):
            self.assertEqual(self.fetch(token=token)[0], 401)
        for path in ("/v1/responses/compact", "/v1/chat/completions", "/v1/responses?route=alternate"):
            self.assertEqual(self.fetch(path=path)[0], 404)
        for field, value in (("instructions", "unreviewed field"), ("tools", [{"type": "web_search"}]),
                             ("previous_response_id", "resp_other"), ("background", True),
                             ("service_tier", "priority"), ("model", "gpt-other"), ("stream", 1),
                             ("max_output_tokens", 4097), ("max_output_tokens", True),
                             ("input", [{"role": "user", "content": [{"type": "input_image",
                                                                       "image_url": "local-image"}]}])):
            with self.subTest(field=field):
                self.assertEqual(self.fetch(body=dict(BODY, **{field: value}))[0], 400)
        raw = json.dumps(BODY)[:-1] + ', "model": "different"}'
        self.assertEqual(self.fetch(body=raw.encode())[0], 400)
        self.assertEqual(self.calls, [])
        self.assert_spend(0)

    def test_rebuilds_the_upstream_payload_and_settles_reported_usage(self):
        self.assertEqual(self.fetch(headers={"OpenAI-Organization": "org-fixture-untrusted",
                                             "X-LiteLLM-Num-Retries": "9"})[0], 200)
        self.assertEqual(len(self.calls), 1)
        path, bearer, request = self.calls[0]
        self.assertEqual(path, "/v1/responses")
        self.assertEqual(bearer, "Bearer " + PRIVATE_UPSTREAM_TOKEN)
        expected = dict(BODY, service_tier="default", store=False, truncation="disabled")
        self.assertEqual({key: request.get(key) for key in expected}, expected)
        self.assertFalse(any(key in request for key in ("tools", "previous_response_id", "background")))
        self.assert_spend(FINAL, wait=True)

    def test_complete_sse_forwards_delta_and_settles(self):
        status, headers, response = self.fetch(body=dict(BODY, stream=True))
        self.assertEqual(status, 200)
        self.assertEqual(headers.get_content_type(), "text/event-stream")
        self.assertIn(b"synthetic-result", response)
        self.assertIn(b"response.completed", response)
        self.assert_spend(FINAL, wait=True)

    def test_429_and_503_passthrough_without_upstream_retry_or_refund(self):
        for attempt, code in enumerate((429, 503), start=1):
            self.mode = str(code)
            status, headers, _ = self.fetch()
            self.assertEqual(status, code)
            self.assertNotIn("Retry-After", headers)
            self.assertEqual(len(self.calls), attempt)
            self.assert_spend(HOLD * attempt)

    def test_redirect_is_not_followed(self):
        self.mode = "redirect"
        status, headers, _ = self.fetch()
        self.assertGreaterEqual(status, 400)
        self.assertNotIn("Location", headers)
        self.assertEqual(len(self.calls), 1)
        self.assert_spend(HOLD)

    def test_malformed_or_different_tier_response_keeps_the_hold(self):
        for attempt, mode in enumerate(("bad-usage", "bad-tier"), start=1):
            self.mode = mode
            status, _, _ = self.fetch()
            self.assertGreaterEqual(status, 400)
            self.assert_spend(HOLD * attempt, wait=True)
            self.assertEqual(len(self.calls), attempt)

    def test_partial_eof_preserves_reservation_across_reopen(self):
        self.seed_near_cap()
        self.mode = "partial-eof"
        status, _, payload = self.fetch(body=dict(BODY, stream=True))
        self.assertEqual(status, 200)
        self.assertIn(b"response.output_text.delta", payload)
        self.assertNotIn(b"response.completed", payload)
        self.assert_spend(START_SPENT + HOLD)
        restarted = self.new_gateway()
        self.assert_local_budget_error(self.fetch(port=restarted))
        self.assertEqual(len(self.calls), 1)

    def test_downstream_cancel_cannot_refund_ongoing_upstream(self):
        self.seed_near_cap()
        self.mode = "cancel"
        conn, response = self.connect(body=dict(BODY, stream=True))
        try:
            self.assertTrue(self.inflight.wait(timeout=3))
            self.assertEqual(response.status, 200)
        finally:
            response.close()
            conn.close()
            self.release.set()
        self.assert_local_budget_error(self.fetch())
        self.assertEqual(len(self.calls), 1)
        self.assert_spend(START_SPENT + HOLD)

    def test_missing_ledger_fails_closed_without_recreating_it(self):
        self.path.rename(self.path.with_suffix(".saved"))
        status, headers, _ = self.fetch()
        self.assertEqual(status, 503)
        self.assertNotIn("Retry-After", headers)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.calls, [])

    def test_expired_policy_rejects_without_opening_a_hold(self):
        port = self.stack.enter_context(running(make_server(
            listen_port=0, ledger=self.ledger, members=self.members, upstream=self.upstream,
            admission_ready=lambda: False,
        )))
        status, _, raw = self.fetch(port=port)
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(raw)["error"]["code"], "pricing_review_required")
        self.assertEqual(self.calls, [])
        self.assert_spend(0)

    def test_rotated_token_does_not_open_a_new_balance(self):
        self.seed_near_cap()
        old_hold = "reserved-before-key-rotation"
        self.ledger.reserve(MEMBER, old_hold, HOLD)
        replacement = "synthetic-member-replacement-0123456789"
        members = {sha256(replacement.encode()).hexdigest(): MEMBER}
        port = self.stack.enter_context(running(make_server(
            listen_port=0, ledger=self.ledger, members=members, upstream=self.upstream,
        )))
        self.assertEqual(self.fetch(port=port)[0], 401)
        self.assert_local_budget_error(self.fetch(port=port, token=replacement))
        self.assertEqual(self.calls, [])
        self.assert_spend(START_SPENT + HOLD)


class TransportTests(unittest.TestCase):
    def test_fixed_official_transport_does_not_follow_redirect(self):
        wire = b'{"test":"synthetic"}'
        fixed_clock = datetime(2026, 11, 21, tzinfo=timezone.utc)
        with patch("member_dollar_cap.datetime") as clock, patch("member_dollar_cap.HTTPSConnection") as https:
            clock.now.return_value = fixed_clock
            connection = https.return_value
            response = connection.getresponse.return_value.__enter__.return_value
            response.status = 302
            response.headers = {"Location": "https://untrusted.invalid/path"}
            with official_upstream(PRIVATE_UPSTREAM_TOKEN)(wire) as received:
                self.assertEqual(received.status, 302)
            https.assert_called_once()
            self.assertEqual(https.call_args.args, ("api.openai.com", 443))
            self.assertTrue(https.call_args.kwargs["context"].check_hostname)
            connection.request.assert_called_once()
            self.assertEqual(connection.request.call_args.args, ("POST", "/v1/responses"))
            self.assertEqual(connection.request.call_args.kwargs["body"], wire)
            self.assertEqual(connection.request.call_args.kwargs["headers"]["Authorization"],
                             "Bearer " + PRIVATE_UPSTREAM_TOKEN)
            connection.close.assert_called_once()


class LiveRunnerTests(unittest.TestCase):
    def test_one_shot_wrapper_with_a_fake_paid_transport(self):
        calls = []

        @contextmanager
        def fixture(wire):
            calls.append(json.loads(wire))
            result = BytesIO(json.dumps(ANSWER).encode())
            result.status, result.length, result.headers = 200, 0, Message()
            result.headers["Content-Type"] = "application/json"
            yield result

        output = StringIO()
        with patch.object(live, "official_upstream", return_value=fixture), \
                patch.object(live, "price_window_open", return_value=True), redirect_stdout(output):
            self.assertEqual(live.run(PRIVATE_UPSTREAM_TOKEN), 0)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["max_output_tokens"], 64)
        self.assertIn("UPSTREAM_ATTEMPTS=1 SETTLED=YES", output.getvalue())
        self.assertNotIn("synthetic-result", output.getvalue())


if __name__ == "__main__":
    unittest.main()
