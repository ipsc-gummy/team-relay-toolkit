#!/usr/bin/env python3
"""Narrow OpenAI Responses lane with durable per-member spend admission."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPSConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import ssl
import stat
from threading import BoundedSemaphore
import time
from uuid import uuid4

from pilot_budget import BudgetBlocked, BudgetError, InsufficientCredits, PilotBudget


HOST = "127.0.0.1"
OPENAI_HOST = "api.openai.com"
ROUTE = "/v1/responses"
MODEL = "gpt-5.4-mini-2026-03-17"
CAP = 100_000_000_000  # nano-USD; $100, not shared across member IDs
INPUT_RATE, OUTPUT_RATE = 750, 4500  # nano-USD per token, full uncached Standard price
MAX_INPUT, DEFAULT_OUTPUT, MAX_OUTPUT = 400_000, 256, 4096
MAX_REQUEST, MAX_RESPONSE, MAX_EVENT = 128 * 1024, 2 * 1024 * 1024, 256 * 1024
REVIEW_UNTIL = datetime(2026, 12, 22, tzinfo=timezone.utc)
MEMBER_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,128}")
TOOL_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")


class Rejected(ValueError):
    pass


def unique(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise Rejected("duplicate_field")
        obj[key] = value
    return obj


def parse(raw):
    def reject_constant(_):
        raise Rejected("invalid_constant")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject_constant)


class Policy:
    """The accepted schema determines the sole, precomputed pricing upper bound."""

    @staticmethod
    def bound(output):
        return MAX_INPUT * INPUT_RATE + output * OUTPUT_RATE

    def prepare(self, raw):
        data = parse(raw)
        if not isinstance(data, dict) or data.keys() - {
            "model", "input", "stream", "max_output_tokens", "instructions", "tools", "tool_choice",
            "parallel_tool_calls", "reasoning", "store", "include", "prompt_cache_key", "text", "client_metadata",
        }:
            raise Rejected("unsupported_request_fields")
        if data.get("model") != MODEL:
            raise Rejected("unsupported_model")
        supplied, stream = data.get("input"), data.get("stream", False)
        output = data.get("max_output_tokens", DEFAULT_OUTPUT)
        if not self._text_input(supplied) or type(stream) is not bool:
            raise Rejected("only_text_input_supported")
        if type(output) is not int or not 16 <= output <= MAX_OUTPUT:
            raise Rejected("invalid_output_limit")
        self._local_codex_fields(data)
        data.update(service_tier="default", store=False, truncation="disabled", stream=stream,
                    max_output_tokens=output)
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), stream, output

    @staticmethod
    def _local_codex_fields(data):
        if (data.get("store", False) is not False or data.get("tool_choice", "auto") not in ("auto", "none")
                or type(data.get("parallel_tool_calls", False)) is not bool
                or not isinstance(data.get("instructions", ""), str)
                or data.get("include", []) not in ([], ["reasoning.encrypted_content"])
                or not isinstance(data.get("prompt_cache_key", ""), str)):
            raise Rejected("unpriced_or_invalid_request_option")
        # Non-inference client telemetry is unnecessary to the independent project.
        metadata = data.pop("client_metadata", None)
        if metadata is not None and (not isinstance(metadata, dict) or
                                     not all(isinstance(value, str) for value in metadata.values())):
            raise Rejected("invalid_client_metadata")
        reasoning = data.get("reasoning")
        if reasoning is None:
            data.pop("reasoning", None)
        elif (not isinstance(reasoning, dict) or reasoning.keys() - {"effort", "summary"}
              or reasoning.get("effort") not in (None, "none", "low", "medium", "high", "xhigh")
              or reasoning.get("summary") not in (None, "auto", "concise", "detailed")):
            raise Rejected("invalid_reasoning_option")
        text = data.get("text")
        if text is None:
            data.pop("text", None)
        elif (not isinstance(text, dict) or text.keys() - {"verbosity", "format"}
              or text.get("verbosity") not in (None, "low", "medium", "high")
              or text.get("format", {"type": "text"}) != {"type": "text"}):
            raise Rejected("unsupported_text_format")
        tools = data.get("tools", [])
        if not isinstance(tools, list) or len(tools) > 64:
            raise Rejected("unsupported_tools")
        for tool in tools:
            if not isinstance(tool, dict) or not Policy._name(tool.get("name")):
                raise Rejected("unsupported_tools")
            if not isinstance(tool.get("description", ""), str):
                raise Rejected("unsupported_tools")
            kind = tool.get("type")
            if kind == "function" and not tool.keys() - {"type", "name", "description", "parameters", "strict"}:
                if isinstance(tool.get("parameters", {}), dict) and type(tool.get("strict", False)) is bool:
                    continue
            if kind == "custom" and not tool.keys() - {"type", "name", "description", "format"}:
                fmt = tool.get("format", {"type": "text"})
                if fmt == {"type": "text"} or (isinstance(fmt, dict)
                        and fmt.keys() == {"type", "syntax", "definition"} and fmt["type"] == "grammar"
                        and fmt["syntax"] in ("lark", "regex") and isinstance(fmt["definition"], str)):
                    continue
            raise Rejected("hosted_or_unreviewed_tool")

    @staticmethod
    def _name(value):
        return isinstance(value, str) and TOOL_NAME.fullmatch(value) is not None

    @staticmethod
    def _text_input(value):
        if isinstance(value, str):
            return bool(value)
        if not isinstance(value, list) or not 1 <= len(value) <= 256:
            return False
        for message in value:
            if not isinstance(message, dict):
                return False
            kind = message.get("type", "message")
            if kind in ("function_call", "custom_tool_call", "function_call_output", "custom_tool_call_output", "reasoning"):
                if not Policy._local_history_item(message, kind):
                    return False
                continue
            if (message.keys() - {"type", "role", "content", "id", "status", "phase"} or kind != "message"
                    or message.get("role") not in ("system", "developer", "user", "assistant")):
                return False
            if not Policy._item_metadata(message) or message.get("phase") not in (None, "commentary", "final_answer"):
                return False
            content = message.get("content")
            if isinstance(content, str) and content:
                continue
            if (not isinstance(content, list) or not 1 <= len(content) <= 256
                    or any(not Policy._text_part(part, message["role"] == "assistant") for part in content)):
                return False
        return True

    @staticmethod
    def _item_metadata(item):
        return (item.get("status") in (None, "completed", "in_progress", "incomplete")
                and isinstance(item.get("id", ""), str))

    @staticmethod
    def _text_part(part, output):
        if not isinstance(part, dict) or not isinstance(part.get("text"), str) or not part["text"]:
            return False
        if part.get("type") == "input_text":
            return part.keys() == {"type", "text"}
        return (output and part.get("type") == "output_text" and not part.keys() - {"type", "text", "annotations"}
                and part.get("annotations", []) == [])

    @staticmethod
    def _local_history_item(item, kind):
        if not Policy._item_metadata(item):
            return False
        if kind == "reasoning":
            if item.keys() - {"type", "id", "status", "summary", "content", "encrypted_content"}:
                return False
            for field, part_type in (("summary", "summary_text"), ("content", "reasoning_text")):
                entries = item.get(field)
                if entries is not None and (not isinstance(entries, list) or any(
                        not isinstance(part, dict) or part.keys() != {"type", "text"}
                        or part["type"] != part_type or not isinstance(part["text"], str) for part in entries)):
                    return False
            opaque = item.get("encrypted_content")
            return opaque is None or isinstance(opaque, str)
        common = {"type", "id", "status", "call_id"}
        if not isinstance(item.get("call_id"), str) or not item["call_id"]:
            return False
        if kind in ("function_call", "custom_tool_call"):
            text_key = "arguments" if kind == "function_call" else "input"
            return (not item.keys() - common - {"name", text_key} and Policy._name(item.get("name"))
                    and isinstance(item.get(text_key), str))
        output = item.get("output")
        return not item.keys() - common - {"output"} and (isinstance(output, str) or (
            isinstance(output, list) and all(Policy._text_part(part, False) for part in output)))

    @staticmethod
    def completed_cost(response, output):
        if (not isinstance(response, dict) or response.get("object") != "response"
                or response.get("status") != "completed" or response.get("model") != MODEL
                or response.get("service_tier") != "default"):
            raise Rejected("unconfirmed_completion")
        usage = response.get("usage")
        if not isinstance(usage, dict) or usage.keys() - {
            "input_tokens", "output_tokens", "total_tokens", "input_tokens_details", "output_tokens_details"
        }:
            raise Rejected("unknown_usage")
        inp, out, total = (usage.get(key) for key in ("input_tokens", "output_tokens", "total_tokens"))
        if (any(type(value) is not int for value in (inp, out, total))
                or not 0 < inp <= MAX_INPUT or not 0 <= out <= output or total != inp + out):
            raise Rejected("invalid_usage")
        for field, allowed, maximum in (("input_tokens_details", "cached_tokens", inp),
                                        ("output_tokens_details", "reasoning_tokens", out)):
            if field in usage:
                details = usage[field]
                if (not isinstance(details, dict) or details.keys() - {allowed}
                        or (allowed in details and (type(details[allowed]) is not int
                                                    or not 0 <= details[allowed] <= maximum))):
                    raise Rejected("unknown_usage_detail")
        # Account for cached tokens at the full input rate. Reasoning is included in output.
        return inp * INPUT_RATE + out * OUTPUT_RATE


class StreamCompletion:
    """Accept only one complete, matching terminal frame before clean HTTP EOF."""

    def __init__(self, policy, output):
        self.policy, self.output = policy, output
        self.buffer, self.cost, self.size = bytearray(), None, 0
        self.event, self.data, self.event_size = None, [], 0

    def feed(self, chunk):
        self.size += len(chunk)
        if self.size > MAX_RESPONSE:
            raise Rejected("response_too_large")
        self.buffer.extend(chunk)
        while (end := self.buffer.find(b"\n")) != -1:
            line = bytes(self.buffer[:end]).rstrip(b"\r")
            del self.buffer[:end + 1]
            self.event_size += len(line) + 1
            if self.event_size > MAX_EVENT:
                raise Rejected("event_too_large")
            if not line:
                self._end()
            elif line.startswith(b"event:"):
                if self.event is not None:
                    raise Rejected("duplicate_event")
                self.event = line[6:].lstrip(b" ")
            elif line.startswith(b"data:"):
                self.data.append(line[5:].lstrip(b" "))
        if len(self.buffer) + self.event_size > MAX_EVENT:
            raise Rejected("event_too_large")

    def _end(self):
        if self.event is not None or self.data:
            if self.cost is not None or not self.data:
                raise Rejected("unexpected_after_terminal")
            item = parse(b"\n".join(self.data))
            if not isinstance(item, dict) or not isinstance(item.get("type"), str):
                raise Rejected("unknown_event")
            kind = item["type"].encode()
            if self.event is not None and self.event != kind:
                raise Rejected("event_type_mismatch")
            if kind in (b"error", b"response.failed", b"response.incomplete"):
                raise Rejected("unconfirmed_completion")
            if kind == b"response.completed":
                self.cost = self.policy.completed_cost(item.get("response"), self.output)
        self.event, self.data, self.event_size = None, [], 0

    def finish(self, result):
        if self.buffer or self.event is not None or self.data or self.cost is None or result.length not in (None, 0):
            raise Rejected("incomplete_stream")
        return self.cost


def make_server(*, listen_port, ledger, members, upstream, admission_ready=lambda: True):
    """`upstream` is injected for testing; the CLI below uses a single fixed HTTPS destination."""
    policy = Policy()
    members = dict(members)
    if not members or any(not re.fullmatch(r"[0-9a-f]{64}", digest) for digest in members):
        raise ValueError("expected provisioned member token hashes")
    for member in set(members.values()):
        if not 0 < ledger.balance(member).limit <= CAP:
            raise ValueError("member ledger balance exceeds policy cap")
    slots = BoundedSemaphore(16)

    class Server(ThreadingHTTPServer):
        # Bound concurrent handlers before allocating threads or accepting the body.
        def process_request(self, request, address):
            if not slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, address)
            except BaseException:
                slots.release()
                raise

        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                slots.release()

        def handle_error(self, _request, _address):
            pass  # No request details, credentials, or response payloads in server logs.

    class Handler(BaseHTTPRequestHandler):
        timeout = 10
        server_version = "MemberBudget"
        sys_version = ""

        def log_message(self, *_):
            pass

        def send_body(self, status, media, body=None):
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            if body is not None:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body is not None:
                self.wfile.write(body)

        def fail(self, status, code):
            message = {"budget_reached": "Member spending limit reached before forwarding.",
                       "upstream_rejected": "The upstream request was rejected; no retry was made."}.get(code, code)
            self.send_body(status, "application/json", json.dumps({"error": {"message": message,
                           "type": code, "code": code}}).encode())

        def member(self):
            values = self.headers.get_all("Authorization", [])
            if len(values) == 1 and values[0].startswith("Bearer "):
                token = values[0][7:]
                if MEMBER_TOKEN.fullmatch(token):
                    member = members.get(sha256(token.encode("ascii")).hexdigest())
                    if member is not None:
                        return member
            self.fail(401, "unauthorized")
            return None

        def do_GET(self):
            if self.member() is None:
                return
            if self.path != "/v1/models" or self.headers.get_all("Upgrade"):
                self.fail(404, "unsupported_route")
                return
            self.send_body(200, "application/json", json.dumps({"object": "list", "data": [
                {"id": MODEL, "object": "model", "owned_by": "openai", "created": 0}]}).encode())

        def do_POST(self):
            member = self.member()
            if member is None:
                return
            if self.path != ROUTE or self.headers.get_all("Upgrade"):
                return self.fail(404, "unsupported_route")
            length = self.headers.get_all("Content-Length", [])
            if (len(length) != 1 or not re.fullmatch(r"[0-9]{1,7}", length[0])
                    or self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Content-Encoding")):
                return self.fail(400, "invalid_request_framing")
            if not 0 < int(length[0]) <= MAX_REQUEST:
                return self.fail(413, "request_too_large")
            if self.headers.get_content_type() != "application/json":
                return self.fail(415, "expected_json")
            try:
                raw = self.rfile.read(int(length[0]))
                if len(raw) != int(length[0]):
                    raise Rejected("incomplete_request")
                body, stream, limit = policy.prepare(raw)
            except (OSError, ValueError, RecursionError):
                return self.fail(400, "request_not_in_bounded_text_policy")
            if not admission_ready():
                return self.fail(503, "pricing_review_required")
            ticket = uuid4().hex
            try:
                ledger.reserve(member, ticket, policy.bound(limit))
            except (InsufficientCredits, BudgetBlocked):
                return self.fail(400, "budget_reached")  # Recognized terminal error in tested Codex.
            except BudgetError:
                return self.fail(503, "ledger_unavailable")
            self.forward(member, ticket, body, stream, limit)

        def forward(self, member, ticket, body, stream, limit):
            started = False
            try:
                with upstream(body) as result:
                    if result.status != 200:
                        started = True
                        status = result.status if result.status in (400, 401, 403, 404, 408, 429, 500, 502, 503, 504) else 502
                        return self.fail(status, "upstream_rejected")
                    media = "text/event-stream" if stream else "application/json"
                    if result.headers.get_content_type() != media or result.headers.get("Content-Encoding") not in (None, "identity"):
                        raise Rejected("unexpected_upstream_format")
                    if stream:
                        parser = StreamCompletion(policy, limit)
                        started = True
                        self.send_body(200, media)
                        deadline = time.monotonic() + 120
                        while chunk := result.read1(4096):
                            if time.monotonic() > deadline:
                                raise Rejected("stream_deadline")
                            parser.feed(chunk)
                            self.wfile.write(chunk)
                            self.wfile.flush()
                        cost = parser.finish(result)
                    else:
                        answer = result.read(MAX_RESPONSE + 1)
                        if len(answer) > MAX_RESPONSE or result.length not in (0, None):
                            raise Rejected("unchecked_response_length")
                        cost = policy.completed_cost(parse(answer), limit)
                        started = True
                        self.send_body(200, media, answer)
                        self.wfile.flush()
                ledger.settle(member, ticket, cost)
            except (OSError, ValueError, RecursionError, HTTPException, BudgetError):
                # Once sent, uncertainty retains the original durable hold. Never replay.
                if not started:
                    try:
                        self.fail(502, "upstream_charge_unconfirmed")
                    except OSError:
                        pass

    return Server((HOST, listen_port), Handler)


def price_window_open():
    return datetime.now(timezone.utc) < REVIEW_UNTIL


def official_upstream(key):
    context = ssl.create_default_context()

    @contextmanager
    def request(payload):
        if not price_window_open():
            raise Rejected("pricing_review_expired")
        connection = HTTPSConnection(OPENAI_HOST, 443, timeout=25, context=context)
        try:
            connection.request("POST", ROUTE, body=payload, headers={"Authorization": "Bearer " + key,
                               "Content-Type": "application/json", "Accept-Encoding": "identity",
                               "Connection": "close"})
            with connection.getresponse() as response:
                yield response
        finally:
            connection.close()

    return request


def read_private(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as data:
        info = os.fstat(data.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077
                or info.st_nlink != 1 or info.st_size > 32_768):
            raise ValueError("expected an owner-only private file")
        raw = data.read(32_769)
        if len(raw) > 32_768:
            raise ValueError("private file too large")
        return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--members", required=True, type=Path, help="Private JSON mapping token SHA-256 hex to member ID")
    parser.add_argument("--key-file", required=True, type=Path, help="Private file for a dedicated project service-account Key")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--allow-official-billing", action="store_true")
    args = parser.parse_args()
    if not args.allow_official_billing or not 1 <= args.port <= 65535 or not price_window_open():
        parser.error("billing must be explicitly enabled within the current reviewed price window")
    try:
        ledger = args.ledger.absolute()
        parent, info = ledger.parent.lstat(), ledger.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or any(item.st_uid != os.getuid() or item.st_mode & 0o077 for item in (parent, info))):
            raise ValueError("ledger must be in a private local directory and must not be a link")
        key = read_private(args.key_file).decode("ascii").strip()
        if not re.fullmatch(r"sk-proj-[A-Za-z0-9_-]{30,512}", key):
            raise ValueError("invalid project Key")
        members = parse(read_private(args.members))
        if not isinstance(members, dict):
            raise ValueError("invalid member map")
        with make_server(listen_port=args.port, ledger=PilotBudget(ledger), members=members,
                         upstream=official_upstream(key), admission_ready=price_window_open) as server:
            server.serve_forever()
    except (OSError, ValueError, TypeError, BudgetError):
        raise SystemExit("Member gateway not started: check the private configuration and existing ledger.") from None


if __name__ == "__main__":
    main()
