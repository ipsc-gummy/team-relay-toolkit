#!/usr/bin/env python3
"""Prove a packaged fake member's SSH path against the real dollar entrance."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from email.message import Message
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
from threading import Event

from member_dollar_cap import CAP, MODEL, Policy, make_server
from pilot_budget import PilotBudget
from pilot_cpa_smoke import fetch
from pilot_member_smoke import MEMBER, member_tunnel, policy_and_package, require, require_isolated_namespace, wait_until
from test_member_dollar_cap import ANSWER, COMPLETE, DELTA, FINAL, running


def smoke():
    require_isolated_namespace()
    token = f"cpa-{MEMBER}-" + secrets.token_hex(32)
    digest = sha256(token.encode()).hexdigest()
    entered, release = Event(), Event()
    calls = []
    body = {"model": MODEL, "input": "isolated member fixture", "max_output_tokens": 64}

    @contextmanager
    def fixture(payload):
        request = json.loads(payload)
        calls.append(request["input"])
        if request["input"] == "hold last spend":
            entered.set()
            if not release.wait(timeout=6):
                raise ValueError("competing request did not finish in time")
        data = DELTA + COMPLETE if request["stream"] else json.dumps(ANSWER).encode()
        response = BytesIO(data)
        response.status, response.length, response.headers = 200, None, Message()
        response.headers["Content-Type"] = "text/event-stream" if request["stream"] else "application/json"
        yield response

    with TemporaryDirectory(prefix="relay-dollar-pilot-", dir="/run") as work:
        root = Path(work)
        root.chmod(0o711)  # OpenSSH must be able to read the ephemeral authorized public key.
        private = root / "private"
        private.mkdir(mode=0o700)
        ledger = PilotBudget.create(private / "budget.sqlite")
        ledger.add_member(MEMBER, CAP)
        members = {digest: MEMBER}
        with running(make_server(listen_port=0, ledger=ledger, members=members, upstream=fixture)) as gateway, \
                running(make_server(listen_port=0, ledger=ledger, members=members, upstream=fixture)) as alternate:
            route = policy_and_package(root, gateway, token)
            with member_tunnel(root, *route, alternate, token) as tunnel:
                require(fetch(tunnel, "/v1/responses", "wrong-fixture-token", body)[0] == 401 and not calls,
                        "dollar-member-auth")
                status, _, payload = fetch(tunnel, "/v1/responses", token, body)
                require(status == 200 and b"synthetic-result" in payload, "dollar-member-json")
                status, headers, payload = fetch(tunnel, "/v1/responses", token, dict(body, stream=True))
                require(status == 200 and "text/event-stream" in headers.get("Content-Type", "")
                        and b"response.completed" in payload, "dollar-member-sse")
                wait_until(lambda: ledger.balance(MEMBER).available == CAP - 2 * FINAL, "dollar-usage-settled")
                # Set exactly enough available for one more request; no paid or bulk requests.
                ledger.reserve(MEMBER, "fixture-consumed-budget", ledger.balance(MEMBER).available - Policy.bound(64))
                with ThreadPoolExecutor(max_workers=1) as pool:
                    first = pool.submit(fetch, tunnel, "/v1/responses", token, dict(body, input="hold last spend"))
                    try:
                        require(entered.wait(timeout=4), "dollar-last-admission")
                        status, headers, payload = fetch(tunnel, "/v1/responses", token, body)
                        require(status == 400 and b"budget_reached" in payload and not headers.get("Retry-After")
                                and len(calls) == 3 and ledger.balance(MEMBER).available == 0,
                                "dollar-competing-request-denied-before-upstream")
                    finally:
                        release.set()
                    require(first.result(timeout=7)[0] == 200, "dollar-admitted-request-completed")
                wait_until(lambda: ledger.balance(MEMBER).available == Policy.bound(64) - FINAL,
                           "dollar-final-settlement")
    print("MEMBER_DOLLAR_PILOT=PASS", flush=True)


if __name__ == "__main__":
    smoke()
