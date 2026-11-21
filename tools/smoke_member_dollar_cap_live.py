#!/usr/bin/env python3
"""Opt-in single paid Responses call; prompt for the dedicated project's Key on the TTY."""

from contextlib import contextmanager
import argparse
from getpass import GetPassWarning, getpass
from hashlib import sha256
from http.client import HTTPConnection
import json
from pathlib import Path
import re
from secrets import token_hex
import sys
from tempfile import TemporaryDirectory
from threading import Lock, Thread
import warnings

from member_dollar_cap import CAP, HOST, MODEL, Policy, ROUTE, make_server, official_upstream, price_window_open
from pilot_budget import PilotBudget


def run(key):
    output = 64
    token = token_hex(32)
    member = "one-shot-live-member"
    count = 0
    lock = Lock()
    upstream = official_upstream(key)

    @contextmanager
    def run_once(body):
        nonlocal count
        with lock:
            if count:
                raise ValueError("one request maximum")
            count += 1
        with upstream(body) as result:
            yield result

    with TemporaryDirectory(prefix="member-live-once-") as tmp:
        ledger = PilotBudget.create(Path(tmp) / "ledger.sqlite")
        # Starting new, with a hard cap far below $100 for this one-off run.
        upper = Policy.bound(output)
        ledger.add_member(member, upper)
        members = {sha256(token.encode()).hexdigest(): member}
        with make_server(listen_port=0, ledger=ledger, members=members, upstream=run_once,
                         admission_ready=price_window_open) as server:
            worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            worker.start()
            conn = HTTPConnection(HOST, server.server_port, timeout=65)
            try:
                conn.request("POST", ROUTE, body=json.dumps({"model": MODEL, "max_output_tokens": output,
                             "input": "Reply with only the word OK.", "stream": False}).encode(),
                             headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
                with conn.getresponse() as result:
                    status = result.status
                    result.read()  # Do not emit any prompt, response content, headers, or identifiers.
            finally:
                conn.close()
                server.shutdown()
                worker.join(timeout=2)
        observed = ledger.balance(member)
        with lock:
            attempts = count
        passed = status == 200 and attempts == 1 and not observed.blocked and 0 < observed.committed < upper
        print(f"LIVE_STATUS={status} UPSTREAM_ATTEMPTS={attempts} SETTLED={'YES' if passed else 'NO'} "
              f"ACCOUNTED_NANO_USD={observed.committed} SAFE_BOUND_NANO_USD={upper}")
        return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--i-authorize-one-paid-request", action="store_true")
    args = parser.parse_args()
    if not args.i_authorize_one_paid_request or not sys.stdin.isatty() or not price_window_open():
        parser.error("one paid request requires the explicit flag, an interactive terminal and a reviewed price window")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            key = getpass("Dedicated project API Key (hidden): ").strip()
        if not re.fullmatch(r"sk-proj-[A-Za-z0-9_-]{30,512}", key):
            parser.error("expected an API project Key, never a ChatGPT token")
        return run(key)
    except (OSError, EOFError, GetPassWarning, KeyboardInterrupt):
        print("LIVE_UNCONFIRMED: do not rerun until you verify project usage.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
