#!/usr/bin/env python3
"""Verify a dedicated project Key once, then keep it private for the team gateway."""

import argparse
from datetime import datetime, timezone
import fcntl
from getpass import GetPassWarning, getpass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
from tempfile import TemporaryDirectory
import warnings

from member_dollar_cap import MODEL, price_window_open, read_private
from smoke_member_dollar_cap_live import run


STATE = Path("/var/lib/sg-budget-relay")
KEY_NAME = "upstream.key"
RECEIPT_NAME = "upstream-verified.json"
KEY_FORMAT = re.compile(rb"sk-proj-[A-Za-z0-9_-]{30,512}")


def check_state(state):
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("expected an owner-only gateway state directory")


def verified(state):
    key = read_private(state / KEY_NAME).strip()
    receipt = json.loads(read_private(state / RECEIPT_NAME))
    return (isinstance(receipt, dict) and receipt.get("schema") == 1 and receipt.get("model") == MODEL
            and isinstance(receipt.get("verified_at"), str) and KEY_FORMAT.fullmatch(key) is not None
            and receipt.get("key_sha256") == sha256(key).hexdigest())


def save_verified(state, key):
    receipt = {"schema": 1, "model": MODEL, "verified_at": datetime.now(timezone.utc).isoformat(),
               "key_sha256": sha256(key).hexdigest()}
    with TemporaryDirectory(prefix=".verified-upstream-", dir=state) as staging:
        staging = Path(staging)
        for name, content in ((KEY_NAME, key + b"\n"), (RECEIPT_NAME, (json.dumps(receipt) + "\n").encode("ascii"))):
            with os.fdopen(os.open(staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        key_installed = False
        try:
            # Exclusive publication prevents overwriting a credential created out of band.
            os.link(staging / KEY_NAME, state / KEY_NAME)
            key_installed = True
            (staging / KEY_NAME).unlink()
            os.link(staging / RECEIPT_NAME, state / RECEIPT_NAME)
            (staging / RECEIPT_NAME).unlink()
        except BaseException:
            if key_installed and not os.path.lexists(state / RECEIPT_NAME):
                (state / KEY_NAME).unlink()
            raise
        directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def verify_and_store(state, prompt, test):
    check_state(state)
    lock = state / "upstream-accept.lock"
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(lock, flags, 0o600), "rb+") as handle:
        info = os.fstat(handle.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("invalid acceptance lock")
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.path.lexists(state / KEY_NAME) or os.path.lexists(state / RECEIPT_NAME):
            if not verified(state):
                raise ValueError("existing Key or receipt is incomplete or unmatched")
            print("UPSTREAM_ACCEPTANCE=ALREADY_VERIFIED")
            return 0
        key = prompt().strip().encode("ascii")
        if KEY_FORMAT.fullmatch(key) is None:
            raise ValueError("expected a dedicated API project's Key")
        if test(key.decode("ascii")) != 0:
            print("UPSTREAM_ACCEPTANCE=UNCONFIRMED; check project usage before any retry.", file=sys.stderr)
            return 1
        save_verified(state, key)
        if not verified(state):
            raise ValueError("stored acceptance failed verification")
        print("UPSTREAM_ACCEPTANCE=PASS; private Key stored for the gateway.")
        return 0


def hidden_key():
    with warnings.catch_warnings():
        warnings.simplefilter("error", GetPassWarning)
        return getpass("Dedicated project API Key (hidden): ")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--i-authorize-one-paid-request", action="store_true")
    args = parser.parse_args()
    if not args.i_authorize_one_paid_request or not sys.stdin.isatty() or not price_window_open() or os.geteuid() == 0:
        parser.error("requires an interactive service-user terminal, explicit approval and a reviewed price window")
    try:
        return verify_and_store(STATE, hidden_key, run)
    except (OSError, ValueError, TypeError, EOFError, GetPassWarning, KeyboardInterrupt):
        print("UPSTREAM_ACCEPTANCE=STOPPED; check file ownership or project usage before retry.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
