#!/usr/bin/env python3
"""Prepare a private, reviewable bundle for one new $100 SSH relay member.

This command only stages files. It never changes SSH users, activates keys,
modifies the current member map, creates/resets a ledger, or starts a service.
"""

import argparse
import hashlib
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess

from member_dollar_cap import CAP, parse, read_private
from pilot_budget import BudgetError, PilotBudget, UnknownMember


USER = re.compile(r"[a-z][a-z0-9_-]{0,30}")
DIGEST = re.compile(r"[0-9a-f]{64}")
REPO = Path(__file__).resolve().parents[1]


def _enrollment_policy():
    spec = spec_from_file_location("relay_existing_ssh_policy", REPO / "程序" / "开通新人.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.restricted_tunnel_policy


def _private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("expected a private owner-only state directory")


def _private_ledger(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("expected an existing private owner-only ledger")
    return PilotBudget(path)


def _public_key(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("expected a regular public-key file")
        data = handle.read(8193)
    lines = data.splitlines()
    if len(data) > 8192 or len(lines) != 1:
        raise ValueError("expected exactly one SSH public key")
    return lines[0].decode("ascii")


def _member_map(path, ledger):
    raw = read_private(path)
    members = parse(raw)
    if not isinstance(members, dict) or any(
            not DIGEST.fullmatch(digest) or not isinstance(user, str) or not USER.fullmatch(user) or user == "root"
            for digest, user in members.items()):
        raise ValueError("the active member map is not a valid token SHA-256 map")
    for member in set(members.values()):
        if not 0 < ledger.balance(member).limit <= CAP:
            raise ValueError("existing member balance has an invalid cap")
    return raw, members


def _json(data):
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("ascii")


def _exclusive(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def prepare(*, user, public_key, fingerprint, gateway_port, state_dir, ledger_name, members_name, stage_name):
    if not USER.fullmatch(user) or user == "root":
        raise ValueError("invalid member identity")
    names = (ledger_name, members_name, stage_name)
    if len(set(names)) != len(names) or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", name)
                                          for name in names):
        raise ValueError("state children must have distinct simple names")
    state_dir = state_dir.absolute()
    _private_directory(state_dir)
    ledger_path, map_path, stage = (state_dir / name for name in names)
    ledger = _private_ledger(ledger_path)
    baseline, members = _member_map(map_path, ledger)
    if user in members.values():
        raise ValueError("member is already mapped; use separate credential rotation")
    try:
        ledger.balance(user)
    except UnknownMember:
        pass
    else:
        raise ValueError("member has an existing ledger identity; never reset it")

    ssh_config, authorized = _enrollment_policy()(user, _public_key(public_key), fingerprint, gateway_port)
    # No second key source for this newly enrolled identity. Activation must still
    # check the effective server config, including any earlier Match clauses.
    ssh_config = ssh_config.replace(f"Match User {user}\n", f"Match User {user}\n"
        "    PubkeyAuthentication yes\n    AuthorizedKeysFile .ssh/authorized_keys\n"
        "    AuthorizedKeysCommand none\n    TrustedUserCAKeys none\n", 1)
    member_token = f"cpa-{user}-{secrets.token_hex(32)}"
    digest = hashlib.sha256(member_token.encode("ascii")).hexdigest()
    if digest in members:
        raise ValueError("generated token unexpectedly collides with an existing mapping")
    members[digest] = user
    candidate = _json(members)
    if len(candidate) > 32_768:
        raise ValueError("candidate member map exceeds the gateway's configuration limit")
    receipt = {"schema": 1, "member": user, "target": f"127.0.0.1:{gateway_port}",
               "public_key_fingerprint": fingerprint,
               "ledger": {"file": ledger_name, "action": "add_member_if_absent", "cap_nano_usd": CAP},
               "map": {"file": members_name, "baseline_sha256": hashlib.sha256(baseline).hexdigest(),
                       "candidate_sha256": hashlib.sha256(candidate).hexdigest()}}
    os.mkdir(stage, 0o700)  # Exclusive; an existing directory, file or symlink is never replaced.
    files = {"sshd.conf": ssh_config.encode("ascii"), "authorized_keys": authorized.encode("ascii"),
             "member.token": (member_token + "\n").encode("ascii"), "members.json": candidate,
             "plan.json": _json(receipt)}  # Written last; its presence is the completion marker.
    for name, contents in files.items():
        _exclusive(stage / name, contents)
    return stage


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--user", required=True)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--gateway-port", required=True, type=int)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--ledger", default="budget.sqlite", help="Existing private ledger filename within state-dir")
    parser.add_argument("--members", default="members.json", help="Existing private map filename; use {} to start")
    parser.add_argument("--stage", required=True, help="New private staging directory name within state-dir")
    parser.add_argument("--expected-hostname", required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0 or socket.gethostname() != args.expected_hostname:
        parser.error("run on the independently verified host as its administrator")
    os.umask(0o077)
    try:
        prepare(user=args.user, public_key=args.public_key, fingerprint=args.fingerprint,
                gateway_port=args.gateway_port, state_dir=args.state_dir, ledger_name=args.ledger,
                members_name=args.members, stage_name=args.stage)
    except (BudgetError, OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"MEMBER_STAGE=STOPPED ({type(exc).__name__}); active state was not changed.\n")
    print("MEMBER_STAGE=READY; no account, service, ledger or member map activated.")


if __name__ == "__main__":
    main()
