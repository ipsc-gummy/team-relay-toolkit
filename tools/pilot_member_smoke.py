#!/usr/bin/env python3
"""Prove the packaged member's SSH -> budget -> CPA -> fake-upstream path."""

import argparse
import ast
from contextlib import contextmanager
from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path
import pwd
import secrets
import socket
import subprocess
import tempfile
from threading import Thread
import time
import zipfile

from pilot_budget import PilotBudget
from pilot_cpa_smoke import MARKER, MODEL, fetch, running_fixture
from pilot_member_gateway import make_server


PROJECT = Path(__file__).resolve().parents[1]
MEMBER = "nobody"  # Existing OS test identity; no account created or changed.
HOST = "127.0.0.1"


def import_script(name):
    spec = spec_from_file_location(name, PROJECT / "程序" / (name + ".py"))
    script = module_from_spec(spec)
    spec.loader.exec_module(script)
    return script


def require(condition, step):
    if not condition:
        raise SystemExit("MEMBER_PILOT_FAIL=" + step)
    print("MEMBER_PILOT_PASS=" + step, flush=True)


def run(*args):
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)


@contextmanager
def process(args):
    job = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    try:
        yield job
    finally:
        if job.poll() is None:
            job.terminate()
            try:
                job.wait(timeout=4)
            except subprocess.TimeoutExpired:
                job.kill()
                job.wait(timeout=4)


def wait_until(probe, step):
    deadline = time.monotonic() + 7
    while time.monotonic() < deadline:
        try:
            if probe():
                return
        except OSError:
            pass
        time.sleep(0.05)
    require(False, step)


def free_ports():
    with socket.socket() as a, socket.socket() as b:
        for sock in (a, b):
            sock.bind((HOST, 0))
        return a.getsockname()[1], b.getsockname()[1]


def listens(port):
    with socket.create_connection((HOST, port), timeout=0.3):
        return True


def policy_and_package(root, port, token):
    enrollment = import_script("开通新人")
    packaging = import_script("打包新人两步接入")
    for key in ("host", "member", "other"):
        require(run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / key)).returncode == 0,
                "fixture-key-" + key)
    public = root / "member.pub"
    fingerprint = run("ssh-keygen", "-lf", str(public)).stdout.decode().split()[1]
    policy, key_line = enrollment.restricted_tunnel_policy(MEMBER, public.read_text().strip(), fingerprint, port)
    auth = root / "auth-keys"
    auth.write_text(key_line)
    auth.chmod(0o644)  # Only an ephemeral public key; sshd reads as the nobody user.
    config = root / "isolated-sshd.conf"
    config.write_text(f"""ListenAddress {HOST}
Port 22
HostKey {root / 'host'}
PidFile {root / 'isolated-sshd.pid'}
AuthorizedKeysFile {auth}
AllowUsers {MEMBER}
PermitRootLogin no
UsePAM yes
StrictModes yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PrintMotd no
LogLevel ERROR
""" + policy)
    require(run("/usr/sbin/sshd", "-t", "-f", str(config)).returncode == 0, "sshd-syntax")
    effective = run("/usr/sbin/sshd", "-T", "-f", str(config), "-C", f"user={MEMBER},host=localhost,addr={HOST}")
    require(effective.returncode == 0 and {f"permitopen {HOST}:{port}", "maxsessions 0", "permitlisten none",
            "allowtcpforwarding local", "authenticationmethods publickey"} <= set(effective.stdout.decode().splitlines()),
            "effective-member-ssh-policy")

    token_path, output = root / "synthetic-token", root / "one-member.zip"
    with os.fdopen(
        os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w"
    ) as file:
        file.write(token + "\n")
    deployment = packaging.load_deployment(HOST, root / "host.pub", port)
    packaging.pack(output, MEMBER, public, token_path, "macos", deployment=deployment)
    with zipfile.ZipFile(output) as bundle:
        require(len(bundle.namelist()) == 7 and output.stat().st_mode & 0o777 == 0o600, "member-package-permissions")
        code = bundle.read("Codex团队接入/程序/切换CodexApp.py").decode()
        constants = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(code).body
                     if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                     and node.targets[0].id in {"HOST", "SSH_PORT", "TARGET", "FINGERPRINTS", "HOST_FP"}}
        require(constants == {"HOST": HOST, "SSH_PORT": 22, "TARGET": f"{HOST}:{port}",
                              "FINGERPRINTS": {MEMBER: fingerprint}, "HOST_FP": deployment.host_fingerprint},
                "package-pinned-gateway-and-identity")
        wire_token = bundle.read("Codex团队接入/中转访问密钥.txt").decode().strip()
        require(wire_token == token, "package-recipient-bearer")
    known = root / "known-hosts"
    known.write_text(constants["HOST"] + " " + deployment.host_key + "\n")
    return config, constants, known, wire_token


def probe(root, config, constants, known, token, cpa_port, cpa_token, ledger, routes):
    base = ["ssh", "-F", "/dev/null", "-T", "-p", str(constants["SSH_PORT"]), "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", f"UserKnownHostsFile={known}", "-o", "ConnectTimeout=3", "-o", "ExitOnForwardFailure=yes"]
    target = MEMBER + "@" + constants["HOST"]
    auth = ["-i", str(root / "member")]
    local, bypass = free_ports()
    with process(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)]) as server:
        wait_until(lambda: server.poll() is None and listens(22), "sshd-loopback-ready")
        require(run(*base, "-i", str(root / "other"), "-N", target).returncode == 255, "wrong-ssh-key-rejected")
        require(run(*base, *auth, target, "true").returncode == 255, "shell-disabled")
        require(run(*base, *auth, "-N", "-R", f"{HOST}:0:{HOST}:{local}", target).returncode == 255,
                "remote-forward-disabled")
        with process([*base, *auth, "-N", "-L", f"{HOST}:{local}:{constants['TARGET']}",
                      "-L", f"{HOST}:{bypass}:{HOST}:{cpa_port}", target]) as tunnel:
            wait_until(lambda: tunnel.poll() is None and fetch(local, "/v1/models", token)[0] == 200,
                       "package-ssh-tunnel")
            require(True, "package-ssh-tunnel")
            try:
                fetch(bypass, "/v1/models", cpa_token)
            except (OSError, ConnectionError):
                require(True, "direct-cpa-forward-blocked-even-with-its-token")
            else:
                require(False, "direct-cpa-forward-blocked-even-with-its-token")
            body = {"model": MODEL, "input": "synthetic", "stream": False}
            require(fetch(local, "/v1/responses", "wrong-fixture-token", body)[0] == 401 and not routes,
                    "wrong-member-bearer-rejected-before-upstream")
            status, _, payload = fetch(local, "/v1/responses", token, body)
            require(status == 200 and MARKER.encode() in payload, "member-json")
            wait_until(lambda: ledger.balance(MEMBER).available == 7, "first-charge-settled")
            status, headers, payload = fetch(local, "/v1/responses", token, dict(body, stream=True))
            require(status == 200 and "text/event-stream" in headers.get("Content-Type", "")
                    and b"response.completed" in payload and MARKER.encode() in payload, "member-sse")
            wait_until(lambda: ledger.balance(MEMBER).available == 4, "second-charge-settled")
            status, _, payload = fetch(local, "/v1/responses", token, body)
            require(status == 429 and b"fixture_budget_exhausted" in payload and len(routes) == 2,
                    "member-over-limit-rejected-before-upstream")


def smoke(archive):
    if (os.geteuid() != 0 or {name for _, name in socket.if_nameindex()} != {"lo"}
            or os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net")):
        raise SystemExit("Root and a separate Linux network namespace with only lo are required")
    pwd.getpwnam(MEMBER)
    # StrictModes rejects the world-writable ancestor of an authorization file.
    with tempfile.TemporaryDirectory(prefix="relay-member-pilot-", dir="/run") as temp, running_fixture(archive) as fixture:
        root = Path(temp)
        root.chmod(0o711)
        cpa_port, cpa_token, routes = fixture
        ledger = PilotBudget.create(root / "credits.sqlite3")
        ledger.add_member(MEMBER, 10)
        token = f"cpa-{MEMBER}-" + secrets.token_hex(32)
        with make_server(listen_port=0, cpa_port=cpa_port, member=MEMBER, member_token=token,
                         cpa_token=cpa_token, ledger=ledger) as server:
            config, constants, known, packaged_token = policy_and_package(root, server.server_port, token)
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                probe(root, config, constants, known, packaged_token, cpa_port, cpa_token, ledger, routes)
            finally:
                server.shutdown()
                worker.join(timeout=3)
    print("MEMBER_PILOT=PASS", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    smoke(parser.parse_args().archive)
