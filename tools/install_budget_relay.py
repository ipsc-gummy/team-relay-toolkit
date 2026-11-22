#!/usr/bin/env python3
"""Install a disabled budget relay or switch its existing immutable release.

Ubuntu/systemd administrator tool. Does not enable/start a disabled service,
change SSH, generate/store keys, enrol members, or issue model requests.
"""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
from http.client import HTTPConnection, HTTPException
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
from tempfile import TemporaryDirectory
import time
from uuid import uuid4

from pilot_budget import BudgetError, PilotBudget


IDENTITY = "sg-budget-relay"
BASE = Path("/opt") / IDENTITY
STATE = Path("/var/lib") / IDENTITY
UNIT = IDENTITY + ".service"
UNIT_PATH = Path("/etc/systemd/system") / UNIT
ADMIN_LOCK = Path("/run/lock/sg-budget-relay-admin.lock")
PORT = 18322
FILES = ("tools/member_dollar_cap.py", "tools/pilot_budget.py", "tools/smoke_member_dollar_cap_live.py",
         "tools/accept_budget_upstream.py", "tools/provision_budget_member.py", "程序/开通新人.py")
SHA = re.compile(r"[0-9a-f]{40}")
PYTHON = "/usr/bin/python3"
SERVICECTL = "/usr/bin/systemctl"


class Stop(RuntimeError):
    pass


def run(*args):
    return subprocess.run(args, capture_output=True, check=True, timeout=40, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}).stdout


def require(ok, reason):
    if not ok:
        raise Stop(reason)


def regular(path, owner, mode):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as handle:
        value = os.fstat(handle.fileno())
        require(stat.S_ISREG(value.st_mode) and value.st_uid == owner and value.st_nlink == 1
                and stat.S_IMODE(value.st_mode) == mode and value.st_size <= 1024 * 1024,
                "unsafe regular file ownership, permissions or size")
        data = handle.read(1024 * 1024 + 1)
        require(len(data) <= 1024 * 1024, "state file grew during verification")
        return data


def directory(path, owner, mode):
    value = path.lstat()
    require(stat.S_ISDIR(value.st_mode) and value.st_uid == owner and stat.S_IMODE(value.st_mode) == mode,
            "unsafe directory ownership or permissions")


def exists(path):
    return os.path.lexists(path)


def exclusive(path, data, mode):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "wb") as out:
        os.fchmod(out.fileno(), mode)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


@contextmanager
def lock():
    fd = os.open(ADMIN_LOCK, os.O_WRONLY | os.O_CREAT | os.O_NONBLOCK | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, "unsafe shared administrator lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def source(repo, revision):
    command = ("/usr/bin/git", "-C", str(repo), "-c", "core.hooksPath=/dev/null", "cat-file")
    require(SHA.fullmatch(revision) is not None and run(*command, "-t", revision) == b"commit\n",
            "expected one audited full Git commit")
    result = {}
    for name in FILES:
        data = run(*command, "blob", f"{revision}:{name}")
        require(0 < len(data) <= 1024 * 1024, "unexpected runtime source size")
        compile(data, name, "exec")
        result[name] = data
    return result


def manifest(revision, files):
    return (json.dumps({"commit": revision, "sha256": {path: hashlib.sha256(data).hexdigest()
                        for path, data in files.items()}}, ensure_ascii=True, sort_keys=True) + "\n").encode("ascii")


def check_release(revision):
    require(SHA.fullmatch(revision) is not None, "invalid release identifier")
    root = BASE / "releases" / revision
    owner = os.geteuid()  # CLI requires root; this also permits disposable unprivileged fixture tests.
    directory(root, owner, 0o755)
    for name in {Path(name).parent for name in FILES}:
        directory(root / name, owner, 0o755)
    data = {name: regular(root / name, owner, 0o644) for name in FILES}
    require(regular(root / "manifest.json", owner, 0o644) == manifest(revision, data), "release manifest mismatch")


def stage(revision, files):
    releases = BASE / "releases"
    destination = releases / revision
    if exists(destination):
        check_release(revision)
        require(regular(destination / "manifest.json", os.geteuid(), 0o644) == manifest(revision, files),
                "different existing release")
        return
    with TemporaryDirectory(prefix=".stage-", dir=releases) as temporary:
        root = Path(temporary) / revision
        root.mkdir(mode=0o755)
        root.chmod(0o755)
        for parent in {Path(name).parent for name in files}:
            (root / parent).mkdir(mode=0o755)
            (root / parent).chmod(0o755)
        for name, data in files.items():
            exclusive(root / name, data, 0o644)
        exclusive(root / "manifest.json", manifest(revision, files), 0o644)
        require(not exists(destination), "release appeared concurrently")
        root.rename(destination)
    check_release(revision)


def current():
    path = BASE / "current"
    value = path.lstat()
    require(stat.S_ISLNK(value.st_mode) and value.st_uid == os.geteuid(), "unsafe current release pointer")
    match = re.fullmatch(r"releases/([0-9a-f]{40})", os.readlink(path))
    require(match is not None, "current pointer is outside the managed release directory")
    check_release(match[1])
    return match[1]


def select(revision):
    check_release(revision)
    scratch = BASE / (".current-" + uuid4().hex)
    scratch.symlink_to(f"releases/{revision}")
    try:
        os.replace(scratch, BASE / "current")
    finally:
        if exists(scratch):
            scratch.unlink()


def unit(port):
    return f"""[Unit]
Description=Team budget relay (loopback only)
After=network.target
ConditionPathExists={STATE}/upstream-verified.json

[Service]
Type=exec
User={IDENTITY}
Group={IDENTITY}
UMask=0077
ExecStart={PYTHON} -B -E -s {BASE}/current/tools/member_dollar_cap.py --ledger {STATE}/budget.sqlite --members {STATE}/members.json --key-file {STATE}/upstream.key --port {port} --allow-official-billing
Restart=no
TimeoutStartSec=20s
TimeoutStopSec=20s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths={STATE}

[Install]
WantedBy=multi-user.target
""".encode("ascii")


def ctl(*args):
    return run(SERVICECTL, "--no-pager", *args)


def status():
    columns = ("LoadState", "ActiveState", "MainPID", "FragmentPath", "DropInPaths", "UnitFileState")
    raw = ctl("show", "--all", *("--property=" + key for key in columns), UNIT).decode("utf-8", "strict")
    result = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    require(set(columns) <= result.keys(), "incomplete service status")
    require(not result["DropInPaths"], "unexpected service drop-in")
    return result


def listeners(port):
    return run("/usr/bin/ss", "-H", "-ltnp", "sport", "=", f":{port}").decode().splitlines()


def health(port, expected=None):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        loaded = status()
        pid = int(loaded["MainPID"])
        rows = listeners(port)
        if loaded["ActiveState"] == "active" and pid > 0 and (expected is None or pid != expected) and len(rows) == 1:
            fields = rows[0].split()
            if len(fields) >= 6 and fields[3] == f"127.0.0.1:{port}" and f"pid={pid}," in rows[0]:
                client = HTTPConnection("127.0.0.1", port, timeout=1)
                try:
                    client.request("GET", "/v1/models")
                    response = client.getresponse()
                    require(response.status == 401, "unauthenticated local probe was not rejected")
                    return
                except (OSError, HTTPException):
                    pass
                finally:
                    client.close()
        time.sleep(0.1)
    raise Stop("relay failed loopback listener or health validation")


def identity(create=False):
    try:
        value = pwd.getpwnam(IDENTITY)
    except KeyError:
        require(create, "dedicated service account missing")
        run("/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", str(STATE),
            "--shell", "/usr/sbin/nologin", IDENTITY)
        value = pwd.getpwnam(IDENTITY)
    require(value.pw_uid > 0 and value.pw_gid > 0 and value.pw_dir == str(STATE)
            and value.pw_shell == "/usr/sbin/nologin" and run("/usr/bin/id", "-Gn", IDENTITY).split() == [IDENTITY.encode()],
            "existing service identity does not match its dedicated account")
    return value


def state_files(service, initialize=False):
    ledger, members = STATE / "budget.sqlite", STATE / "members.json"
    if not exists(STATE):
        require(initialize, "existing relay state is missing; refusing to create a fresh ledger")
        STATE.mkdir(mode=0o700)
        PilotBudget.create(ledger)
        exclusive(members, b"{}\n", 0o600)
        for path in (ledger, members, STATE):
            os.chown(path, service.pw_uid, service.pw_gid)
    directory(STATE, service.pw_uid, 0o700)
    value = ledger.lstat()
    require(stat.S_ISREG(value.st_mode) and value.st_nlink == 1 and value.st_uid == service.pw_uid
            and stat.S_IMODE(value.st_mode) == 0o600, "invalid or missing existing budget ledger")
    mapping = json.loads(regular(members, service.pw_uid, 0o600))
    require(isinstance(mapping, dict), "invalid existing member map")
    if initialize:
        require(not mapping and not exists(STATE / "upstream.key") and not exists(STATE / "upstream-verified.json"),
                "initial install refuses an existing live member map or upstream key")


def install(revision, files, port):
    old = status()
    require(old["LoadState"] == "not-found" and old["ActiveState"] == "inactive" and not old["FragmentPath"]
            and not exists(UNIT_PATH) and not exists(BASE / "current") and not listeners(port),
            "existing service, pointer or port conflict; nothing was activated")
    for path in (BASE, BASE / "releases"):
        if not exists(path):
            path.mkdir(mode=0o755)
            path.chmod(0o755)
        directory(path, os.geteuid(), 0o755)
    service = identity(create=True)
    state_files(service, initialize=True)
    stage(revision, files)
    select(revision)
    installed_unit = False
    try:
        with TemporaryDirectory(prefix=".sg-budget-unit-", dir=UNIT_PATH.parent) as temp:
            prepared = Path(temp) / UNIT
            exclusive(prepared, unit(port), 0o644)
            run("/usr/bin/systemd-analyze", "verify", str(prepared))
            os.link(prepared, UNIT_PATH)
            installed_unit = True
        ctl("daemon-reload")
        loaded = status()
        require(loaded["LoadState"] == "loaded" and loaded["FragmentPath"] == str(UNIT_PATH)
                and loaded["ActiveState"] == "inactive" and loaded["UnitFileState"] == "disabled"
                and not listeners(port), "new unit was not staged disabled and inactive")
    except (OSError, Stop, subprocess.SubprocessError):
        try:
            if installed_unit:
                UNIT_PATH.unlink()
                ctl("daemon-reload")
        finally:
            (BASE / "current").unlink()
        raise


def switch(revision, port, restart_active, files=None):
    directory(BASE, os.geteuid(), 0o755)
    directory(BASE / "releases", os.geteuid(), 0o755)
    previous = current()
    require(regular(UNIT_PATH, os.geteuid(), 0o644) == unit(port), "installed unit differs from the reviewed template")
    state_files(identity())
    running = status()
    state, pid = running["ActiveState"], int(running["MainPID"])
    require(running["LoadState"] == "loaded" and running["FragmentPath"] == str(UNIT_PATH)
            and state in ("active", "inactive"), "service ownership or lifecycle state cannot be confirmed")
    if state == "active":
        require(restart_active, "active service requires the explicit restart flag")
        health(port)
    else:
        require(pid == 0 and not listeners(port), "inactive service port is unexpectedly in use")
    if files is not None:
        stage(revision, files)
    check_release(revision)
    if revision == previous:
        return
    select(revision)
    try:
        if state == "active":
            ctl("restart", UNIT)
            health(port, expected=pid)
        require(current() == revision, "release pointer could not be verified")
    except (OSError, Stop, subprocess.SubprocessError) as failure:
        try:
            select(previous)
            if state == "active":
                ctl("restart", UNIT)
                health(port)
            require(current() == previous, "release rollback pointer could not be verified")
        except (OSError, Stop, subprocess.SubprocessError):
            raise Stop("release rollback could not be confirmed; budget state was not changed") from None
        raise Stop("release change failed; previous release restored (budget state unchanged)") from failure


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("action", choices=("install", "upgrade", "rollback"))
    parser.add_argument("--commit", required=True, help="independently reviewed full Git SHA")
    parser.add_argument("--repo", type=Path, help="trusted local checkout containing that commit; no network fetch")
    parser.add_argument("--restart-active", action="store_true", help="permit restart of this active relay only")
    args = parser.parse_args(argv)
    if (os.geteuid() != 0 or socket.gethostname() != args.expected_hostname or not SHA.fullmatch(args.commit)
            or not 1024 <= args.port <= 65535 or args.port == 8317
            or (args.action == "rollback") == (args.repo is not None)
            or (args.action == "install" and args.restart_active)):
        parser.error("requires the verified administrator host, dedicated port, explicit commit, and local repo for install/upgrade")
    os.umask(0o077)
    try:
        with lock():
            files = source(args.repo.absolute(), args.commit) if args.repo else None
            if args.action == "install":
                install(args.commit, files, args.port)
            else:
                switch(args.commit, args.port, args.restart_active, files)
    except Stop as exc:
        parser.exit(1, f"RELAY_INSTALL=STOPPED: {exc}.\n")
    except (BudgetError, OSError, ValueError, SyntaxError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"RELAY_INSTALL=STOPPED ({type(exc).__name__}); check the dedicated service locally.\n")
    print(f"RELAY_INSTALL=OK action={args.action} commit={args.commit} port={args.port}")


if __name__ == "__main__":
    main()
