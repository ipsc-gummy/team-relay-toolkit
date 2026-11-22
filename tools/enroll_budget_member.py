#!/usr/bin/env python3
"""Stage, then explicitly activate one Mac member on the dedicated Ubuntu relay."""

import argparse
from datetime import datetime, timezone
import fcntl
from hashlib import sha256
from http.client import HTTPConnection
from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import tempfile
import time

from member_dollar_cap import CAP, MODEL, parse
from pilot_budget import BudgetError, UnknownMember
from provision_budget_member import USER, _enrollment_policy, _private_ledger, prepare


SERVICE = "sg-budget-relay"
UNIT = SERVICE + ".service"
STATE = Path("/var/lib") / SERVICE
LOCK = Path("/run/lock") / (SERVICE + "-admin.lock")
SSH_UNIT = "ssh.service"
SSH_INCLUDE = Path("/etc/ssh/sshd_config.d")
HOST_KEY = Path("/etc/ssh/ssh_host_ed25519_key.pub")
STAGES = Path("/var/lib/sg-budget-relay-enrollments")
HOMES = Path("/home")
PORT = 18322
REPO = Path(__file__).resolve().parents[1]


class Stopped(RuntimeError):
    pass


def check(ok, message):
    if not ok:
        raise Stopped(message)


def read(path, uid=0):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        info = os.fstat(file.fileno())
        check(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
              and info.st_uid == uid and info.st_nlink == 1 and info.st_size <= 32768, "unsafe private file")
        data = file.read(32769)
    check(len(data) <= 32768, "private file too large")
    return data


def absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def private_dir(path, uid=0):
    info = path.lstat()
    check(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == uid,
          "unsafe private directory")


def run(*args, allow=False):
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
    result = subprocess.run(args, capture_output=True, text=True, timeout=25, env=env)
    check(allow or result.returncode == 0, f"{Path(args[0]).name} failed")
    return result


def as_user(user, fn):
    """Run only a local ledger/staging operation; secrets never pass in argv or output."""
    child = os.fork()
    if child == 0:
        try:
            os.setgroups([])
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)
            fn()
        except (BudgetError, OSError, ValueError, Stopped, subprocess.SubprocessError):
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    check(status == 0, "state staging or ledger operation failed")


def write(path, data, mode=0o600):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "wb") as out:
        os.fchmod(out.fileno(), mode)
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def atomic_map(path, expected, data, user):
    check(read(path, user.pw_uid) == expected, "member map changed since preparation")
    fd, name = tempfile.mkstemp(prefix=".members-update-", dir=path.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), 0o600)
            os.fchown(out.fileno(), user.pw_uid, user.pw_gid)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        check(read(path, user.pw_uid) == expected, "member map changed during activation")
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        tmp.unlink(missing_ok=True)


def key_accepted(state, uid):
    key = read(state / "upstream.key", uid).strip()
    receipt = parse(read(state / "upstream-verified.json", uid))
    check(re.fullmatch(rb"sk-proj-[A-Za-z0-9_-]{30,512}", key) is not None
          and isinstance(receipt, dict) and receipt.get("schema") == 1 and receipt.get("model") == MODEL
          and receipt.get("key_sha256") == sha256(key).hexdigest(), "unaccepted upstream key")
    when = datetime.fromisoformat(str(receipt.get("verified_at", "")).replace("Z", "+00:00"))
    check(when.utcoffset() == timezone.utc.utcoffset(when) and when <= datetime.now(timezone.utc),
          "invalid acceptance time")


def safe_user(user):
    check(isinstance(user, str) and USER.fullmatch(user) and user != "root" and user != SERVICE, "invalid member identity")
    return user


def packer():
    spec = spec_from_file_location("budget_member_packer", REPO / "程序" / "打包新人两步接入.py")
    loaded = module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def stage_member(args, service, stage):
    user = safe_user(args.user)
    check(not stage.exists() and not stage.is_symlink(), "stage already exists")
    package = packer()
    deployment = package.load_deployment(args.server_ip, HOST_KEY, PORT, args.host_fingerprint)
    stage.mkdir(mode=0o700)
    # Let the service UID read only a sanitized public key; root alone owns the final private output.
    from provision_budget_member import _public_key
    public = _public_key(args.public_key).encode("ascii") + b"\n"
    service_stage = STATE / ("stage-" + stage.name)
    check(absent(service_stage), "service staging path already exists")
    in_file = STATE / ("input-" + stage.name + ".pub")
    write(in_file, public, 0o644)
    try:
        as_user(service, lambda: prepare(user=user, public_key=in_file, fingerprint=args.fingerprint,
                gateway_port=PORT, state_dir=STATE, ledger_name="budget.sqlite",
                members_name="members.json", stage_name=service_stage.name))
    finally:
        in_file.unlink()
    private_dir(service_stage, service.pw_uid)
    for name in ("sshd.conf", "authorized_keys", "member.token", "members.json", "plan.json"):
        write(stage / name, read(service_stage / name, service.pw_uid))
    for name in ("sshd.conf", "authorized_keys", "member.token", "members.json", "plan.json"):
        (service_stage / name).unlink()
    service_stage.rmdir()
    write(stage / "member.pub", public)
    package.pack(stage / "member-mac.zip", user, stage / "member.pub", stage / "member.token",
                 "macos", deployment, True)
    write(stage / "STAGED", b"budget-mac-v1\n")


def validate_plan(stage, active, *, root_uid=0):
    private_dir(stage, root_uid)
    check(read(stage / "STAGED", root_uid) == b"budget-mac-v1\n", "stage not complete")
    plan = parse(read(stage / "plan.json", root_uid))
    check(isinstance(plan, dict), "incorrect enrollment plan")
    user = safe_user(plan.get("member"))
    check(plan.get("schema") == 1 and plan.get("target") == f"127.0.0.1:{PORT}"
          and plan.get("ledger") == {"file": "budget.sqlite", "action": "add_member_if_absent", "cap_nano_usd": CAP},
          "incorrect enrollment plan")
    candidate = read(stage / "members.json", root_uid)
    check(plan.get("map") == {"file": "members.json", "baseline_sha256": sha256(active).hexdigest(),
                             "candidate_sha256": sha256(candidate).hexdigest()}, "stale or changed member map")
    token = read(stage / "member.token", root_uid).strip()
    check(re.fullmatch(rb"cpa-" + user.encode() + rb"-[0-9a-f]{64}", token), "wrong member token")
    members = parse(active)
    digest = sha256(token).hexdigest()
    check(isinstance(members, dict) and user not in members.values() and digest not in members
          and parse(candidate) == (members | {digest: user}), "candidate changes existing authorization")
    bare = read(stage / "member.pub", root_uid).rstrip(b"\n").decode("ascii")
    config, key_line = _enrollment_policy()(user, bare, plan.get("public_key_fingerprint"), PORT)
    config = config.replace(f"Match User {user}\n", f"Match User {user}\n"
        "    PubkeyAuthentication yes\n    AuthorizedKeysFile .ssh/authorized_keys\n"
        "    AuthorizedKeysCommand none\n    TrustedUserCAKeys none\n", 1)
    check(read(stage / "sshd.conf", root_uid) == config.encode("ascii")
          and read(stage / "authorized_keys", root_uid) == key_line.encode("ascii"), "SSH staged policy changed")
    return user, members, candidate, token, config.encode("ascii"), key_line.encode("ascii")


def state_of(unit):
    return run("/usr/bin/systemctl", "is-active", unit, allow=True).stdout.strip()


def gateway_listener(*, running):
    lines = run("/usr/bin/ss", "-H", "-ltnp", f"sport = :{PORT}").stdout.splitlines()
    if not running:
        return not lines
    raw_pid = run("/usr/bin/systemctl", "show", UNIT, "-p", "MainPID", "--value").stdout.strip()
    return (raw_pid.isdigit() and int(raw_pid) > 0 and len(lines) == 1
            and len(lines[0].split()) >= 5 and lines[0].split()[3] == f"127.0.0.1:{PORT}"
            and set(re.findall(r"\bpid=(\d+)\b", lines[0])) == {raw_pid})


def ssh_effective(user):
    return run("/usr/sbin/sshd", "-T", "-C", f"user={user},host=localhost,addr=198.51.100.10").stdout


def check_effective(user):
    required = {"authenticationmethods publickey", "pubkeyauthentication yes", "passwordauthentication no",
                "kbdinteractiveauthentication no", "strictmodes yes", "usepam yes", "authorizedkeysfile .ssh/authorized_keys",
                "authorizedkeyscommand none", "trustedusercakeys none", "allowtcpforwarding local",
                "allowstreamlocalforwarding no", f"permitopen 127.0.0.1:{PORT}", "permitlisten none", "maxsessions 0",
                "permittty no", "allowagentforwarding no", "x11forwarding no", "permituserrc no", "permittunnel no",
                "gatewayports no", "disableforwarding no"}
    check(required <= set(ssh_effective(user).splitlines()), "effective OpenSSH policy does not match expected restrictions")


def health(token):
    end = time.monotonic() + 8
    while time.monotonic() < end:
        conn = HTTPConnection("127.0.0.1", PORT, timeout=1)
        try:
            headers = {"Authorization": "Bearer " + token.decode("ascii")} if token else {}
            conn.request("GET", "/v1/models", headers=headers)
            response = conn.getresponse()
            if token and response.status == 200:
                return [item["id"] for item in parse(response.read(32769))["data"]] == [MODEL]
            if not token and response.status == 401:
                return True
        except (OSError, ValueError):
            pass
        finally:
            conn.close()
        time.sleep(0.15)
    return False


def activate(stage, service, admin):
    active_path = STATE / "members.json"
    active = read(active_path, service.pw_uid)
    user, old_members, candidate, token, rule, key_line = validate_plan(stage, active)
    key_accepted(STATE, service.pw_uid)
    check(absent(stage / "ACTIVATING") and absent(stage / "ACTIVATED"), "previous activation needs review")
    check(state_of(SSH_UNIT) == "active", "host SSH service must be running")
    enabled = run("/usr/bin/systemctl", "is-enabled", UNIT, allow=True).stdout.strip()
    before = state_of(UNIT)
    check((bool(old_members) and before == "active" and enabled == "enabled" and gateway_listener(running=True)
           and health(None)) or (not old_members and before == "inactive" and enabled == "disabled"
           and gateway_listener(running=False)), "unexpected budget service or port status")
    fields = run("/usr/bin/systemctl", "show", UNIT, "-p", "FragmentPath", "-p", "User", "-p", "DropInPaths",
                 "-p", "ExecStart").stdout
    check({f"FragmentPath=/etc/systemd/system/{UNIT}", "User=" + SERVICE, "DropInPaths="} <= set(fields.splitlines()),
          "unexpected gateway unit identity")
    command = next((line for line in fields.splitlines() if line.startswith("ExecStart=")), "")
    check("path=/usr/bin/python3 ; argv[]=/usr/bin/python3 " in command
          and "/opt/sg-budget-relay/current/tools/member_dollar_cap.py " in command
          and all(f"--{option} {value}" in command for option, value in (
              ("port", PORT), ("ledger", STATE / "budget.sqlite"), ("members", active_path),
              ("key-file", STATE / "upstream.key"))) and "--allow-official-billing" in command,
          "unexpected gateway startup command")
    check(all(run("/usr/bin/getent", database, user, allow=True).returncode == 2 for database in ("passwd", "group")),
          "existing Linux identity is not eligible")
    home = HOMES / user
    dropin = SSH_INCLUDE / f"92-sg-budget-{user}.conf"
    check(absent(home) and absent(dropin), "SSH member files already exist")
    existing_ssh = {"root", admin, *old_members.values()}
    for path in SSH_INCLUDE.glob("92-cliproxyapi-*.conf"):
        legacy = path.stem.removeprefix("92-cliproxyapi-")
        if USER.fullmatch(legacy):
            existing_ssh.add(legacy)
    ssh_before = {name: ssh_effective(name) for name in existing_ssh}
    run("/usr/sbin/sshd", "-t")
    write(stage / "ACTIVATING", b"keep ledger on every rollback\n")
    write(stage / "members.before.json", active)
    map_attempted = rule_added = made_user = made_home = made_ssh = made_key = False
    try:
        def append_member():
            ledger = _private_ledger(STATE / "budget.sqlite")
            for previous in set(old_members.values()):
                check(0 < ledger.balance(previous).limit <= CAP, "existing ledger identity invalid")
            try:
                ledger.balance(user)
            except UnknownMember:
                ledger.add_member(user, CAP)
            else:
                raise Stopped("existing ledger identity; refusing to reset")

        as_user(service, append_member)
        map_attempted = True
        atomic_map(active_path, active, candidate, service)
        run("/usr/bin/systemctl", "restart" if old_members else "start", UNIT)
        check(health(None) and health(token) and gateway_listener(running=True), "member gateway health check failed")
        write(dropin, rule, 0o644)
        rule_added = True
        run("/usr/sbin/sshd", "-t")
        check_effective(user)
        check(all(ssh_effective(name) == prior for name, prior in ssh_before.items()), "unrelated SSH rule changed")
        run("/usr/bin/systemctl", "reload", SSH_UNIT)
        # New account gets no login shell and no key until both the gateway and effective SSH settings are verified.
        run("/usr/sbin/useradd", "--no-create-home", "--user-group", "--home-dir", str(home),
            "--shell", "/usr/sbin/nologin", "--comment", "Budget relay tunnel only", user)
        made_user = True
        home.mkdir(mode=0o755)
        made_home = True
        home.chmod(0o755)
        keys = home / ".ssh"
        keys.mkdir(mode=0o755)
        made_ssh = True
        keys.chmod(0o755)
        check(run("/usr/bin/id", "-nG", user).stdout.strip() == user, "unexpected supplementary groups")
        check_effective(user)
        write(keys / "authorized_keys", key_line, 0o644)
        made_key = True
        if not old_members:
            run("/usr/bin/systemctl", "enable", UNIT)
        write(stage / "ACTIVATED", b"private package only; not sent\n")
    except Exception:
        # Remove this enrollment's ability to authenticate first. Preserve all budget rows, even an unused new row.
        for flag, step in (
            (made_key, lambda: (home / ".ssh/authorized_keys").unlink()),
            (made_ssh, lambda: (home / ".ssh").rmdir()),
            (made_home, home.rmdir),
            (made_user, lambda: run("/usr/sbin/userdel", user)),
            (rule_added, dropin.unlink),
            (rule_added, lambda: (run("/usr/sbin/sshd", "-t"), run("/usr/bin/systemctl", "reload", SSH_UNIT))),
        ):
            if flag:
                try:
                    step()
                except (OSError, ValueError, Stopped, subprocess.SubprocessError):
                    print("MEMBER_ROLLBACK=REQUIRES_ADMIN_REVIEW", flush=True)
        if map_attempted:
            try:
                observed = read(active_path, service.pw_uid)
                if observed == candidate:
                    atomic_map(active_path, candidate, active, service)
                    if old_members:
                        run("/usr/bin/systemctl", "restart", UNIT)
                        check(health(None) and gateway_listener(running=True), "original gateway health check failed")
                    else:
                        run("/usr/bin/systemctl", "stop", UNIT)
                        run("/usr/bin/systemctl", "disable", UNIT)
                        check(state_of(UNIT) == "inactive" and gateway_listener(running=False),
                              "original gateway was not stopped")
                else:
                    check(observed == active, "another writer changed the gateway map")
            except (OSError, ValueError, Stopped, subprocess.SubprocessError):
                print("MEMBER_ROLLBACK=REQUIRES_ADMIN_REVIEW", flush=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-hostname", required=True)
    parser.add_argument("--stage", required=True, help="New name for staging; same name when activating")
    modes = parser.add_subparsers(dest="action", required=True)
    staged = modes.add_parser("stage")
    staged.add_argument("--user", required=True)
    staged.add_argument("--public-key", required=True, type=Path)
    staged.add_argument("--fingerprint", required=True)
    staged.add_argument("--server-ip", required=True)
    staged.add_argument("--host-fingerprint", required=True)
    live = modes.add_parser("activate")
    live.add_argument("--admin-login", required=True, help="Existing administrator to compare SSH policy before/after")
    args = parser.parse_args()
    if (os.uname().sysname != "Linux" or os.geteuid() != 0 or socket.gethostname() != args.expected_hostname
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,24}", args.stage)):
        parser.error("expected verified Linux host, administrator privileges and simple stage name")
    os.umask(0o077)
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    try:
        service = pwd.getpwnam(SERVICE)
        check(service.pw_uid > 0 and service.pw_gid > 0, "unsafe gateway service account")
        private_dir(STATE, service.pw_uid)
        if absent(STAGES):
            STAGES.mkdir(mode=0o700)
        private_dir(STAGES)
        lock = os.open(LOCK, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock, "wb") as file:
            info = os.fstat(file.fileno())
            check(info.st_uid == 0 and stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600,
                  "unsafe shared lock")
            fcntl.flock(file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            stage = STAGES / args.stage
            if args.action == "stage":
                stage_member(args, service, stage)
                print(f"MEMBER_STAGE=READY; private package not activated: {stage / 'member-mac.zip'}")
            else:
                if args.admin_login != "root":
                    safe_user(args.admin_login)
                pwd.getpwnam(args.admin_login)
                activate(stage, service, args.admin_login)
                print(f"MEMBER_ACTIVATION=READY; private package not sent: {stage / 'member-mac.zip'}")
    except (BudgetError, OSError, ValueError, KeyError, TypeError, Stopped, subprocess.SubprocessError) as exc:
        parser.exit(1, f"MEMBER_ENROLL=STOPPED ({exc if isinstance(exc, Stopped) else type(exc).__name__})\n")


if __name__ == "__main__":
    main()
