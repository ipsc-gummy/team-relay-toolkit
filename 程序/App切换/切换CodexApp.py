#!/usr/bin/env python3
"""Codex App 配置切换器。仅本地配置；不登录账号，不自动退出或启动 App。"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import copy
import errno
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.request

# Public documentation addresses and RFC8032 test-vector fingerprints only.
# Replace HOST and every fingerprint with independently verified deployment values.
# The published test key is known publicly and MUST NOT be used for deployment.
HOST = "203.0.113.10"
SSH_PORT = 22
TARGET = "127.0.0.1:8317"
FINGERPRINTS = {
    "member-a": "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8",
    "member-b": "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8",
    "owner": "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8",
}
HOST_FP = "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"


class SafeError(Exception):
    pass


class HealthError(SafeError):
    def __init__(self, reason, status=None):
        self.reason=reason;self.status=status
        super().__init__(reason + (f' (HTTP {status})' if status else ''))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise SafeError("所需文件不存在、不是普通文件或是符号链接；请让本机 Agent 检查。")
    return path.read_bytes()


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise SafeError("拒绝覆盖符号链接。")
    fd, tmp_name = tempfile.mkstemp(prefix=".sg-write-", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        if os.name != "nt":
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name=='nt' and path.exists():
            # ReplaceFile preserves the destination's DACL. os.replace would
            # inherit the temporary file's directory ACL instead.
            import ctypes
            kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            replace=kernel.ReplaceFileW
            replace.argtypes=[ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_wchar_p,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_void_p]
            replace.restype=ctypes.c_int
            if not replace(str(path),str(tmp),None,0,None,None):raise ctypes.WinError(ctypes.get_last_error())
        else:os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()  # Only the exact temporary file created above.


@contextmanager
def lock(path):
    """Cross-platform OS lock; no stale PID-based ownership inference."""
    if Path(path).is_symlink():
        raise SafeError("锁文件不能为符号链接。")
    stream = open(path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            if stream.tell() == 0:
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                raise SafeError("同一任务正在运行，请勿重复操作。") from None
        else:
            import fcntl
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SafeError("同一任务正在运行，请勿重复操作。") from None
        yield
    finally:
        stream.close()


def tunnel_running(state):
    try:
        with lock(state / "隧道.lock"):
            return False
    except SafeError:
        return True


def port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def read_settings(state):
    settings = json.loads(read_regular(state / "settings.json"))
    if settings.get("schema") != 1 or settings.get("user") not in FINGERPRINTS:
        raise SafeError("本机初始化信息不正确。")
    if settings.get("host") != HOST or settings.get("target") != TARGET:
        raise SafeError("目标不是本接入包的新加坡服务，已停止。")
    if not isinstance(settings.get("port"), int) or not 1024 <= settings["port"] <= 65535:
        raise SafeError("本机端口不正确。")
    baseline = settings.get("baseline_kind", "personal")
    if baseline not in ("personal", "original") or (baseline == "original" and settings["user"] != "owner"):
        raise SafeError("原模式类型不正确；不会把其他 API 入口当成个人 Plus。")
    return settings


def secret(state, settings):
    key = read_regular(state / "中转访问密钥.txt").decode().strip()
    if not re.fullmatch("cpa-" + settings["user"] + r"-[0-9a-f]{64}", key):
        raise SafeError("中转密钥格式或收件人不匹配。")
    return key


def make_team_config(original, state, settings):
    """Preserve original text; validate the complete semantic diff using tomllib."""
    text = original.decode("utf-8")
    parsed = tomllib.loads(text)
    original_mode = settings.get("baseline_kind") == "original" and settings.get("user") == "owner"
    if not original_mode and parsed.get("model_provider", "openai") != "openai":
        raise SafeError("原配置不是内置个人模式。请先核实本人 Plus 基线，不能把其他中转当成个人模式。")
    if "sg_team" in parsed.get("model_providers", {}):
        raise SafeError("已有同名提供商；请本机 Agent 先核实，不覆盖。")
    # Restrict edits to simple root-level model selectors. Unusual TOML fails closed
    # via the full parsed-diff check rather than modifying unrelated content.
    lines = text.splitlines(keepends=True)
    in_root = True
    kept = []
    for line in lines:
        if re.match(r"^\s*\[", line):
            in_root = False
        if in_root and re.match(r"^\s*(model_provider|model)\s*=", line):
            continue
        kept.append(line)
    quote = lambda value: json.dumps(value, ensure_ascii=False)
    provider = {
        "name": "团队中转",
        "base_url": f"http://127.0.0.1:{settings['port']}/v1",
        "wire_api": "responses",
        "auth": {
            "command": settings["python"],
            "args": [str(state / "切换CodexApp.py"), "_credential", "--state-dir", str(state)],
            "timeout_ms": 5000,
            "refresh_interval_ms": 0,
        },
    }
    prefix = f'model_provider = "sg_team"\nmodel = {quote(settings["model"])}\n'
    suffix = '\n\n[model_providers.sg_team]\n'
    suffix += "".join(f"{key} = {quote(provider[key])}\n" for key in ("name", "base_url", "wire_api"))
    suffix += '\n[model_providers.sg_team.auth]\n'
    suffix += "".join(f"{key} = {quote(value)}\n" for key, value in provider["auth"].items())
    result = prefix + "".join(kept) + suffix
    expected = copy.deepcopy(parsed)
    expected.update(model_provider="sg_team", model=settings["model"])
    expected.setdefault("model_providers", {})["sg_team"] = provider
    try:
        actual = tomllib.loads(result)
    except tomllib.TOMLDecodeError:
        raise SafeError("原 TOML 写法不适合安全自动处理；原文件未修改，请本机 Agent 检查。") from None
    if actual != expected:
        raise SafeError("配置差异超出提供商和模型范围；已停止，原文件未修改。")
    return result.encode()


def initialize(args, state):
    baseline = getattr(args, "baseline", "personal")
    if baseline == "original":
        if args.user != "owner" or not getattr(args, "original_verified", False):
            raise SafeError("恢复原 API 配置模式仅供 owner 本机显式确认，不替代队友的个人 Plus 验证。")
    elif baseline != "personal" or not args.personal_verified:
        raise SafeError("首次配置须由本机 Agent 确认个人 Plus 基线及 App 的凭据助手支持。")
    if not args.app_auth_helper_supported:
        raise SafeError("首次配置须由本机 Agent 确认 App 的凭据助手支持。")
    if not args.user or not args.ssh_key or not args.key_file:
        raise SafeError("首次配置缺少本人用户名、SSH 私钥路径或中转密钥文件。")
    config = Path(args.config).expanduser().absolute()
    original = read_regular(config)
    tomllib.loads(original.decode())
    private_key = Path(args.ssh_key).expanduser().absolute()
    if private_key.is_symlink() or not private_key.is_file():
        raise SafeError("私钥路径无效；不会读取或收集私钥内容。")
    public_key = Path(args.ssh_public_key).expanduser().absolute() if args.ssh_public_key else Path(str(private_key) + ".pub")
    read_regular(public_key)
    ssh = shutil.which("ssh")
    keygen = shutil.which("ssh-keygen")
    if not ssh or not keygen:
        raise SafeError("缺少本机 OpenSSH；请本机 Agent 检查已有安装。")
    check = subprocess.run([keygen, "-lf", str(public_key)], capture_output=True, text=True, timeout=10)
    if check.returncode or FINGERPRINTS[args.user] not in check.stdout.split():
        raise SafeError("公钥指纹不匹配本人接入信息，已停止。")
    key = read_regular(Path(args.key_file).expanduser()).decode().strip()
    if not re.fullmatch("cpa-" + args.user + r"-[0-9a-f]{64}", key):
        raise SafeError("中转密钥不匹配本人账号。")
    settings = {"schema": 1, "user": args.user, "host": HOST, "target": TARGET,
                "port": args.port, "ssh_key": str(private_key), "ssh": str(Path(ssh).absolute()),
                "model": args.model, "config": str(config), "python": str(Path(sys.executable).absolute())}
    if baseline == "original":
        settings["baseline_kind"] = "original"
    if not 1024 <= args.port <= 65535:
        raise SafeError("本机端口须为 1024 至 65535。")
    team = make_team_config(original, state, settings)
    if state.exists():
        raise SafeError("已有本机状态目录；不会重复初始化或覆盖原备份。")
    state.mkdir(mode=0o700, parents=True)
    if os.name == "nt":
        account = subprocess.check_output(["whoami"], text=True).strip()
        result = subprocess.run(["icacls", str(state), "/inheritance:r", "/grant:r",
                                 account + ":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"], capture_output=True)
        if result.returncode:
            raise SafeError("无法限制凭据目录 ACL，未写入密钥；请本机 Agent 检查。")
    atomic_write(state / ("original.toml" if baseline == "original" else "personal.toml"), original)
    atomic_write(state / "team.toml", team)
    atomic_write(state / "中转访问密钥.txt", (key + "\n").encode())
    atomic_write(state / "切换CodexApp.py", Path(__file__).read_bytes())
    settings.update(personal_hash=digest(original), team_hash=digest(team))
    atomic_write(state / "settings.json", json.dumps(settings, ensure_ascii=False, indent=2).encode())
    restore_action = "original" if baseline == "original" else "personal"
    print(f"首次准备完成；原 App 配置及登录未修改。下一步由本机 Agent 验证 team → 重启 App → {restore_action} → 重启 App。")


def api_ready(state, settings):
    url = f"http://127.0.0.1:{settings['port']}/v1/models"
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + secret(state, settings)})
    # Never send the local key through an inherited HTTP proxy or a redirect.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=3) as response:
            data = json.loads(response.read(1024 * 1024))
            if response.status != 200 or not isinstance(data,dict) or not isinstance(data.get('data'),list):
                raise HealthError('HEALTH_RESPONSE_INVALID')
            return True
    except urllib.error.HTTPError as exc:
        if exc.code in (401,403):raise HealthError('AUTH_FAILURE',exc.code) from None
        if 300<=exc.code<400:raise HealthError('HTTP_REDIRECT',exc.code) from None
        if exc.code in (502,503,504):raise HealthError('UPSTREAM_TRANSIENT',exc.code) from None
        raise HealthError('HTTP_FAILURE',exc.code) from None
    except urllib.error.URLError as exc:
        raise HealthError('TUNNEL_MISSING' if getattr(exc.reason,'errno',None)==errno.ECONNREFUSED else 'NETWORK_TRANSIENT') from None
    except OSError:raise HealthError('NETWORK_TRANSIENT') from None
    except ValueError:raise HealthError('HEALTH_RESPONSE_INVALID') from None


def health_check(state,settings):
    for attempt in range(3):
        try:
            if api_ready(state,settings):return
            raise HealthError('NETWORK_TRANSIENT')
        except HealthError as exc:
            if exc.reason not in ('NETWORK_TRANSIENT','UPSTREAM_TRANSIENT') or attempt==2:raise
            time.sleep(.5*(2**attempt))


def ssh_command(settings):
    # Dedicated no-config invocation avoids unrelated LocalForward/ProxyCommand.
    return [settings["ssh"], "-F", "none", "-N", "-T", "-p", str(SSH_PORT),
            "-i", settings["ssh_key"], "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10", "-o", "ExitOnForwardFailure=yes",
            "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=3",
            "-o", "TCPKeepAlive=yes", "-o", "ForwardAgent=no",
            "-L", f"127.0.0.1:{settings['port']}:{TARGET}", f"{settings['user']}@{HOST}"]


def tunnel_worker(state):
    settings = read_settings(state)
    stopped = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.set())
    child = None
    with lock(state / "隧道.lock"):
        try:
            while not stopped.is_set() and not (state / "停止隧道").exists():
                log = state / "ssh-errors.log"
                if log.exists() and log.stat().st_size > 65536:
                    atomic_write(log, b"")
                with open(log, "ab") as output:
                    child = subprocess.Popen(ssh_command(settings), stdin=subprocess.DEVNULL,
                                             stdout=subprocess.DEVNULL, stderr=output)
                    while child.poll() is None and not stopped.wait(0.5):
                        if (state / "停止隧道").exists():
                            stopped.set()
                    if child.poll() is None:
                        child.terminate()
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            child.kill()  # Only our own Popen child, never a discovered PID.
                            child.wait()
                child = None
                stopped.wait(5)
        finally:
            if child is not None and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()


def label(settings):
    return f"com.sgrelay.ssh.{settings['user']}.{settings['port']}"


def stop_tunnel(state, settings):
    atomic_write(state / "停止隧道", b"stop\n")
    if sys.platform == "darwin":
        subprocess.run(["/bin/launchctl", "remove", label(settings)], capture_output=True, timeout=10)
    deadline = time.monotonic() + 12
    while tunnel_running(state) and time.monotonic() < deadline:
        time.sleep(0.2)
    if tunnel_running(state):
        raise SafeError("自身后台尚未完全退出，请本机 Agent 检查；未结束其他进程。")


def ensure_tunnel(state, settings):
    running = tunnel_running(state)
    if not running and port_open(settings["port"]):
        raise SafeError("本机端口由其他进程占用，未抢占或停止它。")
    started = False
    if not running:
        stop_file = state / "停止隧道"
        if stop_file.exists():
            if stop_file.is_symlink():
                raise SafeError("停止标记异常。")
            stop_file.unlink()
        command = [settings["python"], str(state / "切换CodexApp.py"), "_tunnel", "--state-dir", str(state)]
        if sys.platform == "darwin":
            existing = subprocess.run(["/bin/launchctl", "list", label(settings)], capture_output=True, timeout=5)
            if existing.returncode == 0:
                raise SafeError("已有同名 macOS 任务但未取得本套隧道锁，请本机 Agent 检查；未覆盖。")
            result = subprocess.run(["/bin/launchctl", "submit", "-l", label(settings), "--", *command],
                                    capture_output=True, timeout=10)
            if result.returncode:
                raise SafeError("macOS 后台任务启动失败，请本机 Agent 检查。")
        else:
            options = {"creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
            # Never discard worker startup errors; log only this managed process.
            log = state / '后台启动.log'
            if log.is_symlink():
                raise SafeError("后台日志路径异常，停止。")
            if log.exists() and log.stat().st_size > 65536:
                atomic_write(log,b'')
            with open(log,'ab') as output:
                subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=output, **options)
        started = True
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if tunnel_running(state) and port_open(settings["port"]):
                break
            time.sleep(0.5)
        else:
            raise HealthError('TUNNEL_UNAVAILABLE')
    except Exception:
        # Keep our bounded reconnect worker alive across temporary offline periods.
        # Its lock prevents duplicates; never stop SSH because an API returned 502.
        raise
    health_check(state,settings)


def snapshots(state, settings):
    baseline_file = "original.toml" if settings.get("baseline_kind") == "original" else "personal.toml"
    personal = read_regular(state / baseline_file)
    team = read_regular(state / "team.toml")
    if digest(personal) != settings["personal_hash"] or digest(team) != settings["team_hash"]:
        raise SafeError("配置快照发生变化，请本机 Agent 核实；不会使用损坏备份。")
    return personal, team


def switch(state, mode):
    settings = read_settings(state)
    original_mode = settings.get("baseline_kind") == "original"
    if (mode == "personal" and original_mode) or (mode == "original" and not original_mode):
        raise SafeError("恢复模式不匹配：owner 原 API 使用 original，已验证的个人 Plus 使用 personal。")
    with lock(state / "操作.lock"):
        personal, team = snapshots(state, settings)
        config = Path(settings["config"])
        before = read_regular(config)
        if before not in (personal, team):
            raise SafeError("App 配置已被另外修改；为保护你的设置，本次不覆盖。请本机 Agent 合并后重新建立快照。")
        if mode == "team":
            ensure_tunnel(state, settings)
        desired = team if mode == "team" else personal
        if before != desired:
            backup_dir = state / "备份"
            backup_dir.mkdir(mode=0o700, exist_ok=True)
            atomic_write(backup_dir / (datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".toml"), before)
            # Don't overwrite a change that occurred while waiting for SSH.
            if read_regular(config) != before:
                raise SafeError("准备连接期间配置发生变化，已停止切换。")
            atomic_write(config, desired)
        restored_label = "原 API 配置（不是个人 Plus）" if original_mode else "个人 Plus（首次验证的原配置）"
        print("配置已选择：" + ("团队中转（新加坡）" if mode == "team" else restored_label))
        print("请保存任务，完整退出并重新打开 Codex App，再新建任务。关闭窗口不等于退出。")
        print("此结果仅确认配置文件；App 实际请求通道须在重启后验证。本人登录文件未修改。")


def main(argv=None):
    parser = argparse.ArgumentParser(description="一行命令切换 Codex App 配置，然后由本人完整重启 App。")
    parser.add_argument("action", choices=("init", "team", "personal", "original", "check", "status", "stop", "_credential", "_tunnel"))
    parser.add_argument("--state-dir", default=str(Path.home() / ".codex-sg-relay"))
    parser.add_argument("--config", default=str(Path.home() / ".codex" / "config.toml"))
    parser.add_argument("--user", choices=tuple(FINGERPRINTS))
    parser.add_argument("--ssh-key")
    parser.add_argument("--ssh-public-key")
    parser.add_argument("--key-file")
    parser.add_argument("--port", type=int, default=18318)
    parser.add_argument("--model", default="gpt-6-astra")
    parser.add_argument("--personal-verified", action="store_true")
    parser.add_argument("--baseline", choices=("personal", "original"), default="personal")
    parser.add_argument("--original-verified", action="store_true")
    parser.add_argument("--app-auth-helper-supported", action="store_true")
    args = parser.parse_args(argv)
    state = Path(args.state_dir).expanduser().absolute()
    if state.is_symlink() or state == Path.home() or state == Path(state.anchor):
        raise SafeError("状态目录必须是独立的私有目录，不能是用户目录、根目录或符号链接。")
    os.umask(0o077)
    if args.action == "init":
        initialize(args, state)
        return
    if not state.is_dir():
        raise SafeError("尚未首次配置；请将接入包交给本人电脑上的 Agent 完成 init。")
    settings = read_settings(state)
    if args.action == "_credential":
        if sys.stdout.isatty():
            raise SafeError("此内部接口只供 App 读取凭据，不要在终端直接运行。")
        print(secret(state, settings))
    elif args.action == "_tunnel":
        tunnel_worker(state)
    elif args.action in ("team", "personal", "original"):
        if (state/'modes.json').is_file() and json.loads(read_regular(state/'modes.json')).get('schema')==3:
            raise SafeError('此安装已升级：请使用统一接入入口 team / personal / other，不直接运行旧 helper 切换。')
        switch(state, args.action)
    elif args.action == "check":
        with lock(state / "操作.lock"):
            ensure_tunnel(state, settings)
        print("新加坡后台与 API 鉴权通过；未切换 App 配置，App 实际请求仍需重启后验证。")
    elif args.action == "stop":
        with lock(state / "操作.lock"):
            stop_tunnel(state, settings)
        print("本套新加坡后台已停止；没有更改 App 模式或个人登录。")
    else:
        personal, team = snapshots(state, settings)
        current = read_regular(settings["config"])
        restored_label = "原 API 配置（不是个人 Plus）" if settings.get("baseline_kind") == "original" else "个人 Plus"
        mode = "团队中转" if current == team else restored_label if current == personal else "未确认（配置另有修改）"
        print("配置文件模式：" + mode)
        print("本套后台任务：" + ("运行中" if tunnel_running(state) else "未运行"))
        print("App 当前实际模式：未由此命令验证；重启后需在新任务核实。")


if __name__ == "__main__":
    try:
        main()
    except (SafeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        # Unexpected parsing/OS errors may include file text. Never print those.
        message = str(exc) if isinstance(exc, SafeError) else "操作未完成，请本机 Agent 检查文件、权限、格式及运行环境；未输出凭据。"
        print("停止：" + message, file=sys.stderr)
        sys.exit(2)
