#!/usr/bin/env python3
"""Mac-only entry for a pinned SSH tunnel to the new budget gateway."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys


SOURCE = Path(__file__).resolve().parent
PACKAGE = SOURCE.parent
spec = importlib.util.spec_from_file_location("budget_core", SOURCE / "切换CodexApp.py")
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)


def backend_candidates():
    for name in ("ChatGPT.app", "Codex.app"):
        resources = Path("/Applications") / name / "Contents/Resources"
        yield resources / "codex-cli/CodexCLI.app/Contents/MacOS/codex"
        yield resources / "codex"


def discover_backend():
    for path in backend_candidates():
        if path.is_file() and os.access(path, os.X_OK):
            result = subprocess.run([str(path), "--version"], capture_output=True, text=True, timeout=8)
            if result.returncode == 0 and re.fullmatch(r"codex-cli [0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", result.stdout.strip()):
                return result.stdout.strip()
    raise core.SafeError("没有找到已安装的 Mac Codex App 后台；请本机 Agent 核对安装位置。")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "team", "personal", "check", "status", "stop"))
    parser.add_argument("--ssh-key", default=str(Path.home() / ".ssh/id_ed25519_sg_team"))
    args = parser.parse_args(argv)
    if sys.platform != "darwin" or not core.BUDGET_MODE:
        raise core.SafeError("本包只适用于 Mac 团队限额路线。")
    home = Path.home()
    if os.environ.get("CODEX_HOME") and Path(os.environ["CODEX_HOME"]).expanduser() != home / ".codex":
        raise core.SafeError("检测到自定义 Codex 目录，未动既有配置。")
    manifest = json.loads(core.read_regular(PACKAGE / "个人参数.json"))
    user = manifest.get("user")
    if (manifest.get("profile") != "budget-mac" or user not in core.FINGERPRINTS
            or manifest.get("public_fingerprint") != core.FINGERPRINTS[user]
            or manifest.get("host") != core.HOST or manifest.get("host_fingerprint") != core.HOST_FP
            or manifest.get("model") != core.BUDGET_MODEL
            or core.TARGET != f"127.0.0.1:{manifest.get('gateway_port')}"):
        raise core.SafeError("个人包身份、模型或路由不匹配，未切换。")
    state = home / ".codex-sg-budget"
    config = home / ".codex/config.toml"
    if config.parent.is_symlink():
        raise core.SafeError("Codex 目录是链接；未动既有配置。")
    command = ["--state-dir", str(state)]
    if args.action == "prepare":
        print("MAC_CODEX_BACKEND=" + discover_backend())
        core.main(["init", *command, "--config", str(config), "--user", user,
                   "--ssh-key", args.ssh_key, "--key-file", str(PACKAGE / "中转访问密钥.txt"),
                   "--known-hosts", str(PACKAGE / "known_hosts"), "--personal-verified", "--app-auth-helper-supported"])
        return
    settings = core.read_settings(state)
    if (settings.get("user") != user or settings.get("config") != str(config)
            or settings.get("model") != core.BUDGET_MODEL):
        raise core.SafeError("已安装状态与此个人包不一致，不接管。")
    if core.read_regular(state / "切换CodexApp.py") != core.read_regular(SOURCE / "切换CodexApp.py"):
        raise core.SafeError("已安装程序与此包版本不同，不自动覆盖旧安装。")
    core.main([args.action, *command])


if __name__ == "__main__":
    try:
        main()
    except (core.SafeError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print("停止：" + (str(exc) if isinstance(exc, core.SafeError) else "本机文件、权限或运行环境检查失败。未输出凭据。"),
              file=sys.stderr)
        raise SystemExit(2)
