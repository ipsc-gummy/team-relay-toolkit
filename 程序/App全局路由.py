#!/usr/bin/env python3
"""Mac 的 App 路由控制器；不读取任务历史，不修改登录或既有隧道配置。"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent
STATE = ROOT / ".连接凭据/App全局路由"
LEGACY = ROOT / ".连接凭据/App切换状态"
CONFIG = Path.home() / ".codex/config.toml"
PROXY = ROOT / "程序/App全局路由代理.py"
BINARY = Path("/Applications/ChatGPT.app/Contents/Resources/codex")
ASAR = Path("/Applications/ChatGPT.app/Contents/Resources/app.asar")
PROVIDERS = {"team": "sg_team", "original": "custom-api", "personal": "openai"}
MANAGED_PROVIDER_BLOCKS = ("sg_team", "custom-api")
ENV_KEY = "CODEX_CLI_PATH"
_CORE = None
_HEAL = None
_ACTIVE_APP = None


class SafeError(Exception):
    pass


class ConfigDrift(SafeError):
    pass


def healer():
    global _HEAL
    if _HEAL is None:
        spec = importlib.util.spec_from_file_location("sg_app_self_heal", Path(__file__).with_name("App自愈.py"))
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        _HEAL = module
    return _HEAL


def healed_route(*, mode=None, cached=False):
    try:
        return healer().ensure(sys.modules[__name__], mode=mode, cached=cached)
    except healer().Failure as exc:
        raise SafeError(exc.reason) from None


def preflight():
    """Called once BEFORE the official child reads config; no model generation."""
    global _ACTIVE_APP
    value = manifest()
    if value.get("self_heal") and value["enabled"]:
        route = healed_route()
        confirmed = manifest()['self_heal']['app_files']
        if healer().app_files(sys.modules[__name__]) != confirmed:
            raise SafeError("APP_CHANGED_DURING_CHECK")
        _ACTIVE_APP = confirmed
        return route
    return None


def core():
    global _CORE
    if _CORE is None:
        spec = importlib.util.spec_from_file_location("sg_existing_core", ROOT / "程序/App切换/切换CodexApp.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _CORE = module
    return _CORE


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_uid != os.getuid():
        raise SafeError("文件不存在、归属异常或是符号链接；停止操作。")
    return path.read_bytes()


def private_dir(path):
    path = Path(path)
    if path.is_symlink() or not path.is_dir() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise SafeError("私有状态目录权限或归属异常。")


def route_config(data):
    """Only routing authority belongs to this controller; user preferences do not."""
    value = tomllib.loads(data.decode("utf-8"))
    providers = value.get("model_providers", {})
    if any(not isinstance(providers.get(p), dict) for p in MANAGED_PROVIDER_BLOCKS):
        raise ConfigDrift("缺少受管 provider 定义，停止路由。")
    # The App and wrapper legitimately alternate these two paths. No arbitrary
    # CODEX_CLI_PATH is trusted, including one added to another MCP server.
    for server in value.get("mcp_servers", {}).values():
        env = server.get("env", {})
        if ENV_KEY in env and env[ENV_KEY] not in (str(BINARY), str(PROXY)):
            raise ConfigDrift("CODEX_CLI_PATH 指向未知包装程序，停止路由。")
    return {"model_provider": value.get("model_provider"),
            "model_providers": {p: providers[p] for p in MANAGED_PROVIDER_BLOCKS}}


def validate_route_config(current, baseline, mode):
    if mode not in PROVIDERS:
        raise SafeError("受管 mode 缺失或无效，禁止推断线路。")
    expected = route_config(baseline)
    if expected["model_provider"] != PROVIDERS[mode]:
        raise SafeError("受管路由快照的 provider 与 mode 不匹配。")
    if route_config(current) != expected:
        raise ConfigDrift("路由关键配置与受管 mode 不匹配，停止路由；不会覆盖或恢复历史线路。")


def select_provider(data, provider):
    before = tomllib.loads(data.decode("utf-8"))
    lines = data.decode("utf-8").splitlines(keepends=True)
    out, in_root, found = [], True, False
    for line in lines:
        if re.match(r"^\s*\[", line):
            in_root = False
        if in_root and re.match(r"^\s*model_provider\s*=", line):
            if found:
                raise SafeError("配置中提供商定义重复。")
            # Only the selector changes; preserve every other line byte-for-byte.
            line = re.sub(r'^(\s*model_provider\s*=\s*)("[^"\n]*"|\x27[^\x27\n]*\x27)',
                          lambda m: m[1] + json.dumps(provider), line)
            found = True
        out.append(line)
    if not found:
        raise SafeError("缺少已知的根提供商选择项。")
    result = "".join(out).encode()
    expected = copy.deepcopy(before)
    expected["model_provider"] = provider
    if tomllib.loads(result.decode()) != expected:
        raise SafeError("配置变化超出提供商选择范围。")
    return result


def manifest(*, allow_legacy=False):
    private_dir(STATE)
    value = json.loads(read_file(STATE / "状态.json"))
    if value.get("schema") not in (1, 2) or value.get("config") != str(CONFIG) or value.get("proxy") != str(PROXY):
        raise SafeError("安装状态不匹配当前路径。")
    if not isinstance(value.get("enabled"), bool):
        raise SafeError("安装状态字段无效。")
    if value["schema"] == 1:
        if not allow_legacy:
            raise SafeError("旧状态未记录 mode；请先显式执行 migrate --mode team/original/personal。")
    elif value.get("mode") not in PROVIDERS:
        raise SafeError("受管 mode 缺失或无效，禁止推断线路。")
    return value


def save_manifest(value):
    core().atomic_write(STATE / "状态.json", (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())


def route_enabled():
    if not STATE.exists() and not STATE.is_symlink():
        return False
    return manifest()["enabled"]


def fingerprint(path):
    st = path.stat()
    return {"size": st.st_size, "mtime_ns": st.st_mtime_ns}


def verified_snapshots(value):
    modes = set(value.get("hashes", {}))
    if not {"team", "original"} <= modes or not modes <= set(PROVIDERS):
        raise SafeError("受管配置快照清单无效。")
    baselines = {}
    for mode in modes:
        baseline = read_file(STATE / (mode + ".toml"))
        if digest(baseline) != value["hashes"][mode]:
            raise SafeError("受管配置快照哈希校验失败。")
        baselines[mode] = baseline
    return baselines


def validated_config(value=None):
    value = manifest() if value is None else value
    if value.get("self_heal"):
        current = read_file(CONFIG)
        module = healer()
        try:
            provider = module.canonical(sys.modules[__name__], value)
            if module.merge(current, provider, PROVIDERS[value['mode']]) != current:
                raise ConfigDrift("受管字段待修复；请由启动自检处理。")
        except module.Failure as exc:
            raise ConfigDrift(exc.reason) from None
        return value['mode'], current
    mode = value.get("mode")
    if value.get("schema") != 2 or mode not in PROVIDERS:
        raise SafeError("受管 mode 缺失或无效，禁止推断线路。")
    baselines = verified_snapshots(value)
    current = read_file(CONFIG)
    validate_route_config(current, baselines[mode], mode)
    return mode, current


def validate_app(value):
    if not PROXY.is_file() or PROXY.is_symlink() or PROXY.stat().st_uid != os.getuid() or not os.access(PROXY, os.X_OK):
        raise SafeError("协议包装程序不存在、归属异常或不可执行。")
    for key, path in (("binary", BINARY), ("asar", ASAR)):
        if fingerprint(path) != value["app_files"][key]:
            raise SafeError("App 已更新，需要先重新核实协议包装兼容性。")


def validate_launch_env(value):
    previous = launch_env()
    backup = validate_backup(value["backup"])
    if previous not in (None, str(PROXY), backup["launchctl_before"].get(ENV_KEY)):
        raise SafeError("已有其他 App 启动包装，拒绝路由或覆盖。")
    return previous


def load_route():
    value = manifest()
    if not value["enabled"]:
        raise SafeError("全局路由尚未启用。")
    if value.get("self_heal"):
        # The on-disk replacement is not proof about an already-running child.
        if _ACTIVE_APP is not None and healer().app_files(sys.modules[__name__]) != _ACTIVE_APP:
            raise SafeError("APP_RESTART_REQUIRED")
        return healed_route(cached=True)
    validate_app(value)
    validate_launch_env(value)
    mode, _ = validated_config(value)
    if manifest() != value:
        raise SafeError("受管状态正在切换，本次停止路由。")
    return {"provider": PROVIDERS[mode], "mode": mode, "state_dir": STATE}


def launch_env():
    result = subprocess.run(["/bin/launchctl", "getenv", ENV_KEY], capture_output=True, text=True, timeout=5)
    if result.returncode:
        raise SafeError("无法读取 App 启动环境。")
    return result.stdout.rstrip("\n") or None


def set_launch_env(value):
    command = ["/bin/launchctl", "unsetenv", ENV_KEY] if value is None else ["/bin/launchctl", "setenv", ENV_KEY, value]
    result = subprocess.run(command, capture_output=True, timeout=5)
    if result.returncode or launch_env() != value:
        raise SafeError("App 启动环境注册失败；未把它报告为成功。")


def validate_backup(path):
    path = Path(path).absolute()
    private_dir(path)
    value = json.loads(read_file(path / "备份清单.json"))
    if value.get("schema") != 1:
        raise SafeError("修改前备份版本不正确。")
    for item in value["files"]:
        if Path(item["backup"]).name != item["backup"] or digest(read_file(path / item["backup"])) != item["sha256"]:
            raise SafeError("修改前备份哈希校验失败。")
    return value


def prepare(backup):
    if STATE.exists():
        manifest()
        print("已有本人全局路由状态，未重新初始化。")
        return
    backup = Path(backup).absolute()
    validate_backup(backup)
    settings = core().read_settings(LEGACY)
    original, team = core().snapshots(LEGACY, settings)
    before = read_file(CONFIG)
    validate_route_config(before, team, "team")
    school = tomllib.loads(original.decode())["model_providers"]["custom-api"]
    if tomllib.loads(before.decode())["model_providers"]["custom-api"] != school:
        raise SafeError("学校提供商定义变化，停止接入。")
    private_dir(STATE.parent)
    STATE.mkdir(mode=0o700)
    hashes = {}
    for mode, provider in PROVIDERS.items():
        data = select_provider(before, provider)
        core().atomic_write(STATE / (mode + ".toml"), data)
        hashes[mode] = digest(data)
    save_manifest({"schema": 2, "mode": "team", "enabled": False, "config": str(CONFIG), "proxy": str(PROXY),
                   "backup": str(backup), "hashes": hashes,
                   "app_files": {"binary": fingerprint(BINARY), "asar": fingerprint(ASAR)}})
    print("受管快照已建立；原学校快照保持原样，尚未启用 App 包装。")


def migrate(mode):
    """Explicit one-time upgrade. Never infer mode or rewrite the live config."""
    private_dir(STATE)
    with core().lock(STATE / "操作.lock"):
        value = manifest(allow_legacy=True)
        if value["schema"] != 1:
            raise SafeError("状态已记录 mode；切换线路请使用 team/original/personal。")
        upgraded = dict(value, schema=2, mode=mode)
        _, before = validated_config(upgraded)
        validate_app(upgraded)
        validate_launch_env(upgraded)
        saved = read_file(STATE / "状态.json")
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        core().atomic_write(STATE / ("mode迁移前状态_" + stamp + ".json"), saved)
        if read_file(CONFIG) != before or read_file(STATE / "状态.json") != saved:
            raise SafeError("迁移检查期间配置或状态变化，本次停止。")
        save_manifest(upgraded)
    print("受管状态已升级：mode=" + mode + "；配置、旧快照、启动环境和隧道未修改。")


def switch(mode):
    if manifest().get("self_heal"):
        value = manifest()
        previous = validate_launch_env(value)
        if previous != str(PROXY):
            core().atomic_write(STATE / ("启动环境切换前_" + datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".json"),
                                (json.dumps({ENV_KEY: previous}) + "\n").encode())
        try:
            if previous != str(PROXY):set_launch_env(str(PROXY))
            healed_route(mode=mode)
        except Exception:
            if previous != str(PROXY) and launch_env() == str(PROXY):set_launch_env(previous)
            raise
        print("MODE=" + mode + " / " + PROVIDERS[mode])
        print("请保存任务后完整退出并重开 App；当前进程未被中断。")
        return
    private_dir(STATE)
    with core().lock(STATE / "操作.lock"):
        value = manifest()
        _, before = validated_config(value)
        previous_env = validate_launch_env(value)
        validate_app(value)
        if mode == "team":
            with core().lock(LEGACY / "操作.lock"):
                core().ensure_tunnel(LEGACY, core().read_settings(LEGACY))
        if read_file(CONFIG) != before:
            raise SafeError("连接检查期间配置变化，本次停止。")
        desired = select_provider(before, PROVIDERS[mode])
        changes = STATE / "切换前备份"
        changes.mkdir(mode=0o700, exist_ok=True)
        private_dir(changes)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        core().atomic_write(changes / (stamp + ".toml"), before)
        env_attempted = config_changed = False
        try:
            if previous_env != str(PROXY):
                env_attempted = True
                set_launch_env(str(PROXY))
            if read_file(CONFIG) != before:
                raise SafeError("注册包装期间配置变化，本次停止。")
            if desired != before:
                core().atomic_write(CONFIG, desired)
                config_changed = True
            value["enabled"] = True
            value["mode"] = mode
            save_manifest(value)
        except Exception:
            if config_changed and read_file(CONFIG) == desired:
                core().atomic_write(CONFIG, before)
            if env_attempted and launch_env() == str(PROXY):
                set_launch_env(previous_env)
            raise
    labels = {
        "team": "新加坡团队中转（sg_team / 18318）",
        "original": "原学校 API（custom-api / 18317）",
        "personal": "本人 ChatGPT Pro（openai / 直连，不经 SSH 中转）",
    }
    print("全局线路：" + labels[mode])
    print("App 包装入口已注册；无需单独启动 Python 或保持终端窗口。")
    print("请等任务结束后 Cmd+Q 完整退出，再正常打开 App。当前已运行的 App 尚未因此重启。")
    print("新旧任务实际路由仍需重启后验收；切换不修改登录、历史数据库或任务文件。")


def status():
    value = manifest()
    if value.get("self_heal"):
        print("MODE=" + value['mode'] + " / " + PROVIDERS[value['mode']])
        for key, result in healer().inspect(sys.modules[__name__]).items():
            print(key + "=" + result)
        return
    print("受管全局模式：" + value["mode"] + " / " + PROVIDERS[value["mode"]])
    try:
        mode, _ = validated_config(value)
        config_status = mode + " / " + PROVIDERS[mode]
    except ConfigDrift:
        config_status = "未确认（配置或快照变化，禁止自动覆盖）"
    print("配置文件线路：" + config_status)
    print("协议覆盖：" + ("已启用" if value["enabled"] else "未启用"))
    compatible = all(fingerprint(path) == value["app_files"][key] for key, path in (("binary", BINARY), ("asar", ASAR)))
    print("App 版本检查：" + ("匹配已核实版本" if compatible else "已变化；恢复/发送将被阻止，需重新核实"))
    print("下次 App 启动入口：" + ("本套包装已注册" if launch_env() == str(PROXY) else "未注册；需运行 team/original/personal"))
    print("本套 SSH 维护后台：" + ("运行中" if core().tunnel_running(LEGACY) else "未运行"))
    print("App 实际请求线路：需结合重启后运行记录与真实请求验收，以上状态不能代替验收。")
    print("修改前备份：" + value["backup"])


def record_installation():
    value = manifest()
    backup = Path(value["backup"])
    files = [ROOT / "本人App试用.command", ROOT / "本人Mac使用与切换流程.md"]
    hashes = {str(p): digest(read_file(p)) for p in files}
    core().atomic_write(backup / "安装后文件哈希.json", (json.dumps(hashes, ensure_ascii=False, indent=2) + "\n").encode())


def rollback(backup_path):
    value = manifest()
    backup_path = Path(backup_path).absolute()
    if str(backup_path) != value["backup"]:
        raise SafeError("回滚备份与当前安装不匹配。")
    backup = validate_backup(backup_path)
    installed = json.loads(read_file(backup_path / "安装后文件哈希.json"))
    with core().lock(STATE / "操作.lock"):
        value = manifest()
        validated_config(value)
        # The restoration target comes from the verified installation backup,
        # not from guessing the current route from live user preferences.
        config_items = [item for item in backup["files"] if Path(item["path"]) == CONFIG]
        if len(config_items) != 1:
            raise SafeError("回滚备份必须包含唯一配置文件。")
        restored = read_file(backup_path / config_items[0]["backup"])
        selector = tomllib.loads(restored.decode()).get("model_provider")
        restored_mode = next((m for m, p in PROVIDERS.items() if p == selector), None)
        if restored_mode is None:
            raise SafeError("回滚备份的 provider 不属于受管线路。")
        validate_route_config(restored, verified_snapshots(value)[restored_mode], restored_mode)
        for item in backup["files"]:
            p = Path(item["path"])
            if p == CONFIG:
                continue
            current_hash = digest(read_file(p))
            if current_hash not in (item["sha256"], installed.get(str(p))):
                raise SafeError("文件在安装后另有修改，拒绝覆盖回滚。")
        previous_env = backup["launchctl_before"].get(ENV_KEY)
        if launch_env() not in (None, str(PROXY), previous_env):
            raise SafeError("App 启动环境另有修改，拒绝覆盖回滚。")
        # Preserve current managed config in case recovery is interrupted.
        core().atomic_write(STATE / "回滚前配置.toml", read_file(CONFIG))
        set_launch_env(previous_env)
        value["enabled"] = False
        save_manifest(value)
        for item in backup["files"]:
            p = Path(item["path"])
            data = read_file(backup_path / item["backup"])
            if read_file(p) != data:
                core().atomic_write(p, data, item["mode"])
        value["mode"] = restored_mode
        save_manifest(value)
    print("已恢复修改前配置、入口、说明和 App 启动环境；新程序保留作检查，包装已停用。")
    print("请 Cmd+Q 完整退出并重开 App。未修改登录、任务历史或任何隧道。")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "migrate", *PROVIDERS, "status", "check", "stop", "rollback", "record-installation", "enable-self-heal", "self-heal"))
    parser.add_argument("--backup")
    parser.add_argument("--mode", choices=tuple(PROVIDERS))
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.action == "enable-self-heal":
        healer().enable(sys.modules[__name__])
        print("SELF_HEAL=ENABLED")
    elif args.action == "self-heal":
        preflight()
        status()
    elif args.action == "prepare":
        if not args.backup:
            raise SafeError("首次接入必须指定修改前备份。")
        prepare(args.backup)
    elif args.action == "migrate":
        if args.mode is None:
            raise SafeError("迁移旧状态必须显式指定 --mode team/original/personal。")
        migrate(args.mode)
    elif args.action in PROVIDERS:
        switch(args.action)
    elif args.action == "status":
        status()
    elif args.action in ("check", "stop"):
        core().main([args.action, "--state-dir", str(LEGACY)])
        if args.action == "check":
            print("check 只检查/维护已有新加坡隧道，不启用包装、不切换线路、不证明 App 路由。")
    elif args.action == "record-installation":
        record_installation()
    else:
        if not args.backup:
            raise SafeError("回滚必须明确指定本次修改前备份路径。")
        rollback(args.backup)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        message = str(exc) if isinstance(exc, (SafeError, core().SafeError)) else "操作未完成；未输出文件内容或凭据，请检查本套程序。"
        print("停止：" + message, file=sys.stderr)
        sys.exit(2)
