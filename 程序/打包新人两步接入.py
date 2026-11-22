#!/usr/bin/env python3
"""只打包显式文件；说明包无Key，个人包只包含指定收件人的既有Key。"""
import argparse
import ast
import base64
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import NamedTuple
import zipfile

ROOT = Path(__file__).resolve().parent.parent
DOCS = ("第一步_生成公钥发给管理员.md", "第二步_一行安装重启使用.md")
EXAMPLE_HOST = "203.0.113.10"
EXAMPLE_HOST_FP = "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"
EXAMPLE_TARGET = "127.0.0.1:8317"
FINGERPRINT_PATTERN = r'SHA256:[A-Za-z0-9+/]{43}'
ED25519_WIRE_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"


class Deployment(NamedTuple):
    host: str
    host_fingerprint: str
    host_key: str
    gateway_port: int

    @property
    def target(self):
        return f"127.0.0.1:{self.gateway_port}"


def load_deployment(server_ip=None, host_public_key=None, gateway_port=None, host_fingerprint=None):
    supplied = [field is not None for field in (server_ip, host_public_key, gateway_port)]
    if not any(supplied) and host_fingerprint is None:
        return None
    if not all(supplied):
        raise ValueError("server IP, SSH host public key and gateway port must be supplied together")
    host = ipaddress.IPv4Address(server_ip)
    if str(host) == EXAMPLE_HOST or host.is_unspecified or host.is_multicast or int(host) == 0xffffffff:
        raise ValueError("deployment requires a usable IPv4 address, not the template address")
    if type(gateway_port) is not int or not 1 <= gateway_port <= 65535:
        raise ValueError("invalid gateway port")
    if not host_public_key.is_file() or host_public_key.is_symlink():
        raise ValueError("host public key must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(host_public_key, flags), "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("host public key must be a regular file")
        data = handle.read(8193)
    lines = data.splitlines()
    fields = lines[0].split(None, 2) if len(lines) == 1 and len(data) <= 8192 else ()
    if len(fields) < 2 or fields[0] != b"ssh-ed25519":
        raise ValueError("expected one OpenSSH ssh-ed25519 host public key")
    blob = base64.b64decode(fields[1], validate=True)
    if (len(blob) != len(ED25519_WIRE_PREFIX) + 32 or not blob.startswith(ED25519_WIRE_PREFIX)
            or base64.b64encode(blob) != fields[1]):
        raise ValueError("invalid SSH Ed25519 public key wire format")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    if fingerprint == EXAMPLE_HOST_FP:
        raise ValueError("public template host key is not permitted for deployments")
    if host_fingerprint is not None and (not re.fullmatch(FINGERPRINT_PATTERN, host_fingerprint)
                                         or not hmac.compare_digest(fingerprint, host_fingerprint)):
        raise ValueError("host public key does not match the separately verified fingerprint")
    return Deployment(str(host), fingerprint, b" ".join(fields[:2]).decode("ascii"), gateway_port)


def render_assignments(source, values):
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    for name, value in values.items():
        matches = [node for node in tree.body if isinstance(node, ast.Assign) and len(node.targets) == 1
                   and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
        if len(matches) != 1:
            raise ValueError("template assignment missing or duplicated")
        assignment = matches[0]
        line_index = assignment.lineno - 1
        # Keep original indices stable even when replacing a multiline assignment.
        lines[line_index] = name + " = " + repr(value) + "\n"
        for index in range(line_index + 1, assignment.end_lineno):
            lines[index] = ""
    result = "".join(lines)
    ast.parse(result)
    return result.encode()


def render_core(user, fingerprint, deployment=None, budget_mac=False):
    source = (ROOT / "程序/App切换/切换CodexApp.py").read_text()
    values = {"FINGERPRINTS": {user: fingerprint}}
    if deployment:
        values.update(HOST=deployment.host, HOST_FP=deployment.host_fingerprint, TARGET=deployment.target)
    if budget_mac:
        values.update(BUDGET_MODE=True)
    return render_assignments(source, values)


def render_deployment_doc(data, deployment):
    source = data.decode("utf-8")
    lines = source.splitlines(keepends=True)
    fixture_notice = [index for index, line in enumerate(lines) if line.startswith("公开仓库中的 ")]
    if len(fixture_notice) != 1 or not all(value in source for value in (EXAMPLE_HOST, EXAMPLE_HOST_FP, EXAMPLE_TARGET)):
        raise ValueError("deployment documentation template is out of sync")
    lines[fixture_notice[0]] = "此个人包包含管理员为本次部署指定的服务器地址、固定 SSH 主机公钥与本人的转发端口；首次连接会校验主机指纹。\n"
    source = "".join(lines).replace(EXAMPLE_HOST, deployment.host).replace(EXAMPLE_HOST_FP, deployment.host_fingerprint)
    return (source.replace(EXAMPLE_TARGET, deployment.target).replace("示例团队", "本团队")
            .replace("；当前不设个人限额。", "；个人限额以管理员通知为准。").encode("utf-8"))


def check_public(data):
    if re.search(rb'(?:sk-|cpa-)[A-Za-z0-9_-]{25,}|-----BEGIN [A-Z ]*PRIVATE KEY-----', data):
        raise ValueError("unexpected credential or unrelated content")


def build_payload(user=None, fingerprint=None, token=None, platform="macos", deployment=None, budget_mac=False):
    """One payload implementation for new recipients and identity-preserving refreshes."""
    if platform not in ("macos", "windows"):
        raise ValueError("unsupported platform")
    if deployment and not user:
        raise ValueError("deployment parameters are only for personal packages")
    if budget_mac and (not user or platform != "macos" or not deployment
                       or deployment.gateway_port == 8317 or deployment.gateway_port < 1024):
        raise ValueError("budget package requires a verified personal Mac deployment on a dedicated gateway port")
    prefix = "Codex团队接入/" if user else "团队中转_两步说明/"
    docs = ROOT / ("新人接入/Windows两步版" if platform == "windows" else "新人接入/两步版")
    payload = {prefix + name: (docs / name).read_bytes() for name in DOCS}
    if user:
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', user) or user == "root":
            raise ValueError("invalid recipient")
        if not isinstance(fingerprint,str) or not re.fullmatch(FINGERPRINT_PATTERN, fingerprint):
            raise ValueError("invalid public fingerprint")
        if not re.fullmatch('cpa-' + user + '-[0-9a-f]{64}', token):
            raise ValueError("key recipient mismatch")
        entry = "接入.cmd" if platform == "windows" else "接入.command"
        payload[prefix + entry] = (ROOT / "程序/新人一键接入" / entry).read_bytes()
        if platform == "windows":
            payload[prefix + entry] = payload[prefix + entry].replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        code_path = "program/" if platform == "windows" else "程序/"
        installer = (ROOT / "程序/新人一键接入" / ("Mac限额接入.py" if budget_mac else "一键接入.py")).read_bytes()
        if budget_mac:
            payload[prefix + DOCS[0]] = payload[prefix + DOCS[0]].replace("示例团队".encode(), "本团队".encode())
            del payload[prefix + DOCS[1]]
            payload[prefix + "FOR-CODEX.md"] = (docs / "限额版_FOR-CODEX.md").read_bytes()
            payload[prefix + "known_hosts"] = f"{deployment.host} {deployment.host_key}\n".encode("ascii")
        elif deployment:
            installer = render_assignments(installer.decode("utf-8"), {"PINNED_HOST_KEY": deployment.host_key})
            payload[prefix + DOCS[0]] = payload[prefix + DOCS[0]].replace("示例团队".encode(), "本团队".encode())
            payload[prefix + DOCS[1]] = render_deployment_doc(payload[prefix + DOCS[1]], deployment)
        payload[prefix + code_path + ("install.py" if platform == "windows" else "一键接入.py")] = installer
        payload[prefix + code_path + "切换CodexApp.py"] = render_core(user, fingerprint, deployment, budget_mac)
        payload[prefix + "个人参数.json"] = json.dumps({
            "user": user, "public_fingerprint": fingerprint,
            "host": deployment.host if deployment else EXAMPLE_HOST,
            "host_fingerprint": deployment.host_fingerprint if deployment else EXAMPLE_HOST_FP,
            "compatibility_check": "isolated_app_server_command_auth_v1", "provider_display_name": "团队中转",
            "team_name": "本团队" if deployment else "示例团队", "server_provisioning": "must_be_confirmed_by_administrator",
            "platform": platform, "platform_app_validation": "requires_recipient_test",
            "package_release": "2026-09-12-r2", "mode_schema": 3,
            "windows_backend_discovery": "appx_hash_verified_runtime_copy",
            "managed_fields": "route_selectors_and_sg_team_only",
            "existing_powershell_migration": "local_review_required_do_not_overwrite",
            "local_agent_entry": DOCS[1],
            **({"gateway_port": deployment.gateway_port} if deployment else {}),
            **({"profile": "budget-mac", "model": "gpt-5.4-mini-2026-03-17", "local_agent_entry": "FOR-CODEX.md",
                "managed_fields": "budget_team_only_original_snapshot_untouched", "package_release": "budget-mac-v1"}
               if budget_mac else {}),
        }, ensure_ascii=False, indent=2).encode()
        for data in payload.values():
            check_public(data)
        payload[prefix + "中转访问密钥.txt"] = (token + "\n").encode()
    else:
        for data in payload.values():
            check_public(data)
    return payload


def pack(destination, user=None, public_key=None, token_path=None, platform="macos", deployment=None, budget_mac=False):
    fingerprint=token=None
    if user:
        if public_key.is_symlink() or token_path.is_symlink() or token_path.stat().st_mode & 0o077:
            raise ValueError("unsafe source file")
        result=subprocess.run(["ssh-keygen","-lf",str(public_key)],capture_output=True,text=True,timeout=5,check=True)
        fingerprint=result.stdout.split()[1]
        token=token_path.read_text().strip()
    payload=build_payload(user,fingerprint,token,platform,deployment,budget_mac)
    if destination.exists():
        raise ValueError("output already exists; choose a new path, do not overwrite")
    mode = 0o600 if user else 0o644
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    # Establish private permissions at creation, before opening anything readable.
    with os.fdopen(os.open(destination, flags, mode), "wb") as output:
        os.fchmod(output.fileno(), mode)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name, data in payload.items():
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = (0o100700 if name.endswith('.command') else 0o100600 if user else 0o100644) << 16
                entry.compress_type = zipfile.ZIP_DEFLATED
                bundle.writestr(entry, data)
    with zipfile.ZipFile(destination) as bundle:
        assert bundle.testzip() is None
        assert set(bundle.namelist()) == set(payload)
        assert all(bundle.read(name) == data for name, data in payload.items())
    return {"archive": str(destination), "files": len(payload), "markdown_documents": 2,
            "recipient": user, "contains_personal_key": bool(user), "bytes": destination.stat().st_size,
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(), "newcomer_app_test": "NOT_RUN"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--user')
    parser.add_argument('--public-key', type=Path)
    parser.add_argument('--token-file', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--platform', choices=('macos', 'windows'), default='macos')
    route = parser.add_argument_group('个人包部署参数（服务器、公钥、远端端口必须同时指定；否则沿用示例）')
    route.add_argument('--server-ip', help='SSH 服务器 IPv4 地址，SSH 端口仍为 22')
    route.add_argument('--host-public-key', type=Path, help='已通过可信渠道核验的 OpenSSH ssh-ed25519 主机 .pub 文件')
    route.add_argument('--gateway-port', type=int, help='服务器 127.0.0.1 上分配给该成员的网关端口（不改变客户端端口）')
    route.add_argument('--host-fingerprint', help='可选：独立核实的 SSH 主机 SHA256 指纹，用于再次比对')
    route.add_argument('--budget-mac', action='store_true', help='使用固定模型和硬限额线路，禁止打成旧直通包')
    args = parser.parse_args()
    if bool(args.user) != bool(args.public_key) or bool(args.user) != bool(args.token_file):
        parser.error('personal package requires user, public key and existing token file together')
    if not args.user and any(value is not None for value in (args.server_ip, args.host_public_key, args.gateway_port, args.host_fingerprint)):
        parser.error('deployment parameters are only for personal packages')
    deployment = load_deployment(args.server_ip, args.host_public_key, args.gateway_port, args.host_fingerprint)
    if args.budget_mac and not args.host_fingerprint:
        parser.error('--budget-mac requires the separately verified --host-fingerprint')
    print(json.dumps(pack(args.output, args.user, args.public_key, args.token_file, args.platform, deployment, args.budget_mac), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'status':'STOPPED','error_type':type(exc).__name__,'note':'No secret contents displayed'}))
        raise SystemExit(2)
