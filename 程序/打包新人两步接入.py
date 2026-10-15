#!/usr/bin/env python3
"""只打包显式文件；说明包无Key，个人包只包含指定收件人的既有Key。"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent
DOCS = ("第一步_生成公钥发给管理员.md", "第二步_一行安装重启使用.md")


def render_core(user, fingerprint):
    source = (ROOT / "程序/App切换/切换CodexApp.py").read_text()
    tree = ast.parse(source)
    assignment = next(node for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "FINGERPRINTS" for t in node.targets))
    lines = source.splitlines(keepends=True)
    result = "".join(lines[:assignment.lineno - 1]) + "FINGERPRINTS = " + repr({user: fingerprint}) + "\n" + "".join(lines[assignment.end_lineno:])
    ast.parse(result)
    return result.encode()


def check_public(data):
    if re.search(rb'(?:sk-|cpa-)[A-Za-z0-9_-]{25,}|-----BEGIN [A-Z ]*PRIVATE KEY-----', data):
        raise ValueError("unexpected credential or unrelated content")


def build_payload(user=None, fingerprint=None, token=None, platform="macos"):
    """One payload implementation for new recipients and identity-preserving refreshes."""
    if platform not in ("macos", "windows"):
        raise ValueError("unsupported platform")
    prefix = "Codex团队接入/" if user else "团队中转_两步说明/"
    docs = ROOT / ("新人接入/Windows两步版" if platform == "windows" else "新人接入/两步版")
    payload = {prefix + name: (docs / name).read_bytes() for name in DOCS}
    if user:
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', user) or user == "root":
            raise ValueError("invalid recipient")
        if not isinstance(fingerprint,str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fingerprint):
            raise ValueError("invalid public fingerprint")
        if not re.fullmatch('cpa-' + user + '-[0-9a-f]{64}', token):
            raise ValueError("key recipient mismatch")
        entry = "接入.cmd" if platform == "windows" else "接入.command"
        payload[prefix + entry] = (ROOT / "程序/新人一键接入" / entry).read_bytes()
        if platform == "windows":
            payload[prefix + entry] = payload[prefix + entry].replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        code_path = "program/" if platform == "windows" else "程序/"
        payload[prefix + code_path + ("install.py" if platform == "windows" else "一键接入.py")] = (ROOT / "程序/新人一键接入/一键接入.py").read_bytes()
        payload[prefix + code_path + "切换CodexApp.py"] = render_core(user, fingerprint)
        payload[prefix + "个人参数.json"] = json.dumps({
            "user": user, "public_fingerprint": fingerprint,
            # RFC8032 公开测试向量；部署前须与客户端一起替换，不能用于真实服务器。
            "host": "203.0.113.10", "host_fingerprint": "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8",
            "compatibility_check": "isolated_app_server_command_auth_v1", "provider_display_name": "团队中转",
            "team_name": "示例团队", "server_provisioning": "must_be_confirmed_by_administrator",
            "platform": platform, "platform_app_validation": "requires_recipient_test",
            "package_release": "2026-09-12-r2", "mode_schema": 3,
            "windows_backend_discovery": "appx_hash_verified_runtime_copy",
            "managed_fields": "route_selectors_and_sg_team_only",
            "existing_powershell_migration": "local_review_required_do_not_overwrite",
            "local_agent_entry": DOCS[1],
        }, ensure_ascii=False, indent=2).encode()
        for data in payload.values():
            check_public(data)
        payload[prefix + "中转访问密钥.txt"] = (token + "\n").encode()
    else:
        for data in payload.values():
            check_public(data)
    return payload


def pack(destination, user=None, public_key=None, token_path=None, platform="macos"):
    fingerprint=token=None
    if user:
        if public_key.is_symlink() or token_path.is_symlink() or token_path.stat().st_mode & 0o077:
            raise ValueError("unsafe source file")
        result=subprocess.run(["ssh-keygen","-lf",str(public_key)],capture_output=True,text=True,timeout=5,check=True)
        fingerprint=result.stdout.split()[1]
        token=token_path.read_text().strip()
    payload=build_payload(user,fingerprint,token,platform)
    if destination.exists():
        raise ValueError("output already exists; choose a new path, do not overwrite")
    with destination.open("xb") as output:
        os.fchmod(output.fileno(), 0o600 if user else 0o644)
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
    args = parser.parse_args()
    if bool(args.user) != bool(args.public_key) or bool(args.user) != bool(args.token_file):
        parser.error('personal package requires user, public key and existing token file together')
    print(json.dumps(pack(args.output, args.user, args.public_key, args.token_file, args.platform), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'status':'STOPPED','error_type':type(exc).__name__,'note':'No secret contents displayed'}))
        raise SystemExit(2)
