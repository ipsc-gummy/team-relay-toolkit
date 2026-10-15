#!/usr/bin/env python3
"""Check the repository export for private artifacts and deployment identifiers.

This is a targeted export check, not a replacement for manual review or a
full credential scanner. Synthetic fixtures remain allowed only where clear.
"""
from pathlib import Path
import ipaddress
import re

ROOT = Path(__file__).resolve().parents[1]
TEST_PUBLIC_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
TEST_FINGERPRINT = "bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"
DOC_NETWORKS = tuple(ipaddress.ip_network(x) for x in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
PRIVATE_DIRS = {".连接凭据", "队友公钥", "队友接入包", "检查记录", "backups", "state"}
PRIVATE_SUFFIXES = {".token", ".pem", ".key", ".pub", ".pcap", ".pcapng", ".jsonl", ".sqlite", ".sqlite3", ".db", ".zip", ".log"}
SKIP_DIRS = {".git", ".venv", "__pycache__"}


def issues():
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.is_symlink():
            yield relative, "symlink"
            continue
        if not path.is_file():
            continue
        if any(part in PRIVATE_DIRS for part in relative.parts) or path.suffix in PRIVATE_SUFFIXES:
            yield relative, "private artifact"
            continue
        if path.name in {"auth.json", "个人参数.json", "中转访问密钥.txt"}:
            yield relative, "credential filename"
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeError, OSError):
            yield relative, "non-text or unreadable file"
            continue
        checks = (
            (r"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----", "private key"),
            (r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})", "GitHub token"),
            (r"cpa-[a-z][a-z0-9_-]*-[0-9a-f]{64}", "literal member token"),
            (r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{15,}", "JWT"),
            (r"/Users/(?!example(?:/|\b))[A-Za-z0-9_.-]+", "personal Mac path"),
            (r"\biZ[a-zA-Z0-9]{10,}\b", "cloud instance hostname"),
        )
        for pattern, reason in checks:
            if re.search(pattern, text):
                yield relative, reason
        for value in set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text)):
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_loopback or address.is_unspecified or any(address in network for network in DOC_NETWORKS):
                continue
            # Private fixture networks are not production internet endpoints.
            if address.is_private:
                continue
            yield relative, "non-example public IPv4 address"
        for public_key in re.findall(r"ssh-ed25519\s+([A-Za-z0-9+/]{40,}={0,2})", text):
            if public_key != TEST_PUBLIC_KEY:
                yield relative, "non-fixture SSH public key"
        for fingerprint in re.findall(r"SHA256:([A-Za-z0-9+/]{43})(?![A-Za-z0-9+/])", text):
            if fingerprint != TEST_FINGERPRINT:
                yield relative, "non-fixture SSH fingerprint"


if __name__ == "__main__":
    found = list(issues())
    for path, reason in found:
        print(str(path) + ": " + reason)
    print("RELEASE_CHECK=" + ("FAIL" if found else "PASS"))
    raise SystemExit(1 if found else 0)
