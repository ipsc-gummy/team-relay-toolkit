#!/usr/bin/env python3
"""Run only the source repository's isolated test scripts."""
from pathlib import Path
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TESTS = (
    "程序/测试App全局路由.py",
    "程序/测试App全局路由代理.py",
    "程序/测试App自愈.py",
    "程序/App切换/测试切换.py",
    "程序/测试新人一键接入.py",
    "程序/用量统计/test_usage.py",
)


def main():
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    for relative in TESTS:
        path = ROOT / relative
        if not path.is_file():
            raise SystemExit("Missing required isolated test: " + relative)
        print("TEST=" + relative, flush=True)
        result = subprocess.run([sys.executable, "-B", str(path)], cwd=path.parent, env=env)
        if result.returncode:
            raise SystemExit(result.returncode)
    print("ISOLATED_TESTS=PASS")


if __name__ == "__main__":
    main()
