#!/bin/bash
set -euo pipefail
sg_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
sg_candidates=("${SG_RELAY_PYTHON:-python3}" /opt/homebrew/bin/python3 /usr/local/bin/python3 "$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3")
for sg_python in "${sg_candidates[@]}"; do
  if "$sg_python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)' 2>/dev/null; then
    exec "$sg_python" -B "$sg_dir/程序/一键接入.py" "$@"
  fi
done
printf '%s\n' '需要 Python 3.11+，请把这条提示发管理员；没有修改配置或安装软件。' >&2
exit 2
