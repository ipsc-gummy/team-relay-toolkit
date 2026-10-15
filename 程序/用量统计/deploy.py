"""仅向管理员显式指定并已核实 SSH 主机密钥的服务器部署统计模块。"""
import argparse
import base64
import json
from pathlib import Path
import subprocess

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True, help='目标 SSH 主机，例如 root@relay.example.invalid')
    parser.add_argument('--identity', required=True, type=Path, help='管理员 SSH 私钥路径')
    parser.add_argument('--expected-hostname', required=True, help='目标服务器的 hostname')
    args = parser.parse_args()
    if args.host.startswith('-') or not args.identity.is_file():
        parser.error('需要有效的目标主机与现有私钥文件')
    source = Path(__file__).resolve().parent
    payload = {name: (source / name).read_text()
               for name in ['usage.py', 'sysu-usage.service', 'share-codex-usage']}
    code = ('import json,base64,socket\n'
            'if socket.gethostname() != ' + repr(args.expected_hostname) + ':\n'
            '    raise SystemExit("unexpected target hostname")\n'
            'PAYLOAD=json.loads(base64.b64decode(' +
            repr(base64.b64encode(json.dumps(payload).encode()).decode()) + '))\n' +
            (source / 'deploy_remote.py').read_text() + '\nmain(PAYLOAD)\n')
    subprocess.run(['ssh', '-F', 'none', '-i', str(args.identity),
                    '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
                    '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=10',
                    args.host, 'python3 -'], input=code, text=True, check=True)


if __name__ == '__main__':
    main()
