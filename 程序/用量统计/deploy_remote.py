"""Executed over admin SSH with source-only PAYLOAD injected; secrets never leave server."""
import copy
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
import urllib.request

import bcrypt
import yaml

def main(payload):
    required = {'usage.py', 'sysu-usage.service', 'share-codex-usage'}
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError('source payload must contain exactly the required files')
    if any(not isinstance(payload[name], str) or not payload[name] for name in required):
        raise TypeError('source payload values must be nonempty text')

    os.umask(0o077)
    assert os.geteuid() == 0
    config = Path('/etc/cliproxyapi/config.yaml')
    original_bytes = config.read_bytes()
    before = yaml.safe_load(original_bytes)
    assert before['host'] == '127.0.0.1' and before['port'] == 8317
    assert before['usage-statistics-enabled'] is False
    assert before['remote-management']['allow-remote'] is False
    assert not before['remote-management'].get('secret-key')
    assert before['remote-management']['disable-control-panel'] is True
    assert len(before['api-keys']) == len(set(before['api-keys']))
    assert 'redis-usage-queue-retention-seconds' not in before
    state = Path('/var/lib/sysu-usage')
    program = Path('/opt/sysu-usage')
    unit = Path('/etc/systemd/system/sysu-usage.service')
    command = Path('/usr/local/bin/share-codex-usage')
    for target in [state, program, unit, command]:
        assert not target.exists(), 'target exists; review instead of overwrite'
    state.mkdir(mode=0o700)
    program.mkdir(mode=0o755)
    os.chmod(program, 0o755)
    backup = state / 'config.before-usage.yaml'
    backup.write_bytes(original_bytes)
    os.chmod(backup, 0o600)
    token = secrets.token_urlsafe(48)
    (state / 'management.token').write_text(token + '\n')
    hashed = bcrypt.hashpw(token.encode(), bcrypt.gensalt()).decode()
    for name in ['usage.py']:
        target = program / name
        target.write_text(payload[name])
        os.chmod(target, 0o755)
    unit.write_text(payload['sysu-usage.service'])
    os.chmod(unit, 0o644)
    command.write_text(payload['share-codex-usage'])
    os.chmod(command, 0o755)
    subprocess.run(['systemd-analyze', 'verify', str(unit)], check=True)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    # Start before turning on events, without installing boot autostart.
    subprocess.run(['systemctl', 'start', 'sysu-usage.service'], check=True)
    updated = original_bytes.decode()
    updated, n = re.subn(r'(?m)^usage-statistics-enabled: false\s*$', 'usage-statistics-enabled: true', updated)
    assert n == 1
    updated, n = re.subn(r'(?m)^(  secret-key:)\s*""\s*$', lambda m: m[1] + ' "' + hashed + '"', updated)
    assert n == 1
    updated += '\n# Private usage queue; drained locally every 5 seconds.\nredis-usage-queue-retention-seconds: 3600\n'
    after = yaml.safe_load(updated)
    expected = copy.deepcopy(before)
    expected['usage-statistics-enabled'] = True
    expected['remote-management']['secret-key'] = hashed
    expected['redis-usage-queue-retention-seconds'] = 3600
    assert after == expected
    assert config.read_bytes() == original_bytes, 'config changed concurrently'
    pid_before = subprocess.check_output(['systemctl', 'show', 'cliproxyapi', '-p', 'MainPID', '--value'], text=True).strip()
    # Keep inode so the current watcher sees a Write event. Complete write before its debounce.
    with config.open('r+b') as out:
        out.write(updated.encode())
        out.truncate()
        out.flush()
        os.fsync(out.fileno())
    assert yaml.safe_load(config.read_text()) == expected
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    active = False
    for _ in range(15):
        try:
            req = urllib.request.Request('http://127.0.0.1:8317/v0/management/usage-statistics-enabled',
                                         headers={'Authorization': 'Bearer ' + token})
            with opener.open(req, timeout=2) as response:
                active = json.load(response).get('usage-statistics-enabled') is True
            if active:
                break
        except Exception:
            pass
        time.sleep(1)
    pid_after = subprocess.check_output(['systemctl', 'show', 'cliproxyapi', '-p', 'MainPID', '--value'], text=True).strip()
    print(json.dumps({'config_written': True, 'runtime_statistics_enabled': active,
                      'relay_pid_unchanged': pid_before == pid_after,
                      'backup': str(backup), 'collector_started': True,
                      'boot_autostart_added': False}))
    if not active:
        print('Runtime not confirmed. No relay restart performed; check active connections first.')
