#!/usr/bin/env python3
"""Run over admin SSH; reuse existing restricted tunnel policy, never replace a member."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def run(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=15)


def exclusive(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'w') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def effective(user):
    return run('/usr/sbin/sshd', '-T', '-C', f'user={user},host=localhost,addr=198.51.100.10').stdout


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--user', required=True)
    p.add_argument('--public-key', required=True)
    p.add_argument('--fingerprint', required=True)
    p.add_argument('--expected-hostname', required=True,
                   help='管理员已核实的目标主机 hostname；没有默认服务器')
    args = p.parse_args()
    user, public, fp = args.user, args.public_key, args.fingerprint
    os.umask(0o077)
    if os.geteuid() != 0 or socket.gethostname() != args.expected_hostname:
        raise RuntimeError('unexpected host or user')
    import yaml
    assert re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', user) and user != 'root'
    assert '\n' not in public and public.startswith('ssh-ed25519 ')
    home = Path('/home') / user
    conf = Path('/etc/ssh/sshd_config.d') / f'92-cliproxyapi-{user}.conf'
    token = Path('/etc/cliproxyapi/team-clients') / f'{user}.token'
    for path in [home, conf, token]:
        assert not path.exists() and not path.is_symlink(), 'target exists; inspect before retry'
    for kind in ['passwd', 'group']:
        assert run('getent', kind, user, check=False).returncode != 0, 'existing identity'
    config = Path('/etc/cliproxyapi/config.yaml')
    assert not config.is_symlink()
    original = config.read_text()
    cfg = yaml.safe_load(original)
    keys = cfg['api-keys']
    assert cfg['host'] == '127.0.0.1' and cfg['port'] == 8317
    assert isinstance(keys, list) and len(keys) == len(set(keys))
    assert not any(k.startswith('cpa-' + user + '-') for k in keys)
    key = 'cpa-' + user + '-' + secrets.token_hex(32)
    lines = original.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if re.fullmatch(r'api-keys:\s*', line)]
    assert len(starts) == 1
    end = starts[0] + 1
    while end < len(lines) and (not lines[end].strip() or lines[end][0].isspace()):
        end += 1
    replacement = ''.join(lines[:end] + ['  - "' + key + '"\n'] + lines[end:])
    expected = dict(cfg, **{'api-keys': keys + [key]})
    assert yaml.safe_load(replacement) == expected
    source = Path('/etc/ssh/sshd_config.d/90-cliproxyapi-team.conf').read_text()
    assert source.count('Match User member-a,member-b') == 1
    candidate = source.replace('Match User member-a,member-b', 'Match User ' + user).replace(
        '# Applies only to the two explicitly authorized teammate accounts.',
        '# Applies only to the explicitly authorized ' + user + ' tunnel account.')
    query_shell = Path('/usr/local/libexec/sysu-query-shell')
    query_enabled = 'ForceCommand sysu-usage-query' in candidate
    assert not query_enabled or query_shell.is_file(), 'query shell missing'
    records = Path(tempfile.mkdtemp(prefix=user + '-', dir='/etc/cliproxyapi/team-backups'))
    exclusive(records / 'public.pub', public + '\n')
    assert run('ssh-keygen', '-lf', str(records / 'public.pub')).stdout.split()[1] == fp
    exclusive(records / 'config.before.yaml', original)
    unaffected = sorted(set(['root', 'owner', 'member-a', 'member-b', 'cpa-unrelated-check'] +
                            [p.stem for p in token.parent.glob('*.token')
                             if re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', p.stem) and p.stem != user]))
    before = {name: effective(name) for name in unaffected}
    exclusive(conf, candidate, 0o644)
    try:
        run('/usr/sbin/sshd', '-t')
        assert all(effective(name) == before[name] for name in unaffected)
        required = {'authenticationmethods publickey', 'passwordauthentication no',
                    'kbdinteractiveauthentication no', 'allowtcpforwarding local',
                    'allowstreamlocalforwarding no', 'permitopen 127.0.0.1:8317',
                    'permitlisten none', 'maxsessions 1' if query_enabled else 'maxsessions 0', 'permittty no',
                    'allowagentforwarding no', 'permituserrc no'}
        assert required <= set(effective(user).splitlines())
        if query_enabled:
            assert 'forcecommand sysu-usage-query' in effective(user).splitlines()
    except Exception:
        conf.rename(records / 'rejected-ssh.conf')
        raise
    run('systemctl', 'reload', 'ssh.service')
    run('useradd', '--create-home', '--user-group', '--home-dir', str(home), '--shell',
        str(query_shell) if query_enabled else '/usr/sbin/nologin', '--comment', 'CLIProxyAPI restricted tunnel and usage', user)
    home.chmod(0o700)
    run('install', '-d', '-m', '0700', '-o', user, '-g', user, str(home / '.ssh'))
    exclusive(records / 'authorized_keys', 'restrict,port-forwarding,permitopen="127.0.0.1:8317" ' + public + '\n')
    run('install', '-m', '0600', '-o', user, '-g', user, str(records / 'authorized_keys'), str(home / '.ssh/authorized_keys'))
    assert run('id', '-nG', user).stdout.strip() == user
    sudo = run('sudo', '-l', '-U', user, check=False)
    assert 'not allowed to run sudo' in sudo.stdout + sudo.stderr
    for path in [str(config), '/var/lib/sysu-usage/management.token']:
        run('runuser', '-u', user, '--', 'test', '!', '-r', path)
    run('runuser', '-u', user, '--', 'test', '!', '-x', '/var/lib/cliproxyapi/auth')
    print('ACCOUNT_AND_RESTRICTED_SSH=PASS; OTHER_USERS_UNCHANGED', flush=True)
    exclusive(token, key + '\n')
    assert config.read_text() == original, 'concurrent config change; do not overwrite'
    pid_before = run('systemctl', 'show', 'cliproxyapi', '-p', 'MainPID', '--value').stdout.strip()
    # Preserve inode to notify the running watcher, avoiding a relay restart.
    with config.open('r+b') as out:
        out.write(replacement.encode())
        out.truncate()
        out.flush()
        os.fsync(out.fileno())
    assert yaml.safe_load(config.read_text()) == expected
    http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    statuses = []
    for item in keys + [key]:
        status = None
        for _ in range(20):
            req = urllib.request.Request('http://127.0.0.1:8317/v1/models', headers={'Authorization': 'Bearer ' + item})
            try:
                with http.open(req, timeout=5) as response:
                    status = response.status
                break
            except urllib.error.HTTPError as error:
                status = error.code
                if status != 401:
                    break
            time.sleep(0.5)
        statuses.append(status)
    pid_after = run('systemctl', 'show', 'cliproxyapi', '-p', 'MainPID', '--value').stdout.strip()
    print(json.dumps({'user': user, 'home': str(home), 'fingerprint': fp, 'keys_after': len(keys)+1,
                      'key_http_statuses': statuses, 'only_api_keys_changed': True,
                      'relay_pid_unchanged': pid_before == pid_after,
                      'backup': str(records), 'private_key_login': 'NOT_RUN', 'newcomer_app': 'NOT_RUN'}), flush=True)
    assert statuses == [200] * (len(keys) + 1), 'key runtime verification failed; inspect, do not retry blindly'


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'status': 'STOPPED', 'error_type': type(exc).__name__,
                          'note': 'Inspect partial state before retry; no secrets displayed'}), flush=True)
        raise SystemExit(2)
