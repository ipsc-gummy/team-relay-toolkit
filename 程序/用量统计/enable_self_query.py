"""管理员显式指定服务器、成员与既有版本哈希后启用本人用量查询。"""
import argparse
import base64
import json
from pathlib import Path
import subprocess


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',required=True,help='目标 SSH 主机，例如 root@relay.example.invalid')
    parser.add_argument('--identity',required=True,type=Path,help='管理员 SSH 私钥路径')
    parser.add_argument('--expected-hostname',required=True,help='已核实的目标 hostname')
    parser.add_argument('--user',action='append',required=True,help='已开通成员；每位成员重复传一次')
    parser.add_argument('--ssh-dropin',action='append',required=True,help='已核实的 sshd_config.d 文件名；可重复')
    parser.add_argument('--expected-usage-sha256',required=True,help='服务器现有 usage.py 的已核实 SHA-256')
    args=parser.parse_args()
    import re
    if (args.host.startswith('-') or not args.identity.is_file()
            or not re.fullmatch(r'[0-9a-f]{64}',args.expected_usage_sha256)
            or any(not re.fullmatch(r'[a-z][a-z0-9_-]{0,30}',user) or user=='root' for user in args.user)
            or any(not re.fullmatch(r'[A-Za-z0-9_-]+\.conf',name) for name in args.ssh_dropin)):
        parser.error('目标、私钥、成员、drop-in 文件名或 SHA-256 无效')
    SOURCE=Path(__file__).resolve().parent
    payload={name:(SOURCE/name).read_text() for name in ['usage.py','sysu-query-shell','sysu-usage.service']}
    REMOTE=r'''
import os,pathlib,json,subprocess,tempfile,hashlib,sqlite3,time,socket,pwd
os.umask(0o077)
if os.geteuid()!=0 or socket.gethostname()!=OPTIONS['expected_hostname']:
 raise RuntimeError('unexpected host or user')
users=OPTIONS['users']
dropins=OPTIONS['dropins']
shell=pathlib.Path('/usr/local/libexec/sysu-query-shell')
program=pathlib.Path('/opt/sysu-usage/usage.py');unit=pathlib.Path('/etc/systemd/system/sysu-usage.service')
assert not shell.exists()
assert hashlib.sha256(program.read_bytes()).hexdigest()==OPTIONS['expected_usage_sha256']
assert all(pwd.getpwnam(user).pw_shell=='/usr/sbin/nologin' for user in users)
def run(*args):return subprocess.check_output(args,text=True).strip()
def effective(user):return run('/usr/sbin/sshd','-T','-C',f'user={user},host=localhost,addr=198.51.100.10')
before={user:effective(user) for user in users+['root','query-unrelated-test']}
old={pathlib.Path('/etc/ssh/sshd_config.d')/name:(pathlib.Path('/etc/ssh/sshd_config.d')/name).read_bytes() for name in dropins}
assert all(data.count(b'MaxSessions 0')==1 and b'ForceCommand' not in data for data in old.values())
backup=pathlib.Path(tempfile.mkdtemp(prefix='self-query-',dir='/var/lib/sysu-usage'))
config=pathlib.Path('/etc/cliproxyapi/config.yaml');config_hash=hashlib.sha256(config.read_bytes()).hexdigest()
key_hashes={u:hashlib.sha256((pathlib.Path('/home')/u/'.ssh/authorized_keys').read_bytes()).hexdigest() for u in users}
relay_pid=run('systemctl','show','cliproxyapi','-p','MainPID','--value')
with sqlite3.connect('file:/var/lib/sysu-usage/usage.sqlite3?mode=ro',uri=True) as db:
 previous_events=set(row[0] for row in db.execute('SELECT event_id FROM events'))
for path in [program,unit,*old]:
 (backup/path.name).write_bytes(path.read_bytes())
(backup/'original-shells.json').write_text(json.dumps({u:pwd.getpwnam(u).pw_shell for u in users}))
def write(path,text,mode):
 fd,name=tempfile.mkstemp(prefix='.self-query-',dir=path.parent)
 with os.fdopen(fd,'w') as out:
  os.fchmod(out.fileno(),mode);out.write(text);out.flush();os.fsync(out.fileno())
 os.replace(name,path)
if not shell.parent.exists():
 shell.parent.mkdir(mode=0o755)
 shell.parent.chmod(0o755)  # Explicitly undo the private-file umask for traversal.
assert shell.parent.stat().st_mode & 0o005 == 0o005,'query shell parent not traversable'
write(shell,PAYLOAD['sysu-query-shell'],0o755)
write(program,PAYLOAD['usage.py'],0o755)
write(unit,PAYLOAD['sysu-usage.service'],0o644)
subprocess.run(['systemd-analyze','verify',str(unit)],check=True,capture_output=True)
subprocess.run(['systemctl','daemon-reload'],check=True)
started=time.time();subprocess.run(['systemctl','restart','sysu-usage'],check=True)
for _ in range(20):
 if pathlib.Path('/run/sysu-usage-query/query.sock').exists():break
 time.sleep(.25)
assert pathlib.Path('/run/sysu-usage-query/query.sock').exists(),'query service not ready; SSH unchanged'
for path,data in old.items():
 replacement=data.decode().replace('MaxSessions 0','MaxSessions 1\n    ForceCommand sysu-usage-query')
 write(path,replacement,0o644)
try:
 subprocess.run(['/usr/sbin/sshd','-t'],check=True)
 for user in users:
  expected=before[user].replace('maxsessions 0','maxsessions 1').replace('forcecommand none','forcecommand sysu-usage-query')
  assert effective(user)==expected,'unexpected SSH permission change'
 for user in ['root','query-unrelated-test']:assert effective(user)==before[user]
except Exception:
 for path,data in old.items():write(path,data.decode(),0o644)
 raise
# Before reload, the old MaxSessions=0 still forbids commands; after reload the
# custom shell and ForceCommand independently reject arbitrary execution.
for user in users:subprocess.run(['usermod','--shell',str(shell),user],check=True)
subprocess.run(['systemctl','reload','ssh'],check=True)
checks=[]
for user in users:
 result=subprocess.run(['runuser','-u',user,'--',str(shell),'--query'],capture_output=True,text=True,timeout=15)
 assert result.returncode==0 and 'Codex 用量：'+user in result.stdout
 assert all('Codex 用量：'+other+'\n' not in result.stdout for other in users if other!=user)
 for target in ['/var/lib/sysu-usage/usage.sqlite3','/var/lib/sysu-usage/management.token','/etc/cliproxyapi/config.yaml']:
  assert subprocess.run(['runuser','-u',user,'--','test','-r',target]).returncode!=0
 assert hashlib.sha256((pathlib.Path('/home')/user/'.ssh/authorized_keys').read_bytes()).hexdigest()==key_hashes[user]
 checks.append({'user':user,'own_report':True,'other_reports_absent':True,'private_files_unreadable':True})
with sqlite3.connect('file:/var/lib/sysu-usage/usage.sqlite3?mode=ro',uri=True) as db:
 after_events=set(row[0] for row in db.execute('SELECT event_id FROM events'))
 assert previous_events<=after_events
 assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
assert hashlib.sha256(config.read_bytes()).hexdigest()==config_hash
assert relay_pid==run('systemctl','show','cliproxyapi','-p','MainPID','--value')
print(json.dumps({'users':checks,'backup':str(backup),'relay_unchanged':True,'authorized_keys_unchanged':True,
 'existing_events_preserved':len(previous_events),'ssh_reloaded':True,'only_statistics_service_restarted':True,
 'unit_file_state':run('systemctl','show','sysu-usage','-p','UnitFileState','--value')},ensure_ascii=False))
'''
    options={'expected_hostname':args.expected_hostname,'users':args.user,'dropins':args.ssh_dropin,
             'expected_usage_sha256':args.expected_usage_sha256}
    code=('import base64,json\nPAYLOAD=json.loads(base64.b64decode('
          +repr(base64.b64encode(json.dumps(payload).encode()).decode())+'))\n'
          +'OPTIONS='+repr(options)+'\n'+REMOTE)
    subprocess.run(['ssh','-F','none','-i',str(args.identity),'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10',args.host,'python3 -'],input=code,text=True,check=True)


if __name__ == '__main__':
    main()
