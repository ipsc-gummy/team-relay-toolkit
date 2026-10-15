"""Managed-field recovery for the owner's App wrapper. No history/auth mutation."""
from __future__ import annotations
import copy
from contextlib import contextmanager
import datetime as dt
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import tempfile
import time
import tomllib
import urllib.error
import urllib.request

CANONICAL='sg_team.canonical.json'
JOURNAL='自愈备份'
LOG='自愈记录.jsonl'
RETENTION=10
METHODS={'thread/start':'Start','thread/resume':'Resume','thread/fork':'Fork'}
_HEALTH_CACHE={}
HEALTH_TTL=10.0

@contextmanager
def operation_lock(c):
    """Serialize simultaneous App startup checks, without duplicate repair workers."""
    fd=os.open(c.STATE/'操作.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1:raise Failure('LOCK_INVALID')
        deadline=time.monotonic()+35
        while True:
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>=deadline:raise Failure('REPAIR_BUSY')
                time.sleep(0.05)
        yield
    finally:os.close(fd)

class Failure(RuntimeError):
    def __init__(self,reason,status=None):
        self.reason=reason;self.status=status
        super().__init__(reason)  # Never include original OS/HTTP messages or bodies.

def encode(value):return (json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
def sha(value):return hashlib.sha256(value).hexdigest()
def app_files(c):return {k:c.fingerprint(p) for k,p in [('binary',c.BINARY),('asar',c.ASAR)]}

def audit(c,**fields):
    allowed={'app_version','app_fingerprint','repair_reason','config_action','tunnel_action',
             'health_status','http_status','protocol_compatibility','rollback_status','mode'}
    data={k:v for k,v in fields.items() if k in allowed}
    data['timestamp']=dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds')
    try:
        c.private_dir(c.STATE)
        fd=os.open(c.STATE/LOG,os.O_APPEND|os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'ab') as stream:
            info=os.fstat(stream.fileno())
            if info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:return
            fcntl.flock(stream.fileno(),fcntl.LOCK_EX)
            if info.st_size>2*1024*1024:stream.truncate(0)
            stream.write(encode(data).replace(b'\n',b'')+b'\n')
    except OSError:pass

def parse(data):
    try:return tomllib.loads(data.decode('utf-8'))
    except (ValueError,UnicodeError):raise Failure('CONFIG_STRUCTURE') from None

def line_contexts(text):
    """Find statement starts without treating headers inside multiline strings as TOML."""
    quote=None;escaped=False
    for line in text.splitlines(keepends=True):
        yield line,quote is None
        i=0
        while i<len(line):
            if quote:
                if quote.startswith('"') and line[i]=='\\' and not escaped:
                    i+=2;continue
                if line.startswith(quote,i):i+=len(quote);quote=None;continue
                i+=1;continue
            if line[i]=='#':break
            if line[i] in ('"',"'"):
                quote=line[i]*3 if line.startswith(line[i]*3,i) else line[i]
                i+=len(quote);continue
            i+=1

def merge(data,provider,selected):
    before=parse(data)
    providers=before.get('model_providers',{})
    if not isinstance(providers,dict):raise Failure('CONFIG_STRUCTURE')
    if providers.get('sg_team')==provider and before.get('model_provider')==selected:return data
    expected=copy.deepcopy(before);expected['model_provider']=selected
    expected.setdefault('model_providers',{})['sg_team']=provider
    # Canonical is a deliberately narrow, ordinary TOML block, not a generic serializer.
    q=lambda x:json.dumps(x,ensure_ascii=False)
    block='\n[model_providers.sg_team]\n'+''.join(k+' = '+q(provider[k])+'\n' for k in ('name','base_url','wire_api'))
    block+='\n[model_providers.sg_team.auth]\n'+''.join(k+' = '+q(v)+'\n' for k,v in provider['auth'].items())
    rewrite_block=providers.get('sg_team')!=provider
    out=[];root=True;drop=False;selector=False
    for line,statement in line_contexts(data.decode()):
        if statement and re.match(r'^\s*\[',line):
            root=False
            drop=rewrite_block and bool(re.match(r'^\s*\[\s*(?:model_providers|"model_providers"|\x27model_providers\x27)\s*\.\s*(?:sg_team|"sg_team"|\x27sg_team\x27)\s*(?:\.|\])',line))
        if statement and root and re.match(r'^\s*(?:model_provider|"model_provider"|\x27model_provider\x27)\s*=',line):
            line,count=re.subn(r'^(\s*(?:model_provider|"model_provider"|\x27model_provider\x27)\s*=\s*)("[^"\n]*"|\x27[^\x27\n]*\x27)',lambda m:m[1]+q(selected),line,count=1)
            if count!=1:raise Failure('CONFIG_STRUCTURE')
            selector=True
        # Keep comments/blank lines, even when the owned block is replaced.
        if not drop or (statement and (not line.strip() or line.lstrip().startswith('#'))):out.append(line)
    text=''.join(out)
    if not selector:text='model_provider = '+q(selected)+'\n'+text
    if rewrite_block:text+=('' if text.endswith('\n') else '\n')+block
    result=text.encode()
    if parse(result)!=expected:raise Failure('CONFIG_STRUCTURE')
    return result

def validate_provider(c,p,helper_hash=None):
    settings=c.core().read_settings(c.LEGACY)
    if settings.get('user')!='owner' or settings.get('host')!='203.0.113.10' or settings.get('target')!='127.0.0.1:8317' or settings.get('port')!=18318:
        raise Failure('CANONICAL_INVALID')
    helper=c.LEGACY/'切换CodexApp.py'
    expected={'command':settings['python'],'args':[str(helper),'_credential','--state-dir',str(c.LEGACY)],'timeout_ms':5000,'refresh_interval_ms':0}
    if (not isinstance(p,dict) or set(p)!= {'name','base_url','wire_api','auth'}
        or not isinstance(p['name'],str) or p['base_url']!='http://127.0.0.1:18318/v1'
        or p['wire_api']!='responses' or p['auth']!=expected):raise Failure('CANONICAL_INVALID')
    if helper_hash is not None and sha(c.read_file(helper))!=helper_hash:raise Failure('CREDENTIAL_HELPER_CHANGED')
    return settings

def canonical(c,value):
    try:
        if value['self_heal'].get('schema')!=1:raise Failure('CANONICAL_INVALID')
        raw=c.read_file(c.STATE/CANONICAL)
        if sha(raw)!=value['self_heal']['canonical_sha256']:raise Failure('CANONICAL_INVALID')
        obj=json.loads(raw)
        if obj.get('schema')!=1:raise Failure('CANONICAL_INVALID')
        validate_provider(c,obj['provider'],obj['helper_sha256'])
        return obj['provider']
    except (KeyError,ValueError):raise Failure('CANONICAL_INVALID') from None

def resolve(obj,document):
    for _ in range(8):
        if '$ref' not in obj:return obj
        ref=obj['$ref']
        if not ref.startswith('#/'):raise Failure('PROTOCOL_INCOMPATIBLE')
        obj=document
        for part in ref[2:].split('/'):obj=obj[part.replace('~1','/').replace('~0','~')]
    raise Failure('PROTOCOL_INCOMPATIBLE')

def string_field(obj,document):
    obj=resolve(obj,document)
    if any(k in obj for k in ('enum','const','pattern','maxLength','minLength','allOf','not')):return False
    if obj.get('type')=='string' or 'string' in obj.get('type',[]):return True
    return any(string_field(v,document) for v in obj.get('anyOf',[]))

def check_schema(request,responses):
    try:
        for method,name in METHODS.items():
            matches=[x for x in request['oneOf'] if method in x.get('properties',{}).get('method',{}).get('enum',[])]
            if len(matches)!=1:raise Failure('PROTOCOL_INCOMPATIBLE')
            params=resolve(matches[0]['properties']['params'],request)
            if not string_field(params['properties']['modelProvider'],request):raise Failure('PROTOCOL_INCOMPATIBLE')
            permitted=set() if name=='Start' else {'threadId'}
            if set(params.get('required',[]))-permitted:raise Failure('PROTOCOL_INCOMPATIBLE')
            if name!='Start' and not string_field(params['properties']['threadId'],request):raise Failure('PROTOCOL_INCOMPATIBLE')
            response=responses['Thread'+name+'Response']
            if not {'modelProvider','thread'}<=set(response.get('required',[])) or not string_field(response['properties']['modelProvider'],response):
                raise Failure('PROTOCOL_INCOMPATIBLE')
            thread=resolve(response['properties']['thread'],response)
            if 'id' not in thread.get('required',[]) or not string_field(thread['properties']['id'],response):raise Failure('PROTOCOL_INCOMPATIBLE')
        return True
    except (KeyError,TypeError,ValueError):raise Failure('PROTOCOL_INCOMPATIBLE') from None

def probe_protocol(c):
    # Run the CURRENT official binary, not a remembered version or wrapper.
    try:
        with tempfile.TemporaryDirectory(prefix='sg-capability-') as temp:
            home=Path(temp);codex_home=home/'codex-home';codex_home.mkdir(mode=0o700)
            env={k:v for k,v in os.environ.items() if not k.startswith(('CODEX_','OPENAI_')) and k.upper() not in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')}
            env.update(HOME=str(home),CODEX_HOME=str(codex_home),NO_PROXY='127.0.0.1,localhost')
            version=subprocess.run([str(c.BINARY),'--version'],cwd=home,env=env,capture_output=True,text=True,timeout=8)
            if version.returncode or not re.fullmatch(r'codex-cli [0-9A-Za-z.+-]+',version.stdout.strip()):raise Failure('PROTOCOL_CHECK_FAILED')
            target=home/'schema'
            result=subprocess.run([str(c.BINARY),'app-server','generate-json-schema','--out',str(target)],cwd=home,env=env,capture_output=True,timeout=25)
            if result.returncode:raise Failure('PROTOCOL_CHECK_FAILED')
            raw=(target/'ClientRequest.json').read_bytes();request=json.loads(raw);responses={}
            for name in METHODS.values():
                title='Thread'+name+'Response';paths=list(target.rglob(title+'.json'))
                if len(paths)!=1:raise Failure('PROTOCOL_INCOMPATIBLE')
                responses[title]=json.loads(paths[0].read_bytes())
            check_schema(request,responses)
            return {'version':version.stdout.strip(),'schema_sha256':sha(raw+b''.join(encode(v) for v in responses.values()))}
    except Failure:raise
    except (OSError,ValueError,subprocess.SubprocessError):raise Failure('PROTOCOL_CHECK_FAILED') from None

def txn_root(c):
    root=c.STATE/JOURNAL
    if not root.exists():root.mkdir(mode=0o700)
    c.private_dir(root);return root

def valid_journal(c,directory):
    c.private_dir(directory);obj=json.loads(c.read_file(directory/'transaction.json'))
    allowed={str(c.CONFIG),str(c.STATE/'状态.json'),str(c.STATE/CANONICAL)}
    if obj.get('schema')!=1 or obj.get('status') not in ('PENDING','COMMITTED','ROLLED_BACK'):raise Failure('BACKUP_INVALID')
    names={'transaction.json'}
    for i,item in enumerate(obj['files']):
        if item['path'] not in allowed or item['backup']!=str(i)+'.bak':raise Failure('BACKUP_INVALID')
        if item['old_hash'] is not None:
            names.add(item['backup'])
            if sha(c.read_file(directory/item['backup']))!=item['old_hash']:raise Failure('BACKUP_INVALID')
    if {p.name for p in directory.iterdir()}!=names:raise Failure('BACKUP_INVALID')
    return obj

def rollback_txn(c,directory,obj):
    for item in reversed(obj['files']):
        path=Path(item['path']);current=c.read_file(path) if path.exists() else None
        digest=sha(current) if current is not None else None
        if digest==item['old_hash']:continue
        if digest!=item['new_hash']:raise Failure('ROLLBACK_CONFLICT')
        if item['old_hash'] is None:path.unlink()  # Exact new file from this journal only.
        else:c.core().atomic_write(path,c.read_file(directory/item['backup']),item.get('old_mode',0o600))
    obj['status']='ROLLED_BACK';c.core().atomic_write(directory/'transaction.json',encode(obj))
    audit(c,rollback_status='RESTORED')

def recover(c):
    root=c.STATE/JOURNAL
    if not root.exists():return
    c.private_dir(root)
    for directory in sorted(root.iterdir()):
        obj=valid_journal(c,directory)
        if obj['status']=='PENDING':rollback_txn(c,directory,obj)

def prune(c):
    directories=sorted(txn_root(c).iterdir())
    for directory in directories[:-RETENTION]:
        obj=valid_journal(c,directory)
        if obj['status']=='PENDING':continue
        for item in obj['files']:
            if item['old_hash'] is not None:(directory/item['backup']).unlink()
        (directory/'transaction.json').unlink();directory.rmdir()

def transaction(c,payload,expected):
    payload={p:d for p,d in payload.items() if not p.exists() or c.read_file(p)!=d}
    if not payload:return
    if c.read_file(c.CONFIG)!=expected:raise Failure('CONFIG_CONCURRENT_CHANGE')
    directory=Path(tempfile.mkdtemp(prefix=dt.datetime.now().strftime('%Y%m%d-%H%M%S-'),dir=txn_root(c)))
    items=[];created=[]
    try:
        for i,(path,new) in enumerate(payload.items()):
            old=c.read_file(path) if path.exists() else None
            if old is not None:
                backup=directory/(str(i)+'.bak');created.append(backup);c.core().atomic_write(backup,old)
            items.append({'path':str(path),'backup':str(i)+'.bak','old_hash':sha(old) if old is not None else None,'new_hash':sha(new),
                          'old_mode':stat.S_IMODE(path.stat().st_mode) if old is not None else 0o600})
        obj={'schema':1,'status':'PENDING','files':items}
        c.core().atomic_write(directory/'transaction.json',encode(obj))
    except Exception:
        # No target writes have occurred. Remove only our incomplete preparation.
        if not (directory/'transaction.json').exists():
            for path in created:
                if path.is_file() and not path.is_symlink():path.unlink()
            directory.rmdir()
        raise Failure('BACKUP_PREPARATION_FAILED') from None
    try:
        config_expected=expected
        for item,(path,new) in zip(items,payload.items()):
            if c.read_file(c.CONFIG)!=config_expected:raise Failure('CONFIG_CONCURRENT_CHANGE')
            old=c.read_file(path) if path.exists() else None
            if (sha(old) if old is not None else None)!=item['old_hash']:raise Failure('STATE_CONCURRENT_CHANGE')
            c.core().atomic_write(path,new,item['old_mode'])
            if c.read_file(path)!=new:raise Failure('WRITE_VERIFY_FAILED')
            if path==c.CONFIG:config_expected=new
        if c.CONFIG in payload:
            if parse(c.read_file(c.CONFIG))!=parse(payload[c.CONFIG]):raise Failure('CONFIG_STRUCTURE')
        obj['status']='COMMITTED';c.core().atomic_write(directory/'transaction.json',encode(obj))
    except Exception:
        try:rollback_txn(c,directory,obj)
        except Exception:
            audit(c,rollback_status='CONFLICT');raise Failure('ROLLBACK_CONFLICT') from None
        raise Failure('TRANSACTION_ROLLED_BACK') from None
    try:prune(c)
    except Exception:audit(c,repair_reason='RETENTION_DEFERRED')

def health_once(c):
    settings=c.core().read_settings(c.LEGACY)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    try:credential=c.core().secret(c.LEGACY,settings)
    except Exception:raise Failure('AUTH_FAILURE') from None
    try:
        req=urllib.request.Request('http://127.0.0.1:18318/v1/models',headers={'Authorization':'Bearer '+credential})
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        with opener.open(req,timeout=3) as response:
            body=json.loads(response.read(1024*1024))
            if response.status!=200 or not isinstance(body,dict) or not isinstance(body.get('data'),list):raise Failure('HEALTH_RESPONSE_INVALID')
        return {'health_status':'HEALTHY','http_status':200}
    except urllib.error.HTTPError as ex:
        if ex.code in (401,403):raise Failure('AUTH_FAILURE',ex.code) from None
        if ex.code in (502,503,504):raise Failure('UPSTREAM_TRANSIENT',ex.code) from None
        raise Failure('HTTP_REDIRECT' if 300<=ex.code<400 else 'HTTP_FAILURE',ex.code) from None
    except urllib.error.URLError as ex:
        reason=ex.reason
        raise Failure('TUNNEL_MISSING' if isinstance(reason,OSError) and reason.errno==errno.ECONNREFUSED else 'NETWORK_TRANSIENT') from None
    except (TimeoutError,socket.timeout):raise Failure('NETWORK_TRANSIENT') from None
    except (ValueError,UnicodeError):raise Failure('HEALTH_RESPONSE_INVALID') from None

def repair_tunnel(c):
    # Existing maintainer owns SSH; upstream status must not cause tunnel teardown.
    core=c.core();settings=core.read_settings(c.LEGACY)
    original=core.api_ready
    with core.lock(c.LEGACY/'操作.lock'):
        try:
            restart_owned_job(c,settings)
            core.api_ready=lambda state,s:core.port_open(s['port'])
            core.ensure_tunnel(c.LEGACY,settings)
        except Failure:raise
        except Exception:raise Failure('TUNNEL_UNAVAILABLE') from None
        finally:core.api_ready=original

def restart_owned_job(c,settings):
    """Revive an exited registered maintainer only after exact argument matching."""
    core=c.core()
    if core.tunnel_running(c.LEGACY) or core.port_open(18318):return
    label=core.label(settings)
    job=subprocess.run(['/bin/launchctl','list',label],capture_output=True,text=True,timeout=5)
    if job.returncode:return # ensure_tunnel may submit the existing known command.
    args=re.search(r'^\s*"ProgramArguments"\s*=\s*\((.*?)\);',job.stdout,re.M|re.S)
    expected=[settings['python'],str(c.LEGACY/'切换CodexApp.py'),'_tunnel','--state-dir',str(c.LEGACY)]
    try:
        actual=[json.loads(line.strip().removesuffix(';')) for line in args[1].splitlines() if line.strip()] if args else []
    except ValueError:raise Failure('TUNNEL_JOB_CONFLICT') from None
    if actual!=expected:raise Failure('TUNNEL_JOB_CONFLICT')
    if re.search(r'"PID"\s*=\s*[1-9][0-9]*\s*;',job.stdout):raise Failure('TUNNEL_JOB_CONFLICT')
    result=subprocess.run(['/bin/launchctl','start',label],capture_output=True,timeout=5)
    if result.returncode:raise Failure('TUNNEL_UNAVAILABLE')
    deadline=time.monotonic()+5
    while not core.tunnel_running(c.LEGACY):
        if time.monotonic()>=deadline:raise Failure('TUNNEL_UNAVAILABLE')
        time.sleep(0.1)

def healthy(c,repair=True):
    repaired=False
    opened=c.core().port_open(18318)
    if opened and not c.core().tunnel_running(c.LEGACY):raise Failure('TUNNEL_PORT_CONFLICT')
    if not opened:
        if not repair:raise Failure('TUNNEL_MISSING')
        repair_tunnel(c);repaired=True
    for attempt in range(3):
        try:
            result=health_once(c);result['tunnel_action']='REPAIRED' if repaired else 'UNCHANGED';return result
        except Failure as ex:
            if ex.reason=='TUNNEL_MISSING' and repair and not repaired:
                repair_tunnel(c);repaired=True
            elif ex.reason not in ('UPSTREAM_TRANSIENT','NETWORK_TRANSIENT'):raise
            if attempt==2:raise
            time.sleep(0.5*(2**attempt))
    raise Failure('NETWORK_TRANSIENT')

def enable(c):
    """Explicit one-time adoption only from existing hash-verified trusted snapshots."""
    c.private_dir(c.STATE)
    with operation_lock(c):
        recover(c);value=c.manifest()
        if value.get('self_heal'):canonical(c,value);return
        before=c.read_file(c.CONFIG);baselines=c.verified_snapshots(value)
        provider=parse(baselines['team'])['model_providers']['sg_team']
        validate_provider(c,provider)
        files=app_files(c);cap=probe_protocol(c)
        if app_files(c)!=files:raise Failure('APP_CHANGED_DURING_CHECK')
        obj={'schema':1,'provider':provider,'helper_sha256':sha(c.read_file(c.LEGACY/'切换CodexApp.py'))}
        upgraded=copy.deepcopy(value)
        upgraded['self_heal']={'schema':1,'canonical_sha256':sha(encode(obj)),'app_files':files,'capability':cap}
        upgraded['app_files']=files
        transaction(c,{c.STATE/CANONICAL:encode(obj),c.STATE/'状态.json':encode(upgraded)},before)
        audit(c,repair_reason='ENABLE',config_action='UNCHANGED',protocol_compatibility='YES',app_version=cap['version'])

def ensure(c,mode=None,*,cached=False):
    try:
        c.private_dir(c.STATE)
        with operation_lock(c):
            recover(c);value=c.manifest();provider=canonical(c,value)
            selected=mode or value['mode']
            if selected not in c.PROVIDERS or not value['enabled']:raise Failure('MODE_INVALID')
            if not c.PROXY.is_file() or c.PROXY.is_symlink() or c.PROXY.stat().st_uid!=os.getuid() or not os.access(c.PROXY,os.X_OK):raise Failure('WRAPPER_INVALID')
            c.validate_launch_env(value)
            before=c.read_file(c.CONFIG);parse(before)
            current_files=app_files(c);upgraded=copy.deepcopy(value)
            changed=current_files!=value['self_heal']['app_files']
            if changed:
                cap=probe_protocol(c)
                if app_files(c)!=current_files:raise Failure('APP_CHANGED_DURING_CHECK')
                upgraded['self_heal']['app_files']=current_files;upgraded['self_heal']['capability']=cap
                upgraded['app_files']=current_files
            if selected=='original' and not isinstance(parse(before).get('model_providers',{}).get(c.PROVIDERS[selected]),dict):raise Failure('ORIGINAL_PROVIDER_MISSING')
            desired=merge(before,provider,c.PROVIDERS[selected])
            cache_key=(str(c.STATE),value['self_heal']['canonical_sha256'],sha(encode(current_files)),sha(before))
            recent=cached and time.monotonic()-_HEALTH_CACHE.get(cache_key,float('-inf'))<HEALTH_TTL and c.core().port_open(18318) and c.core().tunnel_running(c.LEGACY)
            if selected=='team':
                health={'health_status':'CACHED_HEALTHY','tunnel_action':'UNCHANGED'} if recent else healthy(c)
                if not recent:_HEALTH_CACHE.clear();_HEALTH_CACHE[cache_key]=time.monotonic()
            else:health={'health_status':'NOT_APPLICABLE','tunnel_action':'UNCHANGED'}
            if app_files(c)!=current_files:raise Failure('APP_CHANGED_DURING_CHECK')
            upgraded['mode']=selected
            transaction(c,{c.CONFIG:desired,c.STATE/'状态.json':encode(upgraded)},before)
            if selected=='team' and not recent:
                _HEALTH_CACHE[(str(c.STATE),value['self_heal']['canonical_sha256'],sha(encode(current_files)),sha(desired))]=time.monotonic()
            audit(c,app_version=upgraded['self_heal']['capability']['version'],app_fingerprint=current_files,
                  repair_reason='AUTO_MIGRATE' if changed else 'MANAGED_FIELDS' if before!=desired else 'CHECK',
                  config_action='REPAIRED' if desired!=before else 'UNCHANGED',protocol_compatibility='YES',
                  rollback_status='NOT_NEEDED',mode=selected,**health)
            return {'provider':c.PROVIDERS[selected],'mode':selected,'state_dir':c.STATE}
    except Failure as ex:
        fields={'repair_reason':ex.reason}
        if ex.reason.startswith(('CONFIG','CANONICAL','CREDENTIAL_HELPER')):fields['config_action']='BLOCKED'
        elif ex.reason.startswith(('PROTOCOL','APP_')):fields['protocol_compatibility']='NO' if ex.reason=='PROTOCOL_INCOMPATIBLE' else 'UNCONFIRMED'
        elif ex.reason.startswith('TUNNEL'):fields['tunnel_action']=ex.reason
        elif ex.reason in ('AUTH_FAILURE','UPSTREAM_TRANSIENT','NETWORK_TRANSIENT','HTTP_FAILURE','HTTP_REDIRECT','HEALTH_RESPONSE_INVALID'):
            fields.update(health_status=ex.reason,http_status=ex.status)
        audit(c,**fields)
        raise
    except Exception:
        audit(c,repair_reason='STATE_OR_IO_ERROR');raise Failure('STATE_OR_IO_ERROR') from None

def inspect(c):
    result={'SELF_HEAL':'BLOCKED','APP_COMPATIBLE':'UNCONFIRMED','CONFIG':'UNCONFIRMED','SG_TEAM':'UNCONFIRMED','TUNNEL':'UNCONFIRMED','UPSTREAM':'UNCONFIRMED'}
    try:
        value=c.manifest();provider=canonical(c,value)
        result['STARTUP_WRAPPER']='REGISTERED' if c.launch_env()==str(c.PROXY) else 'NOT_REGISTERED'
        result['SG_TEAM']='READY'
        result['APP_COMPATIBLE']='YES' if app_files(c)==value['self_heal']['app_files'] else 'CHECK_PENDING'
        before=c.read_file(c.CONFIG)
        result['CONFIG']='HEALTHY' if merge(before,provider,c.PROVIDERS[value['mode']])==before else 'REPAIR_PENDING'
        result['TUNNEL']='HEALTHY' if c.core().port_open(18318) else 'MISSING'
        if value['mode']=='team':healthy(c,repair=False);result['UPSTREAM']='HEALTHY'
        else:result['UPSTREAM']='NOT_CHECKED'
        if value['enabled'] and result['STARTUP_WRAPPER']=='REGISTERED' and result['APP_COMPATIBLE']=='YES' and result['CONFIG']=='HEALTHY' and (value['mode']!='team' or result['UPSTREAM']=='HEALTHY'):result['SELF_HEAL']='READY'
    except Failure as ex:
        result['REASON']=ex.reason
        if ex.reason in ('AUTH_FAILURE','UPSTREAM_TRANSIENT','NETWORK_TRANSIENT','HTTP_FAILURE','HTTP_REDIRECT','HEALTH_RESPONSE_INVALID'):result['UPSTREAM']=ex.reason
    except Exception:result['REASON']='STATE_OR_IO_ERROR'
    return result
