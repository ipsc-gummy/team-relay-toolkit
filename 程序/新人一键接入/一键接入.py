#!/usr/bin/env python3
"""新人安装外壳；Mac/Windows 复用原切换器，不改旧任务。"""
import argparse
import copy
from datetime import datetime
import http.server
import importlib.util
import json
import os
import platform
from pathlib import Path
import queue
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import tomllib

SOURCE = Path(__file__).resolve().parent
PACKAGE = SOURCE.parent
spec = importlib.util.spec_from_file_location("team_existing_core", SOURCE / "切换CodexApp.py")
core = importlib.util.module_from_spec(spec)
spec.loader.exec_module(core)
STATE = Path.home() / ".codex-sg-relay"
CONFIG = Path.home() / ".codex/config.toml"
# RFC8032 PUBLIC TEST VECTOR ONLY. Replace with the verified deployment host key.
PINNED_HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
RELEASE = '2026-09-12-r2'
_CAPABILITY = None


def fail(message):
    raise core.SafeError(message)


def run(command, **kwargs):
    if Path(command[0]).name.lower() == 'powershell.exe' and '-Command' in command:
        command = list(command)
        index = command.index('-Command') + 1
        command[index] = '$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); ' + command[index]
        kwargs.update(encoding='utf-8', errors='strict')
    return subprocess.run(command, capture_output=True, text=True, timeout=15, **kwargs)


def comparable(data):
    parsed = tomllib.loads(data.decode())
    catalog = parsed.get("marketplaces", {}).get("openai-bundled")
    if isinstance(catalog, dict) and "last_updated" in catalog:
        # Ignore only a valid timestamp value, never whole env/MCP tables.
        value = catalog["last_updated"]
        if not isinstance(value, str):
            fail("市场更新时间格式未知，请管理员检查。")
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            fail("市场更新时间格式未知，请管理员检查。")
        catalog["last_updated"] = None
    return parsed


def with_current_timestamp(desired, current):
    """Keep one managed timestamp's current spelling; check the semantic result."""
    before = tomllib.loads(current.decode()).get("marketplaces", {}).get("openai-bundled", {})
    if "last_updated" not in before:
        return desired
    section = False
    lines = []
    for line in desired.decode().splitlines(keepends=True):
        if re.match(r'^\s*\[', line):
            section = bool(re.fullmatch(r'\s*\[marketplaces\.openai-bundled\]\s*', line))
        if section and re.match(r'^\s*last_updated\s*=', line):
            line = re.sub(r'^(\s*last_updated\s*=\s*)("[^"\n]*"|\x27[^\x27\n]*\x27)',
                          lambda match: match[1] + json.dumps(before["last_updated"]), line)
        lines.append(line)
    result = "".join(lines).encode()
    if comparable(result) != comparable(desired):
        fail("配置合并校验未通过，原配置不变。")
    return result


def read_config():
    if CONFIG.is_symlink():
        fail("配置不能为符号链接，请管理员检查。")
    return core.read_regular(CONFIG) if CONFIG.exists() else b""


def confirm_manifest():
    manifest = json.loads(core.read_regular(PACKAGE / "个人参数.json"))
    user = manifest.get("user", "")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,30}", user) or user == "root":
        fail("个人包用户名不正确。")
    if manifest.get("public_fingerprint") != core.FINGERPRINTS.get(user):
        fail("个人包公钥指纹不匹配。")
    if manifest.get("host") != core.HOST or manifest.get("host_fingerprint") != core.HOST_FP:
        fail("个人包服务器参数不匹配。")
    return manifest


def host_key_preflight():
    known = Path.home() / ".ssh/known_hosts"
    if known.is_symlink():
        fail("known_hosts 为符号链接，请管理员检查。")
    if known.exists():
        found = run(["ssh-keygen", "-F", core.HOST, "-f", str(known)])
        if found.returncode == 0:
            fingerprint = run(["ssh-keygen", "-lf", "-"], input=found.stdout)
            if core.HOST_FP not in fingerprint.stdout.split():
                fail("已保存的服务器主机指纹不匹配，未覆盖。")
            return
    # Public host key provisioned by the administrator. This avoids ssh-keyscan
    # KEX differences, not host verification: verify its pinned fingerprint below.
    lines = [core.HOST + " " + PINNED_HOST_KEY]
    fingerprint = run(["ssh-keygen", "-lf", "-"], input=lines[0] + "\n")
    if core.HOST_FP not in fingerprint.stdout.split():
        fail("服务器指纹与管理员提供的值不匹配，停止。")
    previous = core.read_regular(known) if known.exists() else b""
    data = previous + (b"\n" if previous and not previous.endswith(b"\n") else b"") + (lines[0] + "\n").encode()
    if (core.read_regular(known) if known.exists() else b"") != previous:
        fail("主机记录被其他程序改动，请重试。")
    core.atomic_write(known, data)


def private_key_preflight(manifest):
    key = Path.home() / ".ssh/id_ed25519_sg_team"
    if (STATE / "settings.json").is_file():
        saved = core.read_settings(STATE)
        if saved["user"] != manifest["user"]:
            fail("已有安装属于其他成员，停止。")
        key = Path(saved["ssh_key"])
    elif not key.is_file():
        matches = []
        for pubfile in (Path.home() / ".ssh").glob("*.pub"):
            if not pubfile.is_symlink() and manifest["public_fingerprint"] in run(["ssh-keygen", "-lf", str(pubfile)]).stdout.split():
                candidate = Path(str(pubfile)[:-4])
                if candidate.is_file() and not candidate.is_symlink():
                    matches.append(candidate)
        if len(matches) != 1:
            fail("未唯一找到登记私钥，请本机 Agent 核实；不要重新生成。")
        key = matches[0]
    pub = Path(str(key) + ".pub")
    if key.is_symlink() or not key.is_file() or not pub.is_file() or pub.is_symlink():
        fail("请先按第一步生成专用密钥；不会改用其他管理私钥。")
    if sys.platform != "win32" and key.stat().st_mode & 0o077:
        fail("私钥权限过宽，请管理员检查；未读取内容。")
    actual = run(["ssh-keygen", "-lf", str(pub)])
    if manifest["public_fingerprint"] not in actual.stdout.split():
        fail("此开通包不匹配本机公钥。")
    if sys.platform == "win32":
        # A passphrase-free key needs no Windows ssh-agent service. Never remove a passphrase.
        unlocked = run(["ssh-keygen", "-y", "-P", "", "-f", str(key)])
        if unlocked.returncode == 0:
            if unlocked.stdout.split()[:2] != pub.read_text().split()[:2]:
                fail("本机私钥与登记公钥不一致。")
            return key
    # Unlock only this key in the existing local SSH agent when needed.
    loaded = run(["ssh-add", "-l"])
    if manifest["public_fingerprint"] not in loaded.stdout.split():
        if sys.platform == "win32" and loaded.returncode == 2:
            fail("专用私钥有口令，但 Windows ssh-agent 未运行。请本机 Agent 协助启动现有服务；不删除口令、不自动提权或设置开机自启。")
        if not sys.stdin.isatty():
            fail("请在本人终端运行，以便本机解锁专用私钥。")
        print("正在将专用私钥加入本机 SSH agent；若设置了口令，请在此输入。", flush=True)
        unlocked = subprocess.run(["ssh-add", str(key)])
        if unlocked.returncode:
            fail("私钥未解锁，停止；不移除口令、不上传私钥。")
    return key


def backend_version(path):
    result = run([str(path), "--version"])
    version = result.stdout.strip()
    if result.returncode or not re.fullmatch(r'codex-cli [0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?', version):
        fail("无法识别 App 内置程序，未修改配置。")
    return version


def probe_app_backend(app_cli, timeout=40):
    """Exercise the bundled app-server against a loopback mock with disposable credentials.

    This is a backend capability test, NOT an actual desktop UI or team relay test.
    Child-only CODEX_HOME isolates config, auth and history; no real keys are read.
    """
    marker = 'SYSU_LOCAL_COMPAT_OK'
    dummy = 'local-probe-' + secrets.token_hex(24)
    received = threading.Event()
    protocol = {"authorization_ok": False, "model_ok": False}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            body = json.dumps({'object': 'list', 'data': [{'id': 'gpt-6-astra', 'object': 'model'}]}).encode()
            self.send_response(200 if self.path == '/v1/models' else 404)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers(); self.wfile.write(body)

        def do_POST(self):
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 1024 * 1024:
                    raise ValueError('invalid request length')
                request = json.loads(self.rfile.read(length))
                valid = self.path == '/v1/responses' and self.headers.get('Authorization') == 'Bearer ' + dummy
                protocol['authorization_ok'] = valid
                protocol['model_ok'] = request.get('model') == 'gpt-6-astra'
                if not valid or not protocol['model_ok']:
                    self.send_error(401); return
                received.set()
                part = {'type': 'output_text', 'text': marker, 'annotations': []}
                item = {'id': 'msg_probe', 'type': 'message', 'role': 'assistant', 'status': 'completed', 'content': [part]}
                response = {'id': 'resp_probe', 'object': 'response', 'created_at': 0, 'status': 'completed',
                            'model': 'gpt-6-astra', 'output': [item],
                            'usage': {'input_tokens': 1, 'output_tokens': 1, 'total_tokens': 2}}
                events = [
                    {'type': 'response.created', 'response': dict(response, status='in_progress', output=[])},
                    {'type': 'response.output_item.added', 'output_index': 0, 'item': dict(item, status='in_progress', content=[])},
                    {'type': 'response.content_part.added', 'item_id': 'msg_probe', 'output_index': 0, 'content_index': 0, 'part': dict(part, text='')},
                    {'type': 'response.output_text.delta', 'item_id': 'msg_probe', 'output_index': 0, 'content_index': 0, 'delta': marker},
                    {'type': 'response.output_text.done', 'item_id': 'msg_probe', 'output_index': 0, 'content_index': 0, 'text': marker},
                    {'type': 'response.content_part.done', 'item_id': 'msg_probe', 'output_index': 0, 'content_index': 0, 'part': part},
                    {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
                    {'type': 'response.completed', 'response': response},
                ]
                body = ''.join('event: ' + e['type'] + '\ndata: ' + json.dumps(e) + '\n\n' for e in events).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
            except (OSError, ValueError, TypeError):
                return

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    proc = None
    phase = 'initialize'
    try:
        with tempfile.TemporaryDirectory(prefix='sysu-compat-') as temp:
            probe_dir = Path(temp)
            probe_home = probe_dir / 'isolated-codex'
            probe_home.mkdir()
            quote = lambda v: json.dumps(v, ensure_ascii=False)
            config = ('model_provider = "sysu_probe"\nmodel = "gpt-6-astra"\n'
                      'check_for_update_on_startup = false\ncli_auth_credentials_store = "file"\n'
                      '[analytics]\nenabled = false\n[feedback]\nenabled = false\n'
                      '[model_providers.sysu_probe]\nname = "Local capability probe"\nwire_api = "responses"\n'
                      f'base_url = "http://127.0.0.1:{server.server_port}/v1"\n'
                      'request_max_retries = 0\nstream_max_retries = 0\n'
                      '[model_providers.sysu_probe.auth]\n'
                      'command = ' + quote(str(Path(sys.executable).absolute())) + '\n'
                      'args = ' + quote(['-c', 'print(' + repr(dummy) + ')']) + '\n'
                      'timeout_ms = 5000\nrefresh_interval_ms = 0\n')
            core.atomic_write(probe_home / 'config.toml', config.encode())
            probe_env = {k: v for k, v in os.environ.items()
                         if not k.upper().startswith(('OPENAI_', 'CODEX_')) and k.upper() not in
                         ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')}
            probe_env.update(CODEX_HOME=str(probe_home), NO_PROXY='127.0.0.1,localhost')
            inbox = queue.Queue()
            proc = subprocess.Popen([str(app_cli), 'app-server'], cwd=probe_dir, env=probe_env,
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, encoding='utf-8', errors='replace', bufsize=1)

            def reader():
                for line in proc.stdout:
                    try:
                        inbox.put(json.loads(line))
                    except ValueError:
                        continue
                inbox.put(None)

            reader_thread = threading.Thread(target=reader, daemon=True)
            reader_thread.start()
            deadline = time.monotonic() + timeout

            def send(message):
                proc.stdin.write(json.dumps(message) + '\n'); proc.stdin.flush()

            def wait_for(predicate):
                while time.monotonic() < deadline:
                    try:
                        msg = inbox.get(timeout=min(0.5, max(0.01, deadline-time.monotonic())))
                    except queue.Empty:
                        continue
                    if msg is None:
                        fail('App 后台在本地兼容检查中提前退出；阶段：' + phase)
                    if 'method' in msg and 'id' in msg:
                        # Never grant tools or other permissions in this mock-only test.
                        send({'id': msg['id'], 'error': {'code': -32601, 'message': 'No tools permitted in capability probe'}})
                        continue
                    if predicate(msg):
                        if 'error' in msg:
                            fail('App 不支持所需的本地测试协议；阶段：' + phase)
                        return msg
                fail('App 本地兼容检查超时；阶段：' + phase + '。未连接真实中转，未修改全局配置。')

            try:
                send({'id': 1, 'method': 'initialize', 'params': {'clientInfo': {'name': 'sysu_compat_probe', 'version': '1.0'}}})
                wait_for(lambda m: m.get('id') == 1)
                send({'method': 'initialized', 'params': {}})
                phase = 'thread/start'
                send({'id': 2, 'method': 'thread/start', 'params': {'model': 'gpt-6-astra', 'modelProvider': 'sysu_probe',
                      'cwd': str(probe_dir), 'ephemeral': True, 'approvalPolicy': 'never', 'sandbox': 'read-only'}})
                started = wait_for(lambda m: m.get('id') == 2)['result']
                if started.get('modelProvider') != 'sysu_probe':
                    fail('本地测试未选中指定提供商，停止；未发送任何模型请求。')
                phase = 'turn/start'
                send({'id': 3, 'method': 'turn/start', 'params': {'threadId': started['thread']['id'],
                      'input': [{'type': 'text', 'text': 'Local protocol check only. Reply OK.'}]}})
                wait_for(lambda m: m.get('id') == 3)
                phase = 'turn/completed'
                completed = wait_for(lambda m: m.get('method') == 'turn/completed')
                turn = completed.get('params', {}).get('turn', {})
                if not received.is_set() or not all(protocol.values()) or turn.get('status') != 'completed':
                    fail('App 本地认证或 Responses 通道验证未通过；未修改全局配置。')
                return {'command_auth': True, 'local_responses': True, 'app_server_turn': True,
                        'desktop_ui_test': 'NOT_RUN', 'real_relay_test': 'NOT_RUN'}
            finally:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill(); proc.wait(timeout=5)
                proc.stdin.close()
                reader_thread.join(timeout=2)
                proc.stdout.close()
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate(); proc.wait(timeout=5)
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def windows_backend_hash(path):
    # Reject junctions/symlinks in every component, then hash without loading the binary.
    for part in (path, *path.parents):
        value=part.lstat()
        if part.is_symlink() or getattr(value,'st_file_attributes',0)&0x400:
            raise core.SafeError('APP_BACKEND_REPARSE')
    before=path.stat()
    import hashlib
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    after=path.stat()
    if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
        fail('APP_CHANGED_DURING_CHECK')
    return digest.hexdigest()


def windows_app_cli(manifest):
    # Store binaries can be readable but not executable by the desktop user.
    # Only admit runtime copies whose bytes match a currently installed package.
    ps = shutil.which("powershell.exe")
    if not ps:
        fail("缺少 Windows PowerShell，请本机 Agent 检查。")
    script = r'''$ErrorActionPreference='Stop'; $paths=@(); $runtime=@(); $running=@();
Get-AppxPackage | Where-Object { $_.Name -match '(^|\.)Codex($|\.)|^OpenAI\.ChatGPT($|\.)' } | ForEach-Object {
    $paths += @(Get-ChildItem -LiteralPath $_.InstallLocation -Filter codex.exe -File -Recurse -Depth 5 -ErrorAction SilentlyContinue | ForEach-Object {$_.FullName})
};
if($env:LOCALAPPDATA){
    $root=Join-Path $env:LOCALAPPDATA 'OpenAI\Codex\bin';
    if(Test-Path -LiteralPath $root){
        Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop | ForEach-Object {
            $p=Join-Path $_.FullName 'codex.exe'; if(Test-Path -LiteralPath $p -PathType Leaf){$runtime+=$p}
        }
    }
};
$session=(Get-Process -Id $PID).SessionId;
Get-Process -Name codex -ErrorAction SilentlyContinue | Where-Object {$_.SessionId -eq $session} | ForEach-Object {
    try{if($_.Path){$running+=$_.Path}}catch{}
};
@{bundled=@($paths|Sort-Object -Unique);runtime=@($runtime|Sort-Object -Unique);running=@($running|Sort-Object -Unique)}|ConvertTo-Json -Compress'''
    result = run([ps, "-NoProfile", "-NonInteractive", "-Command", script])
    if result.returncode:
        fail("无法定位 Windows 桌面 App；请本机 Agent 检查安装位置，未修改全局配置。")
    inventory = json.loads(result.stdout.lstrip('\ufeff').strip() or '{}')
    if (not isinstance(inventory,dict) or any(not isinstance(inventory.get(k),list)
        or any(not isinstance(p,str) for p in inventory[k]) for k in ('bundled','runtime','running'))):
        fail("Windows App 路径检查异常。")
    bundled=[]; anchors=set(); runtimes=[]
    for value in inventory['bundled']:
        path = Path(value)
        if not path.is_absolute() or path.name.lower()!='codex.exe' or "resources" not in value.replace("\\", "/").lower().split("/"):
            continue
        try:
            checksum=windows_backend_hash(path)
        except (OSError,core.SafeError):continue
        bundled.append((path,checksum));anchors.add(checksum)
    root=Path(os.environ['LOCALAPPDATA'])/'OpenAI/Codex/bin' if os.environ.get('LOCALAPPDATA') else None
    for value in inventory['runtime']:
        path=Path(value)
        try:
            if root is None or not path.is_absolute() or len(path.relative_to(root).parts)!=2 or path.name.lower()!='codex.exe':continue
            checksum=windows_backend_hash(path)
            if checksum in anchors:runtimes.append((path,checksum))
        except (ValueError,OSError,core.SafeError):continue
    running={os.path.normcase(p) for p in inventory['running']}
    denied=False
    for candidates in (runtimes,bundled):
        active=[p for p in candidates if os.path.normcase(str(p[0])) in running]
        choices=active or candidates
        if len({h for p,h in choices})>1:
            fail('APP_BACKEND_AMBIGUOUS：发现多个不同版本，无法确认当前 App 后台；请保持 App 打开后核实，不按目录日期猜测。')
        for path,checksum in sorted(set(choices),key=lambda item:str(item[0])):
            try:
                backend_version(path)
            except (OSError,subprocess.SubprocessError):
                denied=True;continue
            except core.SafeError:continue
            if windows_backend_hash(path)!=checksum:fail('APP_CHANGED_DURING_CHECK')
            print('APP_BACKEND_SOURCE='+('VERIFIED_RUNTIME_COPY' if candidates is runtimes else 'APPX_RESOURCES'))
            return path
    if denied:
        fail('APP_BACKEND_EXECUTION_DENIED：后台路径不能以普通用户执行，未找到可执行的同哈希运行副本；不改 WindowsApps ACL、不提权。')
    if inventory['runtime']:
        fail('APP_RUNTIME_UNVERIFIED：运行副本未通过包内 SHA-256/路径核验；不执行未知副本，不重建密钥。')
    fail('APP_BACKEND_NOT_FOUND：未定位可核验的 App 后台，请本机 Agent 检查安装及运行副本；未修改配置。')


def windows_acl(path, create=False):
    """Protect only our new state, then check allow rules by SID (not localized labels)."""
    if create:
        account = "*" + windows_identity()
        if not account:
            fail("无法识别 Windows 本人账号。")
        result = run(["icacls", str(path), "/inheritance:r", "/grant:r",
                      account + ":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"])
        if result.returncode:
            fail("凭据目录 ACL 设置失败，未写入密钥。")
    literal = "'" + str(path).replace("'", "''") + "'"
    script = ("$ErrorActionPreference='Stop'; $a=Get-Acl -LiteralPath " + literal + "; "
              "$me=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; "
              "$trusted=@($me,'S-1-5-18','S-1-5-32-544'); $sandbox=@(); "
              "$g=Get-LocalGroup -Name CodexSandboxUsers -ErrorAction SilentlyContinue; "
              "if($g){$sandbox+= $g.SID.Value; $sandbox+= @(Get-LocalGroupMember -Group $g -ErrorAction Stop | ForEach-Object {$_.SID.Value})}; "
              "$bad=@($a.Access | Where-Object { $s=$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value; "
              "$_.AccessControlType -eq 'Allow' -and $s -notin $trusted -and "
              "($s -notin $sandbox -or (([int]$_.FileSystemRights -band 852310) -ne 0)) }); "
              "if (-not $a.AreAccessRulesProtected -or $bad.Count -gt 0) {exit 3}")
    if run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]).returncode:
        fail("凭据目录 ACL 需审阅；不要逐项删 ACE。请在本人普通 PowerShell 执行 repair；若仍拒绝，回传脱敏 ACL 与 SID，不放宽或循环重写权限。")


def windows_identity():
    """Verify the executing identity against the interactive desktop, never a fixed SID."""
    script = r'''$ErrorActionPreference='Stop'; $id=[Security.Principal.WindowsIdentity]::GetCurrent();
$desktop=(Get-CimInstance Win32_ComputerSystem).UserName;
if (-not $desktop) {exit 3};
$sid=([Security.Principal.NTAccount]::new($desktop)).Translate([Security.Principal.SecurityIdentifier]).Value;
$admin=([Security.Principal.WindowsPrincipal]::new($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);
@{actual=$id.User.Value;desktop=$sid;elevated=$admin}|ConvertTo-Json -Compress'''
    result = run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script])
    if result.returncode:
        fail("无法核实交互桌面身份；请从开始菜单打开本人普通 PowerShell，不在沙箱或远程服务身份下修复。")
    value = json.loads(result.stdout.lstrip('\ufeff'))
    if value.get("elevated") or value.get("actual") != value.get("desktop") or not re.fullmatch(r'S-1-\d+(?:-\d+)+', value.get("actual", "")):
        fail("执行身份不是本人普通桌面身份。请在普通 PowerShell 运行同一命令；不要修改 ACL 迎合沙箱身份。")
    return value["actual"]


def runtime_check():
    if sys.version_info < (3, 11):
        fail("需要 Python 3.11+。")
    if sys.platform in ("msys", "cygwin") or (sys.platform == "win32" and (os.name != "nt" or "MSC" not in platform.python_compiler())):
        fail("请使用明确选定的原生 Windows CPython，不使用 MSYS2/Cygwin Python。")
    if sys.platform == "win32":
        windows_identity()
    if os.environ.get("CODEX_HOME") and Path(os.environ["CODEX_HOME"]).expanduser() != Path.home() / ".codex":
        fail("存在自定义 CODEX_HOME，先由本机 Agent 核实，未改配置。")
    if os.environ.get("CODEX_CLI_PATH"):
        fail("检测到已有 App 包装入口，需单独审阅；不能用新人包覆盖管理员路由。")


def preflight(manifest):
    global _CAPABILITY
    if sys.platform not in ("darwin", "win32"):
        fail("当前一键版仅适配 macOS 和原生 Windows，不在 WSL 中安装。")
    package_platform = manifest.get("platform", "macos")
    if package_platform != ("windows" if sys.platform == "win32" else "macos"):
        fail("此包与电脑系统不匹配，请使用对应系统的个人包。")
    if os.environ.get("CODEX_HOME") and Path(os.environ["CODEX_HOME"]).expanduser() != Path.home() / ".codex":
        fail("使用了非默认 Codex 目录，请管理员适配后安装。")
    for name in ("ssh", "ssh-keygen", "ssh-add"):
        if not shutil.which(name):
            fail("缺少 OpenSSH，请把提示发管理员。")
    app_cli = windows_app_cli(manifest) if sys.platform == "win32" else next((p for p in (Path('/Applications/ChatGPT.app/Contents/Resources/codex'), Path('/Applications/Codex.app/Contents/Resources/codex')) if p.is_file()), None)
    if not app_cli:
        fail("未找到支持的 Codex App 安装位置，请管理员检查。")
    version = backend_version(app_cli)
    print("App 内置后台：" + version + "；正在用本地模拟接口检查兼容性，不消耗 Pro 额度。", flush=True)
    result = probe_app_backend(app_cli)
    _CAPABILITY = ({'path':str(app_cli),'version':version,'size':app_cli.stat().st_size,
                   'mtime_ns':app_cli.stat().st_mtime_ns,'result':result} if app_cli.is_file() else None)
    print("本地后台兼容检查通过；仍需重启 App 后验证真实团队对话。", flush=True)
    return private_key_preflight(manifest)


def initialize(manifest, key):
    original = read_config()
    parsed = tomllib.loads(original.decode())
    if parsed.get("model_provider", "openai") != "openai" or "sg_team" in parsed.get("model_providers", {}):
        fail("已有其他中转配置，不自动覆盖；请管理员做增量迁移。")
    token = core.read_regular(PACKAGE / "中转访问密钥.txt").decode().strip()
    if not re.fullmatch("cpa-" + manifest["user"] + r"-[0-9a-f]{64}", token):
        fail("个人 Key 格式或收件人不匹配。")
    settings = {"schema": 1, "user": manifest["user"], "host": core.HOST, "target": core.TARGET,
                "port": 18318, "ssh_key": str(key), "ssh": str(Path(shutil.which("ssh")).absolute()),
                "model": "gpt-6-astra", "config": str(CONFIG), "python": str(Path(sys.executable).absolute()),
                "simple_installer": 1, "config_existed": CONFIG.exists()}
    team = core.make_team_config(original, STATE, settings)
    # Check locks/port before allocating private state. No other listener is adopted.
    if core.port_open(18318):
        fail("18318 已被占用，未抢占；请管理员检查旧隧道。")
    STATE.mkdir(mode=0o700)  # Never overwrite an existing state directory.
    if sys.platform == "win32":
        windows_acl(STATE, create=True)
    for name, data in (("personal.toml", original), ("team.toml", team),
                       ("中转访问密钥.txt", (token + "\n").encode()),
                       ("切换CodexApp.py", core.read_regular(SOURCE / "切换CodexApp.py")),
                       ("一键接入.py", core.read_regular(Path(__file__)))):
        core.atomic_write(STATE / name, data)
    settings.update(personal_hash=core.digest(original), team_hash=core.digest(team))
    core.atomic_write(STATE / "settings.json", json.dumps(settings, ensure_ascii=False).encode())


def apply_mode(action, manifest):
    settings = core.read_settings(STATE)
    if settings.get("simple_installer") != 1 or settings["user"] != manifest["user"] or settings["config"] != str(CONFIG):
        fail("已有其他版本或账号的安装，不会接管或覆盖。")
    if core.read_regular(STATE / "切换CodexApp.py") != core.read_regular(SOURCE / "切换CodexApp.py"):
        fail("程序版本与已安装状态不同，请管理员增量更新。")
    with core.lock(STATE / "操作.lock"):
        original, team = core.snapshots(STATE, settings)
        before = read_config()
        current = comparable(before)
        is_team = current == comparable(team)
        is_original = current == comparable(original)
        if action == "status":
            print("文件配置：" + ("团队中转（示例团队）" if is_team else "安装前配置" if is_original else "另有改动，未确认"))
            print("后台：" + ("运行中" if core.tunnel_running(STATE) else "未运行"))
            print("这不证明 App 实际请求线路；完整重启后须在新对话验证。")
            return
        if not (is_team or is_original):
            fail("配置另有修改，未覆盖；请管理员合并后再试。")
        if action == "team":
            core.ensure_tunnel(STATE, settings)
        target = with_current_timestamp(team if action == "team" else original, before)
        if comparable(before) != comparable(target):
            backups = STATE / "备份"
            backups.mkdir(mode=0o700, exist_ok=True)
            core.atomic_write(backups / (datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".toml"), before)
            if read_config() != before:
                fail("连接期间配置发生变化，未覆盖。")
            CONFIG.parent.mkdir(mode=0o700, exist_ok=True)
            core.atomic_write(CONFIG, target)
        print("全局配置已选择：团队中转（示例团队）" if action == "team" else "已恢复安装前配置；原登录未修改。")
        print("请保存任务并完整退出 Codex App（包括托盘），再打开并新建对话。旧对话不保证自动换线。" if sys.platform == "win32" else "请 Cmd+Q 完整退出 Codex，再打开并新建对话。旧对话不保证自动换线。")


MODE_KEYS = ("model_provider", "forced_login_method", "openai_base_url", "profile")


def toml_lines(data):
    """Statement boundaries: ignore fake table headers inside multiline strings."""
    quote=None
    for line in data.decode().splitlines(keepends=True):
        yield line, quote is None
        i=0
        while i<len(line):
            if quote:
                if quote.startswith('"') and line[i]=='\\':i+=2;continue
                if line.startswith(quote,i):i+=len(quote);quote=None;continue
                i+=1;continue
            if line[i]=='#':break
            if line[i] in ('"',"'"):
                quote=line[i]*3 if line.startswith(line[i]*3,i) else line[i];i+=len(quote);continue
            i+=1


def selectors(data, values):
    """Change only explicit root routing selectors, preserving all other text."""
    before = tomllib.loads(data.decode())
    lines = []; root = True
    for line,statement in toml_lines(data):
        if statement and re.match(r'^\s*\[', line):
            root = False
        if statement and root and any(re.match(r'^\s*(?:' + re.escape(key) + r'|"'+key+r'"|\x27'+key+r'\x27)\s*=', line) for key in MODE_KEYS):
            continue
        lines.append(line)
    prefix = ''.join(key + ' = ' + json.dumps(value, ensure_ascii=False) + '\n' for key, value in values.items())
    result = (prefix + ''.join(lines)).encode()
    expected = copy.deepcopy(before)
    for key in MODE_KEYS:
        expected.pop(key, None)
    expected.update(values)
    if tomllib.loads(result.decode()) != expected:
        fail("路由字段写法不适合安全更新，未覆盖。")
    return result


def route_guard(data):
    value = tomllib.loads(data.decode())
    # Preferences such as model/effort are not routing authority. Preserve them.
    return {key: value[key] for key in (*MODE_KEYS, "model_providers", "env", "mcp_servers") if key in value}


def team_definition(settings):
    return tomllib.loads(core.make_team_config(b'', STATE, settings).decode())["model_providers"]["sg_team"]


def install_definition(data, definition):
    """Replace only sg_team sections; parsed diff proves no unrelated table loss."""
    parsed = tomllib.loads(data.decode())
    if parsed.get('model_providers',{}).get('sg_team') == definition:
        return data
    kept = []; dropping = False
    for line,statement in toml_lines(data):
        if statement and re.match(r'^\s*\[', line):
            dropping = bool(re.match(r'^\s*\[\s*(?:model_providers|"model_providers"|\x27model_providers\x27)\s*\.\s*(?:sg_team|"sg_team"|\x27sg_team\x27)\s*(?:\.|\])', line))
        if not dropping or (statement and (not line.strip() or line.lstrip().startswith('#'))):
            kept.append(line)
    q = lambda v: json.dumps(v, ensure_ascii=False)
    suffix = '\n\n[model_providers.sg_team]\n' + ''.join(k+' = '+q(definition[k])+'\n' for k in ('name','base_url','wire_api'))
    suffix += '\n[model_providers.sg_team.auth]\n' + ''.join(k+' = '+q(v)+'\n' for k,v in definition['auth'].items())
    result = (''.join(kept)+suffix).encode()
    expected = copy.deepcopy(parsed); expected.setdefault('model_providers',{})['sg_team'] = definition
    if tomllib.loads(result.decode()) != expected:
        fail("团队配置合并超出受管表，未覆盖。")
    return result


def verify_account_channel(data):
    parsed = tomllib.loads(data.decode())
    if 'openai' in parsed.get('model_providers', {}):
        fail("已有自定义 openai 定义，不能冒充官方账户；请本机 Agent 审阅。")
    if parsed.get('env', {}).get('OPENAI_BASE_URL') or os.environ.get('OPENAI_BASE_URL'):
        fail("OPENAI_BASE_URL 另有覆盖，需先核实才能恢复官方账户。")


def transaction_mark(backup,status):
    core.atomic_write(backup/'事务.json',json.dumps({'schema':1,'status':status}).encode())


def recover_transactions():
    directory=STATE/'备份'
    if not directory.exists():return
    if directory.is_symlink():fail('BACKUP_PATH_INVALID')
    for backup in sorted(directory.iterdir()):
        marker=backup/'事务.json'
        if not marker.exists():continue # Historical backups are never inferred/replayed.
        if backup.is_symlink():fail('BACKUP_PATH_INVALID')
        state=json.loads(core.read_regular(marker))
        if state.get('schema')!=1 or state.get('status') not in ('PENDING','COMMITTED','ROLLED_BACK'):fail('BACKUP_INVALID')
        if state['status']!='PENDING':continue
        entries=json.loads(core.read_regular(backup/'清单.json'))
        restore=[]
        for item in entries:
            path=Path(item['path'])
            if path!=CONFIG and (path.parent!=STATE or path.suffix not in ('.py','.json','.toml','.txt')):fail('BACKUP_TARGET_INVALID')
            current=core.read_regular(path) if path.exists() else None
            digest=core.digest(current) if current is not None else None
            if digest==item['old_hash']:continue
            if digest!=item['new_hash']:fail('ROLLBACK_CONFLICT：保留并发改动，需人工审阅。')
            data=None
            if item['backup']:
                if Path(item['backup']).name!=item['backup']:fail('BACKUP_INVALID')
                data=core.read_regular(backup/item['backup'])
                if core.digest(data)!=item['old_hash']:fail('BACKUP_INVALID')
            restore.append((path,data))
        for path,data in reversed(restore):
            if data is None:path.unlink() # Exact newly-created file verified above.
            else:core.atomic_write(path,data)
        transaction_mark(backup,'ROLLED_BACK')


def prune_transactions():
    completed=[]
    for backup in sorted((STATE/'备份').iterdir()):
        if backup.is_symlink() or not (backup/'事务.json').is_file():continue
        value=json.loads(core.read_regular(backup/'事务.json'))
        if value.get('status') not in ('COMMITTED','ROLLED_BACK'):continue
        entries=json.loads(core.read_regular(backup/'清单.json'))
        names={'清单.json','事务.json'}|{x['backup'] for x in entries if x['backup']}
        if any(Path(n).name!=n for n in names) or {p.name for p in backup.iterdir()}!=names:continue
        completed.append((backup,names))
    for backup,names in completed[:-10]:
        for name in names:(backup/name).unlink()
        backup.rmdir()


def snapshot_transaction(payload, expected_config, verify=None):
    """Bounded, recoverable writes. On failure restore exact previous files."""
    if read_config() != expected_config:
        fail("配置被其他程序改动，停止。")
    payload={path:data for path,data in payload.items() if not path.exists() or core.read_regular(path)!=data}
    if not payload:
        if verify:verify()
        if read_config()!=expected_config:fail('CONFIG_CONCURRENT_CHANGE')
        return None
    before = {path: core.read_regular(path) if path.exists() else None for path in payload}
    if (STATE/'备份').is_symlink():
        fail("备份目录异常，停止。")
    backup = STATE / '备份' / datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    backup.mkdir(parents=True, mode=0o700)
    index = []
    for n, (path, data) in enumerate(before.items()):
        name = f'{n}.bak'
        if data is not None:
            core.atomic_write(backup/name, data)
        index.append({'path':str(path),'backup':name if data is not None else None,
                      'old_hash':core.digest(data) if data is not None else None,'new_hash':core.digest(payload[path])})
    core.atomic_write(backup/'清单.json', json.dumps(index,ensure_ascii=False).encode())
    transaction_mark(backup,'PENDING')
    written = []
    try:
        config_expected=expected_config
        for path, data in payload.items():
            if read_config()!=config_expected:fail('CONFIG_CONCURRENT_CHANGE')
            if path == CONFIG and not path.parent.exists():
                path.parent.mkdir(mode=0o700)
            current = core.read_regular(path) if path.exists() else None
            if current != before[path]:
                fail("文件发生并发变化，停止并回退本次写入。")
            core.atomic_write(path, data); written.append(path)
            if core.read_regular(path)!=data:fail('WRITE_VERIFY_FAILED')
            if path==CONFIG:
                tomllib.loads(data.decode());config_expected=data
        if verify is not None:
            verify()
        if read_config()!=config_expected:fail('CONFIG_CONCURRENT_CHANGE')
        transaction_mark(backup,'COMMITTED')
    except Exception:
        for path in reversed(written):
            # Never overwrite another actor's changes during rollback.
            if core.read_regular(path) != payload[path]:
                fail("回退遇到并发改动；保留备份，请人工恢复。")
            if before[path] is None:
                path.unlink()  # Only a file created by this transaction.
            else:
                core.atomic_write(path, before[path])
        transaction_mark(backup,'ROLLED_BACK')
        raise
    try:prune_transactions()
    except (OSError,ValueError,core.SafeError):print('BACKUP_RETENTION=DEFERRED（配置已提交，旧备份保留）')
    return backup


def empty_state():
    """Allow only an empty state or our fully rolled-back first-write journal."""
    allowed = {str(STATE/name) for name in ('personal.toml','team.toml','中转访问密钥.txt',
               '切换CodexApp.py','settings.json','modes.json')}
    for path in STATE.iterdir():
        if path.is_symlink():
            return False
        if path.name == '操作.lock' and path.is_file():
            continue
        if path.name != '备份' or not path.is_dir():
            return False
        for backup in path.iterdir():
            if backup.is_symlink() or not backup.is_dir():
                return False
            if {p.name for p in backup.iterdir()} not in ({'清单.json'},{'清单.json','事务.json'}):
                return False
            if (backup/'事务.json').exists() and json.loads(core.read_regular(backup/'事务.json')).get('status')!='ROLLED_BACK':return False
            entries = json.loads(core.read_regular(backup/'清单.json'))
            if (not isinstance(entries,list) or len(entries)!=len(allowed)
                or {e.get('path') for e in entries} != allowed
                or any(e.get('backup') is not None for e in entries)):
                return False
    return True


def repair(manifest, key, other_provider=None):
    """Import complete legacy/finisher state or safely finish a truly empty state."""
    current = read_config()
    parsed = tomllib.loads(current.decode())
    if parsed.get('profile'):
        fail("当前使用 profile 覆盖，需本机 Agent 先核实实际配置，未修改。")
    verify_account_channel(current)
    created = not STATE.exists()
    if created:
        STATE.mkdir(mode=0o700)
        if sys.platform == 'win32':
            windows_acl(STATE, create=True)
    if sys.platform == 'win32':
        windows_acl(STATE)
    elif STATE.stat().st_mode & 0o077:
        fail("状态目录权限过宽，停止。")
    if (STATE/'settings.json').exists():
        settings = core.read_settings(STATE)
        if settings['user'] != manifest['user'] or settings.get('config') != str(CONFIG):
            fail("现有状态账号或路径不匹配，未接管。")
        if (STATE/'modes.json').exists() and read_modes(manifest)['schema']==3:
            # Original snapshot is archival; the independent canonical is authority.
            baseline='original.toml' if settings.get('baseline_kind')=='original' else 'personal.toml'
            original=core.read_regular(STATE/baseline)
            if core.digest(original)!=settings['personal_hash']:fail('ORIGINAL_BACKUP_CHANGED')
            oldteam=None
        else:original, oldteam = core.snapshots(STATE,settings)
        if (STATE/'modes.json').exists():
            modes = read_modes(manifest)
        if core.secret(STATE,settings) != core.read_regular(PACKAGE/'中转访问密钥.txt').decode().strip():
            fail("已安装 Key 与本人包不一致，未替换。")
    else:
        # Ignore only our lock files. Unknown half-installs need review, not deletion.
        if not empty_state():
            fail("非空半安装状态缺少 settings.json；保留全部文件，请 Agent 核对备份后修复，禁止重置。")
        if parsed.get('model_provider','openai') == 'sg_team' or 'sg_team' in parsed.get('model_providers',{}):
            fail("空状态但已有团队配置，个人基线无法确认，停止。")
        original = current
        settings = {'schema':1,'user':manifest['user'],'host':core.HOST,'target':core.TARGET,
                    'port':18318,'config':str(CONFIG),'simple_installer':1,'config_existed':CONFIG.exists()}
    settings = dict(settings, ssh_key=str(key), ssh=str(Path(shutil.which('ssh')).absolute()),
                    python=str(Path(sys.executable).absolute()), model=parsed.get('model','gpt-6-astra'))
    original_parsed = tomllib.loads(original.decode())
    prior = original_parsed.get('model_provider','openai')
    other = other_provider or (prior if prior not in ('openai','sg_team') else None)
    if (STATE/'modes.json').exists() and other is None:
        other = read_modes(manifest).get('other_provider')
    if other is not None and (other in ('openai','sg_team') or other not in parsed.get('model_providers',{})):
        fail("第二中转必须是本人电脑已有的其他提供商；未连接或创建其他服务器。")
    base = install_definition(current, team_definition(settings))
    definitions = {'team':{'model_provider':'sg_team'},
                   'personal':{'model_provider':'openai','forced_login_method':'chatgpt'}}
    if other:
        origin = original_parsed if prior == other else parsed if parsed.get('model_provider') == other else {}
        definitions['other'] = {key:origin[key] for key in MODE_KEYS if key in origin}
        definitions['other']['model_provider'] = other
    mode_data = {name:selectors(base,select) for name,select in definitions.items()}
    settings['personal_hash'] = core.digest(original)
    settings['team_hash'] = core.digest(mode_data['team'])
    token = core.read_regular(PACKAGE/'中转访问密钥.txt').decode().strip()
    if not re.fullmatch('cpa-'+manifest['user']+r'-[0-9a-f]{64}', token):
        fail("个人 Key 收件人不匹配。")
    canonical=team_definition(settings)
    metadata = {'schema':3,'user':manifest['user'],'other_provider':other,
                'original_mode':'personal' if prior=='openai' else 'other',
                'selectors':definitions,'guards':{name:route_guard(data) for name,data in mode_data.items()},
                'prepared_guard':route_guard(current), 'core_hash':core.digest(core.read_regular(SOURCE/'切换CodexApp.py')),
                'canonical':canonical,'canonical_hash':core.digest(json.dumps(canonical,sort_keys=True).encode()),
                'release':RELEASE,'capability':_CAPABILITY}
    baseline_name = 'original.toml' if settings.get('baseline_kind')=='original' else 'personal.toml'
    payload = {STATE/baseline_name:original, STATE/'team.toml':mode_data['team'],
               STATE/'中转访问密钥.txt':(token+'\n').encode(), STATE/'切换CodexApp.py':core.read_regular(SOURCE/'切换CodexApp.py'),
               STATE/'settings.json':json.dumps(settings,ensure_ascii=False).encode(),
               STATE/'modes.json':json.dumps(metadata,ensure_ascii=False).encode()}
    def check_helper():
        result = subprocess.run([settings['python'], str(STATE/'切换CodexApp.py'), '_credential', '--state-dir', str(STATE)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        if result.returncode or result.stdout.strip() != token.encode():
            fail("认证助手未返回本人凭据，已回退本次状态写入；未输出凭据。")
    with core.lock(STATE/'操作.lock'):
        snapshot_transaction(payload,current,check_helper)
    print("修复准备完成：原配置尚未切换，私钥/登录/历史未改。可执行 team、personal" + ("、other。" if other else "；第二中转未登记。"))


def read_modes(manifest):
    modes = json.loads(core.read_regular(STATE/'modes.json'))
    definitions = modes.get('selectors', {})
    other = modes.get('other_provider')
    names = {'team','personal'} | ({'other'} if other else set())
    if (modes.get('schema') not in (2,3) or modes.get('user')!=manifest['user']
        or set(definitions)!=names or set(modes.get('guards',{}))!=names
        or definitions.get('team') != {'model_provider':'sg_team'}
        or definitions.get('personal') != {'model_provider':'openai','forced_login_method':'chatgpt'}
        or modes.get('original_mode') not in names
        or not isinstance(modes.get('prepared_guard'),dict)
        or (other and (other in ('openai','sg_team') or not isinstance(other,str)
            or definitions['other'].get('model_provider')!=other
            or set(definitions['other'])-set(MODE_KEYS)))):
        fail("切换元数据无效，请本机 Agent 核实。")
    if modes['schema']==3:
        canonical=modes.get('canonical')
        if (canonical!=team_definition(core.read_settings(STATE))
            or core.digest(json.dumps(canonical,sort_keys=True).encode())!=modes.get('canonical_hash')):
            fail('CANONICAL_INVALID：独立团队定义或认证助手参数变化，停止。')
    return modes


def switch_mode(action, manifest, foreground=False):
    modes = read_modes(manifest)
    settings = core.read_settings(STATE)
    if modes.get('core_hash') != core.digest(core.read_regular(STATE/'切换CodexApp.py')):
        fail("已安装核心有变更，请显式 repair 审阅更新。")
    if action == 'original':
        action = modes['original_mode']
    if action not in modes['selectors']:
        fail("未登记第二中转。请本机 Agent 核实已有提供商，再 repair --other-provider 本人提供商ID；不会复制其他人的配置。")
    with core.lock(STATE/'操作.lock'):
        before = read_config(); guard = route_guard(before)
        if modes['schema']==2 and guard not in [*modes['guards'].values(), modes['prepared_guard']]:
            fail("路由/认证字段另有变化，未覆盖；普通模型和思考强度变化允许保留。")
        if action == 'personal':
            verify_account_channel(before)
        if action=='other' and not isinstance(tomllib.loads(before.decode()).get('model_providers',{}).get(modes['other_provider']),dict):
            fail('OTHER_PROVIDER_MISSING：不重建或覆盖本人第二中转。')
        target = selectors(install_definition(before, modes['canonical'] if modes['schema']==3 else team_definition(settings)), modes['selectors'][action])
        if modes['schema']==2 and route_guard(target) != modes['guards'][action]:
            fail("目标路由安全校验不通过。")
        if action == 'team':
            if foreground:
                verify_foreground(settings)
            else:
                core.ensure_tunnel(STATE,settings)
        if before != target:
            snapshot_transaction({CONFIG:target},before)
    print("配置已选择：" + {'team':'示例团队','personal':'本人 ChatGPT 账户','other':'本人第二中转'}[action])
    print("保存任务后完整退出并重开 App，用新对话验收；登录凭据未删除。")
    if action=='other':
        print("仅切换已有第二中转配置；不创建、修改或启动其隧道。")


def check_forward_args(args, settings):
    # Deliberately accept only the documented invocation, not arbitrary SSH configs.
    expected = {'-F':'none', '-i':str(settings['ssh_key']), '-p':'22',
                '-L':f"127.0.0.1:{settings['port']}:{core.TARGET}"}
    options = []
    i = 1
    for flag in ('-N','-T'):
        if args.count(flag)!=1:
            fail("前台命令需使用说明中的独立 -N -T 参数。")
    found = {}
    while i < len(args)-1:
        arg=args[i]
        if arg in ('-N','-T'):
            i+=1; continue
        if arg in (*expected,'-o') and i+1<len(args)-1:
            if arg=='-o':
                options.append(args[i+1])
            elif arg in found:
                fail("前台命令有重复选项，停止。")
            else:
                found[arg]=args[i+1]
            i+=2; continue
        fail("前台命令含未登记选项，停止。")
    safe = {'IdentitiesOnly=yes','StrictHostKeyChecking=yes','ExitOnForwardFailure=yes',
            'ServerAliveInterval=30','ServerAliveCountMax=3','ForwardAgent=no','ConnectTimeout=10'}
    if (found!=expected or not args or args[-1]!=settings['user']+'@'+core.HOST
        or not {'IdentitiesOnly=yes','StrictHostKeyChecking=yes','ExitOnForwardFailure=yes'}.issubset(options)
        or set(options)-safe):
        fail("前台命令目标或主机校验与登记不符，停止。")


def verify_foreground(settings):
    """Require a listener owned by this desktop user's exact SSH invocation."""
    if sys.platform != 'win32':
        fail("前台接管检查仅供 Windows 修复；Mac 请用现有后台入口。")
    script = ("$ErrorActionPreference='Stop'; $n=@(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort " + str(settings['port']) + " -State Listen); "
              "if($n.Count -ne 1){exit 3}; $p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$n[0].OwningProcess); "
              "$o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid; "
              "@{name=$p.Name;command=$p.CommandLine;sid=$o.Sid}|ConvertTo-Json -Compress")
    result = run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script])
    if result.returncode:
        fail("未找到唯一的本人前台隧道，未接管端口。")
    process = json.loads(result.stdout.lstrip('\ufeff'))
    if process.get('name','').lower()!='ssh.exe' or process.get('sid')!=windows_identity():
        fail("监听进程不是本人 ssh.exe，不接管。")
    import ctypes
    shell = ctypes.WinDLL('shell32',use_last_error=True)
    shell.CommandLineToArgvW.argtypes = [ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype = ctypes.POINTER(ctypes.c_wchar_p)
    count=ctypes.c_int(); ptr=shell.CommandLineToArgvW(process['command'],ctypes.byref(count))
    if not ptr:
        fail("无法核实前台命令。")
    try:
        args=[ptr[i] for i in range(count.value)]
    finally:
        kernel=ctypes.WinDLL('kernel32');kernel.LocalFree.argtypes=[ctypes.c_void_p];kernel.LocalFree(ptr)
    check_forward_args(args,settings)
    if not core.api_ready(STATE,settings):
        fail("前台隧道 API 鉴权未通过。")


def mode_status(manifest):
    if not (STATE/'modes.json').exists():
        print("STATE=需要 repair（保留旧状态，不重新安装）"); return
    modes=read_modes(manifest); guard=route_guard(read_config())
    if modes['schema']==3:
        current=tomllib.loads(read_config().decode())
        selected={k:current[k] for k in MODE_KEYS if k in current}
        mode=next((name for name,g in modes['selectors'].items() if g==selected),'未确认/尚未切换')
        print('SG_TEAM='+('READY' if current.get('model_providers',{}).get('sg_team')==modes['canonical'] else 'REPAIR_PENDING'))
    else:mode=next((name for name,g in modes['guards'].items() if g==guard),'未确认/尚未切换')
    print('CONFIG_MODE='+mode)
    print('TUNNEL_WORKER='+str(core.tunnel_running(STATE)))
    print('LOCAL_PORT_LISTENING='+str(core.port_open(core.read_settings(STATE)['port'])))
    print('CODEX_APP_TEST=NOT_RUN（状态检查不代表 App 请求验证）')


def check_existing_install(manifest):
    """Do not silently replace a locally repaired PowerShell/DPAPI installation."""
    roots=[STATE,STATE/manifest['user']]
    if os.environ.get('LOCALAPPDATA'):roots.append(Path(os.environ['LOCALAPPDATA'])/'SGRelay'/manifest['user'])
    for root in roots:
        if (root/'bin/Codex-Mode.ps1').exists():
            fail('EXISTING_POWERSHELL_INSTALL：发现现场 PowerShell/DPAPI 版本。保留原入口与凭据，请本机 Agent 按第二步的既有版本流程审阅，不能用 Python 安装器覆盖。')


def windows_storage_check():
    """Inspect EFS and junctions only; never decrypt files or rewrite existing ACLs."""
    paths=json.dumps([str(PACKAGE),str(STATE),str(CONFIG.parent)],ensure_ascii=False)
    literal="'"+paths.replace("'","''")+"'"
    script=("$ErrorActionPreference='Stop'; $bad=@(); $roots=ConvertFrom-Json "+literal+"; "
      "foreach($r in $roots){ $p=$r; while($p -and -not(Test-Path -LiteralPath $p)){ $p=Split-Path -Parent $p }; "
      "while($p){$x=Get-Item -LiteralPath $p -Force; if(($x.Attributes -band [IO.FileAttributes]::Encrypted) -or ($x.Attributes -band [IO.FileAttributes]::ReparsePoint)){$bad+='EFS_OR_REPARSE'}; $p=Split-Path -Parent $p}; "
      "if(Test-Path -LiteralPath $r){Get-ChildItem -LiteralPath $r -File -Force -ErrorAction Stop | ForEach-Object {if($_.Attributes -band [IO.FileAttributes]::Encrypted){$bad+='EFS'}}}}; ConvertTo-Json -Compress -InputObject @($bad)")
    result=run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script])
    if result.returncode or json.loads(result.stdout.lstrip('\ufeff') or '[]'):
        fail('EFS_OR_REPARSE：安装/状态目录加密、重定向或无法核实。保留文件，不解密、不改 ACL；由本人 Agent 选择并验证未加密目录。')


def refresh_capability(manifest):
    global _CAPABILITY
    modes=read_modes(manifest)
    app_cli=windows_app_cli(manifest) if sys.platform=='win32' else next((p for p in (Path('/Applications/ChatGPT.app/Contents/Resources/codex'),Path('/Applications/Codex.app/Contents/Resources/codex')) if p.is_file()),None)
    if app_cli is None:fail('APP_NOT_FOUND')
    version=backend_version(app_cli)
    identity={'path':str(app_cli),'version':version,'size':app_cli.stat().st_size,'mtime_ns':app_cli.stat().st_mtime_ns}
    known=modes.get('capability') or {}
    if all(known.get(k)==v for k,v in identity.items()):return
    before=read_config();identity['result']=probe_app_backend(app_cli)
    if app_cli.stat().st_mtime_ns!=identity['mtime_ns'] or app_cli.stat().st_size!=identity['size']:fail('APP_CHANGED_DURING_CHECK')
    modes['capability']=identity
    with core.lock(STATE/'操作.lock'):snapshot_transaction({STATE/'modes.json':json.dumps(modes,ensure_ascii=False).encode()},before)
    print('APP_COMPATIBILITY=PASS（本地模拟接口，未使用真实额度）')


def query_usage(manifest):
    """Query by SSH identity; independent of App config, tokens, and tunnel state."""
    if STATE.is_symlink():
        fail("状态目录异常，停止。")
    key = Path.home() / ".ssh/id_ed25519_sg_team"
    if (STATE / "settings.json").exists():
        settings = core.read_settings(STATE)
        if settings["user"] != manifest["user"]:
            fail("已安装账号与个人包不同，停止查询。")
        key = Path(settings["ssh_key"])
    pub = Path(str(key) + ".pub")
    if not key.is_absolute() or key.is_symlink() or not key.is_file() or pub.is_symlink() or not pub.is_file():
        fail("找不到登记的 SSH 密钥，请本机 Agent 检查原密钥路径；不要重新生成。")
    if sys.platform != "win32" and key.stat().st_mode & 0o077:
        fail("私钥权限过宽，请本机 Agent 检查。")
    actual = run(["ssh-keygen", "-lf", str(pub)])
    if actual.returncode or manifest["public_fingerprint"] not in actual.stdout.split():
        fail("本机公钥不匹配此个人包，停止查询。")
    host_key_preflight()
    result = subprocess.run(["ssh", "-F", "none", "-T", "-i", str(key),
                             "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                             "-o", "ConnectTimeout=10", "-o", "ForwardAgent=no",
                             "-o", "ClearAllForwardings=yes",
                             manifest["user"] + "@" + core.HOST, "share-codex-usage"])
    if result.returncode:
        fail("查询未成功，请将无密钥的报错发管理员；未改 App 配置或现有隧道。")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", nargs="?", choices=("repair", "team", "personal", "other", "original", "status", "usage", "check"), default="team")
    parser.add_argument("--foreground", action="store_true", help="仅复用已核实的本人 Windows 前台隧道")
    parser.add_argument("--other-provider", help="仅 repair：登记本人配置中已有的第二提供商")
    args = parser.parse_args()
    if args.other_provider and args.action != 'repair':
        fail("--other-provider 只用于 repair。")
    if args.foreground and args.action != 'team':
        fail("--foreground 只用于 team。")
    os.umask(0o077)
    manifest = confirm_manifest()
    if args.action == "usage":
        query_usage(manifest)
        return
    runtime_check()
    check_existing_install(manifest)
    if sys.platform=='win32':windows_storage_check()
    if STATE.is_symlink() or CONFIG.parent.is_symlink():
        fail("状态或配置目录异常，停止。")
    if args.action not in ("team", "repair") and not STATE.exists():
        fail("尚未安装，没有改动 App。")
    # A single per-user installer lock prevents two first installs racing.
    with core.lock(Path.home() / ".codex-sg-install.lock"):
        if args.action == 'status':
            mode_status(manifest); return
        if STATE.exists():
            with core.lock(STATE/'操作.lock'):recover_transactions()
        if args.action == 'repair' or (args.action=='team' and not STATE.exists()):
            key = preflight(manifest)
            host_key_preflight()
            repair(manifest,key,args.other_provider)
            if args.action=='repair':
                return
        if not (STATE/'modes.json').is_file():
            fail("已有旧版/半安装状态，请先让本机 Agent 执行 repair，不重新初始化。")
        if read_modes(manifest)['schema']!=3:
            fail('MODE_SCHEMA_UPGRADE_REQUIRED：请先执行 repair 增量更新，保留登录及旧快照。')
        if args.action=='check':
            private_key_preflight(manifest);host_key_preflight()
            with core.lock(STATE/'操作.lock'):core.ensure_tunnel(STATE,core.read_settings(STATE))
            print('SSH_API=PASS；未切换配置，App 仍需单独验收。');return
        if args.action == 'team':
            refresh_capability(manifest)
            private_key_preflight(manifest)
            host_key_preflight()
        if sys.platform == "win32":
            windows_acl(STATE)
        elif STATE.stat().st_mode & 0o077:
            fail("状态目录权限异常，请管理员检查。")
        switch_mode(args.action, manifest,args.foreground)


if __name__ == "__main__":
    try:
        main()
    except (core.SafeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("停止：" + (str(exc) if isinstance(exc, core.SafeError) else "文件、依赖或安装状态异常，请把此提示发管理员；未输出凭据。"), file=sys.stderr)
        raise SystemExit(2)
