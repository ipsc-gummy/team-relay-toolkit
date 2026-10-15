import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from contextlib import redirect_stdout
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


builder = module(ROOT / '程序/打包新人两步接入.py', 'simple_builder')


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='relay-onboarding-tests-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() # macOS /var is a symlink; fixtures model plain Windows paths.
        package = self.root / 'Codex团队接入'
        source = package / '程序'
        source.mkdir(parents=True)
        (source / '切换CodexApp.py').write_bytes(builder.render_core('newuser', 'SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8'))
        (source / '一键接入.py').write_bytes((ROOT / '程序/新人一键接入/一键接入.py').read_bytes())
        self.app = module(source / '一键接入.py', 'newcomer_installer')
        self.manifest = {'user':'newuser','public_fingerprint':'SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8','host':self.app.core.HOST,'host_fingerprint':self.app.core.HOST_FP,'tested_cli_version':'fixture'}
        (package / '个人参数.json').write_text(json.dumps(self.manifest))
        self.token = 'cpa-newuser-' + 'a' * 64
        (package / '中转访问密钥.txt').write_text(self.token)
        self.state = self.root / 'state'
        self.config = self.root / 'config.toml'
        self.original = b'# original\nmodel="personal-model"\n[features]\nexample=true\n[marketplaces.openai-bundled]\nlast_updated="2026-09-09T12:00:00Z"\n'
        self.config.write_bytes(self.original)
        self.app.STATE = self.state
        self.app.CONFIG = self.config

    def init(self):
        with mock.patch.object(self.app.core, 'port_open', return_value=False):
            self.app.initialize(self.manifest, self.root / 'fixture_key')

    def test_usage_bypasses_install_and_app_checks(self):
        with mock.patch('sys.argv', ['install.py', 'usage']), mock.patch.object(self.app, 'query_usage') as query, mock.patch.object(self.app, 'preflight') as preflight, mock.patch.object(self.app, 'initialize') as initialize:
            self.app.main()
        query.assert_called_once_with(self.manifest)
        preflight.assert_not_called()
        initialize.assert_not_called()
        self.assertFalse(self.state.exists())
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_usage_uses_saved_key_without_token_or_tunnel(self):
        self.init()
        key = self.root / 'fixture_key'
        key.write_text('test fixture only')
        key.chmod(0o600)
        Path(str(key)+'.pub').write_text('public fixture')
        replies = subprocess.CompletedProcess([], 0, '256 SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8 fixture', '')
        with mock.patch.object(self.app, 'run', return_value=replies), mock.patch.object(self.app, 'host_key_preflight') as host, mock.patch.object(self.app.subprocess, 'run', return_value=subprocess.CompletedProcess([],0)) as ssh, mock.patch.object(self.app.core, 'secret') as secret, mock.patch.object(self.app.core, 'ensure_tunnel') as tunnel:
            self.app.query_usage(self.manifest)
        args = ssh.call_args.args[0]
        self.assertIn(str(key), args)
        self.assertEqual(args[-2:], ['newuser@203.0.113.10', 'share-codex-usage'])
        self.assertIn('ClearAllForwardings=yes', args)
        self.assertIn('StrictHostKeyChecking=yes', args)
        secret.assert_not_called()
        tunnel.assert_not_called()
        host.assert_called_once()
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_usage_rejects_different_installed_user(self):
        self.init()
        with mock.patch.object(self.app.core, 'read_settings', return_value={'user':'other'}):
            with self.assertRaises(self.app.core.SafeError):
                self.app.query_usage(self.manifest)

    def test_usage_rejects_wrong_key_before_connection(self):
        self.init()
        key=self.root/'fixture_key'
        key.write_text('fixture'); key.chmod(0o600)
        Path(str(key)+'.pub').write_text('fixture')
        with mock.patch.object(self.app,'run',return_value=subprocess.CompletedProcess([],0,'SHA256:wrong','')), mock.patch.object(self.app,'host_key_preflight') as host:
            with self.assertRaises(self.app.core.SafeError):
                self.app.query_usage(self.manifest)
        host.assert_not_called()

    def switch(self, action):
        with mock.patch.object(self.app.core, 'ensure_tunnel') as ensure, redirect_stdout(io.StringIO()) as output:
            self.app.apply_mode(action, self.manifest)
        return output.getvalue(), ensure

    def test_init_backs_up_without_changing_config(self):
        self.init()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertEqual((self.state / 'personal.toml').read_bytes(), self.original)
        self.assertEqual((self.state / '中转访问密钥.txt').stat().st_mode & 0o777, 0o600)

    def test_global_team_then_original_roundtrip(self):
        self.init()
        output, ensure = self.switch('team')
        ensure.assert_called_once()
        parsed = tomllib.loads(self.config.read_text())
        self.assertEqual(parsed['model_provider'], 'sg_team')
        provider = parsed['model_providers']['sg_team']
        self.assertEqual(provider['name'], '团队中转')
        self.assertNotIn(self.token, self.config.read_text())
        self.assertNotIn('env_key', provider)
        self.assertIn('示例团队', output)
        _, ensure = self.switch('original')
        ensure.assert_not_called()
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_repeated_install_does_not_rewrite_config(self):
        self.init()
        self.switch('team')
        stamp = self.config.stat().st_mtime_ns
        self.switch('team')
        self.assertEqual(self.config.stat().st_mtime_ns, stamp)

    def test_failed_tunnel_leaves_original(self):
        self.init()
        with mock.patch.object(self.app.core, 'ensure_tunnel', side_effect=self.app.core.SafeError('network')):
            with self.assertRaises(self.app.core.SafeError):
                self.app.apply_mode('team', self.manifest)
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_existing_listener_not_taken_over(self):
        with mock.patch.object(self.app.core, 'port_open', return_value=True):
            with self.assertRaises(self.app.core.SafeError):
                self.app.initialize(self.manifest, self.root / 'fixture')
        self.assertFalse(self.state.exists())

    def test_unknown_changes_rejected_for_both_modes(self):
        self.init()
        changed = self.original + b'\n[env]\nother="new"\n'
        self.config.write_bytes(changed)
        for mode in ('team','original'):
            with self.assertRaises(self.app.core.SafeError):
                self.switch(mode)
        self.assertEqual(self.config.read_bytes(), changed)

    def test_timestamp_drift_allowed_preserved(self):
        self.init()
        changed = self.original.replace(b'12:00:00Z', b'13:00:00Z')
        self.config.write_bytes(changed)
        self.switch('team')
        self.assertIn(b'13:00:00Z', self.config.read_bytes())
        self.switch('original')
        self.assertEqual(self.config.read_bytes(), changed)

    def test_invalid_timestamp_rejected(self):
        with self.assertRaises(self.app.core.SafeError):
            self.app.comparable(self.original.replace(b'2026-09-09T12:00:00Z', b'<managed>'))

    def test_third_party_mcp_path_not_normalized(self):
        self.init()
        self.config.write_bytes(self.original + b'\n[mcp_servers.node_repl.env]\nCODEX_CLI_PATH="/third-party"\n')
        with self.assertRaises(self.app.core.SafeError):
            self.switch('team')

    def test_newcomer_without_config(self):
        # Only delete this exact fixture created by setUp, never user config.
        self.config.unlink()
        self.init()
        self.assertFalse(self.config.exists())
        self.switch('team')
        self.assertEqual(tomllib.loads(self.config.read_text())['model_provider'], 'sg_team')
        self.switch('original')
        self.assertEqual(self.config.read_bytes(), b'')

    def test_existing_state_not_overwritten(self):
        self.init()
        before = (self.state/'personal.toml').read_bytes()
        with self.assertRaises(FileExistsError):
            self.init()
        self.assertEqual((self.state/'personal.toml').read_bytes(),before)

    def test_known_host_mismatch_not_overwritten(self):
        ssh = self.root/'.ssh'
        ssh.mkdir()
        known = ssh/'known_hosts'
        known.write_text('fixture unchanged')
        replies=[subprocess.CompletedProcess([],0,'host fixture',''),subprocess.CompletedProcess([],0,'256 SHA256:wrong','')]
        with mock.patch.object(self.app.Path,'home',return_value=self.root),mock.patch.object(self.app,'run',side_effect=replies):
            with self.assertRaises(self.app.core.SafeError):
                self.app.host_key_preflight()
        self.assertEqual(known.read_text(),'fixture unchanged')

    def test_scanned_host_requires_pinned_fingerprint(self):
        ssh = self.root/'.ssh'
        ssh.mkdir()
        replies=[subprocess.CompletedProcess([],0,self.app.core.HOST+' ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea\n',''),subprocess.CompletedProcess([],0,'256 SHA256:wrong','')]
        with mock.patch.object(self.app.Path,'home',return_value=self.root),mock.patch.object(self.app,'run',side_effect=replies):
            with self.assertRaises(self.app.core.SafeError):
                self.app.host_key_preflight()
        self.assertFalse((ssh/'known_hosts').exists())

    def test_concurrent_edit_during_connect_is_preserved(self):
        self.init()
        changed = self.original + b'\n# edited\n'
        with mock.patch.object(self.app.core, 'ensure_tunnel', side_effect=lambda *_: self.config.write_bytes(changed)):
            with self.assertRaises(self.app.core.SafeError):
                self.app.apply_mode('team', self.manifest)
        self.assertEqual(self.config.read_bytes(), changed)

    def test_existing_other_provider_fails_without_state(self):
        self.config.write_bytes(b'model_provider="other"\n')
        with self.assertRaises(self.app.core.SafeError):
            self.init()
        self.assertFalse(self.state.exists())

    def test_mismatched_recipient_stops(self):
        self.init()
        with self.assertRaises(self.app.core.SafeError):
            self.app.apply_mode('team', dict(self.manifest, user='another'))

    def test_stored_snapshot_hash_protection(self):
        self.init()
        (self.state / 'team.toml').write_bytes(b'model_provider="other"\n')
        with self.assertRaises(self.app.core.SafeError):
            self.switch('team')

    def test_private_helper_uses_new_user_same_core(self):
        self.init()
        settings = self.app.core.read_settings(self.state)
        self.assertEqual(self.app.core.ssh_command(settings)[-1], 'newuser@203.0.113.10')
        result = subprocess.run(['python3','-B',str(self.state/'切换CodexApp.py'),'_credential','--state-dir',str(self.state)],capture_output=True,text=True)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), self.token)

    def test_status_does_not_change_config_or_expose_key(self):
        self.init()
        output, ensure = self.switch('status')
        ensure.assert_not_called()
        self.assertNotIn(self.token, output)
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_two_document_public_zip(self):
        target = self.root / 'docs.zip'
        result = builder.pack(target)
        self.assertFalse(result['contains_personal_key'])
        with zipfile.ZipFile(target) as bundle:
            self.assertEqual(len(bundle.namelist()), 2)
        with self.assertRaises(ValueError):
            builder.pack(target)

    def test_personal_zip_with_throwaway_keys(self):
        key = self.root / 'throwaway_key'
        subprocess.run(['ssh-keygen','-t','ed25519','-f',str(key),'-N','','-C','test-only'],capture_output=True,check=True)
        token = self.root/'fake.token'
        token.write_text(self.token)
        token.chmod(0o600)
        target = self.root/'personal.zip'
        result = builder.pack(target,'newuser',Path(str(key)+'.pub'),token)
        self.assertTrue(result['contains_personal_key'])
        with zipfile.ZipFile(target) as bundle:
            self.assertEqual(sum(n.endswith('.md') for n in bundle.namelist()),2)
            self.assertEqual(len(bundle.namelist()),7)
            self.assertFalse(any('throwaway' in n for n in bundle.namelist()))
            self.assertEqual(bundle.read('Codex团队接入/中转访问密钥.txt').decode().strip(),self.token)

    def test_windows_hyphen_user_zip_reuses_core(self):
        key = self.root / 'win_test_key'
        subprocess.run(['ssh-keygen','-t','ed25519','-f',str(key),'-N','','-C','test-only'],capture_output=True,check=True)
        token = self.root / 'win.token'
        token.write_text('cpa-member-b-' + 'b' * 64)
        token.chmod(0o600)
        target = self.root / 'win.zip'
        result = builder.pack(target, 'member-b', Path(str(key)+'.pub'), token, 'windows')
        self.assertEqual(result['files'], 7)
        with zipfile.ZipFile(target) as bundle:
            names = bundle.namelist()
            self.assertIn('Codex团队接入/接入.cmd', names)
            self.assertIn('Codex团队接入/program/install.py', names)
            self.assertFalse(any(n.endswith('.command') for n in names))
            self.assertEqual(sum(n.endswith('.md') for n in names), 2)
            manifest = json.loads(bundle.read('Codex团队接入/个人参数.json'))
            self.assertEqual(manifest['platform'], 'windows')
            self.assertEqual(manifest['user'], 'member-b')
            self.assertNotIn('ExecutionPolicy', bundle.read('Codex团队接入/接入.cmd').decode())
            core = bundle.read('Codex团队接入/program/切换CodexApp.py').decode()
            self.assertIn('member-b', core)
            self.assertIn('model_providers.sg_team.auth', core)

    def test_manifest_allows_registered_hyphen_not_root(self):
        self.manifest['user'] = 'member-b'
        self.app.core.FINGERPRINTS = {'member-b': 'SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8'}
        (self.app.PACKAGE / '个人参数.json').write_text(json.dumps(self.manifest))
        self.assertEqual(self.app.confirm_manifest()['user'], 'member-b')
        self.manifest['user'] = 'root'
        (self.app.PACKAGE / '个人参数.json').write_text(json.dumps(self.manifest))
        with self.assertRaises(self.app.core.SafeError):
            self.app.confirm_manifest()

    def test_wrong_platform_preflight_stops_before_key_access(self):
        with mock.patch.object(self.app.sys, 'platform', 'win32'):
            with mock.patch.object(self.app, 'private_key_preflight') as private:
                with self.assertRaises(self.app.core.SafeError):
                    self.app.preflight(dict(self.manifest, platform='macos'))
                private.assert_not_called()

    def test_windows_acl_failure_writes_no_secrets(self):
        with mock.patch.object(self.app.sys, 'platform', 'win32'), mock.patch.object(self.app.shutil, 'which', return_value='/fixture/ssh'), mock.patch.object(self.app, 'windows_acl', side_effect=self.app.core.SafeError('ACL')):
            with self.assertRaises(self.app.core.SafeError):
                self.init()
        self.assertFalse((self.state / '中转访问密钥.txt').exists())
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_windows_acl_created_before_secret_write(self):
        def check(path, create=False):
            self.assertTrue(create)
            self.assertFalse((path / '中转访问密钥.txt').exists())
        with mock.patch.object(self.app.sys, 'platform', 'win32'), mock.patch.object(self.app.shutil, 'which', return_value='/fixture/ssh'), mock.patch.object(self.app, 'windows_acl', side_effect=check) as acl:
            self.init()
            acl.assert_called_once()
        self.assertTrue((self.state / '中转访问密钥.txt').is_file())

    def test_windows_app_missing_or_wrong_version_stops(self):
        with mock.patch.object(self.app.shutil, 'which', return_value='powershell.exe'), mock.patch.object(self.app, 'run', return_value=subprocess.CompletedProcess([],0,'[]','')):
            with self.assertRaises(self.app.core.SafeError):
                self.app.windows_app_cli(self.manifest)

    def test_windows_desktop_launcher_is_not_executed(self):
        launcher = self.root / 'codex.exe'
        launcher.touch()
        result = subprocess.CompletedProcess([],0,json.dumps({'bundled':[str(launcher)],'runtime':[],'running':[]}),'')
        with mock.patch.object(self.app.shutil, 'which', return_value='powershell.exe'), mock.patch.object(self.app, 'run', return_value=result) as run:
            with self.assertRaises(self.app.core.SafeError):
                self.app.windows_app_cli(self.manifest)
            self.assertEqual(run.call_count, 1)

    def test_windows_bundled_cli_newer_version_is_discovered(self):
        path = self.root / 'resources' / 'codex.exe'
        path.parent.mkdir(); path.touch()
        results = [subprocess.CompletedProcess([],0,json.dumps({'bundled':[str(path)],'runtime':[],'running':[]}),''), subprocess.CompletedProcess([],0,'codex-cli 0.153.4\n','')]
        with mock.patch.object(self.app.shutil, 'which', return_value='powershell.exe'), mock.patch.object(self.app, 'run', side_effect=results):
            self.assertEqual(self.app.windows_app_cli(self.manifest), path)

    def windows_runtime_fixture(self):
        bundled=self.root/'WindowsApps/app/resources/codex.exe';bundled.parent.mkdir(parents=True)
        runtime=self.root/'LocalAppData/OpenAI/Codex/bin/version1/codex.exe';runtime.parent.mkdir(parents=True)
        bundled.write_bytes(b'fixture-backend-153');runtime.write_bytes(bundled.read_bytes())
        return bundled,runtime

    def discover_fixture(self,bundled,runtime,running=(),version=None):
        result=subprocess.CompletedProcess([],0,json.dumps({'bundled':list(map(str,bundled)),'runtime':list(map(str,runtime)),'running':list(map(str,running))}),'')
        with mock.patch.dict(os.environ,{'LOCALAPPDATA':str(self.root/'LocalAppData')}),mock.patch.object(self.app.shutil,'which',return_value='powershell.exe'),mock.patch.object(self.app,'run',return_value=result),mock.patch.object(self.app,'backend_version',side_effect=version or (lambda p:'codex-cli 0.153.4')) as execute,redirect_stdout(io.StringIO()):
            found=self.app.windows_app_cli(self.manifest)
        return found,execute

    def test_windows_runtime_copy_preferred_without_executing_windowsapps(self):
        bundled,runtime=self.windows_runtime_fixture()
        def version(path):
            if path==bundled:raise PermissionError('Access denied')
            return 'codex-cli 0.153.4'
        found,execute=self.discover_fixture([bundled],[runtime],[runtime],version)
        self.assertEqual(found,runtime);execute.assert_called_once_with(runtime)
        self.assertFalse(self.state.exists());self.assertEqual(self.config.read_bytes(),self.original)

    def test_windows_unmatched_runtime_never_executed(self):
        bundled,runtime=self.windows_runtime_fixture();runtime.write_bytes(b'other binary')
        found,execute=self.discover_fixture([bundled],[runtime])
        self.assertEqual(found,bundled);execute.assert_called_once_with(bundled)

    def test_windows_access_denied_has_specific_safe_error(self):
        bundled,runtime=self.windows_runtime_fixture();runtime.write_bytes(b'other binary')
        calls=[]
        def denied(path):calls.append(path);raise PermissionError('sensitive arbitrary error')
        with self.assertRaisesRegex(self.app.core.SafeError,'APP_BACKEND_EXECUTION_DENIED'):
            self.discover_fixture([bundled],[runtime],version=denied)
        self.assertEqual(calls,[bundled]);self.assertFalse(self.state.exists())

    def test_windows_runtime_requires_readable_package_hash_anchor(self):
        bundled,runtime=self.windows_runtime_fixture()
        with self.assertRaisesRegex(self.app.core.SafeError,'APP_RUNTIME_UNVERIFIED'):
            self.discover_fixture([],[runtime],version=lambda p:self.fail('must not execute unanchored binary'))

    def test_windows_runtime_outside_expected_directory_never_executed(self):
        bundled,runtime=self.windows_runtime_fixture();outside=self.root/'Downloads/codex.exe';outside.parent.mkdir();outside.write_bytes(runtime.read_bytes())
        found,execute=self.discover_fixture([bundled],[outside])
        self.assertEqual(found,bundled);execute.assert_called_once_with(bundled)

    def test_windows_runtime_parent_symlink_rejected(self):
        bundled,runtime=self.windows_runtime_fixture()
        alias=runtime.parent.parent/'linked';alias.symlink_to(runtime.parent,target_is_directory=True)
        found,execute=self.discover_fixture([bundled],[alias/'codex.exe'])
        self.assertEqual(found,bundled);execute.assert_called_once_with(bundled)

    def test_windows_multiple_versions_requires_actual_running_candidate(self):
        bundled,runtime=self.windows_runtime_fixture()
        b2=self.root/'WindowsApps2/resources/codex.exe';b2.parent.mkdir(parents=True);b2.write_bytes(b'other genuine package')
        r2=runtime.parent.parent/'version2/codex.exe';r2.parent.mkdir();r2.write_bytes(b2.read_bytes())
        with self.assertRaisesRegex(self.app.core.SafeError,'APP_BACKEND_AMBIGUOUS'):
            self.discover_fixture([bundled,b2],[runtime,r2])
        found,execute=self.discover_fixture([bundled,b2],[runtime,r2],[r2])
        self.assertEqual(found,r2);execute.assert_called_once_with(r2)

    def test_windows_same_hash_multiple_copies_are_deterministic(self):
        bundled,runtime=self.windows_runtime_fixture()
        r2=runtime.parent.parent/'version2/codex.exe';r2.parent.mkdir();r2.write_bytes(runtime.read_bytes())
        found,execute=self.discover_fixture([bundled],[r2,runtime])
        self.assertEqual(found,runtime);execute.assert_called_once_with(runtime)

    def test_windows_discovery_script_is_read_only(self):
        with mock.patch.object(self.app.shutil,'which',return_value='powershell.exe'),mock.patch.object(self.app,'run',return_value=subprocess.CompletedProcess([],0,'{}','')) as run:
            with self.assertRaises(self.app.core.SafeError):self.app.windows_app_cli(self.manifest)
        script=run.call_args.args[0][-1]
        for forbidden in ('Set-Acl','icacls','Start-Process','Copy-Item','Remove-Item','Stop-Process'):
            self.assertNotIn(forbidden,script)

    def test_new_package_has_capability_policy_not_exact_version(self):
        key = self.root / 'capability_test_key'
        subprocess.run(['ssh-keygen','-t','ed25519','-f',str(key),'-N','','-C','test-only'],capture_output=True,check=True)
        token = self.root / 'cap.token'
        token.write_text(self.token); token.chmod(0o600)
        target = self.root / 'cap.zip'
        builder.pack(target, 'newuser', Path(str(key)+'.pub'), token, 'windows')
        with zipfile.ZipFile(target) as bundle:
            manifest = json.loads(bundle.read('Codex团队接入/个人参数.json'))
            self.assertNotIn('tested_cli_version', manifest)
            self.assertEqual(manifest['compatibility_check'], 'isolated_app_server_command_auth_v1')

    def test_windows_new_version_runs_probe_before_key_unlock(self):
        manifest = dict(self.manifest, platform='windows')
        with mock.patch.object(self.app.sys, 'platform', 'win32'), mock.patch.object(self.app.shutil, 'which', return_value='/fixture/tool'), mock.patch.object(self.app, 'windows_app_cli', return_value=Path('/fixture/resources/codex.exe')), mock.patch.object(self.app, 'backend_version', return_value='codex-cli 0.153.4'), mock.patch.object(self.app, 'probe_app_backend') as probe, mock.patch.object(self.app, 'private_key_preflight', return_value=Path('/fixture/key')) as key:
            with redirect_stdout(io.StringIO()):
                self.app.preflight(manifest)
            probe.assert_called_once(); key.assert_called_once()

    def test_missing_capability_stops_without_private_key_or_config_changes(self):
        manifest = dict(self.manifest, platform='windows')
        with mock.patch.object(self.app.sys, 'platform', 'win32'), mock.patch.object(self.app.shutil, 'which', return_value='/fixture/tool'), mock.patch.object(self.app, 'windows_app_cli', return_value=Path('/fixture/resources/codex.exe')), mock.patch.object(self.app, 'backend_version', return_value='codex-cli 0.153.4'), mock.patch.object(self.app, 'probe_app_backend', side_effect=self.app.core.SafeError('unsupported')), mock.patch.object(self.app, 'private_key_preflight') as key:
            with redirect_stdout(io.StringIO()), self.assertRaises(self.app.core.SafeError):
                self.app.preflight(manifest)
            key.assert_not_called()
        self.assertEqual(self.config.read_bytes(), self.original)
        self.assertFalse(self.state.exists())

    @unittest.skipUnless(os.environ.get('SYSU_PROBE_APP'), 'explicit bundled backend path required')
    def test_real_local_backend_capability(self):
        result = self.app.probe_app_backend(Path(os.environ['SYSU_PROBE_APP']))
        self.assertTrue(result['command_auth'])
        self.assertTrue(result['local_responses'])
        self.assertTrue(result['app_server_turn'])
        self.assertEqual(result['desktop_ui_test'], 'NOT_RUN')
        self.assertEqual(result['real_relay_test'], 'NOT_RUN')
        self.assertEqual(self.config.read_bytes(), self.original)

    @unittest.skipUnless(os.environ.get('SYSU_PROBE_APP'), 'explicit bundled backend path required')
    def test_real_local_backend_without_auth_helper_is_rejected(self):
        write = self.app.core.atomic_write
        def without_auth(path, data, *args, **kwargs):
            if Path(path).name == 'config.toml':
                data = data.split(b'[model_providers.sysu_probe.auth]')[0]
            return write(path, data, *args, **kwargs)
        with mock.patch.object(self.app.core, 'atomic_write', side_effect=without_auth):
            with self.assertRaises(self.app.core.SafeError):
                self.app.probe_app_backend(Path(os.environ['SYSU_PROBE_APP']))
        self.assertEqual(self.config.read_bytes(), self.original)

    def test_windows_message_requires_app_restart_not_cli_success(self):
        self.init()
        with mock.patch.object(self.app.sys, 'platform', 'win32'):
            output, _ = self.switch('team')
        self.assertIn('完整退出 Codex App', output)
        self.assertNotIn('Cmd+Q', output)

    def test_windows_unencrypted_key_needs_no_agent(self):
        key = self.root / '.ssh/id_ed25519_sg_team'
        key.parent.mkdir(); key.write_text('not-a-real-key')
        Path(str(key)+'.pub').write_text('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea test')
        responses = [subprocess.CompletedProcess([],0,'256 SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8 test',''), subprocess.CompletedProcess([],0,'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea','')]
        with mock.patch.object(self.app.sys, 'platform', 'win32'), mock.patch.object(self.app.Path, 'home', return_value=self.root), mock.patch.object(self.app, 'run', side_effect=responses) as run:
            self.assertEqual(self.app.private_key_preflight(self.manifest), key)
            self.assertEqual(run.call_count, 2)

    def prepare_modes(self, other=None):
        with redirect_stdout(io.StringIO()):
            self.app.repair(self.manifest,self.root/'fixture_key',other)

    def select_mode(self, action, **kwargs):
        with mock.patch.object(self.app.core,'ensure_tunnel') as tunnel, redirect_stdout(io.StringIO()) as output:
            self.app.switch_mode(action,self.manifest,**kwargs)
        self.assertNotIn(self.token,output.getvalue())
        return tomllib.loads(self.config.read_text()),tunnel

    def test_modes_fresh_repair_keeps_config_and_real_helper_works(self):
        self.prepare_modes()
        self.assertEqual(self.config.read_bytes(),self.original)
        settings=self.app.core.read_settings(self.state)
        self.assertEqual(self.app.core.secret(self.state,settings),self.token)
        self.assertTrue((self.state/'modes.json').is_file())

    def test_modes_team_personal_roundtrip_preserves_login_and_preferences(self):
        auth=self.root/'auth.json'; auth.write_text('fixture untouched')
        self.prepare_modes()
        team,tunnel=self.select_mode('team'); tunnel.assert_called_once()
        self.assertEqual(team['model_provider'],'sg_team')
        changed=self.config.read_bytes().replace(b'personal-model',b'new-preference')
        self.config.write_bytes(changed)
        personal,tunnel=self.select_mode('personal'); tunnel.assert_not_called()
        self.assertEqual(personal['model_provider'],'openai')
        self.assertEqual(personal['forced_login_method'],'chatgpt')
        self.assertEqual(personal['model'],'new-preference')
        self.assertEqual(auth.read_text(),'fixture untouched')
        self.assertNotIn(self.token,self.config.read_text())
        self.select_mode('team')

    def test_modes_other_preserves_existing_auth_policy(self):
        self.original=b'model_provider="own_api"\nforced_login_method="api"\n[model_providers.own_api]\nbase_url="http://127.0.0.1:19000/v1"\nwire_api="responses"\nenv_key="MY_OWN_KEY"\n'
        self.config.write_bytes(self.original)
        self.prepare_modes()
        self.select_mode('team')
        other,tunnel=self.select_mode('other'); tunnel.assert_not_called()
        self.assertEqual(other['model_provider'],'own_api')
        self.assertEqual(other['forced_login_method'],'api')
        self.select_mode('personal')
        original,_=self.select_mode('original')
        self.assertEqual(original,other)

    def test_modes_missing_other_stops(self):
        self.prepare_modes()
        with self.assertRaises(self.app.core.SafeError):
            self.select_mode('other')
        self.assertEqual(self.config.read_bytes(),self.original)

    def test_modes_repair_legacy_complete_state_with_extra_logs(self):
        self.init(); self.switch('team')
        (self.state/'隧道.log').write_text('fixture')
        self.prepare_modes()
        self.select_mode('personal')
        self.assertEqual((self.state/'personal.toml').read_bytes(),self.original)
        self.assertEqual((self.state/'隧道.log').read_text(),'fixture')

    def test_modes_empty_state_can_resume(self):
        self.state.mkdir(mode=0o700)
        self.prepare_modes(); self.select_mode('team')

    def test_modes_unknown_partial_is_preserved(self):
        self.state.mkdir(mode=0o700)
        unknown=self.state/'credential-state.json'; unknown.write_text('fixture')
        with self.assertRaises(self.app.core.SafeError):
            self.prepare_modes()
        self.assertEqual(unknown.read_text(),'fixture')
        self.assertEqual(self.config.read_bytes(),self.original)

    def test_modes_helper_failure_rolls_back_and_retry_works(self):
        with mock.patch.object(self.app.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'')):
            with self.assertRaises(self.app.core.SafeError):
                self.prepare_modes()
        self.assertEqual(self.config.read_bytes(),self.original)
        self.assertFalse((self.state/'settings.json').exists())
        self.prepare_modes()
        self.select_mode('team')

    def test_modes_failed_legacy_repair_restores_every_file(self):
        self.init()
        previous={p:p.read_bytes() for p in self.state.iterdir() if p.is_file()}
        with mock.patch.object(self.app.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'')):
            with self.assertRaises(self.app.core.SafeError):
                self.prepare_modes()
        for path,data in previous.items():
            self.assertEqual(path.read_bytes(),data)
        self.assertFalse((self.state/'modes.json').exists())

    def test_modes_repeated_repair_and_switch_idempotent(self):
        self.prepare_modes(); self.prepare_modes()
        self.select_mode('team')
        stamp=self.config.stat().st_mtime_ns
        self.select_mode('team')
        self.assertEqual(stamp,self.config.stat().st_mtime_ns)
        self.prepare_modes(); self.select_mode('personal')

    def test_modes_unsafe_route_drift_stops_repair_and_switch(self):
        self.prepare_modes(); self.select_mode('team')
        baseline=self.config.read_bytes()
        for delta in (b'\n[env]\nOPENAI_BASE_URL="https://example.invalid"\n',):
            changed=baseline+delta; self.config.write_bytes(changed)
            with self.assertRaises(self.app.core.SafeError):
                self.select_mode('personal')
            with self.assertRaises(self.app.core.SafeError):
                self.prepare_modes()
            self.assertEqual(self.config.read_bytes(),changed)

    def test_v3_unknown_fields_and_mcp_survive_roundtrip(self):
        self.prepare_modes();self.select_mode('team')
        extra=b'\n[mcp_servers.new_tool.env]\nDYNAMIC_PIPE="changed"\n[projects.fixture]\ntrust_level="trusted"\n'
        self.config.write_bytes(self.config.read_bytes()+extra)
        self.select_mode('personal');self.assertIn(extra,self.config.read_bytes())
        self.select_mode('team');self.assertIn(extra,self.config.read_bytes())

    def test_v3_missing_provider_and_selector_recovered_from_canonical(self):
        self.prepare_modes();self.select_mode('team')
        self.config.write_bytes(self.original+b'\n[projects.new]\ntrust_level="trusted"\n')
        team,_=self.select_mode('team')
        self.assertEqual(team['model_provider'],'sg_team')
        self.assertEqual(team['model_providers']['sg_team']['base_url'],'http://127.0.0.1:18318/v1')
        self.assertIn('new',team['projects'])

    def test_v3_does_not_depend_on_old_team_snapshot_after_adoption(self):
        self.prepare_modes();(self.state/'team.toml').write_bytes(b'damaged historical copy')
        self.select_mode('team');self.select_mode('personal')

    def test_v3_canonical_tamper_fails_before_network(self):
        self.prepare_modes();path=self.state/'modes.json';m=json.loads(path.read_text())
        m['canonical']['base_url']='http://localhost:19999/v1';path.write_text(json.dumps(m))
        with mock.patch.object(self.app.core,'ensure_tunnel') as tunnel:
            with self.assertRaises(self.app.core.SafeError):self.app.switch_mode('team',self.manifest)
        tunnel.assert_not_called()

    def test_v3_multiline_unknown_toml_kept_exact(self):
        self.config.write_bytes(self.original+b'\n[unrelated]\ntext="""\n[model_providers.sg_team]\nmodel_provider=blah\n"""\n')
        self.prepare_modes();self.select_mode('team');self.select_mode('personal')
        self.assertIn(b'text="""\n[model_providers.sg_team]\nmodel_provider=blah\n"""',self.config.read_bytes())

    def test_transaction_checks_config_after_network_and_state_writes(self):
        self.prepare_modes();changed=self.original+b'# concurrently changed\n'
        def verify():self.config.write_bytes(changed)
        with self.assertRaises(self.app.core.SafeError):
            self.app.snapshot_transaction({self.state/'fixture.json':b'{}'},self.original,verify)
        self.assertEqual(self.config.read_bytes(),changed)

    def test_external_powershell_install_detected_without_overwrite(self):
        path=self.state/'newuser/bin/Codex-Mode.ps1';path.parent.mkdir(parents=True);path.write_text('fixture')
        with self.assertRaisesRegex(self.app.core.SafeError,'POWERSHELL'):
            self.app.check_existing_install(self.manifest)
        self.assertEqual(path.read_text(),'fixture');self.assertFalse((self.state/'settings.json').exists())

    def test_efs_check_read_only_and_fail_closed(self):
        with mock.patch.object(self.app,'run',return_value=subprocess.CompletedProcess([],0,'["encrypted"]','')) as run:
            with self.assertRaisesRegex(self.app.core.SafeError,'EFS'):self.app.windows_storage_check()
        command=run.call_args.args[0][-1]
        self.assertNotIn('Set-Acl',command);self.assertNotIn('cipher',command)

    def test_502_does_not_destroy_working_ssh(self):
        self.init();settings=self.app.core.read_settings(self.state)
        with mock.patch.object(self.app.core,'tunnel_running',return_value=True),mock.patch.object(self.app.core,'port_open',return_value=True),mock.patch.object(self.app.core,'api_ready',side_effect=self.app.core.HealthError('UPSTREAM_TRANSIENT',502)) as api,mock.patch.object(self.app.core,'stop_tunnel') as stop,mock.patch.object(self.app.core.time,'sleep'):
            with self.assertRaisesRegex(self.app.core.SafeError,'UPSTREAM_TRANSIENT'):self.app.core.ensure_tunnel(self.state,settings)
        self.assertEqual(api.call_count,3);stop.assert_not_called()

    def test_auth_failure_does_not_retry(self):
        self.init();settings=self.app.core.read_settings(self.state)
        with mock.patch.object(self.app.core,'api_ready',side_effect=self.app.core.HealthError('AUTH_FAILURE',401)) as api:
            with self.assertRaisesRegex(self.app.core.SafeError,'AUTH_FAILURE'):self.app.core.health_check(self.state,settings)
        self.assertEqual(api.call_count,1)

    def test_crash_after_replace_recovers_exact_snapshot(self):
        self.prepare_modes();before=self.config.read_bytes()
        write=self.app.core.atomic_write
        def crash(path,data,*args):
            write(path,data,*args)
            if path==self.config:raise KeyboardInterrupt()
        with mock.patch.object(self.app.core,'atomic_write',side_effect=crash):
            with self.assertRaises(KeyboardInterrupt):
                self.app.snapshot_transaction({self.config:before+b'# managed write\n'},before)
        self.app.recover_transactions();self.assertEqual(self.config.read_bytes(),before)

    def test_only_ten_automatic_backups_retained(self):
        self.prepare_modes()
        for i in range(14):self.select_mode('team' if i%2==0 else 'personal')
        self.assertLessEqual(len(list((self.state/'备份').iterdir())),10)

    def test_noop_transaction_still_checks_concurrent_config(self):
        self.prepare_modes()
        changed=self.original+b'# external change\n'
        with self.assertRaisesRegex(self.app.core.SafeError,'CONFIG_CONCURRENT_CHANGE'):
            self.app.snapshot_transaction({},self.original,lambda:self.config.write_bytes(changed))
        self.assertEqual(self.config.read_bytes(),changed)

    def test_windows_atomic_replace_preserves_dacl_api_contract(self):
        import ctypes
        winos=mock.Mock(wraps=os);winos.name='nt'
        def replace(destination,temporary,backup,flags,exclude,reserved):
            self.assertEqual((backup,flags,exclude,reserved),(None,0,None,None))
            os.replace(temporary,destination)
            return 1
        kernel=mock.Mock();kernel.ReplaceFileW.side_effect=replace
        with mock.patch.object(self.app.core,'os',winos),mock.patch.object(ctypes,'WinDLL',return_value=kernel,create=True):
            self.app.core.atomic_write(self.config,b'# replacement\n')
        kernel.ReplaceFileW.assert_called_once()
        winos.replace.assert_not_called()
        self.assertEqual(self.config.read_bytes(),b'# replacement\n')
        self.assertFalse(list(self.root.glob('.sg-write-*')))

    def test_windows_atomic_replace_failure_keeps_original(self):
        import ctypes
        winos=mock.Mock(wraps=os);winos.name='nt'
        kernel=mock.Mock();kernel.ReplaceFileW.return_value=0
        with mock.patch.object(self.app.core,'os',winos),mock.patch.object(ctypes,'WinDLL',return_value=kernel,create=True),mock.patch.object(ctypes,'get_last_error',return_value=5,create=True),mock.patch.object(ctypes,'WinError',return_value=OSError('fixture denied'),create=True):
            with self.assertRaises(OSError):self.app.core.atomic_write(self.config,b'# rejected\n')
        self.assertEqual(self.config.read_bytes(),self.original)
        self.assertFalse(list(self.root.glob('.sg-write-*')))

    def test_schema2_migration_preserves_new_unrelated_fields(self):
        self.prepare_modes();path=self.state/'modes.json';m=json.loads(path.read_text())
        m['schema']=2;m.pop('canonical');m.pop('canonical_hash');path.write_text(json.dumps(m))
        extra=b'\n[mcp_servers.new.env]\nPIPE="new-pipe"\n[projects.new]\ntrust_level="trusted"\n'
        self.config.write_bytes(self.original+extra)
        self.prepare_modes();self.select_mode('team');self.select_mode('personal')
        self.assertIn(extra,self.config.read_bytes())
        self.assertEqual(json.loads(path.read_text())['schema'],3)

    def test_incompatible_updated_app_does_not_change_state_or_config(self):
        self.prepare_modes();backend=self.root/'codex.exe';backend.write_bytes(b'new incompatible backend')
        previous=(self.state/'modes.json').read_bytes()
        with mock.patch.object(self.app.sys,'platform','win32'),mock.patch.object(self.app,'windows_app_cli',return_value=backend),mock.patch.object(self.app,'backend_version',return_value='fixture'),mock.patch.object(self.app,'probe_app_backend',side_effect=self.app.core.SafeError('PROTOCOL_INCOMPATIBLE')):
            with self.assertRaisesRegex(self.app.core.SafeError,'PROTOCOL_INCOMPATIBLE'):self.app.refresh_capability(self.manifest)
        self.assertEqual((self.state/'modes.json').read_bytes(),previous)
        self.assertEqual(self.config.read_bytes(),self.original)

    def test_current_app_upgrade_probe_is_not_repeated(self):
        self.prepare_modes();backend=self.root/'resources/codex';backend.parent.mkdir();backend.write_bytes(b'version1')
        with mock.patch.object(self.app.sys,'platform','win32'),mock.patch.object(self.app,'windows_app_cli',return_value=backend),mock.patch.object(self.app,'backend_version',return_value='codex-cli 0.153.4'),mock.patch.object(self.app,'probe_app_backend',return_value={'command_auth':True}) as probe,redirect_stdout(io.StringIO()):
            self.app.refresh_capability(self.manifest);self.app.refresh_capability(self.manifest)
            self.assertEqual(probe.call_count,1)
            backend.write_bytes(b'version2 bigger');self.app.refresh_capability(self.manifest)
            self.assertEqual(probe.call_count,2)
        self.assertEqual(self.config.read_bytes(),self.original)

    def test_modes_absent_config_directory_created_on_switch_only(self):
        self.app.CONFIG=self.root/'new-codex'/'config.toml'; self.config=self.app.CONFIG
        self.prepare_modes(); self.assertFalse(self.config.exists())
        self.select_mode('team'); self.select_mode('personal')

    def test_modes_tunnel_failure_never_changes_config(self):
        self.prepare_modes()
        with mock.patch.object(self.app.core,'ensure_tunnel',side_effect=self.app.core.SafeError('offline')):
            with self.assertRaises(self.app.core.SafeError):
                self.app.switch_mode('team',self.manifest)
        self.assertEqual(self.config.read_bytes(),self.original)

    def test_modes_write_failure_rolls_back_exact_config(self):
        self.prepare_modes()
        with self.assertRaises(RuntimeError):
            self.app.snapshot_transaction({self.config:b'# changed\n'},self.original,
                                          lambda: (_ for _ in ()).throw(RuntimeError('fixture')))
        self.assertEqual(self.config.read_bytes(),self.original)

    def test_windows_identity_rejects_wrong_sid_and_elevation(self):
        for identity in ({'actual':'S-1-5-21-1001','desktop':'S-1-5-21-1002','elevated':False},
                         {'actual':'S-1-5-21-1001','desktop':'S-1-5-21-1001','elevated':True}):
            with mock.patch.object(self.app,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(identity),'')):
                with self.assertRaises(self.app.core.SafeError):
                    self.app.windows_identity()

    def test_windows_existing_acl_check_never_rewrites(self):
        with mock.patch.object(self.app,'run',return_value=subprocess.CompletedProcess([],3,'','')) as run:
            with self.assertRaises(self.app.core.SafeError):
                self.app.windows_acl(self.root)
        self.assertEqual(run.call_count,1)
        self.assertEqual(run.call_args.args[0][0],'powershell.exe')
        self.assertNotIn('Set-Acl',run.call_args.args[0][-1])

    def test_windows_msys_rejected_before_any_identity_repair(self):
        with mock.patch.object(self.app.sys,'platform','msys'):
            with self.assertRaises(self.app.core.SafeError):
                self.app.runtime_check()

    def test_foreground_exact_options_no_false_target_match(self):
        settings={'port':18318,'ssh_key':'C:\\Users\\fixture\\key','user':'newuser'}
        args=['ssh.exe','-F','none','-N','-T','-i',settings['ssh_key'],'-p','22',
              '-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','ExitOnForwardFailure=yes',
              '-L','127.0.0.1:18318:127.0.0.1:8317','newuser@203.0.113.10']
        self.app.check_forward_args(args,settings)
        for wrong in (args[:-1]+['other@203.0.113.10'],
                      [a.replace('StrictHostKeyChecking=yes','StrictHostKeyChecking=no') for a in args],
                      [a.replace('18318:127.0.0.1:8317','18318:127.0.0.1:9999') for a in args],
                      args[:-1]+['-R','1234:localhost:1234',args[-1]]):
            with self.assertRaises(self.app.core.SafeError):
                self.app.check_forward_args(wrong,settings)

    def test_bundled_host_key_fingerprint(self):
        public=self.root/'host.pub'; public.write_text(self.app.PINNED_HOST_KEY+'\n')
        result=subprocess.run(['ssh-keygen','-lf',str(public)],capture_output=True,text=True,check=True)
        self.assertIn(self.app.core.HOST_FP,result.stdout.split())

    def test_windows_encrypted_key_missing_agent_fails_without_changes(self):
        key = self.root / '.ssh/id_ed25519_sg_team'
        key.parent.mkdir(); key.write_text('not-a-real-key')
        Path(str(key)+'.pub').write_text('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea test')
        responses = [subprocess.CompletedProcess([],0,'256 SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8 test',''), subprocess.CompletedProcess([],1,'',''), subprocess.CompletedProcess([],2,'','')]
        with mock.patch.object(self.app.sys, 'platform', 'win32'), mock.patch.object(self.app.Path, 'home', return_value=self.root), mock.patch.object(self.app, 'run', side_effect=responses):
            with self.assertRaisesRegex(self.app.core.SafeError, 'ssh-agent'):
                self.app.private_key_preflight(self.manifest)
        self.assertEqual(self.config.read_bytes(), self.original)


if __name__ == '__main__':
    unittest.main(verbosity=2)
