"""隔离 HOME/配置/网络替身；不操作正式 App、SSH 或凭据。"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import tomllib
import unittest
from unittest import mock

def load(name, file):
    spec=importlib.util.spec_from_file_location(name,file)
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

HERE=Path(__file__).parent
c=load('heal_controller',HERE/'App全局路由.py')
h=load('selfheal_tests_module',HERE/'App自愈.py')

class HealingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.legacy=self.root/'legacy';self.legacy.mkdir(mode=0o700)
        self.config=self.root/'config.toml'
        self.binary=self.root/'codex';self.binary.write_bytes(b'fixture');self.binary.chmod(0o700)
        self.asar=self.root/'app.asar';self.asar.write_bytes(b'fixture')
        self.proxy=self.root/'proxy.py';self.proxy.write_bytes(b'fixture');self.proxy.chmod(0o700)
        self.helper=self.legacy/'切换CodexApp.py';self.helper.write_bytes(b'fixture helper')
        self.settings={'schema':1,'user':'owner','host':'203.0.113.10','target':'127.0.0.1:8317','port':18318,
                       'python':sys.executable,'config':str(self.config),'ssh':'/usr/bin/ssh','ssh_key':str(self.root/'key')}
        self.provider={'name':'Fixture','base_url':'http://127.0.0.1:18318/v1','wire_api':'responses',
                       'auth':{'command':sys.executable,'args':[str(self.helper),'_credential','--state-dir',str(self.legacy)],'timeout_ms':5000,'refresh_interval_ms':0}}
        self.original=b'# keep exactly\nmodel_provider="sg_team"\nmodel="fixture-model"\n[features]\nfuture=true\n[model_providers.custom-api]\nname="other fixture"\nbase_url="http://localhost:19191/v1"\n'
        self.initial=h.merge(self.original,self.provider,'sg_team')
        self.config.write_bytes(self.initial)
        for name in ('auth.json','history.sqlite','history.jsonl','key'):(self.root/name).write_bytes(b'untouched sentinel')
        from types import SimpleNamespace
        core=SimpleNamespace(atomic_write=self.write,read_settings=lambda _:self.settings,
             lock=load('heal_core',HERE/'App切换/切换CodexApp.py').lock,
             port_open=mock.Mock(return_value=True),tunnel_running=mock.Mock(return_value=True))
        self.patch(mock.patch.multiple(c,STATE=self.state,LEGACY=self.legacy,CONFIG=self.config,PROXY=self.proxy,BINARY=self.binary,ASAR=self.asar,_CORE=core))
        self.patch(mock.patch.dict(os.environ,{'HOME':str(self.root),'CODEX_HOME':str(self.root/'unused')},clear=False))
        self.patch(mock.patch.object(c,'validate_launch_env',return_value=str(self.proxy)))
        self.patch(mock.patch.object(c,'launch_env',return_value=str(self.proxy)))
        self.patch(mock.patch.object(c,'_HEAL',h,create=True))
        self.patch(mock.patch.object(c,'_ACTIVE_APP',None,create=True))
        h._HEALTH_CACHE.clear()
        self.probe=self.patch(mock.patch.object(h,'probe_protocol',side_effect=lambda _: {'version':'fixture','schema_sha256':'a'*64}))
        self.health=self.patch(mock.patch.object(h,'health_once',return_value={'health_status':'HEALTHY','http_status':200}))
        self.tunnel=self.patch(mock.patch.object(h,'repair_tunnel'))
        self.sleep=self.patch(mock.patch.object(h.time,'sleep'))
        self.manifest={'schema':2,'mode':'team','enabled':True,'config':str(self.config),'proxy':str(self.proxy),
                       'app_files':h.app_files(c),'hashes':{}}
        for mode in ('team','original'):
            data=h.merge(self.initial,self.provider,c.PROVIDERS[mode]);self.write(self.state/(mode+'.toml'),data)
            self.manifest['hashes'][mode]=c.digest(data)
        self.write(self.state/'状态.json',h.encode(self.manifest))
        h.enable(c)
        self.probe.reset_mock();self.health.reset_mock();self.tunnel.reset_mock()

    def patch(self,p):
        v=p.start();self.addCleanup(p.stop);return v

    def write(self,path,data,mode=0o600):
        path=Path(path);self.assertTrue(path.is_relative_to(self.root))
        fd,name=tempfile.mkstemp(dir=path.parent)
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),mode);stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path)

    def assert_sentinels(self):
        for name in ('auth.json','history.sqlite','history.jsonl','key'):self.assertEqual((self.root/name).read_bytes(),b'untouched sentinel')

    def test_normal_start_no_config_write(self):
        before=self.config.stat().st_mtime_ns
        self.assertEqual(h.ensure(c)['provider'],'sg_team')
        self.assertEqual(before,self.config.stat().st_mtime_ns);self.probe.assert_not_called();self.assert_sentinels()

    def test_changed_fingerprint_compatible_auto_migrates(self):
        self.binary.write_bytes(b'updated binary')
        h.ensure(c);self.probe.assert_called_once()
        self.assertEqual(c.manifest()['self_heal']['app_files'],h.app_files(c))
        self.assertEqual(self.config.read_bytes(),self.initial)

    def test_unknown_fields_preserved_byte_exact(self):
        added=b'\n[future_tool]\nvalue = [1,2] # opaque\n[mcp_servers.x.env]\nDYNAMIC_PIPE="changed"\n'
        self.config.write_bytes(self.initial+added);h.ensure(c)
        self.assertEqual(self.config.read_bytes(),self.initial+added)

    def test_missing_provider_and_selector_repaired_only(self):
        before=self.original.replace(b'model_provider="sg_team"\n',b'')+b'\n[future]\nx=4\n'
        self.config.write_bytes(before);h.ensure(c)
        expected=tomllib.loads(before.decode());expected['model_provider']='sg_team';expected['model_providers']['sg_team']=self.provider
        self.assertEqual(tomllib.loads(self.config.read_text()),expected)
        self.assertIn(b'[future]\nx=4\n',self.config.read_bytes());self.assert_sentinels()

    def test_changed_selector_and_sg_block_restore_canonical(self):
        self.config.write_bytes(self.initial.replace(b'model_provider="sg_team"',b'model_provider="unknown"').replace(b'18318/v1',b'19999/v1'))
        h.ensure(c);self.assertEqual(tomllib.loads(self.config.read_text())['model_providers']['sg_team'],self.provider)
        self.assertEqual(tomllib.loads(self.config.read_text())['model_provider'],'sg_team')

    def test_tunnel_missing_repaired(self):
        c.core().port_open.side_effect=[False,True]
        h.ensure(c);self.tunnel.assert_called_once()

    def test_502_503_backoff_never_changes_config(self):
        self.health.side_effect=[h.Failure('UPSTREAM_TRANSIENT',502),h.Failure('UPSTREAM_TRANSIENT',503),{'health_status':'HEALTHY','http_status':200}]
        h.ensure(c);self.assertEqual(self.sleep.call_args_list,[mock.call(0.5),mock.call(1.0)])
        self.tunnel.assert_not_called();self.assertEqual(self.config.read_bytes(),self.initial)

    def test_exhausted_transient_is_bounded(self):
        self.health.side_effect=h.Failure('UPSTREAM_TRANSIENT',504)
        with self.assertRaises(h.Failure) as ex:h.ensure(c)
        self.assertEqual(ex.exception.reason,'UPSTREAM_TRANSIENT');self.assertEqual(self.health.call_count,3)
        self.assertEqual(self.config.read_bytes(),self.initial)

    def test_auth_failure_no_retries_or_config_change(self):
        for status in (401,403):
            self.health.side_effect=h.Failure('AUTH_FAILURE',status)
            self.health.reset_mock()
            with self.assertRaises(h.Failure) as ex:h.ensure(c)
            self.assertEqual(ex.exception.reason,'AUTH_FAILURE');self.assertEqual(self.health.call_count,1)
            self.assertEqual(self.config.read_bytes(),self.initial)

    def test_protocol_incompatible_does_not_accept_or_repair(self):
        old=(self.state/'状态.json').read_bytes();self.binary.write_bytes(b'new incompatible')
        self.config.write_bytes(self.original)
        self.probe.side_effect=h.Failure('PROTOCOL_INCOMPATIBLE')
        with self.assertRaises(h.Failure):h.ensure(c)
        self.assertEqual((self.state/'状态.json').read_bytes(),old);self.assertEqual(self.config.read_bytes(),self.original)

    def test_structurally_broken_toml_stops_without_overwrite(self):
        self.config.write_bytes(b'[broken')
        with self.assertRaises(h.Failure) as ex:h.ensure(c)
        self.assertEqual(ex.exception.reason,'CONFIG_STRUCTURE');self.assertEqual(self.config.read_bytes(),b'[broken')

    def test_canonical_tamper_stops_without_network(self):
        path=self.state/'sg_team.canonical.json';path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(h.Failure):h.ensure(c)
        self.health.assert_not_called()

    def test_atomic_failure_rolls_back_exact_bytes(self):
        self.config.write_bytes(self.original)
        original_write=c.core().atomic_write
        def fail(path,data,*args):
            if Path(path)==self.state/'状态.json':raise OSError('sensitive error must not log')
            return original_write(path,data,*args)
        self.binary.write_bytes(b'new version')
        with mock.patch.object(c.core(),'atomic_write',side_effect=fail):
            with self.assertRaises(h.Failure):h.ensure(c)
        self.assertEqual(self.config.read_bytes(),self.original);self.assert_sentinels()

    def test_backup_retention_ten_and_safe_logs(self):
        for _ in range(13):
            self.config.write_bytes(self.original);h.ensure(c)
        self.assertEqual(len(list((self.state/'自愈备份').iterdir())),10)
        logs=(self.state/'自愈记录.jsonl').read_text()
        for forbidden in ('Authorization','sensitive error','fixture-model','DYNAMIC_PIPE'):
            self.assertNotIn(forbidden,logs)
        for line in logs.splitlines():self.assertIsInstance(json.loads(line),dict)

    def test_original_does_not_check_network_or_rewrite_other_provider(self):
        h.ensure(c,mode='original');self.health.assert_not_called();self.tunnel.assert_not_called()
        self.assertEqual(tomllib.loads(self.config.read_text())['model_provider'],'custom-api')
        self.assertIn(b'base_url="http://localhost:19191/v1"',self.config.read_bytes())

    def test_personal_selects_builtin_openai_without_network_or_history_change(self):
        h.ensure(c,mode='personal');self.health.assert_not_called();self.tunnel.assert_not_called()
        value=tomllib.loads(self.config.read_text())
        self.assertEqual(value['model_provider'],'openai')
        self.assertEqual(value['model_providers']['sg_team'],self.provider)
        self.assertIn(b'base_url="http://localhost:19191/v1"',self.config.read_bytes())
        self.assert_sentinels()

    def test_status_reports_real_current_fields(self):
        report=h.inspect(c)
        for key in ('SELF_HEAL','APP_COMPATIBLE','CONFIG','SG_TEAM','TUNNEL','UPSTREAM'):self.assertIn(key,report)
        self.assertEqual(report['SELF_HEAL'],'READY')

    def test_selector_only_preserves_provider_comments_and_tail(self):
        data=self.initial.replace(b'model_provider="sg_team"',b'model_provider="custom-api" # keep comment')+b'\n\n# tail\n\n\n'
        expected=data.replace(b'"custom-api" # keep comment',b'"sg_team" # keep comment')
        self.assertEqual(h.merge(data,self.provider,'sg_team'),expected)

    def test_multiline_fake_headers_survive_repair(self):
        extra=b'\n[future]\ntext="""\n[model_providers.sg_team]\nmodel_provider="""\n\n\n'
        data=self.original+extra
        self.assertIn(extra,h.merge(data,self.provider,'sg_team'))

    def test_crash_after_replace_recovers_pending_transaction(self):
        self.config.write_bytes(self.original);old=(self.state/'状态.json').read_bytes()
        self.binary.write_bytes(b'new')
        write=c.core().atomic_write
        def crash(path,data,*args):
            if Path(path)==self.state/'状态.json':raise KeyboardInterrupt()
            write(path,data,*args)
        with mock.patch.object(c.core(),'atomic_write',side_effect=crash):
            with self.assertRaises(KeyboardInterrupt):h.ensure(c)
        h.recover(c)
        self.assertEqual(self.config.read_bytes(),self.original)
        self.assertEqual((self.state/'状态.json').read_bytes(),old)

    def test_concurrent_change_not_clobbered_on_rollback(self):
        self.config.write_bytes(self.original);self.binary.write_bytes(b'new')
        write=c.core().atomic_write
        def conflict(path,data,*args):
            if Path(path)==self.state/'状态.json':
                self.config.write_bytes(self.original+b'# user edit\n');raise OSError()
            write(path,data,*args)
        with mock.patch.object(c.core(),'atomic_write',side_effect=conflict):
            with self.assertRaises(h.Failure) as ex:h.ensure(c)
        self.assertEqual(ex.exception.reason,'ROLLBACK_CONFLICT')
        self.assertEqual(self.config.read_bytes(),self.original+b'# user edit\n')

    def test_status_auth_failure_classified(self):
        self.health.side_effect=h.Failure('AUTH_FAILURE',401)
        result=h.inspect(c);self.assertEqual(result['UPSTREAM'],'AUTH_FAILURE')
        self.assertEqual(result['SELF_HEAL'],'BLOCKED')

    def test_status_unregistered_not_ready(self):
        with mock.patch.object(c,'launch_env',return_value=None):
            self.assertEqual(h.inspect(c)['SELF_HEAL'],'BLOCKED')

    def test_controller_preflight_heals_before_child(self):
        self.config.write_bytes(self.original)
        c.preflight();self.assertEqual(c.load_route()['provider'],'sg_team')
        self.assertEqual(tomllib.loads(self.config.read_text())['model_providers']['sg_team'],self.provider)
        self.assertEqual(self.health.call_count,1) # no GET per routed frame

    def test_running_child_update_requires_restart_not_wrong_schema_proof(self):
        c.preflight();self.binary.write_bytes(b'new on disk, old process still alive')
        with self.assertRaises(c.SafeError):c.load_route()
        self.probe.assert_not_called()

    def test_controller_unrelated_drift_not_rejected(self):
        c.preflight();self.config.write_bytes(self.initial+b'\n[unknown]\nnew=true\n')
        self.assertEqual(c.load_route()['provider'],'sg_team')

    def test_health_cache_never_hides_missing_port(self):
        c.preflight();c.core().port_open.return_value=False
        c.load_route();self.tunnel.assert_called_once()

    def test_enable_detects_binary_changed_during_probe(self):
        self.write(self.state/'状态.json',h.encode(self.manifest))
        self.probe.side_effect=lambda _: (self.binary.write_bytes(b'changed during schema'),{'version':'fixture','schema_sha256':'a'*64})[1]
        with self.assertRaises(h.Failure) as ex:h.enable(c)
        self.assertEqual(ex.exception.reason,'APP_CHANGED_DURING_CHECK')

    def test_update_during_health_never_accepts_unprobed_binary(self):
        before=(self.state/'状态.json').read_bytes()
        self.health.side_effect=lambda _: (self.binary.write_bytes(b'concurrent App update'),{'health_status':'HEALTHY','http_status':200})[1]
        with self.assertRaises(h.Failure) as ex:h.ensure(c)
        self.assertEqual(ex.exception.reason,'APP_CHANGED_DURING_CHECK')
        self.assertEqual((self.state/'状态.json').read_bytes(),before)

    def test_config_failure_not_logged_as_network_failure(self):
        self.config.write_bytes(b'[invalid')
        with self.assertRaises(h.Failure):h.ensure(c)
        last=json.loads((self.state/'自愈记录.jsonl').read_text().splitlines()[-1])
        self.assertEqual(last['config_action'],'BLOCKED')
        self.assertNotIn('health_status',last)

    def test_unowned_listener_does_not_receive_credential(self):
        c.core().tunnel_running.return_value=False
        with self.assertRaises(h.Failure) as ex:h.ensure(c)
        self.assertEqual(ex.exception.reason,'TUNNEL_PORT_CONFLICT');self.health.assert_not_called()

    def test_backup_preparation_failure_leaves_no_poison_journal(self):
        self.config.write_bytes(self.original)
        write=c.core().atomic_write
        def fail(path,data,*args):
            if str(path).endswith('.bak'):raise OSError()
            write(path,data,*args)
        with mock.patch.object(c.core(),'atomic_write',side_effect=fail):
            with self.assertRaises(h.Failure):h.ensure(c)
        h.ensure(c);self.assertEqual(c.validated_config()[0],'team')

    def test_real_http_classifier_and_redirect_protection(self):
        import urllib.error
        # Fetch original callable via another module, so it is not the fixture mock.
        real=load('real_http_healer',HERE/'App自愈.py')
        with mock.patch.object(c.core(),'secret',return_value='private-sentinel',create=True):
            for code,reason in [(401,'AUTH_FAILURE'),(403,'AUTH_FAILURE'),(502,'UPSTREAM_TRANSIENT'),(503,'UPSTREAM_TRANSIENT'),(504,'UPSTREAM_TRANSIENT'),(302,'HTTP_REDIRECT')]:
                opener=mock.Mock();opener.open.side_effect=urllib.error.HTTPError('http://local',code,'secret error text',{},None)
                with mock.patch.object(real.urllib.request,'build_opener',return_value=opener):
                    with self.assertRaises(real.Failure) as ex:real.health_once(c)
                    self.assertEqual(ex.exception.reason,reason)
                    self.assertNotIn('secret',str(ex.exception))
            opener=mock.Mock();opener.open.side_effect=urllib.error.URLError(ConnectionRefusedError(61,'refused'))
            with mock.patch.object(real.urllib.request,'build_opener',return_value=opener):
                with self.assertRaises(real.Failure) as ex:real.health_once(c)
                self.assertEqual(ex.exception.reason,'TUNNEL_MISSING')

    @unittest.skip('Private deployment/rollback script is excluded from the public source release')
    def test_deployment_rollback_exact_and_conflict_safe(self):
        # The original test imported a private deployment artifact, not client code.
        # Keep the test explicit without reading a local deployment directory.
        raise unittest.SkipTest('Private deployment/rollback script is not distributed')

    def test_stale_own_job_restarted_not_removed_or_replaced(self):
        from types import SimpleNamespace
        c.core().port_open.return_value=False
        c.core().tunnel_running.side_effect=[False,True]
        args=[self.settings['python'],str(self.helper),'_tunnel','--state-dir',str(self.legacy)]
        output='"ProgramArguments" = (\n'+''.join(json.dumps(x)+';\n' for x in args)+');'
        with mock.patch.object(c.core(),'label',return_value='own.label',create=True):
            with mock.patch.object(h.subprocess,'run',side_effect=[SimpleNamespace(returncode=0,stdout=output),SimpleNamespace(returncode=0)]) as run:
                h.restart_owned_job(c,self.settings)
                self.assertEqual(run.call_args_list[-1].args[0],['/bin/launchctl','start','own.label'])
        c.core().tunnel_running.side_effect=None;c.core().tunnel_running.return_value=False
        with mock.patch.object(c.core(),'label',return_value='own.label',create=True):
            with mock.patch.object(h.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=output.replace('_tunnel','other'))) as run:
                with self.assertRaises(h.Failure):h.restart_owned_job(c,self.settings)
                self.assertEqual(run.call_count,1)

    def test_proxy_subprocess_preflight_precedes_real_child_config_read(self):
        self.proxy_case(False)

    def test_proxy_subprocess_incompatible_never_spawns_child(self):
        self.proxy_case(True)

    def proxy_case(self,incompatible):
        # Separate process: real proxy + controller + healer, only network/binary
        # capabilities are fixtures. The fake app-server reads config at birth.
        code='''
import importlib.util,sys,json,os
from pathlib import Path
from unittest import mock
spec=importlib.util.spec_from_file_location('fixture',sys.argv[1]);t=importlib.util.module_from_spec(spec);sys.modules[spec.name]=t;spec.loader.exec_module(t)
case=t.HealingTests();case.setUp()
c=t.c;h=t.h
c.CONFIG.write_bytes(case.original)
marker=case.root/'child-started'
server=case.root/'fake-server'
server.write_text('#!'+sys.executable+'\\n'+"import json,tomllib,sys\\nfrom pathlib import Path\\np=tomllib.loads(Path("+repr(str(c.CONFIG))+").read_text())\\nassert p['model_providers']['sg_team']['wire_api']=='responses'\\nPath("+repr(str(marker))+").touch()\\nfor line in sys.stdin:\\n r=json.loads(line);print(json.dumps({'id':r['id'],'result':{'modelProvider':r['params']['modelProvider'],'thread':{'id':'fixture-thread'}}}),flush=True)\\n")
server.chmod(0o700)
if sys.argv[2]=='True':
 c.BINARY.write_bytes(b'incompatible');case.probe.side_effect=h.Failure('PROTOCOL_INCOMPATIBLE')
w=t.load('integration_proxy',Path(sys.argv[1]).with_name('App全局路由代理.py'))
with mock.patch.object(w,'load_controller',return_value=c):
 result=w.run_proxy(['app-server'],real_binary=str(server),controller_path=Path(sys.argv[1]),shutdown_grace=3,kill_grace=.2)
expected=sys.argv[2]!='True'
assert marker.exists()==expected, ('child marker',result)
assert result==(0 if expected else 78)
case.doCleanups()
'''
        result=subprocess.run([sys.executable,'-B','-c',code,str(Path(__file__).resolve()),str(incompatible)],
            input=b'{"id":1,"method":"thread/start","params":{}}\n',capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        if incompatible:self.assertEqual(result.stdout,b'')
        else:self.assertEqual(json.loads(result.stdout)['result']['modelProvider'],'sg_team')

class SchemaTests(unittest.TestCase):
    def fixture(self):
        defs={};requests=[];responses={}
        for name,method in [('Start','start'),('Resume','resume'),('Fork','fork')]:
            key='Thread'+name+'Params';defs[key]={'type':'object','properties':{'modelProvider':{'type':['string','null']},'threadId':{'type':'string'}},'required':[] if name=='Start' else ['threadId']}
            requests.append({'properties':{'method':{'enum':['thread/'+method]},'params':{'$ref':'#/definitions/'+key}}})
            responses['Thread'+name+'Response']={'required':['modelProvider','thread'],'properties':{'modelProvider':{'type':'string'},'thread':{'type':'object','required':['id'],'properties':{'id':{'type':'string'}}}}}
        return {'definitions':defs,'oneOf':requests},responses

    def test_required_protocol_fields_present(self):h.check_schema(*self.fixture())

    def test_missing_method_or_field_rejected(self):
        request,responses=self.fixture();request['oneOf'].pop()
        with self.assertRaises(h.Failure):h.check_schema(request,responses)

    def test_narrowed_provider_and_optional_response_rejected(self):
        request,responses=self.fixture();request['definitions']['ThreadStartParams']['properties']['modelProvider']['enum']=['openai']
        with self.assertRaises(h.Failure):h.check_schema(request,responses)
        request,responses=self.fixture();responses['ThreadForkResponse']['required'].remove('modelProvider')
        with self.assertRaises(h.Failure):h.check_schema(request,responses)
        request,responses=self.fixture();request['definitions']['ThreadStartParams']['required']=['newRequired']
        with self.assertRaises(h.Failure):h.check_schema(request,responses)
        request,responses=self.fixture();del request['definitions']['ThreadResumeParams']['properties']['modelProvider']
        with self.assertRaises(h.Failure):h.check_schema(request,responses)

if __name__=='__main__':unittest.main(verbosity=2)
