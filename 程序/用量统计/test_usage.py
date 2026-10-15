import contextlib
import datetime as dt
from decimal import Decimal
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from importlib.machinery import SourceFileLoader

spec = importlib.util.spec_from_file_location('usage', Path(__file__).with_name('usage.py'))
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)
shell_loader = SourceFileLoader('query_shell', str(Path(__file__).with_name('sysu-query-shell')))
shell_spec = importlib.util.spec_from_loader(shell_loader.name, shell_loader)
query_shell = importlib.util.module_from_spec(shell_spec)
shell_loader.exec_module(query_shell)


def event(key='fake-a', **changes):
    r = {'timestamp': '2026-09-09T12:00:00+08:00', 'api_key': key, 'model': 'test-model',
         'tokens': dict(input_tokens=100, output_tokens=20, cached_tokens=80,
                        reasoning_tokens=10, total_tokens=120),
         'token_breakdown': {'quality': 'complete'}, 'failed': False,
         'fail': {'body': 'PRIVATE_BODY'}, 'response_headers': {'X': 'PRIVATE_HEADER'}}
    r.update(changes)
    return r


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name)
        self.con = u.connect(self.state)

    def tearDown(self):
        self.con.close()
        self.temp.cleanup()

    def test_separate_people_and_no_double_count(self):
        self.assertEqual(u.ingest(self.con, [event(), event('fake-b')], {'fake-a': 'alice', 'fake-b': 'bob'}), (2, 0))
        self.assertEqual(self.con.execute('SELECT person,total_tokens FROM events ORDER BY person').fetchall(), [('alice', 120), ('bob', 120)])

    def test_duplicate_is_not_recounted(self):
        self.assertEqual(u.ingest(self.con, [event(), event()], {'fake-a': 'alice'}), (1, 0))

    def test_no_sensitive_payload_persisted(self):
        u.ingest(self.con, [event()], {'fake-a': 'alice'})
        dump = '\n'.join(self.con.iterdump())
        for secret in ['fake-a', 'PRIVATE_BODY', 'PRIVATE_HEADER', 'api_key']:
            self.assertNotIn(secret, dump)

    def test_survives_reopen(self):
        u.ingest(self.con, [event()], {'fake-a': 'alice'})
        other = u.connect(self.state)
        self.assertEqual(other.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)
        other.close()

    def test_malformed_is_counted_and_not_fabricated(self):
        self.assertEqual(u.ingest(self.con, [{'bad': 1}], {}), (0, 1))
        self.assertEqual(self.con.execute("SELECT value FROM metadata WHERE name='rejected_events'").fetchone()[0], '1')

    def test_unknown_key_not_attributed_to_owner(self):
        self.assertEqual(u.normalize(event(), {})[2], 'unknown')

    def test_negative_and_missing_tokens_rejected(self):
        for tokens in [{}, dict(input_tokens=-1, output_tokens=0, cached_tokens=0, reasoning_tokens=0, total_tokens=0)]:
            with self.assertRaises(ValueError):
                u.normalize(event(tokens=tokens), {})

    def test_subsets_flagged_if_inconsistent(self):
        tokens = dict(input_tokens=100, output_tokens=20, cached_tokens=101, reasoning_tokens=10, total_tokens=120)
        self.assertEqual(u.normalize(event(tokens=tokens), {})[-1], 'inconsistent')

    def test_terminal_escape_sanitized(self):
        self.assertNotIn('\x1b', u.normalize(event(model='\x1b[2J'), {})[3])

    def test_calendar_boundaries_beijing(self):
        now = dt.datetime(2026, 9, 21, 9, tzinfo=u.TZ)
        bounds = u.bounds(now, state=self.state)
        self.assertEqual(bounds[0][1].isoformat(), '2026-09-21T00:00:00+08:00')
        self.assertEqual(bounds[1][1].isoformat(), '2026-09-20T17:20:00+08:00')
        start, end = u.subscription_window(now, state=self.state)
        self.assertEqual(start.isoformat(), '2026-09-20T17:20:00+08:00')
        self.assertEqual(end.isoformat(), '2026-09-27T17:20:00+08:00')

    def test_reset_state_overrides_fallback_and_rolls_weekly(self):
        reset_dir = self.state / 'reset-state'
        reset_dir.mkdir()
        reset_at = int(dt.datetime(2026, 10, 1, 12, tzinfo=u.TZ).timestamp())
        (reset_dir / 'weekly.json').write_text(json.dumps({'reset_at': reset_at}))
        start, end = u.subscription_window(
            dt.datetime(2026, 10, 2, 9, tzinfo=u.TZ), state=self.state
        )
        self.assertEqual(start.isoformat(), '2026-10-01T12:00:00+08:00')
        self.assertEqual(end.isoformat(), '2026-10-08T12:00:00+08:00')

    def test_invalid_reset_state_fails_closed_to_confirmed_anchor(self):
        reset_dir = self.state / 'reset-state'
        reset_dir.mkdir()
        (reset_dir / 'weekly.json').write_text('{bad json')
        _, end = u.subscription_window(
            dt.datetime(2026, 9, 21, 9, tzinfo=u.TZ), state=self.state
        )
        self.assertEqual(end.isoformat(), '2026-09-27T17:20:00+08:00')

    def test_person_report_isolation(self):
        u.ingest(self.con, [event(), event('fake-b')], {'fake-a': 'alice', 'fake-b': 'bob'})
        output = io.StringIO()
        with patch.object(u, 'identities', return_value={'fake-a': 'alice', 'fake-b': 'bob'}), contextlib.redirect_stdout(output):
            u.report('alice', self.state, dt.datetime(2026, 9, 9, 20, tzinfo=u.TZ))
        self.assertIn('Codex 用量：alice', output.getvalue())
        self.assertNotIn('Codex 用量：bob', output.getvalue())
        self.assertIn('输入 100 / 输出 20 / 缓存 80 / 推理 10', output.getvalue())

    def test_failed_event_and_incomplete_accounting_visible(self):
        r = event(failed=True, token_breakdown={})
        u.ingest(self.con, [r], {})
        self.assertEqual(self.con.execute('SELECT failed,quality FROM events').fetchone(), (1, 'unclassified'))

    def test_forced_query_exact_command_only(self):
        self.assertTrue(query_shell.allowed(['-c','sysu-usage-query'],'share-codex-usage'))
        self.assertTrue(query_shell.allowed(['--query'],None))
        for command in ['id', 'sh', 'bash', 'share-codex-usage bob', 'share-codex-usage; id', 'share-codex-usage\nid', 'internal-sftp', '', None]:
            self.assertFalse(query_shell.allowed(['-c','sysu-usage-query'],command))
        self.assertFalse(query_shell.allowed([],None))
        self.assertFalse(query_shell.allowed(['-c','id'],'share-codex-usage'))

    def test_query_uses_kernel_identity_not_client_input(self):
        class Connection:
            data=b''
            def settimeout(self, value): pass
            def sendall(self, data): self.data += data
            def recv(self, size): raise AssertionError('must not read a supplied username')
        c=Connection()
        with patch.object(u,'peer_person',return_value='alice'), patch.object(u,'user_report',return_value=b'alice report') as report:
            u.handle_query(c,self.state)
        report.assert_called_once_with('alice',self.state)
        self.assertEqual(c.data,b'alice report')

    def test_self_report_isolated_and_does_not_print_globally(self):
        clients=self.state/'clients';clients.mkdir();(clients/'alice.token').touch()
        u.ingest(self.con,[event(),event('fake-b')],{'fake-a':'alice','fake-b':'bob'})
        captured=io.StringIO()
        with patch.object(u,'CLIENTS',clients), patch.object(u,'identities',return_value={'fake-a':'alice','fake-b':'bob'}), contextlib.redirect_stdout(captured):
            text=u.user_report('alice',self.state).decode()
        self.assertIn('Codex 用量：alice',text)
        self.assertNotIn('Codex 用量：bob',text)
        self.assertEqual(captured.getvalue(),'')

    def test_unknown_or_inactive_member_rejected(self):
        clients=self.state/'clients';clients.mkdir();(clients/'alice.token').touch()
        with patch.object(u,'CLIENTS',clients), patch.object(u,'identities',return_value={}):
            for user in ['alice','bob','owner','../../etc/passwd']:
                with self.assertRaises(PermissionError):u.user_report(user,self.state)

    def test_reference_cost_cache_is_not_billed_as_uncached(self):
        cost, fallback = u.reference_cost('gpt-6-astra', 1000000, 100000, 800000)
        self.assertEqual(cost, Decimal('7.8') * Decimal('2000') / Decimal('1463'))
        self.assertFalse(fallback)

    def test_known_prices_snapshot(self):
        for model, expected in [('gpt-6-sol','12'),('gpt-6-luna','0.6'),
                                ('gpt-5.6-sol','24'),('gpt-5.6-terra','14'),
                                ('gpt-5.6-luna','1.4'),('gpt-5.5','35')]:
            cost, fallback=u.reference_cost(model,1000000,1000000,0)
            self.assertEqual(cost,u.normalize_cycle_cost(model,Decimal(expected)))
            self.assertFalse(fallback)

    def test_radar_calibration_is_separate_from_official_api_price(self):
        self.assertEqual(u.MODEL_CYCLE_RADAR_USD['gpt-6-astra'],Decimal('1463.00'))
        self.assertEqual(u.MODEL_CYCLE_RADAR_USD['gpt-6-sol'],Decimal('1232.00'))
        self.assertEqual(u.MODEL_CYCLE_RADAR_USD['gpt-5.6-sol'],Decimal('1919.83'))
        self.assertEqual(u.MODEL_CYCLE_RADAR_USD['gpt-5.6-luna'],Decimal('1145.10'))
        self.assertEqual(u.DEFAULT_CYCLE_RADAR_USD,u.MODEL_CYCLE_RADAR_USD['gpt-5.6-sol'])

    def test_unknown_model_fallback_retained_without_display_marker(self):
        cost,fallback=u.reference_cost('codex-auto-review',1000000,100000,800000)
        self.assertEqual(cost,u.normalize_cycle_cost('codex-auto-review',Decimal('4.4')))
        self.assertTrue(fallback)
        lines, defaults, invalid=u.cost_table([('codex-auto-review',1,0,1000000,100000,800000,50000,1100000,0)])
        self.assertEqual(defaults,['codex-auto-review'])
        self.assertIn('$4.58','\n'.join(lines))
        self.assertNotIn('*','\n'.join(lines))
        self.assertFalse(invalid)

    def test_empty_cost_table_zero(self):
        lines,defaults,invalid=u.cost_table([])
        self.assertIn('$0.00',lines[-1])
        self.assertFalse(defaults or invalid)

    def test_cost_total_rounds_only_after_summing(self):
        rows=[('gpt-6-astra',1,0,400,0,0,0,400,0)]*3
        lines,_,_=u.cost_table(rows)
        self.assertIn('$0.02',lines[-1])
        self.assertIn('1,200',lines[-1])

    def test_invalid_cost_is_not_silently_zero(self):
        rows=[('gpt-6-astra',1,0,100,10,101,0,110,1)]
        lines,_,invalid=u.cost_table(rows)
        self.assertTrue(invalid)
        self.assertTrue(any('--' in line and 'gpt-6-astra' in line for line in lines))
        self.assertIn('$0.00+',lines[-1])

    def test_report_format_has_cost_without_request_or_budget_columns(self):
        u.ingest(self.con,[event(model='gpt-6-astra')],{'fake-a':'alice'})
        output=io.StringIO()
        with patch.object(u,'identities',return_value={'fake-a':'alice'}):
            u.report('alice',self.state,dt.datetime(2026,9,9,20,tzinfo=u.TZ),output=output)
        text=output.getvalue()
        self.assertTrue(text.startswith('Codex 用量：alice\n'))
        self.assertEqual(text.count('Cost'),2)  # Only the two table headers.
        self.assertNotIn('Requests',text)
        self.assertNotIn('Failed',text)
        self.assertNotIn('2000',text)
        self.assertIn('订阅下次刷新时间：2026-09-13 17:20（北京时间）',text)
        self.assertIn('本周  2026-09-06 17:20',text)
        self.assertNotIn('北京时间／自然周',text)
        self.assertNotIn('统计自',text)
        self.assertNotIn('非实际扣费',text)

    def test_no_price_footnote_and_reasoning_not_counted_twice(self):
        u.ingest(self.con,[event(model='codex-auto-review',tokens=dict(input_tokens=1000000,output_tokens=100000,cached_tokens=800000,reasoning_tokens=50000,total_tokens=1100000))],{'fake-a':'alice'})
        output=io.StringIO()
        with patch.object(u,'identities',return_value={'fake-a':'alice'}):
            u.report('alice',self.state,dt.datetime(2026,9,9,20,tzinfo=u.TZ),output=output)
        self.assertIn('$4.58',output.getvalue())
        self.assertNotIn('*',output.getvalue())
        self.assertNotIn('默认参考价',output.getvalue())
        self.assertIn('Token 明细',output.getvalue())

    def test_compact_columns_and_currency_decimal_alignment(self):
        rows=[('gpt-6-astra',1,0,1000000,100000,800000,50000,1100000,0),
              ('codex-auto-review',1,0,1000000,100000,800000,50000,1100000,0)]
        lines,_,_=u.cost_table(rows)
        data=[line for line in lines if line.startswith(('gpt-6-astra','codex-auto-review','TOTAL'))]
        self.assertEqual(len({line.index('.') for line in data}),1)
        self.assertEqual(lines[0].index('Tokens'),29)
        self.assertEqual(len(lines[0]),46)
        self.assertEqual(lines[1].count('  '),2)

    def test_very_large_totals_expand_without_truncation(self):
        tokens=10**19
        lines,_,_=u.cost_table([('long-model-name-that-exceeds-minimum',1,0,tokens,0,0,0,tokens,0)])
        self.assertIn(f'{tokens:,}',lines[-1])
        self.assertIn('long-model-name-that-exceeds-minimum',lines[2])


if __name__ == '__main__':
    unittest.main()
