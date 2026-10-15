#!/usr/bin/env python3
"""Local-only relay usage collector and administrator report; no request content stored."""
import argparse
import datetime as dt
from decimal import Decimal
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import sqlite3
import struct
import sys
import threading
import time
import urllib.request
from zoneinfo import ZoneInfo

STATE = Path('/var/lib/sysu-usage')
CONFIG = Path('/etc/cliproxyapi/config.yaml')
CLIENTS = Path('/etc/cliproxyapi/team-clients')
TZ = ZoneInfo('Asia/Shanghai')
FIELDS = ('input_tokens', 'output_tokens', 'cached_tokens', 'reasoning_tokens', 'total_tokens')
QUERY_SOCKET = Path('/run/sysu-usage-query/query.sock')
RESET_STATE_RELATIVE = Path('reset-state/weekly.json')
WEEK = dt.timedelta(days=7)
# Example Pro reset: 2026-09-20 17:20 Asia/Shanghai. The state file stores
# the *next* reset, matching the reference server's rolling-window convention.
DEFAULT_NEXT_RESET = dt.datetime(2026, 9, 27, 17, 20, tzinfo=TZ)

# Internal comparison, NOT a bill or a conversion of Pro subscription limits.
# Snapshot: https://developers.openai.com/api/docs/pricing/ (2026-09-27),
# Standard short-context input / output / cached-input dollars per million.
REFERENCE_PRICES = {
    'gpt-6-astra': ('10', '50', '1'),
    'gpt-6-sol': ('2', '10', '0.2'),
    'gpt-6-luna': ('0.1', '0.5', '0.01'),
    'gpt-5.6-sol': ('4', '20', '0.4'),
    'gpt-5.6-terra': ('2', '12', '0.2'),
    'gpt-5.6-luna': ('0.2', '1.2', '0.02'),
    'gpt-5.5': ('5', '30', '0.5'),
}
# Same explicitly labelled fallback convention observed in the reference report.
# This is NOT an official rate or a verified price for codex-auto-review.
DEFAULT_REFERENCE_PRICE = ('5', '30', '0.5')

# Map API-price reference costs to one shared $2,000 reporting scale.
# Radar values are user-provided 20x Pro single-model references, not official
# API prices or a claim about the actual subscription balance.
UNIFIED_CYCLE_USD = Decimal('2000')
MODEL_CYCLE_RADAR_USD = {
    'gpt-6-astra': Decimal('1463.00'),
    'gpt-6-sol': Decimal('1232.00'),
    'gpt-5.6-sol': Decimal('1919.83'),
    'gpt-5.6-luna': Decimal('1145.10'),
}
# Models without a measured radar value use the GPT-5.6 Sol calibration until
# a direct comparison is available (including GPT-6 Luna and auto-review).
DEFAULT_CYCLE_RADAR_USD = MODEL_CYCLE_RADAR_USD['gpt-5.6-sol']


def normalize_cycle_cost(model, amount):
    radar = MODEL_CYCLE_RADAR_USD.get(model, DEFAULT_CYCLE_RADAR_USD)
    return amount * UNIFIED_CYCLE_USD / radar


def reference_cost(model, input_tokens, output_tokens, cached_tokens):
    prices = REFERENCE_PRICES.get(model, DEFAULT_REFERENCE_PRICE)
    prompt, completion, cache = map(Decimal, prices)
    if min(input_tokens, output_tokens, cached_tokens) < 0 or cached_tokens > input_tokens:
        return None, model not in REFERENCE_PRICES
    reference = (Decimal(input_tokens - cached_tokens) * prompt +
                 Decimal(output_tokens) * completion + Decimal(cached_tokens) * cache) / Decimal(1000000)
    return normalize_cycle_cost(model, reference), model not in REFERENCE_PRICES


def cost_table(rows):
    """Render only Model/Tokens/Cost; keep full precision until presentation."""
    result = []
    total = Decimal(0)
    defaults = []
    invalid = False
    for row in rows:
        amount, fallback = reference_cost(row[0], row[3], row[4], row[5])
        if fallback:
            defaults.append(row[0])
        if amount is None:
            invalid = True
        else:
            total += amount
        result.append((row[0], f'{row[7]:,}', '--' if amount is None else f'${amount:.2f}', ''))
    result.append(('TOTAL', f'{sum(row[7] for row in rows):,}',
                   f'${total:.2f}', '+' if invalid else ''))
    header = ('Model', 'Tokens', 'Cost', '')
    # Keep compact column widths; the data-error marker has a separate gutter.
    minimum = (20, 13, 9)
    widths = [max(minimum[i], *(len(row[i]) for row in result)) for i in range(3)]
    def line(row):
        return f'{row[0]:<{widths[0]}}  {row[1]:>{widths[1]}}  {row[2]:>{widths[2]}}{row[3]}'
    separator = '  '.join('-' * width for width in widths)
    lines = [line(header), separator, *(line(row) for row in result[:-1]), separator, line(result[-1])]
    return lines, sorted(set(defaults)), invalid


def connect(state=STATE):
    con = sqlite3.connect(state / 'usage.sqlite3', timeout=15)
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA synchronous=FULL')
    con.executescript('''
      CREATE TABLE IF NOT EXISTS events (
        event_id TEXT PRIMARY KEY, timestamp REAL NOT NULL, person TEXT NOT NULL,
        model TEXT NOT NULL, input_tokens INTEGER NOT NULL, output_tokens INTEGER NOT NULL,
        cached_tokens INTEGER NOT NULL, reasoning_tokens INTEGER NOT NULL,
        total_tokens INTEGER NOT NULL, failed INTEGER NOT NULL, quality TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS events_time_person ON events(timestamp,person);
      CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
    ''')
    with con:
        con.execute('INSERT OR IGNORE INTO metadata VALUES (?,?)', ('started_at', str(time.time())))
    return con


def meta(con, key, value):
    con.execute('INSERT OR REPLACE INTO metadata VALUES (?,?)', (key, str(value)))


def identities(config=CONFIG, clients=CLIENTS):
    import yaml
    keys = yaml.safe_load(config.read_text()).get('api-keys', [])
    result = {}
    for path in sorted(clients.glob('*.token')):
        name = path.stem
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', name):
            continue
        key = path.read_text().strip()
        if key not in keys:
            continue
        if key in result:
            raise ValueError('multiple people share a key; attribution ambiguous')
        result[key] = name
    remaining = [key for key in keys if key not in result]
    for i, key in enumerate(remaining, 1):
        result[key] = 'owner' if len(remaining) == 1 else 'unassigned_' + str(i)
    return result


def clean_label(value):
    return re.sub(r'[^A-Za-z0-9._:/-]', '?', str(value))[:100] or 'unknown'


def normalize(record, people):
    if not isinstance(record, dict) or 'timestamp' not in record or 'tokens' not in record:
        raise ValueError('invalid usage event')
    timestamp = dt.datetime.fromisoformat(record['timestamp'].replace('Z', '+00:00'))
    if timestamp.tzinfo is None:
        raise ValueError('timestamp missing timezone')
    tokens = record['tokens']
    values = []
    for field in FIELDS:
        n = tokens.get(field)
        if type(n) is not int or n < 0 or n > 2**62:
            raise ValueError('invalid token count')
        values.append(n)
    quality = record.get('token_breakdown', {}).get('quality', 'unclassified')
    if quality not in ('complete', 'inconsistent', 'unclassified'):
        quality = 'unclassified'
    # Cache is a subset of input, reasoning a subset of output for Codex.
    # Preserve upstream total; never add those subsets again.
    if values[4] != values[0] + values[1] or values[2] > values[0] or values[3] > values[1]:
        quality = 'inconsistent'
    event_id = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return (event_id, timestamp.timestamp(), people.get(record.get('api_key'), 'unknown'),
            clean_label(record.get('model', 'unknown')), *values,
            int(bool(record.get('failed'))), quality)


def ingest(con, records, people):
    accepted = rejected = 0
    with con:
        for record in records:
            try:
                row = normalize(record, people)
            except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
                rejected += 1
                continue
            cur = con.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)', row)
            accepted += cur.rowcount
        if rejected:
            old = con.execute('SELECT value FROM metadata WHERE name=?', ('rejected_events',)).fetchone()
            meta(con, 'rejected_events', int(old[0] if old else 0) + rejected)
        meta(con, 'last_poll', time.time())
        meta(con, 'last_error', '')
    return accepted, rejected


def management(path, state=STATE):
    secret = (state / 'management.token').read_text().strip()
    request = urllib.request.Request('http://127.0.0.1:8317/v0/management/' + path,
                                     headers={'Authorization': 'Bearer ' + secret})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=10) as response:
        return json.load(response)


def collect(state=STATE):
    os.umask(0o077)
    lock = (state / 'collector.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    con = connect(state)
    start_query_server(state=state)
    print('Team usage collector started (no prompt/content logging)', flush=True)
    while True:
        try:
            # Check mapping and storage BEFORE consuming the destructive queue.
            people = identities()
            with con:
                meta(con, 'heartbeat', time.time())
            records = management('usage-queue?count=200', state)
            if not isinstance(records, list):
                raise ValueError('unexpected queue shape')
            ingest(con, records, people)
            if len(records) == 200:
                continue
        except Exception as exc:
            # Never log a URL, HTTP body, key or raw usage event.
            kind = type(exc).__name__
            with con:
                meta(con, 'last_error', kind)
                meta(con, 'last_error_at', time.time())
            print('Collection error: ' + kind, flush=True)
        time.sleep(5)


def subscription_window(now, state=STATE):
    end = DEFAULT_NEXT_RESET
    try:
        payload = json.loads((state / RESET_STATE_RELATIVE).read_text())
        stamp = payload['reset_at']
        if type(stamp) is not int or not 0 < stamp < 253402300799:
            raise ValueError('invalid reset timestamp')
        end = dt.datetime.fromtimestamp(stamp, TZ)
    except (OSError, ValueError, KeyError, TypeError, OverflowError, json.JSONDecodeError):
        pass
    while now >= end:
        end += WEEK
    while now < end - WEEK:
        end -= WEEK
    return end - WEEK, end


def bounds(now, state=STATE):
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    cycle_start, _ = subscription_window(now, state=state)
    return [('今天', today), ('本周', cycle_start)]


def report(person=None, state=STATE, now=None, output=None):
    # A per-call output target keeps concurrent user reports isolated from stdout.
    import builtins
    def print(*args, **kwargs):
        builtins.print(*args, file=output, **kwargs)
    now = now or dt.datetime.now(TZ)
    if not (state / 'usage.sqlite3').exists():
        raise SystemExit('统计数据库尚未建立。')
    con = sqlite3.connect('file:' + str(state / 'usage.sqlite3') + '?mode=ro', uri=True, timeout=15)
    metadata = dict(con.execute('SELECT name,value FROM metadata'))
    names = sorted(set(identities().values()) | {r[0] for r in con.execute('SELECT DISTINCT person FROM events')})
    if person:
        if person not in names:
            raise SystemExit('未知用户名；可选：' + ', '.join(names))
        names = [person]
    last = float(metadata.get('last_poll', '0'))
    _, cycle_end = subscription_window(now, state=state)
    for name in names:
        print('Codex 用量：' + name)
        print('\n订阅下次刷新时间：' + cycle_end.strftime('%Y-%m-%d %H:%M') + '（北京时间）')
        for label, start in bounds(now, state=state):
            print('\n' + label + '  ' + start.strftime('%Y-%m-%d %H:%M') + ' ～ ' + now.strftime('%Y-%m-%d %H:%M'))
            rows = con.execute('''SELECT model,COUNT(*),SUM(failed),SUM(input_tokens),SUM(output_tokens),
                SUM(cached_tokens),SUM(reasoning_tokens),SUM(total_tokens),
                SUM(CASE WHEN quality != 'complete' THEN 1 ELSE 0 END)
                FROM events WHERE person=? AND timestamp>=? AND timestamp<=? GROUP BY model
                ORDER BY SUM(total_tokens) DESC''', (name, start.timestamp(), now.timestamp())).fetchall()
            lines, defaults, invalid = cost_table(rows)
            for line in lines:
                print(line)
            sums = [sum(r[i] for r in rows) for i in range(1, 9)]
            print(f'Token 明细：输入 {sums[2]:,} / 输出 {sums[3]:,} / 缓存 {sums[4]:,} / 推理 {sums[5]:,}')
            if invalid:
                print('+ 部分 Token 数据异常，无法折算；TOTAL 仅含可折算部分，非完整金额。')
            if sums[7]:
                print(f'注意：{sums[7]} 条事件的 Token 分类不完整或不一致。')
        print()
    if now.timestamp() - last > 30 or metadata.get('last_error'):
        print('警告：采集延迟或异常，当前统计可能不完整。')
    if int(metadata.get('rejected_events', '0')):
        print('警告：格式异常未计入事件数：' + metadata['rejected_events'])
    con.close()


def peer_person(conn):
    """Linux supplies the connecting process UID; no username is accepted from input."""
    _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
    if uid < 1000:
        raise PermissionError('non-member identity')
    return pwd.getpwuid(uid).pw_name


def user_report(person, state=STATE):
    import io
    # Must be an explicitly provisioned member, not an unassigned/admin key label.
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,30}', person) or not (CLIENTS / (person + '.token')).is_file():
        raise PermissionError('not a provisioned member')
    if person not in identities().values():
        raise PermissionError('inactive member')
    output = io.StringIO()
    report(person, state=state, output=output)
    return output.getvalue().encode('utf-8')


def handle_query(conn, state=STATE):
    conn.settimeout(5)
    try:
        data = user_report(peer_person(conn), state)
        if len(data) > 256 * 1024:
            raise ValueError('report size limit')
        conn.sendall(data)
    except (PermissionError, KeyError):
        conn.sendall('查询被拒绝：当前系统身份没有个人用量权限。\n'.encode())
    except Exception:
        conn.sendall('个人用量暂时无法查询，请联系管理员；未输出其他账号信息。\n'.encode())


def start_query_server(path=QUERY_SOCKET, state=STATE):
    # systemd owns/cleans RuntimeDirectory. Never replace an unknown preexisting path.
    if path.exists() or path.is_symlink() or path.parent.is_symlink():
        raise RuntimeError('query socket path not clean')
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    # World-connectable socket, but each request is bound to the kernel peer UID.
    os.chmod(path, 0o666)
    listener.listen(16)
    def serve():
        while True:
            conn, _ = listener.accept()
            with conn:
                try:
                    handle_query(conn, state)
                except OSError:
                    pass
    threading.Thread(target=serve, daemon=True, name='private-usage-query').start()
    return listener


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--collect', action='store_true')
    parser.add_argument('person', nargs='?')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('此命令仅供服务器管理员查询；不改变队友隧道权限。')
    if args.collect:
        collect()
    else:
        report(args.person)
