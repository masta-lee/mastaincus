#!/usr/bin/env python3
"""Seed/verify aged Raft state only on the disposable CI memory fixture."""
import hashlib
import http.client
import json
import os
import pathlib
import socket
import sys
import time

assert os.environ.get('INCUDAL_MEMORY_PRESSURE_TEST') == 'disposable'
assert sys.argv[1:] in [['seed'], ['verify']]
P = pathlib.Path
root = P('/tmp/incudal-raft-memory-fixture')


class Local(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect('/var/lib/incus/unix.socket')


def sql(query):
    c = Local('localhost')
    try:
        c.request('POST', '/internal/sql', json.dumps({'database': 'global', 'query': query}), {'Content-Type': 'application/json'})
        r = c.getresponse()
        value = json.loads(r.read())
        assert r.status == 200 and value['type'] == 'sync', 'real fixture DB write/read failed'
        return value['metadata']['Results']
    finally:
        c.close()


def process_memory():
    pid = int(P('/run/incus/incusd.pid').read_text())
    data = {}
    for line in P(f'/proc/{pid}/smaps_rollup').read_text().splitlines():
        f = line.replace(':', ' ').split()
        if len(f) > 1 and f[1].isdigit():
            data[f[0]] = int(f[1])
    return {'rssKiB': data['Rss'], 'anonymousKiB': data.get('Anonymous', 0), 'swapKiB': data.get('Swap', 0)}


def log_bytes():
    return sum(f.stat().st_size for f in P('/var/lib/incus/database/global').iterdir()
               if f.is_file() and (f.name.startswith('open-') or '-' in f.name and f.name[0].isdigit()))


payload = (b'preserve-raft-database-memory-fixture-' * 512)[:16384]
payload_hex = payload.hex()
started = time.monotonic()
if sys.argv[1] == 'seed':
    assert not root.exists(), 'fixture may be seeded only once'
    root.mkdir(mode=0o700)
    sql('CREATE TABLE incudal_memory_fixture (id INTEGER PRIMARY KEY, seq INTEGER NOT NULL, payload BLOB NOT NULL)')
    sql(f"INSERT INTO incudal_memory_fixture VALUES (1, 0, X'{payload_hex}')")
    for n in range(1, 9217):
        # Distinct writes retain real page-bearing raft entries across many
        # normal snapshot cycles, reproducing a long-lived small standalone.
        sql(f"UPDATE incudal_memory_fixture SET seq={n},payload=X'{payload_hex}' WHERE id=1")
    result = {'seq': 9216, 'sha256': hashlib.sha256(payload).hexdigest(), 'logBytes': log_bytes(),
              'memory': process_memory(), 'seconds': round(time.monotonic()-started, 2)}
    (root/'before.json').write_text(json.dumps(result))
    print('AGED_RAFT_BEFORE:'+json.dumps(result), flush=True)
else:
    before = json.loads((root/'before.json').read_text())
    rows = sql('SELECT seq,hex(payload) FROM incudal_memory_fixture WHERE id=1')[0]['rows']
    assert rows == [[before['seq'], payload_hex.upper()]], 'committed aged data lost on daemon reload'
    for n in range(9217, 10242):
        sql(f"UPDATE incudal_memory_fixture SET seq={n},payload=X'{payload_hex}' WHERE id=1")
    deadline = time.monotonic()+40
    while time.monotonic() < deadline:
        if log_bytes() < before['logBytes'] / 2:
            break
        time.sleep(1)
    rows = sql('SELECT seq,hex(payload) FROM incudal_memory_fixture WHERE id=1')[0]['rows']
    assert rows == [[10241, payload_hex.upper()]], 'committed data lost during normal compaction'
    result = {'seq': 10241, 'logBytes': log_bytes(), 'memory': process_memory(), 'seconds': round(time.monotonic()-started,2)}
    assert result['logBytes'] < before['logBytes']/2, 'standalone normal raft compaction did not reduce retained logs'
    (root/'after.json').write_text(json.dumps(result))
    print('AGED_RAFT_AFTER:'+json.dumps(result), flush=True)
