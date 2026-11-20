#!/usr/bin/env python3
"""Verify compacted Raft recovery only in the disposable memory fixture."""
import hashlib
import json
import os
import pathlib
import shutil
import signal
import subprocess
import time

P = pathlib.Path
assert os.environ.get('INCUDAL_MEMORY_PRESSURE_TEST') == 'disposable'
assert not P('/etc/incudal-onboarding-id').exists()
root = P('/tmp/incudal-raft-memory-fixture')
assert (root / 'after.json').is_file()
assert json.loads(subprocess.check_output(['incus', 'list', '--all-projects', '--format=json'])) == []


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for data in iter(lambda: f.read(32768), b''):
            h.update(data)
    return h.hexdigest()


def state(pid):
    try:
        text = P(f'/proc/{pid}/stat').read_text()
        fields = text[text.rfind(') ') + 2:].split()
        return fields[0], fields[19]
    except FileNotFoundError:
        return None


def stop(crash=False):
    pid = int(P('/run/incus/incusd.pid').read_text())
    before = state(pid)
    assert pid > 1 and before and before[0] != 'Z'
    assert os.readlink(f'/proc/{pid}/exe') == '/usr/sbin/incusd'
    if crash:
        os.kill(pid, signal.SIGKILL)
    else:
        subprocess.run(['rc-service', 'incusd', 'quit'], check=True, timeout=20)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        current = state(pid)
        if current is None or current[0] == 'Z' or current[1] != before[1]:
            return
        time.sleep(.5)
    raise RuntimeError('Exact original fixture daemon did not exit')


def start(expected):
    assert sha('/usr/sbin/incusd') == expected
    subprocess.run(['rc-service', 'incusd', 'zap'], check=True, timeout=10)
    subprocess.run(['rc-service', 'incusd', 'start'], check=True, timeout=20)
    subprocess.run(['incus', 'admin', 'waitready', '--timeout=60'], check=True, timeout=65)
    pid = int(P('/run/incus/incusd.pid').read_text())
    assert state(pid)[0] != 'Z' and sha(f'/proc/{pid}/exe') == expected


def replace(source, target):
    temporary = target.with_name(target.name + '.fixture-recovery')
    assert not temporary.exists() and target.is_file() and not target.is_symlink()
    shutil.copy2(source, temporary)
    temporary.replace(target)


def verify(stage):
    # Execute the real internal SQL API and check the entire committed payload.
    result = subprocess.check_output(['incus', 'admin', 'sql', 'global', '--format=json',
                                     'SELECT seq,hex(payload) FROM incudal_memory_fixture WHERE id=1'], text=True, timeout=15)
    rows = json.loads(result)['rows']
    payload = (b'preserve-raft-database-memory-fixture-' * 512)[:16384]
    assert rows == [[10241, payload.hex().upper()]], stage + ': committed fixture data changed'
    print('RAFT_RECOVERY:' + json.dumps({'stage': stage, 'seq': rows[0][0],
                                       'payloadSha256': hashlib.sha256(bytes.fromhex(rows[0][1])).hexdigest()}), flush=True)


binary = P('/usr/sbin/incusd')
saved = root / 'compacted-daemon'
shutil.copy2(binary, saved)
new_hash = sha(saved)
journal = json.loads(P('/var/lib/incudal-agent/incus-compat.json').read_text())
old = P('/usr/sbin/incusd.incudal-before-sysinfo')
assert sha(old) == journal['OldHash'] and new_hash == journal['NewHash']
metadata = None
saved_metadata = None
try:
    stop()
    start(new_hash)
    verify('graceful-reopen')
    stop()
    replace(old, binary)
    start(journal['OldHash'])
    verify('old-daemon-rollback')
    stop()
    replace(saved, binary)
    start(new_hash)
    verify('new-daemon-after-rollback')
    stop(crash=True)
    start(new_hash)
    verify('abrupt-process-reopen')
    stop()
    snapshots = sorted(P('/var/lib/incus/database/global').glob('snapshot-*.meta'),
                       key=lambda p: tuple(map(int, p.name[:-5].split('-')[1:])))
    assert len(snapshots) >= 2, 'second-last recovery snapshot missing'
    metadata = snapshots[-1]
    saved_metadata = root / 'latest-snapshot.meta'
    shutil.copy2(metadata, saved_metadata)
    corrupted = bytearray(metadata.read_bytes())
    assert len(corrupted) >= 32
    corrupted[8] ^= 1  # A real metadata checksum failure; no log files removed.
    metadata.write_bytes(corrupted)
    start(new_hash)
    verify('previous-snapshot-fallback')
finally:
    # Leave the fixture on the candidate with original snapshot bytes. This
    # cleanup never runs on a customer host or changes real production data.
    if P('/run/incus/incusd.pid').exists():
        pid = int(P('/run/incus/incusd.pid').read_text())
        if state(pid) and state(pid)[0] != 'Z':
            stop()
    if metadata and saved_metadata:
        replace(saved_metadata, metadata)
    replace(saved, binary)
    start(new_hash)
verify('restored-fixture')
