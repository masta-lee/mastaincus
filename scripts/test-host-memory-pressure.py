#!/usr/bin/env python3
"""Disposable cgroup pressure test, never a production repair command."""
import hashlib
import hmac
import http.server
import json
import os
import pathlib
import secrets
import subprocess
import threading
import time

P = pathlib.Path
assert os.environ.get('INCUDAL_MEMORY_PRESSURE_TEST') == 'disposable'
assert P('/out/incudal-agent').is_file() and not P('/etc/incudal-onboarding-id').exists()
budget_group = P('/sys/fs/cgroup/incudal-memory-fixture')
assert os.environ.get('INCUDAL_MEMORY_CGROUP') == str(budget_group)
assert int((budget_group / 'memory.max').read_text()) == 966 * 1024 * 1024
assert json.loads(subprocess.check_output(['incus', 'list', '--format=json'])) == []
root = P('/tmp/host-memory-pressure')
root.mkdir(mode=0o700)
secret = secrets.token_hex(32)
nonces = set()
receipts = []
guest = None


def incus(*args, timeout=30):
    try:
        return subprocess.check_output(['incus', *args], text=True, timeout=timeout)
    except subprocess.CalledProcessError:
        # Disposable logs only, preserve native launch errors before teardown.
        if args and args[0] in ['start', 'restart', 'rebuild']:
            subprocess.run(['incus', 'info', '--show-log', 'memory-customer'], timeout=10)
            print('FIXTURE_CGROUP:'+P('/proc/self/cgroup').read_text(), flush=True)
            print('FIXTURE_CONTROLLERS:'+P('/sys/fs/cgroup/cgroup.controllers').read_text(), flush=True)
        raise


def query(path):
    return json.loads(incus('query', path))


class Panel(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            assert self.path == '/api/agent/heartbeat'
            size = int(self.headers['content-length'])
            assert 0 < size < 1024 * 1024
            data = self.rfile.read(size)
            payload = json.loads(data)
            canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
            digest = hashlib.sha256(canonical).hexdigest()
            stamp, nonce = self.headers['x-incudal-timestamp'], self.headers['x-incudal-nonce']
            assert abs(time.time() * 1000 - int(stamp)) < 30000
            assert nonce not in nonces and digest == self.headers['x-incudal-body-sha256']
            signed = '\n'.join(['POST', self.path, stamp, nonce, digest]).encode()
            assert hmac.compare_digest(hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest(), self.headers['x-incudal-signature'])
            nonces.add(nonce)
            receipts.append({'at': time.monotonic(), 'tools': payload.get('hostProvisioningStatus', {}),
                             'resources': payload.get('resources', {}), 'protection': payload.get('guestProtectionStatus', {})})
            response = {'poolHostBbr': True, 'resourceGuests': []}
            if guest:
                response['resourceGuests'] = [{'name': 'memory-customer', 'uuid': guest['config']['volatile.uuid'], 'memoryMiB': 768}]
            encoded = json.dumps(response).encode()
            self.send_response(200)
            self.send_header('content-type', 'application/json')
            self.send_header('content-length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except Exception:
            self.send_error(403)


def proc_memory(pid):
    values = {}
    for line in P(f'/proc/{pid}/smaps_rollup').read_text().splitlines():
        f = line.replace(':', ' ').split()
        if len(f) > 1 and f[1].isdigit():
            values[f[0]] = int(f[1])
    return {k: values.get(k, 0) for k in ['Rss', 'Pss', 'Anonymous', 'AnonHugePages', 'Swap']}


def guest_cgroup(pid):
    groups = P(f'/proc/{pid}/cgroup').read_text().splitlines()
    group = next(v[3:] for v in groups if v.startswith('0::'))
    path = P('/sys/fs/cgroup') / group.lstrip('/')
    assert path.is_relative_to(budget_group) and '..' not in path.parts, 'guest escaped aggregate pressure budget'
    assert int((path / 'memory.max').read_text()) == 768 * 1024 * 1024
    assert int((path / 'memory.swap.max').read_text()) == 0
    return path


def cgroup_data(path):
    events = dict(line.split() for line in (path / 'memory.events').read_text().splitlines())
    return {'current': int((path / 'memory.current').read_text()), 'swap': int((path / 'memory.swap.current').read_text()),
            'oom': int(events.get('oom', 0)), 'oomKill': int(events.get('oom_kill', 0))}


incus('network', 'create', 'incusbr0', 'ipv4.address=10.199.41.1/24', 'ipv4.nat=true', 'ipv6.address=none')
incus('profile', 'device', 'add', 'default', 'eth0', 'nic', 'network=incusbr0', 'name=eth0')
subprocess.run(['ip', 'link', 'add', 'incudal-mgmt', 'type', 'wireguard'], check=True)
# No packets or remote credentials are needed for management endpoint discovery.
private = subprocess.check_output(['wg', 'genkey'])
public = subprocess.check_output(['wg', 'pubkey'], input=private).decode().strip()
subprocess.run(['wg', 'set', 'incudal-mgmt', 'peer', public, 'endpoint', '198.51.100.1:51820', 'allowed-ips', '10.199.42.1/32'], check=True)
incus('init', 'images:alpine/3.24/tinycloud', 'memory-customer', '-s', 'default', '-c', 'limits.memory=768MiB', '-c', 'limits.memory.swap=false',
      '-c', 'security.syscalls.intercept.sysinfo=true',
      # Root LXC intentionally escapes to PID1's cgroup on a real host. Place
      # only this disposable fixture below our aggregate test budget explicitly.
      '-c', 'raw.lxc=lxc.cgroup.dir = incudal-memory-fixture', timeout=120)
incus('start', 'memory-customer')
guest = query('/1.0/instances/memory-customer')
before = query('/1.0/instances/memory-customer/state')
cg = guest_cgroup(before['pid'])
daemon_pid = int(P('/run/incus/incusd.pid').read_text())
# OpenRC creates host-root service cgroups. Re-enclose only this disposable
# daemon after the tested reload so its C/Go allocations count in the budget.
(budget_group / 'host' / 'cgroup.procs').write_text(str(daemon_pid))
assert str(budget_group).removeprefix('/sys/fs/cgroup') in P(f'/proc/{daemon_pid}/cgroup').read_text()
incus('exec', 'memory-customer', '--', 'sh', '-c', 'printf preserved >/root/memory-marker')
incus('file', 'push', '--mode=0700', '/out/memory-holder', 'memory-customer/root/memory-holder')
P('/etc/incudal-onboarding-id').write_text('disposable-native-memory\n')
server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Panel)
threading.Thread(target=server.serve_forever, daemon=True).start()
config = root / 'config.yaml'
config.write_text(f'panel_url: http://127.0.0.1:{server.server_port}\nagent_id: disposable-memory\nagent_secret: {secret}\nheartbeat_interval_seconds: 30\n')
config.chmod(0o600)
log = (root / 'agent.log').open('w')
agent = subprocess.Popen(['/out/incudal-agent', '--config', str(config)], stdout=log, stderr=log)
holder = None
try:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        assert agent.poll() is None, 'full Agent exited'
        if receipts and receipts[-1]['tools'].get('ready') and receipts[-1]['tools'].get('incusCompat') == 'verified':
            break
        time.sleep(1)
    else:
        raise AssertionError('full Agent provisioning receipts not ready')
    idle = {'agent': proc_memory(agent.pid), 'incus': proc_memory(int(P('/run/incus/incusd.pid').read_text())), 'budget': cgroup_data(budget_group)}
    # Leave 8MiB for container exec/runtime metadata; its total cgroup charge
    # must still reach at least 752MiB of the unchanged 768MiB customer limit.
    baseline = cgroup_data(cg)['current']
    amount = 768 * 1024 * 1024 - baseline - 8 * 1024 * 1024
    assert amount > 720 * 1024 * 1024
    holder = subprocess.Popen(['incus', 'exec', 'memory-customer', '--', '/root/memory-holder', str(amount)], stdout=subprocess.PIPE, text=True)
    samples = []
    start = time.monotonic()
    while time.monotonic() - start < 180:
        assert agent.poll() is None and holder.poll() is None, 'Agent or memory holder exited under pressure'
        state = query('/1.0/instances/memory-customer/state')
        assert state['status'] == 'Running' and state['pid'] == before['pid']
        row = {'seconds': round(time.monotonic()-start, 1), 'guest': cgroup_data(cg), 'budget': cgroup_data(budget_group),
               'agent': proc_memory(agent.pid), 'incus': proc_memory(int(P('/run/incus/incusd.pid').read_text()))}
        assert row['guest']['oomKill'] == row['budget']['oomKill'] == 0
        samples.append(row)
        time.sleep(5)
    assert min(r['guest']['current'] for r in samples[2:]) >= 752 * 1024 * 1024, 'pressure workload below acceptance'
    pressure_receipts = [r for r in receipts if r['at'] >= start]
    assert len(pressure_receipts) >= 5
    assert all(r['tools'].get('ready') and r['tools'].get('incusCompat') == 'verified' for r in pressure_receipts)
    assert max(b['at']-a['at'] for a,b in zip(pressure_receipts, pressure_receipts[1:])) < 45, 'heartbeat delayed by GC/pressure'
    assert query('/1.0/instances/memory-customer')['config']['volatile.uuid'] == guest['config']['volatile.uuid']
    assert incus('exec', 'memory-customer', '--', 'cat', '/root/memory-marker').strip() == 'preserved'
    incus('exec', 'memory-customer', '--', 'pkill', 'memory-holder')
    holder.wait(timeout=20)
    holder = None
    incus('stop', 'memory-customer', '--force')
    assert query('/1.0/instances/memory-customer/state')['status'] == 'Stopped'
    incus('start', 'memory-customer')
    assert query('/1.0/instances/memory-customer/state')['status'] == 'Running'
    incus('restart', 'memory-customer', '--force')
    assert query('/1.0/instances/memory-customer/state')['status'] == 'Running'
    incus('stop', 'memory-customer', '--force')
    incus('rebuild', 'images:alpine/3.24/tinycloud', 'memory-customer', '--force', timeout=120)
    incus('start', 'memory-customer')
    assert query('/1.0/instances/memory-customer/state')['status'] == 'Running'
    assert query('/1.0/instances/memory-customer')['config']['volatile.uuid'] == guest['config']['volatile.uuid']
    incus('delete', 'memory-customer', '--force')
    assert json.loads(incus('list', '--format=json')) == []
    print('MEMORY_PRESSURE_RESULT:'+json.dumps({'scope': '966MiB aggregate cgroup, shared runner kernel, not physical OCI', 'idleKiB': idle,
          'samples': samples, 'signedPressureHeartbeats': len(pressure_receipts), 'limitsUnchanged': True,
          'sameUuidPidDiskDuringPressure': True, 'stopStartRestartRebuildDelete': True}))
finally:
    if holder and holder.poll() is None:
        subprocess.run(['incus', 'exec', 'memory-customer', '--', 'pkill', 'memory-holder'], timeout=10)
    agent.terminate()
    agent.wait(timeout=20)
    server.shutdown()
    log.close()
