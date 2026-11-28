#!/usr/bin/env python3
"""One disposable Debian controller. Only fixed, sanitized events reach CI."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
import uuid

IMAGE_URL = ('https://cloud.debian.org/images/cloud/trixie/20261103-2651/'
             'debian-13-genericcloud-amd64-20261103-2651.qcow2')
IMAGE_SHA = 'de9d63f5e5ec5927d7548bc05b6043b87457b8c1cb9bcb95365168e8d0293b4f'
GUEST = Path('/root/controller-runtime-lab')
JOURNAL = Path('/var/lib/incudal-system-security/runtime-maintenance.json')
BOOT_ID = Path('/proc/sys/kernel/random/boot_id')
PHASES = ('install', 'candidate', 'installed', 'reboot', 'database', 'client', 'recovery', 'complete')


def need(condition, code):
    if not condition:
        raise ValueError(code)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    with path.open('x', encoding='utf8') as handle:
        json.dump(value, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run(args, timeout, **kwargs):
    return subprocess.run(args, check=True, timeout=timeout, **kwargs)


def guest_event(scope, phase, status, reason=''):
    # Never export logs, request parameters, SQL, SSH keys or stage artifacts.
    need(phase in PHASES and status in ('begin', 'pass', 'fail'), 'UNEXPECTED_EVENT')
    if not re.fullmatch(r'[A-Z][A-Z0-9_]{1,100}', reason):
        reason = ''
    env = {'challenge': scope['challenge'], 'phase': phase, 'status': status, 'reason': reason}
    msg = '\nINCUDAL_RUNTIME_LAB ' + json.dumps(env, separators=(',', ':')) + '\n'
    with open('/dev/ttyS0', 'wb', buffering=0) as serial:
        serial.write(msg.encode())


def guest_scope(scope):
    identity = scope['id']
    need(re.fullmatch('[a-f0-9]{32}', identity) and re.fullmatch('[a-f0-9]{48}', scope['challenge']),
         'INVALID_GUEST_SCOPE')
    need(os.geteuid() == 0, 'UNEXPECTED_GUEST_USER')
    need(Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() ==
         str(uuid.UUID(hex=identity)), 'UNEXPECTED_GUEST_UUID')
    need(Path('/sys/class/block/vda/serial').read_text().strip() ==
         'r6-' + identity[:12], 'UNEXPECTED_GUEST_DISK')
    need(Path('/var/lib/cloud/data/instance-id').read_text().strip() ==
         'runtime-' + identity, 'UNEXPECTED_CLOUD_INSTANCE')
    need(Path('/etc/os-release').read_text().find('VERSION_ID="13"') >= 0, 'UNEXPECTED_GUEST_OS')
    need(run(['getconf', 'GNU_LIBC_VERSION'], 10, capture_output=True).stdout.strip() == b'glibc 2.41',
         'UNEXPECTED_LIBC_SERIES')
    need(re.fullmatch('[a-f0-9]{40}', scope['commit']) and
         scope['package'] == 'incudal-v1.8.14-test.' + scope['commit'][:7] + '-linux-amd64.tar.gz',
         'UNEXPECTED_PACKAGE')


def apt_preferences(names, version):
    need(re.fullmatch(r'[0-9][a-z0-9A-Z.:+~-]{0,96}', version), 'INVALID_BASELINE_VERSION')
    return 'Package: ' + ' '.join(names) + '\nPin: version ' + version + '\nPin-Priority: 1001\n'


def install(scope):
    mount = GUEST / 'input'
    mount.mkdir(mode=0o700)
    run(['mount', '-o', 'ro,nosuid,nodev,noexec', '/dev/disk/by-label/RUNTIMEPKG', str(mount)], 20)
    package = mount / scope['package']
    need(not Path('/opt/incudal').exists() and digest(package) == scope['tarSha256'], 'NOT_FRESH_OR_PACKAGE_CHANGED')
    cache = Path('/tmp/incudal')
    cache.mkdir(mode=0o700)
    for name in (package.name, package.name + '.sig'):
        shutil.copyfile(mount / name, cache / name)
    (cache / (package.name + '.sha256')).write_text(scope['tarSha256'] + '  ' + package.name + '\n')
    with tarfile.open(package, 'r:gz') as archive:
        installers = [m for m in archive if m.name.removeprefix('./') == 'scripts/install-panel.sh']
        need(len(installers) == 1 and installers[0].isfile() and installers[0].uid == 0 and
             not installers[0].mode & 0o022 and installers[0].size <= 1024**2, 'INVALID_INSTALLER')
        (GUEST / 'installer.sh').write_bytes(archive.extractfile(installers[0]).read())

    # Freeze only the four real pre-update versions in this new test machine
    # so installer prerequisites cannot consume the patch before the test.
    before = run(['dpkg-query', '-W', '-f=' + chr(36) + '{Version}', 'libc6'], 20,
                 capture_output=True, text=True).stdout
    names = ['libc6', 'libc-bin', 'libc-l10n', 'locales', 'locales-all']
    preferences = Path('/etc/apt/preferences.d/99-incudal-runtime-test')
    original = apt_preferences(names, before)
    with preferences.open('x') as stream:
        stream.write(original)
    prefs = {'DEBIAN_FRONTEND': 'noninteractive', 'ONBOARDING_PUBLIC_HOST': 'gateway.example.com',
             'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
             'HOME': '/root', 'LANG': 'C.UTF-8'}
    run(['apt-get', '-o', 'APT::Update::Error-Mode=any', 'update'], 240,
        stdout=subprocess.DEVNULL)
    run(['localedef', '-i', 'en_US', '-f', 'UTF-8', 'en_US.UTF-8'], 90)
    with (GUEST / 'installer-private.log').open('xb') as private:
        run(['/bin/bash', str(GUEST / 'installer.sh')], 1800, input=b'installer@example.invalid\n3\n',
            stdout=private, stderr=subprocess.STDOUT, env=prefs)
    need(preferences.read_text() == original, 'TEST_PACKAGE_PREFERENCE_CHANGED')
    # Only the two reviewed native libraries enter this transaction. The
    # original planner/worker still verifies the actual APT plan and package DB.
    preferences.write_text(apt_preferences(['libc-l10n', 'locales', 'locales-all'], before))
    root = Path('/opt/incudal/current').resolve() if Path('/opt/incudal/current').exists() else Path('/opt/incudal')
    info = json.loads((root / 'version.json').read_bytes())
    catalog = json.loads((root / 'vendor/gateway/catalog.json').read_bytes())
    need(info['version'] == 'v1.8.14-test.' + scope['commit'][:7] and
         info['gitCommit'] == scope['commit'][:12] and catalog['sourceCommit'] == scope['commit'],
         'INSTALLED_SOURCE_MISMATCH')
    # Suppress the competing timer in this VM before starting the explicit transaction.
    run(['systemctl', 'disable', '--now', 'incudal-system-security.timer'], 30)
    return root


def runtime(root):
    import importlib.util
    path = root / 'scripts/system-security-inventory.py'
    spec = importlib.util.spec_from_file_location('signed_controller_inventory', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    need(module.AUTOMATIC_RUNTIME_MAINTENANCE_ENABLED is False, 'AUTOMATIC_RUNTIME_GATE_CHANGED')
    return module


def host(lab, commit, package):
    need(os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and os.environ.get('GITHUB_ACTIONS') == 'true'
         and os.geteuid() != 0 and re.fullmatch('[a-f0-9]{40}', commit)
         and lab == Path(os.environ['RUNNER_TEMP']) / 'controller-runtime-lab'
         and package == f'incudal-v1.8.14-test.{commit[:7]}-linux-amd64.tar.gz', 'NOT_HOSTED_LAB')
    image = lab / 'debian.qcow2'
    run(['curl', '--proto', '=https', '--proto-redir', '=https', '--retry', '2', '-fsSL', IMAGE_URL,
         '-o', str(image)], 240)
    need(image.stat().st_size == 341180416 and digest(image) == IMAGE_SHA, 'DEBIAN_IMAGE_CHANGED')
    image_info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(image)], timeout=20))
    need(image_info['format'] == 'qcow2' and not image_info.get('backing-filename') and
         not image_info.get('snapshots'), 'INVALID_BASE_IMAGE')
    image.chmod(0o400)
    disk = lab / 'runtime.qcow2'
    run(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image), str(disk), '20G'], 60)
    identity = uuid.uuid4().hex
    scope = {'id': identity, 'challenge': secrets.token_hex(24), 'commit': commit,
             'package': package, 'tarSha256': digest(lab / package)}
    source = Path(__file__).resolve().parent
    payload = {'scope.json': json.dumps(scope).encode(), 'lab.py': Path(__file__).read_bytes(),
               'transaction.py': (source / 'controller-runtime-transaction.py').read_bytes()}
    for name, body in payload.items():
        (lab / name).write_bytes(body)
    unit = ('[Unit]\nDescription=Disposable runtime acceptance\nAfter=network-online.target\n'
            'Wants=network-online.target\n[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=55min\n'
            'ExecStart=/usr/bin/python3 -I -B /root/controller-runtime-lab/lab.py guest\n'
            '[Install]\nWantedBy=multi-user.target\n')
    static = ('#!/bin/sh\nset -eu\np=$(ip -o link show | awk \x27$2 !~ /^lo:/ {gsub(":","",$2); print $2; exit}\x27)\n'
              'test -n "$p"\nip link set "$p" up\nip addr replace 10.0.2.15/24 dev "$p"\n'
              'ip route replace default via 10.0.2.2 dev "$p"\n'
              'if test -L /etc/resolv.conf; then unlink /etc/resolv.conf; fi\n'
              'printf "nameserver 10.0.2.3\\n" > /etc/resolv.conf\n')
    static_unit = ('[Unit]\nDescription=Isolated QEMU static IPv4\nBefore=network-online.target\n'
                   '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/local/sbin/runtime-lab-network\n'
                   '[Install]\nWantedBy=multi-user.target\n')
    payload_files = [{'path': str(GUEST / name), 'encoding': 'b64', 'permissions': '0600',
                      'content': base64.b64encode(body).decode()} for name, body in payload.items()]
    config = {'disable_root': True, 'ssh_pwauth': False, 'users': [], 'write_files': payload_files + [
        {'path': '/etc/systemd/system/runtime-lab.service', 'permissions': '0644', 'content': unit},
        {'path': '/usr/local/sbin/runtime-lab-network', 'permissions': '0700', 'content': static},
        {'path': '/etc/systemd/system/runtime-lab-network.service', 'permissions': '0644', 'content': static_unit}],
        'runcmd': [['systemctl', 'daemon-reload'], ['systemctl', 'enable', 'runtime-lab-network.service'],
                   ['systemctl', 'disable', '--now', 'systemd-networkd-wait-online.service',
                    'systemd-networkd.socket', 'systemd-networkd.service'], ['/usr/local/sbin/runtime-lab-network'],
                   ['systemctl', 'enable', 'runtime-lab.service'],
                   ['systemctl', 'start', '--no-block', 'runtime-lab.service']]}
    (lab / 'user-data').write_text('#cloud-config\n' + json.dumps(config))
    (lab / 'meta-data').write_text(json.dumps({'instance-id': 'runtime-' + identity, 'local-hostname': 'runtime-lab'}))
    mac = '02:00:66:' + ':'.join(identity[i:i + 2] for i in (0, 2, 4))
    network = {'version': 2, 'ethernets': {'uplink': {
        'match': {'macaddress': mac}, 'set-name': 'r6net0',
        'dhcp4': True, 'dhcp6': False, 'accept-ra': False,
    }}}
    (lab / 'network-config').write_text(json.dumps(network))
    def iso(label, output, names):
        run(['xorriso', '-as', 'mkisofs', '-quiet', '-r', '-J', '-joliet-long', '-V', label,
             '-o', str(lab / output), *names], 120, cwd=lab, stdout=subprocess.DEVNULL)
    iso('cidata', 'seed.iso', ['user-data', 'meta-data', 'network-config'])
    iso('RUNTIMEPKG', 'package.iso', [package, package + '.sig'])
    args = ['qemu-system-x86_64', '-nodefaults', '-no-user-config', '-accel', 'kvm', '-cpu', 'host',
            '-machine', 'q35,smm=off', '-m', '3072', '-smp', '2', '-uuid', str(uuid.UUID(hex=identity)),
            '-drive', f'file={disk},format=qcow2,if=none,id=root', '-device',
            'virtio-blk-pci,drive=root,bootindex=1,serial=r6-' + identity[:12], '-device', 'virtio-scsi-pci,id=scsi']
    for i, item in enumerate(('seed.iso', 'package.iso')):
        args += ['-drive', f'file={lab / item},format=raw,readonly=on,if=none,id=iso{i}',
                 '-device', f'scsi-cd,drive=iso{i},bus=scsi.0']
    args += ['-netdev', 'user,id=net0', '-device', 'virtio-net-pci,netdev=net0,romfile=,mac=' + mac, '-display', 'none',
             '-serial', 'file:' + str(lab / 'serial.log'), '-monitor', 'none']
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    try:
        observe(process, lab / 'serial.log', scope)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def observe(process, path, scope):
    # Provide firmware / Linux / cloud-init evidence if the service never
    # reaches Python. Only these fixed labels can enter the public job log.
    milestones = {
        b'Linux version ': 'Linux kernel',
        b'Welcome to ': 'userspace',
        b"running 'init-local'": 'cloud-init local',
        b"running 'init'": 'cloud-init network',
        b'cloud-final.service': 'cloud-init final unit',
        b'Kernel panic': 'kernel panic',
        b'No bootable device': 'no bootable device',
    }
    boot_deadline = time.monotonic() + 8 * 60
    deadline = time.monotonic() + 90 * 60
    offset, partial, completed = 0, b'', []
    first_event = False
    while time.monotonic() < deadline:
        if path.exists():
            need(path.stat().st_size <= 32 * 1024**2, 'GUEST_CONSOLE_LIMIT')
            with path.open('rb') as log:
                log.seek(offset)
                data = log.read(1024**2)
            offset += len(data)
            lines = (partial + data).split(b'\n')
            partial = lines.pop()
            for line in lines:
                for marker in tuple(milestones):
                    if marker in line:
                        print('Guest console:', milestones.pop(marker), flush=True)
                _, marker, raw = line.partition(b'INCUDAL_RUNTIME_LAB ')
                if not marker or not raw.startswith(b'{'):
                    continue
                event = json.loads(raw)
                if event.get('challenge') != scope['challenge']:
                    continue
                first_event = True
                phase, status = event['phase'], event['status']
                need(phase in PHASES and status in ('begin', 'pass', 'fail') and
                     re.fullmatch(r'[A-Z0-9_]{0,101}', event['reason']), 'INVALID_GUEST_EVENT')
                print(f"{phase}: {status} {event['reason']}", flush=True)
                if status == 'fail':
                    raise ValueError('NATIVE_STAGE_FAILED')
                if status == 'pass':
                    need(len(completed) < len(PHASES) and phase == PHASES[len(completed)], 'UNEXPECTED_STAGE_ORDER')
                    completed.append(phase)
        if process.poll() is not None:
            need(process.returncode == 0 and tuple(completed) == PHASES, 'GUEST_COMPLETION_UNCONFIRMED')
            return
        need(first_event or time.monotonic() < boot_deadline, 'GUEST_STARTUP_EVENT_MISSING')
        time.sleep(.5)
    raise TimeoutError('NATIVE_TEST_WINDOW_EXPIRED')

def guest():
    import importlib.util
    scope = json.loads((GUEST / 'scope.json').read_bytes())
    phase = 'install'
    try:
        guest_scope(scope)
        identity = {'id': scope['id'], 'boot': BOOT_ID.read_text().strip(),
                    'machine': digest(Path('/etc/machine-id'))}
        path = GUEST / 'transaction.py'
        spec = importlib.util.spec_from_file_location('native_transaction_test', path)
        tx = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tx)
        if not (GUEST / 'before.json').exists():
            guest_event(scope, phase, 'begin')
            root = install(scope)
            guest_event(scope, phase, 'pass')
            phase = 'candidate'
            guest_event(scope, phase, 'begin')
            module = runtime(root)
            before = tx.prepare(module, identity)
            before['root'] = str(root)
            save(GUEST / 'before.json', before)
            guest_event(scope, phase, 'pass')
            phase = 'installed'
            worker = subprocess.run([sys.executable, '-I', '-B', __file__, 'cut'], timeout=1800,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if worker.returncode != 75 and (GUEST / 'cut-error.json').exists():
                raise ValueError(json.loads((GUEST / 'cut-error.json').read_text())['reason'])
            need(worker.returncode == 75 and (GUEST / 'cut.json').exists(), 'INSTALL_CUT_FAILED')
            need(tx.read(GUEST / 'cut.json') == tx.read(JOURNAL), 'PERSISTED_CUT_CHANGED')
            guest_event(scope, phase, 'pass')
            guest_event(scope, 'reboot', 'begin')
            run(['/usr/bin/systemctl', 'reboot', '--no-block'], 15)
            return
        phase = 'reboot'
        before = tx.read(GUEST / 'before.json')
        need(before['identity']['id'] == identity['id'] and before['identity']['machine'] == identity['machine']
             and before['identity']['boot'] != identity['boot'], 'REBOOT_LINEAGE_CHANGED')
        guest_event(scope, phase, 'pass')
        cut = tx.read(GUEST / 'cut.json')
        module = runtime(Path(before['root']))
        phase = 'database'
        guest_event(scope, phase, 'begin')
        client, retained = tx.fault(module, before, cut, identity, save)
        guest_event(scope, phase, 'pass')
        phase = 'client'
        tx.restore_client(module, before, client, retained)
        guest_event(scope, phase, 'pass')
        phase = 'recovery'
        guest_event(scope, phase, 'begin')
        tx.recover(module, before, cut, identity)
        guest_event(scope, phase, 'pass')
        guest_event(scope, 'complete', 'pass')
        run(['/usr/bin/systemctl', 'poweroff', '--no-block'], 15)
    except Exception as error:
        reason = str(error)
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{1,100}', reason):
            reason = type(error).__name__.upper()
        guest_event(scope, phase, 'fail', reason)
        raise


def cut():
    import importlib.util
    guest_scope(json.loads((GUEST / 'scope.json').read_bytes()))
    path = GUEST / 'transaction.py'
    spec = importlib.util.spec_from_file_location('native_transaction_test', path)
    tx = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tx)
    before = tx.read(GUEST / 'before.json')
    try:
        tx.install_cut(runtime(Path(before['root'])), before, save)
    except Exception as error:
        reason = str(error)
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{1,100}', reason):
            reason = type(error).__name__.upper()
        save(GUEST / 'cut-error.json', {'reason': reason})
        raise


if __name__ == '__main__':
    if sys.argv[1:] == ['guest']:
        guest()
    elif sys.argv[1:] == ['cut']:
        cut()
    elif len(sys.argv) == 5 and sys.argv[1] == 'host':
        host(Path(sys.argv[2]), sys.argv[3], sys.argv[4])
    else:
        raise SystemExit('Expected host, guest or cut')
