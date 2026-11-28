#!/usr/bin/env python3
"""Exercise a kernel update on a fresh Alpine VM and the same VM's original boot."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid

SOURCES = {
    'x86_64': ('946677073fbd8e6345a8f150ce4e1848e10bbb3daef8f05f6c26dcea0d82db23', 157810688),
    'aarch64': ('e83922eefe35a28eb5380fdb2ea0845c6a33c83be44a688ad08932014ceac3d2', 191823872),
}
ROOT = Path('/root/incudal-kernel-lab')
PRODUCTS = ['server/templates/host-kernel-maintenance.py', 'server/templates/host-security-maintenance.py',
            'scripts/test-host-kernel-boot-native.sh', 'scripts/host-kernel-lab-guest.sh']


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def run(argv, timeout, **kwargs):
    return subprocess.run(argv, timeout=timeout, check=True, **kwargs)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def open_kvm():
    path = '/dev/kvm'
    before = os.lstat(path)
    require(stat.S_ISCHR(before.st_mode) and before.st_uid == 0 and
            (os.major(before.st_rdev), os.minor(before.st_rdev)) == (10, 232), 'Unexpected KVM device')
    # The hosted machine can reset a device ACL between separate QEMU boots.
    # Grant only this runner user and confirm O_RDWR on the very same device.
    run(['sudo', '-n', 'setfacl', '-m', f'u:{os.getuid()}:rw', path], 15)
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(os.path.samestat(before, os.fstat(fd)) and os.path.samestat(before, os.lstat(path)),
                'KVM device changed before boot')
    finally:
        os.close(fd)


def native_diagnostic_summary(diagnostic):
    if not isinstance(diagnostic, dict):
        return None
    if 'function' in diagnostic:
        if not (isinstance(diagnostic.get('reason'), str) and
                re.fullmatch(r'HARDENING_[A-Z_]{1,90}', diagnostic['reason']) and
                isinstance(diagnostic['function'], str) and re.fullmatch(r'[a-z_]{1,64}', diagnostic['function']) and
                type(diagnostic.get('line')) is int and 0 < diagnostic['line'] < 100000):
            return None
        return {key: diagnostic[key] for key in ('reason', 'line', 'function')}
    programs = {'apk', 'depmod', 'mkinitfs', 'grub-mkconfig', 'grub-script-check',
                'update-extlinux', 'chronyc', 'rc-service', 'incus'}
    if diagnostic.get('program') not in programs or type(diagnostic.get('exit')) is not int:
        return None
    summary = {'program': diagnostic['program'], 'exit': diagnostic['exit']}
    for key in ('stdoutBytes', 'stderrBytes', 'stderrPrefixBytes'):
        value = diagnostic.get(key)
        if type(value) is int and 0 <= value <= 64 * 1024**2:
            summary[key] = value
    for key in ('stderrPrefixSha256', 'stdoutSha256'):
        value = diagnostic.get(key)
        if isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value):
            summary[key] = value
    if diagnostic.get('diagnosticUnavailable') is True:
        summary['diagnosticUnavailable'] = True
    arguments = diagnostic.get('arguments', [])
    if not isinstance(arguments, list) or len(arguments) > 24 or any(not isinstance(arg, str) for arg in arguments):
        return None
    operations = {'update', 'policy', 'upgrade', 'fix', 'fetch', 'verify', 'status', 'tracking', '-a', '--help'}
    summary['operation'] = next((arg for arg in arguments if arg in operations), 'unspecified')
    errors = diagnostic.get('stderrPrefix', '')
    if not isinstance(errors, str) or len(errors) > 4096:
        return None
    classes = ((r'(?i)(?:unrecognized|unknown|invalid) option', 'OPTION_REJECTED'),
               (r'(?i)unable to select packages|unsatisfiable constraints', 'PACKAGE_SELECTION_FAILED'),
               (r'(?i)certificate verify failed|certificate verification failed', 'TLS_VERIFICATION_FAILED'),
               (r'(?i)permission denied', 'PERMISSION_DENIED'),
               (r'(?i)temporary error|network unreachable|connection refused|operation timed out', 'NETWORK_UNAVAILABLE'),
               (r'(?i)bad signature|signature verification failed|untrusted signature', 'SIGNATURE_REJECTED'))
    summary['errorClass'] = next((label for pattern, label in classes if re.search(pattern, errors)), 'UNCLASSIFIED_NATIVE_EXIT')
    option = re.search(r"""(?i)(?:unrecognized|unknown|invalid) option[: ]+['"]?(-{0,2}[a-z0-9-]+)""", errors)
    if option and any(arg.lstrip('-') == option[1].lstrip('-') for arg in arguments if arg.startswith('-')):
        summary['rejectedOption'] = option[1]
    encoded = diagnostic.get('stdoutBase64')
    if encoded is not None:
        if not isinstance(encoded, str) or len(encoded) > 5592408:
            return None
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError:
            return None
        if len(raw) != summary.get('stdoutBytes') or len(raw) > 4 * 1024**2 or hashlib.sha256(raw).hexdigest() != summary.get('stdoutSha256'):
            return None
        text = raw.decode('utf-8', errors='replace')
        actions = re.findall(r'\b(Installing|Removing|Purging|Downgrading|Upgrading|Reinstalling)\b', text)
        summary['planActionCounts'] = {name: actions.count(name) for name in
                                     ('Installing', 'Removing', 'Purging', 'Downgrading', 'Upgrading', 'Reinstalling')}
        rows = re.findall(r'(?:Installing|Removing|Purging|Downgrading|Upgrading|Reinstalling) ([a-zA-Z0-9+_.-]+) \(', text)
        summary['nonKernelPlanChange'] = any(name not in {'linux-virt', 'linux-lts'} for name in rows)
    return summary


def native_diagnostic_summaries(path):
    result = []
    with path.open('rb') as log:
        if os.fstat(log.fileno()).st_size > 32 * 1024**2:
            return []
        while True:
            line = log.readline(8 * 1024**2 + 1)
            if not line:
                break
            if len(line) > 8 * 1024**2:
                return []
            prefixes = (b'E04_NATIVE_COMMAND_FAILURE ', b'E04_NATIVE_COMMAND_TRACE ', b'E04_NATIVE_PRODUCT_FAILURE ')
            prefix = next((item for item in prefixes if line.startswith(item)), None)
            if prefix is None:
                continue
            try:
                summary = native_diagnostic_summary(json.loads(line[len(prefix):]))
            except (ValueError, TypeError):
                continue
            if summary is not None:
                result.append(summary)
                result = result[-12:]
    return result


class Lab:
    def __init__(self, arch, directory, repo):
        self.arch = arch
        self.arm = arch == 'aarch64'
        self.dir = directory
        self.repo = repo
        self.id = str(uuid.uuid4())
        self.port = 22873
        self.proc = None
        self.console = None
        self.emulator_log = None
        self.boot_console_start = 0
        self.accel = 'kvm' if os.path.exists('/dev/kvm') else 'tcg'
        self.boots = 0
        self.log = (directory / 'private.log').open('xb')

    def cmd(self, args, seconds, **kwargs):
        return run(args, seconds, stdout=self.log, stderr=self.log, **kwargs)

    def prepare(self):
        image = self.dir / 'alpine.qcow2'
        name = f'alpine-3.24.3-{self.arch}-cloudinit-r0.qcow2'
        url = 'https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/cloud/' + name
        self.cmd(['curl', '--proto', '=https', '--proto-redir', '=https', '--retry', '2', '-fsSL', url, '-o', str(image)], 300)
        expected, size = SOURCES[self.arch]
        require(image.stat().st_size == size and digest(image) == expected, 'Invalid public Alpine base')
        info = json.loads(subprocess.check_output(['qemu-img', 'info', '--output=json', str(image)], timeout=30))
        require(info['format'] == 'qcow2' and not info.get('backing-filename') and not info.get('snapshots'), 'Unexpected image layout')
        image.chmod(0o400)
        self.cmd(['qemu-img', 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(image),
                  str(self.dir / 'disk.qcow2'), '10G'], 30)
        firmware_root = Path('/usr/share/AAVMF' if self.arm else '/usr/share/OVMF')
        code = 'AAVMF_CODE.fd' if self.arm else 'OVMF_CODE_4M.fd'
        variables = 'AAVMF_VARS.fd' if self.arm else 'OVMF_VARS_4M.fd'
        self.code = firmware_root / code
        self.var_template = firmware_root / variables
        require(self.code.is_file() and self.var_template.is_file(), 'Missing distribution UEFI firmware')
        shutil.copyfile(self.var_template, self.dir / 'vars.fd')
        for label in ['host', 'client']:
            self.cmd(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.dir / label)], 20)
        public = (self.dir / 'client.pub').read_text().strip()
        host = (self.dir / 'host.pub').read_text().split()
        with (self.dir / 'known_hosts').open('x') as out:
            out.write(f'[127.0.0.1]:{self.port} {host[0]} {host[1]}\n')
        def file(path, content, perm):
            return {'path': str(path), 'encoding': 'b64', 'permissions': perm,
                    'owner': 'root:root', 'content': base64.b64encode(content).decode()}
        contents = [file(ROOT / Path(rel).name, (self.repo / rel).read_bytes(), '0600') for rel in PRODUCTS]
        contents.extend([file(ROOT / 'id', (self.id + '\n').encode(), '0600'),
                         file(ROOT / 'arch', (self.arch + '\n').encode(), '0600')])
        password_hash = subprocess.check_output(['openssl', 'passwd', '-6', '-stdin'],
                                                input=secrets.token_bytes(32).hex().encode() + b'\n',
                                                timeout=10).decode().strip()
        require(password_hash.startswith('$6$'), 'Ephemeral account bootstrap failed')
        cfg = {'users': [{'name': 'root', 'lock_passwd': False, 'hashed_passwd': password_hash,
                          'ssh_authorized_keys': [public]}],
               'disable_root': False, 'ssh_pwauth': False, 'ssh_deletekeys': True,
               'ssh_genkeytypes': ['ed25519'], 'ssh': {'emit_keys_to_console': False},
               'package_update': False, 'package_upgrade': False, 'resize_rootfs': True,
               'growpart': {'mode': 'auto', 'devices': ['/']},
               'ssh_keys': {'ed25519_private': (self.dir / 'host').read_text(), 'ed25519_public': ' '.join(host)},
               'write_files': contents, 'runcmd': [['chmod', '0700', str(ROOT)]]}
        (self.dir / 'user-data').write_text('#cloud-config\n' + json.dumps(cfg))
        (self.dir / 'meta-data').write_text(json.dumps({'instance-id': 'kernel-' + self.id, 'local-hostname': 'kernel-lab'}))
        self.cmd(['xorriso', '-as', 'mkisofs', '-quiet', '-V', 'CIDATA', '-r', '-J', '-o', str(self.dir / 'seed.iso'),
                  'meta-data', 'user-data'], 30, cwd=self.dir)
        self.ssh = ['ssh', '-F', '/dev/null', '-p', str(self.port), '-i', str(self.dir / 'client'),
                    '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
                    '-o', 'KbdInteractiveAuthentication=no', '-o', 'ConnectTimeout=6', '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'UserKnownHostsFile=' + str(self.dir / 'known_hosts'), '-o', 'GlobalKnownHostsFile=/dev/null',
                    '-o', 'HostKeyAlgorithms=ssh-ed25519', 'root@127.0.0.1']

    def start(self, fallback=False):
        require(self.proc is None, 'Previous VM still owned')
        with socket.socket() as port:
            port.bind(('127.0.0.1', self.port))
        self.boots += 1
        variables = self.dir / ('fallback-vars.fd' if fallback else 'vars.fd')
        if fallback:
            require(not variables.exists(), 'Unexpected fallback firmware state')
            shutil.copyfile(self.var_template, variables)
        self.boot_console_start = 0
        if self.accel == 'kvm':
            open_kvm()
            machine, cpu, accel = ('virt,gic-version=host' if self.arm else 'q35'), 'host', 'kvm'
        else:
            require(self.arm, 'AMD64 runner requires KVM')
            machine, cpu, accel = 'virt,gic-version=3', 'max', 'tcg,thread=multi'
        print(f'Booting {self.arch} using {self.accel}, disk boot {self.boots}', flush=True)
        args = ['qemu-system-' + self.arch, '-nodefaults', '-no-user-config', '-accel', accel, '-cpu', cpu,
                '-machine', machine, '-m', '3072', '-smp', '2',
                '-drive', f'if=pflash,format=raw,readonly=on,file={self.code}',
                '-drive', f'if=pflash,format=raw,file={variables}',
                '-drive', f'if=none,id=main,format=qcow2,file={self.dir / "disk.qcow2"}',
                '-device', f'virtio-blk-pci,drive=main,serial=e04-{self.id[:12]},bootindex={2 if fallback else 1}',
                '-device', 'virtio-scsi-pci,id=scsi0',
                '-drive', f'if=none,id=seed,format=raw,readonly=on,media=cdrom,file={self.dir / "seed.iso"}',
                '-device', 'scsi-cd,drive=seed,bus=scsi0.0',
                '-netdev', f'user,id=n,hostfwd=tcp:127.0.0.1:{self.port}-:22', '-device', 'virtio-net-pci,netdev=n',
                '-device', 'virtio-rng-pci', '-display', 'none', '-monitor', 'none', '-serial', 'stdio']
        if fallback:
            args.extend(['-drive', f'if=none,id=return,format=raw,readonly=on,file={self.dir / "fallback.fat"}',
                         '-device', 'scsi-hd,drive=return,bus=scsi0.0,bootindex=1'])
        if self.arm:
            # virt's native MMIO devices avoid optional PCI option ROMs.
            devices = {'virtio-blk-pci': 'virtio-blk-device', 'virtio-scsi-pci': 'virtio-scsi-device',
                       'virtio-net-pci': 'virtio-net-device', 'virtio-rng-pci': 'virtio-rng-device'}
            for i, arg in enumerate(args):
                if arg == '-device':
                    name, comma, opts = args[i + 1].partition(',')
                    args[i + 1] = devices.get(name, name) + comma + opts
        self.console = (self.dir / f'console-{self.boots}.log').open('xb')
        self.emulator_log = (self.dir / f'qemu-{self.boots}.log').open('xb')
        self.proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=self.console, stderr=self.emulator_log)

    def ssh_output(self, command, seconds=20):
        return run(self.ssh + [command], seconds, stdout=subprocess.PIPE, stderr=self.log).stdout.strip()

    def ready(self, old=None):
        # The ARM public runners expose no nested KVM. Measure their cold
        # emulated boot separately; every SSH attempt and product call is bounded.
        started = time.monotonic()
        end = started + (600 if self.accel == 'tcg' else 300)
        path = self.dir / f'console-{self.boots}.log'
        offset = self.boot_console_start
        markers = (b'Linux version ', b'Mounting root: ok', b'Welcome to Alpine Linux', b'login:')
        observed, partial = set(), b''
        query = ('set -eu; for f in /var/lib/cloud/data/instance-id /sys/class/block/vda/serial '
                 '/proc/sys/kernel/random/boot_id; do test -s "$f" || test -r "$f" || exit 75; done; '
                 'printf "%s\\n" "$(cat /var/lib/cloud/data/instance-id)" "$(cat /sys/class/block/vda/serial)" '
                 '"$(uname -m)" "$(cat /proc/sys/kernel/random/boot_id)"')
        while time.monotonic() < end:
            if self.proc.poll() is not None:
                # This file contains only the emulator's stderr. Guest stdout
                # and firmware console use their own file and are never printed.
                self.emulator_log.flush()
                with (self.dir / f'qemu-{self.boots}.log').open('rb') as messages:
                    reason = messages.read(2048).decode(errors='replace')
                reason = re.sub(r"[^A-Za-z0-9 /,.:_=()-]", " ", reason)
                raise ValueError(f'VM exited before SSH ({self.proc.returncode}): {reason[:400]}')
            size = path.stat().st_size
            require(offset <= size <= 32 * 1024**2, 'Unexpected guest console size')
            with path.open('rb') as log:
                log.seek(offset)
                data = log.read(min(size - offset, 1024**2))
            offset += len(data)
            scanned = partial + data
            for n, marker in enumerate(markers):
                if marker in scanned and n not in observed:
                    print(f'Guest boot stage {n + 1} after {time.monotonic() - started:.1f}s', flush=True)
                    observed.add(n)
            require(b'Kernel panic - not syncing' not in scanned and
                    b'Launching initramfs emergency recovery shell' not in scanned, 'Guest kernel/root mount failed')
            partial = scanned[-128:]
            try:
                # An absent first-boot cloud-init marker is transient. Explicit
                # separators preserve fields even when a sysfs read has no LF.
                response = self.ssh_output(query, min(10, max(1, end - time.monotonic()))).decode().splitlines()
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                time.sleep(min(2, max(0, end - time.monotonic())))
                continue
            require(len(response) == 4, 'SSH boot identity field count changed')
            for actual, wanted, field in zip(response, ('kernel-' + self.id, 'e04-' + self.id[:12], self.arch),
                                               ('NoCloud instance ID', 'virtio root disk serial', 'guest architecture')):
                require(actual == wanted, 'Unexpected SSH ' + field)
            require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', response[3]), 'Invalid guest boot ID')
            if response[3] != old:
                print(f'Authenticated {self.arch} guest after {time.monotonic() - started:.1f}s', flush=True)
                return response[3]
            time.sleep(1)
        raise TimeoutError('Original SSH boot identity unavailable')

    def phase(self, name, reboot=False):
        if reboot:
            self.boot_console_start = (self.dir / f'console-{self.boots}.log').stat().st_size
        proc = subprocess.run(self.ssh + ['bash /root/incudal-kernel-lab/host-kernel-lab-guest.sh ' + name],
                              timeout=900, stdout=self.log, stderr=self.log)
        if proc.returncode and not (reboot and proc.returncode == 255):
            # Print only the product's constrained error code, never raw customer data or keys.
            self.log.flush()
            with (self.dir / 'private.log').open('rb') as log:
                log.seek(max(0, log.seek(0, os.SEEK_END) - 65536))
                tail = log.read(65536)
            # Publish fixed facts only; complete APK streams stay private.
            for summary in native_diagnostic_summaries(self.dir / 'private.log'):
                kind = 'PRODUCT' if 'function' in summary else 'COMMAND'
                print('E04_NATIVE_' + kind + '_SUMMARY ' + json.dumps(summary, separators=(',', ':')), flush=True)
            codes = re.findall(rb'\b(?:HARDENING_[A-Z_]{1,90}|E04_GUEST_FAILURE phase=[a-z-]{1,30} line=[0-9]{1,5})\b', tail)
            # The guest's ERR trap runs after the Python driver and can emit
            # more than once. Keep its line and the driver's original code.
            reasons = ', '.join(dict.fromkeys(code.decode() for code in codes[-6:]))
            raise ValueError(name + ' failed' + (': ' + reasons if reasons else ''))
        if not reboot:
            print(name + ' passed', flush=True)

    def poweroff(self):
        proc = subprocess.run(self.ssh + ['sync; poweroff'], timeout=45, stdout=self.log, stderr=self.log)
        require(proc.returncode in (0, 255), 'Poweroff refused')
        require(self.proc.wait(timeout=150) == 0, 'QEMU poweroff failed')
        self.proc = None
        self.console.close()
        self.emulator_log.close()

    def fallback(self):
        expected = {}
        rows = self.ssh_output('cat /root/incudal-kernel-lab/fallback.sha256').decode().splitlines()
        for row in rows:
            match = re.fullmatch(r'([0-9a-f]{64})  /root/incudal-kernel-lab/(fallback\.efi|original-kernel|original-initrd)', row)
            require(match and match[2] not in expected, 'Invalid fallback manifest')
            expected[match[2]] = match[1]
        require(set(expected) == {'fallback.efi', 'original-kernel', 'original-initrd'}, 'Incomplete fallback manifest')
        for name, sha in expected.items():
            dest = self.dir / name
            with dest.open('xb') as stream:
                run(self.ssh + ['cat /root/incudal-kernel-lab/' + name], 90, stdout=stream, stderr=self.log)
            require(0 < dest.stat().st_size < 128 * 1024**2 and digest(dest) == sha, 'Fallback member mismatch')
        fat = self.dir / 'fallback.fat'
        self.cmd(['truncate', '-s', '256M', str(fat)], 10)
        self.cmd(['mkfs.vfat', '-F', '32', '-n', 'E04RETURN', str(fat)], 30)
        self.cmd(['mmd', '-i', str(fat), '::/EFI', '::/EFI/BOOT', '::/boot'], 20)
        for name, target in [('fallback.efi', 'EFI/BOOT/' + ('BOOTAA64.EFI' if self.arm else 'BOOTX64.EFI')),
                             ('original-kernel', 'boot/vmlinuz-virt'), ('original-initrd', 'boot/initramfs-virt')]:
            self.cmd(['mcopy', '-i', str(fat), str(self.dir / name), '::/' + target], 30)

    def check(self):
        self.prepare()
        self.start()
        first = self.ready()
        init = subprocess.run(self.ssh + ['cloud-init status --wait --format=json'], stdout=subprocess.PIPE,
                              stderr=self.log, timeout=360)
        require(init.returncode in (0, 2) and len(init.stdout) <= 65536, 'NoCloud completion query failed')
        result = json.loads(init.stdout)
        # Warn categories and fatal module names are bounded and contain no
        # seed values. A recoverable cloud-init result still fails the task.
        if init.returncode or result.get('status') != 'done' or result.get('errors') or result.get('recoverable_errors'):
            report = json.dumps(result, ensure_ascii=True)
            classes = sorted(set(re.findall(r'(?i)deprecated|deprecation|schema|users.groups|ssh.authkey.fingerprints|'
                                            r'resizefs|growpart|set.passwords|set.hostname|update.hostname|'
                                            r'write.files|scripts.user|invalid|permission.denied', report)))
            raise ValueError('NoCloud startup degraded: ' + ','.join(classes or ['unclassified']))
        self.cmd(self.ssh + ['apk add --no-cache bash util-linux'], 360)
        for rel in PRODUCTS:
            result = self.ssh_output('sha256sum ' + str(ROOT / Path(rel).name)).split()
            require(len(result) == 2 and result[0].decode() == digest(self.repo / rel), 'Guest test source mismatch')
        self.phase('setup')
        self.poweroff()
        self.start()
        base = self.ready(old=first)
        self.phase('base')
        self.phase('pre-rollback')
        self.phase('prepare-activation', reboot=True)
        active = self.ready(old=base)
        self.phase('activated')
        self.fallback()
        self.poweroff()
        self.start(fallback=True)
        final = self.ready(old=active)
        require(final not in (first, base), 'Repeated boot ID')
        self.phase('post-rollback')
        self.poweroff()

    def close(self):
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
                    self.proc.wait(timeout=10)
            self.console.close()
            self.emulator_log.close()
        self.log.close()


def main():
    require(len(sys.argv) == 2 and sys.argv[1] in SOURCES and os.uname().machine == sys.argv[1],
            'Wrong test architecture')
    require(os.geteuid() != 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
            and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and os.environ.get('GITHUB_REPOSITORY') == 'masta-lee/mastaincus'
            and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'Hosted native-architecture runner required')
    if os.path.exists('/dev/kvm') or sys.argv[1] == 'x86_64':
        require(os.access('/dev/kvm', os.R_OK | os.W_OK), 'KVM present but inaccessible, or AMD64 runner missing KVM')
    repo = Path(__file__).resolve().parents[1]
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip() ==
            os.environ['GITHUB_SHA'], 'Checkout commit mismatch')
    directory = Path(os.environ['RUNNER_TEMP']) / 'incudal-host-kernel-lab'
    directory.mkdir(mode=0o700)
    for rel in PRODUCTS:
        print(f'{Path(rel).name} SHA256 {digest(repo / rel)}', flush=True)
    lab = Lab(sys.argv[1], directory, repo)
    try:
        lab.check()
    finally:
        lab.close()


if __name__ == '__main__':
    main()
