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
        cfg = {'users': [{'name': 'root', 'lock_passwd': False, 'passwd': password_hash,
                          'ssh_authorized_keys': [public]}],
               'disable_root': False, 'ssh_pwauth': False, 'ssh_deletekeys': True,
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
        self.console = (self.dir / f'console-{self.boots}.log').open('xb')
        self.proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=self.console, stderr=self.console)

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
            require(self.proc.poll() is None, 'VM exited before SSH')
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
            codes = re.findall(rb'\b(?:HARDENING_[A-Z_]{1,90}|E04_GUEST_FAILURE phase=[a-z-]{1,30} line=[0-9]{1,5})\b', tail)
            raise ValueError(name + ' failed' + (': ' + codes[-1].decode() if codes else ''))
        if not reboot:
            print(name + ' passed', flush=True)

    def poweroff(self):
        proc = subprocess.run(self.ssh + ['sync; poweroff'], timeout=45, stdout=self.log, stderr=self.log)
        require(proc.returncode in (0, 255), 'Poweroff refused')
        require(self.proc.wait(timeout=150) == 0, 'QEMU poweroff failed')
        self.proc = None
        self.console.close()

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
        self.cmd(self.ssh + ['cloud-init status --wait >/dev/null && apk add --no-cache bash util-linux'], 360)
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
