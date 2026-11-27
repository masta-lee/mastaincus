#!/usr/bin/env python3
"""Fixed, empty-host Alpine kernel patch transaction.

Only the authenticated onboarding gateway supplies this exact JSON protocol.
Package names, paths, boot arguments and shell commands are never caller input.
The kernel journal is separate from AppArmor; the root lock is shared. Native
VM boot acceptance is a controller gate, not inferred from an install receipt.
"""
import fcntl
import gzip
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path('/var/lib/incudal-hardening')
RECIPE = 'alpine-kernel-patch-v1'
ZERO = '0' * 64
UUID = re.compile(r'[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}')
HASH = re.compile(r'[a-f0-9]{64}')
VERSION = re.compile(r'([1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-r(0|[1-9][0-9]*)')
RELEASE = re.compile(r'([1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-(0|[1-9][0-9]*)-(virt|lts)')
PHASES = {'prepared-artifacts', 'packages-installed', 'boot-staged', 'prepared', 'reboot-intent', 'activated', 'rolled-back'}
PATH_ENV = '/usr/sbin:/usr/bin:/sbin:/bin'
MAX_TREE_BYTES = 768 * 1024 * 1024
MAX_TREE_FILES = 20000
MAX_JOURNAL_BYTES = 32 * 1024 * 1024
LOCK_FD = None
APPARMOR_JOURNAL_GUARD = None


def fail(code='HARDENING_KERNEL_JOURNAL_CONFLICT'):
    raise ValueError(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def strict_json(data):
    def unique_object(fields):
        value = {}
        for key, field in fields:
            if key in value:
                fail()
            value[key] = field
        return value
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=lambda _value: fail())


def journal_present(path):
    # Python 3.14 exists() also returns False for EACCES/EIO. Only a confirmed
    # missing journal permits another recipe; an unreadable one stays blocked.
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        fail('HARDENING_KERNEL_OTHER_JOURNAL_UNKNOWN')
    return True


def exact_object(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        fail()
    return value


def protected(path, directory=False, private=False, limit=MAX_TREE_BYTES):
    path = Path(path)
    for parent in [path, *path.parents]:
        info = parent.lstat()
        if info.st_uid != 0 or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o022:
            fail('HARDENING_KERNEL_UNTRUSTED_PATH')
        if parent != path and not stat.S_ISDIR(info.st_mode):
            fail('HARDENING_KERNEL_UNTRUSTED_PATH')
    info = path.lstat()
    if directory:
        if not stat.S_ISDIR(info.st_mode) or private and info.st_mode & 0o077:
            fail('HARDENING_KERNEL_UNTRUSTED_PATH')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit or private and info.st_mode & 0o077:
        fail('HARDENING_KERNEL_UNTRUSTED_PATH')
    return info


def file_proof(path, private=False, limit=MAX_TREE_BYTES):
    info = protected(path, private=private, limit=limit)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_mode) != (
                info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode):
            fail('HARDENING_KERNEL_SOURCE_CHANGED')
        hasher = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
        after = os.fstat(fd)
        if (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_mode) != (
                opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns, opened.st_mode):
            fail('HARDENING_KERNEL_SOURCE_CHANGED')
    finally:
        os.close(fd)
    return {'sha256': hasher.hexdigest(), 'size': info.st_size, 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}


def read(path, private=False, limit=1024 * 1024):
    proof = file_proof(path, private, limit)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, 'rb') as stream:
            data = stream.read(limit + 1)
        if len(data) != proof['size'] or digest(data) != proof['sha256']:
            fail('HARDENING_KERNEL_SOURCE_CHANGED')
        return data
    except BaseException:
        # fdopen owns the descriptor, including its exception path.
        raise


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode=0o600):
    protected(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        protected(path)
    fd, temporary = tempfile.mkstemp(prefix='.kernel-write-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def copy_checked(source, destination, wanted, mode=None, gid=None):
    if file_proof(source) != wanted:
        fail('HARDENING_KERNEL_SOURCE_CHANGED')
    protected(destination.parent, directory=True)
    if destination.exists() or destination.is_symlink():
        protected(destination)
    temporary = destination.parent / ('.kernel-copy-' + destination.name)
    wanted_mode = wanted['mode'] if mode is None else mode
    wanted_gid = wanted['gid'] if gid is None else gid
    if temporary.exists() or temporary.is_symlink():
        copied = file_proof(temporary)
        if copied['size'] > wanted['size'] or copied['mode'] != wanted_mode or copied['gid'] != wanted_gid:
            fail('HARDENING_KERNEL_COPY_CHANGED')
        # Interrupted copies are a prefix of their exact authenticated source.
        # Unexpected bytes are preserved; they do not authorize truncation.
        with source.open('rb') as original, temporary.open('rb') as partial:
            while True:
                chunk = partial.read(1024 * 1024)
                if not chunk:
                    break
                if original.read(len(chunk)) != chunk:
                    fail('HARDENING_KERNEL_COPY_CHANGED')
    input_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    output_fd = os.open(temporary, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(input_fd, 'rb') as src, os.fdopen(output_fd, 'wb') as dst:
            os.fchmod(dst.fileno(), wanted_mode)
            os.fchown(dst.fileno(), 0, wanted_gid)
            shutil.copyfileobj(src, dst, 1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        copied = file_proof(Path(temporary))
        if copied['sha256'] != wanted['sha256'] or copied['size'] != wanted['size'] or file_proof(source) != wanted:
            fail('HARDENING_KERNEL_SOURCE_CHANGED')
        os.replace(temporary, destination)
        sync_directory(destination.parent)
    finally:
        # Normal exceptions can leave only our proven prefix. Preserve it for
        # the same-source recovery; do not unlink an unknown replacement.
        pass


def boot():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not UUID.fullmatch(value):
        fail('HARDENING_KERNEL_BOOT_UNKNOWN')
    return value


def current_request(value):
    if time.time() * 1000 >= value['expiresAt']:
        fail('HARDENING_REQUEST_EXPIRED')


def request(value):
    exact_object(value, {'action', 'nodeId', 'requestId', 'identityHash', 'bootId', 'prepareHash', 'recipe', 'architecture',
                         'expiresAt', 'customers', 'expectedPlanHash'})
    if not isinstance(value['action'], str) or value['action'] not in {'inspect', 'prepare', 'status', 'reboot', 'rollback', 'verify'}:
        fail('HARDENING_KERNEL_REQUEST_UNKNOWN')
    if any(not isinstance(value[key], str) or not UUID.fullmatch(value[key]) for key in ['nodeId', 'requestId', 'bootId']):
        fail('HARDENING_KERNEL_REQUEST_UNKNOWN')
    if any(not isinstance(value[key], str) or not HASH.fullmatch(value[key]) for key in ['identityHash', 'prepareHash']):
        fail('HARDENING_KERNEL_REQUEST_UNKNOWN')
    if value['recipe'] != RECIPE or not isinstance(value['architecture'], str) or value['architecture'] not in {'x86_64', 'aarch64'} or value['customers'] != []:
        fail('HARDENING_KERNEL_REQUEST_UNKNOWN')
    if value['action'] == 'inspect':
        if value['prepareHash'] != ZERO or value['expectedPlanHash'] is not None:
            fail('HARDENING_KERNEL_REQUEST_UNKNOWN')
    elif not isinstance(value['expectedPlanHash'], str) or not HASH.fullmatch(value['expectedPlanHash']):
        fail('HARDENING_KERNEL_REQUEST_UNKNOWN')
    now = time.time() * 1000
    if type(value['expiresAt']) is not int or not now < value['expiresAt'] <= now + 60000:
        fail('HARDENING_REQUEST_EXPIRED')
    return value


def identity(value):
    if read(Path('/etc/incudal-onboarding-id'), limit=256).decode().strip() != value['nodeId'] or os.uname().machine != value['architecture']:
        fail('HARDENING_IDENTITY_CHANGED')
    if any(Path(path).exists() for path in ['/opt/incudal', '/usr/local/sbin/incudal-onboarding-gateway',
            '/etc/incudal-onboarding-gateway', '/opt/incudal-gateway', '/etc/incudal-gateway']):
        fail('HARDENING_CONTROL_PLANE_TARGET')


def trusted_program(name):
    path = shutil.which(name, path=PATH_ENV)
    if not path:
        fail('HARDENING_KERNEL_TOOLS_REQUIRED')
    unresolved = Path(path)
    for parent in unresolved.parents:
        protected(parent, directory=True)
    if unresolved.is_symlink():
        info = unresolved.lstat()
        if info.st_uid != 0:
            fail('HARDENING_KERNEL_UNTRUSTED_PATH')
    resolved = unresolved.resolve(strict=True)
    proof = file_proof(resolved)
    if proof['mode'] & 0o111 == 0:
        fail('HARDENING_KERNEL_TOOLS_REQUIRED')
    return {'path': str(resolved), 'proof': proof}


def command_group_alive(group):
    checked, deadline = 0, time.monotonic() + 2
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        checked += 1
        if checked > 65536 or time.monotonic() > deadline:
            fail('HARDENING_KERNEL_PROCESS_QUERY_INCOMPLETE')
        try:
            if os.getpgid(int(path.name)) != group:
                continue
            raw = (path / 'stat').read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue
        at = raw.rfind(') ')
        fields = raw[at + 2:].split()
        if len(raw) > 8192 or at < 0 or len(fields) < 3:
            fail('HARDENING_KERNEL_PROCESS_QUERY_INCOMPLETE')
        if int(fields[2]) == group and fields[0] not in {'Z', 'X'}:
            return True
    return False


def command(args, timeout=8, value=None):
    if value is not None:
        current_request(value)
        timeout = min(timeout, max(0.001, (value['expiresAt'] - time.time() * 1000) / 1000))
    # Generators can leave a cpio/gzip child behind after their shell exits.
    # A separate session bounds this command's descendants and its output;
    # no package child may retain the task lock or keep writing after failure.
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(args, stdout=out, stderr=errors, start_new_session=True,
                                   env={'PATH': PATH_ENV, 'LC_ALL': 'C'}, pass_fds=(() if LOCK_FD is None else (LOCK_FD,)))
        deadline = time.monotonic() + timeout
        unreaped = True
        try:
            while True:
                # Keep the leader unreaped until its group is inspected. Its
                # PID cannot be recycled into an unrelated group we might kill.
                exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if os.fstat(out.fileno()).st_size + os.fstat(errors.fileno()).st_size > 4 * 1024 * 1024:
                    fail('HARDENING_KERNEL_PREPARE_FAILED')
                if exited is not None:
                    break
                if time.monotonic() >= deadline:
                    fail('HARDENING_KERNEL_STEP_TIMEOUT')
                time.sleep(min(.05, max(.001, deadline - time.monotonic())))
            if exited.si_code != os.CLD_EXITED or exited.si_status:
                fail('HARDENING_KERNEL_PREPARE_FAILED')
            if command_group_alive(process.pid):
                fail('HARDENING_KERNEL_CHILD_PENDING')
            if value is not None:
                current_request(value)
            out.seek(0); errors.seek(0)
            result = out.read(4 * 1024 * 1024) + errors.read(4 * 1024 * 1024)
            if len(result) > 4 * 1024 * 1024:
                fail('HARDENING_KERNEL_PREPARE_FAILED')
            process.wait(timeout=2)
            unreaped = False
            return result
        except BaseException:
            if unreaped:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    fail('HARDENING_KERNEL_CHILD_PENDING')
            raise


def version_release(version, flavor):
    match = VERSION.fullmatch(version) if isinstance(version, str) and len(version) <= 64 else None
    if not match or flavor not in {'linux-virt', 'linux-lts'}:
        fail('HARDENING_KERNEL_VERSION_UNSUPPORTED')
    return '.'.join(match.groups()[:3]) + '-' + match[4] + '-' + flavor[6:]


def release_version(release, flavor):
    match = RELEASE.fullmatch(release) if isinstance(release, str) and len(release) <= 64 else None
    if not match or match[5] != flavor[6:]:
        fail('HARDENING_KERNEL_VERSION_UNSUPPORTED')
    return '.'.join(match.groups()[:3]) + '-r' + match[4]


def same_series(before, expected):
    a, b = VERSION.fullmatch(before), VERSION.fullmatch(expected)
    return bool(a and b and a.groups()[:2] == b.groups()[:2] and tuple(map(int, b.groups()[2:])) > tuple(map(int, a.groups()[2:])))


def installed_packages(value=None):
    try:
        output = command([trusted_program('apk')['path'], 'info', '-v'], timeout=8, value=value).decode()
    except ValueError as error:
        if str(error) != 'HARDENING_KERNEL_STEP_TIMEOUT':
            raise
        # Only this read-only inventory may retry after command() has stopped
        # its process group. Recheck the tool and the original request expiry.
        if value is not None:
            current_request(value)
        output = command([trusted_program('apk')['path'], 'info', '-v'], timeout=20, value=value).decode()
    result = {}
    for line in output.splitlines():
        match = re.fullmatch(r'([a-zA-Z0-9+_.-]+)-([0-9][a-zA-Z0-9+_.~-]*)', line)
        if not match or match[1] in result:
            fail('HARDENING_KERNEL_PACKAGE_INVENTORY_UNKNOWN')
        result[match[1]] = match[2]
    if not result or len(result) > 3000:
        fail('HARDENING_KERNEL_PACKAGE_INVENTORY_UNKNOWN')
    return result


def package_context():
    paths = ['/etc/alpine-release', '/etc/apk/world', '/etc/apk/repositories', '/lib/apk/db/installed']
    result = {path: file_proof(Path(path), limit=4 * 1024 * 1024) for path in paths}
    keys = Path('/etc/apk/keys')
    protected(keys, directory=True)
    entries = sorted(keys.iterdir())
    if not 1 <= len(entries) <= 32:
        fail('HARDENING_KERNEL_PACKAGE_SOURCE_UNKNOWN')
    result.update({str(path): file_proof(path, limit=16384) for path in entries})
    return result


def official_repositories(branch):
    text = read(Path('/etc/apk/repositories'), limit=65536).decode()
    if '\x00' in text or '\r' in text:
        fail('HARDENING_KERNEL_PACKAGE_SOURCE_UNKNOWN')
    seen = set()
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if line != line.strip() or len(line) > 256:
            fail('HARDENING_KERNEL_PACKAGE_SOURCE_UNKNOWN')
        url = urlsplit(line)
        if url.scheme not in {'http', 'https'} or not re.fullmatch(r'dl-(?:cdn|[1-9][0-9]?)\.alpinelinux\.org', url.netloc) or url.query or url.fragment:
            fail('HARDENING_KERNEL_PACKAGE_SOURCE_UNKNOWN')
        match = re.fullmatch(r'/alpine/v' + re.escape(branch) + r'/(main|community)/?', url.path)
        if not match or match[1] in seen:
            fail('HARDENING_KERNEL_PACKAGE_SOURCE_UNKNOWN')
        seen.add(match[1])
    if 'main' not in seen:
        fail('HARDENING_KERNEL_PACKAGE_SOURCE_UNKNOWN')
    return ('https://dl-cdn.alpinelinux.org/alpine/v' + branch + '/main\n' +
            ('https://dl-cdn.alpinelinux.org/alpine/v' + branch + '/community\n' if 'community' in seen else '')).encode()


def module_manifest(path, require_modules=True):
    protected(path, directory=True)
    result, total = {}, 0
    for directory, subdirs, files in os.walk(path, followlinks=False):
        base = Path(directory)
        protected(base, directory=True)
        for name in sorted(subdirs):
            child = base / name
            protected(child, directory=True)
            result[str(child.relative_to(path))] = {'directory': True, 'mode': stat.S_IMODE(child.stat().st_mode)}
        for name in sorted(files):
            child = base / name
            proof = file_proof(child, limit=64 * 1024 * 1024)
            result[str(child.relative_to(path))] = proof
            total += proof['size']
            if total > MAX_TREE_BYTES or len(result) > MAX_TREE_FILES:
                fail('HARDENING_KERNEL_DISK_LOW')
    if require_modules and (not result or not any(name.endswith(('.ko', '.ko.gz', '.ko.xz', '.ko.zst')) for name in result)):
        fail('HARDENING_KERNEL_MODULES_UNKNOWN')
    return result


def manifest_size(manifest):
    return sum(row.get('size', 0) for row in manifest.values())


def copy_modules(source, target, manifest, value=None):
    if module_manifest(source) != manifest:
        fail('HARDENING_KERNEL_MODULES_CHANGED')
    target.mkdir(mode=0o700, exist_ok=True)
    protected(target, directory=True, private=True)
    for name, proof in sorted(manifest.items(), key=lambda pair: (pair[0].count('/'), pair[0])):
        if value is not None:
            current_request(value)
        destination = target / name
        if proof.get('directory') is True:
            destination.mkdir(mode=proof['mode'], exist_ok=True)
            protected(destination, directory=True)
        elif destination.exists() and not (destination.parent / ('.kernel-copy-' + destination.name)).exists():
            if file_proof(destination) != proof:
                fail('HARDENING_KERNEL_BACKUP_CHANGED')
        else:
            if destination.exists() and file_proof(destination) != proof:
                fail('HARDENING_KERNEL_BACKUP_CHANGED')
            copy_checked(source / name, destination, proof)
    if module_manifest(target) != manifest:
        fail('HARDENING_KERNEL_MODULES_CHANGED')


def linux_arguments(data, bootloader, flavor):
    text = data.decode()
    if '\x00' in text or '\r' in text:
        fail('HARDENING_KERNEL_BOOT_LAYOUT_UNSUPPORTED')
    if bootloader == 'grub':
        linux = re.findall(r'^\s*linux(?:efi)?\s+(\S+)\s+([^\n]+)$', text, re.M)
        initrd = re.findall(r'^\s*initrd(?:efi)?\s+(\S+)\s*$', text, re.M)
        if len(linux) != 1 or len(initrd) != 1 or linux[0][0] != '/boot/vmlinuz-' + flavor[6:] or initrd[0] != '/boot/initramfs-' + flavor[6:]:
            fail('HARDENING_KERNEL_BOOT_LAYOUT_UNSUPPORTED')
        args = linux[0][1].split()
    else:
        labels = re.findall(r'^\s*LABEL\s+(\S+)\s*$', text, re.I | re.M)
        linux = re.findall(r'^\s*(?:LINUX|KERNEL)\s+(\S+)\s*$', text, re.I | re.M)
        initrd = re.findall(r'^\s*INITRD\s+(\S+)\s*$', text, re.I | re.M)
        lines = re.findall(r'^\s*APPEND\s+([^\n]+)$', text, re.I | re.M)
        if len(labels) != 1 or linux != ['/boot/vmlinuz-' + flavor[6:]] and linux != ['vmlinuz-' + flavor[6:]] or \
                initrd not in [['/boot/initramfs-' + flavor[6:]], ['initramfs-' + flavor[6:]]] or len(lines) != 1:
            fail('HARDENING_KERNEL_BOOT_LAYOUT_UNSUPPORTED')
        args = lines[0].split()
    if any(not re.fullmatch(r'[A-Za-z0-9_=,.:/+@%-]+', arg) for arg in args) or sum(arg.startswith('root=') for arg in args) != 1:
        fail('HARDENING_KERNEL_BOOT_LAYOUT_UNSUPPORTED')
    return args


def runtime_identity():
    paths = [Path('/etc/incudal-onboarding-id'), Path('/var/lib/incus/server.crt')]
    ssh = sorted(Path('/etc/ssh').glob('ssh_host_*_key.pub'))
    if not ssh or len(ssh) > 8:
        fail('HARDENING_IDENTITY_MISSING')
    paths += ssh
    paths += [path for path in [Path('/etc/machine-id'), Path('/etc/incudal-agent.json'), Path('/etc/incudal-agent/config.json')]
              if path.exists()]
    wg = Path('/etc/wireguard')
    if wg.exists():
        protected(wg, directory=True)
        paths += sorted(wg.glob('*.conf'))
    return {str(path): file_proof(path, limit=1024 * 1024) for path in paths}


def boot_baseline(flavor, running):
    grub, extlinux = Path('/boot/grub/grub.cfg'), Path('/boot/extlinux.conf')
    if grub.exists() == extlinux.exists() or Path('/boot/loader/loader.conf').exists():
        fail('HARDENING_KERNEL_BOOT_LAYOUT_UNSUPPORTED')
    bootloader = 'grub' if grub.exists() else 'extlinux'
    config = grub if grub.exists() else extlinux
    arguments = linux_arguments(read(config), bootloader, flavor)
    artifacts = [config, Path('/boot/vmlinuz-' + flavor[6:]), Path('/boot/initramfs-' + flavor[6:])]
    for path in [Path('/boot/config-' + flavor[6:]), Path('/boot/System.map-' + flavor[6:])]:
        if path.exists():
            artifacts.append(path)
    controls = [Path('/etc/mkinitfs/mkinitfs.conf')]
    controls += sorted(Path('/etc/mkinitfs/features.d').glob('*'))
    controls += [Path('/etc/default/grub'), *sorted(Path('/etc/grub.d').glob('*'))] if bootloader == 'grub' else [Path('/etc/update-extlinux.conf')]
    if len(controls) > 128 or any(not path.exists() for path in controls):
        fail('HARDENING_KERNEL_TOOLS_REQUIRED')
    tools = ['apk', 'depmod', 'mkinitfs', 'incus', 'rc-service', 'chronyc', 'reboot']
    tools += ['grub-mkconfig', 'grub-script-check'] if bootloader == 'grub' else ['update-extlinux']
    # The only executable scripts sourced by the ordinary boot generator must
    # be root-owned and stable too; none of their arguments are replaced.
    return {'bootloader': bootloader, 'config': str(config), 'arguments': arguments,
            'artifacts': {str(path): file_proof(path) for path in artifacts},
            'controls': {str(path): file_proof(path, limit=1024 * 1024) for path in controls},
            'tools': {name: trusted_program(name) for name in tools},
            'modules': module_manifest(Path('/lib/modules') / running),
            'identity': runtime_identity(), 'cmdline': Path('/proc/cmdline').read_text().strip()}


def local_incus(path, value=None):
    # Never follow the CLI's mutable default remote. Only this host's root
    # Incus UNIX socket can prove that all its projects are empty and idle.
    socket_path = Path('/var/lib/incus/unix.socket')
    protected(socket_path.parent, directory=True)
    info = socket_path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o007:
        fail('HARDENING_KERNEL_INCUS_IDENTITY_UNKNOWN')
    if value is not None:
        current_request(value)
    class LocalConnection(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(8)
            self.sock.connect(str(socket_path))
            credentials = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
            _, uid, _ = struct.unpack('3i', credentials)
            current = socket_path.lstat()
            if uid != 0 or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                fail('HARDENING_KERNEL_INCUS_IDENTITY_UNKNOWN')
    client = LocalConnection('localhost', timeout=8)
    try:
        client.request('GET', path)
        response = client.getresponse()
        body = response.read(1024 * 1024 + 1)
        if response.status != 200 or len(body) > 1024 * 1024:
            fail('HARDENING_KERNEL_INCUS_UNREADY')
        decoded = strict_json(body)
        if not isinstance(decoded, dict) or decoded.get('type') != 'sync' or decoded.get('status_code') != 200:
            fail('HARDENING_KERNEL_INCUS_UNREADY')
        if value is not None:
            current_request(value)
        return decoded.get('metadata')
    finally:
        client.close()


def empty_remote(value=None):
    inventory = local_incus('/1.0/instances?recursion=1&all-projects=true', value)
    if not isinstance(inventory, list) or inventory:
        fail('HARDENING_KERNEL_HOST_OCCUPIED')
    operations = local_incus('/1.0/operations?recursion=1&all-projects=true', value)
    if not isinstance(operations, dict) or any(not isinstance(group, list) or any(not isinstance(row, dict) or
            not isinstance(row.get('status'), str) or row['status'] not in {'Success', 'Failure', 'Cancelled'} for row in group) for group in operations.values()):
        fail('HARDENING_KERNEL_HOST_BUSY')


def resources(required=256 * 1024 * 1024, boot_required=32 * 1024 * 1024):
    for path in ['/', '/boot', str(ROOT)]:
        space = os.statvfs(path)
        if space.f_flag & os.ST_RDONLY:
            fail('HARDENING_FILESYSTEM_READONLY')
        if space.f_bavail * space.f_frsize < (boot_required if path == '/boot' else required) or space.f_favail < 1024:
            fail('HARDENING_DISK_LOW')
    memory = re.search(r'^MemAvailable:\s+(\d+) kB$', Path('/proc/meminfo').read_text(), re.M)
    if not memory or int(memory[1]) < 128 * 1024:
        fail('HARDENING_MEMORY_LOW')
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            name = (path / 'comm').read_text().strip()
        except OSError:
            continue
        if name in {'apk', 'apt', 'apt-get', 'dpkg', 'rpm', 'dnf'}:
            fail('HARDENING_PACKAGE_BUSY')


def installation_changes(output, before, flavor, expected=None, reinstall=False):
    text = output.decode() if isinstance(output, bytes) else output
    if re.search(r'\b(?:Installing|Removing|Purging|Downgrading)\b', text):
        fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
    pattern = r'(Upgrading|Reinstalling) ([a-zA-Z0-9+_.-]+) \(([0-9][a-zA-Z0-9+_.~-]*)(?: -> ([0-9][a-zA-Z0-9+_.~-]*))?\)'
    changes = re.findall(pattern, text)
    if len(changes) != 1 or text.count('Upgrading ') + text.count('Reinstalling ') != 1:
        fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
    action, name, old, new = changes[0]
    if name != flavor or name not in before:
        fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
    if reinstall:
        if action != 'Reinstalling' or old != expected or new or before[name] != expected:
            fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
        return expected
    if action != 'Upgrading' or old != before[name] or not same_series(old, new) or expected is not None and new != expected:
        fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
    return new


def cache_manifest(path):
    protected(path, directory=True, private=True)
    files = sorted(path.iterdir())
    if not 2 <= len(files) <= 32:
        fail('HARDENING_KERNEL_CACHE_UNKNOWN')
    return {entry.name: file_proof(entry, private=True) for entry in files}


def kernel_payload(path, flavor, version):
    """Bounded legacy signed-APK payload parser; ADB v3 is not guessed.

    Signature trust comes from apk update/fetch/verify first. This parser only
    proves which bytes the approved package may replace before its DB commit.
    """
    initial = file_proof(path, private=True, limit=256 * 1024 * 1024)
    expected_release = version_release(version, flavor)
    result, metadata, signed, total, count = {}, None, False, 0, 0
    # Stream the concatenated signature/control/data tar members. Reading a
    # complete unpacked kernel in memory would exhaust the smallest E2 hosts.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
      if source.read(2) != b'\x1f\x8b':
        fail('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
      source.seek(0)
      with gzip.GzipFile(fileobj=source) as decoder, tarfile.open(fileobj=decoder, mode='r|', ignore_zeros=True) as archive:
        for entry in archive:
            total += entry.size
            count += 1
            if total > MAX_TREE_BYTES or count > MAX_TREE_FILES:
                fail('HARDENING_KERNEL_DISK_LOW')
            name = entry.name.removeprefix('./').rstrip('/')
            if not name or name.startswith('/') or any(part in {'', '.', '..'} for part in name.split('/')):
                fail('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
            if name.startswith('.SIGN.'):
                if not entry.isfile() or signed or entry.size > 16384:
                    fail('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
                signed = True
                continue
            if name == '.PKGINFO':
                if not entry.isfile() or metadata is not None or entry.size > 65536:
                    fail('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
                metadata = archive.extractfile(entry).read().decode()
                continue
            if name.startswith('.'):
                if name not in {'.pre-install', '.post-install', '.pre-upgrade', '.post-upgrade', '.trigger'} or not entry.isfile() or entry.size > 65536:
                    fail('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
                continue
            if entry.isdir():
                if entry.uid != 0 or entry.gid != 0 or entry.mode & 0o022 or name not in {'boot', 'lib', 'lib/modules', 'lib/modules/' + expected_release} and \
                        not name.startswith('lib/modules/' + expected_release + '/'):
                    fail('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
                continue
            if not entry.isfile() or entry.uid != 0 or entry.gid != 0 or entry.mode & 0o022 or entry.size > 64 * 1024 * 1024:
                fail('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
            permitted = name in {'boot/vmlinuz-' + flavor[6:], 'boot/config-' + flavor[6:], 'boot/System.map-' + flavor[6:]} or \
                name.startswith('lib/modules/' + expected_release + '/')
            if not permitted or '/' + name in result:
                fail('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
            stream = archive.extractfile(entry)
            hasher = hashlib.sha256()
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
            result['/' + name] = {'sha256': hasher.hexdigest(), 'size': entry.size, 'mode': entry.mode, 'uid': 0, 'gid': 0}
    if file_proof(path, private=True) != initial:
        fail('HARDENING_KERNEL_CACHE_CHANGED')
    if not signed or metadata is None or '/boot/vmlinuz-' + flavor[6:] not in result or \
            not any(path.endswith(('.ko', '.ko.gz', '.ko.xz', '.ko.zst')) for path in result):
        fail('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
    # Every identity field must occur exactly once, including conflicting
    # duplicates with a different value that a package consumer might select.
    for field, expected in {'pkgname': flavor, 'pkgver': version, 'arch': os.uname().machine}.items():
        if re.findall(r'^[ \t]*' + field + r'[ \t]*=[ \t]*([^\r\n]*)$', metadata, re.M) != [expected]:
            fail('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
    return result


def private_cache_permissions(path):
    protected(path, directory=True, private=True)
    for entry in path.iterdir():
        proof = file_proof(entry)
        if not re.fullmatch(r'(?:APKINDEX\.[a-f0-9]+\.tar\.gz|(?:[a-zA-Z0-9_.-]+\.)?adb|linux-(?:virt|lts)-[0-9][a-zA-Z0-9+_.~-]*\.apk)', entry.name):
            fail('HARDENING_KERNEL_CACHE_UNKNOWN')
        fd = os.open(entry, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if file_proof(entry) != proof:
                fail('HARDENING_KERNEL_CACHE_CHANGED')
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
    sync_directory(path)


def package_base(directory):
    return [trusted_program('apk')['path'], '--cache-dir', str(directory / 'cache'), '--repositories-file', str(directory / 'repositories'),
            '--timeout', '8', '--no-scripts', '--no-commit-hooks']


def signed_policy_candidate(output, flavor, branch, architecture, installed):
    lines = output.decode().splitlines() if isinstance(output, bytes) else output.splitlines()
    if not lines or lines[0] != flavor + ' policy:' or len(lines) > 128:
        fail('HARDENING_KERNEL_PACKAGE_POLICY_UNKNOWN')
    rows, version = {}, None
    for line in lines[1:]:
        match = re.fullmatch(r'  ([0-9.]+-r[0-9]+):', line)
        if match:
            if not VERSION.fullmatch(match[1]) or match[1] in rows:
                fail('HARDENING_KERNEL_PACKAGE_POLICY_UNKNOWN')
            version = match[1]; rows[version] = []
            continue
        source = re.fullmatch(r'    (\S+)', line)
        if source is None or version is None:
            fail('HARDENING_KERNEL_PACKAGE_POLICY_UNKNOWN')
        address = source[1]
        if address not in {'lib/apk/db/installed', '/lib/apk/db/installed'} and not re.fullmatch(
                r'https://dl-cdn\.alpinelinux\.org/alpine/v' + re.escape(branch) + r'/(?:main|community)(?:/' + re.escape(architecture) + r'(?:/APKINDEX\.tar\.gz)?)?', address):
            fail('HARDENING_KERNEL_PACKAGE_SOURCE_UNKNOWN')
        rows[version].append(address)
    candidates = [version for version, sources in rows.items() if any(source.startswith('https://') for source in sources)]
    series = VERSION.fullmatch(installed).groups()[:2]
    compatible = [version for version in candidates if VERSION.fullmatch(version).groups()[:2] == series]
    if not compatible:
        fail('HARDENING_KERNEL_SERIES_CHANGE_REQUIRED')
    candidate = max(compatible, key=lambda item: tuple(map(int, VERSION.fullmatch(item).groups())))
    if candidate != installed and not same_series(installed, candidate):
        fail('HARDENING_KERNEL_PACKAGE_DOWNGRADE_REFUSED')
    return candidate


def signed_planning_cache(value, directory, branch, flavor, expected, base):
    # Inspection and release updates reuse an authenticated package, rather
    # than downloading a complete kernel on every fleet polling round. The
    # later transaction receives its own immutable copy of these exact bytes.
    shared = ROOT / ('kernel-planning-cache-' + branch + '-' + flavor + '-' + value['architecture'])
    shared.mkdir(mode=0o700, exist_ok=True)
    protected(shared, directory=True, private=True)
    source_base = list(base)
    source_base[source_base.index('--cache-dir') + 1] = str(shared)
    command([*source_base, 'update'], timeout=10, value=value)
    private_cache_permissions(shared)
    policy_candidate = signed_policy_candidate(command([*source_base, 'policy', flavor], timeout=8, value=value),
                                               flavor, branch, value['architecture'], expected[flavor])
    output = command([*source_base, '--simulate', 'upgrade', flavor], timeout=8, value=value)
    text = output.decode()
    if not re.search(r'\b(?:Installing|Upgrading|Downgrading|Removing|Purging|Reinstalling)\b', text):
        if policy_candidate != expected[flavor]:
            fail('HARDENING_KERNEL_WORLD_CONSTRAINT')
        return None
    candidate = installation_changes(text, expected, flavor)
    if candidate != policy_candidate:
        fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
    archive = shared / (flavor + '-' + candidate + '.apk')
    verified = False
    if journal_present(archive):
        before = file_proof(archive, private=True, limit=256 * 1024 * 1024)
        try:
            command([trusted_program('apk')['path'], '--no-network', 'verify', str(archive)], timeout=8, value=value)
        except ValueError as error:
            if str(error) != 'HARDENING_KERNEL_PREPARE_FAILED':
                raise
            rejected = ROOT / 'kernel-cache-evidence'
            rejected.mkdir(mode=0o700, exist_ok=True)
            protected(rejected, directory=True, private=True)
            target = rejected / (archive.name + '-' + before['sha256'] + '-' + str(int(time.time() * 1000)))
            if target.exists() or target.is_symlink() or file_proof(archive, private=True) != before:
                fail('HARDENING_KERNEL_CACHE_CHANGED')
            current_request(value)
            os.rename(archive, target)
            sync_directory(shared)
            sync_directory(rejected)
        else:
            # An authenticated unsupported archive format is a capability
            # boundary, not corruption; never redownload/quarantine it in a loop.
            kernel_payload(archive, flavor, candidate)
            verified = True
    if not verified:
        # APK 3's non-recursive MATCH_EXACT compares a package name, not a
        # version constraint. Fetch only this fixed kernel name: recursive
        # fetch would also pull initramfs dependencies outside our plan.
        # The already signed policy and simulation fixed `candidate`; the
        # exact filename, signature and payload identity still have to match.
        command([*source_base, 'fetch', '--output', str(shared), flavor], timeout=10, value=value)
        private_cache_permissions(shared)
        if not journal_present(archive):
            fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
        command([trusted_program('apk')['path'], '--no-network', 'verify', str(archive)], timeout=8, value=value)
        kernel_payload(archive, flavor, candidate)
    index_files = [path for path in shared.iterdir() if path.name.endswith(('.tar.gz', '.adb'))]
    if not 1 <= len(index_files) <= 8:
        fail('HARDENING_KERNEL_CACHE_UNKNOWN')
    for source in [*index_files, archive]:
        proof = file_proof(source, private=True)
        copy_checked(source, directory / 'cache' / source.name, proof)
    return candidate


def fixed_context(context):
    return {path: proof for path, proof in context.items() if path != '/lib/apk/db/installed'}


def simulate_original(transaction, directory, value, current, reinstall=False):
    base = package_base(directory)
    expected = transaction['plan']['candidateVersion']
    flavor = transaction['plan']['flavor']
    # APK fix/upgrade resolve complete argv strings as package names, not version
    # atoms. The immutable offline cache and exact Expected simulation below
    # bind either bare-name action to its original authenticated version.
    atoms = [flavor]
    args = [*base, '--no-network', '--simulate', 'fix', '--reinstall', *atoms] if reinstall else [*base, '--no-network', '--simulate', 'upgrade', *atoms]
    output = command(args, timeout=8, value=value)
    installation_changes(output, current, flavor, expected, reinstall)


def plan_public(transaction):
    return transaction['plan']


def source_transaction(value, directory, previous=None):
    """Read-only signed planning. Its private cache is not a maintenance fence."""
    current_request(value)
    branch_match = re.fullmatch(r'(3\.(?:22|23|24))\.[0-9]+(?:_alpha[0-9]+)?\n?', read(Path('/etc/alpine-release'), limit=64).decode())
    if not branch_match:
        fail('HARDENING_KERNEL_BRANCH_UNSUPPORTED')
    branch = branch_match[1]
    context = package_context()
    before = installed_packages(value)
    flavors = [name for name in ['linux-virt', 'linux-lts'] if name in before]
    if len(flavors) != 1:
        fail('HARDENING_KERNEL_FLAVOR_AMBIGUOUS')
    flavor, running = flavors[0], os.uname().release
    if not VERSION.fullmatch(before[flavor]) or not RELEASE.fullmatch(running) or release_version(running, flavor) is None:
        fail('HARDENING_KERNEL_VERSION_UNSUPPORTED')
    baseline = boot_baseline(flavor, running)
    source = official_repositories(branch)
    directory.mkdir(mode=0o700, exist_ok=False)
    atomic(directory / 'planning.json', encoded({'version': 1, 'identity': identity_fields(value), 'phase': 'source-only'}))
    cache = directory / 'cache'
    cache.mkdir(mode=0o700)
    atomic(directory / 'repositories', source)
    base = package_base(directory)
    reactivation = running != version_release(before[flavor], flavor)
    if reactivation:
        if previous is None or previous['phase'] != 'rolled-back' or previous['identity']['nodeId'] != value['nodeId'] or \
                previous['identity']['identityHash'] != value['identityHash'] or previous['identity']['architecture'] != value['architecture'] or \
                previous['plan']['flavor'] != flavor or previous['plan']['candidateVersion'] != before[flavor] or \
                previous['plan']['runningRelease'] != running or not same_series(release_version(running, flavor), before[flavor]):
            fail('HARDENING_KERNEL_RUNNING_PACKAGE_MISMATCH')
        old_transaction = previous['transaction']
        verify_rollback_files(previous, strict=False)
        if before[flavor] != old_transaction['expectedInstalled'][flavor]:
            fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
        old_directory = run_directory(previous)
        if cache_manifest(old_directory / 'cache') != old_transaction['cache'] or read(old_directory / 'repositories', private=True) != source:
            fail('HARDENING_KERNEL_CACHE_CHANGED')
        for name, proof in old_transaction['cache'].items():
            copy_checked(old_directory / 'cache' / name, cache / name, proof)
        expected = before[flavor]
    else:
        expected = signed_planning_cache(value, directory, branch, flavor, before, base)
        if expected is None:
            if package_context() != context or installed_packages(value) != before:
                fail('HARDENING_KERNEL_SOURCE_CHANGED')
            return {'status': 'up-to-date', 'branch': branch, 'flavor': flavor, 'bootloader': baseline['bootloader'],
                    'runningRelease': running, 'installedVersion': before[flavor], 'candidateVersion': None,
                    'candidateRelease': None, 'planHash': None, 'reason': None}, None
    private_cache_permissions(cache)
    archive = cache / (flavor + '-' + expected + '.apk')
    command([trusted_program('apk')['path'], '--no-network', 'verify', str(archive)], timeout=8, value=value)
    payload = kernel_payload(archive, flavor, expected)
    transaction = {'plan': {'status': 'available', 'branch': branch, 'flavor': flavor, 'bootloader': baseline['bootloader'],
                           'runningRelease': running, 'installedVersion': before[flavor], 'candidateVersion': expected,
                           'candidateRelease': version_release(expected, flavor), 'planHash': None, 'reason': None},
                   'context': context, 'installed': before, 'expectedInstalled': {**before, flavor: expected},
                   'baseline': baseline, 'cache': cache_manifest(cache), 'payload': payload, 'reactivation': reactivation,
                   'staging': None, 'candidateArtifacts': None, 'candidateModules': None}
    # A metadata commit may precede its payload write. Both modes retain the
    # exact original signed archive and never choose a newer upstream plan.
    simulate_original(transaction, directory, value, before, reinstall=reactivation)
    simulate_original(transaction, directory, value, before, reinstall=reactivation)
    if installed_packages(value) != before or package_context() != context or boot_baseline(flavor, running) != baseline or cache_manifest(cache) != transaction['cache']:
        fail('HARDENING_KERNEL_SOURCE_CHANGED')
    transaction['plan']['planHash'] = digest(encoded({key: field for key, field in transaction.items() if key not in {'staging', 'candidateArtifacts', 'candidateModules'}}))
    current_request(value)
    return transaction['plan'], transaction


def cleanup_inspection(directory):
    # Delete only the exact scratch files this planner creates; unexpected
    # entries remain evidence and cannot become a recursive removal target.
    if not directory.exists():
        return
    if directory.parent != ROOT or not re.fullmatch(r'kernel-inspect-' + UUID.pattern, directory.name):
        fail('HARDENING_KERNEL_UNTRUSTED_PATH')
    protected(directory, directory=True, private=True)
    entries = list(directory.iterdir())
    if {entry.name for entry in entries} - {'repositories', 'cache', 'planning.json'}:
        fail('HARDENING_KERNEL_UNTRUSTED_PATH')
    for entry in entries:
        if entry.name == 'cache':
            protected(entry, directory=True, private=True)
            for child in entry.iterdir():
                protected(child)
                child.unlink()
            entry.rmdir()
        else:
            protected(entry)
            entry.unlink()
    directory.rmdir()
    sync_directory(ROOT)


def identity_fields(value):
    return {key: value[key] for key in ['nodeId', 'requestId', 'identityHash', 'bootId', 'recipe', 'architecture', 'expectedPlanHash']}


def run_directory(state):
    request_id = state['identity']['requestId']
    if not isinstance(request_id, str) or not UUID.fullmatch(request_id):
        fail()
    return ROOT / ('kernel-' + request_id)


def valid_proof(proof):
    exact_object(proof, {'sha256', 'size', 'mode', 'uid', 'gid'})
    if not isinstance(proof['sha256'], str) or not HASH.fullmatch(proof['sha256']) or \
            any(type(proof[key]) is not int for key in ['size', 'mode', 'uid', 'gid']) or \
            not 0 <= proof['size'] <= MAX_TREE_BYTES or proof['uid'] != 0 or proof['gid'] < 0 or not 0 <= proof['mode'] <= 0o777 or proof['mode'] & 0o022:
        fail()


def signed_output_metadata(transaction):
    candidates, modules, baseline = transaction['candidateArtifacts'], transaction['candidateModules'], transaction['baseline']
    if candidates is None or modules is None:
        return
    if candidates[baseline['config']] != baseline['artifacts'][baseline['config']]:
        fail('HARDENING_KERNEL_BOOT_ARGUMENTS_CHANGED')
    prefix = '/lib/modules/' + transaction['plan']['candidateRelease'] + '/'
    signed = {}
    for path, proof in transaction['payload'].items():
        if path.startswith('/boot/'):
            before = baseline['artifacts'].get(path)
            if before is None or candidates.get(path) != {**proof, 'mode': before['mode'], 'gid': before['gid']}:
                fail('HARDENING_KERNEL_PACKAGE_PAYLOAD_INCOMPLETE')
        elif path.startswith(prefix):
            signed[path[len(prefix):]] = proof
        else:
            fail('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
    generated = {'modules.alias', 'modules.alias.bin', 'modules.builtin', 'modules.builtin.alias.bin', 'modules.builtin.bin',
                 'modules.builtin.modinfo', 'modules.dep', 'modules.dep.bin', 'modules.devname', 'modules.order',
                 'modules.softdep', 'modules.symbols', 'modules.symbols.bin', 'modules.weakdep'}
    for path, proof in signed.items():
        if modules.get(path) != proof:
            fail('HARDENING_KERNEL_PACKAGE_PAYLOAD_INCOMPLETE')
    for path, proof in modules.items():
        if proof.get('directory') is not True and path not in signed and path not in generated:
            fail('HARDENING_KERNEL_MODULES_UNKNOWN')


def validate_journal(state):
    exact_object(state, {'version', 'identity', 'phase', 'prepareHash', 'plan', 'transaction', 'reboot', 'rolledBackAt'})
    if type(state['version']) is not int or state['version'] != 1 or not isinstance(state['phase'], str) or state['phase'] not in PHASES or not isinstance(state['prepareHash'], str) or not HASH.fullmatch(state['prepareHash']):
        fail()
    saved = exact_object(state['identity'], {'nodeId', 'requestId', 'identityHash', 'bootId', 'recipe', 'architecture', 'expectedPlanHash'})
    request({**saved, 'action': 'status', 'prepareHash': state['prepareHash'], 'expiresAt': int(time.time() * 1000) + 59000, 'customers': []})
    transaction = exact_object(state['transaction'], {'plan', 'context', 'installed', 'expectedInstalled', 'baseline', 'cache', 'payload',
                                                       'reactivation', 'staging', 'candidateArtifacts', 'candidateModules'})
    plan = exact_object(state['plan'], {'status', 'branch', 'flavor', 'bootloader', 'runningRelease', 'installedVersion', 'candidateVersion', 'candidateRelease', 'planHash', 'reason'})
    if transaction['plan'] != plan or plan['status'] != 'available' or plan['branch'] not in {'3.22', '3.23', '3.24'} or \
            plan['flavor'] not in {'linux-virt', 'linux-lts'} or plan['bootloader'] not in {'grub', 'extlinux'} or plan['reason'] is not None or \
            plan['planHash'] != saved['expectedPlanHash'] or version_release(plan['candidateVersion'], plan['flavor']) != plan['candidateRelease'] or \
            type(transaction['reactivation']) is not bool:
        fail()
    original_hash_input = {key: field for key, field in transaction.items() if key not in {'staging', 'candidateArtifacts', 'candidateModules'}}
    original_hash_input['plan'] = {**plan, 'planHash': None}
    if digest(encoded(original_hash_input)) != plan['planHash']:
        fail('HARDENING_KERNEL_PLAN_CHANGED')
    before, expected = transaction['installed'], transaction['expectedInstalled']
    if not isinstance(before, dict) or not 1 <= len(before) <= 3000 or any(not re.fullmatch(r'[a-zA-Z0-9+_.-]+', key) or
            not isinstance(version, str) or not re.fullmatch(r'[0-9][a-zA-Z0-9+_.~-]*', version) for key, version in before.items()) or \
            before.get(plan['flavor']) != plan['installedVersion'] or expected != {**before, plan['flavor']: plan['candidateVersion']}:
        fail()
    if transaction['reactivation']:
        if plan['installedVersion'] != plan['candidateVersion'] or not same_series(release_version(plan['runningRelease'], plan['flavor']), plan['candidateVersion']):
            fail()
    elif plan['runningRelease'] != version_release(plan['installedVersion'], plan['flavor']) or not same_series(plan['installedVersion'], plan['candidateVersion']):
        fail()
    baseline = exact_object(transaction['baseline'], {'bootloader', 'config', 'arguments', 'artifacts', 'controls', 'tools', 'modules', 'identity', 'cmdline'})
    suffix = plan['flavor'][6:]
    config = '/boot/grub/grub.cfg' if plan['bootloader'] == 'grub' else '/boot/extlinux.conf'
    if baseline['bootloader'] != plan['bootloader'] or baseline['config'] != config or not isinstance(baseline['arguments'], list) or not isinstance(baseline['cmdline'], str) or len(baseline['cmdline']) > 65536:
        fail()
    mandatory = {config, '/boot/vmlinuz-' + suffix, '/boot/initramfs-' + suffix}
    if not isinstance(baseline['artifacts'], dict) or not mandatory <= set(baseline['artifacts']) or \
            set(baseline['artifacts']) - mandatory - {'/boot/config-' + suffix, '/boot/System.map-' + suffix}:
        fail()
    for mapping in [baseline['artifacts'], baseline['controls'], baseline['identity'], transaction['context'], transaction['payload'], transaction['cache']]:
        if not isinstance(mapping, dict) or not 1 <= len(mapping) <= MAX_TREE_FILES:
            fail()
        for path, proof in mapping.items():
            if not isinstance(path, str) or len(path) > 512 or '\x00' in path or '..' in Path(path).parts:
                fail()
            valid_proof(proof)
    if not isinstance(baseline['modules'], dict) or not 1 <= len(baseline['modules']) <= MAX_TREE_FILES:
        fail()
    for path, proof in baseline['modules'].items():
        if not isinstance(path, str) or not re.fullmatch(r'[a-zA-Z0-9_./+-]+', path) or path.startswith('/') or '..' in Path(path).parts:
            fail()
        if isinstance(proof, dict) and proof.get('directory') is True:
            exact_object(proof, {'directory', 'mode'})
            if type(proof['mode']) is not int or not 0 <= proof['mode'] <= 0o777 or proof['mode'] & 0o022:
                fail()
        else:
            valid_proof(proof)
    for name, tool in baseline['tools'].items():
        exact_object(tool, {'path', 'proof'})
        if name not in {'apk', 'depmod', 'mkinitfs', 'incus', 'rc-service', 'chronyc', 'reboot', 'grub-mkconfig', 'grub-script-check', 'update-extlinux'} or \
                not isinstance(tool['path'], str) or not tool['path'].startswith(('/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/')):
            fail()
        valid_proof(tool['proof'])
    if transaction['staging'] is not None:
        exact_object(transaction['staging'], {'started'})
        if transaction['staging']['started'] is not True:
            fail()
    if transaction['candidateArtifacts'] is not None:
        if not isinstance(transaction['candidateArtifacts'], dict) or set(transaction['candidateArtifacts']) != set(baseline['artifacts']):
            fail()
        for proof in transaction['candidateArtifacts'].values():
            valid_proof(proof)
    if transaction['candidateModules'] is not None:
        if not isinstance(transaction['candidateModules'], dict) or not 1 <= len(transaction['candidateModules']) <= MAX_TREE_FILES:
            fail()
        for path, proof in transaction['candidateModules'].items():
            if not isinstance(path, str) or not re.fullmatch(r'[a-zA-Z0-9_./+-]+', path) or path.startswith('/') or '..' in Path(path).parts:
                fail()
            if isinstance(proof, dict) and proof.get('directory') is True:
                exact_object(proof, {'directory', 'mode'})
                if type(proof['mode']) is not int or not 0 <= proof['mode'] <= 0o777 or proof['mode'] & 0o022:
                    fail()
            else:
                valid_proof(proof)
    if state['phase'] in {'boot-staged', 'prepared', 'reboot-intent', 'activated'} and (
            transaction['candidateArtifacts'] is None or transaction['candidateModules'] is None):
        fail()
    signed_output_metadata(transaction)
    if state['reboot'] is not None:
        exact_object(state['reboot'], {'issuedAt', 'originalBootId'})
        if type(state['reboot']['issuedAt']) is not int or state['reboot']['issuedAt'] <= 0 or state['reboot']['originalBootId'] != saved['bootId'] or state['phase'] not in {'reboot-intent', 'activated', 'rolled-back'}:
            fail()
    if state['phase'] in {'reboot-intent', 'activated'} and state['reboot'] is None or \
            state['phase'] in {'prepared', 'reboot-intent', 'activated'} and state['prepareHash'] == ZERO or \
            state['phase'] in {'prepared-artifacts', 'packages-installed', 'boot-staged'} and state['prepareHash'] != ZERO or \
            state['phase'] != 'rolled-back' and state['rolledBackAt'] is not None or \
            state['phase'] == 'activated' and transaction['staging'] is None or \
            state['phase'] == 'rolled-back' and (type(state['rolledBackAt']) is not int or state['rolledBackAt'] <= 0 or
                                                state['reboot'] is not None and state['prepareHash'] == ZERO):
        fail()
    return state


def assert_kernel_idle(value):
    """Read only under the caller's existing maintenance flock.

    Another recipe may run after a completed kernel operation, a later boot or
    a customer purchase. Check its original terminal evidence, never today's
    empty inventory or boot files, and never archive or change that evidence.
    """
    if not isinstance(value, dict) or not isinstance(value.get('nodeId'), str) or not UUID.fullmatch(value['nodeId']) or \
            not isinstance(value.get('identityHash'), str) or not HASH.fullmatch(value['identityHash']) or \
            not isinstance(value.get('architecture'), str) or value['architecture'] not in {'x86_64', 'aarch64'}:
        fail('HARDENING_KERNEL_OTHER_JOURNAL_UNKNOWN')
    path = ROOT / 'kernel-maintenance.json'
    if not journal_present(path):
        return
    try:
        state = validate_journal(strict_json(read(path, private=True, limit=MAX_JOURNAL_BYTES)))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        if re.fullmatch(r'HARDENING_[A-Z_]{1,90}', str(error)):
            raise
        fail('HARDENING_KERNEL_OTHER_JOURNAL_UNKNOWN')
    if any(state['identity'][key] != value[key] for key in ['nodeId', 'identityHash', 'architecture']):
        fail('HARDENING_KERNEL_OTHER_JOURNAL_UNKNOWN')
    if state['phase'] not in {'activated', 'rolled-back'}:
        fail('HARDENING_KERNEL_OTHER_MAINTENANCE')
    # validate_journal has checked the original reboot identity/timestamp,
    # rollback timestamp, every proof and signed_output_metadata. A nonzero
    # prepareHash additionally binds the complete original prepared payload.
    if state['prepareHash'] != ZERO and (not state['transaction']['candidateArtifacts'] or
                                        not state['transaction']['candidateModules'] or
                                        state['transaction']['staging'] is None or
                                        state['prepareHash'] != preparation_hash(state)):
        fail('HARDENING_KERNEL_JOURNAL_CONFLICT')


def assert_apparmor_idle(value):
    # The paired, authenticated transport injects the old recipe's own pure
    # schema/hash reader. Never replace that recipe with a weak phase check.
    if callable(APPARMOR_JOURNAL_GUARD):
        APPARMOR_JOURNAL_GUARD(value)
    elif journal_present(ROOT / 'maintenance.json'):
        fail('HARDENING_KERNEL_OTHER_JOURNAL_UNKNOWN')


def receipt(value, state=None, plan=None):
    return {'version': 1, 'nodeId': value['nodeId'], 'requestId': value['requestId'], 'identityHash': value['identityHash'],
            'originalBootId': value['bootId'], 'bootId': boot(), 'architecture': value['architecture'], 'recipe': RECIPE,
            'prepareHash': ZERO if state is None else state['prepareHash'],
            'phase': 'inspected' if plan is not None else 'absent' if state is None else state['phase'],
            'plan': plan if plan is not None else None if state is None else state['plan']}


def check_fixed_baseline(transaction, include_boot=False):
    baseline = transaction['baseline']
    if fixed_context(package_context()) != fixed_context(transaction['context']) or runtime_identity() != baseline['identity']:
        fail('HARDENING_IDENTITY_CHANGED')
    if {path: file_proof(Path(path), limit=1024 * 1024) for path in baseline['controls']} != baseline['controls'] or \
            {name: trusted_program(name) for name in baseline['tools']} != baseline['tools']:
        fail('HARDENING_KERNEL_CONFIGURATION_CHANGED')
    if Path('/proc/cmdline').read_text().strip() != baseline['cmdline']:
        fail('HARDENING_KERNEL_CONFIGURATION_CHANGED')
    if include_boot and {path: file_proof(Path(path)) for path in baseline['artifacts']} != baseline['artifacts']:
        fail('HARDENING_KERNEL_BOOT_FILES_CHANGED')


def check_original_cache(state, value):
    directory = run_directory(state)
    transaction = state['transaction']
    protected(directory, directory=True, private=True)
    if cache_manifest(directory / 'cache') != transaction['cache'] or read(directory / 'repositories', private=True) != official_repositories(state['plan']['branch']):
        fail('HARDENING_KERNEL_CACHE_CHANGED')
    archive = directory / 'cache' / (state['plan']['flavor'] + '-' + state['plan']['candidateVersion'] + '.apk')
    command([transaction['baseline']['tools']['apk']['path'], '--no-network', 'verify', str(archive)], timeout=8, value=value)
    if kernel_payload(archive, state['plan']['flavor'], state['plan']['candidateVersion']) != transaction['payload']:
        fail('HARDENING_KERNEL_CACHE_CHANGED')


def before_path(state, original):
    # Every boot path is validated against the flavor/config allowlist before
    # being mapped into this private backup directory.
    return run_directory(state) / 'before' / Path(original).name


def backup_proof(proof):
    return {**proof, 'mode': 0o600}


def save_before(state, value):
    transaction = state['transaction']
    baseline = transaction['baseline']
    directory = run_directory(state)
    required = manifest_size(baseline['modules']) * 2 + manifest_size(transaction['cache']) + manifest_size(baseline['artifacts']) * 2 + 64 * 1024 * 1024
    boot_required = manifest_size(baseline['artifacts']) * 2 + 16 * 1024 * 1024
    resources(required, boot_required)
    current_request(value)
    backup = directory / 'before'
    backup.mkdir(mode=0o700, exist_ok=True)
    protected(backup, directory=True, private=True)
    for path, proof in baseline['artifacts'].items():
        current_request(value)
        destination = before_path(state, path)
        if destination.exists():
            if file_proof(destination, private=True) != backup_proof(proof):
                fail('HARDENING_KERNEL_BACKUP_CHANGED')
        else:
            copy_checked(Path(path), destination, proof, mode=0o600)
    old_modules = directory / 'old-modules'
    copy_modules(Path('/lib/modules') / state['plan']['runningRelease'], old_modules, baseline['modules'], value)
    current_request(value)
    check_fixed_baseline(transaction, include_boot=True)
    if installed_packages(value) != transaction['installed'] or package_context() != transaction['context']:
        fail('HARDENING_KERNEL_SOURCE_CHANGED')


def save_journal(state, value):
    identity(value)
    validate_journal(state)
    atomic(ROOT / 'kernel-maintenance.json', encoded(state))


def verify_original_backups(state):
    baseline = state['transaction']['baseline']
    for path, proof in baseline['artifacts'].items():
        if file_proof(before_path(state, path), private=True) != backup_proof(proof):
            fail('HARDENING_KERNEL_BACKUP_CHANGED')
    if module_manifest(run_directory(state) / 'old-modules') != baseline['modules']:
        fail('HARDENING_KERNEL_BACKUP_CHANGED')


def check_partial_boot(state):
    transaction, baseline = state['transaction'], state['transaction']['baseline']
    candidates = transaction['candidateArtifacts'] or {}
    for path, before in baseline['artifacts'].items():
        if not Path(path).exists() and not Path(path).is_symlink():
            if path in transaction['payload'] and state['phase'] in {'prepared-artifacts', 'packages-installed', 'rolled-back'}:
                protected(Path(path).parent, directory=True)
                continue
            fail('HARDENING_KERNEL_BOOT_FILES_CHANGED')
        actual = file_proof(Path(path))
        approved = [before]
        if path in transaction['payload']:
            approved.append(transaction['payload'][path])
        if path in candidates:
            approved.append(candidates[path])
        if actual not in approved:
            fail('HARDENING_KERNEL_BOOT_FILES_CHANGED')


def validate_partial_inventory(transaction, current):
    before, expected = transaction['installed'], transaction['expectedInstalled']
    if set(current) != set(before) or any(version not in {before[name], expected[name]} for name, version in current.items()):
        fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')


def install_original(state, value):
    transaction = state['transaction']
    directory = run_directory(state)
    check_fixed_baseline(transaction)
    verify_original_backups(state)
    check_partial_boot(state)
    check_original_cache(state, value)
    empty_remote(value)
    resources()
    current = installed_packages(value)
    validate_partial_inventory(transaction, current)
    expected, flavor = state['plan']['candidateVersion'], state['plan']['flavor']
    # Reinstall the original authenticated payload even if the APK database
    # committed Expected first. The interrupted file half is not an install
    # proof; no different package can enter this replay.
    reinstall = current[flavor] == expected
    simulate_original(transaction, directory, value, current, reinstall)
    simulate_original(transaction, directory, value, current, reinstall)
    if installed_packages(value) != current:
        fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
    check_fixed_baseline(transaction)
    check_partial_boot(state)
    if cache_manifest(directory / 'cache') != transaction['cache']:
        fail('HARDENING_KERNEL_CACHE_CHANGED')
    current_request(value)
    base = package_base(directory)
    args = [*base, '--no-network', 'fix', '--reinstall', flavor] if reinstall else [*base, '--no-network', 'upgrade', flavor]
    command(args, timeout=30, value=value)
    if installed_packages(value) != transaction['expectedInstalled']:
        fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
    check_fixed_baseline(transaction)
    for path, proof in transaction['payload'].items():
        if file_proof(Path(path)) != proof:
            fail('HARDENING_KERNEL_PACKAGE_PAYLOAD_INCOMPLETE')
    # The old modules are retained independently before APK removes them.
    # The actual new tree is checked against all signed payload bytes above.
    state['phase'] = 'packages-installed'
    save_journal(state, value)


def staging_directory(state):
    return run_directory(state) / 'staging'


def candidate_path(state, original):
    return staging_directory(state) / Path(original).name


def check_staging_paths(state):
    directory = staging_directory(state)
    protected(directory, directory=True, private=True)
    permitted = {Path(path).name for path in state['transaction']['baseline']['artifacts']}
    for path in directory.iterdir():
        if path.name not in permitted:
            fail('HARDENING_KERNEL_STAGING_CHANGED')
        protected(path)


def stage_boot(state, value):
    transaction, baseline = state['transaction'], state['transaction']['baseline']
    check_fixed_baseline(transaction)
    verify_original_backups(state)
    check_original_cache(state, value)
    if installed_packages(value) != transaction['expectedInstalled']:
        fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
    for path, proof in transaction['payload'].items():
        if file_proof(Path(path)) != proof:
            fail('HARDENING_KERNEL_PACKAGE_PAYLOAD_INCOMPLETE')
    check_partial_boot(state)
    empty_remote(value)
    current_request(value)
    directory = staging_directory(state)
    if not directory.exists():
        directory.mkdir(mode=0o700)
        sync_directory(directory.parent)
    check_staging_paths(state)
    if transaction['staging'] is None:
        transaction['staging'] = {'started': True}
        save_journal(state, value)
    # This persisted staging intent permits regenerating only these exact
    # private outputs after mkinitfs/generator interruption. Unknown entries
    # or symlinks still refuse; no host boot file is removed to retry.
    release = state['plan']['candidateRelease']
    current_request(value)
    command([baseline['tools']['depmod']['path'], '-a', release], timeout=10, value=value)
    initramfs = '/boot/initramfs-' + state['plan']['flavor'][6:]
    initramfs_candidate = candidate_path(state, initramfs)
    command([baseline['tools']['mkinitfs']['path'], '-o', str(initramfs_candidate), release], timeout=25, value=value)
    os.chmod(initramfs_candidate, baseline['artifacts'][initramfs]['mode'])
    os.chown(initramfs_candidate, 0, baseline['artifacts'][initramfs]['gid'])
    with initramfs_candidate.open('rb') as stream:
        os.fsync(stream.fileno())
    configuration = baseline['config']
    if state['plan']['bootloader'] == 'grub':
        output = candidate_path(state, configuration)
        command([baseline['tools']['grub-mkconfig']['path'], '-o', str(output)], timeout=10, value=value)
        if linux_arguments(read(output), 'grub', state['plan']['flavor']) != baseline['arguments']:
            fail('HARDENING_KERNEL_BOOT_ARGUMENTS_CHANGED')
        command([baseline['tools']['grub-script-check']['path'], str(output)], timeout=8, value=value)
    else:
        # update-extlinux writes the live config directly. The fixed existing
        # bytes already point at this flavor; its -h option must prove a
        # private --conf output before it can be used as a staging generator.
        help_text = command([baseline['tools']['update-extlinux']['path'], '--help'], value=value).decode()
        if '--conf' not in help_text:
            fail('HARDENING_KERNEL_BOOT_GENERATOR_UNSUPPORTED')
        command([baseline['tools']['update-extlinux']['path'], '--conf', str(candidate_path(state, configuration))], timeout=10, value=value)
        if linux_arguments(read(candidate_path(state, configuration)), 'extlinux', state['plan']['flavor']) != baseline['arguments']:
            fail('HARDENING_KERNEL_BOOT_ARGUMENTS_CHANGED')
    # Kernel paths are unchanged. Preserve every existing boot byte (including
    # custom storage/network/security parameters), after verifying the normal
    # generator independently agrees on the one original flavor and arguments.
    original_configuration = read(before_path(state, configuration), private=True)
    atomic(candidate_path(state, configuration), original_configuration, baseline['artifacts'][configuration]['mode'])
    os.chown(candidate_path(state, configuration), 0, baseline['artifacts'][configuration]['gid'])
    with candidate_path(state, configuration).open('rb') as stream:
        os.fsync(stream.fileno())
    for path, before in baseline['artifacts'].items():
        if path in {configuration, initramfs}:
            continue
        actual = file_proof(Path(path))
        expected = transaction['payload'].get(path, before)
        if actual != expected:
            fail('HARDENING_KERNEL_PACKAGE_PAYLOAD_INCOMPLETE')
        copy_checked(Path(path), candidate_path(state, path), actual, mode=before['mode'], gid=before['gid'])
    sync_directory(directory)
    check_staging_paths(state)
    candidates = {path: file_proof(candidate_path(state, path)) for path in baseline['artifacts']}
    for path, proof in candidates.items():
        if proof['mode'] != baseline['artifacts'][path]['mode'] or proof['gid'] != baseline['artifacts'][path]['gid']:
            fail('HARDENING_KERNEL_BOOT_FILES_CHANGED')
    transaction['candidateArtifacts'] = candidates
    transaction['candidateModules'] = module_manifest(Path('/lib/modules') / release)
    signed_output_metadata(transaction)
    current_request(value)
    check_fixed_baseline(transaction)
    empty_remote(value)
    state['phase'] = 'boot-staged'
    save_journal(state, value)


def preparation_hash(state):
    transaction = state['transaction']
    return digest(encoded([state['identity'], state['plan']['planHash'], transaction['expectedInstalled'],
                           transaction['baseline']['artifacts'], transaction['candidateArtifacts'], transaction['candidateModules']]))


def commit_boot(state, value):
    transaction, baseline = state['transaction'], state['transaction']['baseline']
    check_fixed_baseline(transaction)
    verify_original_backups(state)
    check_original_cache(state, value)
    check_staging_paths(state)
    if installed_packages(value) != transaction['expectedInstalled'] or module_manifest(Path('/lib/modules') / state['plan']['candidateRelease']) != transaction['candidateModules']:
        fail('HARDENING_KERNEL_PACKAGE_PAYLOAD_INCOMPLETE')
    for path, proof in transaction['candidateArtifacts'].items():
        if file_proof(candidate_path(state, path)) != proof:
            fail('HARDENING_KERNEL_STAGING_CHANGED')
    check_partial_boot(state)
    empty_remote(value)
    for path, proof in transaction['candidateArtifacts'].items():
        current_request(value)
        identity(value)
        # The latest compare is immediately before each conditional replace.
        check_partial_boot(state)
        if file_proof(Path(path)) != proof:
            copy_checked(candidate_path(state, path), Path(path), proof)
    check_fixed_baseline(transaction)
    if {path: file_proof(Path(path)) for path in baseline['artifacts']} != transaction['candidateArtifacts']:
        fail('HARDENING_KERNEL_PREPARE_INCOMPLETE')
    empty_remote(value)
    current_request(value)
    state['prepareHash'] = preparation_hash(state)
    state['phase'] = 'prepared'
    save_journal(state, value)


def runtime_services(state, value):
    tools = state['transaction']['baseline']['tools']
    empty_remote(value)
    command([tools['rc-service']['path'], 'incus', 'status'], timeout=8, value=value)
    command([tools['rc-service']['path'], 'lxcfs', 'status'], timeout=8, value=value)
    tracking = command([tools['chronyc']['path'], '-n', 'tracking'], timeout=5, value=value).decode()
    offset = re.search(r'^System time\s*:\s*([0-9.]+) seconds (?:fast|slow) of NTP time\s*$', tracking, re.M)
    if not re.search(r'^Leap status\s*:\s*Normal\s*$', tracking, re.M) or not offset or abs(float(offset[1])) > 5:
        fail('HARDENING_KERNEL_CLOCK_UNREADY')
    # The controller may be IPv4-only; host DNS check never assumes gateway
    # IPv6. This probes the existing resolver without changing any network.
    current_request(value)
    if not socket.getaddrinfo('dl-cdn.alpinelinux.org', 443, socket.AF_INET, socket.SOCK_STREAM):
        fail('HARDENING_KERNEL_DNS_UNREADY')
    current_request(value)


def verify_prepared(state, value):
    transaction = state['transaction']
    if state['prepareHash'] != preparation_hash(state):
        fail('HARDENING_KERNEL_PREPARE_CHANGED')
    check_fixed_baseline(transaction)
    check_original_cache(state, value)
    if installed_packages(value) != transaction['expectedInstalled'] or \
            {path: file_proof(Path(path)) for path in transaction['baseline']['artifacts']} != transaction['candidateArtifacts'] or \
            module_manifest(Path('/lib/modules') / state['plan']['candidateRelease']) != transaction['candidateModules']:
        fail('HARDENING_KERNEL_PREPARE_CHANGED')
    runtime_services(state, value)


def restore_module_tree(state):
    baseline = state['transaction']['baseline']
    original = Path('/lib/modules') / state['plan']['runningRelease']
    backup = run_directory(state) / 'old-modules'
    manifest = baseline['modules']
    if module_manifest(backup) != manifest:
        fail('HARDENING_KERNEL_BACKUP_CHANGED')
    if original.exists() or original.is_symlink():
        actual = module_manifest(original, require_modules=False)
        partial = []
        for path, proof in actual.items():
            if path in manifest:
                if proof != manifest[path]:
                    fail('HARDENING_KERNEL_MODULES_CHANGED')
                continue
            name = Path(path)
            if not name.name.startswith('.kernel-copy-'):
                fail('HARDENING_KERNEL_MODULES_CHANGED')
            restored = str(name.parent / name.name.removeprefix('.kernel-copy-'))
            if restored not in manifest or manifest[restored].get('directory') is True:
                fail('HARDENING_KERNEL_MODULES_CHANGED')
            target = original / restored
            if target.exists() and file_proof(target) != manifest[restored]:
                fail('HARDENING_KERNEL_MODULES_CHANGED')
            partial.append(restored)
        for path in partial:
            copy_checked(backup / path, original / path, manifest[path])
    else:
        protected(original.parent, directory=True)
        original.mkdir(mode=0o755)
    for path, proof in sorted(manifest.items(), key=lambda pair: (pair[0].count('/'), pair[0])):
        target = original / path
        if proof.get('directory') is True:
            target.mkdir(mode=proof['mode'], exist_ok=True)
            protected(target, directory=True)
            if stat.S_IMODE(target.stat().st_mode) != proof['mode']:
                fail('HARDENING_KERNEL_MODULES_CHANGED')
        elif not target.exists():
            copy_checked(backup / path, target, proof)
        elif file_proof(target) != proof:
            fail('HARDENING_KERNEL_MODULES_CHANGED')
    if module_manifest(original) != manifest:
        fail('HARDENING_KERNEL_ROLLBACK_INCOMPLETE')
    sync_directory(original)


def verify_rollback_files(state, strict=True):
    baseline = state['transaction']['baseline']
    if strict:
        check_fixed_baseline(state['transaction'])
    elif runtime_identity() != baseline['identity'] or Path('/proc/cmdline').read_text().strip() != baseline['cmdline']:
        fail('HARDENING_IDENTITY_CHANGED')
    if {path: file_proof(Path(path)) for path in baseline['artifacts']} != baseline['artifacts'] or \
            module_manifest(Path('/lib/modules') / state['plan']['runningRelease']) != baseline['modules']:
        fail('HARDENING_KERNEL_ROLLBACK_INCOMPLETE')


def rollback(state, value):
    if state['phase'] == 'rolled-back':
        verify_rollback_files(state)
        return
    current = boot()
    if state['reboot'] is not None:
        # After the barrier, only an authenticated different boot actually
        # running the original release grants a bounded file rollback.
        if current == state['identity']['bootId'] or os.uname().release != state['plan']['runningRelease']:
            fail('HARDENING_KERNEL_ROLLBACK_BOOT_UNCONFIRMED')
    elif current != state['identity']['bootId']:
        fail('HARDENING_IDENTITY_CHANGED')
    check_fixed_baseline(state['transaction'])
    verify_original_backups(state)
    check_partial_boot(state)
    current_inventory = installed_packages(value)
    validate_partial_inventory(state['transaction'], current_inventory)
    empty_remote(value)
    restore_module_tree(state)
    for path, before in state['transaction']['baseline']['artifacts'].items():
        current_request(value)
        check_partial_boot(state)
        if not Path(path).exists() or file_proof(Path(path)) != before:
            copy_checked(before_path(state, path), Path(path), backup_proof(before), mode=before['mode'])
    verify_rollback_files(state)
    if installed_packages(value) != current_inventory:
        fail('HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
    # No APK downgrade and no unknown module/file removal. The signed newer
    # package remains installed, explicitly ready for a fresh boot-only plan.
    state['phase'] = 'rolled-back'
    state['rolledBackAt'] = int(time.time() * 1000)
    save_journal(state, value)


def verify_terminal(state, value):
    if state['identity']['nodeId'] != value['nodeId'] or state['identity']['identityHash'] != value['identityHash'] or state['identity']['architecture'] != value['architecture']:
        fail('HARDENING_IDENTITY_CHANGED')
    if state['phase'] == 'activated':
        if boot() == state['identity']['bootId'] or os.uname().release != state['plan']['candidateRelease']:
            fail('HARDENING_KERNEL_BOOT_UNCONFIRMED')
        transaction = state['transaction']
        if state['prepareHash'] != preparation_hash(state) or runtime_identity() != transaction['baseline']['identity'] or \
                {path: file_proof(Path(path)) for path in transaction['baseline']['artifacts']} != transaction['candidateArtifacts'] or \
                module_manifest(Path('/lib/modules') / state['plan']['candidateRelease']) != transaction['candidateModules']:
            fail('HARDENING_KERNEL_ARCHIVE_CONFLICT')
        empty_remote(value)
    elif state['phase'] == 'rolled-back':
        verify_rollback_files(state, strict=False)
        empty_remote(value)
    else:
        fail('HARDENING_KERNEL_OTHER_MAINTENANCE')


def archive_terminal(state, value):
    verify_terminal(state, value)
    old_path = ROOT / 'kernel-maintenance.json'
    archive = ROOT / ('kernel-maintenance-' + state['identity']['requestId'] + '.json')
    if archive.exists() or archive.is_symlink():
        if read(archive, private=True, limit=MAX_JOURNAL_BYTES) != read(old_path, private=True, limit=MAX_JOURNAL_BYTES):
            fail('HARDENING_KERNEL_ARCHIVE_CONFLICT')
    else:
        atomic(archive, read(old_path, private=True, limit=MAX_JOURNAL_BYTES))
    # This archive is fsynced before publishing any subsequent request.
    sync_directory(ROOT)


def archive_source_only(directory, value):
    protected(directory, directory=True, private=True)
    if directory != ROOT / ('kernel-' + value['requestId']):
        fail('HARDENING_KERNEL_ORPHAN_PREPARATION')
    marker = exact_object(strict_json(read(directory / 'planning.json', private=True, limit=4096)), {'version', 'identity', 'phase'})
    if marker['version'] != 1 or marker['identity'] != identity_fields(value) or marker['phase'] != 'source-only' or \
            {entry.name for entry in directory.iterdir()} - {'planning.json', 'repositories', 'cache'}:
        fail('HARDENING_KERNEL_ORPHAN_PREPARATION')
    for entry in directory.iterdir():
        protected(entry, directory=entry.name == 'cache', private=True)
        if entry.name == 'cache':
            for child in entry.iterdir():
                protected(child)
    target = ROOT / ('kernel-source-only-' + value['requestId'] + '-' + str(int(time.time() * 1000)))
    if target.exists() or target.is_symlink():
        fail('HARDENING_KERNEL_ARCHIVE_CONFLICT')
    # There was no package or boot write before preparation.json. Preserve the
    # bounded signed-fetch residue, then replan this same expected hash.
    os.rename(directory, target)
    sync_directory(ROOT)


def execute(raw):
    global LOCK_FD
    value = request(raw)
    if os.getuid() != 0:
        fail('HARDENING_ADMIN_REQUIRED')
    identity(value)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    protected(ROOT, directory=True, private=True)
    lock = ROOT / 'maintenance.lock'
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        protected(lock, private=True, limit=0)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail('HARDENING_REMOTE_BUSY')
        LOCK_FD = fd
        assert_apparmor_idle(value)
        journal = ROOT / 'kernel-maintenance.json'
        state = validate_journal(strict_json(read(journal, private=True, limit=MAX_JOURNAL_BYTES))) if journal_present(journal) else None
        matching = state is not None and state['identity'] == identity_fields(value)
        if value['action'] == 'inspect':
            if state and state['phase'] not in {'activated', 'rolled-back'}:
                fail('HARDENING_KERNEL_OTHER_MAINTENANCE')
            # Use a UUID scratch name so cleanup cannot name unrelated paths.
            import uuid
            scratch = ROOT / ('kernel-inspect-' + str(uuid.uuid4()))
            try:
                plan, _ = source_transaction(value, scratch, state)
                return receipt(value, plan=plan)
            except ValueError as error:
                code = str(error)
                if not re.fullmatch(r'HARDENING_[A-Z_]{1,90}', code):
                    raise
                return receipt(value, plan={'status': 'blocked', 'branch': None, 'flavor': None, 'bootloader': None,
                    'runningRelease': None, 'installedVersion': None, 'candidateVersion': None, 'candidateRelease': None,
                    'planHash': None, 'reason': code})
            finally:
                cleanup_inspection(scratch)
        if state is not None and not matching:
            if value['action'] == 'status' and value['prepareHash'] == ZERO and state['phase'] in {'activated', 'rolled-back'}:
                verify_terminal(state, value)
                return receipt(value)
            if value['action'] != 'prepare' or state['phase'] not in {'activated', 'rolled-back'}:
                fail('HARDENING_KERNEL_JOURNAL_CONFLICT')
        if state is None and value['action'] == 'status':
            if value['prepareHash'] != ZERO:
                fail()
            return receipt(value)
        if value['action'] == 'prepare' and not matching:
            if boot() != value['bootId'] or value['prepareHash'] != ZERO:
                fail('HARDENING_IDENTITY_CHANGED')
            empty_remote(value)
            current_request(value)
            directory = ROOT / ('kernel-' + value['requestId'])
            prepared_plan = directory / 'preparation.json'
            if directory.exists() and not prepared_plan.exists():
                archive_source_only(directory, value)
            if directory.exists() or directory.is_symlink():
                protected(directory, directory=True, private=True)
                if not prepared_plan.exists():
                    fail('HARDENING_KERNEL_ORPHAN_PREPARATION')
                new_state = validate_journal(strict_json(read(prepared_plan, private=True, limit=MAX_JOURNAL_BYTES)))
                if new_state['identity'] != identity_fields(value) or new_state['phase'] != 'prepared-artifacts':
                    fail('HARDENING_KERNEL_ORPHAN_PREPARATION')
                check_original_cache(new_state, value)
                check_fixed_baseline(new_state['transaction'], include_boot=True)
            else:
                plan, transaction = source_transaction(value, directory, state)
                if transaction is None or plan['planHash'] != value['expectedPlanHash']:
                    fail('HARDENING_KERNEL_PLAN_CHANGED')
                new_state = {'version': 1, 'identity': identity_fields(value), 'phase': 'prepared-artifacts', 'prepareHash': ZERO,
                             'plan': plan, 'transaction': transaction, 'reboot': None, 'rolledBackAt': None}
                current_request(value)
                atomic(prepared_plan, encoded(new_state))
            save_before(new_state, value)
            if state is not None:
                archive_terminal(state, value)
            current_request(value)
            empty_remote(value)
            # Publish the persistent complete plan and before images before
            # APK can change either its registered version or boot payload.
            save_journal(new_state, value)
            return receipt(value, new_state)
        if state is None or not matching or value['prepareHash'] not in {ZERO, state['prepareHash']}:
            fail()
        if value['action'] == 'status':
            return receipt(value, state)
        if value['action'] == 'prepare':
            if boot() != value['bootId']:
                fail('HARDENING_IDENTITY_CHANGED')
            if state['phase'] == 'prepared-artifacts':
                install_original(state, value)
            elif state['phase'] == 'packages-installed':
                stage_boot(state, value)
            elif state['phase'] == 'boot-staged':
                commit_boot(state, value)
            elif state['phase'] == 'prepared':
                verify_prepared(state, value)
            else:
                fail('HARDENING_KERNEL_PREPARE_STATE_UNKNOWN')
            return receipt(value, state)
        if value['action'] == 'rollback':
            rollback(state, value)
            return receipt(value, state)
        if value['prepareHash'] != state['prepareHash'] or state['prepareHash'] == ZERO:
            fail('HARDENING_KERNEL_PREPARE_CHANGED')
        if value['action'] == 'verify':
            if state['phase'] not in {'reboot-intent', 'activated'} or state['reboot'] is None or boot() == value['bootId']:
                fail('HARDENING_KERNEL_BOOT_UNCONFIRMED')
            if os.uname().release != state['plan']['candidateRelease'] or Path('/proc/sys/kernel/osrelease').read_text().strip() != state['plan']['candidateRelease']:
                fail('HARDENING_KERNEL_BOOT_MISMATCH')
            verify_prepared(state, value)
            current_request(value)
            state['phase'] = 'activated'
            save_journal(state, value)
            return receipt(value, state)
        # Reading the original barrier is safe even after transport loss. No
        # caller, expiry or same request can create a second normal reboot.
        if state['phase'] in {'reboot-intent', 'activated'}:
            return receipt(value, state)
        if state['phase'] != 'prepared' or boot() != value['bootId']:
            fail('HARDENING_KERNEL_REBOOT_UNCONFIRMED')
        verify_prepared(state, value)
        empty_remote(value)
        current_request(value)
        identity(value)
        state['reboot'] = {'issuedAt': int(time.time() * 1000), 'originalBootId': value['bootId']}
        state['phase'] = 'reboot-intent'
        save_journal(state, value)
        subprocess.Popen([state['transaction']['baseline']['tools']['reboot']['path']], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, pass_fds=(fd,), env={'PATH': PATH_ENV, 'LC_ALL': 'C'})
        return receipt(value, state)
    finally:
        LOCK_FD = None
        os.close(fd)


def main():
    try:
        data = sys.stdin.buffer.read(8193)
        if len(data) > 8192:
            fail('HARDENING_KERNEL_REQUEST_UNKNOWN')
        print(json.dumps(execute(strict_json(data)), separators=(',', ':')))
    except BaseException as error:
        code = str(error)
        print(json.dumps({'error': code if re.fullmatch(r'HARDENING_[A-Z_]{1,90}', code) else 'HARDENING_KERNEL_PREPARE_FAILED'}))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
