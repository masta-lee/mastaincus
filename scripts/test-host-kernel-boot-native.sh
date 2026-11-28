#!/usr/bin/env bash
# Real Alpine VM phases. chroot/pivot_root and mocked uname are not boot evidence.
set -euo pipefail
if [[ "${PAYINCUS_HOST_KERNEL_NATIVE:-}" != "1" || "${PAYINCUS_HOST_KERNEL_DISPOSABLE_VM:-}" != "1" || "${EUID}" != "0" ]]; then
  printf '%s\n' 'HARDENING_KERNEL_NATIVE_DISPOSABLE_VM_REQUIRED' >&2
  exit 1
fi
phase="${1:-}"
case "$phase" in prepare|status|reboot|verify|rollback) ;; *) printf '%s\n' 'HARDENING_KERNEL_NATIVE_PHASE_UNKNOWN' >&2; exit 1 ;; esac
script_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
kernel_module="${script_root}/../server/templates/host-kernel-maintenance.py"
if [[ ! -f "$kernel_module" ]]; then kernel_module="${script_root}/host-kernel-maintenance.py"; fi
apparmor_module="${script_root}/../server/templates/host-security-maintenance.py"
if [[ ! -f "$apparmor_module" ]]; then apparmor_module="${script_root}/host-security-maintenance.py"; fi
python3 -I -B - "$phase" "$kernel_module" "$apparmor_module" <<'PY'
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import types
import uuid

phase, source, apparmor_source = sys.argv[1:]
def fixed_module(name, source, limit):
    path = Path(source)
    for parent in [path, *path.parents]:
        proof = parent.lstat()
        if proof.st_uid != 0 or stat.S_ISLNK(proof.st_mode) or proof.st_mode & 0o022 or parent != path and not stat.S_ISDIR(proof.st_mode):
            raise ValueError('HARDENING_KERNEL_UNTRUSTED_PATH')
    proof = path.lstat()
    if not stat.S_ISREG(proof.st_mode) or proof.st_nlink != 1 or proof.st_size > limit:
        raise ValueError('HARDENING_KERNEL_UNTRUSTED_PATH')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
                (proof.st_dev, proof.st_ino, proof.st_mode, proof.st_size, proof.st_mtime_ns, proof.st_ctime_ns):
            raise ValueError('HARDENING_KERNEL_SOURCE_CHANGED')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        if len(data) != before.st_size or (before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != \
                (after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('HARDENING_KERNEL_SOURCE_CHANGED')
    finally:
        os.close(fd)
    namespace = types.ModuleType(name)
    namespace.__file__ = str(path)
    exec(compile(data, str(path), 'exec'), namespace.__dict__)
    return namespace

# Use both original recipe readers, as the packaged fixed transport does.
# A bare kernel module cannot declare an existing AppArmor journal idle.
module = fixed_module('native_host_kernel', source, 128 * 1024)
apparmor = fixed_module('native_host_apparmor', apparmor_source, 64 * 1024)
if not callable(getattr(apparmor, 'assert_apparmor_idle', None)) or not callable(module.assert_kernel_idle):
    module.fail('HARDENING_KERNEL_OTHER_JOURNAL_UNKNOWN')
module.APPARMOR_JOURNAL_GUARD = apparmor.assert_apparmor_idle
apparmor.KERNEL_JOURNAL_GUARD = module.assert_kernel_idle
marker = Path('/var/lib/incudal-kernel-native.disposable')
if module.read(marker, private=True, limit=128) != b'payincus-disposable-kernel-v1\n':
    module.fail('HARDENING_KERNEL_NATIVE_DISPOSABLE_VM_REQUIRED')
# A real PID1 rooted in this Alpine installation and a real Alpine package
# release are mandatory. Ubuntu runners with an Alpine chroot fail here.
root, pid1_root = os.stat('/'), os.stat('/proc/1/root')
if (root.st_dev, root.st_ino) != (pid1_root.st_dev, pid1_root.st_ino) or \
        Path('/proc/1/root/etc/alpine-release').read_bytes() != Path('/etc/alpine-release').read_bytes():
    module.fail('HARDENING_KERNEL_NATIVE_REAL_VM_REQUIRED')
if os.uname().machine not in {'x86_64', 'aarch64'} or not module.RELEASE.fullmatch(os.uname().release):
    module.fail('HARDENING_KERNEL_NATIVE_REAL_VM_REQUIRED')
expected = os.environ.get('PAYINCUS_KERNEL_EXPECTED_CANDIDATE', '')
if not module.VERSION.fullmatch(expected):
    module.fail('HARDENING_KERNEL_NATIVE_EXPECTED_VERSION_REQUIRED')
evidence = Path('/var/lib/incudal-kernel-native-evidence')
evidence.mkdir(mode=0o700, exist_ok=True)
module.protected(evidence, directory=True, private=True)
lock = evidence / 'test.lock'
fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
module.protected(lock, private=True, limit=0)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
try:
    state_path = evidence / 'current.json'
    state = module.strict_json(module.read(state_path, private=True, limit=32768)) if module.journal_present(state_path) else None
    if state is not None and (not isinstance(state, dict) or set(state) != {'version', 'wire', 'receipt', 'beforeKernel', 'identity'} or type(state['version']) is not int or state['version'] != 1):
        module.fail('HARDENING_KERNEL_NATIVE_EVIDENCE_UNKNOWN')
    if phase == 'prepare':
        if state is not None:
            probe = module.execute({**state['wire'], 'action': 'status', 'expiresAt': int(time.time() * 1000) + 59000})
            if probe['phase'] in {'activated', 'rolled-back'}:
                archive = evidence / ('transaction-' + state['wire']['requestId'] + '.json')
                module.atomic(archive, module.read(state_path, private=True, limit=32768))
                state = None
        if state is None:
            wire = {'action': 'inspect', 'nodeId': Path('/etc/incudal-onboarding-id').read_text().strip(), 'requestId': str(uuid.uuid4()),
                    'identityHash': module.digest(module.encoded(module.runtime_identity())), 'bootId': module.boot(),
                    'prepareHash': module.ZERO, 'recipe': module.RECIPE, 'architecture': os.uname().machine,
                    'expiresAt': int(time.time() * 1000) + 59000, 'customers': [], 'expectedPlanHash': None}
            inspected = module.execute(wire)
            if inspected['phase'] == 'inspected' and inspected['plan']['status'] == 'blocked':
                reason = inspected['plan'].get('reason')
                if isinstance(reason, str) and re.fullmatch(r'HARDENING_[A-Z_]{1,90}', reason):
                    module.fail(reason)
            if inspected['phase'] != 'inspected' or inspected['plan']['status'] != 'available' or inspected['plan']['candidateVersion'] != expected:
                module.fail('HARDENING_KERNEL_NATIVE_PLAN_UNAVAILABLE')
            wire.update(action='prepare', expectedPlanHash=inspected['plan']['planHash'])
            state = {'version': 1, 'wire': wire, 'receipt': inspected, 'beforeKernel': os.uname().release, 'identity': module.runtime_identity()}
            module.atomic(state_path, module.encoded(state))
        # Each prepare invocation is separately bounded by the real root
        # protocol; a failed stage is retained for same-cache continuation.
        for _ in range(6):
            wire = {**state['wire'], 'action': 'prepare', 'expiresAt': int(time.time() * 1000) + 59000}
            reply = module.execute(wire)
            if reply['phase'] not in {'prepared-artifacts', 'packages-installed', 'boot-staged', 'prepared'}:
                module.fail('HARDENING_KERNEL_NATIVE_PHASE_UNKNOWN')
            state['wire'].update(prepareHash=reply['prepareHash'])
            state['receipt'] = reply
            module.atomic(state_path, module.encoded(state))
            if reply['phase'] == 'prepared':
                break
        if state['receipt']['phase'] != 'prepared':
            module.fail('HARDENING_KERNEL_NATIVE_PREPARE_INCOMPLETE')
    else:
        if state is None:
            module.fail('HARDENING_KERNEL_NATIVE_EVIDENCE_UNKNOWN')
        if state['receipt'].get('plan', {}).get('candidateVersion') != expected:
            module.fail('HARDENING_KERNEL_NATIVE_EXPECTED_VERSION_CHANGED')
        wire = {**state['wire'], 'action': phase, 'expiresAt': int(time.time() * 1000) + 59000}
        # The prepared request is already durable before reboot dispatch. A
        # lost SSH reply cannot cause this harness to invent a new request.
        if phase == 'reboot':
            module.atomic(state_path, module.encoded(state))
        reply = module.execute(wire)
        state['receipt'] = reply
        module.atomic(state_path, module.encoded(state))
        if phase == 'verify':
            if reply['phase'] != 'activated' or reply['bootId'] == wire['bootId'] or os.uname().release != reply['plan']['candidateRelease'] or \
                    module.runtime_identity() != state['identity']:
                module.fail('HARDENING_KERNEL_NATIVE_BOOT_UNCONFIRMED')
        if phase == 'rollback' and reply['phase'] != 'rolled-back':
            module.fail('HARDENING_KERNEL_NATIVE_ROLLBACK_UNCONFIRMED')
    print(json.dumps({'phase': state['receipt']['phase'], 'architecture': os.uname().machine,
                      'bootChanged': module.boot() != state['wire']['bootId'],
                      'runningRelease': os.uname().release,
                      'candidateVersion': state['receipt']['plan']['candidateVersion'],
                      'nativeVm': True}, separators=(',', ':')))
finally:
    os.close(fd)
PY
