#!/usr/bin/env python3
"""Trace the fixed pre-retention rollback helper only on a disposable GitHub-hosted runner; no locals."""
import contextlib
import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys

TARGET = '/usr/local/libexec/incudal/incudal-repository-source-startup'
SOURCE_COMMIT = 'c56f4fefc2f5f5c5b1e9048aa8c77305fa51336d'
EXPECTED = '15193bdd6f6ce50af08c66a7510b8cee3864ae07e1ab878818435ba93b21d932'
EXPECTED_BYTES = 12772
BODY_FIRST_INSTALLER_LINE = 93
BODY_FILENAME = '<fixed-repository-startup>'
FUNCTIONS = frozenset({
    '<module>', '<genexpr>', 'Directory', 'File', '__init__', 'check', 'close',
    'directory', 'facts', 'git_query', 'git_snapshot', 'hold', 'main', 'origin',
    'protected', 'read', 'read_fd', 'recheck', 'refuse', 'runtime', 'source_digest',
})
ERROR_TYPES = frozenset({
    'ValueError', 'PermissionError', 'FileNotFoundError', 'OSError',
    'TimeoutExpired', 'TimeoutError',
})
rows = []


def refused():
    raise ValueError('NORMALIZER_CI_TRACE_REFUSED')


def location(frame):
    if frame.f_code.co_filename != BODY_FILENAME or frame.f_code.co_name not in FUNCTIONS:
        refused()
    return {'function': frame.f_code.co_name, 'bodyLine': frame.f_lineno,
            'installerLine': BODY_FIRST_INSTALLER_LINE + frame.f_lineno - 1}


def trace(frame, event, arg):
    if frame.f_code.co_filename != BODY_FILENAME or len(rows) >= 256:
        return trace
    if event == 'call' and frame.f_code.co_name == 'refuse':
        rows.append({'event': 'refuse', **location(frame.f_back)})
    elif event == 'exception':
        error = arg[1]
        name = type(error).__name__
        if name in ERROR_TYPES:
            errno = getattr(error, 'errno', None)
            rows.append({'event': 'exception', **location(frame), 'type': name,
                         'errno': errno if type(errno) is int and 0 <= errno <= 4095 else None})
    return trace


def timeout(signum, frame):
    raise TimeoutError('NORMALIZER_CI_TRACE_TIMEOUT')


def run():
    if (os.name != 'posix' or os.geteuid() != 0 or len(sys.argv) != 1 or
            os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        refused()
    for name in ('/', '/usr', '/usr/local', '/usr/local/libexec', '/usr/local/libexec/incudal'):
        info = os.lstat(name)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            refused()
    fd = os.open(TARGET, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        initial = os.fstat(fd)
        if (not stat.S_ISREG(initial.st_mode) or initial.st_uid != 0 or initial.st_gid != 0 or
                stat.S_IMODE(initial.st_mode) != 0o755 or initial.st_nlink != 1 or
                initial.st_size != EXPECTED_BYTES):
            refused()
        raw = os.read(fd, initial.st_size + 1)
        if len(raw) != initial.st_size or hashlib.sha256(raw).hexdigest() != EXPECTED:
            refused()
        named, final = os.lstat(TARGET), os.fstat(fd)
        facts = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size',
                 'st_mtime_ns', 'st_ctime_ns')
        if any(getattr(initial, field) != getattr(named, field) or
               getattr(initial, field) != getattr(final, field) for field in facts):
            refused()
    finally:
        os.close(fd)
    shell = raw.decode('utf-8')
    marker, end = "<<'INCUDAL_RETIRED_HELPER_PY'\n", '\nINCUDAL_RETIRED_HELPER_PY'
    if shell.count(marker) != 1 or shell.count(end) != 1:
        refused()
    body = shell.split(marker, 1)[1].split(end, 1)[0] + '\n'
    def record(name):
        try:
            info = os.lstat(name)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024: refused()
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                snapshot_fields = ('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
                snapshot = tuple(getattr(info, key) for key in snapshot_fields)
                if tuple(getattr(os.fstat(file_fd), key) for key in snapshot_fields) != snapshot: refused()
                data = os.read(file_fd, info.st_size + 1)
                held = os.fstat(file_fd)
                if len(data) != info.st_size or tuple(getattr(held, key) for key in snapshot_fields) != snapshot or \
                   tuple(getattr(os.lstat(name), key) for key in snapshot_fields) != snapshot: refused()
                return {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': info.st_size,
                        'uid': info.st_uid, 'gid': info.st_gid,
                        'mode': oct(stat.S_IMODE(info.st_mode)), 'links': info.st_nlink,
                        'dev': info.st_dev, 'ino': info.st_ino,
                        'mtimeNs': info.st_mtime_ns, 'ctimeNs': info.st_ctime_ns}
            finally: os.close(file_fd)
        except FileNotFoundError: return {'missing': True}
    app = os.path.realpath('/opt/incudal/current')
    if not app.startswith('/opt/incudal/releases/') or not os.path.isdir(app): refused()
    source = record(app + '/deploy/incudal-online-task.sh.example')
    installed = record('/usr/local/libexec/incudal/incudal-online-task')
    secure = record('/usr/local/libexec/incudal/database-secure-task')
    unit = subprocess.run(['/usr/bin/systemctl', 'show', 'incudal-backend.service', '-p', 'ExecStartPre', '--value'],
                          capture_output=True, timeout=15, check=True,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    print(json.dumps({'phase': 'fixed-c56-rollback-helper-state',
                      'sourceCommit': SOURCE_COMMIT, 'source': source,
                      'installed': installed, 'databaseSecure': secure,
                      'effectiveLegacyInstallerPrePresent': b'/scripts/install-platform-backup.sh' in unit.stdout,
                      'currentLink': os.readlink('/opt/incudal/current'), 'resolvedCurrent': app}), flush=True)
    output, error = io.StringIO(), io.StringIO()
    old_handler = signal.signal(signal.SIGALRM, timeout)
    code = 0
    try:
        signal.alarm(60)
        sys.settrace(trace)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            exec(compile(body, BODY_FILENAME, 'exec'), {'__name__': '__main__'})
    except SystemExit as status:
        code = 0 if status.code is None else status.code
        if type(code) is not int or not 0 <= code <= 255:
            refused()
    finally:
        sys.settrace(None)
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
    print(json.dumps({'phase': 'fixed-repository-startup-native-trace',
                      'normalizerSourceCommit': SOURCE_COMMIT, 'normalizerSha256': EXPECTED,
                      'exitCode': code, 'trace': rows, 'traceLimitReached': len(rows) == 256,
                      'stdoutEmpty': output.getvalue() == '',
                      'stderrFixedCodeOnly': error.getvalue() in
                      ('', 'INCUDAL_RETIRED_HELPER_REFUSED\n')}), flush=True)
    print(json.dumps({'phase': 'fixed-c56-rollback-helper-after',
                      'source': record(app + '/deploy/incudal-online-task.sh.example'),
                      'installed': record('/usr/local/libexec/incudal/incudal-online-task'),
                      'databaseSecure': record('/usr/local/libexec/incudal/database-secure-task')}), flush=True)
    return code


if __name__ == '__main__':
    try:
        status = run()
    except BaseException as exception:
        name = type(exception).__name__
        print(json.dumps({'phase': 'fixed-repository-startup-native-trace',
                          'code': 'NORMALIZER_CI_TRACE_REFUSED',
                          'exceptionType': name if name in ERROR_TYPES else 'OtherError',
                          'trace': rows}), flush=True)
        status = 1
    raise SystemExit(status)
