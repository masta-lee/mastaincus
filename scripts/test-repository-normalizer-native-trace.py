#!/usr/bin/env python3
"""Trace one fixed helper only on a disposable GitHub-hosted runner; no locals."""
import contextlib
import hashlib
import io
import json
import os
import signal
import stat
import sys

TARGET = '/usr/local/libexec/incudal/incudal-repository-source-startup'
SOURCE_COMMIT = '6be2429921fe4ae1e2106a3ecae69b71d232157a'
EXPECTED = '2745eafdbde9feb8879411a67a26c0d6666bd093f7eddf822d31ccd9976c8c78'
EXPECTED_BYTES = 11695
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
