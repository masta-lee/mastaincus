#!/usr/bin/env python3
"""Inspect the fixed 4a rollback failure only on a disposable GitHub runner."""
import contextlib
import hashlib
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys

TARGET = '/usr/local/libexec/incudal/incudal-repository-source-startup'
SOURCE_COMMIT = '4a3d7c84aa66c2d2508344bfb8b0a6dd0bc54c78'
EXPECTED = '09cef9b5c92ea649d8ef03e97553a789313ff68897108322aeb3295d891ada83'
EXPECTED_BYTES = 13538
BODY_FILENAME = '<fixed-4a-repository-startup>'
FUNCTIONS = frozenset({
    '<module>', '<genexpr>', 'Directory', 'File', '__init__', 'check', 'close',
    'directory', 'facts', 'git_query', 'git_snapshot', 'hold', 'main', 'origin',
    'protected', 'read', 'read_fd', 'recheck', 'refuse', 'runtime', 'source_digest',
})
ERROR_TYPES = frozenset({'ValueError', 'PermissionError', 'FileNotFoundError',
                         'OSError', 'TimeoutExpired', 'TimeoutError'})
FACTS = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size',
         'st_mtime_ns', 'st_ctime_ns')
SYSTEM_ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
rows = []


def refused():
    raise ValueError('CURRENT_ROLLBACK_CI_TRACE_REFUSED')


def snapshot(info):
    return tuple(getattr(info, field) for field in FACTS)


def record(name, required=False):
    try:
        info = os.lstat(name)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > 1024 * 1024):
            refused()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            if snapshot(os.fstat(fd)) != snapshot(info):
                refused()
            raw = os.read(fd, info.st_size + 1)
            if (len(raw) != info.st_size or snapshot(os.fstat(fd)) != snapshot(info)
                    or snapshot(os.lstat(name)) != snapshot(info)):
                refused()
            return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': info.st_size,
                    'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode)),
                    'links': info.st_nlink, 'dev': info.st_dev, 'ino': info.st_ino,
                    'mtimeNs': info.st_mtime_ns, 'ctimeNs': info.st_ctime_ns}, raw
        finally:
            os.close(fd)
    except FileNotFoundError:
        if required:
            refused()
        return {'missing': True}, None


def unit_state():
    result = subprocess.run(['/usr/bin/systemctl', 'show', 'incudal-backend.service',
                             '--property=ActiveState,SubState,Result,ExecMainStatus,MainPID,InvocationID,ExecStartPre,ExecStartPost'],
                            capture_output=True, timeout=15, check=True, env=SYSTEM_ENV)
    if len(result.stdout) > 65536:
        refused()
    values = {}
    for line in result.stdout.decode('utf-8', 'strict').splitlines():
        key, separator, value = line.partition('=')
        if not separator:
            refused()
        if key in ('ActiveState', 'SubState', 'Result'):
            if not re.fullmatch(r'[a-z-]{1,64}', value):
                refused()
            values[key] = value
        elif key in ('ExecMainStatus', 'MainPID'):
            if not re.fullmatch(r'[0-9]{1,12}', value):
                refused()
            values[key] = int(value)
        elif key == 'InvocationID':
            if value and not re.fullmatch(r'[a-f0-9]{32}', value):
                refused()
            values[key] = value
        elif key in ('ExecStartPre', 'ExecStartPost'):
            commands = []
            entries = re.findall(r'\{[^}]*\}', value)
            if value.strip() and not entries:
                refused()
            for entry in entries:
                executable = re.search(r'(?:^|[\s{])path=([^\s;]+)', entry)
                status = re.search(r'(?:^|[\s;])status=([0-9]{1,3})(?:\s|;|})', entry)
                code = re.search(r'(?:^|[\s;])code=([a-z-]{1,32})(?:\s|;|})', entry)
                known = [name for name in ('harden-database.py', 'migrate-database',
                                          'incudal-online-task', 'incudal-repository-source-startup',
                                          'install-platform-backup.sh') if name in entry]
                if executable is None or not re.fullmatch(r'/(?:usr|opt)/[A-Za-z0-9_./+-]{1,240}', executable[1]):
                    refused()
                times = {}
                for field in ('start_time', 'stop_time'):
                    timestamp = re.search(r'(?:^|[\s;])' + field + r'=\[([^\]]{1,96})\]', entry)
                    if timestamp and timestamp[1] != 'n/a' and not re.fullmatch(
                            r'[A-Z][a-z]{2} [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})? [A-Za-z0-9+_-]{1,20}', timestamp[1]):
                        refused()
                    times[field] = timestamp[1] if timestamp and timestamp[1] != 'n/a' else None
                commands.append({'executable': executable[1], 'knownEntries': known,
                                 'exitStatus': int(status[1]) if status else None,
                                 'exitCode': code[1] if code else None, **times})
            values[key] = commands
    return values


def journal_evidence():
    result = subprocess.run(['/usr/bin/journalctl', '-u', 'incudal-backend.service',
                             '--no-pager', '-n', '120', '--output=json'],
                            capture_output=True, timeout=15, check=True, env=SYSTEM_ENV)
    if len(result.stdout) > 2 * 1024 * 1024:
        refused()
    evidence = []
    hints = {'trusted manifest is missing': 'runtime-manifest-missing',
             'release file set or digest differs from trusted manifest': 'runtime-seal-differs',
             'release integrity verification failed': 'runtime-seal-byte-refusal',
             'Database compatibility': 'database-compatibility-message',
             'Refusing': 'explicit-refusal',
             'Control process exited': 'systemd-control-exited',
             'Failed at step': 'systemd-step-failed',
             'Failed with result': 'systemd-unit-failed'}
    for line in result.stdout.splitlines():
        entry = json.loads(line)
        message = entry.get('MESSAGE')
        if not isinstance(message, str):
            continue
        codes = sorted(set(re.findall(r'\b(?:INCUDAL|DATABASE|AUTHENTICATION|FINANCIAL)_[A-Z0-9_]{2,120}\b', message)))
        matched = sorted(label for text, label in hints.items() if text in message)
        steps = sorted(set(re.findall(r'Failed at step ([A-Z_]{2,32})\b', message)))
        if not codes and not matched and not steps:
            continue
        invocations = {}
        for field in ('_SYSTEMD_INVOCATION_ID', 'INVOCATION_ID', 'OBJECT_SYSTEMD_INVOCATION_ID'):
            value = entry.get(field)
            if isinstance(value, str) and re.fullmatch(r'[a-f0-9]{32}', value):
                invocations[field] = value
        pid = entry.get('_PID', '')
        timestamp = entry.get('__REALTIME_TIMESTAMP')
        if not isinstance(timestamp, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', timestamp):
            refused()
        evidence.append({'invocationIds': invocations, 'realtimeMicroseconds': int(timestamp),
                         'pid': int(pid) if isinstance(pid, str) and re.fullmatch(r'[0-9]{1,12}', pid) else None,
                         'knownCodes': codes, 'fixedHints': matched, 'failedSteps': steps,
                         'messageSha256': hashlib.sha256(message.encode('utf-8')).hexdigest()})
    return {'rawMessagesPrinted': False, 'lastEntryLimit': 120, 'sample': True,
            'truncatedPossible': True, 'sizeLimitScope': 'reject-after-capture', 'evidence': evidence}


@contextlib.contextmanager
def held_normalizer():
    info = os.lstat(TARGET)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o755 or info.st_nlink != 1
            or info.st_size != EXPECTED_BYTES):
        refused()
    fd = os.open(TARGET, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        def check():
            if snapshot(os.fstat(fd)) != snapshot(info) or snapshot(os.lstat(TARGET)) != snapshot(info):
                refused()
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, EXPECTED_BYTES + 1)
            if (len(raw) != EXPECTED_BYTES or hashlib.sha256(raw).hexdigest() != EXPECTED
                    or snapshot(os.fstat(fd)) != snapshot(info)):
                refused()
            return raw
        raw = check()
        yield raw, check
        check()
    finally:
        os.close(fd)


def location(frame):
    if frame.f_code.co_filename != BODY_FILENAME or frame.f_code.co_name not in FUNCTIONS:
        refused()
    return {'function': frame.f_code.co_name, 'bodyLine': frame.f_lineno}


def trace(frame, event, arg):
    if frame.f_code.co_filename != BODY_FILENAME or len(rows) >= 256:
        return trace
    if event == 'call' and frame.f_code.co_name == 'refuse':
        rows.append({'event': 'refuse', **location(frame.f_back)})
    elif event == 'exception':
        error = arg[1]
        name = type(error).__name__
        if name in ERROR_TYPES:
            number = getattr(error, 'errno', None)
            rows.append({'event': 'exception', **location(frame), 'type': name,
                         'errno': number if type(number) is int and 0 <= number <= 4095 else None})
    return trace


def timeout(signum, frame):
    raise TimeoutError('CURRENT_ROLLBACK_CI_TRACE_TIMEOUT')


def run():
    if (os.name != 'posix' or os.geteuid() != 0 or len(sys.argv) != 1
            or os.environ.get('GITHUB_ACTIONS') != 'true'
            or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted'):
        refused()
    for name in ('/', '/usr', '/usr/local', '/usr/local/libexec', '/usr/local/libexec/incudal'):
        info = os.lstat(name)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            refused()
    # Capture the failed unit before stopping it. Never print argv/environment
    # or raw journal lines, which can contain generated test credentials.
    before_unit = unit_state()
    print(json.dumps({'phase': 'fixed-4a-current-rollback-unit-before',
                      'sourceCommit': SOURCE_COMMIT, 'unit': before_unit,
                      'scope': 'latest-unit-state-after-original-reproducer-return'}), flush=True)
    print(json.dumps({'phase': 'fixed-4a-current-rollback-journal-before',
                      'sourceCommit': SOURCE_COMMIT, **journal_evidence()}), flush=True)
    failed_normalizer = any('incudal-repository-source-startup' in entry['knownEntries']
                            and entry['exitStatus'] not in (None, 0)
                            for entry in before_unit.get('ExecStartPost', []))
    if not failed_normalizer:
        print(json.dumps({'phase': 'fixed-4a-current-rollback-normalizer-trace-skipped',
                          'sourceCommit': SOURCE_COMMIT,
                          'reason': 'latest-failed-unit-does-not-identify-normalizer-post-failure',
                          'normalizerExecuted': False, 'backendStoppedByTrace': False}), flush=True)
        return 0
    subprocess.run(['/usr/bin/systemctl', 'stop', 'incudal-backend.service'],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=60, check=True, env=SYSTEM_ENV)
    stopped = unit_state()
    if stopped.get('MainPID') != 0 or stopped.get('ActiveState') not in ('inactive', 'failed'):
        refused()
    helper, raw = record(TARGET, required=True)
    if helper['sha256'] != EXPECTED or helper['bytes'] != EXPECTED_BYTES or helper['mode'] != '0o755':
        refused()
    shell = raw.decode('utf-8')
    marker, end = "<<'INCUDAL_RETIRED_HELPER_PY'\n", '\nINCUDAL_RETIRED_HELPER_PY'
    if shell.count(marker) != 1 or shell.count(end) != 1:
        refused()
    body = shell.split(marker, 1)[1].split(end, 1)[0] + '\n'
    current_path = '/opt/incudal/current'
    current_info = os.lstat(current_path)
    if (not stat.S_ISLNK(current_info.st_mode) or current_info.st_uid != 0
            or current_info.st_gid != 0 or current_info.st_nlink != 1):
        refused()
    current_link = os.readlink(current_path)
    app = os.path.realpath(current_path)
    if not re.fullmatch(r'/opt/incudal/releases/[A-Za-z0-9._+-]{1,160}', app):
        refused()
    selected = {'source': app + '/deploy/incudal-online-task.sh.example',
                'installed': '/usr/local/libexec/incudal/incudal-online-task',
                'databaseSecure': '/usr/local/libexec/incudal/database-secure-task'}
    states = {name: record(path)[0] for name, path in selected.items()}
    print(json.dumps({'phase': 'fixed-4a-current-rollback-helper-before',
                      'sourceCommit': SOURCE_COMMIT, 'normalizer': helper,
                      'currentLink': current_link,
                      'resolvedCurrent': app, 'helpers': states, 'unit': stopped}), flush=True)
    output, error = io.StringIO(), io.StringIO()
    old_handler = signal.signal(signal.SIGALRM, timeout)
    code = 0
    with held_normalizer() as (held_raw, normalizer_check):
        if held_raw != raw:
            refused()
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
        normalizer_check()
        if (snapshot(os.lstat(current_path)) != snapshot(current_info)
                or os.readlink(current_path) != current_link or os.path.realpath(current_path) != app):
            refused()
    print(json.dumps({'phase': 'fixed-4a-current-rollback-normalizer-trace',
                      'sourceCommit': SOURCE_COMMIT, 'normalizerSha256': EXPECTED,
                      'exitCode': code, 'trace': rows, 'traceLimitReached': len(rows) == 256,
                      'stdoutEmpty': output.getvalue() == '',
                      'normalizerFdAndNameUnchanged': True, 'currentLinkUnchanged': True,
                      'scope': 'conditional-original-normalizer-execution-in-disposable-runner',
                      'stderrFixedCodeOnly': error.getvalue() in ('', 'INCUDAL_RETIRED_HELPER_REFUSED\n')}), flush=True)
    print(json.dumps({'phase': 'fixed-4a-current-rollback-helper-after',
                      'helpers': {name: record(path)[0] for name, path in selected.items()}}), flush=True)
    return code


if __name__ == '__main__':
    try:
        status = run()
    except BaseException as exception:
        name = type(exception).__name__
        print(json.dumps({'phase': 'fixed-4a-current-rollback-trace-failed',
                          'code': 'CURRENT_ROLLBACK_CI_TRACE_REFUSED',
                          'exceptionType': name if name in ERROR_TYPES else 'OtherError',
                          'trace': rows}), flush=True)
        status = 1
    raise SystemExit(status)
