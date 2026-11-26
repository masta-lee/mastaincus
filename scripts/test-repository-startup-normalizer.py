#!/usr/bin/env python3
"""Run the actual metadata normalizer in new private Linux roots, never /opt.

The optional original archive adds the exact v1.8.13/v1.8.14 helper bytes.
Only four fixed path constants are mapped; identity, Git and file checks run.
"""
import contextlib
import hashlib
import io
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

REPO = Path(__file__).resolve().parents[1]
OLD = b'https://github.com/mastalee928/payincus.git'
NEW = b'https://github.com/masta-lee/mastaincus.git'
HISTORICAL_HELPER = '15fd9cac0a7af20a2a8499b10637c7d3696c99ef1abe81eacce728134011219a'
CURRENT = REPO.joinpath('deploy/incudal-online-task.sh.example').read_bytes()
INSTALLER = REPO.joinpath('scripts/install-panel.sh').read_text()
BEGIN, END = "<<'INCUDAL_RETIRED_HELPER_PY'\n", '\nINCUDAL_RETIRED_HELPER_PY'
assert INSTALLER.count(BEGIN) == 1 and INSTALLER.count(END) == 1
NORMALIZER = INSTALLER.split(BEGIN, 1)[1].split(END, 1)[0] + '\n'
pins = re.search(r'PINNED_STARTUP_HELPERS = frozenset\(\{(.*?)\}\)', NORMALIZER, re.S)
assert pins and set(re.findall(r"'([a-f0-9]{64})'", pins[1])) == {
    hashlib.sha256(CURRENT).hexdigest(), HISTORICAL_HELPER,
}


def write(path, raw, mode=0o600):
    with path.open('xb') as file:
        os.fchmod(file.fileno(), mode)
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())


def git(root, home, *args):
    result = subprocess.run(['/usr/bin/git', '-C', str(root), *args],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=15,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                 'HOME': str(home), 'LC_ALL': 'C', 'GIT_OPTIONAL_LOCKS': '0'})
    assert result.returncode == 0


def normalize(root, seals, helpers, home, before_recheck=None):
    body = NORMALIZER
    for name, path in [('ROOT', root), ('SEALS', seals), ('HELPERS', helpers), ('HOME', home)]:
        matches = re.findall(r'^' + name + r' = .+$', body, re.M)
        assert len(matches) == 1
        body = body.replace(matches[0], name + ' = ' + repr(str(path)))
    out, err, status, fired = io.StringIO(), io.StringIO(), 0, False
    def trace(frame, event, arg):
        nonlocal fired
        if before_recheck is not None and not fired and event == 'call' and \
           frame.f_code.co_filename == '<actual-repository-normalizer>' and frame.f_code.co_name == 'recheck':
            fired = True
            before_recheck()
        return trace
    previous_trace = sys.gettrace()
    try:
        if before_recheck is not None: sys.settrace(trace)
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            exec(compile(body, '<actual-repository-normalizer>', 'exec'), {'__name__': '__main__'})
    except SystemExit as failure:
        status = failure.code
    finally:
        sys.settrace(previous_trace)
    assert before_recheck is None or fired
    return status, out.getvalue(), err.getvalue()


def case(stage, label, source=CURRENT, seal='valid', atomic=False, origin=NEW,
         installed_converted=False, mutation=None, accepted=True):
    folder = stage / label
    folder.mkdir(mode=0o700)
    root, seals, helpers, home = (folder / leaf for leaf in ('app', 'seals', 'helpers', 'cache'))
    for path in (root, seals, helpers, home):
        path.mkdir(mode=0o700)
    app = root
    if atomic:
        (root / 'releases').mkdir(mode=0o700)
        app = root / 'releases' / 'test-release'
        app.mkdir(mode=0o700)
        (root / 'current').symlink_to('releases/test-release')
    (app / 'deploy').mkdir(mode=0o700)
    template = app / 'deploy' / 'incudal-online-task.sh.example'
    write(template, source, 0o644)
    git(root, home, 'init', '--quiet')
    git(root, home, 'remote', 'add', 'origin', origin.decode())
    for sample in (root / '.git' / 'hooks').glob('*.sample'):
        sample.chmod(0o644)
    convertible = OLD in source and NEW not in source
    converted = source.replace(OLD, NEW) if convertible else source
    installed = helpers / 'incudal-online-task'
    write(installed, converted if installed_converted else source, 0o755)
    key = hashlib.sha256(str(app).encode()).hexdigest()
    seal_path = seals / (key + '.sha256')
    if seal in ('valid', 'old', 'malformed', 'missing-links'):
        digest = hashlib.sha256(source).hexdigest() if seal in ('valid', 'missing-links') else HISTORICAL_HELPER
        raw = (digest + '  ./deploy/incudal-online-task.sh.example\n').encode()
        write(seal_path, b'invalid\n' if seal == 'malformed' else raw)
        if seal != 'missing-links':
            write(seals / (key + '.sha256.links'), b'')
    elif seal == 'flat-only':
        flat_key = hashlib.sha256(str(root).encode()).hexdigest()
        write(seals / (flat_key + '.sha256'),
              (HISTORICAL_HELPER + '  ./deploy/incudal-online-task.sh.example\n').encode())
        write(seals / (flat_key + '.sha256.links'), b'')
    else:
        assert seal == 'missing'
    marker = home / 'unexpected-execution'
    sentinel = home / 'sentinel.sh'
    write(sentinel, ('#!/bin/sh\nprintf x >> ' + str(marker) + '\n').encode(), 0o755)
    if mutation == 'installed-bytes':
        with installed.open('ab') as file: file.write(b'\n# changed\n')
    elif mutation == 'source-bytes':
        with template.open('ab') as file: file.write(b'\n# changed\n')
    elif mutation == 'source-writable':
        template.chmod(0o666)
    elif mutation == 'installed-writable':
        installed.chmod(0o777)
    elif mutation == 'source-hardlink':
        os.link(template, folder / 'extra-link')
    elif mutation == 'source-symlink':
        original = template.with_name('original-source')
        template.rename(original)
        template.symlink_to(original.name)
    elif mutation == 'parent-writable':
        (app / 'deploy').chmod(0o777)
    elif mutation == 'local-filter':
        git(root, home, 'config', '--local', 'filter.test.clean', str(sentinel))
    elif mutation == 'global-filter':
        write(home / '.gitconfig', ('[filter "lfs"]\n\tclean = ' + str(sentinel) +
                                   '\n\tsmudge = ' + str(sentinel) + '\n\tprocess = ' + str(sentinel) + '\n').encode())
    elif mutation == 'global-hooks':
        write(home / '.gitconfig', ('[core]\n\thooksPath = ' + str(home) + '\n').encode())
    elif mutation == 'global-include':
        included = home / 'included-config'
        write(included, b'[user]\n\tname = test\n')
        write(home / '.gitconfig', ('[include]\n\tpath = ' + str(included) + '\n').encode())
    elif mutation == 'url-rewrite':
        git(root, home, 'config', '--local', 'url.https://untrusted.invalid/.insteadOf', NEW.decode())
    elif mutation == 'duplicate-origin':
        git(root, home, 'config', '--local', '--add', 'remote.origin.url', OLD.decode())
    elif mutation == 'executable-hook':
        write(root / '.git' / 'hooks' / 'pre-push', sentinel.read_bytes(), 0o755)
    else:
        assert mutation is None or mutation in ('recheck-source-swap', 'recheck-installed-swap',
                                                'recheck-config-change', 'recheck-current-change')
    before_source = template.read_bytes()
    before_installed = installed.read_bytes()
    before_local = (root / '.git' / 'config').read_bytes()
    before_global = (home / '.gitconfig').read_bytes() if (home / '.gitconfig').exists() else None
    before_seals = {path.name: path.read_bytes() for path in seals.iterdir()}
    race = {}
    def named_identity(path):
        info = path.lstat()
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    def change_after_read():
        if mutation in ('recheck-source-swap', 'recheck-installed-swap'):
            target = template if mutation == 'recheck-source-swap' else installed
            replacement = target.with_name('race-replacement')
            write(replacement, target.read_bytes(), stat.S_IMODE(target.stat().st_mode))
            replacement.replace(target)
        elif mutation == 'recheck-config-change':
            with (root / '.git' / 'config').open('ab') as file: file.write(b'\n# concurrent edit\n')
        elif mutation == 'recheck-current-change':
            assert atomic
            other = root / 'releases' / 'other-release'
            other.mkdir(mode=0o700)
            link = root / 'new-current'
            link.symlink_to('releases/other-release')
            link.replace(root / 'current')
        else:
            raise AssertionError(mutation)
        race['source'] = template.read_bytes()
        race['installed'] = installed.read_bytes()
        race['config'] = (root / '.git' / 'config').read_bytes()
        race['identities'] = {str(path): named_identity(path) for path in [template, installed, root / '.git' / 'config']}
        if atomic:
            race['current'] = (named_identity(root / 'current'), os.readlink(root / 'current'))
    racing = mutation is not None and mutation.startswith('recheck-')
    status, out, err = normalize(root, seals, helpers, home, change_after_read if racing else None)
    assert status == (0 if accepted else 1), label
    assert not out and err == ('' if accepted else 'INCUDAL_RETIRED_HELPER_REFUSED\n'), label
    assert template.read_bytes() == race.get('source', before_source), label
    assert installed.read_bytes() == ((converted if origin == NEW else source) if accepted else race.get('installed', before_installed)), label
    assert (root / '.git' / 'config').read_bytes() == race.get('config', before_local), label
    assert ((home / '.gitconfig').read_bytes() if (home / '.gitconfig').exists() else None) == before_global, label
    assert {path.name: path.read_bytes() for path in seals.iterdir()} == before_seals, label
    if racing:
        assert {name: named_identity(Path(name)) for name in race['identities']} == race['identities'], label
        if atomic:
            assert (named_identity(root / 'current'), os.readlink(root / 'current')) == race['current'], label
    assert not marker.exists(), label
    assert not list(helpers.glob('.incudal-online-task.repository-*')), label
    print('PASS repository startup:', label, flush=True)


def root_task_gate(stage, label, mode, seal_state):
    """Execute the mapped actual root wrapper with positive and refusal controls.

    Its own constants and maintenance paths point only into this new fixture.
    The ordinary seal command prepares a valid baseline before tamper cases.
    """
    folder = stage / label
    folder.mkdir(mode=0o700)
    root, seals, helpers, home = (folder / leaf for leaf in ('app', 'seals', 'helpers', 'cache'))
    for path in (root, seals, helpers, home): path.mkdir(mode=0o700)
    (root / 'deploy').mkdir(mode=0o700)
    template = root / 'deploy' / 'incudal-online-task.sh.example'
    write(template, CURRENT, 0o644)
    write(root / 'package.json', b'{"type":"commonjs"}\n', 0o644)
    scripts = root / 'server' / 'dist' / 'scripts'
    scripts.mkdir(mode=0o700, parents=True)
    marker = folder / 'worker-executed'
    worker = ('require("node:fs").writeFileSync(' + repr(str(marker)) + ', "executed");process.exit(99);\n').encode()
    for name in ('run-system-update-task.js', 'rollback-system-update-task.js'):
        write(scripts / name, worker, 0o644)
    git(root, home, 'init', '--quiet')
    git(root, home, 'remote', 'add', 'origin', NEW.decode())
    for sample in (root / '.git' / 'hooks').glob('*.sample'): sample.chmod(0o644)
    write(helpers / 'incudal-online-task', CURRENT, 0o755)
    write(helpers / 'systemctl', b'#!/bin/sh\nexit 98\n', 0o755)
    (helpers / 'ota-path').mkdir(mode=0o700)
    write(helpers / 'ota-path' / 'chown', b'#!/bin/sh\nexit 98\n', 0o755)
    body = CURRENT.decode()
    for name, path in [('INSTALL_DIR', root), ('MANIFEST_DIR', seals), ('HELPER_DIR', helpers), ('ROOT_CACHE_DIR', home)]:
        matches = re.findall(r'^readonly ' + name + r'="[^"]+"$', body, re.M)
        assert len(matches) == 1
        body = body.replace(matches[0], 'readonly ' + name + '="' + str(path) + '"')
    for old, new in [('/var/lib/incudal-platform-operation.lock', str(folder / 'operation.lock')),
                     ('/var/lib/incudal-backup/recovery-hold.json', str(folder / 'no-recovery-hold')),
                     ('/var/lib/incudal-gateway-controller/enrollment.json', str(folder / 'no-enrollment')),
                     ('/var/lib/incudal-database/migration.url', str(folder / 'no-migration-url')),
                     ('/usr/local/libexec/incudal/legacy-database-startup.mjs', str(folder / 'no-legacy-database-startup.mjs'))]:
        assert old in body
        body = body.replace(old, new)
    driver = folder / 'actual-root-helper.sh'
    write(driver, body.encode(), 0o755)
    def run(action, *args):
        return subprocess.run(['/usr/bin/bash', str(driver), action, *args], stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=30,
                              env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': str(home), 'LC_ALL': 'C'})
    if seal_state != 'missing':
        if seal_state == 'old': template.write_bytes(b'# authentic previous tree fixture\n')
        prepared = run('seal')
        assert prepared.returncode == 0, label
        if seal_state == 'old': template.write_bytes(CURRENT)
        elif seal_state == 'runtime-changed':
            with (scripts / 'run-system-update-task.js').open('ab') as file: file.write(b'\n// altered runtime\n')
        elif seal_state != 'valid':
            raise AssertionError(seal_state)
    status, out, err = normalize(root, seals, helpers, home)
    assert status == 0 and not out and not err, label
    before_seals = {path.name: path.read_bytes() for path in seals.iterdir()}
    result = run(mode, '1')
    if seal_state == 'valid':
        assert result.returncode == 99 and marker.read_bytes() == b'executed', label
        assert b'trusted manifest' not in result.stderr, label
    else:
        assert result.returncode != 0 and b'trusted manifest' in result.stderr, label
        assert not marker.exists(), label
    assert template.read_bytes() == CURRENT, label
    assert {path.name: path.read_bytes() for path in seals.iterdir()} == before_seals, label
    print('PASS actual root task gate:', label, flush=True)


def main():
    assert sys.platform.startswith('linux') and os.geteuid() == 0
    parent = Path('/root').lstat()
    assert stat.S_ISDIR(parent.st_mode) and parent.st_uid == parent.st_gid == 0 and not parent.st_mode & 0o022
    assert len(sys.argv) in (1, 2)
    historical = None
    if len(sys.argv) == 2:
        with tarfile.open(sys.argv[1], 'r:gz') as archive:
            member = archive.getmember('./deploy/incudal-online-task.sh.example')
            assert member.isfile() and member.size == 15127
            historical = archive.extractfile(member).read()
            assert hashlib.sha256(historical).hexdigest() == HISTORICAL_HELPER
    count = 0
    with tempfile.TemporaryDirectory(prefix='incudal-repository-startup-test-', dir='/root') as temp:
        stage = Path(temp)
        scenarios = [
            ('flat-current-sealed', {}),
            ('flat-current-old-seal', {'seal': 'old'}),
            ('flat-current-missing-seal', {'seal': 'missing'}),
            ('atomic-current-flat-only-seal', {'seal': 'flat-only', 'atomic': True}),
            ('atomic-current-sealed', {'atomic': True}),
            ('current-source-changed-old-seal', {'seal': 'old', 'mutation': 'source-bytes', 'accepted': False}),
            ('current-source-changed-no-seal', {'seal': 'missing', 'mutation': 'source-bytes', 'accepted': False}),
            ('installed-changed-no-seal', {'seal': 'missing', 'mutation': 'installed-bytes', 'accepted': False}),
            ('unrecognized-valid-source-seal', {'source': CURRENT + b'\n# authenticated future helper\n'}),
            ('unrecognized-no-seal-refused', {'source': CURRENT + b'\n# unknown\n', 'seal': 'missing', 'accepted': False}),
            ('unrecognized-old-seal-refused', {'source': CURRENT + b'\n# unknown\n', 'seal': 'old', 'accepted': False}),
            ('unrecognized-malformed-seal-refused', {'source': CURRENT + b'\n# unknown\n', 'seal': 'malformed', 'accepted': False}),
            ('unrecognized-missing-links-refused', {'source': CURRENT + b'\n# unknown\n', 'seal': 'missing-links', 'accepted': False}),
            ('source-writable-refused', {'mutation': 'source-writable', 'accepted': False}),
            ('source-hardlink-refused', {'mutation': 'source-hardlink', 'accepted': False}),
            ('source-symlink-refused', {'mutation': 'source-symlink', 'accepted': False}),
            ('parent-writable-refused', {'mutation': 'parent-writable', 'accepted': False}),
            ('installed-writable-refused', {'mutation': 'installed-writable', 'accepted': False}),
            ('no-seal-local-filter-refused', {'seal': 'missing', 'mutation': 'local-filter', 'accepted': False}),
            ('no-seal-global-filter-never-executed', {'seal': 'missing', 'mutation': 'global-filter'}),
            ('no-seal-global-hooks-refused', {'seal': 'missing', 'mutation': 'global-hooks', 'accepted': False}),
            ('no-seal-global-include-refused', {'seal': 'missing', 'mutation': 'global-include', 'accepted': False}),
            ('no-seal-url-rewrite-refused', {'seal': 'missing', 'mutation': 'url-rewrite', 'accepted': False}),
            ('no-seal-duplicate-origin-refused', {'seal': 'missing', 'mutation': 'duplicate-origin', 'accepted': False}),
            ('no-seal-executable-hook-refused', {'seal': 'missing', 'mutation': 'executable-hook', 'accepted': False}),
            ('custom-origin-refused', {'origin': b'https://untrusted.invalid/project.git', 'seal': 'missing', 'accepted': False}),
            ('recheck-source-name-swap-refused', {'seal': 'missing', 'mutation': 'recheck-source-swap', 'accepted': False}),
            ('recheck-installed-name-swap-refused', {'seal': 'missing', 'mutation': 'recheck-installed-swap', 'accepted': False}),
            ('recheck-config-edit-refused', {'seal': 'missing', 'mutation': 'recheck-config-change', 'accepted': False}),
            ('recheck-current-switch-refused', {'seal': 'missing', 'atomic': True, 'mutation': 'recheck-current-change', 'accepted': False}),
        ]
        if historical is not None:
            scenarios.extend([
                ('original-flat-old-origin', {'source': historical, 'origin': OLD, 'seal': 'missing'}),
                ('original-flat-new-origin', {'source': historical, 'seal': 'missing'}),
                ('original-atomic-new-origin-no-seal', {'source': historical, 'seal': 'flat-only', 'atomic': True}),
                ('original-converted-to-old-origin', {'source': historical, 'origin': OLD, 'installed_converted': True, 'seal': 'missing'}),
                ('original-converted-new-origin', {'source': historical, 'installed_converted': True, 'seal': 'missing'}),
                ('original-changed-no-seal-refused', {'source': historical, 'seal': 'missing', 'mutation': 'source-bytes', 'accepted': False}),
                ('original-recheck-swap-cleans-own-temp', {'source': historical, 'seal': 'missing', 'mutation': 'recheck-installed-swap', 'accepted': False}),
            ])
        for label, kwargs in scenarios:
            case(stage, label, **kwargs)
            count += 1
        for mode in ('update', 'rollback'):
            for seal_state in ('missing', 'old', 'runtime-changed', 'valid'):
                root_task_gate(stage, mode + '-' + seal_state, mode, seal_state)
                count += 1
    print('PASS native repository startup:', count, 'cases; only new private roots modified', flush=True)


if __name__ == '__main__':
    main()
