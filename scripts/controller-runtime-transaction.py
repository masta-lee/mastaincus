"""Explicit maintenance validation inside the marked disposable VM."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import time

ROOT = Path('/root/controller-runtime-lab')
JOURNAL = Path('/var/lib/incudal-system-security/runtime-maintenance.json')
CLIENT_ERRORS = {'SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED', 'SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED'}


def check(ok, code):
    if not ok:
        raise ValueError(code)


def read(path):
    return json.loads(path.read_bytes())


@contextmanager
def lane(module):
    fd = module.open_platform_operation_lock()
    try:
        s = os.fstat(fd)
        check(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1 and not s.st_mode & 0o077,
              'INVALID_MAINTENANCE_LOCK')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def simulate(module, targets, before):
    limits = ['apt-get', '-o', 'DPkg::Lock::Timeout=5', '-o', 'APT::Get::AllowUnauthenticated=false',
              '--simulate', '--only-upgrade', '--no-remove', 'install']
    changes = module.patch_plan(module.command(limits + targets, 30), before, module.RUNTIME_DEBIAN_BASE_LIBRARIES)
    module.validate_runtime_libc_plan(changes, before)
    check({item.split('=')[0] for item in changes} == {'libc6', 'libc-bin'}, 'NO_REAL_REVIEWED_LIBC_PAIR')
    return sorted(changes)


def prepare(module, identity):
    check(not JOURNAL.exists(), 'EXISTING_RUNTIME_TRANSACTION')
    module.verify_runtime_integrity()
    module.verify_runtime_health()
    backend, database = module.backend_runtime_proof(), module.database_runtime_proof()
    check(backend and database['major'] == 16 and not database.get('sharedReadOnly'), 'LOCAL_PG16_REQUIRED')
    module.verify_runtime_financial_integrity(backend['app'])
    baseline = module.debian_installed_packages()
    installed = module.inventory()['packages']
    check(module.libc_security_series(installed['libc6']) == '2.41', 'BASELINE_LIBC_CHANGED')
    changes = simulate(module, ['libc6', 'libc-bin'], installed)
    check(simulate(module, changes, installed) == changes, 'APT_PLAN_CHANGED')
    expected = dict(baseline)
    for item in changes:
        name, candidate = item.split('=', 1)
        keys = [k for k in baseline if k.split(':')[0] == name]
        check(len(keys) == 1 and baseline[keys[0]] == installed[name] != candidate, 'BASELINE_VERSION_CHANGED')
        expected[keys[0]] = candidate
    # Both the running executables and the retained packages must be genuine.
    policy = module.prepare_runtime_systemd_policy(changes, baseline)
    check(policy and policy['qualification']['manager']['pid'] == 1 and
          policy['qualification']['journald']['pid'] > 1, 'SYSTEMD_QUALIFICATION_REQUIRED')
    vendors = {}
    for name, path in [('nodejs', 'usr/bin/node'), ('postgresql-16', 'usr/lib/postgresql/16/bin/postgres'),
                       ('postgresql-client-16', 'usr/lib/postgresql/16/bin/psql')]:
        key, = [k for k in baseline if k.split(':')[0] == name]
        _, archive, _ = module.acquire_runtime_debian_archive(name, baseline[key], key.split(':')[1], role='before')
        authentic = module.runtime_archive_programs(archive, [path])[path]
        check(module.runtime_payload_regular('/' + path, 128 * 1024**2)['sha256'] == authentic,
              'VENDOR_BEFORE_MISMATCH')
        vendors[name] = authentic
    return {'identity': identity, 'backend': backend, 'database': database, 'changes': changes,
            'baseline': baseline, 'expected': expected, 'vendors': vendors,
            'qualification': policy['qualification'], 'programs': policy['programs']}


def verify_cut(module, before, journal):
    check(journal.get('phase') == 'installed' and journal.get('drainConfirmed') is True and
          not journal.get('activationOnly') and journal['packages'] == before['changes'] and
          journal['backend'] == before['backend'] and journal['database'] == before['database'] and
          journal['baselinePackages'] == before['baseline'] and journal['expectedPackages'] == before['expected'] and
          set(journal['dumpEvidence']) == {'database.dump', 'database-after-drain.dump'} and
          module.debian_installed_packages() == before['expected'], 'INSTALLED_CUT_UNCONFIRMED')
    policy = journal['systemdPolicy']
    check(policy['bootId'] == before['identity']['boot'] and policy['qualification'] == before['qualification']
          and policy['programs'] == before['programs'] and re.fullmatch('[a-f0-9]{32}', policy['token']),
          'SYSTEMD_ORIGIN_CHANGED')
    module.verify_runtime_systemd_package_authority(journal, archives=True)
    module.verify_runtime_original_dumps(journal)
    module.verify_runtime_payload(journal, require='expected', archives=True)


def install_cut(module, before, saved):
    original = module.write_runtime_maintenance

    def after_durable_write(journal, directory=JOURNAL.parent):
        original(journal, directory)
        if journal.get('phase') == 'installed':
            check(read(JOURNAL) == journal, 'JOURNAL_NOT_DURABLE')
            verify_cut(module, before, journal)
            saved(ROOT / 'cut.json', journal)
            os._exit(75)

    module.write_runtime_maintenance = after_durable_write
    try:
        with lane(module):
            module.install_runtime_patches(before['changes'], before['backend'], before['database'],
                                           {'version': 1, 'patchState': 'prepared'}, before['expected'])
        raise ValueError('INSTALL_INTERRUPTION_NOT_REACHED')
    finally:
        module.write_runtime_maintenance = original


def fault(module, before, cut, identity, saved):
    journal = read(JOURNAL)
    check(journal == cut and identity['boot'] != cut['systemdPolicy']['bootId'], 'NEW_BOOT_JOURNAL_CHANGED')
    module.verify_runtime_original_dumps(journal)
    module.verify_runtime_financial_integrity(before['backend']['app'])
    current = module.database_runtime_proof(journal=journal)
    module.verify_runtime_database_configuration(current, journal['database'])
    unit = journal['database']['unit']
    native = module.runtime_boot_database_native(journal['database'], module.runtime_boot_database_execution(journal['database']))
    check(current['pid'] == native['pid'] and current['start'] == native['start'], 'NATIVE_PG_BEFORE_CHANGED')
    client = Path('/usr/lib/postgresql/16/bin/psql')
    retained = client.with_name('psql.incudal-test-' + identity['id'])
    original_client = module.runtime_payload_regular(client, 128 * 1024**2)
    check(original_client['sha256'] == before['vendors']['postgresql-client-16'] and not retained.exists(),
          'PG_CLIENT_BEFORE_CHANGED')
    with lane(module):
        module.command(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', unit], 8)
        until = time.monotonic() + 20
        while time.monotonic() < until:
            execution = module.runtime_boot_database_execution(journal['database'])
            if not execution['pid'] and execution['active'] in ('failed', 'inactive'):
                break
            time.sleep(.25)
        check(not execution['pid'] and execution['active'] in ('failed', 'inactive') and
              execution['result'] != 'success', 'PG_FAULT_UNCONFIRMED')
        client.rename(retained)
        sql_probe = module.database_runtime_proof
        observed = []

        def observe_before_sql(*args, **kwargs):
            state = read(JOURNAL).get('bootRecoveries', {}).get(identity['boot'], {})
            launches = state.get('databaseServiceRecoveryLaunches', [])
            if launches and launches[-1].get('native'):
                observed.append(launches[-1]['native'])
            return sql_probe(*args, **kwargs)

        module.database_runtime_proof = observe_before_sql
        try:
            try:
                module.recover_runtime_maintenance(JOURNAL)
            except ValueError as exc:
                check(str(exc) in CLIENT_ERRORS, 'UNEXPECTED_PG_CLIENT_ERROR')
            else:
                raise ValueError('MISSING_PG_CLIENT_ACCEPTED')
        finally:
            module.database_runtime_proof = sql_probe
        recovery = read(JOURNAL)['bootRecoveries'][identity['boot']]
        launches = recovery['databaseServiceRecoveryLaunches']
        check(len(launches) == 1 and launches[0]['state'] == 'started' and launches[0]['database'] is None and
              observed and launches[0]['native'] == observed[-1] and 'databaseServiceRecovery' not in recovery,
              'MISSING_NATIVE_LAUNCH_BEFORE_SQL')
        saved(ROOT / 'injected-client.json', {'client': original_client, 'nativeLaunch': launches[0],
                                              'path': str(retained)})
    return client, retained


def restore_client(module, before, client, retained):
    record = read(ROOT / 'injected-client.json')
    proof = module.runtime_payload_regular(retained, 128 * 1024**2)
    check(not client.exists() and record['path'] == str(retained) and proof['sha256'] ==
          record['client']['sha256'] == before['vendors']['postgresql-client-16'], 'RETAINED_CLIENT_CHANGED')
    for field in ('mode', 'uid', 'gid', 'size'):
        check(proof[field] == record['client'][field], 'RETAINED_CLIENT_METADATA_CHANGED')
    retained.rename(client)
    check(module.runtime_payload_regular(client, 128 * 1024**2)['sha256'] == proof['sha256'],
          'CLIENT_RESTORATION_FAILED')


def recover(module, before, cut, identity):
    launch = read(ROOT / 'injected-client.json')['nativeLaunch']
    with lane(module):
        for _ in range(3):
            try:
                module.recover_runtime_maintenance(JOURNAL)
            except ValueError as exc:
                check(str(exc) in CLIENT_ERRORS, 'UNEXPECTED_RECOVERY_ERROR')
            if not JOURNAL.exists():
                break
            state = read(JOURNAL)['bootRecoveries'][identity['boot']]
            check(state['databaseServiceRecoveryLaunches'] == [launch], 'SECOND_PG_LAUNCH')
        completed = read(JOURNAL.parent / cut['backup'] / 'completed.json')
        check(completed['phase'] == 'activated' and completed['bootConfirmation']['bootId'] == identity['boot'] and
              module.runtime_systemd_origin_hash(completed['systemdPolicy']) ==
              module.runtime_systemd_origin_hash(cut['systemdPolicy']), 'RECOVERY_ORIGIN_CHANGED')
        module.runtime_backup_evidence(JOURNAL.parent / cut['backup'], completed)
        module.verify_runtime_original_dumps(completed)
        module.verify_runtime_integrity()
        module.verify_runtime_health()
        module.verify_runtime_financial_integrity(before['backend']['app'])
        confirmation = module.runtime_systemd_boot_confirmation(completed)
        check(confirmation['mode'] == 'new-boot-read-only' and
              confirmation['originalBootId'] == before['identity']['boot'], 'BOOT_CONFIRMATION_MISSING')
        native = module.runtime_boot_database_native(completed['database'],
                                                     module.runtime_boot_database_execution(completed['database']))
        database = module.database_runtime_proof(journal=completed)
        backend = module.backend_runtime_proof()
        check(native == launch['native'] and native['pid'] == database['pid'] and native['start'] == database['start'],
              'RECOVERED_PG_PROCESS_CHANGED')
        check(backend and all(backend[k] == before['backend'][k] for k in
                              ('app', 'environmentHash', 'codeHash', 'unitHashes', 'serviceHash')),
              'RECOVERED_BACKEND_CHANGED')
        module.verify_runtime_libc_process(native['pid'], confirmation['libcFiles'])
        module.verify_runtime_libc_process(backend['pid'], confirmation['libcFiles'])
