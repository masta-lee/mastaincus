"""Check the disposable controller's native network JSON contract."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import textwrap
import sys
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location(
    'controller_runtime_lab', Path(__file__).with_name('controller-runtime-lab.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)

if sys.platform == 'win32':
    sys.modules.setdefault('fcntl', SimpleNamespace())
spec = importlib.util.spec_from_file_location(
    'controller_runtime_transaction', Path(__file__).with_name('controller-runtime-transaction.py'))
transaction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transaction)
spec = importlib.util.spec_from_file_location(
    'controller_runtime_inventory', Path(__file__).with_name('system-security-inventory.py'))
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class NetworkProfileTests(unittest.TestCase):
    def setUp(self):
        self.scope = {'id': 'abcdef' + '0' * 26}
        self.links = [{'ifindex': 2, 'ifname': 'r6net0', 'address': '02:00:66:ab:cd:ef'}]
        # IPv4 address output omits the MAC. It is obtained from link output.
        self.addresses = [{'ifindex': 2, 'ifname': 'r6net0', 'addr_info': [
            {'family': 'inet', 'local': '10.0.2.15', 'prefixlen': 24}]}]
        self.routes = [{'dev': 'r6net0', 'gateway': '10.0.2.2'}]
        self.networkd = 'LoadState=loaded\nActiveState=inactive\nMainPID=0\nDropInPaths=\n'
        self.commands = []

    def native_run(self, args, timeout, **kwargs):
        self.commands.append(args)
        self.assertEqual(timeout, 15)
        if args == ['systemctl', 'is-active', '--quiet', 'runtime-lab-network.service']:
            return SimpleNamespace(stdout='')
        if args[:3] == ['systemctl', 'show', 'systemd-networkd.service']:
            return SimpleNamespace(stdout=self.networkd)
        if args == ['ip', '-j', 'link', 'show']:
            value = self.links
        elif args == ['ip', '-j', '-4', 'addr', 'show', 'dev', 'r6net0']:
            value = self.addresses
        elif args == ['ip', '-j', '-4', 'route', 'show', 'default']:
            value = self.routes
        else:
            self.fail('Unexpected native network query: ' + repr(args))
        return SimpleNamespace(stdout=json.dumps(value))

    def check(self):
        with patch.object(lab, 'run', side_effect=self.native_run):
            lab.check_network_profile(self.scope)

    def test_ipv4_without_mac_uses_the_same_native_link(self):
        self.check()
        self.assertEqual(self.commands[-3:], [
            ['ip', '-j', 'link', 'show'],
            ['ip', '-j', '-4', 'addr', 'show', 'dev', 'r6net0'],
            ['ip', '-j', '-4', 'route', 'show', 'default']])

    def test_missing_duplicate_or_invalid_mac_link_is_rejected(self):
        original = copy.deepcopy(self.links)
        for links in [[], original * 2, [{**original[0], 'address': '02:00:66:00:00:00'}],
                      [{**original[0], 'ifindex': True}]]:
            with self.subTest(links=links):
                self.links = links
                with self.assertRaisesRegex(ValueError, 'LAB_STATIC_LINK_CHANGED'):
                    self.check()

    def test_address_must_belong_to_the_selected_link(self):
        original = copy.deepcopy(self.addresses[0])
        for address in [{**original, 'ifindex': 3}, {**original, 'ifname': 'another0'},
                        {**original, 'addr_info': [{'family': 'inet6', 'local': '10.0.2.15', 'prefixlen': 24}]},
                        {**original, 'addr_info': [{'family': 'inet', 'local': '10.0.2.15', 'prefixlen': 32}]}]:
            with self.subTest(address=address):
                self.addresses = [address]
                with self.assertRaisesRegex(ValueError, 'LAB_STATIC_ADDRESS_CHANGED'):
                    self.check()

    def test_route_requires_the_selected_link_and_gateway(self):
        for routes in [[], self.routes * 2, [{'dev': 'another0', 'gateway': '10.0.2.2'}],
                       [{'dev': 'r6net0', 'gateway': '10.0.2.1'}]]:
            with self.subTest(routes=routes):
                self.routes = routes
                with self.assertRaisesRegex(ValueError, 'LAB_STATIC_ROUTE_CHANGED'):
                    self.check()

    def test_running_or_overridden_networkd_is_rejected(self):
        for state, code in [
            ('LoadState=loaded\nActiveState=active\nMainPID=42\nDropInPaths=\n', 'LAB_NETWORKD_RUNNING'),
            ('LoadState=loaded\nActiveState=inactive\nMainPID=0\nDropInPaths=/changed\n', 'LAB_NETWORKD_DROPIN_PRESENT')]:
            with self.subTest(state=state):
                self.networkd = state
                with self.assertRaisesRegex(ValueError, code):
                    self.check()


class VendorBeforeTests(unittest.TestCase):
    def setUp(self):
        self.paths = {'nodejs': '/usr/bin/node',
                      'postgresql-16': '/usr/lib/postgresql/16/bin/postgres',
                      'postgresql-client-16': '/usr/lib/postgresql/16/bin/psql'}
        self.programs = {name: {'type': 'file', 'uid': 0, 'gid': 0, 'mode': 0o755,
                               'size': 126891984 if name == 'nodejs' else 1000,
                               'sha256': hashlib.sha256(name.encode()).hexdigest()}
                         for name in self.paths}
        self.installed = {'libc6': '2.41-12+deb13u4', 'libc-bin': '2.41-12+deb13u4'}
        self.baseline = {name + ':amd64': version for name, version in self.installed.items()}
        self.baseline.update({name + ':amd64': 'installed' for name in self.paths})
        self.changes = ['libc6=2.41-12+deb13u5', 'libc-bin=2.41-12+deb13u5']
        self.archive_files = copy.deepcopy(self.programs)
        self.manifest = Mock(side_effect=lambda raw, layout: {
            self.paths[raw.decode()]: self.archive_files[raw.decode()]
        } if raw.decode() in self.archive_files else {})
        self.current = Mock(side_effect=lambda path, limit: self.programs[
            next(name for name, expected in self.paths.items() if path == expected)])
        self.small_reader = Mock(side_effect=AssertionError('Small-file reader cannot inspect Node'))
        self.module = SimpleNamespace(
            verify_runtime_integrity=Mock(), verify_runtime_health=Mock(),
            backend_runtime_proof=Mock(return_value={'app': '/opt/incudal'}),
            database_runtime_proof=Mock(return_value={'major': 16}),
            verify_runtime_financial_integrity=Mock(),
            debian_installed_packages=Mock(return_value=self.baseline),
            inventory=Mock(return_value={'packages': self.installed}),
            libc_security_series=inventory.libc_security_series,
            command=Mock(return_value=''), patch_plan=Mock(return_value=self.changes),
            RUNTIME_DEBIAN_BASE_LIBRARIES=inventory.RUNTIME_DEBIAN_BASE_LIBRARIES,
            validate_runtime_libc_plan=Mock(),
            prepare_runtime_systemd_policy=Mock(return_value={
                'qualification': {'manager': {'pid': 1}, 'journald': {'pid': 2}}, 'programs': {}}),
            acquire_runtime_debian_archive=Mock(side_effect=lambda name, version, architecture, **kw:
                                                 ({'package': name}, name.encode(), {})),
            runtime_payload_layout=Mock(return_value={}),
            runtime_archive_payload=self.manifest, runtime_archive_programs=self.small_reader,
            validate_runtime_payload_record=inventory.validate_runtime_payload_record,
            runtime_payload_regular=self.current)

    def prepare(self):
        with patch.object(transaction, 'JOURNAL', SimpleNamespace(exists=lambda: False)):
            return transaction.prepare(self.module, {'boot': 'original'})

    def test_all_three_vendors_use_full_manifest_and_matching_regular_files(self):
        before = self.prepare()
        self.assertEqual(before['vendors'], {name: row['sha256'] for name, row in self.programs.items()})
        self.assertEqual(self.manifest.call_count, 3)
        self.module.runtime_payload_layout.assert_called_once_with()
        self.small_reader.assert_not_called()
        self.assertTrue(all(call.args[1] == 128 * 1024**2 for call in self.current.call_args_list))
        self.assertTrue(all(call.kwargs == {'role': 'before'} for call in
                            self.module.acquire_runtime_debian_archive.call_args_list))

    def test_absent_nonregular_unowned_or_noncanonical_mode_is_rejected_before_read(self):
        original = copy.deepcopy(self.programs['nodejs'])
        variants = [None, {**original, 'type': 'directory'}, {**original, 'type': 'symlink'},
                    {**original, 'uid': 1}, {**original, 'gid': 1},
                    {**original, 'mode': 0o644}, {**original, 'mode': 0o777},
                    {**original, 'size': 128 * 1024**2 + 1},
                    {**original, 'sha256': 'not-authenticated'}]
        for row in variants:
            with self.subTest(row=row):
                self.archive_files['nodejs'] = row
                with self.assertRaisesRegex(ValueError, 'VENDOR_BEFORE_UNREVIEWED|PAYLOAD_UNCONFIRMED'):
                    self.prepare()
                self.current.assert_not_called()
        del self.archive_files['nodejs']
        with self.assertRaisesRegex(ValueError, 'VENDOR_BEFORE_UNREVIEWED'):
            self.prepare()
        self.current.assert_not_called()

    def test_running_file_must_match_archive_content_and_all_metadata(self):
        original = copy.deepcopy(self.programs['nodejs'])
        for field, value in [('type', 'symlink'), ('sha256', '0' * 64), ('size', 1001),
                             ('mode', 0o644), ('uid', 1), ('gid', 1)]:
            with self.subTest(field=field):
                self.programs['nodejs'] = {**original, field: value}
                with self.assertRaisesRegex(ValueError, 'VENDOR_BEFORE_MISMATCH'):
                    self.prepare()

    def test_archive_refusal_propagates_before_the_running_file_is_read(self):
        self.manifest.side_effect = ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        with self.assertRaisesRegex(ValueError, 'SYSTEM_SECURITY_ARCHIVE_UNREVIEWED'):
            self.prepare()
        self.current.assert_not_called()
        self.small_reader.assert_not_called()


class FailureReasonTests(unittest.TestCase):
    @staticmethod
    def product_error(source, values=None, filename='system-security-inventory.py'):
        namespace = dict(values or {})
        exec(compile(textwrap.dedent(source), filename, 'exec'), namespace)
        try:
            namespace['probe']()
        except Exception as error:
            return error
        raise AssertionError('Expected a checked refusal')

    def test_archive_diagnosis_exports_only_checked_lines_and_bounded_facts(self):
        raw = b'!<arch>\npublic fixture'
        error = self.product_error('''
            def probe():
                data = payload
                part = 'data'
                limit = 128 * 1024**2
                archive = b'bounded decoded bytes'
                wanted = ['usr/bin/node', 'PRIVATE_PACKAGE_NAME']
                path = '/private/DO_NOT_EMIT'
                argv = ['DO_NOT_EMIT_COMMAND']
                environment = {'token': 'DO_NOT_EMIT_TOKEN'}
                raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        ''', {'payload': raw})
        reason = lab.failure_reason(error)
        self.assertIn('_H' + hashlib.sha256(raw).hexdigest().upper(), reason)
        self.assertIn('_DATA_LIMIT134217728_BYTES21_NODEJS', reason)
        self.assertRegex(reason, r'^SYSTEM_SECURITY_ARCHIVE_UNREVIEWED_L[0-9]+_')
        self.assertRegex(reason, r'^[A-Z][A-Z0-9_]{1,199}$')
        self.assertNotIn('PRIVATE_PACKAGE_NAME', reason)
        self.assertNotIn('DO_NOT_EMIT', reason)

    def test_suppressed_native_context_keeps_the_actual_refusal_line(self):
        error = self.product_error('''
            def probe():
                def decode():
                    raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
                try:
                    decode()
                except ValueError:
                    raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED') from None
        ''')
        self.assertTrue(error.__suppress_context__)
        inner = error.__context__.__traceback__
        while inner.tb_next:
            inner = inner.tb_next
        self.assertIn('_L' + str(inner.tb_lineno) + '_FROM', lab.failure_reason(error))

    def test_unreviewed_sizes_and_names_do_not_reach_the_event(self):
        error = self.product_error('''
            def probe():
                data = b'not an ar archive'
                part = 'PRIVATE_PART_NAME'
                limit = 10**300
                archive = 'PRIVATE_ARCHIVE'
                names = ['PRIVATE_PROGRAM_NAME']
                raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        ''')
        reason = lab.failure_reason(error)
        self.assertRegex(reason, r'^SYSTEM_SECURITY_ARCHIVE_UNREVIEWED_L[0-9]+$')
        self.assertNotIn('PRIVATE', reason)

    def test_context_cycle_is_bounded_and_no_foreign_frame_is_exported(self):
        error = self.product_error('''
            def probe():
                raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        ''')
        error.__context__ = error
        self.assertRegex(lab.failure_reason(error),
                         r'^SYSTEM_SECURITY_ARCHIVE_UNREVIEWED_L[0-9]+$')
        foreign = self.product_error('''
            def probe():
                path = '/private/DO_NOT_EMIT'
                raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        ''', filename='foreign-file.py')
        self.assertEqual(lab.failure_reason(foreign), 'SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')

    def test_unknown_exception_text_is_not_exported(self):
        self.assertEqual(lab.failure_reason(ValueError('/private/DO_NOT_EMIT')), 'VALUEERROR')
        self.assertEqual(lab.failure_reason(ValueError('PUBLIC_REFUSAL')), 'PUBLIC_REFUSAL')


if __name__ == '__main__':
    unittest.main()
