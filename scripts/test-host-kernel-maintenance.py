#!/usr/bin/env python3
"""Kernel transaction fixtures; these do not prove an Alpine kernel booted."""
import copy
import ast
import base64
import contextlib
import errno
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import shutil
import stat
import sys
import tarfile
import tempfile
import time
import types
import unittest
import uuid
from contextlib import ExitStack
from unittest.mock import patch

if os.name == 'nt':
    sys.modules.setdefault('fcntl', types.SimpleNamespace(LOCK_EX=2, LOCK_NB=4, flock=lambda *_: None))
source = Path(__file__).parents[1] / 'server/templates/host-kernel-maintenance.py'
if not source.exists():
    source = Path(__file__).with_name('host-kernel-maintenance.py')
spec = importlib.util.spec_from_file_location('host_kernel_maintenance', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
apparmor_source = source.with_name('host-security-maintenance.py')
apparmor_spec = importlib.util.spec_from_file_location('host_apparmor_maintenance', apparmor_source)
apparmor_module = importlib.util.module_from_spec(apparmor_spec)
apparmor_spec.loader.exec_module(apparmor_module)


@unittest.skipUnless(Path(__file__).with_name('host-kernel-lab.py').is_file() and
                     Path(__file__).with_name('test-host-kernel-boot-native.sh').is_file(),
                     'native test-entry diagnostics are checked from their repository sources')
class KernelNativeDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name('host-kernel-lab.py')
        spec = importlib.util.spec_from_file_location('kernel_lab_diagnostic_test', path)
        cls.lab = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.lab)

    def diagnostic(self, raw):
        return {'program': 'apk', 'arguments': ['--repositories-file', '/private/DO_NOT_EMIT',
                '--simulate', 'upgrade', 'linux-virt'], 'exit': 0, 'stdoutBytes': len(raw),
                'stderrBytes': 0, 'stderrPrefix': '', 'stdoutSha256': hashlib.sha256(raw).hexdigest(),
                'stdoutBase64': base64.b64encode(raw).decode()}

    def test_public_summary_has_only_checked_native_facts_and_plan_classes(self):
        raw = b'Upgrading linux-virt (6.18.58-r0 -> 6.18.65-r0)\nUpgrading DO_NOT_EMIT (1.0-r0 -> 1.1-r0)\n'
        result = self.lab.native_diagnostic_summary(self.diagnostic(raw))
        self.assertEqual(result['planActionCounts']['Upgrading'], 2)
        self.assertIs(result['nonKernelPlanChange'], True)
        self.assertEqual(result['operation'], 'upgrade')
        self.assertEqual(result['stdoutSha256'], hashlib.sha256(raw).hexdigest())
        self.assertNotIn('DO_NOT_EMIT', json.dumps(result))
        self.assertNotIn('stdoutBase64', result); self.assertNotIn('arguments', result)
        legacy = self.diagnostic(b'')
        legacy.pop('stdoutBase64');legacy.pop('stdoutSha256')
        legacy.update(exit=-9,stderrPrefix="apk: unrecognized option: '--no-scripts'")
        legacy['arguments'].append('--no-scripts')
        self.assertEqual(self.lab.native_diagnostic_summary(legacy)['errorClass'], 'OPTION_REJECTED')
        self.assertEqual(self.lab.native_diagnostic_summary(legacy)['rejectedOption'], '--no-scripts')

    def test_changed_stream_and_unchecked_native_fields_are_not_published(self):
        original = self.diagnostic(b'Upgrading linux-virt (6.18.58-r0 -> 6.18.65-r0)\n')
        for changes in [{'stdoutSha256': 'a'*64}, {'stdoutBytes': original['stdoutBytes']+1},
                        {'stdoutBase64': 'invalid#base64'}, {'program': 'DO_NOT_EMIT'},
                        {'arguments': ['/private/DO_NOT_EMIT']*25}, {'exit': True}]:
            with self.subTest(changes=changes):
                self.assertIsNone(self.lab.native_diagnostic_summary({**original, **changes}))
        for row in [{'reason': 'DO_NOT_EMIT','line': 1,'function':'installation_changes'},
                    {'reason': 'HARDENING_KERNEL_PACKAGE_PLAN_CHANGED','line': True,'function':'installation_changes'},
                    {'reason': 'HARDENING_KERNEL_PACKAGE_PLAN_CHANGED','line': 1,'function':['DO_NOT_EMIT']}]:
            self.assertIsNone(self.lab.native_diagnostic_summary(row))

    def test_private_complete_stream_is_kept_while_public_summaries_are_bounded(self):
        raw = b'Upgrading linux-virt (6.18.58-r0 -> 6.18.65-r0)\n' + b'PRIVATE_DATA\n'*7000
        record = self.diagnostic(raw)
        body = b'E04_NATIVE_COMMAND_TRACE '+json.dumps(record).encode()+b'\n'
        with tempfile.TemporaryDirectory()as directory:
            path = Path(directory)/'private.log'
            path.write_bytes(body)
            result = self.lab.native_diagnostic_summaries(path)
            self.assertEqual(path.read_bytes(), body)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['stdoutBytes'], len(raw))
            self.assertNotIn('PRIVATE_DATA', json.dumps(result))
            path.write_bytes(body*13)
            self.assertEqual(len(self.lab.native_diagnostic_summaries(path)), 12)

    def test_native_refusal_captures_the_original_product_caller_and_keeps_its_error(self):
        source = Path(__file__).with_name('test-host-kernel-boot-native.sh').read_text()
        body = source.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        function, = [item for item in ast.parse(body).body if isinstance(item, ast.FunctionDef) and item.name=='diagnose_kernel_refusal']
        namespace = {'module': module, 'original_fail': module.fail, 'sys':sys, 're':__import__('re'), 'json':json}
        exec(compile(ast.Module(body=[function],type_ignores=[]), '<native-refusal-test>', 'exec'), namespace)
        stderr = io.StringIO()
        with patch.object(module,'fail',namespace['diagnose_kernel_refusal']),contextlib.redirect_stderr(stderr),self.assertRaisesRegex(ValueError,'^HARDENING_KERNEL_PACKAGE_PLAN_CHANGED$'):
            module.installation_changes('Upgrading private-package (1.0-r0 -> 1.1-r0)', {'linux-virt':'6.18.58-r0'}, 'linux-virt')
        prefix = 'E04_NATIVE_PRODUCT_FAILURE '
        self.assertTrue(stderr.getvalue().startswith(prefix))
        row = json.loads(stderr.getvalue()[len(prefix):])
        self.assertEqual(row['function'],'installation_changes')
        self.assertEqual(row['reason'],'HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
        self.assertGreater(row['line'],0);self.assertNotIn('private-package',stderr.getvalue())


def base_request():
    return {'action': 'inspect', 'nodeId': str(uuid.uuid4()), 'requestId': str(uuid.uuid4()), 'identityHash': 'a' * 64,
            'bootId': str(uuid.uuid4()), 'prepareHash': module.ZERO, 'recipe': module.RECIPE, 'architecture': 'x86_64',
            'expiresAt': int(module.time.time() * 1000) + 59000, 'customers': [], 'expectedPlanHash': None}


def apparmor_request(value):
    return {**{key: field for key, field in value.items() if key != 'expectedPlanHash'},
            'action': 'prepare', 'recipe': 'alpine-apparmor-grub-v1', 'prepareHash': None,
            'requestId': str(uuid.uuid4()), 'bootId': str(uuid.uuid4()),
            'customers': [{'name': 'sold-customer', 'uuid': str(uuid.uuid4()), 'attempt': str(uuid.uuid4()),
                          'state': 'running', 'autostart': 'true'}]}


def apk3_package_names(args, installed, action):
    # APK 3.0.6 fix_main and upgrade_main both call foreach_matching_name.
    # Its no-wildcard branch looks up each full argv string as a package name;
    # it does not parse a dependency/version atom before selecting packages.
    names = [arg for arg in args[args.index(action) + 1:] if not arg.startswith('-')]
    if not names or any(name not in installed for name in names):
        raise ValueError('HARDENING_KERNEL_PREPARE_FAILED')
    return names


# Exact successful APK3 info stdout and its separate corrupt-cache warnings.
# Captured from the disposable Alpine fixture; contains only public package data.
APK3_CAPTURED_INFO_STDOUT = b"""alpine-base-3.24.3-r0
alpine-baselayout-3.7.2-r1
alpine-baselayout-data-3.7.2-r1
alpine-conf-3.22.0-r0
alpine-keys-2.6-r0
alpine-release-3.24.3-r0
apk-tools-3.0.8-r0
blkid-2.42.3-r1
bridge-1.5-r5
busybox-1.37.0-r31
busybox-binsh-1.37.0-r31
busybox-mdev-openrc-1.37.0-r31
busybox-openrc-1.37.0-r31
busybox-suid-1.37.0-r31
ca-certificates-bundle-20261020-r0
chrony-4.8-r7
chrony-common-4.8-r7
chrony-openrc-4.8-r7
cloud-init-26.1-r3
cloud-init-datasource-akamai-26.1-r3
cloud-init-datasource-akamai-pyc-26.1-r3
cloud-init-datasource-aliyun-26.1-r3
cloud-init-datasource-aliyun-pyc-26.1-r3
cloud-init-datasource-altcloud-26.1-r3
cloud-init-datasource-altcloud-pyc-26.1-r3
cloud-init-datasource-azure-26.1-r3
cloud-init-datasource-azure-pyc-26.1-r3
cloud-init-datasource-bigstep-26.1-r3
cloud-init-datasource-bigstep-pyc-26.1-r3
cloud-init-datasource-cloudcix-26.1-r3
cloud-init-datasource-cloudcix-pyc-26.1-r3
cloud-init-datasource-cloudsigma-26.1-r3
cloud-init-datasource-cloudsigma-pyc-26.1-r3
cloud-init-datasource-cloudstack-26.1-r3
cloud-init-datasource-cloudstack-pyc-26.1-r3
cloud-init-datasource-configdrive-26.1-r3
cloud-init-datasource-configdrive-pyc-26.1-r3
cloud-init-datasource-digitalocean-26.1-r3
cloud-init-datasource-digitalocean-pyc-26.1-r3
cloud-init-datasource-ec2-26.1-r3
cloud-init-datasource-ec2-pyc-26.1-r3
cloud-init-datasource-exoscale-26.1-r3
cloud-init-datasource-exoscale-pyc-26.1-r3
cloud-init-datasource-gce-26.1-r3
cloud-init-datasource-gce-pyc-26.1-r3
cloud-init-datasource-hetzner-26.1-r3
cloud-init-datasource-hetzner-pyc-26.1-r3
cloud-init-datasource-ibmcloud-26.1-r3
cloud-init-datasource-ibmcloud-pyc-26.1-r3
cloud-init-datasource-lxd-26.1-r3
cloud-init-datasource-lxd-pyc-26.1-r3
cloud-init-datasource-maas-26.1-r3
cloud-init-datasource-maas-pyc-26.1-r3
cloud-init-datasource-nocloud-26.1-r3
cloud-init-datasource-nocloud-pyc-26.1-r3
cloud-init-datasource-nwcs-26.1-r3
cloud-init-datasource-nwcs-pyc-26.1-r3
cloud-init-datasource-opennebula-26.1-r3
cloud-init-datasource-opennebula-pyc-26.1-r3
cloud-init-datasource-openstack-26.1-r3
cloud-init-datasource-openstack-pyc-26.1-r3
cloud-init-datasource-oracle-26.1-r3
cloud-init-datasource-oracle-pyc-26.1-r3
cloud-init-datasource-ovf-26.1-r3
cloud-init-datasource-ovf-pyc-26.1-r3
cloud-init-datasource-rbx-26.1-r3
cloud-init-datasource-rbx-pyc-26.1-r3
cloud-init-datasource-scaleway-26.1-r3
cloud-init-datasource-scaleway-pyc-26.1-r3
cloud-init-datasource-smartos-26.1-r3
cloud-init-datasource-smartos-pyc-26.1-r3
cloud-init-datasource-upcloud-26.1-r3
cloud-init-datasource-upcloud-pyc-26.1-r3
cloud-init-datasource-vmware-26.1-r3
cloud-init-datasource-vmware-pyc-26.1-r3
cloud-init-datasource-vultr-26.1-r3
cloud-init-datasource-vultr-pyc-26.1-r3
cloud-init-datasource-wsl-26.1-r3
cloud-init-datasource-wsl-pyc-26.1-r3
cloud-init-datasources-26.1-r3
cloud-init-openrc-26.1-r3
cloud-init-pyc-26.1-r3
cloud-utils-growpart-0.33-r1
cryptsetup-libs-2.8.6-r0
device-mapper-libs-2.03.35-r3
dhcpcd-10.5.2-r1
dhcpcd-openrc-10.5.2-r1
doas-6.8.2-r8
dosfstools-4.2-r2
e2fsprogs-1.47.4-r0
e2fsprogs-extra-1.47.4-r0
e2fsprogs-libs-1.47.4-r0
gdbm-1.26-r0
ifupdown-ng-0.13.0-r0
ifupdown-ng-iproute2-0.13.0-r0
iproute2-minimal-7.0.0-r0
json-c-0.18-r1
kmod-34.2-r1
kmod-libs-34.2-r1
lddtree-1.27-r0
libapk-3.0.8-r0
libblkid-2.42.3-r1
libbsd-0.12.2-r0
libbz2-1.0.8-r6
libcap2-2.78-r0
libcom_err-1.47.4-r0
libcrypto3-3.5.9-r0
libeconf-0.8.3-r0
libedit-20260508.3.1-r1
libelf-0.195-r0
libexpat-2.9.0-r0
libfdisk-2.42.3-r1
libffi-3.5.2-r1
libgcc-15.2.0-r5
libmd-1.2.0-r0
libmnl-1.0.5-r2
libmount-2.42.3-r1
libncursesw-6.6_p20260516-r0
libnvme-1.16.2-r0
libnvmemi-1.16.2-r0
libpanelw-6.6_p20260516-r0
libseccomp-2.6.1-r0
libsmartcols-2.42.3-r1
libssl3-3.5.9-r0
libstdc++-15.2.0-r5
libuuid-2.42.3-r1
limine-bios-12.9.4-r0
limine-bios-updater-12.9.4-r0
limine-efi-updater-12.9.4-r0
limine-efi-x86_64-12.9.4-r0
limine-tool-12.9.4-r0
linux-pam-1.7.1-r2
linux-virt-6.18.58-r0
mdev-conf-4.10-r0
mkinitfs-3.14.1-r0
mount-2.42.3-r1
mpdecimal-4.0.1-r0
musl-1.2.6-r3
musl-utils-1.2.6-r3
ncurses-terminfo-base-6.6_p20260516-r0
nvme-cli-2.16-r1
openrc-0.63.2-r0
openrc-user-0.63.2-r0
openssh-10.3_p1-r1
openssh-client-common-10.3_p1-r1
openssh-client-default-10.3_p1-r1
openssh-keygen-10.3_p1-r1
openssh-server-10.3_p1-r1
openssh-server-common-10.3_p1-r1
openssh-server-common-openrc-10.3_p1-r1
openssh-server-pam-10.3_p1-r1
openssh-sftp-server-10.3_p1-r1
partx-2.42.3-r1
popt-1.19-r4
py3-attrs-26.1.0-r0
py3-attrs-pyc-26.1.0-r0
py3-certifi-2026.2.25-r1
py3-certifi-pyc-2026.2.25-r1
py3-charset-normalizer-3.4.9-r0
py3-charset-normalizer-pyc-3.4.9-r0
py3-configobj-5.0.9-r2
py3-configobj-pyc-5.0.9-r2
py3-idna-3.16-r0
py3-idna-pyc-3.16-r0
py3-jinja2-3.1.6-r1
py3-jinja2-pyc-3.1.6-r1
py3-jsonpatch-1.33-r5
py3-jsonpatch-pyc-1.33-r5
py3-jsonpointer-3.1.1-r0
py3-jsonpointer-pyc-3.1.1-r0
py3-jsonschema-4.26.0-r0
py3-jsonschema-pyc-4.26.0-r0
py3-jsonschema-specifications-2025.9.1-r2
py3-jsonschema-specifications-pyc-2025.9.1-r2
py3-markupsafe-3.0.3-r1
py3-markupsafe-pyc-3.0.3-r1
py3-referencing-0.37.0-r1
py3-referencing-pyc-0.37.0-r1
py3-requests-2.33.1-r0
py3-requests-pyc-2.33.1-r0
py3-rpds-py-0.30.0-r2
py3-rpds-py-pyc-0.30.0-r2
py3-typing-extensions-4.15.0-r1
py3-typing-extensions-pyc-4.15.0-r1
py3-urllib3-2.7.0-r0
py3-urllib3-pyc-2.7.0-r0
py3-yaml-6.0.3-r2
py3-yaml-pyc-6.0.3-r2
pyc-3.14.8-r0
python3-3.14.8-r0
python3-pyc-3.14.8-r0
python3-pycache-pyc0-3.14.8-r0
readline-8.3.3-r1
scanelf-1.3.9-r1
sfdisk-2.42.3-r1
sgdisk-1.0.10-r1
shadow-4.18.0-r1
skalibs-libs-2.15.0.0-r0
sqlite-libs-3.53.4-r0
ssl_client-1.37.0-r31
tzdata-2026e-r0
utmps-libs-0.1.3.3-r0
xz-libs-5.8.4-r0
yaml-0.2.5-r2
zlib-1.3.2-r1
zstd-libs-1.5.7-r2
"""
APK3_CAPTURED_INFO_STDERR = b"""WARNING: opening from cache https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/APKINDEX.tar.gz: unexpected end of file
WARNING: opening from cache https://dl-cdn.alpinelinux.org/alpine/v3.24/community/x86_64/APKINDEX.tar.gz: unexpected end of file
"""


class KernelPlanTests(unittest.TestCase):
    def test_inventory_timeout_rechecks_tool_and_retries_once_with_original_request(self):
        request = base_request()
        calls = []
        tools = [{'path': '/first/apk'}, {'path': '/second/apk'}]

        def command(args, timeout, value, *, stdout_only):
            self.assertIs(stdout_only, True)
            calls.append((args, timeout, value))
            if len(calls) == 1:
                raise ValueError('HARDENING_KERNEL_STEP_TIMEOUT')
            return b'linux-virt-6.18.58-r0\nbaselayout-3.7.0-r0\n'

        with patch.object(module, 'trusted_program', side_effect=tools) as lookup, \
                patch.object(module, 'command', side_effect=command), \
                patch.object(module, 'current_request', wraps=module.current_request) as expiry:
            self.assertEqual(module.installed_packages(request), {'linux-virt': '6.18.58-r0', 'baselayout': '3.7.0-r0'})
        self.assertEqual([(args, timeout) for args, timeout, _ in calls],
                         [(['/first/apk', 'info', '-v'], 8), (['/second/apk', 'info', '-v'], 20)])
        self.assertTrue(all(value is request for _, _, value in calls))
        self.assertEqual(lookup.call_count, 2)
        expiry.assert_called_once_with(request)

    def test_inventory_second_timeout_stops_without_third_attempt(self):
        with patch.object(module, 'trusted_program', return_value={'path': '/trusted/apk'}) as lookup, \
                patch.object(module, 'command', side_effect=ValueError('HARDENING_KERNEL_STEP_TIMEOUT')) as command:
            with self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_STEP_TIMEOUT$'):
                module.installed_packages()
        self.assertEqual(lookup.call_count, 2)
        self.assertEqual([call.kwargs['timeout'] for call in command.call_args_list], [8, 20])

    def test_inventory_non_timeout_and_cleanup_failures_never_retry(self):
        for code in ('HARDENING_KERNEL_PREPARE_FAILED', 'HARDENING_KERNEL_CHILD_PENDING',
                     'HARDENING_REQUEST_EXPIRED', 'HARDENING_KERNEL_UNTRUSTED_PATH'):
            with self.subTest(code=code), \
                    patch.object(module, 'trusted_program', return_value={'path': '/trusted/apk'}) as lookup, \
                    patch.object(module, 'command', side_effect=ValueError(code)) as command:
                with self.assertRaisesRegex(ValueError, '^' + code + '$'):
                    module.installed_packages()
            self.assertEqual(command.call_count, 1)
            self.assertEqual(lookup.call_count, 1)

    def test_inventory_expired_original_request_prevents_second_tool_and_command(self):
        request = base_request()
        request['expiresAt'] = 1
        with patch.object(module, 'trusted_program', return_value={'path': '/trusted/apk'}) as lookup, \
                patch.object(module, 'command', side_effect=ValueError('HARDENING_KERNEL_STEP_TIMEOUT')) as command:
            with self.assertRaisesRegex(ValueError, '^HARDENING_REQUEST_EXPIRED$'):
                module.installed_packages(request)
        self.assertEqual(command.call_count, 1)
        self.assertEqual(lookup.call_count, 1)
        self.assertEqual(request['expiresAt'], 1)

    def test_inventory_retry_still_requires_complete_unique_package_rows(self):
        for output in (b'', b'linux-virt-6.18.58-r0\nlinux-virt-6.18.58-r0\n',
                       b'linux-virt-6.18.58-r0\nwarning: unknown row\n', b'\xff'):
            with self.subTest(output=output), \
                    patch.object(module, 'trusted_program', return_value={'path': '/trusted/apk'}), \
                    patch.object(module, 'command', side_effect=[ValueError('HARDENING_KERNEL_STEP_TIMEOUT'), output]) as command:
                with self.assertRaises((ValueError, UnicodeDecodeError)):
                    module.installed_packages()
            self.assertEqual(command.call_count, 2)

    def test_inventory_retry_rejects_a_newly_untrusted_tool_before_another_process(self):
        with patch.object(module, 'trusted_program', side_effect=[{'path': '/first/apk'}, ValueError('HARDENING_KERNEL_UNTRUSTED_PATH')]) as lookup, \
                patch.object(module, 'command', side_effect=ValueError('HARDENING_KERNEL_STEP_TIMEOUT')) as command:
            with self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_UNTRUSTED_PATH$'):
                module.installed_packages()
        self.assertEqual(command.call_count, 1)
        self.assertEqual(lookup.call_count, 2)

    def test_strict_json_rejects_duplicate_keys_at_every_depth_and_nonfinite_numbers(self):
        value = {'one': [{'two': {'hash': 'a' * 64}}]}
        self.assertEqual(module.strict_json(module.encoded(value)), value)
        for data in [b'{"version":1,"version":1}', b'{"identity":{"nodeId":"same","nodeId":"same"}}',
                     b'{"proofs":[{"mode":384,"mode":384}]}', b'{"size":NaN}', b'{"size":Infinity}',
                     b'{"size":-Infinity}']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                module.strict_json(data)

    def test_request_exact_fields_types_and_empty_customer_inventory(self):
        value = base_request()
        self.assertEqual(module.request(value), value)
        for delta in [{'customers': [{}]}, {'expectedPlanHash': 'b' * 64}, {'prepareHash': None}, {'recipe': 'alpine-apparmor-grub-v1'},
                      {'action': ['inspect']}, {'architecture': ['x86_64']}, {'expiresAt': True}, {'expiresAt': 0},
                      {'expiresAt': value['expiresAt'] + 60000}, {'packages': ['linux-virt']}, {'path': '/boot/vmlinuz-virt'}]:
            with self.subTest(delta=delta), self.assertRaises((ValueError, TypeError)):
                module.request({**value, **delta})
        for action in ['prepare', 'status', 'reboot', 'verify', 'rollback']:
            self.assertEqual(module.request({**value, 'action': action, 'expectedPlanHash': 'b' * 64})['action'], action)

    def test_kernel_release_revision_and_same_series(self):
        self.assertEqual(module.version_release('6.12.118-r0', 'linux-virt'), '6.12.118-0-virt')
        self.assertEqual(module.release_version('6.12.118-12-lts', 'linux-lts'), '6.12.118-r12')
        for before, after, allowed in [('6.12.9-r0', '6.12.10-r0', True), ('6.12.118-r9', '6.12.118-r10', True),
                                      ('6.12.118-r0', '6.13.1-r0', False), ('6.12.118-r0', '6.12.118-r0', False),
                                      ('6.12.118-r0', '6.12.100-r9', False), ('6.12.118-r0', '6.12.118-r00', False)]:
            self.assertEqual(module.same_series(before, after), allowed)
        with self.assertRaises(ValueError):
            module.release_version('6.12.118-0-virt', 'linux-lts')

    def test_only_original_kernel_upgrade_and_exact_reinstall(self):
        before = {'linux-virt': '6.12.100-r0', 'incus': '6.20-r0'}
        good = '(1/1) Upgrading linux-virt (6.12.100-r0 -> 6.12.118-r0)\nOK: 210 MiB in 30 packages\n'
        self.assertEqual(module.installation_changes(good, before, 'linux-virt'), '6.12.118-r0')
        for output in [good + 'Installing new-package (1.0-r0)\n', good.replace('6.12.118', '6.13.1'),
                       good + 'Upgrading incus (6.20-r0 -> 6.21-r0)\n', good * 2,
                       'Reinstalling linux-virt (6.12.100-r0)\n', 'Removing linux-virt (6.12.100-r0)\n']:
            with self.assertRaises(ValueError):
                module.installation_changes(output, before, 'linux-virt')
        installed = {**before, 'linux-virt': '6.12.118-r0'}
        self.assertEqual(module.installation_changes('Reinstalling linux-virt (6.12.118-r0)', installed, 'linux-virt', '6.12.118-r0', True), '6.12.118-r0')
        for output in ['Reinstalling incus (6.20-r0)', 'Reinstalling linux-virt (6.12.100-r0)',
                       'Reinstalling linux-virt (6.12.118-r0)\nReinstalling incus (6.20-r0)']:
            with self.assertRaises(ValueError):
                module.installation_changes(output, installed, 'linux-virt', '6.12.118-r0', True)

    def test_apk3_upgrade_and_reinstall_use_bare_name_but_exact_original_cached_version(self):
        for flavor in ('linux-virt', 'linux-lts'):
            before, expected = '6.12.100-r0', '6.12.118-r0'
            installed = {flavor: expected, 'incus': '6.20-r0'}
            transaction = {'plan': {'flavor': flavor, 'candidateVersion': expected}}
            calls = []
            def command(args, **unused):
                calls.append(args)
                self.assertIn('--no-network', args)
                self.assertIn('--simulate', args)
                self.assertEqual(args.count('--no-scripts'), 1)
                self.assertEqual(args.count('--no-commit-hooks'), 1)
                action = 'fix' if 'fix' in args else 'upgrade'
                self.assertEqual(apk3_package_names(args, installed, action), [flavor])
                if 'fix' in args:
                    return ('Reinstalling ' + flavor + ' (' + installed[flavor] + ')\n').encode()
                return ('Upgrading ' + flavor + ' (' + before + ' -> ' + expected + ')\n').encode()
            with patch.object(module, 'package_base', return_value=['/sbin/apk']), \
                    patch.object(module, 'command', side_effect=command):
                # The real APK name lookup rejects the former argument even
                # though that exact version is installed and in the old cache.
                for action in ('fix', 'upgrade'):
                    with self.assertRaisesRegex(ValueError, 'PREPARE_FAILED'):
                        apk3_package_names(['apk', action, flavor + '=' + expected], installed, action)
                module.simulate_original(transaction, Path('fixture-cache'), base_request(), installed, reinstall=True)
                module.simulate_original(transaction, Path('fixture-cache'), base_request(), {**installed, flavor: before})
            self.assertEqual(calls[0][-1], flavor)
            self.assertEqual(calls[1][-1], flavor)
            for reinstall in (False, True):
                prefix = 'Reinstalling ' + flavor + ' (' if reinstall else 'Upgrading ' + flavor + ' (' + before + ' -> '
                current = installed if reinstall else {**installed, flavor: before}
                for output in [(prefix + '6.12.119-r0)\n').encode(), (prefix + '6.13.1-r0)\n').encode(),
                               (prefix + expected + ')\nReinstalling incus (6.20-r0)\n').encode(),
                               (prefix + expected + ')\nInstalling hidden (1-r0)\n').encode()]:
                    with self.subTest(flavor=flavor, reinstall=reinstall, output=output), \
                            patch.object(module, 'package_base', return_value=['/sbin/apk']), \
                            patch.object(module, 'command', return_value=output), self.assertRaises(ValueError):
                        module.simulate_original(transaction, Path('fixture-cache'), base_request(), current, reinstall=reinstall)

    def test_grub_and_extlinux_keep_root_console_security_arguments(self):
        args = ['root=UUID=original', 'console=ttyS0', 'apparmor=1', 'security=apparmor', 'lsm=landlock,apparmor,bpf']
        grub = ('menuentry stable {\n linux /boot/vmlinuz-virt ' + ' '.join(args) + '\n initrd /boot/initramfs-virt\n}\n').encode()
        extlinux = ('LABEL stable\n KERNEL /boot/vmlinuz-virt\n INITRD /boot/initramfs-virt\n APPEND ' + ' '.join(args) + '\n').encode()
        self.assertEqual(module.linux_arguments(grub, 'grub', 'linux-virt'), args)
        self.assertEqual(module.linux_arguments(extlinux, 'extlinux', 'linux-virt'), args)
        for data, loader in [(grub + grub, 'grub'), (grub.replace(b'vmlinuz-virt', b'vmlinuz-lts'), 'grub'),
                             (grub.replace(b'root=UUID=original', b'root=UUID=original root=UUID=second'), 'grub'),
                             (extlinux + b'LABEL second\n', 'extlinux'), (extlinux.replace(b'initramfs-virt', b'initramfs-other'), 'extlinux')]:
            with self.assertRaises(ValueError):
                module.linux_arguments(data, loader, 'linux-virt')

    def test_partial_package_commit_only_before_or_expected(self):
        transaction = {'installed': {'linux-virt': '6.12.100-r0', 'incus': '6.20-r0'},
                       'expectedInstalled': {'linux-virt': '6.12.118-r0', 'incus': '6.20-r0'}}
        module.validate_partial_inventory(transaction, transaction['installed'])
        module.validate_partial_inventory(transaction, transaction['expectedInstalled'])
        for value in [{'linux-virt': '6.12.110-r0', 'incus': '6.20-r0'}, {'linux-virt': '6.12.118-r0'},
                      {**transaction['expectedInstalled'], 'incus': '6.21-r0'}, {**transaction['expectedInstalled'], 'unknown': '1.0-r0'}]:
            with self.assertRaises(ValueError):
                module.validate_partial_inventory(transaction, value)

    def test_current_signed_policy_distinguishes_world_constraint_from_up_to_date(self):
        policy = 'linux-virt policy:\n  6.12.100-r0:\n    /lib/apk/db/installed\n  6.12.118-r0:\n    https://dl-cdn.alpinelinux.org/alpine/v3.22/main\n'
        self.assertEqual(module.signed_policy_candidate(policy, 'linux-virt', '3.22', 'x86_64', '6.12.100-r0'), '6.12.118-r0')
        for data in [policy.replace('6.12.118', '6.13.1'), policy.replace('dl-cdn.alpinelinux.org', 'untrusted.example'),
                     policy.replace('v3.22', 'edge'), policy + 'Installing hidden (1.0-r0)\n']:
            with self.assertRaises(ValueError):
                module.signed_policy_candidate(data, 'linux-virt', '3.22', 'x86_64', '6.12.100-r0')

    def signed_kernel_cache_fixture(self, flavor, *, selected=None, cached=False, unreadable=False, unsupported=False):
        before, expected = '6.12.100-r0', '6.12.118-r0'
        value = base_request()
        with tempfile.TemporaryDirectory(prefix='kernel-exact-download-') as name:
            root = Path(name).resolve()
            directory = root / 'transaction'
            (directory / 'cache').mkdir(parents=True)
            shared = root / ('kernel-planning-cache-3.22-' + flavor + '-x86_64')
            shared.mkdir(mode=0o700)
            archive = shared / (flavor + '-' + expected + '.apk')
            if cached or unreadable:
                archive.write_bytes(b'original signed-package fixture; no native signature claim')
            original_archive = archive.read_bytes() if archive.is_file() else None
            calls = []
            policy = (flavor + ' policy:\n  ' + before + ':\n    /lib/apk/db/installed\n  ' + expected +
                      ':\n    https://dl-cdn.alpinelinux.org/alpine/v3.22/main\n').encode()
            def command(args, **unused):
                calls.append(args)
                # APK3 exposes script/commit-hook flags only to applets whose
                # optgroup_commit is set. Exercise the real package_base below
                # so global flags cannot make metadata/download calls fail.
                if args[-1] == 'update' or 'policy' in args or 'fetch' in args:
                    self.assertNotIn('--no-scripts', args)
                    self.assertNotIn('--no-commit-hooks', args)
                elif 'upgrade' in args or 'fix' in args:
                    self.assertEqual(args.count('--no-scripts'), 1)
                    self.assertEqual(args.count('--no-commit-hooks'), 1)
                if args[-1] == 'update':
                    (shared / 'APKINDEX.abc.tar.gz').write_bytes(b'index fixture')
                    return b''
                if 'policy' in args:
                    return policy
                if '--simulate' in args:
                    return ('Upgrading ' + flavor + ' (' + before + ' -> ' + expected + ')\n').encode()
                if 'fetch' in args:
                    # Model the independently observed APK 3 MATCH_EXACT name
                    # lookup. A recursive fetch would escape the single-kernel
                    # cache policy; this fixture grants neither alternative.
                    if args[-1] != flavor or '--recursive' in args:
                        raise ValueError('HARDENING_KERNEL_PREPARE_FAILED')
                    chosen = selected or expected
                    (shared / (flavor + '-' + chosen + '.apk')).write_bytes(b'candidate fixture')
                    return b''
                if '--no-network' in args and 'verify' in args:
                    self.assertEqual(args[-1], str(archive))
                    return b''
                self.fail('no package installation or other command belongs to signed planning')
            def proof(path, **unused):
                path = Path(path)
                self.assertTrue(path.is_relative_to(root))
                body = path.read_bytes()
                return {'sha256': module.digest(body), 'size': len(body), 'mode': 0o600, 'uid': 0, 'gid': 0}
            def copy(source, destination, wanted):
                self.assertEqual(proof(source), wanted)
                self.assertTrue(Path(destination).is_relative_to(directory / 'cache'))
                Path(destination).write_bytes(Path(source).read_bytes())
            real_lstat = Path.lstat
            def lstat(path, *args, **kwargs):
                if unreadable and path == archive:
                    raise PermissionError('fixture cache IO denied')
                return real_lstat(path, *args, **kwargs)
            payload = lambda *_: {'fixture': True}
            if unsupported:
                def payload(*unused):
                    raise ValueError('HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED')
            with ExitStack() as stack:
                for key, replacement in [('ROOT', root), ('protected', lambda path, **unused: Path(path)),
                    ('private_cache_permissions', lambda *_: None), ('trusted_program', lambda *_: {'path': '/sbin/apk'}),
                    ('command', command), ('file_proof', proof), ('copy_checked', copy), ('kernel_payload', payload)]:
                    stack.enter_context(patch.object(module, key, replacement))
                stack.enter_context(patch.object(Path, 'lstat', lstat))
                expected_error = ValueError if unreadable or selected and selected != expected or unsupported else None
                if expected_error:
                    with self.assertRaises(expected_error) as rejected:
                        module.signed_planning_cache(value, directory, '3.22', flavor, {flavor: before},
                            module.package_base(directory))
                    self.assertEqual(str(rejected.exception), 'HARDENING_KERNEL_OTHER_JOURNAL_UNKNOWN' if unreadable else
                        'HARDENING_KERNEL_PACKAGE_FORMAT_UNSUPPORTED' if unsupported else 'HARDENING_KERNEL_PACKAGE_PLAN_CHANGED')
                else:
                    self.assertEqual(module.signed_planning_cache(value, directory, '3.22', flavor, {flavor: before},
                        module.package_base(directory)), expected)
                    self.assertEqual({path.name for path in (directory / 'cache').iterdir()},
                        {'APKINDEX.abc.tar.gz', flavor + '-' + expected + '.apk'})
            fetches = [args for args in calls if 'fetch' in args]
            self.assertEqual(len(fetches), 0 if cached or unreadable else 1)
            if original_archive is not None:
                self.assertEqual(archive.read_bytes(), original_archive, 'valid or unreadable original cache remains evidence')

    def test_apk3_download_only_fixed_kernel_name_then_exact_signed_candidate(self):
        for flavor in ('linux-virt', 'linux-lts'):
            for selected in (None, '6.12.119-r0', '6.13.1-r0'):
                with self.subTest(flavor=flavor, selected=selected):
                    self.signed_kernel_cache_fixture(flavor, selected=selected)

    def test_original_signed_kernel_cache_is_reused_and_unsupported_format_not_redownloaded(self):
        for unsupported in (False, True):
            with self.subTest(unsupported=unsupported):
                self.signed_kernel_cache_fixture('linux-virt', cached=True, unsupported=unsupported)

    def test_unreadable_original_kernel_cache_never_becomes_download_authority(self):
        self.signed_kernel_cache_fixture('linux-virt', unreadable=True)

    def test_openrc_service_uses_the_installed_daemon_or_legacy_name(self):
        for names, aliases, expected in [
                ({'incusd'}, {}, 'incusd'), ({'incus'}, {}, 'incus'),
                ({'incusd'}, {'incus': 'incusd'}, 'incusd'),
                ({'incus'}, {'incusd': '/etc/init.d/incus'}, 'incus'),
                (set(), {}, None), ({'incus', 'incusd'}, {}, None),
                (set(), {'incus': 'incusd'}, None),
                ({'incus'}, {'incusd': '/other/incus'}, None)]:
            with self.subTest(names=names, aliases=aliases):
                def status(path):
                    if path.name in aliases:
                        return types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777)
                    if path.name in names:
                        return types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
                    raise FileNotFoundError()
                def protected(path, directory=False):
                    if directory:
                        self.assertEqual(path, Path('/etc/init.d'))
                        return
                    info = status(path)
                    self.assertTrue(stat.S_ISREG(info.st_mode))
                    return info
                with patch.object(Path, 'lstat', status), patch.object(module, 'protected', protected), \
                        patch.object(os, 'readlink', side_effect=lambda path: aliases[path.name]):
                    if expected is None:
                        with self.assertRaisesRegex(ValueError, 'INCUS_IDENTITY_UNKNOWN'):
                            module.incus_openrc_service()
                    else:
                        self.assertEqual(module.incus_openrc_service(), expected)

    def test_local_peer_requires_the_live_installed_executable_identity(self):
        actual = types.SimpleNamespace(st_dev=2, st_ino=19)
        different = types.SimpleNamespace(st_dev=2, st_ino=23)
        for pid, installed, peer, valid in [(48, actual, actual, True), (1, actual, actual, False),
                (48, actual, different, False), (48, different, actual, False), (48, actual, None, False)]:
            with self.subTest(pid=pid, installed=installed, peer=peer):
                with patch.object(Path, 'lstat', return_value=installed), \
                        patch.object(os, 'stat', return_value=peer, side_effect=FileNotFoundError() if peer is None else None) as lookup:
                    if valid:
                        module.verify_incus_peer(pid, actual)
                        lookup.assert_called_once_with('/proc/48/exe')
                    else:
                        with self.assertRaisesRegex(ValueError, 'INCUS_IDENTITY_UNKNOWN'):
                            module.verify_incus_peer(pid, actual)

    def test_runtime_check_uses_selected_openrc_service_and_refuses_its_failure(self):
        state = {'transaction': {'baseline': {'tools': {'rc-service': {'path': '/sbin/rc-service'}}}}}
        value = base_request()
        binary = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755)
        for name in ('incusd', 'incus'):
            with self.subTest(name=name), patch.object(module, 'incus_openrc_service', return_value=name), \
                    patch.object(module, 'protected', return_value=binary) as trusted, \
                    patch.object(module, 'empty_remote') as check_empty, \
                    patch.object(module, 'command', side_effect=ValueError('service failed')) as run:
                with self.assertRaisesRegex(ValueError, 'service failed'):
                    module.runtime_services(state, value)
                trusted.assert_called_once_with(Path('/usr/sbin/incusd'))
                check_empty.assert_called_once_with(value, binary)
                run.assert_called_once_with(['/sbin/rc-service', name, 'status'], timeout=8, value=value)

    def test_all_project_instances_and_operations_are_required(self):
        for inventory, operations, allowed in [([], {}, True), ([{'name': 'stopped', 'status': 'Stopped'}], {}, False),
                                               ([], {'pending': [{'status': 'Pending', 'project': 'other'}]}, False),
                                               ([], {'success': [{'status': 'Success'}]}, True), ([], {'pending': 'unknown'}, False),
                                               ([], {'pending': [{'status': ['Success']}]}, False),
                                               ([], {'pending': [{'status': {'phase': 'Success'}}]}, False)]:
            calls = []
            def local(path, *_):
                calls.append(path)
                return inventory if '/instances?' in path else operations
            with patch.object(module, 'local_incus', side_effect=local):
                if allowed:
                    module.empty_remote()
                else:
                    with self.assertRaises(ValueError):
                        module.empty_remote()
            self.assertEqual(calls[0], '/1.0/instances?recursion=1&all-projects=true')
            if len(calls) > 1:
                self.assertEqual(calls[1], '/1.0/operations?recursion=1&all-projects=true')

    def test_payload_is_streamed_and_rejects_unreviewed_paths(self):
        def tar(entries):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as archive:
                for name, data in entries:
                    info = tarfile.TarInfo(name)
                    info.mode = 0o755 if data is None else 0o644
                    info.uid = info.gid = 0
                    if data is None:
                        info.type = tarfile.DIRTYPE
                        archive.addfile(info)
                    else:
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
            return gzip.compress(stream.getvalue())
        # These are synthetic parsing fixtures, not valid signed packages.
        control = b'pkgname = linux-virt\npkgver = 6.12.118-r0\narch = x86_64\n'
        cases = [(control, [], True), (control, [('../outside', b'x')], False), (control, [('etc/passwd', b'x')], False),
                 (control, [('boot', None), ('lib', None), ('lib/modules', None), ('lib/modules/6.12.118-0-virt', None),
                            ('lib/modules/6.12.118-0-virt/kernel', None)], True),
                 (control, [('etc/unreviewed-kernel-path', None)], False),
                 (control, [('lib/modules/6.12.119-0-virt/kernel', None)], False),
                 (control, [('boot/vmlinuz-virt', b'duplicate kernel')], False),
                 (control, [('lib/modules/6.12.118-0-virt/kernel/test.ko', b'duplicate module')], False)]
        cases += [(control + duplicate, [], False) for duplicate in [b'pkgname = other-kernel\n', b'pkgver = 6.12.119-r0\n',
                                                                    b'arch = aarch64\n', b' pkgname=other-kernel\n']]
        for control_data, extra, accepted in cases:
            data = tar([('.SIGN.RSA.test.pub', b'fixture-only')]) + tar([('.PKGINFO', control_data)]) + tar([
                ('boot/vmlinuz-virt', b'candidate'), ('lib/modules/6.12.118-0-virt/kernel/test.ko', b'module'), *extra])
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'linux-virt-6.12.118-r0.apk'
                path.write_bytes(data)
                def proof(file, **_):
                    body = Path(file).read_bytes()
                    return {'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body), 'mode': 0o600, 'uid': 0, 'gid': 0}
                with patch.object(module, 'file_proof', side_effect=proof), patch.object(module.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), \
                        patch.object(module.os, 'uname', return_value=types.SimpleNamespace(machine='x86_64'), create=True):
                    if accepted:
                        payload = module.kernel_payload(path, 'linux-virt', '6.12.118-r0')
                        self.assertEqual(payload['/boot/vmlinuz-virt']['sha256'], module.digest(b'candidate'))
                    else:
                        with self.assertRaises(ValueError):
                            module.kernel_payload(path, 'linux-virt', '6.12.118-r0')


class KernelAliasPlanTests(unittest.TestCase):
    def test_alias_proof_has_exact_fields_and_explicit_flavor(self):
        for flavor in ['linux-virt', 'linux-lts']:
            target = '/boot/vmlinuz-' + flavor[6:]
            expected = {'symlink': True, 'target': target, 'sha256': hashlib.sha256(target.encode()).hexdigest(),
                        'size': len(target.encode()), 'mode': 0o777, 'uid': 0, 'gid': 0, 'nlink': 1}
            self.assertEqual(module.module_alias_metadata(flavor), expected)
            module.valid_module_alias(expected, flavor)
            self.assertEqual(len(expected), 8)
        for unknown in [None, '', 'virt', 'linux-other', [], True]:
            with self.assertRaises(ValueError):
                module.module_alias_metadata(unknown)

    def test_alias_proof_rejects_foreign_flavor_owner_type_and_extra_fields(self):
        proof = module.module_alias_metadata('linux-virt')
        for change in [{'symlink': 1}, {'mode': 0o755}, {'uid': 1}, {'gid': 1}, {'nlink': 2}, {'nlink': True},
                       {'size': True}, {'sha256': 'a' * 64}, {'target': '/boot/../boot/vmlinuz-virt'},
                       {'unknown': 'field'}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                module.valid_module_alias({**proof, **change}, 'linux-virt')
        with self.assertRaises(ValueError):
            module.valid_module_alias(module.module_alias_metadata('linux-lts'), 'linux-virt')
        with self.assertRaises(ValueError):
            module.valid_proof(proof)
        with self.assertRaises(ValueError):
            module.valid_proof({'sha256': 'a' * 64, 'size': 18, 'uid': 0, 'gid': 0, 'mode': 0o777})

    def test_installed_payload_only_uses_alias_reader_at_exact_signed_release_path(self):
        proof = module.module_alias_metadata('linux-virt')
        release = '6.12.118-0-virt'
        path = '/lib/modules/' + release + '/vmlinuz'
        with patch.object(module, 'module_alias_proof', return_value=proof) as alias, \
                patch.object(module, 'file_proof', side_effect=AssertionError('alias must remain opaque')):
            self.assertEqual(module.installed_payload_proof(path, proof, 'linux-virt', release), proof)
            alias.assert_called_once_with(Path(path), 'linux-virt')
            for wrong in ['/boot/vmlinuz-virt', '/lib/modules/' + release + '/kernel/vmlinuz',
                          '/lib/modules/6.12.119-0-virt/vmlinuz']:
                with self.subTest(path=wrong), self.assertRaises(ValueError):
                    module.installed_payload_proof(wrong, proof, 'linux-virt', release)
            with self.assertRaises(ValueError):
                module.installed_payload_proof(path, proof, 'linux-lts', release)

    def alias_apk(self, flavor='linux-virt', architecture='x86_64', name=None, target=None, kind=tarfile.SYMTYPE,
                  mode=0o777, uid=0, gid=0, size=0, duplicate=False):
        release = '6.12.118-0-' + flavor[6:]
        name = 'lib/modules/' + release + '/vmlinuz' if name is None else name
        target = '/boot/vmlinuz-' + flavor[6:] if target is None else target
        def tar(entries):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w') as archive:
                for entry, body in entries:
                    archive.addfile(entry, None if body is None else io.BytesIO(body))
            return gzip.compress(output.getvalue())
        def regular(name, body):
            entry = tarfile.TarInfo(name);entry.uid = entry.gid = 0;entry.mode = 0o644;entry.size = len(body)
            return entry, body
        signature = tar([regular('.SIGN.RSA.test.pub', b'synthetic parsing input, not an authenticated package')])
        control = tar([regular('.PKGINFO', ('pkgname = ' + flavor + '\npkgver = 6.12.118-r0\narch = ' + architecture + '\n').encode())])
        entry = tarfile.TarInfo(name);entry.type = kind;entry.linkname = target
        entry.mode, entry.uid, entry.gid, entry.size = mode, uid, gid, size
        entries = [regular('boot/vmlinuz-' + flavor[6:], b'candidate'),
                   regular('lib/modules/' + release + '/kernel/test.ko', b'module'), (entry, None)]
        if duplicate:
            entries.append((copy.copy(entry), None))
        return signature + control + tar(entries)

    def parse_alias_apk(self, data, flavor='linux-virt', architecture='x86_64'):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fixture.apk';path.write_bytes(data)
            def proof(file, **_):
                body = Path(file).read_bytes()
                return {'sha256': hashlib.sha256(body).hexdigest(), 'size': len(body), 'mode': 0o600, 'uid': 0, 'gid': 0}
            with patch.object(module, 'file_proof', side_effect=proof), \
                    patch.object(module.os, 'O_NOFOLLOW', getattr(os, 'O_NOFOLLOW', 0), create=True), \
                    patch.object(module.os, 'uname', return_value=types.SimpleNamespace(machine=architecture), create=True):
                return module.kernel_payload(path, flavor, '6.12.118-r0')

    def test_synthetic_payload_alias_supports_both_flavors_and_architectures(self):
        for flavor in ['linux-virt', 'linux-lts']:
            for architecture in ['x86_64', 'aarch64']:
                with self.subTest(flavor=flavor, architecture=architecture):
                    payload = self.parse_alias_apk(self.alias_apk(flavor, architecture), flavor, architecture)
                    path = '/lib/modules/6.12.118-0-' + flavor[6:] + '/vmlinuz'
                    self.assertEqual(payload[path], module.module_alias_metadata(flavor))
                    self.assertEqual(payload['/boot/vmlinuz-' + flavor[6:]]['sha256'], module.digest(b'candidate'))

    def test_synthetic_payload_refuses_noncanonical_aliases_and_hardlinks(self):
        cases = [{'name': 'lib/modules/6.12.118-0-virt/kernel/vmlinuz'},
                 {'name': 'lib/modules/6.12.119-0-virt/vmlinuz'}, {'name': 'lib/modules/6.12.118-0-virt/other'},
                 {'name': '../vmlinuz'}, {'name': 'lib/modules/6.12.118-0-virt/vmlinuz/'},
                 {'target': '/boot/vmlinuz-lts'}, {'target': '../../boot/vmlinuz-virt'},
                 {'target': '/boot/../boot/vmlinuz-virt'}, {'target': '/boot//vmlinuz-virt'},
                 {'kind': tarfile.LNKTYPE}, {'mode': 0o755}, {'mode': 0o4777}, {'uid': 1}, {'gid': 1},
                 {'duplicate': True}]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.parse_alias_apk(self.alias_apk(**case))


class KernelMetadataPlanTests(unittest.TestCase):
    def metadata_apk(self, flavor='linux-virt', architecture='x86_64', changes=None, extra=()):
        release = '6.12.118-0-' + flavor[6:]
        def entry(name, body, **options):
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0; info.mode = 0o644; info.size = len(body)
            for key, value in options.items():
                setattr(info, key, value)
            return info, body
        def tar(entries):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w') as archive:
                for info, body in entries:
                    archive.addfile(info, io.BytesIO(body) if info.isfile() else None)
            return gzip.compress(stream.getvalue())
        metadata = [('boot/config-' + release, b'CONFIG_TEST=y\n'), ('boot/System.map-' + release, b'fixture-map\n'),
                    ('usr/share/kernel/' + flavor[6:] + '/kernel.release', (release + '\n').encode())]
        entries = [entry('boot/vmlinuz-' + flavor[6:], b'candidate'),
                   entry('lib/modules/' + release + '/kernel/test.ko', b'module')]
        for name, body in metadata:
            changes_at_path = (changes or {}).get(name, {})
            entries.append(entry(changes_at_path.get('name', name), changes_at_path.get('body', body),
                                 **{key: value for key, value in changes_at_path.items() if key not in {'name', 'body'}}))
        entries.extend(entry(name, body, **options) for name, body, options in extra)
        # This fixture tests tar parsing only. It carries no real signature.
        return tar([entry('.SIGN.RSA.test.pub', b'synthetic parsing fixture')]) + \
            tar([entry('.PKGINFO', ('pkgname = ' + flavor + '\npkgver = 6.12.118-r0\narch = ' + architecture + '\n').encode())]) + tar(entries)

    def parse(self, data, flavor='linux-virt', architecture='x86_64'):
        return KernelAliasPlanTests.parse_alias_apk(self, data, flavor, architecture)

    def test_metadata_paths_are_exact_same_flavor_and_release(self):
        for flavor in ('linux-virt', 'linux-lts'):
            release = '6.12.118-0-' + flavor[6:]
            self.assertEqual(module.kernel_metadata_paths(flavor, release),
                             {'config': '/boot/config-' + release, 'map': '/boot/System.map-' + release,
                              'release': '/usr/share/kernel/' + flavor[6:] + '/kernel.release'})
            for wrong in ('../6.12.118-0-' + flavor[6:], '6.12.118-r0', '6.12.118-0-other', None):
                with self.subTest(flavor=flavor, release=wrong), self.assertRaises((ValueError, TypeError)):
                    module.kernel_metadata_paths(flavor, wrong)
        for flavor in ('linux-other', 'virt', None, [], True):
            with self.subTest(flavor=flavor), self.assertRaises(ValueError):
                module.kernel_metadata_paths(flavor, '6.12.118-0-virt')

    def test_synthetic_metadata_supports_both_flavors_and_architectures(self):
        for flavor in ('linux-virt', 'linux-lts'):
            for architecture in ('x86_64', 'aarch64'):
                with self.subTest(flavor=flavor, architecture=architecture):
                    payload = self.parse(self.metadata_apk(flavor, architecture), flavor, architecture)
                    release = '6.12.118-0-' + flavor[6:]
                    paths = module.kernel_metadata_paths(flavor, release)
                    self.assertEqual(set(payload), {'/boot/vmlinuz-' + flavor[6:],
                        '/lib/modules/' + release + '/kernel/test.ko', *paths.values()})
                    release_body = (release + '\n').encode()
                    self.assertEqual(payload[paths['release']], {'sha256': module.digest(release_body),
                        'size': len(release_body), 'mode': 0o644, 'uid': 0, 'gid': 0})

    def test_metadata_release_requires_exact_version_and_one_lf(self):
        path = 'usr/share/kernel/virt/kernel.release'
        for body in (b'6.12.118-0-virt', b'6.12.118-0-virt\r\n', b'6.12.118-0-virt\n\n',
                     b'6.12.119-0-virt\n', b'6.12.118-0-lts\n', b''):
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.parse(self.metadata_apk(changes={path: {'body': body}}))

    def test_metadata_archive_cannot_expand_paths_or_admit_foreign_owners_and_links(self):
        paths = module.kernel_metadata_paths('linux-virt', '6.12.118-0-virt')
        for path in paths.values():
            for options in ({'uid': 1}, {'gid': 1}, {'mode': 0o666}, {'mode': 0o4755},
                            {'type': tarfile.SYMTYPE, 'linkname': '/etc/passwd'},
                            {'type': tarfile.LNKTYPE, 'linkname': '/boot/vmlinuz-virt'}):
                with self.subTest(path=path, options=options), self.assertRaises(ValueError):
                    self.parse(self.metadata_apk(changes={path.lstrip('/'): options}))
        for wrong in ('boot/config-6.12.119-0-virt', 'boot/System.map-6.12.118-0-lts',
                      'usr/share/kernel/lts/kernel.release', 'usr/share/kernel/virt/unreviewed',
                      '../usr/share/kernel/virt/kernel.release'):
            with self.subTest(path=wrong), self.assertRaises(ValueError):
                self.parse(self.metadata_apk(changes={'usr/share/kernel/virt/kernel.release': {'name': wrong}}))
        for name, options in (('usr/local', {'type': tarfile.DIRTYPE}), ('usr/share/kernel/lts', {'type': tarfile.DIRTYPE}),
                              ('usr/share/kernel/virt/kernel.release', {})):
            with self.subTest(extra=name), self.assertRaises(ValueError):
                self.parse(self.metadata_apk(extra=[(name, b'', options)]))

    def test_metadata_journal_proofs_reject_false_types_and_noncanonical_release_digest(self):
        plan = {'flavor': 'linux-virt', 'candidateRelease': '6.12.118-0-virt'}
        path = '/usr/share/kernel/virt/kernel.release'
        body = b'6.12.118-0-virt\n'
        proof = {'sha256': module.digest(body), 'size': len(body), 'mode': 0o644, 'uid': 0, 'gid': 0}
        module.validate_metadata_payload(path, proof, plan)
        for changes in ({'gid': 1}, {'uid': True}, {'size': True}, {'mode': 0o666}, {'mode': 0o4755},
                        {'sha256': 'a' * 64}, {'size': len(body) - 1}, {'unknown': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                module.validate_metadata_payload(path, {**proof, **changes}, plan)
        with self.assertRaises(ValueError):
            module.validate_metadata_payload('/usr/share/kernel/lts/kernel.release', proof, plan)


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'waitid') and hasattr(os, 'getuid') and os.getuid() == 0,
                     'requires isolated Linux subprocess fixtures')
class KernelCommandTests(unittest.TestCase):
    def inventory_output_program(self, directory, stdout, stderr, exit_code=0):
        program = Path(directory) / 'apk-output'
        program.write_text('\n'.join(['#!' + sys.executable, 'import sys',
            "assert sys.argv[1:] == ['info', '-v']",
            'sys.stdout.buffer.write(' + repr(stdout) + ')',
            'sys.stderr.buffer.write(' + repr(stderr) + ')',
            'sys.exit(' + repr(exit_code) + ')']) + '\n')
        program.chmod(0o700)
        return program

    def test_real_inventory_parses_captured_206_rows_without_stderr_cache_warnings(self):
        self.assertEqual(hashlib.sha256(APK3_CAPTURED_INFO_STDOUT).hexdigest(),
                         'e9f876f704888d9f2eefc76d2ee3915d33870690af3d0b79d2233124027ee83a')
        self.assertEqual(hashlib.sha256(APK3_CAPTURED_INFO_STDERR).hexdigest(),
                         '898266b4812c8101de86bea810308b9497b2e205222f2e60aeced796154356d7')
        with tempfile.TemporaryDirectory(prefix='incudal-kernel-inventory-streams-', dir='/var/lib') as directory:
            program = self.inventory_output_program(directory, APK3_CAPTURED_INFO_STDOUT, APK3_CAPTURED_INFO_STDERR)
            with patch.object(module, 'trusted_program', return_value={'path': str(program)}):
                inventory = module.installed_packages()
            self.assertEqual(len(inventory), 206)
            self.assertEqual(inventory['linux-virt'], '6.18.58-r0')
            self.assertEqual(inventory['alpine-base'], '3.24.3-r0')

    def test_real_inventory_still_rejects_invalid_stdout_with_expected_stderr(self):
        outputs = [b'', APK3_CAPTURED_INFO_STDOUT + b'linux-virt-6.18.58-r0\n',
            APK3_CAPTURED_INFO_STDOUT + APK3_CAPTURED_INFO_STDERR, b'\xff',
            b''.join(('fixture-' + str(at) + '-1.0-r0\n').encode() for at in range(3001))]
        for output in outputs:
            with self.subTest(bytes=len(output)), tempfile.TemporaryDirectory(
                    prefix='incudal-kernel-inventory-invalid-', dir='/var/lib') as directory:
                program = self.inventory_output_program(directory, output, APK3_CAPTURED_INFO_STDERR)
                with patch.object(module, 'trusted_program', return_value={'path': str(program)}), \
                        self.assertRaises((ValueError, UnicodeDecodeError)):
                    module.installed_packages()

    def test_real_inventory_cannot_accept_valid_rows_after_nonzero_exit(self):
        with tempfile.TemporaryDirectory(prefix='incudal-kernel-inventory-nonzero-', dir='/var/lib') as directory:
            program = self.inventory_output_program(directory, APK3_CAPTURED_INFO_STDOUT, APK3_CAPTURED_INFO_STDERR, 7)
            with patch.object(module, 'trusted_program', return_value={'path': str(program)}) as lookup, \
                    self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_PREPARE_FAILED$'):
                module.installed_packages()
            self.assertEqual(lookup.call_count, 1, 'nonzero exit cannot be treated as an inventory timeout')

    def test_real_stdout_only_keeps_the_combined_four_mib_output_limit(self):
        for stdout_size, stderr_size in [(0, 4 * 1024 * 1024 + 1),
                                        (2 * 1024 * 1024 + 1, 2 * 1024 * 1024 + 1)]:
            program = ('import sys;sys.stdout.buffer.write(b"x"*' + str(stdout_size) + ');'
                       'sys.stderr.buffer.write(b"y"*' + str(stderr_size) + ')')
            with self.subTest(stdout_size=stdout_size, stderr_size=stderr_size), \
                    self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_PREPARE_FAILED$'):
                module.command([sys.executable, '-c', program], timeout=8, stdout_only=True)
        self.assertEqual(module.command([sys.executable, '-c',
            'import sys;sys.stderr.buffer.write(b"y"*(4*1024*1024))'], timeout=8, stdout_only=True), b'')

    def test_real_stdout_only_still_reaps_a_detached_writer_before_reply(self):
        with tempfile.TemporaryDirectory(prefix='incudal-kernel-stdout-group-', dir='/var/lib') as directory:
            record = Path(directory) / 'original-child.json'
            try:
                with patch.object(module.subprocess, 'Popen', side_effect=self.ready_popen(record, allow_exited_parent=True)), \
                        self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_CHILD_PENDING$'):
                    module.command(self.background_command(record, False), timeout=4, stdout_only=True)
                self.assertTrue(record.exists())
                deadline = time.monotonic() + 1
                while self.child_alive(record) and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertFalse(self.child_alive(record), 'stdout-only selection cannot bypass process-group cleanup')
            finally:
                self.cleanup_child(record)

    def inventory_program(self, directory, with_child):
        record, attempts = Path(directory) / 'original-child.json', Path(directory) / 'attempts'
        child = ('import json,os,sys,time;from pathlib import Path;'
                 'raw=Path("/proc/self/stat").read_text();fields=raw[raw.rfind(") ")+2:].split();'
                 'Path(sys.argv[1]).write_text(json.dumps({"pid":os.getpid(),"start":fields[19]}));'
                 'time.sleep(30)')
        lines = ['#!' + sys.executable, 'import json,os,subprocess,sys,time', 'from pathlib import Path',
                 "assert sys.argv[1:] == ['info', '-v']", 'attempts=Path(' + repr(str(attempts)) + ')',
                 'record=Path(' + repr(str(record)) + ')', 'if not attempts.exists():', "    attempts.write_text('first')"]
        if with_child:
            lines += ['    subprocess.Popen([sys.executable,"-c",' + repr(child) + ',str(record)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)',
                      '    deadline=time.monotonic()+10', '    while not record.exists() and time.monotonic()<deadline: time.sleep(.01)',
                      '    assert record.exists()',
                      '    raw=Path("/proc/self/stat").read_text();fields=raw[raw.rfind(") ")+2:].split()',
                      '    record.with_name(record.name+".parent-ready").write_text(json.dumps({"pid":os.getpid(),"start":fields[19]}))']
        lines += ['    time.sleep(30)', 'else:', '    print("linux-virt-6.18.58-r0\\nbaselayout-3.7.0-r0")']
        program = Path(directory) / 'apk'
        program.write_text('\n'.join(lines) + '\n')
        program.chmod(0o700)
        return program, record

    def test_real_inventory_retry_reaps_first_group_before_second_lookup(self):
        with tempfile.TemporaryDirectory(prefix='incudal-kernel-inventory-', dir='/var/lib') as directory:
            program, record = self.inventory_program(directory, True)
            original_command = module.command
            budgets, lookups = [], []

            def lookup(name):
                self.assertEqual(name, 'apk')
                if lookups:
                    self.assertFalse(self.child_alive(record), 'the first writer must be stopped before accepting a retry tool')
                lookups.append(name)
                return {'path': str(program), 'proof': module.file_proof(program)}

            def command(args, timeout, value, *, stdout_only):
                self.assertIs(stdout_only, True)
                budgets.append(timeout)
                # The exact 8/20 budgets are checked above; shorten only this
                # synthetic sleeping process fixture, preserving real cleanup.
                if len(budgets) == 1:
                    with patch.object(module.subprocess, 'Popen', side_effect=self.ready_popen(record)):
                        return original_command(args, timeout=2, value=value, stdout_only=stdout_only)
                return original_command(args, timeout=4, value=value, stdout_only=stdout_only)

            try:
                with patch.object(module, 'trusted_program', side_effect=lookup), patch.object(module, 'command', side_effect=command):
                    self.assertEqual(module.installed_packages(), {'linux-virt': '6.18.58-r0', 'baselayout': '3.7.0-r0'})
                self.assertEqual(budgets, [8, 20])
                self.assertEqual(len(lookups), 2)
                self.assertTrue(record.exists())
                self.assertFalse(self.child_alive(record))
            finally:
                self.cleanup_child(record)

    def test_real_inventory_timeout_cannot_extend_original_request_expiry(self):
        with tempfile.TemporaryDirectory(prefix='incudal-kernel-expiry-', dir='/var/lib') as directory:
            program, record = self.inventory_program(directory, False)
            request = base_request()
            request['expiresAt'] = int(time.time() * 1000) + 2000
            original_expiry = request['expiresAt']
            original_popen = module.subprocess.Popen
            processes = []

            def popen(*args, **kwargs):
                process = original_popen(*args, **kwargs)
                processes.append(process)
                return process

            with patch.object(module, 'trusted_program', return_value={'path': str(program)}) as lookup, \
                    patch.object(module.subprocess, 'Popen', side_effect=popen):
                with self.assertRaisesRegex(ValueError, '^HARDENING_REQUEST_EXPIRED$'):
                    module.installed_packages(request)
            self.assertEqual(lookup.call_count, 1, 'expired authority cannot resolve a second retry executable')
            self.assertEqual(len(processes), 1)
            self.assertTrue(all(process.poll() is not None for process in processes))
            self.assertEqual(request['expiresAt'], original_expiry)

    def child_alive(self, record):
        if not record.exists():
            return False
        identity = json.loads(record.read_text())
        try:
            raw = Path('/proc/' + str(identity['pid']) + '/stat').read_text()
        except FileNotFoundError:
            return False
        fields = raw[raw.rfind(') ') + 2:].split()
        return fields[19] == identity['start'] and fields[0] not in {'Z', 'X'}

    def cleanup_child(self, record):
        if not self.child_alive(record):
            return
        identity = json.loads(record.read_text())
        arguments = Path('/proc/' + str(identity['pid']) + '/cmdline').read_bytes().split(b'\0')
        self.assertIn(str(record).encode(), arguments, 'only this exact synthetic test child may be terminated')
        os.kill(identity['pid'], signal.SIGKILL)
        deadline = time.monotonic() + 2
        while self.child_alive(record) and time.monotonic() < deadline:
            time.sleep(.02)
        self.assertFalse(self.child_alive(record))

    def ready_popen(self, record, allow_exited_parent=False):
        native = module.subprocess.Popen
        parent_record = record.with_name(record.name + '.parent-ready')
        def spawn(*args, **kwargs):
            self.assertIs(kwargs.get('start_new_session'), True)
            process = native(*args, **kwargs)
            deadline = time.monotonic() + 10
            try:
                while time.monotonic() < deadline:
                    # Keep the leader unreaped: command() owns its PID/group.
                    exited = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if exited is not None and not (allow_exited_parent and exited.si_code == os.CLD_EXITED and exited.si_status == 0):
                        self.fail('controlled fixture parent exited before writer-ready acknowledgement')
                    try:
                        child = json.loads(record.read_text())
                        parent = json.loads(parent_record.read_text())
                        child_raw = Path('/proc/' + str(child['pid']) + '/stat').read_text()
                        parent_raw = Path('/proc/' + str(process.pid) + '/stat').read_text()
                        child_fields = child_raw[child_raw.rfind(') ') + 2:].split()
                        parent_fields = parent_raw[parent_raw.rfind(') ') + 2:].split()
                        arguments = Path('/proc/' + str(child['pid']) + '/cmdline').read_bytes().split(b'\0')
                    except (FileNotFoundError, ProcessLookupError, json.JSONDecodeError):
                        time.sleep(.01)
                        continue
                    self.assertEqual(set(child), {'pid', 'start'})
                    self.assertEqual(set(parent), {'pid', 'start'})
                    self.assertIs(type(child['pid']), int)
                    self.assertEqual(parent['pid'], process.pid)
                    self.assertEqual(parent['start'], parent_fields[19])
                    self.assertEqual(child['start'], child_fields[19])
                    self.assertEqual(int(child_fields[2]), process.pid)
                    self.assertNotIn(child_fields[0], {'Z', 'X'})
                    self.assertIn(str(record).encode(), arguments)
                    return process
                self.fail('controlled writer-ready handshake exceeded its fixed 10-second setup bound')
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2)
                raise
        return spawn

    def background_command(self, record, wait):
        child = ('import json,os,sys,time;from pathlib import Path;'
                 'raw=Path("/proc/self/stat").read_text();fields=raw[raw.rfind(") ")+2:].split();'
                 'Path(sys.argv[1]).write_text(json.dumps({"pid":os.getpid(),"start":fields[19]}));'
                 'time.sleep(30)')
        parent = ('import json,os,subprocess,sys,time;from pathlib import Path;'
                  'subprocess.Popen([sys.executable,"-c",sys.argv[1],sys.argv[2]],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);'
                  'record=Path(sys.argv[2]);deadline=time.monotonic()+10\n'
                  'while not record.exists() and time.monotonic()<deadline: time.sleep(.01)\n'
                  'assert record.exists()\n'
                  'raw=Path("/proc/self/stat").read_text();fields=raw[raw.rfind(") ")+2:].split()\n'
                  'record.with_name(record.name+".parent-ready").write_text(json.dumps({"pid":os.getpid(),"start":fields[19]}))\n' +
                  ('time.sleep(30)\n' if wait else ''))
        return [sys.executable, '-c', parent, child, str(record)]

    def test_real_timeout_terminates_the_command_group_before_replay(self):
        with tempfile.TemporaryDirectory(prefix='incudal-kernel-command-', dir='/var/lib') as directory:
            record = Path(directory) / 'original-child.json'
            try:
                with patch.object(module.subprocess, 'Popen', side_effect=self.ready_popen(record)), \
                        self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_STEP_TIMEOUT$'):
                    module.command(self.background_command(record, True), timeout=2)
                self.assertTrue(record.exists(), 'the background writer started before the parent timed out')
                deadline = time.monotonic() + 1
                while self.child_alive(record) and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertFalse(self.child_alive(record), 'a timed-out generator cannot retain its writer or task lock')
            finally:
                self.cleanup_child(record)

    def test_real_successful_parent_cannot_leave_a_detached_writer_in_its_group(self):
        with tempfile.TemporaryDirectory(prefix='incudal-kernel-command-', dir='/var/lib') as directory:
            record = Path(directory) / 'original-child.json'
            try:
                with patch.object(module.subprocess, 'Popen', side_effect=self.ready_popen(record, allow_exited_parent=True)), \
                        self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_CHILD_PENDING$'):
                    module.command(self.background_command(record, False), timeout=4)
                self.assertTrue(record.exists())
                deadline = time.monotonic() + 1
                while self.child_alive(record) and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertFalse(self.child_alive(record))
            finally:
                self.cleanup_child(record)

    def test_real_output_and_failure_keep_fixed_error_boundaries(self):
        program = 'import sys;sys.stdout.buffer.write(b"original-out");sys.stderr.buffer.write(b"original-error")'
        self.assertEqual(module.command([sys.executable, '-c', program], timeout=3), b'original-outoriginal-error')
        with self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_PREPARE_FAILED$'):
            module.command([sys.executable, '-c', program + ';sys.exit(1)'], timeout=3)

    def test_real_oversized_output_is_refused_without_reading_it_into_the_reply(self):
        with self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_PREPARE_FAILED$'):
            module.command([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(b"x"*(5*1024*1024))'], timeout=3)


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'getuid') and os.getuid() == 0, 'requires isolated Linux root alias fixtures')
class KernelModuleAliasFilesystemTests(unittest.TestCase):
    def tree(self, parent, name, flavor):
        root = Path(parent) / name;root.mkdir(mode=0o755)
        kernel = root / 'kernel';kernel.mkdir(mode=0o755)
        module_file = kernel / 'test.ko';module_file.write_bytes(b'ordinary module bytes');module_file.chmod(0o644)
        os.symlink('/boot/vmlinuz-' + flavor[6:], root / 'vmlinuz')
        return root

    def test_manifest_backup_and_idempotent_copy_never_follow_kernel_alias(self):
        for flavor in ['linux-virt', 'linux-lts']:
            with self.subTest(flavor=flavor), tempfile.TemporaryDirectory(prefix='incudal-kernel-alias-', dir='/var/lib') as directory:
                root = Path(directory);root.chmod(0o700)
                source = self.tree(root, 'source', flavor)
                destination = root / 'backup'
                original_stat, original_proof = os.stat, module.file_proof
                def no_boot_stat(path, *args, **kwargs):
                    self.assertFalse(str(path).startswith('/boot/vmlinuz-'), 'alias target must never be statted')
                    return original_stat(path, *args, **kwargs)
                def ordinary_proof(path, *args, **kwargs):
                    self.assertNotEqual(Path(path).name, 'vmlinuz', 'alias must not use the regular reader')
                    self.assertFalse(str(path).startswith('/boot/vmlinuz-'))
                    return original_proof(path, *args, **kwargs)
                with patch.object(module.os, 'stat', side_effect=no_boot_stat), patch.object(module, 'file_proof', side_effect=ordinary_proof):
                    manifest = module.module_manifest(source, flavor=flavor)
                    self.assertEqual(manifest['vmlinuz'], module.module_alias_metadata(flavor))
                    module.copy_modules(source, destination, manifest, flavor=flavor)
                    self.assertEqual(module.module_manifest(destination, flavor=flavor), manifest)
                    copied_before = (destination / 'vmlinuz').lstat()
                    module.copy_modules(source, destination, manifest, flavor=flavor)
                    self.assertEqual(module.module_alias_identity((destination / 'vmlinuz').lstat()),
                                     module.module_alias_identity(copied_before))
                self.assertEqual(os.readlink(destination / 'vmlinuz'), '/boot/vmlinuz-' + flavor[6:])
                self.assertFalse((destination / '.kernel-copy-vmlinuz').exists())

    def test_link_reader_requires_context_and_rejects_foreign_or_relative_targets(self):
        for target in ['/boot/vmlinuz-lts', '/boot/vmlinuz-evil', '../../boot/vmlinuz-virt', '/boot/../boot/vmlinuz-virt']:
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix='incudal-kernel-alias-', dir='/var/lib') as directory:
                root = Path(directory);root.chmod(0o700)
                path = root / 'vmlinuz';os.symlink(target, path)
                before = path.lstat()
                with self.assertRaises(ValueError):
                    module.module_alias_proof(path, 'linux-virt')
                self.assertEqual(os.readlink(path), target)
                self.assertEqual(module.module_alias_identity(path.lstat()), module.module_alias_identity(before))
        with tempfile.TemporaryDirectory(prefix='incudal-kernel-alias-', dir='/var/lib') as directory:
            root = Path(directory);root.chmod(0o700)
            tree = self.tree(root, 'tree', 'linux-virt')
            with self.assertRaises(ValueError):
                module.module_manifest(tree)

    def test_manifest_refuses_nested_alias_and_other_symlinks(self):
        for name in ['kernel/vmlinuz', 'kernel/test-link.ko', 'other']:
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix='incudal-kernel-alias-', dir='/var/lib') as directory:
                root = Path(directory);root.chmod(0o700)
                tree = self.tree(root, 'tree', 'linux-virt')
                (tree / 'vmlinuz').unlink()
                os.symlink('/boot/vmlinuz-virt', tree / name)
                with self.assertRaises(ValueError):
                    module.module_manifest(tree, flavor='linux-virt')
                self.assertEqual(os.readlink(tree / name), '/boot/vmlinuz-virt')

    def test_link_reader_refuses_foreign_owner_and_hardlinked_symlink(self):
        for change in ['owner', 'hardlink']:
            with self.subTest(change=change), tempfile.TemporaryDirectory(prefix='incudal-kernel-alias-', dir='/var/lib') as directory:
                root = Path(directory);root.chmod(0o700)
                path = root / 'vmlinuz';os.symlink('/boot/vmlinuz-virt', path)
                if change == 'owner':
                    os.lchown(path, 65534, 65534)
                else:
                    os.link(path, root / 'hardlinked-alias', follow_symlinks=False)
                with self.assertRaises(ValueError):
                    module.module_alias_proof(path, 'linux-virt')
                self.assertEqual(os.readlink(path), '/boot/vmlinuz-virt')

    def test_link_reader_rejects_same_literal_replacement_during_readlink(self):
        with tempfile.TemporaryDirectory(prefix='incudal-kernel-alias-', dir='/var/lib') as directory:
            root = Path(directory);root.chmod(0o700)
            source = root / 'source';source.mkdir(mode=0o700)
            path = source / 'vmlinuz';os.symlink('/boot/vmlinuz-virt', path)
            original = os.readlink
            def replace_on_read(link):
                target = original(link)
                path.rename(root / 'retained-original-link');os.symlink(target, path)
                return target
            with patch.object(module.os, 'readlink', side_effect=replace_on_read), \
                    self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_SOURCE_CHANGED$'):
                module.module_alias_proof(path, 'linux-virt')
            self.assertEqual(original(path), '/boot/vmlinuz-virt')

    def test_copy_refuses_unknown_destination_and_wrong_destination_name(self):
        for kind in ['regular', 'foreign-link', 'wrong-name']:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='incudal-kernel-alias-', dir='/var/lib') as directory:
                root = Path(directory);root.chmod(0o700)
                source = self.tree(root, 'source', 'linux-virt') / 'vmlinuz'
                output = root / 'output';output.mkdir(mode=0o700)
                destination = output / ('unknown' if kind == 'wrong-name' else 'vmlinuz')
                if kind == 'regular':
                    destination.write_bytes(b'preserve unknown destination');destination.chmod(0o600)
                elif kind == 'foreign-link':
                    os.symlink('/boot/vmlinuz-evil', destination)
                with self.assertRaises(ValueError):
                    module.copy_module_alias(source, destination, module.module_alias_metadata('linux-virt'), 'linux-virt')
                if kind == 'regular':
                    self.assertEqual(destination.read_bytes(), b'preserve unknown destination')
                elif kind == 'foreign-link':
                    self.assertEqual(os.readlink(destination), '/boot/vmlinuz-evil')
                else:
                    self.assertFalse(os.path.lexists(destination))

    def test_exclusive_alias_copy_refuses_a_creation_race_and_preserves_the_other_link(self):
        with tempfile.TemporaryDirectory(prefix='incudal-kernel-alias-', dir='/var/lib') as directory:
            root = Path(directory);root.chmod(0o700)
            source = self.tree(root, 'source', 'linux-virt') / 'vmlinuz'
            output = root / 'output';output.mkdir(mode=0o700);destination = output / 'vmlinuz'
            native = os.symlink
            def race(target, path):
                native('/boot/vmlinuz-evil', path)
                return native(target, path)
            with patch.object(module.os, 'symlink', side_effect=race), \
                    self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_COPY_CHANGED$'):
                module.copy_module_alias(source, destination, module.module_alias_metadata('linux-virt'), 'linux-virt')
            self.assertEqual(os.readlink(destination), '/boot/vmlinuz-evil')

    def test_copy_detects_source_replacement_after_exclusive_creation(self):
        with tempfile.TemporaryDirectory(prefix='incudal-kernel-alias-', dir='/var/lib') as directory:
            root = Path(directory);root.chmod(0o700)
            source = self.tree(root, 'source', 'linux-virt') / 'vmlinuz'
            output = root / 'output';output.mkdir(mode=0o700);destination = output / 'vmlinuz'
            native = os.symlink
            def replace_source(target, path):
                native(target, path)
                source.rename(root / 'retained-original-link');native('/boot/vmlinuz-virt', source)
            with patch.object(module.os, 'symlink', side_effect=replace_source), \
                    self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_SOURCE_CHANGED$'):
                module.copy_module_alias(source, destination, module.module_alias_metadata('linux-virt'), 'linux-virt')
            self.assertEqual(os.readlink(source), '/boot/vmlinuz-virt')
            self.assertEqual(os.readlink(destination), '/boot/vmlinuz-virt')


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'getuid') and os.getuid() == 0, 'requires isolated Linux root filesystem fixtures')
class KernelFilesystemTests(unittest.TestCase):
    def fixture(self, include_alias=False, include_metadata=False):
        stack = ExitStack()
        directory = stack.enter_context(tempfile.TemporaryDirectory(prefix='incudal-kernel-unit-', dir='/var/lib'))
        root, fs = Path(directory), Path(directory) / 'fs'
        root.chmod(0o700)
        fs.mkdir(mode=0o700)
        original_path = Path
        def mapped(value):
            text = str(value)
            return fs / text.lstrip('/') if text.startswith(('/boot/', '/etc/', '/lib/', '/opt/', '/proc/', '/sbin/', '/usr/', '/var/lib/incus/')) else original_path(value)
        def put(path, data, mode=0o644):
            target = mapped(path)
            self.assertTrue(target.is_relative_to(fs), 'every fixture write must stay in its private fake filesystem')
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            target.write_bytes(data)
            target.chmod(mode)
            return target
        value = base_request()
        boot_id, current_boot, running = value['bootId'], [value['bootId']], ['6.12.100-0-virt']
        put('/etc/incudal-onboarding-id', (value['nodeId'] + '\n').encode())
        put('/etc/apk/world', b'linux-virt\nincus\n')
        put('/etc/apk/repositories', b'https://dl-cdn.alpinelinux.org/alpine/v3.22/main\n')
        put('/etc/alpine-release', b'3.22.2\n')
        put('/lib/apk/db/installed', b'original-db\n')
        put('/proc/cmdline', b'root=UUID=original console=ttyS0 apparmor=1\n')
        put('/proc/sys/kernel/osrelease', running[0].encode())
        before_config = b'menuentry stable {\n linux /boot/vmlinuz-virt root=UUID=original console=ttyS0 apparmor=1\n initrd /boot/initramfs-virt\n}\n'
        put('/boot/grub/grub.cfg', before_config, 0o600)
        put('/boot/vmlinuz-virt', b'old-kernel')
        put('/boot/initramfs-virt', b'old-initramfs')
        put('/lib/modules/6.12.100-0-virt/kernel/test.ko', b'old-module')
        if include_alias:
            os.symlink('/boot/vmlinuz-virt', mapped('/lib/modules/6.12.100-0-virt/vmlinuz'))
        if include_metadata:
            put('/boot/config-6.12.100-0-virt', b'old-config')
            put('/boot/System.map-6.12.100-0-virt', b'old-map')
            put('/usr/share/kernel/virt/kernel.release', b'6.12.100-0-virt\n')
        put('/etc/mkinitfs/mkinitfs.conf', b'features="base ext4"\n')
        put('/etc/default/grub', b'GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0 apparmor=1"\n')
        put('/etc/ssh/ssh_host_ed25519_key.pub', b'fixture-original-public-key\n')
        put('/var/lib/incus/server.crt', b'fixture-original-public-certificate\n')
        identity = {'/etc/incudal-onboarding-id': module.file_proof(mapped('/etc/incudal-onboarding-id')),
                    '/etc/ssh/ssh_host_ed25519_key.pub': module.file_proof(mapped('/etc/ssh/ssh_host_ed25519_key.pub'))}
        tools = {}
        for name in ['apk', 'depmod', 'mkinitfs', 'incus', 'rc-service', 'chronyc', 'reboot', 'grub-mkconfig', 'grub-script-check']:
            path = '/sbin/' + name
            tools[name] = {'path': path, 'proof': module.file_proof(put(path, ('fixture ' + name).encode(), 0o755))}
        inventory = {'linux-virt': '6.12.100-r0', 'incus': '6.20-r0'}
        context_paths = ['/etc/alpine-release', '/etc/apk/world', '/etc/apk/repositories', '/lib/apk/db/installed']
        context = lambda: {path: module.file_proof(mapped(path)) for path in context_paths}
        artifact_paths = ['/boot/grub/grub.cfg', '/boot/vmlinuz-virt', '/boot/initramfs-virt']
        def source_transaction(request, target, previous=None):
            installed = inventory['linux-virt']
            candidate = '6.12.118-r0' if installed == '6.12.100-r0' else installed if running[0] != module.version_release(installed, 'linux-virt') else \
                '6.12.' + str(int(installed.split('.')[2].split('-')[0]) + 1) + '-r0'
            candidate_release = module.version_release(candidate, 'linux-virt')
            target.mkdir(mode=0o700)
            (target / 'cache').mkdir(mode=0o700)
            (target / 'cache' / 'APKINDEX.abc.tar.gz').write_bytes(b'synthetic index; no native signature acceptance')
            (target / 'cache' / ('linux-virt-' + candidate + '.apk')).write_bytes(b'synthetic apk; no native signature acceptance')
            for entry in (target / 'cache').iterdir():
                entry.chmod(0o600)
            module.atomic(target / 'repositories', b'https://dl-cdn.alpinelinux.org/alpine/v3.22/main\n')
            plan = {'status': 'available', 'branch': '3.22', 'flavor': 'linux-virt', 'bootloader': 'grub', 'runningRelease': running[0],
                    'installedVersion': installed, 'candidateVersion': candidate, 'candidateRelease': candidate_release, 'planHash': None, 'reason': None}
            payload = {'/boot/vmlinuz-virt': {'sha256': module.digest(b'new-kernel'), 'size': 10, 'mode': 0o644, 'uid': 0, 'gid': 0},
                       '/lib/modules/' + candidate_release + '/kernel/test.ko': {'sha256': module.digest(b'new-module'), 'size': 10, 'mode': 0o644, 'uid': 0, 'gid': 0}}
            if include_alias:
                payload['/lib/modules/' + candidate_release + '/vmlinuz'] = module.module_alias_metadata('linux-virt')
            if include_metadata:
                for path, data in [(('/boot/config-' + candidate_release), b'new-config'),
                                   (('/boot/System.map-' + candidate_release), b'new-map'),
                                   ('/usr/share/kernel/virt/kernel.release', (candidate_release + '\n').encode())]:
                    payload[path] = {'sha256': module.digest(data), 'size': len(data), 'mode': 0o644, 'uid': 0, 'gid': 0}
            transaction = {'plan': plan, 'context': context(), 'installed': dict(inventory), 'expectedInstalled': {**inventory, 'linux-virt': candidate},
                           'baseline': {'bootloader': 'grub', 'config': '/boot/grub/grub.cfg',
                                        'arguments': module.linux_arguments(before_config, 'grub', 'linux-virt'),
                                        'artifacts': {path: module.file_proof(mapped(path)) for path in artifact_paths},
                                        'controls': {path: module.file_proof(mapped(path)) for path in ['/etc/mkinitfs/mkinitfs.conf', '/etc/default/grub']},
                                        'tools': tools, 'modules': module.module_manifest(mapped('/lib/modules/' + running[0]), flavor='linux-virt'),
                                        'identity': identity, 'cmdline': mapped('/proc/cmdline').read_text().strip()},
                           'cache': module.cache_manifest(target / 'cache'), 'payload': payload,
                           'reactivation': installed == candidate, 'staging': None, 'candidateArtifacts': None, 'candidateModules': None}
            if include_metadata:
                transaction['baseline']['packageMetadata'] = module.package_metadata_snapshot('linux-virt', running[0])
            plan['planHash'] = module.digest(module.encoded({key: field for key, field in transaction.items() if key not in {'staging', 'candidateArtifacts', 'candidateModules'}}))
            return plan, transaction
        commands = []
        def command(args, **_):
            commands.append(args)
            program = Path(args[0]).name
            expected, selected_names = inventory['linux-virt'], []
            if program == 'apk' and ('fix' in args or 'upgrade' in args):
                action = 'fix' if 'fix' in args else 'upgrade'
                selected_names = apk3_package_names(args, inventory, action)
                self.assertEqual(selected_names, ['linux-virt'])
                # The original private cache fixes the candidate independently
                # of the bare argv, as the real signed offline solver does.
                cache = Path(args[args.index('--cache-dir') + 1])
                candidates = [entry.name[len('linux-virt-'):-4] for entry in cache.iterdir()
                              if entry.name.startswith('linux-virt-') and entry.name.endswith('.apk')]
                self.assertEqual(len(candidates), 1)
                expected = candidates[0]
                self.assertTrue(module.VERSION.fullmatch(expected))
            if program == 'apk' and '--simulate' in args:
                return ''.join('Reinstalling ' + name + ' (' + expected + ')\n' for name in selected_names).encode() if 'fix' in args else \
                    ('Upgrading linux-virt (' + inventory['linux-virt'] + ' -> ' + expected + ')\n').encode()
            if program == 'apk' and ('upgrade' in args or 'fix' in args):
                inventory['linux-virt'] = expected
                put('/lib/apk/db/installed', b'expected-db\n')
                put('/boot/vmlinuz-virt', b'new-kernel')
                put('/lib/modules/' + module.version_release(expected, 'linux-virt') + '/kernel/test.ko', b'new-module')
                if include_alias:
                    alias = mapped('/lib/modules/' + module.version_release(expected, 'linux-virt') + '/vmlinuz')
                    try:
                        alias.lstat()
                    except FileNotFoundError:
                        os.symlink('/boot/vmlinuz-virt', alias)
                    else:
                        self.assertEqual(os.readlink(alias), '/boot/vmlinuz-virt')
                if include_metadata:
                    for old in ['/boot/config-' + running[0], '/boot/System.map-' + running[0]]:
                        path = mapped(old)
                        self.assertTrue(path.is_relative_to(fs))
                        try:
                            path.unlink()
                        except FileNotFoundError:
                            pass
                    installed_release = module.version_release(expected, 'linux-virt')
                    put('/boot/config-' + installed_release, b'new-config')
                    put('/boot/System.map-' + installed_release, b'new-map')
                    put('/usr/share/kernel/virt/kernel.release', (installed_release + '\n').encode())
                return b'OK\n'
            if program == 'mkinitfs':
                Path(args[args.index('-o') + 1]).write_bytes(b'new-initramfs')
                Path(args[args.index('-o') + 1]).chmod(0o644)
            elif program == 'grub-mkconfig':
                output = Path(args[args.index('-o') + 1])
                output.write_bytes(before_config + b'# generated candidate\n')
                output.chmod(0o600)
            return b''
        def cache_check(state, request):
            self.assertEqual(module.cache_manifest(module.run_directory(state) / 'cache'), state['transaction']['cache'])
        for name, replacement in [('ROOT', root), ('Path', mapped), ('boot', lambda: current_boot[0]), ('source_transaction', source_transaction),
                                  ('empty_remote', lambda *_: None), ('resources', lambda *_: None), ('runtime_identity', lambda: identity),
                                  ('package_context', context), ('installed_packages', lambda *_: dict(inventory)), ('trusted_program', lambda name: tools[name]),
                                  ('command', command), ('check_original_cache', cache_check), ('runtime_services', lambda *_: None)]:
            stack.enter_context(patch.object(module, name, replacement))
        stack.enter_context(patch.object(apparmor_module, 'ROOT', root))
        stack.enter_context(patch.object(module, 'APPARMOR_JOURNAL_GUARD', lambda caller: apparmor_module.assert_apparmor_idle(caller)))
        stack.enter_context(patch.object(module.os, 'uname', return_value=types.SimpleNamespace(machine='x86_64', release=running[0])))
        # Release is read dynamically when a simulated different boot arrives.
        stack.enter_context(patch.object(module.os, 'uname', side_effect=lambda: types.SimpleNamespace(machine='x86_64', release=running[0])))
        return stack, root, fs, value, current_boot, running, inventory, commands, put

    def prepared(self, value):
        inspected = module.execute(value)
        value = {**value, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
        phases = []
        for _ in range(4):
            receipt = module.execute({**value, 'expiresAt': int(module.time.time() * 1000) + 59000})
            phases.append(receipt['phase'])
        self.assertEqual(phases, ['prepared-artifacts', 'packages-installed', 'boot-staged', 'prepared'])
        return {**value, 'prepareHash': receipt['prepareHash']}, receipt

    def activated(self, value, current_boot, running, put):
        request, _ = self.prepared(value)
        with patch.object(module.subprocess, 'Popen', return_value=object()):
            module.execute({**request, 'action': 'reboot'})
        current_boot[0] = str(uuid.uuid4()); running[0] = '6.12.118-0-virt'
        put('/proc/sys/kernel/osrelease', running[0].encode())
        module.execute({**request, 'action': 'verify'})
        return module.strict_json((module.ROOT / 'kernel-maintenance.json').read_bytes())

    def metadata_artifacts(self, value, root):
        inspected = module.execute(value)
        request = {**value, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
        self.assertEqual(module.execute(request)['phase'], 'prepared-artifacts')
        return request, module.strict_json((root / 'kernel-maintenance.json').read_bytes())

    def test_metadata_is_backed_up_before_apk_and_rollback_keeps_registered_new_release(self):
        stack, root, fs, value, _, _, inventory, commands, _ = self.fixture(include_alias=True, include_metadata=True)
        with stack:
            (fs / 'boot/System.map-6.12.100-0-virt').chmod(0o640)
            request, state = self.metadata_artifacts(value, root)
            before = state['transaction']['baseline']['packageMetadata']
            self.assertEqual(set(before), {'/boot/config-6.12.100-0-virt', '/boot/System.map-6.12.100-0-virt',
                                           '/usr/share/kernel/virt/kernel.release'})
            self.assertFalse(any('fix' in args or 'upgrade' in args for args in commands))
            for path, proof in before.items():
                backup = module.metadata_backup_path(state, path)
                self.assertEqual(module.file_proof(backup, private=True), {**proof, 'mode': 0o600})
                self.assertEqual(backup.lstat().st_nlink, 1)
                self.assertEqual(backup.lstat().st_uid, 0); self.assertEqual(backup.lstat().st_gid, 0)
            for phase in ('packages-installed', 'boot-staged', 'prepared'):
                self.assertEqual(module.execute(request)['phase'], phase)
            self.assertFalse((fs / 'boot/config-6.12.100-0-virt').exists())
            self.assertFalse((fs / 'boot/System.map-6.12.100-0-virt').exists())
            self.assertEqual(module.execute({**request, 'action': 'rollback'})['phase'], 'rolled-back')
            self.assertEqual((fs / 'boot/config-6.12.100-0-virt').read_bytes(), b'old-config')
            self.assertEqual((fs / 'boot/System.map-6.12.100-0-virt').read_bytes(), b'old-map')
            self.assertEqual(stat.S_IMODE((fs / 'boot/System.map-6.12.100-0-virt').lstat().st_mode), 0o640)
            self.assertEqual((fs / 'usr/share/kernel/virt/kernel.release').read_bytes(), b'6.12.118-0-virt\n')
            self.assertEqual((fs / 'boot/config-6.12.118-0-virt').read_bytes(), b'new-config')
            self.assertEqual((fs / 'boot/System.map-6.12.118-0-virt').read_bytes(), b'new-map')
            self.assertEqual((fs / 'boot/vmlinuz-virt').read_bytes(), b'old-kernel')
            self.assertEqual(inventory, {'linux-virt': '6.12.118-r0', 'incus': '6.20-r0'})
            self.assertFalse(any('downgrade' in args for args in commands))

    def test_metadata_none_baseline_does_not_invent_old_files_or_backup_records(self):
        stack, root, fs, value, _, _, _, _, _ = self.fixture(include_metadata=True)
        with stack:
            old_paths = module.kernel_metadata_paths('linux-virt', '6.12.100-0-virt')
            for path in old_paths.values():
                target = fs / path.lstrip('/'); self.assertTrue(target.is_relative_to(fs)); target.unlink()
            request, state = self.metadata_artifacts(value, root)
            self.assertEqual(state['transaction']['baseline']['packageMetadata'], dict.fromkeys(old_paths.values()))
            self.assertEqual(list((module.run_directory(state) / 'metadata-before').iterdir()), [])
            for phase in ('packages-installed', 'boot-staged', 'prepared'):
                self.assertEqual(module.execute(request)['phase'], phase)
            self.assertEqual(module.execute({**request, 'action': 'rollback'})['phase'], 'rolled-back')
            self.assertFalse((fs / old_paths['config'].lstrip('/')).exists())
            self.assertFalse((fs / old_paths['map'].lstrip('/')).exists())
            self.assertEqual((fs / old_paths['release'].lstrip('/')).read_bytes(), b'6.12.118-0-virt\n')

    def test_metadata_backup_interruption_resumes_original_plan_before_any_apk(self):
        stack, root, _, value, _, _, _, commands, _ = self.fixture(include_metadata=True)
        with stack:
            inspected = module.execute(value)
            request = {**value, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
            original_copy, copied = module.copy_checked, []
            def interrupted(source, destination, proof, mode=None):
                result = original_copy(source, destination, proof, mode)
                if destination.parent.name == 'metadata-before':
                    copied.append(destination)
                    raise ValueError('HARDENING_KERNEL_STEP_TIMEOUT')
                return result
            with patch.object(module, 'copy_checked', side_effect=interrupted), self.assertRaisesRegex(ValueError, 'STEP_TIMEOUT'):
                module.execute(request)
            self.assertEqual(len(copied), 1)
            old_backup = module.file_proof(copied[0], private=True)
            self.assertFalse((root / 'kernel-maintenance.json').exists())
            self.assertFalse(any('fix' in args or 'upgrade' in args for args in commands))
            self.assertEqual(module.execute(request)['phase'], 'prepared-artifacts')
            self.assertEqual(module.file_proof(copied[0], private=True), old_backup)
            state = module.strict_json((root / 'kernel-maintenance.json').read_bytes())
            self.assertEqual(state['plan']['planHash'], inspected['plan']['planHash'])
            module.verify_package_metadata_backups(state)

    def test_metadata_backup_tampering_stops_before_package_replay(self):
        for change in ('bytes', 'mode', 'link', 'hardlink'):
            stack, root, fs, value, _, _, inventory, commands, _ = self.fixture(include_metadata=True)
            with stack, self.subTest(change=change):
                request, state = self.metadata_artifacts(value, root)
                backup = module.metadata_backup_path(state, '/boot/config-6.12.100-0-virt')
                if change == 'bytes': backup.write_bytes(b'foreign backup')
                elif change == 'mode': backup.chmod(0o644)
                elif change == 'link':
                    backup.unlink(); os.symlink(fs / 'boot/config-6.12.100-0-virt', backup)
                else: os.link(backup, backup.with_name('foreign-hardlink'))
                offset = len(commands)
                with self.assertRaises(ValueError):
                    module.execute(request)
                self.assertEqual(commands[offset:], [])
                self.assertEqual(inventory['linux-virt'], '6.12.100-r0')
                if change == 'bytes': self.assertEqual(backup.read_bytes(), b'foreign backup')
                elif change == 'link': self.assertTrue(backup.is_symlink())

    def test_metadata_apk_file_and_database_commit_orders_replay_exact_original_package(self):
        for registered_expected in (False, True):
            stack, root, fs, value, _, _, inventory, commands, put = self.fixture(include_metadata=True)
            with stack, self.subTest(registered_expected=registered_expected):
                request, state = self.metadata_artifacts(value, root)
                for path in ('boot/config-6.12.100-0-virt', 'boot/System.map-6.12.100-0-virt'):
                    target = fs / path; self.assertTrue(target.is_relative_to(fs)); target.unlink()
                put('/boot/config-6.12.118-0-virt', b'new-config')
                put('/boot/System.map-6.12.118-0-virt', b'new-map')
                put('/usr/share/kernel/virt/kernel.release', b'6.12.118-0-virt\n')
                if registered_expected:
                    inventory['linux-virt'] = '6.12.118-r0'; put('/lib/apk/db/installed', b'expected-db\n')
                self.assertEqual(module.execute(request)['phase'], 'packages-installed')
                module.verify_package_metadata(state['transaction'])
                actual = [args for args in commands if '--simulate' not in args and ('fix' in args or 'upgrade' in args)]
                self.assertEqual(len(actual), 1); self.assertEqual('fix' in actual[0], registered_expected)
                self.assertEqual(actual[0][-1], 'linux-virt'); self.assertIn('--no-network', actual[0])
                self.assertEqual(inventory['linux-virt'], '6.12.118-r0')

    def test_metadata_rollback_uses_original_inventory_after_interrupted_file_commit(self):
        for registered_expected in (False, True):
            stack, root, fs, value, _, _, inventory, commands, put = self.fixture(include_metadata=True)
            with stack, self.subTest(registered_expected=registered_expected):
                request, _ = self.metadata_artifacts(value, root)
                for path in ('boot/config-6.12.100-0-virt', 'boot/System.map-6.12.100-0-virt'):
                    target = fs / path; self.assertTrue(target.is_relative_to(fs)); target.unlink()
                put('/boot/config-6.12.118-0-virt', b'new-config')
                put('/boot/System.map-6.12.118-0-virt', b'new-map')
                put('/usr/share/kernel/virt/kernel.release', b'6.12.118-0-virt\n')
                if registered_expected:
                    inventory['linux-virt'] = '6.12.118-r0'; put('/lib/apk/db/installed', b'expected-db\n')
                offset, original_inventory = len(commands), dict(inventory)
                self.assertEqual(module.execute({**request, 'action': 'rollback'})['phase'], 'rolled-back')
                self.assertEqual(inventory, original_inventory)
                self.assertEqual(commands[offset:], [])
                self.assertEqual((fs / 'boot/config-6.12.100-0-virt').read_bytes(), b'old-config')
                self.assertEqual((fs / 'boot/System.map-6.12.100-0-virt').read_bytes(), b'old-map')
                release = b'6.12.118-0-virt\n' if registered_expected else b'6.12.100-0-virt\n'
                self.assertEqual((fs / 'usr/share/kernel/virt/kernel.release').read_bytes(), release)
                self.assertEqual((fs / 'boot/config-6.12.118-0-virt').read_bytes(), b'new-config')

    def test_metadata_pollution_refuses_rollback_before_any_boot_or_module_restore(self):
        paths = ['/boot/config-6.12.100-0-virt', '/boot/System.map-6.12.100-0-virt',
                 '/usr/share/kernel/virt/kernel.release', '/boot/config-6.12.118-0-virt']
        for path in paths:
            stack, root, fs, value, _, _, _, commands, put = self.fixture(include_metadata=True)
            with stack, self.subTest(path=path):
                request, _ = self.prepared(value)
                put(path, b'foreign administrator edit')
                old_tree = fs / 'lib/modules/6.12.100-0-virt'
                self.assertTrue(old_tree.is_relative_to(fs)); shutil.rmtree(old_tree)
                before = {name: (fs / name).read_bytes() for name in ('boot/vmlinuz-virt', 'boot/initramfs-virt', 'boot/grub/grub.cfg')}
                offset = len(commands)
                with self.assertRaisesRegex(ValueError, 'CONFIGURATION_CHANGED'):
                    module.execute({**request, 'action': 'rollback'})
                self.assertFalse(old_tree.exists(), 'unknown metadata must be rejected before old modules are rewritten')
                self.assertEqual({name: (fs / name).read_bytes() for name in before}, before)
                self.assertEqual((fs / path.lstrip('/')).read_bytes(), b'foreign administrator edit')
                self.assertEqual(commands[offset:], [])

    def test_metadata_copy_race_is_rechecked_before_publishing_the_original_journal(self):
        stack, root, fs, value, _, _, _, commands, put = self.fixture(include_metadata=True)
        with stack:
            inspected = module.execute(value)
            request = {**value, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
            original_copy = module.copy_checked
            def race(source, destination, proof, mode=None):
                result = original_copy(source, destination, proof, mode)
                if destination.parent.name == 'before' and destination.name == 'vmlinuz-virt':
                    put('/boot/config-6.12.100-0-virt', b'foreign administrator edit')
                return result
            with patch.object(module, 'copy_checked', side_effect=race), self.assertRaisesRegex(ValueError, 'CONFIGURATION_CHANGED'):
                module.execute(request)
            self.assertFalse((root / 'kernel-maintenance.json').exists())
            self.assertEqual((fs / 'boot/config-6.12.100-0-virt').read_bytes(), b'foreign administrator edit')
            self.assertFalse(any('fix' in args or 'upgrade' in args for args in commands))

    def test_metadata_backup_and_copy_scratch_are_included_in_disk_reservation(self):
        stack, root, _, value, _, _, _, _, _ = self.fixture(include_metadata=True)
        with stack:
            request, state = self.metadata_artifacts(value, root)
            baseline, transaction = state['transaction']['baseline'], state['transaction']
            records = [*baseline['packageMetadata'].items(), *module.expected_package_metadata(transaction).items()]
            metadata_size = sum(proof['size'] for _, proof in records if proof is not None)
            boot_metadata = sum(proof['size'] for path, proof in records if path.startswith('/boot/') and proof is not None)
            expected_root = module.manifest_size(baseline['modules']) * 2 + module.manifest_size(transaction['cache']) + \
                module.manifest_size(baseline['artifacts']) * 2 + metadata_size * 2 + 64 * 1024 * 1024
            expected_boot = module.manifest_size(baseline['artifacts']) * 2 + boot_metadata * 2 + 16 * 1024 * 1024
            with patch.object(module, 'resources') as reserve:
                module.save_before(state, request)
            self.assertEqual(reserve.call_args_list[0].args, (expected_root, expected_boot))

    def test_metadata_disk_shortfall_refuses_all_backups_and_apk_on_both_filesystems(self):
        native_resources = module.resources
        old_stack, old_root, _, old_value, _, _, _, _, _ = self.fixture()
        with old_stack, patch.object(module, 'resources') as reserve:
            self.metadata_artifacts(old_value, old_root)
            old_root_budget, old_boot_budget = reserve.call_args_list[0].args
        for shortage in ('root', 'boot'):
            stack, root, fs, value, _, _, inventory, commands, _ = self.fixture(include_metadata=True)
            with stack, self.subTest(shortage=shortage):
                original_metadata = module.package_metadata_snapshot('linux-virt', '6.12.100-0-virt')
                original_boot = {name: (fs / name).read_bytes() for name in ('boot/vmlinuz-virt', 'boot/initramfs-virt', 'boot/grub/grub.cfg')}
                original_db = (fs / 'lib/apk/db/installed').read_bytes()
                inspected = module.execute(value)
                request = {**value, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
                def available(path):
                    limit = old_boot_budget if shortage == 'boot' and path == '/boot' else \
                        old_root_budget if shortage == 'root' and path != '/boot' else 1024 * 1024 * 1024
                    return types.SimpleNamespace(f_flag=0, f_bavail=limit, f_frsize=1, f_favail=4096)
                with patch.object(module.os, 'statvfs', side_effect=available), \
                        patch.object(module, 'resources', side_effect=native_resources), \
                        patch.object(module, 'copy_checked', side_effect=AssertionError('low disk must be rejected before any backup copy')), \
                        self.assertRaisesRegex(ValueError, '^HARDENING_DISK_LOW$'):
                    module.execute(request)
                preparation = root / ('kernel-' + request['requestId'])
                self.assertFalse((preparation / 'metadata-before').exists())
                self.assertFalse((preparation / 'before').exists())
                self.assertFalse((preparation / 'old-modules').exists())
                self.assertFalse((root / 'kernel-maintenance.json').exists())
                self.assertEqual(module.package_metadata_snapshot('linux-virt', '6.12.100-0-virt'), original_metadata)
                self.assertEqual({name: (fs / name).read_bytes() for name in original_boot}, original_boot)
                self.assertEqual((fs / 'lib/apk/db/installed').read_bytes(), original_db)
                self.assertEqual(inventory, {'linux-virt': '6.12.100-r0', 'incus': '6.20-r0'})
                self.assertFalse(any('fix' in args or 'upgrade' in args for args in commands))

    def test_metadata_none_baseline_reserves_large_candidate_before_backups_and_before_apk(self):
        native_resources = module.resources
        candidate_size = 40 * 1024 * 1024
        hasher = hashlib.sha256()
        block = b'candidate-metadata' * (1024 * 1024 // len(b'candidate-metadata'))
        remaining = candidate_size
        while remaining:
            part = block[:remaining]
            hasher.update(part); remaining -= len(part)
        for phase in ('before-backup', 'before-apk'):
            for shortage in ('root', 'boot'):
                stack, root, fs, value, _, _, inventory, commands, _ = self.fixture(include_metadata=True)
                with stack, self.subTest(phase=phase, shortage=shortage):
                    for path in module.kernel_metadata_paths('linux-virt', '6.12.100-0-virt').values():
                        target = fs / path.lstrip('/'); self.assertTrue(target.is_relative_to(fs)); target.unlink()
                    original_source = module.source_transaction
                    def candidate(request, directory, previous=None):
                        plan, transaction = original_source(request, directory, previous)
                        # These are declared signed-output proofs in a fake APK
                        # fixture, not a claim of native signature acceptance.
                        for path in ('/boot/config-6.12.118-0-virt', '/boot/System.map-6.12.118-0-virt'):
                            transaction['payload'][path] = {'sha256': hasher.hexdigest(), 'size': candidate_size,
                                                            'mode': 0o644, 'uid': 0, 'gid': 0}
                        plan['planHash'] = None
                        material = {key: field for key, field in transaction.items() if key not in {'staging', 'candidateArtifacts', 'candidateModules'}}
                        plan['planHash'] = module.digest(module.encoded(material))
                        return plan, transaction
                    with patch.object(module, 'source_transaction', side_effect=candidate):
                        inspected = module.execute(value)
                        request = {**value, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
                        if phase == 'before-apk':
                            self.assertEqual(module.execute(request)['phase'], 'prepared-artifacts')
                            state = module.strict_json((root / 'kernel-maintenance.json').read_bytes())
                            self.assertTrue(all(proof is None for proof in state['transaction']['baseline']['packageMetadata'].values()))
                        original_journal = (root / 'kernel-maintenance.json').read_bytes() if (root / 'kernel-maintenance.json').exists() else None
                        original_boot = {name: (fs / name).read_bytes() for name in ('boot/vmlinuz-virt', 'boot/initramfs-virt', 'boot/grub/grub.cfg')}
                        original_db, offset = (fs / 'lib/apk/db/installed').read_bytes(), len(commands)
                        def available(path):
                            free = 32 * 1024 * 1024 if shortage == 'boot' and path == '/boot' else \
                                (300 if phase == 'before-apk' else 128) * 1024 * 1024 if shortage == 'root' and path != '/boot' else 1024 * 1024 * 1024
                            return types.SimpleNamespace(f_flag=0, f_bavail=free // 4096, f_frsize=4096, f_favail=4096)
                        with patch.object(module.os, 'statvfs', side_effect=available), \
                                patch.object(module, 'resources', side_effect=native_resources), \
                                patch.object(module, 'copy_checked', side_effect=AssertionError('candidate shortfall must precede any backup or APK write')), \
                                self.assertRaisesRegex(ValueError, '^HARDENING_DISK_LOW$'):
                            module.execute(request)
                        if phase == 'before-backup':
                            preparation = root / ('kernel-' + request['requestId'])
                            self.assertFalse((preparation / 'metadata-before').exists())
                            self.assertFalse((preparation / 'before').exists())
                            self.assertFalse((preparation / 'old-modules').exists())
                        self.assertEqual((root / 'kernel-maintenance.json').read_bytes() if (root / 'kernel-maintenance.json').exists() else None, original_journal)
                        self.assertEqual({name: (fs / name).read_bytes() for name in original_boot}, original_boot)
                        self.assertEqual((fs / 'lib/apk/db/installed').read_bytes(), original_db)
                        self.assertEqual(inventory, {'linux-virt': '6.12.100-r0', 'incus': '6.20-r0'})
                        self.assertTrue(all(proof is None for proof in module.package_metadata_snapshot('linux-virt', '6.12.100-0-virt').values()))
                        self.assertEqual(commands[offset:], [])

    def test_metadata_interrupted_rollback_resumes_remaining_original_files(self):
        stack, root, fs, value, _, _, inventory, _, _ = self.fixture(include_metadata=True)
        with stack:
            request, _ = self.prepared(value)
            original_copy, calls = module.copy_checked, []
            def interrupted(source, destination, proof, mode=None):
                result = original_copy(source, destination, proof, mode)
                if destination == fs / 'boot/config-6.12.100-0-virt':
                    calls.append(destination)
                    raise ValueError('HARDENING_KERNEL_STEP_TIMEOUT')
                return result
            with patch.object(module, 'copy_checked', side_effect=interrupted), self.assertRaisesRegex(ValueError, 'STEP_TIMEOUT'):
                module.execute({**request, 'action': 'rollback'})
            self.assertEqual(len(calls), 1)
            self.assertEqual((fs / 'boot/config-6.12.100-0-virt').read_bytes(), b'old-config')
            self.assertEqual(module.execute({**request, 'action': 'rollback'})['phase'], 'rolled-back')
            self.assertEqual((fs / 'boot/System.map-6.12.100-0-virt').read_bytes(), b'old-map')
            self.assertEqual((fs / 'usr/share/kernel/virt/kernel.release').read_bytes(), b'6.12.118-0-virt\n')
            self.assertEqual(inventory['linux-virt'], '6.12.118-r0')

    def test_metadata_tampering_blocks_reboot_and_terminal_archive(self):
        for path in ('/boot/config-6.12.118-0-virt', '/boot/System.map-6.12.118-0-virt', '/usr/share/kernel/virt/kernel.release'):
            stack, root, fs, value, current, running, _, _, put = self.fixture(include_metadata=True)
            with stack, self.subTest(path=path):
                request, _ = self.prepared(value)
                put(path, b'foreign metadata')
                with patch.object(module.subprocess, 'Popen') as launch, self.assertRaisesRegex(ValueError, 'PAYLOAD_INCOMPLETE'):
                    module.execute({**request, 'action': 'reboot'})
                launch.assert_not_called()
            stack, root, fs, value, current, running, _, _, put = self.fixture(include_metadata=True)
            with stack, self.subTest(activated_path=path):
                self.activated(value, current, running, put)
                original_journal = (root / 'kernel-maintenance.json').read_bytes()
                put(path, b'foreign metadata')
                fresh = {**value, 'action': 'status', 'requestId': str(uuid.uuid4()), 'bootId': current[0], 'prepareHash': module.ZERO,
                         'expectedPlanHash': 'a' * 64}
                with self.assertRaisesRegex(ValueError, 'PAYLOAD_INCOMPLETE'):
                    module.execute(fresh)
                self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), original_journal)
                self.assertEqual((fs / path.lstrip('/')).read_bytes(), b'foreign metadata')

    def test_metadata_rollback_reactivation_and_next_patch_keep_original_archives(self):
        stack, root, fs, value, current, running, inventory, commands, put = self.fixture(include_alias=True, include_metadata=True)
        with stack:
            original_request, _ = self.prepared(value)
            self.assertEqual(module.execute({**original_request, 'action': 'rollback'})['phase'], 'rolled-back')
            original_journal = (root / 'kernel-maintenance.json').read_bytes()
            world = b'linux-virt\nincus\nlxcfs\n'; put('/etc/apk/world', world)
            fresh = {**value, 'requestId': str(uuid.uuid4()), 'bootId': current[0], 'expectedPlanHash': None}
            offset = len(commands)
            reactivated = self.activated(fresh, current, running, put)
            actual = [args for args in commands[offset:] if '--simulate' not in args and ('fix' in args or 'upgrade' in args)]
            self.assertEqual(len(actual), 1); self.assertIn('fix', actual[0]); self.assertNotIn('upgrade', actual[0])
            self.assertTrue(reactivated['transaction']['reactivation'])
            self.assertEqual((root / ('kernel-maintenance-' + original_request['requestId'] + '.json')).read_bytes(), original_journal)
            self.assertEqual((fs / 'etc/apk/world').read_bytes(), world)
            new_journal = (root / 'kernel-maintenance.json').read_bytes()
            next_value = {**value, 'requestId': str(uuid.uuid4()), 'bootId': current[0], 'expectedPlanHash': None}
            next_request, _ = self.prepared(next_value)
            next_state = module.strict_json((root / 'kernel-maintenance.json').read_bytes())
            self.assertEqual(next_state['plan']['candidateVersion'], '6.12.119-r0')
            self.assertEqual(next_state['transaction']['baseline']['packageMetadata']['/boot/config-6.12.118-0-virt']['sha256'], module.digest(b'new-config'))
            self.assertEqual((root / ('kernel-maintenance-' + fresh['requestId'] + '.json')).read_bytes(), new_journal)
            self.assertEqual(module.execute({**next_request, 'action': 'rollback'})['phase'], 'rolled-back')
            self.assertEqual((fs / 'boot/config-6.12.118-0-virt').read_bytes(), b'new-config')
            self.assertEqual((fs / 'usr/share/kernel/virt/kernel.release').read_bytes(), b'6.12.119-0-virt\n')
            self.assertEqual(inventory['linux-virt'], '6.12.119-r0')

    def test_metadata_journal_exact_keys_and_legacy_no_metadata_hash_are_preserved(self):
        stack, root, _, value, _, _, _, _, _ = self.fixture(include_metadata=True)
        with stack:
            self.prepared(value)
            original = (root / 'kernel-maintenance.json').read_bytes()
            state = module.strict_json(original)
            def rehash(changed):
                transaction = changed['transaction']
                material = {key: field for key, field in transaction.items() if key not in {'staging', 'candidateArtifacts', 'candidateModules'}}
                material['plan'] = {**transaction['plan'], 'planHash': None}
                digest = module.digest(module.encoded(material))
                changed['plan']['planHash'] = transaction['plan']['planHash'] = digest
                changed['identity']['expectedPlanHash'] = digest
            for change in ('extra', 'missing', 'uid', 'gid', 'mode', 'type', 'release'):
                changed = copy.deepcopy(state)
                metadata = changed['transaction']['baseline']['packageMetadata']
                if change == 'extra': metadata['/etc/passwd'] = None
                elif change == 'missing': metadata.pop('/boot/config-6.12.100-0-virt')
                elif change == 'release': changed['transaction']['payload']['/usr/share/kernel/virt/kernel.release']['sha256'] = 'a' * 64
                elif change == 'type': metadata['/boot/config-6.12.100-0-virt'] = False
                else: metadata['/boot/config-6.12.100-0-virt'][change] = 1 if change in {'uid', 'gid'} else 0o777
                rehash(changed)
                with self.subTest(change=change), self.assertRaises(ValueError):
                    module.validate_journal(changed)
                self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), original)
        stack, root, _, value, _, _, _, _, _ = self.fixture(include_alias=True)
        with stack:
            request, _ = self.prepared(value)
            original = (root / 'kernel-maintenance.json').read_bytes()
            state = module.strict_json(original)
            self.assertNotIn('packageMetadata', state['transaction']['baseline'])
            with patch.object(module, 'metadata_proof', side_effect=AssertionError('old journal must not read a new metadata range')):
                self.assertEqual(module.execute({**request, 'action': 'status'})['phase'], 'prepared')
                module.validate_journal(state)
                self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), original)
                self.assertEqual(module.execute({**request, 'action': 'rollback'})['phase'], 'rolled-back')
            after = module.strict_json((root / 'kernel-maintenance.json').read_bytes())
            self.assertNotIn('packageMetadata', after['transaction']['baseline'])
            self.assertEqual(after['plan']['planHash'], state['plan']['planHash'])

    def test_alias_preparation_and_removed_tree_rollback_keep_link_and_original_boot_bytes(self):
        stack, root, fs, value, _current, _running, inventory, _commands, _put = self.fixture(include_alias=True)
        with stack:
            request, _receipt = self.prepared(value)
            state = module.strict_json((root / 'kernel-maintenance.json').read_bytes())
            expected = module.module_alias_metadata('linux-virt')
            self.assertEqual(state['transaction']['baseline']['modules']['vmlinuz'], expected)
            self.assertEqual(state['transaction']['candidateModules']['vmlinuz'], expected)
            backup = module.run_directory(state) / 'old-modules/vmlinuz'
            self.assertEqual(os.readlink(backup), '/boot/vmlinuz-virt')
            old_tree = fs / 'lib/modules/6.12.100-0-virt'
            self.assertTrue(old_tree.is_relative_to(fs))
            shutil.rmtree(old_tree)
            module.execute({**request, 'action': 'rollback', 'expiresAt': int(module.time.time() * 1000) + 59000})
            self.assertEqual((fs / 'boot/vmlinuz-virt').read_bytes(), b'old-kernel')
            self.assertEqual((old_tree / 'kernel/test.ko').read_bytes(), b'old-module')
            self.assertEqual(module.module_alias_proof(old_tree / 'vmlinuz', 'linux-virt'), expected)
            self.assertEqual(inventory['linux-virt'], '6.12.118-r0', 'rollback does not downgrade the installed signed package')

    def test_alias_activation_and_original_boot_fallback_model_keep_full_link_state(self):
        stack, root, fs, value, current_boot, running, _inventory, _commands, put = self.fixture(include_alias=True)
        with stack:
            state = self.activated(value, current_boot, running, put)
            module.validate_journal(state)
            self.assertEqual(state['transaction']['candidateModules']['vmlinuz'], module.module_alias_metadata('linux-virt'))
            current_boot[0] = str(uuid.uuid4());running[0] = '6.12.100-0-virt'
            put('/proc/sys/kernel/osrelease', running[0].encode())
            request = {**value, 'action': 'rollback', 'expectedPlanHash': state['plan']['planHash'],
                       'prepareHash': state['prepareHash'], 'expiresAt': int(module.time.time() * 1000) + 59000}
            module.execute(request)
            restored = module.strict_json((root / 'kernel-maintenance.json').read_bytes())
            self.assertEqual(restored['phase'], 'rolled-back')
            self.assertEqual(os.readlink(fs / 'lib/modules/6.12.100-0-virt/vmlinuz'), '/boot/vmlinuz-virt')
            self.assertEqual((fs / 'boot/vmlinuz-virt').read_bytes(), b'old-kernel')

    def test_journal_keeps_alias_mode_exception_out_of_other_proofs_and_requires_signed_payload_match(self):
        stack, root, _fs, value, _current, _running, _inventory, _commands, _put = self.fixture(include_alias=True)
        with stack:
            self.prepared(value)
            original = (root / 'kernel-maintenance.json').read_bytes()
            state = module.strict_json(original)
            module.validate_journal(state)
            def rehash(changed):
                transaction = changed['transaction']
                material = {key: field for key, field in transaction.items() if key not in {'staging', 'candidateArtifacts', 'candidateModules'}}
                material['plan'] = {**transaction['plan'], 'planHash': None}
                digest = module.digest(module.encoded(material))
                changed['plan']['planHash'] = digest;changed['transaction']['plan']['planHash'] = digest
                changed['identity']['expectedPlanHash'] = digest
            mutations = [
                lambda data: data['transaction']['candidateModules']['vmlinuz'].update(nlink=True),
                lambda data: data['transaction']['candidateModules'].update(vmlinuz=module.module_alias_metadata('linux-lts')),
                lambda data: data['transaction']['candidateArtifacts']['/boot/vmlinuz-virt'].update(mode=0o777),
                lambda data: data['transaction']['candidateModules'].update({'kernel/vmlinuz': data['transaction']['candidateModules'].pop('vmlinuz')}),
                lambda data: data['transaction']['baseline']['modules']['vmlinuz'].update(uid=1),
                lambda data: data['transaction']['payload'].pop('/lib/modules/6.12.118-0-virt/vmlinuz'),
                lambda data: data['transaction']['payload'].update({'/boot/vmlinuz-virt': module.module_alias_metadata('linux-virt')}),
                lambda data: data['transaction']['context'].update({'/etc/alias': module.module_alias_metadata('linux-virt')}),
            ]
            for index, mutate in enumerate(mutations):
                changed = copy.deepcopy(state);mutate(changed);rehash(changed)
                with self.subTest(mutation=index), self.assertRaises(ValueError):
                    module.validate_journal(changed)
                self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), original)

    def saved_apparmor(self, value, phase, customers=None):
        customers = apparmor_request(value)['customers'] if customers is None else customers
        state = {'version': 1, 'phase': phase, 'identity': {'nodeId': value['nodeId'], 'requestId': str(uuid.uuid4()),
            'identityHash': value['identityHash'], 'bootId': str(uuid.uuid4()), 'architecture': value['architecture'],
            'recipe': 'alpine-apparmor-grub-v1', 'customers': customers}, 'beforeHash': 'b' * 64, 'afterHash': 'c' * 64,
            'customerBoot': [{'name': customer['name'], 'guardHash': 'f' * 64} for customer in customers],
            'runlevelBefore': False, 'bootMode': 0o600,
            'grubDefaults': {'beforeHash': 'd' * 64, 'afterHash': 'e' * 64, 'mode': 0o644}}
        state['prepareHash'] = module.digest(json.dumps([state['identity'], state['beforeHash'], state['afterHash'],
            state['runlevelBefore'], state['bootMode'], state['grubDefaults']], sort_keys=True).encode())
        if phase == 'rolled-back':
            state['rolledBackAt'] = 1
        return state

    def cross_recipe_idle(self, value, apparmor=False):
        original_open = os.open
        def only_read(path, flags, *args, **kwargs):
            self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND),
                             'the cross-recipe guard opens evidence only for reading')
            return original_open(path, flags, *args, **kwargs)
        with ExitStack() as readonly:
            for name in ['boot', 'empty_remote', 'verify_terminal', 'runtime_identity', 'runtime_services',
                         'command', 'execute', 'atomic', 'sync_directory', 'current_request']:
                readonly.enter_context(patch.object(module, name, side_effect=AssertionError('read-only guard called ' + name)))
            for name in ['boot', 'empty_remote', 'command', 'execute', 'atomic', 'require_current_request', 'guest_read',
                         'runlevel_enabled', 'grub_defaults_check', 'environment', 'identity']:
                readonly.enter_context(patch.object(apparmor_module, name, side_effect=AssertionError('read-only AppArmor guard called ' + name)))
            readonly.enter_context(patch.object(module.subprocess, 'Popen', side_effect=AssertionError('read-only guard spawned a process')))
            readonly.enter_context(patch.object(module.fcntl, 'flock', side_effect=AssertionError('read-only guard acquired a second lock')))
            readonly.enter_context(patch.object(module.os, 'open', side_effect=only_read))
            return module.assert_apparmor_idle(value) if apparmor else module.assert_kernel_idle(value)

    def test_cross_recipe_guard_absence_and_every_original_nonterminal(self):
        stack, root, _, value, _, _, _, _, _ = self.fixture()
        with stack:
            caller = apparmor_request(value)
            self.assertIsNone(self.cross_recipe_idle(caller))
            inspected = module.execute(value)
            request = {**value, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
            for phase in ['prepared-artifacts', 'packages-installed', 'boot-staged', 'prepared']:
                receipt = module.execute(request)
                self.assertEqual(receipt['phase'], phase)
                before = (root / 'kernel-maintenance.json').read_bytes()
                with self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_OTHER_MAINTENANCE$'):
                    self.cross_recipe_idle(caller)
                self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), before)
            with patch.object(module.subprocess, 'Popen', return_value=object()):
                module.execute({**request, 'action': 'reboot', 'prepareHash': receipt['prepareHash']})
            before = (root / 'kernel-maintenance.json').read_bytes()
            with self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_OTHER_MAINTENANCE$'):
                self.cross_recipe_idle(caller)
            self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), before)

    def test_cross_recipe_activated_guard_keeps_old_request_and_later_customer_changes(self):
        stack, root, _, value, current_boot, running, _, _, put = self.fixture()
        with stack:
            state = self.activated(value, current_boot, running, put)
            before = (root / 'kernel-maintenance.json').read_bytes()
            caller = apparmor_request(value)
            self.assertNotEqual(caller['requestId'], state['identity']['requestId'])
            self.assertNotEqual(caller['bootId'], state['identity']['bootId'])
            put('/boot/grub/grub.cfg', b'later legitimate AppArmor boot configuration\n', 0o600)
            put('/etc/apk/world', b'linux-virt\nincus\nlxcfs\n')
            current_boot[0] = str(uuid.uuid4())
            self.assertIsNone(self.cross_recipe_idle(caller))
            for delta in [{'nodeId': str(uuid.uuid4())}, {'identityHash': 'b' * 64}, {'architecture': 'aarch64'}]:
                with self.subTest(delta=delta), self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_OTHER_JOURNAL_UNKNOWN$'):
                    self.cross_recipe_idle({**caller, **delta})
            self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), before)
            self.assertFalse((root / ('kernel-maintenance-' + state['identity']['requestId'] + '.json')).exists())

    def test_cross_recipe_rolled_back_guard_accepts_early_and_prepared_originals(self):
        for early in [True, False]:
            with self.subTest(early=early):
                stack, root, _, value, _, _, _, _, _ = self.fixture()
                with stack:
                    if early:
                        inspected = module.execute(value)
                        request = {**value, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
                        self.assertEqual(module.execute(request)['phase'], 'prepared-artifacts')
                    else:
                        request, _ = self.prepared(value)
                    module.execute({**request, 'action': 'rollback'})
                    before = (root / 'kernel-maintenance.json').read_bytes()
                    state = module.strict_json(before)
                    self.assertEqual(state['prepareHash'] == module.ZERO, early)
                    self.assertIsNone(self.cross_recipe_idle(apparmor_request(value)))
                    self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), before)
                    if not early:
                        state['reboot'] = {'issuedAt': 1, 'originalBootId': state['identity']['bootId']}
                        module.atomic(root / 'kernel-maintenance.json', module.encoded(state))
                        self.assertIsNone(self.cross_recipe_idle(apparmor_request(value)))

    def test_cross_recipe_activated_guard_rejects_types_tampering_and_nested_duplicates(self):
        stack, root, _, value, current_boot, running, _, _, put = self.fixture()
        with stack:
            original = self.activated(value, current_boot, running, put)
            mutations = [lambda state: state.update(version=True), lambda state: state.update(version=1.0),
                         lambda state: state.update(phase=[]), lambda state: state.update(phase='unexpected'),
                         lambda state: state.update(prepareHash=module.ZERO), lambda state: state.update(prepareHash='c' * 64),
                         lambda state: state.update(rolledBackAt=1), lambda state: state.update(reboot=None),
                         lambda state: state['reboot'].update(issuedAt=True), lambda state: state['reboot'].update(issuedAt=0),
                         lambda state: state['reboot'].update(originalBootId=str(uuid.uuid4())),
                         lambda state: state['transaction'].update(staging=None),
                         lambda state: state['transaction'].update(staging={'started': 1}),
                         lambda state: state['transaction'].update(candidateArtifacts=None),
                         lambda state: state['transaction'].update(candidateModules={}),
                         lambda state: state['transaction']['candidateArtifacts']['/boot/vmlinuz-virt'].update(uid=True),
                         lambda state: state['transaction']['candidateArtifacts']['/boot/vmlinuz-virt'].update(sha256='c' * 64)]
            for change in mutations:
                state = copy.deepcopy(original); change(state)
                module.atomic(root / 'kernel-maintenance.json', module.encoded(state))
                before = (root / 'kernel-maintenance.json').read_bytes()
                with self.assertRaisesRegex(ValueError, '^HARDENING_[A-Z_]+$'):
                    self.cross_recipe_idle(apparmor_request(value))
                self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), before)
            for data in [module.encoded(original).replace(b'"version":1', b'"version":1,"version":1', 1),
                         module.encoded(original).replace(b'"uid":0', b'"uid":0,"uid":0', 1),
                         b'{"private-source":"https://private.invalid/token=never-output"}']:
                module.atomic(root / 'kernel-maintenance.json', data)
                with self.assertRaisesRegex(ValueError, '^HARDENING_[A-Z_]+$'):
                    self.cross_recipe_idle(apparmor_request(value))
                self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), data)

    def test_cross_recipe_rollback_guard_rejects_false_timestamp_and_false_barrier(self):
        for early in [True, False]:
            stack, root, _, value, _, _, _, _, _ = self.fixture()
            with stack:
                if early:
                    inspected = module.execute(value)
                    request = {**value, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
                    module.execute(request)
                else:
                    request, _ = self.prepared(value)
                module.execute({**request, 'action': 'rollback'})
                original = module.strict_json((root / 'kernel-maintenance.json').read_bytes())
                mutations = [lambda state: state.update(rolledBackAt=True), lambda state: state.update(rolledBackAt=0),
                             lambda state: state.update(rolledBackAt=None), lambda state: state.update(prepareHash='c' * 64),
                             lambda state: state.update(reboot={'issuedAt': True, 'originalBootId': state['identity']['bootId']}),
                             lambda state: state.update(reboot={'issuedAt': 1, 'originalBootId': str(uuid.uuid4())})]
                mutations += [lambda state: state.update(reboot={'issuedAt': 1, 'originalBootId': state['identity']['bootId']})] if early else \
                    [lambda state: state['transaction'].update(staging=None)]
                for change in mutations:
                    state = copy.deepcopy(original); change(state)
                    data = module.encoded(state)
                    module.atomic(root / 'kernel-maintenance.json', data)
                    with self.assertRaisesRegex(ValueError, '^HARDENING_[A-Z_]+$'):
                        self.cross_recipe_idle(apparmor_request(value))
                    self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), data)

    def test_cross_recipe_guard_rejects_public_symlink_hardlink_and_oversize_journals(self):
        for kind in ['public', 'symlink', 'dangling', 'hardlink', 'oversize']:
            with self.subTest(kind=kind):
                stack, root, _, value, _, _, _, _, _ = self.fixture()
                with stack:
                    path = root / 'kernel-maintenance.json'
                    module.atomic(path, b'{}')
                    if kind == 'public':
                        path.chmod(0o644)
                    elif kind in ['symlink', 'dangling']:
                        path.unlink()
                        target = root / 'original-journal.json'
                        if kind == 'symlink':
                            module.atomic(target, b'{}')
                        path.symlink_to(target)
                    elif kind == 'hardlink':
                        os.link(path, root / 'original-journal.json')
                    else:
                        with path.open('r+b') as stream:
                            stream.seek(module.MAX_JOURNAL_BYTES); stream.write(b'x')
                    with self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_UNTRUSTED_PATH$'):
                        self.cross_recipe_idle(apparmor_request(value))
                    self.assertTrue(path.exists() or path.is_symlink())

    def test_cross_recipe_guard_cannot_treat_unreadable_journal_as_absent(self):
        stack, root, _, value, _, _, _, _, _ = self.fixture()
        with stack:
            original_lstat = Path.lstat
            for journal, apparmor in [(root / 'kernel-maintenance.json', False), (root / 'maintenance.json', True)]:
                module.atomic(journal, b'{}')
                for code in [errno.EACCES, errno.EIO]:
                    def unavailable(path):
                        if path == journal:
                            raise OSError(code, 'fixture unreadable maintenance journal')
                        return original_lstat(path)
                    with self.subTest(code=code, apparmor=apparmor), patch.object(Path, 'lstat', unavailable), \
                            self.assertRaisesRegex(ValueError, '^HARDENING_JOURNAL_CONFLICT$' if apparmor else
                                                   '^HARDENING_KERNEL_OTHER_JOURNAL_UNKNOWN$'):
                        self.cross_recipe_idle(apparmor_request(value), apparmor)
                self.assertEqual(journal.read_bytes(), b'{}')

    def test_paired_apparmor_guard_requires_callback_and_propagates_its_result(self):
        stack, root, _, value, _, _, _, _, _ = self.fixture()
        with stack:
            with patch.object(module, 'APPARMOR_JOURNAL_GUARD', None):
                self.assertIsNone(self.cross_recipe_idle(value, apparmor=True))
                module.atomic(root / 'maintenance.json', b'{}')
                with self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_OTHER_JOURNAL_UNKNOWN$'):
                    self.cross_recipe_idle(value, apparmor=True)
                self.assertEqual((root / 'maintenance.json').read_bytes(), b'{}')
                (root / 'maintenance.json').unlink()
            calls = []
            def reader(caller):
                calls.append(caller)
            with patch.object(module, 'APPARMOR_JOURNAL_GUARD', reader):
                self.assertIsNone(self.cross_recipe_idle(value, apparmor=True))
            self.assertEqual(calls, [value], 'even absence uses the paired reader when it is available')
            def refused(_caller):
                raise ValueError('HARDENING_KERNEL_OTHER_MAINTENANCE')
            with patch.object(module, 'APPARMOR_JOURNAL_GUARD', refused), \
                    self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_OTHER_MAINTENANCE$'):
                self.cross_recipe_idle(value, apparmor=True)

    def test_paired_legacy_terminal_guard_uses_original_schema_hash_and_shared_identity(self):
        stack, root, _, value, _, _, _, _, _ = self.fixture()
        with stack:
            path = root / 'maintenance.json'
            for phase in ['customers-restored', 'rolled-back']:
                state = self.saved_apparmor(value, phase)
                self.assertNotEqual(state['identity']['customers'], value['customers'], 'history can include a customer already removed')
                data = module.encoded(state)
                module.atomic(path, data)
                self.assertIsNone(self.cross_recipe_idle(value, apparmor=True))
                self.assertEqual(path.read_bytes(), data)
                for delta in [{'nodeId': str(uuid.uuid4())}, {'identityHash': 'c' * 64}, {'architecture': 'aarch64'}]:
                    with self.subTest(phase=phase, delta=delta), self.assertRaisesRegex(ValueError, '^HARDENING_KERNEL_OTHER_JOURNAL_UNKNOWN$'):
                        self.cross_recipe_idle({**value, **delta}, apparmor=True)
            original = self.saved_apparmor(value, 'customers-restored')
            mutations = [lambda state: state.update(version=True), lambda state: state.pop('customerBoot'),
                         lambda state: state.update(runlevelBefore='false'), lambda state: state.update(bootMode=True),
                         lambda state: state.update(prepareHash='c' * 64), lambda state: state['grubDefaults'].update(mode=True),
                         lambda state: state.update(grubDefaults=None)]
            for change in mutations:
                state = copy.deepcopy(original); change(state)
                if state.get('grubDefaults', {}) is None:
                    state['prepareHash'] = module.digest(json.dumps([state['identity'], state['beforeHash'], state['afterHash'],
                        state['runlevelBefore'], state['bootMode'], None], sort_keys=True).encode())
                data = module.encoded(state)
                module.atomic(path, data)
                with self.assertRaisesRegex(ValueError, '^HARDENING_JOURNAL_CONFLICT$'):
                    self.cross_recipe_idle(value, apparmor=True)
                self.assertEqual(path.read_bytes(), data)

    def test_real_control_plane_sentinels_refuse_before_any_kernel_change(self):
        stack, root, fs, value, _, _, _, commands, put = self.fixture()
        with stack:
            for sentinel in ['/opt/incudal', '/usr/local/sbin/incudal-onboarding-gateway',
                             '/etc/incudal-onboarding-gateway', '/opt/incudal-gateway', '/etc/incudal-gateway']:
                with self.subTest(sentinel=sentinel):
                    path = put(sentinel, b'fixture real control-plane sentinel\n', 0o600)
                    self.assertTrue(path.is_relative_to(fs))
                    with self.assertRaisesRegex(ValueError, '^HARDENING_CONTROL_PLANE_TARGET$'):
                        module.execute(value)
                    self.assertEqual(commands, [])
                    self.assertFalse((root / 'kernel-maintenance.json').exists())
                    path.unlink()

    def test_real_atomic_files_before_package_commit_and_bounded_phases(self):
        stack, root, fs, value, _, _, _, commands, _ = self.fixture()
        with stack:
            request, receipt = self.prepared(value)
            state = json.loads((root / 'kernel-maintenance.json').read_text())
            self.assertEqual(module.validate_journal(state)['phase'], 'prepared')
            self.assertEqual((module.before_path(state, '/boot/vmlinuz-virt')).read_bytes(), b'old-kernel')
            self.assertEqual((fs / 'boot/vmlinuz-virt').read_bytes(), b'new-kernel')
            self.assertEqual(set(receipt), {'version', 'nodeId', 'requestId', 'identityHash', 'originalBootId', 'bootId', 'architecture', 'recipe', 'prepareHash', 'phase', 'plan'})
            self.assertNotEqual(request['prepareHash'], module.ZERO)
            installing = [args for args in commands if 'upgrade' in args and '--simulate' not in args]
            self.assertEqual(len(installing), 1)
            self.assertIn('--no-network', installing[0]); self.assertIn('--no-scripts', installing[0]); self.assertIn('--no-commit-hooks', installing[0])
            self.assertEqual(installing[0].count('--no-scripts'), 1)
            self.assertEqual(installing[0].count('--no-commit-hooks'), 1)

    def test_durable_barrier_lost_launch_reply_and_original_request_single_dispatch(self):
        stack, root, _, value, current_boot, running, _, _, put = self.fixture()
        with stack:
            request, _ = self.prepared(value)
            launches = []
            def start(args, **kwargs):
                launches.append((args, kwargs))
                state = json.loads((root / 'kernel-maintenance.json').read_text())
                self.assertEqual(state['phase'], 'reboot-intent')
                self.assertIsNotNone(state['reboot'])
                raise OSError('fixture lost launch reply')
            with patch.object(module.subprocess, 'Popen', side_effect=start):
                with self.assertRaises(OSError):
                    module.execute({**request, 'action': 'reboot'})
                for _ in range(3):
                    self.assertEqual(module.execute({**request, 'action': 'reboot'})['phase'], 'reboot-intent')
                current_boot[0] = str(uuid.uuid4()); running[0] = '6.12.118-0-virt'
                put('/proc/sys/kernel/osrelease', running[0].encode())
                self.assertEqual(module.execute({**request, 'action': 'verify'})['phase'], 'activated')
                self.assertEqual(module.execute({**request, 'action': 'verify'})['phase'], 'activated')
            self.assertEqual(len(launches), 1); self.assertEqual(launches[0][0], ['/sbin/reboot']); self.assertIn('pass_fds', launches[0][1])

    def test_root_refuses_candidate_or_unknown_boot_as_rollback_authority(self):
        stack, _, _, value, current_boot, running, _, _, _ = self.fixture()
        with stack:
            request, _ = self.prepared(value)
            with patch.object(module.subprocess, 'Popen', return_value=object()):
                module.execute({**request, 'action': 'reboot'})
            with self.assertRaisesRegex(ValueError, 'ROLLBACK_BOOT_UNCONFIRMED'):
                module.execute({**request, 'action': 'rollback'})
            current_boot[0] = str(uuid.uuid4()); running[0] = '6.12.118-0-virt'
            with self.assertRaisesRegex(ValueError, 'ROLLBACK_BOOT_UNCONFIRMED'):
                module.execute({**request, 'action': 'rollback'})

    def test_before_barrier_rollback_preserves_new_package_and_restores_old_boot(self):
        stack, root, fs, value, _, _, inventory, commands, _ = self.fixture()
        with stack:
            request, _ = self.prepared(value)
            rolled = module.execute({**request, 'action': 'rollback'})
            self.assertEqual(rolled['phase'], 'rolled-back')
            self.assertEqual((fs / 'boot/vmlinuz-virt').read_bytes(), b'old-kernel')
            self.assertEqual((fs / 'boot/initramfs-virt').read_bytes(), b'old-initramfs')
            self.assertEqual(inventory['linux-virt'], '6.12.118-r0')
            self.assertTrue((fs / 'lib/modules/6.12.118-0-virt/kernel/test.ko').exists())
            self.assertFalse(any('downgrade' in args for args in commands))
            self.assertIsNone(json.loads((root / 'kernel-maintenance.json').read_text())['reboot'])

    def test_unknown_file_cache_mode_identity_or_plan_bytes_are_preserved(self):
        for change in ['boot', 'cache', 'mode', 'identity', 'plan']:
            stack, root, fs, value, _, _, _, _, put = self.fixture()
            with stack:
                request, _ = self.prepared(value)
                if change == 'boot': put('/boot/vmlinuz-virt', b'unknown admin edit')
                elif change == 'cache':
                    state = json.loads((root / 'kernel-maintenance.json').read_text())
                    cache = module.run_directory(state) / 'cache/linux-virt-6.12.118-r0.apk'; cache.write_bytes(b'unknown cache edit')
                elif change == 'mode': (fs / 'boot/vmlinuz-virt').chmod(0o666)
                elif change == 'identity': put('/etc/incudal-onboarding-id', (str(uuid.uuid4()) + '\n').encode())
                else:
                    state = json.loads((root / 'kernel-maintenance.json').read_text()); state['transaction']['installed']['incus'] = '6.21-r0'
                    (root / 'kernel-maintenance.json').write_text(json.dumps(state))
                launches = []
                with patch.object(module.subprocess, 'Popen', side_effect=lambda *_a, **_kw: launches.append(True)), self.assertRaises((ValueError, AssertionError)):
                    module.execute({**request, 'action': 'reboot'})
                self.assertEqual(launches, [])
                if change == 'boot': self.assertEqual((fs / 'boot/vmlinuz-virt').read_bytes(), b'unknown admin edit')

    def test_interrupted_original_package_file_and_db_commit_orders(self):
        for registered_expected in [False, True]:
            stack, root, fs, value, _, _, inventory, commands, put = self.fixture()
            with stack:
                inspected = module.execute(value)
                request = {**value, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
                self.assertEqual(module.execute(request)['phase'], 'prepared-artifacts')
                if registered_expected:
                    inventory['linux-virt'] = '6.12.118-r0'; put('/lib/apk/db/installed', b'expected-db\n')
                else: put('/boot/vmlinuz-virt', b'new-kernel')
                self.assertEqual(module.execute(request)['phase'], 'packages-installed')
                self.assertEqual((fs / 'boot/vmlinuz-virt').read_bytes(), b'new-kernel')
                actual = [args for args in commands if '--simulate' not in args and ('fix' in args or 'upgrade' in args)]
                self.assertEqual(len(actual), 1); self.assertEqual('fix' in actual[0], registered_expected)
                self.assertEqual(actual[0][-1], 'linux-virt')
                action = 'fix' if registered_expected else 'upgrade'
                simulations = [args for args in commands if '--simulate' in args and action in args]
                self.assertEqual(len(simulations), 2)
                self.assertTrue(all(args[-1] == 'linux-virt' and '--no-network' in args for args in simulations))

    def test_apk3_rollback_reactivation_reinstalls_original_payload_without_new_version(self):
        stack, root, fs, value, current_boot, _, inventory, commands, put = self.fixture()
        with stack:
            original_request, _ = self.prepared(value)
            self.assertEqual(module.execute({**original_request, 'action': 'rollback'})['phase'], 'rolled-back')
            original_journal = (root / 'kernel-maintenance.json').read_bytes()
            self.assertEqual((fs / 'boot/vmlinuz-virt').read_bytes(), b'old-kernel')
            self.assertEqual(inventory['linux-virt'], '6.12.118-r0')
            world = b'linux-virt\nincus\nlxcfs\n'
            put('/etc/apk/world', world)
            fresh = {**value, 'bootId': current_boot[0], 'requestId': str(uuid.uuid4()), 'expectedPlanHash': None}
            inspected = module.execute(fresh)
            self.assertEqual(inspected['plan']['candidateVersion'], '6.12.118-r0')
            request = {**fresh, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
            offset, phases = len(commands), []
            for _ in range(4):
                result = module.execute(request)
                phases.append(result['phase'])
            self.assertEqual(phases, ['prepared-artifacts', 'packages-installed', 'boot-staged', 'prepared'])
            actual = [args for args in commands[offset:] if '--simulate' not in args and ('fix' in args or 'upgrade' in args)]
            self.assertEqual(len(actual), 1)
            self.assertIn('fix', actual[0]); self.assertEqual(actual[0][-1], 'linux-virt')
            self.assertIn('--no-network', actual[0]); self.assertNotIn('upgrade', actual[0])
            self.assertEqual(inventory, {'linux-virt': '6.12.118-r0', 'incus': '6.20-r0'})
            self.assertEqual((fs / 'etc/apk/world').read_bytes(), world)
            self.assertEqual((fs / 'boot/vmlinuz-virt').read_bytes(), b'new-kernel')
            self.assertEqual((root / ('kernel-maintenance-' + original_request['requestId'] + '.json')).read_bytes(), original_journal)
            state = module.strict_json((root / 'kernel-maintenance.json').read_bytes())
            self.assertTrue(state['transaction']['reactivation'])
            self.assertEqual(state['transaction']['expectedInstalled']['linux-virt'], '6.12.118-r0')

    def test_prejournal_backup_interruption_resumes_exact_original_plan(self):
        stack, root, _, value, _, _, _, _, _ = self.fixture()
        with stack:
            inspected = module.execute(value)
            request = {**value, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
            original = module.save_before
            with patch.object(module, 'save_before', side_effect=ValueError('HARDENING_KERNEL_STEP_TIMEOUT')):
                with self.assertRaises(ValueError): module.execute(request)
            self.assertFalse((root / 'kernel-maintenance.json').exists())
            self.assertEqual(module.execute(request)['phase'], 'prepared-artifacts')
            self.assertTrue((root / ('kernel-' + request['requestId']) / 'preparation.json').exists())

    def test_matching_apparmor_nonterminal_journal_blocks_kernel(self):
        stack, root, _, value, _, _, _, _, _ = self.fixture()
        with stack:
            original = self.saved_apparmor(value, 'reboot-intent', customers=[])
            module.atomic(root / 'maintenance.json', module.encoded(original))
            with self.assertRaisesRegex(ValueError, 'OTHER_MAINTENANCE'):
                module.execute(value)
            self.assertFalse((root / 'kernel-maintenance.json').exists())

    def test_terminal_status_and_next_patch_keep_original_evidence_and_current_world(self):
        stack, root, _, value, current_boot, running, inventory, _, put = self.fixture()
        with stack:
            request, _ = self.prepared(value)
            with patch.object(module.subprocess, 'Popen', return_value=object()):
                module.execute({**request, 'action': 'reboot'})
            current_boot[0] = str(uuid.uuid4()); running[0] = '6.12.118-0-virt'
            put('/proc/sys/kernel/osrelease', running[0].encode())
            module.execute({**request, 'action': 'verify'})
            before = (root / 'kernel-maintenance.json').read_bytes()
            put('/etc/apk/world', b'linux-virt\nincus\nlxcfs\n')
            fresh = {**value, 'action': 'status', 'bootId': current_boot[0], 'requestId': str(uuid.uuid4()), 'expectedPlanHash': 'd' * 64}
            self.assertEqual(module.execute(fresh)['phase'], 'absent')
            self.assertEqual((root / 'kernel-maintenance.json').read_bytes(), before, 'ordinary status neither archives nor mutates old terminal evidence')
            inspected = module.execute({**fresh, 'action': 'inspect', 'expectedPlanHash': None})
            self.assertEqual(inspected['plan']['candidateVersion'], '6.12.119-r0')
            next_request = {**fresh, 'action': 'prepare', 'expectedPlanHash': inspected['plan']['planHash']}
            for _ in range(4):
                result = module.execute(next_request)
            self.assertEqual(result['phase'], 'prepared')
            self.assertEqual(inventory['linux-virt'], '6.12.119-r0')
            archived = root / ('kernel-maintenance-' + request['requestId'] + '.json')
            self.assertEqual(archived.read_bytes(), before)

    def test_signed_outputs_cannot_be_replaced_in_a_still_discoverable_prepare_hash(self):
        stack, root, _, value, _, _, _, _, _ = self.fixture()
        with stack:
            self.prepared(value)
            state = json.loads((root / 'kernel-maintenance.json').read_text())
            state['transaction']['candidateArtifacts']['/boot/vmlinuz-virt']['sha256'] = 'c' * 64
            state['prepareHash'] = module.preparation_hash(state)
            with self.assertRaisesRegex(ValueError, 'PAYLOAD_INCOMPLETE'):
                module.validate_journal(state)

    def test_known_partial_copy_resumes_and_unknown_copy_bytes_remain(self):
        stack, root, _, _, _, _, _, _, _ = self.fixture()
        with stack:
            source = root / 'copy-source'; source.write_bytes(b'original signed payload'); source.chmod(0o600)
            target = root / 'copy-target'
            partial = root / '.kernel-copy-copy-target'; partial.write_bytes(b'original '); partial.chmod(0o600)
            module.copy_checked(source, target, module.file_proof(source))
            self.assertEqual(target.read_bytes(), source.read_bytes()); self.assertFalse(partial.exists())
            partial.write_bytes(b'unknown replacement'); partial.chmod(0o600)
            with self.assertRaisesRegex(ValueError, 'COPY_CHANGED'):
                module.copy_checked(source, target, module.file_proof(source))
            self.assertEqual(partial.read_bytes(), b'unknown replacement')

    def test_interrupted_old_module_restore_is_completed_from_original_backup(self):
        stack, _, fs, value, _, _, _, _, _ = self.fixture()
        with stack:
            request, _ = self.prepared(value)
            original = fs / 'lib/modules/6.12.100-0-virt/kernel/test.ko'
            original.unlink()
            temporary = original.parent / '.kernel-copy-test.ko'
            temporary.write_bytes(b'old-'); temporary.chmod(0o644)
            rolled = module.execute({**request, 'action': 'rollback'})
            self.assertEqual(rolled['phase'], 'rolled-back')
            self.assertEqual(original.read_bytes(), b'old-module'); self.assertFalse(temporary.exists())


if __name__ == '__main__':
    unittest.main()
