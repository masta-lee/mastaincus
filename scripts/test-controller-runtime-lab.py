"""Check the disposable controller's native network JSON contract."""

import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    'controller_runtime_lab', Path(__file__).with_name('controller-runtime-lab.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


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


if __name__ == '__main__':
    unittest.main()
