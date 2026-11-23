"""Security patch planner regression; no package or service mutations."""
import importlib.util,pathlib,sys,types,unittest,tempfile,os
from unittest.mock import patch
if sys.platform=='win32':sys.modules.setdefault('fcntl',types.SimpleNamespace())
spec=importlib.util.spec_from_file_location('inventory',pathlib.Path(__file__).with_name('system-security-inventory.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class Plans(unittest.TestCase):
    def test_distro_inventory_covers_shared_libc_clock_and_runtime_helpers(self):
        for targets in [module.ALPINE,module.DEBIAN]:
            self.assertEqual(len(targets),len(set(targets)),'duplicate distro package query')
        for package in ['musl','musl-utils','chrony','chrony-openrc','ca-certificates','fuse3-libs','lvm2-libs','device-mapper-libs','tar','gzip','xz','rsync','libnftnl','libmnl']:
            self.assertIn(package,module.ALPINE)
        for package in ['libc6','libc-bin','chrony','libfuse3-3','libfuse3-4','libnftnl11','libmnl0','tar','gzip','xz-utils','rsync','libidn2-0']:
            self.assertIn(package,module.DEBIAN)
    def test_complete_debian_inventory_distinguishes_architecture(self):
        output='libssl3\tamd64\tinstalled\t3.5.9-1\nlibssl3\ti386\tinstalled\t3.5.7-1\nremoved\tall\tconfig-files\t1.0\n'
        with patch.object(module,'command',return_value=output):
            self.assertEqual(module.debian_installed_packages(),{'libssl3:amd64':'3.5.9-1','libssl3:i386':'3.5.7-1'})
        for output in ['wrong', 'libssl3\tamd64\tinstalled\t3.5.9-1\nlibssl3\tamd64\tinstalled\t3.5.7-1']:
            with patch.object(module,'command',return_value=output),self.assertRaises(ValueError):module.debian_installed_packages()
    def test_running_alpine_kernel_exact_version_and_revision(self):
        self.assertFalse(module.alpine_kernel_replaced('6.12.1-0-virt',{'linux-virt':'6.12.1-r0'}))
        for version in ['6.12.10-r0','6.12.1-r1','unknown']:
            self.assertTrue(module.alpine_kernel_replaced('6.12.1-0-virt',{'linux-virt':version}))
        self.assertFalse(module.alpine_kernel_replaced('6.12.1-0-virt',{'linux-lts':'6.18.2-r1'}))
        self.assertFalse(module.alpine_kernel_replaced('6.12.1-1-lts',{'linux-lts':'6.12.1-r1','linux-virt':'6.18.2-r0'}))
    @unittest.skipUnless(hasattr(os,'geteuid') and os.geteuid()==0,'requires Linux root and flock')
    def test_timer_preserves_receipt_during_maintenance(self):
        real_open=os.open
        with tempfile.TemporaryDirectory(dir='/root')as folder:
            lock=pathlib.Path(folder)/'operation.lock';lock.touch(mode=0o600)
            held=os.open(lock,os.O_RDWR)
            module.fcntl.flock(held,module.fcntl.LOCK_EX|module.fcntl.LOCK_NB)
            def opened(path,*args,**kwargs):return real_open(lock if str(path)=='/var/lib/incudal-platform-operation.lock'else path,*args,**kwargs)
            try:
                with patch.object(module.os,'open',side_effect=opened),patch.object(module,'inventory')as inspect,patch.object(module,'persist')as persist:
                    module.record_inventory();inspect.assert_not_called();persist.assert_not_called()
            finally:os.close(held)
    def test_activation_requires_exact_packages_and_loaded_code(self):
        value={'packages':{'nginx':'1.26.3-3+deb13u11'},'restartRequired':False,'loadedCode':{'complete':True,'allHostProcesses':True,'processes':[]}}
        pending=['nginx=1.26.3-3+deb13u11']
        self.assertTrue(module.activation_verified(value,pending))
        for delta in [{'restartRequired':True},{'loadedCode':{'complete':True,'allHostProcesses':False,'processes':[]}},{'loadedCode':{'complete':False,'processes':[]}},{'loadedCode':{'complete':True,'processes':[{'pid':12,'service':'nginx','replacedMappings':1}]}},{'packages':{'nginx':'1.26.3-3+deb13u10'}}]:
            self.assertFalse(module.activation_verified({**value,**delta},pending))
    @unittest.skipUnless(hasattr(os,'geteuid') and os.geteuid()==0,'requires disposable Linux root and private receipt directory')
    def test_completed_activation_survives_refresh_and_reverification(self):
        from unittest.mock import patch
        real_path=module.pathlib.Path
        with tempfile.TemporaryDirectory(dir='/root')as folder:
            root=real_path(folder);status=root/'status.json'
            current={'version':1,'checkedAt':'2026-11-23T00:00:00Z','packages':{'nginx':'1.26.3'},'restartRequired':False,
                'loadedCode':{'complete':True,'allHostProcesses':True,'processes':[]}}
            receipt={'packages':['nginx=1.26.3'],'checkedAt':current['checkedAt'],'bootId':real_path('/proc/sys/kernel/random/boot_id').read_text().strip()}
            status.write_text(__import__('json').dumps({'activationReceipt':receipt,'activationRequired':[],'patchState':'activated'}));status.chmod(0o600)
            with patch.object(module.pathlib,'Path',side_effect=lambda value:root if str(value)=='/var/lib/incudal-system-security'else real_path(value)):
                value={**current};module.persist(value,verify_activation=True)
                self.assertEqual(value['patchState'],'activated');self.assertEqual(value['activationRequired'],[])
                value={'version':1};module.persist(value)
                self.assertEqual(value['patchState'],'activated');self.assertEqual(value['activationReceipt'],receipt)
                for delta in [{'restartRequired':True},{'packages':{'nginx':'1.26.2'}},{'loadedCode':{'complete':False,'allHostProcesses':True,'processes':[]}},
                    {'loadedCode':{'complete':True,'allHostProcesses':True,'processes':[{'pid':12,'service':'nginx','replacedMappings':1}]}}]:
                    value={**current,**delta};module.persist(value,verify_activation=True)
                    self.assertEqual(value['patchState'],'installed-activation-required')
                    self.assertEqual(value['activationRequired'],['nginx=1.26.3'])
                    self.assertEqual(value['activationReceipt'],receipt,'failed verification retains the earlier historical receipt')
                    value={**current};module.persist(value,verify_activation=True)
                    self.assertEqual(value['patchState'],'activated');self.assertEqual(value['activationRequired'],[])
    def test_failed_query_receipt_redacts_exception(self):
        value=module.failure_receipt(ValueError('SYSTEM_SECURITY_CHECK_FAILED credential-internal-data'))
        self.assertEqual(value['error'],'SYSTEM_SECURITY_CHECK_FAILED')
        self.assertEqual(value['patchState'],'failed');self.assertIn('checkedAt',value)
        self.assertEqual(module.failure_receipt(ValueError('SYSTEM_SECURITY_PLAN_REJECTED'))['error'],'SYSTEM_SECURITY_PLAN_REJECTED')
    @unittest.skipIf(sys.platform=='win32','actual Linux proc namespace links')
    def test_replaced_host_maps_exclude_guests_and_secrets(self):
        with tempfile.TemporaryDirectory()as folder:
            root=pathlib.Path(folder)
            for pid,name,namespace,maps in [(1,'systemd','pid:[1]','a-b rw-s 0 0 0 /dev/zero (deleted)\na-b r-xp 0 0 0 /memfd:jit (deleted)\n'),(2,'dnsmasq','pid:[1]','a-b r-xp 0 0 0 /usr/lib/private-secret.so (deleted)\n'),(3,'dnsmasq','pid:[2]','a-b r-xp 0 0 0 /usr/lib/guest.so (deleted)\n'),(4,'unknown','pid:[1]','a-b r-xp 0 0 0 /private (deleted)\n')]:
                path=root/str(pid);(path/'ns').mkdir(parents=True);(path/'ns/pid').symlink_to(namespace)
                (path/'comm').write_text(name);(path/'maps').write_text(maps)
            result=module.replaced_host_mappings(root)
            self.assertTrue(result['complete']);self.assertEqual(result['checkedProcesses'],2)
            self.assertEqual(result['processes'],[{'pid':2,'service':'dnsmasq','replacedMappings':1}])
            self.assertNotIn('secret',str(result));self.assertNotIn('guest',str(result))
            full=module.replaced_host_mappings(root,all_host=True)
            self.assertTrue(full['allHostProcesses']);self.assertEqual(full['checkedProcesses'],3)
            self.assertEqual(full['processes'][-1],{'pid':4,'service':'other','replacedMappings':1})
    def test_inventory_and_noop_preserve_activation(self):
        previous={'activationRequired':['nginx=1.26.3-3+deb13u11']}
        for current in [{'version':1},{'patchState':'current','patchPlan':[]},{'patchState':'failed','error':'SYSTEM_SECURITY_PATCH_NOT_CONFIRMED'}]:
            result=module.preserve_activation(current,previous)
            self.assertEqual(result['activationRequired'],previous['activationRequired'])
            self.assertEqual(result['patchState'],'failed'if current.get('error')else'installed-activation-required')
        result=module.preserve_activation({'patchState':'installed-activation-required','patchPlan':['libssl3=3.5.9-1']},previous)
        self.assertEqual(result['activationRequired'],['libssl3=3.5.9-1','nginx=1.26.3-3+deb13u11'])
        result=module.preserve_activation({'patchState':'installed-activation-required','patchPlan':['nginx=1.26.3-3+deb13u12']},previous)
        self.assertEqual(result['activationRequired'],['nginx=1.26.3-3+deb13u12'])
        result=module.preserve_activation({'patchState':'prepared','patchPlan':['nginx=1.26.3-3+deb13u12']},previous)
        self.assertEqual(result['activationRequired'],['nginx=1.26.3-3+deb13u12']);self.assertEqual(result['patchState'],'prepared')
        for pending in ['nginx', ['nginx=1\ncommand'], ['nginx=1']*257]:
            with self.assertRaises(ValueError):module.preserve_activation({}, {'activationRequired':pending})
        for plan in ['nginx', ['nginx=1\ncommand']]:
            with self.assertRaises(ValueError):module.preserve_activation({'patchState':'installed-activation-required','patchPlan':plan},{})
    @unittest.skipUnless(hasattr(os,'geteuid') and os.geteuid()==0,'requires disposable Linux root and actual policy file permissions')
    def test_interrupted_policy_and_admin_protection(self):
        with tempfile.TemporaryDirectory() as folder:
            policy=pathlib.Path(folder)/'policy';receipt=pathlib.Path(folder)/'receipt'
            module.prepare_service_policy(policy,receipt)
            self.assertTrue(policy.exists())
            module.clean_service_policy(policy,receipt)
            self.assertFalse(policy.exists());self.assertFalse(receipt.exists())
            module.prepare_service_policy(policy,receipt)
            policy.write_text('#!/bin/sh\nexit 0\n')
            with self.assertRaises(ValueError):module.clean_service_policy(policy,receipt)
            self.assertTrue(policy.exists());self.assertTrue(receipt.exists())
    def test_patch_only(self):
        with patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)) as compare:
            result=module.patch_plan('Inst nginx [1.26.3-3+deb13u10] (1.26.3-3+deb13u11 Debian:13/stable [arm64])',{'nginx':'1.26.3-3+deb13u10'},{'nginx'})
            self.assertEqual(compare.call_args.args[0],['dpkg','--compare-versions','1.26.3-3+deb13u11','gt','1.26.3-3+deb13u10'])
        self.assertEqual(result,['nginx=1.26.3-3+deb13u11'])
        with patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)):
            self.assertEqual(module.patch_plan('Inst ca-certificates [20261020] (20261120 Debian:13/stable [all])',{'ca-certificates':'20261020'},{'ca-certificates'}),['ca-certificates=20261120'])
    def test_refused(self):
        with patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)):
            for text in ['Inst nginx [1.26.3] (2.0 Debian:stable [arm64])','Inst new (1.0 Debian:stable [arm64])','Remv nginx','Inst nginx [1.26.2] (1.26.4 Debian:stable [arm64])','Inst nginx [1.26.3] (1.26.4 Debian:stable [arm64])\nInst unrelated [1.0] (1.1 Debian:stable [arm64])','Inst nginx [1.26.3] (1.26.4 Debian:stable [arm64])\nInst nginx [1.26.3] (1.26.5 Debian:stable [arm64])']:
                with self.subTest(text=text),self.assertRaises(ValueError):module.patch_plan(text,{'nginx':'1.26.3'},{'nginx'})
    def test_downgrade_same_major(self):
        with patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=1)),self.assertRaises(ValueError):
            module.patch_plan('Inst nginx [1.26.3] (1.26.2 Debian:stable [arm64])',{'nginx':'1.26.3'},{'nginx'})
    def test_real_apt_dependency_annotation(self):
        with patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)):
            self.assertEqual(module.patch_plan('Inst libsystemd0:amd64 [255.4-1ubuntu8.18] (255.4-1ubuntu8.19 Ubuntu:24.04/noble-updates [amd64]) [systemd:amd64 ]',{'libsystemd0':'255.4-1ubuntu8.18'},{'libsystemd0'}),['libsystemd0=255.4-1ubuntu8.19'])

if __name__=='__main__':unittest.main()
