#!/usr/bin/env python3
"""Fixed boot recipe fixtures. Does not claim native reboot acceptance."""
import importlib.util
import copy
import json
import os
import tempfile
from contextlib import ExitStack
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch
if os.name=='nt':sys.modules.setdefault('fcntl',types.SimpleNamespace(LOCK_EX=2,LOCK_NB=4,flock=lambda *_:None))
source_path=Path(__file__).parents[1]/'server/templates/host-security-maintenance.py'
if not source_path.exists():source_path=Path(__file__).with_name('host-security-maintenance.py')
spec=importlib.util.spec_from_file_location('host_maintenance',source_path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class MaintenanceTests(unittest.TestCase):
    def test_cross_recipe_reader_validates_complete_historical_terminal(self):
        stack,root,config,before,value,calls,_,_=self.fixture()
        with stack:
            module.execute(value)
            path=root/'maintenance.json';state=json.loads(path.read_text());state['phase']='customers-restored'
            path.write_text(json.dumps(state));original=path.read_bytes();commands=len(calls)
            target={**value,'recipe':'alpine-kernel-patch-v1','requestId':'44444444-4444-4444-8444-444444444444',
                'bootId':'55555555-5555-4555-8555-555555555555'}
            self.assertIsNone(module.assert_apparmor_idle(target))
            self.assertEqual(path.read_bytes(),original);self.assertEqual(len(calls),commands)
            invalid=[]
            for delta in [{'version':True},{'customerBoot':None},{'runlevelBefore':1},{'bootMode':True},
                          {'prepareHash':'0'*64},{'dependencyPlan':None},{'unknown':'field'}]:
                invalid.append({**copy.deepcopy(state),**delta})
            null_defaults=copy.deepcopy(state);null_defaults['identity']['recipe']=module.GRUB_RECIPE;null_defaults['grubDefaults']=None
            null_defaults['prepareHash']=module.digest(json.dumps([null_defaults['identity'],state['beforeHash'],state['afterHash'],state['runlevelBefore'],state['bootMode'],None],sort_keys=True).encode())
            invalid.append(null_defaults)
            for damaged in invalid:
                path.write_text(json.dumps(damaged));raw=path.read_bytes()
                with self.assertRaises(ValueError):module.assert_apparmor_idle(target)
                self.assertEqual(path.read_bytes(),raw);self.assertEqual(len(calls),commands)
            path.write_bytes(original)
            for delta in [{'nodeId':'66666666-6666-4666-8666-666666666666'},{'identityHash':'b'*64},{'architecture':'x86_64'}]:
                with self.assertRaisesRegex(ValueError,'OTHER_JOURNAL_UNKNOWN'):module.assert_apparmor_idle({**target,**delta})
                self.assertEqual(path.read_bytes(),original)

    def test_malformed_existing_journals_are_preserved_before_any_write(self):
        for data in [b'{}',b'[]',b'null',b'0',b'{"version":1,"version":1}',b'{"identity":{"phase":"first","phase":"last"}}']:
            stack,root,config,before,value,calls,_,_=self.fixture()
            with stack:
                journal=root/'maintenance.json';journal.write_bytes(data)
                with self.assertRaises(ValueError):module.execute(value)
                self.assertEqual(journal.read_bytes(),data)
                self.assertEqual(config.read_bytes(),before)
                self.assertEqual(calls,[])

    def test_kernel_guard_owns_shared_lock_before_legacy_preparation(self):
        stack,root,config,before,value,calls,_,_=self.fixture()
        with stack:
            journal=root/'kernel-maintenance.json';journal.write_bytes(b'original kernel evidence')
            with self.assertRaisesRegex(ValueError,'OTHER_JOURNAL_UNKNOWN'):module.execute(value)
            self.assertEqual(config.read_bytes(),before);self.assertEqual(calls,[])
            def refused(request):
                self.assertEqual(request,value)
                self.assertTrue((root/'maintenance.lock').exists())
                raise ValueError('HARDENING_KERNEL_OTHER_MAINTENANCE')
            with patch.object(module,'KERNEL_JOURNAL_GUARD',side_effect=refused):
                with self.assertRaisesRegex(ValueError,'OTHER_MAINTENANCE'):module.execute(value)
            self.assertEqual(journal.read_bytes(),b'original kernel evidence');self.assertEqual(config.read_bytes(),before)
            with patch.object(module,'KERNEL_JOURNAL_GUARD',return_value=None) as accepted:
                self.assertEqual(module.execute(value)['phase'],'prepared')
                accepted.assert_called_once_with(value)
            self.assertEqual(journal.read_bytes(),b'original kernel evidence')

    def test_unknown_journal_presence_does_not_become_permission(self):
        for name in ['maintenance.json','kernel-maintenance.json']:
            for error in [PermissionError('denied'),OSError('unreadable')]:
                stack,root,config,before,value,calls,_,_=self.fixture()
                with stack:
                    original=Path.lstat
                    def failed(path,*args,**kwargs):
                        if path==root/name:raise error
                        return original(path,*args,**kwargs)
                    with patch.object(Path,'lstat',failed),self.assertRaises(ValueError):module.execute(value)
                    self.assertEqual(config.read_bytes(),before);self.assertEqual(calls,[])

    def fixture(self, initial_enabled=False):
        stack=ExitStack();directory=stack.enter_context(tempfile.TemporaryDirectory());root=Path(directory)
        original=Path;boot_id='33333333-3333-4333-8333-333333333333';calls=[];enabled=[initial_enabled];boot_value=[boot_id]
        config=root/'extlinux.conf';before=b'LABEL stable\n KERNEL /boot/vmlinuz-lts\n APPEND root=UUID=original console=ttyS0\n';config.write_bytes(before);config.chmod(0o644)
        def mapped(value):return config if str(value)=='/boot/extlinux.conf' else original(value)
        def command(args, **_):
            calls.append(args)
            if args[:2]==['rc-update','add']:enabled[0]=True
            elif args[:2]==['rc-update','del']:enabled[0]=False
            else:self.fail('Unexpected fixture command')
            return b''
        original_open=os.open
        def opened(path,flags,*args,**kwargs):
            if os.name=='nt' and str(path)==str(root):return original_open(root/'maintenance.lock',os.O_RDWR)
            return original_open(path,flags,*args,**kwargs)
        for name,value in [('ROOT',root),('Path',mapped),('identity',lambda _:None),('environment',lambda *_:None),
            ('protected',lambda *_:None),('boot',lambda:boot_value[0]),('runlevel_enabled',lambda:enabled[0]),('empty_remote',lambda:None),('command',command)]:
            stack.enter_context(patch.object(module,name,value))
        stack.enter_context(patch.object(module.os,'getuid',return_value=0,create=True))
        for name in ['O_NOFOLLOW','O_DIRECTORY']:stack.enter_context(patch.object(os,name,getattr(os,name,0),create=True))
        stack.enter_context(patch.object(os,'fchmod',getattr(os,'fchmod',lambda *_:None),create=True))
        stack.enter_context(patch.object(os,'open',side_effect=opened))
        if os.name=='nt':
            original_stat=original.stat
            def file_stat(path,*args,**kwargs):
                info=original_stat(path,*args,**kwargs)
                if path==config:return types.SimpleNamespace(st_mode=0o100644)
                return info
            # NT chmod cannot represent Unix modes; native permissions remain
            # a separate gate. Only the fixture boot file's mode is adapted.
            stack.enter_context(patch.object(original,'stat',file_stat))
        stack.enter_context(patch.object(module.time,'time',return_value=1))
        value={'action':'prepare','nodeId':'11111111-1111-4111-8111-111111111111','requestId':'22222222-2222-4222-8222-222222222222',
            'identityHash':'a'*64,'bootId':boot_id,'prepareHash':'0'*64,'recipe':module.RECIPE,'architecture':'aarch64','expiresAt':59000,'customers':[]}
        return stack,root,config,before,value,calls,enabled,boot_value
    def test_actual_atomic_journal_single_dispatch_lost_response_and_boot(self):
        stack,root,config,before,value,calls,enabled,boot_value=self.fixture()
        with stack:
            first=module.execute(value);self.assertEqual(first['phase'],'prepared');self.assertTrue(enabled[0])
            self.assertNotEqual(config.read_bytes(),before);self.assertEqual(module.execute(value),first)
            request={**value,'prepareHash':first['prepareHash']}
            launches=[]
            def start(args,**kwargs):
                launches.append((args,kwargs))
                self.assertEqual(json.loads((root/'maintenance.json').read_text())['phase'],'reboot-intent','durable barrier precedes launch')
                raise OSError('simulated lost launch result')
            with patch.object(module.subprocess,'Popen',side_effect=start):
                with self.assertRaises(OSError):module.execute({**request,'action':'reboot'})
                self.assertEqual(module.execute({**request,'action':'status'})['phase'],'reboot-intent')
                module.execute({**request,'action':'reboot'})
                boot_value[0]='44444444-4444-4444-8444-444444444444';module.execute({**request,'action':'reboot'})
            self.assertEqual(len(launches),1);self.assertEqual(launches[0][0],['/sbin/reboot']);self.assertIn('pass_fds',launches[0][1])
            with self.assertRaisesRegex(ValueError,'JOURNAL'):module.execute({**request,'requestId':value['nodeId'],'action':'reboot'})
            self.assertEqual(calls,[['rc-update','add','apparmor','boot']])
    def test_interrupted_preparation_and_exact_conditional_rollback(self):
        for initial_enabled in [False,True]:
            stack,root,config,before,value,calls,enabled,_=self.fixture(initial_enabled)
            with stack:
                first=module.execute(value);request={**value,'prepareHash':first['prepareHash']}
                journal=root/'maintenance.json';state=json.loads(journal.read_text());state['phase']='preparing';journal.write_text(json.dumps(state))
                config.write_bytes(before);enabled[0]=initial_enabled
                module.execute(value);self.assertTrue(enabled[0]);self.assertEqual(config.read_bytes(),module.prepare_boot(before))
                config.write_bytes(b'other writer')
                with self.assertRaisesRegex(ValueError,'JOURNAL'):module.execute({**request,'action':'rollback'})
                self.assertEqual(config.read_bytes(),b'other writer')
                config.write_bytes(module.prepare_boot(before))
                rolled=module.execute({**request,'action':'rollback'})
                self.assertEqual(rolled['phase'],'rolled-back');self.assertEqual(config.read_bytes(),before)
                self.assertEqual(enabled[0],initial_enabled,'restore exactly the prior AppArmor boot runlevel')
                self.assertEqual(module.execute({**request,'action':'rollback'}),rolled,'lost rollback receipt is safely replayed')
    def test_empty_host_completion_is_durable_and_rejects_new_inventory(self):
        stack,root,config,before,value,calls,enabled,boot_value=self.fixture()
        with stack:
            first=module.execute(value);request={**value,'prepareHash':first['prepareHash']}
            with patch.object(module.subprocess,'Popen') as reboot:
                module.execute({**request,'action':'reboot'})
                boot_value[0]='44444444-4444-4444-8444-444444444444'
                with patch.object(module,'empty_remote',side_effect=ValueError('HARDENING_IDENTITY_CHANGED')):
                    with self.assertRaisesRegex(ValueError,'IDENTITY_CHANGED'):module.execute({**request,'action':'restore-customers'})
                self.assertEqual(json.loads((root/'maintenance.json').read_text())['phase'],'reboot-intent')
                restored=module.execute({**request,'action':'restore-customers'})
                self.assertEqual(restored['phase'],'customers-restored')
                self.assertEqual(module.execute({**request,'action':'status'}),restored)
                self.assertEqual(module.execute({**request,'action':'restore-customers'}),restored)
                module.execute({**request,'action':'reboot'})
                self.assertEqual(reboot.call_count,1,'completed empty-host receipt never dispatches a second reboot')
    def test_unknown_prepare_status_is_read_only(self):
        stack,root,config,before,value,calls,enabled,_=self.fixture()
        with stack:
            absent=module.execute({**value,'action':'status'})
            self.assertEqual(absent['phase'],'absent')
            self.assertEqual(absent['prepareHash'],'0'*64)
            self.assertFalse((root/'maintenance.json').exists())
            self.assertEqual(config.read_bytes(),before);self.assertEqual(calls,[])
            prepared=module.execute(value)
            journal=root/'maintenance.json';state=json.loads(journal.read_text());state['phase']='preparing';journal.write_text(json.dumps(state))
            count=len(calls)
            discovered=module.execute({**value,'action':'status'})
            self.assertEqual(discovered['phase'],'preparing')
            self.assertEqual(discovered['prepareHash'],prepared['prepareHash'])
            self.assertEqual(len(calls),count,'discovery must not finish preparation')
            with self.assertRaisesRegex(ValueError,'JOURNAL'):
                module.execute({**value,'action':'status','requestId':value['nodeId']})
    def test_reboot_expiry_during_baseline_blocks_durable_dispatch(self):
        stack,root,config,before,value,calls,enabled,boot_value=self.fixture()
        with stack:
            prepared=module.execute(value)
            request={**value,'action':'reboot','prepareHash':prepared['prepareHash']}
            actual_baseline=module.assert_customer_baseline
            clock=[1]
            def baseline(*args,**kwargs):
                actual_baseline(*args,**kwargs)
                clock[0]=60
            with patch.object(module.time,'time',side_effect=lambda:clock[0]), \
                patch.object(module,'assert_customer_baseline',side_effect=baseline), \
                patch.object(module.subprocess,'Popen') as reboot:
                with self.assertRaisesRegex(ValueError,'REQUEST_EXPIRED'):module.execute(request)
                reboot.assert_not_called()
                self.assertEqual(json.loads((root/'maintenance.json').read_text())['phase'],'prepared')
    def test_preparation_expiry_after_read_only_checks_has_no_system_write(self):
        stack,root,config,before,value,calls,enabled,_=self.fixture()
        with stack:
            clock=[1]
            def environment(*_):clock[0]=60
            with patch.object(module.time,'time',side_effect=lambda:clock[0]), \
                patch.object(module,'environment',side_effect=environment):
                with self.assertRaisesRegex(ValueError,'REQUEST_EXPIRED'):module.execute(value)
                self.assertEqual(config.read_bytes(),before)
                self.assertFalse(enabled[0]);self.assertEqual(calls,[])
    def test_new_boot_file_edit_during_preparation_is_never_overwritten(self):
        for action in ['prepare','rollback']:
            stack,root,config,before,value,calls,enabled,_=self.fixture()
            with stack:
                if action=='rollback':
                    prepared=module.execute(value)
                    value={**value,'action':action,'prepareHash':prepared['prepareHash']}
                original_command=module.command
                def command(args,**kwargs):
                    result=original_command(args,**kwargs)
                    config.write_bytes(b'new administrator boot configuration')
                    return result
                with patch.object(module,'command',side_effect=command):
                    with self.assertRaisesRegex(ValueError,'JOURNAL'):module.execute(value)
                    self.assertEqual(config.read_bytes(),b'new administrator boot configuration')

    def test_expiry_during_customer_read_blocks_configuration_put_and_resumes(self):
        stack,root,config,before,value,calls,enabled,_=self.fixture()
        customer={'name':'original','uuid':value['nodeId'],'attempt':value['requestId'],'state':'running','autostart':'true'}
        value={**value,'customers':[customer]}
        remote={'name':'original','type':'container','status':'Running','architecture':'aarch64','description':'original',
            'profiles':[],'ephemeral':False,'devices':{'root':{'type':'disk','path':'/','pool':'original'}},
            'config':{'volatile.uuid':customer['uuid'],'user.payincus.provisioning-attempt':customer['attempt'],
                'boot.autostart':'true','security.privileged':'false'}}
        clock=[1];expire=[True];writes=[]
        def api(method,path,body=None,etag=None):
            self.assertEqual(path,'/1.0/instances/original')
            if method=='GET':
                if expire[0] and (root/'maintenance.json').exists():clock[0]=60
                return {'type':'sync','metadata':json.loads(json.dumps(remote))},'revision'
            self.assertEqual(method,'PUT');self.assertEqual(etag,'revision')
            writes.append(body);remote['config']=body['config']
            return {'type':'sync','metadata':{}},'revision'
        def command(args,**kwargs):
            if args[:2]==['incus','list']:return json.dumps([remote]).encode()
            return self.fixture_command(args,calls,enabled)
        with stack,patch.object(module,'local_incus',side_effect=api),patch.object(module,'command',side_effect=command), \
            patch.object(module.time,'time',side_effect=lambda:clock[0]):
            with self.assertRaisesRegex(ValueError,'REQUEST_EXPIRED'):module.execute(value)
            self.assertEqual(writes,[],'a slow customer GET must not authorize a config PUT after expiry')
            self.assertEqual(config.read_bytes(),before)
            self.assertEqual(json.loads((root/'maintenance.json').read_text())['phase'],'preparing')
            clock[0]=1;expire[0]=False
            self.assertEqual(module.execute(value)['phase'],'prepared')
            self.assertEqual(len(writes),1,'a fresh bounded request resumes the same preparation')
    def test_rolled_back_preparation_can_resume_only_exact_original(self):
        stack,root,config,before,value,calls,enabled,_=self.fixture()
        with stack:
            prepared=module.execute(value)
            module.execute({**value,'action':'rollback','prepareHash':prepared['prepareHash']})
            with self.assertRaisesRegex(ValueError,'REMOTE_BUSY'):module.execute(value)
            module.time.time.return_value=122
            value['expiresAt']=180000
            config.write_bytes(b'new administrator configuration')
            with self.assertRaisesRegex(ValueError,'JOURNAL'):module.execute(value)
            self.assertEqual(config.read_bytes(),b'new administrator configuration')
            config.write_bytes(before)
            resumed=module.execute(value)
            self.assertEqual(resumed['phase'],'prepared')
            self.assertEqual(resumed['prepareHash'],prepared['prepareHash'])
    def test_fixed_boot_changes_preserve_root_network_and_other_bytes(self):
        before=b'DEFAULT stable\nTIMEOUT 20\nLABEL stable\n KERNEL /boot/vmlinuz-lts\n INITRD /boot/initramfs-lts\n APPEND root=UUID=original console=ttyS0 apparmor=0 lsm=landlock,lockdown,yama\n'
        after=module.prepare_boot(before)
        self.assertIn(b'root=UUID=original console=ttyS0',after)
        self.assertIn(b'lsm=landlock,lockdown,yama,apparmor',after)
        self.assertIn(b'apparmor=1 security=apparmor',after)
        self.assertTrue(after.startswith(before[:before.index(b' APPEND')]))
        self.assertEqual(module.prepare_boot(after),after)
        for extra in [b'LABEL alternate\n KERNEL /boot/other\n APPEND root=other\n',b' APPEND another\n']:
            with self.assertRaisesRegex(ValueError,'BOOT_LAYOUT'):module.prepare_boot(before+extra)
        for text in [before.replace(b'console=ttyS0',b'security=selinux'),before.replace(b'root=UUID=original',b'root="$OTHER"'),before.replace(b'\n',b'\r\n')]:
            with self.assertRaisesRegex(ValueError,'BOOT_LAYOUT'):module.prepare_boot(text)
    def test_request_no_arbitrary_action_or_paths(self):
        value={'action':'prepare','nodeId':'11111111-1111-4111-8111-111111111111','requestId':'22222222-2222-4222-8222-222222222222',
            'identityHash':'a'*64,'bootId':'33333333-3333-4333-8333-333333333333','prepareHash':None,
            'recipe':module.RECIPE,'architecture':'aarch64','expiresAt':11000,'customers':[]}
        with patch.object(module.time,'time',return_value=1):
            self.assertEqual(module.request(value),value)
            for delta in [{'script':'reboot'},{'path':'/etc/shadow'},{'action':'arbitrary'},{'expiresAt':True},{'architecture':'riscv64'},{'identityHash':'private'}]:
                with self.assertRaises(ValueError):module.request({**value,**delta})

    def test_grub_retains_kernel_root_and_persistent_defaults(self):
        defaults=b'GRUB_TIMEOUT=1\nGRUB_CMDLINE_LINUX_DEFAULT="modules=sd-mod,ext4 console=ttyS0 rootfstype=ext4"\nGRUB_DISABLE_RECOVERY=true\n'
        config=b'set default="0"\nmenuentry "Alpine" {\n linux /boot/vmlinuz-virt root=UUID=original ro modules=sd-mod,ext4 console=ttyS0\n initrd /boot/initramfs-virt\n}\n'
        changed=module.prepare_grub_config(config)
        self.assertIn(b'root=UUID=original ro modules=sd-mod,ext4 console=ttyS0',changed)
        self.assertIn(b'loadpin,safesetid,integrity,apparmor,bpf',changed)
        self.assertEqual(module.prepare_grub_config(changed),changed)
        after=module.prepare_grub_defaults(defaults)
        self.assertEqual(module.prepare_grub_defaults(after),after)
        self.assertTrue(after.endswith(b'GRUB_DISABLE_RECOVERY=true\n'))
        self.assertIn(b'apparmor=1 security=apparmor',after)
        for malformed in [config+config,config.replace(b'root=UUID=original',b'root=$unknown'),
            config.replace(b' ro ',b' security=selinux '),config.replace(b' ro ',b' apparmor=0 apparmor=1 '),config.replace(b' ro ',b' lsm=selinux '),config.replace(b'\n',b'\r\n')]:
            with self.assertRaisesRegex(ValueError,'BOOT_LAYOUT'):module.prepare_grub_config(malformed)
        for malformed in [defaults+defaults,defaults+b'GRUB_CMDLINE_LINUX="apparmor=0"\n',defaults.replace(b'console=ttyS0',b'console=$(malicious)')]:
            with self.assertRaisesRegex(ValueError,'BOOT_LAYOUT'):module.prepare_grub_defaults(malformed)

    def test_grub_defaults_conditional_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config=root/'grub';config.write_bytes(b'GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0"\n');before=config.read_bytes()
            original=Path
            original_stat=original.stat
            def file_stat(path,*args,**kwargs):
                if path==config:return types.SimpleNamespace(st_mode=0o100644)
                return original_stat(path,*args,**kwargs)
            with patch.object(module,'ROOT',root),patch.object(module,'protected',lambda *_:None),patch.object(module,'Path',side_effect=lambda p:config if p=='/etc/default/grub' else original(p)),patch.object(original,'stat',file_stat):
                saved={'beforeHash':module.digest(before),'afterHash':module.digest(module.prepare_grub_defaults(before)),'mode':0o644}
                (root/'grub-defaults.before').write_bytes(before)
                state={'grubDefaults':saved}
                module.grub_defaults_check(state)
                config.write_bytes(b'other writer')
                with self.assertRaisesRegex(ValueError,'JOURNAL'):module.grub_defaults_check(state)
                self.assertEqual(config.read_bytes(),b'other writer')
    def test_control_plane_target_no_reboot(self):
        value={'nodeId':'node','architecture':'aarch64'}
        with patch.object(Path,'read_text',return_value='node'),patch.object(module.os,'uname',return_value=types.SimpleNamespace(machine='aarch64'),create=True),patch.object(Path,'exists',side_effect=lambda:True):
            with self.assertRaisesRegex(ValueError,'CONTROL_PLANE'):module.identity(value)

    def test_grub_dependency_install_is_journaled_and_yields_before_boot_changes(self):
        stack,root,config,before,value,calls,enabled,_=self.fixture()
        config.write_bytes(b'menuentry "Alpine" {\n linux /boot/vmlinuz-virt root=UUID=original ro\n initrd /boot/initramfs-virt\n}\n')
        before=config.read_bytes();value={**value,'recipe':module.GRUB_RECIPE}
        install_calls=[]
        def install(fd,state,persist,allowed):
            allowed()
            self.assertTrue((root/'maintenance.json').exists())
            self.assertEqual(json.loads((root/'maintenance.json').read_text())['phase'],'preparing')
            self.assertEqual(config.read_bytes(),before,'no boot change during dependency transaction')
            self.assertFalse(enabled[0])
            install_calls.append(fd)
            if len(install_calls)==1:raise TimeoutError('lost package result')
            return len(install_calls)==2
        original_command=self.fixture_command
        def command(args,**_):
            if args[0]=='grub-script-check':return b''
            return original_command(args,calls,enabled)
        defaults={'beforeHash':module.digest(b'original grub defaults'),'afterHash':module.digest(b'prepared grub defaults'),'mode':0o644}
        with stack,patch.object(module,'boot_path',return_value=config),patch.object(module,'grub_defaults_state',return_value=defaults), \
            patch.object(module,'grub_defaults_check'),patch.object(module,'ensure_grub_tools',side_effect=install),patch.object(module,'command',side_effect=command):
            with self.assertRaises(TimeoutError):module.execute(value)
            pending=module.execute(value)
            self.assertEqual(pending['phase'],'preparing')
            self.assertEqual(config.read_bytes(),before)
            prepared=module.execute(value)
            self.assertEqual(prepared['phase'],'prepared')
            self.assertEqual(prepared['prepareHash'],pending['prepareHash'])
            self.assertIn(b'apparmor=1',config.read_bytes())
            rolled=module.execute({**value,'action':'rollback','prepareHash':prepared['prepareHash']})
            self.assertEqual(rolled['phase'],'rolled-back');self.assertEqual(config.read_bytes(),before)

    def test_dependency_plan_yields_pins_versions_and_rejects_changed_baseline(self):
        stack,root,_,_,_,_,_,_=self.fixture()
        (root/'maintenance.lock').touch()
        baseline=['incus-7.0.1-r2','kernel-6.18.58-r0',*[name+'-4.1.7-r1'for name in module.apparmor_packages('3.24')if name not in ['apparmor','apparmor-openrc']]]
        saved={};snapshots=[baseline.copy()]
        writes=[];ready=[False];persisted=[]
        world=['incus=7.0.1-r2\nlinux-lts\n']
        class FakePath:
            def __init__(self,value):self.value=str(value)
            def read_text(self):
                if self.value=='/etc/alpine-release':return '3.24.3'
                if self.value=='/sys/module/apparmor/parameters/enabled':return 'N'
                if self.value=='/proc/meminfo':return 'MemAvailable: 262144 kB\n'
                raise AssertionError(self.value)
            def iterdir(self):return []
        def run(args,**options):
            writes.append(args)
            self.assertIn('pass_fds',options)
            if args[-1]=='update':return types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
            if '--simulate' in args:
                self.assertEqual(options['timeout'],15)
                remaining=[name for name in ['apparmor','apparmor-openrc']if name+'-4.1.7-r1'not in snapshots[0]]
                return types.SimpleNamespace(returncode=0,stdout=''.join('Installing '+name+' (4.1.7-r1)\n'for name in remaining).encode(),stderr=b'')
            requested=args[args.index('add')+1:]
            self.assertTrue(requested);self.assertTrue(set(requested).issubset({'apparmor','apparmor-openrc'}))
            self.assertFalse(any('='in arg for arg in args),'installation does not persist exact version constraints')
            world[0]+='\n'.join(requested)+'\n'
            ready[0]=True
            snapshots[0]+=[name+'-4.1.7-r1'for name in requested]
            return types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
        # Keep this focused on the actual planner/installer, not the surrounding
        # boot fixture. Network simulation and installation must be separate.
        with stack,patch.object(module,'Path',FakePath),patch.object(module,'apparmor_tools_ready',side_effect=lambda:ready[0]), \
            patch.object(module,'installed_packages',side_effect=lambda:sorted(snapshots[0])), \
            patch.object(module.os,'statvfs',return_value=types.SimpleNamespace(f_flag=0,f_bavail=262144,f_frsize=4096,f_favail=4096),create=True), \
            patch.object(module.os,'ST_RDONLY',getattr(module.os,'ST_RDONLY',1),create=True), \
            patch.object(module,'read',side_effect=lambda *_:world[0].encode()), \
            patch.object(module.subprocess,'run',side_effect=run):
            self.assertTrue(module.ensure_grub_tools(9,saved,lambda:persisted.append(json.loads(json.dumps(saved)))))
            self.assertEqual(len(writes),2,'signed index and simulation yield without installation')
            self.assertEqual(persisted[0],saved)
            self.assertEqual(saved['dependencyPlan']['worldBefore'],world[0])
            original_world=world[0]
            for changed in [original_world.replace('incus=7.0.1-r2','incus'),original_world+'unrelated\n',original_world+'apparmor=4.1.7-r1\n']:
                world[0]=changed
                with self.assertRaisesRegex(ValueError,'PACKAGE_BUSY'):module.ensure_grub_tools(9,saved,lambda:None)
                self.assertEqual(len(writes),2,'world drift cannot reach simulation or installation')
                self.assertEqual(world[0],changed,'administrator changes are never overwritten')
            world[0]=original_world
            snapshots[0]=['incus-7.0.2-r0','kernel-6.18.58-r0']
            with self.assertRaisesRegex(ValueError,'PACKAGE_BUSY'):module.ensure_grub_tools(9,saved,lambda:None)
            self.assertEqual(len(writes),2,'changed package baseline never reaches install')
            snapshots[0]=saved['dependencyPlan']['installed'].copy()
            checks=[]
            def expiry_before_install():
                checks.append(True)
                # The repositories write is allowed, then the package
                # baseline lookup consumes the remaining request lifetime.
                if len(checks)==2:raise ValueError('HARDENING_REQUEST_EXPIRED')
            with self.assertRaisesRegex(ValueError,'REQUEST_EXPIRED'):
                module.ensure_grub_tools(9,saved,lambda:None,expiry_before_install)
            self.assertEqual(len(writes),2,'expired preparation cannot start the real package install')
            self.assertEqual(saved['dependencyPlan']['phase'],'planned')
            def partial_install(args,**options):
                if 'add'in args and '--simulate'not in args:
                    writes.append(args);snapshots[0].append('apparmor-4.1.7-r1');world[0]+='apparmor\n'
                    raise TimeoutError('lost partial install response')
                return run(args,**options)
            with patch.object(module.subprocess,'run',side_effect=partial_install),self.assertRaises(TimeoutError):
                module.ensure_grub_tools(9,saved,lambda:None)
            self.assertEqual(saved['dependencyPlan']['phase'],'planned')
            partial_world=world[0];world[0]+='libapparmor\n'
            with self.assertRaisesRegex(ValueError,'PACKAGE_BUSY'):module.ensure_grub_tools(9,saved,lambda:None)
            self.assertEqual(len(writes),4,'partial repair rejects unapproved dependencies in world')
            world[0]=partial_world
            self.assertTrue(module.ensure_grub_tools(9,saved,lambda:None))
            self.assertEqual(len(writes),6)
            self.assertEqual(writes[-1][-1],'apparmor-openrc','resume installs only the missing approved package')
            self.assertEqual(saved['dependencyPlan']['worldAfter'],world[0])
            installed_world=world[0];world[0]+='unrelated\n'
            with self.assertRaisesRegex(ValueError,'PACKAGE_BUSY'):module.ensure_grub_tools(9,saved,lambda:None)
            saved['dependencyPlan']['worldAfter']=world[0]
            with self.assertRaisesRegex(ValueError,'JOURNAL'):module.ensure_grub_tools(9,saved,lambda:None)
            world[0]=installed_world
            del saved['dependencyPlan']['worldAfter']
            with patch.object(module,'command',return_value=b'') as compile_rules:
                self.assertTrue(module.ensure_grub_tools(9,saved,lambda:None),'compile yields separately after install')
                self.assertEqual(saved['dependencyPlan']['worldAfter'],world[0],'lost receipt reconstructs only the validated original world change')
                self.assertEqual(compile_rules.call_count,1)
                self.assertFalse(module.ensure_grub_tools(9,saved,lambda:None),'verified tools avoid repeating install or compile')
                self.assertEqual(compile_rules.call_count,1)
            legacy=json.loads(json.dumps(saved));del legacy['dependencyPlan']['worldBefore'];del legacy['dependencyPlan']['worldAfter']
            self.assertFalse(module.ensure_grub_tools(9,legacy,lambda:None),'legacy completed plans remain compatible')
            self.assertNotIn('worldBefore',legacy['dependencyPlan'],'missing historical ownership is never invented')
            snapshots[0].append('unexpected-1.0-r0')
            with self.assertRaisesRegex(ValueError,'PACKAGE_BUSY'):module.ensure_grub_tools(9,saved,lambda:None)
            snapshots[0]=saved['dependencyPlan']['installed']+['apparmor-4.1.7-r1']
            with self.assertRaisesRegex(ValueError,'TOOLS_REQUIRED'):module.ensure_grub_tools(9,saved,lambda:None)
            snapshots[0]=baseline.copy();ready[0]=False;world[0]=original_world
            for step in ['initial','resume']:
                race_state={}if step=='initial'else {'dependencyPlan':{'packages':['apparmor=4.1.7-r1','apparmor-openrc=4.1.7-r1'],'installed':sorted(baseline),'phase':'planned','worldBefore':original_world}}
                def changed_during_simulation(args,**options):
                    result=run(args,**options)
                    if '--simulate'in args:world[0]+='administrator-package\n'
                    return result
                with patch.object(module.subprocess,'run',side_effect=changed_during_simulation),self.assertRaisesRegex(ValueError,'PACKAGE_BUSY'):
                    module.ensure_grub_tools(9,race_state,lambda:None)
                self.assertNotIn('worldAfter',race_state.get('dependencyPlan',{}))
                self.assertTrue(world[0].endswith('administrator-package\n'))
                world[0]=original_world

    def test_apparmor_world_limits_and_encoding(self):
        for invalid in [b'pkg\x00\n',b'pkg\r\n',b'p'*65537]:
            with patch.object(module,'read',return_value=invalid),self.assertRaisesRegex(ValueError,'PACKAGE_BUSY'):
                module.apparmor_world()
        with patch.object(module,'read',return_value=b'pkg=1.0-r1\n'):
            self.assertEqual(module.apparmor_world(),'pkg=1.0-r1\n')

    def test_apparmor_transaction_preserves_admin_world_and_complete_plan(self):
        world='incus=7.0.1-r2\nlinux-lts\n'
        self.assertTrue(module.apparmor_world_preserved(world,world+'apparmor\napparmor-openrc\n',['apparmor','apparmor-openrc']))
        for after in [world+'apparmor=4.1.7-r1\n',world+'apparmor\nlibapparmor\n','incus\nlinux-lts\napparmor\n']:
            self.assertFalse(module.apparmor_world_preserved(world,after,['apparmor']))
        self.assertEqual(module.apparmor_install_plan('Installing apparmor (4.1.7-r1)\nInstalling libapparmor (4.1.7-r1)'),['apparmor=4.1.7-r1','libapparmor=4.1.7-r1'])
        for plan in ['Installing apparmor (unknown)','Installing apparmor (4.1.7-r1)\nInstalling apparmor (4.1.7-r1)','Upgrading incus (7.0.1-r2 -> 7.6.0-r0)','Installing apparmor (4.1.7-r1)\nRemoving incus']:
            with self.assertRaises(ValueError):module.apparmor_install_plan(plan)

    @unittest.skipUnless(hasattr(os,'geteuid')and os.geteuid()==0,'native root-owned cache paths')
    def test_actual_apparmor_cache_cleanup_preserves_untrusted_entries(self):
        with tempfile.TemporaryDirectory(dir='/root')as folder:
            root=Path(folder);cache=root/'cache';cache.mkdir(mode=0o700)
            (cache/'signed-index').write_bytes(b'fixture')
            module.clean_apparmor_package_cache(cache)
            self.assertFalse(cache.exists())
            cache.mkdir(mode=0o700);(cache/'unexpected-link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):module.clean_apparmor_package_cache(cache)
            self.assertTrue((cache/'unexpected-link').is_symlink())

    def test_customer_autostart_journal_cas_lost_reply_and_exact_restore(self):
        for original in [None,'true','1','false','0']:
            stack,root,config,before,value,calls,enabled,boot_value=self.fixture()
            customer={'name':'original-customer','uuid':value['nodeId'],'attempt':value['requestId'],'state':'running','autostart':original}
            value={**value,'customers':[customer]}
            remote={'name':customer['name'],'type':'container','status':'Running','architecture':'aarch64','description':'original',
                'devices':{'root':{'type':'disk','path':'/','pool':'original'}},'profiles':[],'ephemeral':False,
                'config':{'volatile.uuid':customer['uuid'],'user.payincus.provisioning-attempt':customer['attempt'],
                    'security.privileged':'false','limits.memory':'256MiB'}}
            if original is not None:remote['config']['boot.autostart']=original
            revision=[0];writes=[];lose=[True]
            def api(method,path,body=None,etag=None):
                self.assertEqual(path,'/1.0/instances/original-customer')
                if method=='GET':return {'type':'sync','metadata':json.loads(json.dumps(remote))},str(revision[0])
                self.assertEqual(method,'PUT');self.assertEqual(etag,str(revision[0]))
                self.assertTrue((root/'maintenance.json').exists(),'journal persisted before first customer mutation')
                expected={key:remote[key] for key in ['architecture','description','devices','ephemeral','profiles']}
                self.assertEqual({key:body[key] for key in expected},expected)
                revision[0]+=1;remote['config']=body['config'];writes.append(body)
                if lose[0]:lose[0]=False;raise TimeoutError('lost autostart change reply')
                return {'type':'sync','metadata':{}},str(revision[0])
            def inventory(args,**kwargs):
                if args[:2]==['incus','list']:return json.dumps([remote]).encode()
                return self.fixture_command(args,calls,enabled)
            with stack,patch.object(module,'local_incus',side_effect=api),patch.object(module,'command',side_effect=inventory):
                if original!='false':
                    with self.assertRaises(TimeoutError):module.execute(value)
                    self.assertEqual(json.loads((root/'maintenance.json').read_text())['phase'],'preparing')
                first=module.execute(value)
                self.assertEqual(remote['config']['boot.autostart'],'false')
                self.assertEqual(len(writes),int(original!='false'),'lost response resumes without repeating config change')
                for value_ephemeral in [True,None,'false',0]:
                    remote['ephemeral']=value_ephemeral;count=len(writes)
                    with self.assertRaisesRegex(ValueError,'BOOT_RECOVERY'):module.customer_boot_change(customer,{'guardHash':module.guest_guard(remote)},restore=True)
                    self.assertEqual(len(writes),count,'unknown persistence must not reach a config mutation')
                remote['ephemeral']=False
                request={**value,'prepareHash':first['prepareHash'],'action':'reboot'}
                with patch.object(module.subprocess,'Popen') as reboot:
                    module.execute(request);self.assertEqual(reboot.call_count,1)
                boot_value[0]=customer['uuid'];remote['status']='Running'
                result=module.execute({**request,'action':'restore-customers'})
                self.assertEqual(result['phase'],'customers-restored');self.assertEqual(remote['config'].get('boot.autostart'),original)
                count=len(writes);module.execute({**request,'action':'restore-customers'});self.assertEqual(len(writes),count)
                remote['config']['limits.memory']='512MiB'
                with self.assertRaisesRegex(ValueError,'IDENTITY_CHANGED'):module.execute({**request,'action':'restore-customers'})
                self.assertEqual(remote['config']['limits.memory'],'512MiB','never overwrite a newer config')

    def test_reboot_rechecks_customer_boot_and_runtime(self):
        customer={'name':'original','uuid':'11111111-1111-4111-8111-111111111111',
            'attempt':'22222222-2222-4222-8222-222222222222','state':'running','autostart':'true'}
        remote={'name':'original','type':'container','ephemeral':False,'project':'default','status':'Running','config':{
            'volatile.uuid':customer['uuid'],'user.payincus.provisioning-attempt':customer['attempt'],
            'boot.autostart':'true','security.privileged':'false'}}
        with patch.object(module,'command',side_effect=lambda *_:json.dumps([remote]).encode()):
            module.assert_customer_baseline([customer])
            for value in [True,None,'false',0]:
                remote['ephemeral']=value
                with self.assertRaisesRegex(ValueError,'BOOT_RECOVERY'):module.assert_customer_baseline([customer])
            remote['ephemeral']=False
            with self.assertRaisesRegex(ValueError,'BOOT_RECOVERY'):module.assert_customer_baseline([customer],prepared=True)
            remote['config']['boot.autostart']='false';module.assert_customer_baseline([customer],prepared=True)
            remote['status']='Stopped'
            with self.assertRaisesRegex(ValueError,'HARDENING_BUSY'):module.assert_customer_baseline([customer],prepared=True)
            remote['status']='Running';remote['config']['security.privileged']='true'
            with self.assertRaisesRegex(ValueError,'RUNTIME_UNSAFE'):module.assert_customer_baseline([customer],prepared=True)

    def fixture_command(self,args,calls,enabled):
        calls.append(args)
        if args[:2]==['rc-update','add']:enabled[0]=True
        elif args[:2]==['rc-update','del']:enabled[0]=False
        else:self.fail('Unexpected fixture command')
        return b''
if __name__=='__main__':unittest.main()
