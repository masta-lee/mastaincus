"""Security patch planner regression; no package or service mutations."""
import importlib.util,pathlib,sys,types,unittest,tempfile,os,contextlib
from unittest.mock import patch
if sys.platform=='win32':sys.modules.setdefault('fcntl',types.SimpleNamespace())
spec=importlib.util.spec_from_file_location('inventory',pathlib.Path(__file__).with_name('system-security-inventory.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class Plans(unittest.TestCase):
    def test_runtime_library_maps_only_read_exact_host_process(self):
        import io
        class ProcFile:
            def __init__(self,path):self.path=path
            def __truediv__(self,other):return ProcFile(self.path+'/'+other)
            def readlink(self):return namespaces[self.path]
            def open(self,**_):
                self_outer.assertEqual(self.path,'/proc/12/maps')
                return io.StringIO(maps)
        self_outer=self
        namespaces={'/proc/12/ns/pid':'pid:[1]','/proc/1/ns/pid':'pid:[1]'}
        with patch.object(module.pathlib,'Path',side_effect=lambda *parts:ProcFile('/'.join(parts))):
            for maps,expected in [('a-b r-xp 0 0 0 /usr/lib/current.so\n',False),('a-b r-xp 0 0 0 /usr/lib/old.so (deleted)\n',True),
                ('a-b rw-p 0 0 0 /usr/lib/old.so (deleted)\n',False),('a-b r-xp 0 0 0 /memfd:jit (deleted)\n',False)]:
                self.assertEqual(module.runtime_process_has_replaced_libraries(12),expected)
            namespaces['/proc/12/ns/pid']='pid:[2]'
            with self.assertRaisesRegex(ValueError,'PROCESS_CHANGED'):module.runtime_process_has_replaced_libraries(12)
            namespaces['/proc/12/ns/pid']='pid:[1]';maps='x'*(1024*1024+1)
            with self.assertRaisesRegex(ValueError,'CHECK_INCOMPLETE'):module.runtime_process_has_replaced_libraries(12)
        for pid in [1,True,'12',None]:
            with self.assertRaisesRegex(ValueError,'PROCESS_CHANGED'):module.runtime_process_has_replaced_libraries(pid)
    def test_runtime_library_activation_noop_and_shared_database_protection(self):
        backend={'pid':12};database={'pid':13,'major':16}
        with patch.object(module.pathlib,'Path')as path,patch.object(module,'runtime_process_has_replaced_libraries',return_value=False),patch.object(module,'command')as command:
            path.return_value.stat.return_value=types.SimpleNamespace(st_dev=1,st_ino=2)
            module.activate_runtime_libraries(backend,database,{})
            command.assert_not_called()
            path.reset_mock();module.activate_runtime_libraries(backend,{**database,'sharedReadOnly':True},{})
            self.assertEqual(path.call_count,2,'shared PG must not even be selected for activation')
            command.assert_not_called()
        for current in [None,{**backend,'pid':14}]:
            with patch.object(module.pathlib,'Path')as path,patch.object(module,'runtime_process_has_replaced_libraries',return_value=True),patch.object(module,'backend_runtime_proof',return_value=current),patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'PROCESS_CHANGED'):
                path.return_value.stat.return_value=types.SimpleNamespace(st_dev=1,st_ino=2)
                module.activate_runtime_libraries(backend,database,{})
            command.assert_not_called()
    @unittest.skipUnless(hasattr(os,'geteuid')and os.geteuid()==0,'root-owned original maintenance receipt metadata')
    def test_automatic_no_package_change_still_finishes_runtime_activation(self):
        real_path=pathlib.Path
        with tempfile.TemporaryDirectory()as folder:
            root=real_path(folder);(root/'security').mkdir(mode=0o700);(root/'os-release').write_text('ID=debian\n')
            (root/'sources.list').write_text('');(root/'sources.list.d').mkdir()
            paths={'/etc/os-release':root/'os-release','/etc/apt/sources.list':root/'sources.list','/etc/apt/sources.list.d':root/'sources.list.d','/var/lib/incudal-system-security':root/'security','/var/lib/incudal-backup/recovery-hold.json':root/'absent-hold'}
            def fixture_path(value,*parts):return paths.get(str(value),real_path(value)).joinpath(*parts)
            backend={'pid':12};database={'pid':13,'major':16};initial={'packages':{'nodejs':'24.22.3-1','postgresql-16':'16.16-1'}}
            updated={**initial,'loadedCode':{'complete':True,'allHostProcesses':True,'processes':[{'pid':13,'service':'postgres','replacedMappings':1}]}}
            def activate(b,d,value):
                self.assertEqual((b,d),(backend,database));self.assertIs(value,updated)
                value['backendActivation']={'state':'activated','pid':20,'activationOnly':True}
                value['databaseActivation']={'state':'activated','pid':21,'activationOnly':True}
            fd=os.open(root/'operation.lock',os.O_RDWR|os.O_CREAT,0o600)
            try:
                with patch.object(module.pathlib,'Path',side_effect=fixture_path),patch.object(module,'open_platform_operation_lock',return_value=fd),patch.object(module,'verify_runtime_integrity'),patch.object(module,'recover_runtime_maintenance',return_value=None),patch.object(module,'inventory',side_effect=[initial,updated]),patch.object(module,'backend_runtime_proof',return_value=backend),patch.object(module,'database_runtime_proof',return_value=database),patch.object(module,'clean_service_policy'),patch.object(module,'command',return_value='')as command,patch.object(module,'patch_plan',return_value=[]),patch.object(module,'activate_runtime_libraries',side_effect=activate)as activation,patch.object(module,'replaced_host_mappings',return_value={'complete':True,'allHostProcesses':True,'processes':[]}),patch.object(module,'install_runtime_patches')as install,patch.object(module,'persist')as persist:
                    result=module.apply_patches(automatic=True)
                activation.assert_called_once();install.assert_not_called()
                self.assertTrue(result['backendActivation']['activationOnly']);self.assertTrue(result['databaseActivation']['activationOnly'])
                self.assertEqual(persist.call_args.args[0]['databaseActivation'],result['databaseActivation'])
                self.assertFalse(any(call.args[0][0]=='apt-get'and '--simulate'not in call.args[0]and call.args[0][-1]!='update'for call in command.call_args_list))
            finally:
                try:os.close(fd)
                except OSError:pass
    @unittest.skipUnless(hasattr(os,'geteuid')and os.geteuid()==0,'actual root journal and protected file permissions')
    def test_activation_only_recovery_keeps_packages_and_proves_loaded_libraries(self):
        import json
        real_path=pathlib.Path
        with tempfile.TemporaryDirectory()as folder:
            root=real_path(folder);root.chmod(0o700);path=root/'runtime-maintenance.json'
            backend={'pid':12,'start':'123','app':'/opt/incudal','environmentHash':'a'*64,'codeHash':'b'*64,'serviceHash':'d'*64,'unitHashes':{'/etc/systemd/system/incudal-backend.service':'c'*64}}
            packages={'nodejs:amd64':'24.22.3-1'}
            journal={'version':1,'phase':'stopping-backend','activationOnly':True,'drainConfirmed':True,'backend':backend,'database':None,'backup':'runtime-backup-'+'e'*32,'packages':[], 'baselinePackages':packages,'expectedPackages':packages}
            def fixture_path(*parts):
                if parts in [('/usr/bin/node',),('/proc','12','exe')]:return types.SimpleNamespace(stat=lambda:types.SimpleNamespace(st_dev=1,st_ino=2))
                return real_path(*parts)
            def protected(value,*_,**__):return {str(path):'journal','/opt/incudal/.env':'a'*64,'/opt/incudal/server/dist/app.js':'b'*64,'/etc/systemd/system/incudal-backend.service':'c'*64}[str(value)]
            def run(args,*_):return 'success'if '--property=Result'in args else ''
            for old_maps,actual_packages in [(False,packages),(True,packages),(False,{**packages,'extra:all':'1'})]:
                module.write_runtime_maintenance(journal,root)
                with patch.object(module.pathlib,'Path',side_effect=fixture_path),patch.object(module,'protected_hash',side_effect=protected),patch.object(module,'backend_service_policy',return_value=({},real_path('/opt/incudal'),backend['unitHashes'],backend['serviceHash'])),patch.object(module,'backend_runtime_proof',return_value=backend),patch.object(module,'runtime_process_has_replaced_libraries',return_value=old_maps),patch.object(module,'debian_installed_packages',return_value=actual_packages),patch.object(module,'clean_service_policy'),patch.object(module,'verify_runtime_health'),patch.object(module,'verify_runtime_financial_integrity'),patch.object(module,'archive_runtime_receipt')as receipt,patch.object(module,'complete_runtime_package_transaction')as install,patch.object(module,'command',side_effect=run)as command:
                    if old_maps or actual_packages!=packages:
                        with self.assertRaisesRegex(ValueError,'ACTIVATION_PENDING|BASELINE_CHANGED'):module.recover_runtime_maintenance(path)
                        self.assertEqual(json.loads(path.read_text())['phase'],'stopping-backend');receipt.assert_not_called()
                    else:
                        completed=module.recover_runtime_maintenance(path)
                        self.assertEqual(completed['phase'],'activated');self.assertTrue(completed['activationOnly']);receipt.assert_called_once()
                    install.assert_not_called()
                    self.assertFalse(any(call.args[0][0]=='apt-get'for call in command.call_args_list),'already-installed activation never downloads or reinstalls')
                    if actual_packages!=packages:self.assertFalse(any(call.args[0][:2]==['systemctl','start']for call in command.call_args_list))
            for delta in [{'activationOnly':'true'},{'packages':['nodejs=24.22.3-1']},{'expectedPackages':{'nodejs:amd64':'25.0.0'}},{'phase':'installed'}]:
                module.write_runtime_maintenance({**journal,**delta},root)
                with patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'JOURNAL_INVALID'):module.recover_runtime_maintenance(path)
                command.assert_not_called()
    @unittest.skipUnless(hasattr(os,'geteuid')and os.geteuid()==0,'real root inventory receipt metadata')
    def test_automatic_runtime_upgrade_preserves_both_activation_receipts(self):
        import json
        real_path=pathlib.Path
        with tempfile.TemporaryDirectory()as folder:
            root=real_path(folder);(root/'security').mkdir(mode=0o700)
            (root/'os-release').write_text('ID=debian\n')
            (root/'sources.list').write_text('')
            (root/'sources.list.d').mkdir()
            mapping={'/etc/os-release':root/'os-release','/etc/apt/sources.list':root/'sources.list','/etc/apt/sources.list.d':root/'sources.list.d','/var/lib/incudal-system-security':root/'security','/var/lib/incudal-backup/recovery-hold.json':root/'absent-hold'}
            def fixture_path(value,*parts):return mapping.get(str(value),real_path(value)).joinpath(*parts)
            before={'nodejs:amd64':'24.22.3-1~safe1','postgresql-16:amd64':'16.16-1~safe1'}
            after={'nodejs:amd64':'24.22.3-1','postgresql-16:amd64':'16.16-1'}
            initial={'packages':{k.split(':')[0]:v for k,v in before.items()}}
            updated={'packages':{k.split(':')[0]:v for k,v in after.items()}}
            backend={'pid':10};database={'major':16};planned=['nodejs=24.22.3-1','postgresql-16=16.16-1']
            backend_receipt={'state':'activated','pid':20,'backup':'runtime-backup-'+'a'*32}
            database_receipt={'state':'activated','pid':21}
            def upgrade(changes,b,d,value,expected):
                self.assertEqual(changes,planned);self.assertEqual(expected,after)
                value['backendActivation']=backend_receipt;value['databaseActivation']=database_receipt
            fd=os.open(root/'operation.lock',os.O_RDWR|os.O_CREAT,0o600)
            try:
                with patch.object(module.pathlib,'Path',side_effect=fixture_path),patch.object(module,'open_platform_operation_lock',return_value=fd),patch.object(module,'verify_runtime_integrity'),patch.object(module,'recover_runtime_maintenance',return_value=None),patch.object(module,'inventory',side_effect=[initial,updated]),patch.object(module,'backend_runtime_proof',return_value=backend),patch.object(module,'database_runtime_proof',return_value=database),patch.object(module,'clean_service_policy'),patch.object(module,'command',return_value=''),patch.object(module,'patch_plan',return_value=planned),patch.object(module,'debian_installed_packages',side_effect=[before,after]),patch.object(module,'install_runtime_patches',side_effect=upgrade),patch.object(module,'persist')as persist:
                    result=module.apply_patches(automatic=True)
                self.assertEqual(result['backendActivation'],backend_receipt)
                self.assertEqual(result['databaseActivation'],database_receipt)
                self.assertEqual(persist.call_args.args[0]['databaseActivation'],database_receipt)
                self.assertTrue(persist.call_args.kwargs['verify_activation'])
            finally:
                try:os.close(fd)
                except OSError:pass
    @unittest.skipUnless(hasattr(os,'geteuid') and os.geteuid()==0,'real root-owned Linux flock metadata')
    def test_legacy_empty_platform_lock_tightens_same_inode_without_splitting_flock(self):
        import grp,stat
        with tempfile.TemporaryDirectory(dir='/root')as folder:
            p=pathlib.Path(folder)/'lock';p.touch(mode=0o600);os.chmod(p,0o640)
            # CI runs before platform install, so no incudal group exists yet.
            # Use a numeric fixture group and keep the product identity lookup
            # covered without adding users or changing the runner's groups.
            fixture_gid=54321
            os.chown(p,0,fixture_gid)
            held=os.open(p,os.O_RDWR);module.fcntl.flock(held,module.fcntl.LOCK_EX|module.fcntl.LOCK_NB)
            before=os.fstat(held)
            with patch.object(grp,'getgrnam',return_value=types.SimpleNamespace(gr_gid=fixture_gid)):
                fd=module.open_platform_operation_lock(path=str(p))
            try:
                after=os.fstat(fd);self.assertEqual((before.st_dev,before.st_ino),(after.st_dev,after.st_ino));self.assertEqual(stat.S_IMODE(after.st_mode),0o600)
                with self.assertRaises(BlockingIOError):module.fcntl.flock(fd,module.fcntl.LOCK_EX|module.fcntl.LOCK_NB)
            finally:os.close(fd);os.close(held)
            for mode,content,gid in [(0o640,'unexpected',fixture_gid),(0o644,'',0),(0o640,'',0)]:
                p.write_text(content);os.chmod(p,mode);os.chown(p,0,gid)
                with patch.object(grp,'getgrnam',return_value=types.SimpleNamespace(gr_gid=fixture_gid)),self.assertRaises(ValueError):module.open_platform_operation_lock(path=str(p))
                self.assertEqual(p.read_text(),content);self.assertEqual(stat.S_IMODE(p.stat().st_mode),mode)
            p.unlink();p.symlink_to('/dev/null')
            with self.assertRaises(OSError):module.open_platform_operation_lock(path=str(p))
    @unittest.skipUnless(hasattr(os,'geteuid')and os.geteuid()==0,'root private evidence permissions required')
    def test_completed_runtime_evidence_retention_preserves_recent_incomplete_and_changed(self):
        import json,time
        with tempfile.TemporaryDirectory()as directory:
            root=pathlib.Path(directory);root.chmod(0o700)
            paths=[]
            for number in range(12):
                name='runtime-backup-'+f'{number:032x}';path=root/name;path.mkdir(mode=0o700)
                record=path/'completed.json';record.write_text(json.dumps({'phase':'activated','backup':name}));record.chmod(0o600)
                stamp=time.time()-(40+number)*86400;os.utime(record,(stamp,stamp));paths.append(path)
            recent=paths[-1]/'completed.json';os.utime(recent,None)
            incomplete=root/('runtime-backup-'+'f'*32);incomplete.mkdir(mode=0o700);(incomplete/'database.dump').write_text('unfinished')
            (paths[-2]/'unknown-evidence').write_text('keep')
            current=root/('runtime-backup-'+'e'*32);current.mkdir(mode=0o700)
            module.archive_runtime_receipt({'backup':current.name,'phase':'activated'},root)
            self.assertTrue(current.exists());self.assertTrue(paths[-1].exists());self.assertTrue(paths[-2].exists());self.assertTrue(incomplete.exists())
            self.assertEqual(sum(path.exists()for path in paths),7,'seven newest completed sets plus changed evidence are retained')
            self.assertEqual((current/'completed.json').stat().st_mode&0o777,0o600)
    def test_runtime_download_failure_preserves_running_backend(self):
        b={'pid':12};d={'major':16}
        def execute(args,*_):
            if args==['dpkg','--audit']:return ''
            self.assertIn('--download-only',args);raise ValueError('SYSTEM_SECURITY_DOWNLOAD_UNAVAILABLE')
        with patch.object(module,'backend_runtime_proof',return_value=b),patch.object(module,'database_runtime_proof',return_value=d),patch.object(module,'debian_installed_packages',return_value={}),patch.object(module,'command',side_effect=execute)as command,self.assertRaisesRegex(ValueError,'DOWNLOAD_UNAVAILABLE'):
            module.install_runtime_patches(['nodejs=24.22.3'],b,d,{}, {})
        self.assertFalse(any('systemctl'in c.args[0]for c in command.call_args_list))
    def test_shared_database_allows_only_node_download_without_database_restart(self):
        b={'pid':12};d={'major':16,'sharedReadOnly':True}
        def execute(args,*_):
            if args==['dpkg','--audit']:return ''
            self.assertIn('--download-only',args);raise ValueError('SYSTEM_SECURITY_DOWNLOAD_UNAVAILABLE')
        with patch.object(module,'backend_runtime_proof',return_value=b),patch.object(module,'database_runtime_proof',return_value=d)as proof,patch.object(module,'debian_installed_packages',return_value={}),patch.object(module,'command',side_effect=execute)as command,self.assertRaisesRegex(ValueError,'DOWNLOAD_UNAVAILABLE'):
            module.install_runtime_patches(['nodejs=24.22.3'],b,d,{}, {})
        proof.assert_called_once_with(shared_read_only=True)
        self.assertFalse(any('systemctl'in c.args[0]for c in command.call_args_list))
        for change in ['postgresql-16=16.17','postgresql-client-16=16.17','libpq5=17.13','postgresql-common=280']:
            with patch.object(module,'backend_runtime_proof',return_value=b),patch.object(module,'database_runtime_proof')as proof,patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'DATABASE_CHANGED'):
                module.install_runtime_patches(['nodejs=24.22.3',change],b,d,{}, {})
            proof.assert_not_called();command.assert_not_called()
    def test_runtime_half_installed_exact_version_requires_reinstall(self):
        journal={'baselinePackages':{'zstd:amd64':'1.5.5-1'},'expectedPackages':{'zstd:amd64':'1.5.5-2'},'packages':['zstd=1.5.5-2']}
        states={'zstd:amd64':{'version':'1.5.5-2','status':'half-installed'}}
        output='Inst zstd [1.5.5-2] (1.5.5-2 Ubuntu:24.04/noble-updates [amd64])'
        def run(args,*_):return output if '--simulate'in args else ''
        with patch.object(module,'debian_package_states',return_value=states),patch.object(module,'debian_installed_packages',return_value=journal['expectedPackages']),patch.object(module,'prepare_service_policy'),patch.object(module,'clean_service_policy'),patch.object(module,'command',side_effect=run)as command:
            module.complete_runtime_package_transaction(journal)
        self.assertEqual(sum('--reinstall'in call.args[0]for call in command.call_args_list),2)
        for invalid in [output.replace('1.5.5-2 Ubuntu','1.5.5-3 Ubuntu'),output+'\nRemv zstd',output+'\n'+output]:
            with patch.object(module,'debian_package_states',return_value=states),patch.object(module,'prepare_service_policy')as policy,patch.object(module,'command',return_value=invalid),patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)),self.assertRaisesRegex(ValueError,'PLAN_REJECTED'):
                module.complete_runtime_package_transaction(journal)
            policy.assert_not_called()
    def test_runtime_maintenance_requires_exact_current_authority(self):
        before={'pid':12,'start':'123','app':'/opt/incudal','environmentHash':'a'*64,'codeHash':'b'*64}
        for current in [None,{**before,'pid':13},{**before,'environmentHash':'c'*64}]:
            with patch.object(module,'backend_runtime_proof',return_value=current),patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'BACKEND_PROCESS_CHANGED'):
                module.install_runtime_patches(['nodejs=24.22.3'],before,None,{}, {})
            command.assert_not_called()
    @unittest.skipUnless(hasattr(os,'geteuid')and os.geteuid()==0,'real root journal required')
    def test_runtime_recovery_preserves_configuration_and_busy_package_state(self):
        import json
        with tempfile.TemporaryDirectory()as directory:
            root=pathlib.Path(directory);root.chmod(0o700);path=root/'runtime-maintenance.json'
            before={'pid':12,'start':'123','app':'/opt/incudal','environmentHash':'a'*64,'codeHash':'b'*64,'serviceHash':'d'*64,'unitHashes':{'/etc/systemd/system/incudal-backend.service':'c'*64}}
            original_packages={'nodejs:amd64':'24.22.2'}
            data={'version':1,'phase':'stopping-backend','backend':before,'database':None,'baselinePackages':original_packages,'expectedPackages':{'nodejs:amd64':'24.22.3'},'packages':['nodejs=24.22.3']}
            module.write_runtime_maintenance(data,root)
            with patch.object(module,'protected_hash',return_value='a'*64),patch.object(module,'clean_service_policy'),patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'CONFIGURATION_CHANGED'):
                module.recover_runtime_maintenance(path)
            command.assert_not_called()
            hashes=['journal','a'*64,'b'*64,'c'*64]
            with patch.object(module,'backend_service_policy',return_value=({},pathlib.Path('/opt/incudal'),before['unitHashes'],before['serviceHash'])),patch.object(module,'protected_hash',side_effect=hashes),patch.object(module,'clean_service_policy'),patch.object(module,'command',side_effect=lambda args,*_: 'success'if '--property=Result'in args else 'incomplete package')as command,self.assertRaisesRegex(ValueError,'PACKAGE_CONFIGURATION_PENDING'):
                module.recover_runtime_maintenance(path)
            self.assertEqual(command.call_args.args[0],['dpkg','--audit'])
            self.assertEqual(json.loads(path.read_text())['phase'],'stopping-backend')
            original_path=module.pathlib.Path
            def fixture_path(*parts):
                if parts in [('/usr/bin/node',),('/proc','12','exe')]:return types.SimpleNamespace(stat=lambda:types.SimpleNamespace(st_dev=1,st_ino=2))
                return original_path(*parts)
            policy=({},pathlib.Path('/opt/incudal'),before['unitHashes'],before['serviceHash'])
            with patch.object(module,'backend_service_policy',return_value=policy),patch.object(module.pathlib,'Path',side_effect=fixture_path),patch.object(module,'protected_hash',side_effect=hashes),patch.object(module,'backend_runtime_proof',return_value=before),patch.object(module,'debian_installed_packages',return_value=original_packages),patch.object(module,'runtime_process_has_replaced_libraries',return_value=False),patch.object(module,'verify_runtime_financial_integrity'),patch.object(module,'verify_runtime_health'),patch.object(module,'clean_service_policy'),patch.object(module,'command',side_effect=lambda args,*_: 'success'if '--property=Result'in args else '')as command:
                module.recover_runtime_maintenance(path)
            self.assertEqual([call.args[0]for call in command.call_args_list],[['systemctl','show','incudal-backend.service','--property=SubState','--value'],['systemctl','show','incudal-backend.service','--property=Result','--value'],['dpkg','--audit'],['systemctl','start','incudal-backend.service']])
            self.assertEqual(json.loads(path.read_text())['phase'],'aborted','restoring services before installation is not patch activation')
    def test_runtime_interrupted_packages_are_exact_and_do_not_accept_drift(self):
        journal={'baselinePackages':{'nodejs:amd64':'24.22.2','other:all':'1'},'expectedPackages':{'nodejs:amd64':'24.22.3','other:all':'1'},'packages':['nodejs=24.22.3']}
        states=lambda packages,status='installed':{key:{'version':value,'status':status}for key,value in packages.items()}
        with patch.object(module,'debian_package_states',return_value=states(journal['expectedPackages'])),patch.object(module,'command',return_value='')as command:
            module.complete_runtime_package_transaction(journal)
        self.assertEqual([c.args[0]for c in command.call_args_list],[['dpkg','--audit']])
        for drift in [{'nodejs:amd64':'25.0.0','other:all':'1'},{'nodejs:amd64':'24.22.2'},{**journal['baselinePackages'],'extra:all':'1'}]:
            with patch.object(module,'debian_package_states',return_value=states(drift)),patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'BASELINE_CHANGED'):
                module.complete_runtime_package_transaction(journal)
            command.assert_not_called()
        with patch.object(module,'debian_package_states',return_value=states(journal['baselinePackages'])),patch.object(module,'debian_installed_packages',return_value=journal['expectedPackages']),patch.object(module,'patch_plan',return_value=journal['packages']),patch.object(module,'prepare_service_policy'),patch.object(module,'clean_service_policy'),patch.object(module,'command',return_value='')as command:
            module.complete_runtime_package_transaction(journal)
        self.assertEqual(command.call_args_list[0].args[0][-1],'nodejs=24.22.3')
        for unreviewed in [[],['nodejs=25.0.0'],['nodejs=24.22.3','unrelated=2']]:
            with patch.object(module,'debian_package_states',return_value=states(journal['baselinePackages'])),patch.object(module,'patch_plan',return_value=unreviewed),patch.object(module,'prepare_service_policy')as policy,patch.object(module,'command',return_value=''),self.assertRaisesRegex(ValueError,'PLAN_REJECTED'):
                module.complete_runtime_package_transaction(journal)
            policy.assert_not_called()
        partial=states(journal['expectedPackages']);partial['nodejs:amd64']['status']='unpacked'
        with patch.object(module,'debian_package_states',return_value=partial),patch.object(module,'debian_installed_packages',return_value=journal['expectedPackages']),patch.object(module,'prepare_service_policy')as policy,patch.object(module,'clean_service_policy'),patch.object(module,'command',return_value='')as command:
            module.complete_runtime_package_transaction(journal)
        policy.assert_called_once();self.assertIn(['dpkg','--force-confold','--configure','nodejs'],[call.args[0]for call in command.call_args_list])
        partial['other:all']['status']='half-configured'
        with patch.object(module,'debian_package_states',return_value=partial),patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'BASELINE_CHANGED'):
            module.complete_runtime_package_transaction(journal)
        command.assert_not_called()
    def test_health_requires_business_ready_and_no_recovery_hold(self):
        import json
        rows=[{'status':'ok','businessStartupReady':False,'recoveryHeld':False},{'status':'ok','businessStartupReady':True,'recoveryHeld':True},{'status':'ok','businessStartupReady':True,'recoveryHeld':False}]
        with patch.object(module,'command',side_effect=[json.dumps(row)for row in rows])as command,patch.object(module.time,'sleep'):
            module.verify_runtime_health()
        self.assertEqual(command.call_count,3)
        with patch.object(module,'command',side_effect=[json.dumps(rows[0]),json.dumps(rows[2])])as command,patch.object(module.time,'sleep'),patch.object(module.time,'monotonic',side_effect=[0,180]):
            module.verify_runtime_health()
        self.assertEqual(command.call_count,2,'slow startup beyond two minutes retains exact business-ready checks')
        with patch.object(module,'command',return_value=json.dumps(rows[0])),patch.object(module.time,'sleep'),patch.object(module.time,'monotonic',side_effect=[0,601]),self.assertRaisesRegex(ValueError,'ACTIVATION_PENDING'):
            module.verify_runtime_health()
    def test_runtime_integrity_uses_explicit_environment_and_authentication_seals(self):
        with patch.object(module,'command',return_value='SYSTEM_SECURITY_FINANCIAL_INTEGRITY_VERIFIED')as command:
            module.verify_runtime_financial_integrity('/opt/incudal')
        self.assertEqual(command.call_args.args[0][:5],['/usr/bin/env','ENV_FILE=/opt/incudal/.env','NODE_ENV=production','/usr/bin/node','--input-type=module'])
        self.assertIn('false,true',command.call_args.args[0][-2])
        self.assertIn("verifyFinancialBaseline(readFileSync('/var/lib/incudal-finance/baseline.json'",command.call_args.args[0][-2])
    def test_database_settings_keep_effective_values_and_local_listener_source_transition(self):
        import hashlib,json
        original=[['listen_addresses','localhost','default','postmaster'],['port','5432','default','postmaster'],['search_path','"$user", public','default','user']]
        changed=[row.copy()for row in original];changed[0][2]='configuration file'
        effective,legacy=module.database_settings_hashes(original)
        updated,updated_legacy=module.database_settings_hashes(changed)
        self.assertEqual(effective,updated)
        self.assertNotEqual(legacy,updated_legacy)
        self.assertEqual(legacy,hashlib.sha256(json.dumps([row[:3]for row in original],sort_keys=True).encode()).hexdigest())
        for index,column,value in [(0,1,'*'),(0,2,'override'),(0,3,'user'),(1,2,'configuration file'),(2,2,'user')]:
            rows=[row.copy()for row in original];rows[index][column]=value
            self.assertNotEqual(module.database_settings_hashes(rows)[0],effective)
        for rows in [[],[original[0],original[0]],[[True,'localhost','default','postmaster']],[[*original[0],'extra']]]:
            with self.assertRaisesRegex(ValueError,'CONFIGURATION_CHANGED'):module.database_settings_hashes(rows)
    def test_database_activation_retains_legacy_settings_receipts(self):
        before={key:'same'for key in ['major','data','configHash','hbaHash','unitHash','fileHashes','settingsHash']};before.update(major=16,pid=12)
        current={**before,'settingsHashVersion':2,'settingsHash':'new-policy','settingsLegacyHash':'same'}
        with patch.object(module.pathlib,'Path')as path,patch.object(module,'runtime_process_has_replaced_libraries',return_value=False):
            path.return_value.stat.return_value=types.SimpleNamespace(st_dev=1,st_ino=2)
            module.verify_database_activation(current,before)
            with self.assertRaisesRegex(ValueError,'CONFIGURATION_CHANGED'):module.verify_database_activation({**current,'settingsLegacyHash':'changed'},before)
            module.verify_database_activation(current,{**before,'settingsHashVersion':2,'settingsHash':'new-policy'})
            for version in [True,0,3,'2']:
                with self.assertRaisesRegex(ValueError,'CONFIGURATION_CHANGED'):module.verify_database_activation(current,{**before,'settingsHashVersion':version})
            with self.assertRaisesRegex(ValueError,'CONFIGURATION_CHANGED'):module.verify_database_activation(before,{**before,'settingsHashVersion':2})
    def test_database_activation_requires_config_and_installed_executable(self):
        before={key:'same'for key in ['major','data','configHash','hbaHash','unitHash','fileHashes','settingsHash']};before.update(major=16,pid=12)
        for key in ['major','data','configHash','hbaHash','unitHash','fileHashes','settingsHash']:
            with patch.object(module.pathlib,'Path')as path,self.assertRaisesRegex(ValueError,'CONFIGURATION_CHANGED'):
                module.verify_database_activation({**before,key:'changed'},before)
            path.assert_not_called()
        with patch.object(module.pathlib,'Path')as path,patch.object(module,'runtime_process_has_replaced_libraries',return_value=False):
            path.return_value.stat.return_value=types.SimpleNamespace(st_dev=1,st_ino=2)
            module.verify_database_activation(before,before)
            path.return_value.stat.side_effect=[types.SimpleNamespace(st_dev=1,st_ino=2),types.SimpleNamespace(st_dev=1,st_ino=3)]
            with self.assertRaisesRegex(ValueError,'ACTIVATION_PENDING'):module.verify_database_activation(before,before)
        with patch.object(module.pathlib,'Path')as path,patch.object(module,'runtime_process_has_replaced_libraries',return_value=True),self.assertRaisesRegex(ValueError,'ACTIVATION_PENDING'):
            path.return_value.stat.return_value=types.SimpleNamespace(st_dev=1,st_ino=2)
            module.verify_database_activation(before,before)
    @unittest.skipUnless(hasattr(os,'geteuid')and os.geteuid()==0,'real root file hashes and symlinks required')
    def test_original_sealed_file_checker_rejects_tampered_added_and_changed_links(self):
        import subprocess,hashlib
        source=pathlib.Path(__file__).resolve().parent.parent/'deploy/incudal-online-task.sh.example'
        if not source.exists():source=pathlib.Path(__file__).with_name('incudal-online-task.sh.example')
        text=source.read_text()
        functions=[]
        for name,next_name in [('manifest_path','static_files'),('static_files','static_links'),('static_links','link_entries'),('link_entries','apply_secure_ownership'),('verify_manifest','seal_release')]:
            start=text.index(name+'() {');end=text.index(next_name+'() {',start);functions.append(text[start:end])
        with tempfile.TemporaryDirectory()as directory:
            root=pathlib.Path(directory);app=root/'app';app.mkdir();(app/'index.html').write_text('original');(app/'link').symlink_to('index.html')
            manifest=root/(hashlib.sha256(str(app).encode()).hexdigest()+'.sha256');manifest.write_text(hashlib.sha256(b'original').hexdigest()+'  ./index.html\n')
            (root/(manifest.name+'.links')).write_text('./link -> index.html\n')
            script='set -Eeuo pipefail\nMANIFEST_DIR='+str(root)+'\nresolve_app_dir(){ printf "%s\\n" '+str(app)+'; }\nfail(){ exit 1; }\n'+''.join(functions)+'\nverify_manifest\n'
            def check():return subprocess.run(['/bin/bash','-c',script],cwd=app,stdout=subprocess.PIPE,stderr=subprocess.PIPE).returncode
            self.assertEqual(check(),0)
            (app/'index.html').write_text('injected');self.assertNotEqual(check(),0);(app/'index.html').write_text('original')
            (app/'extra.js').write_text('unknown');self.assertNotEqual(check(),0);(app/'extra.js').unlink()
            (app/'link').unlink();(app/'link').symlink_to('/etc/passwd');self.assertNotEqual(check(),0)
    def test_runtime_check_failure_blocks_maintenance_and_never_reseals(self):
        with patch.object(module.pathlib,'Path')as path,patch.object(module,'command',return_value='INCUDAL_SEALED_RUNTIME_VERIFIED')as command,patch.object(module,'record_runtime_integrity')as receipt:
            path.return_value.lstat.return_value=types.SimpleNamespace(st_mode=0o100755,st_uid=0,st_nlink=1)
            module.verify_runtime_integrity();receipt.assert_called_once_with(True)
            self.assertEqual(command.call_args.args[0][1:],[ 'verify-runtime'])
            self.assertEqual(command.call_args.args[1],600,'complete original seal/link check gets a bounded slow-storage budget')
            self.assertNotIn('seal',str(command.call_args.args))
        with patch.object(module.pathlib,'Path')as path,patch.object(module,'command',side_effect=ValueError('private changed path')),patch.object(module,'record_runtime_integrity')as receipt,self.assertRaisesRegex(ValueError,'RUNTIME_INTEGRITY_MISMATCH'):
            path.return_value.lstat.return_value=types.SimpleNamespace(st_mode=0o100755,st_uid=0,st_nlink=1)
            module.verify_runtime_integrity()
        receipt.assert_called_once_with(False)
        source=pathlib.Path(module.__file__).read_text()
        transaction=source[source.index('def apply_patches'):source.index('def maintain_system_packages')]
        self.assertLess(transaction.index('verify_runtime_integrity()'),transaction.index("value=inventory()"))
        self.assertLess(transaction.index('verify_runtime_integrity()'),transaction.index("command(['apt-get'"))
    @unittest.skipUnless(hasattr(os,'geteuid')and os.geteuid()==0,'real root receipt permissions required')
    def test_runtime_tamper_evidence_survives_later_verified_check(self):
        with tempfile.TemporaryDirectory()as directory:
            root=pathlib.Path(directory);root.chmod(0o700)
            first=module.record_runtime_integrity(False,root)
            after=module.record_runtime_integrity(True,root)
            self.assertEqual(after['firstFailureAt'],first['firstFailureAt']);self.assertEqual(after['lastFailureAt'],first['lastFailureAt'])
            self.assertEqual(after['state'],'verified');self.assertEqual((root/'runtime-integrity.json').stat().st_mode&0o777,0o600)

    def test_unreadable_integrity_evidence_keeps_original_failure_history_with_no_temporary_write_or_replace(self):
        import errno,hashlib,json,stat
        from unittest.mock import MagicMock
        original={'version':1,'state':'failed','checkedAt':'2026-11-23T10:00:00Z','firstFailureAt':'2026-11-22T10:00:00Z','lastFailureAt':'2026-11-23T10:00:00Z','error':'SYSTEM_SECURITY_RUNTIME_INTEGRITY_MISMATCH'}
        for error in [PermissionError(errno.EACCES,'fixture unavailable'),OSError(errno.EIO,'fixture unavailable')]:
            with tempfile.TemporaryDirectory()as directory:
                receipt=pathlib.Path(directory)/'runtime-integrity.json';receipt.write_bytes(json.dumps(original).encode());receipt.chmod(0o600);before=receipt.stat();raw=receipt.read_bytes();digest=hashlib.sha256(raw).hexdigest()
                root=MagicMock();root.__truediv__.return_value=receipt;root.lstat.return_value=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=0);real_lstat=type(receipt).lstat
                def lstat(path,*args,**kwargs):
                    if path==receipt:raise error
                    return real_lstat(path,*args,**kwargs)
                with patch.object(type(receipt),'exists',return_value=False)as exists,patch.object(type(receipt),'is_symlink',return_value=False)as symlink,patch.object(type(receipt),'lstat',lstat),patch.object(module.tempfile,'mkstemp')as temporary,patch.object(module.os,'replace')as replace,self.assertRaisesRegex(ValueError,'UNTRUSTED_PATH'):module.record_runtime_integrity(True,root)
                exists.assert_not_called();symlink.assert_not_called();temporary.assert_not_called();replace.assert_not_called()
                self.assertEqual(receipt.read_bytes(),raw);self.assertEqual(receipt.stat().st_ino,before.st_ino);self.assertEqual(hashlib.sha256(receipt.read_bytes()).hexdigest(),digest);self.assertEqual(json.loads(receipt.read_bytes()),original)

    @unittest.skipUnless(sys.platform=='linux'and hasattr(os,'geteuid')and os.geteuid()==0,'real root integrity receipt metadata and dangling links; temporary files only')
    def test_unknown_or_dangling_integrity_receipt_is_preserved_and_never_overwritten(self):
        import hashlib,json
        for kind in ['unknown','dangling']:
            with tempfile.TemporaryDirectory()as directory:
                root=pathlib.Path(directory);root.chmod(0o700);receipt=root/'runtime-integrity.json'
                if kind=='unknown':receipt.write_bytes(json.dumps({'version':2,'firstFailureAt':'2026-11-22T10:00:00Z','lastFailureAt':'2026-11-23T10:00:00Z'}).encode());receipt.chmod(0o600);raw=receipt.read_bytes();digest=hashlib.sha256(raw).hexdigest()
                else:receipt.symlink_to(root/'missing-original-receipt');raw=os.readlink(receipt)
                before=receipt.lstat()
                with patch.object(module.tempfile,'mkstemp')as temporary,patch.object(module.os,'replace')as replace,self.assertRaisesRegex(ValueError,'RECEIPT_INVALID|UNTRUSTED_PATH'):module.record_runtime_integrity(True,root)
                temporary.assert_not_called();replace.assert_not_called();self.assertEqual(receipt.lstat().st_ino,before.st_ino)
                if kind=='unknown':self.assertEqual(receipt.read_bytes(),raw);self.assertEqual(hashlib.sha256(receipt.read_bytes()).hexdigest(),digest)
                else:self.assertEqual(os.readlink(receipt),raw);self.assertFalse((root/'missing-original-receipt').exists())
    def test_reviewed_debian_inventory_rejects_ambiguous_architectures(self):
        self.assertEqual(module.reviewed_debian_inventory({'libpq5:amd64':'17.12-1','postgresql-client-16:amd64':'16.16-1','unrelated:all':'1.0'},{'libpq5','postgresql-client-16'}),{'libpq5':'17.12-1','postgresql-client-16':'16.16-1'})
        with self.assertRaisesRegex(ValueError,'MULTIARCH_REVIEW_REQUIRED'):
            module.reviewed_debian_inventory({'libpq5:amd64':'17.12-1','libpq5:i386':'17.12-1'},{'libpq5'})
        for name in ['libpq5','postgresql-common','postgresql-client-common']:
            self.assertIn(name,module.DEBIAN)
    @unittest.skipIf(sys.platform=='win32','actual POSIX process exits')
    def test_process_group_native_exit_churn_is_not_an_error(self):
        import subprocess
        for _ in range(75):
            process=subprocess.Popen(['/bin/true'])
            try:self.assertFalse(module.live_process_group(-1))
            finally:process.wait(timeout=5)
    def test_component_activation_failures_preserve_other_work_and_redact_details(self):
        def failed(_):raise ValueError('SYSTEM_SECURITY_NGINX_ACTIVATION_PENDING')
        self.assertEqual(module.service_activation_receipt(failed,{}),{'state':'pending','error':'SYSTEM_SECURITY_NGINX_ACTIVATION_PENDING'})
        def secret(_):raise OSError('private root credential and url')
        self.assertEqual(module.service_activation_receipt(secret,{}),{'state':'pending','error':'SYSTEM_SECURITY_SERVICE_ACTIVATION_PENDING'})
        self.assertEqual(module.service_activation_receipt(lambda _: {'state':'activated','pid':12},{}),{'state':'activated','pid':12})
    def test_security_maintenance_durable_retry_deadlines(self):
        now=1795400000
        for value,delay in [({},6*3600),({'nginxActivation':{'state':'draining'}},300),({'patchState':'failed'},300),({'clockActivation':{'state':'pending'}},300)]:
            updated=module.defer_security_check(value,now)
            self.assertFalse(module.security_patch_check_due(updated,now+delay-1))
            self.assertTrue(module.security_patch_check_due(updated,now+delay))
        for timestamp in ['invalid','2026-99-99T99:99:99Z','2999-01-01T00:00:00Z']:
            with self.assertRaises(ValueError):module.security_patch_check_due({'nextPatchCheckAt':timestamp},now)
    def test_managed_clock_security_activation_rejects_changed_configuration(self):
        before={'pid':12,'configurationHash':'config','helperHash':'helper'}
        for changed in [None,{**before,'pid':13},{**before,'configurationHash':'changed'}]:
            with patch.object(module,'managed_clock_security_proof',return_value=changed),patch.object(module,'command')as command,self.assertRaises(ValueError):
                module.activate_managed_clock(before)
            command.assert_not_called()
        with patch.object(module,'managed_clock_security_proof',side_effect=[before,{**before,'pid':13}]),patch.object(module,'command',return_value='{"state":"activated","synchronized":false}'):
            self.assertEqual(module.activate_managed_clock(before),{'state':'activated','pid':13,'synchronized':False})
    @unittest.skipIf(sys.platform=='win32','native socket symlinks')
    def test_nginx_socket_proof_excludes_worker_ipc(self):
        with tempfile.TemporaryDirectory()as folder:
            root=pathlib.Path(folder);(root/'net').mkdir();process=root/'2';(process/'fd').mkdir(parents=True)
            (root/'net/tcp').write_text('header\n0: 00000000:0050 00000000:0000 0A 0 0 0 0 0 123\n')
            (root/'net/unix').write_text('header\n000: 0 0 00000000 0001 03 456\n')
            (process/'fd/3').symlink_to('socket:[123]');(process/'fd/4').symlink_to('socket:[456]')
            self.assertEqual(module.nginx_listening_sockets(process,root),['socket:[123]'])
    def test_nginx_activation_rejects_changed_supervisor_before_signal(self):
        before={'pid':12,'servicePID':12,'start':'111','configurationHash':'original','unitHash':'unit','sockets':['socket:[1]']}
        for changed in [None,{**before,'pid':13},{**before,'configurationHash':'changed'},{**before,'sockets':['socket:[2]']}]:
            with patch.object(module,'nginx_master_proof',return_value=changed),patch.object(module.os,'kill')as signal,self.assertRaises(ValueError):
                module.activate_nginx_master(before)
            signal.assert_not_called()
        with patch.object(module,'nginx_master_proof',return_value=before),patch.object(module.pathlib,'Path')as path,patch.object(module,'replaced_host_mappings',return_value={'complete':True,'processes':[]}),patch.object(module.os,'kill')as signal:
            path.return_value.exists.return_value=False
            self.assertEqual(module.activate_nginx_master(before),{'state':'current','pid':12});signal.assert_not_called()
    def test_process_group_excludes_only_exited_states(self):
        with tempfile.TemporaryDirectory()as folder:
            root=pathlib.Path(folder);(root/'2').mkdir()
            for state in ['Z','X','R','S']:
                (root/'2/stat').write_text('2 (worker with spaces) '+state+' 1 100 100')
                self.assertEqual(module.live_process_group(100,root),state not in ['Z','X'])

    @unittest.skipIf(sys.platform=='win32','actual POSIX processes and groups')
    def test_bounded_command_child_cleanup_and_output(self):
        self.assertEqual(module.command(['/bin/sh','-c','printf valid'],3),'valid')
        for code in [0,7]:
            with self.assertRaisesRegex(ValueError,'SYSTEM_SECURITY_PACKAGE_'):
                module.command(['/bin/sh','-c','sleep 30 & exit '+str(code)],3)
        with self.assertRaisesRegex(ValueError,'SYSTEM_SECURITY_PACKAGE_'):
            module.command(['/bin/sh','-c','sleep 30'],.2)
    def test_ssh_listener_activation_keeps_unmodified_services_and_rejects_conflicts(self):
        before={'pid':12,'start':'111','configHash':'original','unitHash':'unit','defaultsHash':'defaults','hostKeyHash':'keys'}
        current={'complete':True,'processes':[]}
        with patch.object(module,'ssh_listener_proof',return_value=before),patch.object(module,'replaced_host_mappings',return_value=current),patch.object(module,'command')as command:
            self.assertEqual(module.activate_ssh_listener(before),{'state':'current','pid':12});command.assert_not_called()
        for changed in [{**before,'pid':13},{**before,'configHash':'changed'},{**before,'unitHash':'changed'},{**before,'hostKeyHash':'changed'}]:
            with patch.object(module,'ssh_listener_proof',return_value=changed),patch.object(module,'command')as command,self.assertRaises(ValueError):
                module.activate_ssh_listener(before)
            command.assert_not_called()
        with patch.object(module,'ssh_listener_proof',return_value=before),patch.object(module,'replaced_host_mappings',return_value={'complete':True,'processes':[{'pid':12}]}),patch.object(module,'command',return_value='changed')as command,self.assertRaisesRegex(ValueError,'CONFIG_CHANGED'):
            module.activate_ssh_listener(before)
        self.assertEqual(command.call_count,1,'changed effective configuration cannot reach service reload')
    def test_automatic_patch_policy_excludes_daemon_libc_and_kernel_actions(self):
        self.assertTrue(module.AUTOMATIC_DEBIAN<=set(module.DEBIAN))
        for name in ['openssl','libssl3','curl','libcurl4','ca-certificates','libsqlite3-0','libseccomp2','tar','gzip','xz-utils']:
            self.assertIn(name,module.AUTOMATIC_DEBIAN)
        for name in ['libc6','libc-bin','nginx','nodejs','systemd','chrony','dnsmasq','lxcfs','lvm2','nftables','rsync','postgresql-16','linux-image-amd64']:
            self.assertNotIn(name,module.AUTOMATIC_DEBIAN)
        with patch.object(module.os,'geteuid',return_value=0,create=True),patch.object(module.pathlib,'Path')as path,patch.object(module,'apply_patches')as apply:
            path.return_value.exists.return_value=True
            module.maintain_system_packages();apply.assert_not_called()
            path.return_value.exists.return_value=False;apply.return_value=None
            module.maintain_system_packages();apply.assert_called_once_with(automatic=True)
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
    def test_runtime_libc_requires_the_complete_same_upstream_pair(self):
        before={'libc6':'2.41-12+deb13u4','libc-bin':'2.41-12+deb13u4'}
        changes=['libc6=2.41-12+deb13u5','libc-bin=2.41-12+deb13u5']
        module.validate_runtime_libc_plan(changes,before)
        module.validate_runtime_libc_plan(['nodejs=24.22.3'],{})
        for installed,plan in [({'libc6':before['libc6']},changes),({**before,'libc-bin':'2.41-12+deb13u3'},changes),
            (before,changes[:1]),(before,[item.replace('2.41-12+deb13u5','2.42-1')for item in changes]),
            (before,[changes[0],'libc-bin=2.41-12+deb13u6'])]:
            with self.subTest(installed=installed,plan=plan),self.assertRaisesRegex(ValueError,'LIBC_GROUP_UNREVIEWED'):
                module.validate_runtime_libc_plan(plan,installed)
        with patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=0))as compare:
            output='Inst libc6 [2.41-12+deb13u4] (2.42-1 Debian:13/stable [arm64])'
            with self.assertRaisesRegex(ValueError,'PLAN_REJECTED'):module.patch_plan(output,before,module.RUNTIME_DEBIAN_BASE_LIBRARIES)
            compare.assert_not_called()
    def test_libc_runtime_transaction_preserves_shared_postgresql(self):
        changes=['libc6=2.41-12+deb13u5','libc-bin=2.41-12+deb13u5']
        self.assertTrue(module.runtime_patch_needs_database(changes,{'major':16}))
        self.assertFalse(module.runtime_patch_needs_database(changes,{'major':16,'sharedReadOnly':True}))
        with self.assertRaisesRegex(ValueError,'DATABASE_CHANGED'):module.runtime_patch_needs_database(changes,None)
        for database_change in ['postgresql-16=16.17','libpq5=18.8','postgresql-common=290']:
            with self.subTest(package=database_change),self.assertRaisesRegex(ValueError,'DATABASE_CHANGED'):
                module.runtime_patch_needs_database(changes+[database_change],{'major':16,'sharedReadOnly':True})
    def test_debian_kernel_uses_the_exact_meta_image_and_loaded_package_revision(self):
        import stat
        class Boot:
            def __init__(self):self.names=[]
            def __truediv__(self,name):self.names.append(name);return self
            def lstat(self):return types.SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=0,st_nlink=1,st_size=4096)
        for architecture in ['amd64','arm64']:
            target='6.12.118+deb13-'+architecture;image='linux-image-'+target;meta='linux-image-'+architecture
            packages={meta:'6.12.118-1',image:'6.12.118-1','linux-image-6.12.57+deb13-'+architecture:'6.12.57-1'}
            for running,build,state in [(target,'#1 SMP Debian 6.12.118-1 (2026-11-21)','current'),
                ('6.12.57+deb13-'+architecture,'#1 SMP Debian 6.12.57-1 (2026-08-01)','restart-required'),
                (target,'#1 SMP Debian 6.12.118-1~previous (2026-11-01)','restart-required'),
                (target,'#1 custom kernel','unreviewed')]:
                boot=Boot()
                with self.subTest(architecture=architecture,running=running,build=build),patch.object(module,'command',return_value=image+' (= 6.12.118-1)')as query:
                    result=module.debian_kernel_activation(running,packages,boot,running_build=build)
                self.assertEqual(result['state'],state)
                query.assert_called_once_with(['dpkg-query','-W','-f=${Depends}',meta],15)
                self.assertEqual(boot.names,['vmlinuz-'+target])
                if state!='unreviewed':self.assertEqual(result['packageVersion'],'6.12.118-1')
    def test_debian_kernel_refuses_unknown_dependency_flavour_or_boot_image(self):
        import stat
        class Boot:
            def __init__(self,metadata):self.metadata=metadata
            def __truediv__(self,name):return self
            def lstat(self):return self.metadata
        target='6.12.118+deb13-arm64';image='linux-image-'+target
        packages={'linux-image-arm64':'6.12.118-1',image:'6.12.118-1'}
        safe={'st_mode':stat.S_IFREG|0o644,'st_uid':0,'st_nlink':1,'st_size':4096}
        for delta in [{'st_mode':stat.S_IFLNK|0o777},{'st_mode':stat.S_IFREG|0o666},{'st_uid':1000},{'st_nlink':2},{'st_size':0},{'st_size':512*1024*1024+1}]:
            with self.subTest(metadata=delta),patch.object(module,'command',return_value=image+' (= 6.12.118-1)'):
                result=module.debian_kernel_activation(target,packages,Boot(types.SimpleNamespace(**{**safe,**delta})),running_build='#1 SMP Debian 6.12.118-1')
            self.assertEqual(result['state'],'unreviewed')
        for dependency in [image+' (= 6.12.118-2)',image+' | alternate-image',image+', unknown-hook',image.replace('arm64','amd64')]:
            with self.subTest(dependency=dependency),patch.object(module,'command',return_value=dependency):
                self.assertEqual(module.debian_kernel_activation(target,packages,Boot(types.SimpleNamespace(**safe)),running_build='#1 SMP Debian 6.12.118-1')['state'],'unreviewed')
        with patch.object(module,'command')as query:
            for running,current in [(target,{image:'6.12.118-1'}),('6.12.118-custom',packages),(None,packages)]:
                self.assertEqual(module.debian_kernel_activation(running,current)['state'],'unreviewed')
            query.assert_not_called()
        with patch.object(module,'command',side_effect=ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')):
            self.assertEqual(module.debian_kernel_activation(target,packages)['state'],'unreviewed')
    def test_debian_inventory_keeps_both_installed_and_running_kernel_images(self):
        target='6.12.118+deb13-arm64';running='6.12.57+deb13-arm64';build='#1 SMP Debian 6.12.57-1'
        installed={'linux-image-arm64:arm64':'6.12.118-1','linux-image-'+target+':arm64':'6.12.118-1','linux-image-'+running+':arm64':'6.12.57-1'}
        activation={'state':'restart-required','targetKernel':target,'packageVersion':'6.12.118-1'}
        with patch.object(module.pathlib,'Path')as path,patch.object(module.os,'uname',return_value=types.SimpleNamespace(release=running,version=build),create=True),patch.object(module,'debian_installed_packages',return_value=installed),patch.object(module,'command',return_value='')as command,patch.object(module,'replaced_host_mappings',return_value={}),patch.object(module,'debian_kernel_activation',return_value=activation)as kernel:
            path.return_value.read_text.return_value='ID=debian\nVERSION_ID=13\n';path.return_value.exists.return_value=False
            result=module.inventory()
        self.assertTrue(result['restartRequired'],'a missing reboot-required file must not hide an installed newer kernel')
        self.assertEqual(result['kernelActivation'],activation)
        self.assertEqual(result['packages'],{key.split(':')[0]:value for key,value in installed.items()})
        self.assertEqual(command.call_args.args[0][-3:],sorted(result['packages']))
        kernel.assert_called_once_with(running,result['packages'],running_build=build)
    def test_ubuntu_inventory_does_not_require_debian_build_metadata(self):
        running='6.8.0-1020-oracle';build='#21-Ubuntu SMP (2026-11-21)'
        installed={'linux-image-'+running+':arm64':'6.8.0-1020.21','openssl:arm64':'3.0.13-0ubuntu3.9'}
        with patch.object(module.pathlib,'Path')as path,patch.object(module.os,'uname',return_value=types.SimpleNamespace(release=running,version=build),create=True),patch.object(module,'debian_installed_packages',return_value=installed),patch.object(module,'command',return_value=''),patch.object(module,'replaced_host_mappings',return_value={}),patch.object(module,'debian_kernel_activation')as kernel:
            path.return_value.read_text.return_value='ID=ubuntu\nVERSION_ID=24.04\n';path.return_value.exists.return_value=False
            result=module.inventory()
        self.assertFalse(result['restartRequired'])
        self.assertNotIn('kernelActivation',result)
        kernel.assert_not_called()
    def test_kernel_pending_or_unknown_cannot_confirm_library_activation(self):
        value={'packages':{'libc6':'2.41-12+deb13u5'},'restartRequired':False,'loadedCode':{'complete':True,'allHostProcesses':True,'processes':[]}}
        for state in ['unreviewed','restart-required','unknown']:
            self.assertFalse(module.activation_verified({**value,'kernelActivation':{'state':state}},['libc6=2.41-12+deb13u5']))
        self.assertTrue(module.activation_verified({**value,'kernelActivation':{'state':'current'}},['libc6=2.41-12+deb13u5']))
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
    def test_installed_openssl_provider_is_part_of_the_complete_patch_plan(self):
        before={'openssl-provider-legacy':'3.5.7-1~deb13u3','libssl3t64':'3.5.7-1~deb13u3','openssl':'3.5.7-1~deb13u3'}
        output='\n'.join('Inst '+name+' ['+old+'] (3.5.9-1~deb13u1 Debian:13/stable [arm64])'for name,old in before.items())
        inventory=module.reviewed_debian_inventory({name+':arm64':old for name,old in before.items()},set(module.DEBIAN))
        self.assertEqual(inventory,before,'the provider must be inventoried before solving upgrades')
        with patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=0)):
            self.assertEqual(module.patch_plan(output,inventory,module.AUTOMATIC_DEBIAN),[name+'=3.5.9-1~deb13u1'for name in before])
            for unsafe in [output.replace('Inst openssl-provider-legacy [3.5.7-1~deb13u3]','Inst openssl-provider-legacy'),output.replace('3.5.9-1~deb13u1','4.0.0-1'),output+'\nInst unrelated-provider [1.0] (1.1 Debian:13/stable [arm64])']:
                with self.subTest(plan=unsafe),self.assertRaisesRegex(ValueError,'PLAN_REJECTED'):
                    module.patch_plan(unsafe,inventory,module.AUTOMATIC_DEBIAN)
        with patch.object(module.subprocess,'run',return_value=types.SimpleNamespace(returncode=1)),self.assertRaisesRegex(ValueError,'PLAN_REJECTED'):
            module.patch_plan(output,inventory,module.AUTOMATIC_DEBIAN)

class RuntimeDatabaseClients(unittest.TestCase):
    @staticmethod
    def tools(major=16,digest='a'):
        return {'version':1,'major':major,'files':{path:{'type':'file','mode':0o755,'uid':0,'gid':0,'size':8,'sha256':digest*64}for path in module.runtime_database_client_paths(major).values()}}

    @staticmethod
    def database(shared=False):
        return {'major':16,'data':'/var/lib/postgresql/16/main','config':'/etc/postgresql/16/main/postgresql.conf','hba':'/etc/postgresql/16/main/pg_hba.conf','unit':'postgresql@16-main.service','configHash':'a'*64,'hbaHash':'b'*64,'unitHash':'c'*64,'fileHashes':{'/etc/postgresql/16/main/postgresql.conf':'a'*64},'settingsHash':'d'*64,'settingsHashVersion':2,'pid':33,'start':'44',**({'sharedReadOnly':True}if shared else {})}

    def test_client_paths_reject_other_major_boolean_and_wrapper_selection(self):
        for major in [14,15,16,17,18]:
            paths=module.runtime_database_client_paths(major)
            self.assertEqual(paths,{name:'/usr/lib/postgresql/'+str(major)+'/bin/'+name for name in ['psql','pg_dump','pg_restore']})
        for major in [True,'16',None,13,19]:
            with self.assertRaisesRegex(ValueError,'CLIENT_UNCONFIRMED'):module.runtime_database_client_paths(major)

    def test_local_client_proof_refuses_invalid_permissions_links_missing_fields_and_major_drift(self):
        import copy
        proof=self.tools();module.validate_runtime_database_client_proof(proof,16)
        for change in ['major','version','missing','wrapper','symlink','writable','setuid','not-executable','boolean-mode']:
            changed=copy.deepcopy(proof);path=module.runtime_database_client_paths(16)['pg_dump']
            if change=='major':changed['major']=19
            elif change=='version':changed['version']=True
            elif change=='missing':changed['files'].pop(path)
            elif change=='wrapper':changed['files']['/usr/bin/pg_dump']=changed['files'].pop(path)
            elif change=='symlink':changed['files'][path]={'type':'symlink','mode':0o777,'uid':0,'gid':0,'target':'/usr/bin/pg_dump'}
            elif change=='writable':changed['files'][path]['mode']=0o775
            elif change=='setuid':changed['files'][path]['mode']=0o4755
            elif change=='not-executable':changed['files'][path]['mode']=0o644
            else:changed['files'][path]['mode']=True
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'CLIENT_UNCONFIRMED'):module.validate_runtime_database_client_proof(changed,16)

    def test_changed_tools_never_become_trusted_from_a_first_post_install_hash(self):
        import copy
        database={**self.database(),'clientTools':self.tools()};frozen=copy.deepcopy(database);changed=self.tools(digest='b')
        with patch.object(module,'runtime_database_client_files',return_value=changed),patch.object(module,'runtime_database_payload_clients',return_value=None)as source:
            for journal in [None,{'phase':'stopping-backend'},{'phase':'installed'}]:
                with self.subTest(journal=journal),self.assertRaisesRegex(ValueError,'CLIENT_CHANGED'):module.verify_runtime_database_clients(database,journal)
        self.assertEqual(database,frozen)
        with patch.object(module,'runtime_database_client_files')as files,patch.object(module,'runtime_database_payload_clients',return_value=None),self.assertRaisesRegex(ValueError,'BACKUP_PROOF_MISSING'):
            module.verify_runtime_database_clients(self.database(),{'phase':'installed'})
        files.assert_not_called()

    def test_tool_transition_accepts_only_original_authenticated_before_to_expected(self):
        import copy
        before=self.tools();expected=self.tools(digest='b');database={**self.database(),'clientTools':before};journal={'phase':'installed'}
        def source(_,major,label):self.assertEqual(major,16);return copy.deepcopy(before if label=='before'else expected)
        for current in [before,expected,{'version':1,'major':16,'files':{path:(expected if path.endswith('/pg_dump')else before)['files'][path]for path in before['files']}}]:
            with patch.object(module,'runtime_database_client_files',return_value=current),patch.object(module,'runtime_database_payload_clients',side_effect=source):
                paths,actual=module.verify_runtime_database_clients(database,journal);self.assertEqual(actual,current);self.assertEqual(paths['pg_dump'],'/usr/lib/postgresql/16/bin/pg_dump')
        for wrong in [self.tools(digest='c'),self.tools(major=18)]:
            with patch.object(module,'runtime_database_client_files',return_value=wrong),patch.object(module,'runtime_database_payload_clients',side_effect=source),self.assertRaisesRegex(ValueError,'CLIENT_CHANGED|CLIENT_UNCONFIRMED'):
                module.verify_runtime_database_clients(database,journal)
        with patch.object(module,'runtime_database_client_files',return_value=expected),patch.object(module,'runtime_database_payload_clients',side_effect=lambda _,major,label:self.tools(digest='c')if label=='before'else expected),self.assertRaisesRegex(ValueError,'CLIENT_CHANGED'):
            module.verify_runtime_database_clients(database,journal)

    def test_database_proof_selects_the_running_cluster_before_psql_even_with_a_newer_client_installed(self):
        import json
        rows=[{'version':'16','cluster':'main','port':5432,'running':1},{'version':'19','cluster':'unused','port':5433,'running':0}]
        database=self.database();settings={'settings':[['listen_addresses','localhost','default','postmaster']],'files':[],'invalid':0,'pending':0}
        class File:
            def __init__(self,*parts):self.path=str(pathlib.PurePosixPath(*[str(value)for value in parts]))
            def __truediv__(self,value):return File(self.path,value)
            def stat(self):return types.SimpleNamespace(st_uid=0)
            def readlink(self):return '/usr/lib/postgresql/16/bin/postgres'if self.path.endswith('/exe')else'pid:[1]'
            def read_text(self):return 'DATABASE_URL=postgresql://incudal:unit-fixture@127.0.0.1:5432/incudal\n'if self.path=='/opt/incudal/.env'else'33 (postgres) '+' '.join(['0']*19+['44'])
        def run(args,*_):
            if args==['pg_lsclusters','--json']:return json.dumps(rows)
            if args[0]=='runuser':
                self.assertEqual(args[4],'/usr/lib/postgresql/16/bin/psql')
                return json.dumps(settings if 'pg_file_settings'in args[-1]else{**database,'version':'160016','recovery':False,'replication':0,'otherDatabases':0,'otherClients':0})
            if args[:2]==['systemctl','is-active']:return 'active'
            self.assertEqual(args[:3],['systemctl','show','postgresql@16-main.service'])
            return 'MainPID=33\nFragmentPath=/usr/lib/systemd/system/postgresql@.service\nDropInPaths=\nExecStart={ argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect 16-main start ; }\nExecStop={ argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect -m fast 16-main stop ; }'
        with patch.object(module.pathlib,'Path',side_effect=File),patch.object(module,'protected_hash',return_value='f'*64),patch.object(module,'runtime_database_client_files',return_value=self.tools())as files,patch.object(module,'command',side_effect=run)as commands:
            proof=module.database_runtime_proof()
        self.assertEqual(proof['major'],16);self.assertEqual(commands.call_args_list[0].args[0],['pg_lsclusters','--json'])
        self.assertEqual([call.args for call in files.call_args_list],[(16,('psql',)),(16,('psql',))])
        self.assertFalse(any('19'in str(call.args)for call in files.call_args_list))
        for invalid in [[{**rows[0],'running':True}],[{**rows[0],'port':5433}],[{**rows[0],'version':'19'}],[rows[0],{**rows[0],'cluster':'second'}],[]]:
            with patch.object(module,'command',return_value=json.dumps(invalid))as commands,patch.object(module,'runtime_database_client_files')as files,self.assertRaisesRegex(ValueError,'CLUSTER'):
                module.database_runtime_proof()
            self.assertEqual(commands.call_count,1);files.assert_not_called()

    def test_dump_uses_the_bound_major_and_preserves_output_when_the_client_changes_during_execution(self):
        database={**self.database(),'clientTools':self.tools()};tools=self.tools();changed=self.tools(digest='b')
        with tempfile.TemporaryDirectory()as directory:
            path=pathlib.Path(directory)/'database.dump';calls=[]
            def process(args,**options):
                calls.append(args);os.write(options['stdout'],b'PGDMPoriginally completed data')
                return types.SimpleNamespace(pid=123,wait=lambda **_:0)
            with patch.object(module.os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True),patch.object(module,'verify_runtime_database_files')as configuration,patch.object(module,'runtime_database_client_files',side_effect=[tools,changed]),patch.object(module,'live_process_group',return_value=False),patch.object(module.subprocess,'Popen',side_effect=process),self.assertRaisesRegex(ValueError,'CLIENT_CHANGED'):
                module.dump_runtime_database(path,database)
            self.assertEqual(calls,[['runuser','-u','postgres','--','/usr/lib/postgresql/16/bin/pg_dump','-Fc','incudal']]);self.assertEqual(path.read_bytes(),b'PGDMPoriginally completed data')
            configuration.assert_called_once_with(database,backup_only=True)
            with patch.object(module,'runtime_database_client_files',side_effect=ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')),patch.object(module.subprocess,'Popen')as spawn,self.assertRaisesRegex(ValueError,'CLIENT_UNCONFIRMED'):
                module.dump_runtime_database(pathlib.Path(directory)/'never-created.dump',database)
            spawn.assert_not_called();self.assertFalse((path.parent/'never-created.dump').exists())

    @staticmethod
    def header(major=16,client=None,archive=15,server_version=None,client_version=None):
        client=major if client is None else client
        def integer(value):return bytes([int(value<0)])+abs(value).to_bytes(4,'little')
        def string(value):value=value.encode();return integer(len(value))+value
        return b'PGDMP'+bytes([1,archive,0,4,8,1])+(b'\x01'if archive>=15 else integer(1))+b''.join(integer(0)for _ in range(7))+string('incudal')+string(server_version or str(major)+'.16')+string(client_version or str(client)+'.16')+b'bound archive data'

    def test_legacy_major_comes_from_both_bound_original_dumps_without_executing_a_client(self):
        import hashlib
        for archive in [14,15,16]:
            with self.subTest(archive=archive),tempfile.TemporaryDirectory()as directory:
                root=pathlib.Path(directory);raw=self.header(archive=archive);journal={'dumpEvidence':{name:{'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw)}for name in ['database.dump','database-after-drain.dump']}}
                for name in journal['dumpEvidence']:(root/name).write_bytes(raw)
                def material(path):data=path.read_bytes();return {'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'header':data.startswith(b'PGDMP')}
                with patch.object(module,'runtime_dump_directory',return_value=root),patch.object(module,'runtime_dump_material',side_effect=material),patch.object(module.os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True),patch.object(module.os,'O_NONBLOCK',getattr(os,'O_NONBLOCK',0),create=True),patch.object(module,'command')as command:
                    self.assertEqual(module.runtime_original_dump_major(journal),16)
                    for bad in [self.header(client=18),self.header(major=18),raw[:12],b'PGDMPinvalid header']:
                        (root/'database-after-drain.dump').write_bytes(bad);journal['dumpEvidence']['database-after-drain.dump']={'sha256':hashlib.sha256(bad).hexdigest(),'size':len(bad)}
                        with self.assertRaisesRegex(ValueError,'BACKUP_PROOF_MISSING'):module.runtime_original_dump_major(journal)
                command.assert_not_called()

    def test_legacy_before_clients_are_used_without_rewriting_the_original_database_proof(self):
        import copy
        with self.legacy_cache()as(journal,backup,originals,_,before,command,download,write):
            original=self.database(shared=True);frozen=copy.deepcopy(original);journal['sharedDatabase']=original;bound=copy.deepcopy(journal)
            with patch.object(module,'runtime_database_payload_clients',return_value=before)as source,patch.object(module,'verify_runtime_database_files')as configuration:
                self.assertEqual(module.runtime_boot_backup_database(journal),original)
            self.assertEqual(original,frozen);self.assertEqual(journal,bound);self.assertNotIn('clientTools',original);self.assertNotIn('backupDatabase',journal);write.assert_not_called();command.assert_not_called();download.assert_not_called()
            source.assert_called_once_with(journal,16,'before');configuration.assert_called_once_with(original,backup_only=True)

    @contextlib.contextmanager
    def legacy_cache(self,kind='valid',client_major=16):
        # Exercise the real exact-cache, control/data parsing and legacy proof
        # chain. Only apt-cache output and root metadata are OS adapters; these
        # fixture archives are not an assertion of a vendor signature.
        import copy,hashlib,io,stat,tarfile
        real_path=pathlib.Path;server_version='16.16-1.pgdg13+1';client_version=str(client_major)+('.7'if client_major==18 else'.16');version=client_version+'-1.pgdg13+1';name='postgresql-client-'+str(client_major);architecture='amd64'
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w')as archive:
            for path in module.runtime_database_client_paths(client_major).values():
                content=('fixture '+path).encode();entry=tarfile.TarInfo(path.removeprefix('/'));entry.size=len(content);entry.mode=0o755;entry.uid=entry.gid=0;archive.addfile(entry,io.BytesIO(content))
        control=('Package: '+name+'\nVersion: '+version+'\nArchitecture: '+('arm64'if kind=='cache-architecture'else architecture)+'\n').encode()
        raw=DebianArchive.ar([('debian-binary',b'2.0\n'),('control.tar',DebianArchive.tar([('control',control)])),('data.tar',data.getvalue())])
        digest=hashlib.sha256(raw).hexdigest();source_raw=raw if kind!='cache-changed'else raw[:-1]+b'x'
        metadata='Package: '+name+'\nVersion: '+(version if kind!='wrong-before'else str(client_major)+'.15-1.pgdg13+1')+'\nArchitecture: '+architecture+'\nSHA256: '+digest+'\nSize: '+str(len(raw))+'\n'
        tools={'version':1,'major':client_major,'files':module.runtime_archive_payload(raw,{})}
        if kind=='tools-changed':tools=copy.deepcopy(tools);tools['files'][module.runtime_database_client_paths(client_major)['pg_dump']]['sha256']='f'*64
        if kind=='tools-major':tools=self.tools(major=16)
        with tempfile.TemporaryDirectory()as directory:
            backup=real_path(directory);journal=SystemdPolicy.journal();journal['phase']='installed';journal['backup']='runtime-backup-'+'f'*32
            for field in ['baselinePackages','expectedPackages']:
                journal[field].update({'postgresql-16:amd64':server_version,name+':'+architecture:version})
                if kind=='server-version':journal[field]['postgresql-16:amd64']='16.15-1.pgdg13+1'
                if kind=='client-version':journal[field][name+':'+architecture]=str(client_major)+'.6-1.pgdg13+1'
                if kind=='baseline-architecture':journal[field]['postgresql-16:arm64']=journal[field].pop('postgresql-16:amd64')
                if kind=='duplicate-client':journal[field][name+':arm64']=version
            def original_header(file):
                selected=client_major if kind!='dump-mismatch'or file=='database.dump'else(16 if client_major==18 else 18)
                if kind=='client19':selected=19
                upstream=str(selected)+'.6'if kind=='header-version'else(client_version if selected==client_major else str(selected)+'.16')
                return self.header(client=selected,archive=16 if client_major==18 else 15,client_version=upstream)
            originals={file:original_header(file)for file in ['database.dump','database-after-drain.dump']}
            for file,content in originals.items():(backup/file).write_bytes(content);(backup/file).chmod(0o600)
            journal['dumpEvidence']={file:{'sha256':hashlib.sha256(content).hexdigest(),'size':len(content)}for file,content in originals.items()}
            frozen=copy.deepcopy(journal)
            def material(path):content=path.read_bytes();return {'sha256':hashlib.sha256(content).hexdigest(),'size':len(content),'header':content.startswith(b'PGDMP')}
            file=types.SimpleNamespace(lstat=lambda:types.SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=0,st_nlink=1,st_size=len(source_raw)))
            cache=types.SimpleNamespace(is_symlink=lambda:False,stat=lambda:types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o755),glob=lambda _:[file]if kind!='cache-missing'else [])
            def path(value,*parts):return cache if str(value)=='/var/cache/apt/archives'else real_path(value,*parts)
            def cached(value,*_,**__):self.assertIs(value,file);return {'sha256':hashlib.sha256(source_raw).hexdigest(),'size':len(source_raw),'content':source_raw}
            with contextlib.ExitStack()as stack:
                adapters=[patch.object(module.pathlib,'Path',side_effect=path),patch.object(module,'runtime_dump_directory',return_value=backup),patch.object(module,'runtime_dump_material',side_effect=material),patch.object(module,'runtime_payload_layout',return_value={}),patch.object(module,'runtime_payload_regular',side_effect=cached),patch.object(module,'runtime_database_payload_clients',return_value=None),patch.object(module,'runtime_database_client_files',return_value=tools),patch.object(module,'database_runtime_proof',return_value=self.database(shared=True)),patch.object(module,'verify_runtime_database_files'),patch.object(module.os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True),patch.object(module.os,'O_NONBLOCK',getattr(os,'O_NONBLOCK',0),create=True)]
                for adapter in adapters:stack.enter_context(adapter)
                command=stack.enter_context(patch.object(module,'command',return_value=metadata));download=stack.enter_context(patch.object(module,'acquire_runtime_debian_archive'));write=stack.enter_context(patch.object(module,'write_runtime_maintenance'))
                yield journal,backup,originals,frozen,tools,command,download,write

    def test_legacy_exact_before_cache_proves_original_clients_without_download_or_receipt_changes(self):
        with self.legacy_cache()as(journal,backup,originals,frozen,tools,command,download,write):
            proven=module.runtime_boot_backup_database(journal)
            self.assertEqual(proven['major'],16);self.assertEqual(proven['clientTools'],tools);self.assertEqual(journal,frozen)
            self.assertTrue(command.call_args_list);self.assertTrue(all(call.args[0]==['apt-cache','show','postgresql-client-16:amd64=16.16-1.pgdg13+1']for call in command.call_args_list))
            download.assert_not_called();write.assert_not_called();self.assertNotIn('backupDatabase',journal)
            for name,content in originals.items():self.assertEqual((backup/name).read_bytes(),content)

    def test_legacy_cache_missing_changed_wrong_before_dump_mismatch_or_changed_tools_never_get_retrusted(self):
        for kind,error in [('cache-missing','BACKUP_PROOF_MISSING'),('cache-changed','BACKUP_PROOF_MISSING'),('wrong-before','BACKUP_PROOF_MISSING'),('dump-mismatch','BACKUP_PROOF_MISSING'),('tools-changed','CLIENT_CHANGED')]:
            with self.subTest(kind=kind),self.legacy_cache(kind)as(journal,backup,originals,frozen,tools,command,download,write):
                with self.assertRaisesRegex(ValueError,error):module.runtime_boot_backup_database(journal)
                self.assertEqual(journal,frozen);download.assert_not_called();write.assert_not_called()
                if kind=='dump-mismatch':command.assert_not_called()
                else:self.assertTrue(all(call.args[0][0]=='apt-cache'for call in command.call_args_list))
                for name,content in originals.items():self.assertEqual((backup/name).read_bytes(),content)

    def test_legacy_server16_client18_headers_are_separate_observations_and_client19_is_not_supported(self):
        import hashlib
        with self.legacy_cache(client_major=18)as(journal,backup,originals,frozen,tools,command,download,write):
            versions=module.runtime_original_dump_versions(journal)
            self.assertEqual(versions,{'major':16,'clientMajor':18,'server':'16.16','client':'18.7','serverHeader':'16.16','clientHeader':'18.7'})
            self.assertEqual(module.runtime_original_dump_major(journal),16);command.assert_not_called();download.assert_not_called();write.assert_not_called();self.assertEqual(journal,frozen)
            invalid=self.header(client=19,archive=16,client_version='19.0')
            for name in originals:
                (backup/name).write_bytes(invalid);journal['dumpEvidence'][name]={'sha256':hashlib.sha256(invalid).hexdigest(),'size':len(invalid)}
            with self.assertRaisesRegex(ValueError,'BACKUP_PROOF_MISSING'):module.runtime_original_dump_versions(journal)
            command.assert_not_called()

    def test_legacy_pg18_before_cache_selects_only_client18_and_retains_server16_permissions_and_receipts(self):
        import copy
        for binding in ['none','database','sharedDatabase']:
            with self.subTest(binding=binding),self.legacy_cache(client_major=18)as(journal,backup,originals,_,tools,command,download,write):
                if binding!='none':journal[binding]=self.database(shared=binding=='sharedDatabase')
                frozen=copy.deepcopy(journal);checked=[]
                def files(major,*_):checked.append(major);self.assertEqual(major,18);return copy.deepcopy(tools)
                with patch.object(module,'runtime_database_client_files',side_effect=files):
                    database=module.runtime_boot_backup_database(journal);paths,actual=module.verify_runtime_database_clients(database,journal)
                self.assertEqual(database['major'],16);self.assertEqual(database['unit'],'postgresql@16-main.service');self.assertEqual(paths['pg_dump'],'/usr/lib/postgresql/18/bin/pg_dump');self.assertEqual(actual,tools)
                if binding=='none':self.assertEqual(database['clientTools']['major'],18)
                else:self.assertEqual(database,frozen[binding]);self.assertNotIn('clientTools',journal[binding])
                self.assertTrue(checked);self.assertEqual(journal,frozen);self.assertNotIn('backupDatabase',journal);download.assert_not_called();write.assert_not_called()
                self.assertTrue(command.call_args_list);self.assertTrue(all(call.args[0]==['apt-cache','show','postgresql-client-18:amd64=18.7-1.pgdg13+1']for call in command.call_args_list))
                for name,content in originals.items():self.assertEqual((backup/name).read_bytes(),content)

    def test_legacy_cross_major_requires_matching_headers_versions_archives_architecture_and_tool_bytes(self):
        errors=[('cache-missing','BACKUP_PROOF_MISSING'),('cache-changed','BACKUP_PROOF_MISSING'),('wrong-before','BACKUP_PROOF_MISSING'),('dump-mismatch','BACKUP_PROOF_MISSING'),('server-version','BACKUP_PROOF_MISSING'),('client-version','BACKUP_PROOF_MISSING'),('baseline-architecture','BACKUP_PROOF_MISSING'),('cache-architecture','BACKUP_PROOF_MISSING'),('header-version','BACKUP_PROOF_MISSING'),('duplicate-client','BACKUP_PROOF_MISSING'),('client19','BACKUP_PROOF_MISSING'),('tools-major','CLIENT_UNCONFIRMED'),('tools-changed','CLIENT_CHANGED')]
        for kind,error in errors:
            with self.subTest(kind=kind),self.legacy_cache(kind,client_major=18)as(journal,backup,originals,frozen,tools,command,download,write):
                with self.assertRaisesRegex(ValueError,error):module.runtime_boot_backup_database(journal)
                self.assertEqual(journal,frozen);download.assert_not_called();write.assert_not_called()
                self.assertTrue(all(call.args[0][0]=='apt-cache'for call in command.call_args_list))
                for name,content in originals.items():self.assertEqual((backup/name).read_bytes(),content)

    def test_new_backup_proof_stays_same_major_and_cannot_claim_a_legacy_cross_major_exception(self):
        import copy
        with patch.object(module,'runtime_database_client_files',return_value=self.tools())as files:
            database=module.runtime_backup_database_proof(self.database())
        self.assertEqual(database['clientTools']['major'],16);files.assert_called_once_with(16)
        with self.legacy_cache(client_major=18)as(journal,backup,originals,_,tools,command,download,write):
            journal['backupDatabase']={**self.database(),'clientTools':tools};frozen=copy.deepcopy(journal)
            with patch.object(module,'runtime_database_client_files')as files,self.assertRaisesRegex(ValueError,'BACKUP_PROOF_MISSING'):module.runtime_boot_backup_database(journal)
            files.assert_not_called();command.assert_not_called();download.assert_not_called();write.assert_not_called();self.assertEqual(journal,frozen)

    def test_cross_major_dump_keeps_server_configuration_and_retains_output_when_client18_changes(self):
        import copy
        with self.legacy_cache(client_major=18)as(journal,backup,originals,frozen,tools,command,download,write):
            database=module.runtime_boot_backup_database(journal);target=backup/'new-boot.dump';changed=[False];calls=[];checked=[]
            def files(major,*_):
                checked.append(major);self.assertEqual(major,18);value=copy.deepcopy(tools)
                if changed[0]:value['files'][module.runtime_database_client_paths(18)['pg_dump']]['sha256']='f'*64
                return value
            def process(args,**options):
                calls.append(args);os.write(options['stdout'],self.header(client=18,archive=16,client_version='18.7'));changed[0]=True
                return types.SimpleNamespace(pid=123,wait=lambda **_:0)
            with patch.object(module,'runtime_database_client_files',side_effect=files),patch.object(module,'verify_runtime_database_files')as configuration,patch.object(module,'live_process_group',return_value=False),patch.object(module.subprocess,'Popen',side_effect=process),self.assertRaisesRegex(ValueError,'CLIENT_CHANGED'):
                module.dump_runtime_database(target,database,journal)
            self.assertEqual(calls,[['runuser','-u','postgres','--','/usr/lib/postgresql/18/bin/pg_dump','-Fc','incudal']]);self.assertTrue(checked);self.assertEqual(target.read_bytes(),self.header(client=18,archive=16,client_version='18.7'))
            configuration.assert_called_once_with(database,backup_only=True);self.assertEqual(configuration.call_args.args[0]['major'],16);self.assertEqual(journal,frozen);download.assert_not_called();write.assert_not_called()
            for name,content in originals.items():self.assertEqual((backup/name).read_bytes(),content)

    def test_legacy_client18_new_boot_dump_uses_absolute18_restore_and_never_grants_pg_service_actions(self):
        import copy
        with self.legacy_cache(client_major=18)as(journal,backup,originals,_,tools,command,download,write):
            journal['database']=None;original=journal['systemdPolicy'];original['bootId']='11111111-1111-4111-8111-111111111111';frozen=copy.deepcopy(original)
            derived=copy.deepcopy(original);derived.update(token='a'*32,bootId='22222222-2222-4222-8222-222222222222',directory='runtime-systemctl-'+'a'*32,ordinal=1,originalToken=original['token'],originHash=module.runtime_systemd_origin_hash(original),inheritedActions=[])
            journal['systemdBootPolicies']=[derived];recovery={'version':1,'bootId':derived['bootId'],'token':derived['token'],'phase':'prepared','drainConfirmed':True,'dumpPending':True};journal['bootRecoveries']={derived['bootId']:recovery}
            metadata=command.return_value;events=[];checked=[]
            def run(args,*_):
                if args==['apt-cache','show','postgresql-client-18:amd64=18.7-1.pgdg13+1']:return metadata
                self.assertEqual(args[:2],['/usr/lib/postgresql/18/bin/pg_restore','--file=/dev/null']);self.assertEqual(args[2],str(backup/recovery['dumpAttempts'][0]['file']));self.assertNotIn('--list',args);self.assertNotIn('--dbname',args);events.append('full-offline-restore');return ''
            def files(major,*_):checked.append(major);self.assertEqual(major,18);return copy.deepcopy(tools)
            def process(args,**options):
                self.assertEqual(args,['runuser','-u','postgres','--','/usr/lib/postgresql/18/bin/pg_dump','-Fc','incudal']);self.assertTrue(write.call_args_list);self.assertEqual(recovery['dumpAttempts'][0]['state'],'intent');events.append('dump18')
                os.write(options['stdout'],self.header(client=18,archive=16,client_version='18.7'));return types.SimpleNamespace(pid=123,wait=lambda **_:0)
            with patch.object(module,'runtime_database_client_files',side_effect=files),patch.object(module,'runtime_systemd_policy_lineage',side_effect=lambda value:[value['systemdPolicy'],*value.get('systemdBootPolicies',[])]),patch.object(module,'live_process_group',return_value=False),patch.object(module.subprocess,'Popen',side_effect=process),patch.object(module,'command',side_effect=run)as commands:
                module.runtime_new_boot_dump(journal,recovery);count=commands.call_count;module.runtime_new_boot_dump(journal,recovery);self.assertEqual(commands.call_count,count)
            self.assertEqual(events,['dump18','full-offline-restore']);self.assertTrue(checked);self.assertEqual(recovery['backupDatabase']['major'],16);self.assertEqual(recovery['backupDatabase']['clientTools']['major'],18);self.assertFalse(recovery['dumpPending']);self.assertEqual(recovery['dumpAttempts'][0]['state'],'complete')
            self.assertIsNone(journal['database']);self.assertNotIn('sharedDatabase',journal);self.assertNotIn('backupDatabase',journal);self.assertEqual(journal['systemdPolicy'],frozen);download.assert_not_called()
            for name,content in originals.items():self.assertEqual((backup/name).read_bytes(),content)

    def test_client_transition_rechecks_original_archive_version_controls_and_each_tool_payload(self):
        import copy,hashlib
        original_clients=module.runtime_database_payload_clients
        for major in [16,18]:
            with self.subTest(client_major=major),self.legacy_cache(client_major=major)as(journal,backup,originals,frozen,tools,command,download,write):
                name='postgresql-client-'+str(major);version=('16.16'if major==16 else'18.7')+'-1.pgdg13+1';target=('16.17'if major==16 else'18.8')+'-1.pgdg13+1'
                before,raw,controls=module.authenticated_debian_archive(name,version,'amd64',before=True);expected_raw=raw.replace(version.encode(),target.encode()).replace(b'fixture ',b'changed ')
                expected={**before,'version':target,'sha256':hashlib.sha256(expected_raw).hexdigest(),'size':len(expected_raw)};expected_controls=module.debian_archive_members(expected_raw)
                expected_tools={'version':1,'major':major,'files':module.runtime_archive_payload(expected_raw,{})};key=name+':amd64'
                journal['expectedPackages'][key]=target;journal['packages'].append(name+'='+target);journal['payloadEvidence']={'isolated':True}
                versions={}
                for label,record,body,selected_controls in [('before',before,raw,controls),('expected',expected,expected_raw,expected_controls)]:
                    versions[label]=record;versions[label+'File']=label+'-'+name+'-amd64.deb';versions[label+'Controls']={part:hashlib.sha256(content).hexdigest()for part,content in selected_controls.items()}
                value={'layout':{},'archives':{key:versions},'paths':{path:{'owners':[key],'conffile':False,'before':tools['files'][path],'expected':expected_tools['files'][path]}for path in tools['files']}}
                def archive(source,record,file):
                    self.assertIs(source,journal);label=file.split('-',1)[0];self.assertEqual(record,versions[label]);self.assertEqual(file,label+'-'+name+'-amd64.deb')
                    return record,raw if label=='before'else expected_raw,controls if label=='before'else expected_controls
                database={**self.database(),'clientTools':tools}
                with patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_cached_archive',side_effect=archive),patch.object(module,'runtime_database_client_files',return_value=expected_tools):
                    # legacy_cache supplies a no-payload adapter for other tests.
                    # This test explicitly uses the original client verifier.
                    with patch.object(module,'runtime_database_payload_clients',side_effect=original_clients):
                        self.assertEqual(module.verify_runtime_database_clients(database,journal)[1],expected_tools)
                        changed=copy.deepcopy(value);path=module.runtime_database_client_paths(major)['pg_dump'];changed['paths'][path]['expected']['sha256']='f'*64
                        with patch.object(module,'read_runtime_payload',return_value=changed),self.assertRaisesRegex(ValueError,'CLIENT_UNCONFIRMED'):module.verify_runtime_database_clients(database,journal)
                        for label in ['before','expected']:
                            changed=copy.deepcopy(value);changed['archives'][key][label+'Controls']['control']='f'*64
                            with patch.object(module,'read_runtime_payload',return_value=changed),self.assertRaisesRegex(ValueError,'ARCHIVE_CHANGED'):module.verify_runtime_database_clients(database,journal)
                            changed=copy.deepcopy(value);changed['archives'][key][label]['version']='19.0-1.pgdg13+1'
                            with patch.object(module,'read_runtime_payload',return_value=changed),self.assertRaisesRegex(ValueError,'CLIENT_UNCONFIRMED'):module.verify_runtime_database_clients(database,journal)

class SystemdPolicy(unittest.TestCase):
    def setUp(self):
        # This class isolates the manager/policy state machine. Full original
        # package-byte evidence is exercised separately by RuntimePayload.
        self.payload=self.enterContext(patch.object(module,'verify_runtime_payload',return_value={'unchanged':True,'complete':True,'incomplete':[]}))
        self.enterContext(patch.object(module,'verify_runtime_node_authority'))
    @staticmethod
    def journal():
        import hashlib
        architecture='amd64';token='e'*32;version='2.41-12+deb13u5'
        expected={'systemd:amd64':'257.13-1~deb13u1','libc6:amd64':version,'libc-bin:amd64':version}
        baseline={**expected,'libc6:amd64':'2.41-12+deb13u4','libc-bin:amd64':'2.41-12+deb13u4'}
        manager={'pid':1,'start':'0','binaryHash':'a'*64,'replacedLibraries':True}
        qualification={'manager':manager,'journald':{'pid':21,'start':'22','binaryHash':'b'*64,'replacedLibraries':True},'networkd':{'ActiveState':'inactive','MainPID':'0'},'journaldUnit':'c'*64,'state':{'networkHash':'d'*64,'configurationHashes':{}}}
        archives={name:{'package':name,'version':expected[name+':amd64'],'architecture':architecture,'size':100,'sha256':'f'*64}for name in ['systemd','libc6','libc-bin']}
        proof={'version':1,'ready':True,'token':token,'directory':'runtime-systemctl-'+token,'sourceHash':hashlib.sha256(module.RUNTIME_SYSTEMCTL_WRAPPER.encode()).hexdigest(),'bootId':'fixture-boot','programs':module.RUNTIME_SYSTEMD_PROGRAMS[architecture],'archives':archives,'qualification':qualification,
            'libcPrograms':{path:'0'*64 for path in module.RUNTIME_LIBC_FILES[architecture]},'libcProgramsArchive':'f'*64,'baselineLibcPrograms':{path:'1'*64 for path in module.RUNTIME_LIBC_FILES[architecture]}}
        return {'version':1,'phase':'installed','packages':['libc6='+version,'libc-bin='+version],'baselinePackages':baseline,'expectedPackages':expected,'systemdPolicy':proof}

    def test_installed_controls_allow_only_proven_missing_half_install_scripts(self):
        real_path=pathlib.Path
        with tempfile.TemporaryDirectory()as directory:
            info=real_path(directory);(info/'libc6:amd64.postinst').write_text('original')
            expected={'preinst':'a'*64,'postinst':'b'*64}
            with patch.object(module.pathlib,'Path',side_effect=lambda value:info if value=='/var/lib/dpkg/info'else real_path(value)),patch.object(module,'protected_hash',return_value='b'*64):
                with self.assertRaisesRegex(ValueError,'TRIGGER_UNREVIEWED'):module.installed_maintainer_controls('libc6','amd64',expected)
                module.installed_maintainer_controls('libc6','amd64',expected,incomplete=True)
                (info/'libc6:amd64.config').write_text('unknown')
                with self.assertRaisesRegex(ValueError,'TRIGGER_UNREVIEWED'):module.installed_maintainer_controls('libc6','amd64',expected,incomplete=True)
                (info/'libc6:amd64.config').unlink()
                with patch.object(module,'protected_hash',return_value='c'*64),self.assertRaisesRegex(ValueError,'TRIGGER_UNREVIEWED'):module.installed_maintainer_controls('libc6','amd64',expected,incomplete=True)

    def test_half_installed_libc_requires_original_wrapper_even_if_packages_match(self):
        journal=self.journal();journal.pop('systemdPolicy')
        with patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):module.complete_runtime_package_transaction(journal)
        command.assert_not_called()

    def test_unstarted_intent_requires_exact_original_packages_clean_audit_and_no_actions(self):
        journal=self.journal();journal['phase']='installing'
        states={key:{'version':value,'status':'installed'}for key,value in journal['baselinePackages'].items()}
        variants=[(states,'',[],True),({**states,'libc6:amd64':{**states['libc6:amd64'],'version':'2.41-12+deb13u5'}},'',[],False),({**states,'libc6:amd64':{**states['libc6:amd64'],'status':'half-installed'}},'',[],False),(states,'pending',[],False),(states,'',['manager'],False)]
        for packages,audit,actions,expected in variants:
            with patch.object(module,'debian_package_states',return_value=packages),patch.object(module,'command',return_value=audit),patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'runtime_library_file',return_value={'sha256':'1'*64}),patch.object(module,'read_runtime_systemctl_policy',return_value={'actions':actions,'rejected':False}):
                self.assertEqual(module.runtime_package_transaction_unstarted(journal),expected)
        with patch.object(module,'debian_package_states',return_value=states),patch.object(module,'command',return_value=''),patch.object(module,'verify_runtime_systemd_policy_packages',side_effect=ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')),self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):module.runtime_package_transaction_unstarted(journal)
        for changed,expected in [(False,False),(True,None)]:
            with patch.object(module,'debian_package_states',return_value=states),patch.object(module,'command',return_value=''),patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'verify_runtime_payload',side_effect=ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')if changed else None,return_value={'unchanged':False}),patch.object(module,'read_runtime_systemctl_policy',return_value={'actions':[],'rejected':False}):
                if expected is None:
                    with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.runtime_package_transaction_unstarted(journal)
                else:self.assertFalse(module.runtime_package_transaction_unstarted(journal))

    def test_systemd_trigger_consumer_resumes_only_two_original_pending_states(self):
        journal=self.journal();states={key:{'version':value,'status':'installed'}for key,value in journal['expectedPackages'].items()}
        for status in ['triggers-awaited','triggers-pending','half-configured','half-installed']:
            partial={**states,'systemd:amd64':{**states['systemd:amd64'],'status':status}}
            with patch.object(module,'debian_package_states',return_value=partial),patch.object(module,'debian_installed_packages',return_value=journal['expectedPackages']),patch.object(module,'prepare_service_policy')as policy,patch.object(module,'clean_service_policy'),patch.object(module,'runtime_package_command')as package,patch.object(module,'command',return_value=''):
                if status.startswith('triggers-'):
                    module.complete_runtime_package_transaction(journal)
                    self.assertEqual(package.call_args.args[0],['dpkg','--force-confold','--configure','systemd']);policy.assert_called_once()
                else:
                    with self.assertRaisesRegex(ValueError,'BASELINE_CHANGED'):module.complete_runtime_package_transaction(journal)
                    package.assert_not_called();policy.assert_not_called()

    def test_lost_cache_only_downloads_and_reauthenticates_original_exact_archive(self):
        journal=self.journal();records=journal['systemdPolicy']['archives'];calls=[]
        def archive(name,version,architecture,**_):
            calls.append(name)
            if name=='libc6'and calls.count(name)==1:raise ValueError('SYSTEM_SECURITY_ARCHIVE_NOT_CACHED')
            return records[name],b'fixture-archive',{}
        states={key:{'version':value,'status':'installed'}for key,value in journal['expectedPackages'].items()}
        def programs(_,names):return {name:journal['systemdPolicy']['programs'].get(name,journal['systemdPolicy']['libcPrograms'].get(name))for name in names}
        with patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:'fixture-boot')),patch.object(module,'debian_package_states',return_value=states),patch.object(module,'installed_maintainer_controls'),patch.object(module,'authenticated_debian_archive',side_effect=archive),patch.object(module,'reviewed_maintainer_controls'),patch.object(module,'runtime_archive_programs',side_effect=programs),patch.object(module,'command',return_value='')as command:
            module.verify_runtime_systemd_policy_packages(journal,archives=True)
        self.assertEqual(command.call_args.args[0],['/usr/bin/env','--chdir=/var/cache/apt/archives','apt-get','-o','APT::Get::AllowUnauthenticated=false','download','libc6:amd64=2.41-12+deb13u5'])
        self.assertEqual(calls,['systemd','libc6','libc6','libc-bin'])
        for invalid in ['SYSTEM_SECURITY_ARCHIVE_UNREVIEWED','SYSTEM_SECURITY_UNTRUSTED_PATH']:
            with patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module,'debian_package_states',return_value=states),patch.object(module,'installed_maintainer_controls'),patch.object(module,'authenticated_debian_archive',side_effect=ValueError(invalid)),patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,invalid):module.verify_runtime_systemd_policy_packages(journal,archives=True)
            command.assert_not_called()
        def drift(name,*_,**__):return {**records[name],'sha256':'0'*64},b'fixture',{}
        with patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module,'debian_package_states',return_value=states),patch.object(module,'installed_maintainer_controls'),patch.object(module,'authenticated_debian_archive',side_effect=drift),patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):module.verify_runtime_systemd_policy_packages(journal,archives=True)
        command.assert_not_called()

    def test_changed_archive_and_program_proofs_are_never_reauthenticated(self):
        import copy
        journal=self.journal();states={key:{'version':value,'status':'installed'}for key,value in journal['expectedPackages'].items()}
        for field,value in [('package','other'),('version','2.42-1'),('architecture','arm64'),('size',True),('sha256','bad')]:
            candidate=copy.deepcopy(journal);candidate['systemdPolicy']['archives']['systemd'][field]=value
            with patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module,'debian_package_states',return_value=states),patch.object(module,'installed_maintainer_controls')as scripts,patch.object(module,'authenticated_debian_archive')as archive,self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):module.verify_runtime_systemd_policy_packages(candidate,archives=True)
            scripts.assert_not_called();archive.assert_not_called()
        candidate=copy.deepcopy(journal);candidate['systemdPolicy']['programs']['usr/lib/systemd/systemd']='0'*64
        with patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module,'debian_package_states')as states,self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):module.verify_runtime_systemd_policy_packages(candidate)
        states.assert_not_called()

    def test_installed_registry_missing_controls_still_needs_original_cached_install_intent(self):
        import hashlib
        journal=self.journal();journal['payloadEvidence']={'fixture':True};journal['phase']='installing'
        states={key:{'version':version,'status':'installed'}for key,version in journal['expectedPackages'].items()}
        controls={'control':b'fixture','postinst':b'original'};digest={part:hashlib.sha256(data).hexdigest()for part,data in controls.items()}
        manifest={'archives':{name+':amd64':{'expected':journal['systemdPolicy']['archives'][name],'expectedFile':'expected-'+name+'-amd64.deb','expectedControls':digest}for name in ['libc6','libc-bin']}}
        def cached(_,record,__):return record,b'fixture',controls
        with patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module,'debian_package_states',return_value=states),patch.object(module,'read_runtime_payload',return_value=manifest),patch.object(module,'runtime_cached_archive',side_effect=cached),patch.object(module,'reviewed_maintainer_controls'),patch.object(module,'installed_maintainer_controls')as installed:
            module.verify_runtime_systemd_package_authority(journal)
            self.assertEqual({call.args[0]:call.kwargs['incomplete']for call in installed.call_args_list},{'systemd':False,'libc6':True,'libc-bin':True})
            journal['phase']='prepared';installed.reset_mock();module.verify_runtime_systemd_package_authority(journal)
            self.assertTrue(all(not call.kwargs['incomplete']for call in installed.call_args_list),'initial qualification must still refuse missing installed controls')
            journal['phase']='installing';manifest['archives']['libc6:amd64']['expectedControls']={'control':'a'*64}
            with self.assertRaisesRegex(ValueError,'ARCHIVE_CHANGED'):module.verify_runtime_systemd_package_authority(journal)

    def test_package_command_checks_executable_policy_and_never_falls_through(self):
        journal=self.journal();proof=journal['systemdPolicy'];previous=os.environ.get('PATH')
        with patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'ensure_runtime_systemctl_policy',side_effect=ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')),patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):module.runtime_package_command(['dpkg','--configure','libc6'],journal,30)
        command.assert_not_called()
        with patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'ensure_runtime_systemctl_policy'),patch.object(module,'runtime_systemd_qualification',return_value=proof['qualification']),patch.object(module,'runtime_systemctl_policy_directory',return_value='/fixture'),patch.object(module,'read_runtime_systemctl_policy',side_effect=ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_REJECTED')),patch.object(module,'command',return_value='ignored hook error')as command,self.assertRaisesRegex(ValueError,'POLICY_REJECTED'):module.runtime_package_command(['dpkg','--configure','libc6'],journal,30)
        self.assertEqual(command.call_args.args[0],['/usr/bin/env','PATH=/fixture:/usr/sbin:/usr/bin:/sbin:/bin','dpkg','--configure','libc6']);self.assertEqual(os.environ.get('PATH'),previous)

    def test_systemd_activation_proves_pid_one_and_lost_responses_then_is_idempotent(self):
        import copy
        journal=self.journal();proof=journal['systemdPolicy'];proof.update(cleared=True,deferredActions=list(module.RUNTIME_SYSTEMCTL_ACTIONS.values()))
        before=copy.deepcopy(proof['qualification']);manager_loaded=copy.deepcopy(before);manager_loaded['manager']['replacedLibraries']=False
        activated=copy.deepcopy(manager_loaded);activated['journald'].update(pid=23,start='44',replacedLibraries=False)
        with patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:'fixture-boot')),patch.object(module,'runtime_systemd_qualification',side_effect=[before,manager_loaded,activated]),patch.object(module,'runtime_systemd_process',return_value=manager_loaded['manager']),patch.object(module,'write_runtime_maintenance'),patch.object(module,'command',side_effect=ValueError('SYSTEM_SECURITY_QUERY_FAILED'))as command:
            module.activate_runtime_systemd(journal)
        self.assertEqual([call.args[0]for call in command.call_args_list],[['systemctl','daemon-reexec'],['systemctl','try-restart','systemd-journald.service']])
        self.assertEqual(proof['activation']['state'],'activated');self.assertEqual(proof['qualification']['manager']['start'],'0')
        with patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:'fixture-boot')),patch.object(module,'runtime_systemd_qualification',return_value=activated),patch.object(module,'write_runtime_maintenance'),patch.object(module,'command')as command:
            module.activate_runtime_systemd(journal)
        command.assert_not_called()

    def test_changed_manager_or_configuration_prevents_further_activation_actions(self):
        import copy
        journal=self.journal();proof=journal['systemdPolicy'];proof.update(cleared=True,deferredActions=list(module.RUNTIME_SYSTEMCTL_ACTIONS.values()))
        for field in ['manager','state','networkd','journaldUnit']:
            changed=copy.deepcopy(proof['qualification'])
            if field=='manager':changed[field]['start']='1'
            elif field=='journaldUnit':changed[field]='changed'
            else:changed[field]['changed']='unexpected'
            with patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:'fixture-boot')),patch.object(module,'runtime_systemd_qualification',return_value=changed),patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'PROCESS_CHANGED|CONFIGURATION_CHANGED'):module.activate_runtime_systemd(journal)
            command.assert_not_called()
        changed=copy.deepcopy(proof['qualification']);changed['manager']['replacedLibraries']=False;changed['state']['changed']='unexpected'
        manager={**proof['qualification']['manager'],'replacedLibraries':False}
        with patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:'fixture-boot')),patch.object(module,'runtime_systemd_qualification',side_effect=[proof['qualification'],changed]),patch.object(module,'runtime_systemd_process',return_value=manager),patch.object(module,'write_runtime_maintenance'),patch.object(module,'command',return_value='')as command,self.assertRaisesRegex(ValueError,'CONFIGURATION_CHANGED'):module.activate_runtime_systemd(journal)
        self.assertEqual([call.args[0]for call in command.call_args_list],[['systemctl','daemon-reexec']])

    def test_systemd_qualification_never_touches_active_user_managers_or_networkd(self):
        for active_user,network in [('user@0.service active running',''),('', 'LoadState=loaded\nActiveState=active\nMainPID=5\nFragmentPath=/usr/lib/systemd/system/systemd-networkd.service\nDropInPaths=')]:
            with patch.object(module,'command',side_effect=[active_user,network])as command,patch.object(module,'runtime_systemd_process')as process,self.assertRaisesRegex(ValueError,'USER_MANAGERS_ACTIVE|NETWORKD_ACTIVE'):module.runtime_systemd_qualification({})
            process.assert_not_called();self.assertTrue(all(call.args[0][1]in ['list-units','show']for call in command.call_args_list))

    def test_systemd_network_receipt_covers_ipv6_and_ignores_lease_countdown(self):
        import copy,json,glob
        addresses=[{'ifindex':2,'ifname':'eth0','addr_info':[{'family':'inet','local':'192.0.2.1','prefixlen':24,'scope':'global','valid_life_time':100}]}]
        route4=[{'dst':'default','gateway':'192.0.2.254','dev':'eth0'}];route6=[{'dst':'default','gateway':'2001:db8::1','dev':'eth0'}]
        def receipt(address,ipv6):
            with patch.object(module,'command',side_effect=[json.dumps(address),json.dumps(route4),json.dumps(ipv6)])as command,patch.object(glob,'glob',return_value=[]):
                result=module.runtime_systemd_state()
            self.assertEqual(command.call_args.args[0],['ip','-6','-j','route','show','table','all']);return result
        original=receipt(addresses,route6);changed=copy.deepcopy(addresses);changed[0]['addr_info'][0]['valid_life_time']=99
        self.assertEqual(original,receipt(changed,route6));self.assertNotEqual(original,receipt(addresses,[{**route6[0],'gateway':'2001:db8::2'}]));self.assertTrue(receipt(addresses,[])['networkHash'])

    def test_libc_mapping_requires_current_file_inode_device_and_host_namespace(self):
        import io
        files={name:{'path':'/'+name,'sha256':'0'*64,'inode':number,'device':[8,1]}for number,name in enumerate(sorted(module.RUNTIME_LIBC_FILES['amd64']),51)}
        original='\n'.join('a-b r-xp 0 08:01 '+str(info['inode'])+' '+info['path']for info in files.values());maps=original
        guest=False;root_stat=types.SimpleNamespace(st_dev=1,st_ino=1)
        class Path:
            def __init__(self,*parts):self.path=str(pathlib.PurePosixPath(*parts))
            def __truediv__(self,value):return Path(self.path,value)
            def __str__(self):return self.path
            @property
            def name(self):return pathlib.PurePosixPath(self.path).name
            def resolve(self):return self
            def readlink(self):return 'pid:[2]'if guest and self.path=='/proc/12/ns/pid'else'pid:[1]'
            def stat(self):return root_stat
            def open(self):return io.StringIO(maps)
        with patch.object(module.pathlib,'Path',side_effect=Path):
            module.verify_runtime_libc_process(12,files)
            for invalid in [original.replace('08:01','08:02'),original.replace(' 51 ',' 999 '),original.replace('libc.so.6','libc.so.6.dpkg-tmp'),'\n'.join(line for line in original.splitlines()if not line.endswith('libc.so.6'))]:
                maps=invalid
                with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.verify_runtime_libc_process(12,files)
            maps=original;guest=True
            with self.assertRaisesRegex(ValueError,'PROCESS_CHANGED'):module.verify_runtime_libc_process(12,files)

    @contextlib.contextmanager
    def boot_fixture(self,rejected=False):
        import copy
        from unittest.mock import MagicMock
        journal=self.journal();proof=journal['systemdPolicy'];proof['bootId']='11111111-1111-4111-8111-111111111111';current_boot='22222222-2222-4222-8222-222222222222'
        proof['qualification']['journaldUnit']=proof['programs']['usr/lib/systemd/system/systemd-journald.service'];proof.update(cleared=not rejected,deferredActions=list(module.RUNTIME_SYSTEMCTL_ACTIONS.values()),cleanupHashes={'systemctl':proof['sourceHash'],'policy.lock':'2'*64,'policy.json':'3'*64})
        states={key:{'version':value,'status':'installed'}for key,value in journal['expectedPackages'].items()}
        manager={'pid':1,'start':'0','binaryHash':proof['programs']['usr/lib/systemd/systemd'],'replacedLibraries':False};journald={'pid':23,'start':'4','binaryHash':proof['programs']['usr/lib/systemd/systemd-journald'],'replacedLibraries':False}
        files={key:{'path':'/'+key,'sha256':value,'inode':number,'device':[8,1]}for number,(key,value)in enumerate(proof['libcPrograms'].items(),51)}
        service='LoadState=loaded\nActiveState=active\nMainPID=23\nFragmentPath=/usr/lib/systemd/system/systemd-journald.service\nDropInPaths='
        root=MagicMock();root.exists.return_value=rejected;root.lstat.side_effect=None if rejected else FileNotFoundError();root.iterdir.return_value=[types.SimpleNamespace(name=name)for name in ['systemctl','policy.lock','policy.json']];root.__truediv__.return_value='fixture-source'
        def hashed(path,*_,**__):return proof['sourceHash']if path=='fixture-source'else proof['programs'][str(path).removeprefix('/')]
        with contextlib.ExitStack()as stack:
            for context in [patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:current_boot)),patch.object(module,'debian_package_states',return_value=states),patch.object(module,'verify_runtime_systemd_package_authority'),patch.object(module,'protected_hash',side_effect=hashed),patch.object(module,'runtime_systemd_state',return_value={'configurationHashes':{},'networkHash':'f'*64}),patch.object(module,'runtime_systemctl_policy_directory',return_value=root),patch.object(module,'read_runtime_systemctl_policy',return_value={'actions':[],'rejected':rejected})]:stack.enter_context(context)
            file_check=stack.enter_context(patch.object(module,'runtime_libc_files',return_value=files));mapped=stack.enter_context(patch.object(module,'verify_runtime_libc_process'));process=stack.enter_context(patch.object(module,'runtime_systemd_process',side_effect=[manager,journald]));command=stack.enter_context(patch.object(module,'command',side_effect=lambda args,*_:''if args==['dpkg','--audit']else service))
            yield journal,file_check,mapped,process,command,copy.deepcopy(proof)

    def test_new_boot_reads_expected_payload_and_preserves_original_nonce_without_actions(self):
        with self.boot_fixture()as(journal,files,mapped,process,command,original):
            confirmation=module.runtime_systemd_boot_confirmation(journal)
            self.assertEqual(confirmation['mode'],'new-boot-read-only');self.assertEqual(confirmation['originalBootId'],original['bootId']);self.assertNotEqual(confirmation['bootId'],original['bootId']);self.assertEqual(journal['systemdPolicy'],original)
            self.assertEqual([call.args[0]for call in mapped.call_args_list],[1,23]);self.assertIn('libcFiles',confirmation)
            self.assertTrue(all(call.args[0]==['dpkg','--audit']or call.args[0][:2]==['systemctl','show']for call in command.call_args_list))
        with self.boot_fixture()as(journal,files,mapped,process,command,original):
            files.side_effect=ValueError('SYSTEM_SECURITY_LIBC_PAYLOAD_UNCONFIRMED')
            with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.runtime_systemd_boot_confirmation(journal)
            process.assert_not_called();mapped.assert_not_called();self.assertEqual(journal['systemdPolicy'],original)
        with self.boot_fixture(rejected=True)as(journal,files,mapped,process,command,original):
            with self.assertRaisesRegex(ValueError,'POLICY_REJECTED'):module.runtime_systemd_boot_confirmation(journal)
            self.assertEqual(journal['systemdPolicy'],original)

class SystemdBootRecovery(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(module,'verify_runtime_payload',return_value={'unchanged':False,'complete':False,'incomplete':['libc6:amd64']}))
        self.enterContext(patch.object(module,'verify_runtime_node_authority'))
        # This class isolates lineage/state; the native policy tests below
        # independently exercise partial-file recovery on actual inodes.
        self.enterContext(patch.object(module,'repair_runtime_unready_policy_files'))

    def test_new_boot_uses_a_bounded_derived_nonce_and_reuses_same_boot_without_changing_original(self):
        import copy,hashlib,json
        journal=SystemdPolicy.journal();original=journal['systemdPolicy'];original['bootId']='11111111-1111-4111-8111-111111111111'
        frozen=copy.deepcopy(original);boot=['22222222-2222-4222-8222-222222222222']
        def history(proof):return {'token':proof['token'],'bootId':proof['bootId'],'actions':['manager']if proof is original else[],'receiptHash':hashlib.sha256(proof['token'].encode()).hexdigest()}
        qualification=copy.deepcopy(original['qualification']);qualification['manager']['start']='new-boot'
        with patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:boot[0])),patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module,'runtime_systemd_policy_history',side_effect=history),patch.object(module,'verify_runtime_systemd_package_authority')as authority,patch.object(module,'runtime_systemd_qualification',return_value=qualification)as qualify,patch.object(module,'write_runtime_maintenance')as write,patch.object(module.uuid,'uuid4',side_effect=[types.SimpleNamespace(hex=value*32)for value in ['a','b','c']])as nonce:
            derived=module.prepare_runtime_systemd_boot_policy(journal)
            self.assertEqual(derived['ordinal'],1);self.assertEqual(derived['originalToken'],original['token']);self.assertNotEqual(derived['token'],original['token'])
            self.assertEqual(derived['originHash'],module.runtime_systemd_origin_hash(original));self.assertEqual(derived['inheritedActions'],['manager'])
            self.assertEqual(derived['historyHash'],hashlib.sha256(json.dumps([history(original)],sort_keys=True,separators=(',',':')).encode()).hexdigest())
            self.assertIs(module.prepare_runtime_systemd_boot_policy(journal),derived);self.assertEqual(nonce.call_count,1);self.assertEqual(qualify.call_count,1)
            for value in ['33333333-3333-4333-8333-333333333333','44444444-4444-4444-8444-444444444444']:
                boot[0]=value;module.prepare_runtime_systemd_boot_policy(journal)
            self.assertEqual([proof['ordinal']for proof in journal['systemdBootPolicies']],[1,2,3]);self.assertEqual(nonce.call_count,3);self.assertEqual(write.call_count,3)
            boot[0]='55555555-5555-4555-8555-555555555555'
            with self.assertRaisesRegex(ValueError,'BOOT_RECOVERY_LIMIT'):module.prepare_runtime_systemd_boot_policy(journal)
            self.assertEqual(nonce.call_count,3)
        self.assertEqual(journal['systemdPolicy'],frozen);self.assertEqual(authority.call_count,3)

    def test_old_rejection_and_changed_origin_or_inherited_history_never_get_a_new_permission(self):
        import copy,hashlib
        journal=SystemdPolicy.journal();original=journal['systemdPolicy'];original['bootId']='11111111-1111-4111-8111-111111111111'
        boot='22222222-2222-4222-8222-222222222222'
        def history(proof):return {'token':proof['token'],'bootId':proof['bootId'],'actions':[],'receiptHash':hashlib.sha256(proof['token'].encode()).hexdigest()}
        with patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:boot)),patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module,'runtime_systemd_policy_history',side_effect=ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_REJECTED')),patch.object(module.uuid,'uuid4')as nonce,patch.object(module,'runtime_systemd_qualification')as qualify,self.assertRaisesRegex(ValueError,'POLICY_REJECTED'):
            module.prepare_runtime_systemd_boot_policy(journal)
        nonce.assert_not_called();qualify.assert_not_called();self.assertNotIn('systemdBootPolicies',journal)
        with patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:boot)),patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module,'runtime_systemd_policy_history',side_effect=history),patch.object(module,'verify_runtime_systemd_package_authority'),patch.object(module,'runtime_systemd_qualification',return_value=original['qualification']),patch.object(module,'write_runtime_maintenance'),patch.object(module.uuid,'uuid4',return_value=types.SimpleNamespace(hex='a'*32)):
            module.prepare_runtime_systemd_boot_policy(journal)
        for field in ['origin','archives','inherited']:
            candidate=copy.deepcopy(journal)
            if field=='origin':candidate['systemdPolicy']['qualification']['state']['networkHash']='changed'
            elif field=='archives':candidate['systemdBootPolicies'][0]['archives']['libc6']['sha256']='0'*64
            else:candidate['systemdBootPolicies'][0]['inheritedActions']=['manager']
            with patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:boot)),patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module,'runtime_systemd_policy_history',side_effect=history),patch.object(module.uuid,'uuid4')as nonce,self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):
                module.prepare_runtime_systemd_boot_policy(candidate)
            nonce.assert_not_called()

    def test_new_boot_identifiers_and_ordinals_reject_noncanonical_or_boolean_values(self):
        import copy,hashlib
        journal=SystemdPolicy.journal();original=journal['systemdPolicy'];original['bootId']='11111111-1111-4111-8111-111111111111'
        boot='22222222-2222-4222-8222-222222222222'
        for before,current in [('a'*36,boot),(original['bootId'],'b'*36)]:
            candidate=copy.deepcopy(journal);candidate['systemdPolicy']['bootId']=before
            with patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:current)),patch.object(module,'write_runtime_maintenance')as write,patch.object(module.uuid,'uuid4')as nonce,patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'PROCESS_CHANGED'):
                module.prepare_runtime_systemd_boot_policy(candidate)
            nonce.assert_not_called();write.assert_not_called();command.assert_not_called()
        def history(proof):return {'token':proof['token'],'bootId':proof['bootId'],'actions':[],'receiptHash':hashlib.sha256(proof['token'].encode()).hexdigest()}
        with patch.object(module.pathlib,'Path',return_value=types.SimpleNamespace(read_text=lambda:boot)),patch.object(module,'runtime_systemctl_policy_directory'),patch.object(module,'runtime_systemd_policy_history',side_effect=history),patch.object(module,'verify_runtime_systemd_package_authority'),patch.object(module,'runtime_systemd_qualification',return_value=original['qualification']),patch.object(module,'write_runtime_maintenance'),patch.object(module.uuid,'uuid4',return_value=types.SimpleNamespace(hex='a'*32)):
            module.prepare_runtime_systemd_boot_policy(journal)
        for value in [True,1.0,'1']:
            candidate=copy.deepcopy(journal);candidate['systemdBootPolicies'][0]['ordinal']=value
            with patch.object(module,'runtime_systemctl_policy_directory'),self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):module.runtime_systemd_policy_lineage(candidate)

    def test_unreadable_policy_history_is_not_treated_as_absent_in_python_314(self):
        import errno
        from unittest.mock import MagicMock
        proof=SystemdPolicy.journal()['systemdPolicy'];proof.update(cleared=True,cleanupHashes={'systemctl':proof['sourceHash'],'policy.lock':'1'*64,'policy.json':'2'*64},deferredActions=[])
        root=MagicMock();root.exists.return_value=False;root.is_symlink.return_value=False
        for error in [PermissionError(errno.EACCES,'fixture unavailable'),OSError(errno.EIO,'fixture unavailable')]:
            root.lstat.side_effect=error
            with patch.object(module,'runtime_systemctl_policy_directory',return_value=root),self.assertRaisesRegex(ValueError,'UNTRUSTED_PATH'):module.runtime_systemd_policy_history(proof)
        root.exists.assert_not_called();root.is_symlink.assert_not_called()
        root.lstat.side_effect=FileNotFoundError();self.assertFalse(module.runtime_path_present(root))
        namespace={};exec(module.RUNTIME_SYSTEMCTL_WRAPPER.split('try:sys.exit(execute())',1)[0],namespace)
        base=MagicMock();base.__truediv__.return_value=root
        for error in [PermissionError(errno.EACCES,'fixture unavailable'),OSError(errno.EIO,'fixture unavailable')]:
            root.lstat.side_effect=error
            with self.assertRaises(OSError):namespace['history'](proof,base,module.RUNTIME_SYSTEMCTL_WRAPPER.encode())
        root.exists.assert_not_called();root.is_symlink.assert_not_called()

    def test_unreadable_maintenance_journal_never_starts_or_installs_or_replaces_its_intent(self):
        import errno
        from unittest.mock import MagicMock
        path=MagicMock();path.exists.return_value=False;path.is_symlink.return_value=False
        for error in [PermissionError(errno.EACCES,'fixture unavailable'),OSError(errno.EIO,'fixture unavailable')]:
            path.lstat.side_effect=error
            with patch.object(module,'command')as command,patch.object(module,'complete_runtime_package_transaction')as install,patch.object(module,'write_runtime_maintenance')as write,patch.object(module,'protected_hash')as read,self.assertRaisesRegex(ValueError,'UNTRUSTED_PATH'):
                module.recover_runtime_maintenance(path)
            command.assert_not_called();install.assert_not_called();write.assert_not_called();read.assert_not_called()
        path.exists.assert_not_called();path.is_symlink.assert_not_called()

    @staticmethod
    def database():
        return {'major':16,'data':'/var/lib/postgresql/16/main','config':'/etc/postgresql/16/main/postgresql.conf','hba':'/etc/postgresql/16/main/pg_hba.conf','unit':'postgresql@16-main.service','configHash':'a'*64,'hbaHash':'b'*64,'unitHash':'c'*64,'fileHashes':{'/etc/postgresql/16/main/postgresql.conf':'a'*64},'settingsHash':'d'*64,'settingsHashVersion':2,'pid':33,'start':'44','sharedReadOnly':True,'otherDatabases':6,'otherClients':4}

    def test_shared_database_new_boot_pid_is_fixed_even_after_other_clients_disappear(self):
        import copy
        journal=SystemdPolicy.journal();journal['systemdPolicy']['bootId']='11111111-1111-4111-8111-111111111111';journal['sharedDatabase']=self.database()
        before=copy.deepcopy(journal['sharedDatabase']);fresh={**before,'pid':133,'start':'new-start','otherClients':0};new_boot='22222222-2222-4222-8222-222222222222'
        with patch.object(module,'database_runtime_proof',side_effect=lambda **_:copy.deepcopy(fresh)),patch.object(module,'write_runtime_maintenance')as write,patch.object(module,'command')as command:
            saved=module.runtime_boot_shared_database(journal,new_boot);self.assertEqual(saved['pid'],133);self.assertEqual(write.call_count,1)
            fresh['otherDatabases']=0;self.assertEqual(module.runtime_boot_shared_database(journal,new_boot),saved);self.assertEqual(write.call_count,1)
            fresh['pid']=134
            with self.assertRaisesRegex(ValueError,'DATABASE_PROCESS_CHANGED'):module.runtime_boot_shared_database(journal,new_boot)
            self.assertEqual(journal['bootSharedDatabases'][new_boot]['proof']['pid'],133);self.assertEqual(write.call_count,1)
            with self.assertRaisesRegex(ValueError,'DATABASE_PROCESS_CHANGED'):module.runtime_boot_shared_database(journal,journal['systemdPolicy']['bootId'])
        command.assert_not_called();self.assertEqual(journal['sharedDatabase'],before)

    def test_shared_database_old_settings_hash_and_new_boot_count_are_not_reissued(self):
        import copy
        journal=SystemdPolicy.journal();journal['systemdPolicy']['bootId']='11111111-1111-4111-8111-111111111111';journal['sharedDatabase']=self.database();journal['sharedDatabase'].pop('settingsHashVersion')
        current={**journal['sharedDatabase'],'settingsHash':'e'*64,'settingsHashVersion':2,'settingsLegacyHash':'d'*64,'otherClients':0}
        with patch.object(module,'database_runtime_proof',side_effect=lambda **_:copy.deepcopy(current)),patch.object(module,'write_runtime_maintenance')as write:
            for index,boot in enumerate(['22222222-2222-4222-8222-222222222222','33333333-3333-4333-8333-333333333333','44444444-4444-4444-8444-444444444444'],101):
                current['pid']=index;current['start']=str(index);module.runtime_boot_shared_database(journal,boot)
            self.assertEqual(write.call_count,3)
            current['pid']=104
            with self.assertRaisesRegex(ValueError,'BOOT_RECOVERY_LIMIT'):module.runtime_boot_shared_database(journal,'55555555-5555-4555-8555-555555555555')
            current['settingsLegacyHash']='f'*64
            with self.assertRaisesRegex(ValueError,'CONFIGURATION_CHANGED'):module.runtime_boot_shared_database(journal,'44444444-4444-4444-8444-444444444444')
        self.assertEqual(journal['sharedDatabase']['settingsHash'],'d'*64);self.assertNotIn('settingsHashVersion',journal['sharedDatabase'])

class RuntimeBootDumps(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        import copy,hashlib
        original_path=pathlib.Path
        with tempfile.TemporaryDirectory()as directory:
            backup=original_path(directory)/('runtime-backup-'+'f'*32);backup.mkdir()
            journal=SystemdPolicy.journal();journal['backup']=backup.name;journal['systemdPolicy']['bootId']='11111111-1111-4111-8111-111111111111'
            derived=copy.deepcopy(journal['systemdPolicy']);derived.update(token='a'*32,bootId='22222222-2222-4222-8222-222222222222',directory='runtime-systemctl-'+'a'*32,ordinal=1,originalToken=journal['systemdPolicy']['token'],originHash=module.runtime_systemd_origin_hash(journal['systemdPolicy']),inheritedActions=[])
            journal['systemdBootPolicies']=[derived];saved=[]
            originals={'database.dump':b'PGDMPoriginal live dump','database-after-drain.dump':b'PGDMPoriginal drained dump'}
            journal['dumpEvidence']={name:{'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)}for name,data in originals.items()}
            for name,data in originals.items():(backup/name).write_bytes(data);(backup/name).chmod(0o600)
            recovery={'version':1,'bootId':derived['bootId'],'token':derived['token'],'phase':'prepared','drainConfirmed':True,'dumpPending':True}
            journal['bootRecoveries']={derived['bootId']:recovery}
            tools=RuntimeDatabaseClients.tools();journal['backupDatabase']={**RuntimeDatabaseClients.database(),'clientTools':tools}
            def material(path):
                data=original_path(path).read_bytes();return {'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'header':data.startswith(b'PGDMP')}
            def dump(path,database,source=None):
                self.assertEqual(database,journal['backupDatabase']);self.assertIs(source,journal)
                self.assertFalse(path.exists(),'an original or interrupted dump must never be overwritten')
                self.assertEqual(recovery['dumpAttempts'][-1]['state'],'intent');self.assertTrue(saved,'dump intent must already be durable')
                path.write_bytes(b'PGDMPnew complete rows');path.chmod(0o600)
            with patch.object(module,'runtime_dump_directory',return_value=backup),patch.object(module,'runtime_dump_material',side_effect=material),patch.object(module,'runtime_database_client_files',return_value=tools),patch.object(module,'verify_runtime_database_files'),patch.object(module,'runtime_systemd_policy_lineage',side_effect=lambda value:[value['systemdPolicy'],*value.get('systemdBootPolicies',[])]),patch.object(module,'write_runtime_maintenance',side_effect=lambda value:saved.append(copy.deepcopy(value))),patch.object(module,'dump_runtime_database',side_effect=dump)as dumper:
                yield journal,recovery,backup,originals,saved,dumper,material

    def test_half_dump_and_lost_reply_are_retained_then_a_separate_full_data_checked_dump_is_used(self):
        with self.fixture()as(journal,recovery,backup,originals,saved,dumper,material):
            partial=b'PGDMPcatalogue exists but data block is truncated'
            def interrupted(path,*_):path.write_bytes(partial);path.chmod(0o600);raise OSError('private dump interrupted')
            dumper.side_effect=interrupted
            with self.assertRaises(OSError):module.runtime_new_boot_dump(journal,recovery)
            first=backup/recovery['dumpAttempts'][0]['file'];self.assertEqual(first.read_bytes(),partial);self.assertEqual(recovery['dumpAttempts'][0]['state'],'intent')
            self.assertEqual(saved[0]['bootRecoveries'][recovery['bootId']]['dumpAttempts'][0]['state'],'intent');self.assertNotIn('dump',recovery)
            def fresh(path,*_):self.assertFalse(path.exists());path.write_bytes(b'PGDMPcomplete new data');path.chmod(0o600)
            dumper.side_effect=fresh
            def offline(args,*_):
                self.assertEqual(args[:2],['/usr/lib/postgresql/16/bin/pg_restore','--file=/dev/null']);self.assertNotIn('--list',args);self.assertNotIn('--dbname',args)
                if args[2]==str(first):raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
                return ''
            with patch.object(module,'command',side_effect=offline)as check:module.runtime_new_boot_dump(journal,recovery)
            self.assertEqual(check.call_count,2);self.assertEqual([item['state']for item in recovery['dumpAttempts']],['failed','complete']);self.assertEqual(first.read_bytes(),partial)
            self.assertEqual(recovery['dumpAttempts'][0]['sha256'],material(first)['sha256']);self.assertNotEqual(recovery['dump']['file'],first.name)
            with patch.object(module,'command')as check:module.runtime_new_boot_dump(journal,recovery);module.confirm_runtime_boot_dump(journal,journal['systemdBootPolicies'][0])
            check.assert_not_called();self.assertEqual(dumper.call_count,2)
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_lost_success_reply_requires_full_offline_data_read_before_adopting_the_same_intent(self):
        with self.fixture()as(journal,recovery,backup,originals,saved,dumper,material):
            def interrupted(path,*_):path.write_bytes(b'PGDMPfully written rows');path.chmod(0o600);raise OSError('reply lost after write')
            dumper.side_effect=interrupted
            with self.assertRaises(OSError):module.runtime_new_boot_dump(journal,recovery)
            file=recovery['dumpAttempts'][0]['file'];original=(backup/file).read_bytes()
            with patch.object(module,'command',return_value='')as check:module.runtime_new_boot_dump(journal,recovery)
            self.assertEqual(check.call_args.args[0],['/usr/lib/postgresql/16/bin/pg_restore','--file=/dev/null',str(backup/file)]);self.assertEqual(dumper.call_count,1)
            self.assertEqual(recovery['dump']['file'],file);self.assertEqual((backup/file).read_bytes(),original);self.assertFalse(recovery['dumpPending'])
            self.assertEqual(len(recovery['dumpAttempts']),1)

    def test_three_failed_files_are_retained_and_a_fourth_attempt_is_never_created(self):
        with self.fixture()as(journal,recovery,backup,originals,saved,dumper,material):
            with patch.object(module,'command',side_effect=ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED'))as check,self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):
                module.runtime_new_boot_dump(journal,recovery)
            self.assertEqual(dumper.call_count,3);self.assertEqual(check.call_count,3);self.assertEqual(len(recovery['dumpAttempts']),3)
            self.assertTrue(all(item['state']=='failed'and (backup/item['file']).exists()for item in recovery['dumpAttempts']));self.assertNotIn('dump',recovery)
            with patch.object(module,'command')as check,self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.runtime_new_boot_dump(journal,recovery)
            check.assert_not_called();self.assertEqual(dumper.call_count,3)
            self.assertEqual(len(list(backup.iterdir())),5)

    def test_changed_original_dump_and_wrong_binding_stop_before_any_new_dump_or_database_command(self):
        for changed in ['original','binding']:
            with self.fixture()as(journal,recovery,backup,originals,saved,dumper,material):
                if changed=='original':(backup/'database.dump').write_bytes(b'PGDMPchanged administrator material')
                else:recovery['token']='b'*32
                with patch.object(module,'command')as check,self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.runtime_new_boot_dump(journal,recovery)
                check.assert_not_called();dumper.assert_not_called();self.assertNotIn('dump',recovery)
                self.assertEqual((backup/'database-after-drain.dump').read_bytes(),originals['database-after-drain.dump'])

    def test_first_new_dump_never_claims_a_preexisting_old_complete_file_or_unreadable_name(self):
        import copy,errno
        for kind in ['old-complete','eacces','eio']:
            with self.fixture()as(journal,recovery,backup,originals,saved,dumper,material):
                target=backup/('database-after-drain-boot-'+recovery['bootId']+'-1.dump');old=b'PGDMPcomplete data from an unrelated older backup';frozen=copy.deepcopy(journal);real_lstat=type(backup).lstat
                if kind=='old-complete':target.write_bytes(old);target.chmod(0o600)
                def lstat(path,*args,**kwargs):
                    if path==target and kind!='old-complete':raise PermissionError(errno.EACCES,'fixture unavailable')if kind=='eacces'else OSError(errno.EIO,'fixture unavailable')
                    return real_lstat(path,*args,**kwargs)
                with patch.object(type(backup),'lstat',lstat),patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'BACKUP_FAILED|UNTRUSTED_PATH'):module.runtime_new_boot_dump(journal,recovery)
                command.assert_not_called();dumper.assert_not_called();self.assertEqual(journal,frozen);self.assertEqual(saved,[]);self.assertNotIn('dumpAttempts',recovery)
                if kind=='old-complete':self.assertEqual(target.read_bytes(),old)
                for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_new_dump_creation_collision_is_failed_and_never_adopted_after_the_intent_write(self):
        with self.fixture()as(journal,recovery,backup,originals,saved,dumper,material):
            old=b'PGDMPunowned file appeared during creation';write=module.write_runtime_maintenance;collision=[False]
            def after_intent(value):
                write(value)
                if not collision[0]and recovery.get('dumpAttempts'):
                    collision[0]=True;target=backup/recovery['dumpAttempts'][-1]['file'];target.write_bytes(old);target.chmod(0o600)
            def exclusive(path,*_):
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
                try:os.write(fd,b'PGDMPfresh exclusive output')
                finally:os.close(fd)
                path.chmod(0o600)
            dumper.side_effect=exclusive
            with patch.object(module,'write_runtime_maintenance',side_effect=after_intent),patch.object(module,'command')as command,self.assertRaises(FileExistsError):module.runtime_new_boot_dump(journal,recovery)
            command.assert_not_called();self.assertEqual(dumper.call_count,1);self.assertEqual(recovery['dumpAttempts'][0]['state'],'failed');self.assertNotIn('dump',recovery)
            first=backup/recovery['dumpAttempts'][0]['file'];self.assertEqual(first.read_bytes(),old)
            with patch.object(module,'command',return_value='')as command:module.runtime_new_boot_dump(journal,recovery)
            self.assertEqual(dumper.call_count,2);self.assertEqual(command.call_count,1);self.assertEqual([attempt['state']for attempt in recovery['dumpAttempts']],['failed','complete']);self.assertNotEqual(recovery['dump']['file'],first.name);self.assertEqual(first.read_bytes(),old)

    def test_unreadable_bound_dump_remains_an_intent_and_is_never_persisted_as_absent(self):
        import copy,errno
        for error in [PermissionError(errno.EACCES,'fixture unavailable'),OSError(errno.EIO,'fixture unavailable')]:
            with self.fixture()as(journal,recovery,backup,originals,saved,dumper,material):
                name='database-after-drain-boot-'+recovery['bootId']+'-1.dump';recovery['dumpAttempts']=[{'file':name,'attempt':1,'state':'intent'}]
                frozen=copy.deepcopy(journal);real_lstat=type(backup).lstat
                def lstat(path,*args,**kwargs):
                    if path==backup/name:raise error
                    return real_lstat(path,*args,**kwargs)
                with patch.object(type(backup),'lstat',lstat),patch.object(module,'command')as command:
                    with self.assertRaisesRegex(ValueError,'UNTRUSTED_PATH'):module.runtime_new_boot_dump(journal,recovery)
                    with self.assertRaisesRegex(ValueError,'UNTRUSTED_PATH'):module.preserve_runtime_past_boot_dumps(journal,'33333333-3333-4333-8333-333333333333')
                command.assert_not_called();dumper.assert_not_called();self.assertEqual(journal,frozen);self.assertEqual(saved,[])
                recovery['dumpAttempts'][0]['attempt']=True
                with patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.runtime_new_boot_dump(journal,recovery)
                command.assert_not_called();dumper.assert_not_called();self.assertEqual(saved,[])

    def test_previous_boot_pending_output_is_sealed_as_failure_without_replacing_its_bytes(self):
        for existed in [False,True]:
            with self.subTest(existed=existed),self.fixture()as(journal,recovery,backup,originals,saved,dumper,material):
                file='database-after-drain-boot-'+recovery['bootId']+'-1.dump';recovery['dumpAttempts']=[{'file':file,'attempt':1,'state':'intent'}]
                if existed:(backup/file).write_bytes(b'PGDMPunfinished old boot output');(backup/file).chmod(0o600)
                with patch.object(module,'command')as check:module.preserve_runtime_past_boot_dumps(journal,'33333333-3333-4333-8333-333333333333')
                self.assertEqual(recovery['dumpAttempts'][0]['state'],'failed'if existed else'absent');self.assertNotIn('dump',recovery)
                if existed:self.assertEqual((backup/file).read_bytes(),b'PGDMPunfinished old boot output')
                self.assertEqual(len(saved),1);dumper.assert_not_called();check.assert_not_called()
                for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

class RuntimeBootFlow(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self,mode='missing-node',change_pg_after_dump=False,backup_only=False,legacy_client=False,recovery_checks=False,owned_pg=False):
        # The transaction, boot, nonce, cached-argument, completion and cleanup
        # decisions stay real. OS/process/payload adapters are private fixtures;
        # this is not a native boot, signed-package or PostgreSQL acceptance.
        import copy,hashlib,json
        real_path=pathlib.Path
        with tempfile.TemporaryDirectory()as directory:
            security=real_path(directory);backup=security/('runtime-backup-'+'f'*32);backup.mkdir();(backup/'archives').mkdir()
            cached=backup/'archives'/'expected-nodejs-amd64.deb';cached.write_bytes(b'isolated byte-authority adapter')
            journal,_=RuntimePayload.fixture();journal.update(phase='installed',backup=backup.name,bootId='11111111-1111-4111-8111-111111111111',database=None,drainConfirmed=True,payloadEvidence={'isolated':True})
            original=journal['systemdPolicy'];original['bootId']=journal['bootId'];original.update(cleared=mode!='rejected',deferredActions=list(module.RUNTIME_SYSTEMCTL_ACTIONS.values()),cleanupHashes={'systemctl':original['sourceHash'],'policy.lock':'1'*64,'policy.json':'2'*64})
            programs=original['programs'];original['qualification']['journaldUnit']=programs['usr/lib/systemd/system/systemd-journald.service']
            original['qualification']['manager']['binaryHash']=programs['usr/lib/systemd/systemd'];original['qualification']['journald']['binaryHash']=programs['usr/lib/systemd/systemd-journald']
            backend={'pid':12,'start':'old','app':'/opt/incudal','environmentHash':'a'*64,'codeHash':'b'*64,'serviceHash':'c'*64,'unitHashes':{'/etc/systemd/system/incudal-backend.service':'d'*64}}
            database=SystemdBootRecovery.database()
            if owned_pg and backup_only:raise AssertionError('mutually exclusive private PG authority')
            if backup_only or owned_pg:database={key:value for key,value in database.items()if key!='sharedReadOnly'}
            if owned_pg:journal['database']=database
            journal['backend']=backend
            if not backup_only and not owned_pg:journal['sharedDatabase']=database
            tools=RuntimeDatabaseClients.tools(major=18 if legacy_client else 16)
            if legacy_client:
                for field in ['baselinePackages','expectedPackages']:journal[field].update({'postgresql-16:amd64':'16.16-1.pgdg13+1','postgresql-client-18:amd64':'18.7-1.pgdg13+1'})
            else:journal['backupDatabase']={**database,'clientTools':tools}
            frozen=copy.deepcopy(original);boot_id='22222222-2222-4222-8222-222222222222';boot=security/'boot-id';boot.write_text(boot_id)
            header=RuntimeDatabaseClients.header(client=18,archive=16,client_version='18.7')if legacy_client else b'PGDMP'
            originals={'database.dump':header+b'original live','database-after-drain.dump':header+b'original drained'}
            journal['dumpEvidence']={name:{'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)}for name,data in originals.items()}
            for name,data in originals.items():(backup/name).write_bytes(data)
            path=security/'runtime-maintenance.json';path.write_text(json.dumps(journal));events=[];saved=[]
            state={'nodeReady':mode in ['complete','client-failure'],'backendRunning':mode=='complete','pgPID':133}
            if recovery_checks:state.update(backendStopped=False,backendPID=224,backendStart='new',backendStarts=0,commands=[],backendInvocation='0'*32,backendExecPID=0,backendExecStart=0,backendResult='exit-code')
            if owned_pg:state.update(pgRunning=True,pgStopped=False,pgStarts=0,pgInvocation='d'*32,pgExecPID=90,pgExecStart=88,pgResult='success')
            current_backend={**backend,'pid':224,'start':'new'}
            qualification=copy.deepcopy(original['qualification']);qualification['manager'].update(start='111',replacedLibraries=False);qualification['journald'].update(pid=23,start='222',replacedLibraries=False);qualification['state']['networkHash']='f'*64
            if mode=='client-failure':qualification['manager']['replacedLibraries']=True
            files={key:{'path':'/'+key,'sha256':digest,'inode':number,'device':[8,1]}for number,(key,digest)in enumerate(original['libcPrograms'].items(),51)}
            class App:
                def __str__(self):return '/opt/incudal'
                def resolve(self):return self
                def __truediv__(self,part):return real_path('/opt/incudal')/part
            class Process:
                def __init__(self,key):self.key=key
                def __truediv__(self,part):return Process(self.key+'/'+part)
                def readlink(self):return '/usr/lib/postgresql/16/bin/postgres'if self.key.endswith('/exe')else'pid:[1]'
                def read_text(self):return '133 (postgres) '+' '.join(['0']*19+[str(state['pgPID'])])
            def fixture_path(*parts):
                first=str(parts[0]);key=str(pathlib.PurePosixPath(*[str(part)for part in parts]))
                if key=='/opt/incudal':return App()
                if first=='/var/lib/incudal-system-security':return security.joinpath(*parts[1:])
                if key=='/proc/sys/kernel/random/boot_id':return boot
                if key in ['/proc/133','/proc/134','/proc/1/ns/pid']or owned_pg and key=='/proc/'+str(state['pgPID']):return Process(key)
                if key in ['/var/lib/dpkg/lock','/var/lib/dpkg/lock-frontend']:return security/('absent-'+key.rsplit('/',1)[1])
                if key in ['/usr/bin/node','/proc/224/exe','/usr/lib/postgresql/16/bin/postgres','/proc/133/exe','/proc/134/exe']or recovery_checks and key=='/proc/'+str(state['backendPID'])+'/exe'or owned_pg and key=='/proc/'+str(state['pgPID'])+'/exe':
                    def same():
                        if (key in ['/usr/bin/node','/proc/224/exe']or recovery_checks and key=='/proc/'+str(state['backendPID'])+'/exe')and not state['nodeReady']:raise FileNotFoundError()
                        return types.SimpleNamespace(st_dev=1,st_ino=2)
                    return types.SimpleNamespace(stat=same)
                return real_path(*parts)
            hashes={'/opt/incudal/.env':backend['environmentHash'],'/opt/incudal/server/dist/app.js':backend['codeHash'],**backend['unitHashes'],**{'/'+key:value for key,value in programs.items()}}
            def protected(value,*_,**__):
                key=str(value).replace('\\','/')
                if key in hashes:return hashes[key]
                return hashlib.sha256(real_path(value).read_bytes()).hexdigest()
            def write(value,*_,**__):saved.append(copy.deepcopy(value));path.write_text(json.dumps(value))
            def ensure(value):
                proof=module.runtime_active_systemd_policy(value);root=security/proof['directory']
                if proof.get('ready'):module.read_runtime_systemctl_policy(proof);return
                root.mkdir();(root/'systemctl').write_bytes(module.RUNTIME_SYSTEMCTL_WRAPPER.encode());(root/'policy.lock').write_bytes(b'')
                (root/'policy.json').write_text(json.dumps({'version':1,'token':proof['token'],'sourceHash':proof['sourceHash'],'actions':[],'rejected':False}));proof['ready']=True;write(value)
            if mode=='rejected':
                root=security/original['directory'];root.mkdir();(root/'systemctl').write_bytes(module.RUNTIME_SYSTEMCTL_WRAPPER.encode());(root/'policy.lock').write_bytes(b'')
                (root/'policy.json').write_text(json.dumps({'version':1,'token':original['token'],'sourceHash':original['sourceHash'],'actions':list(module.RUNTIME_SYSTEMCTL_ACTIONS.values()),'rejected':True}))
            def payload(value,require='mixed',**_):
                if require=='expected'and not state['nodeReady']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
                return {'unchanged':False,'complete':state['nodeReady'],'incomplete':[]if state['nodeReady']else['nodejs:amd64']}
            def node(value,current=None,require='expected',allow_missing=False):
                if require=='expected'and not state['nodeReady']:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
                if not state['nodeReady']:self.assertEqual(require,'mixed');self.assertTrue(allow_missing)
            def arguments(value,remaining):self.assertEqual(remaining,['nodejs=24.22.3']);return [str(cached)]
            def material(file):
                data=file.read_bytes();return {'sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'header':data.startswith(b'PGDMP')}
            def dump(file,original_database,source=None):
                if legacy_client:
                    self.assertEqual(original_database['major'],16)
                    if owned_pg:self.assertEqual(module.verify_runtime_database_clients(original_database,source)[1]['major'],18)
                    else:self.assertEqual(original_database['clientTools']['major'],18)
                else:self.assertEqual(original_database,journal['backupDatabase'])
                self.assertEqual(source,saved[-1],'the dump must use the same journal as the durable intent')
                self.assertFalse(file.exists());self.assertFalse(state['backendRunning']);self.assertEqual(saved[-1]['bootRecoveries'][boot_id]['dumpAttempts'][-1]['state'],'intent')
                file.write_bytes(b'PGDMPfresh drain fixture');events.append('dump')
                if change_pg_after_dump:state['pgPID']=134
            def command(args,*_):
                if recovery_checks:state['commands'].append(tuple(args))
                if args==['dpkg','--audit']:return ''
                if owned_pg and args==['systemctl','show','postgresql@16-main.service','--property=ExecStart,ExecStop,FragmentPath,DropInPaths,ControlGroup']:
                    return 'ExecStart={ argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect 16-main start ; }\nExecStop={ argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect -m fast 16-main stop ; }\nFragmentPath=/usr/lib/systemd/system/postgresql@.service\nDropInPaths=\nControlGroup='+('/system.slice/system-postgresql.slice/postgresql@16-main.service'if state['pgRunning']else'')
                if owned_pg and args==['pg_lsclusters','--json']:return json.dumps([{'version':'16','cluster':'main','port':5432,'running':int(state.get('pgClusterRunning',state['pgRunning']))}])
                if args[0]=='/usr/lib/postgresql/'+str(18 if legacy_client else 16)+'/bin/pg_restore':self.assertEqual(args[1],'--file=/dev/null');events.append('read-dump');return ''
                if args[0]=='apt-get'and '--simulate'in args:
                    self.assertIn('--reinstall',args);self.assertEqual(args[-1],str(cached));events.append('simulate');return 'Inst nodejs [24.22.3] (24.22.3 fixture [amd64])'
                if args[0]=='/usr/bin/env'and 'apt-get'in args:
                    self.assertTrue(all(flag in args for flag in ['--no-download','--only-upgrade','--no-remove','--reinstall']));self.assertEqual(args[-1],str(cached));self.assertFalse(state['backendRunning'])
                    self.assertIn('runtime-systemctl-',args[1]);events.append('install-original-cache');state['nodeReady']=True;return ''
                if args[:2]==['systemctl','start']:
                    if owned_pg and args[2]=='postgresql@16-main.service':
                        self.assertFalse(state['pgRunning']);state['pgStarts']+=1;state['pgPID']=133+state['pgStarts']
                        state.update(pgRunning=True,pgClusterRunning=True,pgStopped=False,pgInvocation=format(100+state['pgStarts'],'032x'),pgExecPID=900+state['pgStarts'],pgExecStart=2000+state['pgStarts'],pgResult='success')
                        events.append('start-pg');return ''
                    self.assertEqual(args[2],'incudal-backend.service');self.assertTrue(state['nodeReady'])
                    if recovery_checks:
                        state['backendPID']=224+state['backendStarts'];state['backendStarts']+=1;state['backendStart']='recovered-'+str(state['backendStarts']);state['backendStopped']=False
                        state.update(backendInvocation=format(state['backendStarts'],'032x'),backendExecPID=state['backendPID'],backendExecStart=1000*state['backendStarts'],backendResult='success')
                    state['backendRunning']=True;events.append('start-backend');return ''
                if recovery_checks and args[:2]==['systemctl','stop']:
                    if owned_pg and args[2]=='postgresql@16-main.service':
                        self.assertTrue(state['pgRunning']);state.update(pgRunning=False,pgClusterRunning=False,pgStopped=True,pgResult='success');events.append('stop-pg');return ''
                    self.assertEqual(args[2],'incudal-backend.service');self.assertTrue(state['backendRunning']);state['backendRunning']=False;state['backendStopped']=True;state['backendResult']='success';events.append('stop-backend');return ''
                if args[:2]==['systemctl','show']:
                    if args[2]=='systemd-journald.service':return 'LoadState=loaded\nActiveState=active\nMainPID=23\nFragmentPath=/usr/lib/systemd/system/systemd-journald.service\nDropInPaths='
                    if '--property=SubState'in args:return 'running'if(state['pgRunning']if owned_pg and args[2]=='postgresql@16-main.service'else state['backendRunning'])else'dead'
                    if owned_pg and args[2]=='postgresql@16-main.service'and '--property=MainPID,ActiveState,Result,InvocationID,ExecMainPID,ExecMainStartTimestampMonotonic'in args:
                        return 'MainPID='+(str(state['pgPID'])if state['pgRunning']else'0')+'\nActiveState='+('active'if state['pgRunning']else'inactive'if state['pgStopped']else'failed')+'\nResult='+state['pgResult']+'\nInvocationID='+state['pgInvocation']+'\nExecMainPID='+str(state['pgExecPID'])+'\nExecMainStartTimestampMonotonic='+str(state['pgExecStart'])
                    if recovery_checks and '--property=MainPID,ActiveState,Result,InvocationID,ExecMainPID,ExecMainStartTimestampMonotonic'in args:
                        self.assertEqual(args[2],'incudal-backend.service')
                        return 'MainPID='+(str(state['backendPID'])if state['backendRunning']else'0')+'\nActiveState='+('active'if state['backendRunning']else'inactive'if state['backendStopped']else'failed')+'\nResult='+state['backendResult']+'\nInvocationID='+state['backendInvocation']+'\nExecMainPID='+str(state['backendExecPID'])+'\nExecMainStartTimestampMonotonic='+str(state['backendExecStart'])
                    if '--property=MainPID,ActiveState,Result'in args:
                        if args[2]=='postgresql@16-main.service':return 'MainPID='+(str(state['pgPID'])if not owned_pg or state['pgRunning']else'0')+'\nActiveState='+('active'if not owned_pg or state['pgRunning']else'inactive'if state['pgStopped']else'failed')+'\nResult='+(state['pgResult']if owned_pg else'success')
                        pid=str(state['backendPID'])if recovery_checks else'224';stopped=recovery_checks and state['backendStopped']
                        return 'MainPID='+(pid if state['backendRunning']else'0')+'\nActiveState='+('active'if state['backendRunning']else'inactive'if stopped else'failed')+'\nResult='+(state['backendResult']if recovery_checks else'success'if state['backendRunning']or stopped else'exit-code')
                raise AssertionError('unexpected package/service command in isolated boot fixture')
            def native_pg(proof,execution=None):
                return module.validate_runtime_boot_database_native(proof,{'version':1,'pid':state['pgPID'],'start':str(state['pgPID']),'major':proof['major'],'unit':proof['unit'],'configurationHash':module.runtime_boot_database_native_configuration(proof),'program':'/usr/lib/postgresql/'+str(proof['major'])+'/bin/postgres','programHash':'a'*64,'device':1,'inode':2,'uid':100,'gid':100,'pidNamespace':'pid:[1]','rootDevice':1,'rootInode':1,'commandHash':'b'*64,'cgroup':'/system.slice/system-postgresql.slice/'+proof['unit']})
            def database_proof(**_):
                if owned_pg and not state['pgRunning']:raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
                current={**database,'pid':state['pgPID'],'start':str(state['pgPID']),'otherClients':int(owned_pg and state['backendRunning'])}
                if owned_pg:current['sharedReadOnly']=bool(state['backendRunning'])
                return current
            def finance(_):
                self.assertTrue(state['nodeReady'])
                if owned_pg:self.assertTrue(state['pgRunning'])
                if recovery_checks:events.append('finance-running'if state['backendRunning']else'finance-stopped')
                else:self.assertTrue(state['backendRunning']);events.append('finance')
            def archive(value,_):events.append('receipt');(backup/'completed.json').write_text(json.dumps(value))
            def archive_evidence(current,value):
                self.assertEqual(current,backup);payload(value,require='expected')
                for name,raw in originals.items():self.assertEqual((backup/name).read_bytes(),raw)
                return [backup/name for name in originals],[]
            with contextlib.ExitStack()as stack:
                adapters=[patch.object(module.pathlib,'Path',side_effect=fixture_path),patch.object(module,'protected_hash',side_effect=protected),patch.object(module,'backend_service_policy',return_value=({},App(),backend['unitHashes'],backend['serviceHash'])),patch.object(module,'backend_runtime_proof',side_effect=lambda:{**copy.deepcopy(current_backend),**({'pid':state['backendPID'],'start':state['backendStart']}if recovery_checks else{})}if state['backendRunning']else None),patch.object(module,'database_runtime_proof',side_effect=database_proof),patch.object(module,'runtime_database_client_files',return_value=tools),patch.object(module,'verify_runtime_database_files'),patch.object(module,'runtime_boot_database_native',side_effect=native_pg,create=True),patch.object(module,'debian_package_states',side_effect=lambda:{key:{'version':version,'status':'installed'}for key,version in journal['expectedPackages'].items()}),patch.object(module,'debian_installed_packages',return_value=journal['expectedPackages']),patch.object(module,'runtime_systemctl_policy_directory',side_effect=lambda proof:security/proof['directory']),patch.object(module,'verify_runtime_systemd_package_authority'),patch.object(module,'verify_runtime_payload',side_effect=payload),patch.object(module,'verify_runtime_node_authority',side_effect=node),patch.object(module,'runtime_original_expected_arguments',side_effect=arguments),patch.object(module,'ensure_runtime_systemctl_policy',side_effect=ensure),patch.object(module,'runtime_systemd_qualification',return_value=qualification),patch.object(module,'runtime_systemd_process',side_effect=lambda pid,_:copy.deepcopy(qualification['manager'if pid==1 else'journald'])),patch.object(module,'runtime_systemd_state',return_value=qualification['state']),patch.object(module,'runtime_libc_files',return_value=files),patch.object(module,'verify_runtime_libc_process'),patch.object(module,'runtime_process_has_replaced_libraries',return_value=False),patch.object(module,'runtime_dump_directory',return_value=backup),patch.object(module,'runtime_dump_material',side_effect=material),patch.object(module,'dump_runtime_database',side_effect=dump),patch.object(module,'write_runtime_maintenance',side_effect=write),patch.object(module,'sync_runtime_evidence_directory'),patch.object(module,'restore_runtime_conffiles'),patch.object(module,'prepare_service_policy'),patch.object(module,'clean_service_policy'),patch.object(module,'verify_runtime_health',side_effect=lambda:self.assertTrue(state['backendRunning'])),patch.object(module,'verify_runtime_financial_integrity',side_effect=finance),patch.object(module,'archive_runtime_receipt',side_effect=archive),patch.object(module,'command',side_effect=command),patch.object(module.uuid,'uuid4',return_value=types.SimpleNamespace(hex='a'*32))]
                adapters.append(patch.object(module,'runtime_backup_evidence',side_effect=archive_evidence))
                if legacy_client:
                    adapters.extend([patch.object(module,'runtime_database_payload_clients',side_effect=lambda value,major,label:tools if major==18 and label=='before'else None),patch.object(module.os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True),patch.object(module.os,'O_NONBLOCK',getattr(os,'O_NONBLOCK',0),create=True)])
                for adapter in adapters:stack.enter_context(adapter)
                yield path,backup,originals,frozen,state,events,saved

    def test_missing_node_with_expected_registration_crosses_boot_using_only_original_cache_and_shared_pg_pid(self):
        with self.fixture()as(path,backup,originals,frozen,state,events,saved):
            result=module.recover_runtime_maintenance(path)
            self.assertEqual(result['phase'],'activated');self.assertTrue(state['nodeReady']);self.assertTrue(state['backendRunning']);self.assertEqual(state['pgPID'],133)
            self.assertEqual(events,['dump','read-dump','simulate','install-original-cache','start-backend','finance','receipt'])
            derived=result['systemdBootPolicies'][0];self.assertNotEqual(derived['token'],frozen['token']);self.assertEqual(derived['recordedActions'],[]);self.assertEqual(derived['deferredActions'],[])
            self.assertEqual(module.runtime_systemd_origin_hash(result['systemdPolicy']),module.runtime_systemd_origin_hash(frozen));self.assertEqual(result['sharedDatabase']['pid'],33)
            self.assertEqual(result['bootConfirmation']['sharedDatabasePID'],133);self.assertEqual(result['bootSharedDatabases'][derived['bootId']]['proof']['pid'],133)
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)
            count=len(events);self.assertIsNone(module.recover_runtime_maintenance(path));self.assertEqual(len(events),count,'completed recovery performs no package or service operation')

    def test_fully_expected_natural_boot_only_observes_and_never_replays_a_nonce_or_restarts_services(self):
        with self.fixture(mode='complete')as(path,backup,originals,frozen,state,events,saved):
            result=module.recover_runtime_maintenance(path)
            self.assertEqual(result['phase'],'activated');self.assertEqual(events,['finance','receipt']);self.assertNotIn('systemdBootPolicies',result)
            self.assertEqual(result['systemdPolicy'],frozen);self.assertEqual(result['bootConfirmation']['mode'],'new-boot-read-only')

    def test_node_only_backup_binding_crosses_boot_without_starting_or_stopping_postgresql(self):
        with self.fixture(backup_only=True)as(path,backup,originals,frozen,state,events,saved):
            result=module.recover_runtime_maintenance(path)
            self.assertEqual(result['phase'],'activated');self.assertIsNone(result['database']);self.assertNotIn('sharedDatabase',result)
            self.assertEqual(state['pgPID'],133);self.assertEqual(events,['dump','read-dump','simulate','install-original-cache','start-backend','finance','receipt'])
            self.assertEqual(result['bootRecoveries'][result['systemdBootPolicies'][0]['bootId']]['backupDatabaseProcess'],{'pid':133,'start':'133'})
            self.assertEqual(result['systemdPolicy'],frozen)
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_changed_backup_client_restores_proven_backend_without_reinstall_or_shared_pg_restart(self):
        import json
        with self.fixture(mode='client-failure')as(path,backup,originals,frozen,state,events,saved):
            original=json.loads(path.read_text());tools=RuntimeDatabaseClients.tools(digest='b')
            with patch.object(module,'runtime_database_client_files',return_value=tools),patch.object(module,'runtime_database_payload_clients',return_value=None),self.assertRaisesRegex(ValueError,'CLIENT_CHANGED'):
                module.recover_runtime_maintenance(path)
            self.assertTrue(state['backendRunning']);self.assertEqual(state['pgPID'],133);self.assertEqual(events,['start-backend','finance'])
            pending=json.loads(path.read_text());self.assertEqual(pending['phase'],'installed');self.assertEqual(pending['backupRecovery']['error'],'SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
            self.assertEqual(pending['backupDatabase'],original['backupDatabase']);self.assertEqual(pending['sharedDatabase'],original['sharedDatabase']);self.assertEqual(pending['systemdPolicy'],frozen)
            self.assertNotIn('activatedBackendPID',pending);self.assertNotIn('systemdBootPolicies',pending)
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_legacy_client18_node_only_cross_boot_recovery_preserves_original_pg16_authority_and_nonce(self):
        with self.fixture(backup_only=True,legacy_client=True)as(path,backup,originals,frozen,state,events,saved):
            result=module.recover_runtime_maintenance(path)
            self.assertEqual(result['phase'],'activated');self.assertIsNone(result['database']);self.assertNotIn('sharedDatabase',result);self.assertNotIn('backupDatabase',result);self.assertEqual(result['systemdPolicy'],frozen);self.assertEqual(state['pgPID'],133)
            self.assertEqual(events,['dump','read-dump','simulate','install-original-cache','start-backend','finance','receipt']);recovery=result['bootRecoveries'][result['systemdBootPolicies'][0]['bootId']]
            self.assertEqual(recovery['backupDatabase']['major'],16);self.assertEqual(recovery['backupDatabase']['clientTools']['major'],18);self.assertEqual(recovery['backupDatabaseProcess'],{'pid':133,'start':'133'})
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_legacy_missing_client18_cache_or_changed_tools_restores_backend_before_fixed_failure(self):
        import json
        for kind,error in [('cache-missing','BACKUP_PROOF_MISSING'),('client-changed','CLIENT_CHANGED')]:
            with self.subTest(kind=kind),self.fixture(mode='client-failure',backup_only=True,legacy_client=True)as(path,backup,originals,frozen,state,events,saved):
                with contextlib.ExitStack()as stack:
                    if kind=='cache-missing':
                        stack.enter_context(patch.object(module,'runtime_database_payload_clients',return_value=None));cache=stack.enter_context(patch.object(module,'authenticated_debian_archive',side_effect=ValueError('SYSTEM_SECURITY_ARCHIVE_NOT_CACHED')))
                    else:stack.enter_context(patch.object(module,'runtime_database_client_files',return_value=RuntimeDatabaseClients.tools(major=18,digest='b')))
                    download=stack.enter_context(patch.object(module,'acquire_runtime_debian_archive'))
                    with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                self.assertTrue(state['backendRunning']);self.assertEqual(state['pgPID'],133);self.assertEqual(events,['start-backend','finance']);download.assert_not_called()
                pending=json.loads(path.read_text());self.assertEqual(pending['phase'],'installed');self.assertIsNone(pending['database']);self.assertNotIn('sharedDatabase',pending);self.assertNotIn('backupDatabase',pending);self.assertEqual(pending['systemdPolicy'],frozen);self.assertNotIn('activatedBackendPID',pending);self.assertNotIn('systemdBootPolicies',pending)
                self.assertEqual(pending['backupRecovery']['error'],'SYSTEM_SECURITY_DATABASE_'+error)
                if kind=='cache-missing':cache.assert_called_once_with('postgresql-client-18','18.7-1.pgdg13+1','amd64',before=True)
                for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_old_policy_rejection_and_same_boot_shared_pg_change_stop_before_install_or_backend_start(self):
        for mode,changed,error in [('rejected',False,'POLICY_REJECTED'),('missing-node',True,'DATABASE_PROCESS_CHANGED')]:
            with self.subTest(mode=mode),self.fixture(mode=mode,change_pg_after_dump=changed)as(path,backup,originals,frozen,state,events,saved):
                with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                self.assertFalse(state['backendRunning']);self.assertFalse(state['nodeReady']);self.assertNotIn('install-original-cache',events);self.assertNotIn('start-backend',events);self.assertNotIn('finance',events);self.assertNotIn('receipt',events)
                for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)


class RuntimeBootDumpRecovery(unittest.TestCase):
    # Keep production decisions real; process/package/database adapters remain
    # private. These tests do not attest a native boot or full OSS recovery.
    @contextlib.contextmanager
    def fixture(self,**options):
        with RuntimeBootFlow.fixture(self,mode='client-failure',recovery_checks=True,**options)as values:yield values

    def journal(self,path):
        import json
        return json.loads(path.read_text())

    def recovery(self,journal):
        return journal['bootRecoveries'][journal['systemdBootPolicies'][0]['bootId']]

    def failure(self,events,error=None,data=b'PGDMPowned partial dump'):
        def failed(file,*_):
            file.write_bytes(data);file.chmod(0o600);events.append('dump-failed')
            raise error if error is not None else ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        return failed

    def assert_no_pg_mutation(self,state):
        changes=[args for args in state['commands']if args[:2]in [('systemctl','start'),('systemctl','stop')]]
        self.assertTrue(all(args[2]=='incudal-backend.service'for args in changes))
        self.assertFalse(any(args[0]in ['apt-get','/usr/bin/env']for args in state['commands']))


    def test_third_successful_dump_resumes_after_transaction_boundary_interruption_without_a_fourth_attempt(self):
        import copy
        with self.fixture()as(path,backup,originals,frozen,state,events,saved):
            original_command=module.command;reads=[0];dumper=module.dump_runtime_database
            def offline(args,*values):
                if args[0]=='/usr/lib/postgresql/16/bin/pg_restore':
                    reads[0]+=1
                    if reads[0]<3:events.append('read-failed');raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
                return original_command(args,*values)
            with patch.object(module,'command',side_effect=offline),patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_AFTER_THIRD_VERIFIED_DUMP')):
                with self.assertRaisesRegex(ValueError,'FIXTURE_AFTER_THIRD_VERIFIED_DUMP'):module.recover_runtime_maintenance(path)
                pending=self.journal(path);first=copy.deepcopy(self.recovery(pending)['dumpAttempts']);proof=copy.deepcopy(self.recovery(pending)['dump']);count=len(events)
                with self.assertRaisesRegex(ValueError,'FIXTURE_AFTER_THIRD_VERIFIED_DUMP'):module.recover_runtime_maintenance(path)
            after=self.journal(path);self.assertEqual([row['state']for row in first],['failed','failed','complete']);self.assertEqual(self.recovery(after)['dumpAttempts'],first);self.assertEqual(self.recovery(after)['dump'],proof)
            self.assertEqual(events[count:],[]);self.assertEqual(dumper.call_count,3);self.assertEqual(reads[0],3);self.assertEqual(state['backendStarts'],0);self.assert_no_pg_mutation(state)
            self.assertEqual(after['systemdPolicy'],frozen);self.assertFalse((backup/'completed.json').exists())
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_owned_enospc_before_output_creation_is_sealed_absent_and_recovers_with_three_bounded_attempts(self):
        import errno,copy
        with self.fixture()as(path,backup,originals,frozen,state,events,saved):
            def missing(file,*_):
                self.assertFalse(file.exists());self.assertEqual(self.recovery(saved[-1])['dumpAttempts'][-1]['state'],'intent');events.append('dump-no-output')
                raise OSError(errno.ENOSPC,'fixture unavailable output space')
            dumper=module.dump_runtime_database;dumper.side_effect=missing
            for _ in range(3):
                with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                self.assertTrue(state['backendRunning'])
            pending=self.journal(path);recovery=self.recovery(pending);attempts=copy.deepcopy(recovery['dumpAttempts']);receipt=copy.deepcopy(recovery['serviceRecovery']);count=len(events)
            self.assertEqual(state['backendStarts'],3);self.assertEqual(dumper.call_count,3);self.assertTrue(all(row['state']=='absent'and row['failureCause']=='pg-dump'and not(backup/row['file']).exists()for row in attempts))
            self.assertEqual(receipt['attemptCount'],3);self.assertEqual(receipt['backend'],module.backend_runtime_proof())
            for _ in range(2):
                with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
            self.assertEqual(self.recovery(self.journal(path))['dumpAttempts'],attempts);self.assertEqual(self.recovery(self.journal(path))['serviceRecovery'],receipt)
            self.assertNotIn('stop-backend',events[count:]);self.assertNotIn('start-backend',events[count:]);self.assertEqual(dumper.call_count,3);self.assertEqual(state['backendStarts'],3);self.assert_no_pg_mutation(state)
            self.assertEqual(self.journal(path)['systemdPolicy'],frozen)
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_missing_output_lstat_eacces_or_eio_cannot_be_sealed_absent_or_started_as_execution_recovery(self):
        import errno
        for error in [PermissionError(errno.EACCES,'fixture denied'),OSError(errno.EIO,'fixture unreadable')]:
            with self.subTest(error=type(error).__name__),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                dumped=[False];real_lstat=type(backup).lstat;target_name='database-after-drain-boot-22222222-2222-4222-8222-222222222222-1.dump'
                def missing(file,*_):dumped[0]=True;events.append('dump-no-output');raise OSError(errno.ENOSPC,'fixture no output space')
                def lstat(file,*values,**options):
                    if dumped[0]and file.name==target_name:raise error
                    return real_lstat(file,*values,**options)
                with patch.object(module,'dump_runtime_database',side_effect=missing),patch.object(type(backup),'lstat',lstat),self.assertRaisesRegex(ValueError,'UNTRUSTED_PATH')as caught:module.recover_runtime_maintenance(path)
                recovery=self.recovery(self.journal(path));self.assertNotIsInstance(caught.exception,module.RuntimeBootDumpExecutionFailed)
                self.assertEqual(recovery['dumpAttempts'][0]['state'],'intent');self.assertNotIn('failureCause',recovery['dumpAttempts'][0]);self.assertNotIn('serviceRecovery',recovery)
                self.assertEqual(events,['dump-no-output']);self.assertFalse(state['backendRunning']);self.assertEqual(state['backendStarts'],0);self.assert_no_pg_mutation(state)

    def test_legacy_absent_failures_are_not_reclassified_or_backfilled_as_owned_execution(self):
        import copy
        with RuntimeBootDumps.fixture(self)as(journal,recovery,backup,originals,saved,dumper,material):
            recovery['dumpAttempts']=[{'file':'database-after-drain-boot-'+recovery['bootId']+'-'+str(index)+'.dump','attempt':index,'state':'absent'}for index in range(1,4)]
            frozen=copy.deepcopy(journal)
            with patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'BACKUP_FAILED')as caught:module.runtime_new_boot_dump(journal,recovery)
            self.assertNotIsInstance(caught.exception,module.RuntimeBootDumpExecutionFailed);self.assertEqual(journal,frozen);self.assertEqual(saved,[]);dumper.assert_not_called();command.assert_not_called()


    def test_independent_early_launch_closes_lost_final_recovery_without_restart_or_pg_operations(self):
        import copy
        with self.fixture()as(path,backup,originals,frozen,state,events,saved):
            original=self.journal(path);dumper=module.dump_runtime_database;dumper.side_effect=self.failure(events)
            with patch.object(module,'verify_runtime_health',side_effect=ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')),self.assertRaisesRegex(ValueError,'BACKEND_ACTIVATION_PENDING'):module.recover_runtime_maintenance(path)
            pending=self.journal(path);recovery=self.recovery(pending);launch=copy.deepcopy(recovery['serviceRecoveryLaunches'][0]);count=len(events)
            self.assertNotIn('serviceRecovery',recovery);self.assertEqual(launch['state'],'started');self.assertEqual(launch['backend'],module.backend_runtime_proof());self.assertTrue(state['backendRunning'])
            with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
            closed=self.journal(path);self.assertEqual(events[count:],['finance-running','finance-running']);self.assertEqual(state['backendStarts'],1);self.assertEqual(dumper.call_count,1)
            self.assertEqual(self.recovery(closed)['serviceRecoveryLaunches'],[launch]);self.assertEqual(self.recovery(closed)['serviceRecovery']['launchHash'],module.runtime_boot_record_hash(launch))
            self.assertEqual(closed['backend'],original['backend']);self.assertEqual(closed['systemdPolicy'],frozen);self.assertEqual(closed['phase'],'installed');self.assert_no_pg_mutation(state)
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_first_owned_start_exit_code_failure_has_remaining_budget_after_original_confirmed_stop(self):
        for backup_only in [False,True]:
            with self.subTest(backup_only=backup_only),self.fixture(backup_only=backup_only)as(path,backup,originals,frozen,state,events,saved):
                state.update(backendRunning=True,backendStopped=False,backendInvocation='f'*32,backendExecPID=224,backendExecStart=777,backendResult='success')
                module.dump_runtime_database.side_effect=self.failure(events);original_command=module.command;starts=[0]
                def start(args,*values):
                    if args==['systemctl','start','incudal-backend.service']:
                        starts[0]+=1
                        if starts[0]==1:
                            state['backendStarts']+=1;state.update(backendRunning=False,backendStopped=False,backendInvocation=format(1,'032x'),backendExecPID=501,backendExecStart=1100,backendResult='exit-code');events.append('start-failed')
                            raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
                    return original_command(args,*values)
                with patch.object(module,'command',side_effect=start):
                    with self.assertRaisesRegex(ValueError,'BACKEND_ACTIVATION_PENDING'):module.recover_runtime_maintenance(path)
                    pending=self.journal(path);recovery=self.recovery(pending);self.assertTrue(recovery['stopRequested']);self.assertTrue(recovery['drainConfirmed']);self.assertEqual(recovery['serviceRecoveryLaunches'][0]['state'],'failed');self.assertNotIn('serviceRecovery',recovery)
                    with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                after=self.journal(path);recovery=self.recovery(after);self.assertTrue(state['backendRunning']);self.assertEqual(starts[0],2);self.assertEqual(state['backendStarts'],2)
                self.assertEqual(events.count('stop-backend'),1);self.assertEqual([row['state']for row in recovery['serviceRecoveryLaunches']],['failed','started']);self.assertEqual(recovery['serviceRecoveryStart']['startAttempts'],2)
                self.assertEqual(recovery['serviceRecovery']['backend'],module.backend_runtime_proof());self.assertEqual(after['systemdPolicy'],frozen);self.assert_no_pg_mutation(state)
                for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_start_intent_without_launch_evidence_never_adopts_a_same_configuration_service(self):
        with self.fixture()as(path,backup,originals,frozen,state,events,saved):
            module.dump_runtime_database.side_effect=self.failure(events);write=module.write_runtime_maintenance;interrupted=[False]
            def intent_only(value,*values,**options):
                write(value,*values,**options);recoveries=value.get('bootRecoveries',{})
                if recoveries:
                    recovery=next(iter(recoveries.values()))
                    if recovery.get('serviceRecoveryStart')and not recovery.get('serviceRecoveryLaunches')and not interrupted[0]:interrupted[0]=True;raise OSError('FIXTURE_AFTER_START_INTENT')
            with patch.object(module,'write_runtime_maintenance',side_effect=intent_only),self.assertRaisesRegex(OSError,'FIXTURE_AFTER_START_INTENT'):module.recover_runtime_maintenance(path)
            pending=self.journal(path);self.assertNotIn('serviceRecoveryLaunches',self.recovery(pending));self.assertFalse(state['backendRunning'])
            # Another caller starts the original service, but this program has
            # not published its own launch proof. Matching configuration is insufficient.
            module.command(['systemctl','start','incudal-backend.service']);count=len(events)
            with patch.object(module,'runtime_systemd_boot_confirmation',return_value={'untrusted-early-return':True})as readonly,self.assertRaisesRegex(ValueError,'BACKEND_PROCESS_CHANGED'):module.recover_runtime_maintenance(path)
            readonly.assert_not_called();self.assertEqual(events[count:],[]);self.assertEqual(self.journal(path),pending);self.assertTrue(state['backendRunning']);self.assertEqual(module.dump_runtime_database.call_count,1);self.assert_no_pg_mutation(state)

    def test_early_launch_context_or_real_invocation_tampering_is_refused_without_service_changes(self):
        import json
        for field in ['intent.bootId','intent.token','intent.originHash','intent.startAttempts','intent.attemptsHash','execution.invocationId','execution.mainPID','execution.startedUsec','backend.pid','backend.start','backend.codeHash']:
            with self.subTest(field=field),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                module.dump_runtime_database.side_effect=self.failure(events)
                with patch.object(module,'verify_runtime_health',side_effect=ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')),self.assertRaisesRegex(ValueError,'BACKEND_ACTIVATION_PENDING'):module.recover_runtime_maintenance(path)
                pending=self.journal(path);launch=self.recovery(pending)['serviceRecoveryLaunches'][0];scope,key=field.split('.');count=len(events)
                launch[scope][key]=True if key=='startAttempts'else launch[scope][key]+1 if key in ['mainPID','startedUsec','pid']else'changed';path.write_text(json.dumps(pending))
                with self.assertRaisesRegex(ValueError,'BACKEND_PROCESS_CHANGED|BACKEND_CONFIGURATION_CHANGED|BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                self.assertEqual(events[count:],[]);self.assertTrue(state['backendRunning']);self.assertEqual(state['backendStarts'],1);self.assert_no_pg_mutation(state)
                for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_a_new_stop_failure_never_reuses_the_older_owned_start_failure_permission(self):
        for result in ['exit-code','timeout']:
            with self.subTest(result=result),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                module.dump_runtime_database.side_effect=self.failure(events)
                with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                original_command=module.command
                def failed_stop(args,*values):
                    if args==['systemctl','stop','incudal-backend.service']:
                        state.update(backendRunning=False,backendStopped=False,backendResult=result);events.append('stop-failed');raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
                    return original_command(args,*values)
                with patch.object(module,'command',side_effect=failed_stop),self.assertRaisesRegex(ValueError,'PACKAGE_QUERY_FAILED'):module.recover_runtime_maintenance(path)
                pending=self.journal(path);recovery=self.recovery(pending);count=len(events);self.assertEqual(recovery['phase'],'stopping-backend');self.assertFalse(recovery['retryDrain']['confirmed'])
                with self.assertRaisesRegex(ValueError,'DRAIN_UNCONFIRMED'):module.recover_runtime_maintenance(path)
                self.assertEqual(events[count:],[]);self.assertEqual(self.journal(path),pending);self.assertEqual(module.dump_runtime_database.call_count,1);self.assertEqual(state['backendStarts'],1);self.assert_no_pg_mutation(state)

    def test_second_dump_material_failure_or_success_interruption_resumes_the_actual_confirmed_drain(self):
        import copy
        for outcome in ['failed','complete']:
            with self.subTest(outcome=outcome),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                dumper=module.dump_runtime_database;fresh=dumper.side_effect;dumper.side_effect=self.failure(events)
                with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                original=self.journal(path);write=module.write_runtime_maintenance;interrupted=[False]
                if outcome=='complete':dumper.side_effect=fresh
                def after_material(value,*values,**options):
                    write(value,*values,**options);recovery=self.recovery(value)
                    attempts=recovery.get('dumpAttempts',[])
                    if len(attempts)==2 and attempts[-1]['state']==outcome and not interrupted[0]:interrupted[0]=True;raise OSError('FIXTURE_AFTER_SECOND_MATERIAL')
                with patch.object(module,'write_runtime_maintenance',side_effect=after_material),self.assertRaisesRegex(OSError,'FIXTURE_AFTER_SECOND_MATERIAL'):module.recover_runtime_maintenance(path)
                pending=self.journal(path);recovery=self.recovery(pending);retry=copy.deepcopy(recovery['retryDrain']);second=copy.deepcopy(recovery['dumpAttempts'][1]);count=len(events)
                self.assertEqual(retry['attempt'],2);self.assertTrue(retry['confirmed']);self.assertFalse(state['backendRunning']);dumper.side_effect=fresh
                with patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_AFTER_RESUMED_MATERIAL')),self.assertRaisesRegex(ValueError,'FIXTURE_AFTER_RESUMED_MATERIAL'):module.recover_runtime_maintenance(path)
                after=self.journal(path);recovery=self.recovery(after);self.assertEqual(recovery['retryDrain'],retry);self.assertEqual(recovery['dumpAttempts'][1],second)
                self.assertEqual(events[count:],['dump','read-dump']if outcome=='failed'else[]);self.assertEqual(dumper.call_count,3 if outcome=='failed'else 2);self.assertEqual(state['backendStarts'],1)
                self.assertEqual(recovery['dump']['file'],recovery['dumpAttempts'][-1]['file']);self.assertEqual(after['backend'],original['backend']);self.assertEqual(after['systemdPolicy'],frozen);self.assert_no_pg_mutation(state)
                for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)


    def test_owned_new_dump_execution_failure_restores_the_sole_backend_after_prestart_money_check(self):
        import errno,hashlib,json
        for error in [ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED'),OSError(errno.ENOSPC,'fixture disk full')]:
            with self.subTest(error=type(error).__name__),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                original=self.journal(path);dumper=module.dump_runtime_database;dumper.side_effect=self.failure(events,error)
                with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                pending=self.journal(path);recovery=self.recovery(pending);receipt=recovery['serviceRecovery']
                self.assertTrue(state['backendRunning']);self.assertEqual(state['backendStarts'],1);self.assertEqual(state['pgPID'],133)
                self.assertEqual(events,['dump-failed','finance-stopped','start-backend','finance-running']);self.assert_no_pg_mutation(state)
                self.assertEqual(pending['phase'],'installed');self.assertEqual(pending['backend'],original['backend']);self.assertEqual(pending['systemdPolicy'],frozen)
                self.assertEqual(pending['backupRecovery']['error'],'SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED');self.assertNotIn('activatedBackendPID',pending);self.assertFalse((backup/'completed.json').exists())
                self.assertIsNone(recovery['backend']);self.assertTrue(recovery['drainConfirmed']);self.assertTrue(recovery['dumpPending'])
                self.assertEqual(receipt['attemptCount'],1);self.assertEqual(receipt['attemptsHash'],hashlib.sha256(json.dumps(recovery['dumpAttempts'],sort_keys=True,separators=(',',':')).encode()).hexdigest())
                self.assertEqual(receipt['backend'],module.backend_runtime_proof());self.assertEqual(receipt['originHash'],module.runtime_systemd_origin_hash(frozen))
                self.assertEqual(recovery['dumpAttempts'][0]['failureCause'],'pg-dump');self.assertEqual(recovery['serviceRecoveryStart']['startAttempts'],1);self.assertEqual(dumper.call_count,1)
                self.assertEqual((backup/recovery['dumpAttempts'][0]['file']).read_bytes(),b'PGDMPowned partial dump')
                for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_new_dump_timeout_and_nonzero_child_preserve_owned_bytes_before_service_recovery(self):
        import subprocess
        real_dump=module.dump_runtime_database
        for failure in ['timeout','nonzero']:
            with self.subTest(failure=failure),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                process=types.SimpleNamespace(pid=987654)
                process.wait=unittest.mock.Mock(side_effect=[subprocess.TimeoutExpired('owned pg_dump',120),0]if failure=='timeout'else[2])
                def spawn(args,**options):
                    self.assertEqual(args,['runuser','-u','postgres','--','/usr/lib/postgresql/16/bin/pg_dump','-Fc','incudal'])
                    os.write(options['stdout'],b'PGDMPowned child partial');return process
                with patch.object(module,'dump_runtime_database',side_effect=real_dump)as dumper,patch.object(module.subprocess,'Popen',side_effect=spawn),patch.object(module,'live_process_group',return_value=False),patch.object(module.os,'killpg',create=True)as kill,patch.object(module.signal,'SIGKILL',getattr(module.signal,'SIGKILL',9),create=True),patch.object(module.os,'O_NOFOLLOW',getattr(os,'O_NOFOLLOW',0),create=True),self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):
                    module.recover_runtime_maintenance(path)
                recovery=self.recovery(self.journal(path));self.assertTrue(state['backendRunning']);self.assertEqual(dumper.call_count,1)
                self.assertEqual((backup/recovery['dumpAttempts'][0]['file']).read_bytes(),b'PGDMPowned child partial');self.assertEqual(recovery['dumpAttempts'][0]['failureCause'],'pg-dump')
                if failure=='timeout':self.assertEqual(kill.call_count,1);self.assertEqual(process.wait.call_count,2)
                else:kill.assert_not_called();self.assertEqual(process.wait.call_count,1)
                self.assert_no_pg_mutation(state)

    def test_complete_offline_read_failures_exhaust_three_files_and_later_polls_keep_backend_running(self):
        import copy
        with self.fixture()as(path,backup,originals,frozen,state,events,saved):
            original_command=module.command;dumper=module.dump_runtime_database
            def offline(args,*values):
                if args[0]=='/usr/lib/postgresql/16/bin/pg_restore':events.append('read-failed');raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
                return original_command(args,*values)
            with patch.object(module,'command',side_effect=offline),self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
            pending=self.journal(path);recovery=self.recovery(pending);attempts=copy.deepcopy(recovery['dumpAttempts']);receipt=copy.deepcopy(recovery['serviceRecovery']);count=len(events)
            self.assertEqual(dumper.call_count,3);self.assertEqual(state['backendStarts'],1);self.assertTrue(all(row['state']=='failed'and row['failureCause']=='pg-restore'for row in attempts))
            for _ in range(2):
                with patch.object(module,'command',side_effect=offline),self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
            again=self.journal(path);self.assertTrue(state['backendRunning']);self.assertEqual(state['backendStarts'],1);self.assertEqual(dumper.call_count,3)
            self.assertNotIn('stop-backend',events[count:]);self.assertNotIn('start-backend',events[count:]);self.assertNotIn('dump',events[count:]);self.assert_no_pg_mutation(state)
            self.assertEqual(self.recovery(again)['dumpAttempts'],attempts);self.assertEqual(self.recovery(again)['serviceRecovery'],receipt);self.assertEqual(again['systemdPolicy'],frozen)
            self.assertEqual(len(list(backup.glob('database-after-drain-boot-*.dump'))),3);self.assertFalse((backup/'completed.json').exists())
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_recovered_backend_can_be_drained_for_a_new_attempt_without_overwriting_original_nonce_or_drain(self):
        import copy
        with self.fixture()as(path,backup,originals,frozen,state,events,saved):
            original=self.journal(path);dumper=module.dump_runtime_database;fresh=dumper.side_effect;dumper.side_effect=self.failure(events)
            with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
            pending=self.journal(path);receipt=copy.deepcopy(self.recovery(pending)['serviceRecovery']);first=copy.deepcopy(self.recovery(pending)['dumpAttempts'][0]);count=len(events);dumper.side_effect=fresh
            # Stop at the real post-dump transaction boundary. No claim is made
            # about completing a package install or native service activation.
            with patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_AFTER_VERIFIED_BOOT_DUMP')),self.assertRaisesRegex(ValueError,'FIXTURE_AFTER_VERIFIED_BOOT_DUMP'):module.recover_runtime_maintenance(path)
            after=self.journal(path);recovery=self.recovery(after)
            self.assertEqual(events[count:],['stop-backend','dump','read-dump']);self.assertFalse(state['backendRunning']);self.assertTrue(state['backendStopped'])
            self.assertEqual(recovery['dumpAttempts'][0],first);self.assertEqual(recovery['dumpAttempts'][1]['state'],'complete');self.assertEqual(recovery['dump']['file'],recovery['dumpAttempts'][1]['file'])
            self.assertEqual(recovery['serviceRecovery'],receipt);self.assertEqual(recovery['retryDrain']['backend'],receipt['backend']);self.assertEqual(recovery['retryDrain']['attempt'],2);self.assertTrue(recovery['retryDrain']['confirmed'])
            self.assertIsNone(recovery['backend']);self.assertTrue(recovery['drainConfirmed']);self.assertEqual(after['backend'],original['backend']);self.assertEqual(after['drainConfirmed'],original['drainConfirmed']);self.assertEqual(after['systemdPolicy'],frozen)
            self.assertEqual(dumper.call_count,2);self.assertEqual(state['backendStarts'],1);self.assert_no_pg_mutation(state)
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_unrecorded_pid_or_start_after_recovery_never_gets_a_new_stop_start_or_backup_permission(self):
        for field in ['backendPID','backendStart']:
            with self.subTest(field=field),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                dumper=module.dump_runtime_database;dumper.side_effect=self.failure(events)
                with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                pending=self.journal(path);count=len(events);state[field]=state[field]+1 if field=='backendPID'else'unrecorded'
                with self.assertRaisesRegex(ValueError,'BACKEND_PROCESS_CHANGED'):module.recover_runtime_maintenance(path)
                self.assertEqual(events[count:],[]);self.assertEqual(dumper.call_count,1);self.assertEqual(self.journal(path),pending);self.assertTrue(state['backendRunning']);self.assert_no_pg_mutation(state)

    def test_recovery_receipt_context_and_full_configuration_tampering_stop_before_any_service_change(self):
        import json
        for field in ['bootId','token','originHash','attemptsHash','version','backend.pid','backend.start','backend.app','backend.environmentHash','backend.codeHash','backend.serviceHash','backend.unitHashes']:
            with self.subTest(field=field),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                module.dump_runtime_database.side_effect=self.failure(events)
                with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                pending=self.journal(path);receipt=self.recovery(pending)['serviceRecovery'];count=len(events)
                if field.startswith('backend.'):
                    key=field.split('.')[1];receipt['backend'][key]=225 if key=='pid'else{'/etc/systemd/system/incudal-backend.service':'e'*64}if key=='unitHashes'else'changed'
                else:receipt[field]=True if field=='version'else'changed'
                path.write_text(json.dumps(pending))
                with self.assertRaisesRegex(ValueError,'BACKEND_|BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                self.assertEqual(events[count:],[]);self.assertTrue(state['backendRunning']);self.assertEqual(state['backendStarts'],1);self.assert_no_pg_mutation(state)
                for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_changed_original_or_failed_artifact_is_preserved_and_cannot_be_converted_into_another_recovery(self):
        for target in ['database.dump','database-after-drain.dump','failed']:
            with self.subTest(target=target),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                module.dump_runtime_database.side_effect=self.failure(events)
                with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                pending=self.journal(path);count=len(events);name=self.recovery(pending)['dumpAttempts'][0]['file']if target=='failed'else target;file=backup/name;changed=b'PGDMPuntrusted changed bytes';file.write_bytes(changed)
                with self.assertRaisesRegex(ValueError,'BACKUP_FAILED')as failure:module.recover_runtime_maintenance(path)
                self.assertNotIsInstance(failure.exception,module.RuntimeBootDumpExecutionFailed);self.assertEqual(events[count:],[]);self.assertEqual(file.read_bytes(),changed);self.assertEqual(self.journal(path),pending)
                self.assertTrue(state['backendRunning']);self.assertEqual(state['backendStarts'],1);self.assert_no_pg_mutation(state)

    def test_unreadable_failed_artifact_never_becomes_owned_execution_failure_or_a_new_service_start(self):
        import errno
        for failure in [PermissionError(errno.EACCES,'fixture denied'),OSError(errno.EIO,'fixture unreadable')]:
            with self.subTest(error=type(failure).__name__),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                module.dump_runtime_database.side_effect=self.failure(events)
                with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                pending=self.journal(path);name=self.recovery(pending)['dumpAttempts'][0]['file'];material=module.runtime_dump_material;count=len(events)
                def unreadable(file):
                    if file.name==name:raise failure
                    return material(file)
                with patch.object(module,'runtime_dump_material',side_effect=unreadable),self.assertRaises(OSError)as caught:module.recover_runtime_maintenance(path)
                self.assertNotIsInstance(caught.exception,module.RuntimeBootDumpExecutionFailed);self.assertEqual(events[count:],[]);self.assertEqual(self.journal(path),pending);self.assertEqual(state['backendStarts'],1)

    def test_shared_or_backup_only_pg_identity_change_is_rejected_before_backend_start_and_financial_check(self):
        for backup_only in [False,True]:
            for field in ['pid','start','settingsHash']:
                with self.subTest(backup_only=backup_only,field=field),self.fixture(backup_only=backup_only)as(path,backup,originals,frozen,state,events,saved):
                    original=self.journal(path);proof=module.database_runtime_proof;changed=[False];owned_failure=self.failure(events)
                    def dump(file,*values):changed[0]=True;return owned_failure(file,*values)
                    def database(**options):
                        current=proof(**options)
                        if changed[0]:current[field]=134 if field=='pid'else'changed'
                        return current
                    with patch.object(module,'database_runtime_proof',side_effect=database),patch.object(module,'dump_runtime_database',side_effect=dump),self.assertRaisesRegex(ValueError,'DATABASE_PROCESS_CHANGED|DATABASE_CONFIGURATION_CHANGED'):module.recover_runtime_maintenance(path)
                    self.assertFalse(state['backendRunning']);self.assertEqual(state['backendStarts'],0);self.assertEqual(events,['dump-failed']);self.assert_no_pg_mutation(state)
                    pending=self.journal(path);self.assertEqual(pending['systemdPolicy'],frozen);self.assertEqual(pending['backend'],original['backend']);self.assertNotIn('serviceRecovery',self.recovery(pending))
                    for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_authority_changed_during_owned_dump_failure_is_refused_before_service_start(self):
        for field in ['/opt/incudal/.env','/opt/incudal/server/dist/app.js','/etc/systemd/system/incudal-backend.service','node']:
            with self.subTest(field=field),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                changed=[False];original_hash=module.protected_hash;original_node=module.verify_runtime_node_authority;original_policy=module.backend_service_policy;owned_failure=self.failure(events)
                def dump(file,*values):changed[0]=True;return owned_failure(file,*values)
                def policy():
                    values,app,units,digest=original_policy()
                    if changed[0]and field=='/etc/systemd/system/incudal-backend.service':units={**units,field:'e'*64}
                    return values,app,units,digest
                def protected(value,*values,**options):
                    if changed[0]and str(value).replace('\\','/')==field:return 'e'*64
                    return original_hash(value,*values,**options)
                def node(*values,**options):
                    if changed[0]and field=='node':raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
                    return original_node(*values,**options)
                with patch.object(module,'dump_runtime_database',side_effect=dump),patch.object(module,'protected_hash',side_effect=protected),patch.object(module,'verify_runtime_node_authority',side_effect=node),patch.object(module,'backend_service_policy',side_effect=policy),self.assertRaisesRegex(ValueError,'BACKEND_CONFIGURATION_CHANGED|NODE_AUTHORITY_UNCONFIRMED'):module.recover_runtime_maintenance(path)
                self.assertFalse(state['backendRunning']);self.assertEqual(state['backendStarts'],0);self.assertEqual(events,['dump-failed']);self.assert_no_pg_mutation(state)

    def test_prestart_finance_health_or_poststart_finance_failure_never_publishes_recovery_completion(self):
        for stage in ['before','health','after']:
            with self.subTest(stage=stage),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                module.dump_runtime_database.side_effect=self.failure(events);original_finance=module.verify_runtime_financial_integrity;calls=[0]
                def finance(*values):
                    calls[0]+=1
                    if stage=='before'and calls[0]==1 or stage=='after'and calls[0]==2:raise ValueError('SYSTEM_SECURITY_FINANCIAL_INTEGRITY_INVALID')
                    return original_finance(*values)
                with contextlib.ExitStack()as stack:
                    stack.enter_context(patch.object(module,'verify_runtime_financial_integrity',side_effect=finance))
                    if stage=='health':stack.enter_context(patch.object(module,'verify_runtime_health',side_effect=ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')))
                    with self.assertRaisesRegex(ValueError,'FINANCIAL_INTEGRITY_INVALID|BACKEND_ACTIVATION_PENDING'):module.recover_runtime_maintenance(path)
                pending=self.journal(path);recovery=self.recovery(pending);self.assertNotIn('serviceRecovery',recovery);self.assertNotIn('backupRecovery',pending);self.assertFalse((backup/'completed.json').exists())
                self.assertEqual(state['backendStarts'],0 if stage=='before'else 1);self.assertEqual(pending['phase'],'installed');self.assertEqual(pending['systemdPolicy'],frozen);self.assert_no_pg_mutation(state)

    def test_lost_service_start_reply_requires_health_full_identity_and_financial_proof_before_receipt(self):
        with self.fixture()as(path,backup,originals,frozen,state,events,saved):
            module.dump_runtime_database.side_effect=self.failure(events);original_command=module.command
            def lost_reply(args,*values):
                answer=original_command(args,*values)
                if args==['systemctl','start','incudal-backend.service']:raise OSError('fixture lost start reply')
                return answer
            with patch.object(module,'command',side_effect=lost_reply),self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
            recovery=self.recovery(self.journal(path));self.assertTrue(state['backendRunning']);self.assertEqual(state['backendStarts'],1)
            self.assertEqual(recovery['serviceRecovery']['backend'],module.backend_runtime_proof());self.assertEqual(recovery['serviceRecoveryStart']['startAttempts'],1)
            self.assertEqual(events,['dump-failed','finance-stopped','start-backend','finance-running']);self.assert_no_pg_mutation(state)

    def test_three_failed_service_starts_never_receive_a_fourth_start_or_dump_attempt(self):
        with self.fixture()as(path,backup,originals,frozen,state,events,saved):
            state.update(backendRunning=True,backendStopped=False,backendInvocation='f'*32,backendExecPID=224,backendExecStart=777,backendResult='success')
            module.dump_runtime_database.side_effect=self.failure(events);original_command=module.command;starts=[0]
            def failed_start(args,*values):
                if args==['systemctl','start','incudal-backend.service']:
                    starts[0]+=1;state.update(backendRunning=False,backendStopped=False,backendInvocation=format(starts[0],'032x'),backendExecPID=500+starts[0],backendExecStart=1000*starts[0],backendResult='exit-code');events.append('start-failed');raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
                return original_command(args,*values)
            with patch.object(module,'command',side_effect=failed_start),patch.object(module,'verify_runtime_health',side_effect=ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')):
                for _ in range(5):
                    with self.assertRaisesRegex(ValueError,'BACKEND_ACTIVATION_PENDING'):module.recover_runtime_maintenance(path)
            pending=self.journal(path);recovery=self.recovery(pending);self.assertEqual(starts[0],3);self.assertEqual(module.dump_runtime_database.call_count,3)
            self.assertEqual(recovery['serviceRecoveryStart']['startAttempts'],3);self.assertEqual(len(recovery['dumpAttempts']),3);self.assertNotIn('serviceRecovery',recovery);self.assertFalse(state['backendRunning'])
            self.assertEqual(pending['systemdPolicy'],frozen);self.assert_no_pg_mutation(state)

    def test_unrelated_identity_permission_or_creation_errors_do_not_enter_owned_dump_recovery(self):
        import errno
        failures=[ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED'),ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED'),PermissionError(errno.EACCES,'fixture denied'),FileExistsError(errno.EEXIST,'fixture collision')]
        for failure in failures:
            with self.subTest(error=str(failure)),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                module.dump_runtime_database.side_effect=self.failure(events,failure)
                with self.assertRaises((ValueError,OSError))as caught:module.recover_runtime_maintenance(path)
                self.assertNotIsInstance(caught.exception,module.RuntimeBootDumpExecutionFailed)
                recovery=self.recovery(self.journal(path))
                if str(failure)=='SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED':
                    self.assertEqual(str(caught.exception),str(failure))
                    self.assertTrue(state['backendRunning']);self.assertEqual(state['backendStarts'],1);self.assertEqual(events,['dump-failed','finance-stopped','start-backend','finance-running'])
                    self.assertEqual(self.journal(path)['backupRecovery']['error'],str(failure))
                    self.assertEqual(recovery['serviceRecovery']['clientFailure']['error'],str(failure));self.assertEqual(len(recovery['serviceRecoveryLaunches']),1)
                else:
                    self.assertFalse(state['backendRunning']);self.assertEqual(state['backendStarts'],0);self.assertEqual(events,['dump-failed'])
                    self.assertNotIn('serviceRecovery',recovery);self.assertNotIn('serviceRecoveryStart',recovery);self.assertNotIn('serviceRecoveryLaunches',recovery)
                self.assertNotIn('failureCause',recovery['dumpAttempts'][0]);self.assert_no_pg_mutation(state)

    def prime_client_failure_boundary(self,path,state,events,stage='before',pending_bytes=True):
        state.update(backendRunning=True,backendPID=224,backendStart='new',backendInvocation='c'*32,backendExecPID=224,backendExecStart=77,backendResult='success')
        if stage=='before':
            with patch.object(module,'runtime_new_boot_dump',side_effect=ValueError('FIXTURE_CONFIRMED_DRAIN_BEFORE_DUMP')),self.assertRaisesRegex(ValueError,'FIXTURE_CONFIRMED_DRAIN_BEFORE_DUMP'):module.recover_runtime_maintenance(path)
        elif stage=='failed':
            with patch.object(module,'dump_runtime_database',side_effect=self.failure(events,ValueError('FIXTURE_UNCLASSIFIED_CLIENT_OUTPUT'))),self.assertRaisesRegex(ValueError,'FIXTURE_UNCLASSIFIED_CLIENT_OUTPUT'):module.recover_runtime_maintenance(path)
        elif stage=='intent':
            def interrupted(file,*_):
                if pending_bytes:file.write_bytes(b'PGDMPstable interrupted client output');file.chmod(0o600)
                events.append('intent-interrupted');raise KeyboardInterrupt('FIXTURE_PENDING_CLIENT_INTENT')
            with patch.object(module,'dump_runtime_database',side_effect=interrupted),self.assertRaisesRegex(KeyboardInterrupt,'FIXTURE_PENDING_CLIENT_INTENT'):module.recover_runtime_maintenance(path)
        elif stage=='complete':
            with patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_COMPLETE_DUMP')),self.assertRaisesRegex(ValueError,'FIXTURE_COMPLETE_DUMP'):module.recover_runtime_maintenance(path)
        else:raise AssertionError(stage)
        recovery=self.recovery(self.journal(path));self.assertTrue(recovery['drainConfirmed']);self.assertFalse(state['backendRunning']);self.assertEqual(events.count('stop-backend'),1)
        return recovery

    def assert_client_receipt(self,path,state,error,count):
        recovery=self.recovery(self.journal(path));receipt=recovery['serviceRecovery'];intent=recovery['serviceRecoveryStart'];launch=recovery['serviceRecoveryLaunches'][-1]
        self.assertEqual(receipt['clientFailure']['error'],error);self.assertEqual(receipt['attemptCount'],count);self.assertEqual(intent['clientFailure'],receipt['clientFailure'])
        self.assertEqual(launch['backend'],module.backend_runtime_proof());self.assertEqual(receipt['backend'],launch['backend']);self.assertEqual(receipt['launchHash'],module.runtime_boot_record_hash(launch));self.assertTrue(state['backendRunning'])
        self.assertFalse(any('failureCause'in row for row in receipt['clientFailure']['attempts']));return recovery

    def test_client_failure_before_first_attempt_restores_once_and_healthy_client_resumes_first_dump(self):
        import copy
        for backup_only in [False,True]:
            for error in sorted(module.BOOT_CLIENT_FAILURE_CODES):
                with self.subTest(backup_only=backup_only,error=error),self.fixture(backup_only=backup_only)as(path,backup,originals,frozen,state,events,saved):
                    before=self.prime_client_failure_boundary(path,state,events);self.assertNotIn('dumpAttempts',before);dumper=module.dump_runtime_database
                    with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)):
                        with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                        recovery=self.assert_client_receipt(path,state,error,0);receipt=copy.deepcopy(recovery['serviceRecovery']);original_backend=copy.deepcopy(recovery['backend']);launch=copy.deepcopy(recovery['serviceRecoveryLaunches'])
                        for _ in range(3):
                            with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                        after=self.recovery(self.journal(path));self.assertEqual(after['serviceRecovery'],receipt);self.assertEqual(after['serviceRecoveryLaunches'],launch);self.assertEqual(state['backendStarts'],1);self.assertEqual(events.count('stop-backend'),1);dumper.assert_not_called()
                    with patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_AFTER_CLIENT_FIRST_DUMP')):
                        for _ in range(2):
                            with self.assertRaisesRegex(ValueError,'FIXTURE_AFTER_CLIENT_FIRST_DUMP'):module.recover_runtime_maintenance(path)
                    after=self.recovery(self.journal(path));self.assertEqual(after['backend'],original_backend);self.assertEqual(after['serviceRecovery'],receipt);self.assertEqual(after['retryDrain']['attempt'],1);self.assertTrue(after['retryDrain']['confirmed'])
                    self.assertEqual(len(after['dumpAttempts']),1);self.assertEqual(after['dumpAttempts'][0]['state'],'complete');self.assertEqual(dumper.call_count,1);self.assertEqual(state['backendStarts'],1);self.assertEqual(events.count('stop-backend'),2);self.assert_no_pg_mutation(state)
                    self.assertEqual(self.journal(path)['phase'],'installed');self.assertEqual(self.journal(path)['systemdPolicy'],frozen)
                    for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_client_failure_after_unclassified_failed_output_keeps_original_bytes_and_resumes_next_dump(self):
        import copy
        for backup_only in [False,True]:
            with self.subTest(backup_only=backup_only),self.fixture(backup_only=backup_only)as(path,backup,originals,frozen,state,events,saved):
                before=self.prime_client_failure_boundary(path,state,events,'failed');attempt=copy.deepcopy(before['dumpAttempts'][0]);raw=(backup/attempt['file']).read_bytes();self.assertNotIn('failureCause',attempt);dumper=module.dump_runtime_database
                error='SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED'
                with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)):
                    for _ in range(3):
                        with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                    recovery=self.assert_client_receipt(path,state,error,1);self.assertEqual(recovery['dumpAttempts'][0],attempt);self.assertEqual(state['backendStarts'],1);self.assertEqual(events.count('stop-backend'),1);dumper.assert_not_called()
                with patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_AFTER_CLIENT_NEXT_DUMP')),self.assertRaisesRegex(ValueError,'FIXTURE_AFTER_CLIENT_NEXT_DUMP'):module.recover_runtime_maintenance(path)
                after=self.recovery(self.journal(path));self.assertEqual([row['state']for row in after['dumpAttempts']],['failed','complete']);self.assertEqual(after['dumpAttempts'][0],attempt);self.assertEqual(after['retryDrain']['attempt'],2)
                self.assertEqual((backup/attempt['file']).read_bytes(),raw);self.assertEqual(dumper.call_count,1);self.assertEqual(state['backendStarts'],1);self.assertEqual(events.count('stop-backend'),2);self.assert_no_pg_mutation(state);self.assertEqual(self.journal(path)['systemdPolicy'],frozen)

    def test_client_failure_with_interrupted_intent_binds_bytes_or_absence_before_confirmed_continuation(self):
        import copy
        for backup_only in [False,True]:
            for pending_bytes,offline_failure in [(False,False),(True,False),(True,True)]:
                with self.subTest(backup_only=backup_only,pending_bytes=pending_bytes,offline_failure=offline_failure),self.fixture(backup_only=backup_only)as(path,backup,originals,frozen,state,events,saved):
                    before=self.prime_client_failure_boundary(path,state,events,'intent',pending_bytes);intent=copy.deepcopy(before['dumpAttempts'][0]);file=backup/intent['file'];raw=file.read_bytes()if pending_bytes else None;dumper=module.dump_runtime_database;error='SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED'
                    with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)):
                        for _ in range(3):
                            with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                        recovery=self.assert_client_receipt(path,state,error,1);reason=copy.deepcopy(recovery['serviceRecovery']['clientFailure']);self.assertEqual(recovery['dumpAttempts'],[intent]);self.assertEqual(reason['pendingDump']['file'],intent['file']);self.assertEqual(reason['pendingDump']['material']is not None,pending_bytes)
                        self.assertEqual(state['backendStarts'],1);self.assertEqual(events.count('stop-backend'),1);dumper.assert_not_called()
                    original_command=module.command;failed=[False]
                    def read(args,*values):
                        if offline_failure and args[0]=='/usr/lib/postgresql/16/bin/pg_restore'and not failed[0]:failed[0]=True;raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
                        return original_command(args,*values)
                    with patch.object(module,'command',side_effect=read),patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_AFTER_CLIENT_INTENT')):
                        for _ in range(2):
                            with self.assertRaisesRegex(ValueError,'FIXTURE_AFTER_CLIENT_INTENT'):module.recover_runtime_maintenance(path)
                    after=self.recovery(self.journal(path));self.assertEqual(after['serviceRecovery']['clientFailure'],reason);self.assertEqual(after['retryDrain']['attempt'],1);self.assertTrue(after['retryDrain']['confirmed'])
                    self.assertEqual(after['dumpAttempts'][-1]['state'],'complete');self.assertEqual(len(after['dumpAttempts']),2 if offline_failure else 1);self.assertEqual(dumper.call_count,1 if not pending_bytes or offline_failure else 0)
                    if pending_bytes:self.assertEqual(file.read_bytes(),raw)
                    self.assertEqual(state['backendStarts'],1);self.assertEqual(events.count('stop-backend'),2);self.assert_no_pg_mutation(state);self.assertEqual(self.journal(path)['systemdPolicy'],frozen)

    def test_client_failure_after_complete_dump_recovers_and_reuses_original_complete_ordinal(self):
        import copy
        for backup_only in [False,True]:
            with self.subTest(backup_only=backup_only),self.fixture(backup_only=backup_only)as(path,backup,originals,frozen,state,events,saved):
                before=self.prime_client_failure_boundary(path,state,events,'complete');attempts=copy.deepcopy(before['dumpAttempts']);proof=copy.deepcopy(before['dump']);self.assertFalse(before['dumpPending']);dumper=module.dump_runtime_database;first_count=dumper.call_count;error='SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED'
                with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)):
                    for _ in range(3):
                        with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                    self.assert_client_receipt(path,state,error,1);self.assertEqual(state['backendStarts'],1);self.assertEqual(events.count('stop-backend'),1);self.assertEqual(dumper.call_count,first_count)
                with patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_REUSE_COMPLETE')):
                    for _ in range(2):
                        with self.assertRaisesRegex(ValueError,'FIXTURE_REUSE_COMPLETE'):module.recover_runtime_maintenance(path)
                after=self.recovery(self.journal(path));self.assertEqual(after['dumpAttempts'],attempts);self.assertEqual(after['dump'],proof);self.assertEqual(after['retryDrain']['attempt'],1);self.assertEqual(dumper.call_count,first_count);self.assertEqual(events.count('stop-backend'),2);self.assertEqual(state['backendStarts'],1);self.assert_no_pg_mutation(state)

    def test_client_reason_pending_bytes_and_unknown_service_changes_are_refused_before_actions(self):
        import copy,json
        for case in ['invalid-error','pending-proof','attempt-shape','pending-bytes','missing-launch','unknown-pid','unknown-start']:
            with self.subTest(case=case),self.fixture()as(path,backup,originals,frozen,state,events,saved):
                self.prime_client_failure_boundary(path,state,events,'intent');error='SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED'
                with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)):
                    with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                    journal=self.journal(path);recovery=self.recovery(journal);before_events=len(events);starts=state['backendStarts'];dumps=module.dump_runtime_database.call_count
                    if case=='invalid-error':recovery['serviceRecoveryStart']['clientFailure']['error']='UNREVIEWED_CLIENT'
                    elif case=='pending-proof':recovery['serviceRecoveryStart']['clientFailure']['pendingDump']['material']=None
                    elif case=='attempt-shape':recovery['serviceRecoveryStart']['clientFailure']['attempts'][0]['attempt']=True
                    elif case=='pending-bytes':(backup/recovery['dumpAttempts'][0]['file']).write_bytes(b'PGDMPunowned replacement')
                    elif case=='missing-launch':recovery.pop('serviceRecoveryLaunches')
                    elif case=='unknown-pid':state['backendPID']=999
                    else:state['backendStart']='unrecorded restart'
                    path.write_text(json.dumps(journal));frozen_journal=path.read_bytes()
                    with self.assertRaisesRegex(ValueError,'BACKEND_PROCESS_CHANGED|RUNTIME_BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                    self.assertEqual(path.read_bytes(),frozen_journal);self.assertEqual(events[before_events:],[]);self.assertEqual(state['backendStarts'],starts);self.assertEqual(module.dump_runtime_database.call_count,dumps);self.assertTrue(state['backendRunning']);self.assert_no_pg_mutation(state)
                    for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_client_early_launch_survives_health_failure_then_good_client_finishes_receipt_before_redrain(self):
        import copy
        with self.fixture()as(path,backup,originals,frozen,state,events,saved):
            self.prime_client_failure_boundary(path,state,events);error='SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED'
            with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)),patch.object(module,'verify_runtime_health',side_effect=ValueError('FIXTURE_CLIENT_HEALTH_REPLY_LOST')),self.assertRaisesRegex(ValueError,'FIXTURE_CLIENT_HEALTH_REPLY_LOST'):module.recover_runtime_maintenance(path)
            pending=self.recovery(self.journal(path));self.assertNotIn('serviceRecovery',pending);launch=copy.deepcopy(pending['serviceRecoveryLaunches']);self.assertEqual(len(launch),1);self.assertTrue(state['backendRunning']);before_events=len(events)
            with patch.object(module,'complete_runtime_package_transaction')as transaction,self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
            transaction.assert_not_called();recovery=self.assert_client_receipt(path,state,error,0);self.assertEqual(recovery['serviceRecoveryLaunches'],launch);self.assertEqual(state['backendStarts'],1);self.assertNotIn('stop-backend',events[before_events:]);module.dump_runtime_database.assert_not_called();self.assert_no_pg_mutation(state)

    def assert_owned_pg_actions(self,state):
        commands=[args for args in state['commands']if args[:2]in [('systemctl','start'),('systemctl','stop')]]
        self.assertTrue(all(args[2]in ['incudal-backend.service','postgresql@16-main.service']for args in commands));self.assertFalse(any(args[0]in ['apt-get','/usr/bin/env']for args in state['commands']))

    def test_complete_owned_pg_client_failure_restores_both_owned_services_and_reuses_complete_dump(self):
        import copy
        for legacy_client in [False,True]:
            for error in ['SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED','SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING']:
                with self.subTest(legacy_client=legacy_client,error=error),self.fixture(owned_pg=True,legacy_client=legacy_client)as(path,backup,originals,frozen,state,events,saved):
                    before=self.prime_client_failure_boundary(path,state,events,'complete');database=copy.deepcopy(before['database']);attempts=copy.deepcopy(before['dumpAttempts']);dump=copy.deepcopy(before['dump']);original_database=copy.deepcopy(self.journal(path)['database']);dumper=module.dump_runtime_database;count=dumper.call_count
                    self.assertFalse(state['pgRunning']);self.assertTrue(before['databaseRecoveryDrain']['confirmed']);self.assertEqual(events.count('stop-pg'),1)
                    with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)):
                        for _ in range(3):
                            with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                        recovery=self.assert_client_receipt(path,state,error,1);pg=copy.deepcopy(recovery['databaseServiceRecoveryLaunches']);self.assertEqual(len(pg),1);self.assertEqual(pg[0]['native']['pid'],state['pgPID']);self.assertNotEqual(pg[0]['execution']['mainPID'],pg[0]['native']['pid'],'forking launcher PID is not the server PID')
                        self.assertEqual(recovery['databaseServiceRecovery']['launchHash'],module.runtime_boot_record_hash(pg[0]));self.assertEqual(recovery['database'],database);self.assertEqual(self.journal(path)['database'],original_database)
                        self.assertEqual(state['pgStarts'],1);self.assertEqual(state['backendStarts'],1);self.assertEqual(events.count('stop-pg'),1);self.assertEqual(events.count('stop-backend'),1);self.assertEqual(dumper.call_count,count)
                    with patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_OWNED_COMPLETE_REUSE')):
                        for _ in range(2):
                            with self.assertRaisesRegex(ValueError,'FIXTURE_OWNED_COMPLETE_REUSE'):module.recover_runtime_maintenance(path)
                    after=self.recovery(self.journal(path));self.assertEqual(after['database'],database);self.assertEqual(after['dumpAttempts'],attempts);self.assertEqual(after['dump'],dump);self.assertEqual(after['databaseServiceRecoveryLaunches'],pg)
                    self.assertEqual(after['retryDrain']['attempt'],1);self.assertEqual(after['databaseRecoveryDrain']['database']['pid'],pg[0]['native']['pid']);self.assertTrue(after['databaseRecoveryDrain']['confirmed'])
                    self.assertFalse(state['pgRunning']);self.assertFalse(state['backendRunning']);self.assertEqual(state['pgStarts'],1);self.assertEqual(state['backendStarts'],1);self.assertEqual(events.count('stop-pg'),2);self.assertEqual(dumper.call_count,count);self.assert_owned_pg_actions(state);self.assertEqual(self.journal(path)['systemdPolicy'],frozen)
                    for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_owned_pg_lost_stop_reply_is_confirmed_without_repeating_stop_or_new_dump(self):
        import copy
        with self.fixture(owned_pg=True)as(path,backup,originals,frozen,state,events,saved):
            state.update(backendRunning=True,backendPID=224,backendStart='new',backendInvocation='c'*32,backendExecPID=224,backendExecStart=77,backendResult='success');original_command=module.command;lost=[False]
            def reply(args,*values):
                result=original_command(args,*values)
                if args==['systemctl','stop','postgresql@16-main.service']and not lost[0]:lost[0]=True;raise ValueError('FIXTURE_PG_STOP_REPLY_LOST')
                return result
            with patch.object(module,'command',side_effect=reply),self.assertRaisesRegex(ValueError,'FIXTURE_PG_STOP_REPLY_LOST'):module.recover_runtime_maintenance(path)
            before=self.recovery(self.journal(path));self.assertEqual(before['phase'],'stopping-database');self.assertFalse(before['databaseRecoveryDrain']['confirmed']);proof=copy.deepcopy(before['dump']);count=module.dump_runtime_database.call_count
            with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')):
                for _ in range(2):
                    with self.assertRaisesRegex(ValueError,'CLIENT_CHANGED'):module.recover_runtime_maintenance(path)
            after=self.recovery(self.journal(path));self.assertTrue(after['databaseRecoveryDrain']['confirmed']);self.assertEqual(after['dump'],proof);self.assertTrue(state['backendRunning']);self.assertTrue(state['pgRunning']);self.assertEqual(state['pgStarts'],1);self.assertEqual(events.count('stop-pg'),1);self.assertEqual(module.dump_runtime_database.call_count,count);self.assert_owned_pg_actions(state)

    def test_owned_pg_lost_start_reply_and_lost_final_pg_receipt_resume_exact_launch(self):
        import copy
        for stage in ['start-reply','final-pg-receipt']:
            with self.subTest(stage=stage),self.fixture(owned_pg=True)as(path,backup,originals,frozen,state,events,saved):
                self.prime_client_failure_boundary(path,state,events,'complete');original_command=module.command;original_write=module.write_runtime_maintenance;lost=[False];error='SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED'
                def command(args,*values):
                    result=original_command(args,*values)
                    if stage=='start-reply'and args==['systemctl','start','postgresql@16-main.service']and not lost[0]:lost[0]=True;raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
                    return result
                def write(value,*values,**options):
                    recovery=self.recovery(value)
                    if stage=='final-pg-receipt'and 'databaseServiceRecovery'in recovery and not lost[0]:lost[0]=True;raise ValueError('FIXTURE_PG_FINAL_RECEIPT_LOST')
                    return original_write(value,*values,**options)
                with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)):
                    with patch.object(module,'command',side_effect=command),patch.object(module,'write_runtime_maintenance',side_effect=write),self.assertRaisesRegex(ValueError,'CLIENT_CHANGED|FIXTURE_PG_FINAL_RECEIPT_LOST'):module.recover_runtime_maintenance(path)
                    pending=self.recovery(self.journal(path));launch=copy.deepcopy(pending['databaseServiceRecoveryLaunches']);self.assertEqual(len(launch),1);self.assertTrue(state['pgRunning'])
                    if stage=='final-pg-receipt':self.assertNotIn('databaseServiceRecovery',pending);self.assertFalse(state['backendRunning'])
                    with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                after=self.recovery(self.journal(path));self.assertEqual(after['databaseServiceRecoveryLaunches'],launch);self.assertEqual(after['databaseServiceRecovery']['launchHash'],module.runtime_boot_record_hash(launch[0]));self.assertTrue(state['backendRunning']);self.assertEqual(state['pgStarts'],1);self.assertEqual(state['backendStarts'],1);self.assert_owned_pg_actions(state)

    def test_owned_pg_unknown_pid_intent_only_bad_stop_and_complete_proof_changes_never_get_start(self):
        import copy,json
        for case in ['unknown-backend','unknown-pg','bad-stop','dump-proof','owned-configuration','intent-only','launch-context']:
            with self.subTest(case=case),self.fixture(owned_pg=True)as(path,backup,originals,frozen,state,events,saved):
                self.prime_client_failure_boundary(path,state,events,'complete');error='SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED'
                if case in ['intent-only','launch-context']:
                    original_write=module.write_runtime_maintenance;blocked=[False]
                    def write(value,*values,**options):
                        if 'databaseServiceRecovery'in self.recovery(value)and not blocked[0]:blocked[0]=True;raise ValueError('FIXTURE_STOP_BEFORE_PG_RECEIPT')
                        return original_write(value,*values,**options)
                    with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)),patch.object(module,'write_runtime_maintenance',side_effect=write),self.assertRaisesRegex(ValueError,'FIXTURE_STOP_BEFORE_PG_RECEIPT'):module.recover_runtime_maintenance(path)
                journal=self.journal(path);recovery=self.recovery(journal)
                if case=='unknown-backend':state.update(backendRunning=True,backendPID=999,backendStart='unowned')
                elif case=='unknown-pg':state.update(pgRunning=True,pgStopped=False,pgPID=999,pgInvocation='e'*32,pgExecPID=999,pgExecStart=999)
                elif case=='bad-stop':state.update(pgStopped=False,pgResult='exit-code')
                elif case=='dump-proof':recovery['dump']['sha256']='e'*64
                elif case=='owned-configuration':journal['database']['settingsHash']='e'*64
                elif case=='intent-only':recovery.pop('databaseServiceRecoveryLaunches')
                else:recovery['databaseServiceRecoveryStart']['originHash']='e'*64
                path.write_text(json.dumps(journal));before=path.read_bytes();starts=state['pgStarts'];backend_starts=state['backendStarts'];count=len(events)
                with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)),self.assertRaisesRegex(ValueError,'PROCESS_CHANGED|CONFIGURATION_CHANGED|STOP_UNCONFIRMED|BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                self.assertEqual(path.read_bytes(),before);self.assertEqual(events[count:],[]);self.assertEqual(state['pgStarts'],starts);self.assertEqual(state['backendStarts'],backend_starts);self.assert_owned_pg_actions(state)
                for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_owned_pg_two_real_exit_code_failures_keep_original_complete_proof_and_never_start_a_third(self):
        import copy
        with self.fixture(owned_pg=True)as(path,backup,originals,frozen,state,events,saved):
            before=self.prime_client_failure_boundary(path,state,events,'complete');database=copy.deepcopy(before['database']);dump=copy.deepcopy(before['dump']);original_command=module.command;error='SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED'
            def fail(args,*values):
                result=original_command(args,*values)
                if args==['systemctl','start','postgresql@16-main.service']:
                    state.update(pgRunning=False,pgClusterRunning=False,pgStopped=False,pgResult='exit-code');raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
                return result
            with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)),patch.object(module,'command',side_effect=fail):
                for _ in range(5):
                    with self.assertRaisesRegex(ValueError,'DATABASE_ACTIVATION_PENDING'):module.recover_runtime_maintenance(path)
            recovery=self.recovery(self.journal(path));self.assertEqual(recovery['database'],database);self.assertEqual(recovery['dump'],dump);self.assertEqual(len(recovery['databaseServiceRecoveryLaunches']),2);self.assertTrue(all(row['state']=='failed'for row in recovery['databaseServiceRecoveryLaunches']))
            self.assertNotIn('databaseServiceRecovery',recovery);self.assertNotIn('serviceRecovery',recovery);self.assertEqual(state['pgStarts'],2);self.assertEqual(state['backendStarts'],0);self.assertEqual(events.count('stop-pg'),1);self.assertFalse(state['pgRunning']);self.assertFalse(state['backendRunning']);self.assert_owned_pg_actions(state)

    def test_zero_client_attempt_with_running_owned_pg_never_restarts_pg_then_uses_complete_recovery(self):
        import copy
        for legacy_client in [False,True]:
            with self.subTest(legacy_client=legacy_client),self.fixture(owned_pg=True,legacy_client=legacy_client)as(path,backup,originals,frozen,state,events,saved):
                before=self.prime_client_failure_boundary(path,state,events);original=copy.deepcopy(before['database']);self.assertTrue(state['pgRunning']);error='SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED';dumper=module.dump_runtime_database
                with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)):
                    for _ in range(3):
                        with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                    recovery=self.assert_client_receipt(path,state,error,0);self.assertNotIn('databaseServiceRecovery',recovery);self.assertNotIn('databaseServiceRecoveryStart',recovery);self.assertEqual(recovery['database'],original)
                    self.assertEqual(state['pgStarts'],0);self.assertEqual(events.count('stop-pg'),0);self.assertEqual(state['backendStarts'],1);dumper.assert_not_called()
                with patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_OWNED_FIRST_COMPLETE')),self.assertRaisesRegex(ValueError,'FIXTURE_OWNED_FIRST_COMPLETE'):module.recover_runtime_maintenance(path)
                complete=self.recovery(self.journal(path));dump=copy.deepcopy(complete['dump']);attempts=copy.deepcopy(complete['dumpAttempts']);self.assertFalse(complete['dumpPending']);self.assertEqual(dumper.call_count,1);self.assertFalse(state['pgRunning']);self.assertEqual(events.count('stop-pg'),1)
                with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)):
                    for _ in range(2):
                        with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                    after=self.assert_client_receipt(path,state,error,1);self.assertEqual(after['dump'],dump);self.assertEqual(after['dumpAttempts'],attempts);self.assertEqual(after['database'],original)
                    self.assertEqual(state['pgStarts'],1);self.assertEqual(state['backendStarts'],2);self.assertTrue(state['pgRunning']);self.assertEqual(dumper.call_count,1);self.assertEqual(events.count('stop-pg'),1);self.assert_owned_pg_actions(state);self.assertEqual(self.journal(path)['systemdPolicy'],frozen)
                    for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_incomplete_owned_pg_loss_client_refusal_restores_pg_and_node_without_requiring_new_dump(self):
        import copy
        for stage in ['before','intent','failed']:
            for result in ['success','exit-code']:
                with self.subTest(stage=stage,result=result),self.fixture(owned_pg=True)as(path,backup,originals,frozen,state,events,saved):
                    before=self.prime_client_failure_boundary(path,state,events,stage);database=copy.deepcopy(before['database']);attempts=copy.deepcopy(before.get('dumpAttempts',[]));self.assertTrue(before['dumpPending']);self.assertNotIn('dump',before)
                    state.update(pgRunning=False,pgStopped=result=='success',pgResult=result,pgClusterRunning=False);error='SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED'
                    with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)):
                        with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                        for _ in range(2):
                            with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                    after=self.recovery(self.journal(path));self.assertTrue(state['pgRunning']);self.assertTrue(state['backendRunning']);self.assertEqual(state['pgStarts'],1);self.assertEqual(state['backendStarts'],1);self.assertEqual(events.count('stop-pg'),0)
                    self.assertEqual(after['database'],database);self.assertEqual(after.get('dumpAttempts',[]),attempts);self.assertNotIn('dump',after);self.assertTrue(after['dumpPending']);self.assertEqual(len(after['databaseServiceRecoveryLaunches']),1);self.assert_owned_pg_actions(state)
                    for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_pg_dump_exit_with_owned_pg_loss_recovers_from_original_dumps_then_requires_new_complete_for_install(self):
        import copy
        with self.fixture(owned_pg=True)as(path,backup,originals,frozen,state,events,saved):
            before=self.prime_client_failure_boundary(path,state,events);database=copy.deepcopy(before['database']);error='SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED'
            def crash(file,*_):
                file.write_bytes(b'PGDMPowned dump before PG loss');file.chmod(0o600);events.append('dump-failed');state.update(pgRunning=False,pgStopped=False,pgResult='exit-code',pgClusterRunning=False);raise ValueError(error)
            with patch.object(module,'dump_runtime_database',side_effect=crash),patch.object(module,'complete_runtime_package_transaction')as install,self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
            install.assert_not_called();after=self.recovery(self.journal(path));failed=copy.deepcopy(after['dumpAttempts'][0]);raw=(backup/failed['file']).read_bytes();self.assertEqual(failed['state'],'failed');self.assertEqual(failed['failureCause'],'pg-dump')
            self.assertTrue(state['pgRunning']);self.assertTrue(state['backendRunning']);self.assertEqual(state['pgStarts'],1);self.assertEqual(state['backendStarts'],1);self.assertEqual(after['database'],database);self.assertNotIn('dump',after);self.assertTrue(after['dumpPending'])
            with patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_NEW_COMPLETE_AFTER_PG_LOSS')),self.assertRaisesRegex(ValueError,'FIXTURE_NEW_COMPLETE_AFTER_PG_LOSS'):module.recover_runtime_maintenance(path)
            resumed=self.recovery(self.journal(path));self.assertEqual(resumed['database'],database);self.assertEqual(resumed['dumpAttempts'][0],failed);self.assertEqual((backup/failed['file']).read_bytes(),raw);self.assertEqual(resumed['dumpAttempts'][1]['state'],'complete');self.assertFalse(resumed['dumpPending'])
            self.assertEqual(events.count('stop-pg'),1);self.assertEqual(state['pgStarts'],1);self.assertEqual(state['backendStarts'],1);self.assert_owned_pg_actions(state)

    def test_incomplete_owned_pg_recovery_refuses_live_cluster_bad_original_backup_or_failed_stop(self):
        import copy,json
        for case in ['live-cluster','original-dump','original-configuration','failed-stop']:
            with self.subTest(case=case),self.fixture(owned_pg=True)as(path,backup,originals,frozen,state,events,saved):
                self.prime_client_failure_boundary(path,state,events);state.update(pgRunning=False,pgStopped=False,pgResult='exit-code',pgClusterRunning=False)
                journal=self.journal(path);recovery=self.recovery(journal)
                if case=='live-cluster':state['pgClusterRunning']=True
                elif case=='original-dump':(backup/'database.dump').write_bytes(b'PGDMPchanged original backup')
                elif case=='original-configuration':journal['database']['settingsHash']='e'*64
                else:recovery.update(phase='stopping-database',databaseRecoveryDrain={'confirmed':False})
                path.write_text(json.dumps(journal));before=path.read_bytes();count=len(events)
                with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')),self.assertRaisesRegex(ValueError,'PROCESS_CHANGED|CONFIGURATION_CHANGED|STOP_UNCONFIRMED|BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                self.assertEqual(path.read_bytes(),before);self.assertEqual(events[count:],[]);self.assertEqual(state['pgStarts'],0);self.assertEqual(state['backendStarts'],0);self.assertFalse(state['backendRunning']);self.assert_owned_pg_actions(state)

    def test_incomplete_owned_pg_two_failed_starts_keep_old_dumps_and_never_install_or_start_third(self):
        import copy
        with self.fixture(owned_pg=True)as(path,backup,originals,frozen,state,events,saved):
            before=self.prime_client_failure_boundary(path,state,events);database=copy.deepcopy(before['database']);state.update(pgRunning=False,pgStopped=False,pgResult='exit-code',pgClusterRunning=False);original_command=module.command
            def fail(args,*values):
                result=original_command(args,*values)
                if args==['systemctl','start','postgresql@16-main.service']:
                    state.update(pgRunning=False,pgClusterRunning=False,pgStopped=False,pgResult='exit-code');raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
                return result
            with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')),patch.object(module,'command',side_effect=fail),patch.object(module,'complete_runtime_package_transaction')as install:
                for _ in range(5):
                    with self.assertRaisesRegex(ValueError,'DATABASE_ACTIVATION_PENDING'):module.recover_runtime_maintenance(path)
                install.assert_not_called()
            recovery=self.recovery(self.journal(path));self.assertEqual(recovery['database'],database);self.assertNotIn('dump',recovery);self.assertTrue(recovery['dumpPending']);self.assertEqual(len(recovery['databaseServiceRecoveryLaunches']),2)
            self.assertTrue(all(row['state']=='failed'and row['intent']['faultRecovery']for row in recovery['databaseServiceRecoveryLaunches']));self.assertEqual(state['pgStarts'],2);self.assertEqual(state['backendStarts'],0);self.assert_owned_pg_actions(state)
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_incomplete_pg_loss_before_new_boot_observation_uses_original_owned_record_only_for_a_real_start(self):
        import copy,json
        with self.fixture(owned_pg=True)as(path,backup,originals,frozen,state,events,saved):
            self.prime_client_failure_boundary(path,state,events);journal=self.journal(path);original=copy.deepcopy(journal['database']);recovery=self.recovery(journal);recovery.pop('database');path.write_text(json.dumps(journal))
            state.update(pgRunning=False,pgStopped=False,pgResult='exit-code',pgClusterRunning=False);error='SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED'
            with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError(error)):
                for _ in range(3):
                    with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
            after=self.recovery(self.journal(path));self.assertEqual(after['databaseRecoveryAuthority']['source'],'original-record');self.assertEqual(self.journal(path)['database'],original);self.assertNotIn('database',after)
            self.assertTrue(state['pgRunning']);self.assertTrue(state['backendRunning']);self.assertEqual(state['pgStarts'],1);self.assertEqual(state['backendStarts'],1)
            with patch.object(module,'complete_runtime_package_transaction',side_effect=ValueError('FIXTURE_FIRST_PG_OBSERVATION_AFTER_START')),self.assertRaisesRegex(ValueError,'FIXTURE_FIRST_PG_OBSERVATION_AFTER_START'):module.recover_runtime_maintenance(path)
            complete=self.recovery(self.journal(path));self.assertEqual(complete['database']['pid'],complete['databaseServiceRecoveryLaunches'][0]['native']['pid']);self.assertEqual(self.journal(path)['database'],original);self.assertFalse(complete['dumpPending']);self.assert_owned_pg_actions(state)
        with self.fixture(owned_pg=True)as(path,backup,originals,frozen,state,events,saved):
            self.prime_client_failure_boundary(path,state,events);journal=self.journal(path);self.recovery(journal).pop('database');path.write_text(json.dumps(journal));state.update(pgRunning=True,pgPID=999,pgStopped=False,pgClusterRunning=True)
            with patch.object(module,'verify_runtime_database_clients',side_effect=ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')),self.assertRaisesRegex(ValueError,'DATABASE_PROCESS_CHANGED'):module.recover_runtime_maintenance(path)
            self.assertEqual(state['pgStarts'],0);self.assertEqual(state['backendStarts'],0);self.assert_owned_pg_actions(state)

class RuntimeRecoveryPsql(unittest.TestCase):
    @contextlib.contextmanager
    def client_files(self,root=None,major=16,real_files=None):
        # SQL probing and client decisions remain product code. Client bytes
        # live on disk; Linux uses real FD/permission checks. Windows adapts
        # Unix executable mode/parent ownership only, never the SQL probe.
        import hashlib
        real_path=pathlib.Path;real_open=os.open;real_lstat=os.lstat
        if real_files is None:real_files=module.runtime_database_client_files
        directory=tempfile.TemporaryDirectory(dir='/root'if sys.platform=='linux'and os.geteuid()==0 else str(root)if root is not None else None)
        physical_root=(type(root)if root is not None else real_path)(directory.name);folder=physical_root/'usr/lib/postgresql'/str(major)/'bin';folder.mkdir(mode=0o755,parents=True)
        logical=module.runtime_database_client_paths(major);physical={name:folder/name for name in logical};mapping={logical[name]:physical[name]for name in logical};modes={name:0o755 for name in logical}
        program=physical_root/'usr/lib/postgresql/16/bin/postgres';program.parent.mkdir(mode=0o755,parents=True,exist_ok=True);program.write_bytes(b'physical postgres inode fixture');program.chmod(0o755);mapping['/usr/lib/postgresql/16/bin/postgres']=program;modes['postgres']=0o755
        originals={name:('original bound '+name).encode()for name in logical}
        for name,file in physical.items():file.write_bytes(originals[name]);file.chmod(0o755)
        def mapped(value):return mapping.get(os.fspath(value),value)
        def path(*parts):
            key=str(pathlib.PurePosixPath(*[str(part)for part in parts]))
            return mapping[key]if key in mapping else real_path(*parts)
        def regular(value,limit=128*1024*1024,private=False,content=False):
            file=mapped(value);data=file.read_bytes();info=file.stat();name=file.name
            if info.st_nlink!=1 or len(data)>limit:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            result={'type':'file','sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'mode':modes[name],'uid':0,'gid':0}
            if content:result['content']=data
            return result
        def change(name,kind):
            file=physical[name]
            if kind=='missing':file.unlink()
            elif kind=='not-executable':file.chmod(0o644);modes[name]=0o644
            elif kind=='changed':file.write_bytes(b'unknown substituted executable')
            else:raise AssertionError(kind)
        def restore(name):physical[name].write_bytes(originals[name]);physical[name].chmod(0o755);modes[name]=0o755
        with contextlib.ExitStack()as stack:
            stack.enter_context(patch.object(module.pathlib,'Path',side_effect=path));stack.enter_context(patch.object(module.os,'open',side_effect=lambda value,*args,**kwargs:real_open(mapped(value),*args,**kwargs)));stack.enter_context(patch.object(module.os,'lstat',side_effect=lambda value,*args,**kwargs:real_lstat(mapped(value),*args,**kwargs)));stack.enter_context(patch.object(module,'runtime_database_client_files',new=real_files))
            if sys.platform=='win32':stack.enter_context(patch.object(module,'runtime_payload_parents',return_value=[]));stack.enter_context(patch.object(module,'runtime_payload_regular',side_effect=regular))
            try:yield logical,physical,change,restore
            finally:directory.cleanup()

    @contextlib.contextmanager
    def sql_probe(self,state=None,client_major=16,fallback=None):
        # Only OS/SQL transport is adapted. database_runtime_proof, individual
        # psql validation and effective-settings hashing execute unchanged.
        import hashlib,json
        if state is None:state={'pgRunning':True,'pgPID':133}
        path_api=module.pathlib.Path;protected=module.protected_hash;queries=[]
        database=RuntimeDatabaseClients.database();program='/usr/lib/postgresql/16/bin/postgres';configuration=['/etc/postgresql/16/main/postgresql.conf','/etc/postgresql/16/main/pg_hba.conf','/etc/postgresql/16/main/pg_ctl.conf','/etc/postgresql/16/main/start.conf','/var/lib/postgresql/16/main/postgresql.auto.conf','/usr/lib/systemd/system/postgresql@.service']
        hashes={file:hashlib.sha256(('retained '+file).encode()).hexdigest()for file in configuration}
        settings={'settings':[['listen_addresses','localhost','configuration file','postmaster']],'files':[database['config']],'invalid':0,'pending':0}
        class File:
            def __init__(self,key):self.key=key
            def __truediv__(self,part):return File(self.key+'/'+part)
            def stat(self):
                if self.key.endswith('/exe'):return path_api(program).stat()
                return types.SimpleNamespace(st_uid=0)
            def readlink(self):return program if self.key.endswith('/exe')else'pid:[1]'
            def read_text(self):
                if self.key=='/opt/incudal/.env':return 'DATABASE_URL=postgresql://incudal:unit-fixture@127.0.0.1:5432/incudal\n'
                return str(state['pgPID'])+' (postgres) '+' '.join(['S']+['0']*18+[str(state['pgPID'])])
        def path(*parts):
            key=str(pathlib.PurePosixPath(*[str(part)for part in parts]))
            if key=='/opt/incudal/.env'or key=='/var/lib/postgresql/16/main'or key=='/proc/1/ns/pid'or key=='/proc/'+str(state['pgPID'])or key.startswith('/proc/'+str(state['pgPID'])+'/'):return File(key)
            return path_api(*parts)
        def command(args,*values):
            if args==['pg_lsclusters','--json']:return json.dumps([{'version':'16','cluster':'main','port':5432,'running':int(state['pgRunning'])}])
            if args[0]=='runuser':
                self.assertEqual(args[4],'/usr/lib/postgresql/'+str(client_major)+'/bin/psql');queries.append(tuple(args))
                return json.dumps(settings if 'pg_file_settings'in args[-1]else{'major':16,'version':'160016','data':database['data'],'config':database['config'],'hba':database['hba'],'recovery':False,'replication':0,'otherDatabases':0,'otherClients':0})
            if args==['systemctl','is-active','postgresql@16-main.service']:return 'active'
            if args==['systemctl','show','postgresql@16-main.service','--property=MainPID,ExecStart,ExecStop,FragmentPath,DropInPaths']:
                return 'MainPID='+str(state['pgPID'])+'\nFragmentPath=/usr/lib/systemd/system/postgresql@.service\nDropInPaths=\nExecStart={ argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect 16-main start ; }\nExecStop={ argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect -m fast 16-main stop ; }'
            if fallback is not None:return fallback(args,*values)
            raise AssertionError('unexpected SQL probe command')
        def hash_file(value,*args,**kwargs):
            key=str(value).replace('\\','/')
            return hashes[key]if key in hashes else protected(value,*args,**kwargs)
        with patch.object(module.pathlib,'Path',side_effect=path),patch.object(module,'protected_hash',side_effect=hash_file),patch.object(module,'command',side_effect=command):yield queries

    @staticmethod
    def probe(function,journal,shared=True):
        # Baseline replay calls the original R5 signature too, so failures
        # expose behavior rather than merely the newly added journal argument.
        import inspect
        options={'shared_read_only':shared}
        if 'journal'in inspect.signature(function).parameters:options['journal']=journal
        return function(**options)

    def test_real_psql_missing_mode_and_original_hash_drift_refuse_queries(self):
        real_probe=module.database_runtime_proof
        for kind in ['missing','not-executable','changed']:
            with self.subTest(kind=kind),self.client_files()as(logical,physical,change,restore):
                before=module.runtime_database_client_files(16);journal={'phase':'installed','backupDatabase':{'major':16,'clientTools':before}}
                change('psql',kind)
                with self.sql_probe()as queries,self.assertRaisesRegex(ValueError,'CLIENT_UNCONFIRMED|CLIENT_CHANGED'):self.probe(real_probe,journal)
                self.assertEqual(queries,[]);self.assertEqual(journal['backupDatabase']['clientTools'],before)

    def test_pg_dump_or_restore_loss_does_not_block_the_real_bound_psql_probe(self):
        real_probe=module.database_runtime_proof
        for name in ['pg_dump','pg_restore']:
            with self.subTest(name=name),self.client_files()as(logical,physical,change,restore):
                before=module.runtime_database_client_files(16);journal={'phase':'installed','backupDatabase':{'major':16,'clientTools':before}};change(name,'missing')
                with self.sql_probe()as queries:proof=self.probe(real_probe,journal)
                self.assertEqual(proof['major'],16);self.assertEqual(len(queries),2);self.assertFalse(physical[name].exists());self.assertEqual(journal['backupDatabase']['clientTools'],before)

    def test_real_sql_probe_rechecks_bound_psql_before_a_second_query(self):
        real_probe=module.database_runtime_proof
        with self.client_files()as(logical,physical,change,restore):
            before=module.runtime_database_client_files(16);journal={'phase':'installed','backupDatabase':{'major':16,'clientTools':before}}
            with self.sql_probe()as queries:
                original=module.command
                def replaced(args,*values):
                    result=original(args,*values)
                    if args[0]=='runuser'and len(queries)==1:change('psql','changed')
                    return result
                with patch.object(module,'command',side_effect=replaced),self.assertRaisesRegex(ValueError,'CLIENT_CHANGED'):self.probe(real_probe,journal)
            self.assertEqual(len(queries),1)

    def test_real_psql_expected_transition_requires_the_original_authenticated_before(self):
        import copy
        real_probe=module.database_runtime_proof
        for bad_before in [False,True]:
            with self.subTest(bad_before=bad_before),self.client_files()as(logical,physical,change,restore):
                before=module.runtime_database_client_files(16);journal={'phase':'installed','backupDatabase':{'major':16,'clientTools':before}};physical['psql'].write_bytes(b'authenticated expected psql');expected=module.runtime_database_client_files(16)
                def source(_,major,label):return RuntimeDatabaseClients.tools()if bad_before and label=='before'else copy.deepcopy(before if label=='before'else expected)
                with patch.object(module,'runtime_database_payload_clients',side_effect=source),self.sql_probe()as queries:
                    if bad_before:
                        with self.assertRaisesRegex(ValueError,'CLIENT_CHANGED'):self.probe(real_probe,journal)
                        self.assertEqual(queries,[])
                    else:self.assertEqual(self.probe(real_probe,journal)['major'],16);self.assertEqual(len(queries),2)
                self.assertEqual(journal['backupDatabase']['clientTools'],before)

    def test_legacy_client18_psql_keeps_server16_and_original_before_authority(self):
        real_probe=module.database_runtime_proof
        with self.client_files(major=18)as(logical,physical,change,restore):
            before=module.runtime_database_client_files(18);journal={'phase':'installed','database':{'major':16}}
            with patch.object(module,'runtime_database_legacy_before_clients',return_value=before)as authority,self.sql_probe(client_major=18)as queries:proof=self.probe(real_probe,journal)
            self.assertEqual(proof['major'],16);self.assertEqual(len(queries),2);self.assertTrue(all(call.args==(journal,16)for call in authority.call_args_list));self.assertEqual(journal['database'],{'major':16})

    @contextlib.contextmanager
    def native_process(self):
        # Product native reader stays real. /proc byte files and executable
        # inodes are physical; namespace/root/UID and systemd transport alone
        # are private OS adapters, with no PostgreSQL process/service started.
        import json
        with self.client_files()as(logical,physical,change,restore):
            path_api=module.pathlib.Path;program='/usr/lib/postgresql/16/bin/postgres';binary=path_api(program);root=binary.parent;proc=root/'private-proc';proc.mkdir(mode=0o700);database=RuntimeDatabaseClients.database();execution={'pid':134,'active':'active','result':'success','invocationId':'a'*32,'mainPID':900,'startedUsec':2000};flags={};calls=[]
            (proc/'stat').write_text('134 (postgres) '+' '.join(['S']+['0']*18+['567']));(proc/'status').write_text('Uid:\t1001\t1001\t1001\t1001\nGid:\t1001\t1001\t1001\t1001\n');(proc/'cmdline').write_bytes((program+'\0-D\0'+database['data']+'\0-c\0config_file='+database['config']+'\0').encode());(proc/'cgroup').write_text('0::/system.slice/system-postgresql.slice/postgresql@16-main.service\n')
            class File:
                def __init__(self,key):self.key=key
                def __truediv__(self,part):return File(self.key+'/'+part)
                def stat(self):
                    if self.key==database['data']:return types.SimpleNamespace(st_uid=1001,st_gid=1001)
                    value=binary.stat()if self.key.endswith('/exe')else root.stat()
                    if flags.get('exe')and self.key.endswith('/exe')or flags.get('root')and self.key.endswith('/root'):return types.SimpleNamespace(st_dev=value.st_dev,st_ino=value.st_ino+1)
                    return value
                def readlink(self):return program if self.key.endswith('/exe')else'pid:[2]'if flags.get('namespace')and self.key.startswith('/proc/134/')else'pid:[1]'
                def open(self,*args,**kwargs):return (proc/self.key.rsplit('/',1)[1]).open(*args,**kwargs)
            def path(*parts):
                key=str(pathlib.PurePosixPath(*[str(part)for part in parts]))
                if key in ['/',database['data'],'/proc/134','/proc/1/ns/pid']or key.startswith('/proc/134/'):return File(key)
                return path_api(*parts)
            def command(args,*values):
                calls.append(tuple(args))
                if args==['systemctl','show',database['unit'],'--property=ExecStart,ExecStop,FragmentPath,DropInPaths,ControlGroup']:
                    return 'ExecStart={ argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect 16-main start'+(' -o unknown'if flags.get('unit-override')else'')+' ; }\nExecStop={ argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect -m fast 16-main stop ; }\nFragmentPath=/usr/lib/systemd/system/postgresql@.service\nDropInPaths='+('/etc/systemd/system/unknown.conf'if flags.get('drop-in')else'')+'\nControlGroup=/system.slice/system-postgresql.slice/postgresql@16-main.service'
                self.assertEqual(args,['systemctl','show',database['unit'],'--property=MainPID,ActiveState,Result,InvocationID,ExecMainPID,ExecMainStartTimestampMonotonic'])
                return 'MainPID=134\nActiveState=active\nResult=success\nInvocationID='+execution['invocationId']+'\nExecMainPID=900\nExecMainStartTimestampMonotonic=2000'
            account=types.SimpleNamespace(pw_uid=1001,pw_gid=1001)
            with patch.object(module.pathlib,'Path',side_effect=path),patch.dict(sys.modules,{'pwd':types.SimpleNamespace(getpwnam=lambda name:account)}),patch.object(module,'verify_runtime_database_files')as files,patch.object(module,'verify_runtime_process_libraries')as libraries,patch.object(module,'command',side_effect=command),patch.object(module,'database_runtime_proof')as sql:
                yield database,execution,proc,binary,flags,calls,sql

    def test_native_launch_reads_complete_process_facts_without_sql_and_rejects_wrong_identity(self):
        for kind in ['valid','standard-extra','uid','namespace','exe','root','arguments','unknown-extra','duplicate-extra','unit-override','drop-in','cgroup']:
            with self.subTest(kind=kind),self.native_process()as(database,execution,proc,binary,flags,calls,sql):
                if kind=='uid':(proc/'status').write_text('Uid:\t0\t0\t0\t0\nGid:\t1001\t1001\t1001\t1001\n')
                elif kind in ['namespace','exe','root','unit-override','drop-in']:flags[kind]=True
                elif kind=='arguments':(proc/'cmdline').write_bytes(b'/usr/lib/postgresql/16/bin/postgres\0-D\0/unknown\0-c\0config_file=/unknown\0')
                elif kind=='standard-extra':(proc/'cmdline').write_bytes(('/usr/lib/postgresql/16/bin/postgres\0-D\0'+database['data']+'\0-c\0unix_socket_directories=/var/run/postgresql\0-c\0config_file='+database['config']+'\0-c\0hba_file='+database['hba']+'\0-c\0ident_file=/etc/postgresql/16/main/pg_ident.conf\0-c\0external_pid_file=/var/run/postgresql/16-main.pid\0').encode())
                elif kind in ['unknown-extra','duplicate-extra']:(proc/'cmdline').write_bytes((proc/'cmdline').read_bytes()+('-c\0listen_addresses=0.0.0.0\0'if kind=='unknown-extra'else'-c\0config_file='+database['config']+'\0').encode())
                elif kind=='cgroup':(proc/'cgroup').write_text('0::/system.slice/unrelated.service\n')
                if kind in ['valid','standard-extra']:
                    proof=module.runtime_boot_database_native(database,execution);self.assertEqual(proof['pid'],134);self.assertEqual(proof['start'],'567');self.assertEqual(proof['inode'],binary.stat().st_ino);self.assertNotIn('settingsHash',proof)
                    with self.assertRaisesRegex(ValueError,'PROCESS_CHANGED'):module.validate_runtime_boot_database_native(database,{**proof,'settingsHash':database['settingsHash']})
                else:
                    with self.assertRaisesRegex(ValueError,'PROCESS_CHANGED'):module.runtime_boot_database_native(database,execution)
                sql.assert_not_called();self.assertFalse(any(args[0]=='runuser'for args in calls))

    def test_native_launch_refuses_real_program_inode_or_proc_start_replacement_during_read(self):
        for kind in ['program-inode','proc-start']:
            with self.subTest(kind=kind),self.native_process()as(database,execution,proc,binary,flags,calls,sql):
                regular=module.runtime_payload_regular
                def replaced(*args,**kwargs):
                    result=regular(*args,**kwargs)
                    if kind=='program-inode':
                        data=binary.read_bytes();retained=binary.with_name('retained-postgres');binary.rename(retained);binary.write_bytes(data);binary.chmod(0o755);self.assertNotEqual(binary.stat().st_ino,retained.stat().st_ino)
                    else:(proc/'stat').write_text('134 (postgres) '+' '.join(['S']+['0']*18+['568']))
                    return result
                with patch.object(module,'runtime_payload_regular',side_effect=replaced),self.assertRaisesRegex(ValueError,'PROCESS_CHANGED'):module.runtime_boot_database_native(database,execution)
                sql.assert_not_called()

    @contextlib.contextmanager
    def owned_failure(self,kind):
        import copy,json
        real_probe=module.database_runtime_proof;real_files=module.runtime_database_client_files;flow=RuntimeBootDumpRecovery()
        with flow.fixture(owned_pg=True)as(path,backup,originals,frozen,state,events,saved):
            flow.prime_client_failure_boundary(path,state,events)
            with self.client_files(root=backup.parent,real_files=real_files)as(logical,physical,change,restore),self.sql_probe(state=state,fallback=module.command)as queries,patch.object(module,'runtime_database_payload_clients',return_value=None),patch.object(module,'database_runtime_proof',new=real_probe):
                tools=module.runtime_database_client_files(16);journal=flow.journal(path);journal['backupDatabase']['clientTools']=tools
                observed=self.probe(real_probe,journal);original={key:value for key,value in observed.items()if key!='sharedReadOnly'};original.update(pid=journal['database']['pid'],start=journal['database']['start'])
                journal['database']=copy.deepcopy(original);journal['backupDatabase']={**copy.deepcopy(original),'clientTools':tools};flow.recovery(journal)['database']={key:value for key,value in observed.items()if key!='sharedReadOnly'};path.write_text(json.dumps(journal));retained=copy.deepcopy(journal)
                change('psql',kind);state.update(pgRunning=False,pgClusterRunning=False,pgStopped=False,pgResult='exit-code');queries.clear()
                yield flow,path,backup,originals,frozen,state,events,queries,retained,lambda:restore('psql')

    def test_actual_psql_failure_keeps_native_pg_launch_then_closes_sql_and_backend_once(self):
        import copy
        for kind in ['missing','not-executable','changed']:
            with self.subTest(kind=kind),self.owned_failure(kind)as(flow,path,backup,originals,frozen,state,events,queries,retained,restore):
                error='CLIENT_CHANGED'if kind=='changed'else'CLIENT_UNCONFIRMED'
                with patch.object(module,'complete_runtime_package_transaction')as install:
                    for _ in range(2):
                        with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                    pending=flow.journal(path);recovery=flow.recovery(pending);launch=copy.deepcopy(recovery['databaseServiceRecoveryLaunches'][0]);self.assertIsNone(launch['database']);self.assertIn('native',launch);self.assertNotIn('settingsHash',launch['native']);self.assertNotIn('databaseServiceRecovery',recovery)
                    self.assertEqual(queries,[]);self.assertTrue(state['pgRunning']);self.assertFalse(state['backendRunning']);self.assertEqual(state['pgStarts'],1);self.assertEqual(state['backendStarts'],0)
                    restore()
                    with self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(path)
                    final=flow.journal(path);closed=flow.recovery(final);self.assertEqual(closed['databaseServiceRecoveryLaunches'],[launch]);self.assertEqual(closed['databaseServiceRecovery']['launchHash'],module.runtime_boot_record_hash(launch));self.assertEqual(closed['databaseServiceRecovery']['database']['pid'],launch['native']['pid']);self.assertEqual(closed['databaseServiceRecovery']['database']['settingsHash'],retained['database']['settingsHash'])
                    self.assertTrue(state['backendRunning']);self.assertEqual(state['pgStarts'],1);self.assertEqual(state['backendStarts'],1);self.assertGreater(len(queries),1);install.assert_not_called()
                    self.assertEqual(final['database'],retained['database']);self.assertEqual(closed['database'],flow.recovery(retained)['database']);self.assertEqual(final['systemdPolicy'],frozen);self.assertNotIn('dump',closed);self.assertEqual(events.count('stop-pg'),0)
                    for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_native_launch_cannot_be_recreated_from_intent_or_a_stranger_after_psql_repair(self):
        import json
        for case in ['intent-only','stranger-pid','invocation','native-hash','resume-reason']:
            with self.subTest(case=case),self.owned_failure('missing')as(flow,path,backup,originals,frozen,state,events,queries,retained,restore):
                with self.assertRaisesRegex(ValueError,'CLIENT_UNCONFIRMED'):module.recover_runtime_maintenance(path)
                journal=flow.journal(path);recovery=flow.recovery(journal);launch=recovery['databaseServiceRecoveryLaunches'][0]
                if case=='intent-only':recovery.pop('databaseServiceRecoveryLaunches')
                elif case=='stranger-pid':state['pgPID']=999
                elif case=='invocation':state['pgInvocation']='e'*32
                elif case=='native-hash':launch['native']['configurationHash']='e'*64
                else:launch['resume']['attemptsHash']='e'*64
                path.write_text(json.dumps(journal));restore();before=path.read_bytes();count=len(events)
                with self.assertRaisesRegex(ValueError,'PROCESS_CHANGED|BACKUP_FAILED'):module.recover_runtime_maintenance(path)
                self.assertEqual(path.read_bytes(),before);self.assertEqual(events[count:],[]);self.assertEqual(state['pgStarts'],1);self.assertEqual(state['backendStarts'],0)

class BeforeSnapshot(unittest.TestCase):
    def test_only_the_single_canonical_same_name_snapshot_redirect_is_allowed(self):
        root='https://snapshot.debian.org/file/'+'a'*40+'/'
        for original,target in [('https://snapshot.debian.org/archive/debian/20260711T202405Z/dists/trixie/InRelease',root+'InRelease'),('https://snapshot.debian.org/archive/debian/20260711T202405Z/pool/main/g/glibc/libc6_2.41-12+deb13u4_amd64.deb',root+'libc6_2.41-12%2Bdeb13u4_amd64.deb')]:
            self.assertEqual(module.snapshot_redirect_target(original,target,0),target)
            with self.assertRaisesRegex(ValueError,'SOURCE_REJECTED'):module.snapshot_redirect_target(original,target,1)
        original='https://snapshot.debian.org/archive/debian/20260711T202405Z/dists/trixie/InRelease'
        for target in [root+'Other',root+'%49nRelease',root+'%2FInRelease',root+'%2e%2e',root+'InRelease?x=1',root+'InRelease#x',root.replace('https:','http:')+'InRelease',root.replace('snapshot.debian.org','other.invalid')+'InRelease',root.replace('snapshot.debian.org','root@snapshot.debian.org')+'InRelease',root.replace('snapshot.debian.org','snapshot.debian.org:443')+'InRelease',root.replace('/file/','/archive/')+'InRelease']:
            with self.assertRaisesRegex(ValueError,'SOURCE_REJECTED'):module.snapshot_redirect_target(original,target,0)
        with self.assertRaisesRegex(ValueError,'SOURCE_REJECTED'):module.snapshot_redirect_target('https://snapshot.debian.org/archive/debian/20260711T202405Z/a+b',root+'a%252Bb',0)
        for name in ['a+b','a%2bb','a%252Bb']:
            with self.assertRaisesRegex(ValueError,'SOURCE_REJECTED'):module.snapshot_redirect_target('https://snapshot.debian.org/archive/debian/20260711T202405Z/a+b',root+name,0)

    def test_history_network_budget_is_bounded_before_any_request(self):
        import urllib.request
        for requests,elapsed in [(12,0),(0,20),(0,21)]:
            with patch.object(module.time,'monotonic',return_value=elapsed),patch.object(urllib.request,'build_opener')as network,self.assertRaisesRegex(ValueError,'SOURCE_UNAVAILABLE'):
                module.snapshot_read('/mr/file/'+'a'*40+'/info',1024,{'requests':requests,'started':0})
            network.assert_not_called()

    def test_history_expiry_observation_does_not_rewrite_the_original_source_proof(self):
        source={'collectedAt':150,'historicalExpired':False};signed={'date':100,'validUntil':200,'expired':True}
        with patch.object(module.time,'time',return_value=300):self.assertEqual(module.snapshot_collected_time(source,signed),(150,False))
        self.assertEqual(source,{'collectedAt':150,'historicalExpired':False})
        for candidate in [{'collectedAt':value,'historicalExpired':False}for value in [350,50,250,float('nan'),float('inf'),float('-inf'),True]]:
            with patch.object(module.time,'time',return_value=300),self.assertRaisesRegex(ValueError,'SOURCE_REJECTED'):module.snapshot_collected_time(candidate,signed)

    def test_before_fallback_cannot_be_used_for_expected_or_bad_archive_authority(self):
        snapshot={'source':{'kind':'debian-snapshot','role':'before'}}
        with patch.object(module,'authenticated_before_snapshot')as fallback,self.assertRaisesRegex(ValueError,'ARCHIVE_UNREVIEWED'):module.acquire_runtime_debian_archive('libc6','2.41-12+deb13u4','amd64',snapshot,role='expected')
        fallback.assert_not_called()
        for role,error in [('expected','SYSTEM_SECURITY_BEFORE_INDEX_UNAVAILABLE'),('before','SYSTEM_SECURITY_ARCHIVE_UNREVIEWED'),('before','SYSTEM_SECURITY_UNTRUSTED_PATH')]:
            with patch.object(module,'authenticated_debian_archive',side_effect=ValueError(error)),patch.object(module,'authenticated_before_snapshot')as fallback,self.assertRaisesRegex(ValueError,error):module.acquire_runtime_debian_archive('libc6','2.41-12+deb13u4','amd64',role=role)
            fallback.assert_not_called()
        with patch.object(module,'authenticated_debian_archive',side_effect=ValueError('SYSTEM_SECURITY_BEFORE_INDEX_UNAVAILABLE')),patch.object(module,'authenticated_before_snapshot',return_value=('original',b'archive',{}))as fallback:
            self.assertEqual(module.acquire_runtime_debian_archive('libc6','2.41-12+deb13u4','amd64',role='before'),('original',b'archive',{}))
        fallback.assert_called_once()

    def test_signed_package_lookup_requires_exact_architecture_unique_hash_and_safe_filename(self):
        import lzma,hashlib
        body=b'Package: libc6\nVersion: 2.41-12+deb13u4\nArchitecture: amd64\nSHA256: '+b'a'*64+b'\nSize: 100\nFilename: pool/main/g/glibc/libc6_2.41-12+deb13u4_amd64.deb\n\n'
        record,filename=module.snapshot_package_record(lzma.compress(body),{},'libc6','2.41-12+deb13u4','amd64');self.assertEqual(record['sha256'],'a'*64);self.assertTrue(filename.endswith('.deb'))
        self.assertIsNone(module.snapshot_package_record(lzma.compress(body),{},'libc6','2.41-12+deb13u4','arm64'))
        for invalid in [body+body.replace(b'a'*64,b'b'*64),body.replace(b'pool/main/g/glibc/',b'pool/main/../../opt/'),body.replace(b'Size: 100',b'Size: 999999999999'),body.replace(b'Architecture: amd64',b'Architecture: amd64\nArchitecture: arm64')]:
            with self.assertRaisesRegex(ValueError,'SOURCE_REJECTED'):module.snapshot_package_record(lzma.compress(invalid),{},'libc6','2.41-12+deb13u4','amd64')

class RuntimePayload(unittest.TestCase):
    @staticmethod
    def fixture():
        journal=SystemdPolicy.journal();journal['phase']='installing'
        journal['baselinePackages']['nodejs:amd64']='24.22.2';journal['expectedPackages']['nodejs:amd64']='24.22.3';journal['packages'].append('nodejs=24.22.3')
        paths={};archives={}
        for number,(key,path)in enumerate([('libc6:amd64','/usr/lib/x86_64-linux-gnu/libc.so.6'),('libc-bin:amd64','/usr/sbin/ldconfig'),('nodejs:amd64','/usr/bin/node')],1):
            before={'type':'file','sha256':str(number)*64,'size':100,'mode':0o755,'uid':0,'gid':0};expected={**before,'sha256':str(number+3)*64}
            paths[path]={'owners':[key],'before':before,'expected':expected,'conffile':False}
            name,architecture=key.split(':');archives[key]={}
            for label in ['before','expected']:
                archives[key][label]={'package':name,'architecture':architecture,'version':journal['baselinePackages'if label=='before'else'expectedPackages'][key],'sha256':'f'*64,'size':100}
                archives[key][label+'Controls']={'control':'d'*64}
        value={'version':1,'planHash':module.runtime_payload_plan_hash(journal['baselinePackages'],journal['expectedPackages'],journal['packages']),'layout':{},'paths':paths,'archives':archives}
        return journal,value

    def test_mixed_node_payload_cannot_be_mistaken_for_an_unstarted_libc_transaction(self):
        journal,value=self.fixture();states={key:{'version':version,'status':'installed'}for key,version in journal['baselinePackages'].items()}
        actual={path:record['before']for path,record in value['paths'].items()}
        with patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_payload_actual',side_effect=lambda path,_:actual[path]),patch.object(module,'debian_package_states',return_value=states),patch.object(module,'command',return_value=''),patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'read_runtime_systemctl_policy',return_value={'actions':[],'rejected':False}):
            self.assertTrue(module.runtime_package_transaction_unstarted(journal))
            actual['/usr/bin/node']=value['paths']['/usr/bin/node']['expected']
            self.assertFalse(module.runtime_package_transaction_unstarted(journal),'a Node write before dpkg registration is part of the same original transaction')
            actual['/usr/bin/node']={**actual['/usr/bin/node'],'sha256':'a'*64}
            with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.runtime_package_transaction_unstarted(journal)
        with patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_payload_actual',side_effect=lambda path,_:value['paths'][path]['before']),patch.object(module,'debian_package_states',return_value=states),patch.object(module,'command',return_value=''),patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'read_runtime_systemctl_policy',return_value={'actions':[],'rejected':True}):
            self.assertFalse(module.runtime_package_transaction_unstarted(journal),'an unknown rejected call cannot be erased as an unstarted transaction')

    def test_expected_registration_with_original_node_bytes_reinstalls_the_original_authenticated_plan(self):
        import copy
        journal,value=self.fixture();original=copy.deepcopy(journal)
        actual={path:record['expected']for path,record in value['paths'].items()};actual['/usr/bin/node']=value['paths']['/usr/bin/node']['before']
        states={key:{'version':version,'status':'installed'}for key,version in journal['expectedPackages'].items()}
        def run(args,*_):return 'Inst nodejs [24.22.3] (24.22.3 fixture [amd64])'if '--simulate'in args else''
        def install(args,*_):
            self.assertIn('--reinstall',args);self.assertIn('--no-download',args);self.assertEqual(args[-1],'nodejs=24.22.3')
            actual['/usr/bin/node']=value['paths']['/usr/bin/node']['expected']
        with patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_payload_actual',side_effect=lambda path,_:actual[path]),patch.object(module,'acquire_runtime_debian_archive',side_effect=lambda name,version,architecture,record,**_:(record,b'',{'control':b'fixture'})),patch.object(module,'debian_package_states',return_value=states),patch.object(module,'debian_installed_packages',return_value=journal['expectedPackages']),patch.object(module,'prepare_service_policy'),patch.object(module,'clean_service_policy'),patch.object(module,'runtime_package_command',side_effect=install)as package,patch.object(module,'command',side_effect=run):
            # The fixture control SHA is an independently pinned original,
            # matching the archive adapter, rather than accepting fresh data.
            import hashlib
            for versions in value['archives'].values():
                for label in ['before','expected']:versions[label+'Controls']={'control':hashlib.sha256(b'fixture').hexdigest()}
            module.complete_runtime_package_transaction(journal)
        package.assert_called_once();self.assertEqual(journal,original)

    def test_preserved_admin_conffile_and_payload_authority_refuse_later_changes(self):
        import copy
        journal,value=self.fixture();path='/etc/runtime.conf';before={'type':'file','sha256':'a'*64,'size':20,'mode':0o600,'uid':0,'gid':0}
        value['paths'][path]={'owners':['nodejs:amd64'],'before':before,'expected':before,'conffile':True}
        actual={name:record['expected']for name,record in value['paths'].items()}
        with patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_payload_actual',side_effect=lambda name,_:actual[name]):
            self.assertTrue(module.verify_runtime_payload(journal,require='expected')['complete'])
            actual[path]={**before,'sha256':'b'*64}
            with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.verify_runtime_payload(journal)
        for delta in [{'expected':{**before,'sha256':'b'*64}},{'owners':['nodejs:amd64','nodejs:amd64']},{'before':{**before,'mode':0o666}},{'expected':{'type':'symlink','mode':0o777,'uid':0,'gid':0,'target':'/opt/incudal/.env'}}]:
            candidate=copy.deepcopy(value);candidate['paths'][path].update(delta)
            with patch.object(module,'read_runtime_payload',return_value=candidate),patch.object(module,'runtime_payload_actual',side_effect=lambda name,_:candidate['paths'][name]['before']),self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.verify_runtime_payload(journal)

    def test_only_an_original_conffile_vendor_transition_can_be_restored(self):
        import copy,hashlib
        journal,value=self.fixture();path='/etc/runtime.conf';before={'type':'file','sha256':'a'*64,'size':20,'mode':0o600,'uid':0,'gid':0};vendor={**before,'sha256':'b'*64}
        value['paths'][path]={'owners':['nodejs:amd64'],'before':before,'expected':before,'conffile':True,'vendorExpected':vendor,'beforeFile':hashlib.sha256(path.encode()).hexdigest()+'.before'}
        actual={name:record['expected']for name,record in value['paths'].items()};actual[path]=vendor
        states={key:{'version':version,'status':'installed'}for key,version in journal['expectedPackages'].items()}
        with patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_payload_actual',side_effect=lambda name,_:actual[name]),patch.object(module,'debian_package_states',return_value=states):
            result=module.verify_runtime_payload(journal);self.assertFalse(result['complete']);self.assertFalse(result['unchanged']);self.assertIn('nodejs:amd64',result['incomplete'])
            for requirement in ['before','expected']:
                with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.verify_runtime_payload(journal,require=requirement)
            actual[path]={**vendor,'sha256':'c'*64}
            with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.verify_runtime_payload(journal)
        for phase in ['prepared','stopping-backend','aborted','activated']:
            candidate={**journal,'phase':phase}
            with patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_payload_actual',side_effect=lambda name,_:vendor if name==path else actual[name]),self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.verify_runtime_payload(candidate)

    def test_deleted_original_conffile_stays_absent_and_new_registration_uses_vendor(self):
        journal,value=self.fixture();path='/etc/runtime.conf';vendor={'type':'file','sha256':'b'*64,'size':20,'mode':0o644,'uid':0,'gid':0}
        value['paths'][path]={'owners':['nodejs:amd64'],'before':{'type':'absent'},'expected':{'type':'absent'},'conffile':True,'vendorExpected':vendor,'beforeFile':None}
        actual={name:record['expected']for name,record in value['paths'].items()}
        with patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_payload_actual',side_effect=lambda name,_:actual[name]):self.assertTrue(module.verify_runtime_payload(journal,require='expected')['complete'])
        value['paths'][path]={'owners':['nodejs:amd64'],'before':{'type':'absent'},'expected':vendor,'conffile':True};actual[path]=vendor
        with patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_payload_actual',side_effect=lambda name,_:actual[name]):self.assertTrue(module.verify_runtime_payload(journal,require='expected')['complete'])

    def test_original_dpkg_conffile_registration_never_accepts_flags_or_duplicate_paths(self):
        original=' /etc/runtime.conf '+'a'*32+'\n'
        with patch.object(module,'command',return_value=original):self.assertEqual(module.runtime_dpkg_conffiles('fixture:amd64',{}),{'/etc/runtime.conf':{'md5':'a'*32,'flags':[]}})
        for output in [original+original,original.strip()+'\n',original.rstrip()+' obsolete\n',original.rstrip()+' remove-on-upgrade\n',original.replace('/etc/runtime.conf','/etc/../runtime.conf')]:
            with patch.object(module,'command',return_value=output),self.assertRaisesRegex(ValueError,'CONFFILE_MIGRATION_UNREVIEWED|PAYLOAD_UNCONFIRMED'):module.runtime_dpkg_conffiles('fixture:amd64',{})

    def test_formal_file_absence_needs_original_install_intent_and_never_counts_as_complete(self):
        journal,value=self.fixture();path='/usr/bin/node';actual={name:record['expected']for name,record in value['paths'].items()};actual[path]={'type':'absent'}
        states={key:{'version':version,'status':'installed'}for key,version in journal['expectedPackages'].items()}
        with patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_payload_actual',side_effect=lambda name,_:actual[name]),patch.object(module,'debian_package_states',return_value=states):
            result=module.verify_runtime_payload(journal);self.assertEqual(result['incomplete'],['nodejs:amd64']);self.assertFalse(result['complete']);self.assertFalse(result['unchanged'])
            for requirement in ['before','expected']:
                with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.verify_runtime_payload(journal,require=requirement)
            for phase in ['prepared','stopping-backend','aborted','activated']:
                with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.verify_runtime_payload({**journal,'phase':phase})
            actual[path]={**value['paths'][path]['expected'],'sha256':'a'*64}
            with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.verify_runtime_payload(journal)

    def test_node_authority_is_original_archive_bytes_and_missing_is_never_money_authority(self):
        import io,tarfile,hashlib,copy
        journal,value=self.fixture();journal['payloadEvidence']={'fixture':True};raw={};programs={}
        for label,version,data in [('before','24.22.2',b'original-node-before'),('expected','24.22.3',b'original-node-expected')]:
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w')as files:
                entry=tarfile.TarInfo('./usr/bin/node');entry.mode=0o755;entry.size=len(data);files.addfile(entry,io.BytesIO(data))
            control=b'Package: nodejs\nVersion: '+version.encode()+b'\nArchitecture: amd64\n'
            archive=DebianArchive.ar([('debian-binary',b'2.0\n'),('control.tar',DebianArchive.tar([('control',control)])),('data.tar',stream.getvalue())]);raw[version]=archive
            programs[label]=module.runtime_archive_payload(archive,{})['/usr/bin/node']
            source=value['archives']['nodejs:amd64'];source[label]={'package':'nodejs','architecture':'amd64','version':version,'sha256':hashlib.sha256(archive).hexdigest(),'size':len(archive)};source[label+'File']=label+'-nodejs-amd64.deb';source[label+'Controls']={'control':hashlib.sha256(control).hexdigest()}
            value['paths']['/usr/bin/node'][label]=programs[label]
        value['nodeAuthority']={'version':1,'package':'nodejs:amd64','before':programs['before'],'expected':programs['expected'],'consumer':None};actual=programs['before']
        def cached(_,record,file):
            archive=raw[record['version']];self.assertIn(file,['before-nodejs-amd64.deb','expected-nodejs-amd64.deb','authority-nodejs-amd64.deb']);return record,archive,module.debian_archive_members(archive)
        with patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_cached_archive',side_effect=cached),patch.object(module,'runtime_payload_actual',side_effect=lambda *_:actual),patch.object(module,'runtime_backend_program',return_value=programs['before']):
            module.verify_runtime_node_authority(journal,current={'pid':12},require='mixed')
            with self.assertRaisesRegex(ValueError,'NODE_AUTHORITY_UNCONFIRMED'):module.verify_runtime_node_authority(journal,require='expected')
            actual={'type':'absent'};self.assertTrue(module.verify_runtime_node_authority(journal,require='mixed',allow_missing=True)['missing'])
            with self.assertRaisesRegex(ValueError,'NODE_AUTHORITY_UNCONFIRMED'):module.verify_runtime_node_authority(journal,require='expected')
            for phase in ['prepared','aborted','activated']:
                with self.assertRaisesRegex(ValueError,'NODE_AUTHORITY_UNCONFIRMED'):module.verify_runtime_node_authority({**journal,'phase':phase},require='mixed',allow_missing=True)
            actual={**programs['expected'],'sha256':'a'*64}
            with self.assertRaisesRegex(ValueError,'NODE_AUTHORITY_UNCONFIRMED'):module.verify_runtime_node_authority(journal,require='mixed')
            actual=programs['expected'];module.verify_runtime_node_authority(journal,require='expected')
            value['nodeAuthority']['expected']={**programs['expected'],'sha256':'b'*64}
            with self.assertRaisesRegex(ValueError,'NODE_AUTHORITY_UNCONFIRMED'):module.verify_runtime_node_authority(journal,require='expected')

    def test_archive_payload_refuses_links_outside_package_roots_and_hardlinks(self):
        import io,tarfile
        def archive(name,kind,target=''):
            stream=io.BytesIO()
            with tarfile.open(fileobj=stream,mode='w')as files:
                entry=tarfile.TarInfo(name);entry.type=kind;entry.linkname=target;entry.mode=0o777 if kind==tarfile.SYMTYPE else 0o755;entry.size=0;files.addfile(entry,io.BytesIO(b'')if entry.isfile()else None)
            return DebianArchive.ar([('debian-binary',b'2.0\n'),('data.tar',stream.getvalue())])
        for name,kind,target in [('usr/bin/tool',tarfile.LNKTYPE,'usr/bin/other'),('usr/bin/tool',tarfile.SYMTYPE,'../../opt/incudal/.env'),('usr/bin/tool',tarfile.SYMTYPE,'/var/lib/postgresql/16/main'),('usr//bin/tool',tarfile.REGTYPE,''),('usr/bin/../tool',tarfile.REGTYPE,'')]:
            with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED|ARCHIVE_UNREVIEWED'):module.runtime_archive_payload(archive(name,kind,target),{})
        valid=module.runtime_archive_payload(archive('usr/bin/ld.so',tarfile.SYMTYPE,'../lib64/ld-linux-x86-64.so.2'),{})
        self.assertEqual(valid['/usr/bin/ld.so']['target'],'../lib64/ld-linux-x86-64.so.2')
        for root in ['.','./']:
            raw=DebianArchive.ar([('debian-binary',b'2.0\n'),('data.tar',DebianArchive.tar([(root,b'',tarfile.DIRTYPE),('./usr/bin/valid',b'vendor')]))])
            self.assertEqual(set(module.runtime_archive_payload(raw,{})),{'/usr/bin/valid'})
            with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED|ARCHIVE_UNREVIEWED'):module.runtime_archive_payload(archive(root,tarfile.REGTYPE),{})

@unittest.skipUnless(sys.platform=='linux'and hasattr(os,'geteuid')and os.geteuid()==0,'real root-owned ELF/file descriptors and procfs, no system changes')
class NativePayloadFiles(unittest.TestCase):
    @contextlib.contextmanager
    def client_file_fixture(self):
        # Product paths stay canonical. Only these three logical paths map to
        # private physical fixtures; parent/leaf metadata and FD reads remain
        # real, including the product's refusal of writable parent directories.
        real_path=pathlib.Path;real_open=os.open;real_lstat=os.lstat
        with tempfile.TemporaryDirectory(dir='/root')as directory:
            root=real_path(directory);folder=root/'usr/lib/postgresql/16/bin';folder.mkdir(mode=0o755,parents=True)
            logical=module.runtime_database_client_paths(16);physical={name:folder/name for name in logical}
            mapping={logical[name]:physical[name]for name in logical}
            for name,path in physical.items():path.write_bytes(('original '+name).encode());path.chmod(0o755)
            def mapped(value):return mapping.get(os.fspath(value),value)
            def fixture_path(*parts):
                key=str(pathlib.PurePosixPath(*[str(part)for part in parts]))
                return mapping[key]if key in mapping else real_path(*parts)
            with patch.object(module.pathlib,'Path',side_effect=fixture_path),patch.object(module.os,'open',side_effect=lambda value,*args,**kwargs:real_open(mapped(value),*args,**kwargs)),patch.object(module.os,'lstat',side_effect=lambda value,*args,**kwargs:real_lstat(mapped(value),*args,**kwargs)):
                yield root,folder,logical,physical

    def test_native_postgresql_clients_bind_original_files_and_refuse_missing_permissions_links_and_changes(self):
        import hashlib
        for kind in ['valid','missing','writable','setuid','not-executable','hardlink','symlink','fifo','parent-writable','changed']:
            with self.subTest(kind=kind),self.client_file_fixture()as(root,folder,logical,physical):
                target=physical['pg_dump']
                with patch.object(module,'command')as commands:
                    proof=module.runtime_database_client_files(16);database={'major':16,'clientTools':proof}
                    self.assertEqual(set(proof['files']),set(logical.values()));self.assertEqual(proof['files'][logical['pg_dump']]['sha256'],hashlib.sha256(b'original pg_dump').hexdigest())
                    if kind=='valid':self.assertEqual(module.verify_runtime_database_clients(database)[1],proof)
                    else:
                        if kind=='missing':target.unlink()
                        elif kind=='writable':target.chmod(0o775)
                        elif kind=='setuid':target.chmod(0o4755)
                        elif kind=='not-executable':target.chmod(0o644)
                        elif kind=='hardlink':os.link(target,folder/'second-link')
                        elif kind=='symlink':target.unlink();target.symlink_to(folder/'psql')
                        elif kind=='fifo':target.unlink();os.mkfifo(target)
                        elif kind=='parent-writable':folder.chmod(0o775)
                        else:target.write_bytes(b'changed unknown client')
                        with self.assertRaisesRegex(ValueError,'CLIENT_CHANGED'if kind=='changed'else'CLIENT_UNCONFIRMED'):module.verify_runtime_database_clients(database)
                    commands.assert_not_called()

    def test_native_postgresql_client_replacement_during_read_cannot_be_adopted(self):
        with self.client_file_fixture()as(root,folder,logical,physical):
            target=physical['psql'];replacement=root/'replacement';replacement.write_bytes(b'unknown replacement');replacement.chmod(0o755);read=os.read;changed=[False]
            def replace(fd,size):
                result=read(fd,size)
                if not changed[0]:changed[0]=True;os.replace(replacement,target)
                return result
            with patch.object(module.os,'read',side_effect=replace),self.assertRaisesRegex(ValueError,'CLIENT_UNCONFIRMED'):
                module.runtime_database_client_files(16)
            self.assertTrue(changed[0],'replacement must be injected after a real FD read');self.assertEqual(target.read_bytes(),b'unknown replacement');self.assertEqual(physical['pg_dump'].read_bytes(),b'original pg_dump')

    def test_native_fd_hash_supports_large_libc_and_refuses_permissions_links_and_special_files(self):
        import hashlib
        with tempfile.TemporaryDirectory()as directory:
            root=pathlib.Path(directory);path=root/'library';data=b'fixture-library'*100000;path.write_bytes(data);path.chmod(0o644)
            info=module.runtime_library_file(path);self.assertEqual(info['sha256'],hashlib.sha256(data).hexdigest());self.assertGreater(len(data),1024*1024)
            for mode in [0o664,0o666]:
                path.chmod(mode)
                with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.runtime_library_file(path)
            path.chmod(0o644);link=root/'hardlink';os.link(path,link)
            with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.runtime_library_file(path)
            link.unlink();link.symlink_to(path)
            with self.assertRaises(OSError):module.runtime_library_file(link)
            link.unlink();os.mkfifo(link)
            with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.runtime_library_file(link)
            link.unlink();path.write_bytes(b'')
            with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.runtime_library_file(path)
            with path.open('wb')as out:out.truncate(16*1024*1024+1)
            with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.runtime_library_file(path)

    def test_native_mapped_libc_identity_rejects_a_different_current_inode(self):
        import copy
        paths={}
        for line in pathlib.Path('/proc/self/maps').read_text().splitlines():
            fields=line.split(maxsplit=5)
            if len(fields)==6 and 'x'in fields[1]and pathlib.Path(fields[5]).name in ['libc.so.6','libm.so.6','ld-linux-x86-64.so.2','ld-linux-aarch64.so.1']:
                path=pathlib.Path(fields[5]).resolve();paths[str(path).removeprefix('/')]=module.runtime_library_file(path)
        self.assertIn('libc.so.6',{pathlib.Path(path).name for path in paths},'native acceptance requires a glibc Linux runtime')
        module.verify_runtime_libc_process(os.getpid(),paths)
        changed=copy.deepcopy(paths);next(iter(changed.values()))['inode']+=1
        with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.verify_runtime_libc_process(os.getpid(),changed)

@unittest.skipUnless(sys.platform=='linux'and hasattr(os,'geteuid')and os.geteuid()==0,'real private dump descriptors; temporary files only, no database or service mutation')
class NativeRuntimeDumps(unittest.TestCase):
    def test_real_private_dump_hash_rejects_permissions_links_and_invalid_headers(self):
        import hashlib
        with tempfile.TemporaryDirectory()as directory:
            root=pathlib.Path(directory);file=root/'original.dump';data=b'PGDMP'+b'bounded data'*100000;file.write_bytes(data);file.chmod(0o600)
            self.assertEqual(module.runtime_dump_evidence(file),{'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)})
            file.chmod(0o640)
            with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.runtime_dump_evidence(file)
            file.chmod(0o600);other=root/'hard';os.link(file,other)
            with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.runtime_dump_evidence(file)
            other.unlink();link=root/'link';link.symlink_to(file)
            with self.assertRaises(OSError):module.runtime_dump_evidence(link)
            file.write_bytes(b'PGDM')
            self.assertFalse(module.runtime_dump_material(file)['header'])
            with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.runtime_dump_evidence(file)


    def test_failed_boot_material_permissions_links_and_io_errors_never_authorize_recovery(self):
        import copy,hashlib,errno
        real_material=module.runtime_dump_material
        for case in ['permissions','hardlink','symlink','eacces','eio']:
            with self.subTest(case=case),RuntimeBootDumps.fixture(self)as(journal,recovery,backup,originals,saved,dumper,material):
                file=backup/('database-after-drain-boot-'+recovery['bootId']+'-1.dump');data=b'PGDMPowned failed bytes';file.write_bytes(data);file.chmod(0o600)
                recovery['dumpAttempts']=[{'file':file.name,'attempt':1,'state':'failed','failureCause':'pg-dump','sha256':hashlib.sha256(data).hexdigest(),'size':len(data)}];frozen=copy.deepcopy(journal);original_open=module.os.open
                if case=='permissions':file.chmod(0o640)
                elif case=='hardlink':os.link(file,backup/'retained-hardlink')
                elif case=='symlink':retained=backup/'retained.dump';file.rename(retained);file.symlink_to(retained)
                def opened(target,*values,**options):
                    if str(target)==str(file)and case in ['eacces','eio']:raise PermissionError(errno.EACCES,'fixture denied')if case=='eacces'else OSError(errno.EIO,'fixture unreadable')
                    return original_open(target,*values,**options)
                with patch.object(module,'runtime_dump_material',side_effect=real_material),patch.object(module.os,'open',side_effect=opened),patch.object(module,'command')as command,self.assertRaises((ValueError,OSError))as caught:module.runtime_boot_dump_materials(journal,recovery)
                self.assertNotIsInstance(caught.exception,module.RuntimeBootDumpExecutionFailed);self.assertEqual(journal,frozen);self.assertEqual(saved,[]);command.assert_not_called();dumper.assert_not_called()
                for name,raw in originals.items():self.assertEqual((backup/name).read_bytes(),raw)


    def test_real_dump_hash_rejects_an_inode_replacement_during_read(self):
        with tempfile.TemporaryDirectory()as directory:
            root=pathlib.Path(directory);file=root/'original.dump';data=b'PGDMP'+b'bounded data'*100000;file.write_bytes(data);file.chmod(0o600)
            original_read=os.read;changed=[False]
            def replaced(fd,size):
                block=original_read(fd,size)
                if not changed[0]:
                    changed[0]=True;replacement=root/'replacement';replacement.write_bytes(data);replacement.chmod(0o600);os.replace(replacement,file)
                return block
            with patch.object(module.os,'read',side_effect=replaced),self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.runtime_dump_evidence(file)
            self.assertEqual(file.read_bytes(),data)

    def test_bound_boot_dump_retention_preserves_changed_or_unknown_evidence(self):
        with RuntimeBootDumps.fixture(self)as(journal,recovery,backup,originals,saved,dumper,material):
            with patch.object(module,'command',return_value=''):module.runtime_new_boot_dump(journal,recovery)
            files,folders=module.runtime_backup_evidence(backup,journal)
            self.assertEqual({file.name for file in files},set(originals)|{recovery['dump']['file']});self.assertEqual(folders,[])
            unknown=backup/'operator-evidence';unknown.write_bytes(b'operator evidence');unknown.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'UNTRUSTED_PATH'):module.runtime_backup_evidence(backup,journal)
            self.assertEqual(unknown.read_bytes(),b'operator evidence')
            (backup/recovery['dump']['file']).write_bytes(b'PGDMPchanged backup')
            with self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.runtime_backup_evidence(backup,journal)
            self.assertTrue(unknown.exists())
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

@unittest.skipUnless(sys.platform=='linux'and hasattr(os,'geteuid')and os.geteuid()==0,'real dpkg in an isolated temporary root; no host package/service changes')
class NativeDpkgConffiles(unittest.TestCase):
    def test_six_real_dpkg_conffile_transitions_preserve_original_administrator_bytes(self):
        import hashlib,json,subprocess,stat
        original_path=pathlib.Path;original_write=module.write_runtime_maintenance
        name='runtime-conffile-qa';key=name+':all';virtual='/etc/'+name+'.conf'
        cases=[('unchanged',b'old default\n',b'old default\n',None),('vendor-changed',b'old default\n',b'new default\n',None),('custom',b'old default\n',b'new default\n',b'administrator config\n'),('deleted',b'old default\n',b'new default\n',False),('new',None,b'new default\n',None),('concurrent-admin',b'old default\n',b'new default\n',None)]
        for case,old,new,administrator in cases:
            with self.subTest(case=case),tempfile.TemporaryDirectory()as directory:
                folder=original_path(directory).resolve();system=folder/'system';system.mkdir(mode=0o700);(system/'etc').mkdir()
                security=folder/'security';security.mkdir(mode=0o700);backup=security/('runtime-backup-'+'a'*32);backup.mkdir(mode=0o700);(backup/'archives').mkdir(mode=0o700)
                def run(args):
                    result=subprocess.run(args,capture_output=True,text=True,timeout=30,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
                    self.assertEqual(result.returncode,0,'isolated dpkg stage failed: '+args[0]);return result.stdout.strip('\n')
                raw={}
                for label,version,content in [('before','1.0-1',old),('expected','1.0-2',new)]:
                    package=folder/label;package.mkdir(mode=0o755);package.chmod(0o755);control=package/'DEBIAN';control.mkdir(mode=0o755);control.chmod(0o755)
                    (control/'control').write_text('Package: '+name+'\nVersion: '+version+'\nArchitecture: all\nMaintainer: Isolated QA <qa@example.invalid>\nDescription: Temporary conffile acceptance\n')
                    (control/'control').chmod(0o644)
                    if content is not None:
                        (package/'etc').mkdir(mode=0o755);(package/'etc').chmod(0o755);(package/'etc'/original_path(virtual).name).write_bytes(content);(package/'etc'/original_path(virtual).name).chmod(0o644);(control/'conffiles').write_text(virtual+'\n');(control/'conffiles').chmod(0o644)
                    archive=folder/(label+'.deb');run(['dpkg-deb','-Zxz','--build','--root-owner-group',str(package),str(archive)]);raw[label]=archive.read_bytes()
                    module.write_runtime_evidence_file(backup/'archives'/(label+'-'+name+'-all.deb'),raw[label])
                run(['dpkg','--root='+str(system),'--force-confold','--install',str(folder/'before.deb')])
                target=system/virtual.removeprefix('/')
                if administrator is False:target.unlink()
                elif isinstance(administrator,bytes):target.write_bytes(administrator);target.chmod(0o600)
                before=module.runtime_payload_regular(target)if target.exists()else{'type':'absent'}
                if before['type']=='file':
                    (backup/'conffiles').mkdir(mode=0o700);module.write_runtime_evidence_file(backup/'conffiles'/(hashlib.sha256(virtual.encode()).hexdigest()+'.before'),target.read_bytes())
                run(['dpkg','--root='+str(system),'--force-confold','--install',str(folder/'expected.deb')])
                if case=='vendor-changed':self.assertEqual(target.read_bytes(),new,'real dpkg must exercise the changed unmodified default')
                vendor={'type':'file','sha256':hashlib.sha256(new).hexdigest(),'size':len(new),'mode':0o644,'uid':0,'gid':0}
                record={'owners':[key],'before':before,'expected':vendor if old is None else before,'conffile':True}
                if old is not None:record.update(vendorExpected=vendor,beforeFile=hashlib.sha256(virtual.encode()).hexdigest()+'.before'if before['type']=='file'else None)
                journal={'version':1,'phase':'installing','backup':backup.name,'packages':[name+'=1.0-2'],'baselinePackages':{key:'1.0-1'},'expectedPackages':{key:'1.0-2'}}
                archives={key:{}}
                for label,version,content in [('before','1.0-1',old),('expected','1.0-2',new)]:
                    archives[key][label]={'package':name,'version':version,'architecture':'all','sha256':hashlib.sha256(raw[label]).hexdigest(),'size':len(raw[label])}
                    archives[key][label+'File']=label+'-'+name+'-all.deb';controls=module.debian_archive_members(raw[label]);archives[key][label+'Controls']={part:hashlib.sha256(data).hexdigest()for part,data in controls.items()}
                    archives[key][label+'Conffiles']={}if content is None else{virtual:{'md5':hashlib.md5(content,usedforsecurity=False).hexdigest(),'flags':[]}}
                value={'version':1,'planHash':module.runtime_payload_plan_hash(journal['baselinePackages'],journal['expectedPackages'],journal['packages']),'layout':{},'paths':{virtual:record},'archives':archives}
                encoded=json.dumps(value,sort_keys=True,separators=(',',':')).encode();module.write_runtime_evidence_file(backup/'payload.json',encoded)
                journal['payloadEvidence']={'version':1,'file':'payload.json','planHash':value['planHash'],'sha256':hashlib.sha256(encoded).hexdigest(),'size':len(encoded)};original_write(journal,security)
                def route(*parts):
                    text=str(parts[0]);translated=security if text=='/var/lib/incudal-system-security'else system/text.removeprefix('/')if text=='/etc'or text.startswith('/etc/')else original_path(text)
                    return translated.joinpath(*parts[1:])
                def actual(path,_):
                    candidate=route(path)if str(path).startswith('/etc/')else original_path(path)
                    self.assertTrue(candidate.is_relative_to(system),'native acceptance must stay in its isolated root')
                    if not candidate.exists()and not candidate.is_symlink():return {'type':'absent'}
                    return module.runtime_payload_regular(candidate)
                def command(args,*_):
                    self.assertEqual(args[0],'dpkg-query','conffile verification cannot invoke a real host service or package mutation')
                    return run([args[0],'--admindir='+str(system/'var/lib/dpkg'),*args[1:]])
                states={key:{'version':'1.0-2','status':'installed'}}
                if case=='concurrent-admin':target.write_bytes(b'new administrator edit\n')
                with patch.object(module.pathlib,'Path',side_effect=route),patch.object(module,'read_runtime_payload',return_value=value),patch.object(module,'runtime_payload_actual',side_effect=actual),patch.object(module,'runtime_payload_parents',side_effect=lambda _:[(target.parent,target.parent.lstat())]),patch.object(module,'command',side_effect=command),patch.object(module,'debian_package_states',return_value=states),patch.object(module,'write_runtime_maintenance',side_effect=lambda current,*_,**__:original_write(current,security)):
                    if case=='concurrent-admin':
                        with self.assertRaisesRegex(ValueError,'PAYLOAD_UNCONFIRMED'):module.restore_runtime_conffiles(journal)
                        self.assertEqual(target.read_bytes(),b'new administrator edit\n');self.assertNotIn('conffileRestorations',journal)
                    else:
                        if case=='vendor-changed':
                            original_sync=os.fsync;failed=[False]
                            def interrupted_sync(fd):
                                path=original_path('/proc/self/fd',str(fd)).readlink()
                                if stat.S_ISREG(os.fstat(fd).st_mode)and '.incudal-restore-'in path.name and not failed[0]:
                                    failed[0]=True;raise OSError('isolated private conffile write interruption')
                                return original_sync(fd)
                            with patch.object(module.os,'fsync',side_effect=interrupted_sync),self.assertRaises(OSError):module.restore_runtime_conffiles(journal)
                            temporary=target.parent/journal['conffileRestorations'][virtual]['temporary'];self.assertEqual(stat.S_IMODE(temporary.stat().st_mode),0o600);temporary.write_bytes(old[:4])
                            original_replace=os.replace
                            for edge in ['before-rename','after-rename']:
                                def interrupted(source,destination,*args,**kwargs):
                                    if str(destination)==target.name:
                                        if edge=='after-rename':original_replace(source,destination,*args,**kwargs)
                                        raise OSError('isolated conffile interruption')
                                    return original_replace(source,destination,*args,**kwargs)
                                with patch.object(module.os,'replace',side_effect=interrupted),self.assertRaises(OSError):module.restore_runtime_conffiles(journal)
                                self.assertEqual(journal['conffileRestorations'][virtual]['phase'],'intent')
                        module.restore_runtime_conffiles(journal);self.assertTrue(module.verify_runtime_payload(journal,require='expected')['complete'])
                        module.restore_runtime_conffiles(journal)
                        self.assertEqual(actual(virtual,{})==record['expected'],True)
                        self.assertFalse(list(target.parent.glob('*.incudal-restore-*')))
                        if case=='vendor-changed':
                            failures=journal['conffileRestorationFailures'];self.assertEqual(len(failures),1);self.assertEqual((backup/'conffile-failures'/failures[0]['file']).read_bytes(),old[:4])
                self.assertEqual((backup/'payload.json').read_bytes(),encoded)
                for label in ['before','expected']:self.assertEqual((backup/'archives'/(label+'-'+name+'-all.deb')).read_bytes(),raw[label])

class DebianArchive(unittest.TestCase):
    @staticmethod
    def ar(entries):
        raw=b'!<arch>\n'
        for name,content in entries:
            raw+=(name+'/').encode().ljust(16)+b'0'.ljust(12)+b'0'.ljust(6)+b'0'.ljust(6)+b'100644'.ljust(8)+str(len(content)).encode().ljust(10)+b'`\n'+content+(b'\n'if len(content)%2 else b'')
        return raw
    @staticmethod
    def tar(entries):
        import io,tarfile
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w')as archive:
            for row in entries:
                name,content=row[:2];entry=tarfile.TarInfo(name);entry.size=len(content)
                if len(row)>2:entry.type=row[2];entry.linkname='/outside';entry.size=0
                archive.addfile(entry,io.BytesIO(content)if entry.isfile()else None)
        return data.getvalue()
    def test_archive_reads_only_authenticated_bytes_without_extracting_or_running(self):
        import bz2,gzip,lzma,hashlib
        controls=self.tar([('./control',b'Package: libc6\nVersion: 2.41-12+deb13u5\nArchitecture: amd64\n'),('./postinst',b'#!/bin/sh\nexit 0\n')])
        for suffix,compress in [('',lambda value:value),('.gz',gzip.compress),('.xz',lzma.compress),('.bz2',bz2.compress)]:
            archive=self.ar([('debian-binary',b'2.0\n'),('control.tar'+suffix,compress(controls))])
            result=module.debian_archive_members(archive)
            self.assertEqual(result['postinst'],b'#!/bin/sh\nexit 0\n');module.reviewed_maintainer_controls(result,{'postinst':hashlib.sha256(result['postinst']).hexdigest()})
            with self.assertRaisesRegex(ValueError,'TRIGGER_UNREVIEWED'):module.reviewed_maintainer_controls({**result,'config':b'unknown'}, {'postinst':hashlib.sha256(result['postinst']).hexdigest()})
    def test_archive_refuses_escape_duplicate_type_and_truncation(self):
        import tarfile
        valid=self.tar([('./control',b'x')])
        bad=[self.ar([('debian-binary',b'1.0\n'),('control.tar',valid)]),self.ar([('debian-binary',b'2.0\n'),('control.tar',valid),('control.tar.gz',valid)])]
        for name in ['../escape','/absolute','path\\escape','line\nbreak']:
            bad.append(self.ar([('debian-binary',b'2.0\n'),('control.tar',self.tar([(name,b'x')]))]))
        for entries in [[('./control',b'x'),('control',b'y')],[('postinst',b'',tarfile.SYMTYPE)],[('postinst',b'',tarfile.LNKTYPE)]]:
            bad.append(self.ar([('debian-binary',b'2.0\n'),('control.tar',self.tar(entries))]))
        original=self.ar([('debian-binary',b'2.0\n'),('control.tar',valid)]);bad.extend([original[:-1],original+b'x',b'unknown'])
        for raw in bad:
            with self.subTest(size=len(raw)),self.assertRaisesRegex(ValueError,'ARCHIVE_UNREVIEWED'):module.debian_archive_members(raw)
        ignored=self.ar([('debian-binary',b'2.0\n'),('data.tar',self.tar([('other',b'1'),('other',b'2'),('wanted',b'3')]))])
        with self.assertRaisesRegex(ValueError,'ARCHIVE_UNREVIEWED'):module.debian_archive_members(ignored,'data',{'wanted'})
    def test_archive_bounds_decompression_before_parsing_large_pax_headers(self):
        import gzip
        compressed=gzip.compress(b'x'*(8*1024*1024+1))
        with self.assertRaisesRegex(ValueError,'ARCHIVE_UNREVIEWED'):module.debian_archive_members(self.ar([('debian-binary',b'2.0\n'),('control.tar.gz',compressed)]))
        with self.assertRaisesRegex(ValueError,'ARCHIVE_UNREVIEWED'):module.debian_archive_members(self.ar([('debian-binary',b'2.0\n'),('control.tar.xz',b'not-xz')]))
    def test_apt_archive_requires_unique_sha_size_and_control_identity(self):
        import hashlib,stat
        raw=self.ar([('debian-binary',b'2.0\n'),('control.tar',self.tar([('control',b'Package: libc6\nVersion: 2.41-12+deb13u5\nArchitecture: amd64\n')]))]);digest=hashlib.sha256(raw).hexdigest()
        metadata='Package: libc6\nVersion: 2.41-12+deb13u5\nArchitecture: amd64\nSHA256: '+digest+'\nSize: '+str(len(raw))+'\n'
        file=types.SimpleNamespace(lstat=lambda:types.SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_uid=0,st_nlink=1,st_size=len(raw)),read_bytes=lambda:raw)
        cache=lambda files:types.SimpleNamespace(is_symlink=lambda:False,stat=lambda:types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o755),glob=lambda _:files)
        with patch.object(module,'command',return_value=metadata),patch.object(module.pathlib,'Path',return_value=cache([file])),patch.object(module,'runtime_payload_regular',return_value={'sha256':digest,'size':len(raw),'content':raw}):
            record,body,_=module.authenticated_debian_archive('libc6','2.41-12+deb13u5','amd64');self.assertEqual(record['sha256'],digest);self.assertEqual(body,raw)
        for output,files,error in [(metadata,[],'NOT_CACHED'),(metadata,[file,file],'UNREVIEWED'),(metadata+'SHA256: '+digest+'\n',[file],'UNREVIEWED'),(metadata+'\n'+metadata.replace(digest,'0'*64),[file],'UNREVIEWED')]:
            with patch.object(module,'command',return_value=output),patch.object(module.pathlib,'Path',return_value=cache(files)),patch.object(module,'runtime_payload_regular',return_value={'sha256':digest,'size':len(raw),'content':raw}),self.assertRaisesRegex(ValueError,error):module.authenticated_debian_archive('libc6','2.41-12+deb13u5','amd64')

@unittest.skipUnless(hasattr(os,'geteuid')and os.geteuid()==0,'Linux root, strictly tempfile-only policy evidence and locks')
class NativeSystemdPolicy(unittest.TestCase):
    def setUp(self):
        # Wrapper/lock tests use OS proof adapters; actual payload IO and the
        # full mixed-plan guard have their own native and planner regressions.
        self.enterContext(patch.object(module,'verify_runtime_payload',return_value={'unchanged':True,'complete':True,'incomplete':[]}))
        self.enterContext(patch.object(module,'verify_runtime_node_authority'))
    @contextlib.contextmanager
    def policy_fixture(self,prepare=True):
        # Adapt only the private path/boot constants in an otherwise identical
        # wrapper. Never touch /var, real APT locks, or forward to systemctl.
        import hashlib
        original_path=pathlib.Path;original_write=module.write_runtime_maintenance;original_open=os.open;original_recover=module.recover_runtime_maintenance
        with tempfile.TemporaryDirectory()as directory:
            folder=original_path(directory).resolve();security=folder/'security';security.mkdir(mode=0o700)
            boot=folder/'boot-id';boot.write_text('fixture-boot')
            locks=[folder/'dpkg.lock',folder/'dpkg-frontend.lock']
            for lock in locks:lock.write_text('');lock.chmod(0o600)
            mapping={'/var/lib/incudal-system-security':security,'/var/lib/dpkg/lock':locks[0],'/var/lib/dpkg/lock-frontend':locks[1],'/proc/sys/kernel/random/boot_id':boot}
            def fixture_path(*parts):return mapping.get(parts[0],original_path(parts[0])).joinpath(*parts[1:])
            def fixture_open(path,*args,**kwargs):return original_open(mapping.get(str(path),path),*args,**kwargs)
            def fixture_recover(path=None):
                # Python constructs default Path arguments at module import,
                # before our constructor adapter exists. Relocate only that
                # original default; run the complete original recovery body.
                if path is None or str(path).replace('\\','/')=='/var/lib/incudal-system-security/runtime-maintenance.json':path=security/'runtime-maintenance.json'
                return original_recover(path)
            wrapper=module.RUNTIME_SYSTEMCTL_WRAPPER.replace("pathlib.Path('/var/lib/incudal-system-security')",'pathlib.Path('+repr(str(security))+')').replace("pathlib.Path('/proc/sys/kernel/random/boot_id')",'pathlib.Path('+repr(str(boot))+')')
            journal=SystemdPolicy.journal();journal['phase']='prepared';proof=journal['systemdPolicy'];proof.pop('ready');proof['sourceHash']=hashlib.sha256(wrapper.encode()).hexdigest()
            original_write(journal,security)
            with patch.object(module,'RUNTIME_SYSTEMCTL_WRAPPER',wrapper),patch.object(module.pathlib,'Path',side_effect=fixture_path),patch.object(module.os,'open',side_effect=fixture_open),patch.object(module,'write_runtime_maintenance',side_effect=lambda value,*_,**__:original_write(value,security)),patch.object(module,'recover_runtime_maintenance',side_effect=fixture_recover)as recover:
                if prepare:
                    module.ensure_runtime_systemctl_policy(journal)
                    journal['phase']='installing';journal['drainConfirmed']=True;original_write(journal,security)
                yield {'folder':folder,'security':security,'journal':journal,'source':security/proof['directory']/'systemctl','locks':locks,'path':fixture_path,'write':original_write,'recover':recover}

    def run_wrapper(self,source,args):
        import subprocess
        return subprocess.run([sys.executable,'-I','-B',str(source),*args],capture_output=True,text=True,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})

    def test_policy_directory_entries_are_synced_before_ready_is_durable(self):
        import stat
        synced=[];original_sync=os.fsync;original_write=module.write_runtime_maintenance
        def sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):synced.append(str(pathlib.Path('/proc/self/fd',str(fd)).readlink()))
            return original_sync(fd)
        def write(value,*args,**kwargs):
            proof=value.get('systemdPolicy',{})
            if proof.get('ready'):self.assertTrue(any(path.endswith('/'+proof['directory'])for path in synced),'private policy directory must be durable before ready is committed')
            return original_write(value,*args,**kwargs)
        with patch.object(module.os,'fsync',side_effect=sync),patch.object(module,'write_runtime_maintenance',side_effect=write),self.policy_fixture()as fixture:
            self.assertTrue(fixture['journal']['systemdPolicy']['ready']);self.assertTrue(synced)

    def test_unready_fixed_prefixes_resume_with_original_failed_bytes_and_durable_ready(self):
        import json,stat
        with self.policy_fixture(prepare=False)as fixture:
            journal=fixture['journal'];proof=journal['systemdPolicy'];token=proof['token'];digest=proof['sourceHash'];root=fixture['source'].parent
            backup=fixture['security']/('runtime-backup-'+'f'*32);backup.mkdir(mode=0o700);journal['backup']=backup.name;fixture['write'](journal,fixture['security'])
            expected=module.runtime_systemctl_preparation_files(proof);root.mkdir(mode=0o700)
            prefixes={'systemctl':expected['systemctl'][0][:137],'policy.json':expected['policy.json'][0][:31]}
            for name,data in prefixes.items():(root/name).write_bytes(data);(root/name).chmod(0o644 if name=='systemctl'else 0o600)
            (root/'policy.lock').write_bytes(b'');(root/'policy.lock').chmod(0o600)
            original_write=os.write;partial=[False]
            def interrupted(fd,data):
                if '/policy-failures/'in os.readlink('/proc/self/fd/'+str(fd)):
                    if partial[0]:raise OSError('private evidence copy interrupted')
                    partial[0]=True;return original_write(fd,data[:7])
                return original_write(fd,data)
            with patch.object(module.os,'write',side_effect=interrupted),self.assertRaises(OSError):module.ensure_runtime_systemctl_policy(journal)
            self.assertNotIn('ready',proof);self.assertEqual((root/'systemctl').read_bytes(),prefixes['systemctl'])
            first=journal['policyPreparationFailures'][0];stored=backup/'policy-failures'/first['file'];inode=stored.stat().st_ino;self.assertEqual(stored.read_bytes(),prefixes['systemctl'][:7])
            synced=[];sync=os.fsync;write=module.write_runtime_maintenance
            def fsync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):synced.append(os.readlink('/proc/self/fd/'+str(fd)))
                return sync(fd)
            def durable(value,*args,**kwargs):
                if value['systemdPolicy'].get('ready'):self.assertIn(str(root),synced)
                return write(value,*args,**kwargs)
            with patch.object(module.os,'fsync',side_effect=fsync),patch.object(module,'write_runtime_maintenance',side_effect=durable),patch.object(module,'command')as command:module.ensure_runtime_systemctl_policy(journal)
            command.assert_not_called();self.assertTrue(proof['ready']);self.assertEqual(proof['token'],token);self.assertEqual(proof['sourceHash'],digest);self.assertEqual(stored.stat().st_ino,inode)
            self.assertEqual(len(journal['policyPreparationFailures']),2)
            for name,(data,mode)in expected.items():self.assertEqual((root/name).read_bytes(),data);self.assertEqual(stat.S_IMODE((root/name).stat().st_mode),mode)
            for failure in journal['policyPreparationFailures']:self.assertEqual((backup/'policy-failures'/failure['file']).read_bytes(),prefixes[failure['name']])
            persisted=json.loads((fixture['security']/'runtime-maintenance.json').read_bytes());self.assertEqual(persisted,journal)
            module.runtime_backup_evidence(backup,journal);self.assertEqual(module.read_runtime_systemctl_policy(proof)['actions'],[])

    def test_ready_flag_removed_cannot_reset_a_recorded_action_rejection_or_third_content(self):
        for kind in ['action','rejected','third']:
            with self.policy_fixture()as fixture:
                journal=fixture['journal'];proof=journal['systemdPolicy'];record=fixture['source'].parent/'policy.json'
                if kind=='action':self.assertEqual(self.run_wrapper(fixture['source'],['daemon-reexec']).returncode,0)
                elif kind=='rejected':self.assertEqual(self.run_wrapper(fixture['source'],['unknown-fixed-fixture']).returncode,125)
                else:record.write_bytes(b'changed private receipt')
                original=record.read_bytes();proof['ready']=False;journal['phase']='prepared';fixture['write'](journal,fixture['security'])
                with patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):module.ensure_runtime_systemctl_policy(journal)
                command.assert_not_called();self.assertEqual(record.read_bytes(),original);self.assertFalse(proof['ready']);self.assertNotIn('policyPreparationFailures',journal)

    def test_past_unready_boot_prefixes_are_preserved_without_reissuing_or_readying_the_old_nonce(self):
        import copy
        with self.policy_fixture()as fixture:
            journal=fixture['journal'];original=journal['systemdPolicy'];boot=fixture['folder']/'boot-id';original['bootId']='11111111-1111-4111-8111-111111111111';boot.write_text(original['bootId'])
            backup=fixture['security']/('runtime-backup-'+'f'*32);backup.mkdir(mode=0o700);journal['backup']=backup.name;fixture['write'](journal,fixture['security']);frozen=copy.deepcopy(original)
            with patch.object(module,'verify_runtime_systemd_package_authority'),patch.object(module,'runtime_systemd_qualification',return_value=original['qualification']),patch.object(module.uuid,'uuid4',side_effect=[types.SimpleNamespace(hex='a'*32),types.SimpleNamespace(hex='b'*32)]):
                boot.write_text('22222222-2222-4222-8222-222222222222');old=module.prepare_runtime_systemd_boot_policy(journal);root=fixture['security']/old['directory'];root.mkdir(mode=0o700)
                data=module.runtime_systemctl_preparation_files(old)['policy.json'][0];(root/'policy.json').write_bytes(data[:19]);(root/'policy.json').chmod(0o600)
                boot.write_text('33333333-3333-4333-8333-333333333333');fresh=module.prepare_runtime_systemd_boot_policy(journal)
            self.assertEqual(old['token'],'a'*32);self.assertEqual(old['ordinal'],1);self.assertNotIn('ready',old);self.assertEqual(fresh['token'],'b'*32);self.assertEqual(fresh['ordinal'],2)
            self.assertEqual(journal['systemdPolicy'],frozen);self.assertEqual((root/'policy.json').read_bytes(),data);self.assertEqual(len(journal['policyPreparationFailures']),1)
            failure=journal['policyPreparationFailures'][0];self.assertEqual((backup/'policy-failures'/failure['file']).read_bytes(),data[:19]);module.runtime_systemd_policy_history(old)

    def test_real_wrapper_defers_four_actions_and_preserves_unknown_rejection(self):
        import json,subprocess
        with self.policy_fixture()as fixture:
            journal=fixture['journal'];proof=journal['systemdPolicy'];source=fixture['source'];before=os.environ.get('PATH')
            for args in module.RUNTIME_SYSTEMCTL_ACTIONS:self.assertEqual(self.run_wrapper(source,args).returncode,0)
            value=module.read_runtime_systemctl_policy(proof);self.assertEqual(set(value['actions']),set(module.RUNTIME_SYSTEMCTL_ACTIONS.values()));self.assertFalse(value['rejected']);self.assertEqual(os.environ.get('PATH'),before)
            secret='unrecognized-fixture-only-value'
            swallowed=subprocess.run(['/bin/sh','-c','"$1" "$2" || true','fixture',str(source),secret],capture_output=True,text=True,timeout=10,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            self.assertEqual(swallowed.returncode,0)
            record=source.parent/'policy.json';contents=record.read_text();self.assertTrue(json.loads(contents)['rejected']);self.assertNotIn(secret,contents+swallowed.stdout+swallowed.stderr)
            with self.assertRaisesRegex(ValueError,'POLICY_REJECTED'):module.read_runtime_systemctl_policy(proof)
            with self.assertRaisesRegex(ValueError,'POLICY_REJECTED'):module.ensure_runtime_systemctl_policy(journal)
            self.assertEqual(record.read_text(),contents)
            self.assertEqual(self.run_wrapper(source,['daemon-reexec']).returncode,0);self.assertTrue(json.loads(record.read_text())['rejected'])

    def test_real_wrapper_rejects_changed_nonce_without_overwriting_original_actions(self):
        import copy
        with self.policy_fixture()as fixture:
            journal=fixture['journal'];source=fixture['source'];record=source.parent/'policy.json'
            self.assertEqual(self.run_wrapper(source,['daemon-reexec']).returncode,0);original=record.read_bytes()
            changed=copy.deepcopy(journal);changed['systemdPolicy']['token']='0'*32;fixture['write'](changed,fixture['security'])
            result=self.run_wrapper(source,['try-restart','systemd-journald.service']);self.assertEqual(result.returncode,125);self.assertEqual(record.read_bytes(),original)
            fixture['write'](journal,fixture['security']);module.ensure_runtime_systemctl_policy(journal)
            self.assertEqual(record.read_bytes(),original)

    def test_new_boot_nonce_cannot_use_the_old_wrapper_or_bypass_a_later_old_rejection(self):
        import copy,json
        with self.policy_fixture()as fixture:
            journal=fixture['journal'];original=journal['systemdPolicy'];boot=fixture['folder']/'boot-id'
            original['bootId']='11111111-1111-4111-8111-111111111111';boot.write_text(original['bootId']);fixture['write'](journal,fixture['security'])
            self.assertEqual(self.run_wrapper(fixture['source'],['daemon-reexec']).returncode,0)
            old_record=fixture['source'].parent/'policy.json';old_bytes=old_record.read_bytes();frozen=copy.deepcopy(original)
            new_boot='22222222-2222-4222-8222-222222222222';boot.write_text(new_boot)
            with patch.object(module,'verify_runtime_systemd_package_authority'),patch.object(module,'runtime_systemd_qualification',return_value=original['qualification']),patch.object(module.uuid,'uuid4',return_value=types.SimpleNamespace(hex='a'*32)):
                derived=module.prepare_runtime_systemd_boot_policy(journal)
            journal['bootRecoveries']={new_boot:{'version':1,'bootId':new_boot,'token':derived['token'],'drainConfirmed':True,'dumpPending':False,'dump':{'file':'private-wrapper-proof-fixture','sha256':'f'*64,'size':12}}}
            fixture['write'](journal,fixture['security']);module.ensure_runtime_systemctl_policy(journal)
            source=fixture['security']/derived['directory']/'systemctl'
            self.assertNotEqual(derived['token'],original['token']);self.assertEqual(journal['systemdPolicy'],frozen)
            self.assertEqual(self.run_wrapper(fixture['source'],['daemon-reexec']).returncode,125);self.assertEqual(old_record.read_bytes(),old_bytes)
            self.assertEqual(self.run_wrapper(source,['daemon-reexec']).returncode,0)
            current_record=source.parent/'policy.json';current_bytes=current_record.read_bytes()
            for ordinal in [True,1.0,'1']:
                changed=copy.deepcopy(journal);changed['systemdBootPolicies'][0]['ordinal']=ordinal;fixture['write'](changed,fixture['security'])
                self.assertEqual(self.run_wrapper(source,['daemon-reexec']).returncode,125);self.assertEqual(current_record.read_bytes(),current_bytes)
            fixture['write'](journal,fixture['security'])
            old_value=json.loads(old_bytes);old_value['rejected']=True;old_record.write_bytes(json.dumps(old_value).encode())
            result=self.run_wrapper(source,['try-restart','systemd-journald.service'])
            self.assertEqual(result.returncode,125);self.assertEqual(current_record.read_bytes(),current_bytes);self.assertIn('SYSTEM_SECURITY_SYSTEMD_POLICY_REJECTED',result.stderr)
            with self.assertRaisesRegex(ValueError,'POLICY_REJECTED'):module.prepare_runtime_systemd_boot_policy(journal)
            self.assertTrue(json.loads(old_record.read_bytes())['rejected']);self.assertEqual(journal['systemdPolicy'],frozen)

    def test_lost_execution_permission_or_ready_receipt_never_falls_through_to_real_systemctl(self):
        with self.policy_fixture()as fixture:
            source=fixture['source'];journal=fixture['journal'];source.chmod(0o644)
            with patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):module.runtime_package_command(['dpkg','--configure','libc6'],journal,10)
            command.assert_not_called();source.chmod(0o755)
            (source.parent/'policy.json').unlink()
            with self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):module.ensure_runtime_systemctl_policy(journal)
            self.assertFalse((source.parent/'policy.json').exists(),'a ready nonce must not recreate erased reject/defer evidence')

    def test_real_posix_lock_keeps_policy_until_package_process_finishes(self):
        import subprocess
        with self.policy_fixture()as fixture:
            for args in module.RUNTIME_SYSTEMCTL_ACTIONS:self.assertEqual(self.run_wrapper(fixture['source'],args).returncode,0)
            helper=subprocess.Popen([sys.executable,'-I','-B','-c',"import fcntl,sys; f=open(sys.argv[1],'r+'); fcntl.lockf(f,fcntl.LOCK_EX); print('locked',flush=True); sys.stdin.readline()",str(fixture['locks'][0])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                self.assertEqual(helper.stdout.readline().strip(),'locked')
                with self.assertRaisesRegex(ValueError,'PACKAGE_OPERATION_PENDING'):module.finish_runtime_systemctl_policy(fixture['journal'])
                self.assertTrue(fixture['source'].exists());self.assertNotIn('cleared',fixture['journal']['systemdPolicy'])
            finally:helper.communicate(input='release\n',timeout=10)
            self.assertEqual(helper.returncode,0);module.finish_runtime_systemctl_policy(fixture['journal']);self.assertFalse(fixture['source'].parent.exists())

    def test_cleanup_interruption_resumes_only_the_exact_original_files(self):
        import json
        with self.policy_fixture()as fixture:
            for args in module.RUNTIME_SYSTEMCTL_ACTIONS:self.assertEqual(self.run_wrapper(fixture['source'],args).returncode,0)
            record=fixture['source'].parent/'policy.json';original_unlink=type(record).unlink
            def interrupted(path,*args,**kwargs):
                if path==record:raise OSError('fixture interruption')
                return original_unlink(path,*args,**kwargs)
            with patch.object(type(record),'unlink',interrupted),self.assertRaises(OSError):module.finish_runtime_systemctl_policy(fixture['journal'])
            self.assertFalse(fixture['source'].exists());self.assertTrue(record.exists())
            resumed=json.loads((fixture['security']/'runtime-maintenance.json').read_text());self.assertTrue(resumed['systemdPolicy']['cleared'])
            original=record.read_text();record.write_text(original+' ')
            with self.assertRaisesRegex(ValueError,'POLICY_UNREVIEWED'):module.finish_runtime_systemctl_policy(resumed)
            self.assertTrue(record.exists());record.write_text(original)
            module.finish_runtime_systemctl_policy(resumed);self.assertFalse(record.parent.exists())

    def test_prepared_recovery_cleans_same_nonce_without_any_service_or_package_operation(self):
        with self.policy_fixture()as fixture:
            journal=fixture['journal'];journal['phase']='prepared';fixture['write'](journal,fixture['security'])
            with patch.object(module,'command')as command:
                self.assertIsNone(module.recover_runtime_maintenance(fixture['security']/'runtime-maintenance.json'))
            command.assert_not_called();self.assertFalse(fixture['source'].parent.exists())

    def test_activated_journal_lost_completion_reply_only_resumes_original_evidence_publication(self):
        import json
        with self.policy_fixture()as fixture:
            journal=fixture['journal'];security=fixture['security'];path=security/'runtime-maintenance.json'
            for args in module.RUNTIME_SYSTEMCTL_ACTIONS:self.assertEqual(self.run_wrapper(fixture['source'],args).returncode,0)
            module.finish_runtime_systemctl_policy(journal)
            backup=security/('runtime-backup-'+'f'*32);backup.mkdir(mode=0o700);journal.update(phase='activated',backup=backup.name)
            originals={'database.dump':b'PGDMPoriginal live','database-after-drain.dump':b'PGDMPoriginal drained'}
            for name,data in originals.items():(backup/name).write_bytes(data);(backup/name).chmod(0o600)
            journal['dumpEvidence']={name:module.runtime_dump_evidence(backup/name)for name in originals};fixture['write'](journal,security)
            before=path.read_bytes();replace=module.os.replace
            def interrupted(source,target):
                if str(target)==str(backup/'completed.json'):raise OSError('private completion interrupted')
                return replace(source,target)
            with patch.object(module,'command')as command,patch.object(module.os,'replace',side_effect=interrupted),self.assertRaises(OSError):module.recover_runtime_maintenance(path)
            command.assert_not_called();self.assertEqual(path.read_bytes(),before);self.assertFalse((backup/'completed.json').exists())
            with patch.object(module,'command')as command:self.assertIsNone(module.recover_runtime_maintenance(path))
            command.assert_not_called();completed=backup/'completed.json';self.assertEqual(json.loads(completed.read_bytes()),journal);timestamp=completed.stat().st_mtime_ns
            with patch.object(module,'command')as command:self.assertIsNone(module.recover_runtime_maintenance(path))
            command.assert_not_called();self.assertEqual(completed.stat().st_mtime_ns,timestamp)
            changed={**journal,'phase':'operator evidence'};completed.write_text(json.dumps(changed));changed_bytes=completed.read_bytes()
            with patch.object(module,'command')as command,self.assertRaisesRegex(ValueError,'BACKUP_FAILED'):module.recover_runtime_maintenance(path)
            command.assert_not_called();self.assertEqual(completed.read_bytes(),changed_bytes);self.assertEqual(path.read_bytes(),before)
            for name,data in originals.items():self.assertEqual((backup/name).read_bytes(),data)

    def test_systemd_failure_restores_proven_business_and_keeps_pending_evidence(self):
        import json
        with self.policy_fixture()as fixture:
            journal=fixture['journal'];source=fixture['source'];policy_path=fixture['security']/'runtime-maintenance.json'
            backend={'pid':12,'start':'123','app':'/opt/incudal','environmentHash':'a'*64,'codeHash':'b'*64,'serviceHash':'c'*64,'unitHashes':{'/etc/systemd/system/incudal-backend.service':'d'*64}}
            database={'pid':33,'major':16,'unit':'postgresql@16-main.service','data':'/var/lib/postgresql/16/main','config':'/etc/postgresql/16/main/postgresql.conf','hba':'/etc/postgresql/16/main/pg_hba.conf','configHash':'e'*64,'hbaHash':'f'*64,'unitHash':'a'*64,'fileHashes':{'/etc/postgresql/16/main/postgresql.conf':'e'*64}}
            journal.update(backend=backend,database=database,drainConfirmed=True)
            hashes={'/opt/incudal/.env':'a'*64,'/opt/incudal/server/dist/app.js':'b'*64,**backend['unitHashes'],database['config']:database['configHash'],database['hba']:database['hbaHash'],'/usr/lib/systemd/system/postgresql@.service':database['unitHash']}
            class App:
                def __str__(self):return '/opt/incudal'
                def resolve(self):return self
                def __truediv__(self,part):return fixture['path']('/opt/incudal/'+part)
            def path(*parts):
                if parts==('/opt/incudal',):return App()
                if parts in [('/usr/bin/node',),('/proc','12','exe')]:return types.SimpleNamespace(stat=lambda:types.SimpleNamespace(st_dev=1,st_ino=2))
                if parts==(database['data'],):return types.SimpleNamespace(stat=lambda:types.SimpleNamespace(st_uid=0))
                return fixture['path'](*parts)
            def run(args,*_):
                if '--property=FragmentPath'in args:return '/usr/lib/systemd/system/postgresql@.service'
                if '--property=Result'in args:return 'success'
                return ''
            errors=['SYSTEM_SECURITY_SYSTEMD_POLICY_REJECTED','SYSTEM_SECURITY_SYSTEMD_TRIGGER_NOT_CONFIRMED','SYSTEM_SECURITY_SYSTEMD_ACTIVATION_PENDING','SYSTEM_SECURITY_PACKAGE_OPERATION_PENDING','SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED']
            for error in errors:
                journal['phase']='installed';journal.pop('serviceRecovery',None);fixture['write'](journal,fixture['security'])
                with patch.object(module.pathlib,'Path',side_effect=path),patch.object(module,'protected_hash',side_effect=lambda value,*_,**__:hashes.get(str(value),'fixture journal')),patch.object(module,'backend_service_policy',return_value=({},App(),backend['unitHashes'],backend['serviceHash'])),patch.object(module,'clean_service_policy'),patch.object(module,'complete_runtime_package_transaction')as package,patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'finish_runtime_systemctl_policy',side_effect=ValueError(error)),patch.object(module,'activate_runtime_systemd')as activation,patch.object(module,'command',side_effect=run)as command,patch.object(module,'verify_runtime_health'),patch.object(module,'backend_runtime_proof',return_value=backend),patch.object(module,'database_runtime_proof',return_value=database),patch.object(module,'runtime_process_has_replaced_libraries',return_value=False),patch.object(module,'verify_database_activation'),patch.object(module,'verify_runtime_financial_integrity')as finance,patch.object(module,'archive_runtime_receipt')as receipt,self.assertRaisesRegex(ValueError,error):module.recover_runtime_maintenance(policy_path)
                package.assert_called_once();activation.assert_not_called();receipt.assert_not_called()
                starts=[call.args[0]for call in command.call_args_list if call.args[0][1]=='start']
                value=json.loads(policy_path.read_text());self.assertEqual(value['phase'],'installed');self.assertTrue(source.exists(),'rejected policy evidence is retained')
                if error in errors[:3]:
                    self.assertEqual(starts,[['systemctl','start',database['unit']],['systemctl','start','incudal-backend.service']]);finance.assert_called_once()
                    self.assertEqual(value['serviceRecovery']['backendPID'],12);self.assertEqual(value['serviceRecovery']['databasePID'],33);self.assertEqual(value['systemdPolicy']['activation']['error'],error)
                else:self.assertEqual(starts,[]);finance.assert_not_called();self.assertNotIn('serviceRecovery',value)

    def test_actual_install_preflight_or_spawn_failure_restores_original_runtime_without_retrying_apt(self):
        # Run real install -> runtime_package_command -> finally recovery.
        # Only OS I/O/proof adapters are mocked; complete transaction and phase
        # decisions stay real. All files and locks belong to this tempfile.
        import copy,json
        for failure in ['user-manager','network-state','manager-identity','command-spawn']:
            with self.policy_fixture()as fixture:
                expected_error={'user-manager':'SYSTEM_SECURITY_SYSTEMD_USER_MANAGERS_ACTIVE','network-state':'SYSTEM_SECURITY_SYSTEMD_CONFIGURATION_CHANGED','manager-identity':'SYSTEM_SECURITY_SYSTEMD_PROCESS_CHANGED','command-spawn':'SYSTEM_SECURITY_QUERY_FAILED'}[failure]
                before=fixture['journal'];proof=before['systemdPolicy'];baseline={**before['baselinePackages'],'nodejs:amd64':'24.22.3','postgresql-16:amd64':'16.16'};expected={**before['expectedPackages'],'nodejs:amd64':'24.22.3','postgresql-16:amd64':'16.16'}
                original_protected=module.protected_hash
                states={key:{'version':value,'status':'installed'}for key,value in baseline.items()}
                backend={'pid':12,'start':'123','app':'/opt/incudal','environmentHash':'a'*64,'codeHash':'b'*64,'serviceHash':'c'*64,'unitHashes':{'/etc/systemd/system/incudal-backend.service':'d'*64}}
                database={'pid':33,'major':16,'unit':'postgresql@16-main.service','data':'/var/lib/postgresql/16/main','config':'/etc/postgresql/16/main/postgresql.conf','hba':'/etc/postgresql/16/main/pg_hba.conf','configHash':'e'*64,'hbaHash':'f'*64,'unitHash':'a'*64,'settingsHash':'b'*64,'fileHashes':{'/etc/postgresql/16/main/postgresql.conf':'e'*64}}
                hashes={'/opt/incudal/.env':'a'*64,'/opt/incudal/server/dist/app.js':'b'*64,**backend['unitHashes'],database['config']:database['configHash'],database['hba']:database['hbaHash'],'/usr/lib/systemd/system/postgresql@.service':database['unitHash']}
                class App:
                    def __str__(self):return '/opt/incudal'
                    def resolve(self):return self
                    def __truediv__(self,part):return fixture['path']('/opt/incudal/'+part)
                def path(*parts):
                    if parts==('/opt/incudal',):return App()
                    if parts in [('/usr/bin/node',),('/proc','12','exe'),('/usr/lib/postgresql','16','bin/postgres'),('/proc','33','exe')]:return types.SimpleNamespace(stat=lambda:types.SimpleNamespace(st_dev=1,st_ino=2))
                    if parts==(database['data'],):return types.SimpleNamespace(stat=lambda:types.SimpleNamespace(st_uid=0))
                    return fixture['path'](*parts)
                running={'backend':True,'database':True};dispatched=[];qualifications=[]
                def command(args,*_):
                    if args==['dpkg','--audit']:return ''
                    if args[0]=='runuser'and 'SELECT pg_database_size' in args[-1]:return '1'
                    if args[0]=='apt-get'and '--download-only'in args:return ''
                    if args[0]=='/usr/bin/env'and 'apt-get'in args:
                        dispatched.append(args)
                        if failure=='command-spawn':raise ValueError('SYSTEM_SECURITY_QUERY_FAILED')
                        raise AssertionError('a refused preflight must never dispatch APT')
                    if args[:2]==['systemctl','stop']:
                        running['backend'if args[2]=='incudal-backend.service'else'database']=False;return ''
                    if args[:2]==['systemctl','start']:
                        running['backend'if args[2]=='incudal-backend.service'else'database']=True;return ''
                    if '--property=MainPID'in args:return '0'
                    if '--property=Result'in args:return 'success'
                    if '--property=SubState'in args:return 'dead'
                    if '--property=MainPID,ActiveState,Result'in args:return 'MainPID=0\nActiveState=inactive\nResult=success'
                    if '--property=FragmentPath'in args:return '/usr/lib/systemd/system/postgresql@.service'
                    raise AssertionError('unexpected OS operation in stage fixture')
                def qualification(_):
                    qualifications.append(running.copy())
                    if len(qualifications)==1:return proof['qualification']
                    if failure=='user-manager':raise ValueError('SYSTEM_SECURITY_SYSTEMD_USER_MANAGERS_ACTIVE')
                    current=copy.deepcopy(proof['qualification'])
                    if failure=='network-state':current['state']['networkHash']='0'*64
                    if failure=='manager-identity':current['manager']['start']='1'
                    return current
                tools=RuntimeDatabaseClients.tools()
                def dump(path,original_database,source=None):
                    self.assertEqual(original_database,{**database,'clientTools':tools});self.assertIsNone(source)
                    path.write_bytes(b'PGDMPfixture dump');path.chmod(0o600)
                def protected(value,*args,**kwargs):return hashes[str(value)]if str(value)in hashes else original_protected(value,*args,**kwargs)
                with contextlib.ExitStack()as stack:
                    for context in [patch.object(module.pathlib,'Path',side_effect=path),patch.object(module,'protected_hash',side_effect=protected),patch.object(module,'backend_service_policy',return_value=({},App(),backend['unitHashes'],backend['serviceHash'])),patch.object(module,'backend_runtime_proof',return_value=backend),patch.object(module,'database_runtime_proof',return_value=database),patch.object(module,'runtime_database_client_files',return_value=tools),patch.object(module,'debian_installed_packages',return_value=baseline),patch.object(module,'debian_package_states',return_value=states),patch.object(module,'command',side_effect=command),patch.object(module,'prepare_runtime_systemd_policy',return_value=proof),patch.object(module,'prepare_runtime_payload',return_value={'fixture':True}),patch.object(module,'runtime_original_expected_arguments',side_effect=lambda _,changes:changes),patch.object(module,'verify_runtime_systemd_policy_packages'),patch.object(module,'runtime_library_file',return_value={'sha256':'1'*64}),patch.object(module,'runtime_systemd_qualification',side_effect=qualification),patch.object(module.os,'statvfs',return_value=types.SimpleNamespace(f_bavail=1024*1024,f_frsize=4096)),patch.object(module,'dump_runtime_database',side_effect=dump),patch.object(module,'verify_runtime_financial_integrity'),patch.object(module,'verify_runtime_health'),patch.object(module,'runtime_process_has_replaced_libraries',return_value=False),patch.object(module,'persist'),patch.object(module,'prepare_service_policy'),patch.object(module,'clean_service_policy')]:stack.enter_context(context)
                    complete=stack.enter_context(patch.object(module,'complete_runtime_package_transaction',wraps=module.complete_runtime_package_transaction));receipt=stack.enter_context(patch.object(module,'archive_runtime_receipt'))
                    with self.assertRaisesRegex(ValueError,expected_error)as error:module.install_runtime_patches(before['packages'],backend,database,{},expected)
                self.assertEqual(str(error.exception),expected_error);fixture['recover'].assert_called_once_with()
                self.assertTrue(all(running.values()),'original runtime must recover after '+failure);complete.assert_not_called();receipt.assert_not_called()
                self.assertEqual(len(dispatched),int(failure=='command-spawn'))
                self.assertEqual(qualifications[-1],{'backend':False,'database':False},'fault is injected after both normal stops')
                finished=json.loads((fixture['security']/'runtime-maintenance.json').read_text());self.assertEqual(finished['phase'],'aborted');self.assertNotIn('activatedBackendPID',finished)
                self.assertFalse(fixture['source'].parent.exists());backups=list(fixture['security'].glob('runtime-backup-*'));self.assertEqual(len(backups),1)
                self.assertEqual({path.name for path in backups[0].iterdir()},{'database.dump','database-after-drain.dump'})

@unittest.skipUnless(sys.platform=='linux'and hasattr(os,'geteuid')and os.geteuid()==0,'real root-owned completion descriptors and SIGKILL; temporary evidence only, no services or database mutations')
class NativeRuntimeCompletions(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self,payload=False):
        import hashlib,json
        with tempfile.TemporaryDirectory()as directory:
            root=pathlib.Path(directory).resolve();root.chmod(0o700);backup=root/('runtime-backup-'+'f'*32);backup.mkdir(mode=0o700)
            originals={'database.dump':b'PGDMPoriginal live material','database-after-drain.dump':b'PGDMPoriginal drained material'}
            for name,data in originals.items():(backup/name).write_bytes(data);(backup/name).chmod(0o600)
            journal={'version':1,'phase':'activated','backup':backup.name,'dumpEvidence':{name:module.runtime_dump_evidence(backup/name)for name in originals}}
            if payload:
                baseline={'nodejs:amd64':'22.12.0-1'};expected={'nodejs:amd64':'22.13.0-1'};changes=['nodejs=22.13.0-1'];plan=module.runtime_payload_plan_hash(baseline,expected,changes)
                data=json.dumps({'planHash':plan,'archives':{},'paths':{}},separators=(',',':')).encode();(backup/'payload.json').write_bytes(data);(backup/'payload.json').chmod(0o600);originals['payload.json']=data
                journal.update(baselinePackages=baseline,expectedPackages=expected,packages=changes,payloadEvidence={'version':1,'file':'payload.json','sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'planHash':plan})
            module.write_runtime_maintenance(journal,root);module.runtime_backup_evidence(backup,journal)
            name,data=module.runtime_completion_preparation(journal)
            yield root,backup,journal,root/'runtime-maintenance.json',backup/name,data,originals

    def test_zero_middle_and_complete_pending_prefixes_resume_the_same_inode_without_commands(self):
        import json
        for length in [0,37,None]:
            with self.fixture()as(root,backup,journal,path,pending,data,originals):
                prefix=data if length is None else data[:length];pending.write_bytes(prefix);pending.chmod(0o600);inode=pending.stat().st_ino;before=path.read_bytes()
                with patch.object(module,'command')as command:self.assertIsNone(module.recover_runtime_maintenance(path))
                command.assert_not_called();completed=backup/'completed.json';self.assertFalse(pending.exists());self.assertEqual(completed.stat().st_ino,inode);self.assertEqual(completed.read_bytes(),data);self.assertEqual(json.loads(data),journal);self.assertEqual(path.read_bytes(),before)
                stamp=completed.stat().st_mtime_ns
                with patch.object(module,'command')as command:self.assertIsNone(module.recover_runtime_maintenance(path))
                command.assert_not_called();self.assertEqual(completed.stat().st_mtime_ns,stamp)
                for name,raw in originals.items():self.assertEqual((backup/name).read_bytes(),raw)

    def test_real_sigkill_leaves_a_bound_prefix_that_resumes_without_finally_cleanup(self):
        import json,signal,subprocess
        with self.fixture()as(root,backup,journal,path,pending,data,originals):
            helper="import os,sys,json; value=json.loads(sys.stdin.readline()); path=value['path']; data=bytes.fromhex(value['data']); fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); os.write(fd,data[:37]); os.fsync(fd); os.close(fd); parent=os.open(os.path.dirname(path),os.O_RDONLY|os.O_DIRECTORY); os.fsync(parent); os.close(parent); print('written',flush=True); sys.stdin.readline()"
            child=subprocess.Popen([sys.executable,'-I','-B','-c',helper],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                child.stdin.write(json.dumps({'path':str(pending),'data':data.hex()})+'\n');child.stdin.flush();self.assertEqual(child.stdout.readline().strip(),'written');child.kill();child.wait(timeout=10);self.assertEqual(child.returncode,-signal.SIGKILL)
            finally:
                if child.poll()is None:child.kill()
                child.communicate(timeout=10)
            self.assertEqual(pending.read_bytes(),data[:37]);inode=pending.stat().st_ino
            with patch.object(module,'command')as command:self.assertIsNone(module.recover_runtime_maintenance(path))
            command.assert_not_called();self.assertEqual((backup/'completed.json').read_bytes(),data);self.assertEqual((backup/'completed.json').stat().st_ino,inode)

    def test_existing_complete_receipt_preserves_its_bound_prefix_residue_and_rechecks_all_evidence(self):
        with self.fixture(payload=True)as(root,backup,journal,path,pending,data,originals):
            completed=backup/'completed.json';completed.write_bytes(data);completed.chmod(0o600);stamp=completed.stat().st_mtime_ns;prefix=data[:37];pending.write_bytes(prefix);pending.chmod(0o600);before=path.read_bytes()
            with patch.object(module,'command')as command:self.assertIsNone(module.recover_runtime_maintenance(path))
            command.assert_not_called();self.assertEqual(pending.read_bytes(),prefix);self.assertEqual(completed.stat().st_mtime_ns,stamp);self.assertEqual(path.read_bytes(),before)
            for name,raw in originals.items():self.assertEqual((backup/name).read_bytes(),raw)

    def test_unknown_or_changed_completion_material_and_unsafe_metadata_are_preserved_and_refused(self):
        for kind in ['unknown','third','permissions','symlink','hardlink']:
            with self.fixture()as(root,backup,journal,path,pending,data,originals):
                if kind=='unknown':pending=backup/('.completed-'+'0'*64+'.pending');pending.write_bytes(data[:37]);pending.chmod(0o600)
                elif kind=='symlink':outside=root/'outside';outside.write_bytes(data[:37]);outside.chmod(0o600);pending.symlink_to(outside)
                elif kind=='hardlink':outside=root/'outside';outside.write_bytes(data[:37]);outside.chmod(0o600);os.link(outside,pending)
                else:pending.write_bytes(b'changed completion material'if kind=='third'else data[:37]);pending.chmod(0o640 if kind=='permissions'else 0o600)
                original=pending.read_bytes();before=path.read_bytes()
                with patch.object(module,'command')as command,self.assertRaises((ValueError,OSError)):module.recover_runtime_maintenance(path)
                command.assert_not_called();self.assertEqual(pending.read_bytes(),original);self.assertEqual(path.read_bytes(),before);self.assertFalse((backup/'completed.json').exists())

    def test_pending_eacces_or_eio_never_looks_absent_and_never_writes_or_runs_commands(self):
        import errno
        for error in [PermissionError(errno.EACCES,'fixture unavailable'),OSError(errno.EIO,'fixture unavailable')]:
            with self.fixture()as(root,backup,journal,path,pending,data,originals):
                pending.write_bytes(data[:37]);pending.chmod(0o600);before=path.read_bytes();original_lstat=type(pending).lstat
                def lstat(value,*args,**kwargs):
                    if value==pending:raise error
                    return original_lstat(value,*args,**kwargs)
                with patch.object(type(pending),'lstat',lstat),patch.object(module,'command')as command,patch.object(module,'complete_runtime_fixed_evidence')as write,self.assertRaisesRegex(ValueError,'UNTRUSTED_PATH'):module.recover_runtime_maintenance(path)
                command.assert_not_called();write.assert_not_called();self.assertEqual(pending.read_bytes(),data[:37]);self.assertEqual(path.read_bytes(),before)

    def test_original_dump_or_payload_change_refuses_even_an_already_complete_receipt(self):
        for complete in [False,True]:
            for target in ['database.dump','payload.json']:
                with self.fixture(payload=True)as(root,backup,journal,path,pending,data,originals):
                    pending.write_bytes(data[:37]);pending.chmod(0o600);before=path.read_bytes()
                    if complete:(backup/'completed.json').write_bytes(data);(backup/'completed.json').chmod(0o600)
                    (backup/target).write_bytes(b'PGDMPchanged original material'if target=='database.dump'else b'changed original payload');changed=(backup/target).read_bytes()
                    with patch.object(module,'command')as command,patch.object(module,'complete_runtime_fixed_evidence')as write,self.assertRaisesRegex(ValueError,'BACKUP_FAILED|PAYLOAD_UNCONFIRMED'):module.recover_runtime_maintenance(path)
                    command.assert_not_called();write.assert_not_called();self.assertEqual(pending.read_bytes(),data[:37]);self.assertEqual((backup/target).read_bytes(),changed);self.assertEqual(path.read_bytes(),before)
                    if complete:self.assertEqual((backup/'completed.json').read_bytes(),data)
                    else:self.assertFalse((backup/'completed.json').exists())

if __name__=='__main__':unittest.main()
