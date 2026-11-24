"""Security patch planner regression; no package or service mutations."""
import importlib.util,pathlib,sys,types,unittest,tempfile,os
from unittest.mock import patch
if sys.platform=='win32':sys.modules.setdefault('fcntl',types.SimpleNamespace())
spec=importlib.util.spec_from_file_location('inventory',pathlib.Path(__file__).with_name('system-security-inventory.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class Plans(unittest.TestCase):
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
            data={'version':1,'phase':'stopping-backend','backend':before,'database':None}
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
            with patch.object(module,'backend_service_policy',return_value=policy),patch.object(module.pathlib,'Path',side_effect=fixture_path),patch.object(module,'protected_hash',side_effect=hashes),patch.object(module,'backend_runtime_proof',return_value=before),patch.object(module,'verify_runtime_financial_integrity'),patch.object(module,'verify_runtime_health'),patch.object(module,'clean_service_policy'),patch.object(module,'command',side_effect=lambda args,*_: 'success'if '--property=Result'in args else '')as command:
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
    def test_database_activation_requires_config_and_installed_executable(self):
        before={key:'same'for key in ['major','data','configHash','hbaHash','unitHash','fileHashes','settingsHash']};before.update(major=16,pid=12)
        for key in ['major','data','configHash','hbaHash','unitHash','fileHashes','settingsHash']:
            with patch.object(module.pathlib,'Path')as path,self.assertRaisesRegex(ValueError,'CONFIGURATION_CHANGED'):
                module.verify_database_activation({**before,key:'changed'},before)
            path.assert_not_called()
        with patch.object(module.pathlib,'Path')as path:
            path.return_value.stat.return_value=types.SimpleNamespace(st_dev=1,st_ino=2)
            module.verify_database_activation(before,before)
            path.return_value.stat.side_effect=[types.SimpleNamespace(st_dev=1,st_ino=2),types.SimpleNamespace(st_dev=1,st_ino=3)]
            with self.assertRaisesRegex(ValueError,'ACTIVATION_PENDING'):module.verify_database_activation(before,before)
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
