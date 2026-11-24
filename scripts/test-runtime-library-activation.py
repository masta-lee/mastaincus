"""Opt-in native service activation on a disposable GitHub runner."""
import fcntl,hashlib,importlib.util,json,os,pathlib,pwd,re,shutil,stat,subprocess,tempfile,time,traceback

if os.environ.get('GITHUB_ACTIONS')!='true'or os.environ.get('RUNNER_ENVIRONMENT')!='github-hosted'or os.geteuid()!=0:
    raise SystemExit('DISPOSABLE_GITHUB_ROOT_RUNTIME_REQUIRED')

source=pathlib.Path('/usr/local/libexec/incudal/system-security-inventory.py')
expected=pathlib.Path(__file__).with_name('system-security-inventory.py')
assert hashlib.sha256(source.read_bytes()).digest()==hashlib.sha256(expected.read_bytes()).digest()
spec=importlib.util.spec_from_file_location('native_runtime_activation',source)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
root=pathlib.Path(tempfile.mkdtemp(prefix='incudal-runtime-library-native-'));root.chmod(0o700)
shared_database='incudal_runtime_library_native_test'
lock=None;shared_created=False;restore_timer=False
result={'success':False,'sameLibraryBytes':True,'actualManagedServices':True}

def pg(sql,database='incudal'):
    return module.command(['runuser','-u','postgres','--','psql','-X','-At','-v','ON_ERROR_STOP=1','-d',database,'-c',sql],30)
def protected_configuration():
    files=['/opt/incudal/.env',*['/var/lib/incudal-gateway-controller/'+name for name in ['identity.json','enrollment.json','signing.pem']]]
    value={name:module.protected_hash(name)for name in files}
    # The application's signed financial baseline deliberately belongs to its
    # service account. Attest that exact owner, retaining the private mode.
    finance=pathlib.Path('/var/lib/incudal-finance/baseline.json')
    value[str(finance)]=module.protected_hash(finance,(pwd.getpwnam('incudal').pw_uid,),private=True)
    return value
def same_backend(before,after):
    assert all(before[key]==after[key]for key in ['app','environmentHash','codeHash','unitHashes','serviceHash'])
def verify_receipt(value,packages):
    backup=pathlib.Path('/var/lib/incudal-system-security')/value['backendActivation']['backup']
    receipt=json.loads((backup/'completed.json').read_text())
    assert receipt['phase']=='activated'and receipt['activationOnly']is True and receipt['drainConfirmed']is True
    assert receipt['packages']==[]and receipt['baselinePackages']==receipt['expectedPackages']==packages
    for name in ['database.dump','database-after-drain.dump']:
        path=backup/name;metadata=path.lstat()
        assert stat.S_ISREG(metadata.st_mode)and metadata.st_uid==0 and metadata.st_nlink==1 and not metadata.st_mode&0o077
        with path.open('rb')as stream:assert stream.read(5)==b'PGDMP'
    return receipt
def library_for(backend,database):
    def mapped(pid):
        paths=set()
        for line in pathlib.Path('/proc',str(pid),'maps').read_text().splitlines():
            fields=line.split(maxsplit=5)
            if len(fields)==6 and 'x'in fields[1]and fields[5].startswith('/')and not line.endswith(' (deleted)'):
                paths.add(str(pathlib.Path(fields[5]).resolve()))
        return paths
    common=mapped(backend['pid'])&mapped(database['pid'])
    candidates=[pathlib.Path(path)for path in common if re.fullmatch(r'/usr/lib/(?:x86_64|aarch64)-linux-gnu/libm\.so\.6',path)]
    assert len(candidates)==1
    return candidates[0]
def replace_identical_library(path):
    old=path.lstat();data=path.read_bytes()
    assert stat.S_ISREG(old.st_mode)and old.st_uid==0 and not old.st_mode&0o022
    fd,name=tempfile.mkstemp(prefix='.incudal-runtime-library-native-',dir=path.parent);os.close(fd)
    try:
        shutil.copy2(path,name);os.chown(name,old.st_uid,old.st_gid);os.chmod(name,stat.S_IMODE(old.st_mode))
        assert pathlib.Path(name).read_bytes()==data
        with open(name,'rb')as stream:os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)
    assert path.read_bytes()==data and path.stat().st_ino!=old.st_ino

try:
    assert pg('SELECT count(*)FROM hosts')=='0'and pg('SELECT count(*)FROM instances')=='0'
    assert not pathlib.Path('/var/lib/incudal-backup/recovery-hold.json').exists()
    assert module.command(['systemctl','show','incudal-system-security.service','--property=MainPID','--value'],20)=='0'
    restore_timer=module.command(['systemctl','show','incudal-system-security.timer','--property=ActiveState','--value'],20)=='active'
    module.command(['systemctl','stop','incudal-system-security.timer'],30)
    lock=module.open_platform_operation_lock();fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    module.verify_runtime_health();module.verify_runtime_integrity()
    backend=module.backend_runtime_proof();database=module.database_runtime_proof();packages=module.debian_installed_packages()
    module.verify_runtime_financial_integrity(backend['app']);protected=protected_configuration()
    library=library_for(backend,database);replace_identical_library(library)
    assert module.runtime_process_has_replaced_libraries(backend['pid'])and module.runtime_process_has_replaced_libraries(database['pid'])
    value={};module.activate_runtime_libraries(backend,database,value)
    current=module.backend_runtime_proof();current_db=module.database_runtime_proof()
    assert current['pid']!=backend['pid']and current_db['pid']!=database['pid']
    same_backend(backend,current);module.verify_database_activation(current_db,database)
    assert not module.runtime_process_has_replaced_libraries(current['pid'])and not module.runtime_process_has_replaced_libraries(current_db['pid'])
    receipt=verify_receipt(value,packages)
    assert receipt['activatedBackendPID']==current['pid']and receipt['activatedDatabasePID']==current_db['pid']
    repeat={};module.activate_runtime_libraries(current,current_db,repeat)
    assert repeat=={}and module.backend_runtime_proof()['pid']==current['pid']and module.database_runtime_proof()['pid']==current_db['pid']
    assert pg("SELECT count(*)FROM pg_database WHERE datname='"+shared_database+"'")=='0'
    module.command(['runuser','-u','postgres','--','createdb',shared_database],30);shared_created=True
    pg("CREATE TABLE proof(value text PRIMARY KEY);INSERT INTO proof VALUES('shared-process-and-data-preserved')",shared_database)
    try:module.database_runtime_proof();raise AssertionError('SHARED_DATABASE_NOT_REJECTED')
    except ValueError as error:assert str(error)=='SYSTEM_SECURITY_DATABASE_SHARED_OR_REPLICATED'
    shared=module.database_runtime_proof(shared_read_only=True);current=module.backend_runtime_proof()
    replace_identical_library(library)
    assert module.runtime_process_has_replaced_libraries(current['pid'])and module.runtime_process_has_replaced_libraries(shared['pid'])
    value={};module.activate_runtime_libraries(current,shared,value)
    after=module.backend_runtime_proof();after_db=module.database_runtime_proof(shared_read_only=True)
    assert after['pid']!=current['pid']and after_db['pid']==shared['pid']and after_db['start']==shared['start']
    assert not module.runtime_process_has_replaced_libraries(after['pid'])and module.runtime_process_has_replaced_libraries(after_db['pid'])
    same_backend(current,after);assert 'databaseActivation'not in value and verify_receipt(value,packages)['database']is None
    assert pg('SELECT value FROM proof',shared_database)=='shared-process-and-data-preserved'
    module.command(['runuser','-u','postgres','--','dropdb',shared_database],30);shared_created=False
    value={};module.activate_runtime_libraries(module.backend_runtime_proof(),module.database_runtime_proof(),value)
    final=module.backend_runtime_proof();final_db=module.database_runtime_proof()
    same_backend(backend,final);module.verify_database_activation(final_db,database)
    assert not module.runtime_process_has_replaced_libraries(final['pid'])and not module.runtime_process_has_replaced_libraries(final_db['pid'])
    module.verify_runtime_health();module.verify_runtime_integrity();module.verify_runtime_financial_integrity(final['app'])
    assert module.debian_installed_packages()==packages and protected_configuration()==protected
    assert not list(library.parent.glob('.incudal-runtime-library-native-*'))
    result.update(success=True,fullActivation=True,idempotent=True,sharedDatabaseRestarts=0,twoVerifiedDumps=True,configurationIdentityFinancePreserved=True)
except BaseException:
    (root/'error.private.log').write_text(traceback.format_exc())
    raise SystemExit('NATIVE_RUNTIME_LIBRARY_ACTIVATION_FAILED; private diagnostic: '+str(root/'error.private.log'))
finally:
    if shared_created:
        module.command(['runuser','-u','postgres','--','dropdb',shared_database],30)
    if lock is not None:
        try:module.recover_runtime_maintenance();module.verify_runtime_health()
        finally:os.close(lock)
    if restore_timer:module.command(['systemctl','start','incudal-system-security.timer'],30)
    (root/'summary.json').write_text(json.dumps(result,sort_keys=True))
print('PASS actual managed runtime library activation: '+json.dumps(result,sort_keys=True))
