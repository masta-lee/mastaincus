#!/usr/bin/env python3
"""Bounded package/runtime security receipt. Never changes a major or reboots."""
import json,os,pathlib,subprocess,sys,time,tempfile,re,fcntl,signal,uuid,stat

ALPINE=['openssl','libssl3','libcrypto3','curl','libcurl','openssh','openssh-server','openssh-client-default','dnsmasq','lxc','lxc-libs','lxcfs','lxcfs-openrc','lvm2','device-mapper','btrfs-progs','wireguard-tools','qemu-system-x86_64','qemu-system-aarch64']
DEBIAN=['openssl','libssl3','libssl3t64','curl','libcurl4','libcurl4t64','openssh-server','openssh-client','dnsmasq','lxc','liblxc1','liblxc-common','lxcfs','lvm2','libdevmapper1.02.1','libdevmapper-event1.02.1','btrfs-progs','wireguard-tools','nginx','nginx-common','nodejs','qemu-system-x86','qemu-system-arm','qemu-system-common','qemu-utils','systemd','systemd-dev','systemd-sysv','systemd-timesyncd','systemd-resolved','libsystemd0','libsystemd-shared','libpam-systemd','udev','libudev1','chrony','nftables','ca-certificates']

def command(args,timeout=90):
    # Keep the complete apt/dpkg process group under the deadline. A surviving
    # package hook must not outlive the temporary service policy or task lock.
    with tempfile.TemporaryFile()as out,tempfile.TemporaryFile()as error:
        process=subprocess.Popen(args,stdout=out,stderr=error,start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_MODE':'l'})
        deadline=time.monotonic()+timeout;failed=False
        while process.poll() is None:
            if time.monotonic()>deadline or os.fstat(out.fileno()).st_size+os.fstat(error.fileno()).st_size>2*1024*1024:failed=True;break
            time.sleep(.1)
        if failed:
            for kind in [signal.SIGTERM,signal.SIGKILL]:
                try:os.killpg(process.pid,kind)
                except ProcessLookupError:pass
                if kind==signal.SIGTERM:time.sleep(.2)
            process.wait()
        # Also terminate detached children still in the original group after
        # their apt parent failed; only this newly created process group is used.
        if failed or process.returncode:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
        try:
            os.killpg(process.pid,0)
        except ProcessLookupError:pass
        else:
            os.killpg(process.pid,signal.SIGKILL)
            raise ValueError('SYSTEM_SECURITY_PACKAGE_CHILD_PENDING')
        if os.fstat(out.fileno()).st_size>2*1024*1024:raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
        out.seek(0);return out.read(2*1024*1024).decode().strip()

HOST_SERVICES={'incusd','lxcfs','dnsmasq','sshd','nginx','postgres','systemd','systemd-resolve','systemd-timesyn','chronyd','node'}

def replaced_host_mappings(proc=pathlib.Path('/proc'),all_host=False):
    # Installed package versions cannot attest to old mapped libraries. Inspect
    # only recognized services in the host PID namespace; no guest process,
    # argument, mapped filename or credential is written to the receipt.
    host_namespace=(proc/'1/ns/pid').readlink();rows=[];checked=0;complete=True
    deadline=time.monotonic()+5
    for path in proc.iterdir():
        if not path.name.isdigit():continue
        if time.monotonic()>deadline:complete=False;break
        try:
            if (path/'ns/pid').readlink()!=host_namespace:continue
            name=(path/'comm').read_text()[:32].strip()
            # Node may expose MainThread as comm. The executable basename is
            # local proof only, never included in the public/private receipt.
            if name not in HOST_SERVICES:
                try:executable=str((path/'exe').readlink()).removesuffix(' (deleted)')
                except (OSError,ValueError):
                    if not all_host:continue
                    executable=''
                if pathlib.Path(executable).name=='node':name='node'
            if name not in HOST_SERVICES:
                if not all_host:continue
                name='other'
            if checked>=256:complete=False;break
            checked+=1
            with (path/'maps').open()as source:data=source.read(1024*1024+1)
            if len(data)>1024*1024:complete=False;continue
            count=0
            for line in data.splitlines():
                if not line.endswith(' (deleted)'):continue
                fields=line.split(maxsplit=5)
                if len(fields)!=6 or 'x'not in fields[1]:continue
                mapped_path=fields[5]
                # Unlinked shared memory, memfd/JIT and System V mappings are
                # intentional runtime data, not replaced package code.
                if not mapped_path.startswith('/')or mapped_path.startswith(('/dev/','/memfd:','/SYSV')):continue
                count+=1
            if count:rows.append({'pid':int(path.name),'service':name,'replacedMappings':count})
        except (FileNotFoundError,ProcessLookupError):continue
        except (OSError,ValueError):complete=False
    return {'complete':complete,'allHostProcesses':all_host,'checkedProcesses':checked,'processes':sorted(rows,key=lambda row:row['pid'])}

def inventory(all_loaded_code=False):
    release=dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '='in line)
    system=release.get('ID','').strip('"');packages={};pending=[]
    if system=='alpine':
        installed=command(['apk','info','-v']).splitlines()
        for name in ALPINE+['linux-virt','linux-lts','linux-edge']:
            matches=[line for line in installed if line.startswith(name+'-') and line[len(name)+1:len(name)+2].isdigit()]
            if matches:packages[name]=matches[0][len(name)+1:]
        simulated=command(['apk','--simulate','--no-cache','--wait','5','upgrade',*sorted(packages)]) if packages else ''
        pending=[line for line in simulated.splitlines() if 'Upgrading 'in line]
    elif system in ['debian','ubuntu']:
        names=DEBIAN+['postgresql-'+str(n) for n in range(14,19)]+['linux-image-amd64','linux-image-arm64','linux-image-'+os.uname().release]
        for name in names:
            result=subprocess.run(['dpkg-query','-W','-f=${db:Status-Status} ${Version}',name],capture_output=True,timeout=5)
            if result.returncode==0 and result.stdout.startswith(b'installed '):packages[name]=result.stdout.decode().split(' ',1)[1]
        output=command(['apt-get','-o','DPkg::Lock::Timeout=5','--simulate','--only-upgrade','--no-remove','install',*sorted(packages)]) if packages else ''
        pending=[line for line in output.splitlines() if line.startswith('Inst ')]
    else:raise ValueError('SYSTEM_SECURITY_DISTRIBUTION_UNSUPPORTED')
    running_kernel=os.uname().release
    restart_required=pathlib.Path('/var/run/reboot-required').exists() or alpine_kernel_replaced(running_kernel,packages)
    return {'version':1,'checkedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'distribution':system,'release':release.get('VERSION_ID','').strip('"'),'runningKernel':running_kernel,'packages':packages,'pending':pending,'loadedCode':replaced_host_mappings(all_host=all_loaded_code),'restartRequired':restart_required,'policy':'same-distribution-signed-packages; no-major-upgrade; no-automatic-customer-reboot','unreleasedAdvisories':['OpenSSL-20261117: official release planned 2026-12-01; feature conditions require review']}

def alpine_kernel_replaced(running,packages):
    # Alpine package revisions are part of the actual uname release. Prefix
    # comparisons confuse 6.12.1 with 6.12.10 and miss same-version rN fixes.
    # An installed alternative flavour is not the kernel currently in use.
    for name in ['linux-virt','linux-lts','linux-edge']:
        flavour=name.removeprefix('linux-')
        if not running.endswith('-'+flavour)or name not in packages:continue
        version=packages[name];match=re.fullmatch(r'([0-9]+\.[0-9]+\.[0-9]+)-r([0-9]+)',version)
        return not match or running!=match.group(1)+'-'+match.group(2)+'-'+flavour
    return False

def patch_plan(output,installed,allowed):
    """Only explicit existing packages, same major; no solver expansion."""
    if any(word in output for word in ['Remv ','Removing ','Downgrading ','UNTRUSTED','WARNING: The following packages cannot be authenticated']):raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
    changes=[]
    for line in output.splitlines():
        if not line.startswith('Inst '):continue
        match=re.fullmatch(r'Inst ([a-z0-9+.-]+)(?::(?:amd64|arm64))? \[([^\]]+)\] \(([^\s]+) [^\r\n]+\)(?: \[[^\]\r\n]*\])?',line)
        if not match:raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
        name,old,new=match.groups()
        major=lambda v: re.match(r'(?:\d+:)?(\d+)',v).group(1) if re.match(r'(?:\d+:)?(\d+)',v)else None
        if name not in allowed or installed.get(name)!=old or not major(old) or major(old)!=major(new):raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
        # Debian version ordering includes epochs, tildes and distro revisions;
        # a same-major comparison alone must never authorize a downgrade.
        check=subprocess.run(['dpkg','--compare-versions',new,'gt',old],capture_output=True,timeout=5)
        if check.returncode:raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
        changes.append(name+'='+new)
    if len(changes)>64 or len(changes)!=len({item.split('=',1)[0]for item in changes}):raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
    return changes

def debian_installed_packages():
    output=command(['dpkg-query','-W','-f=${Package}\t${Architecture}\t${db:Status-Status}\t${Version}\n'],30)
    packages={}
    for line in output.splitlines():
        fields=line.split('\t')
        if len(fields)!=4:raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
        name,architecture,status,version=fields
        if status!='installed':continue
        if not re.fullmatch(r'[a-z0-9+.-]+',name)or not re.fullmatch(r'[a-z0-9-]+',architecture)or not re.fullmatch(r'[^\s\x00-\x1f]{1,200}',version):raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
        identity=name+':'+architecture
        if identity in packages or len(packages)>=20000:raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
        packages[identity]=version
    return packages

POLICY=pathlib.Path('/usr/sbin/policy-rc.d')
POLICY_RECEIPT=pathlib.Path('/var/lib/incudal-system-security/service-policy.json')

def clean_service_policy(policy=POLICY,receipt=POLICY_RECEIPT):
    if not receipt.exists() and not receipt.is_symlink():return
    info=receipt.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    if info.st_size>4096:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    value=json.loads(receipt.read_text())
    if not re.fullmatch(r'[a-f0-9]{32}',value.get('token','')):raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    text='#!/bin/sh\n# PayIncus security maintenance '+value['token']+'\nexit 101\n'
    if policy.exists() or policy.is_symlink():
        info=policy.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>4096 or policy.read_text()!=text:raise ValueError('SYSTEM_SECURITY_EXISTING_SERVICE_POLICY')
        # After a hard termination, do not remove the policy while apt/dpkg or
        # their maintainer hooks can still be running. Their locks are POSIX
        # record locks, not flock locks.
        locks=[]
        try:
            for path in ['/var/lib/dpkg/lock','/var/lib/dpkg/lock-frontend']:
                if not pathlib.Path(path).exists():continue
                fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW);locks.append(fd)
                fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            policy.unlink()
        except BlockingIOError:raise ValueError('SYSTEM_SECURITY_PACKAGE_OPERATION_PENDING')
        finally:
            for fd in locks:os.close(fd)
    receipt.unlink()

def recover_service_policy():
    if not POLICY_RECEIPT.exists() and not POLICY_RECEIPT.is_symlink():return
    fd=os.open('/var/lib/incudal-platform-operation.lock',os.O_RDWR|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        clean_service_policy()
    finally:os.close(fd)

def prepare_service_policy(policy=POLICY,receipt=POLICY_RECEIPT):
    clean_service_policy(policy,receipt)
    if policy.exists() or policy.is_symlink():raise ValueError('SYSTEM_SECURITY_EXISTING_SERVICE_POLICY')
    token=uuid.uuid4().hex
    fd=os.open(receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w')as out:out.write(json.dumps({'version':1,'token':token}));out.flush();os.fsync(out.fileno())
    fd=os.open(policy,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)
    with os.fdopen(fd,'w')as out:out.write('#!/bin/sh\n# PayIncus security maintenance '+token+'\nexit 101\n');out.flush();os.fsync(out.fileno())

def apply_patches():
    # Explicit root maintenance action. Timers remain read-only. dpkg suppresses
    # service restarts during installation; actual activation stays visible as
    # pending until the operator uses the service's reviewed maintenance path.
    if os.geteuid()!=0:raise ValueError('SYSTEM_SECURITY_ROOT_REQUIRED')
    if pathlib.Path('/var/lib/incudal-backup/recovery-hold.json').exists():raise ValueError('SYSTEM_SECURITY_RECOVERY_HELD')
    value=inventory()
    if value['distribution'] not in ['debian','ubuntu']:raise ValueError('SYSTEM_SECURITY_DISTRIBUTION_UNSUPPORTED')
    allowed=set(DEBIAN)|{'postgresql-'+str(n) for n in range(14,19)}
    sources=[pathlib.Path('/etc/apt/sources.list'),*pathlib.Path('/etc/apt/sources.list.d').glob('*')]
    for source in sources:
        if not source.is_file():continue
        if source.stat().st_size>1024*1024:raise ValueError('SYSTEM_SECURITY_REPOSITORY_UNTRUSTED')
        if source.is_symlink() or source.stat().st_uid!=0 or source.stat().st_mode&0o022:raise ValueError('SYSTEM_SECURITY_REPOSITORY_UNTRUSTED')
        if re.search(r'trusted\s*=\s*yes|Trusted:\s*yes|Allow-Insecure:\s*yes',source.read_text(),re.I):raise ValueError('SYSTEM_SECURITY_REPOSITORY_UNTRUSTED')
    lock=pathlib.Path('/var/lib/incudal-system-security');lock.mkdir(mode=0o700,exist_ok=True)
    if lock.is_symlink() or lock.stat().st_uid!=0 or lock.stat().st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    fd=os.open('/var/lib/incudal-platform-operation.lock',os.O_CREAT|os.O_NOFOLLOW|os.O_RDWR,0o600)
    info=os.fstat(fd)
    if info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:os.close(fd);raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        clean_service_policy()
        command(['apt-get','-o','Acquire::AllowInsecureRepositories=false','-o','Acquire::AllowDowngradeToInsecureRepositories=false','-o','Acquire::AllowWeakRepositories=false','update'],180)
        names=sorted(set(value['packages'])&allowed)
        output=command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','--simulate','--only-upgrade','--no-remove','install',*names])
        changes=patch_plan(output,value['packages'],allowed)
        value['patchPlan']=changes;value['patchState']='prepared';persist(value)
        if changes:
            before=debian_installed_packages()
            planned=patch_plan(command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','--simulate','--only-upgrade','--no-remove','install',*changes]),value['packages'],allowed)
            if sorted(planned)!=sorted(changes):raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
            expected=dict(before)
            for item in changes:
                name,version=item.split('=',1);matches=[identity for identity in before if identity.split(':',1)[0]==name]
                if len(matches)!=1 or before[matches[0]]!=value['packages'][name]:raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
                expected[matches[0]]=version
            prepare_service_policy()
            try:command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','-o','Dpkg::Options::=--force-confold','--assume-yes','--only-upgrade','--no-remove','install',*changes],600)
            finally:
                clean_service_policy()
            if debian_installed_packages()!=expected:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')
        after=inventory()
        for package in changes:
            name,version=package.split('=',1)
            if after['packages'].get(name)!=version:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')
        value=after;value['patchPlan']=changes;value['patchState']='installed-activation-required' if changes else 'current';persist(value)
        return value
    except Exception:
        value['patchState']='failed';value['error']='SYSTEM_SECURITY_PATCH_NOT_CONFIRMED';persist(value)
        raise
    finally:os.close(fd)

def preserve_activation(value,previous):
    # Refreshing package inventory is not proof that daemons have reloaded the
    # patched code. Keep the exact installed change set across timer refreshes
    # and later no-op patch runs until a separate activation verifies it.
    pending=previous.get('activationRequired',[])
    if not isinstance(pending,list) or len(pending)>256 or any(not isinstance(item,str) or not re.fullmatch(r'[a-z0-9+.-]+=[^\s=\x00-\x1f]{1,200}',item)for item in pending):raise ValueError('SYSTEM_SECURITY_RECEIPT_INVALID')
    if value.get('patchState') in ['prepared','installed-activation-required']:
        plan=value.get('patchPlan',[])
        if not isinstance(plan,list) or len(plan)>64 or any(not isinstance(item,str) or not re.fullmatch(r'[a-z0-9+.-]+=[^\s=\x00-\x1f]{1,200}',item)for item in plan):raise ValueError('SYSTEM_SECURITY_RECEIPT_INVALID')
        # A newer installed patch still needs activation, but replaces its
        # earlier version's pending entry rather than growing without bound.
        versions=dict(item.split('=',1)for item in pending+plan)
        pending=sorted(name+'='+version for name,version in versions.items())
    if len(pending)>256:raise ValueError('SYSTEM_SECURITY_RECEIPT_INVALID')
    if pending:
        value['activationRequired']=pending
        if value.get('patchState') not in ['failed','prepared']:value['patchState']='installed-activation-required'
    return value

def activation_verified(value,pending):
    loaded=value.get('loadedCode',{})
    if value.get('restartRequired') is not False or loaded.get('complete') is not True or loaded.get('allHostProcesses') is not True or loaded.get('processes')!=[]:return False
    packages=value.get('packages',{})
    return all(packages.get(name)==version for name,version in (item.split('=',1)for item in pending))

def record_inventory():
    # A timer cannot attest to a half-installed package set or overlap the
    # restore/OTA/service maintenance lane. Busy means preserve the receipt,
    # not overwrite a still-active patch plan with an incomplete observation.
    if os.geteuid()!=0:raise ValueError('SYSTEM_SECURITY_ROOT_REQUIRED')
    if pathlib.Path('/var/lib/incudal-backup/recovery-hold.json').exists():return
    fd=os.open('/var/lib/incudal-platform-operation.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        clean_service_policy()
        value=inventory(all_loaded_code=True)
        persist(value,verify_activation=True)
    finally:os.close(fd)

def persist(value,verify_activation=False):
    root=pathlib.Path('/var/lib/incudal-system-security')
    if os.geteuid()!=0:raise ValueError('SYSTEM_SECURITY_ROOT_REQUIRED')
    if root.is_symlink():raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    root.mkdir(mode=0o700,exist_ok=True)
    info=root.stat()
    if info.st_uid!=0 or info.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    lock=os.open(root/'receipt.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    info=os.fstat(lock)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:os.close(lock);raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    try:
        fcntl.flock(lock,fcntl.LOCK_EX)
        status=root/'status.json';previous={}
        if status.exists() or status.is_symlink():
            info=status.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077 or info.st_size>128*1024:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
            previous=json.loads(status.read_text())
            if not isinstance(previous,dict):raise ValueError('SYSTEM_SECURITY_RECEIPT_INVALID')
            # Adopt the exact pending list from the earlier receipt format.
            if 'activationRequired'not in previous and previous.get('patchState')=='installed-activation-required':previous['activationRequired']=previous.get('patchPlan',[])
        preserve_activation(value,previous)
        if 'activationReceipt' in previous and 'activationReceipt'not in value:
            value['activationReceipt']=previous['activationReceipt']
            value.setdefault('activationRequired',[])
        if verify_activation:
            pending=value.get('activationRequired',[])
            # A past receipt is history, not proof after a later package change,
            # service rollback, reboot or incomplete scan. Recheck its original
            # targets as strictly as a newly installed patch on every refresh.
            if not pending and value.get('activationReceipt'):
                pending=value['activationReceipt'].get('packages',[])
                if not isinstance(pending,list) or not pending or len(pending)>256 or any(not isinstance(item,str) or not re.fullmatch(r'[a-z0-9+.-]+=[^\s=\x00-\x1f]{1,200}',item)for item in pending):raise ValueError('SYSTEM_SECURITY_RECEIPT_INVALID')
            if pending and activation_verified(value,pending):
                value['activationRequired']=[]
                value['activationReceipt']={'packages':pending,'checkedAt':value['checkedAt'],'bootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
                value['patchState']='activated'
            elif pending:
                value['activationRequired']=pending
                value['patchState']='installed-activation-required'
        elif value.get('patchState') is None and previous.get('patchState')=='activated' and not value.get('activationRequired') and value.get('activationReceipt'):
            value['patchState']='activated'
        fd,name=tempfile.mkstemp(dir=root,prefix='.receipt-')
        try:
            with os.fdopen(fd,'w')as out:out.write(json.dumps(value,separators=(',',':')));out.flush();os.fsync(out.fileno())
            os.replace(name,status)
            parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(parent)
            finally:os.close(parent)
        finally:
            if os.path.exists(name):os.unlink(name)
    finally:
        os.close(lock)

def failure_receipt(error):
    code=str(error)
    if not re.fullmatch(r'SYSTEM_SECURITY_[A-Z_]{1,100}',code):code='SYSTEM_SECURITY_CHECK_FAILED'
    return {'version':1,'checkedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'patchState':'failed','error':code}

if __name__=='__main__':
    try:
        if sys.argv[1:]==['--verify-activation']:
            # No service restart or customer operation: attest only after the
            # separately reviewed maintenance has loaded the installed code.
            if os.geteuid()!=0:raise ValueError('SYSTEM_SECURITY_ROOT_REQUIRED')
            if pathlib.Path('/var/lib/incudal-backup/recovery-hold.json').exists():raise ValueError('SYSTEM_SECURITY_RECOVERY_HELD')
            fd=os.open('/var/lib/incudal-platform-operation.lock',os.O_RDWR|os.O_NOFOLLOW)
            try:
                info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                value=inventory(all_loaded_code=True);persist(value,verify_activation=True)
                print(json.dumps(value,separators=(',',':')))
            finally:os.close(fd)
            sys.exit(0)
        if sys.argv[1:]==['--record']:
            record_inventory();sys.exit(0)
        if sys.argv[1:]==['--apply']:value=apply_patches()
        else:value=inventory()
        if sys.argv[1:]==['--apply']:print(json.dumps(value,separators=(',',':')))
        elif sys.argv[1:]:raise ValueError('SYSTEM_SECURITY_ARGUMENT_INVALID')
        else:print(json.dumps(value,separators=(',',':')))
    except Exception as error:
        value=failure_receipt(error)
        if sys.argv[1:]in [['--record'],['--apply'],['--verify-activation']]:
            try:persist(value)
            except Exception:pass # Unsafe/unwritable state is never repaired implicitly.
        print(json.dumps(value,separators=(',',':')));sys.exit(1)
