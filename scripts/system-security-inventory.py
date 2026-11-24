#!/usr/bin/env python3
"""Bounded package/runtime security receipt. Never changes a major or reboots."""
import json,os,pathlib,subprocess,sys,time,tempfile,re,fcntl,signal,uuid,stat
import hashlib
import calendar

def open_platform_operation_lock(create=True,path='/var/lib/incudal-platform-operation.lock'):
    # Earlier root launchers created this empty lock as root:incudal 0640.
    # Tighten only that exact historical metadata, through the held inode;
    # replacing a lock file would split flock authority between two writers.
    flags=os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_CREAT if create else 0)
    fd=os.open(path,flags,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        mode=stat.S_IMODE(info.st_mode)
        if mode==0o640:
            import grp
            if info.st_size!=0 or info.st_gid!=grp.getgrnam('incudal').gr_gid:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
            current=os.lstat(path)
            if (current.st_dev,current.st_ino)!=(info.st_dev,info.st_ino):raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
            os.fchmod(fd,0o600)
            info=os.fstat(fd)
        if info.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        return fd
    except BaseException:
        os.close(fd);raise

ALPINE=['openssl','libssl3','libcrypto3','curl','libcurl','openssh','openssh-server','openssh-client-default','dnsmasq','lxc','lxc-libs','lxcfs','lxcfs-openrc','lvm2','device-mapper','btrfs-progs','wireguard-tools','qemu-system-x86_64','qemu-system-aarch64','sqlite-libs','libseccomp','libcap2','acl-libs','libattr','libuv','lz4-libs','zstd-libs','xz-libs','libintl','libgcc','dbus-libs','eudev-libs','raft-cowsql','cowsql']
DEBIAN=['openssl','libssl3','libssl3t64','curl','libcurl4','libcurl4t64','openssh-server','openssh-client','dnsmasq','lxc','liblxc1','liblxc-common','lxcfs','lvm2','libdevmapper1.02.1','libdevmapper-event1.02.1','btrfs-progs','wireguard-tools','nginx','nginx-common','nodejs','qemu-system-x86','qemu-system-arm','qemu-system-common','qemu-utils','systemd','systemd-dev','systemd-sysv','systemd-timesyncd','systemd-resolved','libsystemd0','libsystemd-shared','libpam-systemd','udev','libudev1','chrony','nftables','ca-certificates','libsqlite3-0','libseccomp2','libcap2','libacl1','libattr1','libuv1','libuv1t64','liblz4-1','libzstd1','liblzma5','libdbus-1-3','libgcc-s1']

# libc, clock and the actual storage/network helper libraries must not vanish
# from inventory just because a signed package transaction cannot safely
# activate them while a customer is using the host. These are distro packages,
# never guest software; installation and activation retain separate receipts.
ALPINE+=['musl','musl-utils','chrony','chrony-openrc','ca-certificates','fuse3-libs','lvm2-libs','device-mapper-libs','device-mapper-event-libs',
    'tar','gzip','xz','squashfs-tools','rsync','libpsl','libidn2','libunistring','c-ares','brotli-libs','nghttp2-libs','nftables','libnftnl','libmnl','iptables','ip6tables']
DEBIAN+=['openssl-provider-legacy','libc6','libc-bin','libfuse3-3','libfuse3-4','libnftnl11','libmnl0','iptables','libxtables12','libip4tc2','libip6tc2',
    'tar','gzip','xz-utils','zstd','squashfs-tools','rsync','libpsl5','libpsl5t64','libidn2-0','libunistring5','libc-ares2','libbrotli1','libnghttp2-14','openssh-sftp-server','libpq5','postgresql-common','postgresql-client-common']

# These tools and libraries have no daemon lifecycle operation. Installed
# services loading an old mapping remain activation-required, never marked
# patched by an installed version alone. libc/kernel/service packages retain
# their separate reviewed activation paths and are still fully inventoried.
AUTOMATIC_DEBIAN=frozenset(['openssl','openssl-provider-legacy','libssl3','libssl3t64','curl','libcurl4','libcurl4t64','ca-certificates',
    'libsqlite3-0','libseccomp2','libcap2','libacl1','libattr1','libuv1','libuv1t64','liblz4-1','libzstd1','liblzma5',
    'tar','gzip','xz-utils','zstd','squashfs-tools','libpsl5','libpsl5t64','libidn2-0','libunistring5','libc-ares2','libbrotli1','libnghttp2-14'])

def ssh_listener_proof(proc=pathlib.Path('/proc')):
    output=command(['systemctl','show','ssh.service','--property=LoadState,ActiveState,MainPID,FragmentPath,ExecStart,ExecReload,DropInPaths'],30)
    fields=dict(line.split('=',1)for line in output.splitlines()if '='in line)
    if fields.get('LoadState')!='loaded'or fields.get('ActiveState')!='active':return None
    pid=int(fields.get('MainPID','0'))
    if pid<2 or fields.get('DropInPaths','')or fields.get('FragmentPath')not in ['/usr/lib/systemd/system/ssh.service','/lib/systemd/system/ssh.service']:raise ValueError('SYSTEM_SECURITY_SSH_SERVICE_UNREVIEWED')
    for name in ['FragmentPath']:
        path=pathlib.Path(fields[name]);info=path.stat()
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    if 'argv[]=/usr/sbin/sshd -D $SSHD_OPTS ;'not in fields.get('ExecStart','')or '-HUP $MAINPID'not in fields.get('ExecReload',''):raise ValueError('SYSTEM_SECURITY_SSH_SERVICE_UNREVIEWED')
    defaults=pathlib.Path('/etc/default/ssh')
    defaults_hash=None
    if defaults.exists():
        info=defaults.lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>65536:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        if any(line.strip()and not line.lstrip().startswith('#')and not re.fullmatch(r'SSHD_OPTS=(?:""|\'\'|)',line.strip())for line in defaults.read_text().splitlines()):raise ValueError('SYSTEM_SECURITY_SSH_SERVICE_UNREVIEWED')
        defaults_hash=hashlib.sha256(defaults.read_bytes()).hexdigest()
    process=proc/str(pid)
    if (process/'ns/pid').readlink()!=(proc/'1/ns/pid').readlink()or str((process/'exe').readlink()).removesuffix(' (deleted)')!='/usr/sbin/sshd':raise ValueError('SYSTEM_SECURITY_SSH_PROCESS_CHANGED')
    raw=(process/'stat').read_text();at=raw.rfind(') ');fields_stat=raw[at+2:].split()
    if at<0 or len(fields_stat)<20:raise ValueError('SYSTEM_SECURITY_SSH_PROCESS_CHANGED')
    config=command([str(process/'exe'),'-T'],30)
    if len(config)>1024*1024:raise ValueError('SYSTEM_SECURITY_SSH_CONFIG_UNREVIEWED')
    hostkeys=hashlib.sha256()
    keys=sorted(pathlib.Path('/etc/ssh').glob('ssh_host_*_key'))
    if not keys or len(keys)>16:raise ValueError('SYSTEM_SECURITY_SSH_KEY_UNREVIEWED')
    for path in keys:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_size>65536 or info.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        hostkeys.update(path.name.encode());hostkeys.update(path.read_bytes())
    return {'pid':pid,'start':fields_stat[19],'configHash':hashlib.sha256(config.encode()).hexdigest(),
        'unitHash':hashlib.sha256(pathlib.Path(fields['FragmentPath']).read_bytes()).hexdigest(),'defaultsHash':defaults_hash,'hostKeyHash':hostkeys.hexdigest()}

def activate_ssh_listener(before):
    if before is None:return None
    current=ssh_listener_proof()
    if current!=before:raise ValueError('SYSTEM_SECURITY_SSH_PROCESS_CHANGED')
    loaded=replaced_host_mappings(all_host=True)
    if not loaded['complete']:raise ValueError('SYSTEM_SECURITY_SSH_CHECK_INCOMPLETE')
    if not any(row['pid']==before['pid']for row in loaded['processes']):return {'state':'current','pid':before['pid']}
    config=command(['/usr/sbin/sshd','-T'],30)
    if hashlib.sha256(config.encode()).hexdigest()!=before['configHash']:raise ValueError('SYSTEM_SECURITY_SSH_CONFIG_CHANGED')
    command(['/usr/sbin/sshd','-t'],30)
    command(['systemctl','reload','ssh.service'],30)
    after=None;deadline=time.monotonic()+10
    while after is None and time.monotonic()<deadline:
        after=ssh_listener_proof()
        if after is None:time.sleep(.1)
    if after is None or any(after[key]!=before[key]for key in ['configHash','unitHash','defaultsHash','hostKeyHash']):raise ValueError('SYSTEM_SECURITY_SSH_CONFIG_CHANGED')
    installed=pathlib.Path('/usr/sbin/sshd').stat();running=pathlib.Path('/proc',str(after['pid']),'exe').stat()
    loaded=replaced_host_mappings(all_host=True)
    if (installed.st_dev,installed.st_ino)!=(running.st_dev,running.st_ino)or not loaded['complete']or any(row['pid']==after['pid']for row in loaded['processes']):raise ValueError('SYSTEM_SECURITY_SSH_ACTIVATION_PENDING')
    # Existing authenticated child sessions keep their connection and old code;
    # this receipt attests to the listener for new logins, not all processes.
    return {'state':'activated','pid':after['pid'],'checkedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}

def nginx_listening_sockets(process,proc=pathlib.Path('/proc')):
    listeners=set()
    for name in ['tcp','tcp6','udp','udp6']:
        path=proc/'net'/name
        if not path.exists():continue
        data=path.read_text()
        if len(data)>2*1024*1024:raise ValueError('SYSTEM_SECURITY_NGINX_LISTENERS_UNREVIEWED')
        for line in data.splitlines()[1:]:
            fields=line.split()
            if len(fields)<10:raise ValueError('SYSTEM_SECURITY_NGINX_LISTENERS_UNREVIEWED')
            if fields[3]=='0A'or name.startswith('udp')and fields[3]=='07':listeners.add('socket:['+fields[9]+']')
    path=proc/'net/unix'
    if path.exists():
        data=path.read_text()
        if len(data)>2*1024*1024:raise ValueError('SYSTEM_SECURITY_NGINX_LISTENERS_UNREVIEWED')
        for line in data.splitlines()[1:]:
            fields=line.split()
            if len(fields)>=7 and fields[3]=='00010000':listeners.add('socket:['+fields[6]+']')
    sockets=[]
    for path in (process/'fd').iterdir():
        try:value=str(path.readlink())
        except FileNotFoundError:continue
        if value in listeners:sockets.append(value)
    return sorted(sockets)

def nginx_master_proof(pid=None):
    unit=command(['systemctl','show','nginx.service','--property=LoadState,ActiveState,MainPID,FragmentPath,DropInPaths,ExecStart,PIDFile'],30)
    fields=dict(line.split('=',1)for line in unit.splitlines()if '='in line)
    if fields.get('LoadState')!='loaded'or fields.get('ActiveState')!='active':return None
    if fields.get('DropInPaths','')or fields.get('PIDFile')!='/run/nginx.pid'or fields.get('FragmentPath')not in ['/usr/lib/systemd/system/nginx.service','/lib/systemd/system/nginx.service']or 'argv[]=/usr/sbin/nginx -g daemon on; master_process on; ;'not in fields.get('ExecStart',''):raise ValueError('SYSTEM_SECURITY_NGINX_SERVICE_UNREVIEWED')
    service_pid=int(fields.get('MainPID','0'));pid=service_pid if pid is None else pid
    process=pathlib.Path('/proc',str(pid))
    if pid<2 or (process/'ns/pid').readlink()!=pathlib.Path('/proc/1/ns/pid').readlink()or str((process/'exe').readlink()).removesuffix(' (deleted)')!='/usr/sbin/nginx':raise ValueError('SYSTEM_SECURITY_NGINX_PROCESS_CHANGED')
    command_line=(process/'cmdline').read_bytes()
    if not command_line.startswith(b'nginx: master process /usr/sbin/nginx -g daemon on; master_process on;'):raise ValueError('SYSTEM_SECURITY_NGINX_SERVICE_UNREVIEWED')
    raw=(process/'stat').read_text();at=raw.rfind(') ');stats=raw[at+2:].split()
    if at<0 or len(stats)<20:raise ValueError('SYSTEM_SECURITY_NGINX_PROCESS_CHANGED')
    unit_path=pathlib.Path(fields['FragmentPath']);info=unit_path.lstat()
    if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    configuration=command([str(process/'exe'),'-T','-g','daemon on; master_process on;'],30)
    sockets=nginx_listening_sockets(process)
    if not sockets or len(sockets)>256:raise ValueError('SYSTEM_SECURITY_NGINX_LISTENERS_UNREVIEWED')
    return {'pid':pid,'servicePID':service_pid,'start':stats[19],'configurationHash':hashlib.sha256(configuration.encode()).hexdigest(),
        'unitHash':hashlib.sha256(unit_path.read_bytes()).hexdigest(),'sockets':sockets}

def nginx_pid(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>32:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    text=path.read_text().strip()
    if not text.isdecimal()or int(text)<2:raise ValueError('SYSTEM_SECURITY_NGINX_PROCESS_CHANGED')
    return int(text)

def nginx_workers_current(master):
    loaded=replaced_host_mappings(all_host=True)
    if not loaded['complete']:return False
    old={row['pid']for row in loaded['processes']};workers=[]
    installed=pathlib.Path('/usr/sbin/nginx').stat()
    for process in pathlib.Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try:
            raw=(process/'stat').read_text();stats=raw[raw.rfind(') ')+2:].split()
            if int(stats[1])!=master or (process/'comm').read_text().strip()!='nginx':continue
            if stats[0]in ['Z','X']:continue
            mapped=(process/'exe').stat()
            if int(process.name)in old or (mapped.st_dev,mapped.st_ino)!=(installed.st_dev,installed.st_ino):return False
            workers.append(process.name)
        except FileNotFoundError:continue
    return bool(workers)

def finish_nginx_activation(before,new):
    # systemd reloads PIDFile when a forking MainPID exits. Verify the new
    # process/listeners first, then QUIT only the old master after WINCH;
    # existing old workers continue draining their established connections.
    if new['configurationHash']!=before['configurationHash']or new['unitHash']!=before['unitHash']or not set(before['sockets'])<=set(new['sockets'])or not nginx_workers_current(new['pid']):raise ValueError('SYSTEM_SECURITY_NGINX_CONFIG_CHANGED')
    current=nginx_master_proof(before['pid'])
    if current is None or current['start']!=before['start']or current['configurationHash']!=before['configurationHash']or current['unitHash']!=before['unitHash']:raise ValueError('SYSTEM_SECURITY_NGINX_PROCESS_CHANGED')
    os.kill(before['pid'],signal.SIGWINCH)
    # Do not QUIT the master until its old workers have finished active
    # requests. It retains inherited listeners as a supervised standby while
    # a long transfer drains, and a later maintenance pass completes adoption.
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        workers=False
        for process in pathlib.Path('/proc').iterdir():
            if not process.name.isdigit():continue
            try:
                raw=(process/'stat').read_text();stats=raw[raw.rfind(') ')+2:].split()
                if int(stats[1])==before['pid']and stats[0]not in ['Z','X']and (process/'comm').read_text().strip()=='nginx'and int(process.name)!=new['pid']:workers=True;break
            except FileNotFoundError:continue
        if not workers:break
        time.sleep(.1)
    if workers:return {'state':'draining','pid':new['pid'],'supervisedStandbyPID':before['pid'],'checkedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
    current=nginx_master_proof(before['pid'])
    if current is None or current['start']!=before['start']or not nginx_workers_current(new['pid']):raise ValueError('SYSTEM_SECURITY_NGINX_PROCESS_CHANGED')
    os.kill(before['pid'],signal.SIGQUIT)
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        # The supervised old PID may be gracefully draining and have closed
        # its own listen sockets. Wait for systemd's PIDFile adoption before
        # collecting the new master's listener proof.
        current=int(command(['systemctl','show','nginx.service','--property=MainPID','--value'],10))
        proof=nginx_master_proof()if current==new['pid']else None
        if proof is not None and proof['pid']==new['pid']and proof['configurationHash']==before['configurationHash']and proof['unitHash']==before['unitHash']and nginx_workers_current(proof['pid']):
            return {'state':'activated','pid':proof['pid'],'checkedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
        time.sleep(.1)
    raise ValueError('SYSTEM_SECURITY_NGINX_SUPERVISOR_PENDING')

def activate_nginx_master(before):
    if before is None:return None
    if nginx_master_proof()!=before:raise ValueError('SYSTEM_SECURITY_NGINX_PROCESS_CHANGED')
    oldbin=pathlib.Path('/run/nginx.pid.oldbin');current_pid=pathlib.Path('/run/nginx.pid')
    # Resume only the original PIDFile handoff; never start a third master.
    if oldbin.exists():
        if nginx_pid(oldbin)!=before['pid']:raise ValueError('SYSTEM_SECURITY_NGINX_PROCESS_CHANGED')
        new=nginx_master_proof(nginx_pid(current_pid))
        if new is None or new['configurationHash']!=before['configurationHash']or new['unitHash']!=before['unitHash']or not set(before['sockets'])<=set(new['sockets'])or not nginx_workers_current(new['pid']):raise ValueError('SYSTEM_SECURITY_NGINX_ACTIVATION_PENDING')
        return finish_nginx_activation(before,new)
    loaded=replaced_host_mappings(all_host=True)
    if not loaded['complete']:raise ValueError('SYSTEM_SECURITY_NGINX_CHECK_INCOMPLETE')
    if not any(row['service']=='nginx'for row in loaded['processes']):return {'state':'current','pid':before['pid']}
    configuration=command(['/usr/sbin/nginx','-T','-g','daemon on; master_process on;'],30)
    if hashlib.sha256(configuration.encode()).hexdigest()!=before['configurationHash']:raise ValueError('SYSTEM_SECURITY_NGINX_CONFIG_CHANGED')
    command(['/usr/sbin/nginx','-t'],30)
    if nginx_master_proof()!=before:raise ValueError('SYSTEM_SECURITY_NGINX_PROCESS_CHANGED')
    os.kill(before['pid'],signal.SIGUSR2)
    new=None;deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        try:
            if oldbin.exists()and nginx_pid(oldbin)==before['pid']:
                candidate=nginx_master_proof(nginx_pid(current_pid))
                if candidate is not None and candidate['pid']!=before['pid']and nginx_workers_current(candidate['pid']):new=candidate;break
        except FileNotFoundError:pass
        time.sleep(.1)
    if new is None:raise ValueError('SYSTEM_SECURITY_NGINX_ACTIVATION_PENDING')
    if new['configurationHash']!=before['configurationHash']or new['unitHash']!=before['unitHash']or not set(before['sockets'])<=set(new['sockets']):raise ValueError('SYSTEM_SECURITY_NGINX_CONFIG_CHANGED')
    return finish_nginx_activation(before,new)

def managed_clock_security_proof():
    helper=pathlib.Path('/usr/local/libexec/incudal/ensure-time-sync.py')
    config=pathlib.Path('/etc/chrony/incudal-clock.conf');unit=pathlib.Path('/etc/systemd/system/incudal-clock.service')
    if not helper.exists()or not config.exists()or not unit.exists():return None
    for path in [helper,config,unit]:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>262144:raise ValueError('SYSTEM_SECURITY_CLOCK_SERVICE_UNREVIEWED')
    expected_config='# payincus-time-sync-v1\npool pool.ntp.org iburst maxsources 4\ndriftfile /var/lib/chrony/incudal-clock/chrony.drift\nrtcsync\nmaxslewrate 10000\ncmdport 0\n'
    if config.read_text()!=expected_config:raise ValueError('SYSTEM_SECURITY_CLOCK_SERVICE_UNREVIEWED')
    value=dict(line.split('=',1)for line in command(['systemctl','show','incudal-clock.service','--property=MainPID,ActiveState,FragmentPath,DropInPaths,Environment'],20).splitlines()if '='in line)
    if value.get('FragmentPath')!=str(unit)or value.get('DropInPaths','')or value.get('Environment',''):raise ValueError('SYSTEM_SECURITY_CLOCK_SERVICE_UNREVIEWED')
    if value.get('ActiveState')!='active'or int(value.get('MainPID','0'))<2:return None
    pid=int(value['MainPID']);process=pathlib.Path('/proc',str(pid))
    binary=str((process/'exe').readlink()).removesuffix(' (deleted)')
    if (process/'ns/pid').readlink()!=pathlib.Path('/proc/1/ns/pid').readlink()or not os.path.samestat((process/'root').stat(),pathlib.Path('/').stat())or binary not in ['/usr/sbin/chronyd','/sbin/chronyd']:raise ValueError('SYSTEM_SECURITY_CLOCK_PROCESS_CHANGED')
    expected_unit='# payincus-time-sync-v1\n[Unit]\nDescription=PayIncus continuous clock synchronization\nWants=network-online.target\nAfter=network-online.target\n[Service]\nType=simple\nRuntimeDirectory=chrony\nRuntimeDirectoryMode=0750\nExecStartPre=/usr/bin/install -d -m 0750 -o _chrony -g _chrony /run/chrony\nExecStart='+binary+' -d -f /etc/chrony/incudal-clock.conf\nRestart=on-failure\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n'
    if unit.read_text()!=expected_unit:raise ValueError('SYSTEM_SECURITY_CLOCK_SERVICE_UNREVIEWED')
    with (process/'cmdline').open('rb')as source:args=source.read(4097)
    if args!=os.fsencode(binary)+b'\0-d\0-f\0/etc/chrony/incudal-clock.conf\0':raise ValueError('SYSTEM_SECURITY_CLOCK_PROCESS_CHANGED')
    raw=(process/'stat').read_text();at=raw.rfind(') ');fields=raw[at+2:].split()
    if at<0 or len(raw)>8192 or len(fields)<20:raise ValueError('SYSTEM_SECURITY_CLOCK_PROCESS_CHANGED')
    return {'pid':pid,'start':fields[19],'configurationHash':hashlib.sha256(config.read_bytes()+unit.read_bytes()).hexdigest(),'helperHash':hashlib.sha256(helper.read_bytes()).hexdigest()}

def activate_managed_clock(before):
    if before is None:return None
    if managed_clock_security_proof()!=before:raise ValueError('SYSTEM_SECURITY_CLOCK_PROCESS_CHANGED')
    helper=pathlib.Path('/usr/local/libexec/incudal/ensure-time-sync.py')
    result=json.loads(command(['/usr/bin/python3','-I','-B',str(helper),'--activate-security'],90))
    after=managed_clock_security_proof()
    if after is None or after['configurationHash']!=before['configurationHash']or after['helperHash']!=before['helperHash']or result.get('state')not in ['current','activated']:raise ValueError('SYSTEM_SECURITY_CLOCK_ACTIVATION_PENDING')
    return {'state':result['state'],'pid':after['pid'],'synchronized':result.get('synchronized')is True}

def service_activation_receipt(operation,before):
    try:return operation(before)
    except (ValueError,OSError,subprocess.SubprocessError,json.JSONDecodeError)as error:
        code=str(error)
        if not re.fullmatch(r'SYSTEM_SECURITY_[A-Z_]{1,100}',code):code='SYSTEM_SECURITY_SERVICE_ACTIVATION_PENDING'
        # A service failure cannot suppress activation of other components or
        # overwrite an already completed signed package transaction as failed.
        return {'state':'pending','error':code}

def live_process_group(group,proc=pathlib.Path('/proc')):
    checked=0
    for path in proc.iterdir():
        if not path.name.isdigit():continue
        checked+=1
        if checked>65536:raise ValueError('SYSTEM_SECURITY_PROCESS_BUDGET_EXCEEDED')
        if proc==pathlib.Path('/proc'):
            try:actual_group=os.getpgid(int(path.name))
            except ProcessLookupError:continue
            if actual_group!=group:continue
        try:raw=(path/'stat').read_text()
        except (FileNotFoundError,ProcessLookupError):continue
        if len(raw)>8192:raise ValueError('SYSTEM_SECURITY_PROCESS_BUDGET_EXCEEDED')
        at=raw.rfind(') ');fields=raw[at+2:].split()
        if at<0 or len(fields)<3:raise ValueError('SYSTEM_SECURITY_PROCESS_QUERY_FAILED')
        if int(fields[2])==group and fields[0]not in ['Z','X']:return True
    return False

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
        if live_process_group(process.pid):
            os.killpg(process.pid,signal.SIGKILL)
            raise ValueError('SYSTEM_SECURITY_PACKAGE_CHILD_PENDING')
        if os.fstat(out.fileno()).st_size+os.fstat(error.fileno()).st_size>2*1024*1024:raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
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
        names=set(DEBIAN)|{'postgresql-'+str(n)for n in range(14,19)}|{'postgresql-client-'+str(n)for n in range(14,19)}|{'linux-image-amd64','linux-image-arm64','linux-image-'+os.uname().release}
        packages=reviewed_debian_inventory(debian_installed_packages(),names)
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
        dated=name=='ca-certificates'and re.fullmatch(r'[0-9]{8}(?:[+~._-][a-zA-Z0-9.+~_-]+)?',old)and re.fullmatch(r'[0-9]{8}(?:[+~._-][a-zA-Z0-9.+~_-]+)?',new)
        if name not in allowed or installed.get(name)!=old or not dated and (not major(old)or major(old)!=major(new)):raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
        # Debian version ordering includes epochs, tildes and distro revisions;
        # a same-major comparison alone must never authorize a downgrade.
        check=subprocess.run(['dpkg','--compare-versions',new,'gt',old],capture_output=True,timeout=5)
        if check.returncode:raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
        changes.append(name+'='+new)
    if len(changes)>64 or len(changes)!=len({item.split('=',1)[0]for item in changes}):raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
    return changes

def debian_installed_packages():
    return {key:value['version']for key,value in debian_package_states().items()if value['status']=='installed'}

def debian_package_states():
    output=command(['dpkg-query','-W','-f=${Package}\t${Architecture}\t${db:Status-Status}\t${Version}\n'],30)
    packages={}
    for line in output.splitlines():
        fields=line.split('\t')
        if len(fields)!=4:raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
        name,architecture,status,version=fields
        if status in ['not-installed','config-files']:continue
        if status not in ['installed','unpacked','half-configured','half-installed','triggers-awaited','triggers-pending']:raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
        if not re.fullmatch(r'[a-z0-9+.-]+',name)or not re.fullmatch(r'[a-z0-9-]+',architecture)or not re.fullmatch(r'[^\s\x00-\x1f]{1,200}',version):raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
        identity=name+':'+architecture
        if identity in packages or len(packages)>=20000:raise ValueError('SYSTEM_SECURITY_PACKAGE_QUERY_FAILED')
        packages[identity]={'version':version,'status':status}
    return packages

def reviewed_debian_inventory(installed,names):
    # One complete bounded dpkg snapshot replaces dozens of independent reads.
    # Query failures cannot silently turn a missing security component green.
    packages={}
    for identity,version in installed.items():
        name,architecture=identity.split(':',1)
        if name not in names:continue
        if name in packages:raise ValueError('SYSTEM_SECURITY_MULTIARCH_REVIEW_REQUIRED')
        packages[name]=version
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
    fd=open_platform_operation_lock(False)
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

def apply_patches(automatic=False):
    # Automatic mode is limited to reviewed tools and shared libraries; the
    # explicit root action retains the full inventory policy. dpkg suppresses
    # service restarts during installation; actual activation stays visible as
    # pending until the operator uses the service's reviewed maintenance path.
    if os.geteuid()!=0:raise ValueError('SYSTEM_SECURITY_ROOT_REQUIRED')
    if pathlib.Path('/var/lib/incudal-backup/recovery-hold.json').exists():raise ValueError('SYSTEM_SECURITY_RECOVERY_HELD')
    release=dict(line.split('=',1)for line in pathlib.Path('/etc/os-release').read_text().splitlines()if '='in line)
    distribution=release.get('ID','').strip('"')
    if distribution not in ['debian','ubuntu']:raise ValueError('SYSTEM_SECURITY_DISTRIBUTION_UNSUPPORTED')
    value={'version':1,'distribution':distribution,'checkedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
    allowed=set(AUTOMATIC_DEBIAN)if automatic else set(DEBIAN)|{'postgresql-'+str(n) for n in range(14,19)}
    sources=[pathlib.Path('/etc/apt/sources.list'),*pathlib.Path('/etc/apt/sources.list.d').glob('*')]
    for source in sources:
        if not source.is_file():continue
        if source.stat().st_size>1024*1024:raise ValueError('SYSTEM_SECURITY_REPOSITORY_UNTRUSTED')
        if source.is_symlink() or source.stat().st_uid!=0 or source.stat().st_mode&0o022:raise ValueError('SYSTEM_SECURITY_REPOSITORY_UNTRUSTED')
        if re.search(r'trusted\s*=\s*yes|Trusted:\s*yes|Allow-Insecure:\s*yes',source.read_text(),re.I):raise ValueError('SYSTEM_SECURITY_REPOSITORY_UNTRUSTED')
    lock=pathlib.Path('/var/lib/incudal-system-security');lock.mkdir(mode=0o700,exist_ok=True)
    if lock.is_symlink() or lock.stat().st_uid!=0 or lock.stat().st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    fd=open_platform_operation_lock()
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:os.close(fd);raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            if automatic:return None
            raise
        if pathlib.Path('/var/lib/incudal-backup/recovery-hold.json').exists():raise ValueError('SYSTEM_SECURITY_RECOVERY_HELD')
        # Routine checks must catch code tampering before any repository or
        # service mutation. Never reseal or stop customer instances here.
        if automatic:verify_runtime_integrity()
        recovered=recover_runtime_maintenance()if automatic else None
        if recovered:
            value=inventory(all_loaded_code=True);value['patchPlan']=recovered['packages'];value['patchState']='installed-activation-required'
            value['backendActivation']={'state':'activated','pid':recovered['activatedBackendPID'],'backup':recovered['backup']}
            if recovered.get('database'):value['databaseActivation']={'state':'activated','pid':recovered['activatedDatabasePID']}
            defer_security_check(value);persist(value,verify_activation=True);return value
        status=lock/'status.json'
        if automatic and status.exists():
            info=status.lstat()
            if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077 or info.st_size>128*1024:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
            previous=json.loads(status.read_text())
            if not security_patch_check_due(previous):
                # The five-minute timer observes a durable deadline instead of
                # hitting all package repositories on every tick.
                return None
        # Recheck installed versions after owning the maintenance lane. A
        # concurrent authorized updater may have completed since discovery.
        value=inventory()
        runtime_before=None;runtime_error=None
        if automatic and 'nodejs'in value['packages']:
            try:runtime_before=backend_runtime_proof()
            except (ValueError,OSError):runtime_error='SYSTEM_SECURITY_BACKEND_UNREVIEWED'
        database_before=None;database_error=None
        if automatic and any(name.startswith('postgresql-')and name.removeprefix('postgresql-').isdigit()for name in value['packages']):
            try:database_before=database_runtime_proof()
            except (ValueError,OSError)as error:
                database_error='SYSTEM_SECURITY_DATABASE_UNREVIEWED'
                # A verified local application DB still supports a Node-only
                # patch. Shared databases/clients prohibit restarting PG, not
                # draining this application's sole backend. No shared data or
                # service is stopped or included in our database dumps.
                if isinstance(error,ValueError)and str(error)=='SYSTEM_SECURITY_DATABASE_SHARED_OR_REPLICATED':
                    try:database_before=database_runtime_proof(shared_read_only=True)
                    except (ValueError,OSError):pass
            if runtime_before is not None and database_before is not None:
                allowed.add('nodejs')
                if not database_before.get('sharedReadOnly'):
                    allowed|={'postgresql-'+str(database_before['major']),'postgresql-client-'+str(database_before['major']),'libpq5','postgresql-common','postgresql-client-common'}
        ssh_before=None;ssh_error=None
        if automatic and 'openssh-server'in value['packages']:
            try:ssh_before=ssh_listener_proof()
            except (ValueError,OSError):ssh_error='SYSTEM_SECURITY_SSH_SERVICE_UNREVIEWED'
            if ssh_before is not None:allowed|={'openssh-server','openssh-client','openssh-sftp-server'}
        nginx_before=None;nginx_error=None
        if automatic and 'nginx'in value['packages']:
            try:nginx_before=nginx_master_proof()
            except (ValueError,OSError):nginx_error='SYSTEM_SECURITY_NGINX_SERVICE_UNREVIEWED'
            if nginx_before is not None and not pathlib.Path('/run/nginx.pid.oldbin').exists():allowed|={'nginx','nginx-common'}
        clock_before=None;clock_error=None
        if automatic and 'chrony'in value['packages']:
            try:clock_before=managed_clock_security_proof()
            except (ValueError,OSError):clock_error='SYSTEM_SECURITY_CLOCK_SERVICE_UNREVIEWED'
            if clock_before is not None:allowed.add('chrony')
        clean_service_policy()
        command(['apt-get','-o','Acquire::AllowInsecureRepositories=false','-o','Acquire::AllowDowngradeToInsecureRepositories=false','-o','Acquire::AllowWeakRepositories=false','update'],180)
        names=sorted(set(value['packages'])&allowed)
        if not names:return value
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
            runtime_plan=[item for item in changes if item.split('=',1)[0]=='nodejs' or item.split('=',1)[0].startswith('postgresql-')or item.split('=',1)[0]in ['libpq5','postgresql-common']]
            if automatic and runtime_plan:
                install_runtime_patches(changes,runtime_before,database_before,value,expected)
            else:
                prepare_service_policy()
                try:command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','-o','Dpkg::Options::=--force-confold','--assume-yes','--only-upgrade','--no-remove','install',*changes],600)
                finally:
                    clean_service_policy()
            if debian_installed_packages()!=expected:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')
        after=inventory(all_loaded_code=True)
        # A prior package install can leave the same executable mapped against
        # old libraries. A no-op apt plan must still finish the reviewed runtime
        # activation; it does not reinstall packages or restart shared PG.
        if automatic and runtime_before is not None and database_before is not None and not value.get('backendActivation'):
            try:activate_runtime_libraries(runtime_before,database_before,after)
            except (ValueError,OSError)as error:
                code=str(error)
                if not re.fullmatch(r'SYSTEM_SECURITY_[A-Z_]{1,100}',code):code='SYSTEM_SECURITY_RUNTIME_ACTIVATION_PENDING'
                after['backendActivation']={'state':'pending','error':code}
            after['loadedCode']=replaced_host_mappings(all_host=True)
        for receipt in ['backendActivation','databaseActivation']:
            if value.get(receipt):after[receipt]=value[receipt]
        if runtime_error:after['backendActivation']={'state':'pending','error':runtime_error}
        if database_error:after['databaseActivation']={'state':'pending','error':database_error}
        for package in changes:
            name,version=package.split('=',1)
            if after['packages'].get(name)!=version:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')
        if automatic and ssh_before is not None:
            after['sshListenerActivation']=service_activation_receipt(activate_ssh_listener,ssh_before)
            after['loadedCode']=replaced_host_mappings(all_host=True)
        elif ssh_error:after['sshListenerActivation']={'state':'pending','error':ssh_error}
        if automatic and nginx_before is not None:
            after['nginxActivation']=service_activation_receipt(activate_nginx_master,nginx_before)
            after['loadedCode']=replaced_host_mappings(all_host=True)
        elif nginx_error:after['nginxActivation']={'state':'pending','error':nginx_error}
        if automatic and clock_before is not None:
            after['clockActivation']=service_activation_receipt(activate_managed_clock,clock_before)
            after['loadedCode']=replaced_host_mappings(all_host=True)
        elif clock_error:after['clockActivation']={'state':'pending','error':clock_error}
        value=after;value['patchPlan']=changes;value['patchState']='installed-activation-required' if changes else 'current'
        if automatic:defer_security_check(value)
        persist(value,verify_activation=True)
        return value
    except Exception:
        value['patchState']='failed';value['error']='SYSTEM_SECURITY_PATCH_NOT_CONFIRMED'
        if automatic:defer_security_check(value)
        persist(value)
        raise
    finally:os.close(fd)

def maintain_system_packages():
    if os.geteuid()!=0:raise ValueError('SYSTEM_SECURITY_ROOT_REQUIRED')
    # Recovery and an already active maintenance transaction preserve their
    # previous receipt. A busy lane is not an unsuccessful patch transaction.
    if pathlib.Path('/var/lib/incudal-backup/recovery-hold.json').exists():return
    value=apply_patches(automatic=True)
    if value is not None:print(json.dumps(value,separators=(',',':')))

def maintenance_needs_prompt_retry(value):
    return value.get('patchState')in ['prepared','failed']or value.get('activationRequired')or any(isinstance(value.get(key),dict)and value[key].get('state')in ['draining','pending']for key in ['nginxActivation','sshListenerActivation','clockActivation','backendActivation','databaseActivation'])

def protected_hash(path,owners=(0,),private=False):
    path=pathlib.Path(path);info=path.lstat()
    if not stat.S_ISREG(info.st_mode)or info.st_uid not in owners or info.st_nlink!=1 or info.st_mode&(0o077 if private else 0o022)or info.st_size>1048576:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    return hashlib.sha256(path.read_bytes()).hexdigest()

def backend_service_policy():
    values=dict(line.split('=',1)for line in command(['systemctl','show','incudal-backend.service','--property=ActiveState,MainPID,User,Group,WorkingDirectory,TimeoutStartUSec,TimeoutStopUSec,ExecStart,ExecStartPre,ExecStartPost,ExecStop,Environment,EnvironmentFiles,DropInPaths'],20).splitlines()if '='in line)
    if values.get('User')!='incudal'or values.get('Group')!='incudal'or values.get('WorkingDirectory')not in ['/opt/incudal','/opt/incudal/current']:raise ValueError('SYSTEM_SECURITY_BACKEND_UNREVIEWED')
    if values.get('TimeoutStopUSec')!='35min':raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_POLICY_REQUIRED')
    if values.get('ExecStop',''):raise ValueError('SYSTEM_SECURITY_BACKEND_UNREVIEWED')
    app=pathlib.Path(values['WorkingDirectory']).resolve()
    if not (str(app)=='/opt/incudal'or str(app).startswith('/opt/incudal/releases/')):raise ValueError('SYSTEM_SECURITY_BACKEND_UNREVIEWED')
    unit_data=command(['systemctl','show','incudal-backend.service','--property=FragmentPath,DropInPaths'],20)
    unit_fields=dict(line.split('=',1)for line in unit_data.splitlines()if '='in line)
    if unit_fields.get('FragmentPath')!='/etc/systemd/system/incudal-backend.service':raise ValueError('SYSTEM_SECURITY_BACKEND_UNREVIEWED')
    allowed_dropins=['/etc/systemd/system/incudal-backend.service.d/platform-backup.conf','/etc/systemd/system/incudal-backend.service.d/zz-database-security.conf','/etc/systemd/system/incudal-backend.service.d/local-gateway.conf']
    if any(path not in allowed_dropins for path in unit_fields.get('DropInPaths','').split()):raise ValueError('SYSTEM_SECURITY_BACKEND_UNREVIEWED')
    units=[unit_fields['FragmentPath'],*unit_fields.get('DropInPaths','').split()]
    unit_hashes={path:protected_hash(path)for path in units}
    expected_start='argv[]=/usr/bin/node '+str(app/'server/dist/app.js')+' ;'
    if expected_start not in values.get('ExecStart','')and 'argv[]=/usr/bin/node /opt/incudal/current/server/dist/app.js ;'not in values.get('ExecStart',''):raise ValueError('SYSTEM_SECURITY_BACKEND_UNREVIEWED')
    if values.get('EnvironmentFiles')not in ['/opt/incudal/.env (ignore_errors=no)','/opt/incudal/.env (ignore_errors=yes)']:raise ValueError('SYSTEM_SECURITY_BACKEND_UNREVIEWED')
    stable={key:(re.findall(r'argv\[\]=(.*?) ;',value)if key.startswith('Exec')else value)for key,value in values.items()if key not in ['ActiveState','MainPID']}
    service_hash=hashlib.sha256(json.dumps(stable,sort_keys=True).encode()).hexdigest()
    return values,app,unit_hashes,service_hash

def backend_runtime_proof():
    values,app,unit_hashes,service_hash=backend_service_policy()
    if values.get('ActiveState')!='active':return None
    pid=int(values.get('MainPID','0'))
    process=pathlib.Path('/proc',str(pid))
    if pid<2 or str((process/'exe').readlink()).removesuffix(' (deleted)')!='/usr/bin/node':raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    if (process/'ns/pid').readlink()!=pathlib.Path('/proc/1/ns/pid').readlink():raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    import pwd
    user_id=pwd.getpwnam('incudal').pw_uid
    process_uid=re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',(process/'status').read_text(),re.M)
    if not process_uid or any(int(value)!=user_id for value in process_uid.groups()):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    argv=[x.decode()for x in (process/'cmdline').read_bytes().split(b'\0')if x]
    if len(argv)!=2 or argv[0]!='/usr/bin/node'or pathlib.Path(argv[1]).resolve()!=app/'server/dist/app.js':raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    # Unknown parallel backends cannot be treated as the supported one writer.
    deadline=time.monotonic()+5;count=0
    for other in pathlib.Path('/proc').iterdir():
        if not other.name.isdigit()or int(other.name)==pid:continue
        count+=1
        if count>65536 or time.monotonic()>deadline:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHECK_INCOMPLETE')
        try:
            commandline=(other/'cmdline').read_bytes()
            if len(commandline)>65536:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHECK_INCOMPLETE')
            arguments=commandline.split(b'\0')
            if (other/'ns/pid').readlink()!=pathlib.Path('/proc/1/ns/pid').readlink():continue
            if any(re.fullmatch(rb'/opt/incudal/(?:releases/[A-Za-z0-9._-]+/|current/)?server/dist/app\.js',argument)for argument in arguments):raise ValueError('SYSTEM_SECURITY_BACKEND_MULTIPLE_WRITERS')
        except(FileNotFoundError,ProcessLookupError):pass
    raw=(process/'stat').read_text();parts=raw[raw.rfind(') ')+2:].split()
    if len(parts)<20:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    if command(['systemctl','show','incudal-backend.service','--property=Result','--value'],20)!='success':raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    app=pathlib.Path(app)
    for required in ['server/dist/lib/financial-integrity.js','server/dist/lib/authentication-integrity.js']:
        protected_hash(app/required)
    return {'pid':pid,'start':parts[19],'app':str(app),'environmentHash':protected_hash('/opt/incudal/.env'),
        'codeHash':protected_hash(app/'server/dist/app.js'),'unitHashes':unit_hashes,
        # ExecStart also contains per-launch pid, timestamps and exit status.
        # Hash the reviewed argv and persistent policy, with runtime identity
        # attested separately by /proc start time, exe and command line.
        'serviceHash':service_hash}

def database_settings_hashes(settings):
    if not isinstance(settings,list)or not settings or len(settings)>10000:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
    legacy=[];effective=[];names=set()
    for row in settings:
        if not isinstance(row,list)or len(row)!=4 or any(not isinstance(value,str)for value in row)or row[0]in names:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
        name,setting,source,context=row;names.add(name)
        legacy.append(row[:3])
        # The installer retains localhost and adds its local-only include.
        # PostgreSQL keeps the default source until its first restart even
        # when the parsed setting is identical. Preserve every effective
        # value and all other sources; file hashes still attest the include.
        if name=='listen_addresses'and setting=='localhost'and context=='postmaster'and source in ['default','configuration file']:source='retained-local-listener'
        effective.append([name,setting,source])
    digest=lambda rows:hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest()
    return digest(effective),digest(legacy)

def database_runtime_proof(shared_read_only=False):
    sql="SELECT json_build_object('major',current_setting('server_version_num')::int/10000,'version',current_setting('server_version_num'),'data',current_setting('data_directory'),'config',current_setting('config_file'),'hba',current_setting('hba_file'),'recovery',pg_is_in_recovery(),'replication',(SELECT count(*) FROM pg_stat_replication),'otherDatabases',(SELECT count(*)FROM pg_database WHERE NOT datistemplate AND datname NOT IN('incudal','postgres')),'otherClients',(SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend'AND pid<>pg_backend_pid()AND(coalesce(datname,'')<>'incudal'OR usename NOT IN('incudal','incudal_migrate'))))"
    value=json.loads(command(['runuser','-u','postgres','--','psql','-X','-At','-v','ON_ERROR_STOP=1','-d','incudal','-c',sql],20))
    environment=pathlib.Path('/opt/incudal/.env').read_text()
    matches=re.findall(r'^DATABASE_URL=(.+)$',environment,re.M)
    if len(matches)!=1 or not re.fullmatch(r"['\"]?postgres(?:ql)?://incudal:[^\s]+@(?:127\.0\.0\.1|localhost):5432/incudal(?:\?[^'\"\s]*)?['\"]?",matches[0]):raise ValueError('SYSTEM_SECURITY_DATABASE_IDENTITY_UNREVIEWED')
    if value['recovery']or value['replication']or value['major']not in [14,15,16,17,18]or not shared_read_only and (value['otherDatabases']or value['otherClients']):raise ValueError('SYSTEM_SECURITY_DATABASE_SHARED_OR_REPLICATED')
    if shared_read_only:value['sharedReadOnly']=True
    major=value['major'];expected='/var/lib/postgresql/'+str(major)+'/main'
    if value['data']!=expected or value['config']!='/etc/postgresql/'+str(major)+'/main/postgresql.conf'or value['hba']!='/etc/postgresql/'+str(major)+'/main/pg_hba.conf':raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    value['configHash']=protected_hash(value['config'],(0,pathlib.Path(expected).stat().st_uid));value['hbaHash']=protected_hash(value['hba'],(0,pathlib.Path(expected).stat().st_uid))
    value['unit']='postgresql@'+str(major)+'-main.service'
    clusters=json.loads(command(['pg_lsclusters','--json'],20))
    if not isinstance(clusters,list)or any(not isinstance(row,dict)or row.get('running')not in [0,1]for row in clusters):raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    if any(row['running']==1 and (row.get('version')!=str(major)or row.get('cluster')!='main')for row in clusters):raise ValueError('SYSTEM_SECURITY_DATABASE_MULTIPLE_CLUSTERS')
    if command(['systemctl','is-active',value['unit']],20)!='active':raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    service=dict(line.split('=',1)for line in command(['systemctl','show',value['unit'],'--property=MainPID,ExecStart,ExecStop,FragmentPath,DropInPaths'],20).splitlines()if '='in line)
    if service.get('DropInPaths')or service.get('FragmentPath')not in ['/lib/systemd/system/postgresql@.service','/usr/lib/systemd/system/postgresql@.service']:raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    start='argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect '+str(major)+'-main start ;'
    stop='argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect -m fast '+str(major)+'-main stop ;'
    if start not in service.get('ExecStart','')or stop not in service.get('ExecStop',''):raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    value['unitHash']=protected_hash(service['FragmentPath'])
    value['pid']=int(service.get('MainPID','0'));process=pathlib.Path('/proc',str(value['pid']))
    if value['pid']<2 or str((process/'exe').readlink()).removesuffix(' (deleted)')!='/usr/lib/postgresql/'+str(major)+'/bin/postgres':raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    if (process/'ns/pid').readlink()!=pathlib.Path('/proc/1/ns/pid').readlink():raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    value['start']=(process/'stat').read_text().split(') ',1)[1].split()[19]
    # Include effective settings and every parsed include, not just the two
    # main files. Preserve ALTER SYSTEM and administrator configuration.
    settings=json.loads(command(['runuser','-u','postgres','--','psql','-X','-At','-d','incudal','-c',"SELECT json_build_object('settings',(SELECT json_agg(json_build_array(name,setting,source,context)ORDER BY name)FROM pg_settings WHERE name NOT IN ('server_version','server_version_num')),'files',(SELECT json_agg(DISTINCT sourcefile)FROM pg_file_settings),'invalid',(SELECT count(*)FROM pg_file_settings WHERE error IS NOT NULL),'pending',(SELECT count(*)FROM pg_settings WHERE pending_restart))"],20))
    if settings['invalid']or not isinstance(settings['files'],list)or len(settings['files'])>64:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
    if settings['pending']:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_RESTART_REQUIRED')
    value['settingsHash'],value['settingsLegacyHash']=database_settings_hashes(settings['settings']);value['settingsHashVersion']=2
    paths=set(settings['files'])|{expected+'/postgresql.auto.conf','/etc/postgresql/'+str(major)+'/main/pg_ctl.conf','/etc/postgresql/'+str(major)+'/main/start.conf'}
    if any(not isinstance(path,str)or not(path.startswith('/etc/postgresql/'+str(major)+'/main/')or path==expected+'/postgresql.auto.conf')for path in paths):raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    value['fileHashes']={path:protected_hash(path,(0,pathlib.Path(expected).stat().st_uid))for path in sorted(paths)}
    return value

def activate_runtime_libraries(backend,database,value):
    def replaced(pid,program):
        installed=pathlib.Path(program).stat();running=pathlib.Path('/proc',str(pid),'exe').stat()
        return (installed.st_dev,installed.st_ino)!=(running.st_dev,running.st_ino)or runtime_process_has_replaced_libraries(pid)
    need_backend=replaced(backend['pid'],'/usr/bin/node')
    need_database=not database.get('sharedReadOnly')and replaced(database['pid'],'/usr/lib/postgresql/'+str(database['major'])+'/bin/postgres')
    if not need_backend and not need_database:return
    if backend_runtime_proof()!=backend:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    def database_proof():return database_runtime_proof(shared_read_only=True)if database.get('sharedReadOnly')else database_runtime_proof()
    if database_proof()!=database:raise ValueError('SYSTEM_SECURITY_DATABASE_CHANGED')
    if command(['dpkg','--audit'],30):raise ValueError('SYSTEM_SECURITY_PACKAGE_CONFIGURATION_PENDING')
    baseline=debian_installed_packages()
    backup=pathlib.Path('/var/lib/incudal-system-security')/('runtime-backup-'+uuid.uuid4().hex);backup.mkdir(mode=0o700)
    size=int(command(['runuser','-u','postgres','--','psql','-X','-At','-d','incudal','-c',"SELECT pg_database_size('incudal')"],20))
    filesystem=os.statvfs(backup)
    if size<0 or filesystem.f_bavail*filesystem.f_frsize<max(size*3,128*1024*1024):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_SPACE_REQUIRED')
    dump_runtime_database(backup/'database.dump')
    verify_runtime_financial_integrity(backend['app'])
    if backend_runtime_proof()!=backend or database_proof()!=database or debian_installed_packages()!=baseline:raise ValueError('SYSTEM_SECURITY_RUNTIME_BASELINE_CHANGED')
    journal={'version':1,'phase':'prepared','activationOnly':True,'backend':backend,'database':database if need_database else None,
        'backup':backup.name,'packages':[],'baselinePackages':baseline,'expectedPackages':baseline}
    write_runtime_maintenance(journal)
    stopped=False
    try:
        journal['phase']='stopping-backend';write_runtime_maintenance(journal);stopped=True
        command(['systemctl','stop','incudal-backend.service'],36*60)
        if command(['systemctl','show','incudal-backend.service','--property=MainPID','--value'],20)!='0':raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_PENDING')
        if command(['systemctl','show','incudal-backend.service','--property=Result','--value'],20)!='success':raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
        journal['drainConfirmed']=True;write_runtime_maintenance(journal)
        dump_runtime_database(backup/'database-after-drain.dump')
        if need_database:
            if database_proof()!=database:raise ValueError('SYSTEM_SECURITY_DATABASE_CHANGED')
            journal['phase']='stopping-database';write_runtime_maintenance(journal)
            command(['systemctl','stop',database['unit']],180)
            state=dict(line.split('=',1)for line in command(['systemctl','show',database['unit'],'--property=MainPID,ActiveState,Result'],20).splitlines()if '='in line)
            if state.get('MainPID')!='0'or state.get('ActiveState')!='inactive'or state.get('Result')!='success':raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
    finally:
        if stopped:completed=recover_runtime_maintenance()
    if not completed or completed.get('phase')!='activated':raise ValueError('SYSTEM_SECURITY_RUNTIME_ACTIVATION_PENDING')
    value['backendActivation']={'state':'activated','pid':completed['activatedBackendPID'],'backup':backup.name,'activationOnly':True}
    if need_database:value['databaseActivation']={'state':'activated','pid':completed['activatedDatabasePID'],'activationOnly':True}

def install_runtime_patches(changes,backend,database,value,expected):
    if backend is None or backend_runtime_proof()!=backend:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    need_database=any(item.split('=',1)[0].startswith('postgresql-')or item.split('=',1)[0]in ['libpq5','postgresql-common']for item in changes)
    if database is None or need_database and database.get('sharedReadOnly'):raise ValueError('SYSTEM_SECURITY_DATABASE_CHANGED')
    def database_proof():
        return database_runtime_proof(shared_read_only=True)if database.get('sharedReadOnly')else database_runtime_proof()
    if database_proof()!=database:raise ValueError('SYSTEM_SECURITY_DATABASE_CHANGED')
    if command(['dpkg','--audit'],30):raise ValueError('SYSTEM_SECURITY_PACKAGE_CONFIGURATION_PENDING')
    baseline=debian_installed_packages()
    # Acquire authenticated exact archives while the existing backend is live.
    # Repository/network failures must not leave it stopped awaiting download.
    command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','--download-only','--assume-yes','--only-upgrade','--no-remove','install',*changes],600)
    backup=pathlib.Path('/var/lib/incudal-system-security')/('runtime-backup-'+uuid.uuid4().hex);backup.mkdir(mode=0o700)
    size=int(command(['runuser','-u','postgres','--','psql','-X','-At','-d','incudal','-c',"SELECT pg_database_size('incudal')"],20))
    filesystem=os.statvfs(backup)
    if size<0 or filesystem.f_bavail*filesystem.f_frsize<max(size*3,128*1024*1024):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_SPACE_REQUIRED')
    dump_runtime_database(backup/'database.dump')
    originals={key:protected_hash(key,private=False)for key in ['/opt/incudal/.env',backend['app']+'/server/dist/app.js',*backend['unitHashes']]}
    verify_runtime_financial_integrity(backend['app'])
    if backend_runtime_proof()!=backend or database_proof()!=database or debian_installed_packages()!=baseline:raise ValueError('SYSTEM_SECURITY_RUNTIME_BASELINE_CHANGED')
    stopped=False
    journal={'version':1,'phase':'prepared','backend':backend,'database':database if need_database else None,'backup':backup.name,'packages':changes,'expectedPackages':expected,'baselinePackages':baseline}
    write_runtime_maintenance(journal)
    try:
        journal['phase']='stopping-backend';write_runtime_maintenance(journal);stopped=True
        command(['systemctl','stop','incudal-backend.service'],36*60)
        if command(['systemctl','show','incudal-backend.service','--property=MainPID','--value'],20)!='0':raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_PENDING')
        if command(['systemctl','show','incudal-backend.service','--property=Result','--value'],20)!='success':raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
        journal['drainConfirmed']=True;write_runtime_maintenance(journal)
        if any(protected_hash(key)!=digest for key,digest in originals.items()):raise ValueError('SYSTEM_SECURITY_BACKEND_CONFIGURATION_CHANGED')
        dump_runtime_database(backup/'database-after-drain.dump')
        if need_database:
            if database_runtime_proof()!=database:raise ValueError('SYSTEM_SECURITY_DATABASE_CHANGED')
            journal['phase']='stopping-database';write_runtime_maintenance(journal)
            command(['systemctl','stop',database['unit']],180)
            state=dict(line.split('=',1)for line in command(['systemctl','show',database['unit'],'--property=MainPID,ActiveState,Result'],20).splitlines()if '='in line)
            if state.get('MainPID')!='0'or state.get('ActiveState')!='inactive'or state.get('Result')!='success':raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
        value['backendActivation']={'state':'draining','backup':backup.name};persist(value)
        journal['phase']='installing';write_runtime_maintenance(journal)
        prepare_service_policy()
        try:command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','-o','Dpkg::Options::=--force-confold','--assume-yes','--only-upgrade','--no-remove','--no-download','install',*changes],600)
        finally:clean_service_policy()
        if command(['dpkg','--audit'],30)or debian_installed_packages()!=expected:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')
        journal['phase']='installed';write_runtime_maintenance(journal)
    finally:
        if stopped:recover_runtime_maintenance()
    current=backend_runtime_proof()
    if current is None or any(current[k]!=backend[k]for k in ['app','environmentHash','codeHash','serviceHash','unitHashes']):raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    installed=pathlib.Path('/usr/bin/node').stat();running=pathlib.Path('/proc',str(current['pid']),'exe').stat()
    if (installed.st_dev,installed.st_ino)!=(running.st_dev,running.st_ino):raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    verify_runtime_process_libraries(current['pid'],'SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    if need_database:
        current_db=database_runtime_proof()
        verify_database_activation(current_db,database)
    verify_runtime_health()
    verify_runtime_financial_integrity(backend['app'])
    value['backendActivation']={'state':'activated','pid':current['pid'],'backup':backup.name};value['patchState']='installed-activation-required'
    if need_database:value['databaseActivation']={'state':'activated','pid':current_db['pid']}
    persist(value)
    journal['phase']='activated';journal['activatedBackendPID']=current['pid']
    if need_database:journal['activatedDatabasePID']=current_db['pid']
    write_runtime_maintenance(journal);archive_runtime_receipt(journal,pathlib.Path('/var/lib/incudal-system-security'))

def write_runtime_maintenance(value,root=pathlib.Path('/var/lib/incudal-system-security')):
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    fd,name=tempfile.mkstemp(prefix='.runtime-maintenance-',dir=root)
    try:
        with os.fdopen(fd,'w')as stream:stream.write(json.dumps(value,separators=(',',':')));stream.flush();os.fsync(stream.fileno())
        os.replace(name,root/'runtime-maintenance.json')
        parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
    finally:
        if os.path.exists(name):os.unlink(name)

def recover_runtime_maintenance(path=pathlib.Path('/var/lib/incudal-system-security/runtime-maintenance.json')):
    if not path.exists()and not path.is_symlink():return
    protected_hash(path,private=True);journal=json.loads(path.read_text())
    if journal.get('version')!=1 or journal.get('phase')not in ['prepared','stopping-backend','stopping-database','installing','installed','activated','aborted']:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    activation_only=journal.get('activationOnly',False)
    if not isinstance(activation_only,bool):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    if activation_only:
        baseline=journal.get('baselinePackages')
        if journal.get('packages')!=[]or not isinstance(baseline,dict)or not baseline or len(baseline)>20000 or baseline!=journal.get('expectedPackages')or journal['phase']in ['installing','installed']:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        if any(not re.fullmatch(r'[a-z0-9+.-]+:[a-z0-9-]+',key)or not isinstance(version,str)or not re.fullmatch(r'[^\s=\x00-\x1f]{1,200}',version)for key,version in baseline.items()):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    if journal['phase']in ['prepared','activated','aborted']:return
    backend=journal.get('backend',{});database=journal.get('database')
    app=backend.get('app')
    if not isinstance(app,str)or not(app=='/opt/incudal'or re.fullmatch(r'/opt/incudal/releases/[A-Za-z0-9._-]+',app))or str(pathlib.Path(app).resolve())!=app:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    if protected_hash('/opt/incudal/.env')!=backend.get('environmentHash')or protected_hash(pathlib.Path(backend['app'])/'server/dist/app.js')!=backend.get('codeHash'):raise ValueError('SYSTEM_SECURITY_BACKEND_CONFIGURATION_CHANGED')
    if not isinstance(backend.get('unitHashes'),dict)or not backend['unitHashes']:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    for unit_path,digest in backend['unitHashes'].items():
        if unit_path not in ['/etc/systemd/system/incudal-backend.service','/etc/systemd/system/incudal-backend.service.d/platform-backup.conf','/etc/systemd/system/incudal-backend.service.d/zz-database-security.conf','/etc/systemd/system/incudal-backend.service.d/local-gateway.conf']or protected_hash(unit_path)!=digest:raise ValueError('SYSTEM_SECURITY_BACKEND_CONFIGURATION_CHANGED')
    _,app_path,units,service_hash=backend_service_policy()
    if str(app_path)!=app or units!=backend['unitHashes']or service_hash!=backend.get('serviceHash'):raise ValueError('SYSTEM_SECURITY_BACKEND_CONFIGURATION_CHANGED')
    if command(['systemctl','show','incudal-backend.service','--property=SubState','--value'],20)in ['stop','stop-sigterm','stop-sigkill','stop-post']:raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_PENDING')
    # A later start can fail transiently after a confirmed graceful stop. Its
    # service Result must not permanently prevent restarting the same code.
    # A crash during the stop still requires independent success evidence.
    if not journal.get('drainConfirmed') and command(['systemctl','show','incudal-backend.service','--property=Result','--value'],20)!='success':raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
    clean_service_policy()
    installation_started=journal['phase']in ['installing','installed']
    if installation_started:complete_runtime_package_transaction(journal)
    elif command(['dpkg','--audit'],30):raise ValueError('SYSTEM_SECURITY_PACKAGE_CONFIGURATION_PENDING')
    if activation_only and debian_installed_packages()!=baseline:raise ValueError('SYSTEM_SECURITY_RUNTIME_BASELINE_CHANGED')
    if database is not None:
        major=database.get('major')
        if database.get('sharedReadOnly'):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        if major not in [14,15,16,17,18]or database.get('unit')!='postgresql@'+str(major)+'-main.service':raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        if database.get('data')!='/var/lib/postgresql/'+str(major)+'/main'or database.get('config')!='/etc/postgresql/'+str(major)+'/main/postgresql.conf'or database.get('hba')!='/etc/postgresql/'+str(major)+'/main/pg_hba.conf':raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        owner=pathlib.Path(database['data']).stat().st_uid
        if protected_hash(database['config'],(0,owner))!=database['configHash']or protected_hash(database['hba'],(0,owner))!=database['hbaHash']:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
        files=database.get('fileHashes')
        if not isinstance(files,dict)or not files or len(files)>68:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        for file,digest in files.items():
            if not isinstance(file,str)or not(file.startswith('/etc/postgresql/'+str(major)+'/main/')or file==database['data']+'/postgresql.auto.conf')or protected_hash(file,(0,owner))!=digest:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
        unit_path=command(['systemctl','show',database['unit'],'--property=FragmentPath','--value'],20)
        if unit_path not in ['/lib/systemd/system/postgresql@.service','/usr/lib/systemd/system/postgresql@.service']or protected_hash(unit_path)!=database.get('unitHash'):raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
        if command(['systemctl','show',database['unit'],'--property=SubState','--value'],20)in ['stop','stop-sigterm','stop-sigkill','stop-post']:raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_PENDING')
        command(['systemctl','start',database['unit']],180)
    command(['systemctl','start','incudal-backend.service'],11*60)
    verify_runtime_health()
    current=backend_runtime_proof()
    if current is None or any(current[key]!=backend.get(key)for key in ['app','environmentHash','codeHash','unitHashes','serviceHash']):raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    installed=pathlib.Path('/usr/bin/node').stat();running=pathlib.Path('/proc',str(current['pid']),'exe').stat()
    if (installed.st_dev,installed.st_ino)!=(running.st_dev,running.st_ino):raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    verify_runtime_process_libraries(current['pid'],'SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    if database is not None:
        proof=database_runtime_proof()
        verify_database_activation(proof,database)
    verify_runtime_financial_integrity(app)
    # A stop failure or interruption before apt ran only restores the prior
    # services. Never issue an activation receipt for an unapplied patch.
    journal['phase']='activated'if installation_started or activation_only else 'aborted'
    if installation_started or activation_only:
        journal['activatedBackendPID']=current['pid']
        if database is not None:journal['activatedDatabasePID']=proof['pid']
    write_runtime_maintenance(journal,path.parent)
    if installation_started or activation_only:
        archive_runtime_receipt(journal,path.parent)
    return journal if installation_started or activation_only else None

def archive_runtime_receipt(journal,root):
    name=journal.get('backup')
    if not isinstance(name,str)or not re.fullmatch(r'runtime-backup-[a-f0-9]{32}',name):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    backup=root/name;info=backup.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    for file in backup.iterdir():
        if file.name not in ['database.dump','database-after-drain.dump','completed.json']:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        metadata=file.lstat()
        if not stat.S_ISREG(metadata.st_mode)or metadata.st_uid!=0 or metadata.st_nlink!=1 or metadata.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    receipt=backup/'completed.json'
    if receipt.exists():protected_hash(receipt,private=True)
    fd,temporary=tempfile.mkstemp(prefix='.completed-',dir=backup)
    try:
        with os.fdopen(fd,'w')as stream:stream.write(json.dumps(journal,separators=(',',':')));stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,receipt)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)
    # Keep seven completed rollback snapshots and all records newer than 30
    # days. Incomplete, unrecognized or changed evidence is never swept.
    complete=[]
    for path in root.glob('runtime-backup-*'):
        if not re.fullmatch(r'runtime-backup-[a-f0-9]{32}',path.name)or not(path/'completed.json').exists():continue
        metadata=path.lstat()
        if not stat.S_ISDIR(metadata.st_mode)or metadata.st_uid!=0 or metadata.st_mode&0o077:continue
        record=path/'completed.json'
        try:
            protected_hash(record,private=True);value=json.loads(record.read_text())
            if value.get('phase')!='activated'or value.get('backup')!=path.name:continue
            if any(file.name not in ['database.dump','database-after-drain.dump','completed.json']or not stat.S_ISREG(file.lstat().st_mode)or file.lstat().st_uid!=0 or file.lstat().st_nlink!=1 or file.lstat().st_mode&0o077 for file in path.iterdir()):continue
        except(ValueError,OSError,json.JSONDecodeError):continue
        complete.append((record.stat().st_mtime,path))
    for timestamp,path in sorted(complete,reverse=True)[7:]:
        if path==backup or timestamp>time.time()-30*86400:continue
        for file in path.iterdir():file.unlink()
        path.rmdir()

def complete_runtime_package_transaction(journal):
    baseline=journal.get('baselinePackages');expected=journal.get('expectedPackages');changes=journal.get('packages')
    if not isinstance(baseline,dict)or not isinstance(expected,dict)or baseline.keys()!=expected.keys()or not isinstance(changes,list)or not changes or len(changes)>64:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    if len(baseline)>20000 or any(not re.fullmatch(r'[a-z0-9+.-]+:[a-z0-9-]+',key)or not isinstance(version,str)or not re.fullmatch(r'[^\s=\x00-\x1f]{1,200}',version)for packages in [baseline,expected]for key,version in packages.items()):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    planned={}
    for item in changes:
        if not isinstance(item,str)or not re.fullmatch(r'[a-z0-9+.-]+=[^\s=\x00-\x1f]{1,200}',item):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        name,version=item.split('=',1);matches=[key for key in expected if key.split(':')[0]==name]
        if len(matches)!=1 or expected[matches[0]]!=version or name in planned:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        planned[name]=version
    if any(baseline[key]!=expected[key]and key.split(':')[0]not in planned for key in baseline):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    states=debian_package_states();current={key:value['version']for key,value in states.items()}
    configured=all(value['status']=='installed'for value in states.values())
    if current==expected and configured and not command(['dpkg','--audit'],30):return
    # A failed install can have advanced some exact planned packages. Unknown
    # removals, additions or versions are refused instead of starting that code.
    if current.keys()!=baseline.keys()or any(current[key]not in [baseline[key],expected[key]]for key in baseline):raise ValueError('SYSTEM_SECURITY_RUNTIME_PACKAGE_BASELINE_CHANGED')
    if any(value['status']!='installed'and key.split(':')[0]not in planned for key,value in states.items()):raise ValueError('SYSTEM_SECURITY_RUNTIME_PACKAGE_BASELINE_CHANGED')
    remaining=[];reinstall=set()
    for item in changes:
        name,version=item.split('=',1);key=next(key for key in expected if key.split(':')[0]==name)
        if current[key]!=version or states[key]['status']=='half-installed':remaining.append(item)
        if states[key]['status']=='half-installed':reinstall.add(name)
    if remaining:
        reviewed={key.split(':')[0]:version for key,version in current.items()}
        if len(reviewed)!=len(current):raise ValueError('SYSTEM_SECURITY_MULTIARCH_REVIEW_REQUIRED')
        output=command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','--simulate','--only-upgrade','--no-remove',*(['--reinstall']if reinstall else []),'install',*remaining],90)
        ordinary=[];reinstalled=[]
        for line in output.splitlines():
            if line.startswith('Inst '):
                match=re.fullmatch(r'Inst ([a-z0-9+.-]+)(?::(?:amd64|arm64))? \[([^\]]+)\] \(([^\s]+) [^\r\n]+\)(?: \[[^\]\r\n]*\])?',line)
                if match and match[1]in reinstall and match[2]==reviewed[match[1]]and match[3]==planned[match[1]]:
                    reinstalled.append(match[1]+'='+match[3]);continue
            ordinary.append(line)
        planned=patch_plan('\n'.join(ordinary),reviewed,set(planned))+reinstalled
        if sorted(planned)!=sorted(remaining):raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
    else:
        prepare_service_policy()
        configuring=sorted(key.split(':')[0]for key,value in states.items()if value['status']!='installed')
        try:command(['dpkg','--force-confold','--configure',*configuring],300)
        finally:clean_service_policy()
        if command(['dpkg','--audit'],30)or debian_installed_packages()!=expected:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')
        return
    prepare_service_policy()
    try:
        command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','-o','Dpkg::Options::=--force-confold','--assume-yes','--only-upgrade','--no-remove',*(['--reinstall']if reinstall else []),'install',*remaining],600)
    finally:clean_service_policy()
    if command(['dpkg','--audit'],30)or debian_installed_packages()!=expected:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')

def verify_database_activation(current,before):
    if any(current[key]!=before[key]for key in ['major','data','configHash','hbaHash','unitHash','fileHashes']):raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
    version=before.get('settingsHashVersion',1)
    if type(version)is not int or version not in [1,2]or version==2 and current.get('settingsHashVersion')!=2:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
    # Earlier private receipts remain bound to their exact original digest.
    # A new comparison policy cannot silently re-attest an old baseline.
    settings=current.get('settingsLegacyHash',current.get('settingsHash'))if version==1 else current.get('settingsHash')
    if not isinstance(before.get('settingsHash'),str)or settings!=before['settingsHash']:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
    installed=pathlib.Path('/usr/lib/postgresql',str(current['major']),'bin/postgres').stat();running=pathlib.Path('/proc',str(current['pid']),'exe').stat()
    if (installed.st_dev,installed.st_ino)!=(running.st_dev,running.st_ino):raise ValueError('SYSTEM_SECURITY_DATABASE_ACTIVATION_PENDING')
    verify_runtime_process_libraries(current['pid'],'SYSTEM_SECURITY_DATABASE_ACTIVATION_PENDING')

def verify_runtime_process_libraries(pid,error):
    if runtime_process_has_replaced_libraries(pid):raise ValueError(error)

def runtime_process_has_replaced_libraries(pid):
    # Prove this exact managed process independently. An unrelated process or
    # a partial global inventory cannot prevent its original service recovery.
    if type(pid)is not int or pid<2:raise ValueError('SYSTEM_SECURITY_RUNTIME_PROCESS_CHANGED')
    process=pathlib.Path('/proc',str(pid))
    if (process/'ns/pid').readlink()!=pathlib.Path('/proc/1/ns/pid').readlink():raise ValueError('SYSTEM_SECURITY_RUNTIME_PROCESS_CHANGED')
    with (process/'maps').open(encoding='utf-8',errors='replace')as stream:data=stream.read(1024*1024+1)
    if len(data)>1024*1024:raise ValueError('SYSTEM_SECURITY_RUNTIME_CHECK_INCOMPLETE')
    for line in data.splitlines():
        if not line.endswith(' (deleted)'):continue
        fields=line.split(maxsplit=5)
        if len(fields)==6 and 'x'in fields[1]and fields[5].startswith('/')and not fields[5].startswith(('/dev/','/memfd:','/SYSV')):return True
    return False

def verify_runtime_financial_integrity(app):
    code="const root=process.argv[1];await import(root+'/server/dist/config/env.js');const{readFileSync}=await import('node:fs');const{verifyFinancialBaseline,verifyFinancialDatabaseSeals}=await import(root+'/server/dist/lib/financial-integrity.js');verifyFinancialBaseline(readFileSync('/var/lib/incudal-finance/baseline.json','utf8'),process.env.ENCRYPTION_KEY);await verifyFinancialDatabaseSeals('incudal',process.env.ENCRYPTION_KEY,false,true);console.log('SYSTEM_SECURITY_FINANCIAL_INTEGRITY_VERIFIED')"
    if command(['/usr/bin/env','ENV_FILE=/opt/incudal/.env','NODE_ENV=production','/usr/bin/node','--input-type=module','-e',code,app],90)!='SYSTEM_SECURITY_FINANCIAL_INTEGRITY_VERIFIED':raise ValueError('SYSTEM_SECURITY_FINANCIAL_INTEGRITY_INVALID')

def verify_runtime_health():
    # The service may be active while the unique backend still loads its
    # database/authentication baseline. Match the reviewed startup budget;
    # a live process alone never attests business readiness.
    deadline=time.monotonic()+600
    while True:
        try:
            value=json.loads(command(['curl','-fsS','--max-time','5','http://127.0.0.1:3001/api/health'],10))
            if isinstance(value,dict)and value.get('status')=='ok'and value.get('businessStartupReady')is True and value.get('recoveryHeld')is False:return
        except(ValueError,OSError,json.JSONDecodeError):pass
        if time.monotonic()>deadline:raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
        time.sleep(.5)

def dump_runtime_database(path):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    process=None
    try:
        with tempfile.TemporaryFile()as errors:
            process=subprocess.Popen(['runuser','-u','postgres','--','pg_dump','-Fc','incudal'],stdout=fd,stderr=errors,start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            try:code=process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait();raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            if code or os.fstat(fd).st_size<5 or live_process_group(process.pid):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            os.fsync(fd)
        with pathlib.Path(path).open('rb')as input:
            if input.read(5)!=b'PGDMP':raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    finally:
        if process is not None and live_process_group(process.pid):
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        os.close(fd)

def verify_runtime_integrity():
    helper=pathlib.Path('/usr/local/libexec/incudal/incudal-online-task')
    info=helper.lstat()
    if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022:raise ValueError('SYSTEM_SECURITY_RUNTIME_HELPER_UNTRUSTED')
    verified=False
    try:
        # Verify the complete release and every link on slow small controllers
        # too. Retain a finite budget and the exact original seal checks.
        verified=command([str(helper),'verify-runtime'],600)=='INCUDAL_SEALED_RUNTIME_VERIFIED'
    except (ValueError,OSError):pass
    record_runtime_integrity(verified)
    if not verified:raise ValueError('SYSTEM_SECURITY_RUNTIME_INTEGRITY_MISMATCH')

def record_runtime_integrity(verified,root=pathlib.Path('/var/lib/incudal-system-security')):
    root.mkdir(mode=0o700,exist_ok=True)
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    path=root/'runtime-integrity.json';previous={}
    if path.exists()or path.is_symlink():
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077 or info.st_size>8192:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        previous=json.loads(path.read_text())
        if not isinstance(previous,dict)or previous.get('version')!=1:raise ValueError('SYSTEM_SECURITY_RECEIPT_INVALID')
        for key in ['firstFailureAt','lastFailureAt']:
            if key in previous and (not isinstance(previous[key],str)or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',previous[key])):raise ValueError('SYSTEM_SECURITY_RECEIPT_INVALID')
        if bool(previous.get('firstFailureAt'))!=bool(previous.get('lastFailureAt')):raise ValueError('SYSTEM_SECURITY_RECEIPT_INVALID')
    now=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    value={'version':1,'checkedAt':now,'state':'verified'if verified else'failed'}
    if previous.get('firstFailureAt'):value['firstFailureAt']=previous['firstFailureAt'];value['lastFailureAt']=previous['lastFailureAt']
    if not verified:value.update(firstFailureAt=value.get('firstFailureAt',now),lastFailureAt=now,error='SYSTEM_SECURITY_RUNTIME_INTEGRITY_MISMATCH')
    fd,name=tempfile.mkstemp(prefix='.runtime-integrity-',dir=root)
    try:
        with os.fdopen(fd,'w')as out:out.write(json.dumps(value,separators=(',',':')));out.flush();os.fsync(out.fileno())
        os.replace(name,path)
        directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(name):os.unlink(name)
    return value

def defer_security_check(value,now=None):
    now=time.time()if now is None else now
    value['nextPatchCheckAt']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(now+(300 if maintenance_needs_prompt_retry(value)else 6*3600)))
    return value

def security_patch_check_due(value,now=None):
    timestamp=value.get('nextPatchCheckAt')
    if timestamp is None:return True
    if not isinstance(timestamp,str)or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',timestamp):raise ValueError('SYSTEM_SECURITY_RECEIPT_INVALID')
    try:deadline=calendar.timegm(time.strptime(timestamp,'%Y-%m-%dT%H:%M:%SZ'))
    except ValueError:raise ValueError('SYSTEM_SECURITY_RECEIPT_INVALID')
    current=time.time()if now is None else now
    if deadline>current+6*3600+60:raise ValueError('SYSTEM_SECURITY_RECEIPT_INVALID')
    return current>=deadline

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
    fd=open_platform_operation_lock()
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
        if 'nextPatchCheckAt'in value and maintenance_needs_prompt_retry(value):defer_security_check(value)
        if not verify_activation and value.get('patchState') is None and previous.get('patchState')=='activated' and not value.get('activationRequired') and value.get('activationReceipt'):
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
            fd=open_platform_operation_lock(False)
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
        if sys.argv[1:]==['--maintain']:
            maintain_system_packages();sys.exit(0)
        if sys.argv[1:]==['--apply']:value=apply_patches()
        else:value=inventory()
        if sys.argv[1:]==['--apply']:print(json.dumps(value,separators=(',',':')))
        elif sys.argv[1:]:raise ValueError('SYSTEM_SECURITY_ARGUMENT_INVALID')
        else:print(json.dumps(value,separators=(',',':')))
    except Exception as error:
        value=failure_receipt(error)
        if sys.argv[1:]in [['--record'],['--apply'],['--maintain'],['--verify-activation']]:
            try:persist(value)
            except Exception:pass # Unsafe/unwritable state is never repaired implicitly.
        print(json.dumps(value,separators=(',',':')));sys.exit(1)
