#!/usr/bin/env python3
"""Bounded package/runtime security receipt. Never changes a major or reboots."""
import json,os,pathlib,subprocess,sys,time,tempfile,re,fcntl,signal,uuid,stat
import hashlib
import calendar

ALPINE=['openssl','libssl3','libcrypto3','curl','libcurl','openssh','openssh-server','openssh-client-default','dnsmasq','lxc','lxc-libs','lxcfs','lxcfs-openrc','lvm2','device-mapper','btrfs-progs','wireguard-tools','qemu-system-x86_64','qemu-system-aarch64','sqlite-libs','libseccomp','libcap2','acl-libs','libattr','libuv','lz4-libs','zstd-libs','xz-libs','libintl','libgcc','dbus-libs','eudev-libs','raft-cowsql','cowsql']
DEBIAN=['openssl','libssl3','libssl3t64','curl','libcurl4','libcurl4t64','openssh-server','openssh-client','dnsmasq','lxc','liblxc1','liblxc-common','lxcfs','lvm2','libdevmapper1.02.1','libdevmapper-event1.02.1','btrfs-progs','wireguard-tools','nginx','nginx-common','nodejs','qemu-system-x86','qemu-system-arm','qemu-system-common','qemu-utils','systemd','systemd-dev','systemd-sysv','systemd-timesyncd','systemd-resolved','libsystemd0','libsystemd-shared','libpam-systemd','udev','libudev1','chrony','nftables','ca-certificates','libsqlite3-0','libseccomp2','libcap2','libacl1','libattr1','libuv1','libuv1t64','liblz4-1','libzstd1','liblzma5','libdbus-1-3','libgcc-s1']

# libc, clock and the actual storage/network helper libraries must not vanish
# from inventory just because a signed package transaction cannot safely
# activate them while a customer is using the host. These are distro packages,
# never guest software; installation and activation retain separate receipts.
ALPINE+=['musl','musl-utils','chrony','chrony-openrc','ca-certificates','fuse3-libs','lvm2-libs','device-mapper-libs','device-mapper-event-libs',
    'tar','gzip','xz','squashfs-tools','rsync','libpsl','libidn2','libunistring','c-ares','brotli-libs','nghttp2-libs','nftables','libnftnl','libmnl','iptables','ip6tables']
DEBIAN+=['libc6','libc-bin','libfuse3-3','libfuse3-4','libnftnl11','libmnl0','iptables','libxtables12','libip4tc2','libip6tc2',
    'tar','gzip','xz-utils','squashfs-tools','rsync','libpsl5','libpsl5t64','libidn2-0','libunistring5','libc-ares2','libbrotli1','libnghttp2-14','openssh-sftp-server']

# These tools and libraries have no daemon lifecycle operation. Installed
# services loading an old mapping remain activation-required, never marked
# patched by an installed version alone. libc/kernel/service packages retain
# their separate reviewed activation paths and are still fully inventoried.
AUTOMATIC_DEBIAN=frozenset(['openssl','libssl3','libssl3t64','curl','libcurl4','libcurl4t64','ca-certificates',
    'libsqlite3-0','libseccomp2','libcap2','libacl1','libattr1','libuv1','libuv1t64','liblz4-1','libzstd1','liblzma5',
    'tar','gzip','xz-utils','squashfs-tools','libpsl5','libpsl5t64','libidn2-0','libunistring5','libc-ares2','libbrotli1','libnghttp2-14'])

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
    text=config.read_text()
    if '# payincus-time-sync-v1'not in text.splitlines()or re.search(r'(?m)^\s*(?:makestep|initstepslew)\b',text)or '# payincus-time-sync-v1'not in unit.read_text().splitlines():raise ValueError('SYSTEM_SECURITY_CLOCK_SERVICE_UNREVIEWED')
    value=dict(line.split('=',1)for line in command(['systemctl','show','incudal-clock.service','--property=MainPID,ActiveState'],20).splitlines()if '='in line)
    if value.get('ActiveState')!='active'or int(value.get('MainPID','0'))<2:return None
    pid=int(value['MainPID']);process=pathlib.Path('/proc',str(pid))
    if (process/'ns/pid').readlink()!=pathlib.Path('/proc/1/ns/pid').readlink()or str((process/'exe').readlink()).removesuffix(' (deleted)')not in ['/usr/sbin/chronyd','/sbin/chronyd']:raise ValueError('SYSTEM_SECURITY_CLOCK_PROCESS_CHANGED')
    return {'pid':pid,'configurationHash':hashlib.sha256(config.read_bytes()+unit.read_bytes()).hexdigest(),'helperHash':hashlib.sha256(helper.read_bytes()).hexdigest()}

def activate_managed_clock(before):
    if before is None:return None
    if managed_clock_security_proof()!=before:raise ValueError('SYSTEM_SECURITY_CLOCK_PROCESS_CHANGED')
    helper=pathlib.Path('/usr/local/libexec/incudal/ensure-time-sync.py')
    result=json.loads(command(['/usr/bin/python3','-I','-B',str(helper),'--activate-security'],90))
    after=managed_clock_security_proof()
    if after is None or after['configurationHash']!=before['configurationHash']or after['helperHash']!=before['helperHash']or result.get('state')not in ['current','activated']:raise ValueError('SYSTEM_SECURITY_CLOCK_ACTIVATION_PENDING')
    return {'state':result['state'],'pid':after['pid'],'synchronized':result.get('synchronized')is True}

def live_process_group(group,proc=pathlib.Path('/proc')):
    checked=0
    for path in proc.iterdir():
        if not path.name.isdigit():continue
        checked+=1
        if checked>65536:raise ValueError('SYSTEM_SECURITY_PROCESS_BUDGET_EXCEEDED')
        try:raw=(path/'stat').read_text()
        except FileNotFoundError:continue
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
    fd=os.open('/var/lib/incudal-platform-operation.lock',os.O_CREAT|os.O_NOFOLLOW|os.O_RDWR,0o600)
    info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:os.close(fd);raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            if automatic:return None
            raise
        if pathlib.Path('/var/lib/incudal-backup/recovery-hold.json').exists():raise ValueError('SYSTEM_SECURITY_RECOVERY_HELD')
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
            prepare_service_policy()
            try:command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','-o','Dpkg::Options::=--force-confold','--assume-yes','--only-upgrade','--no-remove','install',*changes],600)
            finally:
                clean_service_policy()
            if debian_installed_packages()!=expected:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')
        after=inventory(all_loaded_code=True)
        for package in changes:
            name,version=package.split('=',1)
            if after['packages'].get(name)!=version:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')
        if automatic and ssh_before is not None:
            after['sshListenerActivation']=activate_ssh_listener(ssh_before)
            after['loadedCode']=replaced_host_mappings(all_host=True)
        elif ssh_error:after['sshListenerActivation']={'state':'pending','error':ssh_error}
        if automatic and nginx_before is not None:
            after['nginxActivation']=activate_nginx_master(nginx_before)
            after['loadedCode']=replaced_host_mappings(all_host=True)
        elif nginx_error:after['nginxActivation']={'state':'pending','error':nginx_error}
        if automatic and clock_before is not None:
            after['clockActivation']=activate_managed_clock(clock_before)
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
    return value.get('patchState')in ['prepared','failed']or value.get('activationRequired')or any(isinstance(value.get(key),dict)and value[key].get('state')in ['draining','pending']for key in ['nginxActivation','sshListenerActivation','clockActivation'])

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
