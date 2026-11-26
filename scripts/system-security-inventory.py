#!/usr/bin/env python3
"""Bounded package/runtime security receipt. Never changes a major or reboots."""
import json,os,pathlib,subprocess,sys,time,tempfile,re,fcntl,signal,uuid,stat
import hashlib
import calendar,math

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

# Base libc is not an ordinary leaf update. Its authenticated pair may only
# enter the existing backed-up, drained runtime transaction after both the
# original application and its local database have been independently proved.
RUNTIME_DEBIAN_BASE_LIBRARIES=frozenset(['libc6','libc-bin'])

# These are reviewed raw control bytes, not hashes of a decoded shell script.
# The exact candidate archive still has to be authenticated by APT. A changed
# maintainer program or another trigger consumer requires a new review.
RUNTIME_LIBC_CONTROL={
    'libc6':{
        'arm64':{'preinst':'47f047126448416b1f94d48a9bb9c26d39b7806c3a1aedbd3f24ccbc64b45eb6',
            'postinst':'ff2a3a7a0e74ceac331ca5ad22e7ef57c974a7b891a9b1e7f3def4377ec6f1b5',
            'postrm':'08b978ce79395b33e7aa89549092399320a4a58e15c4a0a2cee05c427d0d4098',
            'triggers':'c67ab4558a59eb1e96d899a5bdbb153d6a2ab0e580f4acf5bfb1e4e6150ad2f4'},
        'amd64':{'preinst':'964a417b9c330f80213fe8aebb1f44eaea307203962aecb0de493742583bb454',
            'postinst':'ff2a3a7a0e74ceac331ca5ad22e7ef57c974a7b891a9b1e7f3def4377ec6f1b5',
            'postrm':'d911893b23b52a371e843a621a27d49060f0aefdc07c8cb43ef77563a84fbd5b',
            'triggers':'c67ab4558a59eb1e96d899a5bdbb153d6a2ab0e580f4acf5bfb1e4e6150ad2f4'}},
    'libc-bin':{'arm64':{'postinst':'3daa7e3ffd429c1d77287f0fc840a490a607697906d2303452f70578647ce0d4',
        'triggers':'c3d6b5df131336e54c31dc5687929467de7abea5c5798e3d6a6b2a64ef971fd4'},
        'amd64':{'postinst':'3daa7e3ffd429c1d77287f0fc840a490a607697906d2303452f70578647ce0d4',
            'triggers':'c3d6b5df131336e54c31dc5687929467de7abea5c5798e3d6a6b2a64ef971fd4'}}}
RUNTIME_SYSTEMD_CONTROL={'postinst':'7a95419baad7f5e6cfa7a422ae8965e67a5b25f9c74fa6cb6596090c1c236793',
    'preinst':'bcf12d1b4fa4b7a22e9ab7db0fd273839c35036576946158a996887da96b080e',
    'postrm':'781f34e5df4d482e4f1f7725c356a1560226fa812217e9f87bfe9c4e2d5d825e',
    'prerm':'686758f30f18776b6f60f030b11f451639576a2c9f3262e5907a92b1c2f1b48a',
    'triggers':'f437e8a59b6a78ef87c93d055c385f203ef4b58cee0d2bfc85adf0a80213e9f8'}
RUNTIME_SYSTEMD_PROGRAMS={
    'amd64':{'usr/lib/systemd/systemd':'799fd89964a716fb5f26c4506047190b6e842ac2745b473bd45351c4d8cbd929',
        'usr/lib/systemd/systemd-journald':'23a541006c8fbde1564364736560fdadc11f5f8deb03ef4ce05af8171f5d173c',
        'usr/lib/systemd/system/systemd-journald.service':'4baf517dd2dbbe52173b3b6c0e4f9690a8ab03ac6406ba455c468bf140f6bd95'},
    'arm64':{'usr/lib/systemd/systemd':'46044b7912af7f7087837554b186ca3ddb640c0f6646cf5e625be5078d5db80d',
        'usr/lib/systemd/systemd-journald':'f6f2f32452c075a895225c826f6631ebe88d07a003bbb2a8218f3a4ca5d16e55',
        'usr/lib/systemd/system/systemd-journald.service':'4baf517dd2dbbe52173b3b6c0e4f9690a8ab03ac6406ba455c468bf140f6bd95'}}
RUNTIME_LIBC_FILES={'amd64':{'usr/lib/x86_64-linux-gnu/'+name for name in ['ld-linux-x86-64.so.2','libc.so.6','libm.so.6']},
    'arm64':{'usr/lib/aarch64-linux-gnu/'+name for name in ['ld-linux-aarch64.so.1','libc.so.6','libm.so.6']}}
RUNTIME_SYSTEMCTL_ACTIONS={('daemon-reexec',):'manager',
    ('kill','--kill-whom=main','--signal=SIGRTMIN+25','user@*.service'):'user-managers',
    ('try-restart','systemd-networkd.service'):'networkd',
    ('try-restart','systemd-journald.service'):'journald'}
RUNTIME_SYSTEMCTL_WRAPPER=r'''#!/usr/bin/python3 -I
import os,sys,json,stat,pathlib,hashlib,tempfile,fcntl,re
sys.dont_write_bytecode=True
def checked(path,limit=1048576,private=False):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&(0o077 if private else 0o022) or info.st_size>limit:raise ValueError()
    return path.read_bytes()
def present(path):
    try:path.lstat();return True
    except FileNotFoundError:return False
def history(proof,base,source):
    token=proof.get('token','');directory=proof.get('directory');digest=proof.get('sourceHash')
    if proof.get('version')!=1 or not re.fullmatch(r'[a-f0-9]{32}',token)or directory!='runtime-systemctl-'+token or digest!=hashlib.sha256(source).hexdigest():raise ValueError()
    root=base/directory
    exists=present(root)
    if exists:
        info=root.lstat()
        if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or root.resolve()!=root:raise ValueError()
    allowed={'manager','user-managers','networkd','journald'}
    if proof.get('cleared'):
        hashes=proof.get('cleanupHashes');actions=proof.get('recordedActions',proof.get('deferredActions'))
        if not isinstance(hashes,dict)or set(hashes)!={'systemctl','policy.lock','policy.json'}or hashes.get('systemctl')!=digest or any(not isinstance(value,str)or not re.fullmatch(r'[a-f0-9]{64}',value)for value in hashes.values()):raise ValueError()
        if exists:
            for file in root.iterdir():
                if file.name not in hashes or hashlib.sha256(checked(file,private=file.name!='systemctl')).hexdigest()!=hashes[file.name]:raise ValueError()
        receipt=hashes['policy.json']
    elif proof.get('ready'):
        if not exists or {file.name for file in root.iterdir()}!={'systemctl','policy.lock','policy.json'}or checked(root/'systemctl')!=source:raise ValueError()
        raw=checked(root/'policy.json',16384,True);value=json.loads(raw)
        if value.get('version')!=1 or value.get('token')!=token or value.get('sourceHash')!=digest or value.get('rejected')is not False:raise ValueError()
        actions=value.get('actions');receipt=hashlib.sha256(raw).hexdigest()
    else:
        if not proof.get('originHash'):raise ValueError()
        files={'systemctl':source,'policy.lock':b'','policy.json':json.dumps({'version':1,'token':token,'sourceHash':digest,'actions':[],'rejected':False}).encode()}
        if exists:
            for file in root.iterdir():
                if file.name not in files or checked(file,private=file.name!='systemctl')!=files[file.name]:raise ValueError()
        actions=[];receipt=hashlib.sha256(files['policy.json']).hexdigest()
    if not isinstance(actions,list)or len(actions)>4 or len(actions)!=len(set(actions))or any(action not in allowed for action in actions):raise ValueError()
    return {'token':token,'bootId':proof['bootId'],'actions':actions,'receiptHash':receipt}
def execute():
    if os.geteuid()!=0:raise ValueError()
    source=pathlib.Path(__file__);root=source.parent
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or root.resolve()!=root or root.parent!=pathlib.Path('/var/lib/incudal-system-security'):raise ValueError()
    lock=os.open(root/'policy.lock',os.O_RDWR|os.O_NOFOLLOW)
    try:
        info=os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:raise ValueError()
        fcntl.flock(lock,fcntl.LOCK_EX)
        record=root/'policy.json';value=json.loads(checked(record,16384,True))
        journal=json.loads(checked(root.parent/'runtime-maintenance.json',private=True))
        original=journal.get('systemdPolicy',{});boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        policies=journal.get('systemdBootPolicies',[])
        if not isinstance(policies,list) or len(policies)>3 or any(not isinstance(item,dict)for item in policies):raise ValueError()
        current=[item for item in policies if item.get('bootId')==boot]
        if len(current)>1:raise ValueError()
        proof=current[0]if current else original
        if current:
            if not isinstance(original.get('bootId'),str)or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',original['bootId']):raise ValueError()
            fields=['version','token','directory','sourceHash','bootId','archives','programs','qualification','libcPrograms','libcProgramsArchive','baselineLibcPrograms']
            origin=hashlib.sha256(json.dumps({field:original[field]for field in fields},sort_keys=True,separators=(',',':')).encode()).hexdigest()
            recovery=journal.get('bootRecoveries',{}).get(boot,{})
            if proof.get('originHash')!=origin or proof.get('originalToken')!=original.get('token') or proof.get('token')==original.get('token') or proof.get('sourceHash')!=original.get('sourceHash') or recovery.get('version')!=1 or recovery.get('bootId')!=boot or recovery.get('token')!=proof.get('token')or recovery.get('drainConfirmed') is not True or recovery.get('dumpPending')is not False or not isinstance(recovery.get('dump'),dict):raise ValueError()
            tokens={original['token']};boots={original['bootId']}
            for ordinal,item in enumerate(policies,1):
                if type(item.get('ordinal'))is not int or item['ordinal']!=ordinal or item.get('originalToken')!=original['token']or item.get('originHash')!=origin or item.get('sourceHash')!=original['sourceHash']or item.get('token')in tokens or item.get('bootId')in boots or not isinstance(item.get('bootId'),str)or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',item['bootId']):raise ValueError()
                if any(item.get(field)!=original[field]for field in ['archives','programs','libcPrograms','libcProgramsArchive','baselineLibcPrograms']):raise ValueError()
                tokens.add(item['token']);boots.add(item['bootId'])
            previous=[history(item,root.parent,checked(source))for item in [original,*policies]if item['bootId']!=boot]
            inherited=sorted({action for item in previous for action in item['actions']})
            if proof.get('historyHash')!=hashlib.sha256(json.dumps(previous,sort_keys=True,separators=(',',':')).encode()).hexdigest()or proof.get('inheritedActions')!=inherited:raise ValueError()
        if value.get('version')!=1 or proof.get('ready')is not True or journal.get('drainConfirmed')is not True or journal.get('phase') not in ['installing','installed'] or value.get('token')!=proof.get('token') or proof.get('directory')!=root.name or value.get('sourceHash')!=proof.get('sourceHash') or hashlib.sha256(checked(source)).hexdigest()!=proof.get('sourceHash'):raise ValueError()
        if boot!=proof.get('bootId'):raise ValueError()
        actions={('daemon-reexec',):'manager',('kill','--kill-whom=main','--signal=SIGRTMIN+25','user@*.service'):'user-managers',('try-restart','systemd-networkd.service'):'networkd',('try-restart','systemd-journald.service'):'journald'}
        action=actions.get(tuple(sys.argv[1:]));rejected=action is None
        recorded=value.get('actions')
        if not isinstance(recorded,list) or any(item not in actions.values() for item in recorded) or type(value.get('rejected')) is not bool:raise ValueError()
        value['rejected']=value['rejected'] or rejected
        value['actions']=sorted(set(recorded+([action] if action else [])))
        fd,name=tempfile.mkstemp(prefix='.policy-',dir=root)
        try:
            with os.fdopen(fd,'w') as stream:stream.write(json.dumps(value,separators=(',',':')));stream.flush();os.fsync(stream.fileno())
            os.replace(name,record)
            parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(parent)
            finally:os.close(parent)
        finally:
            if os.path.exists(name):os.unlink(name)
        return 125 if rejected else 0
    finally:os.close(lock)
try:sys.exit(execute())
except BaseException as error:
    if isinstance(error,SystemExit):raise
    sys.stderr.write('SYSTEM_SECURITY_SYSTEMD_POLICY_REJECTED\n');sys.exit(125)
'''

def debian_archive_members(data,part='control',wanted=None,manifest=False):
    import io,tarfile,bz2,lzma,zlib
    if part not in ['control','data']or not isinstance(data,bytes)or not 8<len(data)<=256*1024*1024 or data[:8]!=b'!<arch>\n':raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
    position=8;archive=None;archive_name=None;count=0;members=set();format_verified=False
    while position<len(data):
        header=data[position:position+60];count+=1
        if len(header)!=60 or header[58:]!=b'`\n'or count>16:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        try:name=header[:16].decode('ascii').strip().removesuffix('/');size=int(header[48:58])
        except (ValueError,UnicodeDecodeError):raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        if size<0 or position+60+size>len(data)or not re.fullmatch(r'[a-zA-Z0-9_.+-]{1,16}',name)or name in members:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        members.add(name)
        if name=='debian-binary':format_verified=data[position+60:position+60+size]==b'2.0\n'
        if name in [part+'.tar',part+'.tar.gz',part+'.tar.xz',part+'.tar.bz2']:
            if archive is not None:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
            archive=data[position+60:position+60+size];archive_name=name
        position+=60+size+(size%2)
    if position!=len(data)or archive is None or not format_verified:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
    # Bound decompression before tarfile parses extended headers; otherwise a
    # forged PAX size can allocate memory before any member-size check runs.
    limit=(8 if part=='control'else 256 if manifest else 128)*1024*1024
    try:
        decoder=None
        if archive_name.endswith('.xz'):
            decoder=lzma.LZMADecompressor(memlimit=64*1024*1024)
        elif archive_name.endswith('.gz'):
            decoder=zlib.decompressobj(31)
        elif archive_name.endswith('.bz2'):
            decoder=bz2.BZ2Decompressor()
        if decoder is not None:
            archive=decoder.decompress(archive,limit+1)
            if not decoder.eof or decoder.unused_data:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
    except (OSError,EOFError,ValueError,lzma.LZMAError,zlib.error):raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
    if len(archive)>limit:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
    result={};total=0;count=0;names=set()
    try:
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:')as files:
            for entry in files:
                count+=1;total+=entry.size
                name=entry.name.removeprefix('./')
                if count>20000 or entry.size<0 or total>limit or name.startswith('/')or '..'in name.split('/')or re.search(r'[\\\x00-\x1f\x7f]',name)or name in names:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
                names.add(name)
                if wanted is not None and name not in wanted:continue
                if manifest:
                    name=name.rstrip('/')
                    if name in ['', '.']and entry.isdir():continue
                    if not name or name!=str(pathlib.PurePosixPath(name))or not re.fullmatch(r'[A-Za-z0-9_+.,:@%=/\-]{1,2048}',name)or entry.uid!=0 or entry.gid!=0:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
                    record={'type':'directory'if entry.isdir()else'symlink'if entry.issym()else'file','mode':entry.mode&0o7777,'uid':entry.uid,'gid':entry.gid}
                    if entry.islnk()or not(entry.isdir()or entry.issym()or entry.isfile())or name in result:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
                    if entry.issym():record['target']=entry.linkname
                    elif entry.isfile():
                        if entry.size>128*1024*1024:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
                        digest=hashlib.sha256();size=0
                        with files.extractfile(entry)as stream:
                            while True:
                                block=stream.read(262144)
                                if not block:break
                                size+=len(block);digest.update(block)
                        if size!=entry.size:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
                        record.update(sha256=digest.hexdigest(),size=size)
                    if not entry.issym()and record['mode']&0o022:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
                    result[name]=record;continue
                if entry.isdir():continue
                if not entry.isfile()or entry.size>16*1024*1024 or name in result:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
                if part=='control'and ('/'in name or entry.size>1024*1024):raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
                with files.extractfile(entry)as stream:content=stream.read(entry.size+1)
                if len(content)!=entry.size:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
                result[name]=content
    except (OSError,tarfile.TarError,EOFError):raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
    if wanted is not None and set(result)!=set(wanted):raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
    return result

def authenticated_debian_archive(name,version,architecture,before=False):
    if not re.fullmatch(r'[a-z0-9+.-]+',name)or not isinstance(version,str)or not re.fullmatch(r'[^\s=\x00-\x1f]{1,200}',version)or architecture not in ['amd64','arm64','all']:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
    try:metadata=command(['apt-cache','show',name+':'+architecture+'='+version],30)
    except ValueError as error:
        if before and str(error)=='SYSTEM_SECURITY_QUERY_FAILED':raise ValueError('SYSTEM_SECURITY_BEFORE_INDEX_UNAVAILABLE')
        raise
    records=[]
    for block in metadata.split('\n\n'):
        fields={};invalid=False
        for line in block.splitlines():
            if line[:1].isspace()or ': 'not in line:continue
            key,value=line.split(': ',1)
            if key in fields:invalid=True
            fields[key]=value
        if fields.get('Package')!=name or fields.get('Version')!=version or fields.get('Architecture')!=architecture:continue
        if invalid:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        if before and 'SHA256'not in fields and 'Size'not in fields:continue
        digest=fields.get('SHA256','');size=fields.get('Size','')
        if not re.fullmatch(r'[a-f0-9]{64}',digest)or not size.isdecimal()or not 8<int(size)<=256*1024*1024:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        records.append((digest,int(size)))
    if before and not records:raise ValueError('SYSTEM_SECURITY_BEFORE_INDEX_UNAVAILABLE')
    if len(set(records))!=1:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
    digest,size=records[0];cache=pathlib.Path('/var/cache/apt/archives');matches=[]
    if cache.is_symlink()or cache.stat().st_uid!=0 or cache.stat().st_mode&0o022:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    for checked,path in enumerate(cache.glob(name+'_*.deb')):
        if checked>=128:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        if info.st_size!=size:continue
        checked=runtime_payload_regular(path,256*1024*1024,content=True)
        if checked['size']!=size or checked['sha256']!=digest:continue
        raw=checked['content']
        controls=debian_archive_members(raw)
        fields=dict(line.split(': ',1)for line in controls.get('control',b'').decode('utf-8').splitlines()if line[:1]not in [' ','\t']and ': 'in line)
        if any(fields.get(key)!=value for key,value in [('Package',name),('Version',version),('Architecture',architecture)]):raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        matches.append((path,raw,controls))
    if not matches:raise ValueError('SYSTEM_SECURITY_ARCHIVE_NOT_CACHED')
    if len(matches)!=1:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
    path,raw,controls=matches[0]
    return {'package':name,'version':version,'architecture':architecture,'sha256':digest,'size':size},raw,controls

def acquire_runtime_debian_archive(name,version,architecture,original=None,role='expected'):
    if role not in ['before','expected']:raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
    if original is not None and original.get('source',{}).get('kind')=='debian-snapshot':
        if role!='before':raise ValueError('SYSTEM_SECURITY_ARCHIVE_UNREVIEWED')
        return authenticated_before_snapshot(name,version,architecture,original)
    try:record,raw,controls=authenticated_debian_archive(name,version,architecture,before=role=='before')
    except ValueError as error:
        if role=='before'and str(error)=='SYSTEM_SECURITY_BEFORE_INDEX_UNAVAILABLE':return authenticated_before_snapshot(name,version,architecture,original)
        if str(error)!='SYSTEM_SECURITY_ARCHIVE_NOT_CACHED':raise
        command(['/usr/bin/env','--chdir=/var/cache/apt/archives','apt-get','-o','APT::Get::AllowUnauthenticated=false','download',name+':'+architecture+'='+version],600)
        record,raw,controls=authenticated_debian_archive(name,version,architecture,before=role=='before')
    if original is not None and record!=original:raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
    return record,raw,controls

DEBIAN_SNAPSHOT_KEYS={'debian':frozenset(['B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8','04B54C3CDCA79751B16BC6B5225629DF75B188BD','41587F7DB8C774BCCF131416762F67A0B2C39DE4']),
    'debian-security':frozenset(['5E04A1E3223A19A20706E20F9904613D4CCE68C6'])}

def snapshot_redirect_target(original,target,count):
    import urllib.parse,posixpath
    value=urllib.parse.urlsplit(target)
    basename=posixpath.basename(urllib.parse.urlsplit(original).path);encoded=urllib.parse.quote(basename,safe='-._~')
    target_name=posixpath.basename(value.path)
    if count!=0 or value.scheme!='https'or value.hostname!='snapshot.debian.org'or value.netloc!='snapshot.debian.org'or value.query or value.fragment or value.username or value.password or not re.fullmatch(r'/file/[a-f0-9]{40}/[A-Za-z0-9_.~:%\-]+',value.path)or target_name!=encoded or urllib.parse.unquote(target_name)!=basename:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
    return target

def snapshot_collected_time(source,signed):
    captured=source.get('collectedAt')if source else time.time()
    if type(captured)not in [int,float]or type(captured)is float and not math.isfinite(captured)or captured<signed['date']or captured>time.time():raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
    expired=signed['validUntil']is not None and signed['validUntil']<captured
    if source and (type(source.get('historicalExpired'))is not bool or source['historicalExpired']!=expired):raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
    return captured,expired

def snapshot_read(path,limit,budget):
    import urllib.request,urllib.error
    if not isinstance(path,str)or not path.startswith(('/mr/','/archive/'))or re.search(r'[\x00-\x20\\?#]',path)or '..'in path.split('/'):raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
    class Redirect(urllib.request.HTTPRedirectHandler):
        def __init__(self):self.count=0
        def redirect_request(self,request,fp,code,msg,headers,newurl):
            snapshot_redirect_target(request.full_url,newurl,self.count);self.count+=1;spend()
            return super().redirect_request(request,fp,code,msg,headers,newurl)
    def spend():
        if budget['requests']>=12 or time.monotonic()-budget['started']>=20:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_UNAVAILABLE')
        budget['requests']+=1
    spend();request=urllib.request.Request('https://snapshot.debian.org'+path,headers={'Accept-Encoding':'identity','User-Agent':'PayIncus-before-source-proof/1'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),Redirect());blocks=[];size=0
    try:
        with opener.open(request,timeout=max(.1,20-(time.monotonic()-budget['started'])))as stream:
            length=stream.headers.get('Content-Length')
            if length is not None and (not length.isdecimal()or int(length)>limit):raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
            while True:
                block=stream.read(min(262144,limit+1-size))
                if not block:break
                size+=len(block)
                if size>limit or time.monotonic()-budget['started']>=20:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_UNAVAILABLE')
                blocks.append(block)
    except (urllib.error.URLError,TimeoutError,OSError):raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_UNAVAILABLE')
    return b''.join(blocks)

def snapshot_release_fields(raw,archive,snapshot_time,directory):
    import email.utils
    if archive not in DEBIAN_SNAPSHOT_KEYS or not raw.startswith(b'-----BEGIN PGP SIGNED MESSAGE-----\n')or len(raw)>2*1024*1024:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
    keyring=pathlib.Path('/usr/share/keyrings/debian-archive-keyring.gpg');protected_hash(keyring)
    signature=directory/'InRelease';write_runtime_evidence_file(signature,raw)
    status=command(['gpgv','--status-fd=1','--keyring',str(keyring),str(signature)],30)
    fingerprints=[]
    for line in status.splitlines():
        fields=line.split()
        if len(fields)>=3 and fields[:2]==['[GNUPG:]','VALIDSIG']:
            fingerprint=fields[-1]if re.fullmatch(r'[A-F0-9]{40}',fields[-1])else fields[2]
            if fingerprint not in DEBIAN_SNAPSHOT_KEYS[archive]:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
            fingerprints.append(fingerprint)
    if not fingerprints or any(code in status for code in [' BADSIG ',' ERRSIG ',' NO_PUBKEY ',' NODATA ']):raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
    try:
        body=raw.split(b'\n\n',1)[1].split(b'\n-----BEGIN PGP SIGNATURE-----',1)[0]
        text='\n'.join(line.removeprefix('- ')for line in body.decode('utf-8').splitlines());fields={};sha={};section=None
        for line in text.splitlines():
            if line.startswith(' '):
                if section=='SHA256':
                    match=re.fullmatch(r' ([a-f0-9]{64})\s+(\d+)\s+([A-Za-z0-9_+./:-]+)',line)
                    if not match or match[3]in sha:raise ValueError()
                    sha[match[3]]={'sha256':match[1],'size':int(match[2])}
                continue
            key,value=line.split(':',1)
            if key in fields:raise ValueError()
            fields[key]=value.strip();section=key
        suite='trixie-security'if archive=='debian-security'else'trixie'
        date=email.utils.parsedate_to_datetime(fields['Date']).timestamp();selected=calendar.timegm(time.strptime(snapshot_time,'%Y%m%dT%H%M%SZ'))
        if fields.get('Origin')!='Debian'or fields.get('Codename')!=suite or fields.get('Suite')not in (['stable-security','oldstable-security','testing-security']if archive=='debian-security'else['stable','oldstable','testing'])or date>selected or date>time.time()or 'main'not in fields.get('Components','').split():raise ValueError()
        until=email.utils.parsedate_to_datetime(fields['Valid-Until']).timestamp()if fields.get('Valid-Until')else None
        if until is not None and until<date:raise ValueError()
    except (ValueError,KeyError,UnicodeDecodeError,IndexError):raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
    return {'suite':suite,'fingerprints':sorted(set(fingerprints)),'sha256':sha,'date':date,'validUntil':until,'historicalOnly':True,'expired':until is not None and until<time.time()}

def snapshot_package_record(compressed,release,name,version,architecture):
    import lzma,io
    try:
        decoder=lzma.LZMADecompressor(memlimit=64*1024*1024);raw=decoder.decompress(compressed,512*1024*1024+1)
        if len(raw)>512*1024*1024 or not decoder.eof or decoder.unused_data:raise ValueError()
        records=[];fields={};count=0
        for line in io.BytesIO(raw):
            count+=1
            if len(line)>262144 or count>10000000:raise ValueError()
            if line==b'\n':
                if fields.get('Package')==name and fields.get('Version')==version and fields.get('Architecture')==architecture:records.append(fields)
                fields={};continue
            if line[:1].isspace():continue
            key,value=line.decode('utf-8').rstrip('\n').split(': ',1)
            if key in fields:raise ValueError()
            fields[key]=value
        if fields.get('Package')==name and fields.get('Version')==version and fields.get('Architecture')==architecture:records.append(fields)
        if not records:return None
        unique={(row.get('SHA256'),row.get('Size'),row.get('Filename'))for row in records}
        if len(unique)!=1:raise ValueError()
        digest,size,filename=next(iter(unique))
        if not re.fullmatch(r'[a-f0-9]{64}',digest or '')or not isinstance(size,str)or not size.isdecimal()or not 8<int(size)<=256*1024*1024 or not re.fullmatch(r'pool/main/[A-Za-z0-9_+./:~\-]+\.deb',filename or '')or '..'in filename.split('/'):raise ValueError()
    except (ValueError,UnicodeDecodeError,lzma.LZMAError):raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
    return {'package':name,'version':version,'architecture':architecture,'sha256':digest,'size':int(size)},filename

def write_runtime_evidence_file(path,data):
    if path.exists()or path.is_symlink():
        value=runtime_payload_regular(path,max(len(data),1),private=True,content=True)
        if value['content']!=data:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
        return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def sync_runtime_evidence_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        os.fsync(fd)
    finally:os.close(fd)

def complete_runtime_fixed_evidence(path,data):
    # The caller binds this exact private pathname and byte string to the
    # durable original journal. A crash may leave only its own prefix; append
    # the remainder through that same inode without replacing the old bytes.
    exists=runtime_path_present(path)
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|(0 if exists else os.O_CREAT|os.O_EXCL),0o600)
    try:
        if not exists:os.fchmod(fd,0o600)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or not 0<=info.st_size<=len(data):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        raw=os.read(fd,len(data)+1);after=os.fstat(fd)
        if len(raw)!=info.st_size or not data.startswith(raw)or not os.path.samestat(info,os.lstat(path))or any(getattr(info,key)!=getattr(after,key)for key in ['st_size','st_mtime_ns','st_ctime_ns']):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        os.lseek(fd,0,os.SEEK_END);view=memoryview(data)[len(raw):]
        while view:
            written=os.write(fd,view)
            if written<=0:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            view=view[written:]
        os.fsync(fd)
        if not os.path.samestat(info,os.lstat(path))or os.fstat(fd).st_size!=len(data):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    finally:os.close(fd)
    sync_runtime_evidence_directory(path.parent)

def authenticated_before_snapshot(name,version,architecture,original=None):
    import urllib.parse,datetime
    if not re.fullmatch(r'[a-z0-9+.-]+',name)or not re.fullmatch(r'[0-9A-Za-z.+:~_\-]{1,200}',version)or architecture not in ['amd64','arm64','all']:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
    release=dict(line.split('=',1)for line in pathlib.Path('/etc/os-release').read_text().splitlines()if '='in line)
    if release.get('ID','').strip('"')!='debian'or release.get('VERSION_CODENAME','').strip('"')!='trixie':raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_UNAVAILABLE')
    root=pathlib.Path('/var/lib/incudal-system-security')/'before-sources';root.mkdir(mode=0o700,exist_ok=True)
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or root.resolve()!=root:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    cache_key=hashlib.sha256((name+'\n'+version+'\n'+architecture).encode()).hexdigest();cache=root/cache_key
    budget={'requests':0,'started':time.monotonic()}
    with tempfile.TemporaryDirectory(prefix='.snapshot-verify-',dir=root)as temporary:
        verify_directory=pathlib.Path(temporary)
        if cache.exists()or cache.is_symlink():
            info=cache.lstat()
            if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or cache.resolve()!=cache or {path.name for path in cache.iterdir()}-{'InRelease','Packages.xz','archive.deb','proof.json'}:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
        record=None;cached_source=None
        if (cache/'proof.json').exists():
            proof=json.loads(runtime_payload_regular(cache/'proof.json',65536,private=True,content=True)['content']);source=proof.get('source',{})
            if source.get('role')!='before'or source.get('kind')!='debian-snapshot'or source.get('cacheKey')!=cache_key or source.get('archive')not in DEBIAN_SNAPSHOT_KEYS or not re.fullmatch(r'\d{8}T\d{6}Z',source.get('snapshotTime','')):raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
            inrelease=runtime_payload_regular(cache/'InRelease',2*1024*1024,private=True,content=True)['content'];index=runtime_payload_regular(cache/'Packages.xz',64*1024*1024,private=True,content=True)['content'];archive_raw=runtime_payload_regular(cache/'archive.deb',256*1024*1024,private=True,content=True)['content']
            candidates=[(source['archive'],source['snapshotTime'])]
            cached_source=source
        else:
            metadata=json.loads(snapshot_read('/mr/binary/'+name+'/'+urllib.parse.quote(version,safe='')+'/binfiles',1024*1024,budget))
            if metadata.get('binary')!=name or metadata.get('binary_version')!=version or not isinstance(metadata.get('result'),list)or len(metadata['result'])>32:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
            hashes={row.get('hash')for row in metadata['result']if isinstance(row,dict)and row.get('architecture')==architecture}
            if len(hashes)!=1 or not re.fullmatch(r'[a-f0-9]{40}',next(iter(hashes))or ''):raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
            identifier=next(iter(hashes));locations=json.loads(snapshot_read('/mr/file/'+identifier+'/info',1024*1024,budget))
            if locations.get('hash')!=identifier or not isinstance(locations.get('result'),list)or len(locations['result'])>64:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
            times=[]
            for row in locations['result']:
                if isinstance(row,dict)and row.get('archive_name')in DEBIAN_SNAPSHOT_KEYS and re.fullmatch(r'\d{8}T\d{6}Z',row.get('first_seen','')):
                    first=datetime.datetime.strptime(row['first_seen'],'%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc)
                    if first.timestamp()>time.time():raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
                    times.extend((row['archive_name'],(first+datetime.timedelta(days=day)).strftime('%Y%m%dT%H%M%SZ'))for day in [0,1]if (first+datetime.timedelta(days=day)).timestamp()<=time.time())
            candidates=sorted(set(times),key=lambda row:row[1])[:2]
            if not candidates:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_UNAVAILABLE')
        for archive,snapshot_time in candidates:
            base='/archive/'+archive+'/'+snapshot_time+'/';suite='trixie-security'if archive=='debian-security'else'trixie'
            if not (cache/'proof.json').exists():inrelease=snapshot_read(base+'dists/'+suite+'/InRelease',2*1024*1024,budget)
            signed=snapshot_release_fields(inrelease,archive,snapshot_time,verify_directory);index_path='main/binary-'+('amd64'if architecture=='all'else architecture)+'/Packages.xz';index_record=signed['sha256'].get(index_path)
            if not isinstance(index_record,dict)or not 0<index_record['size']<=64*1024*1024:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
            if not (cache/'proof.json').exists():index=snapshot_read(base+'dists/'+suite+'/'+index_path,64*1024*1024,budget)
            if len(index)!=index_record['size']or hashlib.sha256(index).hexdigest()!=index_record['sha256']:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
            match=snapshot_package_record(index,signed,name,version,architecture)
            if match is None:
                if (verify_directory/'InRelease').exists():(verify_directory/'InRelease').unlink()
                continue
            record,filename=match
            if not (cache/'proof.json').exists():archive_raw=snapshot_read(base+filename,256*1024*1024,budget)
            if len(archive_raw)!=record['size']or hashlib.sha256(archive_raw).hexdigest()!=record['sha256']:raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
            controls=debian_archive_members(archive_raw);identity=dict(line.split(': ',1)for line in controls.get('control',b'').decode('utf-8').splitlines()if ': 'in line and not line[:1].isspace())
            if any(identity.get(key)!=value for key,value in [('Package',name),('Version',version),('Architecture',architecture)]):raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_REJECTED')
            collected,expired=snapshot_collected_time(cached_source,signed)
            record['source']={'role':'before','kind':'debian-snapshot','cacheKey':cache_key,'archive':archive,'suite':suite,'snapshotTime':snapshot_time,'fingerprints':signed['fingerprints'],'releaseSha256':hashlib.sha256(inrelease).hexdigest(),'indexSha256':index_record['sha256'],'filename':filename,'historicalDate':signed['date'],'historicalValidUntil':signed['validUntil'],'collectedAt':collected,'historicalExpired':expired}
            if cached_source is not None and record!=proof:raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
            if original is not None:
                # A previously authenticated APT Before may disappear from
                # its index after cache cleanup. Preserve that original proof
                # while independently authenticating exactly the same bytes
                # through the limited historical source; never turn history
                # into an Expected installation archive.
                compared=record if original.get('source')else{key:value for key,value in record.items()if key!='source'}
                if compared!=original:raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
            cache.mkdir(mode=0o700,exist_ok=True)
            for filename,data in [('InRelease',inrelease),('Packages.xz',index),('archive.deb',archive_raw)]:write_runtime_evidence_file(cache/filename,data)
            write_runtime_evidence_file(cache/'proof.json',json.dumps(record,sort_keys=True,separators=(',',':')).encode())
            sync_runtime_evidence_directory(root);sync_runtime_evidence_directory(root.parent)
            return original if original is not None else record,archive_raw,controls
    raise ValueError('SYSTEM_SECURITY_BEFORE_SOURCE_UNAVAILABLE')

def reviewed_maintainer_controls(controls,expected):
    metadata={'control','conffiles','md5sums','templates','shlibs','symbols'}
    actual={name:hashlib.sha256(raw).hexdigest()for name,raw in controls.items()if name not in metadata}
    if not expected or actual!=expected:raise ValueError('SYSTEM_SECURITY_SYSTEMD_TRIGGER_UNREVIEWED')
    return actual

def installed_maintainer_controls(name,architecture,expected,incomplete=False):
    info=pathlib.Path('/var/lib/dpkg/info');actual={}
    for suffix in ['preinst','postinst','prerm','postrm','config','triggers']:
        paths=[path for path in [info/(name+'.'+suffix),info/(name+':'+architecture+'.'+suffix)]if path.exists()or path.is_symlink()]
        if len(paths)>1:raise ValueError('SYSTEM_SECURITY_SYSTEMD_TRIGGER_UNREVIEWED')
        if paths:actual[suffix]=protected_hash(paths[0])
    if actual!=expected and (not incomplete or any(expected.get(key)!=value for key,value in actual.items())):raise ValueError('SYSTEM_SECURITY_SYSTEMD_TRIGGER_UNREVIEWED')

def runtime_archive_programs(raw,names):
    return {path:hashlib.sha256(content).hexdigest()for path,content in debian_archive_members(raw,'data',names).items()}

def runtime_systemd_state():
    # Compare stable address/route configuration, not declining DHCP lease
    # lifetimes or traffic counters. Configuration values are never logged.
    address=json.loads(command(['ip','-j','address','show'],20));route=json.loads(command(['ip','-j','route','show','table','all'],20));route6=json.loads(command(['ip','-6','-j','route','show','table','all'],20))
    if not isinstance(address,list)or not isinstance(route,list)or not isinstance(route6,list)or len(address)>4096 or len(route)+len(route6)>20000:raise ValueError('SYSTEM_SECURITY_SYSTEMD_NETWORK_UNREVIEWED')
    links=[]
    for row in address:
        value={key:row.get(key)for key in ['ifindex','ifname','flags','mtu','operstate','master','address','link_type']}
        value['addresses']=[{key:item.get(key)for key in ['family','local','prefixlen','scope','label','flags']}for item in row.get('addr_info',[])]
        value['addresses'].sort(key=lambda item:json.dumps(item,sort_keys=True));links.append(value)
    routes=[[family,{key:row.get(key)for key in ['dst','gateway','dev','protocol','scope','type','prefsrc','table','metric','nexthops']}]for family,rows in [(4,route),(6,route6)]for row in rows]
    links.sort(key=lambda item:json.dumps(item,sort_keys=True));routes.sort(key=lambda item:json.dumps(item,sort_keys=True))
    files={}
    for pattern in ['/etc/systemd/system.conf','/etc/systemd/system.conf.d/*.conf','/etc/systemd/journald.conf','/etc/systemd/journald.conf.d/*.conf','/etc/wireguard/*.conf','/etc/network/interfaces','/etc/network/interfaces.d/*','/etc/netplan/*.yaml']:
        import glob
        for path in glob.glob(pattern):
            if len(files)>=256:raise ValueError('SYSTEM_SECURITY_SYSTEMD_CONFIGURATION_UNREVIEWED')
            files[path]=protected_hash(path)
    return {'configurationHashes':files,'networkHash':hashlib.sha256(json.dumps([links,routes],sort_keys=True).encode()).hexdigest()}

def runtime_systemd_process(pid,program):
    if type(pid)is not int or pid<1:raise ValueError('SYSTEM_SECURITY_SYSTEMD_PROCESS_CHANGED')
    process=pathlib.Path('/proc',str(pid));binary=pathlib.Path(program)
    if str((process/'exe').readlink()).removesuffix(' (deleted)')!=program or not os.path.samestat(binary.stat(),(process/'exe').stat())or (process/'ns/pid').readlink()!=pathlib.Path('/proc/1/ns/pid').readlink()or not os.path.samestat((process/'root').stat(),pathlib.Path('/').stat()):raise ValueError('SYSTEM_SECURITY_SYSTEMD_PROCESS_CHANGED')
    status=(process/'status').read_text();uids=re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',status,re.M)
    if not uids or any(value!='0'for value in uids.groups()):raise ValueError('SYSTEM_SECURITY_SYSTEMD_PROCESS_CHANGED')
    raw=(process/'stat').read_text();position=raw.rfind(') ');fields=raw[position+2:].split()
    if position<0 or len(raw)>8192 or len(fields)<20 or not fields[19].isdecimal():raise ValueError('SYSTEM_SECURITY_SYSTEMD_PROCESS_CHANGED')
    with (process/'maps').open()as stream:maps=stream.read(1024*1024+1)
    if len(maps)>1024*1024:raise ValueError('SYSTEM_SECURITY_SYSTEMD_CHECK_INCOMPLETE')
    replaced=any(line.endswith(' (deleted)')and len(line.split(maxsplit=5))==6 and 'x'in line.split(maxsplit=5)[1]and line.split(maxsplit=5)[5].startswith('/')and not line.split(maxsplit=5)[5].startswith(('/dev/','/memfd:','/SYSV'))for line in maps.splitlines())
    return {'pid':pid,'start':fields[19],'binaryHash':protected_hash(binary),'replacedLibraries':replaced}

def runtime_systemd_qualification(programs):
    if command(['systemctl','list-units','--type=service','--state=active,activating,reloading,deactivating','--no-legend','--plain','--no-pager','user@*.service'],20):raise ValueError('SYSTEM_SECURITY_SYSTEMD_USER_MANAGERS_ACTIVE')
    networkd=dict(line.split('=',1)for line in command(['systemctl','show','systemd-networkd.service','--property=LoadState,ActiveState,MainPID,FragmentPath,DropInPaths'],20).splitlines()if '='in line)
    if networkd.get('ActiveState')!='inactive'or networkd.get('MainPID')!='0'or networkd.get('DropInPaths','')or networkd.get('LoadState')not in ['loaded','not-found']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_NETWORKD_ACTIVE')
    if networkd.get('LoadState')=='loaded':
        if networkd.get('FragmentPath')not in ['/usr/lib/systemd/system/systemd-networkd.service','/lib/systemd/system/systemd-networkd.service']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_NETWORK_UNREVIEWED')
        networkd['unitHash']=protected_hash(networkd['FragmentPath'])
    journald=dict(line.split('=',1)for line in command(['systemctl','show','systemd-journald.service','--property=LoadState,ActiveState,MainPID,FragmentPath,DropInPaths'],20).splitlines()if '='in line)
    if journald.get('LoadState')!='loaded'or journald.get('ActiveState')!='active'or journald.get('DropInPaths','')or journald.get('FragmentPath')not in ['/usr/lib/systemd/system/systemd-journald.service','/lib/systemd/system/systemd-journald.service']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_JOURNAL_UNREVIEWED')
    pid=int(journald.get('MainPID','0'));journal_process=runtime_systemd_process(pid,'/usr/lib/systemd/systemd-journald')
    manager=runtime_systemd_process(1,'/usr/lib/systemd/systemd')
    for path,digest in programs.items():
        if protected_hash('/'+path)!=digest:raise ValueError('SYSTEM_SECURITY_SYSTEMD_BINARY_UNREVIEWED')
    return {'manager':manager,'journald':journal_process,'networkd':networkd,'journaldUnit':protected_hash(journald['FragmentPath']),'state':runtime_systemd_state()}

def prepare_runtime_systemd_policy(changes,baseline):
    if not any(item.split('=',1)[0]in RUNTIME_DEBIAN_BASE_LIBRARIES for item in changes):return None
    installed=reviewed_debian_inventory(baseline,RUNTIME_DEBIAN_BASE_LIBRARIES|{'systemd'})
    validate_runtime_libc_plan(changes,installed)
    systemd=[key for key in baseline if key.split(':')[0]=='systemd']
    if len(systemd)!=1 or libc_security_series(installed.get('libc6'))!='2.41':raise ValueError('SYSTEM_SECURITY_SYSTEMD_TRIGGER_UNREVIEWED')
    architecture=systemd[0].split(':')[1];version=baseline[systemd[0]]
    if architecture not in RUNTIME_LIBC_CONTROL['libc6']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_TRIGGER_UNREVIEWED')
    # Authenticate the installed manager's actual maintainer code against its
    # exact repository archive too. Local dpkg information alone is not trust.
    archives={};programs={};libc_programs={};libc_before={}
    for name in ['systemd','libc6','libc-bin']:
        candidate=dict(item.split('=',1)for item in changes).get(name,installed[name])
        archive,raw,controls=acquire_runtime_debian_archive(name,candidate,architecture,role='before'if name=='systemd'else'expected')
        expected=RUNTIME_SYSTEMD_CONTROL if name=='systemd'else RUNTIME_LIBC_CONTROL[name][architecture]
        reviewed_maintainer_controls(controls,expected);installed_maintainer_controls(name,architecture,expected)
        archives[name]=archive
        if name=='systemd':
            wanted=['usr/lib/systemd/systemd','usr/lib/systemd/systemd-journald','usr/lib/systemd/system/systemd-journald.service']
            programs=runtime_archive_programs(raw,wanted)
            if programs!=RUNTIME_SYSTEMD_PROGRAMS[architecture]:raise ValueError('SYSTEM_SECURITY_SYSTEMD_BINARY_UNREVIEWED')
        elif name=='libc6':
            libc_programs=runtime_archive_programs(raw,RUNTIME_LIBC_FILES[architecture])
            _,original_raw,original_controls=acquire_runtime_debian_archive(name,installed[name],architecture,role='before')
            reviewed_maintainer_controls(original_controls,expected)
            libc_before=runtime_archive_programs(original_raw,RUNTIME_LIBC_FILES[architecture])
            if any(runtime_library_file('/'+path)['sha256']!=digest for path,digest in libc_before.items()):raise ValueError('SYSTEM_SECURITY_LIBC_PAYLOAD_UNCONFIRMED')
    interests=[]
    for file in pathlib.Path('/var/lib/dpkg/info').glob('*.triggers'):
        if file.stat().st_size>1024*1024:raise ValueError('SYSTEM_SECURITY_SYSTEMD_TRIGGER_UNREVIEWED')
        protected_hash(file)
        if any(re.fullmatch(r'\s*interest(?:-noawait|-await)?\s+libc-upgrade\s*',line)for line in file.read_text().splitlines()if not line.lstrip().startswith('#')):interests.append(file.name)
    if interests!=['systemd.triggers']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_TRIGGER_UNREVIEWED')
    qualification=runtime_systemd_qualification(programs);token=uuid.uuid4().hex
    return {'version':1,'token':token,'directory':'runtime-systemctl-'+token,'sourceHash':hashlib.sha256(RUNTIME_SYSTEMCTL_WRAPPER.encode()).hexdigest(),
        'bootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'archives':archives,'programs':programs,'qualification':qualification,
        'libcPrograms':libc_programs,'libcProgramsArchive':archives['libc6']['sha256'],'baselineLibcPrograms':libc_before}

def runtime_path_present(path):
    # Python 3.14 exists()/is_symlink() suppress access and IO failures too.
    # Only an actual missing entry is authority to skip or create evidence.
    try:path.lstat();return True
    except FileNotFoundError:return False
    except OSError:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')

def runtime_systemctl_policy_directory(proof):
    if not isinstance(proof,dict)or proof.get('version')!=1 or not re.fullmatch(r'[a-f0-9]{32}',proof.get('token',''))or proof.get('directory')!='runtime-systemctl-'+proof['token']or proof.get('sourceHash')!=hashlib.sha256(RUNTIME_SYSTEMCTL_WRAPPER.encode()).hexdigest():raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    root=pathlib.Path('/var/lib/incudal-system-security')/proof['directory']
    if runtime_path_present(root):
        info=root.lstat()
        if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or root.resolve()!=root:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    return root

def runtime_systemctl_preparation_files(proof):
    return {'systemctl':(RUNTIME_SYSTEMCTL_WRAPPER.encode(),0o755),'policy.lock':(b'',0o600),
        'policy.json':(json.dumps({'version':1,'token':proof['token'],'sourceHash':proof['sourceHash'],'actions':[],'rejected':False}).encode(),0o600)}

def repair_runtime_systemctl_preparation(journal,proof,path,data,mode):
    if proof.get('ready')or path.parent!=runtime_systemctl_policy_directory(proof):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    value=runtime_payload_regular(path,max(len(data),1),private=path.name!='systemctl',content=True);raw=value['content']
    if not data.startswith(raw)or value['uid']!=0:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    if raw==data and value['mode']==mode:return
    # This nonce has never been published ready, so the wrapper cannot have
    # acted on these bytes. Preserve only a proven prefix of our own fixed
    # preparation; a recorded refusal/action or third content cannot match it.
    digest=value['sha256'];binding=hashlib.sha256((proof['token']+'\n'+path.name+'\n'+digest+'\n'+str(value['mode'])).encode()).hexdigest()
    failure={'token':proof['token'],'name':path.name,'sha256':digest,'size':value['size'],'mode':value['mode'],'file':binding+'.partial'}
    failures=journal.setdefault('policyPreparationFailures',[])
    if not isinstance(failures,list)or len(failures)>32:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    if failure not in failures:
        if len(failures)>=32:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        failures.append(failure);write_runtime_maintenance(journal)
    directory=runtime_dump_directory(journal)/'policy-failures'
    if not runtime_path_present(directory):directory.mkdir(mode=0o700);sync_runtime_evidence_directory(directory.parent)
    info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or directory.resolve()!=directory:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    complete_runtime_fixed_evidence(directory/failure['file'],raw)
    fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=value['mode']or info.st_size!=len(raw)or os.read(fd,len(raw)+1)!=raw:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        os.ftruncate(fd,0);os.lseek(fd,0,os.SEEK_SET)
        view=memoryview(data)
        while view:
            written=os.write(fd,view)
            if written<=0:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
            view=view[written:]
        os.fsync(fd);os.fchmod(fd,mode);os.fsync(fd)
    finally:os.close(fd)

def repair_runtime_unready_policy_files(journal,proof):
    if proof.get('ready'):return
    root=runtime_systemctl_policy_directory(proof)
    if not runtime_path_present(root):return
    expected=runtime_systemctl_preparation_files(proof)
    for path in root.iterdir():
        if path.name not in expected:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        data,mode=expected[path.name];repair_runtime_systemctl_preparation(journal,proof,path,data,mode)

RUNTIME_SYSTEMD_ORIGIN_FIELDS=('version','token','directory','sourceHash','bootId','archives','programs','qualification','libcPrograms','libcProgramsArchive','baselineLibcPrograms')

def runtime_systemd_origin_hash(proof):
    if not isinstance(proof,dict)or any(field not in proof for field in RUNTIME_SYSTEMD_ORIGIN_FIELDS):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    return hashlib.sha256(json.dumps({field:proof[field]for field in RUNTIME_SYSTEMD_ORIGIN_FIELDS},sort_keys=True,separators=(',',':')).encode()).hexdigest()

def runtime_systemd_policy_history(proof):
    root=runtime_systemctl_policy_directory(proof);exists=runtime_path_present(root)
    if proof.get('cleared'):
        actions=proof.get('recordedActions',proof.get('deferredActions'));hashes=proof.get('cleanupHashes')
        if not isinstance(actions,list)or len(actions)!=len(set(actions))or any(action not in RUNTIME_SYSTEMCTL_ACTIONS.values()for action in actions)or not isinstance(hashes,dict)or set(hashes)!={'systemctl','policy.lock','policy.json'}or hashes.get('systemctl')!=proof['sourceHash']or any(not isinstance(value,str)or not re.fullmatch(r'[a-f0-9]{64}',value)for value in hashes.values()):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        if exists:
            for file in root.iterdir():
                if file.name not in hashes or protected_hash(file,private=file.name!='systemctl')!=hashes[file.name]:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        digest=hashes['policy.json']
    elif not proof.get('ready'):
        # An appended permission which never became ready cannot have been
        # used by the wrapper. Retain its ordinal and exact preparation bytes
        # across another boot instead of issuing an unbounded replacement.
        if not proof.get('originHash'):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        prepared={'systemctl':RUNTIME_SYSTEMCTL_WRAPPER.encode(),'policy.lock':b'',
            'policy.json':json.dumps({'version':1,'token':proof['token'],'sourceHash':proof['sourceHash'],'actions':[],'rejected':False}).encode()}
        if exists:
            for file in root.iterdir():
                if file.name not in prepared or protected_hash(file,private=file.name!='systemctl')!=hashlib.sha256(prepared[file.name]).hexdigest():raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        actions=[];digest=hashlib.sha256(prepared['policy.json']).hexdigest()
    else:
        if not exists or {file.name for file in root.iterdir()}!={'systemctl','policy.lock','policy.json'}or protected_hash(root/'systemctl')!=proof['sourceHash']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        value=read_runtime_systemctl_policy(proof,allow_rejected=True)
        if value['rejected']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_REJECTED')
        actions=value['actions'];digest=protected_hash(root/'policy.json',private=True)
    return {'token':proof['token'],'bootId':proof['bootId'],'actions':actions,'receiptHash':digest}

def runtime_systemd_policy_lineage(journal):
    original=journal.get('systemdPolicy')
    if not original:return []
    runtime_systemctl_policy_directory(original);origin=runtime_systemd_origin_hash(original)
    policies=journal.get('systemdBootPolicies',[])
    if not isinstance(policies,list)or len(policies)>3:raise ValueError('SYSTEM_SECURITY_SYSTEMD_BOOT_RECOVERY_LIMIT')
    if policies and(not isinstance(original.get('bootId'),str)or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',original['bootId'])):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    tokens={original['token']};boots={original['bootId']}
    for ordinal,proof in enumerate(policies,1):
        runtime_systemctl_policy_directory(proof)
        if type(proof.get('ordinal'))is not int or proof['ordinal']!=ordinal or proof.get('originalToken')!=original['token']or proof.get('originHash')!=origin or proof.get('sourceHash')!=original['sourceHash']or not isinstance(proof.get('bootId'),str)or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',proof['bootId'])or proof['bootId']in boots or proof['token']in tokens:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        for field in ['archives','programs','libcPrograms','libcProgramsArchive','baselineLibcPrograms']:
            if proof.get(field)!=original.get(field):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        inherited=proof.get('inheritedActions')
        if not isinstance(inherited,list)or len(inherited)!=len(set(inherited))or any(action not in RUNTIME_SYSTEMCTL_ACTIONS.values()for action in inherited):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        tokens.add(proof['token']);boots.add(proof['bootId'])
    return [original,*policies]

def runtime_active_systemd_policy(journal):
    lineage=runtime_systemd_policy_lineage(journal)
    if not lineage:return None
    if len(lineage)==1:return lineage[0]
    boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    return next((proof for proof in lineage if proof['bootId']==boot),lineage[0])

def prepare_runtime_systemd_boot_policy(journal):
    original=journal.get('systemdPolicy');boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not original or boot==original.get('bootId'):return None
    if not isinstance(original.get('bootId'),str)or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',original['bootId'])or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot):raise ValueError('SYSTEM_SECURITY_SYSTEMD_PROCESS_CHANGED')
    lineage=runtime_systemd_policy_lineage(journal)
    # Every old refusal remains binding. We never erase an old receipt or
    # reissue its token simply because the machine has a new boot identifier.
    for previous in lineage:
        if previous.get('originHash')and not previous.get('ready'):repair_runtime_unready_policy_files(journal,previous)
    histories=[runtime_systemd_policy_history(proof)for proof in lineage if proof['bootId']!=boot]
    history_hash=hashlib.sha256(json.dumps(histories,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    inherited=sorted({action for history in histories for action in history['actions']})
    active=next((proof for proof in lineage if proof['bootId']==boot),None)
    if active is not None:
        if active.get('historyHash')!=history_hash or active['inheritedActions']!=inherited:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        if active.get('ready'):runtime_systemd_policy_history(active)
        return active
    if len(lineage)>=4:raise ValueError('SYSTEM_SECURITY_SYSTEMD_BOOT_RECOVERY_LIMIT')
    verify_runtime_systemd_package_authority(journal,archives=True);verify_runtime_payload(journal,archives=True)
    qualification=runtime_systemd_qualification(original['programs'])
    if qualification['state']['configurationHashes']!=original['qualification']['state']['configurationHashes']or any(qualification[field]!=original['qualification'][field]for field in ['networkd','journaldUnit']):raise ValueError('SYSTEM_SECURITY_SYSTEMD_CONFIGURATION_CHANGED')
    token=uuid.uuid4().hex
    proof=json.loads(json.dumps({field:original[field]for field in RUNTIME_SYSTEMD_ORIGIN_FIELDS}))
    proof.update(token=token,directory='runtime-systemctl-'+token,bootId=boot,qualification=qualification,ordinal=len(lineage),originalToken=original['token'],originHash=runtime_systemd_origin_hash(original),historyHash=history_hash,inheritedActions=inherited)
    journal.setdefault('systemdBootPolicies',[]).append(proof)
    write_runtime_maintenance(journal)
    return proof

def ensure_runtime_systemctl_policy(journal):
    proof=runtime_active_systemd_policy(journal)
    if not proof:return
    root=runtime_systemctl_policy_directory(proof)
    if proof.get('cleared'):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    names={file.name for file in root.iterdir()}if runtime_path_present(root)else set()
    if not names<={'systemctl','policy.lock','policy.json'}or proof.get('ready')and names!={'systemctl','policy.lock','policy.json'}:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    if not proof.get('ready')and journal.get('phase')!='prepared':
        recovery=journal.get('bootRecoveries',{}).get(proof['bootId'],{})
        if not proof.get('originHash')or journal.get('phase')not in ['installing','installed']or recovery.get('bootId')!=proof['bootId']or recovery.get('drainConfirmed')is not True:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    root.mkdir(mode=0o700,exist_ok=True)
    if not proof.get('ready'):repair_runtime_unready_policy_files(journal,proof)
    for name,content,mode in [('systemctl',RUNTIME_SYSTEMCTL_WRAPPER,0o755),('policy.lock','',0o600),('policy.json',json.dumps({'version':1,'token':proof['token'],'sourceHash':proof['sourceHash'],'actions':[],'rejected':False}),0o600)]:
        path=root/name
        if runtime_path_present(path):
            protected_hash(path,private=name!='systemctl')
            if name=='systemctl'and (stat.S_IMODE(path.lstat().st_mode)!=0o755 or hashlib.sha256(path.read_bytes()).hexdigest()!=proof['sourceHash']):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
            continue
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        os.fchmod(fd,mode)
        with os.fdopen(fd,'w')as out:out.write(content);out.flush();os.fsync(out.fileno())
    read_runtime_systemctl_policy(proof)
    if not proof.get('ready'):
        # Persist the wrapper and receipt directory entries before recording
        # ready in the parent journal. A durable parent rename alone does not
        # make the files in this new directory survive a power loss.
        directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
        proof['ready']=True;write_runtime_maintenance(journal)

def read_runtime_systemctl_policy(proof,allow_rejected=False):
    root=runtime_systemctl_policy_directory(proof);path=root/'policy.json';protected_hash(path,private=True)
    value=json.loads(path.read_text())
    if value.get('version')!=1 or value.get('token')!=proof.get('token')or value.get('sourceHash')!=proof.get('sourceHash')or type(value.get('rejected'))is not bool or not isinstance(value.get('actions'),list)or len(value['actions'])>4 or any(not isinstance(action,str)for action in value['actions'])or len(set(value['actions']))!=len(value['actions'])or any(action not in RUNTIME_SYSTEMCTL_ACTIONS.values()for action in value['actions']):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    if value['rejected']and not allow_rejected:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_REJECTED')
    return value

def verify_runtime_systemd_package_authority(journal,archives=False):
    proof=journal.get('systemdPolicy');runtime_systemctl_policy_directory(proof)
    records=proof.get('archives');expected=journal.get('expectedPackages')
    if not isinstance(records,dict)or set(records)!={'systemd','libc6','libc-bin'}or any(not isinstance(record,dict)for record in records.values())or not isinstance(expected,dict):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    architecture=records['systemd'].get('architecture')
    if architecture not in RUNTIME_SYSTEMD_PROGRAMS or proof.get('programs')!=RUNTIME_SYSTEMD_PROGRAMS[architecture]:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    for key in ['libcPrograms','baselineLibcPrograms']:
        profile=proof.get(key)
        if not isinstance(profile,dict)or set(profile)!=RUNTIME_LIBC_FILES[architecture]or any(not isinstance(digest,str)or not re.fullmatch(r'[a-f0-9]{64}',digest)for digest in profile.values()):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    if proof.get('libcProgramsArchive')!=records['libc6'].get('sha256'):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    states=debian_package_states()
    for name,record in records.items():
        if not isinstance(record,dict)or record.get('package')!=name or record.get('architecture')!=architecture or record.get('version')!=expected.get(name+':'+architecture)or not re.fullmatch(r'[a-f0-9]{64}',record.get('sha256',''))or type(record.get('size'))is not int or not 8<record['size']<=256*1024*1024:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        reviewed=RUNTIME_SYSTEMD_CONTROL if name=='systemd'else RUNTIME_LIBC_CONTROL[name][architecture]
        state=states.get(name+':'+architecture)
        if not isinstance(state,dict)or state.get('version')not in [journal['baselinePackages'].get(name+':'+architecture),expected.get(name+':'+architecture)]:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        incomplete=name in RUNTIME_DEBIAN_BASE_LIBRARIES and state.get('status')!='installed'and journal.get('phase')in ['installing','installed']
        if name in RUNTIME_DEBIAN_BASE_LIBRARIES and state.get('status')=='installed'and journal.get('phase')in ['installing','installed']and journal.get('payloadEvidence'):
            # An interrupted formal control write can coexist with an
            # installed dpkg registration. Only an original authenticated
            # plan/cached archive can authorize repairing its missing entry.
            manifest=read_runtime_payload(journal);source=manifest['archives'].get(name+':'+architecture)
            if not isinstance(source,dict)or source.get('expected')!=record:raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
            _,_,cached=runtime_cached_archive(journal,record,source.get('expectedFile'))
            if {part:hashlib.sha256(data).hexdigest()for part,data in cached.items()}!=source.get('expectedControls'):raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
            reviewed_maintainer_controls(cached,reviewed)
            incomplete=True
        installed_maintainer_controls(name,architecture,reviewed,incomplete=incomplete)
        if archives:
            if journal.get('payloadEvidence'):
                manifest=read_runtime_payload(journal)
                if name=='systemd':
                    consumer=manifest.get('consumerArchive')
                    if not isinstance(consumer,dict)or consumer.get('record')!=record or consumer.get('file')!='authority-systemd-'+architecture+'.deb':raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
                    actual,raw,controls=runtime_cached_archive(journal,record,consumer['file'])
                else:actual,raw,controls=runtime_cached_archive(journal,record,manifest['archives'][name+':'+architecture]['expectedFile'])
            else:
                actual,raw,controls=acquire_runtime_debian_archive(name,record['version'],architecture)
            if actual!=record:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
            reviewed_maintainer_controls(controls,reviewed)
            programs=proof['programs']if name=='systemd'else proof['libcPrograms']if name=='libc6'else None
            if programs is not None and runtime_archive_programs(raw,set(programs))!=programs:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
def verify_runtime_systemd_policy_packages(journal,archives=False):
    verify_runtime_systemd_package_authority(journal,archives)
    if runtime_active_systemd_policy(journal).get('bootId')!=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip():raise ValueError('SYSTEM_SECURITY_SYSTEMD_PROCESS_CHANGED')

def runtime_library_file(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022 or not 0<info.st_size<=16*1024*1024:raise ValueError('SYSTEM_SECURITY_LIBC_PAYLOAD_UNCONFIRMED')
        digest=hashlib.sha256();size=0
        while True:
            data=os.read(fd,262144)
            if not data:break
            size+=len(data)
            if size>16*1024*1024:raise ValueError('SYSTEM_SECURITY_LIBC_PAYLOAD_UNCONFIRMED')
            digest.update(data)
        after=os.fstat(fd);current=os.lstat(path)
        if size!=info.st_size or not os.path.samestat(info,current)or any(getattr(info,key)!=getattr(after,key)for key in ['st_size','st_mtime_ns','st_ctime_ns']):raise ValueError('SYSTEM_SECURITY_LIBC_PAYLOAD_UNCONFIRMED')
        return {'path':str(pathlib.Path(path).resolve()),'sha256':digest.hexdigest(),'inode':info.st_ino,'device':[os.major(info.st_dev),os.minor(info.st_dev)]}
    finally:os.close(fd)

def runtime_payload_layout():
    layout={}
    for path,target in [('/bin','usr/bin'),('/sbin','usr/sbin'),('/lib','usr/lib'),('/lib64','usr/lib64')]:
        try:info=os.lstat(path)
        except FileNotFoundError:continue
        if info.st_uid!=0:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        if stat.S_ISLNK(info.st_mode):
            if os.readlink(path)not in [target,'/'+target]:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            layout[path]='/'+target
        elif stat.S_ISDIR(info.st_mode)and not info.st_mode&0o022:layout[path]=path
        else:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    return layout

def runtime_payload_path(path,layout):
    if not isinstance(path,str)or not re.fullmatch(r'/[A-Za-z0-9_+.,:@%=/\-]{1,2048}',path)or path!=str(pathlib.PurePosixPath(path))or '..'in path.split('/'):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    for prefix,target in layout.items():
        if path==prefix or path.startswith(prefix+'/'):path=target+path[len(prefix):];break
    if not(path in ['/usr','/etc','/var','/var/lib','/var/log','/var/lib/dpkg','/var/cache','/var/cache/ldconfig','/bin','/sbin','/lib','/lib64']or path.startswith(('/usr/','/etc/','/lib/','/lib64/','/bin/','/sbin/','/var/lib/dpkg/info/'))or path in ['/var/lib/postgresql','/var/log/postgresql']):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    if re.match(r'/etc/(?:passwd|shadow|gshadow|group)(?:$|[.-])',path)or path.startswith(('/etc/ssh/ssh_host_','/etc/incudal')):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    return path

def runtime_payload_link(path,target,layout):
    import posixpath
    if not isinstance(target,str)or not target or len(target)>2048 or re.search(r'[\\\x00-\x20\x7f]',target):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    value=posixpath.normpath(target if target.startswith('/')else posixpath.join(posixpath.dirname(path),target))
    resolved=runtime_payload_path(value,layout)
    if resolved.startswith('/var/')or resolved in ['/var','/usr','/etc']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    return resolved

def runtime_payload_parents(path):
    parents=[]
    for parent in reversed(pathlib.Path(path).parents):
        try:info=parent.lstat()
        except FileNotFoundError:break
        if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        parents.append((parent,info))
    return parents

def runtime_payload_regular(path,limit=128*1024*1024,private=False,content=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&(0o077 if private else 0o022)or not 0<=info.st_size<=limit:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        digest=hashlib.sha256();size=0;blocks=[]
        while True:
            block=os.read(fd,262144)
            if not block:break
            size+=len(block)
            if size>limit:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            digest.update(block)
            if content:blocks.append(block)
        after=os.fstat(fd);current=os.lstat(path)
        if size!=info.st_size or not os.path.samestat(info,current)or any(getattr(info,key)!=getattr(after,key)for key in ['st_size','st_mtime_ns','st_ctime_ns']):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        value={'type':'file','sha256':digest.hexdigest(),'size':size,'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}
        if content:value['content']=b''.join(blocks)
        return value
    finally:os.close(fd)

def runtime_payload_actual(path,layout):
    path=runtime_payload_path(path,layout);parents=runtime_payload_parents(path)
    try:info=os.lstat(path)
    except FileNotFoundError:return {'type':'absent'}
    if stat.S_ISREG(info.st_mode):value=runtime_payload_regular(path)
    elif stat.S_ISLNK(info.st_mode):
        if info.st_uid!=0 or info.st_nlink!=1:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        target=os.readlink(path);runtime_payload_link(path,target,layout)
        value={'type':'symlink','target':target,'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}
    elif stat.S_ISDIR(info.st_mode):
        if info.st_uid!=0 or info.st_mode&0o022:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        value={'type':'directory','mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}
    else:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    current=os.lstat(path)
    if not os.path.samestat(info,current)or info.st_ctime_ns!=current.st_ctime_ns:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    for parent,before in parents:
        after=parent.lstat()
        if not os.path.samestat(before,after)or any(getattr(before,key)!=getattr(after,key)for key in ['st_mode','st_uid','st_gid']):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    return value

def validate_runtime_payload_record(path,value,layout):
    if not isinstance(value,dict)or value.get('type')not in ['file','symlink','directory','absent']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    if value['type']=='absent':
        if set(value)!={'type'}:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        return
    common={'type','mode','uid','gid'}
    fields=common|({'sha256','size'}if value['type']=='file'else {'target'}if value['type']=='symlink'else set())
    if set(value)!=fields or type(value['mode'])is not int or not 0<=value['mode']<=0o7777 or type(value['uid'])is not int or value['uid']!=0 or type(value['gid'])is not int or value['gid']<0:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    if value['type']=='symlink':runtime_payload_link(path,value['target'],layout)
    elif value['mode']&0o022:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    if value['type']=='file'and (not isinstance(value['sha256'],str)or not re.fullmatch(r'[a-f0-9]{64}',value['sha256'])or type(value['size'])is not int or not 0<=value['size']<=128*1024*1024 or path.startswith('/var/')and not path.startswith('/var/lib/dpkg/info/')):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')

def runtime_payload_plan_hash(baseline,expected,changes):
    return hashlib.sha256(json.dumps({'baseline':baseline,'expected':expected,'changes':changes},sort_keys=True,separators=(',',':')).encode()).hexdigest()

def runtime_archive_payload(raw,layout):
    entries={}
    for name,record in debian_archive_members(raw,'data',manifest=True).items():
        path=runtime_payload_path('/'+name,layout)
        if path in entries:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        if record['type']=='symlink':runtime_payload_link(path,record['target'],layout)
        entries[path]=record
    return entries

def runtime_archive_conffiles(controls,layout):
    result=set()
    for line in controls.get('conffiles',b'').decode('utf-8').splitlines():
        fields=line.split()
        # Removal migrations need a separately reviewed recipe. Do not
        # silently turn an administrator's intentionally absent config into
        # a request to restore the vendor default.
        if len(fields)!=1:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        path=runtime_payload_path(fields[0],layout)
        if path in result:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        result.add(path)
    return result

def runtime_archive_conffile_registration(raw,paths,layout):
    if not paths:return {}
    names={path.removeprefix('/')for path in paths}
    contents=debian_archive_members(raw,'data',wanted=names)
    return {runtime_payload_path('/'+path,layout):{'md5':hashlib.md5(data,usedforsecurity=False).hexdigest(),'flags':[]}for path,data in contents.items()}

def runtime_dpkg_conffiles(key,layout):
    output=command(['dpkg-query','--show','--showformat=${Conffiles}\n',key],30);result={}
    if len(output)>1024*1024:raise ValueError('SYSTEM_SECURITY_RUNTIME_CONFFILE_MIGRATION_UNREVIEWED')
    for line in output.splitlines():
        if not line.strip():continue
        match=re.fullmatch(r' (/[A-Za-z0-9_+.,:@%=/\-]+) ([a-f0-9]{32})',line)
        if not match:raise ValueError('SYSTEM_SECURITY_RUNTIME_CONFFILE_MIGRATION_UNREVIEWED')
        path=runtime_payload_path(match[1],layout)
        if path in result:raise ValueError('SYSTEM_SECURITY_RUNTIME_CONFFILE_MIGRATION_UNREVIEWED')
        result[path]={'md5':match[2],'flags':[]}
    return result

def prepare_runtime_conffile(backup,path,before,layout):
    if before['type']!='file':return None
    # Original administrator bytes are private evidence, never sourced from
    # the new vendor default or re-attested after package installation.
    data=runtime_payload_regular(path,128*1024*1024,content=True)
    if {key:value for key,value in data.items()if key!='content'}!=before:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    root=backup/'conffiles'
    if not root.exists():root.mkdir(mode=0o700)
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or root.resolve()!=root:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    name=hashlib.sha256(path.encode()).hexdigest()+'.before'
    write_runtime_evidence_file(root/name,data['content']);sync_runtime_evidence_directory(backup)
    if runtime_payload_actual(path,layout)!=before:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    return name

def runtime_cached_conffile(journal,path,record):
    before=record['before'];file=record.get('beforeFile')
    if before['type']!='file':
        if file is not None:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        return None
    if file!=hashlib.sha256(path.encode()).hexdigest()+'.before':raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    backup=journal.get('backup')
    if not isinstance(backup,str)or not re.fullmatch(r'runtime-backup-[a-f0-9]{32}',backup):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    root=pathlib.Path('/var/lib/incudal-system-security')/backup/'conffiles';info=root.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or root.resolve()!=root:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    value=runtime_payload_regular(root/file,128*1024*1024,private=True,content=True)
    if value['sha256']!=before['sha256']or value['size']!=before['size']or value['mode']!=0o600:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    return value['content']

def prepare_runtime_payload(changes,baseline,expected,backup,systemd_policy=None):
    # Before is vendor-authenticated too. Capturing current executable bytes
    # for the first time must never turn a prior injection into trusted code.
    layout=runtime_payload_layout();paths={};archives={};total=0
    archive_root=backup/'archives';archive_root.mkdir(mode=0o700)
    for item in changes:
        name,version=item.split('=',1);keys=[key for key in baseline if key.split(':')[0]==name]
        if len(keys)!=1:raise ValueError('SYSTEM_SECURITY_MULTIARCH_REVIEW_REQUIRED')
        key=keys[0];architecture=key.split(':')[1];versions={};entries={};conffiles=set();old_conffiles=set();new_conffiles=set()
        for label,selected in [('before',baseline[key]),('expected',version)]:
            record,raw,controls=acquire_runtime_debian_archive(name,selected,architecture,role=label);total+=len(raw)
            if total>1024*1024*1024:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            versions[label]=record;versions[label+'Controls']={part:hashlib.sha256(data).hexdigest()for part,data in controls.items()}
            archive_file=label+'-'+name+'-'+architecture+'.deb';write_runtime_evidence_file(archive_root/archive_file,raw);versions[label+'File']=archive_file
            entries[label]=runtime_archive_payload(raw,layout);selected_conffiles=runtime_archive_conffiles(controls,layout);conffiles|=selected_conffiles
            versions[label+'Conffiles']=runtime_archive_conffile_registration(raw,selected_conffiles,layout)
            if label=='before':old_conffiles=selected_conffiles
            else:new_conffiles=selected_conffiles
            versions[label+'Maintainers']=debian_archive_members(raw,'control',wanted={part for part in controls if part in ['preinst','postinst','prerm','postrm','config','triggers']},manifest=True)
        archives[key]=versions
        if runtime_dpkg_conffiles(key,layout)!=versions['beforeConffiles']:raise ValueError('SYSTEM_SECURITY_RUNTIME_CONFFILE_MIGRATION_UNREVIEWED')
        if name=='libc-bin':
            # This path is created by the independently reviewed postinst,
            # rather than registered as a dpkg conffile. Its old customer
            # resolution policy must still be attested and preserved.
            path='/etc/nsswitch.conf';source='/usr/share/libc-bin/nsswitch.conf'
            if any(entries[label].get(source,{}).get('type')!='file'for label in ['before','expected']):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            for label in ['before','expected']:entries[label][path]=entries[label][source]
            old_conffiles.add(path);new_conffiles.add(path);conffiles.add(path)
        registered=command(['dpkg-query','-L',key],30).splitlines()
        if len(registered)>20000:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        registered_paths={runtime_payload_path(path.rstrip('/'),layout)for path in registered if path not in ['/.','/']}
        # Unknown registered regular files/links are not implicitly accepted
        # as old vendor payload. Directories contain other packages' data.
        for path in registered_paths-set(entries['before']):
            if runtime_payload_actual(path,layout)['type']not in ['directory','absent']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        info=pathlib.Path('/var/lib/dpkg/info');prefixes=[prefix for prefix in [name,name+':'+architecture]if (info/(prefix+'.list')).exists()]
        if len(prefixes)!=1:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        prefix=prefixes[0];protected_hash(info/(prefix+'.list'))
        for part in ['preinst','postinst','prerm','postrm','config','triggers']:
            path=str(info/(prefix+'.'+part))
            if all(part not in versions[label+'Maintainers']for label in ['before','expected'])and runtime_payload_actual(path,layout)['type']!='absent':raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            for label in ['before','expected']:
                source=versions[label+'Maintainers'].get(part)
                if source is not None:entries[label][path]=source
        for path in sorted(set(entries['before'])|set(entries['expected'])):
            before_vendor=entries['before'].get(path,{'type':'absent'});after_vendor=entries['expected'].get(path,{'type':'absent'});actual=runtime_payload_actual(path,layout)
            conffile=path in conffiles
            # A content-only vendor default transition can be restored to the
            # original, pre-attested administrator value. Registration/path,
            # ownership and permission migrations need a separate review.
            if path in old_conffiles and (path not in new_conffiles or before_vendor['type']!='file'or after_vendor['type']!='file'or any(before_vendor[field]!=after_vendor[field]for field in ['type','mode','uid','gid']))or path in new_conffiles-old_conffiles and (before_vendor['type']!='absent'or actual['type']!='absent'):raise ValueError('SYSTEM_SECURITY_RUNTIME_CONFFILE_MIGRATION_UNREVIEWED')
            shared_directory=actual['type']=='directory'and before_vendor['type']in ['directory','absent']and after_vendor['type']in ['directory','absent']
            if not conffile and not shared_directory and actual!=before_vendor:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            if conffile and actual['type']not in ['file','symlink','absent']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            after=actual if path in old_conffiles or conffile and actual['type']!='absent'or after_vendor['type']=='directory'and actual['type']=='directory'or before_vendor['type']=='directory'and after_vendor['type']=='absent'else after_vendor
            value={'owners':[key],'before':actual,'expected':after,'conffile':conffile}
            if path in old_conffiles:
                value['vendorExpected']=after_vendor;value['beforeFile']=prepare_runtime_conffile(backup,path,actual,layout)
            if path in paths:
                prior=paths[path]
                if any(prior.get(field)!=value.get(field)for field in ['before','expected','conffile','vendorExpected','beforeFile']):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
                prior['owners'].append(key)
            else:paths[path]=value
        if len(paths)>50000:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    consumer=None
    if systemd_policy:
        record=systemd_policy['archives']['systemd'];_,raw,controls=acquire_runtime_debian_archive('systemd',record['version'],record['architecture'],record,role='before')
        file='authority-systemd-'+record['architecture']+'.deb';write_runtime_evidence_file(archive_root/file,raw)
        consumer={'record':record,'file':file,'controls':{part:hashlib.sha256(data).hexdigest()for part,data in controls.items()}}
    node_keys=[key for key in baseline if key.split(':')[0]=='nodejs']
    if len(node_keys)!=1:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
    node_key=node_keys[0];node_consumer=None
    if node_key in archives:
        node_path=paths.get('/usr/bin/node')
        if not isinstance(node_path,dict)or node_key not in node_path['owners']:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
        node_before=node_path['before'];node_expected=node_path['expected']
    else:
        architecture=node_key.split(':')[1];record,raw,controls=acquire_runtime_debian_archive('nodejs',baseline[node_key],architecture,role='before');total+=len(raw)
        if total>1024*1024*1024:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        node_before=runtime_archive_payload(raw,layout).get('/usr/bin/node');node_expected=node_before
        if not isinstance(node_before,dict)or runtime_payload_actual('/usr/bin/node',layout)!=node_before:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
        file='authority-nodejs-'+architecture+'.deb';write_runtime_evidence_file(archive_root/file,raw)
        node_consumer={'record':record,'file':file,'controls':{part:hashlib.sha256(data).hexdigest()for part,data in controls.items()}}
    for program in [node_before,node_expected]:
        validate_runtime_payload_record('/usr/bin/node',program,layout)
        if program['type']!='file'or not program['mode']&0o111 or program['size']<1:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
    node_authority={'version':1,'package':node_key,'before':node_before,'expected':node_expected,'consumer':node_consumer}
    sync_runtime_evidence_directory(backup)
    value={'version':1,'planHash':runtime_payload_plan_hash(baseline,expected,changes),'layout':layout,'archives':archives,'paths':paths,'consumerArchive':consumer,'nodeAuthority':node_authority}
    data=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    if len(data)>16*1024*1024:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    path=backup/'payload.json';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb')as out:out.write(data);out.flush();os.fsync(out.fileno())
        directory=os.open(backup,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
    except BaseException:raise
    return {'version':1,'file':'payload.json','sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'planHash':value['planHash']}

def read_runtime_payload(journal):
    baseline,expected,changes,_=validated_runtime_package_plan(journal);proof=journal.get('payloadEvidence');name=journal.get('backup')
    if not isinstance(proof,dict)or proof.get('version')!=1 or proof.get('file')!='payload.json'or not re.fullmatch(r'runtime-backup-[a-f0-9]{32}',name or '')or proof.get('planHash')!=runtime_payload_plan_hash(baseline,expected,changes)or type(proof.get('size'))is not int or not 0<proof['size']<=16*1024*1024 or not re.fullmatch(r'[a-f0-9]{64}',proof.get('sha256','')):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    path=pathlib.Path('/var/lib/incudal-system-security')/name/'payload.json'
    info=path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or path.parent.resolve()!=path.parent:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    metadata=runtime_payload_regular(path,16*1024*1024,private=True,content=True)
    if metadata['size']!=proof['size']or metadata['sha256']!=proof['sha256']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    value=json.loads(metadata['content'])
    if value.get('version')!=1 or value.get('planHash')!=proof['planHash']or value.get('layout')!=runtime_payload_layout()or not isinstance(value.get('paths'),dict)or not value['paths']or len(value['paths'])>50000 or not isinstance(value.get('archives'),dict)or set(value['archives'])!={key for key in baseline if key.split(':')[0]in {item.split('=',1)[0]for item in changes}}:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    return value

def runtime_cached_archive(journal,record,file):
    if not isinstance(file,str)or not re.fullmatch(r'(?:before|expected|authority)-[a-z0-9+.-]+-(?:amd64|arm64|all)\.deb',file):raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
    if file.startswith('expected-')and record.get('source',{}).get('kind')=='debian-snapshot':raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
    backup=journal.get('backup')
    if not isinstance(backup,str)or not re.fullmatch(r'runtime-backup-[a-f0-9]{32}',backup):raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
    root=pathlib.Path('/var/lib/incudal-system-security')/backup/'archives'
    info=root.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or root.resolve()!=root:raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
    value=runtime_payload_regular(root/file,256*1024*1024,private=True,content=True)
    if value['size']!=record.get('size')or value['sha256']!=record.get('sha256'):raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
    raw=value['content'];controls=debian_archive_members(raw)
    fields={}
    for line in controls.get('control',b'').decode('utf-8').splitlines():
        if line[:1].isspace()or ': 'not in line:continue
        key,content=line.split(': ',1)
        if key in fields:raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
        fields[key]=content
    if any(fields.get(key)!=record.get(value)for key,value in [('Package','package'),('Version','version'),('Architecture','architecture')]):raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
    return record,raw,controls

def runtime_original_expected_arguments(journal,remaining):
    value=read_runtime_payload(journal);_,expected,changes,_=validated_runtime_package_plan(journal)
    if not isinstance(remaining,list)or not remaining or len(remaining)!=len(set(remaining))or any(item not in changes for item in remaining):raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
    arguments=[]
    for item in remaining:
        name,version=item.split('=',1);key=next(key for key in expected if key.split(':')[0]==name);source=value['archives'][key];file=source.get('expectedFile')
        if source['expected'].get('version')!=version or file!='expected-'+name+'-'+key.split(':')[1]+'.deb':raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
        _,_,controls=runtime_cached_archive(journal,source['expected'],file)
        if {part:hashlib.sha256(data).hexdigest()for part,data in controls.items()}!=source['expectedControls']:raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
        arguments.append(str(pathlib.Path('/var/lib/incudal-system-security')/journal['backup']/'archives'/file))
    return arguments

def runtime_backend_program(current):
    pid=current.get('pid')if isinstance(current,dict)else None
    if type(pid)is not int or pid<2:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
    process=pathlib.Path('/proc',str(pid));exe=process/'exe'
    if str(exe.readlink()).removesuffix(' (deleted)')!='/usr/bin/node'or (process/'ns/pid').readlink()!=pathlib.Path('/proc/1/ns/pid').readlink()or not os.path.samestat((process/'root').stat(),pathlib.Path('/').stat()):raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
    # The kernel's already identified procfs exe link is deliberately opened;
    # an absent on-disk Node must never be replaced by an arbitrary executable
    # for money validation. This observation performs no Node execution.
    fd=os.open(exe,os.O_RDONLY|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink not in [0,1]or info.st_mode&0o022 or not 0<info.st_size<=128*1024*1024:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
        digest=hashlib.sha256();size=0
        while True:
            block=os.read(fd,262144)
            if not block:break
            size+=len(block)
            if size>128*1024*1024:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
            digest.update(block)
        after=os.fstat(fd)
        if size!=info.st_size or not os.path.samestat(info,exe.stat())or any(getattr(info,key)!=getattr(after,key)for key in ['st_size','st_mtime_ns','st_ctime_ns']):raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
        return {'type':'file','mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,'size':size,'sha256':digest.hexdigest()}
    finally:os.close(fd)

def verify_runtime_node_authority(journal,current=None,require='expected',allow_missing=False):
    if not journal.get('payloadEvidence'):return
    if require not in ['before','expected','mixed']:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
    value=read_runtime_payload(journal);authority=value.get('nodeAuthority');baseline,expected,_,_=validated_runtime_package_plan(journal)
    if not isinstance(authority,dict)or set(authority)!={'version','package','before','expected','consumer'}or authority.get('version')!=1 or not isinstance(authority.get('package'),str)or authority['package'].split(':')[0]!='nodejs'or authority['package']not in baseline:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
    key=authority['package'];architecture=key.split(':')[1]
    for label in ['before','expected']:
        program=authority[label];validate_runtime_payload_record('/usr/bin/node',program,value['layout'])
        if program['type']!='file'or not program['mode']&0o111 or program['size']<1:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
    consumer=authority['consumer']
    if key in value['archives']:
        if consumer is not None or value['paths'].get('/usr/bin/node',{}).get('before')!=authority['before']or value['paths']['/usr/bin/node'].get('expected')!=authority['expected']:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
        sources=[(label,value['archives'][key][label],value['archives'][key].get(label+'File'),value['archives'][key].get(label+'Controls'))for label in ['before','expected']]
    else:
        if not isinstance(consumer,dict)or set(consumer)!={'record','file','controls'}or consumer.get('file')!='authority-nodejs-'+architecture+'.deb'or consumer['record'].get('package')!='nodejs'or consumer['record'].get('architecture')!=architecture or consumer['record'].get('version')!=baseline[key]or baseline[key]!=expected[key]or authority['before']!=authority['expected']:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
        sources=[('before',consumer['record'],consumer['file'],consumer['controls'])]
    for label,record,file,controls in sources:
        _,raw,actual=runtime_cached_archive(journal,record,file)
        if {part:hashlib.sha256(data).hexdigest()for part,data in actual.items()}!=controls or runtime_archive_payload(raw,value['layout']).get('/usr/bin/node')!=authority[label]:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
    allowed=[authority[require]]if require!='mixed'else[authority['before'],authority['expected']]
    actual=runtime_payload_actual('/usr/bin/node',value['layout'])
    missing=allow_missing and require=='mixed'and key in value['archives']and journal.get('phase')in ['installing','installed']and actual=={'type':'absent'}
    if actual not in allowed and not missing:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
    if current is not None and runtime_backend_program(current)not in allowed:raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
    return {'package':key,'missing':missing,'program':actual}

def verify_runtime_payload(journal,require='mixed',archives=False):
    if require not in ['mixed','before','expected']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    value=read_runtime_payload(journal);baseline,expected,_,planned=validated_runtime_package_plan(journal)
    incomplete=set();unchanged=True;complete=True;covered=set();states=None
    for key,versions in value['archives'].items():
        if not isinstance(versions,dict):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        name,architecture=key.split(':',1)
        for label,packages in [('before',baseline),('expected',expected)]:
            record=versions.get(label);controls=versions.get(label+'Controls')
            if not isinstance(record,dict)or record.get('package')!=name or record.get('architecture')!=architecture or record.get('version')!=packages[key]or type(record.get('size'))is not int or not 8<record['size']<=256*1024*1024 or not re.fullmatch(r'[a-f0-9]{64}',record.get('sha256',''))or not isinstance(controls,dict)or any(not re.fullmatch(r'[a-z0-9_.+-]+',part)or not re.fullmatch(r'[a-f0-9]{64}',digest)for part,digest in controls.items()):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            if archives:
                if journal.get('payloadEvidence'):
                    file=versions.get(label+'File')
                    if file!=label+'-'+name+'-'+architecture+'.deb':raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
                    _,_,actual=runtime_cached_archive(journal,record,file)
                else:_,_,actual=acquire_runtime_debian_archive(name,record['version'],architecture,record,role=label)
                if {part:hashlib.sha256(data).hexdigest()for part,data in actual.items()}!=controls:raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
        if 'beforeConffiles'in versions or 'expectedConffiles'in versions:
            for label in ['before','expected']:
                registration=versions.get(label+'Conffiles')
                if not isinstance(registration,dict)or len(registration)>4096 or any(runtime_payload_path(path,value['layout'])!=path or not isinstance(record,dict)or set(record)!={'md5','flags'}or record['flags']!=[]or not re.fullmatch(r'[a-f0-9]{32}',record.get('md5',''))for path,record in registration.items()):raise ValueError('SYSTEM_SECURITY_RUNTIME_CONFFILE_MIGRATION_UNREVIEWED')
            registration=runtime_dpkg_conffiles(key,value['layout'])
            allowed=[versions['beforeConffiles'],versions['expectedConffiles']]if require=='mixed'and journal.get('phase')in ['installing','installed']else[versions[('expected'if require=='expected'else'before')+'Conffiles']]
            if registration not in allowed:raise ValueError('SYSTEM_SECURITY_RUNTIME_CONFFILE_MIGRATION_UNREVIEWED')
            unchanged=unchanged and registration==versions['beforeConffiles'];complete=complete and registration==versions['expectedConffiles']
            if registration!=versions['expectedConffiles']:incomplete.add(key)
    for path,record in value['paths'].items():
        fields={'owners','before','expected','conffile'}|({'vendorExpected','beforeFile'}if isinstance(record,dict)and 'vendorExpected'in record else set())
        if runtime_payload_path(path,value['layout'])!=path or not isinstance(record,dict)or set(record)!=fields or type(record['conffile'])is not bool or not isinstance(record['owners'],list)or not record['owners']or len(record['owners'])!=len(set(record['owners']))or any(key not in value['archives']for key in record['owners']):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        for field in ['before','expected']:validate_runtime_payload_record(path,record[field],value['layout'])
        if record['conffile']and record['before']['type']!='absent'and record['expected']!=record['before']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        if 'vendorExpected'in record:
            validate_runtime_payload_record(path,record['vendorExpected'],value['layout'])
            if not record['conffile']or record['expected']!=record['before']or record['vendorExpected']['type']!='file'or record['before']['type']not in ['file','symlink','absent']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            if record['before']['type']=='file'and record['beforeFile']!=hashlib.sha256(path.encode()).hexdigest()+'.before'or record['before']['type']!='file'and record['beforeFile']is not None:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            if archives:runtime_cached_conffile(journal,path,record)
        covered.update(record['owners']);actual=runtime_payload_actual(path,value['layout'])
        if actual not in [record['before'],record['expected']]:
            vendor=record.get('vendorExpected')
            transition=require=='mixed'and journal.get('phase')in ['installing','installed']and vendor is not None and actual==vendor
            # dpkg can lose a planned formal file or maintainer entry while
            # its exact original package is half-installed. Absence here
            # authorizes only reinstalling that original authenticated plan;
            # it never counts as an unchanged or completed installation.
            if not transition and (actual['type']!='absent'or record['conffile']or record['expected']['type']not in ['file','symlink']or require in ['before','expected']):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            if states is None:states=debian_package_states()
            if journal.get('phase')not in ['installing','installed']or any(states.get(key,{}).get('version')not in [baseline[key],expected[key]]or states.get(key,{}).get('status')not in ['half-installed','unpacked','half-configured','installed']for key in record['owners']):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        unchanged=unchanged and actual==record['before'];complete=complete and actual==record['expected']
        if actual!=record['expected']:incomplete.update(record['owners'])
    if covered!=set(value['archives'])or require=='before'and not unchanged or require=='expected'and not complete:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    return {'unchanged':unchanged,'complete':complete,'incomplete':sorted(incomplete)}

def repair_runtime_conffile_temporary(journal,path,record,intent,data,parent):
    temporary=pathlib.Path(path).parent/intent['temporary']
    if record['before']['type']!='file'or not isinstance(data,bytes):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    value=runtime_payload_regular(temporary,max(len(data),1),private=True,content=True)
    complete=len(value['content'])==len(data)
    if value['mode']!=0o600 or value['gid']not in ([0,record['before']['gid']]if complete else[0])or not data.startswith(value['content']):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    # A root-private file created by this persisted intent may have stopped
    # part way through write/fsync. Preserve that exact prefix as evidence,
    # then rebuild only from the original, immutable administrator snapshot.
    backup=pathlib.Path('/var/lib/incudal-system-security')/journal['backup'];root=backup/'conffile-failures'
    root.mkdir(mode=0o700,exist_ok=True);info=root.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or root.resolve()!=root:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    file=hashlib.sha256((path+'\n'+intent['binding']+'\n'+value['sha256']).encode()).hexdigest()+'.partial'
    failures=journal.get('conffileRestorationFailures',[])
    if not isinstance(failures,list)or len(failures)>64:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    evidence={'path':path,'binding':intent['binding'],'temporary':intent['temporary'],'file':file,'sha256':value['sha256'],'size':value['size']}
    existing=[item for item in failures if isinstance(item,dict)and item.get('file')==file]
    if existing and existing!=[evidence]or not existing and len(failures)>=64:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    write_runtime_evidence_file(root/file,value['content']);sync_runtime_evidence_directory(backup)
    if not existing:
        failures.append(evidence);journal['conffileRestorationFailures']=failures;write_runtime_maintenance(journal)
    current=runtime_payload_regular(temporary,max(len(data),1),private=True,content=True)
    if current!=value:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    os.unlink(intent['temporary'],dir_fd=parent);os.fsync(parent)

def restore_runtime_conffiles(journal):
    if not journal.get('payloadEvidence'):return
    if journal.get('phase')not in ['installing','installed']:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    verify_runtime_payload(journal,archives=True);value=read_runtime_payload(journal)
    restorations=journal.get('conffileRestorations',{})
    if not isinstance(restorations,dict)or len(restorations)>4096 or any(path not in value['paths']or 'vendorExpected'not in value['paths'][path]for path in restorations):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
    for path,record in value['paths'].items():
        if 'vendorExpected'not in record:continue
        target=pathlib.Path(path);actual=runtime_payload_actual(path,value['layout']);intent=restorations.get(path)
        binding=hashlib.sha256(json.dumps({'path':path,'record':record,'payload':journal['payloadEvidence']['sha256']},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if intent is not None and (not isinstance(intent,dict)or set(intent)!={'binding','phase','temporary'}or intent.get('binding')!=binding or intent.get('phase')not in ['intent','restored']or intent.get('temporary')is not None and not re.fullmatch(re.escape(target.name)+r'\.incudal-restore-[a-f0-9]{32}',intent['temporary'])):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        if actual==record['expected']and intent is None:continue
        if actual not in [record['expected'],record['vendorExpected']]:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        data=runtime_cached_conffile(journal,path,record)
        if intent is None:
            intent={'binding':binding,'phase':'intent','temporary':None if record['before']['type']=='absent'else target.name+'.incudal-restore-'+uuid.uuid4().hex}
            restorations[path]=intent;journal['conffileRestorations']=restorations;write_runtime_maintenance(journal)
        temporary=target.parent/intent['temporary']if intent['temporary']is not None else None
        if intent['phase']=='restored':
            if actual!=record['expected']or temporary is not None and (temporary.exists()or temporary.is_symlink()):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            continue
        parents=runtime_payload_parents(path);parent=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            if not os.path.samestat(os.fstat(parent),target.parent.lstat()):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            if temporary is not None and (temporary.exists()or temporary.is_symlink()):
                if runtime_payload_actual(str(temporary),value['layout'])!=record['expected']:
                    repair_runtime_conffile_temporary(journal,path,record,intent,data,parent)
            if temporary is not None and not(temporary.exists()or temporary.is_symlink())and actual!=record['expected']:
                if record['before']['type']=='file':
                    fd=os.open(intent['temporary'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                    with os.fdopen(fd,'wb')as stream:
                        stream.write(data);stream.flush();os.fsync(stream.fileno())
                        os.fchown(stream.fileno(),record['before']['uid'],record['before']['gid']);os.fchmod(stream.fileno(),record['before']['mode']);os.fsync(stream.fileno())
                elif record['before']['type']=='symlink':
                    os.symlink(record['before']['target'],intent['temporary'],dir_fd=parent);os.chown(intent['temporary'],record['before']['uid'],record['before']['gid'],dir_fd=parent,follow_symlinks=False)
                else:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
                os.fsync(parent)
            current=runtime_payload_actual(path,value['layout'])
            for directory,before in parents:
                after=directory.lstat()
                if not os.path.samestat(before,after)or any(getattr(before,key)!=getattr(after,key)for key in ['st_mode','st_uid','st_gid']):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            if current!=record['expected']:
                if current!=record['vendorExpected']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
                if temporary is None:os.unlink(target.name,dir_fd=parent)
                else:
                    if runtime_payload_actual(str(temporary),value['layout'])!=record['expected']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
                    if record['before']['type']=='file':
                        fd=os.open(intent['temporary'],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
                        try:os.fsync(fd)
                        finally:os.close(fd)
                    os.replace(intent['temporary'],target.name,src_dir_fd=parent,dst_dir_fd=parent)
                os.fsync(parent)
            elif temporary is not None and (temporary.exists()or temporary.is_symlink()):
                if runtime_payload_actual(str(temporary),value['layout'])!=record['expected']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
                os.unlink(intent['temporary'],dir_fd=parent);os.fsync(parent)
            if runtime_payload_actual(path,value['layout'])!=record['expected']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            # A previous rename may have succeeded just before its process
            # died, so the resume path must sync the directory too.
            os.fsync(parent)
        finally:os.close(parent)
        intent['phase']='restored';write_runtime_maintenance(journal)

def runtime_libc_files(proof):
    profiles=proof.get('libcPrograms');architecture=proof['archives']['libc6']['architecture']
    if not isinstance(profiles,dict)or set(profiles)!=RUNTIME_LIBC_FILES.get(architecture):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    files={path:runtime_library_file('/'+path)for path in profiles}
    if any(info['sha256']!=profiles[path]for path,info in files.items()):raise ValueError('SYSTEM_SECURITY_LIBC_PAYLOAD_UNCONFIRMED')
    return files

def verify_runtime_libc_process(pid,files):
    process=pathlib.Path('/proc',str(pid))
    if type(pid)is not int or pid<1 or (process/'ns/pid').readlink()!=pathlib.Path('/proc/1/ns/pid').readlink()or not os.path.samestat((process/'root').stat(),pathlib.Path('/').stat()):raise ValueError('SYSTEM_SECURITY_SYSTEMD_PROCESS_CHANGED')
    with (process/'maps').open()as stream:maps=stream.read(1024*1024+1)
    if len(maps)>1024*1024:raise ValueError('SYSTEM_SECURITY_SYSTEMD_CHECK_INCOMPLETE')
    names={pathlib.Path(path).name:path for path in files};seen=set()
    for line in maps.splitlines():
        fields=line.split(maxsplit=5)
        if len(fields)!=6 or 'x'not in fields[1]or not fields[5].startswith('/'):continue
        path=fields[5].removesuffix(' (deleted)');base=pathlib.Path(path).name
        key=next((name for name in names if base==name or base.startswith(name+'.dpkg-')),None)
        if key is None:continue
        info=files[names[key]]
        if not re.fullmatch(r'[a-fA-F0-9]+:[a-fA-F0-9]+',fields[3])or not fields[4].isdecimal()or [int(value,16)for value in fields[3].split(':')]!=info['device']or int(fields[4])!=info['inode']or str(pathlib.Path(path).resolve())!=info['path']:raise ValueError('SYSTEM_SECURITY_LIBC_PAYLOAD_UNCONFIRMED')
        seen.add(key)
    if not {name for name in names if name=='libc.so.6'or name.startswith('ld-linux-')}<=seen:raise ValueError('SYSTEM_SECURITY_LIBC_PAYLOAD_UNCONFIRMED')

def runtime_systemd_boot_confirmation(journal):
    proof=journal.get('systemdPolicy')
    if not proof:return None
    boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if boot==proof.get('bootId'):return None
    if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot)or not isinstance(proof.get('bootId'),str)or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',proof['bootId']):raise ValueError('SYSTEM_SECURITY_SYSTEMD_PROCESS_CHANGED')
    _,expected,_,_=validated_runtime_package_plan(journal)
    states=debian_package_states()
    if {key:value['version']for key,value in states.items()}!=expected or any(value['status']!='installed'for value in states.values())or command(['dpkg','--audit'],30):raise ValueError('SYSTEM_SECURITY_SYSTEMD_BOOT_RECOVERY_PENDING')
    # Reading original authenticated archive evidence is not permission to
    # replay its old nonce. Independently prove the naturally loaded manager
    # and journal, their original configuration and exact installed package
    # set. Active user/network services need no restart for this observation.
    verify_runtime_systemd_package_authority(journal)
    verify_runtime_payload(journal,require='expected')
    verify_runtime_node_authority(journal,require='expected')
    libc_files=runtime_libc_files(proof)
    for program,digest in proof['programs'].items():
        if protected_hash('/'+program)!=digest:raise ValueError('SYSTEM_SECURITY_SYSTEMD_BINARY_UNREVIEWED')
    manager=runtime_systemd_process(1,'/usr/lib/systemd/systemd')
    service=dict(line.split('=',1)for line in command(['systemctl','show','systemd-journald.service','--property=LoadState,ActiveState,MainPID,FragmentPath,DropInPaths'],20).splitlines()if '='in line)
    before=proof['qualification']
    if service.get('LoadState')!='loaded'or service.get('ActiveState')!='active'or service.get('DropInPaths','')or service.get('FragmentPath')not in ['/lib/systemd/system/systemd-journald.service','/usr/lib/systemd/system/systemd-journald.service']or protected_hash(service['FragmentPath'])!=before['journaldUnit']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_JOURNAL_UNREVIEWED')
    journald=runtime_systemd_process(int(service.get('MainPID','0')),'/usr/lib/systemd/systemd-journald')
    state=runtime_systemd_state()
    if manager['replacedLibraries']or journald['replacedLibraries']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_ACTIVATION_PENDING')
    verify_runtime_libc_process(manager['pid'],libc_files);verify_runtime_libc_process(journald['pid'],libc_files)
    if state['configurationHashes']!=before['state']['configurationHashes']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_CONFIGURATION_CHANGED')
    histories=[runtime_systemd_policy_history(item)for item in runtime_systemd_policy_lineage(journal)]
    return {'version':1,'mode':'new-boot-read-only','originalBootId':proof['bootId'],'bootId':boot,
        'archivesHash':hashlib.sha256(json.dumps(proof['archives'],sort_keys=True).encode()).hexdigest(),'originalPolicy':histories[0],
        'policyHistoryHash':hashlib.sha256(json.dumps(histories,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'manager':manager,'journald':journald,'networkHash':state['networkHash'],'libcFiles':libc_files}

BOOT_CLIENT_FAILURE_CODES=frozenset(['SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED','SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED','SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING'])

class RuntimeBootClientValidationFailed(ValueError):
    """An existing confirmed new-boot drain can recover from client refusal."""
    def __init__(self,journal,recovery,error,client_failure=None):
        if error not in BOOT_CLIENT_FAILURE_CODES:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        super().__init__(error)
        self.boot_id=recovery['bootId'];self.token=recovery['token']
        self.origin_hash=runtime_systemd_origin_hash(journal['systemdPolicy'])
        attempts=runtime_boot_dump_materials(journal,recovery)
        if client_failure is None:
            pending=None
            if attempts and attempts[-1]['state']=='intent':
                target=runtime_dump_directory(journal)/attempts[-1]['file']
                pending={'file':attempts[-1]['file'],'material':runtime_dump_material(target)if runtime_path_present(target)else None}
            client_failure={'error':error,'attempts':json.loads(json.dumps(attempts)),'pendingDump':pending}
        if not isinstance(client_failure,dict)or client_failure.get('error')!=error:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        runtime_boot_client_failure_materials(journal,recovery,client_failure,attempts)
        self.client_failure=client_failure;self.attempt_count=len(client_failure['attempts'])

def runtime_boot_client_failure_materials(journal,recovery,reason,attempts):
    if not isinstance(reason,dict)or set(reason)!={'error','attempts','pendingDump'}or not isinstance(reason.get('error'),str)or reason['error']not in BOOT_CLIENT_FAILURE_CODES:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    saved=runtime_boot_dump_attempts(journal,{**recovery,'dumpAttempts':reason['attempts']})
    if len(saved)>len(attempts):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    pending=reason['pendingDump'];last_intent=bool(saved and saved[-1]['state']=='intent')
    if last_intent:
        if not isinstance(pending,dict)or set(pending)!={'file','material'}or pending.get('file')!=saved[-1]['file']:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        material=pending['material']
        if material is not None and (not isinstance(material,dict)or set(material)!={'sha256','size','header'}or not isinstance(material.get('sha256'),str)or not re.fullmatch(r'[a-f0-9]{64}',material['sha256'])or type(material.get('size'))is not int or not 0<=material['size']<=64*1024*1024*1024 or type(material.get('header'))is not bool):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    elif pending is not None:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    for old,current in zip(saved,attempts):
        if old['state']!='intent':
            if current!=old:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            continue
        if any(current[key]!=old[key]for key in ['file','attempt'])or current['state']not in ['intent','absent','failed','complete']:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        target=runtime_dump_directory(journal)/old['file'];present=runtime_path_present(target);material=pending['material']
        if material is not None:
            if not present or runtime_dump_material(target)!=material or current['state']=='absent' or current['state']in ['failed','complete']and any(current[key]!=material[key]for key in ['sha256','size']):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        elif current['state']in ['intent','absent']:
            if present:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        elif recovery.get('drainConfirmed')is not True:raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
    return saved

def runtime_boot_client_recovery_request(journal,error):
    original=journal.get('systemdPolicy')
    if not original:return None
    boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if boot==original.get('bootId'):return None
    recoveries=journal.get('bootRecoveries',{})
    if not isinstance(recoveries,dict):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    recovery=recoveries.get(boot)
    if recovery is None:return None
    if not isinstance(recovery,dict):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    if recovery.get('drainConfirmed')is not True:return None
    return RuntimeBootClientValidationFailed(journal,recovery,error)

class RuntimeBootDumpExecutionFailed(ValueError):
    """Only an owned new-boot dump execution can request service recovery."""
    def __init__(self,journal,recovery):
        super().__init__('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        self.boot_id=recovery['bootId'];self.token=recovery['token']
        self.attempt_count=len(recovery.get('dumpAttempts',[]))
        self.origin_hash=runtime_systemd_origin_hash(journal['systemdPolicy'])

def runtime_boot_dump_materials(journal,recovery):
    verify_runtime_original_dumps(journal);backup=runtime_dump_directory(journal)
    attempts=runtime_boot_dump_attempts(journal,recovery)
    for attempt in attempts:
        path=backup/attempt['file']
        if attempt['state']=='absent':
            if runtime_path_present(path):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        elif attempt['state']in ['failed','complete']:
            material=runtime_dump_material(path)
            if any(material[key]!=attempt[key]for key in ['sha256','size'])or attempt['state']=='complete'and not material['header']:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    return attempts

def runtime_boot_backend_proof(journal,proof):
    fields={'pid','start','app','environmentHash','codeHash','unitHashes','serviceHash'}
    if not isinstance(proof,dict)or set(proof)!=fields or type(proof.get('pid'))is not int or proof['pid']<2 or not isinstance(proof.get('start'),str)or not re.fullmatch(r'[^\x00-\x1f]{1,64}',proof['start']):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    if any(proof.get(key)!=journal['backend'].get(key)for key in fields-{'pid','start'}):raise ValueError('SYSTEM_SECURITY_BACKEND_CONFIGURATION_CHANGED')
    return proof

def runtime_boot_record_hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def runtime_boot_backend_execution(proof=None):
    fields={'pid','active','result','invocationId','mainPID','startedUsec'}
    if proof is None:
        properties='MainPID,ActiveState,Result,InvocationID,ExecMainPID,ExecMainStartTimestampMonotonic'
        raw=dict(line.split('=',1)for line in command(['systemctl','show','incudal-backend.service','--property='+properties],20).splitlines()if '='in line)
        if set(raw)!=set(properties.split(','))or any(not raw[key].isdecimal()for key in ['MainPID','ExecMainPID','ExecMainStartTimestampMonotonic']):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        proof={'pid':int(raw['MainPID']),'active':raw['ActiveState'],'result':raw['Result'],'invocationId':raw['InvocationID']or'0'*32,'mainPID':int(raw['ExecMainPID']),'startedUsec':int(raw['ExecMainStartTimestampMonotonic'])}
    if not isinstance(proof,dict)or set(proof)!=fields or any(type(proof.get(key))is not int or not 0<=proof[key]<2**63 for key in ['pid','mainPID','startedUsec'])or proof.get('active')not in ['active','inactive','failed']or proof.get('result')not in ['success','exit-code','signal','core-dump','timeout','resources','protocol','start-limit-hit','watchdog','oom-kill']or not isinstance(proof.get('invocationId'),str)or not re.fullmatch(r'[a-f0-9]{32}',proof['invocationId']):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    return proof

def runtime_boot_start_records(journal,recovery,attempts=None):
    if attempts is None:attempts=runtime_boot_dump_materials(journal,recovery)
    context={'version':1,'bootId':recovery['bootId'],'token':recovery['token'],'originHash':runtime_systemd_origin_hash(journal['systemdPolicy'])}
    def intent_valid(intent):
        if not isinstance(intent,dict):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        fields=set(context)|{'attemptCount','attemptsHash','startAttempts','beforeExecution'}|({'clientFailure'}if'clientFailure'in intent else set())
        if set(intent)!=fields or any(intent.get(key)!=value for key,value in context.items())or type(intent.get('version'))is not int or type(intent.get('startAttempts'))is not int or not 1<=intent['startAttempts']<=3 or type(intent.get('attemptCount'))is not int or not 0<=intent['attemptCount']<=min(3,len(attempts)):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        if'clientFailure'in intent:
            prefix=runtime_boot_client_failure_materials(journal,recovery,intent['clientFailure'],attempts)
            if intent['attemptCount']!=len(prefix):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        else:
            prefix=attempts[:intent['attemptCount']]
            if not prefix or any(row['state']not in ['failed','absent']for row in prefix)or prefix[-1].get('failureCause')not in ['pg-dump','pg-restore']:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        if intent.get('attemptsHash')!=runtime_boot_record_hash(prefix):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        if not isinstance(intent.get('beforeExecution'),dict):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        before=runtime_boot_backend_execution(intent['beforeExecution'])
        if before['pid']!=0 or before['active']not in ['inactive','failed']:raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
        return intent
    intent=recovery.get('serviceRecoveryStart');launches=recovery.get('serviceRecoveryLaunches',[])
    if intent is not None:intent_valid(intent)
    if not isinstance(launches,list)or len(launches)>3 or launches and intent is None:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    ordinal=0
    for launch in launches:
        if not isinstance(launch,dict)or set(launch)!={'intent','state','backend','execution'}or launch.get('state')not in ['started','failed']:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        if not isinstance(launch.get('execution'),dict):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        recorded=intent_valid(launch['intent']);execution=runtime_boot_backend_execution(launch['execution']);count=recorded['startAttempts']
        if not ordinal<count<=intent['startAttempts']or count==intent['startAttempts']and recorded!=intent or execution['invocationId']=='0'*32 or execution['invocationId']==recorded['beforeExecution']['invocationId']or execution['mainPID']<2 or execution['startedUsec']<=0:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        if launch['state']=='started':
            backend=runtime_boot_backend_proof(journal,launch['backend'])
            if execution['pid']!=backend['pid']or execution['mainPID']!=backend['pid']or execution['active']!='active'or execution['result']!='success':raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        elif launch['backend']is not None or execution['pid']!=0 or execution['active']!='failed'or execution['result']!='exit-code':raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        ordinal=count
    return intent,launches

def runtime_boot_launch_for_backend(journal,recovery,backend):
    intent,launches=runtime_boot_start_records(journal,recovery)
    if not launches or launches[-1]['state']!='started'or launches[-1]['intent']!=intent or launches[-1]['backend']!=backend:return None
    launch=launches[-1]
    if runtime_boot_backend_execution()!=launch['execution']:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    return launch

def runtime_boot_owned_start_failure(journal,recovery):
    intent,launches=runtime_boot_start_records(journal,recovery)
    if not launches:return False
    execution=runtime_boot_backend_execution();launch=launches[-1]
    if intent['startAttempts']>launch['intent']['startAttempts']and intent['beforeExecution']!=execution:return False
    return execution['pid']==0 and execution['active']=='failed'and execution['result']=='exit-code'and all(execution[key]==launch['execution'][key]for key in ['invocationId','mainPID','startedUsec'])

def runtime_boot_drain_confirmed(journal,recovery,state,allow_start_failure=True):
    if state.get('MainPID')!='0'or state.get('ActiveState')not in ['inactive','failed']:return False
    if not recovery.get('stopRequested')or state.get('Result')=='success':return True
    return allow_start_failure and recovery.get('phase')!='stopping-backend'and runtime_boot_owned_start_failure(journal,recovery)

def record_runtime_boot_backend_launch(journal,recovery,path,backend):
    intent,launches=runtime_boot_start_records(journal,recovery);execution=runtime_boot_backend_execution()
    if intent is None:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    if backend is not None:
        runtime_boot_backend_proof(journal,backend)
        installed=pathlib.Path('/usr/bin/node').stat();running=pathlib.Path('/proc',str(backend['pid']),'exe').stat()
        if not os.path.samestat(installed,running):raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
        verify_runtime_process_libraries(backend['pid'],'SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    launch={'intent':json.loads(json.dumps(intent)),'state':'started'if backend is not None else'failed','backend':backend,'execution':execution}
    if any(row['intent']['startAttempts']==intent['startAttempts']for row in launches):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    recovery['serviceRecoveryLaunches']=[*launches,launch]
    # Validate the independent launch proof before publishing. If publication
    # is interrupted, no same-config stranger is accepted from intent alone.
    try:runtime_boot_start_records(journal,recovery)
    except BaseException:
        recovery['serviceRecoveryLaunches']=launches;raise
    verify_runtime_boot_dump_database(journal,recovery);write_runtime_maintenance(journal,path.parent)
    return launch

def runtime_boot_service_recovery(journal,recovery):
    attempts=runtime_boot_dump_materials(journal,recovery);receipt=recovery.get('serviceRecovery')
    _,launches=runtime_boot_start_records(journal,recovery,attempts)
    context={'version':1,'bootId':recovery['bootId'],'token':recovery['token'],'originHash':runtime_systemd_origin_hash(journal['systemdPolicy'])}
    digest=lambda rows:hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if receipt is not None:
        if not isinstance(receipt,dict):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        fields=set(context)|{'attemptCount','attemptsHash','backend','launchHash'}|({'clientFailure'}if'clientFailure'in receipt else set())
        if set(receipt)!=fields or any(receipt.get(key)!=value for key,value in context.items())or type(receipt.get('version'))is not int or type(receipt.get('attemptCount'))is not int or not 0<=receipt['attemptCount']<=min(3,len(attempts)):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        if'clientFailure'in receipt:
            prefix=runtime_boot_client_failure_materials(journal,recovery,receipt['clientFailure'],attempts)
            if receipt['attemptCount']!=len(prefix):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        else:
            prefix=attempts[:receipt['attemptCount']]
            if not prefix or any(row['state']not in ['failed','absent']for row in prefix)or prefix[-1].get('failureCause')not in ['pg-dump','pg-restore']:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        if receipt.get('attemptsHash')!=digest(prefix):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        runtime_boot_backend_proof(journal,receipt['backend'])
        matches=[launch for launch in launches if launch['state']=='started'and runtime_boot_record_hash(launch)==receipt.get('launchHash')and launch['backend']==receipt['backend']and all(launch['intent'].get(key)==receipt.get(key)for key in set(context)|{'attemptCount','attemptsHash','clientFailure'})]
        if len(matches)!=1:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    retry=recovery.get('retryDrain')
    if retry is not None:
        if not isinstance(retry,dict)or set(retry)!=set(context)|{'attempt','attemptsHash','backend','confirmed'}or any(retry.get(key)!=value for key,value in context.items())or type(retry.get('version'))is not int or type(retry.get('attempt'))is not int or not 1<=retry['attempt']<=min(3,len(attempts)+1)or type(retry.get('confirmed'))is not bool or retry.get('attemptsHash')!=digest(attempts[:retry['attempt']-1]):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        runtime_boot_backend_proof(journal,retry['backend'])
        if retry['attempt']==1 and not any(launch['state']=='started'and launch['backend']==retry['backend']and 'clientFailure'in launch['intent']and launch['intent']['attemptCount']in [0,1]for launch in launches):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    return receipt

def runtime_boot_database_execution(database,proof=None):
    if not isinstance(database,dict)or type(database.get('major'))is not int or database['major']not in [14,15,16,17,18]or database.get('sharedReadOnly')or database.get('unit')!='postgresql@'+str(database['major'])+'-main.service':raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    if proof is None:
        properties='MainPID,ActiveState,Result,InvocationID,ExecMainPID,ExecMainStartTimestampMonotonic'
        raw=dict(line.split('=',1)for line in command(['systemctl','show',database['unit'],'--property='+properties],20).splitlines()if '='in line)
        if set(raw)!=set(properties.split(','))or any(not raw[key].isdecimal()for key in ['MainPID','ExecMainPID','ExecMainStartTimestampMonotonic']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        proof={'pid':int(raw['MainPID']),'active':raw['ActiveState'],'result':raw['Result'],'invocationId':raw['InvocationID']or'0'*32,'mainPID':int(raw['ExecMainPID']),'startedUsec':int(raw['ExecMainStartTimestampMonotonic'])}
    try:return runtime_boot_backend_execution(proof)
    except ValueError as error:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')from error

def runtime_boot_database_authority(journal,recovery):
    authority=recovery.get('databaseRecoveryAuthority')
    if authority is None:
        original=recovery.get('database')
        if original is None:original=journal.get('database')
    else:
        if not isinstance(authority,dict)or set(authority)!={'source','database'}or authority.get('source')not in ['boot-record','original-record']or not isinstance(authority.get('database'),dict):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        original=recovery.get('database')if authority['source']=='boot-record'else journal.get('database')
        if not isinstance(original,dict)or authority['database']!={key:value for key,value in original.items()if key not in ['otherClients','sharedReadOnly']}:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        original=authority['database']
    if not isinstance(original,dict):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    return original

def runtime_boot_database_identity(journal,recovery,proof):
    original=runtime_boot_database_authority(journal,recovery);database=journal.get('database')
    if not isinstance(original,dict)or not isinstance(database,dict)or database.get('sharedReadOnly')or not isinstance(proof,dict):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    current={key:value for key,value in proof.items()if key not in ['otherClients','sharedReadOnly']}
    fields=set(original)-{'otherClients','sharedReadOnly'}
    if set(current)!=fields or type(current.get('pid'))is not int or current['pid']<2 or not isinstance(current.get('start'),str)or not re.fullmatch(r'[^\x00-\x1f]{1,64}',current['start'])or current.get('unit')!=database.get('unit'):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    verify_runtime_database_configuration(current,database);verify_runtime_database_configuration(current,original)
    return current

def runtime_boot_database_recovery_context(journal,recovery):
    database=journal.get('database');dump=recovery.get('dump')
    if not isinstance(database,dict)or database.get('sharedReadOnly')or journal.get('sharedDatabase')is not None or recovery.get('drainConfirmed')is not True or type(recovery.get('dumpPending'))is not bool:raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
    # Service recovery is bound to the two original validated backups. A PG
    # outage must not require the new backup that the stopped PG cannot produce.
    attempts=runtime_boot_dump_materials(journal,recovery)
    if dump is None:
        if recovery['dumpPending']is not True or any(row['state']=='complete'for row in attempts):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    elif not isinstance(dump,dict)or recovery['dumpPending']is not False or set(dump)!={'file','sha256','size'}or not any(row['state']=='complete'and all(row[key]==dump[key]for key in dump)for row in attempts)or runtime_dump_evidence(runtime_dump_directory(journal)/dump['file'])!={key:dump[key]for key in ['sha256','size']}:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    original=runtime_boot_database_identity(journal,recovery,runtime_boot_database_authority(journal,recovery))
    return {'version':1,'bootId':recovery['bootId'],'token':recovery['token'],'originHash':runtime_systemd_origin_hash(journal['systemdPolicy']),'originalDumpsHash':runtime_boot_record_hash(journal['dumpEvidence']),'originalDatabaseHash':runtime_boot_record_hash(original)}

def runtime_boot_database_empty_clusters(database,proof=None):
    native=proof is None
    rows=json.loads(command(['pg_lsclusters','--json'],20))if native else proof
    fields={'version','cluster','port','running'}
    if not isinstance(rows,list)or not 1<=len(rows)<=64:raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    normalized=[]
    for row in rows:
        if not isinstance(row,dict)or not native and set(row)!=fields or not isinstance(row.get('version'),str)or not re.fullmatch(r'[0-9]{1,2}',row['version'])or not isinstance(row.get('cluster'),str)or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',row['cluster'])or type(row.get('running'))is not int or row['running']not in [0,1]or not isinstance(row.get('port'),(str,int))or type(row['port'])is bool or not str(row['port']).isdecimal()or not 1<=int(row['port'])<=65535:raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
        if row['running']:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        normalized.append({'version':row['version'],'cluster':row['cluster'],'port':int(row['port']),'running':0})
    if len([row for row in normalized if row['version']==str(database['major'])and row['cluster']=='main'and row['port']==5432])!=1:raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    return sorted(normalized,key=lambda row:(row['version'],row['cluster'],row['port']))

def runtime_boot_database_unit_policy(database):
    verify_runtime_database_files(database)
    fields='ExecStart,ExecStop,FragmentPath,DropInPaths,ControlGroup'
    state=dict(line.split('=',1)for line in command(['systemctl','show',database['unit'],'--property='+fields],20).splitlines()if '='in line)
    if set(state)!=set(fields.split(','))or state.get('DropInPaths')or state.get('FragmentPath')not in ['/lib/systemd/system/postgresql@.service','/usr/lib/systemd/system/postgresql@.service']:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    start='/usr/bin/pg_ctlcluster --skip-systemctl-redirect '+str(database['major'])+'-main start';stop='/usr/bin/pg_ctlcluster --skip-systemctl-redirect -m fast '+str(database['major'])+'-main stop'
    if re.findall(r'argv\[\]=(.*?) ;',state['ExecStart'])!=[start]or re.findall(r'argv\[\]=(.*?) ;',state['ExecStop'])!=[stop]:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    return state

def runtime_boot_database_native_configuration(database):
    fields=['major','unit','data','config','hba','configHash','hbaHash','unitHash','fileHashes']
    if not isinstance(database,dict)or any(key not in database for key in fields):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    return runtime_boot_record_hash({key:database[key]for key in fields})

def validate_runtime_boot_database_native(database,proof):
    fields={'version','pid','start','major','unit','configurationHash','program','programHash','device','inode','uid','gid','pidNamespace','rootDevice','rootInode','commandHash','cgroup'}
    if not isinstance(proof,dict)or set(proof)!=fields or type(proof.get('version'))is not int or proof['version']!=1 or type(proof.get('pid'))is not int or proof['pid']<2 or not isinstance(proof.get('start'),str)or not proof['start'].isdecimal()or int(proof['start'])<1:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    if type(proof.get('major'))is not int or proof['major']!=database.get('major')or proof.get('unit')!=database.get('unit')or proof.get('configurationHash')!=runtime_boot_database_native_configuration(database)or proof.get('program')!='/usr/lib/postgresql/'+str(database['major'])+'/bin/postgres':raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    if any(type(proof.get(key))is not int or not 0<=proof[key]<2**64 for key in ['device','inode','rootDevice','rootInode'])or any(type(proof.get(key))is not int or not 0<proof[key]<2**32 for key in ['uid','gid'])or any(proof[key]<1 for key in ['inode','rootInode']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    if any(not isinstance(proof.get(key),str)or not re.fullmatch(r'[a-f0-9]{64}',proof[key])for key in ['programHash','commandHash'])or not isinstance(proof.get('pidNamespace'),str)or not re.fullmatch(r'pid:\[[0-9]+\]',proof['pidNamespace'])or not isinstance(proof.get('cgroup'),str)or not re.fullmatch(r'/system\.slice/(?:system-postgresql\.slice/)?postgresql@'+str(database['major'])+r'-main\.service',proof['cgroup']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    return proof

def runtime_boot_database_native(database,execution=None):
    # This is a process observation, not a SQL/configuration attestation. In
    # particular no old settingsHash is copied into a new database proof.
    verify_runtime_database_files(database)
    before=runtime_boot_database_execution(database)
    if execution is not None and execution!=before:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    if before['active']!='active'or before['result']!='success'or before['pid']<2 or before['invocationId']=='0'*32:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    import pwd
    account=pwd.getpwnam('postgres');owner=pathlib.Path(database['data']).stat()
    if account.pw_uid<1 or account.pw_gid<1 or owner.st_uid!=account.pw_uid or owner.st_gid!=account.pw_gid:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    pid=before['pid'];process=pathlib.Path('/proc',str(pid));program='/usr/lib/postgresql/'+str(database['major'])+'/bin/postgres'
    binary=pathlib.Path(program);installed=binary.stat();running=(process/'exe').stat();root=pathlib.Path('/').stat();process_root=(process/'root').stat()
    if str((process/'exe').readlink())!=program or not os.path.samestat(installed,running)or not os.path.samestat(root,process_root):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    namespace=str((process/'ns/pid').readlink())
    if namespace!=str(pathlib.Path('/proc/1/ns/pid').readlink()):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    def read(part,binary=False,limit=65536):
        with (process/part).open('rb')as stream:data=stream.read(limit+1)
        if len(data)>limit:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        if binary:return data
        try:return data.decode('utf-8')
        except UnicodeDecodeError:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    def start():
        raw=read('stat',limit=8192);position=raw.rfind(') ');fields=raw[position+2:].split()
        if position<0 or raw[:raw.find(' ')]!=str(pid)or len(fields)<20 or fields[0]in ['Z','X','x']or not fields[19].isdecimal()or int(fields[19])<1:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        return fields[19]
    started=start();status=read('status');uids=re.search(r'^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',status,re.M);gids=re.search(r'^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',status,re.M)
    if not uids or not gids or any(int(value)!=account.pw_uid for value in uids.groups())or any(int(value)!=account.pw_gid for value in gids.groups()):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    raw=read('cmdline',binary=True)
    try:arguments=[value.decode('utf-8')for value in raw.split(b'\0')if value]
    except UnicodeDecodeError:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    if not 5<=len(arguments)<=64 or arguments[:3]!=[program,'-D',database['data']]or len(arguments[3:])%2 or any(re.search(r'[\x00-\x1f]',value)for value in arguments):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    cdir='/etc/postgresql/'+str(database['major'])+'/main';allowed={'config_file':[database['config']],'hba_file':[database['hba']],'ident_file':[cdir+'/pg_ident.conf'],'unix_socket_directories':['/var/run/postgresql','/run/postgresql'],'external_pid_file':['/var/run/postgresql/'+str(database['major'])+'-main.pid','/run/postgresql/'+str(database['major'])+'-main.pid']};options={}
    for index in range(3,len(arguments),2):
        value=arguments[index+1].split('=',1)
        if arguments[index]!='-c'or len(value)!=2 or value[0]in options or value[0]not in allowed or value[1]not in allowed[value[0]]:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        options[value[0]]=value[1]
    if options.get('config_file')!=database['config']:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    cgroup=runtime_boot_database_unit_policy(database)['ControlGroup']
    rows=read('cgroup').splitlines()
    if not rows or len(rows)>64 or not any(len(parts:=row.split(':',2))==3 and (parts[0]=='0'and parts[1]==''or'name=systemd'in parts[1].split(','))and parts[2]==cgroup for row in rows):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    record=runtime_payload_regular(program,64*1024*1024)
    if record['size']<1 or record['mode']&0o7000 or record['mode']&0o111!=0o111:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    verify_runtime_process_libraries(pid,'SYSTEM_SECURITY_DATABASE_ACTIVATION_PENDING')
    if start()!=started or read('cmdline',binary=True)!=raw or not os.path.samestat(installed,binary.stat())or not os.path.samestat(installed,(process/'exe').stat())or runtime_boot_database_execution(database)!=before:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    verify_runtime_database_files(database)
    return validate_runtime_boot_database_native(database,{'version':1,'pid':pid,'start':started,'major':database['major'],'unit':database['unit'],'configurationHash':runtime_boot_database_native_configuration(database),'program':program,'programHash':record['sha256'],'device':installed.st_dev,'inode':installed.st_ino,'uid':account.pw_uid,'gid':account.pw_gid,'pidNamespace':namespace,'rootDevice':root.st_dev,'rootInode':root.st_ino,'commandHash':hashlib.sha256(raw).hexdigest(),'cgroup':cgroup})

def runtime_boot_database_launch_matches(launch,proof):
    if not isinstance(proof,dict):return False
    if 'native'in launch:return all(launch['native'][key]==proof.get(key)for key in ['pid','start'])
    return launch.get('database')==proof

def validate_runtime_boot_database_resume(journal,recovery,reason):
    fields={'kind','error','attemptCount','attemptsHash'}|({'clientFailure'}if isinstance(reason,dict)and reason.get('kind')=='client'else set())
    attempts=runtime_boot_dump_materials(journal,recovery)
    if not isinstance(reason,dict)or set(reason)!=fields or reason.get('kind')not in ['client','dump']or type(reason.get('attemptCount'))is not int or not 0<=reason['attemptCount']<=len(attempts):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    if reason['kind']=='client':
        if reason.get('error')not in BOOT_CLIENT_FAILURE_CODES:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        prefix=runtime_boot_client_failure_materials(journal,recovery,reason['clientFailure'],attempts)
        if reason['clientFailure']['error']!=reason['error']or len(prefix)!=reason['attemptCount']:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    else:
        prefix=attempts[:reason['attemptCount']]
        if reason['error']!='SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED'or not prefix or any(row['state']not in ['failed','absent']for row in prefix)or prefix[-1].get('failureCause')not in ['pg-dump','pg-restore']:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    if reason.get('attemptsHash')!=runtime_boot_record_hash(prefix):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    return reason

def runtime_boot_database_resume_reason(journal,recovery,failure):
    if not isinstance(failure,(RuntimeBootDumpExecutionFailed,RuntimeBootClientValidationFailed))or failure.boot_id!=recovery.get('bootId')or failure.token!=recovery.get('token')or failure.origin_hash!=runtime_systemd_origin_hash(journal['systemdPolicy']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    attempts=runtime_boot_dump_materials(journal,recovery)
    if isinstance(failure,RuntimeBootClientValidationFailed):
        prefix=runtime_boot_client_failure_materials(journal,recovery,failure.client_failure,attempts)
        reason={'kind':'client','error':str(failure),'attemptCount':len(prefix),'attemptsHash':runtime_boot_record_hash(prefix),'clientFailure':failure.client_failure}
    else:reason={'kind':'dump','error':str(failure),'attemptCount':failure.attempt_count,'attemptsHash':runtime_boot_record_hash(attempts)}
    return validate_runtime_boot_database_resume(journal,recovery,reason)

def runtime_boot_database_resume_request(journal,recovery,launch):
    reason=validate_runtime_boot_database_resume(journal,recovery,launch['resume'])
    if reason['kind']=='client':return RuntimeBootClientValidationFailed(journal,recovery,reason['error'],client_failure=reason['clientFailure'])
    return RuntimeBootDumpExecutionFailed(journal,recovery)

def runtime_boot_database_start_records(journal,recovery):
    context=runtime_boot_database_recovery_context(journal,recovery);database=journal['database'];intent=recovery.get('databaseServiceRecoveryStart');launches=recovery.get('databaseServiceRecoveryLaunches',[])
    if 'databaseServiceRecoveryStart'in recovery and intent is None or not isinstance(launches,list)or len(launches)>2 or launches and intent is None:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    def validate_intent(record,previous):
        if not isinstance(record,dict)or set(record)!=set(context)|{'attempt','beforeExecution','drain','faultRecovery','emptyClusters'}or any(record.get(key)!=value for key,value in context.items())or type(record.get('version'))is not int or type(record.get('attempt'))is not int or not 1<=record['attempt']<=2 or not isinstance(record.get('beforeExecution'),dict):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        before=runtime_boot_database_execution(database,record['beforeExecution'])
        if before['pid']!=0 or before['active']not in ['inactive','failed']or type(record.get('faultRecovery'))is not bool:raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
        if not isinstance(record.get('emptyClusters'),list)or runtime_boot_database_empty_clusters(database,record['emptyClusters'])!=record['emptyClusters']:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        drain=record['drain']
        if drain is not None:
            if record['faultRecovery']:raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
            if not isinstance(drain,dict)or set(drain)!=set(context)|{'database','beforeExecution','afterExecution','confirmed'}or any(drain.get(key)!=value for key,value in context.items())or drain.get('confirmed')is not True or not isinstance(drain.get('beforeExecution'),dict)or not isinstance(drain.get('afterExecution'),dict):raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
            prior=runtime_boot_database_identity(journal,recovery,drain['database']);active=runtime_boot_database_execution(database,drain['beforeExecution']);stopped=runtime_boot_database_execution(database,drain['afterExecution'])
            authority=runtime_boot_database_identity(journal,recovery,runtime_boot_database_authority(journal,recovery))
            if prior!=authority and not any(row['state']=='started'and runtime_boot_database_launch_matches(row,prior)for row in previous):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
            if active['pid']!=prior['pid']or active['active']!='active'or active['result']!='success'or stopped!=before or stopped['result']!='success'or any(stopped[key]!=active[key]for key in ['mainPID','startedUsec'])or stopped['invocationId']not in ['0'*32,active['invocationId']]:raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
        elif not previous:
            # Earlier prepared complete journals attest the original successful
            # owned PG stop. Only its actually inactive successful unit qualifies.
            if record['attempt']!=1 or before['result']!='success'and not record['faultRecovery']:raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
        else:
            prior=previous[-1]['execution']
            if before['active']!='failed'or before['result']!='exit-code'or any(before[key]!=prior[key]for key in ['invocationId','mainPID','startedUsec']):raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
        return record
    previous=[]
    for launch in launches:
        if not isinstance(launch,dict)or set(launch)!={'intent','state','database','execution'}|({'native','resume'}if'native'in launch else set())or launch.get('state')not in ['started','failed']or not isinstance(launch.get('execution'),dict):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        saved=validate_intent(launch['intent'],previous);execution=runtime_boot_database_execution(database,launch['execution'])
        if saved['attempt']!=(previous[-1]['intent']['attempt']+1 if previous else 1)or execution['invocationId']=='0'*32 or execution['invocationId']==saved['beforeExecution']['invocationId']or execution['startedUsec']<=0:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        if launch['state']=='started':
            if 'native'in launch:
                proof=validate_runtime_boot_database_native(database,launch['native'])
                validate_runtime_boot_database_resume(journal,recovery,launch['resume'])
                if launch['database']is not None:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
            else:proof=runtime_boot_database_identity(journal,recovery,launch['database'])
            if execution['pid']!=proof['pid']or execution['active']!='active'or execution['result']!='success':raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        elif 'native'in launch or launch['database']is not None or execution['pid']!=0 or execution['active']!='failed'or execution['result']!='exit-code'or execution['mainPID']<2:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        previous.append(launch)
    if intent is not None:
        if not isinstance(intent,dict)or type(intent.get('attempt'))is not int:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        prefix=[row for row in launches if row['intent']['attempt']<intent['attempt']]
        validate_intent(intent,prefix)
        if launches and (intent['attempt']<launches[-1]['intent']['attempt']or intent['attempt']==launches[-1]['intent']['attempt']and intent!=launches[-1]['intent']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    return context,intent,launches

def runtime_boot_database_launch_for_current(journal,recovery,current):
    context,intent,launches=runtime_boot_database_start_records(journal,recovery)
    receipt=recovery.get('databaseServiceRecovery')
    if 'databaseServiceRecovery'in recovery and receipt is None:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    if receipt is not None:
        if not isinstance(receipt,dict)or set(receipt)!=set(context)|{'database','launchHash'}or any(receipt.get(key)!=value for key,value in context.items()):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        proof=runtime_boot_database_identity(journal,recovery,receipt['database'])
        if len([row for row in launches if row['state']=='started'and runtime_boot_database_launch_matches(row,proof)and runtime_boot_record_hash(row)==receipt.get('launchHash')])!=1:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    identity=runtime_boot_database_identity(journal,recovery,current)
    if not launches or launches[-1]['state']!='started'or launches[-1]['intent']!=intent or not runtime_boot_database_launch_matches(launches[-1],identity):return None
    launch=launches[-1]
    if runtime_boot_database_execution(journal['database'])!=launch['execution']:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    if 'native'in launch and runtime_boot_database_native(journal['database'],launch['execution'])!=launch['native']:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    return launch

def restore_runtime_boot_owned_database(journal,recovery,path,failure=None):
    database=journal.get('database')
    if database is None:return
    if database.get('sharedReadOnly')or journal.get('sharedDatabase')is not None:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    execution=runtime_boot_database_execution(database)
    if execution['active']=='active':
        _,intent,launches=runtime_boot_database_start_records(journal,recovery)
        if launches and 'native'in launches[-1]:
            launch=launches[-1]
            if launch['state']!='started'or launch['intent']!=intent or launch['execution']!=execution or runtime_boot_database_native(database,execution)!=launch['native']:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        else:
            current=database_runtime_proof(journal=journal);identity=runtime_boot_database_identity(journal,recovery,current)
            if execution['pid']!=identity['pid']:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
            if isinstance(recovery.get('database'),dict)and identity==runtime_boot_database_identity(journal,recovery,recovery['database'])and not any(key in recovery for key in ['databaseServiceRecoveryStart','databaseServiceRecoveryLaunches','databaseServiceRecovery']):return
            launch=runtime_boot_database_launch_for_current(journal,recovery,current)
            if launch is None:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    else:
        if 'databaseRecoveryAuthority'not in recovery:
            authority=runtime_boot_database_identity(journal,recovery,runtime_boot_database_authority(journal,recovery))
            recovery['databaseRecoveryAuthority']={'source':'boot-record'if recovery.get('database')is not None else'original-record','database':authority}
        drain=recovery.get('databaseRecoveryDrain')
        if isinstance(drain,dict)and drain.get('confirmed')is False:record_runtime_boot_database_drain(journal,recovery,None,confirmed=True)
        context,intent,launches=runtime_boot_database_start_records(journal,recovery)
        if execution['pid']!=0 or execution['active']not in ['inactive','failed']or recovery.get('phase')not in ['drained','prepared','stopping-database']:raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
        count=intent['attempt']if intent is not None else 0
        if count>=2:raise ValueError('SYSTEM_SECURITY_DATABASE_ACTIVATION_PENDING')
        if intent is not None and count>len(launches):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        drain=recovery.get('databaseRecoveryDrain')if execution['result']=='success'else None
        fault=recovery.get('dumpPending')is True and recovery.get('dump')is None and recovery.get('phase')=='drained'and 'databaseRecoveryDrain'not in recovery
        empty=runtime_boot_database_empty_clusters(database)
        next_intent={**context,'attempt':count+1,'beforeExecution':execution,'drain':drain,'faultRecovery':fault,'emptyClusters':empty}
        recovery['databaseServiceRecoveryStart']=next_intent
        try:runtime_boot_database_start_records(journal,recovery)
        except BaseException:
            if intent is None:recovery.pop('databaseServiceRecoveryStart',None)
            else:recovery['databaseServiceRecoveryStart']=intent
            raise
        resume=runtime_boot_database_resume_reason(journal,recovery,failure)
        verify_runtime_database_files(database);runtime_boot_database_unit_policy(database);write_runtime_maintenance(journal,path.parent)
        try:command(['systemctl','start',database['unit']],180)
        except(ValueError,OSError):pass
        after=runtime_boot_database_execution(database)
        native=runtime_boot_database_native(database,after)if after['active']=='active'else None
        launch={'intent':json.loads(json.dumps(next_intent)),'state':'started'if native is not None else'failed','database':None,'execution':after}
        if native is not None:launch.update(native=native,resume=resume)
        recovery['databaseServiceRecoveryLaunches']=[*launches,launch]
        # Publish the actual native launch before any SQL/client observation.
        # An interrupted query cannot erase ownership of this exact process.
        runtime_boot_database_start_records(journal,recovery);write_runtime_maintenance(journal,path.parent)
        if native is None:raise ValueError('SYSTEM_SECURITY_DATABASE_ACTIVATION_PENDING')
    context,_,_=runtime_boot_database_start_records(journal,recovery)
    current=database_runtime_proof(journal=journal);identity=runtime_boot_database_identity(journal,recovery,current);verify_database_activation(current,database)
    if not runtime_boot_database_launch_matches(launch,identity)or runtime_boot_database_execution(database)!=launch['execution']:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    if 'native'in launch and runtime_boot_database_native(database,launch['execution'])!=launch['native']:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    recovery['databaseServiceRecovery']={**context,'database':identity,'launchHash':runtime_boot_record_hash(launch)};write_runtime_maintenance(journal,path.parent)

def record_runtime_boot_database_drain(journal,recovery,current,confirmed=False):
    if recovery.get('dumpPending')is not False or recovery.get('dump')is None:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    context=runtime_boot_database_recovery_context(journal,recovery);database=journal['database'];execution=runtime_boot_database_execution(database)
    if not confirmed:
        identity=runtime_boot_database_identity(journal,recovery,current)
        if identity!=runtime_boot_database_identity(journal,recovery,recovery['database'])and runtime_boot_database_launch_for_current(journal,recovery,current)is None:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        if execution['pid']!=identity['pid']or execution['active']!='active'or execution['result']!='success':raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        recovery['databaseRecoveryDrain']={**context,'database':identity,'beforeExecution':execution,'confirmed':False}
    else:
        drain=recovery.get('databaseRecoveryDrain')
        if not isinstance(drain,dict)or drain.get('confirmed')is not False or any(drain.get(key)!=value for key,value in context.items())or execution['pid']!=0 or execution['active']not in ['inactive','failed']or execution['result']!='success'or any(execution[key]!=drain['beforeExecution'][key]for key in ['mainPID','startedUsec'])or execution['invocationId']not in ['0'*32,drain['beforeExecution']['invocationId']]:raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
        drain.update(confirmed=True,afterExecution=execution)
    write_runtime_maintenance(journal)

def verify_runtime_boot_dump_database(journal,recovery):
    shared=journal.get('sharedDatabase');owned=journal.get('database')
    database=journal.get('backupDatabase')or owned or shared or recovery.get('backupDatabase')
    if not isinstance(database,dict):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    if shared is not None:
        recorded=recovery.get('sharedDatabase');saved=journal.get('bootSharedDatabases',{}).get(recovery['bootId'],{}).get('proof')
        if not isinstance(recorded,dict)or not isinstance(saved,dict)or any(recorded.get(key)!=saved.get(key)for key in ['pid','start']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    elif owned is not None:recorded=recovery.get('database')
    else:recorded=recovery.get('backupDatabaseProcess')
    if owned is not None and recorded is None and any(key in recovery for key in ['databaseServiceRecoveryStart','databaseServiceRecoveryLaunches','databaseServiceRecovery']):
        _,intent,launches=runtime_boot_database_start_records(journal,recovery)
        if not launches or launches[-1]['state']!='started'or launches[-1]['intent']!=intent:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        recorded=launches[-1]['native']if'native'in launches[-1]else launches[-1]['database']
    if not isinstance(recorded,dict)or type(recorded.get('pid'))is not int or recorded['pid']<2 or not isinstance(recorded.get('start'),str):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    current=database_runtime_proof(shared_read_only=True,journal=journal)
    verify_runtime_database_configuration(current,database)
    for original in [owned,shared]:
        if original is not None:verify_runtime_database_configuration(current,original)
    if owned is not None and any(key in recovery for key in ['databaseServiceRecoveryStart','databaseServiceRecoveryLaunches','databaseServiceRecovery']):
        launch=runtime_boot_database_launch_for_current(journal,recovery,current)
        if launch is None:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        recorded=launch['native']if'native'in launch else launch['database']
    if any(current[key]!=recorded.get(key)for key in ['pid','start']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    verify_runtime_database_files(database,backup_only=True)
    return current

def runtime_dump_material(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600 or not 0<=info.st_size<=64*1024*1024*1024:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        digest=hashlib.sha256();size=0;header=b''
        while True:
            block=os.read(fd,262144)
            if not block:break
            if len(header)<5:header=(header+block)[:5]
            digest.update(block);size+=len(block)
            if size>64*1024*1024*1024:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        after=os.fstat(fd)
        if size!=info.st_size or not os.path.samestat(info,os.lstat(path))or any(getattr(info,key)!=getattr(after,key)for key in ['st_size','st_mtime_ns','st_ctime_ns']):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        return {'sha256':digest.hexdigest(),'size':size,'header':header==b'PGDMP'}
    finally:os.close(fd)

def runtime_dump_evidence(path):
    value=runtime_dump_material(path)
    if not value['header']:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    return {key:value[key]for key in ['sha256','size']}

def runtime_dump_directory(journal):
    name=journal.get('backup')
    if not isinstance(name,str)or not re.fullmatch(r'runtime-backup-[a-f0-9]{32}',name):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    backup=pathlib.Path('/var/lib/incudal-system-security')/name;info=backup.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or backup.resolve()!=backup:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    return backup

def verify_runtime_original_dumps(journal):
    proofs=journal.get('dumpEvidence');backup=runtime_dump_directory(journal)
    if not isinstance(proofs,dict)or set(proofs)!={'database.dump','database-after-drain.dump'}:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    for name,proof in proofs.items():
        if runtime_dump_evidence(backup/name)!=proof:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')

def runtime_original_dump_versions(journal):
    verify_runtime_original_dumps(journal);backup=runtime_dump_directory(journal);versions=[]
    for name in ['database.dump','database-after-drain.dump']:
        fd=os.open(backup/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(fd);data=os.read(fd,4096);after=os.fstat(fd)
            if not os.path.samestat(before,os.lstat(backup/name))or any(getattr(before,key)!=getattr(after,key)for key in ['st_size','st_mtime_ns','st_ctime_ns']):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
        finally:os.close(fd)
        # Read only the original custom archive header. Neither a wrapper nor
        # an unproven installed client is used to infer the source cluster.
        if len(data)<12 or data[:5]!=b'PGDMP'or data[5]!=1 or not 14<=data[6]<=16 or data[7]!=0 or data[8]not in [4,8]or data[9]not in [4,8]or data[10]!=1:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
        integer_size=data[8];position=11
        def integer():
            nonlocal position
            if position+integer_size+1>len(data)or data[position]not in [0,1]:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
            negative=data[position];number=int.from_bytes(data[position+1:position+integer_size+1],'little');position+=integer_size+1
            return -number if negative else number
        def string():
            nonlocal position
            size=integer()
            if not 0<=size<=256 or position+size>len(data):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
            try:value=data[position:position+size].decode('ascii')
            except UnicodeDecodeError:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
            position+=size;return value
        if data[6]>=15:
            if position>=len(data)or data[position]not in [0,1,2,3]:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
            position+=1
        elif not -1<=integer()<=9:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
        for _ in range(7):integer()
        if string()!='incudal':raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
        source=string();client=string()
        parsed=[re.fullmatch(r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?: \([^\x00-\x1f]*\))?',value)for value in [source,client]]
        if any(value is None for value in parsed):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
        versions.append({'major':int(parsed[0][1].split('.')[0]),'clientMajor':int(parsed[1][1].split('.')[0]),'server':parsed[0][1],'client':parsed[1][1],'serverHeader':source,'clientHeader':client})
    if versions[0]!=versions[1]or versions[0]['major']not in [14,15,16,17,18]or versions[0]['clientMajor']not in [14,15,16,17,18]:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    verify_runtime_original_dumps(journal)
    return versions[0]

def runtime_original_dump_major(journal):return runtime_original_dump_versions(journal)['major']

def runtime_boot_backup_database(journal,recovery=None):
    original=journal['backupDatabase']if 'backupDatabase'in journal else journal.get('database')or journal.get('sharedDatabase')
    if original is None:
        # Old Node-only transactions did not save a database proof. Require
        # the original complete package baseline, both bound original dumps
        # and the authenticated Before client payload, never the newest client.
        major=runtime_original_dump_major(journal)
        clients=runtime_database_legacy_before_clients(journal,major)
        verify_runtime_database_clients({'major':major,'clientTools':clients},journal)
        observed=database_runtime_proof(shared_read_only=True,journal=journal)
        if observed.get('major')!=major:raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
        original={**observed,'clientTools':clients}
        if recovery is not None:
            prior=recovery.get('backupDatabase')
            if prior is not None:
                if not isinstance(prior,dict):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
                verify_runtime_database_configuration(observed,prior)
                if any(observed[key]!=prior.get(key)for key in ['pid','start'])or prior.get('clientTools')!=clients:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
                original=prior
            else:recovery['backupDatabase']=original;write_runtime_maintenance(journal)
    if not isinstance(original,dict):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    for existing in [journal.get('database'),journal.get('sharedDatabase')]:
        if existing is not None:verify_runtime_database_configuration(original,existing)
    verify_runtime_database_files(original,backup_only=True);verify_runtime_database_clients(original,journal)
    return original

def runtime_boot_dump_attempts(journal,recovery):
    boot=recovery.get('bootId');token=recovery.get('token')
    policies=runtime_systemd_policy_lineage(journal)
    if not isinstance(boot,str)or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot)or not any(proof['bootId']==boot and proof['token']==token for proof in policies[1:]):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    attempts=recovery.get('dumpAttempts',[])
    if not isinstance(attempts,list)or len(attempts)>3:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    for ordinal,attempt in enumerate(attempts,1):
        fields={'file','attempt','state'}|({'sha256','size'}if isinstance(attempt,dict)and attempt.get('state')in ['failed','complete']else set())
        if isinstance(attempt,dict)and 'failureCause'in attempt:
            if attempt.get('state')not in ['failed','absent']or attempt['failureCause']not in ['pg-dump','pg-restore']or attempt.get('state')=='absent'and attempt['failureCause']!='pg-dump':raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            fields.add('failureCause')
        if not isinstance(attempt,dict)or set(attempt)!=fields or type(attempt.get('attempt'))is not int or attempt['attempt']!=ordinal or attempt.get('file')!='database-after-drain-boot-'+boot+'-'+str(ordinal)+'.dump'or attempt.get('state')not in ['intent','absent','failed','complete']:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        if attempt['state']=='intent'and ordinal!=len(attempts):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        if attempt['state']in ['failed','complete']and (not re.fullmatch(r'[a-f0-9]{64}',attempt.get('sha256',''))or type(attempt.get('size'))is not int or not 0<=attempt['size']<=64*1024*1024*1024):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    if sum(attempt['state']=='complete'for attempt in attempts)>1:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    return attempts

def runtime_new_boot_dump(journal,recovery):
    verify_runtime_original_dumps(journal);backup=runtime_dump_directory(journal)
    attempts=runtime_boot_dump_materials(journal,recovery)
    proof=recovery.get('dump')
    if proof is not None:
        if not isinstance(proof,dict)or set(proof)!={'file','sha256','size'}or not any(attempt['state']=='complete'and all(attempt[key]==proof[key]for key in proof)for attempt in attempts)or runtime_dump_evidence(backup/proof['file'])!={key:proof[key]for key in ['sha256','size']}:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        return
    if any(attempt['state']=='complete'for attempt in attempts):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    database=runtime_boot_backup_database(journal,recovery)
    # Reserve each new filename durably before pg_dump can create it. An
    # interrupted output stays at its original path and is never overwritten;
    # a later valid dump is a separate, bounded attempt.
    while True:
        attempt=attempts[-1]if attempts and attempts[-1]['state']=='intent'else None
        fresh=attempt is None
        if attempt is None:
            if len(attempts)>=3:
                if all(row['state']in ['failed','absent']and row.get('failureCause')in ['pg-dump','pg-restore']for row in attempts):raise RuntimeBootDumpExecutionFailed(journal,recovery)
                raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            ordinal=len(attempts)+1
            attempt={'file':'database-after-drain-boot-'+recovery['bootId']+'-'+str(ordinal)+'.dump','attempt':ordinal,'state':'intent'}
            # A pre-existing filename has no authority from a newly created
            # intent. Only an already durable original intent can resume it.
            if runtime_path_present(backup/attempt['file']):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            attempts.append(attempt);recovery['dumpAttempts']=attempts;write_runtime_maintenance(journal)
        target=backup/attempt['file']
        if fresh or not runtime_path_present(target):
            _,before_tools=verify_runtime_database_clients(database,journal)
            try:dump_runtime_database(target,database,journal)
            except (ValueError,OSError)as error:
                execution=isinstance(error,ValueError)and str(error)=='SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED'or isinstance(error,OSError)and error.errno in [5,11,12,24,28,122]
                if isinstance(error,OSError)and not isinstance(error,FileExistsError)and not execution:raise
                if runtime_path_present(target):
                    material=runtime_dump_material(target)
                    if execution:
                        if runtime_database_client_files(before_tools['major'])!=before_tools:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
                        verify_runtime_original_dumps(journal)
                    attempt.update(state='failed',**{key:material[key]for key in ['sha256','size']})
                    if execution:attempt['failureCause']='pg-dump'
                    write_runtime_maintenance(journal)
                    if execution:raise RuntimeBootDumpExecutionFailed(journal,recovery)
                elif execution:
                    # The durable intent owns this attempted name; only a
                    # genuinely missing output is sealed as absent. A failed
                    # lstat/read, collision or identity check never gets here.
                    if runtime_database_client_files(before_tools['major'])!=before_tools:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
                    verify_runtime_original_dumps(journal)
                    attempt.update(state='absent',failureCause='pg-dump');write_runtime_maintenance(journal)
                    raise RuntimeBootDumpExecutionFailed(journal,recovery)
                raise
        material=runtime_dump_material(target)
        valid=material['header'];validation_failed=False
        if valid:
            clients,tools=verify_runtime_database_clients(database,journal)
            try:
                # --list only reads the catalogue. This offline command also
                # decompresses every data block, without opening a database.
                command([clients['pg_restore'],'--file=/dev/null',str(target)],300)
            except ValueError as error:
                if str(error)not in ['SYSTEM_SECURITY_PACKAGE_QUERY_FAILED','SYSTEM_SECURITY_PACKAGE_CHILD_PENDING']:raise
                valid=False;validation_failed=True
            if runtime_database_client_files(tools['major'])!=tools:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
        if runtime_dump_material(target)!=material:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        if validation_failed:verify_runtime_original_dumps(journal)
        attempt.update(state='complete'if valid else'failed',**{key:material[key]for key in ['sha256','size']})
        if validation_failed:attempt['failureCause']='pg-restore'
        if valid:
            recovery['dump']={'file':attempt['file'],**{key:material[key]for key in ['sha256','size']}};recovery['dumpPending']=False
        write_runtime_maintenance(journal)
        if valid:return

def preserve_runtime_past_boot_dumps(journal,boot):
    recoveries=journal.get('bootRecoveries',{})
    if not isinstance(recoveries,dict)or len(recoveries)>3:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    backup=runtime_dump_directory(journal);updates=[]
    for previous,recovery in recoveries.items():
        if previous==boot:continue
        if not isinstance(recovery,dict)or recovery.get('bootId')!=previous:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        for attempt in runtime_boot_dump_attempts(journal,recovery):
            if attempt['state']!='intent':continue
            path=backup/attempt['file']
            if runtime_path_present(path):
                material=runtime_dump_material(path);updates.append((attempt,{'state':'failed',**{key:material[key]for key in ['sha256','size']}}))
            else:updates.append((attempt,{'state':'absent'}))
    for attempt,update in updates:attempt.update(update)
    if updates:write_runtime_maintenance(journal)

def confirm_runtime_boot_dump(journal,proof):
    recovery=journal.get('bootRecoveries',{}).get(proof['bootId'])
    if not isinstance(recovery,dict)or recovery.get('version')!=1 or recovery.get('bootId')!=proof['bootId']or recovery.get('token')!=proof['token']or recovery.get('drainConfirmed')is not True or recovery.get('dumpPending')is not False:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    dump=recovery.get('dump');attempts=runtime_boot_dump_attempts(journal,recovery)
    if not isinstance(dump,dict)or set(dump)!={'file','sha256','size'}or not any(attempt['state']=='complete'and all(attempt[key]==dump[key]for key in dump)for attempt in attempts):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    verify_runtime_original_dumps(journal)
    if runtime_dump_evidence(runtime_dump_directory(journal)/dump['file'])!={key:dump[key]for key in ['sha256','size']}:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    if journal.get('sharedDatabase')is not None:
        shared=recovery.get('sharedDatabase');record=journal.get('bootSharedDatabases',{}).get(proof['bootId'])
        if not isinstance(shared,dict)or not isinstance(record,dict)or not isinstance(record.get('proof'),dict)or any(shared.get(key)!=record['proof'].get(key)for key in ['pid','start']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        current=database_runtime_proof(shared_read_only=True,journal=journal);verify_runtime_database_configuration(current,journal['sharedDatabase'])
        if any(current[key]!=shared[key]for key in ['pid','start']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')

def runtime_boot_shared_database(journal,boot):
    original=journal.get('sharedDatabase')
    if original is None:return None
    policy=journal.get('systemdPolicy')
    if not isinstance(original,dict)or original.get('sharedReadOnly')is not True:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    original_boot=policy.get('bootId')if isinstance(policy,dict)else journal.get('bootId')
    original_token=policy.get('token')if isinstance(policy,dict)else None
    origin=runtime_systemd_origin_hash(policy)if isinstance(policy,dict)else hashlib.sha256(json.dumps({field:journal.get(field)for field in ['version','bootId','backend','sharedDatabase','packages','baselinePackages','expectedPackages','backup']},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    current=database_runtime_proof(shared_read_only=True,journal=journal);verify_runtime_database_configuration(current,original)
    if original_boot is None or boot==original_boot:
        if any(current[key]!=original[key]for key in ['pid','start']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        return original
    baselines=journal.setdefault('bootSharedDatabases',{})
    if not isinstance(baselines,dict)or len(baselines)>3:raise ValueError('SYSTEM_SECURITY_SYSTEMD_BOOT_RECOVERY_LIMIT')
    for key,record in baselines.items():
        if not isinstance(key,str)or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',key)or key==original_boot or not isinstance(record,dict)or set(record)!={'version','bootId','originalToken','originHash','proof'}or record.get('version')!=1 or record.get('bootId')!=key or record.get('originalToken')!=original_token or record.get('originHash')!=origin or not isinstance(record.get('proof'),dict)or record['proof'].get('sharedReadOnly')is not True:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    record=baselines.get(boot)
    if record is None:
        if len(baselines)>=3 or not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',boot):raise ValueError('SYSTEM_SECURITY_SYSTEMD_BOOT_RECOVERY_LIMIT')
        record={'version':1,'bootId':boot,'originalToken':original_token,'originHash':origin,'proof':current}
        baselines[boot]=record;write_runtime_maintenance(journal)
    elif any(current[key]!=record['proof'].get(key)for key in ['pid','start']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    return record['proof']

def prepare_runtime_boot_recovery(journal):
    original=journal.get('systemdPolicy');boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if not original or boot==original.get('bootId'):return None
    baseline,expected,_,planned=validated_runtime_package_plan(journal);states=debian_package_states()
    current_packages={key:value['version']for key,value in states.items()}
    if current_packages.keys()!=baseline.keys()or any(current_packages[key]not in [baseline[key],expected[key]]for key in baseline)or any(value['status']!='installed'and key.split(':')[0]not in planned and not(key.split(':')[0]=='systemd'and value['status']in ['triggers-awaited','triggers-pending'])for key,value in states.items()):raise ValueError('SYSTEM_SECURITY_RUNTIME_PACKAGE_BASELINE_CHANGED')
    verify_runtime_systemd_package_authority(journal,archives=True);payload=verify_runtime_payload(journal,archives=True)
    lineage=runtime_systemd_policy_lineage(journal)
    for previous in lineage:
        if previous.get('originHash')and not previous.get('ready'):repair_runtime_unready_policy_files(journal,previous)
    histories=[runtime_systemd_policy_history(proof)for proof in lineage if proof['bootId']!=boot]
    if current_packages==baseline and all(value['status']=='installed'for value in states.values())and payload['unchanged']and not command(['dpkg','--audit'],30)and all(history['actions']==[]for history in histories):
        verify_runtime_node_authority(journal,require='before')
        return {'unstarted':True,'bootId':boot}
    verify_runtime_original_dumps(journal)
    preserve_runtime_past_boot_dumps(journal,boot)
    current=backend_runtime_proof()
    if current is not None and any(current[key]!=journal['backend'].get(key)for key in ['app','environmentHash','codeHash','serviceHash','unitHashes']):raise ValueError('SYSTEM_SECURITY_BACKEND_CONFIGURATION_CHANGED')
    verify_runtime_node_authority(journal,current=current,require='mixed',allow_missing=True)
    backup_database=runtime_boot_backup_database(journal)
    shared_authority=runtime_boot_shared_database(journal,boot)
    if not isinstance(journal.get('bootRecoveries',{}),dict):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    if boot not in journal.get('bootRecoveries',{})and current_packages==expected and all(value['status']=='installed'for value in states.values())and payload['complete']and not command(['dpkg','--audit'],30):
        try:confirmation=runtime_systemd_boot_confirmation(journal)
        except ValueError as error:
            if str(error)not in ['SYSTEM_SECURITY_SYSTEMD_ACTIVATION_PENDING','SYSTEM_SECURITY_LIBC_PAYLOAD_UNCONFIRMED']:raise
        else:return {'bootId':boot,'confirmation':confirmation,'sharedDatabase':shared_authority}
    policy=prepare_runtime_systemd_boot_policy(journal)
    recoveries=journal.setdefault('bootRecoveries',{})
    if not isinstance(recoveries,dict)or len(recoveries)>3 or any(key not in {proof['bootId']for proof in journal.get('systemdBootPolicies',[])}for key in recoveries):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    recovery=recoveries.get(boot)
    if recovery is None:
        recovery={'version':1,'bootId':boot,'token':policy['token'],'phase':'prepared','backend':current,'dumpPending':True}
        if shared_authority is not None:recovery['sharedDatabase']=shared_authority
        recoveries[boot]=recovery;write_runtime_maintenance(journal)
    elif not isinstance(recovery,dict)or recovery.get('version')!=1 or recovery.get('bootId')!=boot or recovery.get('token')!=policy['token']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    attempts=runtime_boot_dump_materials(journal,recovery);receipt=runtime_boot_service_recovery(journal,recovery)
    pg_launches=recovery.get('databaseServiceRecoveryLaunches',[])
    if journal.get('database')is not None and pg_launches and 'native'in pg_launches[-1]and recovery.get('databaseServiceRecovery')is None:
        runtime_boot_database_start_records(journal,recovery)
        raise runtime_boot_database_resume_request(journal,recovery,pg_launches[-1])
    launch=runtime_boot_launch_for_backend(journal,recovery,current)if current is not None else None
    if current is not None and recovery.get('serviceRecoveryStart')is not None and launch is None:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    if launch is not None and (receipt is None or receipt['backend']!=current or receipt['launchHash']!=runtime_boot_record_hash(launch)):
        # Complete an independently recorded own launch before another drain.
        # Intent alone never attests an unrecorded same-configuration process.
        if'clientFailure'in launch['intent']:
            reason=launch['intent']['clientFailure']
            raise RuntimeBootClientValidationFailed(journal,recovery,reason['error'],client_failure=reason)
        if not attempts or attempts[-1]['state']not in ['failed','absent']or attempts[-1].get('failureCause')not in ['pg-dump','pg-restore']:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        raise RuntimeBootDumpExecutionFailed(journal,recovery)
    if recovery.get('dump')is not None:
        # A completed third dump resumes its original ordinal. Verify that
        # exact retained proof before any drain; no fourth dump is requested.
        runtime_new_boot_dump(journal,recovery)
        next_attempt=next(row['attempt']for row in attempts if row['state']=='complete')
    else:next_attempt=attempts[-1]['attempt']if attempts and attempts[-1]['state']=='intent'else len(attempts)+1
    if next_attempt>3:
        if all(row['state']in ['failed','absent']and row.get('failureCause')in ['pg-dump','pg-restore']for row in attempts):raise RuntimeBootDumpExecutionFailed(journal,recovery)
        raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    if current is not None:
        # Only the exact backend proved by our own recovery may be drained
        # again. The original backend and original drain evidence stay fixed.
        restored=receipt is not None and current==receipt['backend']
        if restored:
            retry=recovery.get('retryDrain')
            if retry is not None and retry['confirmed']and retry['backend']==current:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
            if retry is not None and retry['attempt']==next_attempt:
                if retry['backend']!=current or retry['confirmed']:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
            else:
                recovery['retryDrain']={'version':1,'bootId':boot,'token':policy['token'],'originHash':runtime_systemd_origin_hash(original),'attempt':next_attempt,
                    'attemptsHash':hashlib.sha256(json.dumps(attempts[:next_attempt-1],sort_keys=True,separators=(',',':')).encode()).hexdigest(),'backend':current,'confirmed':False}
                write_runtime_maintenance(journal)
        else:
            previous=recovery.get('backend')
            if previous is None and recovery.get('phase')=='prepared'and recovery.get('drainConfirmed')is not True:
                recovery['backend']=current;previous=current;write_runtime_maintenance(journal)
            if not isinstance(previous,dict)or any(current[key]!=previous[key]for key in ['pid','start','app','environmentHash','codeHash','serviceHash','unitHashes']):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
            if recovery.get('drainConfirmed')is True:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    state=dict(line.split('=',1)for line in command(['systemctl','show','incudal-backend.service','--property=MainPID,ActiveState,Result'],20).splitlines()if '='in line)
    if current is None and state.get('MainPID')!='0'or current is not None and state.get('MainPID')!=str(current['pid']):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    stop_issued=False
    if current is not None or state.get('ActiveState')not in ['inactive','failed']:
        stop_issued=True;recovery['phase']='stopping-backend';recovery['stopRequested']=True;write_runtime_maintenance(journal)
        command(['systemctl','stop','incudal-backend.service'],36*60)
    state=dict(line.split('=',1)for line in command(['systemctl','show','incudal-backend.service','--property=MainPID,ActiveState,Result'],20).splitlines()if '='in line)
    if not runtime_boot_drain_confirmed(journal,recovery,state,allow_start_failure=not stop_issued):raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
    retry=recovery.get('retryDrain')
    if receipt is not None:
        if retry is None or retry['attempt']>next_attempt or retry['attempt']<next_attempt and not retry['confirmed']:raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
        # A later dump may share the same proven quiescence after interruption;
        # retain the actual drained ordinal rather than replacing its evidence.
        retry['confirmed']=True
    recovery['drainConfirmed']=True;recovery['phase']='drained';write_runtime_maintenance(journal)
    shared=recovery.get('sharedDatabase')
    if shared is not None:
        fresh=database_runtime_proof(shared_read_only=True,journal=journal);verify_runtime_database_configuration(fresh,journal['sharedDatabase'])
        if any(fresh[key]!=shared[key]for key in ['pid','start']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        if shared_authority is None or any(shared[key]!=shared_authority[key]for key in ['pid','start']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        runtime_new_boot_dump(journal,recovery)
    elif journal.get('database') is not None:
        database=journal['database'];state=dict(line.split('=',1)for line in command(['systemctl','show',database['unit'],'--property=MainPID,ActiveState,Result'],20).splitlines()if '='in line)
        if state.get('MainPID')=='0'and state.get('ActiveState')in ['inactive','failed']and recovery.get('dump')is None:
            if recovery.get('database')is not None:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
            verify_runtime_database_files(database)
            attempts=recovery.get('databaseStartAttempts',0)
            if type(attempts)is not int or not 0<=attempts<2:raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
            recovery['databaseStartAttempts']=attempts+1;write_runtime_maintenance(journal)
            command(['systemctl','start',database['unit']],180)
            state=dict(line.split('=',1)for line in command(['systemctl','show',database['unit'],'--property=MainPID,ActiveState,Result'],20).splitlines()if '='in line)
        if state.get('ActiveState')=='active':
            fresh=database_runtime_proof(journal=journal);verify_runtime_database_configuration(fresh,database)
            recorded=recovery.get('database')
            if recorded is not None and any(fresh[key]!=recorded[key]for key in ['pid','start']):
                if not any(key in recovery for key in ['databaseServiceRecoveryStart','databaseServiceRecoveryLaunches','databaseServiceRecovery'])or runtime_boot_database_launch_for_current(journal,recovery,fresh)is None:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
            if recorded is None:
                if any(key in recovery for key in ['databaseServiceRecoveryStart','databaseServiceRecoveryLaunches','databaseServiceRecovery'])and runtime_boot_database_launch_for_current(journal,recovery,fresh)is None:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
                recovery['database']=fresh
            write_runtime_maintenance(journal);runtime_new_boot_dump(journal,recovery)
            recovery['phase']='stopping-database';write_runtime_maintenance(journal)
            record_runtime_boot_database_drain(journal,recovery,fresh)
            command(['systemctl','stop',database['unit']],180)
            state=dict(line.split('=',1)for line in command(['systemctl','show',database['unit'],'--property=MainPID,ActiveState,Result'],20).splitlines()if '='in line)
            if state.get('Result')!='success':raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
            record_runtime_boot_database_drain(journal,recovery,None,confirmed=True)
        if state.get('MainPID')!='0'or state.get('ActiveState')not in ['inactive','failed']:raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
    else:
        # backupDatabase is a read-only binding for Node-only maintenance.
        # It must never grant the authority to start/stop PostgreSQL that is
        # represented separately by journal.database.
        fresh=database_runtime_proof(shared_read_only=True,journal=journal);verify_runtime_database_configuration(fresh,backup_database)
        recorded=recovery.get('backupDatabaseProcess')
        if recorded is not None and (not isinstance(recorded,dict)or set(recorded)!={'pid','start'}or any(fresh[key]!=recorded.get(key)for key in ['pid','start'])):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        if recorded is None:
            recovery['backupDatabaseProcess']={key:fresh[key]for key in ['pid','start']};write_runtime_maintenance(journal)
        runtime_new_boot_dump(journal,recovery)
        confirmed=database_runtime_proof(shared_read_only=True,journal=journal);verify_runtime_database_configuration(confirmed,backup_database)
        if any(confirmed[key]!=fresh[key]for key in ['pid','start']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    if recovery.get('dump')is None or recovery.get('dumpPending')is not False:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    recovery['phase']='prepared';write_runtime_maintenance(journal);ensure_runtime_systemctl_policy(journal)
    return recovery

def runtime_package_command(args,journal,timeout):
    proof=runtime_active_systemd_policy(journal)
    if not proof:return command(args,timeout)
    verify_runtime_systemd_policy_packages(journal,archives=True)
    verify_runtime_payload(journal,archives=True)
    if proof.get('originHash'):confirm_runtime_boot_dump(journal,proof)
    ensure_runtime_systemctl_policy(journal)
    verify_runtime_systemd_qualification(proof,runtime_systemd_qualification(proof['programs']))
    root=runtime_systemctl_policy_directory(proof)
    if journal.get('phase')not in ['installing','installed']:
        if journal.get('phase')not in ['stopping-backend','stopping-database']or journal.get('drainConfirmed')is not True:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        # Persist installation intent only after all first-dispatch checks.
        # A preflight refusal must recover the original unmodified runtime.
        journal['phase']='installing';write_runtime_maintenance(journal)
    # Only this package process inherits the policy. The application's PATH,
    # installed systemctl, maintainer programs and configuration are intact.
    result=command(['/usr/bin/env','PATH='+str(root)+':/usr/sbin:/usr/bin:/sbin:/bin',*args],timeout)
    read_runtime_systemctl_policy(proof)
    return result

def finish_runtime_systemctl_policy(journal,applied=True,confirmation=None,selected=None):
    proof=runtime_active_systemd_policy(journal)if selected is None else selected
    if not proof:return
    if selected is not None and not any(item is proof for item in runtime_systemd_policy_lineage(journal)):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    if confirmation is not None:
        current=runtime_systemd_boot_confirmation(journal)
        if current is None or any(current.get(key)!=confirmation.get(key)for key in ['bootId','manager','journald','networkHash','libcFiles','policyHistoryHash']):raise ValueError('SYSTEM_SECURITY_SYSTEMD_BOOT_RECOVERY_PENDING')
    root=runtime_systemctl_policy_directory(proof)
    if proof.get('cleared'):
        if not runtime_path_present(root):return
        names={file.name for file in root.iterdir()}
        if not names<={'systemctl','policy.lock','policy.json'}:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        hashes=proof.get('cleanupHashes')
        if not isinstance(hashes,dict)or set(hashes)!={'systemctl','policy.lock','policy.json'}or hashes.get('systemctl')!=proof['sourceHash']or any(not isinstance(digest,str)or not re.fullmatch(r'[a-f0-9]{64}',digest)for digest in hashes.values()):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        value={'actions':proof.get('recordedActions',proof.get('deferredActions',[]))}
    elif not proof.get('ready')and confirmation is not None:
        prior=runtime_systemd_policy_history(proof)
        value={'actions':prior['actions'],'rejected':False}
        proof['cleanupHashes']={'systemctl':proof['sourceHash'],'policy.lock':hashlib.sha256(b'').hexdigest(),'policy.json':prior['receiptHash']}
    else:
        value=read_runtime_systemctl_policy(proof,allow_rejected=True)
        if {file.name for file in root.iterdir()}!={'systemctl','policy.lock','policy.json'}or protected_hash(root/'systemctl')!=proof['sourceHash']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    locks=[]
    try:
        for path in ['/var/lib/dpkg/lock','/var/lib/dpkg/lock-frontend']:
            if not runtime_path_present(pathlib.Path(path)):continue
            fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW);locks.append(fd)
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
            fcntl.lockf(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if value.get('rejected'):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_REJECTED')
        actions=value['actions']
        if proof.get('originHash')and confirmation is None:
            active=prepare_runtime_systemd_boot_policy(journal)
            if active is not proof:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
            actions=sorted(set(actions+proof['inheritedActions']))
        if not isinstance(actions,list)or any(not isinstance(action,str)for action in actions)or len(actions)!=len(set(actions))or not set(actions)<=set(RUNTIME_SYSTEMCTL_ACTIONS.values())or confirmation is None and set(actions)!=(set(RUNTIME_SYSTEMCTL_ACTIONS.values())if applied else set()):raise ValueError('SYSTEM_SECURITY_SYSTEMD_TRIGGER_NOT_CONFIRMED')
        if not proof.get('cleared')and proof.get('ready'):proof['cleanupHashes']={name:protected_hash(root/name,private=name!='systemctl')for name in ['systemctl','policy.lock','policy.json']}
        proof['recordedActions']=value['actions'];proof['deferredActions']=actions;proof['cleared']=True
        if confirmation is not None:proof['naturalBootId']=confirmation['bootId']
        write_runtime_maintenance(journal)
        for name in ['systemctl','policy.json','policy.lock']:
            if not runtime_path_present(root/name):continue
            digest=protected_hash(root/name,private=name!='systemctl')
            if digest!=proof['cleanupHashes'][name]:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
            (root/name).unlink()
        if runtime_path_present(root):root.rmdir()
        sync_runtime_evidence_directory(root.parent)
    except BlockingIOError:raise ValueError('SYSTEM_SECURITY_PACKAGE_OPERATION_PENDING')
    finally:
        for fd in locks:os.close(fd)

def verify_runtime_systemd_qualification(proof,current):
    before=proof.get('qualification',{})
    if any(current['manager'][key]!=before['manager'][key]for key in ['pid','start','binaryHash']):raise ValueError('SYSTEM_SECURITY_SYSTEMD_PROCESS_CHANGED')
    if any(current[key]!=before[key]for key in ['state','networkd','journaldUnit']):raise ValueError('SYSTEM_SECURITY_SYSTEMD_CONFIGURATION_CHANGED')

def activate_runtime_systemd(journal):
    proof=runtime_active_systemd_policy(journal)
    if not proof:return
    verify_runtime_systemd_policy_packages(journal)
    runtime_systemctl_policy_directory(proof)
    if proof.get('cleared')is not True or set(proof.get('deferredActions',[]))!=set(RUNTIME_SYSTEMCTL_ACTIONS.values())or proof.get('bootId')!=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip():raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    before=proof.get('qualification',{});current=runtime_systemd_qualification(proof['programs']);verify_runtime_systemd_qualification(proof,current)
    activation=proof.setdefault('activation',{})
    if current['manager']['replacedLibraries']:
        if activation.get('managerAttempts',0)>=2:raise ValueError('SYSTEM_SECURITY_SYSTEMD_ACTIVATION_PENDING')
        activation['managerAttempts']=activation.get('managerAttempts',0)+1;activation['manager']='intent';write_runtime_maintenance(journal)
        try:command(['systemctl','daemon-reexec'],90)
        except (ValueError,OSError):pass
        updated=runtime_systemd_process(1,'/usr/lib/systemd/systemd')
        if any(updated[key]!=before['manager'][key]for key in ['pid','start','binaryHash'])or updated['replacedLibraries']:
            raise ValueError('SYSTEM_SECURITY_SYSTEMD_ACTIVATION_PENDING')
    activation['manager']='activated';write_runtime_maintenance(journal)
    current=runtime_systemd_qualification(proof['programs']);verify_runtime_systemd_qualification(proof,current)
    if current['journald']['replacedLibraries']:
        if activation.get('journalAttempts',0)>=2:raise ValueError('SYSTEM_SECURITY_SYSTEMD_ACTIVATION_PENDING')
        activation['journalAttempts']=activation.get('journalAttempts',0)+1;activation['journald']='intent';write_runtime_maintenance(journal)
        try:command(['systemctl','try-restart','systemd-journald.service'],90)
        except (ValueError,OSError):pass
    current=runtime_systemd_qualification(proof['programs']);verify_runtime_systemd_qualification(proof,current)
    if current['manager']['replacedLibraries']or current['journald']['replacedLibraries']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_ACTIVATION_PENDING')
    activation['journald']='activated';activation['state']='activated';write_runtime_maintenance(journal)

def libc_security_series(version):
    if not isinstance(version,str):return None
    match=re.fullmatch(r'(?:[0-9]+:)?([0-9]+\.[0-9]+)(?:\.[0-9]+)?-[a-zA-Z0-9.+~_-]+',version)
    return match.group(1)if match else None

def validate_runtime_libc_plan(changes,installed):
    if not any(item.split('=',1)[0]in RUNTIME_DEBIAN_BASE_LIBRARIES for item in changes):return
    before=[installed.get(name)for name in sorted(RUNTIME_DEBIAN_BASE_LIBRARIES)]
    if before[0]!=before[1]or not libc_security_series(before[0]):raise ValueError('SYSTEM_SECURITY_LIBC_GROUP_UNREVIEWED')
    expected=dict(installed)
    for item in changes:
        name,version=item.split('=',1);expected[name]=version
    after=[expected.get(name)for name in sorted(RUNTIME_DEBIAN_BASE_LIBRARIES)]
    if after[0]!=after[1]or libc_security_series(after[0])!=libc_security_series(before[0]):raise ValueError('SYSTEM_SECURITY_LIBC_GROUP_UNREVIEWED')

def runtime_patch_needs_database(changes,database):
    scoped=any(item.split('=',1)[0].startswith('postgresql-')or item.split('=',1)[0]in ['libpq5','postgresql-common']for item in changes)
    if database is None or scoped and database.get('sharedReadOnly'):raise ValueError('SYSTEM_SECURITY_DATABASE_CHANGED')
    # Updating libc must load the new library in our sole PostgreSQL too.
    # A shared cluster remains alive and truthfully pending; its other users
    # are never included in our dumps or stopped by the application updater.
    return scoped or not database.get('sharedReadOnly')and any(item.split('=',1)[0]=='libc6'for item in changes)

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
        installed=debian_installed_packages()
        if system=='debian':names|={identity.split(':',1)[0]for identity in installed if re.fullmatch(r'linux-image-[a-z0-9.+-]{1,190}:[a-z0-9-]+',identity)}
        packages=reviewed_debian_inventory(installed,names)
        output=command(['apt-get','-o','DPkg::Lock::Timeout=5','--simulate','--only-upgrade','--no-remove','install',*sorted(packages)]) if packages else ''
        pending=[line for line in output.splitlines() if line.startswith('Inst ')]
    else:raise ValueError('SYSTEM_SECURITY_DISTRIBUTION_UNSUPPORTED')
    running_kernel=os.uname().release
    restart_required=pathlib.Path('/var/run/reboot-required').exists() or alpine_kernel_replaced(running_kernel,packages)
    value={'version':1,'checkedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'distribution':system,'release':release.get('VERSION_ID','').strip('"'),'runningKernel':running_kernel,'packages':packages,'pending':pending,'loadedCode':replaced_host_mappings(all_host=all_loaded_code),'restartRequired':restart_required,'policy':'same-distribution-signed-packages; no-major-upgrade; no-automatic-customer-reboot','unreleasedAdvisories':['OpenSSL-20261117: official release planned 2026-12-01; feature conditions require review']}
    if system=='debian':
        value['kernelActivation']=debian_kernel_activation(running_kernel,packages,running_build=os.uname().version)
        value['restartRequired']=restart_required or value['kernelActivation']['state']=='restart-required'
    return value

def debian_kernel_activation(running,packages,boot=pathlib.Path('/boot'),running_build=None):
    # Debian need not create /var/run/reboot-required after installing a new
    # kernel ABI. Follow only the installed meta package's exact image, never
    # an unrelated flavour or a lexical guess about which version is newest.
    # Ubuntu retains its existing reboot-required policy; its build metadata
    # must not be rejected for lacking Debian's package-revision marker.
    rejected={'state':'unreviewed','error':'SYSTEM_SECURITY_KERNEL_BOOT_UNREVIEWED'}
    if not isinstance(running,str)or not isinstance(packages,dict):return rejected
    match=re.fullmatch(r'[0-9][a-zA-Z0-9.+~-]{1,190}-(amd64|arm64|generic|generic-64k|virtual|aws|azure|gcp|oracle)',running)
    if not match:return rejected
    meta='linux-image-'+match.group(1)
    if meta not in packages:return rejected
    try:
        depends=command(['dpkg-query','-W','-f=${Depends}',meta],15)
        selected=re.fullmatch(r'\s*(linux-image-[0-9][a-zA-Z0-9.+~-]{1,190})\s*(?:\(=\s*([^\s()]+)\))?\s*',depends)
        if not selected:return rejected
        name,version=selected.groups();target=name.removeprefix('linux-image-')
        installed=packages.get(name)
        if not target.endswith('-'+match.group(1))or not isinstance(installed,str)or version is not None and installed!=version:return rejected
        info=(boot/('vmlinuz-'+target)).lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022 or not 0<info.st_size<=512*1024*1024:return rejected
        # The ABI basename may be retained for a Debian package revision. The
        # running build identifies that revision too; matching only uname -r
        # would call an older loaded kernel current after replacing its image.
        if target==running:
            build=running_build if running_build is not None else os.uname().version
            built=re.search(r'(?:^|\s)Debian ([^\s()]+)(?=\s|$)',build)if isinstance(build,str)and len(build)<=4096 else None
            if not built:return rejected
            current=built.group(1)==installed
        else:current=False
        return {'state':'current'if current else'restart-required','targetKernel':target,'packageVersion':installed}
    except (ValueError,OSError):return rejected

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
        if name in RUNTIME_DEBIAN_BASE_LIBRARIES and (not libc_security_series(old)or libc_security_series(old)!=libc_security_series(new)):raise ValueError('SYSTEM_SECURITY_PLAN_REJECTED')
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
                libc=[value['packages'].get(name)for name in sorted(RUNTIME_DEBIAN_BASE_LIBRARIES)]
                if libc[0]==libc[1]and libc_security_series(libc[0]):allowed|=RUNTIME_DEBIAN_BASE_LIBRARIES
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
        validate_runtime_libc_plan(changes,value['packages'])
        if not automatic and any(item.split('=',1)[0]in RUNTIME_DEBIAN_BASE_LIBRARIES for item in changes):raise ValueError('SYSTEM_SECURITY_LIBC_RUNTIME_PROOF_REQUIRED')
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
            runtime_plan=[item for item in changes if item.split('=',1)[0]=='nodejs' or item.split('=',1)[0].startswith('postgresql-')or item.split('=',1)[0]in ['libpq5','postgresql-common']or item.split('=',1)[0]in RUNTIME_DEBIAN_BASE_LIBRARIES]
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

def runtime_database_client_paths(major):
    if type(major)is not int or major not in [14,15,16,17,18]:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
    return {name:'/usr/lib/postgresql/'+str(major)+'/bin/'+name for name in ['psql','pg_dump','pg_restore']}

def runtime_database_client_files(major,names=('psql','pg_dump','pg_restore')):
    paths=runtime_database_client_paths(major);files={}
    try:
        for name in names:
            if name not in paths:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
            path=paths[name];parents=runtime_payload_parents(path);record=runtime_payload_regular(path,16*1024*1024)
            if record['size']<1 or record['mode']&0o7000 or record['mode']&0o111!=0o111:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
            for parent,before in parents:
                after=parent.lstat()
                if not os.path.samestat(before,after)or any(getattr(before,key)!=getattr(after,key)for key in ['st_mode','st_uid','st_gid']):raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
            files[path]=record
    except(OSError,ValueError):raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
    return {'version':1,'major':major,'files':files}

def validate_runtime_database_client_proof(proof,major):
    paths=runtime_database_client_paths(major)
    if not isinstance(proof,dict)or set(proof)!={'version','major','files'}or type(proof.get('version'))is not int or proof['version']!=1 or type(proof.get('major'))is not int or proof['major']!=major or not isinstance(proof.get('files'),dict)or set(proof['files'])!=set(paths.values()):raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
    try:
        for path,record in proof['files'].items():
            validate_runtime_payload_record(path,record,{})
            if record['type']!='file'or not 0<record['size']<=16*1024*1024 or record['mode']&0o7000 or record['mode']&0o111!=0o111:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
    except ValueError:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
    return paths

def runtime_database_payload_clients(journal,major,label):
    if label not in ['before','expected']:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
    if not journal.get('payloadEvidence'):return None
    value=read_runtime_payload(journal);baseline,expected,_,_=validated_runtime_package_plan(journal)
    names=runtime_database_client_paths(major);keys=[key for key in value['archives']if key.split(':')[0]=='postgresql-client-'+str(major)]
    if not keys:return None
    if len(keys)!=1:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
    key=keys[0];versions=value['archives'][key];record=versions.get(label);controls=versions.get(label+'Controls');file=versions.get(label+'File')
    selected=(baseline if label=='before'else expected).get(key)
    if not isinstance(record,dict)or record.get('package')!=key.split(':')[0]or record.get('architecture')!=key.split(':')[1]or record.get('version')!=selected or not isinstance(selected,str)or not re.match(r'^(?:[0-9]+:)?'+str(major)+r'\.',selected)or file!=label+'-'+key.split(':')[0]+'-'+key.split(':')[1]+'.deb':raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
    _,raw,actual_controls=runtime_cached_archive(journal,record,file)
    if not isinstance(controls,dict)or {part:hashlib.sha256(data).hexdigest()for part,data in actual_controls.items()}!=controls:raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
    payload=runtime_archive_payload(raw,value['layout']);files={}
    for path in names.values():
        entry=value['paths'].get(path)
        if not isinstance(entry,dict)or key not in entry.get('owners',[])or entry.get('conffile')is not False or entry.get(label)!=payload.get(path):raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
        files[path]=payload.get(path)
    proof={'version':1,'major':major,'files':files};validate_runtime_database_client_proof(proof,major)
    return proof

def runtime_backup_database_proof(database):
    if not isinstance(database,dict):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    # This binds the original local files and configuration. It does not grant
    # vendor authority or permission to stop a shared cluster.
    return {**database,'clientTools':runtime_database_client_files(database.get('major'))}

def runtime_database_legacy_baseline(journal):
    if not isinstance(journal,dict)or not isinstance(journal.get('dumpEvidence'),dict)or set(journal['dumpEvidence'])!={'database.dump','database-after-drain.dump'}:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    if journal.get('activationOnly')is True:
        baseline=journal.get('baselinePackages')
        if journal.get('packages')!=[]or not isinstance(baseline,dict)or not baseline or len(baseline)>20000 or baseline!=journal.get('expectedPackages')or any(not re.fullmatch(r'[a-z0-9+.-]+:[a-z0-9-]+',key)or not isinstance(version,str)or not re.fullmatch(r'[^\s=\x00-\x1f]{1,200}',version)for key,version in baseline.items()):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
        return baseline
    return validated_runtime_package_plan(journal)[0]

def runtime_database_legacy_client_baseline(journal,major):
    runtime_database_client_paths(major)
    if not isinstance(journal,dict)or 'backupDatabase'in journal:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    baseline=runtime_database_legacy_baseline(journal);versions=runtime_original_dump_versions(journal);client_major=versions['clientMajor']
    # Old pg_wrapper legitimately selected the installed PG18 client for a
    # PG16 main cluster. This exception is derived from both original dumps
    # and the complete Before package baseline, never a new journal field.
    if versions['major']!=major or client_major!=major and (major,client_major)!=(16,18):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    keys={}
    for name,field in [('postgresql-'+str(major),'server'),('postgresql-client-'+str(client_major),'client')]:
        matches=[key for key in baseline if key.split(':')[0]==name and key.split(':')[1]in ['amd64','arm64']]
        if len(matches)!=1:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
        key=matches[0];upstream=re.fullmatch(r'(?:[0-9]+:)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)-[^\s=\x00-\x1f]{1,200}',baseline[key])
        if upstream is None or upstream[1]!=versions[field]:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
        keys[field]=key
    if keys['server'].split(':')[1]!=keys['client'].split(':')[1]:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    return client_major,keys['client'],baseline[keys['client']]

def runtime_database_legacy_before_clients(journal,major):
    client_major,key,version=runtime_database_legacy_client_baseline(journal,major);paths=runtime_database_client_paths(client_major)
    proof=runtime_database_payload_clients(journal,client_major,'before')
    if proof is not None:
        validate_runtime_database_client_proof(proof,client_major);return proof
    name,architecture=key.split(':')
    # Exact already authenticated local Before cache only. A missing index or
    # cache is not permission to download, use a candidate, or re-sign a receipt.
    try:record,raw,_=authenticated_debian_archive(name,version,architecture,before=True)
    except(ValueError,OSError):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    if record.get('package')!=name or record.get('version')!=version or record.get('architecture')!=architecture or record.get('size')!=len(raw)or record.get('sha256')!=hashlib.sha256(raw).hexdigest():raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    payload=runtime_archive_payload(raw,runtime_payload_layout());proof={'version':1,'major':client_major,'files':{path:payload.get(path)for path in paths.values()}}
    validate_runtime_database_client_proof(proof,client_major);return proof

def verify_runtime_database_clients(database,journal=None):
    if not isinstance(database,dict):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    major=database.get('major');runtime_database_client_paths(major);proof=database.get('clientTools');client_major=major;legacy_before=None
    if proof is None or isinstance(proof,dict)and proof.get('major')!=major:
        # Legacy receipts are never filled in or re-signed from current files.
        # Only their authenticated exact original Before material can supply
        # the missing client identity.
        if journal is None:raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
        legacy_before=runtime_database_legacy_before_clients(journal,major);client_major=legacy_before['major']
        if proof is None:proof=legacy_before
        elif proof!=legacy_before:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
    paths=validate_runtime_database_client_proof(proof,client_major);current=runtime_database_client_files(client_major);validate_runtime_database_client_proof(current,client_major)
    if current==proof:return paths,current
    if journal is None or journal.get('phase')not in ['installing','installed']:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
    before=legacy_before if legacy_before is not None else runtime_database_payload_clients(journal,client_major,'before');expected=runtime_database_payload_clients(journal,client_major,'expected')
    if before!=proof or expected is None or any(current['files'][path]not in [proof['files'][path],expected['files'][path]]for path in paths.values()):raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
    return paths,current

def verify_runtime_database_psql(journal,major):
    # Recovery may need SQL while pg_dump/pg_restore is unavailable. Execute
    # only the individually bound psql, never adopt its current hash as trust.
    runtime_database_client_paths(major)
    database=journal['backupDatabase']if 'backupDatabase'in journal else journal.get('database')or journal.get('sharedDatabase')
    if database is not None and (not isinstance(database,dict)or database.get('major')!=major):raise ValueError('SYSTEM_SECURITY_DATABASE_BACKUP_PROOF_MISSING')
    proof=database.get('clientTools')if isinstance(database,dict)else None;client_major=major;legacy_before=None
    if proof is None or isinstance(proof,dict)and proof.get('major')!=major:
        legacy_before=runtime_database_legacy_before_clients(journal,major);client_major=legacy_before['major']
        if proof is None:proof=legacy_before
        elif proof!=legacy_before:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
    paths=validate_runtime_database_client_proof(proof,client_major);psql=paths['psql'];current=runtime_database_client_files(client_major,('psql',))
    if current.get('major')!=client_major or set(current.get('files',{}))!={psql}:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_UNCONFIRMED')
    if current['files'][psql]==proof['files'][psql]:return psql,current
    if journal.get('phase')not in ['installing','installed']:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
    before=legacy_before if legacy_before is not None else runtime_database_payload_clients(journal,client_major,'before');expected=runtime_database_payload_clients(journal,client_major,'expected')
    if before!=proof or expected is None or current['files'][psql]!=expected['files'].get(psql):raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
    validate_runtime_database_client_proof(expected,client_major)
    return psql,current

def database_runtime_proof(shared_read_only=False,journal=None):
    clusters=json.loads(command(['pg_lsclusters','--json'],20))
    if not isinstance(clusters,list)or any(not isinstance(row,dict)or type(row.get('running'))is not int or row['running']not in [0,1]for row in clusters):raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    running=[row for row in clusters if row['running']==1]
    if len(running)>1:raise ValueError('SYSTEM_SECURITY_DATABASE_MULTIPLE_CLUSTERS')
    if not running or running[0].get('version')not in [str(major)for major in [14,15,16,17,18]]or running[0].get('cluster')!='main'or str(running[0].get('port'))!='5432':raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    selected=int(running[0]['version'])
    if journal is None:client=runtime_database_client_files(selected,('psql',));psql=runtime_database_client_paths(selected)['psql']
    else:psql,client=verify_runtime_database_psql(journal,selected)
    def query(sql,strict=False):
        if journal is not None and verify_runtime_database_psql(journal,selected)!=(psql,client):raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
        args=['runuser','-u','postgres','--',psql,'-X','-At',*(['-v','ON_ERROR_STOP=1']if strict else[]),'-d','incudal','-c',sql]
        data=command(args,20)
        if journal is not None and runtime_database_client_files(client['major'],('psql',))!=client:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
        return data
    sql="SELECT json_build_object('major',current_setting('server_version_num')::int/10000,'version',current_setting('server_version_num'),'data',current_setting('data_directory'),'config',current_setting('config_file'),'hba',current_setting('hba_file'),'recovery',pg_is_in_recovery(),'replication',(SELECT count(*) FROM pg_stat_replication),'otherDatabases',(SELECT count(*)FROM pg_database WHERE NOT datistemplate AND datname NOT IN('incudal','postgres')),'otherClients',(SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend'AND pid<>pg_backend_pid()AND(coalesce(datname,'')<>'incudal'OR usename NOT IN('incudal','incudal_migrate'))))"
    value=json.loads(query(sql,strict=True))
    environment=pathlib.Path('/opt/incudal/.env').read_text()
    matches=re.findall(r'^DATABASE_URL=(.+)$',environment,re.M)
    if len(matches)!=1 or not re.fullmatch(r"['\"]?postgres(?:ql)?://incudal:[^\s]+@(?:127\.0\.0\.1|localhost):5432/incudal(?:\?[^'\"\s]*)?['\"]?",matches[0]):raise ValueError('SYSTEM_SECURITY_DATABASE_IDENTITY_UNREVIEWED')
    if value['recovery']or value['replication']or value['major']not in [14,15,16,17,18]or not shared_read_only and (value['otherDatabases']or value['otherClients']):raise ValueError('SYSTEM_SECURITY_DATABASE_SHARED_OR_REPLICATED')
    if shared_read_only:value['sharedReadOnly']=True
    major=value['major'];expected='/var/lib/postgresql/'+str(major)+'/main'
    if type(major)is not int or major!=selected:raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    if value['data']!=expected or value['config']!='/etc/postgresql/'+str(major)+'/main/postgresql.conf'or value['hba']!='/etc/postgresql/'+str(major)+'/main/pg_hba.conf':raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    value['configHash']=protected_hash(value['config'],(0,pathlib.Path(expected).stat().st_uid));value['hbaHash']=protected_hash(value['hba'],(0,pathlib.Path(expected).stat().st_uid))
    value['unit']='postgresql@'+str(major)+'-main.service'
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
    settings=json.loads(query("SELECT json_build_object('settings',(SELECT json_agg(json_build_array(name,setting,source,context)ORDER BY name)FROM pg_settings WHERE name NOT IN ('server_version','server_version_num')),'files',(SELECT json_agg(DISTINCT sourcefile)FROM pg_file_settings),'invalid',(SELECT count(*)FROM pg_file_settings WHERE error IS NOT NULL),'pending',(SELECT count(*)FROM pg_settings WHERE pending_restart))"))
    if settings['invalid']or not isinstance(settings['files'],list)or len(settings['files'])>64:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
    if settings['pending']:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_RESTART_REQUIRED')
    value['settingsHash'],value['settingsLegacyHash']=database_settings_hashes(settings['settings']);value['settingsHashVersion']=2
    paths=set(settings['files'])|{expected+'/postgresql.auto.conf','/etc/postgresql/'+str(major)+'/main/pg_ctl.conf','/etc/postgresql/'+str(major)+'/main/start.conf'}
    if any(not isinstance(path,str)or not(path.startswith('/etc/postgresql/'+str(major)+'/main/')or path==expected+'/postgresql.auto.conf')for path in paths):raise ValueError('SYSTEM_SECURITY_DATABASE_CLUSTER_UNREVIEWED')
    value['fileHashes']={path:protected_hash(path,(0,pathlib.Path(expected).stat().st_uid))for path in sorted(paths)}
    if runtime_database_client_files(client['major'],('psql',))!=client:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
    return value

def activate_runtime_libraries(backend,database,value):
    def replaced(pid,program):
        installed=pathlib.Path(program).stat();running=pathlib.Path('/proc',str(pid),'exe').stat()
        return (installed.st_dev,installed.st_ino)!=(running.st_dev,running.st_ino)or runtime_process_has_replaced_libraries(pid)
    need_backend=replaced(backend['pid'],'/usr/bin/node')
    need_database=not database.get('sharedReadOnly')and replaced(database['pid'],'/usr/lib/postgresql/'+str(database['major'])+'/bin/postgres')
    if not need_backend and not need_database:return
    if backend_runtime_proof()!=backend:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    journal=None
    def database_proof():
        if journal is not None:return database_runtime_proof(shared_read_only=bool(database.get('sharedReadOnly')),journal=journal)
        return database_runtime_proof(shared_read_only=True)if database.get('sharedReadOnly')else database_runtime_proof()
    if database_proof()!=database:raise ValueError('SYSTEM_SECURITY_DATABASE_CHANGED')
    if command(['dpkg','--audit'],30):raise ValueError('SYSTEM_SECURITY_PACKAGE_CONFIGURATION_PENDING')
    baseline=debian_installed_packages()
    backup_database=runtime_backup_database_proof(database)
    backup=pathlib.Path('/var/lib/incudal-system-security')/('runtime-backup-'+uuid.uuid4().hex);backup.mkdir(mode=0o700)
    clients,_=verify_runtime_database_clients(backup_database)
    size=int(command(['runuser','-u','postgres','--',clients['psql'],'-X','-At','-d','incudal','-c',"SELECT pg_database_size('incudal')"],20))
    filesystem=os.statvfs(backup)
    if size<0 or filesystem.f_bavail*filesystem.f_frsize<max(size*3,128*1024*1024):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_SPACE_REQUIRED')
    dump_runtime_database(backup/'database.dump',backup_database)
    verify_runtime_financial_integrity(backend['app'])
    if backend_runtime_proof()!=backend or database_proof()!=database or debian_installed_packages()!=baseline:raise ValueError('SYSTEM_SECURITY_RUNTIME_BASELINE_CHANGED')
    journal={'version':1,'phase':'prepared','activationOnly':True,'backend':backend,'database':database if need_database else None,'backupDatabase':backup_database,'bootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'backup':backup.name,'packages':[],'baselinePackages':baseline,'expectedPackages':baseline,
        'dumpEvidence':{'database.dump':runtime_dump_evidence(backup/'database.dump')}}
    if database.get('sharedReadOnly'):journal['sharedDatabase']=database
    write_runtime_maintenance(journal)
    stopped=False
    try:
        journal['phase']='stopping-backend';write_runtime_maintenance(journal);stopped=True
        command(['systemctl','stop','incudal-backend.service'],36*60)
        if command(['systemctl','show','incudal-backend.service','--property=MainPID','--value'],20)!='0':raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_PENDING')
        if command(['systemctl','show','incudal-backend.service','--property=Result','--value'],20)!='success':raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
        journal['drainConfirmed']=True;write_runtime_maintenance(journal)
        dump_runtime_database(backup/'database-after-drain.dump',backup_database)
        journal['dumpEvidence']['database-after-drain.dump']=runtime_dump_evidence(backup/'database-after-drain.dump');write_runtime_maintenance(journal)
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
    need_database=runtime_patch_needs_database(changes,database)
    journal=None
    def database_proof():
        if journal is not None:return database_runtime_proof(shared_read_only=bool(database.get('sharedReadOnly')),journal=journal)
        return database_runtime_proof(shared_read_only=True)if database.get('sharedReadOnly')else database_runtime_proof()
    if database_proof()!=database:raise ValueError('SYSTEM_SECURITY_DATABASE_CHANGED')
    if command(['dpkg','--audit'],30):raise ValueError('SYSTEM_SECURITY_PACKAGE_CONFIGURATION_PENDING')
    baseline=debian_installed_packages()
    validate_runtime_libc_plan(changes,reviewed_debian_inventory(baseline,RUNTIME_DEBIAN_BASE_LIBRARIES))
    # Acquire authenticated exact archives while the existing backend is live.
    # Repository/network failures must not leave it stopped awaiting download.
    command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','--download-only','--assume-yes','--only-upgrade','--no-remove','install',*changes],600)
    backup_database=runtime_backup_database_proof(database)
    systemd_policy=prepare_runtime_systemd_policy(changes,baseline)
    backup=pathlib.Path('/var/lib/incudal-system-security')/('runtime-backup-'+uuid.uuid4().hex);backup.mkdir(mode=0o700)
    client_change=any(item.split('=',1)[0]=='postgresql-client-'+str(database['major'])for item in changes)
    payload=prepare_runtime_payload(changes,baseline,expected,backup,systemd_policy)if systemd_policy or client_change else None
    journal={'version':1,'phase':'prepared','backend':backend,'database':database if need_database else None,'backupDatabase':backup_database,'bootId':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'backup':backup.name,'packages':changes,'expectedPackages':expected,'baselinePackages':baseline}
    if database.get('sharedReadOnly'):journal['sharedDatabase']=database
    if systemd_policy:journal['systemdPolicy']=systemd_policy
    if payload:journal['payloadEvidence']=payload
    verify_runtime_node_authority(journal,current=backend,require='before')
    clients,_=verify_runtime_database_clients(backup_database)
    size=int(command(['runuser','-u','postgres','--',clients['psql'],'-X','-At','-d','incudal','-c',"SELECT pg_database_size('incudal')"],20))
    filesystem=os.statvfs(backup)
    if size<0 or filesystem.f_bavail*filesystem.f_frsize<max(size*3,128*1024*1024):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_SPACE_REQUIRED')
    dump_runtime_database(backup/'database.dump',backup_database)
    journal['dumpEvidence']={'database.dump':runtime_dump_evidence(backup/'database.dump')}
    originals={key:protected_hash(key,private=False)for key in ['/opt/incudal/.env',backend['app']+'/server/dist/app.js',*backend['unitHashes']]}
    verify_runtime_financial_integrity(backend['app'])
    if backend_runtime_proof()!=backend or database_proof()!=database or debian_installed_packages()!=baseline:raise ValueError('SYSTEM_SECURITY_RUNTIME_BASELINE_CHANGED')
    stopped=False
    write_runtime_maintenance(journal)
    ensure_runtime_systemctl_policy(journal)
    try:
        journal['phase']='stopping-backend';write_runtime_maintenance(journal);stopped=True
        command(['systemctl','stop','incudal-backend.service'],36*60)
        if command(['systemctl','show','incudal-backend.service','--property=MainPID','--value'],20)!='0':raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_PENDING')
        if command(['systemctl','show','incudal-backend.service','--property=Result','--value'],20)!='success':raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
        journal['drainConfirmed']=True;write_runtime_maintenance(journal)
        if any(protected_hash(key)!=digest for key,digest in originals.items()):raise ValueError('SYSTEM_SECURITY_BACKEND_CONFIGURATION_CHANGED')
        dump_runtime_database(backup/'database-after-drain.dump',backup_database)
        journal['dumpEvidence']['database-after-drain.dump']=runtime_dump_evidence(backup/'database-after-drain.dump');write_runtime_maintenance(journal)
        if payload:verify_runtime_payload(journal,require='before')
        if systemd_policy and runtime_systemd_qualification(systemd_policy['programs'])!=systemd_policy['qualification']:raise ValueError('SYSTEM_SECURITY_SYSTEMD_BASELINE_CHANGED')
        if need_database:
            if database_runtime_proof(journal=journal)!=database:raise ValueError('SYSTEM_SECURITY_DATABASE_CHANGED')
            journal['phase']='stopping-database';write_runtime_maintenance(journal)
            command(['systemctl','stop',database['unit']],180)
            state=dict(line.split('=',1)for line in command(['systemctl','show',database['unit'],'--property=MainPID,ActiveState,Result'],20).splitlines()if '='in line)
            if state.get('MainPID')!='0'or state.get('ActiveState')!='inactive'or state.get('Result')!='success':raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_UNCONFIRMED')
        value['backendActivation']={'state':'draining','backup':backup.name};persist(value)
        if not systemd_policy:journal['phase']='installing';write_runtime_maintenance(journal)
        prepare_service_policy()
        package_args=runtime_original_expected_arguments(journal,changes)if payload else changes
        try:runtime_package_command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','-o','Dpkg::Options::=--force-confold','--assume-yes','--only-upgrade','--no-remove','--no-download','install',*package_args],journal,600)
        finally:clean_service_policy()
        if command(['dpkg','--audit'],30)or debian_installed_packages()!=expected:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')
        if payload:
            restore_runtime_conffiles(journal);verify_runtime_payload(journal,require='expected')
        journal['phase']='installed';write_runtime_maintenance(journal)
    finally:
        if stopped:recover_runtime_maintenance()
    current=backend_runtime_proof()
    if current is None or any(current[k]!=backend[k]for k in ['app','environmentHash','codeHash','serviceHash','unitHashes']):raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    installed=pathlib.Path('/usr/bin/node').stat();running=pathlib.Path('/proc',str(current['pid']),'exe').stat()
    if (installed.st_dev,installed.st_ino)!=(running.st_dev,running.st_ino):raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    verify_runtime_process_libraries(current['pid'],'SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    if need_database:
        current_db=database_runtime_proof(journal=journal)
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

def restore_runtime_backup_failure(journal,path,error,boot_dump=None):
    # A missing/changed dump client may block further maintenance, but does
    # not authorize another install or leaving proven services stopped. Keep
    # every original dump/policy and validate current code before any start.
    verify_runtime_original_dumps(journal)
    if journal.get('activationOnly'):
        baseline=journal['baselinePackages'];expected=baseline
        if debian_installed_packages()!=baseline:raise ValueError('SYSTEM_SECURITY_RUNTIME_BASELINE_CHANGED')
    else:baseline,expected,_,planned=validated_runtime_package_plan(journal)
    states=debian_package_states();current={key:record['version']for key,record in states.items()}
    if current.keys()!=baseline.keys()or any(current[key]not in [baseline[key],expected[key]]for key in baseline):raise ValueError('SYSTEM_SECURITY_RUNTIME_PACKAGE_BASELINE_CHANGED')
    installed=journal.get('phase')in ['installing','installed']
    if journal.get('payloadEvidence'):
        verify_runtime_payload(journal,require='mixed'if installed else'before',archives=True)
        verify_runtime_node_authority(journal,require='mixed'if installed else'before')
    elif current!=baseline or any(record['status']!='installed'for record in states.values()):raise ValueError('SYSTEM_SECURITY_RUNTIME_PACKAGE_BASELINE_CHANGED')
    if not journal.get('activationOnly')and any(record['status']!='installed'and key.split(':')[0]not in planned and not(key.split(':')[0]=='systemd'and journal.get('systemdPolicy')and record['status']in ['triggers-awaited','triggers-pending'])for key,record in states.items()):raise ValueError('SYSTEM_SECURITY_RUNTIME_PACKAGE_BASELINE_CHANGED')
    backend=journal['backend'];database=journal.get('database');shared=journal.get('sharedDatabase')
    boot_recovery=None;boot_context=None;pre_backend=None;boot_launch=None
    if boot_dump is not None:
        if not isinstance(boot_dump,(RuntimeBootDumpExecutionFailed,RuntimeBootClientValidationFailed)):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        client_failure=isinstance(boot_dump,RuntimeBootClientValidationFailed)
        boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();lineage=runtime_systemd_policy_lineage(journal)
        boot_recovery=journal.get('bootRecoveries',{}).get(boot)
        if not isinstance(boot_recovery,dict)or boot_recovery.get('version')!=1 or boot_recovery.get('bootId')!=boot or boot_recovery.get('drainConfirmed')is not True or type(boot_recovery.get('dumpPending'))is not bool or not client_failure and boot_recovery['dumpPending']is not True or boot_dump.boot_id!=boot or boot_dump.token!=boot_recovery.get('token')or boot_dump.origin_hash!=runtime_systemd_origin_hash(journal['systemdPolicy'])or not any(row['bootId']==boot and row['token']==boot_dump.token for row in lineage[1:]):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        attempts=runtime_boot_dump_materials(journal,boot_recovery)
        if client_failure:
            prefix=runtime_boot_client_failure_materials(journal,boot_recovery,boot_dump.client_failure,attempts)
            if boot_dump.attempt_count!=len(prefix):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        else:
            prefix=attempts
            if boot_dump.attempt_count!=len(attempts)or not attempts or attempts[-1]['state']not in ['failed','absent']or attempts[-1].get('failureCause')not in ['pg-dump','pg-restore']:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        receipt=runtime_boot_service_recovery(journal,boot_recovery)
        for policy in lineage:runtime_systemd_policy_history(policy)
        _,app_path,units,service_hash=backend_service_policy()
        if str(app_path)!=backend['app']or units!=backend['unitHashes']or service_hash!=backend['serviceHash']or protected_hash('/opt/incudal/.env')!=backend['environmentHash']or protected_hash(pathlib.Path(backend['app'])/'server/dist/app.js')!=backend['codeHash']:raise ValueError('SYSTEM_SECURITY_BACKEND_CONFIGURATION_CHANGED')
        pre_backend=backend_runtime_proof()
        if pre_backend is not None:
            boot_launch=runtime_boot_launch_for_backend(journal,boot_recovery,pre_backend)
            if boot_launch is None:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        else:
            state=dict(line.split('=',1)for line in command(['systemctl','show','incudal-backend.service','--property=MainPID,ActiveState,Result'],20).splitlines()if '='in line)
            if not runtime_boot_drain_confirmed(journal,boot_recovery,state):raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
        if database is not None:restore_runtime_boot_owned_database(journal,boot_recovery,path,failure=boot_dump)
        verify_runtime_boot_dump_database(journal,boot_recovery)
        verify_runtime_financial_integrity(backend['app'])
        boot_context={'version':1,'bootId':boot,'token':boot_dump.token,'originHash':boot_dump.origin_hash,'attemptCount':len(prefix),'attemptsHash':runtime_boot_record_hash(prefix)}
        if client_failure:boot_context['clientFailure']=boot_dump.client_failure
        if boot_launch is not None:
            # A later refusal never rewrites what authorized the actual launch.
            boot_context={key:value for key,value in boot_launch['intent'].items()if key not in ['startAttempts','beforeExecution']}
        if pre_backend is None:
            intent,_=runtime_boot_start_records(journal,boot_recovery,attempts);count=intent['startAttempts']if intent is not None else 0
            if count>=3:raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
            before_execution=runtime_boot_backend_execution()
            if before_execution['pid']!=0 or before_execution['active']not in ['inactive','failed']:raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
            boot_recovery['serviceRecoveryStart']={**boot_context,'startAttempts':count+1,'beforeExecution':before_execution};write_runtime_maintenance(journal,path.parent)
    if boot_dump is None:
        if database is not None:
            verify_runtime_database_files(database)
            state=dict(line.split('=',1)for line in command(['systemctl','show',database['unit'],'--property=MainPID,ActiveState,Result'],20).splitlines()if '='in line)
            if state.get('ActiveState')!='active':command(['systemctl','start',database['unit']],180)
        elif shared is not None:verify_runtime_database_files(shared,backup_only=True)
    current_backend=backend_runtime_proof()
    if boot_dump is not None and current_backend is not None and (pre_backend is None or current_backend!=pre_backend):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    if current_backend is None:
        if boot_dump is None:command(['systemctl','start','incudal-backend.service'],11*60)
        else:
            try:command(['systemctl','start','incudal-backend.service'],11*60)
            except(ValueError,OSError):pass # Observe a lost start reply; never assume success.
            current_backend=backend_runtime_proof()
            boot_launch=record_runtime_boot_backend_launch(journal,boot_recovery,path,current_backend)
            if current_backend is None:raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    elif any(current_backend[key]!=backend.get(key)for key in ['app','environmentHash','codeHash','unitHashes','serviceHash']):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    verify_runtime_health();current_backend=backend_runtime_proof()
    if current_backend is None or any(current_backend[key]!=backend.get(key)for key in ['app','environmentHash','codeHash','unitHashes','serviceHash']):raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    if boot_dump is not None and (boot_launch is None or current_backend!=boot_launch['backend']or runtime_boot_backend_execution()!=boot_launch['execution']):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
    installed_node=pathlib.Path('/usr/bin/node').stat();running_node=pathlib.Path('/proc',str(current_backend['pid']),'exe').stat()
    if not os.path.samestat(installed_node,running_node):raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    verify_runtime_process_libraries(current_backend['pid'],'SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    if database is not None or shared is not None:
        bound=database if database is not None else shared
        state=dict(line.split('=',1)for line in command(['systemctl','show',bound['unit'],'--property=MainPID,ActiveState,Result'],20).splitlines()if '='in line)
        if state.get('ActiveState')!='active'or not state.get('MainPID','').isdecimal()or int(state['MainPID'])<2:raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        process=pathlib.Path('/proc',state['MainPID'])
        if str((process/'exe').readlink()).removesuffix(' (deleted)')!='/usr/lib/postgresql/'+str(bound['major'])+'/bin/postgres'or (process/'ns/pid').readlink()!=pathlib.Path('/proc/1/ns/pid').readlink():raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        start=(process/'stat').read_text().split(') ',1)[1].split()[19]
        boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        original_boot=journal.get('systemdPolicy',{}).get('bootId',journal.get('bootId'))
        prior=journal.get('bootSharedDatabases',{}).get(boot,{}).get('proof')if shared is not None and boot!=original_boot else shared
        if shared is not None and prior is not None and (int(state['MainPID'])!=prior.get('pid')or start!=prior.get('start')):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
    verify_runtime_financial_integrity(backend['app']);verify_runtime_original_dumps(journal)
    if boot_dump is not None:
        verify_runtime_boot_dump_database(journal,boot_recovery)
        if backend_runtime_proof()!=current_backend:raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        runtime_boot_dump_materials(journal,boot_recovery)
        if runtime_boot_backend_execution()!=boot_launch['execution']or any(boot_launch['intent'].get(key)!=value for key,value in boot_context.items()):raise ValueError('SYSTEM_SECURITY_BACKEND_PROCESS_CHANGED')
        boot_recovery['serviceRecovery']={**boot_context,'backend':current_backend,'launchHash':runtime_boot_record_hash(boot_launch)}
    journal['backupRecovery']={'error':error,'backendPID':current_backend['pid'],'checkedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
    write_runtime_maintenance(journal,path.parent)
    raise ValueError(error)

def recover_runtime_maintenance(path=pathlib.Path('/var/lib/incudal-system-security/runtime-maintenance.json')):
    if not runtime_path_present(path):return
    protected_hash(path,private=True);journal=json.loads(path.read_text())
    if journal.get('version')!=1 or journal.get('phase')not in ['prepared','stopping-backend','stopping-database','installing','installed','activated','aborted']:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    activation_only=journal.get('activationOnly',False)
    if not isinstance(activation_only,bool):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    if activation_only:
        baseline=journal.get('baselinePackages')
        if journal.get('packages')!=[]or not isinstance(baseline,dict)or not baseline or len(baseline)>20000 or baseline!=journal.get('expectedPackages')or journal['phase']in ['installing','installed']:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        if any(not re.fullmatch(r'[a-z0-9+.-]+:[a-z0-9-]+',key)or not isinstance(version,str)or not re.fullmatch(r'[^\s=\x00-\x1f]{1,200}',version)for key,version in baseline.items()):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    if journal['phase']in ['prepared','activated','aborted']:
        if journal['phase']=='activated':
            name=journal.get('backup')
            if not isinstance(name,str)or not re.fullmatch(r'runtime-backup-[a-f0-9]{32}',name):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
            completed=path.parent/name/'completed.json'
            if runtime_path_present(completed):
                runtime_backup_evidence(completed.parent,journal)
                protected_hash(completed,private=True)
                if json.loads(completed.read_text())!=journal:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
                return
            # A power loss after the activated journal rename can precede its
            # completion receipt. Resume evidence publication, without any
            # service start/stop or package command.
            archive_runtime_receipt(journal,path.parent);return
        if journal.get('systemdPolicy'):
            if journal['phase']=='prepared':ensure_runtime_systemctl_policy(journal)
            finish_runtime_systemctl_policy(journal,applied=journal['phase']=='activated')
            if journal['phase']=='prepared':journal['phase']='aborted';write_runtime_maintenance(journal,path.parent)
        return
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
    clean_service_policy()
    installation_started=journal['phase']in ['installing','installed']
    if database is not None:verify_runtime_database_files(database)
    try:boot_recovery=prepare_runtime_boot_recovery(journal)if journal.get('systemdPolicy')else None
    except(RuntimeBootDumpExecutionFailed,RuntimeBootClientValidationFailed)as error:
        restore_runtime_backup_failure(journal,path,str(error),boot_dump=error)
    except ValueError as error:
        if str(error)not in BOOT_CLIENT_FAILURE_CODES:raise
        request=runtime_boot_client_recovery_request(journal,str(error))
        restore_runtime_backup_failure(journal,path,str(error),boot_dump=request)
    boot_confirmation=boot_recovery.get('confirmation')if boot_recovery else None
    if boot_recovery is None and not journal.get('drainConfirmed')and command(['systemctl','show','incudal-backend.service','--property=Result','--value'],20)!='success':raise ValueError('SYSTEM_SECURITY_BACKEND_DRAIN_UNCONFIRMED')
    if boot_recovery and boot_recovery.get('unstarted'):installation_started=False
    elif installation_started and not boot_confirmation and boot_recovery is None and runtime_package_transaction_unstarted(journal):installation_started=False
    if installation_started and not boot_confirmation:complete_runtime_package_transaction(journal)
    elif command(['dpkg','--audit'],30):raise ValueError('SYSTEM_SECURITY_PACKAGE_CONFIGURATION_PENDING')
    if installation_started and boot_recovery and not boot_confirmation:
        try:boot_confirmation=runtime_systemd_boot_confirmation(journal)
        except ValueError as error:
            if str(error)not in ['SYSTEM_SECURITY_SYSTEMD_ACTIVATION_PENDING','SYSTEM_SECURITY_LIBC_PAYLOAD_UNCONFIRMED']:raise
    if not installation_started and not activation_only:
        original,_,_,_=validated_runtime_package_plan(journal)
        if debian_installed_packages()!=original:raise ValueError('SYSTEM_SECURITY_RUNTIME_PACKAGE_BASELINE_CHANGED')
        if journal.get('systemdPolicy'):verify_runtime_payload(journal,require='before')
    if activation_only and debian_installed_packages()!=baseline:raise ValueError('SYSTEM_SECURITY_RUNTIME_BASELINE_CHANGED')
    if journal.get('payloadEvidence'):
        verify_runtime_payload(journal,require='expected'if installation_started else'before')
        verify_runtime_node_authority(journal,require='expected'if installation_started else'before')
    systemd_error=None
    if installation_started and journal.get('systemdPolicy')and not boot_confirmation:
        # Original package and maintainer authority must still be valid before
        # restoring services. A blocked trigger or failed manager activation
        # must not itself leave this application's proven runtime stopped.
        verify_runtime_systemd_policy_packages(journal)
        try:
            finish_runtime_systemctl_policy(journal)
            activate_runtime_systemd(journal)
        except (ValueError,OSError)as error:
            code=str(error)if isinstance(error,ValueError)else 'SYSTEM_SECURITY_SYSTEMD_ACTIVATION_PENDING'
            if code not in ['SYSTEM_SECURITY_SYSTEMD_POLICY_REJECTED','SYSTEM_SECURITY_SYSTEMD_TRIGGER_NOT_CONFIRMED',
                'SYSTEM_SECURITY_SYSTEMD_ACTIVATION_PENDING','SYSTEM_SECURITY_SYSTEMD_PROCESS_CHANGED','SYSTEM_SECURITY_SYSTEMD_CONFIGURATION_CHANGED',
                'SYSTEM_SECURITY_SYSTEMD_USER_MANAGERS_ACTIVE','SYSTEM_SECURITY_SYSTEMD_NETWORKD_ACTIVE','SYSTEM_SECURITY_SYSTEMD_JOURNAL_UNREVIEWED',
                'SYSTEM_SECURITY_SYSTEMD_CHECK_INCOMPLETE','SYSTEM_SECURITY_SYSTEMD_NETWORK_UNREVIEWED']:raise
            systemd_error=code
    if journal.get('sharedDatabase')is not None:runtime_boot_shared_database(journal,pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    if database is not None:
        verify_runtime_database_files(database)
        if not boot_confirmation or command(['systemctl','show',database['unit'],'--property=ActiveState','--value'],20)!='active':command(['systemctl','start',database['unit']],180)
    if not boot_confirmation or backend_runtime_proof()is None:command(['systemctl','start','incudal-backend.service'],11*60)
    verify_runtime_health()
    current=backend_runtime_proof()
    if current is None or any(current[key]!=backend.get(key)for key in ['app','environmentHash','codeHash','unitHashes','serviceHash']):raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    installed=pathlib.Path('/usr/bin/node').stat();running=pathlib.Path('/proc',str(current['pid']),'exe').stat()
    if (installed.st_dev,installed.st_ino)!=(running.st_dev,running.st_ino):raise ValueError('SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    verify_runtime_process_libraries(current['pid'],'SYSTEM_SECURITY_BACKEND_ACTIVATION_PENDING')
    if boot_confirmation:verify_runtime_libc_process(current['pid'],boot_confirmation['libcFiles'])
    if database is not None:
        proof=database_runtime_proof(journal=journal)
        verify_database_activation(proof,database)
        if boot_confirmation:verify_runtime_libc_process(proof['pid'],boot_confirmation['libcFiles'])
    if journal.get('sharedDatabase')is not None:
        shared=journal.get('sharedDatabase')
        if not isinstance(shared,dict)or shared.get('sharedReadOnly')is not True:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
        authority=runtime_boot_shared_database(journal,pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        shared_current=database_runtime_proof(shared_read_only=True,journal=journal);verify_runtime_database_configuration(shared_current,shared)
        if any(shared_current[key]!=authority[key]for key in ['pid','start']):raise ValueError('SYSTEM_SECURITY_DATABASE_PROCESS_CHANGED')
        if boot_confirmation:
            verify_database_activation(shared_current,shared);verify_runtime_libc_process(shared_current['pid'],boot_confirmation['libcFiles'])
            boot_confirmation['sharedDatabasePID']=shared_current['pid'];boot_confirmation['sharedDatabaseStart']=shared_current['start']
    verify_runtime_financial_integrity(app)
    if systemd_error:
        journal['phase']='installed'
        journal['serviceRecovery']={'backendPID':current['pid'],'checkedAt':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
        if database is not None:journal['serviceRecovery']['databasePID']=proof['pid']
        runtime_active_systemd_policy(journal).setdefault('activation',{}).update(state='pending',error=systemd_error)
        write_runtime_maintenance(journal,path.parent)
        raise ValueError(systemd_error)
    if boot_confirmation:
        confirmation=runtime_systemd_boot_confirmation(journal)
        if any(confirmation[key]!=boot_confirmation[key]for key in ['bootId','manager','journald','networkHash','libcFiles','policyHistoryHash']):raise ValueError('SYSTEM_SECURITY_SYSTEMD_BOOT_RECOVERY_PENDING')
        confirmation['backendPID']=current['pid']
        if database is not None:confirmation['databasePID']=proof['pid']
        elif 'sharedDatabasePID'in boot_confirmation:
            confirmation['sharedDatabasePID']=boot_confirmation['sharedDatabasePID'];confirmation['sharedDatabaseStart']=boot_confirmation['sharedDatabaseStart']
        # A natural boot attests activation separately from deferred trigger
        # requests. Cleanup stores the actual requests, including an incomplete
        # set, rather than inventing a successful trigger receipt.
        for policy in runtime_systemd_policy_lineage(journal):finish_runtime_systemctl_policy(journal,confirmation=confirmation,selected=policy)
        verify_runtime_original_dumps(journal)
        confirmation=runtime_systemd_boot_confirmation(journal)|{key:value for key,value in confirmation.items()if key in ['backendPID','databasePID','sharedDatabasePID','sharedDatabaseStart']}
        journal['bootConfirmation']=confirmation
    # A stop failure or interruption before apt ran only restores the prior
    # services. Never issue an activation receipt for an unapplied patch.
    journal['phase']='activated'if installation_started or activation_only else 'aborted'
    if installation_started or activation_only:
        journal['activatedBackendPID']=current['pid']
        if database is not None:journal['activatedDatabasePID']=proof['pid']
    write_runtime_maintenance(journal,path.parent)
    if not installation_started and journal.get('systemdPolicy'):finish_runtime_systemctl_policy(journal,applied=False)
    if installation_started or activation_only:
        archive_runtime_receipt(journal,path.parent)
    return journal if installation_started or activation_only else None

def runtime_completion_preparation(journal):
    if journal.get('phase')!='activated':raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    data=json.dumps(journal,separators=(',',':')).encode()
    return '.completed-'+hashlib.sha256(data).hexdigest()+'.pending',data

def runtime_backup_evidence(backup,journal):
    """Enumerate only original private evidence; never sweep unknown files."""
    allowed={'database.dump','database-after-drain.dump','completed.json'};files=[];directories=[]
    if journal.get('phase')=='activated':
        name,data=runtime_completion_preparation(journal);path=backup/name
        if runtime_path_present(path):
            material=runtime_payload_regular(path,max(len(data),1),private=True,content=True)
            if material['mode']!=0o600 or not data.startswith(material['content']):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            allowed.add(name)
    dumps=journal.get('dumpEvidence')
    if dumps is not None:
        if not isinstance(dumps,dict)or not dumps or not set(dumps)<={'database.dump','database-after-drain.dump'}or journal.get('phase')=='activated'and set(dumps)!={'database.dump','database-after-drain.dump'}:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        for name,record in dumps.items():
            if not isinstance(record,dict)or set(record)!={'sha256','size'}or runtime_dump_evidence(backup/name)!=record:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    recoveries=journal.get('bootRecoveries',{})
    if not isinstance(recoveries,dict)or len(recoveries)>3:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    for boot,recovery in recoveries.items():
        if not isinstance(recovery,dict)or recovery.get('version')!=1 or recovery.get('bootId')!=boot:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        attempts=runtime_boot_dump_attempts(journal,recovery)
        for attempt in attempts:
            path=backup/attempt['file']
            if attempt['state']=='intent':raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            if attempt['state']=='absent':
                if runtime_path_present(path):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
                continue
            material=runtime_dump_material(path)
            if any(material[key]!=attempt[key]for key in ['sha256','size'])or attempt['state']=='complete'and not material['header']:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            allowed.add(attempt['file'])
        dump=recovery.get('dump')
        if dump is not None and (not isinstance(dump,dict)or set(dump)!={'file','sha256','size'}or recovery.get('dumpPending')is not False or not any(attempt['state']=='complete'and all(attempt[key]==dump[key]for key in dump)for attempt in attempts)):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    failures=journal.get('policyPreparationFailures',[])
    if not isinstance(failures,list)or len(failures)>32:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    if failures:
        policies={proof['token']:proof for proof in runtime_systemd_policy_lineage(journal)};members={}
        for failure in failures:
            if not isinstance(failure,dict)or set(failure)!={'token','name','sha256','size','mode','file'}or failure.get('token')not in policies or failure.get('name')not in ['systemctl','policy.lock','policy.json']or not re.fullmatch(r'[a-f0-9]{64}',failure.get('sha256',''))or type(failure.get('size'))is not int or type(failure.get('mode'))is not int or not 0<=failure['mode']<=0o7777:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
            expected,_=runtime_systemctl_preparation_files(policies[failure['token']])[failure['name']]
            binding=hashlib.sha256((failure['token']+'\n'+failure['name']+'\n'+failure['sha256']+'\n'+str(failure['mode'])).encode()).hexdigest()
            if not 0<=failure['size']<=len(expected)or failure['file']!=binding+'.partial'or failure['file']in members:raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
            members[failure['file']]=(failure,expected)
        directory=backup/'policy-failures';info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or directory.resolve()!=directory or {file.name for file in directory.iterdir()}!=set(members):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
        for name,(record,expected)in members.items():
            value=runtime_payload_regular(directory/name,max(len(expected),1),private=True,content=True)
            if value['mode']!=0o600 or value['size']!=record['size']or value['sha256']!=record['sha256']or not expected.startswith(value['content']):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
            files.append(directory/name)
        directories.append(directory);allowed.add('policy-failures')
    proof=journal.get('payloadEvidence')
    if proof:
        if not isinstance(proof,dict)or proof.get('version')!=1 or proof.get('file')!='payload.json'or type(proof.get('size'))is not int or not 0<proof['size']<=16*1024*1024 or not re.fullmatch(r'[a-f0-9]{64}',proof.get('sha256','')):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        payload=runtime_payload_regular(backup/'payload.json',16*1024*1024,private=True,content=True)
        if payload['sha256']!=proof['sha256']or payload['size']!=proof['size']:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        manifest=json.loads(payload['content']);baseline,expected,changes,_=validated_runtime_package_plan(journal)
        if manifest.get('planHash')!=runtime_payload_plan_hash(baseline,expected,changes)or proof.get('planHash')!=manifest['planHash']or not isinstance(manifest.get('archives'),dict)or not isinstance(manifest.get('paths'),dict):raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        allowed|={'payload.json','archives'};archive_files={};conffile_files={}
        for key,source in manifest['archives'].items():
            name,architecture=key.split(':',1)
            for label in ['before','expected']:
                file=source.get(label+'File')
                if file!=label+'-'+name+'-'+architecture+'.deb':raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
                archive_files[file]=source[label]
        node_authority=manifest.get('nodeAuthority')
        if node_authority is not None and not isinstance(node_authority,dict):raise ValueError('SYSTEM_SECURITY_NODE_AUTHORITY_UNCONFIRMED')
        for name,consumer in [('systemd',manifest.get('consumerArchive')),('nodejs',node_authority.get('consumer')if node_authority else None)]:
            if consumer is not None:
                if not isinstance(consumer,dict)or consumer.get('file')!='authority-'+name+'-'+consumer.get('record',{}).get('architecture','')+'.deb':raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
                archive_files[consumer['file']]=consumer['record']
        for path,record in manifest['paths'].items():
            if 'vendorExpected'in record and record.get('before',{}).get('type')=='file':
                if record.get('beforeFile')!=hashlib.sha256(path.encode()).hexdigest()+'.before':raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
                conffile_files[record['beforeFile']]=record['before']
        if conffile_files:allowed.add('conffiles')
        failure_files={};failures=journal.get('conffileRestorationFailures',[])
        if not isinstance(failures,list)or len(failures)>64:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
        for failure in failures:
            if not isinstance(failure,dict)or set(failure)!={'path','binding','temporary','file','sha256','size'}or failure.get('path')not in manifest['paths']or not re.fullmatch(r'[a-f0-9]{64}',failure.get('sha256',''))or type(failure.get('size'))is not int:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            path=failure['path'];record=manifest['paths'][path];binding=hashlib.sha256(json.dumps({'path':path,'record':record,'payload':proof['sha256']},sort_keys=True,separators=(',',':')).encode()).hexdigest()
            if record.get('before',{}).get('type')!='file'or not 0<=failure['size']<=record['before']['size']or failure['binding']!=binding or not re.fullmatch(re.escape(pathlib.PurePosixPath(path).name)+r'\.incudal-restore-[a-f0-9]{32}',failure.get('temporary',''))or failure.get('file')!=hashlib.sha256((path+'\n'+binding+'\n'+failure['sha256']).encode()).hexdigest()+'.partial'or failure['file']in failure_files:raise ValueError('SYSTEM_SECURITY_RUNTIME_PAYLOAD_UNCONFIRMED')
            failure_files[failure['file']]=failure
        if failure_files:allowed.add('conffile-failures')
        for name,members in [('archives',archive_files),('conffiles',conffile_files),('conffile-failures',failure_files)]:
            directory=backup/name
            if not members:
                if runtime_path_present(directory):raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
                continue
            info=directory.lstat()
            if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077 or directory.resolve()!=directory or {file.name for file in directory.iterdir()}!=set(members):raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
            for file,record in members.items():
                value=runtime_payload_regular(directory/file,256*1024*1024,private=True)
                if value['mode']!=0o600 or value['sha256']!=record.get('sha256')or value['size']!=record.get('size'):raise ValueError('SYSTEM_SECURITY_RUNTIME_ARCHIVE_CHANGED')
                files.append(directory/file)
            directories.append(directory)
    for file in backup.iterdir():
        if file.name not in allowed:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        if file.name in ['archives','conffiles','conffile-failures','policy-failures']:continue
        metadata=file.lstat()
        if not stat.S_ISREG(metadata.st_mode)or metadata.st_uid!=0 or metadata.st_nlink!=1 or metadata.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
        files.append(file)
    return files,directories

def archive_runtime_receipt(journal,root):
    name=journal.get('backup')
    if not isinstance(name,str)or not re.fullmatch(r'runtime-backup-[a-f0-9]{32}',name):raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    backup=root/name;info=backup.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o077:raise ValueError('SYSTEM_SECURITY_UNTRUSTED_PATH')
    runtime_backup_evidence(backup,journal)
    receipt=backup/'completed.json'
    if runtime_path_present(receipt):
        protected_hash(receipt,private=True)
        if json.loads(receipt.read_text())!=journal:raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
    else:
        name,data=runtime_completion_preparation(journal);temporary=backup/name
        complete_runtime_fixed_evidence(temporary,data)
        # Leave the bound complete/prefix material on any interruption. A
        # later read-only recovery validates all original evidence first.
        os.replace(temporary,receipt);sync_runtime_evidence_directory(backup)
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
            members,directories=runtime_backup_evidence(path,value)
        except(ValueError,OSError,json.JSONDecodeError):continue
        complete.append((record.stat().st_mtime,path,members,directories))
    for timestamp,path,members,directories in sorted(complete,key=lambda row:row[0],reverse=True)[7:]:
        if path==backup or timestamp>time.time()-30*86400:continue
        latest=json.loads((path/'completed.json').read_text());verified,folders=runtime_backup_evidence(path,latest)
        if set(verified)!=set(members)or set(folders)!=set(directories):continue
        for file in members:file.unlink()
        for directory in directories:directory.rmdir()
        path.rmdir();sync_runtime_evidence_directory(root)

def validated_runtime_package_plan(journal):
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
    validate_runtime_libc_plan(changes,reviewed_debian_inventory(baseline,RUNTIME_DEBIAN_BASE_LIBRARIES))
    if any(name in RUNTIME_DEBIAN_BASE_LIBRARIES for name in planned)and not journal.get('systemdPolicy'):raise ValueError('SYSTEM_SECURITY_SYSTEMD_POLICY_UNREVIEWED')
    return baseline,expected,changes,planned

def runtime_package_transaction_unstarted(journal):
    proof=runtime_active_systemd_policy(journal)
    if not proof or proof.get('cleared')or journal.get('phase')!='installing':return False
    baseline,_,_,_=validated_runtime_package_plan(journal)
    states=debian_package_states()
    if {key:value['version']for key,value in states.items()}!=baseline or any(value['status']!='installed'for value in states.values())or command(['dpkg','--audit'],30):return False
    verify_runtime_systemd_policy_packages(journal)
    if not verify_runtime_payload(journal)['unchanged']:return False
    # A crash after writing intent but before exec is indistinguishable from
    # a failed first dispatch. Exact original packages, clean dpkg state and
    # no deferred action let us restore the original services and abort;
    # another update can retry from the live, independently qualified host.
    policy=read_runtime_systemctl_policy(proof,allow_rejected=True)
    return policy['actions']==[]and not policy['rejected']

def complete_runtime_package_transaction(journal):
    baseline,expected,changes,planned=validated_runtime_package_plan(journal)
    states=debian_package_states();current={key:value['version']for key,value in states.items()}
    configured=all(value['status']=='installed'for value in states.values())
    payload=verify_runtime_payload(journal,archives=True)if journal.get('systemdPolicy')or journal.get('payloadEvidence')else None
    if current==expected and configured and not command(['dpkg','--audit'],30):
        if journal.get('payloadEvidence'):
            restore_runtime_conffiles(journal);payload=verify_runtime_payload(journal,archives=True)
        if payload is None or payload['complete']:return
    # A failed install can have advanced some exact planned packages. Unknown
    # removals, additions or versions are refused instead of starting that code.
    if current.keys()!=baseline.keys()or any(current[key]not in [baseline[key],expected[key]]for key in baseline):raise ValueError('SYSTEM_SECURITY_RUNTIME_PACKAGE_BASELINE_CHANGED')
    if any(value['status']!='installed'and key.split(':')[0]not in planned and not(key.split(':')[0]=='systemd'and journal.get('systemdPolicy')and value['status']in ['triggers-awaited','triggers-pending'])for key,value in states.items()):raise ValueError('SYSTEM_SECURITY_RUNTIME_PACKAGE_BASELINE_CHANGED')
    remaining=[];reinstall=set()
    for item in changes:
        name,version=item.split('=',1);key=next(key for key in expected if key.split(':')[0]==name)
        incomplete=payload is not None and key in payload['incomplete']
        if current[key]!=version or states[key]['status']=='half-installed'or incomplete:remaining.append(item)
        if states[key]['status']=='half-installed'or incomplete and current[key]==version:reinstall.add(name)
    if remaining:
        reviewed={key.split(':')[0]:version for key,version in current.items()}
        if len(reviewed)!=len(current):raise ValueError('SYSTEM_SECURITY_MULTIARCH_REVIEW_REQUIRED')
        package_args=runtime_original_expected_arguments(journal,remaining)if journal.get('payloadEvidence')else remaining
        output=command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','--simulate','--only-upgrade','--no-remove','--no-download',*(['--reinstall']if reinstall else []),'install',*package_args],90)
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
        try:runtime_package_command(['dpkg','--force-confold','--configure',*configuring],journal,300)
        finally:clean_service_policy()
        if command(['dpkg','--audit'],30)or debian_installed_packages()!=expected:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')
        if payload:
            restore_runtime_conffiles(journal);verify_runtime_payload(journal,require='expected')
        return
    prepare_service_policy()
    try:
        runtime_package_command(['apt-get','-o','DPkg::Lock::Timeout=5','-o','APT::Get::AllowUnauthenticated=false','-o','Dpkg::Options::=--force-confold','--assume-yes','--only-upgrade','--no-remove','--no-download',*(['--reinstall']if reinstall else []),'install',*package_args],journal,600)
    finally:clean_service_policy()
    if command(['dpkg','--audit'],30)or debian_installed_packages()!=expected:raise ValueError('SYSTEM_SECURITY_PATCH_NOT_CONFIRMED')
    if payload:
        restore_runtime_conffiles(journal);verify_runtime_payload(journal,require='expected')

def verify_runtime_database_configuration(current,before):
    if any(current[key]!=before[key]for key in ['major','data','configHash','hbaHash','unitHash','fileHashes']):raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
    version=before.get('settingsHashVersion',1)
    if type(version)is not int or version not in [1,2]or version==2 and current.get('settingsHashVersion')!=2:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
    # Earlier private receipts remain bound to their exact original digest.
    # A new comparison policy cannot silently re-attest an old baseline.
    settings=current.get('settingsLegacyHash',current.get('settingsHash'))if version==1 else current.get('settingsHash')
    if not isinstance(before.get('settingsHash'),str)or settings!=before['settingsHash']:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')

def verify_runtime_database_files(database,backup_only=False):
    if not isinstance(database,dict)or database.get('sharedReadOnly')and not backup_only:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    major=database.get('major')
    if type(major)is not int or major not in [14,15,16,17,18]or database.get('unit')!='postgresql@'+str(major)+'-main.service':raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    if database.get('data')!='/var/lib/postgresql/'+str(major)+'/main'or database.get('config')!='/etc/postgresql/'+str(major)+'/main/postgresql.conf'or database.get('hba')!='/etc/postgresql/'+str(major)+'/main/pg_hba.conf':raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    owner=pathlib.Path(database['data']).stat().st_uid
    if protected_hash(database['config'],(0,owner))!=database.get('configHash')or protected_hash(database['hba'],(0,owner))!=database.get('hbaHash'):raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
    files=database.get('fileHashes')
    if not isinstance(files,dict)or not files or len(files)>68:raise ValueError('SYSTEM_SECURITY_RUNTIME_JOURNAL_INVALID')
    for file,digest in files.items():
        if not isinstance(file,str)or not(file.startswith('/etc/postgresql/'+str(major)+'/main/')or file==database['data']+'/postgresql.auto.conf')or protected_hash(file,(0,owner))!=digest:raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
    unit_path=command(['systemctl','show',database['unit'],'--property=FragmentPath','--value'],20)
    if unit_path not in ['/lib/systemd/system/postgresql@.service','/usr/lib/systemd/system/postgresql@.service']or protected_hash(unit_path)!=database.get('unitHash'):raise ValueError('SYSTEM_SECURITY_DATABASE_CONFIGURATION_CHANGED')
    if command(['systemctl','show',database['unit'],'--property=SubState','--value'],20)in ['stop','stop-sigterm','stop-sigkill','stop-post']:raise ValueError('SYSTEM_SECURITY_DATABASE_STOP_PENDING')

def verify_database_activation(current,before):
    verify_runtime_database_configuration(current,before)
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

def dump_runtime_database(path,database,journal=None):
    clients,tools=verify_runtime_database_clients(database,journal)
    verify_runtime_database_files(database,backup_only=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    process=None
    try:
        with tempfile.TemporaryFile()as errors:
            process=subprocess.Popen(['runuser','-u','postgres','--',clients['pg_dump'],'-Fc','incudal'],stdout=fd,stderr=errors,start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
            try:code=process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait();raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            if code or os.fstat(fd).st_size<5 or live_process_group(process.pid):raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
            os.fsync(fd)
        with pathlib.Path(path).open('rb')as input:
            if input.read(5)!=b'PGDMP':raise ValueError('SYSTEM_SECURITY_RUNTIME_BACKUP_FAILED')
        if runtime_database_client_files(tools['major'])!=tools:raise ValueError('SYSTEM_SECURITY_DATABASE_CLIENT_CHANGED')
        verify_runtime_database_files(database,backup_only=True)
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
    if runtime_path_present(path):
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
    kernel=value.get('kernelActivation')
    if kernel is not None and (not isinstance(kernel,dict)or kernel.get('state')!='current'):return False
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
