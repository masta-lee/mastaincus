#!/usr/bin/env bash
# ============================================================================
# PayIncus 面板一键部署脚本（产物包模式）
#
# 功能：
#   - 安装 Node.js 24、PostgreSQL 16 和系统仓库提供的 Redis
#   - 从 GitHub Releases 下载预构建产物包
#   - 自动配置数据库、环境变量、systemd 服务
#   - 支持 Nginx+Certbot / Cloudflare Tunnel / 纯端口 三种外部访问方案
#   - 支持升级已有安装
#
# 用法：
#   安装：  sudo bash install-panel.sh
#   升级：  sudo bash install-panel.sh --upgrade
#   卸载：  sudo bash install-panel.sh --uninstall
#
# 项目地址: https://github.com/masta-lee/mastaincus
# ============================================================================
set -euo pipefail

# ========================== 全局常量 ==========================
readonly SCRIPT_VERSION="3.1.0"
readonly GITHUB_REPO="masta-lee/mastaincus"
readonly INSTALL_DIR="/opt/incudal"
readonly SERVICE_NAME="incudal-backend"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly ENV_FILE="${INSTALL_DIR}/.env"
readonly INSTALLATION_IDENTITY_PATHS=(
    "$SERVICE_FILE"
    /etc/systemd/system/incudal.service
    /var/lib/incudal-gateway-controller/enrollment.json
    /var/lib/incudal-gateway-controller/identity.json
    /var/lib/incudal-gateway-controller/signing.pem
    /root/.ssh/incudal-host-management
    /root/.ssh/incudal-host-management.pub
    /etc/wireguard/incudal-mgmt.conf
    /var/lib/incudal-backup/recovery-hold.json
)
readonly INSTALLATION_GATEWAY_STATE_DIR="/var/lib/incudal-management-gateway"
readonly RUN_USER="incudal"
readonly DEFAULT_PORT=3001
readonly NODE_MAJOR=24
readonly PNPM_VERSION="9.14.2"
readonly PG_VERSION=16
readonly INSTALLER_SYSTEM_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
RELEASE_VERIFIED_THIS_RUN=false
VERIFIED_LEGACY_DATABASE_PACKAGE=""
CF_TUNNEL_SELECTED=false
CF_TUNNEL_VERIFIED=false

normalize_legacy_online_task_helper() {
    local helper_file="$1" normalized
    # Original v1.8.13/v1.8.14 archives keep their exact signed/pinned bytes.
    # Only the extracted deployment helper's old origin constant is generated
    # for this installation; a current helper keeps its legacy identity gate.
    if grep -Fq 'https://github.com/mastalee928/payincus.git' "$helper_file" &&
        ! grep -Fq "https://github.com/${GITHUB_REPO}.git" "$helper_file"; then
        normalized="$(mktemp)" || return 1
        if ! sed "s#https://github[.]com/mastalee928/payincus[.]git#https://github.com/${GITHUB_REPO}.git#g" "$helper_file" > "$normalized" ||
            ! bash -n "$normalized" || ! mv -f -- "$normalized" "$helper_file"; then
            rm -f -- "$normalized"
            return 1
        fi
    fi
}

repository_startup_guard_identity() {
    local file="$1" metadata digest
    [[ -f "$file" && ! -L "$file" && $(stat -c '%u:%g:%a:%h' "$file") == 0:0:755:1 ]] || return 1
    metadata="$(stat -c '%d:%i:%u:%g:%a:%h' "$file")" || return 1
    digest="$(sha256sum "$file" | awk '{print $1}')" || return 1
    [[ "$digest" =~ ^[a-f0-9]{64}$ && "$(stat -c '%d:%i:%u:%g:%a:%h' "$file")" == "$metadata" ]] || return 1
    printf '%s:%s' "$metadata" "$digest"
}

install_repository_startup_guard() {
    (
    local PATH=/usr/sbin:/usr/bin:/sbin:/bin
    export PATH
    unset BASH_ENV ENV LD_PRELOAD LD_LIBRARY_PATH PYTHONPATH PYTHONHOME NODE_OPTIONS NODE_PATH
    local directory=/usr/local/libexec/incudal target temporary before current parent parent_before expected_hash
    target="$directory/incudal-repository-source-startup"
    for parent in / /usr /usr/local /usr/local/libexec; do
        if [[ ! -e "$parent" && ! -L "$parent" ]]; then install -d -o root -g root -m 0755 "$parent" || return 1; fi
        [[ -d "$parent" && ! -L "$parent" && $(stat -c '%u:%g' "$parent") == 0:0 && -z $(find "$parent" -maxdepth 0 -perm /022 -print) ]] || return 1
    done
    if [[ -e "$directory" || -L "$directory" ]]; then
        [[ -d "$directory" && ! -L "$directory" && $(stat -c '%u:%g' "$directory") == 0:0 && -z $(find "$directory" -maxdepth 0 -perm /022 -print) ]] || return 1
    else
        install -d -o root -g root -m 0755 "$directory" || return 1
    fi
    parent_before="$(for parent in / /usr /usr/local /usr/local/libexec "$directory"; do stat -c '%d:%i:%u:%g:%a' "$parent" || exit 1; done)" || return 1
    before=missing
    if [[ -e "$target" || -L "$target" ]]; then
        before="$(repository_startup_guard_identity "$target")" || return 1
    fi
    temporary="$(mktemp "$directory/.repository-source.XXXXXX")" || return 1
    if ! cat > "$temporary" <<'INCUDAL_REPOSITORY_SOURCE_SCRIPT'
#!/usr/bin/bash
# Restore only an authenticated runtime launcher for its verified repository; no arguments.
# The systemd caller must use /usr/bin/env -i BEFORE starting this Bash program.
set -Eeuo pipefail
[[ $# -eq 0 && $EUID -eq 0 ]] || { printf '%s\n' INCUDAL_RETIRED_HELPER_REFUSED >&2; exit 1; }
exec /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/var/cache/incudal-ota \
  /usr/bin/python3 -I -B - <<'INCUDAL_RETIRED_HELPER_PY'
import hashlib
import os
import posixpath
import re
import secrets
import stat
import subprocess
import sys

ROOT = '/opt/incudal'
SEALS = '/var/lib/incudal-ota/manifests'
HELPERS = '/usr/local/libexec/incudal'
HOME = '/var/cache/incudal-ota'
SOURCE = 'deploy/incudal-online-task.sh.example'
TARGET = 'incudal-online-task'
OLD = b'https://github.com/mastalee928/payincus.git'
NEW = b'https://github.com/masta-lee/mastaincus.git'
GIT = '/usr/bin/git'
OFLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
FACTS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
DIRECTORY_FACTS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid')
# The original worker restarts before its root postflight writes the new seal.
# These complete publisher helper bytes authorize metadata normalization,
# including pre-seal update/rollback windows. Unknown helpers require a seal;
# every root task continues to verify its entire runtime before execution.
PINNED_STARTUP_HELPERS = frozenset({
    '2c2407c17f6997c01e3997fbb040fb302c66a3854346746b08891e9822f1e820',
    '15fd9cac0a7af20a2a8499b10637c7d3696c99ef1abe81eacce728134011219a',
})
CURRENT_SECURE_HELPER = '2c2407c17f6997c01e3997fbb040fb302c66a3854346746b08891e9822f1e820'
LEGACY_HELPER = '15fd9cac0a7af20a2a8499b10637c7d3696c99ef1abe81eacce728134011219a'

def refuse():
    raise ValueError('INCUDAL_RETIRED_HELPER_REFUSED')

def facts(info, fields=FACTS):
    return tuple(getattr(info, key) for key in fields)

def protected(info, directory=False, modes=None):
    if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
        refuse()
    if directory:
        if not stat.S_ISDIR(info.st_mode): refuse()
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        refuse()
    if modes is not None and stat.S_IMODE(info.st_mode) not in modes: refuse()

def read_fd(fd, size):
    os.lseek(fd, 0, os.SEEK_SET)
    blocks, total = [], 0
    while total <= size:
        block = os.read(fd, min(262144, size + 1 - total))
        if not block: break
        blocks.append(block); total += len(block)
    if total != size: refuse()
    return b''.join(blocks)

class Directory:
    def __init__(self, name, parent=None):
        self.name = name
        self.fd = os.open(name if parent is None else posixpath.basename(name),
                          os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                          **({} if parent is None else {'dir_fd': parent.fd}))
        try:
            self.initial = os.fstat(self.fd)
            protected(self.initial, directory=True)
            self.check()
        except BaseException:
            os.close(self.fd); raise

    def check(self):
        current, named = os.fstat(self.fd), os.lstat(self.name)
        protected(current, directory=True)
        protected(named, directory=True)
        if facts(current, DIRECTORY_FACTS) != facts(self.initial, DIRECTORY_FACTS) or \
           facts(named, DIRECTORY_FACTS) != facts(self.initial, DIRECTORY_FACTS): refuse()

    def close(self): os.close(self.fd)

class File:
    def __init__(self, name, parent, limit, modes):
        self.name, self.parent, self.leaf, self.limit = name, parent, posixpath.basename(name), limit
        self.fd = os.open(self.leaf, OFLAGS, dir_fd=parent.fd)
        try:
            self.initial = os.fstat(self.fd)
            self.named = os.stat(self.leaf, dir_fd=parent.fd, follow_symlinks=False)
            protected(self.initial, modes=modes)
            protected(self.named, modes=modes)
            if (self.initial.st_dev, self.initial.st_ino) != (self.named.st_dev, self.named.st_ino) or \
               not 0 <= self.initial.st_size <= limit: refuse()
            self.raw = self.read()
            self.sha = hashlib.sha256(self.raw).hexdigest()
            self.check()
        except BaseException:
            os.close(self.fd); raise

    def read(self):
        return read_fd(self.fd, self.initial.st_size)

    def check(self):
        self.parent.check()
        if facts(os.fstat(self.fd)) != facts(self.initial) or \
           facts(os.stat(self.leaf, dir_fd=self.parent.fd, follow_symlinks=False)) != facts(self.named): refuse()
        if hasattr(self, 'sha') and hashlib.sha256(self.read()).hexdigest() != self.sha: refuse()
        if facts(os.fstat(self.fd)) != facts(self.initial): refuse()

    def close(self): os.close(self.fd)

def runtime():
    current = ROOT + '/current'
    try: info = os.lstat(current)
    except FileNotFoundError: return ROOT, None
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 1: refuse()
    link = os.readlink(current)
    app = os.path.realpath(current)
    if not re.fullmatch(re.escape(ROOT) + r'/releases/[A-Za-z0-9._+-]{1,160}', app): refuse()
    return app, (facts(info), link)

def source_digest(raw):
    matches = []
    for line in raw.splitlines(keepends=True):
        row = re.fullmatch(rb'(\\?)([a-f0-9]{64})  (.+)\n', line)
        if row is None: refuse()
        name = row[3].decode('utf-8', 'surrogateescape')
        if posixpath.normpath(name) == SOURCE:
            if row[1] or line != row[2] + b'  ./' + SOURCE.encode() + b'\n': refuse()
            matches.append(row[2].decode('ascii'))
    if len(matches) != 1: refuse()
    return matches[0]

def git_snapshot():
    root = ROOT + '/.git'
    records, count = [], 0
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in [base] + [posixpath.join(base, part) for part in dirs + files]:
            info = os.lstat(name); count += 1
            if count > 65536 or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022 or \
               not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)): refuse()
            if name.startswith(root + '/hooks/') and stat.S_ISREG(info.st_mode) and info.st_mode & 0o111: refuse()
            records.append((name, facts(info)))
    if not records: refuse()
    return sorted(records)

def git_query(args, missing=False):
    result = subprocess.run([GIT, '-C', ROOT, *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': HOME, 'LC_ALL': 'C', 'GIT_OPTIONAL_LOCKS': '0'})
    if result.returncode == 1 and missing and not result.stdout: return None
    if result.returncode != 0 or len(result.stdout) > 65536: refuse()
    return result.stdout

def origin():
    dangerous = r'^(core\.hookspath|core\.fsmonitor|filter\..*\.(clean|smudge|process)|diff\..*\.command|include\.path|includeif\..*\.path)$'
    # Repository-controlled executable settings remain forbidden. These fixed
    # metadata-only Git commands never run filters; a root-protected system
    # Git LFS installation must not block normal startup. Keep global includes
    # and core execution settings closed, and check effective URLs unchanged.
    global_dangerous = r'^(core\.hookspath|core\.fsmonitor|include\.path|includeif\..*\.path)$'
    if git_query(['config', '--local', '--get-regexp', dangerous], missing=True) is not None or \
       git_query(['config', '--get-regexp', global_dangerous], missing=True) is not None: refuse()
    raw = git_query(['config', '--local', '--get-all', 'remote.origin.url'])
    if raw not in (OLD + b'\n', NEW + b'\n'): refuse()
    if git_query(['remote', 'get-url', 'origin']) != raw: refuse()
    for fixed in (OLD, NEW):
        if git_query(['ls-remote', '--get-url', fixed.decode('ascii')]) != fixed + b'\n': refuse()
    return raw[:-1]

def main():
    if os.geteuid() != 0: refuse()
    directories, files, temporary, temporary_fd = {}, [], None, None
    def directory(name):
        if name not in directories:
            parent = None if name == '/' else directory(posixpath.dirname(name))
            directories[name] = Directory(name, parent)
        return directories[name]
    def hold(name, limit, modes):
        item = File(name, directory(posixpath.dirname(name)), limit, modes); files.append(item); return item
    try:
        directory(ROOT); directory(ROOT + '/.git'); directory(SEALS); helper_dir = directory(HELPERS); directory(HOME)
        app, current = runtime(); directory(app); directory(app + '/deploy')
        source = hold(app + '/' + SOURCE, 1024 * 1024, {0o644, 0o755})
        if source.sha not in PINNED_STARTUP_HELPERS:
            key = hashlib.sha256(app.encode('utf-8')).hexdigest()
            manifest = hold(SEALS + '/' + key + '.sha256', 64 * 1024 * 1024, {0o600, 0o644})
            hold(SEALS + '/' + key + '.sha256.links', 16 * 1024 * 1024, {0o600, 0o644})
            if source.sha != source_digest(manifest.raw): refuse()
        installed = hold(HELPERS + '/' + TARGET, 1024 * 1024, {0o755})
        retained_secure = source.sha == LEGACY_HELPER and installed.sha == CURRENT_SECURE_HELPER
        if retained_secure:
            # Role-separation startup deliberately keeps the verified new
            # launcher after rollback and does not rerun the older installer.
            # Retain it only with its independently held exact secure copy.
            secure = hold(HELPERS + '/database-secure-task', 1024 * 1024, {0o755})
            if secure.sha != CURRENT_SECURE_HELPER or secure.raw != installed.raw: refuse()
        # Hold both mandatory local Git configuration and any active global inputs.
        hold(ROOT + '/.git/config', 1024 * 1024, {0o600, 0o644})
        for name in ('/etc/gitconfig', HOME + '/.gitconfig', HOME + '/.config/git/config'):
            try: os.lstat(name)
            except FileNotFoundError: continue
            hold(name, 1024 * 1024, {0o600, 0o644})
        git_before = git_snapshot(); raw_origin = origin()
        convertible = OLD in source.raw and NEW not in source.raw
        converted = source.raw.replace(OLD, NEW) if convertible else source.raw
        if not retained_secure and installed.raw not in (source.raw, converted): refuse()
        wanted = installed.raw if retained_secure else (converted if raw_origin == NEW else source.raw)
        def recheck(check_installed=True):
            if runtime() != (app, current): refuse()
            for item in directories.values(): item.check()
            for item in files:
                if check_installed or item is not installed: item.check()
            if git_snapshot() != git_before or origin() != raw_origin: refuse()
        if installed.raw == wanted:
            recheck(); return
        temporary = '.incudal-online-task.repository-' + secrets.token_hex(16)
        temporary_fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                               0o600, dir_fd=helper_dir.fd)
        offset = 0
        while offset < len(wanted):
            count = os.write(temporary_fd, wanted[offset:])
            if count <= 0: refuse()
            offset += count
        os.fchown(temporary_fd, 0, 0); os.fchmod(temporary_fd, 0o755); os.fsync(temporary_fd)
        temporary_info = os.fstat(temporary_fd)
        protected(temporary_info, modes={0o755})
        if temporary_info.st_size != len(wanted): refuse()
        if read_fd(temporary_fd, len(wanted)) != wanted: refuse()
        named = os.stat(temporary, dir_fd=helper_dir.fd, follow_symlinks=False)
        if (named.st_dev, named.st_ino) != (temporary_info.st_dev, temporary_info.st_ino): refuse()
        recheck()
        os.replace(temporary, TARGET, src_dir_fd=helper_dir.fd, dst_dir_fd=helper_dir.fd)
        temporary = None
        os.fsync(helper_dir.fd)
        recheck(check_installed=False)
        final = os.stat(TARGET, dir_fd=helper_dir.fd, follow_symlinks=False)
        protected(final, modes={0o755})
        if (final.st_dev, final.st_ino) != (temporary_info.st_dev, temporary_info.st_ino) or final.st_size != len(wanted): refuse()
        if read_fd(temporary_fd, len(wanted)) != wanted: refuse()
    finally:
        errors = False
        if temporary is not None and temporary_fd is not None:
            try:
                ours = os.fstat(temporary_fd); named = os.stat(temporary, dir_fd=helper_dir.fd, follow_symlinks=False)
                if (ours.st_dev, ours.st_ino) == (named.st_dev, named.st_ino) and \
                   stat.S_ISREG(named.st_mode) and named.st_uid == 0 and named.st_nlink == 1:
                    os.unlink(temporary, dir_fd=helper_dir.fd)
            except FileNotFoundError: pass
            except OSError: errors = True
        if temporary_fd is not None:
            try: os.close(temporary_fd)
            except OSError: errors = True
        for item in reversed(files):
            try: item.close()
            except OSError: errors = True
        for item in reversed(list(directories.values())):
            try: item.close()
            except OSError: errors = True
        if errors: refuse()

try:
    main()
except Exception:
    print('INCUDAL_RETIRED_HELPER_REFUSED', file=sys.stderr)
    raise SystemExit(1)
INCUDAL_RETIRED_HELPER_PY
INCUDAL_REPOSITORY_SOURCE_SCRIPT
    then rm -f -- "$temporary"; return 1; fi
    current=missing
    if [[ -e "$target" || -L "$target" ]]; then
        current="$(repository_startup_guard_identity "$target")" || { rm -f -- "$temporary"; return 1; }
    fi
    if [[ "$current" != "$before" ]] ||
        ! /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin /usr/bin/bash -n "$temporary" ||
        ! chown root:root "$temporary" || ! chmod 0755 "$temporary" || ! sync -f "$temporary"; then
        rm -f -- "$temporary"; return 1
    fi
    expected_hash="$(sha256sum "$temporary" | awk '{print $1}')" || { rm -f -- "$temporary"; return 1; }
    current=missing
    if [[ -e "$target" || -L "$target" ]]; then
        current="$(repository_startup_guard_identity "$target")" || { rm -f -- "$temporary"; return 1; }
    fi
    if [[ "$current" != "$before" || "$(for parent in / /usr /usr/local /usr/local/libexec "$directory"; do stat -c '%d:%i:%u:%g:%a' "$parent" || exit 1; done)" != "$parent_before" ]]; then rm -f -- "$temporary"; return 1; fi
    if [[ "$before" != missing ]] && cmp -s -- "$temporary" "$target"; then
        rm -f -- "$temporary"
    elif ! mv -T -- "$temporary" "$target"; then
        rm -f -- "$temporary"; return 1
    fi
    sync -f "$directory" || return 1
    [[ "$(for parent in / /usr /usr/local /usr/local/libexec "$directory"; do stat -c '%d:%i:%u:%g:%a' "$parent" || exit 1; done)" == "$parent_before" ]] || return 1
    current="$(repository_startup_guard_identity "$target")" || return 1
    [[ "${current##*:}" == "$expected_hash" ]] || return 1
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/bin/python3 -I -B - '/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/bin/bash /usr/local/libexec/incudal/incudal-repository-source-startup' <<'INCUDAL_REPOSITORY_STARTUP_UNITS'
import hashlib,os,re,secrets,stat,sys
DIRECTORY='/etc/systemd/system'
POST='+'+sys.argv[1]
FIELDS=('st_dev','st_ino','st_uid','st_gid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def facts(info):return tuple(getattr(info,key)for key in FIELDS)
def refused():raise ValueError('INCUDAL_REPOSITORY_STARTUP_UNITS_REFUSED')
def safe_file(info):
    if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>1048576:refused()
def read(fd,size):
    os.lseek(fd,0,os.SEEK_SET);chunks=[];total=0
    while total<=size:
        part=os.read(fd,min(65536,size+1-total))
        if not part:break
        chunks.append(part);total+=len(part)
    if total!=size:refused()
    return b''.join(chunks)
def present(raw,section,key,wanted):
    current='';values=[]
    for line in raw.decode('utf8').splitlines():
        text=line.strip()
        if text.startswith(('#',';')):continue
        heading=re.fullmatch(r'\[([^\]]+)\]',text)
        if heading:current=heading[1];continue
        if current!=section or '='not in text:continue
        name,value=text.split('=',1)
        if name.strip()!=key:continue
        value=value.strip()
        if not value:values=[]
        else:values.append(value)
    return wanted in (' '.join(values).split()if key=='After'else values)
def update(directory,name,section,key,wanted,check_parents):
    fd=None;temporary=None;output_fd=None
    try:
        try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        except FileNotFoundError:return
        before=os.fstat(fd);named=os.stat(name,dir_fd=directory,follow_symlinks=False);safe_file(before);safe_file(named)
        if facts(before)!=facts(named):refused()
        raw=read(fd,before.st_size)
        if b'\0'in raw:refused()
        if present(raw,section,key,wanted):
            if facts(os.fstat(fd))!=facts(before)or facts(os.stat(name,dir_fd=directory,follow_symlinks=False))!=facts(named)or read(fd,before.st_size)!=raw:refused()
            check_parents()
            return
        eol=b'\r\n'if b'\r\n'in raw else b'\n'
        delimiter=eol if raw and not raw.endswith((b'\r',b'\n'))else b''
        payload=raw+delimiter+eol+('['+section+']').encode()+eol+(key+'='+wanted).encode()+eol
        temporary='.'+name+'.repository-'+secrets.token_hex(16)
        output_fd=os.open(temporary,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
        offset=0
        while offset<len(payload):
            written=os.write(output_fd,payload[offset:])
            if written<=0:refused()
            offset+=written
        os.fchown(output_fd,before.st_uid,before.st_gid);os.fchmod(output_fd,stat.S_IMODE(before.st_mode));os.fsync(output_fd)
        proposed=os.fstat(output_fd);safe_file(proposed)
        if read(output_fd,len(payload))!=payload:refused()
        if facts(os.fstat(fd))!=facts(before)or facts(os.stat(name,dir_fd=directory,follow_symlinks=False))!=facts(named)or read(fd,before.st_size)!=raw:refused()
        if facts(os.stat(temporary,dir_fd=directory,follow_symlinks=False))!=facts(proposed):refused()
        check_parents()
        os.replace(temporary,name,src_dir_fd=directory,dst_dir_fd=directory);temporary=None;os.fsync(directory)
        check_parents()
        final=os.stat(name,dir_fd=directory,follow_symlinks=False);safe_file(final)
        if(final.st_dev,final.st_ino,final.st_uid,final.st_gid,stat.S_IMODE(final.st_mode))!=(proposed.st_dev,proposed.st_ino,before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))or read(output_fd,len(payload))!=payload:refused()
        check_parents()
    finally:
        if temporary is not None and output_fd is not None:
            try:
                owned=os.fstat(output_fd);named=os.stat(temporary,dir_fd=directory,follow_symlinks=False)
                if(owned.st_dev,owned.st_ino)==(named.st_dev,named.st_ino)and stat.S_ISREG(named.st_mode)and named.st_uid==0 and named.st_nlink==1:os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError:pass
        if output_fd is not None:os.close(output_fd)
        if fd is not None:os.close(fd)
def main():
    if os.geteuid()!=0 or len(sys.argv)!=2:refused()
    directories=[];parent=None
    try:
        for name in ['/','/etc','/etc/systemd',DIRECTORY]:
            fd=os.open(name if parent is None else os.path.basename(name),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,**({}if parent is None else{'dir_fd':parent}))
            info=os.fstat(fd);named=os.lstat(name)
            if not stat.S_ISDIR(info.st_mode)or info.st_uid!=0 or info.st_mode&0o022 or(info.st_dev,info.st_ino)!=(named.st_dev,named.st_ino):os.close(fd);refused()
            directories.append((name,fd,info));parent=fd
        def check_parents():
            for path,fd,initial in directories:
                now=os.lstat(path)
                opened=os.fstat(fd)
                expected=(initial.st_dev,initial.st_ino,initial.st_uid,initial.st_gid,initial.st_mode)
                if(now.st_dev,now.st_ino,now.st_uid,now.st_gid,now.st_mode)!=expected or(opened.st_dev,opened.st_ino,opened.st_uid,opened.st_gid,opened.st_mode)!=expected:refused()
        for name,section,key,wanted in [('incudal-backend.service','Service','ExecStartPost',POST),('incudal-online-update@.service','Unit','After','incudal-backend.service'),('incudal-online-rollback@.service','Unit','After','incudal-backend.service')]:
            check_parents()
            update(parent,name,section,key,wanted,check_parents)
        check_parents()
    finally:
        for _,fd,_ in reversed(directories):os.close(fd)
try:main()
except Exception:
    print('INCUDAL_REPOSITORY_STARTUP_UNITS_REFUSED',file=sys.stderr);raise SystemExit(1)
INCUDAL_REPOSITORY_STARTUP_UNITS
    )
}

install_verified_root_helpers_from_archive() {
    local tar_file="$1"
    local helper entry tmp

    install -d -o root -g root -m 0755 /usr/local/libexec/incudal /usr/local/libexec/incudal/ota-path || return "$?"
    for helper in \
        incudal-online-task.sh.example \
        incudal-systemctl-wrapper.sh.example \
        incudal-ota-chown-wrapper.sh.example; do
        entry="$(tar -tzf "$tar_file" | grep -E "^(\./)?deploy/${helper}$" || true)"
        if [[ "$(printf '%s\n' "$entry" | sed '/^$/d' | wc -l)" -ne 1 ]]; then
            error "已验证产物缺少唯一 root helper: deploy/${helper}"
            return 1
        fi
        tmp="$(mktemp)" || return "$?"
        if ! tar -xOzf "$tar_file" "$entry" > "$tmp"; then rm -f -- "$tmp"; return 1; fi
        if [[ "$helper" == incudal-online-task.sh.example ]] && ! normalize_legacy_online_task_helper "$tmp"; then
            rm -f -- "$tmp"
            return 1
        fi
        if [[ ! -s "$tmp" ]] || ! bash -n "$tmp"; then
            rm -f "$tmp"
            error "已验证产物中的 root helper 无效: deploy/${helper}"
            return 1
        fi
        case "$helper" in
            incudal-online-task.sh.example) install -o root -g root -m 0755 "$tmp" /usr/local/libexec/incudal/incudal-online-task || return "$?" ;;
            incudal-systemctl-wrapper.sh.example) install -o root -g root -m 0755 "$tmp" /usr/local/libexec/incudal/systemctl || return "$?" ;;
            incudal-ota-chown-wrapper.sh.example) install -o root -g root -m 0755 "$tmp" /usr/local/libexec/incudal/ota-path/chown || return "$?" ;;
        esac
        rm -f "$tmp" || return "$?"
    done
    install -d -o root -g root -m 0755 /var/cache/incudal-ota /var/lib/incudal-ota/manifests || return "$?"
}

# ========================== 颜色定义 ==========================
readonly RED='\033[1;31m'
readonly GREEN='\033[1;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[1;36m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly NC='\033[0m'

# ========================== 工具函数 ==========================
# 所有日志输出到 stderr，避免在 $() 子 shell 中被捕获
log()   { echo -e "${GREEN}[✓]${NC} $1" >&2; }
info()  { echo -e "${CYAN}[i]${NC} $1" >&2; }
warn()  { echo -e "${YELLOW}[!]${NC} $1" >&2; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; }
step()  { echo -e "\n${CYAN}[▶]${NC} ${BOLD}$1${NC}" >&2; }

divider() {
    echo -e "${DIM}────────────────────────────────────────────────────${NC}" >&2
}

# 生成随机密码
gen_password() {
    openssl rand -hex 64 | cut -c "1-${1:-24}"
}

gen_secret() {
    local generated_entropy
    generated_entropy="$(openssl rand -hex 64)" || return "$?"
    printf 'A1!%s' "$generated_entropy" | cut -c "1-${1:-48}"
}

is_valid_email() {
    local email="$1"
    [[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]
}

prompt_initial_admin_email() {
    local default_email="${ADMIN_EMAIL:-admin@payincus.local}"
    local input

    if [[ -f "$ENV_FILE" ]]; then
        local existing_email
        existing_email="$(get_env_value "ADMIN_EMAIL")" || return "$?"
        if [[ -n "$existing_email" ]]; then
            printf '%s' "$existing_email"
            return 0
        fi
    fi

    echo -ne "  ${BOLD}请输入初始管理员邮箱 [${default_email}]: ${NC}" >&2
    read -r input || return "$?"
    input="${input:-$default_email}"

    if ! is_valid_email "$input"; then
        error "管理员邮箱格式不正确: ${input}"
        exit 1
    fi

    printf '%s' "$input"
}

env_dotenv_data() {
    local operation="$1" key="$2" value="${3-}" last_byte
    [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || return 1
    last_byte="$(tail -c 1 -- "$ENV_FILE" | od -An -tu1)" || return 1
    last_byte="${last_byte//[[:space:]]/}"
    # Parse data with the base-system tools available before Node installation.
    # Values are never shell code or command arguments. Keep the original bytes,
    # including CRLF/no final LF, and skip complete quoted credential blocks.
    cat -- "$ENV_FILE" | INCUDAL_ENV_WRITE_VALUE="$value" LC_ALL=C awk -v BINMODE=3 \
        -v operation="$operation" -v key="$key" -v final_byte="$last_byte" '
        function fail() {
            print "Environment data parsing failed; original configuration retained." > "/dev/stderr"
            exit 65
        }
        function ws(s, p, c, b) {
            c = substr(s, p, 1)
            if (c != "" && c ~ /[[:space:]]/) return 1
            if (substr(s, p, 2) == "\302\240") return 2
            b = substr(s, p, 3)
            if (b == "\357\273\277" || b == "\341\232\200" ||
                b == "\342\200\250" || b == "\342\200\251" || b == "\342\200\257" ||
                b == "\342\201\237" || b == "\343\200\200" ||
                (substr(b, 1, 2) == "\342\200" && substr(b, 3, 1) ~ /^[\200-\212]$/)) return 3
            return 0
        }
        function skip_space(s, p, n) { while ((n = ws(s, p)) > 0) p += n; return p }
        function trim_end(s, end, start, n) {
            while (end >= start) {
                if (ws(s, end) == 1) end--
                else if (end - 1 >= start && ws(s, end - 1) == 2) end -= 2
                else if (end - 2 >= start && ws(s, end - 2) == 3) end -= 3
                else break
            }
            return end
        }
        function trim(s, start, end) { start = skip_space(s, 1); end = trim_end(s, length(s), start); return substr(s, start, end - start + 1) }
        function line_end(s, p, c) { while (p <= length(s)) { c = substr(s, p, 1); if (c == "\r" || c == "\n") break; p++ } return p }
        function next_line(s, p) { p = line_end(s, p); if (substr(s, p, 2) == "\r\n") return p + 2; return p + 1 }
        function record_end(s, p, c, b) {
            while (p <= length(s)) {
                c = substr(s, p, 1); b = substr(s, p, 3)
                if (c == "\r" || c == "\n" || b == "\342\200\250" || b == "\342\200\251") break
                p++
            }
            return p
        }
        function next_record(s, p, b) {
            p = record_end(s, p); b = substr(s, p, 3)
            if (b == "\342\200\250" || b == "\342\200\251") return p + 3
            if (substr(s, p, 2) == "\r\n") return p + 2
            return p + 1
        }
        function quote_end(s, p, q, j, fallback) {
            # dotenv may backtrack an escaped quote at a valid record tail
            # into the closing quote. A non-escaped quote cannot be body data.
            for (j = p + 1; j <= length(s); j++) if (substr(s, j, 1) == q) {
                if (substr(s, j - 1, 1) != "\\") return quote_tail(s, j + 1) ? j : fallback
                if (quote_tail(s, j + 1)) fallback = j
            }
            return fallback
        }
        function quote_tail(s, p, n, c) {
            while ((n = ws(s, p)) > 0 && record_end(s, p) != p) p += n
            c = substr(s, p, 1); return c == "" || c == "#" || record_end(s, p) == p
        }
        function decoded(s, q) {
            s = trim(s); q = substr(s, 1, 1)
            gsub(/\r\n?/, "\n", s)
            if (length(s) >= 2 && (q == single || q == "\"" || q == "`") && substr(s, length(s), 1) == q) {
                s = substr(s, 2, length(s) - 2)
            }
            # dotenv expands these escapes whenever the value starts with a
            # double quote, including its legal unquoted-fallback form.
            if (q == "\"") { gsub(/\\n/, "\n", s); gsub(/\\r/, "\r", s) }
            return s
        }
        function encoded(s, preferred, q) {
            if (index(s, "\r")) fail()
            if (preferred != "" && !index(s, preferred) &&
                (preferred != "\"" || (!index(s, "\\n") && !index(s, "\\r")))) return preferred s preferred
            q = substr(s, 1, 1)
            if (trim(s) == s && !index(s, "#") && !index(s, "\n") && q != single && q != "\"" && q != "`") return s
            if (!index(s, single)) return single s single
            if (!index(s, "`")) return "`" s "`"
            if (!index(s, "\"") && !index(s, "\\n") && !index(s, "\\r")) return "\"" s "\""
            fail()
        }
        { raw = raw $0 "\n"; records++ }
        END {
            single = sprintf("%c", 39)
            if (records && final_byte != 10) raw = substr(raw, 1, length(raw) - 1)
            if (key !~ /^[A-Za-z0-9_.-]+$/ || operation !~ /^(read|repository|presence|set|migrate|needs-migration)$/) fail()
            cursor = 1
            while (cursor <= length(raw)) {
                line = cursor; p = skip_space(raw, cursor)
                if (substr(raw, p, 1) == "#") { cursor = next_record(raw, p); continue }
                if (substr(raw, p, 6) == "export" && ws(raw, p + 6)) p = skip_space(raw, p + 6)
                if (!match(substr(raw, p), /^[A-Za-z0-9_.-]+/)) { cursor = next_record(raw, line); continue }
                name = substr(raw, p, RLENGTH); p = skip_space(raw, p + RLENGTH)
                separator = substr(raw, p, 1)
                if (separator != "=" && !(separator == ":" && ws(raw, p + 1))) { cursor = next_record(raw, line); continue }
                p++
                # The colon branch consumes at least one whitespace character.
                # dotenv normalizes CRLF into one LF before this step.
                if (separator == ":") p += substr(raw, p, 2) == "\r\n" ? 2 : ws(raw, p)
                while (ws(raw, p) && substr(raw, p, 1) != "\r" && substr(raw, p, 1) != "\n") p += ws(raw, p)
                begin = p; look = skip_space(raw, p); q = substr(raw, look, 1); closing = 0; bounded_record = 0
                if (q == single || q == "\"" || q == "`") closing = quote_end(raw, look, q)
                if (closing && quote_tail(raw, closing + 1)) { begin = look; finish = closing + 1; bounded_record = 1 }
                else {
                    finish = line_end(raw, p)
                    for (j = p; j < finish; j++) if (substr(raw, j, 1) == "#") { finish = j; bounded_record = 1; break }
                    finish = trim_end(raw, finish - 1, begin) + 1
                }
                count++; names[count] = name; starts[count] = begin; ends[count] = finish
                values[count] = decoded(substr(raw, begin, finish - begin)); last[name] = count
                cursor = bounded_record ? next_record(raw, finish) : next_line(raw, finish)
            }
            if (operation == "presence") {
                printf "%d\n", (length(values[last[key]]) > 0)
            } else if (operation == "read" || operation == "repository") {
                result = values[last[key]]
                if (operation == "repository") {
                    result = trim(result)
                    if (result != "" && result !~ /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/) fail()
                }
                printf "%s\n", result
            } else if (operation == "needs-migration") {
                found = 0
                for (i = 1; i <= count; i++) if (names[i] == key && tolower(trim(values[i])) == "mastalee928/payincus") found = 1
                printf "%d\n", found
            } else if (operation == "migrate") {
                result = ""; previous = 1
                for (i = 1; i <= count; i++) if (names[i] == key && tolower(trim(values[i])) == "mastalee928/payincus") {
                    piece = substr(raw, starts[i], ends[i] - starts[i])
                    if (!match(tolower(piece), /mastalee928\/payincus/)) fail()
                    result = result substr(raw, previous, starts[i] - previous) substr(piece, 1, RSTART - 1) \
                        "masta-lee/mastaincus" substr(piece, RSTART + RLENGTH)
                    previous = ends[i]
                }
                printf "%s", result substr(raw, previous)
            } else {
                i = last[key]; preferred = ""
                if (i) {
                    piece = substr(raw, starts[i], ends[i] - starts[i]); q = substr(piece, 1, 1)
                    if (length(piece) >= 2 && (q == single || q == "\"" || q == "`") && substr(piece, length(piece), 1) == q) preferred = q
                    printf "%s%s%s", substr(raw, 1, starts[i] - 1), encoded(ENVIRON["INCUDAL_ENV_WRITE_VALUE"], preferred), substr(raw, ends[i])
                } else {
                    eol = "\n"; p = line_end(raw, 1)
                    if (substr(raw, p, 2) == "\r\n") eol = "\r\n"
                    else if (substr(raw, p, 1) == "\r") eol = "\r"
                    delimiter = raw != "" && substr(raw, length(raw), 1) != "\n" && substr(raw, length(raw), 1) != "\r" ? eol : ""
                    printf "%s%s%s=%s%s", raw, delimiter, key, encoded(ENVIRON["INCUDAL_ENV_WRITE_VALUE"], ""), eol
                }
            }
        }
    '
}

get_env_value() {
    local key="$1"
    [[ -f "$ENV_FILE" ]] || return 0
    env_dotenv_data read "$key"
}

env_file_identity() {
    local metadata digest
    [[ -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || return 1
    metadata="$(stat -c '%d:%i:%u:%g:%a:%h' "$ENV_FILE")" || return 1
    [[ "${metadata##*:}" == 1 ]] || return 1
    digest="$(sha256sum "$ENV_FILE" | awk '{print $1}')" || return 1
    [[ "$digest" =~ ^[a-f0-9]{64}$ ]] || return 1
    printf '%s:%s' "$metadata" "$digest"
}

write_env_atomically() {
    local candidate="$1" expected="$2"
    # The candidate is created beside the original, so rename cannot degrade
    # into a cross-filesystem copy. Failure never truncates the credential file.
    if [[ "$(env_file_identity)" != "$expected" ]] ||
        ! chown --reference="$ENV_FILE" "$candidate" ||
        ! chmod --reference="$ENV_FILE" "$candidate" ||
        { [[ "$(uname -s)" == Linux ]] && ! sync -f "$candidate"; } ||
        [[ "$(env_file_identity)" != "$expected" ]] ||
        ! mv -T -- "$candidate" "$ENV_FILE"; then
        rm -f -- "$candidate"
        printf 'Environment update failed; original configuration retained.\n' >&2
        return 1
    fi
}

set_env_if_missing() {
    local key="$1"
    local value="$2"
    local label="$3"
    local current
    if [[ "$key" == SYSTEM_UPDATE_RELEASE_REPOSITORY || "$key" == INCUDAL_AGENT_RELEASE_REPOSITORY ]]; then
        current="$(env_dotenv_data repository "$key")" || return 1
    else
        current="$(env_dotenv_data presence "$key")" || return 1
        [[ "$current" != 1 ]] || return 0
        [[ "$current" == 0 ]] || return 1
        current=""
    fi
    if [[ -n "$current" ]]; then
        return 0
    fi

    local tmp_file original_state
    original_state="$(env_file_identity)" || return 1
    tmp_file="$(mktemp "${ENV_FILE}.incudal-env.XXXXXX")" || return 1
    if ! env_dotenv_data set "$key" "$value" > "$tmp_file"; then rm -f -- "$tmp_file"; return 1; fi
    write_env_atomically "$tmp_file" "$original_state" || return 1

    log "已自动补充 ${label}: ${key}"
}

set_env_value() {
    local key="$1"
    local value="$2"
    local label="$3"

    local tmp_file original_state
    original_state="$(env_file_identity)" || return 1
    tmp_file="$(mktemp "${ENV_FILE}.incudal-env.XXXXXX")" || return 1
    if ! env_dotenv_data set "$key" "$value" > "$tmp_file"; then rm -f -- "$tmp_file"; return 1; fi
    write_env_atomically "$tmp_file" "$original_state" || return 1

    log "已更新 ${label}: ${key}"
}

get_release_repository_default() {
    local alias="$1" primary="${2-}" configured
    # Respect the effective last primary before inspecting an alias.
    if [[ -n "$primary" ]]; then
        configured="$(env_dotenv_data repository "$primary")" || return 1
        if [[ -n "$configured" ]]; then printf '%s\n' "$configured"; return 0; fi
    fi
    configured="$(env_dotenv_data repository "$alias")" || return 1
    printf '%s\n' "${configured:-$GITHUB_REPO}"
}
migrate_release_repository() {
    local key="$1" tmp_file original_state migration_needed
    [[ -f "$ENV_FILE" ]] || return 0
    migration_needed="$(env_dotenv_data needs-migration "$key")" || return 1
    [[ "$migration_needed" != 0 ]] || return 0
    [[ "$migration_needed" == 1 ]] || return 1
    original_state="$(env_file_identity)" || return 1
    tmp_file="$(mktemp "${ENV_FILE}.incudal-env.XXXXXX")" || return 1
    # Replace only actual retired values, retaining quoting and every other
    # byte. Unmatched files never change identity or announce a migration.
    if ! env_dotenv_data migrate "$key" > "$tmp_file"; then rm -f -- "$tmp_file"; return 1; fi
    if ! cmp -s "$ENV_FILE" "$tmp_file"; then
        write_env_atomically "$tmp_file" "$original_state" || return 1
        log "已迁移退役的 Release 仓库: ${key}"
    fi
    rm -f "$tmp_file"
}

set_env_if_value() {
    local key="$1"
    local expected_current="$2"
    local new_value="$3"
    local label="$4"
    local current
    current="$(get_env_value "$key" && printf '\037')" || return 1
    current="${current%$'\037'}"
    current="${current%$'\n'}"

    if [[ "$current" == "$expected_current" ]]; then
        set_env_value "$key" "$new_value" "$label"
    fi
}

ensure_env_keys() {
    if [[ ! -f "$ENV_FILE" ]]; then
        return 0
    fi
    local system_repository agent_repository generated_env_value
    system_repository="$(get_release_repository_default GITHUB_REPO SYSTEM_UPDATE_RELEASE_REPOSITORY)" || return 1
    agent_repository="$(get_release_repository_default GITHUB_REPOSITORY INCUDAL_AGENT_RELEASE_REPOSITORY)" || return 1

    set_env_if_missing "NODE_ENV" "production" "运行环境" || return "$?"
    set_env_if_missing "HOST" "127.0.0.1" "后端监听地址" || return "$?"
    set_env_if_missing "PORT" "${DEFAULT_PORT}" "后端监听端口" || return "$?"
    set_env_if_value "PORT" "3000" "${DEFAULT_PORT}" "后端监听端口（迁移旧版前端端口）" || return "$?"
    set_env_if_missing "TRUST_PROXY" "true" "信任本机 Nginx 代理头" || return "$?"
    generated_env_value="$(gen_secret 48)" || return "$?"
    set_env_if_missing "JWT_SECRET" "$generated_env_value" "JWT 密钥" || return "$?"
    generated_env_value="$(gen_secret 48)" || return "$?"
    set_env_if_missing "COOKIE_SECRET" "$generated_env_value" "Cookie 密钥" || return "$?"
    generated_env_value="$(openssl rand -base64 32)" || return "$?"
    set_env_if_missing "ENCRYPTION_KEY" "$generated_env_value" "敏感数据加密密钥" || return "$?"
    set_env_if_missing "ADMIN_EMAIL" "admin@payincus.local" "管理员初始邮箱" || return "$?"
    generated_env_value="$(gen_password 16)" || return "$?"
    set_env_if_missing "ADMIN_PASSWORD" "$generated_env_value" "管理员初始密码" || return "$?"
    local current_admin_password
    current_admin_password="$(get_env_value "ADMIN_PASSWORD" && printf '\037')" || return 1
    current_admin_password="${current_admin_password%$'\037'}"
    current_admin_password="${current_admin_password%$'\n'}"
    if [[ -z "$current_admin_password" || "$current_admin_password" == "admin123" ]]; then
        generated_env_value="$(gen_password 16)" || return "$?"
        set_env_value "ADMIN_PASSWORD" "$generated_env_value" "管理员初始密码" || return "$?"
    fi
    set_env_if_missing "SERVE_STATIC_CLIENT" "false" "后端静态文件服务开关" || return "$?"
    set_env_if_missing "VITE_API_BASE_URL" "/api" "前端 API 基础路径" || return "$?"
    set_env_if_missing "VITE_CUSTOMER_BASE_URL" "" "管理后台生成客户链接的前端地址" || return "$?"
    set_env_if_missing "VITE_ADMIN_BASE_URL" "" "客户前端管理后台地址" || return "$?"
    set_env_if_missing "SYSTEM_UPDATE_ALLOWED_ADMIN_IDS" "" "允许执行在线更新的管理员 ID" || return "$?"
    set_env_if_missing "SYSTEM_UPDATE_LOG_DIR" "${INSTALL_DIR}/update-logs" "在线更新日志目录" || return "$?"
    set_env_if_missing "SYSTEM_UPDATE_STARTED_BY_USER_ID" "" "命令行更新任务发起管理员 ID" || return "$?"
    set_env_if_missing "SYSTEM_UPDATE_RELEASE_REPOSITORY" "$system_repository" "在线更新 GitHub Release 仓库" || return "$?"
    set_env_if_missing "SYSTEM_UPDATE_RELEASE_TOKEN" "" "在线更新私有 Release Token" || return "$?"
    set_env_if_missing "SYSTEM_UPDATE_APPLY_MODE" "auto" "在线更新应用模式" || return "$?"
    set_env_if_missing "INCUDAL_AGENT_RELEASE_REPOSITORY" "$agent_repository" "Agent GitHub Release 仓库" || return "$?"
    local repository_key
    for repository_key in SYSTEM_UPDATE_RELEASE_REPOSITORY INCUDAL_AGENT_RELEASE_REPOSITORY GITHUB_REPO GITHUB_REPOSITORY; do
        migrate_release_repository "$repository_key" || return "$?"
    done
    set_env_if_missing "INCUDAL_AGENT_RELEASE_TOKEN" "${INCUDAL_AGENT_RELEASE_TOKEN:-}" "Agent GitHub Release Token" || return "$?"
    set_env_if_missing "INCUDAL_AGENT_RELEASE_DIR" "" "Agent 本地 Release 目录" || return "$?"
    set_env_if_missing "INCUDAL_AGENT_BINARY_URL" "" "Agent 自定义二进制地址" || return "$?"
    set_env_if_missing "INCUDAL_AGENT_BINARY_SHA256" "" "Agent 自定义二进制 SHA256" || return "$?"
    set_env_if_missing "COOKIE_SAME_SITE" "" "Cookie SameSite 策略" || return "$?"
    set_env_if_missing "COOKIE_SECURE" "" "Cookie Secure 开关" || return "$?"
    set_env_if_missing "COOKIE_DOMAIN" "" "Cookie 共享域（必须留空以隔离客户面板和管理后台）" || return "$?"

    local frontend_url
    frontend_url="$(get_env_value "FRONTEND_URL")" || return "$?"
    if [[ -n "$frontend_url" ]]; then
        set_env_if_missing "SITE_URL" "$frontend_url" "站点公网地址" || return "$?"
        set_env_if_missing "PAYMENT_CALLBACK_BASE_URL" "$frontend_url" "支付回调公网地址" || return "$?"
    fi

    # root-run OTA units read this file.  Keep it readable by the service group,
    # but never writable by the service account (prevents NODE_OPTIONS/env injection).
    chown "root:${RUN_USER}" "$ENV_FILE" 2>/dev/null || return "$?"
    chmod 640 "$ENV_FILE" || return "$?"
}

# ========================== 系统检查 ==========================
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        error "请以 root 权限运行此部署脚本！"
        error "用法: sudo bash $0"
        exit 1
    fi
}

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "无法检测操作系统（/etc/os-release 不存在）"
        exit 1
    fi

    source /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_CODENAME="${VERSION_CODENAME:-unknown}"
    ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)

    # 仅支持 Ubuntu 和 Debian
    if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" ]]; then
        error "不支持的操作系统: ${OS_ID}"
        error "本脚本仅支持 Ubuntu 和 Debian 系统"
        exit 1
    fi

    # 版本检查
    case "$OS_ID" in
        ubuntu)
            local major="${OS_VERSION%%.*}"
            if [[ "$major" -lt 22 ]] 2>/dev/null; then
                error "Ubuntu 版本过低 (${OS_VERSION})，最低要求 Ubuntu 22.04"
                exit 1
            fi
            ;;
        debian)
            local major="${OS_VERSION%%.*}"
            if [[ "$major" -lt 12 ]] 2>/dev/null; then
                error "Debian 版本过低 (${OS_VERSION})，最低要求 Debian 12 (Bookworm)"
                exit 1
            fi
            ;;
    esac

    # 架构检查
    case "$ARCH" in
        amd64|x86_64) ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *)
            error "不支持的系统架构: ${ARCH}"
            error "仅支持 amd64 (x86_64) 和 arm64 (aarch64)"
            exit 1
            ;;
    esac

    log "系统检测通过: ${OS_ID} ${OS_VERSION} (${ARCH})"
}

# ========================== 显示横幅 ==========================
show_banner() {
    clear 2>/dev/null || true
    echo ""
    echo -e "${CYAN}  ╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}  ║                                                  ║${NC}"
    echo -e "${CYAN}  ║          ${BOLD}PayIncus 面板一键部署脚本${NC}${CYAN}               ║${NC}"
    echo -e "${CYAN}  ║          ${DIM}Pre-built Package Deploy${NC}${CYAN}                ║${NC}"
    echo -e "${CYAN}  ║                                                  ║${NC}"
    echo -e "${CYAN}  ╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${DIM}版本: ${SCRIPT_VERSION}  |  仓库: ${GITHUB_REPO}${NC}"
    echo ""
}

# ========================== 检查已有安装 ==========================
check_existing() {
    if [[ -d "$INSTALL_DIR" && (
        -f "${INSTALL_DIR}/server/dist/app.js" ||
        -f "${INSTALL_DIR}/current/server/dist/app.js"
    ) ]]; then
        return 0  # 已安装
    fi
    return 1  # 未安装
}

has_existing_installation_identity() {
    local identity_path
    for identity_path in "${INSTALLATION_IDENTITY_PATHS[@]}"; do
        [[ ! -e "$identity_path" && ! -L "$identity_path" ]] || return 0
    done
    [[ ! -L "$INSTALLATION_GATEWAY_STATE_DIR" ]] || return 0
    [[ ! -e "$INSTALLATION_GATEWAY_STATE_DIR/owner.json" && ! -L "$INSTALLATION_GATEWAY_STATE_DIR/owner.json" ]] || return 0
    for identity_path in \
        "$INSTALLATION_GATEWAY_STATE_DIR"/*/identity.json \
        "$INSTALLATION_GATEWAY_STATE_DIR"/*/bootstrap.json \
        "$INSTALLATION_GATEWAY_STATE_DIR"/*/transport/gateway-identity.json \
        "$INSTALLATION_GATEWAY_STATE_DIR"/*/auth/gateway-auth.json; do
        [[ ! -e "$identity_path" && ! -L "$identity_path" ]] || return 0
    done
    return 1
}

is_atomic_layout() {
    [[ -L "${INSTALL_DIR}/current" && -f "${INSTALL_DIR}/current/server/dist/app.js" ]]
}

# ========================== 安装 Node.js ==========================
install_nodejs() {
    step "安装 Node.js ${NODE_MAJOR}..."

    # systemd executes /usr/bin/node with ProtectHome enabled. A Node binary
    # from nvm or a CI tool cache does not satisfy that runtime requirement.
    if [[ -x /usr/bin/node ]]; then
        local current_ver
        current_ver=$(/usr/bin/node -v 2>/dev/null | sed 's/v//')
        if /usr/bin/node -e 'const [a,b,c]=process.versions.node.split(".").map(Number);process.exit(a===24&&(b>22||b===22&&c>=3)?0:1)'; then
            log "系统 Node.js $(/usr/bin/node -v) 已满足安全补丁基线，跳过"
            return 0
        fi
        info "系统 Node.js 版本较低 ($(/usr/bin/node -v))，将升级到 v${NODE_MAJOR}"
    fi

    # Configure the signed repository directly; no mutable remote root script.
    info "添加 NodeSource APT 源..."
    apt-get install -y -qq ca-certificates curl gnupg >/dev/null 2>&1 || return "$?"
    local node_key
    node_key=$(mktemp) || return "$?"
    if ! curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 15 --max-time 60 https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key -o "$node_key" ||
       [[ $(sha256sum "$node_key" | awk '{print $1}') != b42e0321dabdc24e892115da705cf061167eac12a317f23d329862d0aa0a271d ]]; then
        rm -f "$node_key"; error 'NodeSource 签名身份校验失败'; return 1
    fi
    install -d -o root -g root -m 0755 /etc/apt/keyrings || return "$?"
    gpg --batch --yes --dearmor -o /etc/apt/keyrings/nodesource.gpg "$node_key" || return "$?"
    rm -f "$node_key" || return "$?"
    chmod 0644 /etc/apt/keyrings/nodesource.gpg || return "$?"
    printf 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_%s.x nodistro main\n' "$NODE_MAJOR" > /etc/apt/sources.list.d/nodesource.list || return "$?"
    apt-get update -qq >/dev/null 2>&1 || return "$?"
    apt-get install -y -qq nodejs >/dev/null 2>&1 || return "$?"

    [[ -x /usr/bin/node ]] || { error "系统 Node.js 安装失败，缺少 /usr/bin/node"; return 1; }
    /usr/bin/node -e 'const [a,b,c]=process.versions.node.split(".").map(Number);process.exit(a===24&&(b>22||b===22&&c>=3)?0:1)' || { error '系统 Node.js 未达到 24.22.3 安全补丁基线'; return 1; }
    log "系统 Node.js $(/usr/bin/node -v) 安装完成"
}

# ========================== 安装 pnpm ==========================
install_pnpm() {
    step "安装 pnpm ${PNPM_VERSION}..."

    if command -v pnpm &>/dev/null; then
        log "pnpm $(pnpm --version) 已安装，跳过"
        return 0
    fi

    if command -v corepack &>/dev/null; then
        corepack enable >/dev/null 2>&1 || return "$?"
        corepack prepare "pnpm@${PNPM_VERSION}" --activate >/dev/null 2>&1 || return "$?"
    else
        npm install -g "pnpm@${PNPM_VERSION}" >/dev/null 2>&1 || return "$?"
    fi

    if ! command -v pnpm &>/dev/null; then
        error "pnpm 安装失败，请检查 Node.js/Corepack 环境"
        exit 1
    fi

    log "pnpm $(pnpm --version) 安装完成"
}

# ========================== 安装系统工具 ==========================
install_system_tools() {
    step "安装基础系统工具..."

    apt-get install -y -qq ca-certificates curl git sudo tar python3 openssh-client openssh-server wireguard-tools locales >/dev/null 2>&1 || return "$?"

    # apt 的错误此前被完全吞掉：任何一个基础工具没装上，后面都会以难以定位的方式失败
    # （例如 git 缺失会让部署目录不是 Git 工作区，只留下一句 warn）。这里显式验一遍。
    local missing=""
    for _tool in curl git sudo tar python3 ssh ssh-keygen wg locale localedef; do
        command -v "$_tool" &>/dev/null || missing="${missing} ${_tool}"
    done
    if [[ -n "$missing" ]]; then
        error "基础系统工具安装失败，缺少：${missing# }。请先修复 apt 源后重试。"
        exit 1
    fi

    log "基础系统工具安装完成"
}

# ========================== 安装 PostgreSQL ==========================
ensure_postgresql_running() {
    systemctl enable postgresql >/dev/null 2>&1 || return "$?"
    systemctl start postgresql || return "$?"
    local attempt
    for attempt in $(seq 1 30); do
        if pg_isready -h 127.0.0.1 -p 5432 -q; then
            return 0
        fi
        sleep 1 || return "$?"
    done
    error "PostgreSQL 在 127.0.0.1:5432 未就绪，请检查 postgresql 服务及集群配置后重试"
    return 1
}

install_postgresql() {
    step "安装 PostgreSQL ${PG_VERSION}..."

    if command -v psql &>/dev/null; then
        local pg_ver
        pg_ver=$(psql --version 2>/dev/null | awk '{print $3}' | cut -d. -f1)
        if [[ "$pg_ver" -ge "$PG_VERSION" ]] 2>/dev/null; then
            info "PostgreSQL ${pg_ver} 已安装，检查服务是否就绪"
            ensure_postgresql_running
            return "$?"
        fi
    fi

    # 添加 PostgreSQL 官方 APT 源
    info "添加 PostgreSQL 官方 APT 源..."
    apt-get install -y -qq gnupg lsb-release >/dev/null 2>&1 || return "$?"

    local pg_key
    pg_key=$(mktemp) || return "$?"
    if ! curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 15 --max-time 60 \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc -o "$pg_key" ||
       [[ $(sha256sum "$pg_key" | awk '{print $1}') != 0144068502a1eddd2a0280ede10ef607d1ec592ce819940991203941564e8e76 ]]; then
        rm -f "$pg_key"; error 'PostgreSQL 软件源签名身份校验失败'; return 1
    fi
    install -d -o root -g root -m 0755 /etc/apt/keyrings || return "$?"
    if ! gpg --batch --yes --dearmor -o /etc/apt/keyrings/postgresql.gpg "$pg_key"; then
        rm -f "$pg_key"; error 'PostgreSQL 软件源签名密钥无效'; return 1
    fi
    rm -f "$pg_key" || return "$?"
    # APT verifies repositories as _apt, including when the caller uses umask 077.
    # This is a public verification key; keep private runtime files restricted.
    chmod 0644 /etc/apt/keyrings/postgresql.gpg || return "$?"

    echo "deb [signed-by=/etc/apt/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt ${OS_CODENAME}-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list || return "$?"

    apt-get update -qq >/dev/null 2>&1 || return "$?"
    apt-get install -y -qq "postgresql-${PG_VERSION}" >/dev/null 2>&1 || return "$?"

    # 确保服务启动
    ensure_postgresql_running || return "$?"

    log "PostgreSQL ${PG_VERSION} 安装完成"
}

# ========================== 安装 Redis ==========================
install_redis() {
    step "安装 Redis..."

    if command -v redis-server &>/dev/null; then
        log "Redis $(redis-server --version | awk '{print $3}' | sed 's/v=//') 已安装，跳过"
        return 0
    fi

    apt-get install -y -qq redis-server >/dev/null 2>&1 || return "$?"

    # 确保服务启动
    systemctl enable redis-server >/dev/null 2>&1 || return "$?"
    systemctl start redis-server || return "$?"

    log "Redis 安装完成"
}

# ========================== 手动包目录 ==========================
readonly MANUAL_PKG_DIR="/tmp/incudal"

# ========================== 获取最新版本号（快速尝试） ==========================
get_latest_version() {
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local response=""
    local version=""

    # 5 秒超时速查，不阻塞
    response=$(curl -sL --connect-timeout 5 --max-time 8 "$api_url" 2>/dev/null) || true

    if [[ -n "$response" ]]; then
        version=$(echo "$response" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/' || true)
    fi

    echo "$version"
}

# ========================== 自动下载产物包 ==========================
download_release() {
    local version="$1"
    local filename="incudal-${version}-linux-${ARCH}.tar.gz"
    local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/${filename}"
    local tmp_file="/tmp/${filename}"
    local checksum_url="${download_url}.sha256"
    local checksum_file="${tmp_file}.sha256"

    info "下载地址: ${download_url}"

    if curl --proto '=https' --proto-redir '=https' -fSL --progress-bar --connect-timeout 15 --max-time 600 \
        "$download_url" -o "$tmp_file" 2>/dev/null && \
        curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 15 --max-time 60 \
        "$checksum_url" -o "$checksum_file" 2>/dev/null && \
        { curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 15 --max-time 60 "$download_url.sig" -o "$tmp_file.sig" 2>/dev/null || rm -f "$tmp_file.sig"; } && \
        verify_release_checksum "$tmp_file" && verify_release_publisher "$tmp_file"; then
        local file_size
        file_size=$(du -h "$tmp_file" | cut -f1 || true)
        log "下载和 SHA256 校验完成 (${file_size})"
        echo "$tmp_file"
        return 0
    fi

    rm -f "$tmp_file" "$checksum_file" "$tmp_file.sig" 2>/dev/null || true
    return 1
}

verify_release_checksum() {
    local tar_file="$1"
    local checksum_file="${tar_file}.sha256"
    local expected=""
    local actual=""

    if [[ ! -f "$checksum_file" ]]; then
        error "缺少校验文件: ${checksum_file}"
        error "请从同一 GitHub Release 下载对应的 .sha256 文件"
        return 1
    fi

    expected=$(grep -Eo '^[A-Fa-f0-9]{64}' "$checksum_file" | head -n1 || true)
    if [[ ! "$expected" =~ ^[A-Fa-f0-9]{64}$ ]]; then
        error "SHA256 文件格式无效: ${checksum_file}"
        return 1
    fi

    actual=$(sha256sum "$tar_file" | awk '{print $1}')
    if [[ "${actual,,}" != "${expected,,}" ]]; then
        error "产物包 SHA256 校验失败: $(basename "$tar_file")"
        return 1
    fi

    return 0
}

validate_release_archive() {
    local tar_file="$1"
    local entry=""

    if ! tar -tzf "$tar_file" >/dev/null 2>&1; then
        error "产物包不是有效的 tar.gz 文件: ${tar_file}"
        return 1
    fi

    while IFS= read -r entry; do
        entry="${entry#./}"
        if [[ "$entry" == /* || "$entry" == ".." || "$entry" == ../* || "$entry" == */../* || "$entry" == */.. ]]; then
            error "产物包包含不安全路径: ${entry}"
            return 1
        fi
    done < <(tar -tzf "$tar_file")

    return 0
}

verify_release_publisher() {
    local file="$1" name version architecture signature work actual legacy_version=""
    VERIFIED_LEGACY_DATABASE_PACKAGE=""
    name=$(basename "$file")
    [[ "$name" =~ ^incudal-(.+)-linux-(amd64|arm64)\.tar\.gz$ ]] || return 1
    version="${BASH_REMATCH[1]}"; architecture="${BASH_REMATCH[2]}"
    [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ || "$version" =~ ^preview-[a-f0-9]{7}$ ]] || return 1
    actual=$(sha256sum "$file" | awk '{print $1}')
    # Only these exact public legacy bytes remain eligible without a signature.
    case "$name:$actual" in
        incudal-v1.8.13-linux-amd64.tar.gz:f4b1e4274d7d9d3beeff775346bac900a540d47eb57d6a9c4d24cefed7bd6d84|incudal-v1.8.13-linux-arm64.tar.gz:d9114de77354731f8385a302ddb3c549a7617c738eaa85f2705326e0c37e072b|incudal-v1.8.14-linux-amd64.tar.gz:9cfd05408aa6ddd0ec0d7872099c2a0b550d96bce2beb2a063f220f55dd85ee4|incudal-v1.8.14-linux-arm64.tar.gz:03bfb27d636d628048761a44e3bdca8f5d55b1f33183e2466465dfdd98657eaf) legacy_version="$version"; if [[ ! -f "$file.sig" ]]; then VERIFIED_LEGACY_DATABASE_PACKAGE="$legacy_version"; return 0; fi ;;
    esac
    [[ -f "$file.sig" ]] || { error '缺少独立发布签名'; return 1; }
    signature=$(tr -d '\n\r' < "$file.sig")
    [[ "$signature" =~ ^[A-Za-z0-9+/]{86}==$ ]] || return 1
    work=$(mktemp -d)
    printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00' > "$work/public.der"
    printf '%s' 'y6C9aLon6OtgHPp5KPVDpxoNha95YptW03o4Dp2djQA=' | openssl base64 -d -A >> "$work/public.der"
    printf '%s' "$signature" | openssl base64 -d -A > "$work/signature"
    printf 'payincus/panel-package/v1\n%s\nlinux-%s\n%s' "${version#v}" "$architecture" "$actual" > "$work/message"
    local status=0
    openssl pkeyutl -verify -pubin -keyform DER -rawin -inkey "$work/public.der" -sigfile "$work/signature" -in "$work/message" >/dev/null 2>&1 || status=$?
    rm -rf -- "$work"
    [[ $status -eq 0 ]] || return 1
    VERIFIED_LEGACY_DATABASE_PACKAGE="$legacy_version"
}

# ========================== 扫描手动放置的产物包 ==========================
scan_manual_package() {
    local found=""

    if [[ ! -d "$MANUAL_PKG_DIR" ]]; then
        return 1
    fi

    # 优先匹配当前架构的包
    found=$(find "$MANUAL_PKG_DIR" -maxdepth 1 -name "incudal-*-linux-${ARCH}.tar.gz" -type f 2>/dev/null | head -n1 || true)

    # 退而匹配任意 incudal tar.gz
    if [[ -z "$found" ]]; then
        found=$(find "$MANUAL_PKG_DIR" -maxdepth 1 -name "incudal-*.tar.gz" -type f 2>/dev/null | head -n1 || true)
    fi

    if [[ -n "$found" ]]; then
        echo "$found"
        return 0
    fi

    return 1
}

# ========================== 等待用户放置产物包 ==========================
wait_for_manual_package() {
    echo "" >&2
    divider
    echo -e "  ${YELLOW}${BOLD}⚠ 自动获取产物包失败${NC}" >&2
    echo -e "  ${DIM}（仓库可能是私有的，或网络无法连接 GitHub）${NC}" >&2
    divider
    echo "" >&2
    echo -e "  ${BOLD}请手动下载产物包并放到以下目录：${NC}" >&2
    echo "" >&2
    echo -e "  ${CYAN}${BOLD}${MANUAL_PKG_DIR}/${NC}" >&2
    echo "" >&2
    echo -e "  ${BOLD}下载地址：${NC}" >&2
    echo -e "  ${CYAN}https://github.com/${GITHUB_REPO}/releases${NC}" >&2
    echo "" >&2
    echo -e "  ${BOLD}所需文件名格式：${NC}" >&2
    echo -e "  ${GREEN}incudal-vX.Y.Z-linux-${ARCH}.tar.gz${NC}" >&2
    echo -e "  ${GREEN}incudal-vX.Y.Z-linux-${ARCH}.tar.gz.sha256${NC}" >&2
    echo -e "  ${GREEN}incudal-vX.Y.Z-linux-${ARCH}.tar.gz.sig${NC}" >&2
    echo "" >&2
    echo -e "  ${DIM}提示: 可使用 scp、wget、rz 等方式将文件传到服务器${NC}" >&2
    echo -e "  ${DIM}例如: scp incudal-v1.0.0-linux-${ARCH}.tar.gz root@服务器IP:${MANUAL_PKG_DIR}/${NC}" >&2
    divider
    echo "" >&2

    # 创建目录
    mkdir -p "$MANUAL_PKG_DIR"

    # 轮询等待文件出现
    local wait_count=0
    local max_wait=600  # 最多等 10 分钟（含上传时间）
    local spin_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local MIN_SIZE_KB=10240  # 产物包至少 10MB

    while true; do
        # 尝试扫描
        local pkg_file=""
        pkg_file=$(scan_manual_package) || true

        if [[ -n "$pkg_file" ]]; then
            # 检测到文件，等待上传完成（文件大小稳定）
            echo "" >&2
            info "检测到文件: $(basename "$pkg_file")"
            info "等待上传完成..."

            local stable_count=0
            local last_size=0

            while true; do
                local current_size
                current_size=$(stat -c%s "$pkg_file" 2>/dev/null || echo "0")
                local current_size_human
                current_size_human=$(du -h "$pkg_file" 2>/dev/null | cut -f1 || echo "?")

                if [[ "$current_size" -eq "$last_size" && "$current_size" -gt 0 ]]; then
                    stable_count=$((stable_count + 1))
                else
                    stable_count=0
                    last_size="$current_size"
                fi

                # 连续 3 次（9 秒）大小不变，认为上传完成
                if [[ $stable_count -ge 3 ]]; then
                    if [[ ! -f "${pkg_file}.sha256" ]]; then
                        info "已收到产物包，继续等待对应的 $(basename "${pkg_file}.sha256")..."
                        stable_count=0
                        sleep 3
                        continue
                    fi
                    if [[ ! -f "${pkg_file}.sig" ]]; then
                        info "等待独立发布签名 $(basename "${pkg_file}.sig")..."
                        stable_count=0
                        sleep 3
                        continue
                    fi

                    # 检查最小文件大小
                    local size_kb=$((current_size / 1024))
                    if [[ $size_kb -lt $MIN_SIZE_KB ]]; then
                        warn "文件过小 (${current_size_human})，产物包通常 >100MB，可能不完整"
                        warn "如确认无误，请将文件删除后重新放置"
                        # 继续等待
                        stable_count=0
                        last_size=0
                        sleep 3
                        continue
                    fi

                    log "上传完成！文件大小: ${current_size_human}"
                    echo "$pkg_file"
                    return 0
                fi

                printf "\r  ${CYAN}⏳${NC} 上传中... 当前大小: ${current_size_human}  " >&2
                sleep 3
                wait_count=$((wait_count + 3))

                if [[ $wait_count -ge $max_wait ]]; then
                    echo "" >&2
                    error "等待超时 (${max_wait}s)，请重新运行脚本"
                    return 1
                fi
            done
        fi

        # 显示等待动画（输出到 stderr）
        local spin_idx=$((wait_count % ${#spin_chars}))
        local spin_char="${spin_chars:$spin_idx:1}"
        printf "\r  ${CYAN}${spin_char}${NC} 等待产物包... (已等待 %ds，输入 Ctrl+C 取消)  " "$wait_count" >&2

        sleep 2
        wait_count=$((wait_count + 2))

        if [[ $wait_count -ge $max_wait ]]; then
            echo "" >&2
            error "等待超时 (${max_wait}s)，请重新运行脚本"
            return 1
        fi
    done
}

# ========================== 统一入口：获取产物包 ==========================
obtain_release() {
    step "获取 PayIncus 产物包..."

    # ---- 阶段 0：检查是否已有手动放置的包 ----
    local existing_pkg=""
    existing_pkg=$(scan_manual_package) || true
    if [[ -n "$existing_pkg" ]]; then
        log "检测到手动放置的产物包: $(basename "$existing_pkg")"
        echo "$existing_pkg"
        return 0
    fi

    # ---- 阶段 1：尝试 API 自动获取版本号 ----
    info "正在查询最新版本（5 秒超时）..."
    local version=""
    version=$(get_latest_version)

    if [[ -n "$version" ]]; then
        info "最新版本: ${version}"

        # ---- 阶段 2：尝试自动下载 ----
        local tar_file=""
        tar_file=$(download_release "$version") || true

        if [[ -n "$tar_file" && -f "$tar_file" ]]; then
            echo "$tar_file"
            return 0
        fi

        warn "自动下载失败（文件可能不存在或网络受限）"
    else
        warn "自动获取版本号失败（仓库可能是私有的）"
    fi

    # ---- 阶段 3：引导用户手动放置包 ----
    local manual_file=""
    manual_file=$(wait_for_manual_package) || return 1
    echo "$manual_file"
    return 0
}

# ========================== 解压安装 ==========================
install_release() {
    local tar_file="$1"
    local is_upgrade="${2:-false}"
    RELEASE_VERIFIED_THIS_RUN=false
    VERIFIED_LEGACY_DATABASE_PACKAGE=""

    step "安装产物包..."

    verify_release_checksum "$tar_file" || return 1
    verify_release_publisher "$tar_file" || return 1
    validate_release_archive "$tar_file" || return 1
    install_verified_root_helpers_from_archive "$tar_file" || return 1

    # 创建安装目录
    mkdir -p "$INSTALL_DIR" || return "$?"
    # Existing installations may still be service-owned.  Seal ownership
    # before root extracts over the tree to avoid pre-existing symlink/write
    # races during an upgrade.
    /usr/local/libexec/incudal/incudal-online-task harden || return "$?"

    if [[ "$is_upgrade" == "true" ]]; then
        # 升级模式：先备份当前版本
        info "备份当前版本..."
        local backup_dir
        backup_dir="${INSTALL_DIR}.bak.$(date +%Y%m%d%H%M%S)" || return "$?"
        [[ ! -e "$backup_dir" && ! -L "$backup_dir" ]] || { error "当前版本备份路径已存在，原数据保持；请稍后重试。"; return 1; }
        cp -r "$INSTALL_DIR" "$backup_dir" || return "$?"
        info "备份已保存到: ${backup_dir}"

        # 保留 .env 文件和证书目录
        local env_backup=""
        local certs_backup=""
        if [[ -f "${INSTALL_DIR}/.env" ]]; then
            env_backup=$(mktemp) || return "$?"
            cp -a "${INSTALL_DIR}/.env" "$env_backup" || return "$?"
        fi
        if [[ -d "${INSTALL_DIR}/server/certs" ]]; then
            certs_backup=$(mktemp -d) || return "$?"
            cp -a "${INSTALL_DIR}/server/certs" "$certs_backup/" || return "$?"
        fi

        # 清理旧文件（保留 .env 和 certs）
        rm -rf "${INSTALL_DIR}/client" "${INSTALL_DIR}/server/dist" "${INSTALL_DIR}/server/node_modules" || return "$?"

        # 解压新版本
        tar -xzf "$tar_file" -C "$INSTALL_DIR" --strip-components=0 || return "$?"

        # 恢复 .env 和证书
        if [[ -n "$env_backup" ]]; then
            [[ -f "$env_backup" && ! -L "$env_backup" ]] || { error "原环境备份缺失或不是普通文件，停止后续配置。"; return 1; }
            local env_restore
            env_restore=$(mktemp "$INSTALL_DIR/.env.restore.XXXXXXXX") || return "$?"
            cp -a "$env_backup" "$env_restore" || return "$?"
            mv -fT -- "$env_restore" "${INSTALL_DIR}/.env" || return "$?"
            rm -f "$env_backup" || return "$?"
        fi
        if [[ -n "$certs_backup" ]]; then
            [[ -d "$certs_backup/certs" && ! -L "$certs_backup/certs" ]] || { error "原证书备份缺失或目录无效，停止后续配置。"; return 1; }
            local certs_restore certs_retained restore_status
            certs_restore=$(mktemp -d "$INSTALL_DIR/server/.certs.restore.XXXXXXXX") || return "$?"
            cp -a "$certs_backup/certs/." "$certs_restore/" || return "$?"
            certs_retained=$(mktemp -d "$INSTALL_DIR/server/.certs.retained.XXXXXXXX") || return "$?"
            rmdir -- "$certs_retained" || return "$?"
            mv -T -- "${INSTALL_DIR}/server/certs" "$certs_retained" || return "$?"
            if mv -T -- "$certs_restore" "${INSTALL_DIR}/server/certs"; then
                rm -rf "$certs_retained" "$certs_backup" || return "$?"
            else
                restore_status=$?
                mv -T -- "$certs_retained" "${INSTALL_DIR}/server/certs" || {
                    error "证书目录还原未完成，原证书保留在受限临时目录；停止后续配置。"
                    return 1
                }
                return "$restore_status"
            fi
        fi
    else
        # 全新安装
        tar -xzf "$tar_file" -C "$INSTALL_DIR" --strip-components=0 || return "$?"
    fi

    # 清理下载的临时文件
    rm -f "$tar_file" "${tar_file}.sha256" "${tar_file}.sig" || return "$?"

    # 创建证书目录
    mkdir -p "${INSTALL_DIR}/server/certs" || return "$?"

    # The fixed helper came directly from the checksum-verified archive.  Use
    # its non-executing harden action before any service account can modify the
    # extracted code tree.
    /usr/local/libexec/incudal/incudal-online-task harden || return "$?"

    log "产物包安装完成" || return "$?"
    RELEASE_VERIFIED_THIS_RUN=true
}

# ========================== 配置 Git 在线更新元数据 ==========================
configure_git_metadata() {
    step "配置 Git 在线更新元数据..."

    if ! command -v git &>/dev/null; then
        warn "git 未安装，后台在线更新将不可用"
        return 0
    fi

    cd "$INSTALL_DIR" || return "$?"

    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        git remote get-url origin >/dev/null 2>&1 && \
            git remote set-url origin "https://github.com/${GITHUB_REPO}.git" || \
            git remote add origin "https://github.com/${GITHUB_REPO}.git" || return "$?"
    else
        git init -q || return "$?"
        git remote add origin "https://github.com/${GITHUB_REPO}.git" 2>/dev/null || \
            git remote set-url origin "https://github.com/${GITHUB_REPO}.git" 2>/dev/null || return "$?"
    fi

    # Git creates executable sample hooks; root OTA rejects executable hooks.
    # Samples are documentation only, so keep them without execute permission.
    if [[ -d "${INSTALL_DIR}/.git/hooks" ]]; then
        find "${INSTALL_DIR}/.git/hooks" -type f -name '*.sample' -exec chmod a-x {} + || return "$?"
    fi

    git config --global --add safe.directory "$INSTALL_DIR" 2>/dev/null || true
    sudo -u "$RUN_USER" HOME="$INSTALL_DIR" git config --global --add safe.directory "$INSTALL_DIR" 2>/dev/null || true
    if git fetch --tags --force --quiet origin; then
        log "Git release tags 已同步，后台在线更新可用"
    else
        warn "Git tags 同步失败，后台在线更新检查可能暂时不可用；可稍后在 ${INSTALL_DIR} 执行 git fetch --tags"
    fi
}

# ========================== 创建系统用户 ==========================
create_user() {
    step "配置系统用户..."

    if id "$RUN_USER" &>/dev/null; then
        log "用户 ${RUN_USER} 已存在，跳过"
    else
        useradd --system --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin "$RUN_USER" || return "$?"
        log "系统用户 ${RUN_USER} 创建完成"
    fi

    # 创建 npm 缓存目录（npx/prisma 需要可写的 home 目录）
    mkdir -p "${INSTALL_DIR}/.npm" || return "$?"
    mkdir -p "${INSTALL_DIR}/.cache" || return "$?"
    [[ ! -L /var/lib/incudal-images ]] || { error '镜像库目录不能是符号链接'; return 1; }
    install -d -o "$RUN_USER" -g "$RUN_USER" -m 0750 /var/lib/incudal-images || return "$?"

    # Nginx runs as www-data and must be able to traverse the install root
    # to serve client/dist while .env stays owner-only below.
    for mutable in \
        .npm .cache .incudal-update-downloads update-logs \
        agent-release; do
        if [[ -e "${INSTALL_DIR}/${mutable}" ]]; then
            chown -R "${RUN_USER}:${RUN_USER}" "${INSTALL_DIR}/${mutable}" || return "$?"
        fi
    done
    chmod 751 "$INSTALL_DIR" || return "$?"
    if [[ -f "$ENV_FILE" ]]; then
        chown "root:${RUN_USER}" "$ENV_FILE" || return "$?"
        chmod 640 "$ENV_FILE" || return "$?"
    fi
}

# ========================== 生成面板客户端证书 ==========================
generate_panel_cert() {
    local cert_dir="${INSTALL_DIR}/server/certs"
    local cert_file="${cert_dir}/client.crt"
    local key_file="${cert_dir}/client.key"

    step "配置面板客户端证书..."

    # 幂等性：证书已存在则跳过
    if [[ -f "$cert_file" && -f "$key_file" ]]; then
        log "面板客户端证书已存在，跳过生成"
        return 0
    fi

    mkdir -p "$cert_dir" || return "$?"

    # 生成自签名客户端证书（用于面板与 Incus API 的 mTLS 通信）
    info "生成面板客户端证书（RSA 4096 位，有效期 10 年）..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$key_file" \
        -out "$cert_file" \
        -days 3650 -nodes \
        -subj "/CN=incudal-panel/O=PayIncus" \
        2>/dev/null || return "$?"

    # 设置权限：只有 incudal 用户可读
    chmod 600 "$cert_file" "$key_file" || return "$?"
    chown "${RUN_USER}:${RUN_USER}" "$cert_file" "$key_file" || return "$?"

    log "面板客户端证书生成完成"
    info "证书路径: ${cert_file}"
    info "密钥路径: ${key_file}"
}

# ========================== 配置数据库 ==========================
setup_database() {
    local db_password="$1"

    step "配置 PostgreSQL 数据库..."
    # Passwords never enter SQL text, process argv or PostgreSQL statement logs.
    # A resumed installation authenticates the retained role without resetting it.
    (
    export INCUDAL_INSTALL_DB_PASSWORD="$db_password"
    /usr/bin/python3 -I -B - <<'DATABASE_BOOTSTRAP'
import os,subprocess,secrets,hashlib,hmac,base64
password=os.environ['INCUDAL_INSTALL_DB_PASSWORD']
if not password or not password.isascii() or any(ord(c)<32 or ord(c)==127 for c in password):raise SystemExit('DATABASE_BOOTSTRAP_PASSWORD_INVALID')
def query(sql):
    result=subprocess.run(['/usr/sbin/runuser','-u','postgres','--','/usr/bin/psql','-X','-v','ON_ERROR_STOP=1','-At','-d','postgres'],input=sql.encode(),env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin'},capture_output=True,timeout=15)
    if result.returncode:raise SystemExit('DATABASE_BOOTSTRAP_QUERY_FAILED')
    return result.stdout.decode().strip()
try:
    if query("SELECT 1 FROM pg_roles WHERE rolname='incudal'")!='1':
        salt=secrets.token_bytes(16);salted=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,4096)
        stored=hashlib.sha256(hmac.new(salted,b'Client Key','sha256').digest()).digest()
        server=hmac.new(salted,b'Server Key',hashlib.sha256).digest()
        encode=lambda value:base64.b64encode(value).decode()
        verifier=f'SCRAM-SHA-256$4096:{encode(salt)}${encode(stored)}:{encode(server)}'
        query("CREATE ROLE incudal LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+verifier+"'")
    if query("SELECT 1 FROM pg_database WHERE datname='incudal'")!='1':query('CREATE DATABASE incudal OWNER incudal')
    environment={'PATH':'/usr/bin:/bin','PGHOST':'127.0.0.1','PGPORT':'5432','PGDATABASE':'incudal','PGUSER':'incudal','PGPASSWORD':password,'PGCONNECT_TIMEOUT':'5'}
    result=subprocess.run(['/usr/bin/psql','-X','-At','-c','SELECT 1'],env=environment,capture_output=True,timeout=15)
    if result.returncode or result.stdout.strip()!=b'1':raise SystemExit('DATABASE_BOOTSTRAP_AUTHENTICATION_FAILED')
except (OSError,subprocess.TimeoutExpired):raise SystemExit('DATABASE_BOOTSTRAP_QUERY_FAILED')
print('DATABASE_BOOTSTRAP_READY')
DATABASE_BOOTSTRAP
    ) || return "$?"
    log "PostgreSQL 数据库与原登录身份已核验"
}

# ========================== 生成环境变量 ==========================
generate_env() {
    local db_password="$1"
    local redis_password="$2"
    local admin_password="${3:-}"
    if [[ -z "$admin_password" ]]; then admin_password="$(gen_password 16)" || return "$?"; fi
    local admin_email="${4:-admin@payincus.local}"

    step "生成环境配置..."

    if [[ -f "$ENV_FILE" ]]; then
        info ".env 文件已存在，检查并补齐缺失的密钥配置"
        ensure_env_keys
        return "$?"
    fi

    local jwt_secret
    jwt_secret=$(gen_secret 48) || return "$?"
    local cookie_secret
    cookie_secret=$(gen_secret 48) || return "$?"
    local encryption_key
    encryption_key=$(openssl rand -base64 32) || return "$?"

    (
    umask 077 || exit "$?"
    cat > "$ENV_FILE" << EOF || exit "$?"
# ============================================================================
# PayIncus 环境配置
# 由安装脚本自动生成于 $(date '+%Y-%m-%d %H:%M:%S')
# ============================================================================

# ============ 运行环境 ============
NODE_ENV=production
HOST=127.0.0.1
PORT=${DEFAULT_PORT}
TRUST_PROXY=true

# ============ 数据库配置 ============
DATABASE_URL=postgresql://incudal:${db_password}@127.0.0.1:5432/incudal
# 生产环境不要设置 RESET_DATABASE；真要清库还必须设置
# ALLOW_PRODUCTION_DATABASE_RESET=RESET_PRODUCTION_DATABASE

# ============ Redis 配置 ============
REDIS_URL=redis://:${redis_password}@127.0.0.1:6379

# ============ 安全配置（请勿泄露！）============
JWT_SECRET=${jwt_secret}
COOKIE_SECRET=${cookie_secret}
ENCRYPTION_KEY=${encryption_key}

# ============ 应用配置 ============
ADMIN_EMAIL=${admin_email}
ADMIN_PASSWORD=${admin_password}
SERVE_STATIC_CLIENT=false
VITE_API_BASE_URL=/api
VITE_CUSTOMER_BASE_URL=
VITE_ADMIN_BASE_URL=
LOG_LEVEL=info
DISABLE_REQUEST_LOG=true

# ============ 后台在线更新 ============
SYSTEM_UPDATE_ALLOWED_ADMIN_IDS=
SYSTEM_UPDATE_LOG_DIR=${INSTALL_DIR}/update-logs
SYSTEM_UPDATE_STARTED_BY_USER_ID=
SYSTEM_UPDATE_RELEASE_REPOSITORY=${GITHUB_REPO}
SYSTEM_UPDATE_RELEASE_TOKEN=
SYSTEM_UPDATE_APPLY_MODE=auto

# ============ Agent Release 配置 ============
# 可使用 GitHub Release 仓库、本地 release 目录，或自定义二进制 URL+SHA256。
INCUDAL_AGENT_RELEASE_REPOSITORY=${GITHUB_REPO}
INCUDAL_AGENT_RELEASE_TOKEN=${INCUDAL_AGENT_RELEASE_TOKEN:-}
INCUDAL_AGENT_RELEASE_DIR=
INCUDAL_AGENT_BINARY_URL=
INCUDAL_AGENT_BINARY_SHA256=

# ============ CORS 配置（必须修改为实际域名！）============
# 支付回调地址也会使用这个域名，必须是公网可访问的地址
FRONTEND_URL=
ADMIN_FRONTEND_URL=
SITE_URL=
PAYMENT_CALLBACK_BASE_URL=

# ============ Cookie 配置 ============
# HTTPS 同域 /api 反代部署保持留空即可。仅 HTTP 内网验证时可设置 COOKIE_SECURE=false。
# 若 API 与前端跨站，请设置：
# COOKIE_SAME_SITE=none
# COOKIE_SECURE=true
# COOKIE_DOMAIN must stay empty so customer/admin subdomains do not share refresh cookies.
COOKIE_SAME_SITE=
COOKIE_SECURE=
COOKIE_DOMAIN=

# ============ 监控告警（可选）============
# ALERT_WEBHOOK_URL=https://your-webhook-url
EOF
    ) || return "$?"

    chown "root:${RUN_USER}" "$ENV_FILE" || return "$?"
    chmod 640 "$ENV_FILE" || return "$?"

    log "环境配置文件生成完成: ${ENV_FILE}"
}

# ========================== 配置 Redis 密码 ==========================
setup_redis() {
    local redis_password="$1"

    step "配置 Redis..."

    local redis_conf="/etc/redis/redis.conf"
    if [[ -f "$redis_conf" ]]; then
        # 设置密码
        if grep -q "^requirepass" "$redis_conf" 2>/dev/null; then
            sed -i "s/^requirepass.*/requirepass ${redis_password}/" "$redis_conf" || return "$?"
        elif grep -q "^# requirepass" "$redis_conf" 2>/dev/null; then
            sed -i "s/^# requirepass.*/requirepass ${redis_password}/" "$redis_conf" || return "$?"
        else
            echo "requirepass ${redis_password}" >> "$redis_conf" || return "$?"
        fi

        systemctl restart redis-server || return "$?"
        log "Redis 密码配置完成"
    else
        warn "Redis 配置文件不存在，跳过密码配置"
    fi
}

# ========================== 运行数据库迁移 ==========================
database_migration_mode() {
    local app_dir="$1"
    [[ "$RELEASE_VERIFIED_THIS_RUN" == true ]] || { error '本次安装尚未完成完整产物验证，拒绝执行数据库迁移'; return 1; }
    if [[ "$VERIFIED_LEGACY_DATABASE_PACKAGE" == v1.8.13 || "$VERIFIED_LEGACY_DATABASE_PACKAGE" == v1.8.14 ]]; then
        [[ ! -e "$app_dir/scripts/harden-database.py" && ! -L "$app_dir/scripts/harden-database.py" && ! -e "$app_dir/scripts/migrate-database.sh" && ! -L "$app_dir/scripts/migrate-database.sh" ]] || { error '原历史产物中出现额外数据库迁移工具，拒绝执行'; return 1; }
        printf '%s\n' legacy
    else
        [[ -f "$app_dir/scripts/harden-database.py" && ! -L "$app_dir/scripts/harden-database.py" && -f "$app_dir/scripts/migrate-database.sh" && ! -L "$app_dir/scripts/migrate-database.sh" ]] || { error '当前产物的数据库迁移工具缺失或不是普通文件'; return 1; }
        printf '%s\n' modern
    fi
}

run_migrations() {
    step "执行数据库迁移..."

    cd "${INSTALL_DIR}/server" || return "$?"
    local migration_mode
    migration_mode="$(database_migration_mode "$INSTALL_DIR")" || return 1
    if [[ "$migration_mode" == legacy ]]; then
        # The retained original archives predate the root-only migration tools.
        # Keep their original database owner and run their ORM as that user.
        /usr/sbin/runuser -u "$RUN_USER" -- /usr/bin/env -i "PATH=$INSTALLER_SYSTEM_PATH" "ENV_FILE=$ENV_FILE" "HOME=$INSTALL_DIR" pnpm exec prisma migrate deploy || return "$?"
    else
        env "ENV_FILE=$ENV_FILE" python3 "$INSTALL_DIR/scripts/harden-database.py" || return "$?"
        env "ENV_FILE=$ENV_FILE" bash "$INSTALL_DIR/scripts/migrate-database.sh" || return "$?"
    fi

    log "数据库迁移完成"
}

# ========================== 创建 systemd 服务 ==========================
create_service() {
    step "创建 systemd 服务..."

    local app_dir="${INSTALL_DIR}"
    if [[ -L "${INSTALL_DIR}/current" ]]; then
        app_dir="${INSTALL_DIR}/current"
    fi
    local migration_mode migration_start
    migration_mode="$(database_migration_mode "$app_dir")" || return 1
    migration_start="ExecStartPre=+/usr/bin/bash ${app_dir}/scripts/migrate-database.sh"
    if [[ "$migration_mode" == legacy ]]; then
        migration_start="ExecStartPre=/usr/bin/env -i PATH=${INSTALLER_SYSTEM_PATH} HOME=${INSTALL_DIR} ENV_FILE=${ENV_FILE} /usr/bin/bash --noprofile --norc -c 'cd ${app_dir}/server && exec pnpm exec prisma migrate deploy'"
    fi
    cat > "$SERVICE_FILE" << EOF || return "$?"
[Unit]
Description=PayIncus 容器虚拟化管理平台
Documentation=https://github.com/${GITHUB_REPO}
After=network.target postgresql.service redis-server.service
Requires=postgresql.service redis-server.service
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
WorkingDirectory=${app_dir}
EnvironmentFile=${ENV_FILE}

# 确保 npm 缓存目录可写
Environment=HOME=${INSTALL_DIR}
Environment=NPM_CONFIG_CACHE=${INSTALL_DIR}/.npm
Environment=XDG_CACHE_HOME=${INSTALL_DIR}/.cache
Environment=PATH=/usr/local/libexec/incudal:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# 启动前自动执行数据库迁移
ExecStartPre=+/usr/bin/bash -c 'if [ -f ${app_dir}/scripts/install-platform-backup.sh ]; then bash ${app_dir}/scripts/install-platform-backup.sh; fi'
${migration_start}

# 启动主程序
ExecStart=/usr/bin/node ${app_dir}/server/dist/app.js
ExecStartPost=+/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C /usr/bin/bash /usr/local/libexec/incudal/incudal-repository-source-startup

# 优雅关闭
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=35min
TimeoutStartSec=10min

# 自动重启
Restart=on-failure
RestartSec=10

# 安全加固
# 后台在线更新需要通过受限 sudoers 启动 root-owned systemd oneshot 单元。
# 如果启用 NoNewPrivileges，sudo 会被内核直接拒绝。
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${INSTALL_DIR} ${INSTALL_DIR}/current ${INSTALL_DIR}/releases ${INSTALL_DIR}/server/certs ${INSTALL_DIR}/.npm ${INSTALL_DIR}/.cache ${INSTALL_DIR}/.git ${INSTALL_DIR}/update-logs /var/lib/incudal-images
PrivateTmp=true

# 资源限制
LimitNOFILE=65536

# 日志
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

[Install]
WantedBy=multi-user.target
EOF

    install_repository_startup_guard || return 1

    systemctl daemon-reload || return "$?"
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || return "$?"

    log "systemd 服务创建完成"
}

# ========================== 创建在线更新 systemd 单元和 sudoers ==========================
create_online_update_service() {
    step "创建在线更新 systemd 单元..."

    mkdir -p "${INSTALL_DIR}/update-logs" || return "$?"
    local app_dir="${INSTALL_DIR}"
    if [[ -L "${INSTALL_DIR}/current" ]]; then
        app_dir="${INSTALL_DIR}/current"
    fi
    if [[ "$RELEASE_VERIFIED_THIS_RUN" != "true" ]]; then
        error "本次运行未验证并安装 Release 产物，拒绝为既有目录建立可信清单"
        error "既有机器请由 owner 按 audits/fixes/FX-008-owner-steps.md 从已验证产物迁移"
        return 1
    fi

    # FX-008: root units may only enter through fixed, root-owned helpers.  The
    # release package is SHA256-verified before extraction; seal records a
    # root-only manifest so later task starts also verify the installed tree.
    local helper
    for helper in \
        incudal-online-task.sh.example \
        incudal-systemctl-wrapper.sh.example \
        incudal-ota-chown-wrapper.sh.example; do
        local installed_helper=""
        case "$helper" in
            incudal-online-task.sh.example) installed_helper=/usr/local/libexec/incudal/incudal-online-task ;;
            incudal-systemctl-wrapper.sh.example) installed_helper=/usr/local/libexec/incudal/systemctl ;;
            incudal-ota-chown-wrapper.sh.example) installed_helper=/usr/local/libexec/incudal/ota-path/chown ;;
        esac
        if [[ ! -f "$installed_helper" || -L "$installed_helper" || "$(stat -c '%u:%g:%a' "$installed_helper")" != "0:0:755" ]]; then
            error "root helper 属主或权限无效: ${installed_helper}"
            return 1
        fi
    done

    install -d -o root -g root -m 0755 /usr/local/libexec/incudal /usr/local/libexec/incudal/ota-path || return "$?"
    install -d -o root -g root -m 0755 /var/cache/incudal-ota /var/lib/incudal-ota/manifests || return "$?"

    cat > /etc/systemd/system/incudal-online-update@.service << EOF || return "$?"
[Unit]
Description=PayIncus online update task %i
Documentation=https://github.com/${GITHUB_REPO}
After=network.target postgresql.service redis-server.service incudal-backend.service
Requires=postgresql.service redis-server.service

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
Environment=HOME=/var/cache/incudal-ota
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/local/libexec/incudal/incudal-online-task update %i
TimeoutStartSec=120min
StandardOutput=journal
StandardError=journal
SyslogIdentifier=incudal-online-update
EOF

    cat > /etc/systemd/system/incudal-online-rollback@.service << EOF || return "$?"
[Unit]
Description=PayIncus online update rollback task %i
Documentation=https://github.com/${GITHUB_REPO}
After=network.target postgresql.service redis-server.service incudal-backend.service
Requires=postgresql.service redis-server.service

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
Environment=HOME=/var/cache/incudal-ota
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/usr/local/libexec/incudal/incudal-online-task rollback %i
TimeoutStartSec=60min
StandardOutput=journal
StandardError=journal
SyslogIdentifier=incudal-online-rollback
EOF

    local sudoers_tmp
    sudoers_tmp="$(mktemp)" || return "$?"
    cat > "$sudoers_tmp" << EOF || return "$?"
Defaults:${RUN_USER} secure_path=/usr/local/libexec/incudal:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Only the root-owned wrapper is allowed.  It rejects extra arguments and only
# accepts only fixed managed unit templates and validated task IDs.
${RUN_USER} ALL=(root) NOPASSWD: /usr/local/libexec/incudal/systemctl
EOF
    chmod 440 "$sudoers_tmp" || return "$?"
    visudo -cf "$sudoers_tmp" >/dev/null || return "$?"
    install -o root -g root -m 0440 "$sudoers_tmp" /etc/sudoers.d/incudal-online-update || return "$?"
    rm -f "$sudoers_tmp" || return "$?"

    # seal is run only after install_release verified the release SHA256.  It
    # makes code/current/releases root-owned, leaves only documented runtime
    # directories writable by incudal, and writes the trusted file manifest.
    /usr/local/libexec/incudal/incudal-online-task seal || return "$?"

    if [[ -f "${app_dir}/scripts/install-platform-backup.sh" ]]; then
        bash "${app_dir}/scripts/install-platform-backup.sh" || return "$?"
    fi
    # Legacy backup installers copy their original helper again. Generate the
    # same repository constant after that hook, without changing the archive or
    # its sealed runtime template; current helpers remain byte-identical.
    local repository_helper
    repository_helper="$(mktemp)" || return "$?"
    cp "${app_dir}/deploy/incudal-online-task.sh.example" "$repository_helper" || return "$?"
    normalize_legacy_online_task_helper "$repository_helper" || return "$?"
    install -o root -g root -m 0755 "$repository_helper" /usr/local/libexec/incudal/incudal-online-task || return "$?"
    rm -f -- "$repository_helper" || return "$?"

    systemctl daemon-reload || return "$?"

    log "在线更新 systemd 单元和 sudoers 创建完成"
}

# ========================== Nginx + Certbot ==========================
write_nginx_split_server_block() {
    local server_name="$1"
    local root_dir="$2"
    local default_server="${3:-}"
    local listen_suffix=""

    if [[ "$default_server" == "default" ]]; then
        listen_suffix=" default_server"
    fi

    cat <<NGINX
server {
    listen 80${listen_suffix};
    listen [::]:80${listen_suffix};
    server_name ${server_name};

    root ${root_dir};
    index index.html;
    client_max_body_size 100m;
    # API query strings can contain terminal/download credentials. Keep
    # application audits, but never copy bearer URLs into proxy diagnostics.
    access_log off;
    error_log /dev/null;

    add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://challenges.cloudflare.com https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: http: https: https://kkksr.com https://api.dicebear.com https://dicebear.incudal.com https://*.githubusercontent.com https://avatars.githubusercontent.com https://lh3.googleusercontent.com; connect-src 'self' https://challenges.cloudflare.com https://cloudflareinsights.com https://api.dicebear.com https://dicebear.incudal.com; frame-src 'self' https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location = /healthz {
        add_header Content-Type text/plain;
        return 200 "ok\n";
    }

    location = /index.html {
        expires epoch;
    }

    location /assets/ {
        try_files \$uri =404;
        expires 1y;
    }

    location /api/ws/ {
        proxy_pass http://127.0.0.1:${DEFAULT_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Host \$incudal_forwarded_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$incudal_forwarded_proto;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }

    # The script URL is a bearer credential; do not retain it in proxy logs.
    location ^~ /api/hosts/caddy-script/ {
        access_log off;
        error_log /dev/null;
        proxy_pass http://127.0.0.1:${DEFAULT_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Host \$incudal_forwarded_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$incudal_forwarded_proto;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }
    location /api/ {
        proxy_pass http://127.0.0.1:${DEFAULT_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Host \$incudal_forwarded_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$incudal_forwarded_proto;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
NGINX
}

resolve_static_dist_dir() {
    local relative_dist="$1"
    local current_dist="${INSTALL_DIR}/current/${relative_dist}"
    local legacy_dist="${INSTALL_DIR}/${relative_dist}"

    if [[ -d "$current_dist" ]]; then
        printf '%s\n' "$current_dist"
        return 0
    fi

    printf '%s\n' "$legacy_dist"
}

write_nginx_split_maps() {
    cat <<'NGINX'
map $http_x_forwarded_proto $incudal_forwarded_proto {
    default $http_x_forwarded_proto;
    "" $scheme;
}

map $http_x_forwarded_host $incudal_forwarded_host {
    default $http_x_forwarded_host;
    "" $host;
}

NGINX
}

setup_nginx_certbot() {
    info "准备配置 Nginx 反代及 Let's Encrypt SSL 自动证书"
    local client_dist
    local admin_client_dist
    client_dist="$(resolve_static_dist_dir "client/dist/user")" || return "$?"
    admin_client_dist="$(resolve_static_dist_dir "client/dist/admin")" || return "$?"

    if [[ ! -d "$client_dist" ]]; then
        error "未找到前端构建目录: $client_dist"
        error "请确认安装包包含 client/dist/user，或先完成前端构建后再配置 Nginx。"
        return 1
    fi

    if [[ ! -d "$admin_client_dist" ]]; then
        error "未找到后台前端构建目录: $admin_client_dist"
        error "请确认安装包包含 client/dist/admin，或先完成前端构建后再配置 Nginx。"
        return 1
    fi

    echo -ne "  ${BOLD}请输入客户面板域名 (例如 panel.example.com): ${NC}"
    read -r DOMAIN || return "$?"

    if [[ -z "$DOMAIN" ]]; then
        error "域名不能为空！"
        return 1
    fi

    echo -ne "  ${BOLD}请输入管理后台域名 (例如 admin.example.com): ${NC}"
    read -r ADMIN_DOMAIN || return "$?"

    if [[ -z "$ADMIN_DOMAIN" ]]; then
        error "管理后台域名不能为空！"
        return 1
    fi

    if [[ "$ADMIN_DOMAIN" == "$DOMAIN" ]]; then
        error "管理后台域名必须与客户面板域名分开！"
        return 1
    fi

    echo -ne "  ${BOLD}请输入你的邮箱 (用于证书过期通知，可留空): ${NC}"
    read -r EMAIL || return "$?"

    info "安装 Nginx 与 Certbot..."
    apt-get install -y -qq nginx certbot python3-certbot-nginx >/dev/null 2>&1 || return "$?"

    # 更新公网 URL：CORS、页面链接、支付回调都应使用浏览器可访问的前端域名
    set_env_value "FRONTEND_URL" "https://${DOMAIN}" "前端公网地址" || return "$?"
    set_env_value "ADMIN_FRONTEND_URL" "https://${ADMIN_DOMAIN}" "管理后台公网地址" || return "$?"
    set_env_value "SITE_URL" "https://${DOMAIN}" "站点公网地址" || return "$?"
    set_env_value "PAYMENT_CALLBACK_BASE_URL" "https://${DOMAIN}" "支付回调公网地址" || return "$?"
    set_env_value "VITE_CUSTOMER_BASE_URL" "https://${DOMAIN}" "管理后台生成客户链接的前端地址" || return "$?"
    set_env_value "VITE_ADMIN_BASE_URL" "https://${ADMIN_DOMAIN}" "前端管理后台地址" || return "$?"

    log "配置 Nginx 站点..."
    {
        write_nginx_split_maps || return "$?"
        write_nginx_split_server_block "$DOMAIN" "$client_dist" || return "$?"
        write_nginx_split_server_block "$ADMIN_DOMAIN" "$admin_client_dist" || return "$?"
    } > /etc/nginx/sites-available/incudal.conf || return "$?"

    ln -sf /etc/nginx/sites-available/incudal.conf /etc/nginx/sites-enabled/ || return "$?"
    # 移除默认站点（避免冲突）
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    nginx -t >/dev/null 2>&1 || return "$?"
    systemctl reload nginx || return "$?"

    log "申请 Let's Encrypt SSL 证书..."
    if [[ -n "$EMAIL" ]]; then
        certbot --nginx -d "$DOMAIN" -d "$ADMIN_DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect || return "$?"
    else
        certbot --nginx -d "$DOMAIN" -d "$ADMIN_DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email --redirect || return "$?"
    fi

    log "HTTPS 配置完成！客户面板: https://${DOMAIN}，管理后台: https://${ADMIN_DOMAIN}"
}

# ========================== Cloudflare Tunnel ==========================
show_cf_tunnel_guide() {
    info "准备配置 Cloudflare Tunnel 内网穿透（外部访问选项 2）"
    cat <<'GUIDE'
  先在 Cloudflare Zero Trust → Networks → Tunnels / Connectors 创建 Cloudflared Tunnel。
  一个 Tunnel 添加两个 Public Hostnames / Published application routes：

  用途       子域名示例   Domain           Path   Type   URL
  客户面板   panel        example.com      留空   HTTP   127.0.0.1:80
  管理后台   admin        example.com      留空   HTTP   127.0.0.1:80

  若界面只有「内网 Service URL」输入框，直接填写完整地址 http://127.0.0.1:80。
  若 Type 和 URL 分开填写，选择 HTTP，URL 填 127.0.0.1:80。
  两个域名共用本机 Nginx 的 80 端口；不要填后端 3001，不需要选择 HTTPS。
  浏览器仍使用 HTTPS；高级设置保持默认，HTTP Host Header 留空以区分两端。
  Domain 必须由 Cloudflare 管理；保存路由后检查对应 DNS 记录已创建。
  Token 是 CF 安装命令中 service install 后的长字符串，只复制 Token，不是 API Token。
  脚本会在本机配置 Nginx 托管前端并反代 /api 到后端，不会代建 CF 路由。
  此 Tunnel 只提供网站访问；机器池 WireGuard / SSH 网关仍需直连公网地址。
GUIDE
}

show_cf_route_summary() {
    info "请在同一个 Tunnel 保存以下两条路由（两端均使用本机 Nginx）："
    printf '  %-12s %-36s %s\n' '用途' 'Public Hostname' '内网 Service URL' >&2
    printf '  %-12s %-36s %s\n' '客户面板' "$DOMAIN" 'http://127.0.0.1:80' >&2
    printf '  %-12s %-36s %s\n' '管理后台' "$ADMIN_DOMAIN" 'http://127.0.0.1:80' >&2
    info "Zone 选择对应的 Cloudflare 域名；Path 和 HTTP Host Header 留空。保存后确认 DNS 记录已创建。"
}

is_valid_cf_domain() {
    local domain="$1" label
    local -a labels
    [[ ${#domain} -le 253 && "$domain" == *.* && "$domain" != *[!a-zA-Z0-9.-]* ]] || return 1
    [[ "$domain" != .* && "$domain" != *. && "$domain" != *..* && ! "$domain" =~ ^[0-9.]+$ ]] || return 1
    IFS='.' read -r -a labels <<< "$domain"
    for label in "${labels[@]}"; do
        [[ ${#label} -le 63 && "$label" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]] || return 1
    done
}

prompt_cf_domain() {
    local label="$1" example="$2" input
    while true; do
        echo -ne "  ${BOLD}请输入${label}域名 (例: ${example}，不带 https://): ${NC}" >&2
        if ! read -r input; then
            error "未读到域名，已停止配置。"
            return 1
        fi
        if is_valid_cf_domain "$input"; then
            printf '%s' "${input,,}"
            return 0
        fi
        error "Cloudflare Tunnel 生产部署必须配置浏览器访问域名；只填域名，不带协议、端口、路径或空格。"
        info "FRONTEND_URL/SITE_URL/PAYMENT_CALLBACK_BASE_URL 会用于 WebSocket Origin、OAuth 和支付回调。"
    done
}

cf_service_exists() {
    local state
    state="$(systemctl show cloudflared.service -p LoadState --value 2>/dev/null)" || {
        [[ "$state" == not-found ]] || return 2;
    }
    [[ -n "$state" ]] || return 2
    [[ "$state" != "not-found" || -e /etc/systemd/system/cloudflared.service ||
        -e /lib/systemd/system/cloudflared.service || -e /usr/lib/systemd/system/cloudflared.service ]]
}

check_cf_prerequisites() {
    local tool listeners
    for tool in curl python3 systemctl ss; do
        if ! command -v "$tool" &>/dev/null; then
            error "CF 配置缺少工具 ${tool}；请先安装 curl、python3、iproute2，并使用 systemd 系统。"
            return 1
        fi
    done
    if ! listeners="$(ss -H -ltnp '( sport = :80 )' 2>/dev/null)"; then
        error "无法检查本机 80 端口占用，已停止配置。"
        return 1
    fi
    if [[ -n "$listeners" ]] && [[ -n "$(printf '%s\n' "$listeners" | grep -v '"nginx"' || true)" ]]; then
        error "本机 80 端口被其他程序占用；请自行检查 sudo ss -ltnp，不会自动停止其他服务。"
        return 1
    fi
    if command -v nginx &>/dev/null && ! nginx -t >/dev/null 2>&1; then
        error "现有 Nginx 配置未通过检查；请先在本机运行 sudo nginx -t 修复，未写入 CF 配置。"
        return 1
    fi
}

install_cf_service() {
    # Never trace or forward cloudflared output: both can contain the Tunnel token.
    set +x
    local cf_token output install_status=0
    echo -ne "  ${BOLD}请输入 Cloudflare Tunnel Token（隐藏输入）: ${NC}" >&2
    if ! read -r -s cf_token; then
        echo >&2
        error "未读到 Token，已停止配置。"
        return 1
    fi
    echo >&2
    if [[ -z "$cf_token" || "$cf_token" == *[[:space:]]* || "$cf_token" == -* ]]; then
        error "Token 不能为空、含空格或是一整条命令；请只复制 service install 后的 Token。"
        return 1
    fi
    output="$(cloudflared service install "$cf_token" 2>&1)" || install_status=$?
    unset cf_token
    if [[ "$install_status" -ne 0 ]]; then
        if [[ "${output,,}" == *"token"* && "${output,,}" == *"invalid"* ]] ||
            [[ "${output,,}" == *"token is not valid"* ]]; then
            error "cloudflared 服务安装失败：Token 无效，请从正确的 Tunnel 页面重新复制。"
        elif [[ "${output,,}" == *"already"* ]]; then
            error "cloudflared 服务安装失败：已有服务，未覆盖。请检查已有 Tunnel 的用途。"
        elif [[ "${output,,}" == *"permission denied"* ]]; then
            error "cloudflared 服务安装失败：权限不足，请使用 sudo 运行脚本。"
        else
            error "cloudflared 服务安装失败（退出码 ${install_status}）；检查 Token、systemd 和出站网络。"
        fi
        info "原始 cloudflared 输出可能包含凭证，因此不打印。可运行 --check-cf-tunnel 查看分层诊断。"
        return 1
    fi
}

configure_cf_nginx() {
    local client_dist="$1" admin_client_dist="$2"
    local server_name="${DOMAIN}"
    info "安装并配置本机 Nginx 静态前端与 /api 反代..."
    if ! apt-get install -y -qq nginx >/dev/null 2>&1; then
        error "Nginx 软件包安装失败，请检查 APT 源和网络。"
        return 1
    fi
    {
        write_nginx_split_maps || return "$?"
        write_nginx_split_server_block "$server_name" "$client_dist" "default" || return "$?"
        write_nginx_split_server_block "$ADMIN_DOMAIN" "$admin_client_dist" || return "$?"
    } > /etc/nginx/sites-available/incudal.conf || { error "无法写入 Nginx 站点配置。"; return 1; }
    ln -sf /etc/nginx/sites-available/incudal.conf /etc/nginx/sites-enabled/ || return 1
    rm -f /etc/nginx/sites-enabled/default || return 1
    if ! nginx -t >/dev/null 2>&1; then
        error "新 Nginx 配置检查失败；请在本机运行 sudo nginx -t 检查端口、重复 default_server 或站点冲突。"
        return 1
    fi
    if ! systemctl enable nginx >/dev/null 2>&1 || ! systemctl restart nginx >/dev/null 2>&1; then
        error "Nginx 启动失败；检查 80 端口占用和 Nginx 配置。"
        return 1
    fi
}

setup_cf_tunnel() {
    set +x
    show_cf_tunnel_guide
    local reuse=false existing_status=0 input
    cf_service_exists || existing_status=$?
    if [[ "$existing_status" -eq 2 ]]; then
        error "无法查询 cloudflared 的 systemd 服务，已停止配置。"
        return 1
    elif [[ "$existing_status" -eq 0 ]]; then
        warn "检测到已有 cloudflared 服务；不会安装新 Token、覆盖配置或重启该服务。"
        warn "只有确认它就是本面板使用的 Tunnel，且 CF 两条域名路由已配置时才复用。"
        echo -ne "  输入 reuse 复用已有服务；回车停止配置: " >&2
        read -r input || return 1
        [[ "$input" == "reuse" ]] || { error "已停止配置，已有 Tunnel 保持原样。"; return 1; }
        reuse=true
    fi
    DOMAIN="$(prompt_cf_domain "客户面板" "panel.example.com")" || return 1
    ADMIN_DOMAIN="$(prompt_cf_domain "管理后台" "admin.example.com")" || return 1
    if [[ "$ADMIN_DOMAIN" == "$DOMAIN" ]]; then
        error "管理后台域名必须与客户面板域名分开！"
        return 1
    fi
    show_cf_route_summary
    local client_dist admin_client_dist
    client_dist="$(resolve_static_dist_dir "client/dist/user")" || return "$?"
    admin_client_dist="$(resolve_static_dist_dir "client/dist/admin")" || return "$?"
    if [[ ! -s "$client_dist/index.html" || ! -s "$admin_client_dist/index.html" ]]; then
        error "缺少用户端或管理端 index.html，请确认安装包包含 client/dist/user 和 client/dist/admin。"
        return 1
    fi
    check_cf_prerequisites || return 1
    if [[ "$reuse" == false ]]; then
        if ! command -v cloudflared &>/dev/null; then
            local binary cloudflared_hash
            info "下载 cloudflared..."
            binary="$(mktemp)" || return "$?"
            case "$ARCH" in
                amd64) cloudflared_hash=97bb3b02d23a5980fc9c15a1a270e692da1923f103f920d5b16d4931d5ab55e7 ;;
                arm64) cloudflared_hash=b155cec3e48e489cfb8e5c602769fb8c771083018d8881d68b4d18a791567c5a ;;
                *) rm -f "$binary"; return 1 ;;
            esac
            if ! curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 10 --max-time 180 \
                "https://github.com/cloudflare/cloudflared/releases/download/2026.11.1/cloudflared-linux-${ARCH}" -o "$binary" ||
                [[ $(sha256sum "$binary" | awk '{print $1}') != "$cloudflared_hash" ]] ||
                ! install -m 0755 "$binary" /usr/local/bin/cloudflared; then
                rm -f "$binary"
                error "cloudflared 下载或安装失败，请检查 GitHub 访问和系统架构。"
                return 1
            fi
            rm -f "$binary" || return "$?"
        fi
        install_cf_service || return 1
        if ! systemctl enable cloudflared >/dev/null 2>&1 || ! systemctl start cloudflared >/dev/null 2>&1; then
            error "cloudflared 服务启动失败；安装未完成，请运行 --check-cf-tunnel 检查。"
            return 1
        fi
    elif ! systemctl is-active --quiet cloudflared; then
        error "已有 cloudflared 服务未运行；请先确认其配置并自行启动，再复用。"
        return 1
    fi
    configure_cf_nginx "$client_dist" "$admin_client_dist" || return 1
    set_env_value "FRONTEND_URL" "https://${DOMAIN}" "前端公网地址" || return "$?"
    set_env_value "ADMIN_FRONTEND_URL" "https://${ADMIN_DOMAIN}" "管理后台公网地址" || return "$?"
    set_env_value "SITE_URL" "https://${DOMAIN}" "站点公网地址" || return "$?"
    set_env_value "PAYMENT_CALLBACK_BASE_URL" "https://${DOMAIN}" "支付回调公网地址" || return "$?"
    set_env_value "VITE_CUSTOMER_BASE_URL" "https://${DOMAIN}" "管理后台生成客户链接的前端地址" || return "$?"
    set_env_value "VITE_ADMIN_BASE_URL" "https://${ADMIN_DOMAIN}" "前端管理后台地址" || return "$?"
    CF_TUNNEL_SELECTED=true
    CF_TUNNEL_VERIFIED=false
    info "本机配置已写入；后端启动后将检查两端页面、API、隧道和公网入口。"
}

cf_health_body_ok() {
    python3 - "$1" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding='utf-8'))
    sys.exit(0 if isinstance(data, dict) and data.get('status') == 'ok' else 1)
except (OSError, ValueError):
    sys.exit(1)
PY
}

cf_probe_http() {
    local label="$1" url="$2" expected="$3" host="${4:-}" body code rc=0 attempt max_attempts=1
    local -a args=(--silent --show-error --compressed --connect-timeout 3 --max-time 12)
    [[ -z "$host" ]] || args+=(--noproxy '*' -H "Host: ${host}")
    [[ "$url" != http://127.0.0.1:* ]] || args+=(--noproxy '*')
    [[ "$url" != https://* ]] || max_attempts=3
    body="$(mktemp)"
    for ((attempt=1; attempt<=max_attempts; attempt++)); do
        rc=0
        code="$(curl "${args[@]}" -o "$body" -w '%{http_code}' "$url" 2>/dev/null)" || rc=$?
        # Retry transient public network failures only; HTTP/content/certificate
        # errors stay visible and no alternative resolver can claim success.
        [[ "$rc" -eq 6 || "$rc" -eq 7 || "$rc" -eq 28 ]] || break
        [[ "$attempt" -lt "$max_attempts" ]] || break
        info "${label}：暂时无法访问（curl ${rc}），3 秒后重试（$((attempt+1))/${max_attempts}）；新域名可能仍受 DNS 缓存或传播延迟影响。"
        sleep 3
    done
    if [[ "$rc" -ne 0 ]]; then
        case "$rc" in
            6) error "${label}：尚未验证，DNS 解析失败；检查 CF 路由和 DNS 记录。若浏览器已能访问，服务器自身可能仍有 DNS 缓存或传播延迟；稍后重跑 --check-cf-tunnel，无需重装面板。" ;;
            7) error "${label}：无法连接目标端口；本机检查 Nginx / 后端，公网检查出站网络及 DNS 是否仍指向旧地址。" ;;
            28) error "${label}：尚未验证，请求超时；检查网络、CF 路由并稍后重试。" ;;
            35|60) error "${label}：HTTPS / 证书检查失败；检查系统时间与 CA 证书、CF 边缘证书。" ;;
            *) error "${label}：请求失败（curl 退出码 ${rc}）。" ;;
        esac
    elif [[ "$code" != 200 ]]; then
        case "$code" in
            502) error "${label}：HTTP 502；检查 CF 路由 Type=HTTP、URL=127.0.0.1:80（内网 Service URL=http://127.0.0.1:80），以及本机 /api 反代。" ;;
            530) error "${label}：HTTP 530；检查 CF Tunnel 在线状态、路由与 DNS（可能是 1033 隧道未连接）。" ;;
            301|302|303|307|308|401|403) error "${label}：HTTP ${code}；可能被 Cloudflare Access、WAF 或重定向拦截。" ;;
            *) error "${label}：HTTP ${code}；检查域名路由及 Nginx 站点。" ;;
        esac
    elif [[ "$expected" == health ]] && cf_health_body_ok "$body"; then
        rm -f "$body"
        log "${label}：通过（API status=ok）"
        return 0
    elif [[ "$expected" != health ]] && cmp -s "$body" "$expected"; then
        rm -f "$body"
        log "${label}：通过（页面与本机对应构建一致）"
        return 0
    else
        error "${label}：HTTP 200 但内容不符；检查两端是否指反、HTTP Host Header、Access 登录页或 CF 缓存/HTML 改写。"
    fi
    rm -f "$body"
    return 1
}

cf_connection_ready() {
    local invocation metrics_log endpoint port metrics
    systemctl is-active --quiet cloudflared || return 1
    # Only the current process's loopback metrics are trusted; never print raw journals or units.
    invocation="$(systemctl show cloudflared.service -p InvocationID --value 2>/dev/null)" || return 2
    [[ "$invocation" =~ ^[a-fA-F0-9]{32}$ ]] || return 2
    metrics_log="$(journalctl "_SYSTEMD_INVOCATION_ID=${invocation}" --no-pager -o cat \
        --grep 'Starting metrics server on' -n 1 2>/dev/null)" || return 2
    endpoint="$(printf '%s\n' "$metrics_log" | sed -nE 's/.*Starting metrics server on ((127\.0\.0\.1|\[::1\]):[0-9]+)\/metrics.*/\1/p')"
    port="${endpoint##*:}"
    [[ "$port" =~ ^[0-9]{1,5}$ && "$port" -gt 0 && "$port" -le 65535 ]] || return 2
    metrics="$(curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 "http://${endpoint}/metrics" 2>/dev/null)" || return 2
    printf '%s\n' "$metrics" | awk '
        /^cloudflared_tunnel_ha_connections(\{|[[:space:]])/ { seen=1; if ($NF+0 > 0) ready=1 }
        END { if (!seen) exit 2; exit ready ? 0 : 1 }
    '
}

diagnose_cf_tunnel() {
    set +x
    CF_TUNNEL_VERIFIED=false
    local failed=0 attempt connection_status=2 client_dist admin_client_dist
    step "Cloudflare Tunnel 分层检查"
    info "此检查不修改 CF 或本机配置，不打印 Token、systemd 启动命令或原始日志。"
    if ! is_valid_cf_domain "${DOMAIN:-}" || ! is_valid_cf_domain "${ADMIN_DOMAIN:-}" || [[ "${DOMAIN,,}" == "${ADMIN_DOMAIN,,}" ]]; then
        error "缺少有效且不同的两端域名；请运行 --configure-cf-tunnel 补配。"
        return 1
    fi
    for attempt in curl python3 nginx systemctl journalctl; do
        command -v "$attempt" &>/dev/null || { error "检查缺少 ${attempt}，请先补齐工具。"; return 1; }
    done
    if nginx -t >/dev/null 2>&1; then
        log "Nginx 配置：通过"
    else
        error "Nginx 配置：失败；请在本机运行 sudo nginx -t。"
        failed=1
    fi
    client_dist="$(resolve_static_dist_dir "client/dist/user")"
    admin_client_dist="$(resolve_static_dist_dir "client/dist/admin")"
    cf_probe_http "本机用户端" "http://127.0.0.1:80/" "$client_dist/index.html" "$DOMAIN" || failed=1
    cf_probe_http "本机管理端" "http://127.0.0.1:80/" "$admin_client_dist/index.html" "$ADMIN_DOMAIN" || failed=1
    info "等待后端 API 启动，最多检查 10 次..."
    for attempt in {1..10}; do
        if curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 "http://127.0.0.1:${DEFAULT_PORT}/api/health" >/dev/null 2>&1; then
            break
        fi
        [[ "$attempt" -eq 10 ]] || sleep 1
    done
    cf_probe_http "后端 API" "http://127.0.0.1:${DEFAULT_PORT}/api/health" health || failed=1
    cf_probe_http "本机用户端 API 反代" "http://127.0.0.1:80/api/health" health "$DOMAIN" || failed=1
    cf_probe_http "本机管理端 API 反代" "http://127.0.0.1:80/api/health" health "$ADMIN_DOMAIN" || failed=1
    if systemctl is-active --quiet cloudflared; then
        log "cloudflared 服务：运行中（运行不等于隧道在线）"
        info "等待隧道连接，最多检查 10 次..."
        for attempt in {1..10}; do
            connection_status=0
            cf_connection_ready || connection_status=$?
            [[ "$connection_status" -ne 0 ]] || break
            [[ "$attempt" -eq 10 ]] || sleep 2
        done
        if [[ "$connection_status" -eq 0 ]]; then
            log "隧道连接：通过（当前进程实时连接数大于 0）"
        elif [[ "$connection_status" -eq 2 ]]; then
            warn "隧道连接：尚未验证，无法读取当前进程的本机连接指标；请在 CF 后台确认 Healthy。"
            failed=1
        else
            error "隧道连接：未建立；检查 Token 是否撤销，以及出站 UDP/TCP 7844，CF 后台应显示 Healthy。"
            failed=1
        fi
    else
        error "cloudflared 服务：未运行；检查服务是否安装成功及 Token，勿分享含凭证的原始服务配置。"
        failed=1
    fi
    cf_probe_http "用户端公网页面" "https://${DOMAIN}/" "$client_dist/index.html" || failed=1
    cf_probe_http "用户端公网 API" "https://${DOMAIN}/api/health" health || failed=1
    cf_probe_http "管理端公网页面" "https://${ADMIN_DOMAIN}/" "$admin_client_dist/index.html" || failed=1
    cf_probe_http "管理端公网 API" "https://${ADMIN_DOMAIN}/api/health" health || failed=1
    if [[ "$failed" -ne 0 ]]; then
        warn "CF 访问检查未全部通过；修正上方失败项后运行 sudo bash $0 --check-cf-tunnel。"
        return 1
    fi
    CF_TUNNEL_VERIFIED=true
    log "Cloudflare Tunnel 两端页面与 API 访问检查通过；请继续在浏览器实测登录和受影响流程。"
    info "客户面板：https://${DOMAIN}；管理后台：https://${ADMIN_DOMAIN}"
}

load_cf_domains() {
    local user_url admin_url
    user_url="$(get_env_value FRONTEND_URL)"
    admin_url="$(get_env_value ADMIN_FRONTEND_URL)"
    [[ "$user_url" == https://* && "$admin_url" == https://* ]] || {
        error "当前 .env 未配置两端 HTTPS 地址；请运行 --configure-cf-tunnel。"; return 1;
    }
    DOMAIN="${user_url#https://}"
    ADMIN_DOMAIN="${admin_url#https://}"
    DOMAIN="${DOMAIN%/}"
    ADMIN_DOMAIN="${ADMIN_DOMAIN%/}"
    is_valid_cf_domain "$DOMAIN" && is_valid_cf_domain "$ADMIN_DOMAIN" && [[ "${DOMAIN,,}" != "${ADMIN_DOMAIN,,}" ]]
}

# ========================== 启动服务 ==========================
start_service() {
    step "启动 PayIncus 服务..."

    systemctl start "$SERVICE_NAME" || return "$?"

    # 等待几秒检查状态
    sleep 3 || return "$?"

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "PayIncus 服务启动成功！"
    else
        error "服务启动失败，详细日志保留在本机，请在可信 root 会话中查看。"
        local status_summary
        status_summary=$(systemctl show "$SERVICE_NAME" --property=ActiveState,SubState,Result,ExecMainStatus --no-pager 2>/dev/null || true)
        printf '%s\n' "$status_summary" | while IFS= read -r status_line; do
            case "$status_line" in
                ActiveState=active|ActiveState=inactive|ActiveState=failed|ActiveState=activating|ActiveState=deactivating|\
                SubState=running|SubState=dead|SubState=failed|SubState=start|SubState=start-pre|SubState=start-post|SubState=auto-restart|\
                Result=success|Result=exit-code|Result=signal|Result=core-dump|Result=timeout|Result=resources|Result=oom-kill|Result=start-limit-hit)
                    printf '%s\n' "$status_line" ;;
                ExecMainStatus=*)
                    [[ "$status_line" =~ ^ExecMainStatus=[0-9]{1,3}$ ]] && printf '%s\n' "$status_line" || true ;;
            esac
        done
        exit 1
    fi
}

# ========================== 显示安装结果 ==========================
show_result() {
    local admin_password
    admin_password="$(get_env_value "ADMIN_PASSWORD")"
    local admin_email
    admin_email="$(get_env_value "ADMIN_EMAIL")"

    echo ""
    divider
    if [[ "$CF_TUNNEL_SELECTED" == true && "$CF_TUNNEL_VERIFIED" != true ]]; then
        echo -e "  ${YELLOW}${BOLD}PayIncus 本机已部署，CF 外部访问尚未全部验证通过。${NC}"
    else
        echo -e "  ${GREEN}${BOLD}✅ PayIncus 面板部署成功！${NC}"
    fi
    divider
    echo ""
    echo -e "  ${BOLD}面板信息${NC}"
    echo -e "  安装路径  :  ${GREEN}${INSTALL_DIR}${NC}"
    echo -e "  配置文件  :  ${GREEN}${ENV_FILE}${NC}"
    echo -e "  服务名称  :  ${GREEN}${SERVICE_NAME}${NC}"
    echo -e "  监听端口  :  ${GREEN}${DEFAULT_PORT}${NC}"
    if [[ "$CF_TUNNEL_SELECTED" == true ]]; then
        echo -e "  客户面板  :  ${GREEN}https://${DOMAIN}${NC}"
        echo -e "  管理后台  :  ${GREEN}https://${ADMIN_DOMAIN}${NC}"
        echo -e "  CF 复查   :  ${CYAN}sudo bash $0 --check-cf-tunnel${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}默认账号${NC}"
    echo -e "  用户名    :  ${GREEN}admin${NC}"
    echo -e "  邮箱      :  ${GREEN}${admin_email:-admin@payincus.local}${NC}"
    if [[ -n "$admin_password" ]]; then
        echo -e "  密码      :  ${GREEN}${admin_password}${NC}  ${YELLOW}（请在首次登录后立即修改！）${NC}"
    else
        echo -e "  密码      :  ${YELLOW}请查看 ${ENV_FILE} 中的 ADMIN_PASSWORD${NC}"
    fi
    echo ""
    echo -e "  ${BOLD}常用命令${NC}"
    echo -e "  启动服务  :  ${CYAN}systemctl start ${SERVICE_NAME}${NC}"
    echo -e "  停止服务  :  ${CYAN}systemctl stop ${SERVICE_NAME}${NC}"
    echo -e "  重启服务  :  ${CYAN}systemctl restart ${SERVICE_NAME}${NC}"
    echo -e "  查看状态  :  ${CYAN}systemctl status ${SERVICE_NAME}${NC}"
    echo -e "  查看日志  :  ${CYAN}journalctl -u ${SERVICE_NAME} -f${NC}"
    echo ""
    divider
}

# ========================== 升级流程 ==========================
do_upgrade() {
    show_banner
    check_os || return "$?"

    if ! check_existing; then
        error "未检测到已安装的 PayIncus，请先执行全新安装"
        exit 1
    fi

    if is_atomic_layout; then
        error "检测到原子 OTA 布局，不能使用旧版 --upgrade 覆盖 current/releases"
        error "请在管理后台执行 OTA；如需命令行维护，请使用后台生成的更新任务"
        exit 1
    fi

    info "检测到已安装的 PayIncus，准备升级..."

    apt-get update -qq >/dev/null 2>&1 || return "$?"
    install_system_tools || return "$?"

    # 停止服务
    info "停止当前服务..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl stop incudal 2>/dev/null || true

    # 获取产物包（自动下载或手动放置）
    local tar_file
    tar_file=$(obtain_release) || exit 1
    if [[ -z "$tar_file" ]]; then
        exit 1
    fi
    install_release "$tar_file" true || return "$?"
    if [[ -f "$INSTALL_DIR/scripts/refresh-onboarding-gateway.sh" ]]; then
        bash "$INSTALL_DIR/scripts/refresh-onboarding-gateway.sh" || return "$?"
    fi

    local version="unknown"
    if [[ -f "${INSTALL_DIR}/version.json" ]]; then
        version=$(node -e "try { console.log(require('${INSTALL_DIR}/version.json').version || 'unknown') } catch { console.log('unknown') }")
    fi

    # 修复权限
    chmod 751 "$INSTALL_DIR" || return "$?"
    if [[ -f "$ENV_FILE" ]]; then
        chown "root:${RUN_USER}" "$ENV_FILE" || return "$?"
        chmod 640 "$ENV_FILE" || return "$?"
    fi

    configure_git_metadata || return "$?"
    ensure_env_keys || return "$?"
    create_service || return "$?"
    create_online_update_service || return "$?"

    # 运行迁移
    run_migrations || return "$?"

    # 重启服务
    start_service || return "$?"

    echo ""
    divider
    echo -e "  ${GREEN}${BOLD}✅ PayIncus 升级到 ${version} 完成！${NC}"
    divider
}

# ========================== 卸载流程 ==========================
do_uninstall() {
    show_banner

    echo -e "  ${RED}${BOLD}⚠️  警告：卸载将执行以下操作：${NC}"
    echo -e "  ${RED}  1. 停止并删除 PayIncus systemd 服务${NC}"
    echo -e "  ${RED}  2. 删除安装目录 ${INSTALL_DIR}${NC}"
    echo -e "  ${RED}  3. 删除系统用户 ${RUN_USER}${NC}"
    echo -e "  ${RED}  安装目录中的运行资产、OTA release 和更新日志也会被删除${NC}"
    echo -e "  ${YELLOW}  注意：PostgreSQL/Redis 和数据库数据不会被删除${NC}"
    echo ""
    echo -ne "  ${BOLD}确认卸载？${NC}[y/N]: "
    read -r confirm
    if [[ ! "$confirm" =~ ^[yY]$ ]]; then
        info "已取消卸载"
        exit 0
    fi

    # 停止服务
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    systemctl stop incudal 2>/dev/null || true
    systemctl disable incudal 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    rm -f /etc/systemd/system/incudal.service
    rm -f /etc/systemd/system/incudal-online-update@.service
    rm -f /etc/systemd/system/incudal-online-rollback@.service
    rm -f /etc/sudoers.d/incudal-online-update
    rm -rf /usr/local/libexec/incudal /var/cache/incudal-ota /var/lib/incudal-ota
    systemctl daemon-reload

    # 删除安装目录
    rm -rf "$INSTALL_DIR"

    # 删除用户
    userdel "$RUN_USER" 2>/dev/null || true

    # 清理 Nginx 配置
    rm -f /etc/nginx/sites-enabled/incudal.conf 2>/dev/null || true
    rm -f /etc/nginx/sites-available/incudal.conf 2>/dev/null || true
    systemctl reload nginx 2>/dev/null || true

    echo ""
    log "PayIncus 已完全卸载"
    info "数据库数据保留在 PostgreSQL 中，如需删除请手动执行："
    echo -e "  ${CYAN}sudo -u postgres psql -c \"DROP DATABASE incudal;\"${NC}"
    echo -e "  ${CYAN}sudo -u postgres psql -c \"DROP USER incudal;\"${NC}"
}

# ========================== 机器池管理网关 ==========================
configure_host_pool_gateway() {
    local public_host="${ONBOARDING_PUBLIC_HOST:-}"
    local gateway_key gateway_value gateway_configured=true
    for gateway_key in ONBOARDING_GATEWAY_HOST ONBOARDING_GATEWAY_KEY_PATH ONBOARDING_GATEWAY_FINGERPRINT ONBOARDING_WG_ENDPOINT; do
        gateway_value="$(get_env_value "$gateway_key")" || return "$?"
        [[ -n "$gateway_value" ]] || gateway_configured=false
    done
    if [[ "$gateway_configured" == true ]]; then
        info "机器池管理网关已配置，保留现有地址和密钥"
        return 0
    fi
    if [[ -z "$public_host" ]]; then
        echo -ne "  ${BOLD}机器池管理网关公网 IPv4 或直连域名（不能经过 CDN，留空稍后配置）: ${NC}" >&2
        read -r public_host || return "$?"
    fi
    if [[ -z "$public_host" ]]; then
        warn "自动接入尚未配置。需要时运行: sudo bash install-panel.sh --configure-host-pool"
        return 0
    fi
    local app_dir="$INSTALL_DIR"
    is_atomic_layout && app_dir="$INSTALL_DIR/current"
    python3 "$app_dir/scripts/setup-onboarding-control.py" \
        --public-host "$public_host" \
        --management-address "${ONBOARDING_MANAGEMENT_ADDRESS:-10.253.240.1/20}" \
        --listen-port "${ONBOARDING_WG_PORT:-51820}" \
        --ssh-port "${ONBOARDING_CONTROL_SSH_PORT:-22}" || return "$?"
}

# ========================== 全新安装流程 ==========================
do_install() {
    show_banner
    check_os || return "$?"

    if [[ -e "$ENV_FILE" || -L "$ENV_FILE" ]]; then
        if ! env_file_identity > /dev/null; then
            error "现有环境配置不是安全的普通文件，已停止安装并保留原数据。"
            return 1
        fi
    elif has_existing_installation_identity; then
        error "检测到已有服务或控制身份，但环境配置缺失；请从可信备份恢复原配置，不能重新生成身份。"
        return 1
    fi

    if check_existing; then
        warn "检测到已安装的 PayIncus (${INSTALL_DIR})"
        info "将重新验证完整产物，并保留已有配置和证书后续接"
        info "如需全新安装，请先运行: sudo bash $0 --uninstall"
        echo "" >&2
    fi

    # 密码处理：如果 .env 已存在则复用旧密码，避免密码不一致
    local db_password database_url
    local redis_password redis_url
    local admin_email

    if [[ -f "$ENV_FILE" ]]; then
        info "检测到已有 .env 配置，复用现有密码"
        # Decode the existing dotenv record without sourcing it. Quoting and
        # whitespace around '=' are valid, while an invalid original URL must
        # still fail before any package or service changes.
        database_url="$(get_env_value "DATABASE_URL")" || return "$?"
        if [[ "$database_url" =~ ^postgresql://[^:]+:([^@]+)@ ]]; then
            db_password="${BASH_REMATCH[1]}"
        else
            error "无法从现有 .env 提取数据库密码，已停止安装并保留原配置。请检查 DATABASE_URL 后重试。"
            return 1
        fi
        if check_existing; then
            # Re-enter the existing authenticated upgrade path. Merely finding
            # app.js never sets the per-run package verification receipt.
            do_upgrade
            return "$?"
        fi
        redis_url="$(get_env_value "REDIS_URL")" || return "$?"
        if [[ "$redis_url" =~ ^redis://:([^@]+)@ ]]; then
            redis_password="${BASH_REMATCH[1]}"
        else
            redis_password=$(gen_password 24) || return "$?"
        fi
    else
        db_password=$(gen_password 24) || return "$?"
        redis_password=$(gen_password 24) || return "$?"
    fi

    # 初始管理员邮箱
    admin_email="$(prompt_initial_admin_email)" || return "$?"

    # 安装依赖
    step "更新系统包索引..."
    apt-get update -qq >/dev/null 2>&1 || return "$?"

    install_system_tools || return "$?"
    install_nodejs || return "$?"
    install_pnpm || return "$?"
    install_postgresql || return "$?"
    install_redis || return "$?"

    # 创建用户（必须早于 install_release）：install_release 会创建 server/certs 并立即
    # 调用 incudal-online-task harden，而 harden 会把 .env / server/certs 等 chown 到
    # root:${RUN_USER} 组。若此时系统用户/组尚未创建，chown 会以
    # "invalid group: 'root:incudal'" 失败，导致全新安装中断。
    create_user || return "$?"

    # A partial code tree is not a verification receipt. Re-obtain the full
    # authenticated archive before any configuration writes; retain existing
    # partial certificates and remove stale runtime code through upgrade mode.
    local tar_file retain_partial=false
    if check_existing || [[ -f "$ENV_FILE" || -e "$INSTALL_DIR/server/certs" || -L "$INSTALL_DIR/server/certs" ]]; then
        retain_partial=true
    fi
    tar_file=$(obtain_release) || exit 1
    [[ -n "$tar_file" ]] || exit 1
    install_release "$tar_file" "$retain_partial" || return 1

    if [[ -f "$ENV_FILE" ]]; then
        local configured_admin_email
        configured_admin_email="$(get_env_value "ADMIN_EMAIL")" || return "$?"
        if [[ -z "$configured_admin_email" ]]; then
            set_env_value "ADMIN_EMAIL" "$admin_email" "管理员初始邮箱" || return "$?"
        fi
    fi

    # 配置 Git 元数据
    configure_git_metadata || return "$?"

    # 生成面板客户端证书（与 Incus API mTLS 通信所需）
    generate_panel_cert || return "$?"

    # 配置数据库
    setup_database "$db_password" || return "$?"

    # 配置 Redis
    setup_redis "$redis_password" || return "$?"

    # 生成 .env
    local initial_admin_password
    initial_admin_password="$(gen_password 16)" || return "$?"
    generate_env "$db_password" "$redis_password" "$initial_admin_password" "$admin_email" || return "$?"

    # Only a fresh, checksum-verified release with its full signed component
    # catalog may initialize a new controller identity. Restarts never do this.
    if [[ -f "$INSTALL_DIR/vendor/gateway/catalog.json" ]]; then
        if [[ -f /var/lib/incudal-gateway-controller/enrollment.json ]]; then
            bash "$INSTALL_DIR/scripts/install-gateway-controller.sh" || return "$?"
        else
            bash "$INSTALL_DIR/scripts/install-gateway-controller.sh" --initialize-release || return "$?"
        fi
    fi

    # 创建 systemd 服务
    create_service || return "$?"
    create_online_update_service || return "$?"

    # 运行数据库迁移
    run_migrations || return "$?"

    # 选择网络方案
    echo ""
    divider
    echo -e "  ${BOLD}请选择外部访问方案：${NC}"
    divider
    echo -e "  ${CYAN}[1]${NC} Nginx + Certbot   ${YELLOW}（推荐：自动 HTTPS，需要公网 IP 和域名）${NC}"
    echo -e "  ${CYAN}[2]${NC} Cloudflare Tunnel  ${YELLOW}（适合无公网 IP 或隐藏源站 IP）${NC}"
    echo -e "  ${CYAN}[3]${NC} 仅启动服务        ${DIM}（手动配置反代）${NC}"
    echo ""
    echo -ne "  ${BOLD}请选择 [1-3]: ${NC}"
    read -r net_opt || return "$?"

    case "${net_opt:-3}" in
        1) setup_nginx_certbot || return "$?" ;;
        2) setup_cf_tunnel || return "$?" ;;
        3) info "跳过网络配置，服务将监听 127.0.0.1:${DEFAULT_PORT}" ;;
        *) info "无效选项，跳过网络配置" ;;
    esac

    # 配置管理隧道及受限 SSH 网关，成功验证后才写入环境配置。
    configure_host_pool_gateway || return "$?"

    # 启动服务
    start_service || return "$?"

    if [[ "$CF_TUNNEL_SELECTED" == true ]] && ! diagnose_cf_tunnel; then
        show_result
        return 1
    fi

    # 显示结果
    show_result || return "$?"
}

# ========================== 主入口 ==========================
main() {
    check_root

    case "${1:-}" in
        --install-repository-startup-guard)
            [[ $# -eq 1 ]] || return 1
            install_repository_startup_guard
            ;;
        --migrate-release-repository)
            [[ $# -eq 1 && -f "$ENV_FILE" && ! -L "$ENV_FILE" ]] || { error "需要现有受管环境配置"; return 1; }
            local repository_key
            for repository_key in SYSTEM_UPDATE_RELEASE_REPOSITORY INCUDAL_AGENT_RELEASE_REPOSITORY GITHUB_REPO GITHUB_REPOSITORY; do
                migrate_release_repository "$repository_key"
            done
            ;;
        --upgrade|-u)
            do_upgrade
            ;;
        --uninstall|--remove)
            do_uninstall
            ;;
        --configure-host-pool)
            check_existing || { error "请先安装面板"; exit 1; }
            install_system_tools
            configure_host_pool_gateway
            systemctl restart "$SERVICE_NAME"
            ;;
        --configure-gateway-controller)
            check_existing || { error "请先安装面板"; exit 1; }
            local app_dir="$INSTALL_DIR"
            [[ ! -L "$INSTALL_DIR/current" ]] || app_dir="$(readlink -f -- "$INSTALL_DIR/current")"
            [[ "$app_dir" == "$INSTALL_DIR" || "$app_dir" == "$INSTALL_DIR/releases/"* ]] || { error "安装路径无效"; exit 1; }
            local action="${2:-}"
            [[ $# -eq 2 && ( "$action" == --initialize || "$action" == --refresh || "$action" == --verify ) ]] || { error "需要显式 --initialize、--refresh 或 --verify"; exit 1; }
            bash "$app_dir/scripts/install-gateway-controller.sh" "$action"
            ;;
        --configure-cf-tunnel)
            check_existing || { error "请先安装面板"; exit 1; }
            check_os
            setup_cf_tunnel
            if ! systemctl restart "$SERVICE_NAME"; then
                error "后端重启失败；请在本机检查 incudal-backend 服务。"
                exit 1
            fi
            diagnose_cf_tunnel
            ;;
        --check-cf-tunnel)
            check_existing || { error "请先安装面板"; exit 1; }
            load_cf_domains || { error "两端域名配置无效，请先运行 --configure-cf-tunnel。"; exit 1; }
            diagnose_cf_tunnel
            ;;
        --help|-h)
            echo "PayIncus 面板部署脚本 v${SCRIPT_VERSION}"
            echo ""
            echo "用法: sudo bash $0 [选项]"
            echo ""
            echo "选项:"
            echo "  (无参数)      全新安装"
            echo "  --upgrade     升级已有安装"
            echo "  --migrate-release-repository  仅迁移退役的默认发行源，保留密钥和自定义来源"
            echo "  --uninstall   卸载 PayIncus"
            echo "  --configure-host-pool  配置机器池管理网关"
            echo "  --configure-gateway-controller --initialize|--refresh|--verify  显式登记或核验独立网关控制身份（JSON 从 stdin 读取）"
            echo "  --configure-cf-tunnel  为已有安装配置 CF Tunnel（不升级程序或迁移数据库）"
            echo "  --check-cf-tunnel      只检查 CF 两端页面、API 和隧道连接"
            echo "  --help        显示帮助"
            ;;
        *)
            do_install
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
