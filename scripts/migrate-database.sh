#!/usr/bin/env bash
set -Eeuo pipefail
# Prisma's TypeScript config loader writes a Jiti code cache inside node_modules.
# Never generate group/world-writable executable cache when systemd's '+' root
# startup command runs without inheriting the service account's usual umask.
umask 077
export JITI_FS_CACHE=false
stage=runtime-directory
trap 'printf "DATABASE_MIGRATION_PREPARATION_FAILED:%s\n" "$stage" >&2' ERR
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
if [[ "$root" == /usr/local/libexec ]]; then
  root=/opt/incudal
  [[ ! -L /opt/incudal/current ]] || root=$(readlink -f -- /opt/incudal/current)
fi
root=$(readlink -f -- "$root")
[[ "$root" == /opt/incudal || "$root" == /opt/incudal/releases/* ]] || { echo 'DATABASE_MIGRATION_RUNTIME_PATH_INVALID' >&2;exit 1; }
if [[ ! -d "$root" || $(stat -c %u "$root") != 0 || -n $(find "$root/server" -xdev \( -type f -o -type d \) \( ! -user root -o -perm /022 \) -print -quit) ]]; then
  echo 'DATABASE_MIGRATION_RUNTIME_UNTRUSTED' >&2
  # Classify the rejected tree without exposing certificate names or contents.
  /usr/bin/python3 -I -B - "$root" <<'PY'
import os,sys,stat
from pathlib import Path
root=Path(sys.argv[1]);print('DATABASE_MIGRATION_ROOT_METADATA',root.stat().st_uid,oct(stat.S_IMODE(root.stat().st_mode)),flush=True)
count=0
for parent,directories,files in os.walk(root/'server',followlinks=False):
    for name in ['',*files]:
        path=Path(parent)/name
        info=path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode)or stat.S_ISDIR(info.st_mode)):continue
        if info.st_uid==0 and not info.st_mode&0o022:continue
        relative=path.relative_to(root/'server');category=relative.parts[0]if relative.parts and relative.parts[0]in ['certs','node_modules','dist','prisma','templates']else 'other'
        print('DATABASE_MIGRATION_REJECTED_METADATA',category,info.st_uid,oct(stat.S_IMODE(info.st_mode)),flush=True)
        count+=1
        if count>=8:raise SystemExit(0)
PY
  exit 1
fi
env_file="${ENV_FILE:-/opt/incudal/.env}"
stage=environment
[[ $EUID -eq 0 && -f "$env_file" && ! -L "$env_file" && $(stat -c %u "$env_file") == 0 ]] || { echo 'DATABASE_MIGRATION_ENVIRONMENT_UNTRUSTED' >&2;exit 1; }
export DATABASE_URL
unset NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV PYTHONPATH PYTHONHOME
export PATH=/usr/local/bin:/usr/bin:/bin
stage=migration-identity
DATABASE_URL=$(python3 -I -B - <<'PY'
import sys,urllib.parse
from pathlib import Path
directory=Path('/var/lib/incudal-database')
if not directory.is_dir() or directory.is_symlink() or directory.stat().st_uid!=0 or directory.stat().st_mode&0o077:raise SystemExit('Untrusted migration credential directory')
path=Path('/var/lib/incudal-database/migration.url')
if not path.is_file() or path.is_symlink() or path.stat().st_uid!=0 or path.stat().st_mode&0o077 or path.stat().st_nlink!=1 or path.stat().st_size>4096:raise SystemExit('Untrusted migration credential file')
value=path.read_text().strip();url=urllib.parse.urlsplit(value)
if url.scheme not in ['postgres','postgresql'] or url.hostname not in ['localhost','127.0.0.1','::1'] or url.port!=5432 or url.path!='/incudal' or url.username!='incudal_migrate' or not url.password or url.fragment:raise SystemExit('Untrusted migration credential identity')
print(value)
PY
)
cd "$root/server"
stage=migration-cli
cli=$(readlink -f node_modules/prisma/build/index.js)
[[ "$cli" == "$root/"* && -f "$cli" ]] || { echo 'DATABASE_MIGRATION_CLI_UNTRUSTED' >&2;exit 1; }
stage=prisma-migrate
/usr/bin/node "$cli" migrate deploy
# Credentials stay in a child environment, never a command-line URL.
stage=runtime-grants
/usr/bin/python3 - <<'PY'
import os,subprocess,urllib.parse
url=urllib.parse.urlsplit(os.environ['DATABASE_URL'])
env={'PATH':'/usr/bin:/bin','PGHOST':url.hostname,'PGPORT':url.port and str(url.port) or '5432','PGDATABASE':urllib.parse.unquote(url.path[1:]),'PGUSER':urllib.parse.unquote(url.username),'PGPASSWORD':urllib.parse.unquote(url.password)}
subprocess.run(['/usr/bin/psql','-X','-v','ON_ERROR_STOP=1','-c','REVOKE INSERT,UPDATE,DELETE ON public._prisma_migrations FROM incudal'],env=env,check=True,stdout=subprocess.DEVNULL)
PY
stage=network-mode
/usr/bin/node --input-type=module -e 'const db=await import("./dist/db/prisma.js");try {await db.normalizeLegacyNetworkModes()}finally {await db.closePrismaDatabase()}process.exit(0)'
