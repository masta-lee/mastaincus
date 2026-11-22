#!/usr/bin/env bash
set -Eeuo pipefail
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
if [[ "$root" == /usr/local/libexec ]]; then root=/opt/incudal/current; [[ -e "$root" ]] || root=/opt/incudal; fi
root=$(readlink -f -- "$root")
[[ "$root" == /opt/incudal || "$root" == /opt/incudal/releases/* ]] || exit 1
[[ -d "$root" && $(stat -c %u "$root") == 0 && -z $(find "$root/server" -xdev \( -type f -o -type d \) \( ! -user root -o -perm /022 \) -print -quit) ]] || exit 1
env_file="${ENV_FILE:-/opt/incudal/.env}"
[[ $EUID -eq 0 && -f "$env_file" && ! -L "$env_file" && $(stat -c %u "$env_file") == 0 ]] || exit 1
export DATABASE_URL
unset NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV PYTHONPATH PYTHONHOME
export PATH=/usr/local/bin:/usr/bin:/bin
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
cli=$(readlink -f node_modules/prisma/build/index.js)
[[ "$cli" == "$root/"* && -f "$cli" ]] || exit 1
/usr/bin/node "$cli" migrate deploy
# Credentials stay in a child environment, never a command-line URL.
/usr/bin/python3 - <<'PY'
import os,subprocess,urllib.parse
url=urllib.parse.urlsplit(os.environ['DATABASE_URL'])
env={'PATH':'/usr/bin:/bin','PGHOST':url.hostname,'PGPORT':url.port and str(url.port) or '5432','PGDATABASE':urllib.parse.unquote(url.path[1:]),'PGUSER':urllib.parse.unquote(url.username),'PGPASSWORD':urllib.parse.unquote(url.password)}
subprocess.run(['/usr/bin/psql','-X','-v','ON_ERROR_STOP=1','-c','REVOKE INSERT,UPDATE,DELETE ON public._prisma_migrations FROM incudal'],env=env,check=True,stdout=subprocess.DEVNULL)
PY
/usr/bin/node --input-type=module -e 'const db=await import("./dist/db/prisma.js");try {await db.normalizeLegacyNetworkModes()}finally {await db.closePrismaDatabase()}process.exit(0)'
