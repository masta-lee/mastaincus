#!/usr/bin/env python3
"""Local root database role separation; never handles remote PostgreSQL."""
import os,pathlib,re,secrets,subprocess,urllib.parse,fcntl,hashlib,hmac,base64,tempfile

def run(sql):
    return subprocess.check_output(['runuser','-u','postgres','--','psql','-X','-v','ON_ERROR_STOP=1','-At','-d','postgres'],input=sql.encode(),stderr=subprocess.PIPE).decode().strip()
def literal(value):return "'"+value.replace("'","''")+"'"
def ident(value):return '"'+value.replace('"','""')+'"'
def password_verifier(password):
    # Send PostgreSQL only a SCRAM verifier. DDL logging must never receive the
    # original runtime or migration password as SQL text.
    salt=secrets.token_bytes(16);iterations=4096
    salted=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,iterations)
    stored=hashlib.sha256(hmac.new(salted,b'Client Key','sha256').digest()).digest()
    server=hmac.new(salted,b'Server Key','sha256').digest()
    encode=lambda value:base64.b64encode(value).decode()
    return f'SCRAM-SHA-256${iterations}:{encode(salt)}${encode(stored)}:{encode(server)}'
if os.geteuid()!=0:raise SystemExit('Database role preparation requires local root')
if pathlib.Path('/var/lib/incudal-backup/recovery-hold.json').exists():raise SystemExit(0)
path=pathlib.Path(os.environ.get('ENV_FILE','/opt/incudal/.env'))
if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or path.stat().st_mode&0o022 or path.stat().st_nlink!=1:raise SystemExit('Untrusted database environment file')
lines=path.read_text().splitlines();env={}
for line in lines:
    if '=' in line and not line.lstrip().startswith('#'):
        key,value=line.split('=',1);env[key.strip()]=value.strip().strip("'\"")
url=urllib.parse.urlsplit(env.get('DATABASE_URL',''))
if url.scheme not in ['postgresql','postgres'] or url.fragment or url.hostname not in ['127.0.0.1','localhost','::1'] or url.port not in [None,5432]:raise SystemExit('Remote/custom PostgreSQL requires a reviewed database-role plan')
database=urllib.parse.unquote(url.path.lstrip('/'));runtime=urllib.parse.unquote(url.username or '')
if database!='incudal' or runtime!='incudal':raise SystemExit('Custom database identities require a reviewed database-role plan')
runtime_password=urllib.parse.unquote(url.password or '')
if not runtime_password or not runtime_password.isascii() or any(ord(c)<32 or ord(c)==127 for c in runtime_password):raise SystemExit('Legacy database password requires reviewed SCRAM conversion')
# Reject unsupported patch/runtime states before creating roles or revoking any
# authority. Distro backports require a separately reviewed exact identity.
numeric=int(run("SELECT current_setting('server_version_num')"));minimum={14:25,15:20,16:16,17:12,18:7}
if numeric//10000 not in minimum or numeric%10000<minimum[numeric//10000]:raise SystemExit('Patched PostgreSQL required before database role separation')
# Do not remove legacy DDL authority before the independently retained rollback
# shim can run on this installation's patched Node runtime.
node_check=subprocess.run(['/usr/bin/node','-e',"const [a,b,c]=process.versions.node.split('.').map(Number);const patched=a===22&&(b>23||b===23&&c>=5)||a===24&&(b>22||b===22&&c>=3);process.exit(patched&&typeof require('node:module').registerHooks==='function'?0:1)"],env={'PATH':'/usr/bin:/bin'},stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
if node_check.returncode:raise SystemExit('Database security preparation requires a patched Node 22 or 24 runtime')
config_path=pathlib.Path(run("SELECT setting FROM pg_settings WHERE name='config_file'"))
hba=pathlib.Path(run("SELECT setting FROM pg_settings WHERE name='hba_file'"))
for target in [config_path,hba]:
    if target.is_symlink() or not target.is_file() or target.stat().st_mode&0o022:raise SystemExit('Untrusted PostgreSQL configuration path')
if run("SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL")!='0':raise SystemExit('PostgreSQL authentication configuration did not validate')
marker='# PayIncus database local-only authentication v1'
rules=[marker,'host incudal incudal,incudal_migrate 127.0.0.0/8 scram-sha-256','host incudal incudal,incudal_migrate ::1/128 scram-sha-256','host incudal all 0.0.0.0/0 reject','host incudal all ::0/0 reject']
if marker in hba.read_text().splitlines() and hba.read_text().splitlines()[:len(rules)]!=rules:raise SystemExit('Retained PostgreSQL authentication policy does not match the reviewed rules')
if os.environ.get('INCUDAL_DATABASE_PREFLIGHT')=='1':
    print('DATABASE_ROLE_PREFLIGHT_READY');raise SystemExit(0)
private_dir=pathlib.Path('/var/lib/incudal-database')
if private_dir.exists() and (private_dir.is_symlink() or private_dir.stat().st_uid!=0 or private_dir.stat().st_mode&0o077):raise SystemExit('Untrusted migration credential directory')
private_dir.mkdir(mode=0o700,exist_ok=True);os.chown(private_dir,0,0);os.chmod(private_dir,0o700)
lock_file=private_dir/'prepare.lock'
lock_fd=os.open(lock_file,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
lock_stat=os.fstat(lock_fd)
if lock_stat.st_uid!=0 or lock_stat.st_nlink!=1 or lock_stat.st_mode&0o077:raise SystemExit('Untrusted database preparation lock')
fcntl.flock(lock_fd,fcntl.LOCK_EX)
private_file=private_dir/'migration.url'
if private_file.exists() and (private_file.is_symlink() or private_file.stat().st_uid!=0 or private_file.stat().st_nlink!=1 or private_file.stat().st_mode&0o077 or private_file.stat().st_size>4096):raise SystemExit('Untrusted migration credential file')
existing=run("SELECT rolname FROM pg_roles WHERE rolname='incudal_migrate'")
# Refuse shared ownership before making any role or credential changes.
if run("SELECT datname FROM pg_database WHERE datdba=(SELECT oid FROM pg_roles WHERE rolname='incudal') AND datname<>'incudal' UNION ALL SELECT spcname FROM pg_tablespace WHERE spcowner=(SELECT oid FROM pg_roles WHERE rolname='incudal')"):
    raise SystemExit('Database role owns unrelated resources; scoped ownership review required')
migration=urllib.parse.urlsplit(private_file.read_text().strip()) if private_file.exists() else None
if migration and (migration.username!='incudal_migrate' or migration.hostname!=url.hostname or migration.path!=url.path or migration.port!=5432 or migration.scheme!=url.scheme or not migration.password):raise SystemExit('Retained migration identity is invalid')
if existing:
    if not migration:raise SystemExit('Existing migration identity does not match the retained configuration')
    password=urllib.parse.unquote(migration.password or '')
else:
    password=urllib.parse.unquote(migration.password or '') if migration else secrets.token_urlsafe(36)
    if not migration:
        address='['+url.hostname+']' if ':' in url.hostname else url.hostname
        provisional=urllib.parse.urlunsplit((url.scheme,'incudal_migrate:'+urllib.parse.quote(password,safe='')+'@'+address+':5432',url.path,url.query,''))
        fd=os.open(private_file,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w')as out:out.write(provisional+'\n');out.flush();os.fsync(out.fileno())
    run("CREATE ROLE incudal_migrate LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD "+literal(password_verifier(password))+';')
# Convert legacy MD5 to SCRAM with the same retained runtime password before
# installing SCRAM HBA rules. Existing connections and credentials stay valid.
# ASCII passwords are used by the installer. Non-ASCII legacy secrets need
# PostgreSQL's exact SASLprep behavior rather than a home-grown replacement.
if not runtime_password.isascii():raise SystemExit('Legacy database password requires reviewed SCRAM conversion')
verifier=run("SELECT rolpassword FROM pg_authid WHERE rolname='incudal'")
if not verifier.startswith('SCRAM-SHA-256$'):
    run('ALTER ROLE incudal PASSWORD '+literal(password_verifier(runtime_password))+';')
else:
    # Repeated startup must preserve the existing SCRAM salt/globals. Validate
    # the retained identity without changing its password on every run.
    check_env={'PATH':'/usr/bin:/bin','PGHOST':url.hostname,'PGPORT':'5432','PGDATABASE':database,'PGUSER':runtime,'PGPASSWORD':runtime_password,'PGCONNECT_TIMEOUT':'5'}
    subprocess.run(['psql','-X','-At','-c','SELECT 1'],env=check_env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
run('ALTER ROLE incudal NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;')
run('ALTER ROLE incudal_migrate NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;')
for role in ['incudal','incudal_migrate']:
    members=run("SELECT parent.rolname FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles child ON child.oid=m.member WHERE child.rolname="+literal(role))
    for parent in members.splitlines():
        if parent:run('REVOKE '+ident(parent)+' FROM '+ident(role)+';')
script="""
BEGIN;
REASSIGN OWNED BY incudal TO incudal_migrate;
ALTER SCHEMA public OWNER TO incudal_migrate;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC,incudal;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC,incudal;
REVOKE CREATE ON SCHEMA public FROM PUBLIC,incudal;
GRANT USAGE ON SCHEMA public TO incudal;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO incudal;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO incudal;
DO $$ BEGIN IF to_regclass('public._prisma_migrations') IS NOT NULL THEN REVOKE INSERT,UPDATE,DELETE ON public._prisma_migrations FROM incudal; END IF; END $$;
ALTER DEFAULT PRIVILEGES FOR ROLE incudal_migrate IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO incudal;
ALTER DEFAULT PRIVILEGES FOR ROLE incudal_migrate IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO incudal;
COMMIT;
"""
subprocess.run(['runuser','-u','postgres','--','psql','-X','-v','ON_ERROR_STOP=1','-d',database],input=script.encode(),check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
run('ALTER DATABASE incudal OWNER TO incudal_migrate; REVOKE ALL ON DATABASE incudal FROM PUBLIC; REVOKE CREATE,TEMPORARY ON DATABASE incudal FROM incudal; GRANT CONNECT ON DATABASE incudal TO incudal;')
address='['+url.hostname+']' if ':' in url.hostname else url.hostname
migration_url=urllib.parse.urlunsplit((url.scheme,'incudal_migrate:'+urllib.parse.quote(password,safe='')+'@'+address+':5432',url.path,url.query,''))
fd,temporary=tempfile.mkstemp(dir=private_dir,prefix='.roles-new-');tmp=pathlib.Path(temporary)
try:
    with os.fdopen(fd,'w')as out:out.write(migration_url+'\n');out.flush();os.fsync(out.fileno())
    os.chown(tmp,0,0);os.replace(tmp,private_file)
finally:
    if tmp.exists():tmp.unlink()
config=run("SELECT setting FROM pg_settings WHERE name='config_file'")
config_path=pathlib.Path(config)
if config_path.is_symlink() or not config_path.is_file():raise SystemExit('Untrusted PostgreSQL configuration path')
# Network rejection takes effect on reload without restarting PostgreSQL or
# changing other applications' listeners. Tighten listen_addresses on the next
# scheduled service restart only when this cluster has no other user databases.
if not run("SELECT datname FROM pg_database WHERE NOT datistemplate AND datname NOT IN ('postgres','incudal')"):
    include=config_path.parent/'conf.d'
    if include.is_symlink():raise SystemExit('Untrusted PostgreSQL include directory')
    include.mkdir(exist_ok=True)
    conf=include/'incudal-local-only.conf'
    if conf.is_symlink():raise SystemExit('Untrusted PostgreSQL include file')
    conf.write_text("listen_addresses = 'localhost'\n")
    if not re.search(r"^\s*include_dir\s*=\s*'conf.d'",config_path.read_text(),re.M):
        with config_path.open('a')as out:out.write("\ninclude_dir = 'conf.d'\n")
hba=pathlib.Path(run("SELECT setting FROM pg_settings WHERE name='hba_file'"))
if hba.is_symlink() or not hba.is_file():raise SystemExit('Untrusted PostgreSQL authentication configuration')
marker='# PayIncus database local-only authentication v1'
rules=[marker,'host incudal incudal,incudal_migrate 127.0.0.0/8 scram-sha-256','host incudal incudal,incudal_migrate ::1/128 scram-sha-256','host incudal all 0.0.0.0/0 reject','host incudal all ::0/0 reject']
hba_lines=hba.read_text().splitlines()
if marker in hba_lines and hba_lines[:len(rules)]!=rules:raise SystemExit('Retained PostgreSQL authentication policy does not match the reviewed rules')
if marker not in hba_lines:
    original=hba.read_bytes()
    def replace_hba(data):
        fd,temporary_name=tempfile.mkstemp(prefix='.incudal-hba-',dir=hba.parent)
        temporary=pathlib.Path(temporary_name)
        try:
            with os.fdopen(fd,'wb')as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
            os.chown(temporary,hba.stat().st_uid,hba.stat().st_gid);os.chmod(temporary,hba.stat().st_mode&0o777)
            os.replace(temporary,hba)
        finally:
            if temporary.exists():temporary.unlink()
    try:
        replace_hba(('\n'.join(rules+hba_lines)+'\n').encode())
        # Validate the complete file before reloading. A pre-existing bad line
        # must not leave a partially written authentication policy installed.
        if run("SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL")!='0':raise ValueError('PostgreSQL authentication configuration did not validate')
        if run('SELECT pg_reload_conf();')!='t':raise ValueError('PostgreSQL authentication configuration did not reload')
    except Exception:
        replace_hba(original);run('SELECT pg_reload_conf();');raise
else:
    if run("SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL")!='0':raise SystemExit('PostgreSQL authentication configuration did not validate')
    run('SELECT pg_reload_conf();')
print('DATABASE_ROLE_SEPARATION_READY')
