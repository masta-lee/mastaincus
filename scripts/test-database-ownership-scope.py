"""Real PostgreSQL regression in the disposable installer/upgrade VM only."""
import ast,pathlib,subprocess,sys,os,tempfile,stat,re

def check_listening_policy(source):
    tree=ast.parse(source);function=next(node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name=='write_local_listening_policy')
    context={'os':os,'pathlib':pathlib,'tempfile':tempfile,'stat':stat,'re':re};exec(compile(ast.Module(body=[function],type_ignores=[]),'harden-database.py','exec'),context)
    with tempfile.TemporaryDirectory()as folder:
        root=pathlib.Path(folder);root.chmod(0o755);config=root/'postgresql.conf';config.write_text("# original administrator settings\n");config.chmod(0o644)
        old=os.umask(0o077)
        try:
            context['write_local_listening_policy'](config);context['write_local_listening_policy'](config)
        finally:os.umask(old)
        conf=root/'conf.d/incudal-local-only.conf';assert conf.stat().st_mode&0o777==0o644
        assert (root/'conf.d').stat().st_mode&0o777==0o755
        assert subprocess.check_output(['runuser','-u','postgres','--','cat',str(conf)])==b"listen_addresses = 'localhost'\n"
        assert config.read_text().count("include_dir = 'conf.d'")==1
        conf.chmod(0o600);context['write_local_listening_policy'](config);assert conf.stat().st_mode&0o777==0o644
        for mode in ['changed','link','writable']:
            if mode=='changed':conf.write_text('administrator custom value\n')
            if mode=='link':conf.unlink();conf.symlink_to(config)
            if mode=='writable':conf.unlink();conf.write_bytes(b"listen_addresses = 'localhost'\n");conf.chmod(0o666)
            try:context['write_local_listening_policy'](config);raise AssertionError('untrusted policy accepted')
            except ValueError:pass
        print('PASS strict umask: PostgreSQL reads root-owned policy, repeat repair, unknown content/link/write rejects')

def main():
    source=pathlib.Path(__file__).with_name('harden-database.py').read_text()
    check_listening_policy(source)
    tree=ast.parse(source)
    sql=next(ast.literal_eval(node.value)for node in tree.body if isinstance(node,ast.Assign)and any(isinstance(target,ast.Name)and target.id=='ownership_sql'for target in node.targets))
    def query(database,statement):
        return subprocess.check_output(['runuser','-u','postgres','--','psql','-X','-At','-v','ON_ERROR_STOP=1','-d',database,'-c',statement],stderr=subprocess.PIPE).decode().strip()
    baseline=query('postgres',"SELECT coalesce(json_agg(json_build_array(datname,datdba)ORDER BY datname),'[]') FROM pg_database")
    name='incudal_ownership_scope_test';created=False;role_created=False
    try:
        if query('postgres',"SELECT count(*) FROM pg_roles WHERE rolname='incudal_migrate'")=='0':
            query('postgres','CREATE ROLE incudal_migrate NOLOGIN');role_created=True
        query('postgres','CREATE DATABASE '+name+' OWNER incudal');created=True
        query(name,"CREATE TABLE public.scope_probe(id int primary key,value text);ALTER TABLE public.scope_probe OWNER TO incudal;INSERT INTO public.scope_probe VALUES(1,'preserved');CREATE TYPE public.scope_enum AS ENUM('a','b');ALTER TYPE public.scope_enum OWNER TO incudal;CREATE FUNCTION public.scope_function() RETURNS int LANGUAGE sql AS 'SELECT 4';ALTER FUNCTION public.scope_function() OWNER TO incudal;CREATE SEQUENCE public.scope_sequence;ALTER SEQUENCE public.scope_sequence OWNER TO incudal;")
        large=int(query(name,"SELECT lo_from_bytea(0,decode(repeat('0011223344556677',800),'hex'))"))
        empty=int(query(name,'SELECT lo_create(0)'))
        query(name,f'ALTER LARGE OBJECT {large} OWNER TO incudal;ALTER LARGE OBJECT {empty} OWNER TO incudal;')
        lo_state=f"SELECT coalesce(json_agg(json_build_array(oid,lomowner,lomacl::text,encode(sha256(lo_get(oid)),'hex')) ORDER BY oid),'[]') FROM pg_largeobject_metadata WHERE oid IN ({large},{empty})"
        lo_pages=f"SELECT coalesce(json_agg(json_build_array(loid,pageno,encode(sha256(data),'hex')) ORDER BY loid,pageno),'[]') FROM pg_largeobject WHERE loid IN ({large},{empty})"
        original_lo=query(name,lo_state);original_pages=query(name,lo_pages)
        assert int(query(name,f'SELECT count(*) FROM pg_largeobject WHERE loid={large}'))>1
        assert query(name,f'SELECT count(*) FROM pg_largeobject WHERE loid={empty}')=='0'
        before=query(name,'SELECT row_to_json(t) FROM scope_probe t')
        for _ in range(2):query(name,'BEGIN;'+sql+'COMMIT;')
        assert query(name,'SELECT row_to_json(t) FROM scope_probe t')==before
        assert query(name,lo_state)==original_lo and query(name,lo_pages)==original_pages
        assert query(name,f'SET ROLE incudal;SELECT octet_length(lo_get({large}))').splitlines()[-1]=='6400'
        query(name,f"SET ROLE incudal;SELECT lo_put({large},0,decode('aabbccdd','hex'))")
        assert query(name,f"SET ROLE incudal;SELECT encode(lo_get({large},0,4),'hex')").splitlines()[-1]=='aabbccdd'
        assert query(name,f'SET ROLE incudal;SELECT lo_unlink({empty})').splitlines()[-1]=='1'
        assert query(name,"SELECT count(*) FROM pg_class WHERE relname='scope_probe' AND relowner=(SELECT oid FROM pg_roles WHERE rolname='incudal_migrate')")=='1'
        assert query('postgres',"SELECT datdba=(SELECT oid FROM pg_roles WHERE rolname='incudal') FROM pg_database WHERE datname='"+name+"'")=='t'
        query(name,'CREATE SCHEMA forbidden AUTHORIZATION incudal;CREATE TABLE forbidden.reject_me(id int);ALTER TABLE forbidden.reject_me OWNER TO incudal;CREATE TABLE public.atomic_probe(id int);ALTER TABLE public.atomic_probe OWNER TO incudal;')
        try:query(name,'BEGIN;'+sql+'COMMIT;');raise AssertionError('unhandled ownership accepted')
        except subprocess.CalledProcessError as error:assert b'DATABASE_LOCAL_OWNERSHIP_UNSUPPORTED' in error.stderr
        assert query(name,"SELECT relowner=(SELECT oid FROM pg_roles WHERE rolname='incudal') FROM pg_class WHERE relname='atomic_probe'")=='t'
        assert query(name,f'SET ROLE incudal;SELECT lo_unlink({large})').splitlines()[-1]=='1'
        print('PASS scoped ownership: unchanged data/shared DB owners and original multi/zero-page LO, native runtime LO read/write/unlink, repeat-safe transfer, other-local-owner atomic refusal')
    finally:
        if created:query('postgres','DROP DATABASE '+name)
        if role_created:query('postgres','DROP ROLE incudal_migrate')
        assert query('postgres',"SELECT coalesce(json_agg(json_build_array(datname,datdba)ORDER BY datname),'[]') FROM pg_database")==baseline

if __name__=='__main__':main()
