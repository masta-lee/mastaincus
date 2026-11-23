"""Real PostgreSQL regression in the disposable installer/upgrade VM only."""
import ast,pathlib,subprocess,sys

def main():
    source=pathlib.Path(__file__).with_name('harden-database.py').read_text()
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
        before=query(name,'SELECT row_to_json(t) FROM scope_probe t')
        for _ in range(2):query(name,'BEGIN;'+sql+'COMMIT;')
        assert query(name,'SELECT row_to_json(t) FROM scope_probe t')==before
        assert query(name,"SELECT count(*) FROM pg_class WHERE relname='scope_probe' AND relowner=(SELECT oid FROM pg_roles WHERE rolname='incudal_migrate')")=='1'
        assert query('postgres',"SELECT datdba=(SELECT oid FROM pg_roles WHERE rolname='incudal') FROM pg_database WHERE datname='"+name+"'")=='t'
        query(name,'CREATE SCHEMA forbidden AUTHORIZATION incudal;CREATE TABLE forbidden.reject_me(id int);ALTER TABLE forbidden.reject_me OWNER TO incudal;CREATE TABLE public.atomic_probe(id int);ALTER TABLE public.atomic_probe OWNER TO incudal;')
        try:query(name,'BEGIN;'+sql+'COMMIT;');raise AssertionError('unhandled ownership accepted')
        except subprocess.CalledProcessError as error:assert b'DATABASE_LOCAL_OWNERSHIP_UNSUPPORTED' in error.stderr
        assert query(name,"SELECT relowner=(SELECT oid FROM pg_roles WHERE rolname='incudal') FROM pg_class WHERE relname='atomic_probe'")=='t'
        print('PASS scoped ownership: unchanged data/shared DB owners, repeat-safe transfer, unsupported-local atomic rollback')
    finally:
        if created:query('postgres','DROP DATABASE '+name)
        if role_created:query('postgres','DROP ROLE incudal_migrate')
        assert query('postgres',"SELECT coalesce(json_agg(json_build_array(datname,datdba)ORDER BY datname),'[]') FROM pg_database")==baseline

if __name__=='__main__':main()
