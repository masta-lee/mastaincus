import type { PrismaClient } from '@prisma/client'

export async function assertRuntimeDatabaseRole(db: PrismaClient) {
  const [version]=await db.$queryRaw<Array<{version:string}>>`SELECT current_setting('server_version_num') version`
  // Checked upstream baselines; distro revisions/backports must be reviewed
  // against the official tracker, never inferred from an arbitrary suffix.
  const numeric=Number(version?.version),major=Math.floor(numeric/10000),minimum:Record<number,number>={14:25,15:20,16:16,17:12,18:7}
  if(!minimum[major]||numeric%10000<minimum[major])throw new Error('DATABASE_SECURITY_PATCH_REQUIRED')
  const [role]=await db.$queryRaw<Array<{superuser:boolean;create_role:boolean;create_db:boolean;bypass_rls:boolean;replication:boolean;owner:boolean;member:boolean}>>`
    SELECT r.rolsuper superuser,r.rolcreaterole create_role,r.rolcreatedb create_db,r.rolbypassrls bypass_rls,r.rolreplication replication,
      d.datdba=r.oid owner,EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid) member
    FROM pg_roles r JOIN pg_database d ON d.datname=current_database() WHERE r.rolname=current_user`
  if(!role || role.superuser||role.create_role||role.create_db||role.bypass_rls||role.replication||role.owner||role.member)throw new Error('DATABASE_RUNTIME_ROLE_UNSAFE')
  const [objects]=await db.$queryRaw<Array<{owned:boolean}>>`SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user)) owned`
  if(objects.owned)throw new Error('DATABASE_RUNTIME_OBJECT_OWNERSHIP_UNSAFE')
  const [privileges] = await db.$queryRaw<Array<{schema_create:boolean;temporary_create:boolean;dangerous_function:boolean;migration_write:boolean}>>`
    SELECT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND has_schema_privilege(current_user,n.oid,'CREATE')) schema_create,
      has_database_privilege(current_user,current_database(),'TEMPORARY') temporary_create,
      EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND p.prosecdef AND has_function_privilege(current_user,p.oid,'EXECUTE')) dangerous_function,
      CASE WHEN to_regclass('public._prisma_migrations') IS NULL THEN false ELSE has_table_privilege(current_user,'public._prisma_migrations','INSERT,UPDATE,DELETE') END migration_write`
  if (!privileges || privileges.schema_create || privileges.temporary_create || privileges.dangerous_function || privileges.migration_write) throw new Error('DATABASE_RUNTIME_PRIVILEGES_UNSAFE')
  const [tables]=await db.$queryRaw<Array<{unsafe:boolean}>>`SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','m') AND has_table_privilege(current_user,c.oid,'TRUNCATE,TRIGGER')) unsafe`
  if(!tables||tables.unsafe)throw new Error('DATABASE_RUNTIME_TABLE_PRIVILEGES_UNSAFE')
}
