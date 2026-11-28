import { spawn, execFile } from 'node:child_process'
import { createReadStream, createWriteStream, existsSync } from 'node:fs'
import { chmod, mkdir, mkdtemp, open, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { pipeline } from 'node:stream/promises'
import { promisify } from 'node:util'
import { createHash } from 'node:crypto'
import { Pool, type PoolClient } from 'pg'
import { BackupError, ensure } from './platform-backup-core.js'
import type { BackupMigration } from './platform-backup-compatibility.js'
import { ensureBackupLocales } from './platform-backup-locale.js'
import { verifyFinancialDatabaseSeals } from '../lib/financial-integrity.js'
import { retainedMigrationIdentity } from '../lib/database-migration-identity.js'

const exec = promisify(execFile)
export function postgresConnection() {
  const url = new URL(process.env.DATABASE_URL || '')
  ensure(url.protocol === 'postgresql:' || url.protocol === 'postgres:', 'OSS_DATABASE_INVALID')
  const database = decodeURIComponent(url.pathname.slice(1)), user = decodeURIComponent(url.username)
  ensure(database && user && database.length <= 63 && !/[\x00-\x1f]/.test(database + user), 'OSS_DATABASE_INVALID')
  return { url, database, user }
}
function pgEnv(database?: string) {
  const connection = postgresConnection()
  return { PATH: '/usr/local/bin:/usr/bin:/bin', PGHOST: connection.url.hostname, PGPORT: connection.url.port || '5432',
    PGUSER: connection.user, PGPASSWORD: decodeURIComponent(connection.url.password), PGDATABASE: database || connection.database,
    PGSSLMODE: connection.url.searchParams.get('sslmode') || 'prefer', PGCONNECT_TIMEOUT: '15', LC_ALL: 'C' }
}
// Classify locally; utility diagnostics can contain SQL, values and credentials.
// Only the fixed code may reach a task receipt, never the raw stderr text.
export function databaseToolFailure(stderr: string, launchCode?: string, timedOut = false): BackupError {
  if (timedOut) return new BackupError('OSS_DATABASE_TOOL_TIMEOUT', 503)
  if (launchCode === 'ENOENT') return new BackupError('OSS_DATABASE_TOOL_MISSING', 503)
  if (['EACCES','EPERM'].includes(launchCode || '') || /permission denied|password authentication failed|no pg_hba.conf entry|must be (?:owner|superuser)/i.test(stderr))
    return new BackupError('OSS_DATABASE_TOOL_PERMISSION_DENIED', 503)
  if (/no space left on device|disk full/i.test(stderr)) return new BackupError('OSS_DATABASE_STORAGE_FULL', 503)
  if (/unsupported version .* in file header|does not appear to be a valid archive|input file is too short|unexpected end of file|could not read from input file/i.test(stderr))
    return new BackupError('OSS_DATABASE_ARCHIVE_INVALID', 409)
  if (/connection refused|could not connect to server|connection to server .* failed|server closed the connection unexpectedly|database system is (?:starting up|shutting down)|connection timed out/i.test(stderr))
    return new BackupError('OSS_DATABASE_UNAVAILABLE', 503)
  return new BackupError('OSS_DATABASE_TOOL_FAILED', 503)
}
export async function pgQuery<T extends import('pg').QueryResultRow>(sql: string, params: unknown[] = [], database?: string): Promise<T[]> {
  let { url } = postgresConnection()
  if (database && process.platform === 'linux' && process.getuid?.() === 0 && /^incudal_(check|restore|verify)_[a-f0-9]{32}$/.test(database)) url = await retainedMigrationIdentity(url)
  if (database) url.pathname = `/${database}`
  const pool = new Pool({ connectionString: url.toString(), max: 1, connectionTimeoutMillis: 15000, statement_timeout: 60000 })
  try { return (await pool.query<T>(sql, params)).rows } finally { await pool.end() }
}
// Reuse a single connection and snapshot for final recovery gates and changes.
export async function pgRecoveryTransaction<T>(action: (query: typeof pgQuery) => Promise<T>, database?: string): Promise<T> {
  const url = postgresConnection().url
  if (database) url.pathname = `/${database}`
  const pool = new Pool({ connectionString: url.toString(), max: 1, connectionTimeoutMillis: 15000, statement_timeout: 60000 })
  const client = await pool.connect().catch(async error => { await pool.end(); throw error })
  try {
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE')
    const query: typeof pgQuery = async (sql, params = [], database) => {
      ensure(database === undefined, 'OSS_DATABASE_INVALID')
      return (await client.query(sql, params)).rows
    }
    const result = await action(query)
    await client.query('COMMIT')
    return result
  } catch (error) { await client.query('ROLLBACK'); throw error }
  finally { client.release(); await pool.end() }
}
export async function appliedBackupMigrations(database?: string): Promise<BackupMigration[]> {
  const [unfinished] = await pgQuery<{ count: string }>('SELECT count(*)::text AS count FROM "_prisma_migrations" WHERE finished_at IS NULL AND rolled_back_at IS NULL', [], database)
  ensure(unfinished.count === '0', 'OSS_MIGRATION_HISTORY_MISMATCH', 409)
  return pgQuery<BackupMigration>('SELECT migration_name, checksum FROM "_prisma_migrations" WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL ORDER BY migration_name', [], database)
}
export async function databaseMetadata(database?: string) {
  const [info] = await pgQuery<{ version: string; bytes: string; superuser: boolean }>("SELECT current_setting('server_version_num') AS version, pg_database_size(current_database())::text AS bytes, rolsuper AS superuser FROM pg_roles WHERE rolname=current_user", [], database)
  ensure(!info.superuser, 'OSS_DATABASE_SUPERUSER_FORBIDDEN', 503)
  const migrations = await appliedBackupMigrations(database)
  return { postgresMajor: Math.floor(Number(info.version) / 10000), bytes: Number(info.bytes), migrationHash: createHash('sha256').update(JSON.stringify(migrations)).digest('hex') }
}
type PgTool = 'pg_dump' | 'pg_restore' | 'psql'
function pgTool(major: number, name: PgTool) {
  ensure(Number.isInteger(major) && major >= 14 && major <= 30, 'OSS_POSTGRES_VERSION_MISMATCH', 409)
  return `/usr/lib/postgresql/${major}/bin/${name}`
}
async function connectedPgMajor() {
  const [row] = await pgQuery<{ version: string }>("SELECT current_setting('server_version_num') AS version")
  return Math.floor(Number(row.version) / 10000)
}
async function archiveReader(source: string, major: number) {
  const fd = await open(source, 'r')
  const header = Buffer.alloc(8)
  try {
    ensure((await fd.read(header, 0, header.length, 0)).bytesRead === 8
      && header.subarray(0, 5).equals(Buffer.from('PGDMP'))
      && header[5] === 1 && header[6] >= 14 && header[6] <= 16 && header[7] === 0,
    'OSS_DATABASE_ARCHIVE_INVALID', 409)
  }
  finally { await fd.close() }
  const requiredMajor = header[6] === 16 ? 17 : header[6] === 15 ? 16 : 14
  const candidates = [...new Set([major, 14, 15, 16, 17, 18])]
  const inspectorMajor = candidates.find(value => value >= requiredMajor && existsSync(pgTool(value, 'pg_restore')))
  ensure(inspectorMajor, 'OSS_DATABASE_TOOL_MISSING', 503)
  const sourceVersions = await archivedDumpToolchain(source, pgTool(inspectorMajor, 'pg_restore'))
  const producer = dumpVersionMajor(sourceVersions.dumpVersion)
  ensure(dumpVersionMajor(sourceVersions.databaseVersion) === major
    && producer >= major && producer >= requiredMajor && producer <= 18,
  'OSS_POSTGRES_VERSION_MISMATCH', 409)
  // Verification reproduces the producer's schema dump. Check its tool before
  // importing data so an unavailable fingerprint tool leaves the target empty.
  ensure(existsSync(pgTool(producer, 'pg_dump')), 'OSS_DATABASE_TOOL_MISSING', 503)
  const readerMajor = existsSync(pgTool(producer, 'pg_restore')) ? producer : inspectorMajor
  return { reader: pgTool(readerMajor, 'pg_restore'), sourceVersions,
    requiresSqlCompatibility: major < 17 && readerMajor >= 17 }
}
function dumpVersionMajor(version: string) {
  ensure(/^\d+\.\d+(?:\.\d+)?(?: \([^\r\n]{1,200}\))?$/.test(version)
    && [...version].every(character => character.charCodeAt(0) >= 32 && character.charCodeAt(0) <= 126),
  'OSS_DATABASE_ARCHIVE_INVALID', 409)
  return Number.parseInt(version, 10)
}
function sqlDumpToolchain(head: Buffer): DumpToolchain {
  const header = /^--\r?\n-- PostgreSQL database dump\r?\n--\r?\n\r?\n(?:\\restrict [A-Za-z0-9]+\r?\n\r?\n)?-- Dumped from database version ([^\r\n]+)\r?\n-- Dumped by pg_dump version ([^\r\n]+)\r?\n/.exec(head.subarray(0, 4096).toString('latin1'))
  ensure(header, 'OSS_DATABASE_ARCHIVE_INVALID', 409)
  return { databaseVersion: header[1], dumpVersion: header[2] }
}
// The renderer can be newer than the producer named in the archive. Remove
// the unsupported setting only from its bounded native session prologue.
export function compatiblePgRestorePrefix(head: Buffer, versions: DumpToolchain): Buffer {
  const databaseMajor = dumpVersionMajor(versions.databaseVersion)
  const producerMajor = dumpVersionMajor(versions.dumpVersion)
  ensure(databaseMajor >= 14 && databaseMajor <= 18 && producerMajor >= databaseMajor && producerMajor <= 18,
    'OSS_POSTGRES_VERSION_MISMATCH', 409)
  const actual = sqlDumpToolchain(head)
  ensure(actual.databaseVersion === versions.databaseVersion && actual.dumpVersion === versions.dumpVersion,
    'OSS_DATABASE_ARCHIVE_INVALID', 409)
  const text = head.subarray(0, 4096).toString('latin1')
  const opening = /^--\r?\n-- PostgreSQL database dump\r?\n--\r?\n\r?\n(?:\\restrict [A-Za-z0-9]+\r?\n\r?\n)?-- Dumped from database version [^\r\n]+\r?\n-- Dumped by pg_dump version [^\r\n]+\r?\n\r?\n(?:BEGIN;\r?\n\r?\n)?SET statement_timeout = 0;\r?\nSET lock_timeout = 0;\r?\nSET idle_in_transaction_session_timeout = 0;\r?\n/.exec(text)
  ensure(opening, 'OSS_DATABASE_ARCHIVE_INVALID', 409)
  const start = opening[0].length
  const setting = /^SET transaction_timeout = 0;\r?\n/.exec(text.slice(start))
  const next = start + (setting?.[0].length ?? 0)
  ensure(text.startsWith('SET client_encoding = ', next), 'OSS_DATABASE_ARCHIVE_INVALID', 409)
  if (!setting || databaseMajor >= 17) return head
  return Buffer.concat([head.subarray(0, start), head.subarray(next)])
}
async function executeCompatibleRestoreSql(source: string, database: string, args: string[], versions?: DumpToolchain) {
  ensure(/^incudal_(check|restore|verify)_[a-f0-9]{32}$/.test(database) && !/[\r\n]/.test(database),
    'OSS_DATABASE_INVALID')
  const major = await connectedPgMajor()
  const fd = await open(source, 'r')
  try {
    const head = Buffer.alloc(4096)
    const { bytesRead } = await fd.read(head, 0, head.length, 0)
    const sourceVersions = versions ?? sqlDumpToolchain(head.subarray(0, bytesRead))
    ensure(dumpVersionMajor(sourceVersions.databaseVersion) === major, 'OSS_POSTGRES_VERSION_MISMATCH', 409)
    ensure(existsSync(pgTool(dumpVersionMajor(sourceVersions.dumpVersion), 'pg_dump')),
      'OSS_DATABASE_TOOL_MISSING', 503)
    const prefix = compatiblePgRestorePrefix(head.subarray(0, bytesRead), sourceVersions)
    async function* compatibleSql() {
      yield prefix
      yield* fd.createReadStream({start: bytesRead, autoClose: false})
    }
    await runPgTool(pgTool(major, 'psql'), 'psql', args, database, compatibleSql(), undefined, true)
  } finally { await fd.close() }
}
async function pgProcess(command: PgTool, args: string[], database: string | undefined, input?: string, output?: string, dumpMajor?: number) {
  const major = dumpMajor ?? await connectedPgMajor()
  if (command === 'pg_restore' && input && database) {
    ensure(/^incudal_(check|restore|verify)_[a-f0-9]{32}$/.test(database), 'OSS_DATABASE_INVALID')
    const { reader, sourceVersions, requiresSqlCompatibility } = await archiveReader(input, major)
    if (requiresSqlCompatibility) {
      // Finish decoding before any SQL reaches the isolated target. A corrupt
      // archive or disk write failure can never deliver the generated COMMIT.
      const folder = await mkdtemp(join(dirname(input), '.pg-restore-'))
      const sql = join(folder, 'restore.sql')
      try {
        await runPgTool(reader, 'pg_restore', ['--no-owner', '--no-privileges', '--single-transaction', '--file=-'], undefined, input, sql)
        await executeCompatibleRestoreSql(sql, database,
          ['-X', '--set', 'ON_ERROR_STOP=1', '--no-password', '--dbname', database], sourceVersions)
      } finally { await rm(folder, {recursive:true, force:true}) }
      return
    }
    await runPgTool(reader, command, args, database, input, output)
    return
  }
  await runPgTool(pgTool(major, command), command, args, database, input, output)
}
async function runPgTool(program: string, command: PgTool, args: string[], database: string | undefined, input?: string | AsyncIterable<Buffer>, output?: string, unprivilegedOs = false) {
  let uid = Number((await exec('/usr/bin/id', ['-u', 'incudal'])).stdout.trim())
  let gid = Number((await exec('/usr/bin/id', ['-g', 'incudal'])).stdout.trim())
  ensure(uid > 0 && gid > 0, 'OSS_RUNTIME_INVALID', 503)
  let environment = pgEnv(database)
  if (database && command !== 'pg_dump') {
    ensure(/^incudal_(check|restore|verify)_[a-f0-9]{32}$/.test(database), 'OSS_DATABASE_INVALID')
    const migrationUrl=await retainedMigrationIdentity(postgresConnection().url)
    if (!unprivilegedOs) { uid=0;gid=0 }
    environment={...environment,PGUSER:decodeURIComponent(migrationUrl.username),PGPASSWORD:decodeURIComponent(migrationUrl.password)}
  }
  const child = spawn(program, args, { uid, gid, env: environment, stdio: ['pipe', 'pipe', 'pipe'] })
  let timedOut = false, diagnostic = ''
  const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL') }, 60 * 60 * 1000)
  child.stderr.on('data', chunk => { diagnostic = (diagnostic + chunk.toString()).slice(-32768) })
  const finished = new Promise<void>((resolve, reject) => {
    child.once('error', (error: NodeJS.ErrnoException) => reject(databaseToolFailure(diagnostic, error.code, timedOut)))
    child.once('close', code => code === 0 ? resolve() : reject(databaseToolFailure(diagnostic, undefined, timedOut)))
  })
  try {
    const operations: Promise<unknown>[] = [finished]
    if (input) operations.push(pipeline(typeof input === 'string' ? createReadStream(input) : input, child.stdin))
    else child.stdin.end()
    if (output) operations.push(pipeline(child.stdout, createWriteStream(output, { flags: 'wx', mode: 0o600 })))
    else child.stdout.resume()
    try { await Promise.all(operations) }
    catch (error) {
      // An early utility refusal can close stdin first. Preserve the actual
      // utility classification instead of turning EPIPE into a retryable outage.
      if ((error as NodeJS.ErrnoException).code === 'EPIPE') await finished
      throw error
    }
  } finally { clearTimeout(timer); if (child.exitCode === null) child.kill('SIGKILL') }
}
export async function dumpDatabase(destination: string, snapshot?: string, database?: string) {
  // Preserve ownership and grants in the archive; restore maps them separately.
  if(database)ensure(/^incudal_check_[a-f0-9]{32}$/.test(database),'OSS_DATABASE_INVALID')
  await pgProcess('pg_dump', ['--format=custom', '--create', '--large-objects', ...(snapshot ? [`--snapshot=${validateSnapshot(snapshot)}`] : [])], database, undefined, destination)
}
export async function restoreDatabase(source: string, target: string) {
  await pgProcess('pg_restore', ['--dbname', target, '--no-owner', '--no-privileges', '--exit-on-error', '--single-transaction'], target, source)
  await grantRestoredRuntime(target)
}
export function restoredLargeObjectOwnershipSql(target: string, runtime: string): string {
  ensure(typeof target==='string' && /^incudal_(check|restore|verify)_[a-f0-9]{32}$/.test(target) && !/[\r\n]/.test(target) && runtime === 'incudal', 'OSS_DATABASE_LO_RESTORE_SCOPE_INVALID', 409)
  // Native lo_unlink requires ownership, not SELECT/UPDATE grants. Only these
  // restored data objects belong to the runtime; schema/DDL owners stay separate.
  return `\\connect ${quoteIdentifier(target)}
BEGIN;
SET LOCAL search_path = pg_catalog;
DO $incudal_lo_ownership$ DECLARE runtime_id oid; migration_id oid; item record; BEGIN
  SELECT oid INTO runtime_id FROM pg_roles WHERE rolname='incudal' AND rolcanlogin
    AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls);
  SELECT oid INTO migration_id FROM pg_roles WHERE rolname='incudal_migrate' AND rolcanlogin
    AND NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls);
  IF current_database()<>${quoteLiteral(target)} OR runtime_id IS NULL OR migration_id IS NULL
    OR NOT EXISTS(SELECT 1 FROM pg_database WHERE datname=current_database() AND datdba=migration_id)
    OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member IN (runtime_id,migration_id) OR roleid IN (runtime_id,migration_id)) THEN
    RAISE EXCEPTION 'OSS_DATABASE_LO_RESTORE_SCOPE_INVALID';
  END IF;
  IF EXISTS(SELECT 1 FROM pg_largeobject_metadata m WHERE m.lomowner NOT IN (runtime_id,migration_id)
    OR EXISTS(SELECT 1 FROM aclexplode(m.lomacl) a WHERE a.grantor NOT IN (runtime_id,migration_id)
      OR a.grantee NOT IN (runtime_id,migration_id))) THEN
    RAISE EXCEPTION 'OSS_DATABASE_LO_RESTORE_AUTHORIZATION_INVALID';
  END IF;
  FOR item IN SELECT oid,lomowner FROM pg_largeobject_metadata ORDER BY oid LOOP
    IF item.lomowner<>runtime_id THEN
      EXECUTE format('ALTER LARGE OBJECT %s OWNER TO %I',item.oid,'incudal');
    END IF;
    EXECUTE format('GRANT SELECT,UPDATE ON LARGE OBJECT %s TO %I',item.oid,'incudal');
  END LOOP;
  IF EXISTS(SELECT 1 FROM pg_largeobject_metadata m WHERE m.lomowner<>runtime_id
    OR NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(m.lomacl,acldefault('L',m.lomowner))) a WHERE a.grantee=runtime_id AND a.privilege_type='SELECT')
    OR NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(m.lomacl,acldefault('L',m.lomowner))) a WHERE a.grantee=runtime_id AND a.privilege_type='UPDATE')
    OR EXISTS(SELECT 1 FROM aclexplode(m.lomacl) a WHERE a.grantor<>runtime_id OR a.grantee<>runtime_id)) THEN
    RAISE EXCEPTION 'OSS_DATABASE_LO_RESTORE_AUTHORIZATION_INVALID';
  END IF;
END $incudal_lo_ownership$;
COMMIT;
`
}
async function grantRestoredRuntime(target: string) {
  ensure(/^incudal_(check|restore|verify)_[a-f0-9]{32}$/.test(target), 'OSS_DATABASE_INVALID')
  const connection=postgresConnection()
  const [objects]=await pgQuery<{present:boolean}>('SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_largeobject_metadata) AS present',[],target)
  ensure(typeof objects?.present==='boolean','OSS_DATABASE_LO_RESTORE_SCOPE_INVALID',409)
  if(objects.present){
    ensure(connection.database==='incudal'&&connection.user==='incudal','OSS_DATABASE_LO_RESTORE_SCOPE_INVALID',409)
    await localDatabaseAdmin(restoredLargeObjectOwnershipSql(target,connection.user))
  }
  const user=quoteIdentifier(connection.user)
  const sql=`REVOKE ALL ON DATABASE ${quoteIdentifier(target)} FROM PUBLIC; REVOKE CREATE,TEMPORARY ON DATABASE ${quoteIdentifier(target)} FROM ${user}; GRANT CONNECT ON DATABASE ${quoteIdentifier(target)} TO ${user};
    DO $incudal_grants$ DECLARE n record; role_name text:=${quoteLiteral(postgresConnection().user)}; BEGIN FOR n IN SELECT nspname FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname<>'information_schema' LOOP
      EXECUTE format('REVOKE CREATE ON SCHEMA %I FROM PUBLIC,%I',n.nspname,role_name);
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM PUBLIC,%I',n.nspname,role_name);
      EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM PUBLIC,%I',n.nspname,role_name);
      EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I',n.nspname,role_name);
      EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA %I TO %I',n.nspname,role_name);
      EXECUTE format('GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I',n.nspname,role_name);
    END LOOP; END $incudal_grants$; REVOKE INSERT,UPDATE,DELETE ON public._prisma_migrations FROM ${user};`
  const environment=pgEnv(target),migrationUrl=await retainedMigrationIdentity(postgresConnection().url)
  await exec('/usr/bin/psql',['-X','--set','ON_ERROR_STOP=1','-c',sql],{uid:0,gid:0,env:{...environment,PGUSER:decodeURIComponent(migrationUrl.username),PGPASSWORD:decodeURIComponent(migrationUrl.password)},timeout:15000,maxBuffer:4096})
}

export async function migrateBackupDatabase(app: string, database: string) {
  const uid = Number((await exec('/usr/bin/id', ['-u', 'incudal'])).stdout.trim())
  const gid = Number((await exec('/usr/bin/id', ['-g', 'incudal'])).stdout.trim())
  ensure(uid > 0 && gid > 0 && /^incudal_(check|restore)_[a-f0-9]{32}$/.test(database), 'OSS_RUNTIME_INVALID', 503)
  const url = await retainedMigrationIdentity(postgresConnection().url); url.pathname = `/${database}`
  // Execute installed release tooling only, with destination credentials in env.
  // Never load archived .env or execute archived migration files.
  try {
    await exec('/usr/bin/node', [join(app, 'server/node_modules/prisma/build/index.js'), 'migrate', 'deploy'], {
      cwd: join(app, 'server'), uid:0, gid:0, timeout: 10 * 60 * 1000, maxBuffer: 1024 * 1024,
      env: { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: '/opt/incudal', NODE_ENV: 'production', JITI_FS_CACHE:'false', DATABASE_URL: url.toString() }
    })
  } catch { throw new BackupError('OSS_BACKUP_MIGRATION_FAILED', 409) }
  await grantRestoredRuntime(database)
}
export async function restoreDatabaseSql(source: string, target: string) {
  await executeCompatibleRestoreSql(source, target,
    ['-X', '--set', 'ON_ERROR_STOP=1', '--single-transaction', '--no-password', '--dbname', target])
  await grantRestoredRuntime(target)
}
// Derive SQL from the already verified custom archive, never a second live dump.
export async function exportReadableDatabase(source: string, report: DatabaseIntegrity, directory: string) {
  const folder = join(directory, 'readable-sql'); await mkdir(folder, { mode: 0o700 })
  const sources: Array<{ name: string; path: string }> = []
  const { reader } = await archiveReader(source, await connectedPgMajor())
  const exportSql = async (name: string, args: string[]) => {
    const path = join(folder, `${sources.length}.sql`)
    await exec(reader, [...args, '--file', path, source], { env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }, timeout: 3600000, maxBuffer: 65536 })
    await chmod(path, 0o600); sources.push({ name, path })
  }
  // Portable full SQL restores into an explicitly selected isolated target.
  // The native dump and globals retain original ownership/authorization.
  await exportSql('database.sql', ['--no-owner', '--no-privileges'])
  for (const table of report.tables) {
    // Percent-encode unusual identifier characters so filenames cannot escape their directory.
    const safe = (value: string) => encodeURIComponent(value).replace(/\./g, '%2E')
    await exportSql(`tables/${safe(table.schema)}/${safe(table.name)}.sql`, ['--schema', table.schema, '--table', table.name])
  }
  return sources
}
export const quoteIdentifier = (value: string) => `"${value.replace(/"/g, '""')}"`
const quoteLiteral = (value: string) => `'${value.replace(/'/g, "''")}'`
function validateSnapshot(value: string) {
  ensure(/^[0-9a-f-]{1,100}$/i.test(value), 'OSS_DATABASE_SNAPSHOT_INVALID')
  return value
}
export interface DatabaseIntegrity {
  format: 1
  dataEncoding: 'postgres-record-text-v1'
  database: Record<string, unknown>
  schemaSha256: string
  tables: Array<{ schema: string; name: string; kind: string; rows: string; sha256: string }>
  sequences: Array<{ schema: string; name: string; reference: string; lastValue: string; isCalled: boolean }>
  largeObjects: { objects: string; pages: string; sha256: string }
}
const integrityQuery = `SELECT n.nspname AS schema, c.relname AS name, c.relkind AS kind
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname !~ '^pg_' AND n.nspname<>'information_schema' AND c.relkind IN ('r','p','m','f')
  ORDER BY n.nspname COLLATE "C", c.relname COLLATE "C"`
const publicSchemaComment="\n--\n-- Name: public; Type: SCHEMA; Schema: -; Owner: -\n--\n\n-- *not* creating schema, since initdb creates it\n"
async function snapshotConnection(database?: string) {
  const { url } = postgresConnection(); if (database) url.pathname = `/${database}`
  const pool = new Pool({ connectionString: url.toString(), max: 1, connectionTimeoutMillis: 15000, statement_timeout: 3600000 })
  let client: PoolClient | undefined
  try {
    client = await pool.connect()
    await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL search_path=pg_catalog; SET LOCAL timezone='UTC'; SET LOCAL datestyle='ISO'; SET LOCAL extra_float_digits=3; SET LOCAL bytea_output='hex'; SET LOCAL row_security=off")
    const result = await client.query<{ snapshot: string; captured: Date }>('SELECT pg_export_snapshot() AS snapshot,clock_timestamp() AS captured')
    return { client, pool, snapshot: validateSnapshot(result.rows[0].snapshot), snapshotAt: result.rows[0].captured.toISOString() }
  } catch (error) { client?.release(); await pool.end(); throw error }
}
async function closeSnapshot(connection: Awaited<ReturnType<typeof snapshotConnection>>) {
  try { await connection.client.query('ROLLBACK') } finally { connection.client.release(); await connection.pool.end() }
}
export function normalizedDumpHash(value: string) {
  // Patched pg_dump/pg_dumpall generate a fresh psql restrict key on every run.
  // Only normalize the outer session-control pair; keep all database SQL unchanged.
  const match = /^\\restrict ([A-Za-z0-9]+)\r?$/m.exec(value)
  if (match) {
    value = value.slice(0, match.index) + '\\restrict NORMALIZED' + value.slice(match.index + match[0].length)
    const closing = `\\unrestrict ${match[1]}`; const end = value.lastIndexOf(closing)
    ensure(end >= 0, 'OSS_DATABASE_DUMP_INVALID')
    value = value.slice(0, end) + '\\unrestrict NORMALIZED' + value.slice(end + closing.length)
  }
  return createHash('sha256').update(value).digest('hex')
}
interface DumpToolchain { databaseVersion: string; dumpVersion: string }
export function restoreDumpToolchainHeader(value: string, toolchain: DumpToolchain) {
  for (const version of [toolchain.databaseVersion, toolchain.dumpVersion]) {
    ensure(/^\d+\.\d+(?:\.\d+)?(?: \([^\r\n]{1,200}\))?$/.test(version) && [...version].every(character => character.charCodeAt(0) >= 32 && character.charCodeAt(0) <= 126), 'OSS_DATABASE_DUMP_INVALID')
  }
  // Only the pg_dump prologue is rewritten, using metadata from its authenticated
  // custom archive. Keep SQL, function bodies and legacy integrity hashes exact.
  const header = /^(--\r?\n-- PostgreSQL database dump\r?\n--\r?\n(?:\r?\n|\\restrict [A-Za-z0-9]+\r?\n)*-- Dumped from database version )[^\r\n]+(\r?\n-- Dumped by pg_dump version )[^\r\n]+(\r?\n)/
  ensure(header.test(value), 'OSS_DATABASE_DUMP_INVALID')
  return value.replace(header, (_all, opening: string, middle: string, ending: string) => `${opening}${toolchain.databaseVersion}${middle}${toolchain.dumpVersion}${ending}`)
}
async function archivedDumpToolchain(source: string, reader?: string): Promise<DumpToolchain> {
  const program = reader ?? (await archiveReader(source, await connectedPgMajor())).reader
  const { stdout } = await exec(program, ['--list', source], { env: { PATH: '/usr/bin:/bin', LC_ALL:'C' }, maxBuffer: 16 * 1024 * 1024 })
  const field = (name: string) => {
    const matches = [...stdout.matchAll(new RegExp(`^;[ \\t]+${name}: ([^\\r\\n]+)\\r?$`, 'gm'))]
    ensure(matches.length === 1, 'OSS_DATABASE_DUMP_INVALID')
    return matches[0][1]
  }
  return { databaseVersion: field('Dumped from database version'), dumpVersion: field('Dumped by pg_dump version') }
}
export async function schemaFingerprint(directory: string, suffix: string, database?: string, snapshot?: string, toolchain?: DumpToolchain, expectedHash?:string) {
  const path = join(directory, `schema-${suffix}.sql`)
  // Verification normalizes destination role/tablespace mapping only. The actual archive keeps this metadata.
  const fingerprintMajor = toolchain ? dumpVersionMajor(toolchain.dumpVersion) : undefined
  await pgProcess('pg_dump', ['--schema-only', '--no-owner', '--no-privileges', '--no-tablespaces', ...(snapshot ? [`--snapshot=${validateSnapshot(snapshot)}`] : [])], database, undefined, path, fingerprintMajor)
  ensure((await stat(path)).size <= 64 * 1024 * 1024, 'OSS_DATABASE_SCHEMA_TOO_LARGE')
  const value = await readFile(path, 'utf8')
  return publicSchemaFingerprint(toolchain ? restoreDumpToolchainHeader(value, toolchain) : value,expectedHash)
}
// pg_dump emits this comment-only public-schema entry when its owner differs
// from initdb; --no-owner restore maps that owner to the destination creator.
// Normalize only the exact pre-table generated block, never SQL or body text.
export function normalizePublicSchemaPrologue(value:string):string {
  const block=publicSchemaComment
  const marker='\nSET row_security = off;\n',start=value.indexOf(marker)
  if(start<0)return value
  const end=start+marker.length
  if(!value.startsWith(block,end))return value
  // Types and functions may precede the first table. Match only the exact
  // generated block immediately after pg_dump's session preamble.
  const next=end+block.length,extra=value[next]==='\n'&&value[next+1]==='\n'?1:0
  return value.slice(0,end)+value.slice(next+extra)
}
export function publicSchemaFingerprint(value:string,expectedHash?:string):string {
  const normalized=normalizePublicSchemaPrologue(value),canonical=normalizedDumpHash(normalized)
  if(!expectedHash||expectedHash===canonical)return canonical
  // Old authenticated archives used the literal generated comment. Accept
  // that exact cosmetic representation while retaining every SQL byte.
  if(normalizedDumpHash(value)===expectedHash)return expectedHash
  const block=publicSchemaComment
  const marker='\nSET row_security = off;\n',prologueStart=normalized.indexOf(marker)
  if(prologueStart>=0){
    const end=prologueStart+marker.length
    for(const gap of ['','\n']){
      const literal=normalized.slice(0,end)+block+gap+normalized.slice(end)
      if(normalizedDumpHash(literal)===expectedHash)return expectedHash
    }
  }
  return canonical
}
// Fixed local postgres peer connection. Output goes only to a root-private file or a hash.
async function peerUtility(command: 'pg_dumpall' | 'psql', args: string[], database: string, output?: string) {
  const { url } = postgresConnection()
  ensure(['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname), 'OSS_LOCAL_RESTORE_REQUIRED', 409)
  const child = spawn('/usr/sbin/runuser', ['-u', 'postgres', '--', command, ...args], {
    env: { PATH: '/usr/local/bin:/usr/bin:/bin', PGPORT: url.port || '5432', PGDATABASE: database, PGCLIENTENCODING: 'UTF8' }, stdio: ['ignore', 'pipe', 'pipe']
  })
  const timer = setTimeout(() => child.kill('SIGKILL'), 3600000)
  child.stderr.resume()
  const hash = createHash('sha256'); let lines = 0n
  const finished = new Promise<void>((resolve, reject) => {
    child.once('error', () => reject(new BackupError('OSS_DATABASE_TOOL_FAILED', 503)))
    child.once('exit', code => code === 0 ? resolve() : reject(new BackupError('OSS_DATABASE_TOOL_FAILED', 503)))
  })
  try {
    const consume = output ? pipeline(child.stdout, createWriteStream(output, { flags: 'wx', mode: 0o600 })) : (async () => {
      for await (const chunk of child.stdout) { const bytes = Buffer.from(chunk); hash.update(bytes); for (const byte of bytes) if (byte === 10) lines++ }
    })()
    await Promise.all([finished, consume])
    return { pages: lines.toString(), sha256: hash.digest('hex') }
  } finally { clearTimeout(timer); if (child.exitCode === null) child.kill('SIGKILL') }
}
async function inventory(connection: Awaited<ReturnType<typeof snapshotConnection>>, directory: string, suffix: string, database?: string, toolchain?: DumpToolchain, expectedSchema?:string): Promise<DatabaseIntegrity> {
  const { client, snapshot } = connection
  const relations = (await client.query<{ schema: string; name: string; kind: string }>(integrityQuery)).rows
  ensure(relations.length <= 10000, 'OSS_DATABASE_TOO_MANY_TABLES')
  // pg_dump does not include foreign-server table rows by default; fail rather than silently omit them.
  ensure(!relations.some(row => row.kind === 'f'), 'OSS_DATABASE_FOREIGN_TABLE_UNSUPPORTED', 409)
  for (const row of relations) {
    const target = `${quoteIdentifier(row.schema)}.${quoteIdentifier(row.name)}`
    // PostgreSQL rejects explicit LOCK TABLE on materialized views; a SELECT retains the same read lock.
    await client.query(row.kind === 'm' ? `SELECT 1 FROM ${target} LIMIT 0` : `LOCK TABLE ${target} IN ACCESS SHARE MODE`)
  }
  const tables: DatabaseIntegrity['tables'] = []
  for (const relation of relations) {
    const target = `${quoteIdentifier(relation.schema)}.${quoteIdentifier(relation.name)}`
    // SHA256 each complete row in PostgreSQL, then stream the sorted multiset in bounded batches.
    // This detects edits even when counts match, including duplicate rows and tables without a primary key.
    await client.query(`DECLARE incudal_backup_integrity NO SCROLL CURSOR FOR SELECT hash FROM (SELECT encode(sha256(convert_to(pg_catalog.record_out(t)::text,'UTF8')),'hex') AS hash FROM ONLY ${target} t) fingerprints ORDER BY hash COLLATE "C"`)
    const digest = createHash('sha256'); let rows = 0n
    try {
      while (true) {
        const batch = (await client.query<{ hash: string }>('FETCH FORWARD 1000 FROM incudal_backup_integrity')).rows
        if (!batch.length) break
        for (const row of batch) { ensure(/^[a-f0-9]{64}$/.test(row.hash), 'OSS_DATABASE_FINGERPRINT_INVALID'); digest.update(row.hash + '\n'); rows++ }
      }
    } finally { await client.query('CLOSE incudal_backup_integrity') }
    tables.push({ ...relation, rows: rows.toString(), sha256: digest.digest('hex') })
  }
  const [{ properties }] = (await client.query<{ properties: Record<string, unknown> }>("SELECT to_jsonb(d) || jsonb_build_object('encodingName',pg_encoding_to_char(d.encoding)) AS properties FROM pg_database d WHERE datname=current_database()")).rows
  const [{ objects }] = (await client.query<{ objects: string }>('SELECT count(*)::text AS objects FROM pg_largeobject_metadata')).rows
  const sequenceNames = (await client.query<{ schema: string; name: string; reference: string }>(`SELECT n.nspname AS schema,c.relname AS name,format('%I.%I',n.nspname,c.relname) AS reference FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='S' AND n.nspname !~ '^pg_' AND n.nspname<>'information_schema' ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C"`)).rows
  ensure(sequenceNames.length <= 10000, 'OSS_DATABASE_TOO_MANY_TABLES')
  const sequences: DatabaseIntegrity['sequences'] = []
  for (const sequence of sequenceNames) {
    const [{ value, called }] = (await client.query<{ value: string; called: boolean }>(`SELECT last_value::text AS value,is_called AS called FROM ${quoteIdentifier(sequence.schema)}.${quoteIdentifier(sequence.name)}`)).rows
    sequences.push({ ...sequence, lastValue: value, isCalled: called })
  }
  const pages = await peerUtility('psql', ['-X', '-q', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-c', `BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT ${quoteLiteral(snapshot)}; COPY (SELECT loid,pageno,pg_catalog.encode(pg_catalog.sha256(data),'hex') FROM pg_catalog.pg_largeobject ORDER BY loid,pageno) TO STDOUT; COMMIT;`], database || postgresConnection().database)
  return { format: 1, dataEncoding: 'postgres-record-text-v1', database: properties, schemaSha256: await schemaFingerprint(directory, suffix, database, snapshot, toolchain, expectedSchema), tables, sequences, largeObjects: { objects, ...pages } }
}
export function assertDatabaseIntegrity(expected: DatabaseIntegrity, actual: DatabaseIntegrity) {
  ensure(expected?.format === 1 && actual?.format === 1 && expected.dataEncoding === 'postgres-record-text-v1' && actual.dataEncoding === expected.dataEncoding && /^[a-f0-9]{64}$/.test(expected.schemaSha256) && Array.isArray(expected.tables) && expected.tables.length <= 10000 && expected.largeObjects && expected.database, 'OSS_DATABASE_INTEGRITY_INVALID')
  const checks={schema:actual.schemaSha256===expected.schemaSha256,tables:JSON.stringify(actual.tables)===JSON.stringify(expected.tables),
    sequences:JSON.stringify(actual.sequences)===JSON.stringify(expected.sequences),largeObjects:JSON.stringify(actual.largeObjects)===JSON.stringify(expected.largeObjects)}
  if(Object.values(checks).some(value=>!value))console.error('Database backup integrity checks',checks)
  ensure(Object.values(checks).every(Boolean), 'OSS_DATABASE_INTEGRITY_MISMATCH', 409)
  for (const key of ['encoding', 'datcollate', 'datctype', 'datlocprovider', 'daticulocale', 'datlocale']) ensure(actual.database[key] === expected.database[key], 'OSS_DATABASE_LOCALE_MISMATCH', 409)
}
async function archivedSequenceStates(source: string, sequences: DatabaseIntegrity['sequences'], directory: string) {
  if (!sequences.length) return []
  // Sequence counters are non-MVCC. Capture their exact dump values, then verify those values after restore.
  // These pg_restore calls only inspect the locally generated archive; no SQL is executed.
  const env = { PATH: '/usr/bin:/bin', LC_ALL: 'C' }
  const { reader } = await archiveReader(source, await connectedPgMajor())
  const { stdout } = await exec(reader, ['--list', source], { env, maxBuffer: 16 * 1024 * 1024 })
  const entries = stdout.split('\n').filter(line => /^\d+; .* SEQUENCE SET /.test(line))
  const list = join(directory, 'sequence-list'), sql = join(directory, 'sequence-values.sql')
  await writeFile(list, entries.join('\n') + '\n', { flag: 'wx', mode: 0o600 })
  await exec(reader, ['--use-list', list, '--file', sql, source], { env, maxBuffer: 1024 * 1024 })
  await chmod(sql, 0o600)
  ensure((await stat(sql)).size <= 4 * 1024 * 1024, 'OSS_DATABASE_TOO_MANY_TABLES')
  const states = new Map<string, { lastValue: string; isCalled: boolean }>()
  for (const match of (await readFile(sql, 'utf8')).matchAll(/^SELECT pg_catalog\.setval\('((?:[^']|'')*)', (-?\d+), (true|false)\);$/gm)) {
    const name = match[1].replace(/''/g, "'"); ensure(!states.has(name), 'OSS_DATABASE_SEQUENCE_INVALID')
    states.set(name, { lastValue: match[2], isCalled: match[3] === 'true' })
  }
  ensure(states.size === sequences.length, 'OSS_DATABASE_SEQUENCE_INVALID')
  return sequences.map(sequence => { const value = states.get(sequence.reference); ensure(value, 'OSS_DATABASE_SEQUENCE_INVALID'); return { ...sequence, ...value } })
}
export async function captureDatabaseBackup(destination: string, directory: string, database?: string) {
  if(database)ensure(/^incudal_check_[a-f0-9]{32}$/.test(database),'OSS_DATABASE_INVALID')
  const connection = await snapshotConnection(database)
  try {
    const [{ standby }] = (await connection.client.query<{ standby: boolean }>('SELECT pg_is_in_recovery() AS standby')).rows
    ensure(!standby, 'OSS_DATABASE_STANDBY_UNSUPPORTED', 409)
    const globals = join(directory, 'database-globals.sql'), globalsAfter = join(directory, 'database-globals-after.sql')
    await peerUtility('pg_dumpall', ['--globals-only', '--database=postgres'], 'postgres', globals)
    const report = await inventory(connection, directory, 'source', database)
    await dumpDatabase(destination, connection.snapshot, database)
    report.sequences = await archivedSequenceStates(destination, report.sequences, directory)
    const [{ version, bytes }] = (await connection.client.query<{ version: string; bytes: string }>("SELECT current_setting('server_version_num') AS version, pg_database_size(current_database())::text AS bytes")).rows
    const migrations = (await connection.client.query('SELECT migration_name, checksum FROM public."_prisma_migrations" WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL ORDER BY migration_name')).rows
    await peerUtility('pg_dumpall', ['--globals-only', '--database=postgres'], 'postgres', globalsAfter)
    const digest = async (path: string) => { ensure((await stat(path)).size <= 1024 * 1024, 'OSS_DATABASE_GLOBALS_TOO_LARGE'); return normalizedDumpHash(await readFile(path, 'utf8')) }
    ensure(await digest(globals) === await digest(globalsAfter), 'OSS_DATABASE_GLOBALS_CHANGED', 409)
    return { report, globals, snapshotAt: connection.snapshotAt, metadata: { postgresMajor: Math.floor(Number(version) / 10000), bytes: Number(bytes), migrationHash: createHash('sha256').update(JSON.stringify(migrations)).digest('hex') } }
  } finally { await closeSnapshot(connection) }
}
export async function verifyRestoredDatabase(database: string, expected: DatabaseIntegrity, directory: string, suffix: string, source?: string) {
  const toolchain = source ? await archivedDumpToolchain(source) : undefined
  const connection = await snapshotConnection(database)
  try {
    const actual=await inventory(connection,directory,suffix,database,toolchain,expected.schemaSha256)
    if(actual.schemaSha256!==expected.schemaSha256){
      const sourcePath=join(directory,'schema-source.sql'),targetPath=join(directory,`schema-${suffix}.sql`)
      // Root-private local files only. Report categories, never SQL/table names,
      // literal values or credentials. The full integrity refusal remains.
      if(source&&existsSync(sourcePath)){
        const [before,after]=await Promise.all([readFile(sourcePath,'utf8'),readFile(targetPath,'utf8')])
        const original=normalizePublicSchemaPrologue(before),restored=normalizePublicSchemaPrologue(restoreDumpToolchainHeader(after,toolchain!))
        const a=original.split('\n'),b=restored.split('\n');let index=0;while(index<a.length&&a[index]===b[index])index++
        const category=(line:string|undefined)=>!line?'blank':line.startsWith('--')?'comment':line.startsWith('\\')?'session':line.startsWith('SET ')?'setting':line.startsWith('CREATE ')?'create':line.startsWith('ALTER ')?'alter':'sql'
        console.error('Database schema mismatch location',{line:index,source:category(a[index]),restored:category(b[index]),sourceLines:a.length,restoredLines:b.length})
      }
    }
    assertDatabaseIntegrity(expected,actual)
  } finally { await closeSnapshot(connection) }
}
export async function verifyDatabaseBackup(source: string, expected: DatabaseIntegrity, directory: string, taskId: string, allowLegacy = false) {
  ensure(/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(taskId), 'OSS_TASK_INVALID')
  const staging = `incudal_verify_${taskId.replace(/-/g, '')}`
  await createBackupRestoreDatabase(staging, expected)
  try {
    await restoreDatabase(source, staging)
    await verifyRestoredDatabase(staging, expected, directory, 'verified', source)
    const authentication=expected.tables.find(table=>table.schema==='public'&&table.name==='authentication_integrity_seals')
    // Historical unsealed archives retain their exact signed row fingerprints.
    // Never treat a nonempty authenticated seal table as a legacy archive.
    await verifyFinancialDatabaseSeals(staging, process.env.ENCRYPTION_KEY || '', allowLegacy, !allowLegacy||!!authentication&&authentication.rows!=='0')
  }
  finally { await localDatabaseAdmin(`DROP DATABASE ${quoteIdentifier(staging)} WITH (FORCE);`) }
}
export async function createBackupRestoreDatabase(staging: string, expected?: DatabaseIntegrity) {
  ensure(/^incudal_(check|restore|verify)_[a-f0-9]{32}$/.test(staging), 'OSS_RUNTIME_INVALID', 503)
  if (!expected) {
    await localDatabaseAdmin(`CREATE DATABASE ${quoteIdentifier(staging)} OWNER incudal_migrate TEMPLATE template0; REVOKE ALL ON DATABASE ${quoteIdentifier(staging)} FROM PUBLIC; GRANT CONNECT ON DATABASE ${quoteIdentifier(staging)} TO ${quoteIdentifier(postgresConnection().user)};`)
    return
  }
  const properties = expected.database
  ensure(typeof properties.datcollate === 'string' && typeof properties.datctype === 'string' && typeof properties.encodingName === 'string', 'OSS_DATABASE_INTEGRITY_INVALID')
  const provider = properties.datlocprovider
  ensure(!provider || provider === 'c', 'OSS_DATABASE_LOCALE_UNSUPPORTED', 409)
  await ensureBackupLocales([properties.datcollate, properties.datctype])
  // Locale differences must not silently change index or text semantics during verification.
  await localDatabaseAdmin(`CREATE DATABASE ${quoteIdentifier(staging)} OWNER incudal_migrate TEMPLATE template0 ENCODING ${quoteLiteral(properties.encodingName)} LC_COLLATE ${quoteLiteral(properties.datcollate)} LC_CTYPE ${quoteLiteral(properties.datctype)}; REVOKE ALL ON DATABASE ${quoteIdentifier(staging)} FROM PUBLIC; GRANT CONNECT ON DATABASE ${quoteIdentifier(staging)} TO ${quoteIdentifier(postgresConnection().user)};`)
}
export function databaseAdminFailure(stderr: string, timedOut: boolean): string {
  if (timedOut) return 'OSS_DATABASE_ADMIN_TIMEOUT'
  // psql VERBOSITY=verbose adds SQLSTATE. Retain only a fixed classification;
  // SQL text, role names and database contents never enter a public result.
  const states=[...stderr.matchAll(/(?:ERROR|FATAL|PANIC):\s+([0-9A-Z]{5}):/g)].map(row=>row[1])
  if(states.some(code=>['57P01','57P02','57P03','53300','53400','08000','08001','08003','08004','08006'].includes(code)))return 'OSS_DATABASE_UNAVAILABLE'
  if(states.some(code=>['55P03','40P01','40001'].includes(code)))return 'OSS_DATABASE_BUSY'
  if(states.includes('53100'))return 'OSS_DATABASE_STORAGE_FULL'
  if(states.includes('22023') && /invalid LC_(?:COLLATE|CTYPE) locale name/i.test(stderr))return 'OSS_DATABASE_LOCALE_UNAVAILABLE'
  return 'OSS_DATABASE_ADMIN_FAILED'
}
export async function localDatabaseAdmin(sql: string) {
  const { url } = postgresConnection()
  ensure(['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname), 'OSS_LOCAL_RESTORE_REQUIRED', 409)
  // Fixed local peer-authenticated administrator; never use credentials from the archive.
  const child = spawn('/usr/sbin/runuser', ['-u', 'postgres', '--', 'psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose', '-p', url.port || '5432', '-d', 'postgres'], {
    env: { PATH: '/usr/bin:/bin', PGCONNECT_TIMEOUT: '15', LC_ALL:'C' }, stdio: ['pipe', 'pipe', 'pipe']
  })
  let output = ''
  child.stdout.on('data', chunk => { if (output.length < 65536) output += String(chunk) })
  let diagnostic='',timedOut=false
  child.stderr.on('data',chunk=>{diagnostic=(diagnostic+String(chunk)).slice(-65536)})
  const timer = setTimeout(() => {timedOut=true;child.kill('SIGKILL')}, 60000)
  try {
    await new Promise<void>((resolve, reject) => {
      child.once('error', () => reject(new BackupError('OSS_DATABASE_ADMIN_FAILED', 503)))
      child.once('close', async code => {
        if(code===0){resolve();return}
        let failure=databaseAdminFailure(diagnostic,timedOut)
        if(code===2 && failure==='OSS_DATABASE_ADMIN_FAILED') {
          // Exit 2 also covers authentication failure. Probe local readiness
          // before treating it as a temporary outage, without executing SQL.
          try { await exec('/usr/sbin/runuser',['-u','postgres','--','pg_isready','-q','-t','3','-p',url.port||'5432','-d','postgres'],
            {env:{PATH:'/usr/bin:/bin'},timeout:5000}) }
          catch(error){if([1,2].includes(Number((error as {code?:unknown}).code)))failure='OSS_DATABASE_UNAVAILABLE'}
        }
        reject(new BackupError(failure,503))
      })
      child.stdin.on('error', () => {}); child.stdin.end(sql)
    })
    return output.trim()
  } finally { clearTimeout(timer) }
}
