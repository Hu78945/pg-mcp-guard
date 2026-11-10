/** The MCP surface: tools and resources, through a real MCP client. */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createReadOnlyRunner } from '../src/db.js';
import { startServer } from './helpers.js';

let ctx: Awaited<ReturnType<typeof startServer>>;
beforeAll(async () => (ctx = await startServer()));
afterAll(() => ctx.close());

describe('tools', () => {
  it('advertises exactly the five read-only tools', async () => {
    const { tools } = await ctx.client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(['describe_table', 'explain_query', 'list_schemas', 'run_query', 'sample_rows']);
    expect(tools.every((t) => t.annotations?.readOnlyHint)).toBe(true);
  });

  it('list_schemas shows only allowlisted tables', async () => {
    const { data } = await ctx.call('list_schemas');
    expect(data.public.map((t: { table: string }) => t.table).sort()).toEqual(['customers', 'order_items', 'orders', 'products']);
    expect(data.public.find((t: { table: string }) => t.table === 'orders').rowEstimate).toBe(1000);
  });

  it('describe_table returns columns, masks, comments and foreign keys, without hidden columns', async () => {
    const { data } = await ctx.call('describe_table', { table: 'customers' });
    const cols = Object.fromEntries(data.columns.map((c: { name: string }) => [c.name, c]));
    expect(Object.keys(cols)).not.toContain('password_hash');
    expect(cols.email).toMatchObject({ type: 'text', nullable: false, mask: 'email', comment: expect.stringContaining('PII') });
    expect(data.comment).toMatch(/PII/);

    const orders = await ctx.call('describe_table', { table: 'public.orders' });
    expect(orders.data.foreignKeys).toEqual([
      { name: 'orders_customer_id_fkey', definition: 'FOREIGN KEY (customer_id) REFERENCES customers(id)' },
    ]);
  });

  it('describe_table refuses hidden tables', async () => {
    const res = await ctx.call('describe_table', { table: 'admin_users' });
    expect(res.isError).toBe(true);
  });

  it('sample_rows applies masking', async () => {
    const { data } = await ctx.call('sample_rows', { table: 'customers', limit: 3 });
    expect(data.rowCount).toBe(3);
    expect(data.columns).toEqual(['id', 'full_name', 'email', 'phone', 'city', 'created_at']);
    expect(data.rows[0][2]).toBe('***@example.com');
    expect(data.rows[0][3]).toMatch(/^\*\*\*\d{4}$/);
  });

  it('run_query reports truncation at the row cap', async () => {
    const { data } = await ctx.call('run_query', { sql: 'SELECT * FROM order_items' });
    expect(data).toMatchObject({ rowCount: ctx.policy.maxRows, truncated: true });
  });

  it('run_query keeps duplicate column names (array rows)', async () => {
    const { data } = await ctx.call('run_query', { sql: 'SELECT o.id, c.id FROM orders o JOIN customers c ON c.id = o.customer_id LIMIT 1' });
    expect(data.columns).toEqual(['id', 'id']);
    expect(data.rows[0]).toHaveLength(2);
  });

  it('explain_query returns a JSON plan without executing', async () => {
    const { data } = await ctx.call('explain_query', { sql: 'SELECT * FROM orders WHERE customer_id = 5' });
    expect(data.plan[0].Plan['Node Type']).toBeDefined();
    expect(data.executedSql).not.toMatch(/LIMIT/);
    const bad = await ctx.call('explain_query', { sql: 'DELETE FROM orders' });
    expect(bad.text).toMatch(/^Rejected by guard/);
  });
});

describe('resources', () => {
  it('exposes the visible schema as one JSON document', async () => {
    const res = await ctx.client.readResource({ uri: 'pg-mcp-guard://schema' });
    const tables = JSON.parse((res.contents[0] as { text: string }).text);
    expect(tables.map((t: { name: string }) => t.name)).not.toContain('admin_users');
  });

  it('lists and reads per-table resources', async () => {
    const { resources } = await ctx.client.listResources();
    expect(resources.map((r) => r.uri)).toContain('pg-mcp-guard://table/public/orders');
    const res = await ctx.client.readResource({ uri: 'pg-mcp-guard://table/public/orders' });
    expect(JSON.parse((res.contents[0] as { text: string }).text).name).toBe('orders');
    await expect(ctx.client.readResource({ uri: 'pg-mcp-guard://table/public/admin_users' })).rejects.toThrow();
  });
});

describe('audit log', () => {
  it('records status, original and executed SQL, row count and duration', async () => {
    await ctx.call('run_query', { sql: 'SELECT id FROM products LIMIT 2' });
    expect(ctx.audit.at(-1)).toMatchObject({
      tool: 'run_query',
      status: 'ok',
      sql: 'SELECT id FROM products LIMIT 2',
      executedSql: expect.stringContaining('public.products'),
      rowCount: 2,
      durationMs: expect.any(Number),
    });
    await ctx.call('run_query', { sql: 'DROP TABLE orders' });
    expect(ctx.audit.at(-1)).toMatchObject({ status: 'rejected', reason: expect.stringContaining('DropStmt') });
  });
});

describe('defense in depth: the read-only transaction', () => {
  // These bypass the guard on purpose, to prove Postgres itself is the second wall.
  const readOnly = () => createReadOnlyRunner(ctx.db, 1234);

  it.each([
    ["INSERT INTO products (sku, name, category, price_cents) VALUES ('x', 'x', 'x', 1)"],
    ['UPDATE products SET price_cents = 1'],
    ['DELETE FROM orders'],
    ['CREATE TABLE pwned (id int)'],
    ["SELECT nextval('orders_id_seq')"],
    ['SELECT * FROM orders FOR UPDATE'],
  ])('rejects %s even without the guard', async (sql) => {
    await expect(readOnly()((tx) => tx.query(sql))).rejects.toThrow(/read-only transaction/);
  });

  it('sets statement_timeout for the transaction only', async () => {
    const run = readOnly();
    const inside = await run((tx) => tx.query('SHOW statement_timeout'));
    expect(inside.rows[0].statement_timeout).toBe('1234ms');
    const after = await ctx.db.query('SHOW statement_timeout');
    expect(after.rows[0].statement_timeout).toBe('0');
  });

  // PGlite runs single-threaded in WASM and cannot interrupt a running query, so this only runs against real Postgres.
  it.runIf(process.env.TEST_DATABASE_URL)('statement_timeout cancels a runaway query', async () => {
    const res = await readOnly()((tx) => tx.query('SELECT count(*) FROM generate_series(1, 1e10)')).catch((e) => e);
    expect(String(res)).toMatch(/statement timeout/);
  });

  it('serializes concurrent requests on the single connection', async () => {
    const run = readOnly();
    const results = await Promise.all(Array.from({ length: 10 }, (_, i) => run((tx) => tx.query(`SELECT ${i} AS i`))));
    expect(results.map((r) => r.rows[0].i)).toEqual([...Array(10).keys()]);
  });
});
