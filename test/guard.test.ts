/** Unit tests for the rewrite itself: what SQL actually reaches Postgres. */
import { beforeAll, describe, expect, it } from 'vitest';
import { loadCatalog, type Catalog } from '../src/catalog.js';
import { GuardError, guardSql } from '../src/guard.js';
import { PolicySchema, type Policy } from '../src/policy.js';
import { demoPolicy, seededDb } from './helpers.js';

let catalog: Catalog;
const policy = demoPolicy();
const guard = (sql: string, p: Policy = policy, enforceLimit = true) => guardSql(sql, { policy: p, catalog, enforceLimit });

beforeAll(async () => {
  const db = await seededDb();
  catalog = await loadCatalog(db, ['public']);
  await db.close();
});

describe('rewriting', () => {
  it('pins unqualified tables to their schema', async () => {
    const { sql, tables } = await guard('SELECT id FROM orders LIMIT 5');
    expect(sql).toMatch(/FROM public\.orders/);
    expect(tables).toEqual(['public.orders']);
  });

  it('replaces a masked table with a subquery that drops hidden columns and masks the rest', async () => {
    const { sql } = await guard('SELECT * FROM customers c');
    expect(sql).not.toMatch(/password_hash/);
    expect(sql).toMatch(/regexp_replace\(email::text/);
    expect(sql).toMatch(/AS c\b/);
  });

  it('adds a LIMIT when there is none, lowers one above the cap, keeps one below it', async () => {
    expect((await guard('SELECT 1')).sql).toMatch(/LIMIT 201$/);
    expect((await guard('SELECT 1 LIMIT 100000')).sql).toMatch(/LIMIT 201$/);
    expect((await guard('SELECT 1 LIMIT 7')).sql).toMatch(/LIMIT 7$/);
  });

  it('caps a LIMIT expression from an outer query', async () => {
    const { sql } = await guard('SELECT 1 LIMIT (SELECT 5)');
    expect(sql).toMatch(/^SELECT \*\s+FROM \(/);
    expect(sql).toMatch(/LIMIT 201$/);
  });

  it('can skip the LIMIT for EXPLAIN', async () => {
    expect((await guard('SELECT 1', policy, false)).sql).not.toMatch(/LIMIT/);
  });

  it('records every table read, including inside CTEs and subqueries', async () => {
    const { tables } = await guard('WITH x AS (SELECT * FROM orders) SELECT * FROM x WHERE customer_id IN (SELECT id FROM customers)');
    expect(tables.sort()).toEqual(['public.customers', 'public.orders']);
  });
});

describe('policy variants', () => {
  it('without a tables allowlist, every table in the schemas is allowed and unmasked', async () => {
    const open = PolicySchema.parse({ schemas: ['public'] });
    const { sql } = await guard('SELECT api_token FROM admin_users', open);
    expect(sql).toMatch(/FROM public\.admin_users/);
  });

  it('still rejects tables outside the configured schemas', async () => {
    const open = PolicySchema.parse({ schemas: ['public'] });
    await expect(guard('SELECT * FROM pg_catalog.pg_authid', open)).rejects.toThrow(GuardError);
  });

  it('honours extra denied functions from the policy', async () => {
    const strict = PolicySchema.parse({ ...policy, deniedFunctions: ['^md5$'] });
    await expect(guard('SELECT md5(sku) FROM products', strict)).rejects.toThrow(/md5/);
  });

  it('rejects malformed policy table keys', () => {
    expect(() => PolicySchema.parse({ tables: { customers: {} } })).toThrow(/schema\.table/);
  });

  it('applies the configured row cap', async () => {
    const small = PolicySchema.parse({ ...policy, maxRows: 10 });
    expect((await guard('SELECT 1', small)).sql).toMatch(/LIMIT 11$/);
  });
});
