/**
 * False-positive check: realistic analytical queries an assistant would write must pass the
 * guard AND execute correctly after rewriting (masking subqueries, schema pinning, LIMIT cap).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startServer } from './helpers.js';

const benign: [string, string][] = [
  ['simple select', 'SELECT id, name, price_cents FROM products ORDER BY id LIMIT 5'],
  ['qualified table', 'SELECT count(*) FROM public.orders'],
  ['join + aggregate', `SELECT c.city, count(*) AS orders FROM orders o JOIN customers c ON c.id = o.customer_id GROUP BY c.city ORDER BY 2 DESC`],
  ['three-way join', `SELECT p.category, sum(oi.quantity * oi.unit_price_cents) / 100.0 AS revenue
     FROM order_items oi JOIN orders o ON o.id = oi.order_id JOIN products p ON p.id = oi.product_id
    WHERE o.status IN ('paid', 'shipped') GROUP BY 1 ORDER BY 2 DESC`],
  ['window function', 'SELECT id, customer_id, rank() OVER (PARTITION BY customer_id ORDER BY created_at) FROM orders LIMIT 20'],
  ['CTE', 'WITH paid AS (SELECT * FROM orders WHERE status = \'paid\') SELECT count(*) FROM paid'],
  ['CTE shadowing a real table name', 'WITH orders AS (SELECT 1 AS id) SELECT * FROM orders'],
  ['chained CTEs', 'WITH a AS (SELECT customer_id FROM orders), b AS (SELECT DISTINCT customer_id FROM a) SELECT count(*) FROM b'],
  ['recursive CTE', 'WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 10) SELECT sum(i) FROM n'],
  ['subquery in WHERE', 'SELECT name FROM products WHERE id IN (SELECT product_id FROM order_items WHERE quantity = 3)'],
  ['EXISTS', 'SELECT count(*) FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.id)'],
  ['LATERAL', 'SELECT c.id, last.created_at FROM customers c, LATERAL (SELECT created_at FROM orders o WHERE o.customer_id = c.id ORDER BY created_at DESC LIMIT 1) last LIMIT 5'],
  ['UNION', "SELECT 'product' AS kind, count(*) FROM products UNION ALL SELECT 'order', count(*) FROM orders"],
  ['CASE + FILTER', "SELECT count(*) FILTER (WHERE status = 'refunded') AS refunds, sum(CASE WHEN status = 'paid' THEN 1 ELSE 0 END) FROM orders"],
  ['DISTINCT ON', 'SELECT DISTINCT ON (customer_id) customer_id, id FROM orders ORDER BY customer_id, created_at DESC LIMIT 10'],
  ['GROUPING SETS', 'SELECT category, count(*) FROM products GROUP BY GROUPING SETS ((category), ())'],
  ['date functions', "SELECT date_trunc('month', created_at) AS m, count(*) FROM orders GROUP BY 1 ORDER BY 1"],
  ['json_agg', 'SELECT json_agg(json_build_object(\'sku\', sku, \'price\', price_cents)) FROM products WHERE id < 4'],
  ['VALUES', 'VALUES (1, \'a\'), (2, \'b\')'],
  ['generate_series', 'SELECT g FROM generate_series(1, 5) g'],
  ['now() and casts', "SELECT now()::date - '2025-01-01'::date AS days"],
  ['ILIKE + COALESCE', "SELECT coalesce(phone, 'n/a') FROM customers WHERE full_name ILIKE 'customer 1%' LIMIT 3"],
  ['masked column in output', 'SELECT id, email FROM customers ORDER BY id LIMIT 3'],
  ['string containing ;DROP (dollar-quoted)', 'SELECT $$; DROP TABLE orders; $$ AS s'],
  ['comment containing ;DELETE', 'SELECT 1 /* ; DELETE FROM orders */ AS x'],
  ['string containing DELETE FROM', "SELECT count(*) FROM products WHERE name <> 'DELETE FROM orders'"],
  ['quoted identifiers', 'SELECT "id", "sku" FROM "public"."products" LIMIT 1'],
  ['OFFSET + FETCH FIRST', 'SELECT id FROM orders ORDER BY id OFFSET 10 FETCH FIRST 5 ROWS ONLY'],
  ['TABLESAMPLE', 'SELECT count(*) >= 0 FROM orders TABLESAMPLE BERNOULLI (10)'],
  ['trailing semicolon', 'SELECT 1;'],
];

let ctx: Awaited<ReturnType<typeof startServer>>;
beforeAll(async () => (ctx = await startServer()));
afterAll(() => ctx.close());

describe('benign queries are allowed and execute', () => {
  it.each(benign)('%s', async (_name, sql) => {
    const res = await ctx.call('run_query', { sql });
    expect(res.isError, res.text).toBe(false);
    expect(res.data.rowCount).toBeGreaterThan(0);
  });

  it('keeps query semantics after rewriting', async () => {
    const res = await ctx.call('run_query', { sql: 'SELECT count(*)::int AS n FROM orders o JOIN customers c ON c.id = o.customer_id' });
    expect(res.data.rows).toEqual([[1000]]);
  });

  it('LIMIT expressions keep their meaning under the row cap', async () => {
    const expr = await ctx.call('run_query', { sql: 'SELECT id FROM products ORDER BY id LIMIT (SELECT 3)' });
    expect(expr.data.rows).toEqual([[1], [2], [3]]);
  });
});
