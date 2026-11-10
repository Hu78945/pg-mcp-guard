// Guard overhead per query (parse + validate + rewrite + deparse + re-parse), on the built code.
// Run: npm run build && npm run bench
import { readFileSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';
import { loadCatalog } from '../dist/catalog.js';
import { fromPglite } from '../dist/db.js';
import { guardSql } from '../dist/guard.js';
import { loadPolicy } from '../dist/policy.js';

const policy = loadPolicy(new URL('../policy.example.yaml', import.meta.url).pathname);
const pglite = new PGlite();
await pglite.exec(readFileSync(new URL('../seed/ecommerce.sql', import.meta.url), 'utf8'));
const catalog = await loadCatalog(fromPglite(pglite), policy.schemas);

const queries = {
  'simple select': 'SELECT id, name FROM products WHERE price_cents > 1000',
  'CTE + 4-table join, masked table': `WITH paid AS (SELECT * FROM orders WHERE status = 'paid')
    SELECT c.city, p.category, sum(oi.quantity * oi.unit_price_cents)
      FROM paid o JOIN customers c ON c.id = o.customer_id
      JOIN order_items oi ON oi.order_id = o.id JOIN products p ON p.id = oi.product_id
     GROUP BY 1, 2 ORDER BY 3 DESC`,
};

for (const [name, sql] of Object.entries(queries)) {
  for (let i = 0; i < 200; i++) await guardSql(sql, { policy, catalog }); // warm-up
  const times = [];
  for (let i = 0; i < 2000; i++) {
    const t = performance.now();
    await guardSql(sql, { policy, catalog });
    times.push(performance.now() - t);
  }
  times.sort((a, b) => a - b);
  const pct = (p) => times[Math.floor(times.length * p)].toFixed(3);
  console.log(`${name.padEnd(36)} p50 ${pct(0.5)} ms   p99 ${pct(0.99)} ms   (n=${times.length})`);
}
await pglite.close();
