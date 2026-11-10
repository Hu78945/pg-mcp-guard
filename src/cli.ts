#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createAudit } from './audit.js';
import { loadCatalog } from './catalog.js';
import { fromPg, fromPglite, type Db } from './db.js';
import { loadPolicy } from './policy.js';
import { createServer } from './server.js';

const asset = (p: string) => fileURLToPath(new URL(`../${p}`, import.meta.url));

/** --demo: in-process PGlite seeded with the sample e-commerce database. No Postgres needed. */
async function openDemo(): Promise<Db> {
  const { PGlite } = await import('@electric-sql/pglite');
  const pglite = new PGlite();
  await pglite.exec(readFileSync(asset('seed/ecommerce.sql'), 'utf8'));
  return fromPglite(pglite);
}

async function openPostgres(url: string): Promise<Db> {
  const { default: pg } = await import('pg');
  const client = new pg.Client({ connectionString: url, application_name: 'pg-mcp-guard' });
  client.on('error', (e) => {
    console.error(`pg-mcp-guard: connection lost: ${e.message}`);
    process.exit(1);
  });
  await client.connect();
  return fromPg(client);
}

async function main() {
  const demo = process.argv.includes('--demo');
  const url = process.env.DATABASE_URL;
  if (!demo && !url) {
    console.error('pg-mcp-guard: set DATABASE_URL, or run with --demo for a built-in sample database.');
    process.exit(2);
  }

  const policy = loadPolicy(process.env.POLICY_FILE ?? (demo ? asset('policy.example.yaml') : undefined));
  const db = demo ? await openDemo() : await openPostgres(url!);
  // ponytail: catalog is read once at startup; restart the server after schema changes.
  const catalog = await loadCatalog(db, policy.schemas);
  const server = createServer({ db, policy, catalog, audit: createAudit(process.env.AUDIT_LOG) });

  await server.connect(new StdioServerTransport());
  console.error(`pg-mcp-guard: ready (${catalog.size} relations in ${policy.schemas.join(', ')}${demo ? ', demo database' : ''})`);

  const shutdown = async () => {
    await server.close();
    await db.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((e) => {
  console.error(`pg-mcp-guard: ${e.message}`);
  process.exit(1);
});
