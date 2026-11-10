import { readFileSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { AuditEntry } from '../src/audit.js';
import { loadCatalog } from '../src/catalog.js';
import pg from 'pg';
import { fromPg, fromPglite } from '../src/db.js';
import { loadPolicy, PolicySchema, type Policy } from '../src/policy.js';
import { createServer } from '../src/server.js';

export const SEED = readFileSync(new URL('../seed/ecommerce.sql', import.meta.url), 'utf8');
export const demoPolicy = (): Policy => loadPolicy(new URL('../policy.example.yaml', import.meta.url).pathname);

/**
 * Seeded in-process Postgres (PGlite) — no Docker, no network.
 * With TEST_DATABASE_URL set, the same suites run against a real server instead;
 * seed it once beforehand: psql "$TEST_DATABASE_URL" -f seed/ecommerce.sql
 */
export async function seededDb() {
  if (process.env.TEST_DATABASE_URL) {
    const client = new pg.Client({ connectionString: process.env.TEST_DATABASE_URL });
    await client.connect();
    return fromPg(client);
  }
  const pglite = new PGlite();
  await pglite.exec(SEED);
  return fromPglite(pglite);
}

/** A real MCP client connected to the server over an in-memory transport. */
export async function startServer(policy: Policy = demoPolicy()) {
  const db = await seededDb();
  const catalog = await loadCatalog(db, policy.schemas);
  const audit: AuditEntry[] = [];
  const server = createServer({ db, policy: PolicySchema.parse(policy), catalog, audit: (e) => audit.push(e) });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0' });
  await Promise.all([server.connect(serverSide), client.connect(clientSide)]);

  async function call(name: string, args: Record<string, unknown> = {}) {
    const res = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: { text: string }[] };
    const text = res.content[0].text;
    return { isError: !!res.isError, text, data: res.isError ? undefined : JSON.parse(text) };
  }

  return { db, catalog, policy, audit, client, call, close: () => client.close().then(() => db.close()) };
}

/** Raw sensitive values from the seed: none of these may ever appear in tool output. */
export const SECRET_PATTERNS = [
  /customer\d+@example\.com/, // unmasked email
  /\+1-555-\d{4}/, // unmasked phone
  /\$2b\$12\$/, // password hash
  /tok_[0-9a-f]{8}/, // admin API token
];
