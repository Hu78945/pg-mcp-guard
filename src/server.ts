import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { Audit } from './audit.js';
import { foreignKeys, visibleTables, type Catalog, type Table } from './catalog.js';
import { createReadOnlyRunner, type Db } from './db.js';
import { GuardError, guardSql } from './guard.js';
import type { Policy } from './policy.js';

export interface ServerDeps {
  db: Db;
  policy: Policy;
  catalog: Catalog;
  audit: Audit;
}

const json = (value: unknown) =>
  JSON.stringify(value, (_k, v) => (typeof v === 'bigint' ? v.toString() : v), 2);
const text = (value: unknown) => ({ content: [{ type: 'text' as const, text: json(value) }] });
const fail = (message: string) => ({ isError: true, content: [{ type: 'text' as const, text: message }] });

export function createServer({ db, policy, catalog, audit }: ServerDeps): McpServer {
  const server = new McpServer({ name: 'pg-mcp-guard', version: '0.1.0' });
  const readOnly = createReadOnlyRunner(db, policy.statementTimeoutMs);
  const tables = () => visibleTables(catalog, policy);

  const findTable = (name: string): Table | undefined => {
    const [a, b] = name.split('.');
    const candidates = b ? [`${a}.${b}`] : policy.schemas.map((s) => `${s}.${a}`);
    return tables().find((t) => candidates.includes(`${t.schema}.${t.name}`));
  };

  /** Guard -> read-only transaction -> audit. Every SQL path in the server goes through here. */
  async function execute(tool: string, sql: string, explain = false) {
    const started = performance.now();
    let executedSql: string | undefined;
    try {
      const guarded = await guardSql(sql, { policy, catalog, enforceLimit: !explain });
      executedSql = explain ? `EXPLAIN (FORMAT JSON) ${guarded.sql}` : guarded.sql;
      const res = await readOnly((tx) => tx.query(executedSql!, [], 'array'));
      const durationMs = Math.round(performance.now() - started);

      if (explain) {
        audit({ tool, sql, executedSql, status: 'ok', durationMs });
        const plan = res.rows[0][0];
        return text({ plan: typeof plan === 'string' ? JSON.parse(plan) : plan, executedSql });
      }
      const truncated = res.rows.length > policy.maxRows;
      const rows = res.rows.slice(0, policy.maxRows);
      audit({ tool, sql, executedSql, status: 'ok', rowCount: rows.length, durationMs });
      return text({ columns: res.fields.map((f) => f.name), rows, rowCount: rows.length, truncated, durationMs });
    } catch (e) {
      const durationMs = Math.round(performance.now() - started);
      const reason = (e as Error).message;
      const rejected = e instanceof GuardError;
      audit({ tool, sql, executedSql, status: rejected ? 'rejected' : 'error', reason, durationMs });
      return fail(rejected ? `Rejected by guard: ${reason}` : `Query failed: ${reason}`);
    }
  }

  server.registerTool(
    'list_schemas',
    {
      description: 'List the schemas and tables this server exposes, with row estimates and comments.',
      annotations: { readOnlyHint: true },
    },
    async () => {
      const bySchema: Record<string, { table: string; kind: string; rowEstimate: number | null; comment: string | null }[]> = {};
      for (const t of tables()) {
        (bySchema[t.schema] ??= []).push({ table: t.name, kind: t.kind, rowEstimate: t.rowEstimate, comment: t.comment });
      }
      return text(bySchema);
    },
  );

  server.registerTool(
    'describe_table',
    {
      description: 'Columns (type, nullability, comment, masking), foreign keys, row estimate and comment for one table.',
      inputSchema: { table: z.string().describe('Table name, optionally schema-qualified: "orders" or "public.orders"') },
      annotations: { readOnlyHint: true },
    },
    async ({ table }) => {
      const t = findTable(table);
      if (!t) return fail(`Unknown or disallowed table: ${table}`);
      const fks = await readOnly((tx) => foreignKeys(tx, t));
      // Don't reveal hidden tables through FK targets.
      const visible = new Set(tables().map((v) => `${v.schema}.${v.name}`));
      return text({ ...t, foreignKeys: fks.filter((fk) => visible.has(fk.target)).map(({ name, definition }) => ({ name, definition })) });
    },
  );

  server.registerTool(
    'run_query',
    {
      description:
        `Run ONE read-only SELECT (or WITH ... SELECT). Writes, DDL, multiple statements and dangerous functions are rejected. ` +
        `At most ${policy.maxRows} rows are returned; some columns are masked by policy.`,
      inputSchema: { sql: z.string().describe('A single SELECT statement') },
      annotations: { readOnlyHint: true },
    },
    ({ sql }) => execute('run_query', sql),
  );

  server.registerTool(
    'explain_query',
    {
      description: 'Show the PostgreSQL query plan (EXPLAIN, never ANALYZE: the query is not executed).',
      inputSchema: { sql: z.string().describe('A single SELECT statement') },
      annotations: { readOnlyHint: true },
    },
    ({ sql }) => execute('explain_query', sql, true),
  );

  server.registerTool(
    'sample_rows',
    {
      description: 'Return a few rows from a table (masking applies).',
      inputSchema: {
        table: z.string().describe('Table name, optionally schema-qualified'),
        limit: z.number().int().min(1).max(100).default(10),
      },
      annotations: { readOnlyHint: true },
    },
    ({ table, limit }) => {
      const t = findTable(table);
      if (!t) return fail(`Unknown or disallowed table: ${table}`);
      const q = (s: string) => `"${s.replaceAll('"', '""')}"`;
      return execute('sample_rows', `SELECT * FROM ${q(t.schema)}.${q(t.name)} LIMIT ${limit}`);
    },
  );

  server.registerResource(
    'schema',
    'pg-mcp-guard://schema',
    { description: 'Every exposed table with its columns, as JSON.', mimeType: 'application/json' },
    async (uri) => ({ contents: [{ uri: uri.href, mimeType: 'application/json', text: json(tables()) }] }),
  );

  server.registerResource(
    'table',
    new ResourceTemplate('pg-mcp-guard://table/{schema}/{table}', {
      list: async () => ({
        resources: tables().map((t) => ({ uri: `pg-mcp-guard://table/${t.schema}/${t.name}`, name: `${t.schema}.${t.name}` })),
      }),
    }),
    { description: 'One exposed table with its columns, as JSON.', mimeType: 'application/json' },
    async (uri, { schema, table }) => {
      const t = findTable(`${schema}.${table}`);
      if (!t) throw new Error(`Unknown or disallowed table: ${schema}.${table}`);
      return { contents: [{ uri: uri.href, mimeType: 'application/json', text: json(t) }] };
    },
  );

  return server;
}
