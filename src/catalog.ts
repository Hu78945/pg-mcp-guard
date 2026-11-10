import type { Db } from './db.js';
import type { Mask, Policy } from './policy.js';

export interface Column {
  name: string;
  type: string;
  nullable: boolean;
  comment: string | null;
  mask?: Mask;
}

export interface Table {
  schema: string;
  name: string;
  kind: 'table' | 'view' | 'materialized view' | 'partitioned table' | 'foreign table';
  rowEstimate: number | null;
  comment: string | null;
  columns: Column[];
}

/** "schema.table" -> table, for every relation in the policy's schemas. */
export type Catalog = Map<string, Table>;

const KINDS: Record<string, Table['kind']> = {
  r: 'table',
  v: 'view',
  m: 'materialized view',
  p: 'partitioned table',
  f: 'foreign table',
};

export async function loadCatalog(db: Db, schemas: string[]): Promise<Catalog> {
  const { rows } = await db.query(
    `SELECT n.nspname AS schema, c.relname AS name, c.relkind::text AS kind,
            c.reltuples::float8 AS estimate, obj_description(c.oid, 'pg_class') AS comment,
            json_agg(json_build_object(
              'name', a.attname,
              'type', format_type(a.atttypid, a.atttypmod),
              'nullable', NOT a.attnotnull,
              'comment', col_description(c.oid, a.attnum)) ORDER BY a.attnum) AS columns
       FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace
       JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
      WHERE n.nspname = ANY($1) AND c.relkind IN ('r', 'v', 'm', 'p', 'f')
      GROUP BY c.oid, n.nspname
      ORDER BY 1, 2`,
    [schemas],
  );
  const catalog: Catalog = new Map();
  for (const r of rows) {
    const columns = typeof r.columns === 'string' ? JSON.parse(r.columns) : r.columns;
    catalog.set(`${r.schema}.${r.name}`, {
      schema: r.schema,
      name: r.name,
      kind: KINDS[r.kind],
      // reltuples is -1 for never-analyzed tables (PG14+).
      rowEstimate: r.estimate >= 0 ? Math.round(r.estimate) : null,
      comment: r.comment,
      columns,
    });
  }
  return catalog;
}

/** The catalog as the agent is allowed to see it: allowlisted tables/columns, masks annotated. */
export function visibleTables(catalog: Catalog, policy: Policy): Table[] {
  const out: Table[] = [];
  for (const [key, table] of catalog) {
    const rule = policy.tables ? policy.tables[key] : { mask: {} as Record<string, Mask> };
    if (!rule) continue;
    const columns = table.columns
      .filter((c) => !rule.columns || rule.columns.includes(c.name))
      .map((c) => (rule.mask[c.name] ? { ...c, mask: rule.mask[c.name] } : c));
    out.push({ ...table, columns });
  }
  return out;
}

export async function foreignKeys(db: Db, table: Table) {
  const { rows } = await db.query(
    `SELECT conname AS name, pg_get_constraintdef(c.oid) AS definition,
            rn.nspname || '.' || r.relname AS target
       FROM pg_constraint c
       JOIN pg_class t ON t.oid = c.conrelid
       JOIN pg_namespace n ON n.oid = t.relnamespace
       JOIN pg_class r ON r.oid = c.confrelid
       JOIN pg_namespace rn ON rn.oid = r.relnamespace
      WHERE c.contype = 'f' AND n.nspname = $1 AND t.relname = $2
      ORDER BY 1`,
    [table.schema, table.name],
  );
  return rows as { name: string; definition: string; target: string }[];
}
