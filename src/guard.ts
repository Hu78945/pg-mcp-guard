import { parse, parseSync } from 'libpg-query';
import { deparse } from 'pgsql-deparser';
import type { Catalog } from './catalog.js';
import type { Mask, Policy, TableRule } from './policy.js';

export class GuardError extends Error {}

export const MAX_SQL_LENGTH = 20_000;

/**
 * Parse-tree node types a read-only SELECT may contain. Anything else (locking
 * clauses, DML inside CTEs, parameters, XML/JSON table functions, ...) is rejected:
 * new or unusual syntax fails closed instead of slipping through.
 */
const ALLOWED_NODES = new Set([
  'SelectStmt', 'ResTarget', 'ColumnRef', 'A_Star', 'A_Const', 'A_Expr', 'A_Indirection',
  'A_Indices', 'A_ArrayExpr', 'String', 'Integer', 'Float', 'Boolean', 'BitString', 'List',
  'TypeCast', 'TypeName', 'FuncCall', 'NamedArgExpr', 'BoolExpr', 'NullTest', 'BooleanTest',
  'CaseExpr', 'CaseWhen', 'CoalesceExpr', 'MinMaxExpr', 'SubLink', 'RowExpr', 'CollateClause',
  'SQLValueFunction', 'GroupingFunc', 'GroupingSet', 'SortBy', 'WindowDef', 'RangeVar',
  'RangeSubselect', 'RangeFunction', 'JoinExpr', 'CommonTableExpr', 'RangeTableSample',
]);

/** Fields that turn a SELECT into a write even though the statement type is SelectStmt. */
const FORBIDDEN_FIELDS = new Set(['intoClause']);

/**
 * Functions with side effects, file/network access, sleeps, or that execute a SQL
 * string (which would bypass this parser entirely).
 */
const DENIED_FUNCTIONS = [
  /^pg_sleep/, /^dblink/, /^lo_/, /^pg_read_/, /^pg_ls_/, /^pg_stat_file$/, /^pg_file_/,
  /^set_config$/, /^pg_terminate_backend$/, /^pg_cancel_backend$/, /^pg_reload_conf$/,
  /^pg_rotate_logfile$/, /^pg_switch_wal$/, /^pg_promote$/, /^pg_backup_/, /^pg_(create|drop)_/,
  /^pg_logical_/, /^pg_replication_/, /^pg_advisory_/, /^pg_try_advisory_/, /^pg_notify$/,
  /^(query|cursor|table|schema|database)_to_xml/, /^ts_stat$/, /^nextval$/, /^setval$/,
  /^txid_current$/, /^pg_current_xact_id$/, /^pg_import_system_collations$/,
];

export interface GuardResult {
  /** The SQL that will actually run: tables schema-qualified, masks applied, LIMIT enforced. */
  sql: string;
  /** Tables the query reads, as "schema.table". */
  tables: string[];
}

export interface GuardOptions {
  policy: Policy;
  catalog: Catalog;
  /** Clamp the outer LIMIT to policy.maxRows + 1 (the +1 detects truncation). Default true. */
  enforceLimit?: boolean;
}

type Node = Record<string, any>;

const ident = (s: string) => `"${s.replaceAll('"', '""')}"`;

const MASK_SQL: Record<Mask, (col: string) => string> = {
  redact: (c) => `CASE WHEN ${c} IS NULL THEN NULL ELSE '***' END`,
  email: (c) => `regexp_replace(${c}::text, '^[^@]*', '***')`,
  last4: (c) => `'***' || right(${c}::text, 4)`,
  hash: (c) => `md5(${c}::text)`,
};

export async function guardSql(sql: string, opts: GuardOptions): Promise<GuardResult> {
  if (sql.length > MAX_SQL_LENGTH) throw new GuardError(`query longer than ${MAX_SQL_LENGTH} characters`);

  const select = await parseSingleSelect(sql);
  const tables = new Set<string>();
  const denied = [...DENIED_FUNCTIONS, ...opts.policy.deniedFunctions.map((p) => new RegExp(p, 'i'))];
  let rewritten = new Walker(opts, denied, tables).select(select, new Set());
  if (opts.enforceLimit !== false) rewritten = clampLimit(rewritten, opts.policy.maxRows + 1);

  const out = await deparse({ version: 0, stmts: [{ stmt: { SelectStmt: rewritten } }] } as any);
  // Validate what we execute, not just what we were given: a deparser bug must not
  // turn an allowed tree into a different, unchecked statement.
  new Walker(opts, denied, new Set(), true).select(await parseSingleSelect(out), new Set());
  return { sql: out, tables: [...tables] };
}

async function parseSingleSelect(sql: string): Promise<Node> {
  let tree;
  try {
    tree = await parse(sql);
  } catch (e) {
    throw new GuardError(`could not parse SQL: ${(e as Error).message}`);
  }
  const stmts = tree.stmts ?? [];
  if (stmts.length !== 1) throw new GuardError(`expected exactly one statement, got ${stmts.length}`);
  const [type] = Object.keys(stmts[0].stmt ?? {});
  if (type !== 'SelectStmt') throw new GuardError(`only SELECT is allowed, got ${type ?? 'empty statement'}`);
  return (stmts[0].stmt as Node).SelectStmt;
}

/** Make sure the outermost query returns at most `max` rows. */
function clampLimit(select: Node, max: number): Node {
  const n = select.limitCount?.A_Const?.ival?.ival;
  if (Number.isInteger(n) && n <= max) return select;
  if (!select.limitCount || select.limitCount.A_Const) {
    // No limit, LIMIT ALL, or a constant above the cap: lowering it keeps the same first rows.
    return { ...select, limitCount: { A_Const: { ival: { ival: max } } }, limitOption: 'LIMIT_OPTION_COUNT' };
  }
  // LIMIT <expression>: keep the user's semantics and cap from outside.
  const outer = (parseSync(`SELECT * FROM (SELECT 1) AS limited LIMIT ${max}`).stmts![0].stmt as Node).SelectStmt;
  outer.fromClause[0].RangeSubselect.subquery = { SelectStmt: select };
  return outer;
}

/**
 * One recursive pass over the parse tree that validates every node and rewrites
 * table references. `scope` holds the CTE names visible at the current position,
 * so `WITH customers AS (...)` cannot be used to smuggle a real table past the allowlist.
 */
class Walker {
  constructor(
    private opts: GuardOptions,
    private denied: RegExp[],
    private tables: Set<string>,
    /** Validate only (second pass over our own output): no rewriting. */
    private checkOnly = false,
  ) {}

  visit(value: any, scope: Set<string>): any {
    if (Array.isArray(value)) return value.map((v) => this.visit(v, scope));
    if (value === null || typeof value !== 'object') return value;

    const keys = Object.keys(value);
    if (keys.length === 1 && /^[A-Z]/.test(keys[0])) {
      const [type] = keys;
      const body = value[type];
      if (!ALLOWED_NODES.has(type)) throw new GuardError(`${type} is not allowed in a read-only query`);
      if (type === 'FuncCall') this.checkFunction(body);
      if (type === 'RangeVar') return this.rangeVar(body, scope);
      if (type === 'SelectStmt') return { SelectStmt: this.select(body, scope) };
      return { [type]: this.fields(body, scope) };
    }
    return this.fields(value, scope);
  }

  fields(obj: Node, scope: Set<string>): Node {
    const out: Node = {};
    for (const [k, v] of Object.entries(obj)) {
      if (FORBIDDEN_FIELDS.has(k)) throw new GuardError('SELECT ... INTO is not allowed');
      out[k] = this.visit(v, scope);
    }
    return out;
  }

  select(stmt: Node, scope: Set<string>): Node {
    this.checkLimit(stmt);
    const { withClause, ...rest } = stmt;
    if (!withClause) return this.fields(rest, scope);

    const ctes: Node[] = withClause.ctes ?? [];
    const names = ctes.map((c) => c.CommonTableExpr?.ctename);
    const visited = ctes.map((cte, i) => {
      // Non-recursive CTEs only see earlier siblings; recursive ones also see themselves.
      const visible = names.slice(0, withClause.recursive ? i + 1 : i);
      return this.visit(cte, new Set([...scope, ...visible]));
    });
    const inner = new Set([...scope, ...names]);
    return { ...this.fields(rest, inner), withClause: { ...withClause, ctes: visited } };
  }

  checkLimit(stmt: Node) {
    // pgsql-deparser drops WITH TIES (emits a plain LIMIT); refuse rather than silently change results.
    if (stmt.limitOption === 'LIMIT_OPTION_WITH_TIES') throw new GuardError('FETCH ... WITH TIES is not supported');
  }

  checkFunction(call: Node) {
    const parts = (call.funcname ?? []).map((n: Node) => n.String?.sval ?? '');
    const name = String(parts.at(-1)).toLowerCase();
    if (this.denied.some((re) => re.test(name))) throw new GuardError(`function ${parts.join('.')}() is not allowed`);
  }

  rangeVar(rv: Node, scope: Set<string>): Node {
    if (rv.catalogname) throw new GuardError('cross-database references are not allowed');
    if (!rv.schemaname && scope.has(rv.relname)) return { RangeVar: rv }; // CTE reference

    const { policy, catalog } = this.opts;
    const key = rv.schemaname
      ? `${rv.schemaname}.${rv.relname}`
      : policy.schemas.map((s) => `${s}.${rv.relname}`).find((k) => catalog.has(k));
    const table = key && catalog.get(key);
    const rule: TableRule | undefined = policy.tables ? policy.tables[key ?? ''] : { mask: {} };
    if (!table || !rule) {
      throw new GuardError(`table ${rv.schemaname ? rv.schemaname + '.' : ''}${rv.relname} is not allowed or does not exist`);
    }
    this.tables.add(key);
    if (this.checkOnly) return { RangeVar: rv };

    if (!rule.columns && Object.keys(rule.mask).length === 0) {
      return { RangeVar: { ...rv, schemaname: table.schema } }; // pin resolution; search_path can't redirect it
    }

    // Replace the table with a subquery that only exposes allowed columns, with masks
    // applied. The original table is then unreachable from the query: WHERE clauses,
    // functions, SELECT *, whole-row references and JSON casts all see masked values.
    const cols = table.columns
      .filter((c) => !rule.columns || rule.columns.includes(c.name))
      .map((c) => {
        const mask = rule.mask[c.name];
        return mask ? `${MASK_SQL[mask](ident(c.name))} AS ${ident(c.name)}` : ident(c.name);
      });
    if (cols.length === 0) throw new GuardError(`no readable columns in ${key}`);
    const sub = parseSync(`SELECT ${cols.join(', ')} FROM ${ident(table.schema)}.${ident(table.name)}`);
    return {
      RangeSubselect: {
        subquery: sub.stmts![0].stmt,
        alias: rv.alias ?? { aliasname: rv.relname },
      },
    };
  }
}
