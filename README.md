# pg-mcp-guard

A security-first [Model Context Protocol](https://modelcontextprotocol.io) server that lets AI assistants (Claude Desktop, Claude Code, Cursor, ...) explore and query a PostgreSQL database without being able to change it, read what they shouldn't, or tie it up.

Most "Postgres MCP" servers pass the model's SQL straight to the database, sometimes after a regex check. This one treats every query as untrusted input and puts four independent layers between it and your data:

1. **A real SQL parser** (`libpg-query`, PostgreSQL's own parser compiled to WASM) accepts only a single `SELECT` / `WITH ... SELECT`, built from an allowlist of parse-tree node types, with no dangerous functions.
2. **A rewrite step** pins every table to its schema, swaps tables that have masked or hidden columns for a masking subquery, and caps the row count with `LIMIT`.
3. **Postgres runs the query in `BEGIN READ ONLY`** with `SET LOCAL statement_timeout`, then always `ROLLBACK`. So even a query that got past the guard cannot write.
4. **Every attempt goes to an audit log** (JSON lines): the original SQL, the SQL that actually ran, the outcome, the row count and the duration.

## Measured results

| What | Result |
|---|---|
| Adversarial corpus (`test/attacks.test.ts`), run end to end through the MCP `run_query` tool | **205 / 205 blocked**: 170 by the guard, 5 by Postgres (hidden columns), 30 neutralized (masked output or capped rows) |
| Realistic analytical queries (`test/benign.test.ts`) | **30 / 30 allowed and executed correctly** after rewriting |
| Full test suite | **269 passed, 1 skipped** on in-process PGlite (PostgreSQL 18); **270 / 270** against a real PostgreSQL 16 server |
| Database state after the attack corpus | unchanged (an md5 snapshot of every table is compared before and after) |
| Guard overhead (`npm run bench`, Apple M3 Pro, Node 24) | p50 **0.04 ms** for a simple select, **0.18 ms** for a CTE + 4-table join over a masked table |

The skipped test checks that `statement_timeout` really cancels a runaway query. PGlite runs single-threaded in WASM and can't interrupt a running query, so that test runs only against a real server (`TEST_DATABASE_URL`, and in CI).

I also checked that the tests can fail: I disabled each defense in turn and confirmed that tests go red. Turning off CTE scoping fails 1 test, schema-aware CTE resolution 1, masking substitution 28, the `SELECT ... INTO` check 5, the node allowlist 9 (with `LockingClause`, `ParamRef`, `XmlExpr` and `RangeTableFunc` allowed), the single-statement check 11, the function denylist 37 (everything except `pg_sleep*`, which would hang the in-process test database) and the row cap 4. These were manual runs, not a scripted mutation-testing tool.

## Quickstart

```bash
npm install
npm run build

# Try it with no Postgres at all: an in-process demo e-commerce database (PGlite)
node dist/cli.js --demo

# Or point it at your own database
DATABASE_URL=postgres://mcp_reader:...@localhost:5432/shop \
POLICY_FILE=./policy.example.yaml \
AUDIT_LOG=./audit.jsonl \
node dist/cli.js
```

To load the demo schema into a real database: `psql "$DATABASE_URL" -f seed/ecommerce.sql`. It creates 200 customers, 50 products, 1,000 orders and 2,760 order items, plus an `admin_users` table that the demo policy hides.

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "postgres": {
      "command": "node",
      "args": ["/absolute/path/to/pg-mcp-guard/dist/cli.js"],
      "env": {
        "DATABASE_URL": "postgres://mcp_reader:change-me@localhost:5432/shop",
        "POLICY_FILE": "/absolute/path/to/pg-mcp-guard/policy.example.yaml",
        "AUDIT_LOG": "/absolute/path/to/pg-mcp-guard/audit.jsonl"
      }
    }
  }
}
```

For the zero-setup demo, use `"args": ["/absolute/path/to/pg-mcp-guard/dist/cli.js", "--demo"]` and leave out `env`.

### Claude Code

```bash
claude mcp add postgres \
  -e DATABASE_URL=postgres://mcp_reader:change-me@localhost:5432/shop \
  -e POLICY_FILE=$PWD/policy.example.yaml \
  -- node $PWD/dist/cli.js

# or the demo
claude mcp add pg-demo -- node $PWD/dist/cli.js --demo
```

Cursor uses the same `mcpServers` JSON shape in `.cursor/mcp.json`.

## Tools and resources

| Tool | What it does |
|---|---|
| `list_schemas` | Lists the exposed schemas and tables, with row estimates (`pg_class.reltuples`) and comments |
| `describe_table` | Shows columns (type, nullability, comment, mask), foreign keys, row estimate and table comment. Hidden columns, and foreign keys that point at hidden tables, are left out |
| `run_query` | Runs one read-only `SELECT`. Rows come back as arrays plus a column list, so duplicate column names survive, with `truncated: true` when the row cap was hit |
| `explain_query` | Returns `EXPLAIN (FORMAT JSON)`, never `ANALYZE`, so the query is not executed. It goes through the same guard |
| `sample_rows` | Returns the first N rows of a table, built as SQL and sent through the same guard, so masking applies |

| Resource | Content |
|---|---|
| `pg-mcp-guard://schema` | Every exposed table and its columns, as JSON |
| `pg-mcp-guard://table/{schema}/{table}` | One table, as JSON (listable) |

All tools carry `readOnlyHint: true`.

## Request path

```mermaid
flowchart TD
    A[AI assistant<br/>Claude Desktop / Code / Cursor] -->|MCP over stdio<br/>tools/call run_query| B[pg-mcp-guard]
    B --> C{"Length ≤ 20k chars?"}
    C -- no --> R[Rejected + audit]
    C -- yes --> D["libpg-query parse<br/>(PostgreSQL's real parser)"]
    D --> E{"Exactly 1 statement,<br/>and it's a SelectStmt?"}
    E -- no --> R
    E -- yes --> F["Walk the whole parse tree<br/>• node type allowlist<br/>• no INTO / FOR UPDATE / WITH TIES<br/>• function denylist<br/>• table allowlist, CTE-scope aware"]
    F -- violation --> R
    F --> G["Rewrite<br/>• pin tables to their schema<br/>• masked tables → masking subquery<br/>• clamp outer LIMIT to maxRows+1"]
    G --> H["Deparse, then re-parse and re-validate<br/>(check what will actually run)"]
    H -- violation --> R
    H --> I["BEGIN READ ONLY<br/>SET LOCAL statement_timeout<br/>run query<br/>ROLLBACK (always)"]
    I -- Postgres error --> X[Error + audit]
    I --> J["Trim to maxRows,<br/>flag truncated, audit"] --> A
```

## Policy

Everything the policy doesn't allow is denied. See `policy.example.yaml`:

```yaml
schemas: [public]
maxRows: 200
statementTimeoutMs: 5000
tables:                       # table allowlist; omit to allow every table in `schemas`
  public.customers:
    columns: [id, full_name, email, phone, city, created_at]   # password_hash is invisible
    mask: { email: email, phone: last4 }
  public.products: {}
  public.orders: {}
  public.order_items: {}
deniedFunctions: []           # extra regexes on top of the built-in denylist
```

Mask strategies: `redact` (`***`), `email` (`***@domain`), `last4` (`***1234`), `hash` (`md5`, which keeps values joinable).

### How masking works, and why it isn't post-processing

A common approach masks result columns by name after the query runs. That is easy to bypass with `SELECT email AS e`, `row_to_json(c)`, `upper(email)` or `string_agg(email, ',')`, and it does nothing about `WHERE email = 'alice@x.com'`, which leaks data through which rows match.

pg-mcp-guard instead **replaces the table itself**. `FROM customers c` becomes:

```sql
FROM (SELECT id, full_name,
             regexp_replace(email::text, '^[^@]*', '***') AS email,
             '***' || right(phone::text, 4) AS phone,
             city, created_at
        FROM public.customers) AS c
```

The real table can't be reached from the query, so every expression sees masked values. That covers `SELECT *`, whole-row references, JSON casts, aggregates and `WHERE`/`JOIN` predicates. An equality or `LIKE` probe against a real email matches nothing. Hidden columns don't exist in the subquery at all, so referencing them fails inside Postgres. The attack corpus tests 23 masking bypasses and 5 hidden-column probes, including those oracles.

## Threat model

**The adversary** is the model's SQL. The model may be confused or hallucinating, or it may be prompt-injected by content it read (a ticket, a web page, a row in your own database). Treat every `run_query` argument as hostile.

**Protected assets and how each is protected:**

| Asset | Threat | Defense |
|---|---|---|
| Data integrity | DML/DDL, writes hidden in CTEs, `SELECT INTO`, `COPY`, `nextval`, `FOR UPDATE` locks, `COMMIT; DELETE` stacking | parser (single `SelectStmt`, node allowlist, `intoClause` check, denylist) **and** a `READ ONLY` transaction that always rolls back |
| Confidential tables | Querying non-allowlisted tables, `pg_authid`/`pg_shadow`, `information_schema`, `pg_stat_activity` (other sessions' SQL) | table allowlist, applied wherever a table appears (subqueries, CTEs, LATERAL, UNION, EXISTS) |
| Confidential columns | Direct reads, aliasing, whole-row/JSON/aggregate tricks, `WHERE` oracles | relation substitution (see above) |
| Allowlist bypass via names | `WITH admin_users AS (...)` shadowing, forward references between CTEs, `public.<cte name>` | CTE scope tracking that follows Postgres's rules: non-recursive CTEs see only earlier siblings, and a schema-qualified name is never a CTE |
| Execution of unparsed SQL | `query_to_xml('...')`, `ts_stat('...')`, `dblink`, `cursor_to_xml` (they run SQL strings the guard never sees) | function denylist |
| Server/host | `pg_read_file`, `pg_ls_dir`, `lo_import/lo_export`, `COPY ... PROGRAM`, `pg_terminate_backend`, `pg_reload_conf`, replication slots | statement allowlist + function denylist |
| Availability | `pg_sleep`, advisory locks, huge result sets, cross-join explosions | denylist, `statement_timeout`, row cap enforced in SQL (`LIMIT`) and again in code |
| Accountability | Silent misuse | JSONL audit of every attempt (ok/rejected/error), with both the original and the executed SQL |

**Defense in depth is tested, not just claimed.** `test/server.test.ts` sends raw `INSERT`/`UPDATE`/`DELETE`/`CREATE`/`nextval`/`FOR UPDATE` straight to the read-only runner, skipping the guard, and checks that Postgres refuses every one.

**Out of scope / residual risk. Read this before production use:**

- **Use a least-privilege role.** The guard is not a substitute for `GRANT SELECT` on only the tables you mean to expose. Connect as a role without superuser, `pg_read_server_files`, `pg_execute_server_program` or write grants. If the database role is locked down, a bug in this project degrades to "the model saw something the policy meant to hide", never to "the model dropped a table".
- **Function denylist, not allowlist.** User-defined functions (and extension functions not on the list) are allowed. A `SECURITY DEFINER` function that reads a hidden table would bypass the table allowlist. The read-only transaction still stops it from writing. If your database has such functions, add them to `deniedFunctions`.
- **Masked values can still be inferred in aggregate.** For example, `count(*) GROUP BY city` over customers is allowed by design. `hash` masking is unsalted md5, so low-entropy values such as phone numbers can be brute-forced. Use `redact` for those.
- **Resource exhaustion inside the timeout.** A 5-second query can still be heavy (big sorts, hash joins). Tune `statementTimeoutMs`, and consider pointing the server at a read replica.
- **Postgres error messages** are returned to the model. They can echo identifiers from the query, but not data. A missing table and a disallowed table produce the same message, so the error doesn't reveal whether a table exists.
- **The catalog is read at startup.** Restart the server after schema changes.

## Design trade-offs

- **Parser over regex.** `SELECT $$; DROP TABLE orders; $$` is a harmless string, and `/* SELECT */ DELETE ...` is a delete. Only a real parser gets both right, and both cases are in the test suites. `libpg-query` is the actual PostgreSQL grammar, so there is no dialect gap between what the guard sees and what the server parses.
- **Allowlist of node types, denylist of functions.** Unfamiliar syntax (XMLTABLE, JSON_TABLE, locking clauses, bind parameters) is rejected by default. A function allowlist would be stricter, but it would also reject most of the useful analytical SQL an assistant writes. That's the documented residual risk above.
- **Rewrite, then validate the output.** The rewritten tree is turned back into SQL with `pgsql-deparser`, re-parsed and validated again, so the guard checks the SQL that actually runs. This caught a real issue during development: the deparser silently drops `WITH TIES`, which would have changed results. `FETCH ... WITH TIES` is now rejected with a clear message rather than quietly rewritten.
- **Row cap in SQL, not only in code.** The outer `LIMIT` is clamped to `maxRows + 1`. The extra row detects truncation, and Postgres can stop early instead of streaming a million rows to a process that throws them away. A `LIMIT (expression)` is kept and capped from an outer query, so its meaning doesn't change.
- **One connection, serialized.** A stdio MCP server has one client, and a single connection keeps the `BEGIN ... ROLLBACK` bracket simple and correct. Switch to a `pg.Pool` if many agents share one server.
- **stdio only.** Streamable HTTP would add authentication, CORS and DNS-rebinding concerns to a tool whose job is to reduce attack surface. Claude Desktop, Claude Code and Cursor all speak stdio.
- **PGlite for tests.** The whole suite runs in-process against real PostgreSQL 18 compiled to WASM, with no Docker, in about 2 seconds. CI also runs it against real PostgreSQL 16 and 17 service containers, which covers `statement_timeout`.

## Development

```bash
npm test            # 270 tests, in-process PGlite; prints the attack-corpus tally
npm run typecheck
npm run build
npm run bench       # guard latency (needs a build)

# Same suites against a real server:
psql "$TEST_DATABASE_URL" -f seed/ecommerce.sql
TEST_DATABASE_URL=postgres://... npm test
```

```
src/
  cli.ts      entry point: env/flags, --demo, stdio transport
  server.ts   MCP tools + resources; the one execute() path: guard → read-only txn → audit
  guard.ts    parse, validate, rewrite, deparse, re-validate
  policy.ts   policy schema (zod) + YAML loader
  catalog.ts  schema introspection; policy-filtered view of it
  db.ts       pg / PGlite adapters; read-only transaction runner
  audit.ts    JSONL audit log
test/
  attacks.test.ts   205-case adversarial corpus, per-layer tally
  benign.test.ts    false-positive check: 30 realistic queries
  guard.test.ts     rewrite output and policy variants
  server.test.ts    MCP tools/resources, audit, read-only defense in depth
```

## License

MIT
