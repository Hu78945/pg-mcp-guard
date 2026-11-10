import type { PGlite } from '@electric-sql/pglite';
import type pg from 'pg';

export interface QueryResult {
  rows: any[];
  fields: { name: string }[];
}

/** The two calls the server needs; implemented for node-postgres and PGlite. */
export interface Db {
  query(sql: string, params?: unknown[], rowMode?: 'array'): Promise<QueryResult>;
  close(): Promise<void>;
}

export function fromPg(client: pg.Client): Db {
  return {
    query: (text, values, rowMode) =>
      rowMode ? client.query({ text, values, rowMode }) : client.query({ text, values }),
    close: () => client.end(),
  };
}

export function fromPglite(db: PGlite): Db {
  return {
    query: (sql, params, rowMode) => db.query(sql, params, { rowMode: rowMode ?? 'object' }),
    close: () => db.close(),
  };
}

/**
 * Run `fn` inside BEGIN READ ONLY with a statement timeout, then always ROLLBACK.
 * Even if the SQL guard were bypassed, Postgres itself refuses writes here.
 */
export function createReadOnlyRunner(db: Db, timeoutMs: number) {
  // ponytail: one connection, requests serialized; switch to a pg.Pool if many agents share one server.
  let queue: Promise<unknown> = Promise.resolve();
  return function readOnly<T>(fn: (db: Db) => Promise<T>): Promise<T> {
    const run = async () => {
      await db.query('BEGIN TRANSACTION READ ONLY');
      try {
        await db.query(`SET LOCAL statement_timeout = ${Math.trunc(timeoutMs)}`);
        return await fn(db);
      } finally {
        await db.query('ROLLBACK');
      }
    };
    const result = queue.then(run, run);
    queue = result.catch(() => {});
    return result;
  };
}
