import { appendFileSync } from 'node:fs';

export interface AuditEntry {
  tool: string;
  sql?: string;
  executedSql?: string;
  status: 'ok' | 'rejected' | 'error';
  reason?: string;
  rowCount?: number;
  durationMs?: number;
}

export type Audit = (entry: AuditEntry) => void;

/** JSON-lines audit log. Goes to stderr when no file is given (stdout is the MCP channel). */
export function createAudit(path?: string): Audit {
  return (entry) => {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n';
    if (path) appendFileSync(path, line);
    else process.stderr.write(line);
  };
}
