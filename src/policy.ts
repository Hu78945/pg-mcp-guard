import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

export const MASKS = ['redact', 'email', 'last4', 'hash'] as const;
export type Mask = (typeof MASKS)[number];

const TableRule = z.object({
  /** Column allowlist. Omit to allow every column. */
  columns: z.array(z.string()).optional(),
  /** column -> masking strategy, applied before the query ever sees the value. */
  mask: z.record(z.string(), z.enum(MASKS)).default({}),
});
export type TableRule = z.infer<typeof TableRule>;

export const PolicySchema = z.object({
  schemas: z.array(z.string()).min(1).default(['public']),
  maxRows: z.number().int().positive().max(10_000).default(200),
  statementTimeoutMs: z.number().int().positive().max(600_000).default(5_000),
  /** Table allowlist keyed by "schema.table". Omit to allow every table in `schemas`. */
  tables: z
    .record(z.string().regex(/^[^.]+\.[^.]+$/, 'table keys must be "schema.table"'), TableRule)
    .optional(),
  /** Extra function-name regexes to deny, on top of the built-in denylist. */
  deniedFunctions: z.array(z.string()).default([]),
});
export type Policy = z.infer<typeof PolicySchema>;

export function loadPolicy(path?: string): Policy {
  const raw = path ? parseYaml(readFileSync(path, 'utf8')) : {};
  return PolicySchema.parse(raw ?? {});
}
