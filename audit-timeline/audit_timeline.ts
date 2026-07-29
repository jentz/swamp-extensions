/**
 * Swamp workflow-scope report: `@jentz/audit-timeline`.
 *
 * Renders a change-audit timeline from Logs Insights query rows collected
 * earlier in the workflow (any model producing `query_results` artifacts,
 * e.g. `@webframp/aws/logs`), plus an actor roster and a ready-to-run
 * identity-resolution SQL statement built from a template carried in local
 * config (any model producing a `config` artifact, e.g.
 * `@jentz/local-config`). Pure data shaping — no cloud API access.
 *
 * The report itself is environment-free: every environment-specific detail
 * (field names, SQL template, source-IP origin map) comes from the config
 * artifact. Config contract (all keys optional unless noted):
 *
 * ```jsonc
 * {
 *   "identityResolution": {
 *     // required to emit SQL; {account} and {userid_list} are substituted
 *     "sqlTemplate": "SELECT ... FROM db{account}.users WHERE id IN ({userid_list});",
 *     // per-actor term; {guid_hex} is the actor id with braces/dashes stripped
 *     "useridTerm": "UNHEX('{guid_hex}')"
 *   },
 *   // source-IP -> origin annotation for rows that carry a source IP
 *   "natMap": { "198.51.100.7": { "account": "x", "service": "y", "note": "z" } },
 *   "auditTimeline": {
 *     // override which row fields the report reads; defaults shown
 *     "fields": {
 *       "timestamp": "@timestamp",
 *       "actor": "user_id",
 *       "account": "account_id",
 *       "requestId": "request_id",
 *       "service": "service",
 *       "method": "http.method",
 *       "path": "http.path",
 *       "status": "http.status",
 *       "body": "http.body",
 *       "sourceIp": ""
 *     }
 *   }
 * }
 * ```
 *
 * The report never throws — a missing upstream step, malformed artifact, or
 * schema drift degrades to a logged warning and a still-useful (possibly
 * empty) report.
 *
 * @module
 */

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Constants and schemas
// ---------------------------------------------------------------------------

/** Spec name of Logs Insights query artifacts consumed by this report. */
export const QUERY_RESULTS_SPEC = "query_results";
/** Spec name of local-config artifacts consumed by this report. */
export const CONFIG_SPEC = "config";

const QueryArtifactSchema = z.object({
  results: z.array(z.record(z.string(), z.string())),
  status: z.string().optional(),
  statistics: z
    .object({
      recordsMatched: z.number(),
      recordsScanned: z.number(),
      bytesScanned: z.number(),
    })
    .nullable()
    .optional(),
});

const NatEntrySchema = z.object({
  account: z.string().optional(),
  service: z.string().optional(),
  note: z.string().optional(),
});

const FieldMapSchema = z.object({
  timestamp: z.string().default("@timestamp"),
  actor: z.string().default("user_id"),
  account: z.string().default("account_id"),
  requestId: z.string().default("request_id"),
  service: z.string().default("service"),
  method: z.string().default("http.method"),
  path: z.string().default("http.path"),
  status: z.string().default("http.status"),
  body: z.string().default("http.body"),
  sourceIp: z.string().default(""),
});

/**
 * Which raw row fields feed each timeline column. Mirrors `FieldMapSchema`,
 * which stays the runtime validation source of truth; the explicit interface
 * keeps zod internals out of the public API surface.
 */
export interface FieldMap {
  /** Row field holding the event timestamp. */
  timestamp: string;
  /** Row field holding the actor identifier. */
  actor: string;
  /** Row field holding the account identifier. */
  account: string;
  /** Row field holding the correlation/request id. */
  requestId: string;
  /** Row field holding the producing service/domain. */
  service: string;
  /** Row field holding the HTTP method. */
  method: string;
  /** Row field holding the target path. */
  path: string;
  /** Row field holding the HTTP status. */
  status: string;
  /** Row field holding the submitted body. */
  body: string;
  /** Row field holding the source IP; `""` disables origin lookup. */
  sourceIp: string;
}

/** One normalized change event on the timeline. */
export interface ChangeEvent {
  /** ISO-8601 UTC timestamp with milliseconds. */
  timestamp: string;
  /** Actor identifier exactly as logged (e.g. a GUID); `""` if absent. */
  actor: string;
  /** Account identifier from the row; `""` if absent. */
  account: string;
  /** Correlation/request id; `""` if absent. */
  requestId: string;
  /** Producing service/domain (e.g. `widgets`). */
  service: string;
  /** Change verb derived from the HTTP method: add/update/delete/other. */
  verb: string;
  /** Raw HTTP method. */
  method: string;
  /** Target path. */
  path: string;
  /** Site segment parsed from `/sites/{site}/` in the path; `""` if absent. */
  site: string;
  /** HTTP status; `""` if absent (e.g. network-level failure rows). */
  status: string;
  /** Submitted body for add/update rows; `""` otherwise. */
  body: string;
  /** Origin annotation from the natMap for the row's source IP; `""` if none. */
  origin: string;
}

/** Everything collected from upstream workflow steps. */
export interface Collected {
  /** Normalized change events, sorted by timestamp. */
  events: ChangeEvent[];
  /** Parsed config artifact, `{}` when no config step was found. */
  config: Record<string, unknown>;
  /** Artifacts that failed to decode or validate. */
  skipped: number;
}

/** Structured JSON payload emitted alongside the markdown body. */
export interface ReportJson {
  /** Report name (`@jentz/audit-timeline`). */
  report: string;
  /** Name of the workflow the report ran against. */
  workflow: string;
  /** ISO-8601 generation timestamp. */
  generatedAt: string;
  /** Normalized change events, sorted by timestamp. */
  events: ChangeEvent[];
  /** Number of events. */
  eventCount: number;
  /** Per-actor rollups, most changes first. */
  actors: ActorSummary[];
  /** One identity-resolution SQL statement per distinct account. */
  resolutionSql: string[];
  /** Artifacts that failed to decode or validate. */
  skipped: number;
  /** True when an unexpected failure degraded the report. */
  degraded: boolean;
}

/** Per-actor rollup for the roster table. */
export interface ActorSummary {
  /** Actor identifier exactly as logged. */
  actor: string;
  /** Number of changes attributed to this actor. */
  changes: number;
  /** Timestamp of the actor's earliest change. */
  firstSeen: string;
  /** Timestamp of the actor's latest change. */
  lastSeen: string;
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for tests)
// ---------------------------------------------------------------------------

/**
 * Normalize a Logs Insights timestamp (`2026-06-11 08:40:04.097`, implicit
 * UTC) or any Date-parseable string to ISO-8601 UTC with milliseconds.
 * Returns the input unchanged when it cannot be parsed.
 */
export function toIsoUtc(ts: string): string {
  const insights = ts.match(
    /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}(?:\.\d+)?)$/,
  );
  const candidate = insights ? `${insights[1]}T${insights[2]}Z` : ts;
  const parsed = new Date(candidate);
  if (isNaN(parsed.getTime())) return ts;
  return parsed.toISOString();
}

/** Map an HTTP method to a change verb. */
export function methodToVerb(method: string): string {
  switch (method.toUpperCase()) {
    case "POST":
      return "add";
    case "PUT":
    case "PATCH":
      return "update";
    case "DELETE":
      return "delete";
    default:
      return method ? method.toLowerCase() : "other";
  }
}

/** Extract the site segment from a `/sites/{site}/...` path, else `""`. */
export function siteFromPath(path: string): string {
  const m = path.match(/\/sites\/([^/]+)\//);
  return m ? m[1] : "";
}

/** Strip braces and dashes from a GUID for use inside `UNHEX('…')`. */
export function guidToHex(guid: string): string {
  return guid.replace(/[{}-]/g, "");
}

/**
 * Build one identity-resolution SQL statement per distinct account seen in
 * the events, from the config's `identityResolution` template. Returns `[]`
 * when the template, term, or actor list is missing/empty.
 */
export function buildResolutionSql(
  events: ChangeEvent[],
  config: Record<string, unknown>,
): string[] {
  const ir = config.identityResolution as
    | { sqlTemplate?: string; useridTerm?: string }
    | undefined;
  if (!ir?.sqlTemplate || !ir?.useridTerm) return [];

  const byAccount = new Map<string, Set<string>>();
  for (const e of events) {
    if (!e.actor) continue;
    const set = byAccount.get(e.account) ?? new Set<string>();
    set.add(e.actor);
    byAccount.set(e.account, set);
  }

  const statements: string[] = [];
  for (const [account, actors] of [...byAccount.entries()].sort()) {
    const terms = [...actors]
      .sort()
      .map((a) => ir.useridTerm!.replaceAll("{guid_hex}", guidToHex(a)));
    statements.push(
      ir.sqlTemplate
        .replaceAll("{account}", account)
        .replaceAll("{userid_list}", terms.join(", ")),
    );
  }
  return statements;
}

/** Roll events up into a per-actor roster, sorted by change count desc. */
export function summarizeActors(events: ChangeEvent[]): ActorSummary[] {
  const map = new Map<string, ActorSummary>();
  for (const e of events) {
    if (!e.actor) continue;
    const cur = map.get(e.actor);
    if (!cur) {
      map.set(e.actor, {
        actor: e.actor,
        changes: 1,
        firstSeen: e.timestamp,
        lastSeen: e.timestamp,
      });
    } else {
      cur.changes++;
      if (e.timestamp < cur.firstSeen) cur.firstSeen = e.timestamp;
      if (e.timestamp > cur.lastSeen) cur.lastSeen = e.timestamp;
    }
  }
  return [...map.values()].sort(
    (a, b) => b.changes - a.changes || a.actor.localeCompare(b.actor),
  );
}

/** Convert one raw Insights row into a ChangeEvent using the field map. */
export function rowToEvent(
  row: Record<string, string>,
  fields: FieldMap,
  natMap: Record<string, { account?: string; service?: string; note?: string }>,
): ChangeEvent {
  const method = row[fields.method] ?? "";
  const path = row[fields.path] ?? "";
  const ip = fields.sourceIp ? row[fields.sourceIp] ?? "" : "";
  const nat = ip ? natMap[ip] : undefined;
  const origin = nat
    ? [nat.account, nat.service, nat.note].filter(Boolean).join(" / ")
    : "";
  return {
    timestamp: toIsoUtc(row[fields.timestamp] ?? ""),
    actor: row[fields.actor] ?? "",
    account: row[fields.account] ?? "",
    requestId: row[fields.requestId] ?? "",
    service: row[fields.service] ?? "",
    verb: methodToVerb(method),
    method,
    path,
    site: siteFromPath(path),
    status: row[fields.status] ?? "",
    body: row[fields.body] ?? "",
    origin,
  };
}

// ---------------------------------------------------------------------------
// Never-throws helpers
// ---------------------------------------------------------------------------

function tryLog(
  // deno-lint-ignore no-explicit-any
  logger: any,
  level: "info" | "warn",
  msg: string,
  props: Record<string, unknown>,
): void {
  try {
    logger?.[level]?.(msg, props);
  } catch {
    // logging must never break the report
  }
}

function decodeJson(bytes: Uint8Array | null): unknown {
  if (!bytes) return undefined;
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

/** Gather query rows and config from the workflow's step executions. */
export async function collect(
  // deno-lint-ignore no-explicit-any
  context: any,
): Promise<Collected> {
  const logger = context.logger;
  let config: Record<string, unknown> = {};
  const rawRows: Record<string, string>[] = [];
  let skipped = 0;

  for (const step of context.stepExecutions ?? []) {
    for (const handle of step.dataHandles ?? []) {
      const specName: string | undefined = handle.metadata?.tags?.specName ??
        handle.specName;
      if (specName !== QUERY_RESULTS_SPEC && specName !== CONFIG_SPEC) continue;

      let bytes: Uint8Array | null;
      try {
        bytes = await context.dataRepository.getContent(
          step.modelType,
          step.modelId,
          handle.name,
          handle.version,
        );
      } catch {
        skipped++;
        tryLog(logger, "warn", "Could not read {spec} artifact {handle}", {
          spec: specName,
          handle: handle.name,
        });
        continue;
      }
      const value = decodeJson(bytes);
      if (value === undefined) {
        skipped++;
        continue;
      }

      if (specName === CONFIG_SPEC) {
        if (value && typeof value === "object" && !Array.isArray(value)) {
          config = value as Record<string, unknown>;
        } else {
          skipped++;
        }
        continue;
      }

      const res = QueryArtifactSchema.safeParse(value);
      if (!res.success) {
        skipped++;
        tryLog(
          logger,
          "warn",
          "query_results artifact {handle} failed schema",
          {
            handle: handle.name,
          },
        );
        continue;
      }
      rawRows.push(...res.data.results);
    }
  }

  const fields = FieldMapSchema.parse(
    (config.auditTimeline as { fields?: unknown } | undefined)?.fields ?? {},
  );
  const natMapRaw = (config.natMap ?? {}) as Record<string, unknown>;
  const natMap: Record<string, z.infer<typeof NatEntrySchema>> = {};
  for (const [ip, entry] of Object.entries(natMapRaw)) {
    const res = NatEntrySchema.safeParse(entry);
    if (res.success) natMap[ip] = res.data;
  }

  const events = rawRows
    .map((row) => rowToEvent(row, fields, natMap))
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  return { events, config, skipped };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function mdEscape(s: string): string {
  return s.replaceAll("|", "\\|").replaceAll("\n", " ");
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

/** Render the markdown body. */
export function renderMarkdown(
  collected: Collected,
  actors: ActorSummary[],
  resolutionSql: string[],
  generatedAt: string,
  workflowName: string,
): string {
  const { events, skipped } = collected;
  const hasOrigin = events.some((e) => e.origin !== "");
  const lines: string[] = [];

  lines.push("# Audit timeline");
  lines.push("");
  lines.push(
    `_Workflow **${workflowName}** · generated ${generatedAt} · ` +
      `${events.length} change(s) · ${actors.length} actor(s)` +
      `${skipped ? ` · ${skipped} artifact(s) skipped` : ""}_`,
  );
  lines.push("");

  lines.push("## Timeline");
  lines.push("");
  if (events.length === 0) {
    lines.push("_No changes matched the query window and filters._");
  } else {
    const originHead = hasOrigin ? " Origin |" : "";
    lines.push(
      `| Timestamp (UTC) | Actor | Verb | Service | Site | Path | Status |${originHead} Submitted body |`,
    );
    lines.push(
      `|---|---|---|---|---|---|---|${hasOrigin ? "---|" : ""}---|`,
    );
    for (const e of events) {
      const originCell = hasOrigin ? ` ${mdEscape(e.origin)} |` : "";
      lines.push(
        `| ${e.timestamp} | \`${mdEscape(e.actor) || "—"}\` | ${e.verb} | ` +
          `${mdEscape(e.service)} | ${mdEscape(e.site) || "—"} | ` +
          `\`${mdEscape(e.path)}\` | ${e.status || "—"} |${originCell} ` +
          `${e.body ? "`" + mdEscape(truncate(e.body, 120)) + "`" : "—"} |`,
      );
    }
  }
  lines.push("");

  lines.push("## Actor roster");
  lines.push("");
  if (actors.length === 0) {
    lines.push("_No actors observed._");
  } else {
    lines.push("| Actor | Changes | First seen | Last seen |");
    lines.push("|---|---|---|---|");
    for (const a of actors) {
      lines.push(
        `| \`${
          mdEscape(a.actor)
        }\` | ${a.changes} | ${a.firstSeen} | ${a.lastSeen} |`,
      );
    }
  }
  lines.push("");

  lines.push("## Identity resolution (human-in-the-loop)");
  lines.push("");
  if (resolutionSql.length === 0) {
    lines.push(
      "_No resolution SQL emitted (no actors, or no `identityResolution` " +
        "template in config)._",
    );
  } else {
    lines.push(
      "Run against the admin database; results stay with the operator.",
    );
    lines.push("");
    lines.push("```sql");
    for (const sql of resolutionSql) lines.push(sql);
    lines.push("```");
  }
  lines.push("");
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Report definition
// ---------------------------------------------------------------------------

/**
 * The `@jentz/audit-timeline` workflow-scope report definition consumed by
 * the swamp report loader.
 */
export const report = {
  name: "@jentz/audit-timeline",
  description:
    "Change-audit timeline built from Logs Insights query rows collected " +
    "earlier in the workflow: per-change timestamp/actor/verb/target table, " +
    "an actor roster, and ready-to-run identity-resolution SQL from a " +
    "config-carried template. Generic — field names, SQL template, and " +
    "source-IP origin map all come from a config artifact in the same " +
    "workflow.",
  scope: "workflow" as const,
  labels: ["audit", "logs", "timeline", "forensics", "report"],
  // deno-lint-ignore no-explicit-any
  execute: async (context: any): Promise<{
    markdown: string;
    json: ReportJson;
  }> => {
    const workflowName = context.workflowName ?? "<unknown-workflow>";
    const logger = context.logger;
    tryLog(logger, "info", "Running audit-timeline for {workflow}", {
      workflow: workflowName,
    });

    let collected: Collected = { events: [], config: {}, skipped: 0 };
    let actors: ActorSummary[] = [];
    let resolutionSql: string[] = [];
    let generatedAt = "";
    let degraded = false;
    let markdown = "";

    try {
      generatedAt = new Date().toISOString();
      collected = await collect(context);
      actors = summarizeActors(collected.events);
      resolutionSql = buildResolutionSql(collected.events, collected.config);
      markdown = renderMarkdown(
        collected,
        actors,
        resolutionSql,
        generatedAt,
        workflowName,
      );
    } catch (err) {
      degraded = true;
      const detail = err instanceof Error ? err.message : String(err);
      tryLog(logger, "warn", "report degraded: {detail}", { detail });
      markdown = `# Audit timeline\n\n_Report degraded: ${detail}_\n`;
    }

    const json: ReportJson = {
      report: "@jentz/audit-timeline",
      workflow: workflowName,
      generatedAt,
      events: collected.events,
      eventCount: collected.events.length,
      actors,
      resolutionSql,
      skipped: collected.skipped,
      degraded,
    };

    tryLog(logger, "info", "report finished: {events} event(s){degraded}", {
      events: collected.events.length,
      degraded: degraded ? " (degraded)" : "",
    });

    return { markdown, json };
  },
};
