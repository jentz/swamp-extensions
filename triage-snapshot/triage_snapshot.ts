/**
 * Swamp workflow-scope report: `@jentz/triage-snapshot`.
 *
 * Renders a one-look snapshot of the service-triage artifacts collected
 * earlier in the workflow. Pure data shaping — no cloud API access. The
 * report recognizes artifacts by spec name and shape and renders one
 * section per artifact, in step order:
 *
 * - `lambda_failure_scan` (e.g. `@jentz/aws-metric-scan`) — per-function
 *   invocations/errors table with the deterministic-failure flag.
 * - `queue_depth` (e.g. `@jentz/aws-metric-scan`) — per-queue depth and
 *   oldest-message age table.
 * - `query_results` with `groups`/`items` (e.g. `@jentz/aws-dynamodb-query`)
 *   — grouped-counts table (key columns + count, sorted by count).
 * - `query_results` with `results` (e.g. `@webframp/aws/logs`) — Logs
 *   Insights rows table. An artifact whose `status` is present but not
 *   `Complete` is listed in `incompleteQueries` and stamped as a warning,
 *   so a cut-off query cannot read as "all clear".
 *
 * Generic by design: the report carries no environment identifiers and
 * renders whatever recognized artifacts the workflow produced. Verdicts
 * (what counts as an anomaly) belong to the calling workflow's assert
 * steps, not to this report.
 *
 * The report never throws — a missing upstream step, malformed artifact,
 * or schema drift degrades to a logged warning and a still-useful
 * (possibly empty) report.
 *
 * @module
 */

import { z } from "npm:zod@4.4.3";

// ---------------------------------------------------------------------------
// Constants and schemas
// ---------------------------------------------------------------------------

/** Spec name of lambda failure-scan artifacts consumed by this report. */
export const LAMBDA_SCAN_SPEC = "lambda_failure_scan";
/** Spec name of queue-depth artifacts consumed by this report. */
export const QUEUE_DEPTH_SPEC = "queue_depth";
/** Spec name of query artifacts (DynamoDB and Logs Insights) consumed. */
export const QUERY_RESULTS_SPEC = "query_results";

/** Cap on rendered rows per table; the JSON payload is never capped. */
export const MAX_TABLE_ROWS = 100;

const WindowSchema = z
  .object({ start: z.string(), end: z.string() })
  .nullable()
  .optional();

/** Schema of a lambda failure-scan artifact. */
const LambdaScanSchema = z.object({
  functions: z.array(
    z.object({
      functionName: z.string(),
      invocations: z.number(),
      errors: z.number(),
      errorRate: z.number().optional(),
      deterministic: z.boolean(),
    }),
  ),
  window: WindowSchema,
  note: z.string().optional(),
});

/** Schema of a queue-depth artifact. */
const QueueDepthSchema = z.object({
  queues: z.array(
    z.object({
      queueName: z.string(),
      visibleMessages: z.number(),
      notVisibleMessages: z.number(),
      oldestMessageAgeSeconds: z.number().optional(),
    }),
  ),
  window: WindowSchema,
  note: z.string().optional(),
});

/** Schema of a DynamoDB query artifact. */
const GroupedQuerySchema = z.object({
  table: z.string().optional(),
  groups: z.array(
    z.object({
      key: z.record(z.string(), z.string()),
      count: z.number(),
    }),
  ).nullish().transform((v) => v ?? []),
  items: z.array(z.record(z.string(), z.unknown())).nullish().transform((v) =>
    v ?? []
  ),
  itemCount: z.number().optional(),
  scannedCount: z.number().optional(),
  note: z.string().nullable().optional(),
});

/** Schema of a Logs Insights query artifact. */
const LogsQuerySchema = z.object({
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

/** Inclusive query window. */
export interface QueryWindow {
  /** ISO-8601 window start. */
  start: string;
  /** ISO-8601 window end. */
  end: string;
}

/** Parsed lambda failure-scan artifact. */
export interface LambdaScan {
  /** One row per scanned function. */
  functions: Array<{
    /** Lambda function name. */
    functionName: string;
    /** Invocation count over the window. */
    invocations: number;
    /** Error count over the window. */
    errors: number;
    /** errors / invocations, when the producer computed it. */
    errorRate?: number;
    /** True when every invocation in the window errored. */
    deterministic: boolean;
  }>;
  /** The scanned window, when the producer recorded it. */
  window?: QueryWindow | null;
  /** Free-text producer note (e.g. evidence horizon). */
  note?: string;
}

/** Parsed queue-depth artifact. */
export interface QueueDepth {
  /** One row per queried queue. */
  queues: Array<{
    /** Queue name. */
    queueName: string;
    /** Visible (deliverable) message count. */
    visibleMessages: number;
    /** In-flight (not visible) message count. */
    notVisibleMessages: number;
    /** Age of the oldest message, seconds. */
    oldestMessageAgeSeconds?: number;
  }>;
  /** The scanned window, when the producer recorded it. */
  window?: QueryWindow | null;
  /** Free-text producer note (e.g. evidence horizon). */
  note?: string;
}

/** Parsed DynamoDB query artifact (grouped counts and/or plain items). */
export interface GroupedQuery {
  /** Source table name. */
  table?: string;
  /** Grouped counts; empty when the query had no grouping. */
  groups: Array<{
    /** Group key fields (stringified). */
    key: Record<string, string>;
    /** Records in the group. */
    count: number;
  }>;
  /** Plain result rows; rendered when `groups` is empty. */
  items: Array<Record<string, unknown>>;
  /** Total records matched. */
  itemCount?: number;
  /** Total records scanned. */
  scannedCount?: number;
  /** Free-text producer note (e.g. evidence horizon). */
  note?: string | null;
}

/** Parsed Logs Insights query artifact. */
export interface LogsQuery {
  /** Result rows, field name to value. */
  results: Array<Record<string, string>>;
  /** Terminal query status; anything but `Complete` means cut off. */
  status?: string;
  /** Logs Insights scan statistics. */
  statistics?: {
    /** Records matched by the query. */
    recordsMatched: number;
    /** Records scanned. */
    recordsScanned: number;
    /** Bytes scanned. */
    bytesScanned: number;
  } | null;
}

/** One rendered section, in workflow step order. */
export interface Section {
  /** Workflow step that produced the artifact. */
  step: string;
  /** Data artifact name. */
  artifact: string;
  /** Which renderer this section uses. */
  kind: "lambda_scan" | "queue_depth" | "grouped_counts" | "logs_query";
  /** Present when kind is `lambda_scan`. */
  lambdaScan?: LambdaScan;
  /** Present when kind is `queue_depth`. */
  queueDepth?: QueueDepth;
  /** Present when kind is `grouped_counts`. */
  groupedCounts?: GroupedQuery;
  /** Present when kind is `logs_query`. */
  logsQuery?: LogsQuery;
}

/** A query artifact whose status never reached Complete. */
export interface IncompleteQuery {
  /** Workflow step that produced the artifact. */
  step: string;
  /** Data artifact name. */
  artifact: string;
  /** The status the query was left in (e.g. `Running`). */
  status: string;
}

/** Everything gathered from one workflow run's step executions. */
export interface Collected {
  /** Recognized artifacts, in step order. */
  sections: Section[];
  /** Query artifacts whose status never reached Complete. */
  incomplete: IncompleteQuery[];
  /** Count of unreadable or schema-mismatched artifacts. */
  skipped: number;
}

/** Structured JSON payload emitted alongside the markdown body. */
export interface ReportJson {
  /** Report name (`@jentz/triage-snapshot`). */
  report: string;
  /** Workflow the report ran for. */
  workflow: string;
  /** ISO-8601 generation timestamp. */
  generatedAt: string;
  /** Recognized artifacts, in step order. */
  sections: Section[];
  /** Convenience count of `sections`. */
  sectionCount: number;
  /** Query artifacts whose status never reached Complete. */
  incompleteQueries: IncompleteQuery[];
  /** Convenience count of `incompleteQueries`. */
  incompleteQueryCount: number;
  /** Count of unreadable or schema-mismatched artifacts. */
  skipped: number;
  /** True when an unexpected failure degraded the report. */
  degraded: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// deno-lint-ignore no-explicit-any
function tryLog(logger: any, level: string, msg: string, args?: unknown) {
  try {
    logger?.[level]?.(msg, args);
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

/** Escape a value for a markdown table cell. */
export function mdCell(value: string): string {
  return value.replaceAll("|", "\\|").replaceAll("\n", " ").trim();
}

function mdTable(headers: string[], rows: string[][]): string {
  const lines = [
    `| ${headers.join(" | ")} |`,
    `| ${headers.map(() => "---").join(" | ")} |`,
  ];
  for (const row of rows.slice(0, MAX_TABLE_ROWS)) {
    lines.push(`| ${row.map(mdCell).join(" | ")} |`);
  }
  if (rows.length > MAX_TABLE_ROWS) {
    lines.push(`\n_…and ${rows.length - MAX_TABLE_ROWS} more row(s)._`);
  }
  return lines.join("\n");
}

function windowLine(window: LambdaScan["window"]): string {
  if (!window) return "";
  return `_Window: ${window.start} → ${window.end}_\n\n`;
}

/** Classify one decoded query_results artifact by shape. */
export function classifyQueryArtifact(
  value: unknown,
):
  | { kind: "grouped_counts"; parsed: GroupedQuery }
  | { kind: "logs_query"; parsed: LogsQuery }
  | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  // Discriminate by key: with groups/items nullable, the grouped schema
  // would otherwise accept any object.
  if ("results" in value) {
    const logs = LogsQuerySchema.safeParse(value);
    if (logs.success) return { kind: "logs_query", parsed: logs.data };
    return null;
  }
  if ("groups" in value || "items" in value) {
    const grouped = GroupedQuerySchema.safeParse(value);
    if (grouped.success) {
      return { kind: "grouped_counts", parsed: grouped.data };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

/** Walk the workflow's step executions and collect recognized artifacts. */
export async function collect(
  // deno-lint-ignore no-explicit-any
  context: any,
): Promise<Collected> {
  const logger = context.logger;
  const sections: Section[] = [];
  const incomplete: IncompleteQuery[] = [];
  let skipped = 0;

  for (const step of context.stepExecutions ?? []) {
    const stepName = typeof step.stepName === "string" ? step.stepName : "";
    for (const handle of step.dataHandles ?? []) {
      const specName: string | undefined = handle.metadata?.tags?.specName ??
        handle.specName;
      if (
        specName !== LAMBDA_SCAN_SPEC && specName !== QUEUE_DEPTH_SPEC &&
        specName !== QUERY_RESULTS_SPEC
      ) continue;

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

      if (specName === LAMBDA_SCAN_SPEC) {
        const res = LambdaScanSchema.safeParse(value);
        if (!res.success) {
          skipped++;
          continue;
        }
        sections.push({
          step: stepName,
          artifact: handle.name,
          kind: "lambda_scan",
          lambdaScan: res.data,
        });
        continue;
      }

      if (specName === QUEUE_DEPTH_SPEC) {
        const res = QueueDepthSchema.safeParse(value);
        if (!res.success) {
          skipped++;
          continue;
        }
        sections.push({
          step: stepName,
          artifact: handle.name,
          kind: "queue_depth",
          queueDepth: res.data,
        });
        continue;
      }

      const classified = classifyQueryArtifact(value);
      if (classified === null) {
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
      if (classified.kind === "grouped_counts") {
        sections.push({
          step: stepName,
          artifact: handle.name,
          kind: "grouped_counts",
          groupedCounts: classified.parsed,
        });
      } else {
        const status = classified.parsed.status ?? "";
        if (status !== "" && status !== "Complete") {
          incomplete.push({ step: stepName, artifact: handle.name, status });
          tryLog(
            logger,
            "warn",
            "query artifact {handle} has status {status}",
            {
              handle: handle.name,
              status,
            },
          );
        }
        sections.push({
          step: stepName,
          artifact: handle.name,
          kind: "logs_query",
          logsQuery: classified.parsed,
        });
      }
    }
  }

  return { sections, incomplete, skipped };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderLambdaScan(section: Section): string {
  const scan = section.lambdaScan!;
  const deterministic = scan.functions.filter((f) => f.deterministic);
  const headline = deterministic.length === 0
    ? `${scan.functions.length} function(s), no deterministic failure.`
    : `**${deterministic.length} deterministic failure(s):** ${
      deterministic.map((f) => f.functionName).join(", ")
    }`;
  const table = mdTable(
    ["Function", "Invocations", "Errors", "Deterministic"],
    scan.functions.map((f) => [
      f.functionName,
      String(f.invocations),
      String(f.errors),
      f.deterministic ? "**yes**" : "no",
    ]),
  );
  const note = scan.note ? `\n\n_${scan.note}_` : "";
  return `## Lambda failure scan — ${section.artifact}\n\n${
    windowLine(scan.window)
  }${headline}\n\n${table}${note}\n`;
}

function renderQueueDepth(section: Section): string {
  const depth = section.queueDepth!;
  const table = mdTable(
    ["Queue", "Visible", "In flight", "Oldest message (s)"],
    depth.queues.map((q) => [
      q.queueName,
      String(q.visibleMessages),
      String(q.notVisibleMessages),
      q.oldestMessageAgeSeconds === undefined
        ? ""
        : String(q.oldestMessageAgeSeconds),
    ]),
  );
  const note = depth.note ? `\n\n_${depth.note}_` : "";
  return `## Queue depth — ${section.artifact}\n\n${
    windowLine(depth.window)
  }${table}${note}\n`;
}

function renderGroupedCounts(section: Section): string {
  const grouped = section.groupedCounts!;
  const note = grouped.note ? `\n\n_${grouped.note}_` : "";

  if (grouped.groups.length === 0) {
    // No grouping — render the plain items (e.g. a settings roster).
    const columns = [
      ...new Set(grouped.items.flatMap((i) => Object.keys(i))),
    ].sort();
    const table = grouped.items.length === 0 ? "_No rows._" : mdTable(
      columns,
      grouped.items.map((i) => columns.map((c) => String(i[c] ?? ""))),
    );
    const count = grouped.itemCount ?? grouped.items.length;
    return `## Query rows — ${section.artifact}\n\n${count} record(s).\n\n${table}${note}\n`;
  }

  const keyColumns = [
    ...new Set(grouped.groups.flatMap((g) => Object.keys(g.key))),
  ].sort();
  const rows = [...grouped.groups]
    .sort((a, b) => b.count - a.count)
    .map((g) => [...keyColumns.map((c) => g.key[c] ?? ""), String(g.count)]);
  const total = grouped.itemCount ??
    grouped.groups.reduce((sum, g) => sum + g.count, 0);
  const table = mdTable([...keyColumns, "count"], rows);
  return `## Grouped counts — ${section.artifact}\n\n${total} record(s) in ${grouped.groups.length} group(s).\n\n${table}${note}\n`;
}

function renderLogsQuery(section: Section): string {
  const query = section.logsQuery!;
  const rows = query.results;
  const columns = [
    ...new Set(rows.flatMap((r) => Object.keys(r))),
  ].filter((c) => c !== "@ptr");
  const table = rows.length === 0
    ? "_No rows._"
    : mdTable(columns, rows.map((r) => columns.map((c) => r[c] ?? "")));
  const statusLine = query.status && query.status !== "Complete"
    ? `\n\n**Warning: query status is ${query.status} — results may be cut off.**`
    : "";
  return `## Query results — ${section.artifact}\n\n${rows.length} row(s).${statusLine}\n\n${table}\n`;
}

/** Render the full markdown body. */
export function renderMarkdown(
  collected: Collected,
  generatedAt: string,
  workflowName: string,
): string {
  const parts: string[] = [
    `# Triage snapshot — ${workflowName}`,
    "",
    `_Generated ${generatedAt}._`,
    "",
  ];
  if (collected.incomplete.length > 0) {
    const list = collected.incomplete
      .map((q) => `\`${q.artifact}\` (${q.status}, step \`${q.step}\`)`)
      .join(", ");
    parts.push(
      `**Warning: ${collected.incomplete.length} quer${
        collected.incomplete.length === 1 ? "y" : "ies"
      } never reached Complete status: ${list}. Empty sections below may be cut-off queries, not all-clear.**`,
      "",
    );
  }
  if (collected.sections.length === 0) {
    parts.push("_No recognized triage artifacts in this workflow run._", "");
  }
  for (const section of collected.sections) {
    switch (section.kind) {
      case "lambda_scan":
        parts.push(renderLambdaScan(section));
        break;
      case "queue_depth":
        parts.push(renderQueueDepth(section));
        break;
      case "grouped_counts":
        parts.push(renderGroupedCounts(section));
        break;
      case "logs_query":
        parts.push(renderLogsQuery(section));
        break;
    }
  }
  if (collected.skipped > 0) {
    parts.push(`_Skipped ${collected.skipped} unreadable artifact(s)._`, "");
  }
  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Report definition
// ---------------------------------------------------------------------------

/**
 * The `@jentz/triage-snapshot` workflow-scope report definition.
 *
 * Collects recognized triage artifacts from the workflow's step executions
 * and emits a markdown snapshot plus a structured JSON payload.
 */
export const report = {
  name: "@jentz/triage-snapshot",
  description:
    "One-look snapshot of service-triage artifacts collected earlier in " +
    "the workflow: lambda failure scans, queue depths, grouped DynamoDB " +
    "counts, and Logs Insights rows, one section per artifact in step " +
    "order. Generic — verdicts belong to the calling workflow's assert " +
    "steps. Query artifacts that never reached Complete status are " +
    "surfaced as a warning so a cut-off query cannot read as all-clear.",
  scope: "workflow" as const,
  labels: ["triage", "health", "snapshot", "report"],
  // deno-lint-ignore no-explicit-any
  execute: async (context: any): Promise<{
    markdown: string;
    json: ReportJson;
  }> => {
    const workflowName = context.workflowName ?? "<unknown-workflow>";
    const logger = context.logger;
    tryLog(logger, "info", "Running triage-snapshot for {workflow}", {
      workflow: workflowName,
    });

    let collected: Collected = { sections: [], incomplete: [], skipped: 0 };
    let generatedAt = "";
    let degraded = false;
    let markdown = "";

    try {
      generatedAt = new Date().toISOString();
      collected = await collect(context);
      markdown = renderMarkdown(collected, generatedAt, workflowName);
    } catch (err) {
      degraded = true;
      const detail = err instanceof Error ? err.message : String(err);
      tryLog(logger, "warn", "report degraded: {detail}", { detail });
      markdown = `# Triage snapshot\n\n_Report degraded: ${detail}_\n`;
    }

    const json: ReportJson = {
      report: "@jentz/triage-snapshot",
      workflow: workflowName,
      generatedAt,
      sections: collected.sections,
      sectionCount: collected.sections.length,
      incompleteQueries: collected.incomplete,
      incompleteQueryCount: collected.incomplete.length,
      skipped: collected.skipped,
      degraded,
    };

    tryLog(logger, "info", "report finished: {sections} section(s){degraded}", {
      sections: collected.sections.length,
      degraded: degraded ? " (degraded)" : "",
    });

    return { markdown, json };
  },
};
