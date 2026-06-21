/**
 * Swamp workflow-scope report: `@jentz/aws-rds-inventory-report`.
 *
 * Consumes the `cluster` and `instance` resources produced earlier in the
 * workflow by `@jentz/aws-rds-inventory` and emits an operator inventory of
 * every RDS cluster and member instance observed. Pure data shaping — no AWS
 * API access.
 *
 * The markdown body is a human-readable summary (cluster count, instance
 * count, engines, writer/reader split, multi-AZ count) followed by the full
 * inventory table; the `json` payload carries structured `clusters[]` +
 * `instances[]` rows (mirroring the model's row fields, in a stable sort
 * order) plus the summary counts, the skipped-artifact count, and a
 * `degraded` flag. No `csv` field is emitted — a downstream `jq` recipe in
 * the README covers that case.
 *
 * The report never throws — a missing upstream step, malformed artifact, or
 * schema drift degrades to a logged warning and a still-useful (possibly
 * empty) report.
 *
 * @module
 */

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Model type whose outputs this report consumes. */
export const INVENTORY_MODEL_TYPE = "@jentz/aws-rds-inventory";

// ---------------------------------------------------------------------------
// Never-throws helpers
// ---------------------------------------------------------------------------

function tryLog(
  // deno-lint-ignore no-explicit-any
  logger: any,
  level: "info" | "warn" | "debug" | "error",
  message: string,
  props?: Record<string, unknown>,
): void {
  try {
    logger?.[level]?.(message, props);
  } catch {
    // swallow — logging is observability, not correctness
  }
}

const TEXT_DECODER = new TextDecoder();

// Wired into `collect` in a later phase; defined now so the never-throws
// decode posture is in place from the package's first commit.
// deno-lint-ignore no-unused-vars
function decodeJson(bytes: Uint8Array | null): unknown | undefined {
  if (!bytes || bytes.length === 0) return undefined;
  try {
    return JSON.parse(TEXT_DECODER.decode(bytes));
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Report export
// ---------------------------------------------------------------------------

/** Structured JSON payload returned alongside the markdown body. */
export interface ReportJson {
  /** Stable report name. */
  report: string;
  /** Originating workflow. */
  workflow: string;
  /** ISO timestamp; `""` if the host clock was unavailable. */
  generatedAt: string;
  /** Number of cluster rows. */
  clusterCount: number;
  /** Number of instance rows. */
  instanceCount: number;
  /** Artifacts skipped during collection. */
  skipped: number;
  /** True when the outer guard absorbed an unexpected failure. */
  degraded: boolean;
}

/**
 * The `@jentz/aws-rds-inventory-report` workflow-scope report. Returns
 * `{ markdown, json }`; swamp persists them as `report-{name}`
 * (text/markdown) and `report-{name}-json` (application/json).
 */
export const report = {
  name: "@jentz/aws-rds-inventory-report",
  description: "Operator inventory of RDS clusters and member instances " +
    "(identifier, engine, role, instance class, multi-AZ) built from " +
    "@jentz/aws-rds-inventory rows collected earlier in the workflow. Emits " +
    "a markdown table and a structured JSON payload with one row per cluster " +
    "and one per instance.",
  scope: "workflow" as const,
  labels: ["aws", "rds", "inventory", "report"],
  // deno-lint-ignore no-explicit-any
  execute: async (context: any): Promise<{
    markdown: string;
    json: ReportJson;
  }> => {
    const workflowName = context.workflowName ?? "<unknown-workflow>";
    const logger = context.logger;
    tryLog(
      logger,
      "info",
      "Running aws-rds-inventory-report for {workflow}",
      { workflow: workflowName },
    );

    let generatedAt = "";
    let degraded = false;
    let markdown = "";

    try {
      generatedAt = new Date().toISOString();
      // Collection + rendering land in later phases. For now the report
      // produces a valid empty payload under the never-throws guard.
      markdown = `# AWS RDS Inventory\n\n` +
        `_Generated ${generatedAt} · workflow \`${workflowName}\`_\n`;
      await Promise.resolve();
    } catch (err) {
      degraded = true;
      const detail = err instanceof Error ? err.message : String(err);
      tryLog(logger, "warn", "report degraded: {detail}", { detail });
      markdown = `# AWS RDS Inventory\n\n_Report degraded: ${detail}_\n`;
    }

    const json: ReportJson = {
      report: "@jentz/aws-rds-inventory-report",
      workflow: workflowName,
      generatedAt,
      clusterCount: 0,
      instanceCount: 0,
      skipped: 0,
      degraded,
    };

    tryLog(logger, "info", "report finished{degraded}", {
      degraded: degraded ? " (degraded)" : "",
    });

    return { markdown, json };
  },
};
