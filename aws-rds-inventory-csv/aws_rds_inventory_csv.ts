/**
 * Swamp workflow-scope report: `@jentz/aws-rds-inventory-csv`.
 *
 * Consumes `instance` resources produced earlier in the workflow by
 * `@jentz/aws-rds-inventory` and emits a single CSV summary (one row
 * per cluster member). Pure data shaping — no AWS API access.
 *
 * The swamp report runtime persists two artifacts per report:
 * `report-{name}` (content type `text/markdown`) and `report-{name}-json`
 * (content type `application/json`). There is no built-in `csv` channel
 * and `dataRepository` is read-only on report contexts, so the CSV body
 * is returned in `markdown` (so `swamp report get` shows the rows) and
 * mirrored under `json.csv` for machine consumers:
 *
 *   swamp data get --workflow <workflow> report-aws-rds-inventory-csv-json --json \
 *     | jq -r .csv > inventory.csv
 *
 * The report never throws — missing upstream step, malformed artifact,
 * schema mismatch, etc. all degrade to a logged warning and a useful
 * (possibly empty) CSV.
 *
 * @module
 */

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Model type whose outputs this report consumes. */
export const INVENTORY_MODEL_TYPE = "@jentz/aws-rds-inventory";

/** Instance spec name on the upstream inventory model. */
export const INSTANCE_SPEC = "instance";
/** Cluster spec name on the upstream inventory model — counted but not rendered. */
export const CLUSTER_SPEC = "cluster";

/**
 * Default CSV columns in the order they appear in the header. Kept as a
 * single source of truth so the README, the column-validator, and the
 * row-renderer cannot drift apart.
 */
export const DEFAULT_COLUMNS = [
  "cluster_id",
  "instance_id",
  "instance_class",
  "role",
  "az",
  "engine",
  "engine_version",
  "promotion_tier",
  "parameter_group_status",
  "tags",
] as const;

/** One element of {@link DEFAULT_COLUMNS}. */
export type ColumnName = typeof DEFAULT_COLUMNS[number];

const COLUMN_SET: ReadonlySet<string> = new Set(DEFAULT_COLUMNS);

/** Env var that overrides {@link DEFAULT_COLUMNS}. */
export const COLUMNS_ENV = "AWS_RDS_INVENTORY_CSV_COLUMNS";

// ---------------------------------------------------------------------------
// Never-throws helpers
// ---------------------------------------------------------------------------

/**
 * Best-effort env-var read. Returns `undefined` when `Deno.env` access is
 * not granted (e.g. inside a sandboxed runtime) rather than throwing.
 * The defaulting behavior is observable from the CSV header — operators
 * who set the env var and don't see the override applied can confirm
 * the value from `swamp data get ... --json` (the resolved column list
 * is on `json.columns`).
 */
function readEnv(name: string): string | undefined {
  try {
    return Deno.env.get(name) ?? undefined;
  } catch {
    return undefined;
  }
}

/**
 * Call a logger method and swallow exceptions. The report contract is
 * never-throws; a misbehaving host-injected logger must not break it.
 */
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

// ---------------------------------------------------------------------------
// Schema — mirrors @jentz/aws-rds-inventory's public instance shape
//
// The InstanceSchema below is a hand-mirror of the producer's
// `InstanceSchema` in `../aws-rds-inventory/aws_rds_inventory.ts`. If
// upstream renames or tightens a field, every artifact will fail
// safeParse here and the report will silently drop rows. The
// schema-failure warn includes the zod issue paths so the drift is
// diagnosable from logs alone; if you change one schema, check the other.
// ---------------------------------------------------------------------------

const TagsSchema = z.record(z.string(), z.string()).default({});

const InstanceSchema = z.object({
  DBInstanceIdentifier: z.string(),
  DBClusterIdentifier: z.string(),
  DBInstanceClass: z.string(),
  Role: z.enum(["writer", "reader"]),
  AvailabilityZone: z.string().optional(),
  Engine: z.string(),
  EngineVersion: z.string().optional(),
  Status: z.string().optional(),
  PromotionTier: z.number().optional(),
  DBClusterParameterGroupStatus: z.string().optional(),
  tags: TagsSchema,
});

/** Instance resource as collected from upstream `@jentz/aws-rds-inventory`. */
export interface Instance {
  /** AWS instance identifier. */
  DBInstanceIdentifier: string;
  /** Back-reference to the owning cluster. */
  DBClusterIdentifier: string;
  /** AWS instance class (e.g. `db.r7g.large`). */
  DBInstanceClass: string;
  /** Role within the cluster. */
  Role: "writer" | "reader";
  /** Availability zone, if returned. */
  AvailabilityZone?: string;
  /** Engine string. */
  Engine: string;
  /** Engine version, if returned. */
  EngineVersion?: string;
  /** Instance lifecycle status. */
  Status?: string;
  /** Failover priority, 0-15. Absent when AWS omitted the field. */
  PromotionTier?: number;
  /** Parameter-group apply status (`in-sync`, `applying`, etc). Absent when AWS omitted the field. */
  DBClusterParameterGroupStatus?: string;
  /** Per-instance tags (flattened). */
  tags: Record<string, string>;
}

/** Collected inventory across every matching upstream step. */
export interface CollectedInventory {
  /** Successfully decoded instance resources. */
  instances: Instance[];
  /**
   * Distinct cluster identifiers observed across cluster artifacts —
   * counted directly (cluster bodies are not decoded). A cluster id that
   * appears in this set without any instance row is a partial-upstream
   * signal: cluster artifact present, no instance artifacts emitted.
   */
  clusterArtifactIds: Set<string>;
  /** Count of artifacts that failed to decode or validate. */
  skipped: number;
  /** Count of (cluster_id, instance_id) duplicates observed across artifacts. */
  duplicates: number;
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

const TEXT_DECODER = new TextDecoder();

type ParseOutcome =
  | { kind: "ok"; value: unknown }
  | { kind: "missing" }
  | { kind: "parse-error" };

function decodeJson(bytes: Uint8Array | null): ParseOutcome {
  if (!bytes || bytes.length === 0) return { kind: "missing" };
  try {
    return { kind: "ok", value: JSON.parse(TEXT_DECODER.decode(bytes)) };
  } catch {
    return { kind: "parse-error" };
  }
}

/**
 * Walk `context.stepExecutions`, locate steps whose `modelType` is
 * {@link INVENTORY_MODEL_TYPE}, and decode their `instance` resource
 * outputs. Cluster artifacts are counted (by identifier only) but not
 * decoded — every column the report emits is read from instance state.
 * Malformed JSON, schema mismatch, missing bytes, and duplicate
 * (cluster_id, instance_id) artifacts each log a warning and increment
 * the appropriate counter. The report never throws — every logger call
 * routes through {@link tryLog} so a misbehaving host logger cannot
 * escape the function.
 *
 * Returns empty arrays (not throws) when no inventory step is present
 * in the workflow; if `stepExecutions` is non-empty but no step matched
 * the inventory model type, logs a warn listing the model types it did
 * see so the operator has a diagnostic.
 */
export async function collectInventory(
  // deno-lint-ignore no-explicit-any
  context: any,
): Promise<CollectedInventory> {
  const logger = context.logger;
  const instances: Instance[] = [];
  const clusterArtifactIds = new Set<string>();
  const seenInstanceKeys = new Map<string, Instance>();
  let skipped = 0;
  let duplicates = 0;
  let matchingStepCount = 0;
  const observedModelTypes = new Set<string>();

  for (const step of context.stepExecutions ?? []) {
    if (typeof step?.modelType === "string") {
      observedModelTypes.add(step.modelType);
    }
    if (step.modelType !== INVENTORY_MODEL_TYPE) continue;
    matchingStepCount++;

    for (const handle of step.dataHandles ?? []) {
      const specName: string | undefined = handle.metadata?.tags?.specName ??
        handle.specName;

      // Cluster artifacts: count the identifier and move on. The
      // identifier sits in handle.name for the upstream's resource
      // storage-key pattern (`cluster-<id>`); falling back to nothing
      // when the convention doesn't match is safe — we only use this
      // to detect partial-upstream failures.
      if (specName === CLUSTER_SPEC) {
        if (typeof handle.name === "string" && handle.name.length > 0) {
          clusterArtifactIds.add(handle.name);
        }
        continue;
      }
      if (specName !== INSTANCE_SPEC) continue;

      const stepLabel = `${step.jobName}.${step.stepName}`;
      const bytes: Uint8Array | null = await context.dataRepository.getContent(
        step.modelType,
        step.modelId,
        handle.name,
        handle.version,
      );
      const outcome = decodeJson(bytes);
      if (outcome.kind === "missing") {
        skipped++;
        tryLog(
          logger,
          "warn",
          "No bytes for {spec} artifact {handle} from {step}",
          { spec: specName, handle: handle.name, step: stepLabel },
        );
        continue;
      }
      if (outcome.kind === "parse-error") {
        skipped++;
        tryLog(
          logger,
          "warn",
          "Could not parse {spec} artifact {handle} from {step} as JSON",
          { spec: specName, handle: handle.name, step: stepLabel },
        );
        continue;
      }

      const res = InstanceSchema.safeParse(outcome.value);
      if (!res.success) {
        skipped++;
        const fields = res.error.issues
          .map((i) => i.path.join(".") || "<root>")
          .join(", ");
        tryLog(
          logger,
          "warn",
          "Instance artifact {handle} from {step} failed schema validation " +
            "on field(s): {fields}",
          { handle: handle.name, step: stepLabel, fields },
        );
        continue;
      }

      const inst = res.data;
      const key = `${inst.DBClusterIdentifier}/${inst.DBInstanceIdentifier}`;
      const existing = seenInstanceKeys.get(key);
      if (existing) {
        duplicates++;
        // Last-write-wins so the latest version of an instance retried
        // by upstream supersedes the earlier one. Track via the
        // instances array order so the eventual sort is stable.
        const idx = instances.indexOf(existing);
        if (idx >= 0) instances[idx] = inst;
        seenInstanceKeys.set(key, inst);
        tryLog(
          logger,
          "warn",
          "Duplicate instance {cluster}/{instance} from {step}; last write wins",
          {
            cluster: inst.DBClusterIdentifier,
            instance: inst.DBInstanceIdentifier,
            step: stepLabel,
          },
        );
        continue;
      }
      seenInstanceKeys.set(key, inst);
      instances.push(inst);
    }
  }

  // If the workflow had steps but none of them came from the inventory
  // model, give the operator a pointer rather than a silent empty CSV.
  const hadSteps = (context.stepExecutions ?? []).length > 0;
  if (hadSteps && matchingStepCount === 0) {
    tryLog(
      logger,
      "warn",
      "No step matched modelType={expected}; observed modelTypes: {observed}. " +
        "If the workflow ran the inventory model under a different type, " +
        "the report will emit an empty CSV.",
      {
        expected: INVENTORY_MODEL_TYPE,
        observed: [...observedModelTypes].sort().join(", ") || "<none>",
      },
    );
  }

  tryLog(
    logger,
    "info",
    "Collected {instances} instance(s) from {steps} matching step(s); " +
      "{clusters} cluster artifact id(s) observed; {skipped} artifact(s) " +
      "skipped; {duplicates} duplicate(s) deduped",
    {
      instances: instances.length,
      steps: matchingStepCount,
      clusters: clusterArtifactIds.size,
      skipped,
      duplicates,
    },
  );

  return {
    instances,
    clusterArtifactIds,
    skipped,
    duplicates,
  };
}

// ---------------------------------------------------------------------------
// Column selection
// ---------------------------------------------------------------------------

/**
 * Parse a comma-separated column override into a validated, ordered list.
 * Unknown column names are dropped with a warning. Empty / unset input
 * returns the default column set in default order.
 */
export function resolveColumns(
  raw: string | undefined,
  // deno-lint-ignore no-explicit-any
  logger?: any,
): ColumnName[] {
  if (raw === undefined) return [...DEFAULT_COLUMNS];
  const trimmed = raw.trim();
  if (trimmed.length === 0) return [...DEFAULT_COLUMNS];

  const requested = trimmed.split(",").map((c) => c.trim()).filter((c) =>
    c.length > 0
  );
  const out: ColumnName[] = [];
  const unknown: string[] = [];
  const seen = new Set<string>();
  for (const name of requested) {
    if (!COLUMN_SET.has(name)) {
      unknown.push(name);
      continue;
    }
    if (seen.has(name)) continue;
    seen.add(name);
    out.push(name as ColumnName);
  }
  if (unknown.length > 0) {
    tryLog(
      logger,
      "warn",
      "Ignoring unknown column(s) in {env}: {unknown}",
      { env: COLUMNS_ENV, unknown: unknown.join(", ") },
    );
  }
  // If every requested column was unknown, fall back to defaults so the
  // CSV is still useful rather than header-only-with-no-columns. Warn
  // explicitly so an operator who asked for a narrow subset isn't
  // surprised by a wider one (e.g. tags column appearing when they
  // wanted only ids).
  if (out.length === 0) {
    tryLog(
      logger,
      "warn",
      "{env} resolved to zero recognized columns; falling back to the " +
        "default {count}-column set ({defaults}). Set {env} to a subset " +
        "of these names to narrow the CSV.",
      {
        env: COLUMNS_ENV,
        count: DEFAULT_COLUMNS.length,
        defaults: DEFAULT_COLUMNS.join(", "),
      },
    );
    return [...DEFAULT_COLUMNS];
  }
  return out;
}

// ---------------------------------------------------------------------------
// CSV rendering
// ---------------------------------------------------------------------------

/** RFC 4180-ish field escaping. */
export function csvField(value: string): string {
  if (/[",\r\n]/.test(value)) {
    return '"' + value.replaceAll('"', '""') + '"';
  }
  return value;
}

/**
 * JSON-encode `tags` with keys sorted alphabetically so the same set of
 * tags always serializes to the same string — required for byte-stable
 * CSV output across runs.
 */
export function stableTagJson(tags: Record<string, string>): string {
  const keys = Object.keys(tags).sort();
  const ordered: Record<string, string> = {};
  for (const k of keys) ordered[k] = tags[k];
  return JSON.stringify(ordered);
}

function roleRank(role: "writer" | "reader"): number {
  return role === "writer" ? 0 : 1;
}

function compareInstances(a: Instance, b: Instance): number {
  if (a.DBClusterIdentifier !== b.DBClusterIdentifier) {
    return a.DBClusterIdentifier < b.DBClusterIdentifier ? -1 : 1;
  }
  const rankDiff = roleRank(a.Role) - roleRank(b.Role);
  if (rankDiff !== 0) return rankDiff;
  if (a.DBInstanceIdentifier === b.DBInstanceIdentifier) return 0;
  return a.DBInstanceIdentifier < b.DBInstanceIdentifier ? -1 : 1;
}

function valueForColumn(instance: Instance, column: ColumnName): string {
  switch (column) {
    case "cluster_id":
      return instance.DBClusterIdentifier;
    case "instance_id":
      return instance.DBInstanceIdentifier;
    case "instance_class":
      return instance.DBInstanceClass;
    case "role":
      return instance.Role;
    case "az":
      return instance.AvailabilityZone ?? "";
    case "engine":
      return instance.Engine;
    case "engine_version":
      return instance.EngineVersion ?? "";
    case "promotion_tier":
      return instance.PromotionTier === undefined
        ? ""
        : String(instance.PromotionTier);
    case "parameter_group_status":
      return instance.DBClusterParameterGroupStatus ?? "";
    case "tags":
      return stableTagJson(instance.tags);
  }
}

/** Options accepted by {@link renderCsv}. */
export interface RenderCsvOptions {
  /** Column subset in any order; defaults to {@link DEFAULT_COLUMNS}. */
  columns?: ColumnName[];
}

/**
 * Render `instances` as CSV. Empty input produces a header-only output
 * (no data rows). Row order is stable: cluster_id ascending, writer
 * before reader, then instance_id ascending.
 *
 * @returns A CSV string ending in `\n` (header always present).
 */
export function renderCsv(
  instances: Instance[],
  options: RenderCsvOptions = {},
): string {
  const columns = options.columns ?? [...DEFAULT_COLUMNS];
  const header = columns.join(",");
  const sorted = [...instances].sort(compareInstances);
  const rows = sorted.map((instance) =>
    columns.map((col) => csvField(valueForColumn(instance, col))).join(",")
  );
  return [header, ...rows].join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Report export
// ---------------------------------------------------------------------------

/** Structured JSON shape returned alongside the markdown/CSV body. */
export interface ReportJson {
  /** Stable report name. */
  report: string;
  /** Name of the workflow that produced the inputs. */
  workflow: string;
  /** ISO 8601 timestamp the report was generated; empty string if the host clock is unavailable. */
  generatedAt: string;
  /** Selected columns, in the order they appear in the header. */
  columns: string[];
  /** Number of data rows (excludes the header). */
  rowCount: number;
  /**
   * Number of distinct clusters represented in the data rows. Derived from
   * `DBClusterIdentifier` across emitted instance rows.
   */
  clusterCount: number;
  /**
   * Number of distinct cluster identifiers observed in upstream `cluster`
   * artifacts. When this is greater than `clusterCount` the upstream wrote
   * a cluster artifact whose members never reached this report — typically
   * a partial-failure signal worth investigating.
   */
  clusterArtifactCount: number;
  /** Number of upstream artifacts that were skipped due to errors. */
  skipped: number;
  /** Number of duplicate (cluster_id, instance_id) artifacts deduped during collection. */
  duplicates: number;
  /** True when the outer try/catch absorbed an unexpected failure; the CSV is then header-only. */
  degraded: boolean;
  /** The CSV body (header + rows + trailing newline). */
  csv: string;
}

/**
 * The `@jentz/aws-rds-inventory-csv` workflow-scope report.
 *
 * Confirmed against the swamp report API spec at swamp 20260520.150010.0:
 * `ReportDefinition.execute` returns `{ markdown, json }`; swamp persists
 * them as `report-{name}` (text/markdown) and `report-{name}-json`
 * (application/json). There is no separate CSV channel, so the CSV body
 * lives in `markdown` and is mirrored on `json.csv` for machine pickups.
 */
export const report = {
  name: "@jentz/aws-rds-inventory-csv",
  description:
    "Emit a CSV summary of RDS DB clusters and instances collected by " +
    "@jentz/aws-rds-inventory earlier in the workflow. One row per " +
    "cluster member; columns configurable via AWS_RDS_INVENTORY_CSV_COLUMNS.",
  scope: "workflow" as const,
  labels: ["aws", "rds", "inventory", "csv"],
  // deno-lint-ignore no-explicit-any
  execute: async (context: any): Promise<{
    markdown: string;
    json: ReportJson;
  }> => {
    // Single outer try/catch is the never-throws guarantee. Every logger
    // call inside also goes through `tryLog` so a misbehaving host logger
    // cannot escape the report either.
    const workflowName = context.workflowName ?? "<unknown-workflow>";
    const logger = context.logger;
    tryLog(
      logger,
      "info",
      "Running aws-rds-inventory-csv report for workflow {workflow}",
      { workflow: workflowName },
    );

    let inventory: CollectedInventory = {
      instances: [],
      clusterArtifactIds: new Set<string>(),
      skipped: 0,
      duplicates: 0,
    };
    let columns: ColumnName[] = [...DEFAULT_COLUMNS];
    let csv = renderCsv([], { columns });
    let clusterCount = 0;
    let generatedAt = "";
    let degraded = false;

    try {
      // Compute the timestamp inside the never-throws envelope so a
      // hostile Date polyfill can't escape the report contract.
      generatedAt = new Date().toISOString();

      inventory = await collectInventory(context);
      columns = resolveColumns(readEnv(COLUMNS_ENV), logger);
      csv = renderCsv(inventory.instances, { columns });
      clusterCount = new Set(
        inventory.instances.map((i) => i.DBClusterIdentifier),
      ).size;
    } catch (err) {
      // Anything that escapes the per-artifact catches inside
      // collectInventory — a logger that throws, a malformed step
      // record, an unexpected library failure — lands here. Degrade to
      // a header-only CSV but preserve whatever partial state was
      // already recorded (skipped, duplicates, cluster ids). Operators
      // checking those counters keep a real signal of what happened
      // before the failure.
      degraded = true;
      const detail = err instanceof Error ? err.message : String(err);
      tryLog(
        logger,
        "warn",
        "aws-rds-inventory-csv: unexpected error during execute: {detail}",
        { detail },
      );
      csv = renderCsv([], { columns });
      clusterCount = 0;
    }

    if (
      inventory.clusterArtifactIds.size > clusterCount &&
      inventory.clusterArtifactIds.size > 0
    ) {
      tryLog(
        logger,
        "warn",
        "Upstream wrote {artifacts} cluster artifact id(s) but only " +
          "{rendered} cluster(s) appear in the CSV; {missing} cluster(s) " +
          "had no instance artifacts (possible partial upstream failure).",
        {
          artifacts: inventory.clusterArtifactIds.size,
          rendered: clusterCount,
          missing: inventory.clusterArtifactIds.size - clusterCount,
        },
      );
    }

    tryLog(
      logger,
      "info",
      "aws-rds-inventory-csv finished: {rows} row(s), {clusters} cluster(s)" +
        "{degradedHint}",
      {
        rows: inventory.instances.length,
        clusters: clusterCount,
        degradedHint: degraded ? " (degraded)" : "",
      },
    );

    const json: ReportJson = {
      report: "@jentz/aws-rds-inventory-csv",
      workflow: workflowName,
      generatedAt,
      columns: [...columns],
      rowCount: inventory.instances.length,
      clusterCount,
      clusterArtifactCount: inventory.clusterArtifactIds.size,
      skipped: inventory.skipped,
      duplicates: inventory.duplicates,
      degraded,
      csv,
    };

    return { markdown: csv, json };
  },
};
