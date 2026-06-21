/**
 * Swamp workflow-scope report: `@jentz/aws-rds-inventory-report`.
 *
 * Consumes the `cluster` and `instance` resources produced earlier in the
 * workflow by `@jentz/aws-rds-inventory` and emits an operator inventory of
 * every RDS cluster and member instance observed. Pure data shaping — no AWS
 * API access.
 *
 * The markdown body is a human-readable summary (cluster count, instance
 * count, engines, writer/reader split, multi-AZ count, and a skipped-artifact
 * count that flags an incomplete run) followed by the full inventory table;
 * the `json` payload carries structured `clusters[]` +
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

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Model type whose outputs this report consumes. */
export const INVENTORY_MODEL_TYPE = "@jentz/aws-rds-inventory";

/** Cluster spec name on the upstream inventory model. */
export const CLUSTER_SPEC = "cluster";
/** Instance spec name on the upstream inventory model. */
export const INSTANCE_SPEC = "instance";

// ---------------------------------------------------------------------------
// Schemas — hand-mirror of the producer's public shapes. If upstream tightens
// a field, artifacts fail safeParse here and are skipped with a logged warning.
// Mirrors @jentz/aws-rds-inventory's ClusterSchema / InstanceSchema.
// ---------------------------------------------------------------------------

const TagsSchema = z.record(z.string(), z.string()).default({});

const ClusterRecordSchema = z.object({
  DBClusterIdentifier: z.string(),
  Engine: z.string(),
  EngineVersion: z.string().optional(),
  Status: z.string().optional(),
  Endpoint: z.string().optional(),
  ReaderEndpoint: z.string().optional(),
  MultiAZ: z.boolean().optional(),
  tags: TagsSchema,
});

const InstanceRecordSchema = z.object({
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

// Explicit interfaces (not `z.infer` aliases) so the public API surface stays
// free of private zod internals — `deno doc --lint` rejects exported types that
// reference the schema's inferred output type. The schemas above remain the
// runtime decode/validation source of truth; these mirror their shapes,
// field-for-field with the model's ClusterResource / InstanceResource.

/** A decoded cluster row, mirroring the upstream model's `cluster` resource. */
export interface ClusterRecord {
  /** AWS cluster identifier; also the resource instance name. */
  DBClusterIdentifier: string;
  /** AWS engine string (`aurora-mysql`, `mysql`, ...). */
  Engine: string;
  /** Engine version, if returned. */
  EngineVersion?: string;
  /** Cluster lifecycle status (`available`, `creating`, ...). */
  Status?: string;
  /** Writer endpoint, if returned. */
  Endpoint?: string;
  /** Reader endpoint, if returned. */
  ReaderEndpoint?: string;
  /** Whether the cluster is multi-AZ. */
  MultiAZ?: boolean;
  /** Cluster tags, flattened from AWS's `[{Key,Value},...]` array. */
  tags: Record<string, string>;
}

/**
 * A decoded instance row, mirroring the upstream model's `instance` resource.
 * Back-references its cluster via `DBClusterIdentifier`.
 */
export interface InstanceRecord {
  /** AWS instance identifier; also the resource instance name. */
  DBInstanceIdentifier: string;
  /** Back-reference to the owning cluster. */
  DBClusterIdentifier: string;
  /** AWS instance class (e.g. `db.r7g.large`). */
  DBInstanceClass: string;
  /** Whether this member is the cluster writer or a reader. */
  Role: "writer" | "reader";
  /** Availability zone of the instance, if returned. */
  AvailabilityZone?: string;
  /** Engine string (falls back to the cluster's engine if absent on instance). */
  Engine: string;
  /** Engine version, if returned. */
  EngineVersion?: string;
  /** Instance lifecycle status (`available`, ...). */
  Status?: string;
  /** Failover priority, 0 (highest) – 15 (lowest); undefined when AWS omits it. */
  PromotionTier?: number;
  /** Whether the cluster's parameter group has been applied to this member. */
  DBClusterParameterGroupStatus?: string;
  /** Per-instance tags, flattened from AWS's `[{Key,Value},...]` array. */
  tags: Record<string, string>;
}

/** Everything collected from upstream inventory steps. */
export interface Collected {
  /** Decoded cluster rows. */
  clusters: ClusterRecord[];
  /** Decoded instance rows. */
  instances: InstanceRecord[];
  /** Artifacts that failed to decode or validate. */
  skipped: number;
}

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

function decodeJson(bytes: Uint8Array | null): unknown | undefined {
  if (!bytes || bytes.length === 0) return undefined;
  try {
    return JSON.parse(TEXT_DECODER.decode(bytes));
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

/**
 * Walk `context.stepExecutions`, find steps whose `modelType` is
 * {@link INVENTORY_MODEL_TYPE}, and decode their `cluster` and `instance`
 * artifacts. Malformed or schema-mismatched artifacts are counted and skipped,
 * never thrown.
 *
 * @param context The report execution context supplied by the swamp runtime.
 * @returns The decoded cluster rows, instance rows, and a skipped count.
 */
export async function collect(
  // deno-lint-ignore no-explicit-any
  context: any,
): Promise<Collected> {
  const logger = context.logger;
  const clusters: ClusterRecord[] = [];
  const instances: InstanceRecord[] = [];
  let skipped = 0;
  let matchingSteps = 0;
  const observed = new Set<string>();

  for (const step of context.stepExecutions ?? []) {
    if (typeof step?.modelType === "string") observed.add(step.modelType);
    if (step.modelType !== INVENTORY_MODEL_TYPE) continue;
    matchingSteps++;

    for (const handle of step.dataHandles ?? []) {
      const specName: string | undefined = handle.metadata?.tags?.specName ??
        handle.specName;
      if (specName !== CLUSTER_SPEC && specName !== INSTANCE_SPEC) continue;

      let bytes: Uint8Array | null;
      try {
        bytes = await context.dataRepository.getContent(
          step.modelType,
          step.modelId,
          handle.name,
          handle.version,
        );
      } catch {
        // A storage read failure for one handle is a per-handle skip, not a
        // whole-report failure — count it and move on.
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
        tryLog(logger, "warn", "Could not decode {spec} artifact {handle}", {
          spec: specName,
          handle: handle.name,
        });
        continue;
      }

      if (specName === CLUSTER_SPEC) {
        const res = ClusterRecordSchema.safeParse(value);
        if (!res.success) {
          skipped++;
          tryLog(
            logger,
            "warn",
            "Cluster row {handle} failed schema on: {fields}",
            {
              handle: handle.name,
              fields: res.error.issues.map((i) => i.path.join(".") || "<root>")
                .join(", "),
            },
          );
          continue;
        }
        clusters.push(res.data);
      } else {
        const res = InstanceRecordSchema.safeParse(value);
        if (!res.success) {
          skipped++;
          tryLog(
            logger,
            "warn",
            "Instance row {handle} failed schema on: {fields}",
            {
              handle: handle.name,
              fields: res.error.issues.map((i) => i.path.join(".") || "<root>")
                .join(", "),
            },
          );
          continue;
        }
        instances.push(res.data);
      }
    }
  }

  const hadSteps = (context.stepExecutions ?? []).length > 0;
  if (hadSteps && matchingSteps === 0) {
    tryLog(
      logger,
      "warn",
      "No step matched modelType={expected}; observed: {observed}",
      {
        expected: INVENTORY_MODEL_TYPE,
        observed: [...observed].sort().join(", ") || "<none>",
      },
    );
  }

  tryLog(
    logger,
    "info",
    "Collected {clusters} cluster(s), {instances} instance(s) from " +
      "{steps} step(s); {skipped} skipped",
    {
      clusters: clusters.length,
      instances: instances.length,
      steps: matchingSteps,
      skipped,
    },
  );

  return { clusters, instances, skipped };
}

// ---------------------------------------------------------------------------
// Sort comparators
// ---------------------------------------------------------------------------

/** Stable order: by cluster identifier. */
export function compareClusters(a: ClusterRecord, b: ClusterRecord): number {
  return a.DBClusterIdentifier < b.DBClusterIdentifier
    ? -1
    : a.DBClusterIdentifier > b.DBClusterIdentifier
    ? 1
    : 0;
}

/**
 * Stable order: by cluster identifier, then writer before reader, then
 * instance identifier.
 */
export function compareInstances(a: InstanceRecord, b: InstanceRecord): number {
  if (a.DBClusterIdentifier !== b.DBClusterIdentifier) {
    return a.DBClusterIdentifier < b.DBClusterIdentifier ? -1 : 1;
  }
  if (a.Role !== b.Role) return a.Role === "writer" ? -1 : 1;
  return a.DBInstanceIdentifier < b.DBInstanceIdentifier
    ? -1
    : a.DBInstanceIdentifier > b.DBInstanceIdentifier
    ? 1
    : 0;
}

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

function mdEscape(value: string): string {
  return value.replaceAll("|", "\\|");
}

function mdTable(instances: InstanceRecord[]): string {
  if (instances.length === 0) return "_None._\n";
  const cols = [
    "cluster",
    "instance",
    "role",
    "class",
    "engine",
    "version",
    "AZ",
    "status",
  ];
  const header = `| ${cols.join(" | ")} |`;
  const sep = `| ${cols.map(() => "---").join(" | ")} |`;
  const rows = [...instances].sort(compareInstances).map((i) => {
    const cells = [
      i.DBClusterIdentifier,
      i.DBInstanceIdentifier,
      i.Role,
      i.DBInstanceClass,
      i.Engine,
      i.EngineVersion ?? "",
      i.AvailabilityZone ?? "",
      i.Status ?? "",
    ].map((c) => mdEscape(c));
    return `| ${cells.join(" | ")} |`;
  });
  return [header, sep, ...rows].join("\n") + "\n";
}

/**
 * Render the operator markdown report from collected cluster and instance
 * rows.
 *
 * @param collected Cluster and instance rows from {@link collect}.
 * @param generatedAt ISO timestamp for the report header.
 * @param workflowName Originating workflow name, for the header.
 * @returns The full markdown document.
 */
export function renderMarkdown(
  collected: Collected,
  generatedAt: string,
  workflowName: string,
): string {
  const { clusters, instances, skipped } = collected;

  const engines = new Set(clusters.map((c) => c.Engine));
  const writers = instances.filter((i) => i.Role === "writer");
  const readers = instances.filter((i) => i.Role === "reader");
  const multiAz = clusters.filter((c) => c.MultiAZ);

  const lines: string[] = [];
  lines.push("# AWS RDS Inventory");
  lines.push("");
  lines.push(`_Generated ${generatedAt} · workflow \`${workflowName}\`_`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Clusters inventoried: **${clusters.length}**`);
  lines.push(`- Instances inventoried: **${instances.length}**`);
  lines.push(
    `  - writers: **${writers.length}**, readers: **${readers.length}**`,
  );
  lines.push(
    `- Engines: ${
      engines.size ? [...engines].sort().map((e) => `\`${e}\``).join(", ") : "—"
    }`,
  );
  lines.push(`- Multi-AZ clusters: **${multiAz.length}**`);
  lines.push(
    skipped > 0
      ? `- ⚠️ Skipped artifacts: **${skipped}** (unreadable, malformed, or ` +
        "schema-drifted rows omitted from this report; see run logs)"
      : `- Skipped artifacts: **0**`,
  );
  lines.push("");
  lines.push("## Inventory");
  lines.push("");
  lines.push(mdTable(instances));

  return lines.join("\n") + "\n";
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
  /**
   * Structured cluster rows, one object per cluster, mirroring the model's
   * cluster row fields, in stable {@link compareClusters} sort order.
   */
  clusters: ClusterRecord[];
  /**
   * Structured instance rows, one object per instance, mirroring the model's
   * instance row fields, in stable {@link compareInstances} sort order as the
   * markdown table.
   */
  instances: InstanceRecord[];
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

    let collected: Collected = { clusters: [], instances: [], skipped: 0 };
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
      markdown = `# AWS RDS Inventory\n\n_Report degraded: ${detail}_\n`;
    }

    const sortedClusters = [...collected.clusters].sort(compareClusters);
    const sortedInstances = [...collected.instances].sort(compareInstances);

    const json: ReportJson = {
      report: "@jentz/aws-rds-inventory-report",
      workflow: workflowName,
      generatedAt,
      clusters: sortedClusters,
      instances: sortedInstances,
      clusterCount: sortedClusters.length,
      instanceCount: sortedInstances.length,
      skipped: collected.skipped,
      degraded,
    };

    tryLog(
      logger,
      "info",
      "report finished: {clusters} cluster(s), {instances} instance(s)" +
        "{degraded}",
      {
        clusters: collected.clusters.length,
        instances: collected.instances.length,
        degraded: degraded ? " (degraded)" : "",
      },
    );

    return { markdown, json };
  },
};
