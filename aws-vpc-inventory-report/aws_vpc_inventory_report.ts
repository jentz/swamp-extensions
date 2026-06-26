/**
 * Swamp workflow-scope report: `@jentz/aws-vpc-inventory-report`.
 *
 * Consumes the `vpc` and `scan_error` resources produced earlier in the
 * workflow by `@jentz/aws-vpc-inventory` and emits an operator inventory
 * of every VPC observed across the swept profiles × regions. Pure data
 * shaping — no AWS API access.
 *
 * The markdown body is a human-readable summary (accounts seen, VPC
 * count, default-VPC count, shared-in count) followed by the full
 * inventory table and a coverage-gaps section; the `json` payload carries
 * a structured `vpcs[]` rows array (one object per VPC, mirroring the
 * model's VPC row fields, in the same stable sort order as the table) plus
 * the summary counts, a per-kind error breakdown, the skipped-artifact
 * count, and a `degraded` flag.
 *
 * The report never throws — a missing upstream step, malformed artifact,
 * or schema drift degrades to a logged warning and a still-useful
 * (possibly empty) report.
 *
 * @module
 */

import { z } from "npm:zod@4.4.3";
import {
  errorBucket,
  type ScanError,
  ScanErrorSchema,
} from "./_lib/scan_error.ts";

export type { ScanError };

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Model type whose outputs this report consumes. */
export const INVENTORY_MODEL_TYPE = "@jentz/aws-vpc-inventory";

/** VPC spec name on the upstream inventory model. */
export const VPC_SPEC = "vpc";
/** Scan-error spec name on the upstream inventory model. */
export const SCAN_ERROR_SPEC = "scan_error";

// ---------------------------------------------------------------------------
// Schemas — hand-mirror of the producer's public shapes. If upstream tightens
// a field, artifacts fail safeParse here and are skipped with a logged warning.
// ---------------------------------------------------------------------------

const TagsSchema = z.record(z.string(), z.string()).default({});

const VpcRecordSchema = z.object({
  accountId: z.string(),
  accountName: z.string(),
  profile: z.string(),
  region: z.string(),
  vpcId: z.string(),
  vpcName: z.string(),
  vpcIsDefault: z.boolean(),
  ownerAccountId: z.string(),
  isSharedIn: z.boolean(),
  cidrBlocks: z.array(z.string()),
  vpcTags: TagsSchema,
  scannedAt: z.iso.datetime(),
});

// Explicit interfaces (not `z.infer` aliases) so the public API surface stays
// free of private zod internals — `deno doc --lint` rejects exported types that
// reference the schema's inferred output type. The `VpcRecordSchema` above
// remains the runtime decode/validation source of truth; this mirrors its
// shape. The scan-error shape (schema + `ScanError` interface) is imported from
// the shared `./_lib/scan_error.ts` twin, so a `network` row and the `service`
// tag decode rather than being dropped as malformed.

/** A decoded VPC row, mirroring the upstream model's `vpc` resource. */
export interface VpcRecord {
  /** 12-digit AWS account id of the scanning credentials. */
  accountId: string;
  /** Friendly account label derived from the profile. */
  accountName: string;
  /** Profile that produced this row; `""` for the ambient credential chain. */
  profile: string;
  /** AWS region. */
  region: string;
  /** VPC id. */
  vpcId: string;
  /** VPC `Name` tag, or `""`. */
  vpcName: string;
  /** Whether this is the AWS-created default VPC. */
  vpcIsDefault: boolean;
  /** Account that owns the VPC; differs from `accountId` for RAM-shared VPCs. */
  ownerAccountId: string;
  /** True when the VPC is shared into this account (ownerAccountId !== accountId). */
  isSharedIn: boolean;
  /** All IPv4 CIDR blocks, primary first then associated secondaries. */
  cidrBlocks: string[];
  /** All VPC tags, flattened. */
  vpcTags: Record<string, string>;
  /** ISO 8601 scan timestamp. */
  scannedAt: string;
}

/** Everything collected from upstream inventory steps. */
export interface Collected {
  /** Decoded VPC rows. */
  vpcs: VpcRecord[];
  /** Decoded scan errors. */
  errors: ScanError[];
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
 * {@link INVENTORY_MODEL_TYPE}, and decode their `vpc` and `scan_error`
 * artifacts. Malformed or schema-mismatched artifacts are counted and
 * skipped, never thrown.
 *
 * @param context The report execution context supplied by the swamp runtime.
 * @returns The decoded VPC rows, errors, and a skipped count.
 */
export async function collect(
  // deno-lint-ignore no-explicit-any
  context: any,
): Promise<Collected> {
  const logger = context.logger;
  const vpcs: VpcRecord[] = [];
  const errors: ScanError[] = [];
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
      if (specName !== VPC_SPEC && specName !== SCAN_ERROR_SPEC) continue;

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

      if (specName === VPC_SPEC) {
        const res = VpcRecordSchema.safeParse(value);
        if (!res.success) {
          skipped++;
          tryLog(
            logger,
            "warn",
            "VPC row {handle} failed schema on: {fields}",
            {
              handle: handle.name,
              fields: res.error.issues.map((i) => i.path.join(".") || "<root>")
                .join(", "),
            },
          );
          continue;
        }
        vpcs.push(res.data);
      } else {
        const res = ScanErrorSchema.safeParse(value);
        if (!res.success) {
          skipped++;
          continue;
        }
        errors.push(res.data);
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
    "Collected {vpcs} VPC(s), {errors} error(s) from {steps} step(s); " +
      "{skipped} skipped",
    {
      vpcs: vpcs.length,
      errors: errors.length,
      steps: matchingSteps,
      skipped,
    },
  );

  return { vpcs, errors, skipped };
}

// ---------------------------------------------------------------------------
// Row derivation + sort
// ---------------------------------------------------------------------------

/** Stable order: by account id, then region, then VPC id. */
export function compareVpcs(a: VpcRecord, b: VpcRecord): number {
  if (a.accountId !== b.accountId) return a.accountId < b.accountId ? -1 : 1;
  if (a.region !== b.region) return a.region < b.region ? -1 : 1;
  return a.vpcId < b.vpcId ? -1 : a.vpcId > b.vpcId ? 1 : 0;
}

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

function mdEscape(value: string): string {
  return value.replaceAll("|", "\\|");
}

function mdTable(vpcs: VpcRecord[]): string {
  if (vpcs.length === 0) return "_None._\n";
  const cols = [
    "account",
    "name",
    "region",
    "vpc",
    "vpc id",
    "default",
    "shared",
    "CIDRs",
  ];
  const header = `| ${cols.join(" | ")} |`;
  const sep = `| ${cols.map(() => "---").join(" | ")} |`;
  const rows = [...vpcs].sort(compareVpcs).map((v) => {
    const cells = [
      v.accountId,
      v.accountName,
      v.region,
      v.vpcName,
      v.vpcId,
      v.vpcIsDefault ? "yes" : "",
      v.isSharedIn ? `from ${v.ownerAccountId}` : "",
      v.cidrBlocks.join(", "),
    ].map((c) => mdEscape(c));
    return `| ${cells.join(" | ")} |`;
  });
  return [header, sep, ...rows].join("\n") + "\n";
}

/**
 * Render the operator markdown report from collected VPC rows and errors.
 *
 * @param collected VPC rows and errors from {@link collect}.
 * @param generatedAt ISO timestamp for the report header.
 * @param workflowName Originating workflow name, for the header.
 * @returns The full markdown document.
 */
export function renderMarkdown(
  collected: Collected,
  generatedAt: string,
  workflowName: string,
): string {
  const { vpcs, errors } = collected;

  const networkErrors = errors.filter((e) => e.kind === "network");
  const authExpired = errors.filter((e) => e.kind === "auth_expired");
  const accessDenied = errors.filter((e) => e.kind === "access_denied");
  const otherErrors = errors.filter((e) => e.kind === "other");

  const accounts = new Set(vpcs.map((v) => v.accountId));
  for (const e of errors) if (e.accountId) accounts.add(e.accountId);
  const regions = new Set(vpcs.map((v) => v.region));
  const defaultVpcs = vpcs.filter((v) => v.vpcIsDefault);
  const shared = vpcs.filter((v) => v.isSharedIn);

  const lines: string[] = [];
  lines.push("# AWS VPC Inventory");
  lines.push("");
  lines.push(`_Generated ${generatedAt} · workflow \`${workflowName}\`_`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Accounts seen: **${accounts.size}**`);
  lines.push(`- Regions covered: **${regions.size}**`);
  lines.push(`- VPCs inventoried: **${vpcs.length}**`);
  lines.push(
    `  - default VPCs: **${defaultVpcs.length}**, ` +
      `shared-in via RAM: **${shared.length}**`,
  );
  lines.push(
    `- Coverage gaps: **${authExpired.length}** region(s) need ` +
      "`aws sso login` (expired token), " +
      `**${accessDenied.length}** region(s) blocked by SCP/IAM` +
      (networkErrors.length
        ? `, **${networkErrors.length}** transient network error(s)`
        : "") +
      (otherErrors.length ? `, **${otherErrors.length}** other error(s)` : ""),
  );
  lines.push("");
  lines.push("## Inventory");
  lines.push("");
  lines.push(mdTable(vpcs));

  if (authExpired.length > 0) {
    lines.push("## 🔑 Needs `aws sso login` (could not assess)");
    lines.push("");
    const byProfile = new Map<string, number>();
    for (const e of authExpired) {
      const k = e.profile || "<ambient>";
      byProfile.set(k, (byProfile.get(k) ?? 0) + 1);
    }
    for (const [p, n] of [...byProfile.entries()].sort()) {
      lines.push(`- \`${p}\` — ${n} region(s) unassessed`);
    }
    lines.push("");
  }

  if (accessDenied.length > 0) {
    const blockedRegions = [
      ...new Set(accessDenied.map((e) => e.region).filter(Boolean)),
    ].sort();
    lines.push("## 🚫 Blocked by SCP/IAM (expected for out-of-scope regions)");
    lines.push("");
    lines.push(
      `${accessDenied.length} region-scans were denied — typically a ` +
        "region your org's SCP does not permit. Regions: " +
        (blockedRegions.length
          ? blockedRegions.map((r) => `\`${r}\``).join(", ")
          : "—"),
    );
    lines.push("");
  }

  if (networkErrors.length > 0) {
    lines.push(
      `## 🌐 Transient network errors (\`${errorBucket("network")}\`)`,
    );
    lines.push("");
    lines.push(
      `${networkErrors.length} scan(s) hit a transient DNS/socket failure and ` +
        "could not be assessed — re-run the sweep to clear them. Affected " +
        "service/region pairs:",
    );
    lines.push("");
    const seen = new Set<string>();
    for (const e of networkErrors) {
      const svc = e.service || "<unknown>";
      const reg = e.region || "<account>";
      const key = `${svc}/${reg}`;
      if (seen.has(key)) continue;
      seen.add(key);
      lines.push(`- \`${svc}\` in \`${reg}\``);
    }
    lines.push("");
  }

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
   * Structured VPC rows, one object per VPC, mirroring the model's VPC row
   * fields, in the same stable {@link compareVpcs} sort order as the table.
   */
  vpcs: VpcRecord[];
  /** Number of VPC rows. */
  vpcCount: number;
  /** Number of accounts represented in the rows. */
  accountCount: number;
  /** Number of regions represented in the rows. */
  regionCount: number;
  /** Number of default VPCs. */
  defaultVpcCount: number;
  /** Number of VPCs shared-in via RAM. */
  sharedVpcCount: number;
  /** Count of scan errors by kind. */
  errorsByKind: Record<string, number>;
  /** Artifacts skipped during collection. */
  skipped: number;
  /** True when the outer guard absorbed an unexpected failure. */
  degraded: boolean;
}

/**
 * The `@jentz/aws-vpc-inventory-report` workflow-scope report. Returns
 * `{ markdown, json }`; swamp persists them as `report-{name}`
 * (text/markdown) and `report-{name}-json` (application/json).
 */
export const report = {
  name: "@jentz/aws-vpc-inventory-report",
  description: "Operator inventory of VPCs (account, name, region, VPC id, " +
    "CIDRs) built from @jentz/aws-vpc-inventory rows collected earlier " +
    "in the workflow. Emits a markdown table and a structured JSON payload " +
    "with one row per VPC plus coverage-gap counts.",
  scope: "workflow" as const,
  labels: ["aws", "vpc", "inventory", "report"],
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
      "Running aws-vpc-inventory-report for {workflow}",
      { workflow: workflowName },
    );

    let collected: Collected = { vpcs: [], errors: [], skipped: 0 };
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
      markdown = `# AWS VPC Inventory\n\n_Report degraded: ${detail}_\n`;
    }

    const errorsByKind: Record<string, number> = {
      network: 0,
      auth_expired: 0,
      access_denied: 0,
      other: 0,
    };
    for (const e of collected.errors) errorsByKind[e.kind]++;

    const sortedVpcs = [...collected.vpcs].sort(compareVpcs);
    const accounts = new Set(sortedVpcs.map((v) => v.accountId));
    const regions = new Set(sortedVpcs.map((v) => v.region));
    const defaultCount = sortedVpcs.filter((v) => v.vpcIsDefault).length;
    const sharedCount = sortedVpcs.filter((v) => v.isSharedIn).length;

    const json: ReportJson = {
      report: "@jentz/aws-vpc-inventory-report",
      workflow: workflowName,
      generatedAt,
      vpcs: sortedVpcs,
      vpcCount: sortedVpcs.length,
      accountCount: accounts.size,
      regionCount: regions.size,
      defaultVpcCount: defaultCount,
      sharedVpcCount: sharedCount,
      errorsByKind,
      skipped: collected.skipped,
      degraded,
    };

    tryLog(logger, "info", "report finished: {rows} VPC(s){degraded}", {
      rows: sortedVpcs.length,
      degraded: degraded ? " (degraded)" : "",
    });

    return { markdown, json };
  },
};
