/**
 * Swamp workflow-scope report: `@jentz/integration-coverage`.
 *
 * Coalesces two independent lenses produced earlier in the same workflow —
 * the **StackSet lens** (`@jentz/aws-stackset-audit` `instance` rows) and the
 * **IAM lens** (`@jentz/aws-iam-role-audit` `role` rows) — into a per-account
 * coverage matrix answering, for each account, *is it covered?* (across all of
 * the integration's required roles) and *by which way?* (this stackset / other
 * stack / manual / missing), flagging where the two lenses disagree.
 *
 * The coalesce logic lives in `./_lib/coverage.ts` and is shared with the
 * queryable model `@jentz/aws-integration-coverage` (same package), so the
 * report and the model always agree. This file only adds the report's own data
 * acquisition (walking `stepExecutions`) and markdown rendering. Never throws.
 *
 * @module
 */

import {
  type AccountMechanism,
  coalesce,
  type CoalesceResult,
  type Collected,
  type Coverage,
  type CoverageRow,
  IAM_ERROR_SPEC,
  IAM_MODEL_TYPE,
  IAM_ROLE_SPEC,
  type IamError,
  IamErrorSchema,
  type Instance,
  InstanceSchema,
  type Mechanism,
  type Role,
  type RoleDetail,
  type RoleRollup,
  RoleSchema,
  STACKSET_INSTANCE_SPEC,
  STACKSET_MODEL_TYPE,
  STACKSET_SUMMARY_SPEC,
  summarizeCoverage,
  type Summary,
  SummarySchema,
  type UnresolvedProfile,
} from "./_lib/coverage.ts";

// Re-export the shared-core types this report surfaces in its public API
// (directly or transitively), so consumers and `deno doc --lint` see them as
// part of this entry point's documented surface rather than as references to a
// "private" imported type. The combined model+report ships one shared core, so
// surfacing its public contract here keeps the report self-describing.
export type {
  AccountMechanism,
  CoalesceResult,
  Collected,
  Coverage,
  CoverageRow,
  IamError,
  Instance,
  Mechanism,
  Role,
  RoleDetail,
  RoleRollup,
  Summary,
  UnresolvedProfile,
};

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
  } catch { /* logging is observability, not correctness */ }
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
// Collection (report-specific: from workflow stepExecutions)
// ---------------------------------------------------------------------------

/**
 * Walk `context.stepExecutions` and decode the StackSet `instance`/`summary`
 * and IAM `role`/`scan_error` artifacts from the two upstream lenses. Malformed
 * or schema-mismatched artifacts are counted and skipped, never thrown.
 *
 * @param context The workflow report context supplied by the swamp runtime.
 * @returns Decoded instances, summaries, roles, errors, and a skipped count.
 */
export async function collect(
  // deno-lint-ignore no-explicit-any
  context: any,
): Promise<Collected> {
  const logger = context.logger;
  const instances: Collected["instances"] = [];
  const summaries: Collected["summaries"] = [];
  const roles: Collected["roles"] = [];
  const iamErrors: Collected["iamErrors"] = [];
  let skipped = 0;

  for (const step of context.stepExecutions ?? []) {
    const isStackset = step.modelType === STACKSET_MODEL_TYPE;
    const isIam = step.modelType === IAM_MODEL_TYPE;
    if (!isStackset && !isIam) continue;

    for (const handle of step.dataHandles ?? []) {
      const specName: string | undefined = handle.metadata?.tags?.specName ??
        handle.specName;
      if (specName === undefined) continue;

      const bytes: Uint8Array | null = await context.dataRepository.getContent(
        step.modelType,
        step.modelId,
        handle.name,
        handle.version,
      );
      const value = decodeJson(bytes);
      if (value === undefined) {
        skipped++;
        continue;
      }

      if (isStackset && specName === STACKSET_INSTANCE_SPEC) {
        const r = InstanceSchema.safeParse(value);
        r.success ? instances.push(r.data) : skipped++;
      } else if (isStackset && specName === STACKSET_SUMMARY_SPEC) {
        const r = SummarySchema.safeParse(value);
        r.success ? summaries.push(r.data) : skipped++;
      } else if (isIam && specName === IAM_ROLE_SPEC) {
        const r = RoleSchema.safeParse(value);
        r.success ? roles.push(r.data) : skipped++;
      } else if (isIam && specName === IAM_ERROR_SPEC) {
        const r = IamErrorSchema.safeParse(value);
        r.success ? iamErrors.push(r.data) : skipped++;
      }
    }
  }

  tryLog(
    logger,
    "info",
    "Collected {inst} instance(s), {roles} role row(s), {errs} IAM error(s); {sk} skipped",
    {
      inst: instances.length,
      roles: roles.length,
      errs: iamErrors.length,
      sk: skipped,
    },
  );
  return { instances, summaries, roles, iamErrors, skipped };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/**
 * Render the operator markdown for the coalesced coverage matrix.
 *
 * @param res The coalesce result.
 * @param collected The raw collected rows (for the skipped footnote).
 * @param generatedAt ISO timestamp for the header.
 * @param workflowName Originating workflow name.
 * @returns The full markdown document.
 */
export function renderMarkdown(
  res: CoalesceResult,
  collected: Collected,
  generatedAt: string,
  workflowName: string,
): string {
  const { rows } = res;
  const { byCoverage, byMechanism, byRole, discrepancies } = summarizeCoverage(
    rows,
  );

  const lines: string[] = [];
  const roleLabel = res.roleNames.length ? res.roleNames.join(", ") : "role";
  lines.push(`# Integration coverage — \`${roleLabel}\``);
  lines.push("");
  lines.push(
    `_Generated ${generatedAt} · workflow \`${workflowName}\` · stackset ` +
      `\`${res.stackSetName || "?"}\`_`,
  );
  lines.push("");
  lines.push("## Coverage (per account, over required roles)");
  lines.push("");
  lines.push(`- Accounts coalesced: **${rows.length}**`);
  lines.push(
    `- covered-compliant: **${byCoverage["covered-compliant"] ?? 0}**, ` +
      `covered-partial: **${byCoverage["covered-partial"] ?? 0}**, ` +
      `covered-noncompliant: **${byCoverage["covered-noncompliant"] ?? 0}**, ` +
      `uncovered: **${byCoverage["uncovered"] ?? 0}**, ` +
      `unknown: **${byCoverage["unknown"] ?? 0}**`,
  );
  lines.push("");

  lines.push("### Per role (across accounts in the IAM sweep)");
  lines.push("");
  lines.push("| Role | Required | Present | Compliant | Missing |");
  lines.push("|---|---|---|---|---|");
  for (const r of byRole) {
    lines.push(
      `| ${r.roleName} | ${r.required ? "yes" : "no"} | ${r.present} | ` +
        `${r.compliant} | ${r.missing} |`,
    );
  }
  lines.push("");

  lines.push("### Account coverage, by mechanism");
  lines.push("");
  lines.push("| Mechanism | Accounts |");
  lines.push("|---|---|");
  for (const [k, v] of Object.entries(byMechanism).sort()) {
    lines.push(`| ${k} | ${v} |`);
  }
  lines.push("");

  if (discrepancies.length > 0) {
    lines.push("## ⚠️ Lens disagreements");
    lines.push("");
    for (const r of discrepancies) {
      lines.push(
        `- \`${r.accountName}\` (${r.accountId}) — ${r.reconciliation}`,
      );
    }
    lines.push("");
  }

  lines.push("## Per-account matrix");
  lines.push("");
  const cols = [
    "account",
    "id",
    "coverage",
    "req",
    "mechanism",
    "stackset",
    "missing roles",
    "reconciliation",
  ];
  lines.push(`| ${cols.join(" | ")} |`);
  lines.push(`| ${cols.map(() => "---").join(" | ")} |`);
  for (const r of rows) {
    const cells = [
      r.accountName,
      r.accountId,
      r.coverage,
      `${r.requiredCompliant}/${r.requiredTotal}`,
      r.mechanism,
      r.stacksetStatus,
      r.missingRequiredRoles.join(", "),
      r.reconciliation,
    ].map((c) => String(c).replaceAll("|", "\\|"));
    lines.push(`| ${cells.join(" | ")} |`);
  }
  lines.push("");

  if (res.unresolvedProfiles.length > 0) {
    lines.push("## 🔑 Profiles that could not be assessed");
    lines.push("");
    for (
      const p of res.unresolvedProfiles.sort((a, b) =>
        a.profile < b.profile ? -1 : 1
      )
    ) {
      lines.push(`- \`${p.profile}\` — ${p.kind} (run \`aws sso login\`)`);
    }
    lines.push("");
  }

  if (collected.skipped > 0) {
    lines.push(`_Note: ${collected.skipped} upstream artifact(s) skipped._`);
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
  /** ISO timestamp; "" if the host clock was unavailable. */
  generatedAt: string;
  /** Target stackset name. */
  stackSetName: string;
  /** Role names observed. */
  roleNames: string[];
  /** Per-account coverage rows. */
  accounts: CoverageRow[];
  /** Counts by aggregate coverage verdict. */
  byCoverage: Record<string, number>;
  /** Counts by aggregate mechanism. */
  byMechanism: Record<string, number>;
  /** Per-role rollup across accounts. */
  byRole: RoleRollup[];
  /** Accounts where the two lenses disagree. */
  discrepancies: CoverageRow[];
  /** Profiles that failed before an account id was known. */
  unresolvedProfiles: UnresolvedProfile[];
  /** Upstream artifacts skipped during collection. */
  skipped: number;
  /** True when the outer guard absorbed an unexpected failure. */
  degraded: boolean;
}

/**
 * The `@jentz/integration-coverage` workflow-scope report. Returns
 * `{ markdown, json }`; swamp persists them as `report-{name}` and
 * `report-{name}-json`.
 */
export const report = {
  name: "@jentz/integration-coverage",
  description:
    "Coalesces the StackSet lens (@jentz/aws-stackset-audit) and the IAM lens " +
    "(@jentz/aws-iam-role-audit) collected earlier in the workflow into a " +
    "per-account coverage matrix across all of the integration's required " +
    "roles: covered? by which mechanism (this stackset / other stack / manual " +
    "/ missing)?",
  scope: "workflow" as const,
  labels: ["aws", "iam", "coverage", "audit", "cloudformation"],
  // deno-lint-ignore no-explicit-any
  execute: async (context: any): Promise<{
    markdown: string;
    json: ReportJson;
  }> => {
    const workflowName = context.workflowName ?? "<unknown-workflow>";
    const logger = context.logger;
    tryLog(logger, "info", "Running integration-coverage for {workflow}", {
      workflow: workflowName,
    });

    let collected: Collected = {
      instances: [],
      summaries: [],
      roles: [],
      iamErrors: [],
      skipped: 0,
    };
    let res: CoalesceResult = {
      rows: [],
      stackSetName: "",
      roleNames: [],
      unresolvedProfiles: [],
    };
    let generatedAt = "";
    let degraded = false;
    let markdown = "";

    try {
      generatedAt = new Date().toISOString();
      collected = await collect(context);
      res = coalesce(collected);
      markdown = renderMarkdown(res, collected, generatedAt, workflowName);
    } catch (err) {
      degraded = true;
      const detail = err instanceof Error ? err.message : String(err);
      tryLog(logger, "warn", "report degraded: {detail}", { detail });
      markdown = `# Integration coverage\n\n_Report degraded: ${detail}_\n`;
    }

    const { byCoverage, byMechanism, byRole, discrepancies } =
      summarizeCoverage(
        res.rows,
      );

    const json: ReportJson = {
      report: "@jentz/integration-coverage",
      workflow: workflowName,
      generatedAt,
      stackSetName: res.stackSetName,
      roleNames: res.roleNames,
      accounts: res.rows,
      byCoverage,
      byMechanism,
      byRole,
      discrepancies,
      unresolvedProfiles: res.unresolvedProfiles,
      skipped: collected.skipped,
      degraded,
    };

    tryLog(logger, "info", "integration-coverage finished: {n} account(s){d}", {
      n: res.rows.length,
      d: degraded ? " (degraded)" : "",
    });
    return { markdown, json };
  },
};
