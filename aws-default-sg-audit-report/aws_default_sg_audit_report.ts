/**
 * Swamp workflow-scope report: `@jentz/aws-default-sg-audit-report`.
 *
 * Consumes the `finding` and `scan_error` resources produced earlier in the
 * workflow by `@jentz/aws-default-sg-audit` and emits an operator worklist for
 * AWS Security Hub control EC2.2 ("VPC default security groups should not allow
 * inbound or outbound traffic"). Pure data shaping — no AWS API access.
 *
 * The markdown body is a human-readable report: a summary, then two action
 * tables (default SGs that are **safe to strip now** vs. those **in use** that
 * need a workload migrated first), then a coverage-gaps section (profiles whose
 * SSO token expired and need `aws sso login`, plus regions an SCP blocked). The
 * `json` payload carries the per-verdict / per-error counts; every finding's
 * data is already exposed by the upstream model, so no flat CSV is emitted.
 *
 * The report never throws — a missing upstream step, malformed artifact, or
 * schema drift degrades to a logged warning and a still-useful (possibly empty)
 * report.
 *
 * @module
 */

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Model type whose outputs this report consumes. */
export const AUDIT_MODEL_TYPE = "@jentz/aws-default-sg-audit";

/** Finding spec name on the upstream audit model. */
export const FINDING_SPEC = "finding";
/** Scan-error spec name on the upstream audit model. */
export const SCAN_ERROR_SPEC = "scan_error";

// ---------------------------------------------------------------------------
// Schemas — hand-mirror of the producer's public shapes. If upstream tightens
// a field, artifacts fail safeParse here and are skipped with a logged warning.
// ---------------------------------------------------------------------------

const TagsSchema = z.record(z.string(), z.string()).default({});

const EniSchema = z.object({
  id: z.string(),
  interfaceType: z.string(),
  description: z.string(),
  requesterId: z.string(),
  requesterManaged: z.boolean(),
  category: z.string(),
  attachedInstanceId: z.string(),
});

const FindingSchema = z.object({
  accountId: z.string(),
  profile: z.string(),
  region: z.string(),
  vpcId: z.string(),
  vpcName: z.string(),
  vpcIsDefault: z.boolean(),
  defaultSgId: z.string(),
  ingressRuleCount: z.number(),
  egressRuleCount: z.number(),
  compliant: z.boolean(),
  eniCount: z.number(),
  enis: z.array(EniSchema),
  verdict: z.enum(["compliant", "safe_to_remediate", "in_use_needs_migration"]),
  vpcTags: TagsSchema,
  scannedAt: z.iso.datetime(),
});

const ScanErrorSchema = z.object({
  profile: z.string(),
  accountId: z.string(),
  region: z.string(),
  phase: z.string(),
  kind: z.enum(["auth_expired", "access_denied", "other"]),
  message: z.string(),
  scannedAt: z.iso.datetime(),
});

// Explicit interfaces (not `z.infer` aliases) so the public API surface stays
// free of private zod internals — `deno doc --lint` rejects exported types that
// reference the schema's inferred output type. The schemas above remain the
// runtime decode/validation source of truth; these mirror their shapes.

/** EC2.2 remediation verdict for a default security group. */
export type Verdict =
  | "compliant"
  | "safe_to_remediate"
  | "in_use_needs_migration";

/** A single ENI that references a default security group. */
export interface Eni {
  /** ENI id (`eni-...`). */
  id: string;
  /** AWS interface type. */
  interfaceType: string;
  /** AWS-supplied description. */
  description: string;
  /** Requester principal for service-managed ENIs; `""` for plain ENIs. */
  requesterId: string;
  /** Whether AWS (a managed service) owns this ENI. */
  requesterManaged: boolean;
  /** Derived bucket (`amazon-elasticache`, `nat_gateway`, `ec2-instance`, …). */
  category: string;
  /** Instance id when the ENI is attached to an EC2 instance; `""` otherwise. */
  attachedInstanceId: string;
}

/** A decoded finding row, mirroring the upstream model's `finding` resource. */
export interface Finding {
  /** 12-digit AWS account id. */
  accountId: string;
  /** Profile that produced this finding; `""` for the ambient credential chain. */
  profile: string;
  /** AWS region. */
  region: string;
  /** VPC the default SG belongs to. */
  vpcId: string;
  /** VPC `Name` tag, or `""`. */
  vpcName: string;
  /** Whether this is the AWS-created default VPC. */
  vpcIsDefault: boolean;
  /** The default security group id (the EC2.2 resource). */
  defaultSgId: string;
  /** Number of inbound (ingress) rules; EC2.2 wants 0. */
  ingressRuleCount: number;
  /** Number of outbound (egress) rules; EC2.2 wants 0. */
  egressRuleCount: number;
  /** True when both rule counts are 0 — EC2.2 compliant. */
  compliant: boolean;
  /** Number of ENIs that reference this default SG. */
  eniCount: number;
  /** The referencing ENIs, classified. */
  enis: Eni[];
  /** Remediation verdict driven by rule compliance and ENI usage. */
  verdict: Verdict;
  /** All VPC tags, flattened. Surfaces owner/team/service for the operator. */
  vpcTags: Record<string, string>;
  /** ISO 8601 scan timestamp. */
  scannedAt: string;
}

/** A decoded scan-error row, mirroring the upstream model's `scan_error` resource. */
export interface ScanError {
  /** Profile being swept; `""` for ambient. */
  profile: string;
  /** Account id if known by the time of failure; `""` otherwise. */
  accountId: string;
  /** Region being scanned; `""` for account-level failures. */
  region: string;
  /** Stage that failed: `credentials`, `describe_regions`, `describe_security_groups`, … */
  phase: string;
  /** Coarse classification driving the operator's next action. */
  kind: "auth_expired" | "access_denied" | "other";
  /** Error detail. */
  message: string;
  /** ISO 8601 timestamp. */
  scannedAt: string;
}

/** Everything collected from upstream audit steps. */
export interface Collected {
  /** Decoded findings. */
  findings: Finding[];
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
 * {@link AUDIT_MODEL_TYPE}, and decode their `finding` and `scan_error`
 * artifacts. Malformed or schema-mismatched artifacts are counted and skipped,
 * never thrown.
 *
 * @param context The report execution context supplied by the swamp runtime.
 * @returns The decoded findings, errors, and a skipped count.
 */
export async function collect(
  // deno-lint-ignore no-explicit-any
  context: any,
): Promise<Collected> {
  const logger = context.logger;
  const findings: Finding[] = [];
  const errors: ScanError[] = [];
  let skipped = 0;
  let matchingSteps = 0;
  const observed = new Set<string>();

  for (const step of context.stepExecutions ?? []) {
    if (typeof step?.modelType === "string") observed.add(step.modelType);
    if (step.modelType !== AUDIT_MODEL_TYPE) continue;
    matchingSteps++;

    for (const handle of step.dataHandles ?? []) {
      const specName: string | undefined = handle.metadata?.tags?.specName ??
        handle.specName;
      if (specName !== FINDING_SPEC && specName !== SCAN_ERROR_SPEC) continue;

      const bytes: Uint8Array | null = await context.dataRepository.getContent(
        step.modelType,
        step.modelId,
        handle.name,
        handle.version,
      );
      const value = decodeJson(bytes);
      if (value === undefined) {
        skipped++;
        tryLog(logger, "warn", "Could not decode {spec} artifact {handle}", {
          spec: specName,
          handle: handle.name,
        });
        continue;
      }

      if (specName === FINDING_SPEC) {
        const res = FindingSchema.safeParse(value);
        if (!res.success) {
          skipped++;
          tryLog(
            logger,
            "warn",
            "Finding {handle} failed schema on: {fields}",
            {
              handle: handle.name,
              fields: res.error.issues.map((i) => i.path.join(".") || "<root>")
                .join(", "),
            },
          );
          continue;
        }
        findings.push(res.data);
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
        expected: AUDIT_MODEL_TYPE,
        observed: [...observed].sort().join(", ") || "<none>",
      },
    );
  }

  tryLog(
    logger,
    "info",
    "Collected {findings} finding(s), {errors} error(s) from {steps} step(s); " +
      "{skipped} skipped",
    {
      findings: findings.length,
      errors: errors.length,
      steps: matchingSteps,
      skipped,
    },
  );

  return { findings, errors, skipped };
}

// ---------------------------------------------------------------------------
// Row derivation
// ---------------------------------------------------------------------------

/** Pick the most useful owner contact from a VPC's tags. */
export function ownerFromTags(tags: Record<string, string>): string {
  return tags["VantaOwner"] ?? tags["Owner"] ?? tags["owner"] ?? "";
}

/** Pick the team from a VPC's tags. */
export function teamFromTags(tags: Record<string, string>): string {
  return tags["team"] ?? tags["Team"] ?? "";
}

/** Unique ENI categories on a finding, sorted, `|`-joined (`""` when none). */
export function eniCategories(finding: Finding): string {
  return [...new Set(finding.enis.map((e) => e.category))].sort().join("|");
}

/** Verdict sort rank: in-use first (needs planning), then safe, then compliant. */
function verdictRank(v: Verdict): number {
  switch (v) {
    case "in_use_needs_migration":
      return 0;
    case "safe_to_remediate":
      return 1;
    case "compliant":
      return 2;
  }
}

/** Stable order: by verdict severity, then account, region, SG id. */
export function compareFindings(a: Finding, b: Finding): number {
  const r = verdictRank(a.verdict) - verdictRank(b.verdict);
  if (r !== 0) return r;
  if (a.accountId !== b.accountId) return a.accountId < b.accountId ? -1 : 1;
  if (a.region !== b.region) return a.region < b.region ? -1 : 1;
  return a.defaultSgId < b.defaultSgId
    ? -1
    : a.defaultSgId > b.defaultSgId
    ? 1
    : 0;
}

// ---------------------------------------------------------------------------
// Markdown rendering
// ---------------------------------------------------------------------------

function mdEscape(value: string): string {
  return value.replaceAll("|", "\\|");
}

function mdTable(findings: Finding[]): string {
  if (findings.length === 0) return "_None._\n";
  const cols = [
    "account",
    "region",
    "vpc",
    "owner",
    "team",
    "default SG",
    "in/out",
    "ENIs",
    "ENI types",
  ];
  const header = `| ${cols.join(" | ")} |`;
  const sep = `| ${cols.map(() => "---").join(" | ")} |`;
  const rows = [...findings].sort(compareFindings).map((f) => {
    const cells = [
      f.accountId,
      f.region,
      f.vpcName || f.vpcId,
      ownerFromTags(f.vpcTags),
      teamFromTags(f.vpcTags),
      f.defaultSgId,
      `${f.ingressRuleCount}/${f.egressRuleCount}`,
      String(f.eniCount),
      eniCategories(f),
    ].map((c) => mdEscape(c));
    return `| ${cells.join(" | ")} |`;
  });
  return [header, sep, ...rows].join("\n") + "\n";
}

/**
 * Render the operator markdown report from collected findings and errors.
 *
 * @param collected Findings and errors from {@link collect}.
 * @param generatedAt ISO timestamp for the report header.
 * @param workflowName Originating workflow name, for the header.
 * @returns The full markdown document.
 */
export function renderMarkdown(
  collected: Collected,
  generatedAt: string,
  workflowName: string,
): string {
  const { findings, errors } = collected;
  const migrate = findings.filter((f) =>
    f.verdict === "in_use_needs_migration"
  );
  const safe = findings.filter((f) => f.verdict === "safe_to_remediate");
  const compliant = findings.filter((f) => f.verdict === "compliant");

  const authExpired = errors.filter((e) => e.kind === "auth_expired");
  const accessDenied = errors.filter((e) => e.kind === "access_denied");
  const otherErrors = errors.filter((e) => e.kind === "other");

  const accounts = new Set(findings.map((f) => f.accountId));
  for (const e of errors) if (e.accountId) accounts.add(e.accountId);

  const lines: string[] = [];
  lines.push("# EC2.2 — Default Security Group Audit");
  lines.push("");
  lines.push(`_Generated ${generatedAt} · workflow \`${workflowName}\`_`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Accounts seen: **${accounts.size}**`);
  lines.push(`- Default SGs audited: **${findings.length}**`);
  lines.push(
    `  - ❌ non-compliant: **${migrate.length + safe.length}** ` +
      `(⚠️ needs migration: **${migrate.length}**, ✅ safe to strip now: ` +
      `**${safe.length}**)`,
  );
  lines.push(`  - ✅ already compliant: **${compliant.length}**`);
  lines.push(
    `- Coverage gaps: **${authExpired.length}** region(s) need ` +
      "`aws sso login` (expired token), " +
      `**${accessDenied.length}** region(s) blocked by SCP/IAM` +
      (otherErrors.length ? `, **${otherErrors.length}** other error(s)` : ""),
  );
  lines.push("");
  lines.push("## ✅ Safe to remediate now (no ENIs use the default SG)");
  lines.push("");
  lines.push(
    "Revoke all ingress + egress on these default SGs — nothing depends on them.",
  );
  lines.push("");
  lines.push(mdTable(safe));
  lines.push("## ⚠️ In use — migrate workload first");
  lines.push("");
  lines.push(
    "These default SGs are referenced by live ENIs. Move the attached " +
      "workload(s) to a dedicated SG **before** stripping rules, or " +
      "connectivity breaks.",
  );
  lines.push("");
  lines.push(mdTable(migrate));

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
    const regions = [
      ...new Set(accessDenied.map((e) => e.region).filter(Boolean)),
    ]
      .sort();
    lines.push("## 🚫 Blocked by SCP/IAM (expected for out-of-scope regions)");
    lines.push("");
    lines.push(
      `${accessDenied.length} region-scans were denied — typically a ` +
        "region your org's SCP does not permit, so no workloads (and thus no " +
        "exposed default SGs) can exist there. Regions: " +
        (regions.length ? regions.map((r) => `\`${r}\``).join(", ") : "—"),
    );
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
  /** Number of finding rows. */
  findingCount: number;
  /** Count by verdict. */
  byVerdict: Record<string, number>;
  /** Count of scan errors by kind. */
  errorsByKind: Record<string, number>;
  /** Artifacts skipped during collection. */
  skipped: number;
  /** True when the outer guard absorbed an unexpected failure. */
  degraded: boolean;
}

/**
 * The `@jentz/aws-default-sg-audit-report` workflow-scope report. Returns
 * `{ markdown, json }`; swamp persists them as `report-{name}` (text/markdown)
 * and `report-{name}-json` (application/json).
 */
export const report = {
  name: "@jentz/aws-default-sg-audit-report",
  description:
    "Operator worklist for AWS Security Hub control EC2.2, built from the " +
    "default-SG audit findings collected earlier in the workflow. Groups " +
    "default SGs into safe-to-strip vs needs-migration, and lists coverage " +
    "gaps (SSO re-login needed, SCP-blocked regions).",
  scope: "workflow" as const,
  labels: ["aws", "ec2", "security-hub", "ec2.2", "compliance"],
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
      "Running aws-default-sg-audit-report for {workflow}",
      {
        workflow: workflowName,
      },
    );

    let collected: Collected = { findings: [], errors: [], skipped: 0 };
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
      markdown = `# EC2.2 — Default Security Group Audit\n\n` +
        `_Report degraded: ${detail}_\n`;
    }

    const byVerdict: Record<string, number> = {
      compliant: 0,
      safe_to_remediate: 0,
      in_use_needs_migration: 0,
    };
    for (const f of collected.findings) byVerdict[f.verdict]++;
    const errorsByKind: Record<string, number> = {
      auth_expired: 0,
      access_denied: 0,
      other: 0,
    };
    for (const e of collected.errors) errorsByKind[e.kind]++;

    const json: ReportJson = {
      report: "@jentz/aws-default-sg-audit-report",
      workflow: workflowName,
      generatedAt,
      findingCount: collected.findings.length,
      byVerdict,
      errorsByKind,
      skipped: collected.skipped,
      degraded,
    };

    tryLog(logger, "info", "report finished: {rows} finding(s){degraded}", {
      rows: collected.findings.length,
      degraded: degraded ? " (degraded)" : "",
    });

    return { markdown, json };
  },
};
