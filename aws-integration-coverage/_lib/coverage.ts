/**
 * Shared coalesce core for integration-coverage.
 *
 * The StackSet lens (`@jentz/aws-stackset-audit`) and the IAM lens
 * (`@jentz/aws-iam-role-audit`) are correlated into a per-account coverage
 * matrix here, so the workflow-scope report (`@jentz/integration-coverage`) and
 * the queryable model (`@jentz/aws-integration-coverage`) produce identical
 * verdicts from one source of truth. No model/report export and no swamp/AWS
 * dependencies — pure data shaping + zod schemas, unit-testable in isolation.
 *
 * An integration may define **several roles** (e.g. a Readonly + ECR + EBS
 * trio). The IAM lens emits one `role` row per (account, roleName), each with a
 * `required` flag. Coverage here aggregates per account over the *required*
 * roles: an account is `covered-compliant` only when every required role is
 * present and compliant. A single-role integration is just the one-role case
 * and yields the same verdicts it always did.
 *
 * @module
 */

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Upstream model types + specs
// ---------------------------------------------------------------------------

/** Model type of the StackSet lens. */
export const STACKSET_MODEL_TYPE = "@jentz/aws-stackset-audit";
/** Model type of the IAM lens. */
export const IAM_MODEL_TYPE = "@jentz/aws-iam-role-audit";

/** StackSet per-instance spec name. */
export const STACKSET_INSTANCE_SPEC = "instance";
/** StackSet summary spec name. */
export const STACKSET_SUMMARY_SPEC = "summary";
/** IAM role spec name. */
export const IAM_ROLE_SPEC = "role";
/** IAM scan-error spec name. */
export const IAM_ERROR_SPEC = "scan_error";

// ---------------------------------------------------------------------------
// Mirrored upstream schemas (subset used). Tolerant: passthrough + safeParse
// means upstream additions never break coalescing.
// ---------------------------------------------------------------------------

/** StackSet `instance` row (subset). */
export const InstanceSchema = z.object({
  stackSetName: z.string().default(""),
  account: z.string(),
  region: z.string().default(""),
  overallStatus: z.string().default(""),
  detailedStatus: z.string().default(""),
  failureCategory: z.string().default(""),
}).passthrough();

/** StackSet `summary` row (subset). */
export const SummarySchema = z.object({
  stackSetName: z.string().default(""),
  accountsTargeted: z.number().default(0),
  instanceCount: z.number().default(0),
}).passthrough();

/**
 * IAM `role` row (subset). `required` defaults to `true` so rows written by the
 * pre-multi-role IAM model still coalesce as required roles.
 */
export const RoleSchema = z.object({
  accountId: z.string(),
  accountName: z.string().default(""),
  profile: z.string().default(""),
  roleName: z.string().default(""),
  required: z.boolean().default(true),
  exists: z.boolean(),
  managementMechanism: z.string().default(""),
  cfnStackName: z.string().default(""),
  cfnStackRegion: z.string().default(""),
  compliant: z.boolean().default(false),
  findings: z.array(z.string()).default([]),
  attachedManagedPolicyArns: z.array(z.string()).default([]),
  createDate: z.string().default(""),
}).passthrough();

/** IAM `scan_error` row (subset). */
export const IamErrorSchema = z.object({
  profile: z.string().default(""),
  accountId: z.string().default(""),
  roleName: z.string().default(""),
  kind: z.string().default("other"),
  message: z.string().default(""),
}).passthrough();

/**
 * A decoded StackSet instance row. Explicit interface (not `z.infer`) so the
 * public surface does not leak a private zod-derived type and `deno doc --lint`
 * stays clean.
 */
export interface Instance {
  /** Target StackSet name. */
  stackSetName: string;
  /** 12-digit account id the instance is deployed in. */
  account: string;
  /** AWS region of the instance. */
  region: string;
  /** Overall instance status (CURRENT / OUTDATED / INOPERABLE / …). */
  overallStatus: string;
  /** Detailed instance status. */
  detailedStatus: string;
  /** Normalized failure category, "" when healthy. */
  failureCategory: string;
  /** Tolerant passthrough of any additional upstream fields. */
  [key: string]: unknown;
}

/** A decoded StackSet summary row. */
export interface Summary {
  /** Target StackSet name. */
  stackSetName: string;
  /** Number of accounts the StackSet targets. */
  accountsTargeted: number;
  /** Number of stack instances reported. */
  instanceCount: number;
  /** Tolerant passthrough of any additional upstream fields. */
  [key: string]: unknown;
}

/** A decoded IAM role row. */
export interface Role {
  /** 12-digit account id. */
  accountId: string;
  /** Friendly account name from the IAM profile. */
  accountName: string;
  /** AWS profile the role was assessed under. */
  profile: string;
  /** Role name. */
  roleName: string;
  /** Whether this role is expected to be deployed for the integration. */
  required: boolean;
  /** Whether the role exists in the account. */
  exists: boolean;
  /** How the role got there (manual / cfn-standalone-stack / cfn-stackset / …). */
  managementMechanism: string;
  /** Owning CloudFormation stack name, or "". */
  cfnStackName: string;
  /** Region of the owning CloudFormation stack, or "". */
  cfnStackRegion: string;
  /** Whether the role meets its configured expectations. */
  compliant: boolean;
  /** Unmet expectations for this role. */
  findings: string[];
  /** Managed policy ARNs attached to the role. */
  attachedManagedPolicyArns: string[];
  /** Role creation date, or "". */
  createDate: string;
  /** Tolerant passthrough of any additional upstream fields. */
  [key: string]: unknown;
}

/** A decoded IAM scan error. */
export interface IamError {
  /** AWS profile the scan failed under. */
  profile: string;
  /** 12-digit account id, "" when the failure preceded account resolution. */
  accountId: string;
  /** Role name the scan targeted, or "". */
  roleName: string;
  /** Error classification. */
  kind: string;
  /** Human-readable error detail. */
  message: string;
  /** Tolerant passthrough of any additional upstream fields. */
  [key: string]: unknown;
}

/** Everything collected from the two upstream lenses. */
export interface Collected {
  /** StackSet instance rows. */
  instances: Instance[];
  /** StackSet summary rows (usually one). */
  summaries: Summary[];
  /** IAM role rows (one per account × role). */
  roles: Role[];
  /** IAM scan errors. */
  iamErrors: IamError[];
  /** Artifacts that failed to decode or validate. */
  skipped: number;
}

// ---------------------------------------------------------------------------
// Coverage model
// ---------------------------------------------------------------------------

/** How a role was created. */
export type Mechanism =
  | "this-stackset"
  | "other-stackset"
  | "standalone-stack"
  | "manual"
  | "missing"
  | "unknown";

/** Aggregate mechanism for an account (across its present roles). */
export type AccountMechanism = Mechanism | "mixed";

/** The coverage verdict for an account. */
export type Coverage =
  | "covered-compliant"
  | "covered-noncompliant"
  | "covered-partial"
  | "uncovered"
  | "unknown";

/** Per-(account, role) detail. */
export interface RoleDetail {
  /** Role name. */
  roleName: string;
  /** Whether this role is expected to be deployed for the integration. */
  required: boolean;
  /** Whether the role exists in the account. */
  exists: boolean;
  /** Whether the role meets its configured expectations. */
  compliant: boolean;
  /** How the role got there. */
  mechanism: Mechanism;
  /** Owning CloudFormation stack name, or "". */
  cfnStackName: string;
  /** Unmet expectations for this role. */
  findings: string[];
}

/** Per-account coalesced view (aggregated over all roles). */
export interface CoverageRow {
  /** 12-digit account id. */
  accountId: string;
  /** Friendly name (from the IAM profile) or the account id. */
  accountName: string;
  /** Aggregate coverage verdict over the required roles. */
  coverage: Coverage;
  /** Aggregate mechanism over the present roles (or "mixed"/"missing"/"unknown"). */
  mechanism: AccountMechanism;
  /** Number of required roles configured. */
  requiredTotal: number;
  /** Number of required roles present. */
  requiredPresent: number;
  /** Number of required roles present AND compliant. */
  requiredCompliant: number;
  /** Required roles that are absent. */
  missingRequiredRoles: string[];
  /** Per-role detail (all configured roles, required or not). */
  roles: RoleDetail[];
  /** Representative StackSet instance status for the account. */
  stacksetStatus: string;
  /** Whether the StackSet targets this account (has any instance). */
  inStacksetTargets: boolean;
  /** Whether the IAM lens produced any role row for this account. */
  inIamSweep: boolean;
  /** Human-readable reconciliation of the two lenses. */
  reconciliation: string;
}

/** Zod schema for {@link RoleDetail}. */
export const RoleDetailSchema = z.object({
  roleName: z.string(),
  required: z.boolean(),
  exists: z.boolean(),
  compliant: z.boolean(),
  mechanism: z.string(),
  cfnStackName: z.string(),
  findings: z.array(z.string()),
});

/** Zod schema for a {@link CoverageRow} (for model resource validation). */
export const CoverageRowSchema = z.object({
  accountId: z.string(),
  accountName: z.string(),
  coverage: z.enum([
    "covered-compliant",
    "covered-noncompliant",
    "covered-partial",
    "uncovered",
    "unknown",
  ]),
  mechanism: z.string(),
  requiredTotal: z.number(),
  requiredPresent: z.number(),
  requiredCompliant: z.number(),
  missingRequiredRoles: z.array(z.string()),
  roles: z.array(RoleDetailSchema),
  stacksetStatus: z.string(),
  inStacksetTargets: z.boolean(),
  inIamSweep: z.boolean(),
  reconciliation: z.string(),
});

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/** Tally a list by a string key into a `{value: count}` map. */
export function countBy<T>(items: T[], key: (i: T) => string): Record<
  string,
  number
> {
  const out: Record<string, number> = {};
  for (const it of items) {
    const k = key(it);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

/** Pick a single representative StackSet status for an account's instances. */
export function representativeStacksetStatus(rows: Instance[]): string {
  if (rows.length === 0) return "no-instance";
  const overall = rows.map((r) => r.overallStatus);
  if (overall.includes("CURRENT")) return "CURRENT";
  if (overall.includes("INOPERABLE")) return "INOPERABLE";
  if (overall.includes("OUTDATED")) return "OUTDATED";
  return rows[0].detailedStatus || rows[0].overallStatus || "unknown";
}

/** Refine a role's IAM mechanism using the target stackset name. */
export function refineMechanism(role: Role, stackSetName: string): Mechanism {
  if (!role.exists) return "missing";
  switch (role.managementMechanism) {
    case "manual":
      return "manual";
    case "cfn-standalone-stack":
      return "standalone-stack";
    case "cfn-stackset": {
      const prefix = stackSetName ? `StackSet-${stackSetName}-` : "StackSet-";
      return role.cfnStackName.startsWith(prefix)
        ? "this-stackset"
        : "other-stackset";
    }
    default:
      return "unknown";
  }
}

/** Aggregate the mechanisms of an account's present roles into one label. */
export function aggregateMechanism(roles: RoleDetail[]): AccountMechanism {
  const present = roles.filter((r) => r.exists).map((r) => r.mechanism);
  if (present.length === 0) return "missing";
  const distinct = [...new Set(present)];
  return distinct.length === 1 ? distinct[0] : "mixed";
}

/** Compute the aggregate coverage verdict from an account's role details. */
export function aggregateCoverage(
  roles: RoleDetail[],
  inIamSweep: boolean,
): Coverage {
  if (!inIamSweep) return "unknown";
  const required = roles.filter((r) => r.required);
  // No required roles configured: treat any present-and-compliant role as cover.
  const pool = required.length > 0 ? required : roles;
  if (pool.length === 0) return "unknown";
  const present = pool.filter((r) => r.exists);
  const compliant = present.filter((r) => r.compliant);
  if (present.length === 0) return "uncovered";
  if (compliant.length === pool.length) return "covered-compliant";
  if (present.length === pool.length) return "covered-noncompliant";
  return "covered-partial";
}

/** Input to {@link reconcileAccount}. */
export interface ReconcileInput {
  /** Per-role detail for the account. */
  roles: RoleDetail[];
  /** Required roles that are absent. */
  missingRequiredRoles: string[];
  /** Aggregate mechanism for the account. */
  mechanism: AccountMechanism;
  /** Representative StackSet status for the account. */
  stacksetStatus: string;
  /** Whether the IAM lens produced any role row for the account. */
  inIamSweep: boolean;
}

/** Derive the account-level reconciliation label. */
export function reconcileAccount(input: ReconcileInput): string {
  const { roles, missingRequiredRoles, mechanism, stacksetStatus, inIamSweep } =
    input;
  if (!inIamSweep) return "unknown: account not covered by the IAM sweep";
  const parts: string[] = [];
  const present = roles.filter((r) => r.exists);
  if (present.length > 0) {
    if (mechanism === "this-stackset") {
      parts.push(
        stacksetStatus === "CURRENT"
          ? "consistent: role(s) present via this stackset, instance CURRENT"
          : `stackset-behind: role(s) present via this stackset, but instance is ${stacksetStatus}`,
      );
    } else if (mechanism === "mixed") {
      parts.push("role(s) present via mixed mechanisms");
    } else {
      parts.push(`role(s) present via ${mechanism}`);
    }
  }
  if (missingRequiredRoles.length > 0) {
    const list = missingRequiredRoles.join(", ");
    parts.push(
      stacksetStatus === "CURRENT"
        ? `DISCREPANCY: stackset CURRENT but missing required role(s): ${list}`
        : `missing required role(s): ${list}`,
    );
  }
  if (parts.length === 0) parts.push("no roles present");
  return parts.join("; ");
}

/** True when a row's reconciliation marks a lens disagreement. */
export function isDisagreement(r: CoverageRow): boolean {
  return r.reconciliation.includes("DISCREPANCY") ||
    r.reconciliation.includes("stackset-behind");
}

/** A profile whose credentials failed before an account id was known. */
export interface UnresolvedProfile {
  /** AWS profile name. */
  profile: string;
  /** Error classification. */
  kind: string;
}

/** Result of {@link coalesce}. */
export interface CoalesceResult {
  /** Per-account rows, sorted by account id. */
  rows: CoverageRow[];
  /** Target stackset name (from the summary, else inferred from instances). */
  stackSetName: string;
  /** Distinct role names observed, sorted. */
  roleNames: string[];
  /** Profiles whose credentials failed before an account id was known. */
  unresolvedProfiles: UnresolvedProfile[];
}

/**
 * Coalesce the StackSet and IAM lenses into a per-account coverage matrix,
 * aggregating each account over all of its roles.
 *
 * @param c Collected upstream rows.
 * @returns Per-account coverage rows plus the stackset name, role names, and
 *   any profiles that could not be resolved to an account.
 */
export function coalesce(c: Collected): CoalesceResult {
  const stackSetName = c.summaries[0]?.stackSetName ??
    c.instances[0]?.stackSetName ?? "";

  const instByAccount = new Map<string, Instance[]>();
  for (const i of c.instances) {
    const arr = instByAccount.get(i.account) ?? [];
    arr.push(i);
    instByAccount.set(i.account, arr);
  }
  const rolesByAccount = new Map<string, Role[]>();
  for (const r of c.roles) {
    const arr = rolesByAccount.get(r.accountId) ?? [];
    arr.push(r);
    rolesByAccount.set(r.accountId, arr);
  }

  const roleNames = [...new Set(c.roles.map((r) => r.roleName).filter(Boolean))]
    .sort();

  const allAccounts = new Set<string>([
    ...instByAccount.keys(),
    ...rolesByAccount.keys(),
  ]);

  const rows: CoverageRow[] = [];
  for (const accountId of allAccounts) {
    const roleRows = rolesByAccount.get(accountId) ?? [];
    const instRows = instByAccount.get(accountId) ?? [];
    const inStacksetTargets = instRows.length > 0;
    const inIamSweep = roleRows.length > 0;
    const stacksetStatus = representativeStacksetStatus(instRows);

    const roles: RoleDetail[] = roleRows
      .map((r) => ({
        roleName: r.roleName,
        required: r.required,
        exists: r.exists,
        compliant: r.compliant,
        mechanism: refineMechanism(r, stackSetName),
        cfnStackName: r.cfnStackName,
        findings: r.findings,
      }))
      .sort((a, b) => (a.roleName < b.roleName ? -1 : 1));

    const required = roles.filter((r) => r.required);
    const requiredPresent = required.filter((r) => r.exists);
    const requiredCompliant = requiredPresent.filter((r) => r.compliant);
    const missingRequiredRoles = required.filter((r) => !r.exists).map((r) =>
      r.roleName
    );
    const mechanism = aggregateMechanism(roles);
    const coverage = aggregateCoverage(roles, inIamSweep);
    const accountName = roleRows.find((r) => r.accountName)?.accountName ||
      accountId;

    rows.push({
      accountId,
      accountName,
      coverage,
      mechanism,
      requiredTotal: required.length,
      requiredPresent: requiredPresent.length,
      requiredCompliant: requiredCompliant.length,
      missingRequiredRoles,
      roles,
      stacksetStatus,
      inStacksetTargets,
      inIamSweep,
      reconciliation: reconcileAccount({
        roles,
        missingRequiredRoles,
        mechanism,
        stacksetStatus,
        inIamSweep,
      }),
    });
  }
  rows.sort((a, b) => (a.accountId < b.accountId ? -1 : 1));

  const unresolvedProfiles = c.iamErrors
    .filter((e) => !e.accountId)
    .map((e) => ({ profile: e.profile, kind: e.kind }));

  return { rows, stackSetName, roleNames, unresolvedProfiles };
}

/** Per-role rollup across accounts. */
export interface RoleRollup {
  /** Role name. */
  roleName: string;
  /** Whether the role is configured as required. */
  required: boolean;
  /** Accounts where the role is present. */
  present: number;
  /** Accounts where the role is present and compliant. */
  compliant: number;
  /** Accounts (in the IAM sweep) where the role is absent. */
  missing: number;
}

/** Rollups derived from coverage rows, shared by the report JSON and the model summary. */
export interface CoverageRollup {
  /** Counts by aggregate coverage verdict. */
  byCoverage: Record<string, number>;
  /** Counts by aggregate mechanism. */
  byMechanism: Record<string, number>;
  /** Per-role rollup across accounts. */
  byRole: RoleRollup[];
  /** Accounts where the two lenses disagree. */
  discrepancies: CoverageRow[];
}

/** Compute the standard coverage rollups from coalesced rows. */
export function summarizeCoverage(rows: CoverageRow[]): CoverageRollup {
  // Per-role rollup: walk every account's role details.
  const roleAgg = new Map<
    string,
    { required: boolean; present: number; compliant: number; missing: number }
  >();
  for (const row of rows) {
    if (!row.inIamSweep) continue;
    for (const rd of row.roles) {
      const a = roleAgg.get(rd.roleName) ??
        { required: rd.required, present: 0, compliant: 0, missing: 0 };
      if (rd.exists) {
        a.present++;
        if (rd.compliant) a.compliant++;
      } else {
        a.missing++;
      }
      a.required = a.required || rd.required;
      roleAgg.set(rd.roleName, a);
    }
  }
  const byRole: RoleRollup[] = [...roleAgg.entries()]
    .map(([roleName, a]) => ({ roleName, ...a }))
    .sort((x, y) => (x.roleName < y.roleName ? -1 : 1));

  return {
    byCoverage: countBy(rows, (r) => r.coverage),
    byMechanism: countBy(rows, (r) => r.mechanism),
    byRole,
    discrepancies: rows.filter(isDisagreement),
  };
}
