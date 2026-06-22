/**
 * `@jentz/aws-stackset-audit` — read-only operational audit of a CloudFormation
 * StackSet and all of its stack instances, from the management / delegated-admin
 * account.
 *
 * The official `@swamp/aws/cloudformation/stack-set` type wraps the Cloud
 * Control API, so it only sees the StackSet *resource* (config + template) — not
 * per-instance deployment status, operation history, or drift. This model fills
 * that gap using the native CloudFormation API.
 *
 * The single `audit` method is the **fan-out sweep** (repo rule 6): in one
 * locked execution it calls `DescribeStackSet`, paginates `ListStackInstances`
 * across every account × region, and reads recent `ListStackSetOperations`, then
 * writes:
 *
 *   - one `summary` resource — stackset config, drift-detection rollup,
 *     per-dimension counts (status / region / drift / failure category), recent
 *     operations, a normalized `rootCauses` grouping, detected anti-patterns,
 *     and a derived `safeToReapply` verdict, and
 *   - one `instance` resource per stack instance (keyed by account+region),
 *     carrying its deployment status, status reason, drift status, stack id,
 *     OU, and a normalized `failureCategory` — fully queryable via CEL.
 *
 * The audit reports each instance's **existing** drift status exactly as the
 * StackSet API returns it; it never triggers a fresh drift-detection run.
 * Measuring drift is a separate, **mutating** capability (it needs
 * `cloudformation:DetectStackSetDrift` plus the stackset admin role), shipped as
 * a sibling extension. Compose the two in a swamp workflow: run the
 * drift-detection step first, then this `audit` step with
 * `dependsOn: [<drift-step>: succeeded]`, so the audit reads the refreshed
 * per-instance `driftStatus`. That keeps this model strictly read-only, so it
 * can run under a `*-readonly` profile.
 *
 * Auth mirrors the repo's `@jentz/aws-vpc-inventory` model: an optional named
 * `profile` (`fromIni`) or the ambient credential chain (`AWS_PROFILE`/env).
 *
 * @module
 */

import { z } from "npm:zod@4.4.3";
import {
  CloudFormationClient,
  DescribeStackSetCommand,
  ListStackInstancesCommand,
  ListStackSetOperationsCommand,
} from "npm:@aws-sdk/client-cloudformation@3.1073.0";
import { fromIni } from "npm:@aws-sdk/credential-providers@3.1073.0";

/** Credential provider as returned by `fromIni`; `undefined` means the ambient chain. */
type CredentialProvider = ReturnType<typeof fromIni>;

// ---------------------------------------------------------------------------
// Global arguments
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  stackSetName: z.string().min(1).describe(
    "The name of the CloudFormation StackSet to audit (e.g. 'ExampleOrgBaseline').",
  ),
  callAs: z.enum(["SELF", "DELEGATED_ADMIN"]).default("SELF").describe(
    "Who you are calling as. SELF when signed in to the org management " +
      "account (the case for SERVICE_MANAGED stacksets there); " +
      "DELEGATED_ADMIN from a delegated administrator account.",
  ),
  region: z.string().min(1).default("us-east-1").describe(
    "Region of the CloudFormation endpoint to talk to. StackSet metadata is " +
      "global to the admin account; us-east-1 is a safe default.",
  ),
  profile: z.string().default("").describe(
    "Named AWS profile to use (resolved via fromIni). Empty (default) uses " +
      "the ambient credential chain — whatever AWS_PROFILE / env is set.",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Resource schemas
// ---------------------------------------------------------------------------

const ParameterSchema = z.object({
  key: z.string(),
  value: z.string(),
});

const OperationSchema = z.object({
  operationId: z.string(),
  action: z.string(),
  status: z.string(),
  creationTimestamp: z.string(),
  endTimestamp: z.string(),
  statusReason: z.string(),
});

const RootCauseSchema = z.object({
  failureCategory: z.string(),
  count: z.number(),
  exampleReason: z.string(),
  affectedAccounts: z.number(),
  accounts: z.array(z.string()),
});

const PatternSchema = z.object({
  pattern: z.string(),
  description: z.string(),
  affectedAccounts: z.number(),
  evidence: z.string(),
});

const DriftSchema = z.object({
  driftStatus: z.string(),
  totalStackInstancesCount: z.number(),
  driftedStackInstancesCount: z.number(),
  inSyncStackInstancesCount: z.number(),
  inProgressStackInstancesCount: z.number(),
  failedStackInstancesCount: z.number(),
  lastDriftCheckTimestamp: z.string(),
});

const SafeToReapplySchema = z.object({
  verdict: z.enum(["yes", "no", "caution", "unknown"]),
  reasons: z.array(z.string()),
  remediation: z.array(z.string()),
});

const SummarySchema = z.object({
  stackSetName: z.string(),
  stackSetId: z.string(),
  status: z.string(),
  permissionModel: z.string(),
  description: z.string(),
  organizationalUnitIds: z.array(z.string()),
  capabilities: z.array(z.string()),
  autoDeploymentEnabled: z.boolean(),
  managedExecutionActive: z.boolean(),
  parameters: z.array(ParameterSchema),
  drift: DriftSchema,
  regions: z.array(z.string()),
  accountsTargeted: z.number(),
  instanceCount: z.number(),
  byDetailedStatus: z.record(z.string(), z.number()),
  byOverallStatus: z.record(z.string(), z.number()),
  byRegion: z.record(z.string(), z.number()),
  byDriftStatus: z.record(z.string(), z.number()),
  byFailureCategory: z.record(z.string(), z.number()),
  operations: z.array(OperationSchema),
  rootCauses: z.array(RootCauseSchema),
  detectedPatterns: z.array(PatternSchema),
  safeToReapply: SafeToReapplySchema,
  auditedAt: z.iso.datetime(),
});

const InstanceRecordSchema = z.object({
  stackSetName: z.string(),
  account: z.string(),
  region: z.string(),
  detailedStatus: z.string(),
  overallStatus: z.string(),
  statusReason: z.string(),
  driftStatus: z.string(),
  lastDriftCheckTimestamp: z.string(),
  stackId: z.string(),
  organizationalUnitId: z.string(),
  failureCategory: z.string(),
  auditedAt: z.iso.datetime(),
});

// ---------------------------------------------------------------------------
// Public resource shapes (explicit interfaces — deno doc --lint friendly)
// ---------------------------------------------------------------------------

/** One stack instance of the stackset, in one (account, region). */
export interface InstanceRecord {
  /** StackSet this instance belongs to. */
  stackSetName: string;
  /** 12-digit member account id. */
  account: string;
  /** AWS region of the instance. */
  region: string;
  /**
   * Outcome of the last operation on this instance:
   * `SUCCEEDED` | `FAILED` | `CANCELLED` | `PENDING` | `RUNNING` |
   * `INOPERABLE` | `SKIPPED_SUSPENDED_ACCOUNT` | `FAILED_IMPORT`.
   */
  detailedStatus: string;
  /** Overall instance status: `CURRENT` | `OUTDATED` | `INOPERABLE`. */
  overallStatus: string;
  /** Human-readable reason for the status, or `""`. */
  statusReason: string;
  /** Drift status: `DRIFTED` | `IN_SYNC` | `NOT_CHECKED` | `UNKNOWN`. */
  driftStatus: string;
  /** ISO 8601 of the last drift check, or `""` if never checked. */
  lastDriftCheckTimestamp: string;
  /** Physical stack id in the member account, or `""`. */
  stackId: string;
  /** OU id when service-managed, or `""`. */
  organizationalUnitId: string;
  /** Normalized failure classification (see {@link classifyFailure}). */
  failureCategory: string;
  /** ISO 8601 audit timestamp. */
  auditedAt: string;
}

// The helpers below are exported as test seams. Their public signatures use
// explicit interfaces (rather than `z.infer<typeof …>`) so the public API does
// not reference the private schema constants — required for `deno doc --lint`.
// The zod schemas above remain the runtime validation source for the resources.

/** A recent stackset operation, as summarized onto the `summary` resource. */
export interface Operation {
  /** Operation id. */
  operationId: string;
  /** CREATE | UPDATE | DELETE | DETECT_DRIFT. */
  action: string;
  /** RUNNING | SUCCEEDED | FAILED | STOPPING | STOPPED | QUEUED. */
  status: string;
  /** ISO 8601 start time, or `""`. */
  creationTimestamp: string;
  /** ISO 8601 end time, or `""`. */
  endTimestamp: string;
  /** Status reason, or `""`. */
  statusReason: string;
}

/** A ranked root cause: failed instances grouped by failure category. */
export interface RootCause {
  /** Normalized failure category (see {@link classifyFailure}). */
  failureCategory: string;
  /** Number of instances in this category. */
  count: number;
  /** A representative status reason for the category, or `""`. */
  exampleReason: string;
  /** Number of distinct accounts affected. */
  affectedAccounts: number;
  /** The affected account ids, sorted. */
  accounts: string[];
}

/** A detected cross-instance anti-pattern. */
export interface Pattern {
  /** Stable pattern identifier. */
  pattern: string;
  /** Human-readable explanation. */
  description: string;
  /** Number of accounts the pattern affects. */
  affectedAccounts: number;
  /** Concrete evidence drawn from the instances. */
  evidence: string;
}

/** The StackSet-level drift-detection rollup. */
export interface Drift {
  /** DRIFTED | IN_SYNC | NOT_CHECKED | UNKNOWN. */
  driftStatus: string;
  /** Instances covered by the last drift check. */
  totalStackInstancesCount: number;
  /** Drifted instances at last check. */
  driftedStackInstancesCount: number;
  /** In-sync instances at last check. */
  inSyncStackInstancesCount: number;
  /** In-progress instances at last check. */
  inProgressStackInstancesCount: number;
  /** Failed instances at last check. */
  failedStackInstancesCount: number;
  /** ISO 8601 of the last drift check, or `""` if never checked. */
  lastDriftCheckTimestamp: string;
}

/** The derived safe-to-reapply verdict. */
export interface SafeToReapply {
  /** Conservative verdict. */
  verdict: "yes" | "no" | "caution" | "unknown";
  /** Why this verdict was reached. */
  reasons: string[];
  /** Suggested remediation steps, if any. */
  remediation: string[];
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit-test access)
// ---------------------------------------------------------------------------

/**
 * Normalize a stack instance's outcome into a coarse failure category the
 * summary groups on. `SUCCEEDED` → `none`. The IAM-conflict case is the
 * fingerprint of deploying a fixed-name *global* IAM resource (managed policy /
 * role) to multiple regions: at most one region per account can create the
 * name, the rest fail `AlreadyExists`.
 */
export function classifyFailure(
  detailedStatus: string,
  statusReason: string,
): string {
  if (detailedStatus === "SUCCEEDED") return "none";
  if (detailedStatus === "SKIPPED_SUSPENDED_ACCOUNT") {
    return "suspended-account";
  }
  const r = (statusReason ?? "").toLowerCase();
  if (detailedStatus === "CANCELLED") {
    return r.includes("failure tolerance")
      ? "cancelled-tolerance"
      : "cancelled";
  }
  if (
    detailedStatus === "FAILED" || detailedStatus === "FAILED_IMPORT" ||
    detailedStatus === "INOPERABLE"
  ) {
    const alreadyExists = r.includes("already exists") ||
      r.includes("alreadyexists");
    const iam = r.includes("iam") || r.includes("managedpolicy") ||
      r.includes("policy") || r.includes("role");
    if (alreadyExists && iam) return "iam-name-conflict";
    if (alreadyExists) return "resource-already-exists";
    if (
      r.includes("not authorized") || r.includes("accessdenied") ||
      r.includes("access denied") || r.includes("explicit deny")
    ) {
      return "access-denied";
    }
    return "other-failure";
  }
  if (
    detailedStatus === "PENDING" || detailedStatus === "RUNNING" ||
    detailedStatus === "QUEUED"
  ) {
    return "in-progress";
  }
  return "other";
}

/** Tally a list of records by a string key into a `{value: count}` map. */
export function countBy<T>(items: T[], key: (item: T) => string): Record<
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

/**
 * Group failed instances by {@link classifyFailure} category into ranked root
 * causes, each carrying a representative reason and the affected accounts.
 * `none` and `in-progress` are not root causes and are excluded.
 */
export function buildRootCauses(
  instances: InstanceRecord[],
): RootCause[] {
  const byCat = new Map<string, InstanceRecord[]>();
  for (const i of instances) {
    if (i.failureCategory === "none" || i.failureCategory === "in-progress") {
      continue;
    }
    const arr = byCat.get(i.failureCategory) ?? [];
    arr.push(i);
    byCat.set(i.failureCategory, arr);
  }
  const out = [...byCat.entries()].map(([failureCategory, arr]) => {
    const accounts = [...new Set(arr.map((i) => i.account))].sort();
    const exampleReason = arr.find((i) => i.statusReason.length > 0)
      ?.statusReason ?? "";
    return {
      failureCategory,
      count: arr.length,
      exampleReason,
      affectedAccounts: accounts.length,
      accounts,
    };
  });
  out.sort((a, b) => b.count - a.count);
  return out;
}

/**
 * Detect cross-instance anti-patterns the per-instance view can't express.
 *
 * - `iam-global-resource-multi-region-collision`: an account succeeded in one
 *   region but hit an IAM name conflict in another — the signature of a
 *   fixed-name global IAM resource deployed to several regions.
 * - `drift-never-detected`: drift has never been measured on the stackset, so
 *   the drift dimension is unknown (not "in sync").
 */
export function detectPatterns(
  instances: InstanceRecord[],
  drift: Drift,
): Pattern[] {
  const patterns: Pattern[] = [];

  const byAccount = new Map<string, { succeeded: string[]; iam: string[] }>();
  for (const i of instances) {
    const e = byAccount.get(i.account) ?? { succeeded: [], iam: [] };
    if (i.detailedStatus === "SUCCEEDED") e.succeeded.push(i.region);
    if (i.failureCategory === "iam-name-conflict") e.iam.push(i.region);
    byAccount.set(i.account, e);
  }
  const collision = [...byAccount.entries()].filter(
    ([, e]) => e.succeeded.length > 0 && e.iam.length > 0,
  );
  if (collision.length > 0) {
    const [exAcct, exRegions] = collision[0];
    patterns.push({
      pattern: "iam-global-resource-multi-region-collision",
      description:
        "A named, global IAM resource (managed policy and/or role) is deployed " +
        "to multiple regions. IAM is global, so only the first region per " +
        "account can create the fixed name; sibling regions fail with " +
        "AlreadyExists. The stackset only needs to succeed in one region per " +
        "account.",
      affectedAccounts: collision.length,
      evidence:
        `${collision.length} account(s) succeeded in one region but hit ` +
        `an IAM name conflict in another (e.g. account ${exAcct} succeeded in ` +
        `[${exRegions.succeeded.join(", ")}], conflicted in ` +
        `[${exRegions.iam.join(", ")}]).`,
    });
  }

  if (
    drift.driftStatus === "NOT_CHECKED" || drift.totalStackInstancesCount === 0
  ) {
    patterns.push({
      pattern: "drift-never-detected",
      description:
        "Drift detection has never run on this stackset, so per-instance " +
        "driftStatus is NOT_CHECKED and the drift posture is unknown — not " +
        "the same as 'in sync'. To populate it, run the separate " +
        "drift-detection sibling extension (it needs write creds) as an " +
        "upstream workflow step before this audit.",
      affectedAccounts: 0,
      evidence:
        `StackSetDriftDetectionDetails.DriftStatus=${drift.driftStatus}, ` +
        `TotalStackInstancesCount=${drift.totalStackInstancesCount}.`,
    });
  }

  return patterns;
}

/**
 * Derive whether it is safe to re-run the stackset, from the operation history,
 * status rollups, and detected patterns. Conservative: an in-flight operation
 * or a known structural conflict blocks a clean reapply.
 */
export function deriveSafeToReapply(input: {
  operations: Operation[];
  byDetailedStatus: Record<string, number>;
  byOverallStatus: Record<string, number>;
  patterns: Pattern[];
}): SafeToReapply {
  const { operations, byDetailedStatus, byOverallStatus, patterns } = input;
  const reasons: string[] = [];
  const remediation: string[] = [];

  const activeOp = operations.find((o) =>
    ["RUNNING", "STOPPING", "QUEUED"].includes(o.status)
  );
  if (activeOp) {
    return {
      verdict: "no",
      reasons: [
        `A stackset operation is currently ${activeOp.status} ` +
        `(${activeOp.operationId}, ${activeOp.action}). Wait for it to reach a ` +
        `terminal state before starting another operation.`,
      ],
      remediation: [],
    };
  }

  let verdict: "yes" | "no" | "caution" | "unknown" = "unknown";

  const collision = patterns.find((p) =>
    p.pattern === "iam-global-resource-multi-region-collision"
  );
  if (collision) {
    verdict = "no";
    reasons.push(
      "Re-running the current template and region targeting reproduces the " +
        "global IAM name collision: only one region per account can create the " +
        "fixed-name policy/role, the rest fail AlreadyExists and re-trip " +
        "failure tolerance.",
    );
    remediation.push(
      "Target ONE region per account for this stackset — IAM is global, so a " +
        "single region creates the role for the whole account.",
    );
    remediation.push(
      "Alternatively drop the fixed names (ManagedPolicyName / RoleName) so each " +
        "region gets a unique auto-generated name — but that leaves duplicate " +
        "roles per account, which the auditor integration does not need.",
    );
    remediation.push(
      "After fixing targeting/names, redeploy; the OUTDATED instances converge " +
        "once the collision is gone.",
    );
  }

  const inoperable = (byOverallStatus["INOPERABLE"] ?? 0) +
    (byDetailedStatus["INOPERABLE"] ?? 0);
  if (inoperable > 0) {
    if (verdict !== "no") verdict = "caution";
    reasons.push(
      `${inoperable} instance(s) are INOPERABLE and need manual remediation ` +
        `(delete or import the stack) before a clean redeploy.`,
    );
  }

  if (verdict === "unknown") {
    const failed = byDetailedStatus["FAILED"] ?? 0;
    const cancelled = byDetailedStatus["CANCELLED"] ?? 0;
    if (failed === 0 && cancelled === 0) {
      verdict = "yes";
      reasons.push(
        "No failed, cancelled, or inoperable instances and no in-flight " +
          "operation; a reapply should converge cleanly.",
      );
    } else {
      verdict = "caution";
      reasons.push(
        `${failed} failed and ${cancelled} cancelled instance(s) exist; review ` +
          `rootCauses before reapplying.`,
      );
    }
  }

  return { verdict, reasons, remediation };
}

/** Stable storage key for an instance row (unique across account/region). */
export function instanceKey(account: string, region: string): string {
  return `instance-${account}-${region}`;
}

/** Coerce an SDK timestamp (Date | string | undefined) to an ISO string or "". */
export function isoOrEmpty(ts: unknown): string {
  if (ts instanceof Date) return ts.toISOString();
  if (typeof ts === "string" && ts.length > 0) return ts;
  return "";
}

// ---------------------------------------------------------------------------
// AWS facade — minimal surface so logic stays testable without the SDK
// ---------------------------------------------------------------------------

/** Minimal stackset shape this extension reads from DescribeStackSet. */
export interface AwsStackSet {
  /** StackSet id (`name:uuid`). */
  StackSetId?: string;
  /** StackSet name. */
  StackSetName?: string;
  /** ACTIVE | DELETED. */
  Status?: string;
  /** Operator description. */
  Description?: string;
  /** SERVICE_MANAGED | SELF_MANAGED. */
  PermissionModel?: string;
  /** Acknowledged capabilities. */
  Capabilities?: string[];
  /** Target OU ids (service-managed). */
  OrganizationalUnitIds?: string[];
  /** Template parameters. */
  Parameters?: { ParameterKey?: string; ParameterValue?: string }[];
  /** Auto-deployment config. */
  AutoDeployment?: {
    Enabled?: boolean;
    RetainStacksOnAccountRemoval?: boolean;
  };
  /** Managed-execution config. */
  ManagedExecution?: { Active?: boolean };
  /** Drift-detection rollup. */
  StackSetDriftDetectionDetails?: {
    DriftStatus?: string;
    TotalStackInstancesCount?: number;
    DriftedStackInstancesCount?: number;
    InSyncStackInstancesCount?: number;
    InProgressStackInstancesCount?: number;
    FailedStackInstancesCount?: number;
    LastDriftCheckTimestamp?: Date | string;
  };
}

/** Minimal stack-instance summary shape from ListStackInstances. */
export interface AwsStackInstanceSummary {
  /** Member account id. */
  Account?: string;
  /** Region. */
  Region?: string;
  /** Physical stack id. */
  StackId?: string;
  /** Overall status: CURRENT | OUTDATED | INOPERABLE. */
  Status?: string;
  /** Status reason. */
  StatusReason?: string;
  /** Detailed last-operation status. */
  StackInstanceStatus?: { DetailedStatus?: string };
  /** OU id (service-managed). */
  OrganizationalUnitId?: string;
  /** Drift status. */
  DriftStatus?: string;
  /** Last drift check timestamp. */
  LastDriftCheckTimestamp?: Date | string;
}

/** Minimal stackset operation summary from ListStackSetOperations. */
export interface AwsOperationSummary {
  /** Operation id. */
  OperationId?: string;
  /** CREATE | UPDATE | DELETE | DETECT_DRIFT. */
  Action?: string;
  /** RUNNING | SUCCEEDED | FAILED | STOPPING | STOPPED | QUEUED. */
  Status?: string;
  /** Start time. */
  CreationTimestamp?: Date | string;
  /** End time. */
  EndTimestamp?: Date | string;
  /** Status reason. */
  StatusReason?: string;
}

/** Facade over the read-only CloudFormation calls this extension uses. */
export interface StackSetApi {
  /** DescribeStackSet for the configured stackset. */
  describeStackSet(): Promise<AwsStackSet>;
  /** All stack-instance summaries (paginated internally). */
  listStackInstances(): Promise<AwsStackInstanceSummary[]>;
  /** The most recent stackset operations, newest first (capped at `limit`). */
  listOperations(limit: number): Promise<AwsOperationSummary[]>;
}

// ---------------------------------------------------------------------------
// SDK-backed facade
// ---------------------------------------------------------------------------

const CLIENT_RETRY = { maxAttempts: 8 } as const;

function sdkApi(
  credentials: CredentialProvider | undefined,
  region: string,
  callAs: "SELF" | "DELEGATED_ADMIN",
  stackSetName: string,
  signal?: AbortSignal,
): StackSetApi {
  const client = new CloudFormationClient({
    region,
    credentials,
    ...CLIENT_RETRY,
  });
  const opts = { abortSignal: signal };

  return {
    describeStackSet: async () => {
      const resp = await client.send(
        new DescribeStackSetCommand({
          StackSetName: stackSetName,
          CallAs: callAs,
        }),
        opts,
      );
      return (resp.StackSet ?? {}) as AwsStackSet;
    },
    listStackInstances: async () => {
      const out: AwsStackInstanceSummary[] = [];
      let token: string | undefined;
      do {
        const resp = await client.send(
          new ListStackInstancesCommand({
            StackSetName: stackSetName,
            CallAs: callAs,
            NextToken: token,
            MaxResults: 100,
          }),
          opts,
        );
        out.push(...((resp.Summaries ?? []) as AwsStackInstanceSummary[]));
        token = resp.NextToken;
      } while (token);
      return out;
    },
    listOperations: async (limit: number) => {
      const out: AwsOperationSummary[] = [];
      let token: string | undefined;
      do {
        const resp = await client.send(
          new ListStackSetOperationsCommand({
            StackSetName: stackSetName,
            CallAs: callAs,
            NextToken: token,
            MaxResults: 50,
          }),
          opts,
        );
        out.push(...((resp.Summaries ?? []) as AwsOperationSummary[]));
        token = resp.NextToken;
      } while (token && out.length < limit);
      return out.slice(0, limit);
    },
  };
}

// ---------------------------------------------------------------------------
// Core audit logic — parameterized on its AWS facade and runtime context
// ---------------------------------------------------------------------------

/** Dependencies for {@link runAudit}. */
export interface AuditDeps {
  /** AWS facade bound to the admin account's credentials. */
  api: StackSetApi;
  /** StackSet name (echoed onto every record). */
  stackSetName: string;
  /** How many recent operations to capture. */
  recentOperations: number;
  /** Swamp method-execution context (host-injected; typed `any`). */
  // deno-lint-ignore no-explicit-any
  context: any;
}

/** Result of {@link runAudit}. */
export interface AuditResult {
  /** Data handles produced, in write order. */
  dataHandles: unknown[];
  /** Number of instance rows written. */
  instanceCount: number;
  /** The derived safe-to-reapply verdict. */
  verdict: string;
}

/**
 * Core `audit` logic. Reads the stackset, every stack instance, and recent
 * operations; classifies each instance; rolls everything up; and writes one
 * `summary` plus one `instance` resource per stack instance.
 *
 * @param deps API facade, stackset name, operation limit, and runtime context.
 * @returns Data handles, instance count, and the reapply verdict.
 */
export async function runAudit(deps: AuditDeps): Promise<AuditResult> {
  const { api, stackSetName, recentOperations, context } = deps;
  const auditedAt = new Date().toISOString();
  const handles: unknown[] = [];

  const ss = await api.describeStackSet();
  const summaries = await api.listStackInstances();
  const ops = await api.listOperations(recentOperations);

  context.logger.info(
    "Audited stackset {name}: {count} instance(s), {ops} recent operation(s)",
    { name: stackSetName, count: summaries.length, ops: ops.length },
  );

  const instances: InstanceRecord[] = summaries.map((s) => {
    const detailedStatus = s.StackInstanceStatus?.DetailedStatus ?? "";
    const statusReason = s.StatusReason ?? "";
    return {
      stackSetName,
      account: s.Account ?? "",
      region: s.Region ?? "",
      detailedStatus,
      overallStatus: s.Status ?? "",
      statusReason,
      driftStatus: s.DriftStatus ?? "",
      lastDriftCheckTimestamp: isoOrEmpty(s.LastDriftCheckTimestamp),
      stackId: s.StackId ?? "",
      organizationalUnitId: s.OrganizationalUnitId ?? "",
      failureCategory: classifyFailure(detailedStatus, statusReason),
      auditedAt,
    };
  });

  const d = ss.StackSetDriftDetectionDetails ?? {};
  const drift = {
    driftStatus: d.DriftStatus ?? "NOT_CHECKED",
    totalStackInstancesCount: d.TotalStackInstancesCount ?? 0,
    driftedStackInstancesCount: d.DriftedStackInstancesCount ?? 0,
    inSyncStackInstancesCount: d.InSyncStackInstancesCount ?? 0,
    inProgressStackInstancesCount: d.InProgressStackInstancesCount ?? 0,
    failedStackInstancesCount: d.FailedStackInstancesCount ?? 0,
    lastDriftCheckTimestamp: isoOrEmpty(d.LastDriftCheckTimestamp),
  };

  const operations = ops.map((o) => ({
    operationId: o.OperationId ?? "",
    action: o.Action ?? "",
    status: o.Status ?? "",
    creationTimestamp: isoOrEmpty(o.CreationTimestamp),
    endTimestamp: isoOrEmpty(o.EndTimestamp),
    statusReason: o.StatusReason ?? "",
  }));

  const byDetailedStatus = countBy(
    instances,
    (i) => i.detailedStatus || "UNKNOWN",
  );
  const byOverallStatus = countBy(
    instances,
    (i) => i.overallStatus || "UNKNOWN",
  );
  const byRegion = countBy(instances, (i) => i.region || "UNKNOWN");
  const byDriftStatus = countBy(instances, (i) => i.driftStatus || "UNKNOWN");
  const byFailureCategory = countBy(instances, (i) => i.failureCategory);
  const rootCauses = buildRootCauses(instances);
  const detectedPatterns = detectPatterns(instances, drift);
  const safeToReapply = deriveSafeToReapply({
    operations,
    byDetailedStatus,
    byOverallStatus,
    patterns: detectedPatterns,
  });

  const regions = [...new Set(instances.map((i) => i.region).filter(Boolean))]
    .sort();
  const accountsTargeted =
    new Set(instances.map((i) => i.account).filter(Boolean)).size;

  const summary = {
    stackSetName,
    stackSetId: ss.StackSetId ?? "",
    status: ss.Status ?? "",
    permissionModel: ss.PermissionModel ?? "",
    description: ss.Description ?? "",
    organizationalUnitIds: ss.OrganizationalUnitIds ?? [],
    capabilities: ss.Capabilities ?? [],
    autoDeploymentEnabled: ss.AutoDeployment?.Enabled ?? false,
    managedExecutionActive: ss.ManagedExecution?.Active ?? false,
    parameters: (ss.Parameters ?? []).map((p) => ({
      key: p.ParameterKey ?? "",
      value: p.ParameterValue ?? "",
    })),
    drift,
    regions,
    accountsTargeted,
    instanceCount: instances.length,
    byDetailedStatus,
    byOverallStatus,
    byRegion,
    byDriftStatus,
    byFailureCategory,
    operations,
    rootCauses,
    detectedPatterns,
    safeToReapply,
    auditedAt,
  };

  handles.push(await context.writeResource("summary", "summary", summary));
  for (const inst of instances) {
    handles.push(
      await context.writeResource(
        "instance",
        instanceKey(inst.account, inst.region),
        inst,
      ),
    );
  }

  context.logger.info(
    "stackset-audit complete: verdict={verdict}, {count} instance row(s) written",
    { verdict: safeToReapply.verdict, count: instances.length },
  );

  return {
    dataHandles: handles,
    instanceCount: instances.length,
    verdict: safeToReapply.verdict,
  };
}

// ---------------------------------------------------------------------------
// Credential + facade construction
// ---------------------------------------------------------------------------

function apiFromGlobals(g: GlobalArgs, signal?: AbortSignal): StackSetApi {
  const credentials = g.profile.length > 0
    ? fromIni({ profile: g.profile })
    : undefined;
  return sdkApi(credentials, g.region, g.callAs, g.stackSetName, signal);
}

// ---------------------------------------------------------------------------
// Model export
// ---------------------------------------------------------------------------

/**
 * The `@jentz/aws-stackset-audit` model.
 *
 * A single read-only method, `audit`, is the fan-out sweep that builds the data
 * model: it describes the stackset, paginates every stack instance, and reads
 * recent operations, then writes one `summary` and one `instance` row per stack
 * instance. It reports each instance's existing drift status as returned by the
 * StackSet API — it never triggers a fresh drift-detection run. Measuring drift
 * is a separate, mutating capability shipped as a sibling extension; compose the
 * two in a swamp workflow (drift-detect step first, then this `audit` step with
 * `dependsOn: succeeded`).
 */
export const model = {
  type: "@jentz/aws-stackset-audit",
  version: "2026.06.22.0",
  globalArguments: GlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.06.13.0",
      description: "Initial publish",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.22.0",
      description: "Dependency refresh, no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    summary: {
      description:
        "StackSet-level audit: config, drift rollup, per-dimension counts, " +
        "recent operations, ranked root causes, detected anti-patterns, and a " +
        "derived safe-to-reapply verdict.",
      schema: SummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    instance: {
      description:
        "One stack instance (account, region) with its deployment status, " +
        "status reason, drift status, stack id, OU, and normalized " +
        "failureCategory.",
      schema: InstanceRecordSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    audit: {
      description: "Read-only fan-out sweep: DescribeStackSet + paginated " +
        "ListStackInstances + recent ListStackSetOperations. Writes one " +
        "summary and one instance row per stack instance. Reports each " +
        "instance's existing drift status only; it never triggers fresh drift " +
        "detection (that is the separate drift-detection sibling extension).",
      arguments: z.object({
        recentOperations: z.number().int().min(1).max(100).default(15)
          .describe("How many recent stackset operations to capture."),
      }),
      execute: (
        args: { recentOperations: number },
        // deno-lint-ignore no-explicit-any
        context: any,
      ): Promise<AuditResult> => {
        const g = GlobalArgsSchema.parse(context.globalArgs);
        return runAudit({
          api: apiFromGlobals(g, context.signal),
          stackSetName: g.stackSetName,
          recentOperations: args.recentOperations ?? 15,
          context,
        });
      },
    },
  },
};
