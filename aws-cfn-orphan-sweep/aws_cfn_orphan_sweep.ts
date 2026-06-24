/**
 * `@jentz/aws-cfn-orphan-sweep` — find and (optionally) clean up standalone
 * CloudFormation stacks left behind by a retired StackSet, fleet-wide.
 *
 * When a StackSet is retired with `delete-stack-instances --retain-stacks`, the
 * StackSet records are dropped but the per-account/region member stacks remain
 * as ordinary standalone stacks named `StackSet-<setname>-<guid>`. The official
 * `@swamp/aws/cloudformation/stack` type is single-stack CRUD with no
 * list-by-prefix and no `RetainResources` on delete, and `@jentz/aws-stackset-audit`
 * only sees instances of a *live* StackSet — neither can find or safely remove
 * these orphans. This model fills that gap.
 *
 * It is account-scoped: it runs against whatever credentials are in the ambient
 * chain (the `*-devops` / `*-readonly` SSO creds exported into the environment),
 * resolves its own account id via STS, and fans out across the configured
 * `regions` in one locked execution (repo rule 6). Run it once per account; each
 * run writes rows keyed by account+region+stack so a single model instance
 * accumulates the whole fleet, queryable via CEL.
 *
 * Two methods:
 *
 *   - `enumerate` (READ-ONLY): `ListStacks` per region (every status except
 *     DELETE_COMPLETE), keep names starting with `namePrefix`, and
 *     `ListStackResources` on each match to capture the custom-resource logical
 *     id to retain, the IAM role logical id + physical name (the audit smell we
 *     want gone), and the Lambda. Writes one `orphan` row per stack plus one
 *     per-account `summary`. Safe under a `*-readonly` profile.
 *
 *   - `cleanup` (MUTATING; dry-run unless `apply=true`): for each orphan,
 *     `DeleteStack` retaining ONLY the dead `Custom::*` resource (so the broken
 *     Lambda is never invoked) while CloudFormation still deletes the Lambda and
 *     its IAM role. Polls to terminal, then verifies the IAM role is gone via
 *     `GetRole` → NoSuchEntity. Refuses any stack whose name does not match
 *     `namePrefix`, and refuses to retain anything that is not the detected
 *     custom resource. Needs `cloudformation:DeleteStack` + `iam:GetRole`, so it
 *     runs from a `*-devops` profile, never a read-only one.
 *
 * @module
 */

import { z } from "npm:zod@4";
import {
  CloudFormationClient,
  DeleteStackCommand,
  DescribeStacksCommand,
  ListStackResourcesCommand,
  ListStacksCommand,
} from "npm:@aws-sdk/client-cloudformation@3.1021.0";
import { GetRoleCommand, IAMClient } from "npm:@aws-sdk/client-iam@3.1021.0";
import {
  DeleteFunctionCommand,
  LambdaClient,
} from "npm:@aws-sdk/client-lambda@3.1021.0";
import {
  GetCallerIdentityCommand,
  STSClient,
} from "npm:@aws-sdk/client-sts@3.1021.0";
import { fromIni } from "npm:@aws-sdk/credential-providers@3.1021.0";

/** Credential provider as returned by `fromIni`; `undefined` means the ambient chain. */
type CredentialProvider = ReturnType<typeof fromIni>;

// ---------------------------------------------------------------------------
// Global arguments
// ---------------------------------------------------------------------------

/** Every CloudFormation StackStatus except DELETE_COMPLETE — what `enumerate` scans. */
const ACTIVE_STATUS_FILTER = [
  "CREATE_IN_PROGRESS",
  "CREATE_FAILED",
  "CREATE_COMPLETE",
  "ROLLBACK_IN_PROGRESS",
  "ROLLBACK_FAILED",
  "ROLLBACK_COMPLETE",
  "DELETE_IN_PROGRESS",
  "DELETE_FAILED",
  "UPDATE_IN_PROGRESS",
  "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
  "UPDATE_COMPLETE",
  "UPDATE_FAILED",
  "UPDATE_ROLLBACK_IN_PROGRESS",
  "UPDATE_ROLLBACK_FAILED",
  "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
  "UPDATE_ROLLBACK_COMPLETE",
  "REVIEW_IN_PROGRESS",
  "IMPORT_IN_PROGRESS",
  "IMPORT_COMPLETE",
  "IMPORT_ROLLBACK_IN_PROGRESS",
  "IMPORT_ROLLBACK_FAILED",
  "IMPORT_ROLLBACK_COMPLETE",
] as const;

const DEFAULT_REGIONS = [
  "us-east-1",
  "eu-west-1",
  "eu-central-1",
  "eu-north-1",
];

const GlobalArgsSchema = z.object({
  namePrefix: z.string().min(1).default("StackSet-IAMCustomPasswordPolicy-")
    .describe(
      "Only stacks whose name starts with this prefix are enumerated and " +
        "(ever) considered for deletion. The orphan-stack guard keys off this.",
    ),
  regions: z.array(z.string().min(1)).min(1).default(DEFAULT_REGIONS).describe(
    "Regions to fan out across in one execution.",
  ),
  profile: z.string().default("").describe(
    "Named AWS profile (resolved via fromIni). Empty (default) uses the " +
      "ambient credential chain — the SSO creds exported into AWS_* env vars.",
  ),
});

/**
 * Resolved global arguments — the parsed shape of the global-args schema, with
 * every field defaulted. Exposed on {@link EnumerateDeps} and
 * {@link CleanupDeps}.
 *
 * Declared as an explicit interface (rather than `z.infer`) so the public API
 * does not leak zod's internal types; a compile-time check below keeps it in
 * exact sync with the schema's inferred output.
 */
export interface GlobalArgs {
  /**
   * Only stacks whose name starts with this prefix are enumerated and (ever)
   * considered for deletion. The orphan-stack guard keys off this.
   */
  namePrefix: string;
  /** Regions to fan out across in one execution. */
  regions: string[];
  /**
   * Named AWS profile (resolved via `fromIni`). Empty uses the ambient
   * credential chain — the SSO creds exported into `AWS_*` env vars.
   */
  profile: string;
}

// Compile-time guard: the explicit interface and the schema's inferred output
// must be assignable in both directions. If the schema gains, drops, or
// retypes a field, one of these type aliases fails to type-check. Emits no
// runtime code.
type _AssertExtends<A extends B, B> = true;
type _SchemaToInterface = _AssertExtends<
  z.infer<typeof GlobalArgsSchema>,
  GlobalArgs
>;
type _InterfaceToSchema = _AssertExtends<
  GlobalArgs,
  z.infer<typeof GlobalArgsSchema>
>;

// ---------------------------------------------------------------------------
// Resource schemas
// ---------------------------------------------------------------------------

const ResourceRefSchema = z.object({
  logicalId: z.string(),
  physicalId: z.string(),
  type: z.string(),
  status: z.string(),
});

const OrphanSchema = z.object({
  account: z.string(),
  region: z.string(),
  stackName: z.string(),
  stackId: z.string(),
  stackStatus: z.string(),
  statusReason: z.string(),
  creationTime: z.string(),
  /** Logical id of the (dead) custom resource to retain on delete, or "". */
  customResourceLogicalId: z.string(),
  customResourceType: z.string(),
  /** Logical id of the IAM role the stack created, or "". */
  iamRoleLogicalId: z.string(),
  /** Physical name of that role — the handle used to verify it is gone. */
  iamRolePhysicalName: z.string(),
  lambdaLogicalId: z.string(),
  resourceCount: z.number(),
  resources: z.array(ResourceRefSchema),
  scannedAt: z.iso.datetime(),
}).passthrough();

const SummarySchema = z.object({
  account: z.string(),
  regionsScanned: z.array(z.string()),
  orphanCount: z.number(),
  byRegion: z.record(z.string(), z.number()),
  byStatus: z.record(z.string(), z.number()),
  deleteFailed: z.array(z.string()),
  scannedAt: z.iso.datetime(),
}).passthrough();

const DeletionSchema = z.object({
  account: z.string(),
  region: z.string(),
  stackName: z.string(),
  stackId: z.string(),
  /**
   * Planned or performed action. Dry-run: "skip" | "would-initiate-delete" |
   * "would-retain-delete" | "would-wait". Apply: "delete-initiated" |
   * "delete-in-progress" | "delete-retain" | "already-gone" | "skip" | "error".
   */
  action: z.string(),
  retainedResources: z.array(z.string()),
  finalStatus: z.string(),
  gone: z.boolean(),
  roleChecked: z.boolean(),
  roleGone: z.boolean(),
  iamRolePhysicalName: z.string(),
  error: z.string(),
  startedAt: z.iso.datetime(),
  finishedAt: z.iso.datetime(),
}).passthrough();

// ---------------------------------------------------------------------------
// Public resource shapes (explicit interfaces — deno doc --lint friendly)
// ---------------------------------------------------------------------------

/** One CloudFormation resource reference captured from ListStackResources. */
export interface ResourceRef {
  /** Template logical id. */
  logicalId: string;
  /** Physical resource id / name in the account. */
  physicalId: string;
  /** CloudFormation resource type, e.g. `AWS::IAM::Role`. */
  type: string;
  /** Resource status, e.g. `CREATE_COMPLETE` / `DELETE_FAILED`. */
  status: string;
}

/** One orphaned standalone stack found by {@link runEnumerate}. */
export interface Orphan {
  /** 12-digit account id (resolved from the active creds). */
  account: string;
  /** Region the stack lives in. */
  region: string;
  /** Stack name. */
  stackName: string;
  /** Physical stack id (ARN). */
  stackId: string;
  /** Current stack status. */
  stackStatus: string;
  /** Status reason, or "". */
  statusReason: string;
  /** ISO 8601 creation time, or "". */
  creationTime: string;
  /** Logical id of the dead custom resource to retain on delete, or "". */
  customResourceLogicalId: string;
  /** Custom resource type, or "". */
  customResourceType: string;
  /** Logical id of the stack's IAM role, or "". */
  iamRoleLogicalId: string;
  /** Physical name of that role — used to verify removal, or "". */
  iamRolePhysicalName: string;
  /** Logical id of the stack's Lambda, or "". */
  lambdaLogicalId: string;
  /** Total resource count. */
  resourceCount: number;
  /** All resource references. */
  resources: ResourceRef[];
  /** ISO 8601 scan timestamp. */
  scannedAt: string;
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit-test access)
// ---------------------------------------------------------------------------

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

/** Reduce arbitrary target text to a safe data-name segment. */
export function safeNameSegment(s: string): string {
  const slug = s.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/-{2,}/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "").slice(0, 90);
  return slug.length > 0 ? slug : "x";
}

/** Stable storage key for an orphan row (unique across account/region/stack). */
export function orphanKey(
  o: { account: string; region: string; stackName: string },
): string {
  return `orphan-${o.account}-${o.region}-${safeNameSegment(o.stackName)}`;
}

/**
 * Guard: an orphan stack is only deletable if its name starts with the
 * configured prefix. Returns "" when allowed, else a refusal reason.
 */
export function stackRefusalReason(
  stackName: string,
  namePrefix: string,
): string {
  if (stackName.startsWith(namePrefix)) return "";
  return `stack '${stackName}' does not start with the configured prefix ` +
    `'${namePrefix}' — refusing to touch it`;
}

/**
 * Decide what to retain on delete. We retain exactly the detected custom
 * resource (so the dead Lambda is never invoked) and nothing else. An override
 * is honored only if it matches the detected custom-resource logical id.
 * Returns `{ retain, reason }`; a non-empty `reason` means refuse.
 */
export function computeRetain(
  resources: ResourceRef[],
  override: string,
): { retain: string[]; reason: string } {
  const customIds = resources
    .filter((r) =>
      r.type.startsWith("Custom::") ||
      r.type === "AWS::CloudFormation::CustomResource"
    )
    .map((r) => r.logicalId);
  const failedCustom = resources
    .filter((r) =>
      r.status.includes("DELETE_FAILED") && customIds.includes(r.logicalId)
    )
    .map((r) => r.logicalId);

  let retain = failedCustom.length > 0
    ? failedCustom
    : (customIds.length > 0 ? [customIds[0]] : []);

  if (override.length > 0) {
    if (!customIds.includes(override)) {
      return {
        retain: [],
        reason: `retainLogicalId='${override}' is not a custom resource in ` +
          `this stack (${customIds.join(", ") || "none"}) — refusing`,
      };
    }
    retain = [override];
  }

  // Safety: only ever retain Custom:: resources, so the IAM role and Lambda
  // are always deleted. Refuse if anything else slipped in.
  const bad = retain.filter((id) => !customIds.includes(id));
  if (bad.length > 0) {
    return {
      retain: [],
      reason: `refusing to retain non-custom resource(s): ${bad.join(", ")}`,
    };
  }
  return { retain, reason: "" };
}

/** Pick the salient resources (custom resource, IAM role, Lambda) from a list. */
export function classifyResources(resources: ResourceRef[]): {
  customResourceLogicalId: string;
  customResourceType: string;
  iamRoleLogicalId: string;
  iamRolePhysicalName: string;
  lambdaLogicalId: string;
} {
  const custom = resources.find((r) =>
    r.type.startsWith("Custom::") ||
    r.type === "AWS::CloudFormation::CustomResource"
  );
  const role = resources.find((r) => r.type === "AWS::IAM::Role");
  const lambda = resources.find((r) => r.type === "AWS::Lambda::Function");
  return {
    customResourceLogicalId: custom?.logicalId ?? "",
    customResourceType: custom?.type ?? "",
    iamRoleLogicalId: role?.logicalId ?? "",
    iamRolePhysicalName: role?.physicalId ?? "",
    lambdaLogicalId: lambda?.logicalId ?? "",
  };
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

/** Minimal stack summary from ListStacks. */
export interface StackSummary {
  /** Stack name, as returned by ListStacks. */
  StackName?: string;
  /** Physical stack id (ARN). */
  StackId?: string;
  /** Current CloudFormation stack status. */
  StackStatus?: string;
  /** Reason for the current status, when AWS provides one. */
  StackStatusReason?: string;
  /** Creation time (SDK `Date`, or a string from a replayed fixture). */
  CreationTime?: Date | string;
}

/** Facade over the AWS calls this extension uses, for one account. */
export interface SweepApi {
  /** Resolve the account id for the active credentials. */
  getAccountId(): Promise<string>;
  /** List stacks in a region (active statuses only), paginated. */
  listStacks(region: string): Promise<StackSummary[]>;
  /** List a stack's resources (logical id, physical id, type, status). */
  listStackResources(stackName: string, region: string): Promise<ResourceRef[]>;
  /** Current stack status, or null if the stack does not exist. */
  describeStackStatus(
    stackName: string,
    region: string,
  ): Promise<string | null>;
  /** Issue a DeleteStack, retaining the given logical ids. */
  deleteStack(
    stackName: string,
    region: string,
    retain: string[],
  ): Promise<void>;
  /** Delete a Lambda function by name (no-op if already gone). */
  deleteFunction(functionName: string, region: string): Promise<void>;
  /** Whether an IAM role still exists (by physical name). */
  roleExists(roleName: string): Promise<boolean>;
}

const CLIENT_RETRY = { maxAttempts: 6 } as const;

function isDoesNotExist(err: unknown): boolean {
  const name = (err as { name?: string } | null)?.name ?? "";
  const message = err instanceof Error ? err.message : String(err);
  return name === "ValidationError" && message.includes("does not exist");
}

function sdkApi(
  credentials: CredentialProvider | undefined,
  iamRegion: string,
  signal?: AbortSignal,
): SweepApi {
  const cfnClients = new Map<string, CloudFormationClient>();
  const cfn = (region: string): CloudFormationClient => {
    let c = cfnClients.get(region);
    if (!c) {
      c = new CloudFormationClient({ region, credentials, ...CLIENT_RETRY });
      cfnClients.set(region, c);
    }
    return c;
  };
  const lambdaClients = new Map<string, LambdaClient>();
  const lambda = (region: string): LambdaClient => {
    let c = lambdaClients.get(region);
    if (!c) {
      c = new LambdaClient({ region, credentials, ...CLIENT_RETRY });
      lambdaClients.set(region, c);
    }
    return c;
  };
  const sts = new STSClient({
    region: iamRegion,
    credentials,
    ...CLIENT_RETRY,
  });
  const iam = new IAMClient({
    region: iamRegion,
    credentials,
    ...CLIENT_RETRY,
  });
  const opts = { abortSignal: signal };

  return {
    getAccountId: async () => {
      const resp = await sts.send(new GetCallerIdentityCommand({}), opts);
      return resp.Account ?? "";
    },
    listStacks: async (region) => {
      const out: StackSummary[] = [];
      let token: string | undefined;
      do {
        const resp = await cfn(region).send(
          new ListStacksCommand({
            StackStatusFilter: [...ACTIVE_STATUS_FILTER],
            NextToken: token,
          }),
          opts,
        );
        out.push(...((resp.StackSummaries ?? []) as StackSummary[]));
        token = resp.NextToken;
      } while (token);
      return out;
    },
    listStackResources: async (stackName, region) => {
      const out: ResourceRef[] = [];
      let token: string | undefined;
      do {
        const resp = await cfn(region).send(
          new ListStackResourcesCommand({
            StackName: stackName,
            NextToken: token,
          }),
          opts,
        );
        for (const r of resp.StackResourceSummaries ?? []) {
          out.push({
            logicalId: r.LogicalResourceId ?? "",
            physicalId: r.PhysicalResourceId ?? "",
            type: r.ResourceType ?? "",
            status: r.ResourceStatus ?? "",
          });
        }
        token = resp.NextToken;
      } while (token);
      return out;
    },
    describeStackStatus: async (stackName, region) => {
      try {
        const resp = await cfn(region).send(
          new DescribeStacksCommand({ StackName: stackName }),
          opts,
        );
        return resp.Stacks?.[0]?.StackStatus ?? null;
      } catch (err) {
        if (isDoesNotExist(err)) return null;
        throw err;
      }
    },
    deleteStack: async (stackName, region, retain) => {
      await cfn(region).send(
        new DeleteStackCommand({
          StackName: stackName,
          RetainResources: retain.length > 0 ? retain : undefined,
        }),
        opts,
      );
    },
    deleteFunction: async (functionName, region) => {
      try {
        await lambda(region).send(
          new DeleteFunctionCommand({ FunctionName: functionName }),
          opts,
        );
      } catch (err) {
        const name = (err as { name?: string } | null)?.name ?? "";
        if (name === "ResourceNotFoundException") return; // already gone
        throw err;
      }
    },
    roleExists: async (roleName) => {
      if (roleName.length === 0) return false;
      try {
        await iam.send(new GetRoleCommand({ RoleName: roleName }), opts);
        return true;
      } catch (err) {
        const name = (err as { name?: string } | null)?.name ?? "";
        if (name === "NoSuchEntityException" || name === "NoSuchEntity") {
          return false;
        }
        throw err;
      }
    },
  };
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      reject(new Error("aborted"));
    }, { once: true });
  });
}

// ---------------------------------------------------------------------------
// enumerate (read-only)
// ---------------------------------------------------------------------------

/** Dependencies for {@link runEnumerate}. */
export interface EnumerateDeps {
  /** AWS facade used to list stacks and their resources. */
  api: SweepApi;
  /** Resolved global arguments (prefix, regions, profile). */
  globals: GlobalArgs;
  /** The swamp method context (logger, `writeResource`, abort signal). */
  // deno-lint-ignore no-explicit-any
  context: any;
}

/** Result of {@link runEnumerate}. */
export interface EnumerateResult {
  /** Handles for the written `orphan` and `summary` rows. */
  dataHandles: unknown[];
  /** The account id the sweep ran against. */
  account: string;
  /** Number of orphan stacks found. */
  orphanCount: number;
  /** The orphan rows, in scan order. */
  orphans: Orphan[];
}

/**
 * READ-ONLY fan-out: list stacks in every configured region, keep those whose
 * name starts with `namePrefix`, capture each stack's resources, and write one
 * `orphan` row per match plus one per-account `summary`.
 */
export async function runEnumerate(
  deps: EnumerateDeps,
): Promise<EnumerateResult> {
  const { api, globals, context } = deps;
  const scannedAt = new Date().toISOString();
  const handles: unknown[] = [];

  const account = await api.getAccountId();
  const orphans: Orphan[] = [];

  for (const region of globals.regions) {
    const stacks = await api.listStacks(region);
    const matches = stacks.filter((s) =>
      (s.StackName ?? "").startsWith(globals.namePrefix)
    );
    context.logger.info(
      "Scanned {region} in {account}: {matched}/{total} stack(s) match '{prefix}'",
      {
        region,
        account,
        matched: matches.length,
        total: stacks.length,
        prefix: globals.namePrefix,
      },
    );
    for (const s of matches) {
      const stackName = s.StackName ?? "";
      const resources = await api.listStackResources(stackName, region);
      const c = classifyResources(resources);
      orphans.push({
        account,
        region,
        stackName,
        stackId: s.StackId ?? "",
        stackStatus: s.StackStatus ?? "",
        statusReason: s.StackStatusReason ?? "",
        creationTime: isoOrEmpty(s.CreationTime),
        customResourceLogicalId: c.customResourceLogicalId,
        customResourceType: c.customResourceType,
        iamRoleLogicalId: c.iamRoleLogicalId,
        iamRolePhysicalName: c.iamRolePhysicalName,
        lambdaLogicalId: c.lambdaLogicalId,
        resourceCount: resources.length,
        resources,
        scannedAt,
      });
    }
  }

  for (const o of orphans) {
    handles.push(await context.writeResource("orphan", orphanKey(o), o));
  }

  const summary = {
    account,
    regionsScanned: globals.regions,
    orphanCount: orphans.length,
    byRegion: countBy(orphans, (o) => o.region),
    byStatus: countBy(orphans, (o) => o.stackStatus || "UNKNOWN"),
    deleteFailed: orphans.filter((o) => o.stackStatus === "DELETE_FAILED").map(
      (o) => o.stackName,
    ),
    scannedAt,
  };
  handles.push(
    await context.writeResource("summary", `summary-${account}`, summary),
  );

  context.logger.info(
    "enumerate complete for {account}: {count} orphan stack(s)",
    { account, count: orphans.length },
  );

  return {
    dataHandles: handles,
    account,
    orphanCount: orphans.length,
    orphans,
  };
}

// ---------------------------------------------------------------------------
// cleanup (mutating; dry-run unless apply=true)
// ---------------------------------------------------------------------------

/** Arguments for the `cleanup` method. */
export interface CleanupArgs {
  /** When false, dry-run (write plan rows, mutate nothing); true to delete. */
  apply: boolean;
  /** If set, refuse to run unless the resolved account id matches. */
  expectAccount: string;
  /** If set, only act on orphans in this region. */
  onlyRegion: string;
  /** If set, only act on this exact stack name. */
  onlyStack: string;
  /** Override the retained logical id; honored only if it is the custom resource. */
  retainLogicalId: string;
  /** Seconds between `DescribeStacks` polls while waiting for deletion. */
  waitSeconds: number;
  /** Maximum polls before giving up on a delete. */
  maxWaits: number;
  /** After delete, `GetRole` on the captured role name to confirm removal. */
  verifyRole: boolean;
  /** Fire the delete and return without polling to completion. */
  initiateOnly: boolean;
  /** Delete the backing Lambda first so the custom resource deletes cleanly. */
  predeleteLambda: boolean;
}

/** Dependencies for {@link runCleanup}. */
export interface CleanupDeps {
  /** AWS facade used to enumerate, delete, and verify resources. */
  api: SweepApi;
  /** Resolved global arguments (prefix, regions, profile). */
  globals: GlobalArgs;
  /** The per-run cleanup arguments. */
  args: CleanupArgs;
  /** The swamp method context (logger, `writeResource`, abort signal). */
  // deno-lint-ignore no-explicit-any
  context: any;
}

/** Result of {@link runCleanup}. */
export interface CleanupResult {
  /** Handles for the written `deletion` rows. */
  dataHandles: unknown[];
  /** The account id the cleanup ran against. */
  account: string;
  /** Whether the run actually mutated (`apply=true`) or was a dry-run. */
  applied: boolean;
  /** Number of target stacks considered after scoping filters. */
  considered: number;
  /** Number of stacks confirmed gone. */
  deleted: number;
  /** Number of stacks whose delete was initiated but not confirmed complete. */
  initiated: number;
  /** Number of stacks skipped (e.g. refused by the prefix guard). */
  skipped: number;
  /** Number of stacks that errored during processing. */
  errors: number;
}

/** Outcome of processing one stack through the delete state machine. */
export interface StackOutcome {
  /** What happened, e.g. `delete-retain`, `delete-initiated`, `already-gone`, `skip`, `error`. */
  action: string;
  /** Logical ids retained on the delete (only ever the custom resource). */
  retain: string[];
  /** Final observed stack status, or `GONE`. */
  finalStatus: string;
  /** Whether the stack is gone. */
  gone: boolean;
  /** Whether the IAM role was checked (per `verifyRole`). */
  roleChecked: boolean;
  /** Whether the IAM role is gone (only meaningful when `roleChecked`). */
  roleGone: boolean;
  /** Refusal or error reason, or "". */
  error: string;
}

/**
 * MUTATING (when `apply=true`). Re-enumerates orphans live, then runs the
 * correct delete for each stack's current state — AWS only accepts
 * `RetainResources` on a stack that is already `DELETE_FAILED`:
 *
 *   - healthy (CREATE/UPDATE_COMPLETE …): pass 1 — a plain `DeleteStack` with no
 *     retain. The dead custom resource stalls the delete until CloudFormation
 *     times it out to `DELETE_FAILED`.
 *   - `DELETE_FAILED`: pass 2 — `DeleteStack` retaining only the failed custom
 *     resource, so the Lambda and IAM role are deleted and the stack completes.
 *   - `DELETE_IN_PROGRESS`: a pass 1 is already running; wait or report.
 *
 * Unless `initiateOnly` is set, one run drives a stack through pass 1 →
 * `DELETE_FAILED` → pass 2 → gone within its wait budget; if the budget runs
 * out it records `delete-initiated`/`delete-retain` and is safe to re-run
 * (idempotent — already-gone stacks are skipped). With `initiateOnly` it fires
 * pass 1 and returns immediately, for fast fleet fan-out (re-run later for
 * pass 2). With `apply=false` it writes plan rows and touches nothing.
 */
export async function runCleanup(deps: CleanupDeps): Promise<CleanupResult> {
  const { api, globals, args, context } = deps;
  const handles: unknown[] = [];

  const account = await api.getAccountId();
  if (args.expectAccount.length > 0 && args.expectAccount !== account) {
    throw new Error(
      `expectAccount='${args.expectAccount}' but the active credentials are ` +
        `for account '${account}' — refusing to run`,
    );
  }

  const { orphans } = await runEnumerateInline(api, globals, context);
  let targets = orphans;
  if (args.onlyRegion.length > 0) {
    targets = targets.filter((o) => o.region === args.onlyRegion);
  }
  if (args.onlyStack.length > 0) {
    targets = targets.filter((o) => o.stackName === args.onlyStack);
  }

  context.logger.info(
    "cleanup ({mode}{io}) for {account}: {n} target stack(s)",
    {
      mode: args.apply ? "APPLY" : "dry-run",
      io: args.initiateOnly ? ", initiate-only" : "",
      account,
      n: targets.length,
    },
  );

  let deleted = 0, initiated = 0, skipped = 0, errors = 0;

  for (const o of targets) {
    const startedAt = new Date().toISOString();
    const refusal = stackRefusalReason(o.stackName, globals.namePrefix);
    if (refusal.length > 0) {
      skipped++;
      handles.push(
        await writeDeletion(context, o, {
          action: "skip",
          retainedResources: [],
          finalStatus: o.stackStatus,
          gone: false,
          roleChecked: false,
          roleGone: false,
          error: refusal,
          startedAt,
        }),
      );
      continue;
    }

    if (!args.apply) {
      const isFailed = o.stackStatus === "DELETE_FAILED";
      const planned = isFailed
        ? "would-retain-delete"
        : (o.stackStatus.startsWith("DELETE_IN_PROGRESS")
          ? "would-wait"
          : "would-initiate-delete");
      const { retain } = computeRetain(o.resources, args.retainLogicalId);
      handles.push(
        await writeDeletion(context, o, {
          action: planned,
          retainedResources: isFailed ? retain : [],
          finalStatus: o.stackStatus,
          gone: false,
          roleChecked: false,
          roleGone: false,
          error: "",
          startedAt,
        }),
      );
      continue;
    }

    try {
      const r = await processStack(api, o, args, context);
      if (r.gone) deleted++;
      else if (
        r.action === "delete-initiated" || r.action === "delete-in-progress"
      ) initiated++;
      else if (r.error.length > 0) errors++;
      handles.push(
        await writeDeletion(context, o, {
          action: r.action,
          retainedResources: r.retain,
          finalStatus: r.finalStatus,
          gone: r.gone,
          roleChecked: r.roleChecked,
          roleGone: r.roleGone,
          error: r.error,
          startedAt,
        }),
      );
      context.logger.info(
        "{stack} in {account}/{region}: action={action} final={final} gone={gone} roleGone={roleGone}",
        {
          stack: o.stackName,
          account,
          region: o.region,
          action: r.action,
          final: r.finalStatus,
          gone: r.gone,
          roleGone: r.roleGone,
        },
      );
    } catch (err) {
      errors++;
      handles.push(
        await writeDeletion(context, o, {
          action: "error",
          retainedResources: [],
          finalStatus: "UNKNOWN",
          gone: false,
          roleChecked: false,
          roleGone: false,
          error: err instanceof Error ? err.message : String(err),
          startedAt,
        }),
      );
    }
  }

  context.logger.info(
    "cleanup complete for {account}: considered={c} deleted={d} initiated={i} skipped={s} errors={e} applied={a}",
    {
      account,
      c: targets.length,
      d: deleted,
      i: initiated,
      s: skipped,
      e: errors,
      a: args.apply,
    },
  );

  return {
    dataHandles: handles,
    account,
    applied: args.apply,
    considered: targets.length,
    deleted,
    initiated,
    skipped,
    errors,
  };
}

/** Run the enumeration logic without writing `orphan`/`summary` rows. */
async function runEnumerateInline(
  api: SweepApi,
  globals: GlobalArgs,
  // deno-lint-ignore no-explicit-any
  _context: any,
): Promise<{ account: string; orphans: Orphan[] }> {
  const scannedAt = new Date().toISOString();
  const account = await api.getAccountId();
  const orphans: Orphan[] = [];
  for (const region of globals.regions) {
    const stacks = await api.listStacks(region);
    for (const s of stacks) {
      const stackName = s.StackName ?? "";
      if (!stackName.startsWith(globals.namePrefix)) continue;
      const resources = await api.listStackResources(stackName, region);
      const c = classifyResources(resources);
      orphans.push({
        account,
        region,
        stackName,
        stackId: s.StackId ?? "",
        stackStatus: s.StackStatus ?? "",
        statusReason: s.StackStatusReason ?? "",
        creationTime: isoOrEmpty(s.CreationTime),
        customResourceLogicalId: c.customResourceLogicalId,
        customResourceType: c.customResourceType,
        iamRoleLogicalId: c.iamRoleLogicalId,
        iamRolePhysicalName: c.iamRolePhysicalName,
        lambdaLogicalId: c.lambdaLogicalId,
        resourceCount: resources.length,
        resources,
        scannedAt,
      });
    }
  }
  return { account, orphans };
}

/** Verify the captured IAM role is gone (when verifyRole is on and we have a name). */
async function checkRole(
  api: SweepApi,
  o: Orphan,
  args: CleanupArgs,
): Promise<{ roleChecked: boolean; roleGone: boolean }> {
  if (args.verifyRole && o.iamRolePhysicalName.length > 0) {
    const exists = await api.roleExists(o.iamRolePhysicalName);
    return { roleChecked: true, roleGone: !exists };
  }
  return { roleChecked: false, roleGone: false };
}

/**
 * Drive one stack through the delete state machine: fire pass 1 on a healthy
 * stack, then (unless initiateOnly) poll until DELETE_FAILED and fire pass 2
 * (retain the custom resource), continuing until the stack is gone or the wait
 * budget is exhausted. Verifies the IAM role on success.
 */
async function processStack(
  api: SweepApi,
  o: Orphan,
  args: CleanupArgs,
  // deno-lint-ignore no-explicit-any
  context: any,
): Promise<StackOutcome> {
  let status = await api.describeStackStatus(o.stackName, o.region);
  if (status === null) {
    const rv = await checkRole(api, o, args);
    return {
      action: "already-gone",
      retain: [],
      finalStatus: "GONE",
      gone: true,
      ...rv,
      error: "",
    };
  }

  // Predelete the dead backing Lambda first. With the function gone, the custom
  // resource's Delete has no provider to invoke, so CloudFormation deletes it
  // cleanly instead of hanging ~1h on the missing callback — the whole stack
  // (custom resource, Lambda, role) then deletes in one plain pass.
  if (args.predeleteLambda) {
    const fn = o.resources.find((r) => r.type === "AWS::Lambda::Function");
    if (fn && fn.physicalId.length > 0) {
      await api.deleteFunction(fn.physicalId, o.region);
      context.logger.info(
        "predeleted backing Lambda {fn} for {stack} in {region}",
        { fn: fn.physicalId, stack: o.stackName, region: o.region },
      );
    }
  }

  // Pass 1: a healthy stack cannot take RetainResources — issue a plain delete.
  if (status !== "DELETE_FAILED" && !status.startsWith("DELETE_IN_PROGRESS")) {
    await api.deleteStack(o.stackName, o.region, []);
    context.logger.info(
      "pass1 plain DeleteStack issued for {stack} in {region}",
      { stack: o.stackName, region: o.region },
    );
    status = "DELETE_IN_PROGRESS";
  }

  if (args.initiateOnly && status !== "DELETE_FAILED") {
    return {
      action: "delete-initiated",
      retain: [],
      finalStatus: status,
      gone: false,
      roleChecked: false,
      roleGone: false,
      error: "",
    };
  }

  let pass2Issued = false;
  let lastRetain: string[] = [];
  for (let i = 0; i < args.maxWaits; i++) {
    const s = await api.describeStackStatus(o.stackName, o.region);
    if (s === null) {
      const rv = await checkRole(api, o, args);
      return {
        action: "delete-retain",
        retain: lastRetain,
        finalStatus: "GONE",
        gone: true,
        ...rv,
        error: "",
      };
    }
    if (s === "DELETE_FAILED" && !pass2Issued) {
      // Pass 2: retain only the failed custom resource so the rest deletes.
      const live = await api.listStackResources(o.stackName, o.region);
      const { retain, reason } = computeRetain(live, args.retainLogicalId);
      if (reason.length > 0) {
        return {
          action: "skip",
          retain: [],
          finalStatus: s,
          gone: false,
          roleChecked: false,
          roleGone: false,
          error: reason,
        };
      }
      await api.deleteStack(o.stackName, o.region, retain);
      lastRetain = retain;
      pass2Issued = true;
      context.logger.info(
        "pass2 retain-delete issued for {stack} in {region}, retain={retain}",
        { stack: o.stackName, region: o.region, retain: retain.join(",") },
      );
    } else {
      context.logger.info(
        "waiting on {stack} in {region}: {status} (poll {i}/{max}, pass2={p2})",
        {
          stack: o.stackName,
          region: o.region,
          status: s,
          i: i + 1,
          max: args.maxWaits,
          p2: pass2Issued,
        },
      );
    }
    await delay(args.waitSeconds * 1000, context.signal);
  }

  const last = await api.describeStackStatus(o.stackName, o.region);
  if (last === null) {
    const rv = await checkRole(api, o, args);
    return {
      action: "delete-retain",
      retain: lastRetain,
      finalStatus: "GONE",
      gone: true,
      ...rv,
      error: "",
    };
  }
  return {
    action: pass2Issued ? "delete-retain" : "delete-initiated",
    retain: lastRetain,
    finalStatus: last,
    gone: false,
    roleChecked: false,
    roleGone: false,
    error: pass2Issued
      ? `did not reach DELETE_COMPLETE within wait budget (last: ${last})`
      : "",
  };
}

/** Write one `deletion` row. */
function writeDeletion(
  // deno-lint-ignore no-explicit-any
  context: any,
  o: Orphan,
  fields: {
    action: string;
    retainedResources: string[];
    finalStatus: string;
    gone: boolean;
    roleChecked: boolean;
    roleGone: boolean;
    error: string;
    startedAt: string;
  },
): Promise<{ name: string }> {
  return context.writeResource(
    "deletion",
    `deletion-${o.account}-${o.region}-${safeNameSegment(o.stackName)}`,
    {
      account: o.account,
      region: o.region,
      stackName: o.stackName,
      stackId: o.stackId,
      action: fields.action,
      retainedResources: fields.retainedResources,
      finalStatus: fields.finalStatus,
      gone: fields.gone,
      roleChecked: fields.roleChecked,
      roleGone: fields.roleGone,
      iamRolePhysicalName: o.iamRolePhysicalName,
      error: fields.error,
      startedAt: fields.startedAt,
      finishedAt: new Date().toISOString(),
    },
  );
}

// ---------------------------------------------------------------------------
// Credential + facade construction
// ---------------------------------------------------------------------------

function apiFromGlobals(g: GlobalArgs, signal?: AbortSignal): SweepApi {
  const credentials = g.profile.length > 0
    ? fromIni({ profile: g.profile })
    : undefined;
  // IAM is global; use the first configured region for the IAM/STS endpoint.
  return sdkApi(credentials, g.regions[0] ?? "us-east-1", signal);
}

// ---------------------------------------------------------------------------
// Model export
// ---------------------------------------------------------------------------

/**
 * The `@jentz/aws-cfn-orphan-sweep` model.
 *
 * `enumerate` (read-only) builds the orphan inventory; `cleanup` (mutating,
 * dry-run unless `apply=true`) deletes the orphans retaining only the dead
 * custom resource and verifies the IAM role is gone.
 */
export const model = {
  type: "@jentz/aws-cfn-orphan-sweep",
  version: "2026.06.16.3",
  globalArguments: GlobalArgsSchema,
  resources: {
    orphan: {
      description:
        "One standalone CloudFormation stack matching namePrefix, with its " +
        "status, the custom-resource logical id to retain on delete, and the " +
        "IAM role (logical id + physical name) that the cleanup removes.",
      schema: OrphanSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    summary: {
      description:
        "Per-account rollup: regions scanned, orphan count, counts by region " +
        "and status, and the names of any DELETE_FAILED stacks.",
      schema: SummarySchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    deletion: {
      description:
        "One delete attempt (or dry-run plan) for an orphan stack: action, " +
        "retained logical ids, final status, whether the stack and its IAM " +
        "role are gone, and any error.",
      schema: DeletionSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    enumerate: {
      description:
        "READ-ONLY fan-out: ListStacks (active statuses) per region, keep names " +
        "starting with namePrefix, ListStackResources on each. Writes one " +
        "orphan row per stack plus a per-account summary. Safe under *-readonly.",
      arguments: z.object({}),
      execute: (
        _args: Record<string, never>,
        // deno-lint-ignore no-explicit-any
        context: any,
      ): Promise<EnumerateResult> => {
        const g = GlobalArgsSchema.parse(context.globalArgs);
        return runEnumerate({
          api: apiFromGlobals(g, context.signal),
          globals: g,
          context,
        });
      },
    },
    cleanup: {
      description:
        "MUTATING when apply=true (dry-run otherwise). By default predeletes " +
        "the dead backing Lambda then issues one plain DeleteStack so the whole " +
        "stack (incl. IAM role) is removed fast; falls back to a two-pass " +
        "retain-delete otherwise. Verifies the IAM role is gone. Refuses names " +
        "outside namePrefix and never retains anything but the custom resource. " +
        "Needs cloudformation:DeleteStack + lambda:DeleteFunction + iam:GetRole " +
        "— run from *-devops.",
      arguments: z.object({
        apply: z.boolean().default(false).describe(
          "When false (default), dry-run: write would-delete rows, mutate " +
            "nothing. Set true to actually delete.",
        ),
        expectAccount: z.string().default("").describe(
          "If set, refuse to run unless the resolved account id matches — a " +
            "guardrail against running against the wrong account.",
        ),
        onlyRegion: z.string().default("").describe(
          "If set, only act on orphans in this region (canary scoping).",
        ),
        onlyStack: z.string().default("").describe(
          "If set, only act on this exact stack name (single-stack canary).",
        ),
        retainLogicalId: z.string().default("").describe(
          "Override the retained logical id. Honored only if it equals the " +
            "detected custom-resource logical id; otherwise the stack is skipped.",
        ),
        waitSeconds: z.number().int().min(2).max(60).default(10).describe(
          "Seconds between DescribeStacks polls while waiting for deletion.",
        ),
        maxWaits: z.number().int().min(1).max(120).default(30).describe(
          "Maximum polls before giving up on a delete.",
        ),
        verifyRole: z.boolean().default(true).describe(
          "After delete, GetRole on the captured role name to confirm removal.",
        ),
        initiateOnly: z.boolean().default(false).describe(
          "Fire the delete on each stack and return immediately without polling " +
            "to completion — for fast fleet fan-out. Re-run (or enumerate) to " +
            "confirm. Combine with predeleteLambda so the delete completes on " +
            "its own in seconds.",
        ),
        predeleteLambda: z.boolean().default(true).describe(
          "Delete the stack's backing Lambda before deleting the stack, so the " +
            "dead custom resource deletes cleanly (no ~1h hang) and the whole " +
            "stack — including the IAM role — is removed in one plain pass. " +
            "Needs lambda:DeleteFunction. Set false for the slow pure-CFN path.",
        ),
      }),
      execute: (
        args: CleanupArgs,
        // deno-lint-ignore no-explicit-any
        context: any,
      ): Promise<CleanupResult> => {
        const g = GlobalArgsSchema.parse(context.globalArgs);
        return runCleanup({
          api: apiFromGlobals(g, context.signal),
          globals: g,
          args,
          context,
        });
      },
    },
  },
};
