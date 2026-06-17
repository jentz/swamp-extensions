/**
 * `@jentz/aws-stackset-lifecycle` — write-side retirement operations for a
 * CloudFormation StackSet, from the management / delegated-admin account.
 *
 * The official `@swamp/aws/cloudformation/stack-set` (Cloud Control) type can
 * create/update/delete a StackSet, but its delete tears down **every** instance
 * at once with **no batching and no `RetainStacks` control** — unusable for a
 * staged, low-blast-radius retirement. This model fills that gap with the native
 * CloudFormation StackSets API, as a mutating sibling to the read-only
 * `@jentz/aws-stackset-audit` and `@jentz/aws-stackset-drift-detect`.
 *
 * Two mutating methods, each a single locked execution writing one `result`
 * resource:
 *
 *   - `deleteInstances` — `DeleteStackInstances` for an explicit set of
 *     deployment targets (OUs + accounts) and regions, with an explicit
 *     `retainStacks` flag. Use it batch-by-batch (a handful of accounts per run)
 *     so each member is only briefly affected. A safety guard refuses to operate
 *     on a whole OU/root unless `confirmWholeTarget: true` is set.
 *   - `deleteStackSet` — `DeleteStackSet` once the stackset is empty.
 *
 * Auth mirrors `@jentz/aws-stackset-audit`: an optional named `profile`
 * (`fromIni`) or the ambient credential chain. For SSO, export credentials into
 * the env first (the `@jentz/aws-*` models do not read the SSO cache via
 * `fromIni`) and leave `profile` empty:
 *   eval "$(aws configure export-credentials --profile <p> --format env)"
 *
 * MUTATING: needs `cloudformation:DeleteStackInstances` /
 * `cloudformation:DeleteStackSet` plus the stackset admin role — a `*-readonly`
 * profile cannot run these, by design.
 *
 * @module
 */

import { z } from "npm:zod@4";
import {
  CloudFormationClient,
  DeleteStackInstancesCommand,
  DeleteStackSetCommand,
  DescribeStackSetOperationCommand,
} from "npm:@aws-sdk/client-cloudformation@3.1021.0";
import { fromIni } from "npm:@aws-sdk/credential-providers@3.1021.0";

/** Credential provider as returned by `fromIni`; `undefined` means the ambient chain. */
type CredentialProvider = ReturnType<typeof fromIni>;

// ---------------------------------------------------------------------------
// Global arguments
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  stackSetName: z.string().min(1).describe(
    "The name of the CloudFormation StackSet to operate on (e.g. 'ExampleOrgBaseline').",
  ),
  callAs: z.enum(["SELF", "DELEGATED_ADMIN"]).default("SELF").describe(
    "Who you are calling as. SELF from the org management account; " +
      "DELEGATED_ADMIN from a delegated administrator account.",
  ),
  region: z.string().min(1).default("us-east-1").describe(
    "Region of the CloudFormation endpoint (the stackset admin region — where " +
      "the stackset object is homed; NOT the instance regions). Set it to " +
      "wherever the stackset object lives.",
  ),
  profile: z.string().default("").describe(
    "Named AWS profile to use (resolved via fromIni). Empty (default) uses the " +
      "ambient credential chain — export SSO creds into the env first.",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Method argument schemas
// ---------------------------------------------------------------------------

const DeploymentTargetsSchema = z.object({
  organizationalUnitIds: z.array(z.string()).default([]).describe(
    "Target OU ids (service-managed). For an INTERSECTION batch, the OU(s) the " +
      "accounts live under (the org root r-... is valid).",
  ),
  accounts: z.array(z.string().regex(/^[0-9]{12}$/)).default([]).describe(
    "Explicit 12-digit member account ids for this batch.",
  ),
  accountFilterType: z.enum(["NONE", "UNION", "INTERSECTION", "DIFFERENCE"])
    .default("INTERSECTION").describe(
      "How accounts and OUs combine. INTERSECTION (default) = exactly the listed " +
        "accounts that are also in the listed OUs — the safe batched shape.",
    ),
});

const DeleteInstancesArgsSchema = z.object({
  deploymentTargets: DeploymentTargetsSchema,
  regions: z.array(z.string().min(1)).min(1).describe(
    "Instance regions to delete in this account set. List every region this " +
      "batch is deployed to (e.g. eu-west-1, eu-north-1, eu-central-1, us-east-1).",
  ),
  retainStacks: z.boolean().describe(
    "REQUIRED by the API. false = delete the member stacks AND their resources. " +
      "true = keep the resources, only detach them from the stackset.",
  ),
  confirmWholeTarget: z.boolean().default(false).describe(
    "Safety guard. Must be true to delete instances for a whole OU/root with no " +
      "explicit account list. Leave false for batched account-scoped deletes.",
  ),
  pollSeconds: z.number().int().min(5).max(300).default(15)
    .describe("Seconds between operation status polls."),
  maxPolls: z.number().int().min(1).max(360).default(120)
    .describe("Maximum status polls before timing out."),
});

// `deleteStackSet` takes no method arguments: `DeleteStackSet` returns no
// StackSet operation to poll, so the method issues the delete and records the
// outcome immediately. (`deleteInstances` owns the poll-tuning args above.)
const DeleteStackSetArgsSchema = z.object({});

// ---------------------------------------------------------------------------
// Resource schema
// ---------------------------------------------------------------------------

const ResultSchema = z.object({
  action: z.enum(["delete-instances", "delete-stackset"]),
  stackSetName: z.string(),
  callAs: z.string(),
  region: z.string(),
  operationId: z.string(),
  status: z.string(),
  statusReason: z.string(),
  regions: z.array(z.string()),
  deploymentTargets: z.object({
    organizationalUnitIds: z.array(z.string()),
    accounts: z.array(z.string()),
    accountFilterType: z.string(),
  }),
  retainStacks: z.boolean(),
  startedAt: z.iso.datetime(),
  finishedAt: z.iso.datetime(),
});

/** Outcome of a lifecycle operation (delete-instances or delete-stackset). */
export interface LifecycleResult {
  /** Which operation ran. */
  action: "delete-instances" | "delete-stackset";
  /** StackSet name. */
  stackSetName: string;
  /** SELF | DELEGATED_ADMIN. */
  callAs: string;
  /** Admin endpoint region used. */
  region: string;
  /** StackSet operation id (or "" if none). */
  operationId: string;
  /** Terminal operation status: SUCCEEDED | FAILED | STOPPED. */
  status: string;
  /** Reason, when the operation did not SUCCEED. */
  statusReason: string;
  /** Instance regions targeted (empty for delete-stackset). */
  regions: string[];
  /** Deployment targets used (empty for delete-stackset). */
  deploymentTargets: {
    organizationalUnitIds: string[];
    accounts: string[];
    accountFilterType: string;
  };
  /** RetainStacks flag used (false for delete-stackset). */
  retainStacks: boolean;
  /** ISO 8601 start. */
  startedAt: string;
  /** ISO 8601 finish. */
  finishedAt: string;
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit-test access)
// ---------------------------------------------------------------------------

/**
 * Validate a delete-instances request before any AWS call. Returns an error
 * message when the request is unsafe/malformed, or `null` when it is OK.
 *
 * The guard's job is to make a fat-fingered fleet-wide delete impossible: an
 * account-scoped batch must list explicit accounts; operating on a whole OU/root
 * (no accounts, NONE/UNION filter) requires `confirmWholeTarget: true`.
 */
export function validateDeleteInstances(input: {
  organizationalUnitIds: string[];
  accounts: string[];
  accountFilterType: string;
  regions: string[];
  confirmWholeTarget: boolean;
}): string | null {
  if (input.regions.length === 0) return "at least one region is required";
  const hasOus = input.organizationalUnitIds.length > 0;
  const hasAccounts = input.accounts.length > 0;
  if (!hasOus && !hasAccounts) {
    return "deploymentTargets must include organizationalUnitIds and/or accounts";
  }
  const accountScoped = hasAccounts &&
    input.accountFilterType === "INTERSECTION";
  if (!accountScoped && !input.confirmWholeTarget) {
    return "refusing a whole-OU/root delete: pass an explicit accounts list with " +
      "accountFilterType=INTERSECTION (batched), or set confirmWholeTarget=true";
  }
  return null;
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

/** Input to a DeleteStackInstances call. */
export interface DeleteInstancesInput {
  /** Target OU ids. */
  organizationalUnitIds: string[];
  /** Target account ids. */
  accounts: string[];
  /** Account/OU combination filter. */
  accountFilterType: "NONE" | "UNION" | "INTERSECTION" | "DIFFERENCE";
  /** Instance regions. */
  regions: string[];
  /** Retain member stacks/resources on delete. */
  retainStacks: boolean;
}

/** Facade over the CloudFormation calls this extension uses. */
export interface LifecycleApi {
  /** Start a DeleteStackInstances operation; returns the operation id. */
  deleteInstances(input: DeleteInstancesInput): Promise<string>;
  /** Delete the (empty) stackset. Returns void. */
  deleteStackSet(): Promise<void>;
  /** Current status + reason of a stackset operation. */
  describeOperation(
    operationId: string,
  ): Promise<{ status: string; reason: string }>;
}

const CLIENT_RETRY = { maxAttempts: 8 } as const;

function sdkApi(
  credentials: CredentialProvider | undefined,
  region: string,
  callAs: "SELF" | "DELEGATED_ADMIN",
  stackSetName: string,
  signal?: AbortSignal,
): LifecycleApi {
  const client = new CloudFormationClient({
    region,
    credentials,
    ...CLIENT_RETRY,
  });
  const opts = { abortSignal: signal };

  return {
    deleteInstances: async (input: DeleteInstancesInput) => {
      const resp = await client.send(
        new DeleteStackInstancesCommand({
          StackSetName: stackSetName,
          CallAs: callAs,
          Regions: input.regions,
          RetainStacks: input.retainStacks,
          DeploymentTargets: {
            OrganizationalUnitIds: input.organizationalUnitIds.length > 0
              ? input.organizationalUnitIds
              : undefined,
            Accounts: input.accounts.length > 0 ? input.accounts : undefined,
            AccountFilterType: input.accountFilterType,
          },
        }),
        opts,
      );
      if (!resp.OperationId) {
        throw new Error("DeleteStackInstances returned no OperationId");
      }
      return resp.OperationId;
    },
    deleteStackSet: async () => {
      await client.send(
        new DeleteStackSetCommand({
          StackSetName: stackSetName,
          CallAs: callAs,
        }),
        opts,
      );
    },
    describeOperation: async (operationId: string) => {
      const resp = await client.send(
        new DescribeStackSetOperationCommand({
          StackSetName: stackSetName,
          OperationId: operationId,
          CallAs: callAs,
        }),
        opts,
      );
      return {
        status: resp.StackSetOperation?.Status ?? "UNKNOWN",
        reason: resp.StackSetOperation?.StatusReason ?? "",
      };
    },
  };
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error("aborted"));
      return;
    }
    const onAbort = () => {
      clearTimeout(timer);
      reject(new Error("aborted"));
    };
    const timer = setTimeout(() => {
      // Drop the listener so a shared signal does not accumulate one dead
      // listener per poll iteration (MaxListenersExceededWarning).
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

const TERMINAL = new Set(["SUCCEEDED", "FAILED", "STOPPED"]);

/**
 * Poll a stackset operation to a terminal state, or throw on timeout.
 *
 * @param api Facade bound to the stackset + admin credentials.
 * @param operationId The operation to poll.
 * @param pollSeconds Seconds between polls.
 * @param maxPolls Maximum polls before timing out.
 * @param context Swamp runtime context (logger + signal).
 * @returns The terminal status and its reason.
 */
export async function pollToTerminal(
  api: LifecycleApi,
  operationId: string,
  pollSeconds: number,
  maxPolls: number,
  // deno-lint-ignore no-explicit-any
  context: any,
): Promise<{ status: string; reason: string }> {
  let last = { status: "RUNNING", reason: "" };
  for (let poll = 0; poll < maxPolls; poll++) {
    last = await api.describeOperation(operationId);
    if (TERMINAL.has(last.status)) return last;
    context.logger.info(
      "Operation {op} is {status} (poll {poll}/{max})",
      { op: operationId, status: last.status, poll: poll + 1, max: maxPolls },
    );
    await delay(pollSeconds * 1000, context.signal);
  }
  throw new Error(
    `Operation ${operationId} did not finish within ${maxPolls} polls ` +
      `(last status ${last.status})`,
  );
}

// ---------------------------------------------------------------------------
// Core lifecycle logic — parameterized on its AWS facade and runtime context
// ---------------------------------------------------------------------------

// `DeleteInstancesArgs` mirrors the runtime shape of `DeleteInstancesArgsSchema`
// as an explicit public interface so the exported `DeleteInstancesDeps` does not
// reference the private schema constant — required for `deno doc --lint`. The
// zod schema above remains the runtime validation source for the method.

/** Parsed `deleteInstances` method arguments. */
export interface DeleteInstancesArgs {
  /** The deployment targets (OUs + accounts) and how they combine. */
  deploymentTargets: {
    /** Target OU ids (service-managed). */
    organizationalUnitIds: string[];
    /** Explicit 12-digit member account ids for this batch. */
    accounts: string[];
    /** How accounts and OUs combine. */
    accountFilterType: "NONE" | "UNION" | "INTERSECTION" | "DIFFERENCE";
  };
  /** Instance regions to delete in this account set. */
  regions: string[];
  /** Retain member stacks/resources on delete. */
  retainStacks: boolean;
  /** Confirm a whole-OU/root delete (bypasses the safety guard). */
  confirmWholeTarget: boolean;
  /** Seconds between operation status polls. */
  pollSeconds: number;
  /** Maximum status polls before timing out. */
  maxPolls: number;
}

/** Dependencies for {@link runDeleteInstances}. */
export interface DeleteInstancesDeps {
  /** AWS facade bound to the admin account's credentials. */
  api: LifecycleApi;
  /** StackSet name (echoed onto the result). */
  stackSetName: string;
  /** SELF | DELEGATED_ADMIN. */
  callAs: string;
  /** Admin endpoint region. */
  region: string;
  /** Parsed deleteInstances method arguments. */
  args: DeleteInstancesArgs;
  /** Swamp method-execution context (host-injected; typed `any`). */
  // deno-lint-ignore no-explicit-any
  context: any;
}

/** Dependencies for {@link runDeleteStackSet}. */
export interface DeleteStackSetDeps {
  /** AWS facade bound to the admin account's credentials. */
  api: LifecycleApi;
  /** StackSet name (echoed onto the result). */
  stackSetName: string;
  /** SELF | DELEGATED_ADMIN. */
  callAs: string;
  /** Admin endpoint region. */
  region: string;
  /** Swamp method-execution context (host-injected; typed `any`). */
  // deno-lint-ignore no-explicit-any
  context: any;
}

/**
 * Core `deleteInstances` logic. Validates the request, starts a
 * `DeleteStackInstances` operation, polls it to a terminal state, and writes one
 * `result` resource keyed `delete-instances-${operationId}`. Throws when the
 * request is unsafe or the operation does not end `SUCCEEDED`.
 *
 * @param deps API facade, stackset identity, parsed args, and runtime context.
 * @returns The result plus the produced data handle.
 */
export async function runDeleteInstances(
  deps: DeleteInstancesDeps,
): Promise<LifecycleResult & { dataHandles: unknown[] }> {
  const { api, stackSetName, callAs, region, args, context } = deps;
  const dt = args.deploymentTargets;

  const err = validateDeleteInstances({
    organizationalUnitIds: dt.organizationalUnitIds,
    accounts: dt.accounts,
    accountFilterType: dt.accountFilterType,
    regions: args.regions,
    confirmWholeTarget: args.confirmWholeTarget,
  });
  if (err) throw new Error(`refusing unsafe deleteInstances: ${err}`);

  const startedAt = new Date().toISOString();

  context.logger.info(
    "DeleteStackInstances on {name}: accounts={accts} ous={ous} " +
      "regions={regions} retainStacks={retain}",
    {
      name: stackSetName,
      accts: dt.accounts.join(",") || "(none)",
      ous: dt.organizationalUnitIds.join(",") || "(none)",
      regions: args.regions.join(","),
      retain: args.retainStacks,
    },
  );

  const operationId = await api.deleteInstances({
    organizationalUnitIds: dt.organizationalUnitIds,
    accounts: dt.accounts,
    accountFilterType: dt.accountFilterType,
    regions: args.regions,
    retainStacks: args.retainStacks,
  });

  const { status, reason } = await pollToTerminal(
    api,
    operationId,
    args.pollSeconds,
    args.maxPolls,
    context,
  );
  const finishedAt = new Date().toISOString();

  if (status !== "SUCCEEDED") {
    context.logger.error(
      "DeleteStackInstances {op} ended {status}: {reason}",
      { op: operationId, status, reason },
    );
  }

  const result: LifecycleResult = {
    action: "delete-instances",
    stackSetName,
    callAs,
    region,
    operationId,
    status,
    statusReason: reason,
    regions: args.regions,
    deploymentTargets: {
      organizationalUnitIds: dt.organizationalUnitIds,
      accounts: dt.accounts,
      accountFilterType: dt.accountFilterType,
    },
    retainStacks: args.retainStacks,
    startedAt,
    finishedAt,
  };
  const handle = await context.writeResource(
    "result",
    `delete-instances-${operationId}`,
    result,
  );
  if (status !== "SUCCEEDED") {
    throw new Error(
      `DeleteStackInstances ${operationId} ended ${status}: ${reason}`,
    );
  }
  return { ...result, dataHandles: [handle] };
}

/**
 * Core `deleteStackSet` logic. Deletes the (already empty) stackset and writes
 * one `result` resource keyed `delete-stackset-${stackSetName}`.
 *
 * @param deps API facade, stackset identity, and runtime context.
 * @returns The result plus the produced data handle.
 */
export async function runDeleteStackSet(
  deps: DeleteStackSetDeps,
): Promise<LifecycleResult & { dataHandles: unknown[] }> {
  const { api, stackSetName, callAs, region, context } = deps;
  const startedAt = new Date().toISOString();

  context.logger.info("DeleteStackSet on {name}", { name: stackSetName });
  await api.deleteStackSet();
  const finishedAt = new Date().toISOString();

  const result: LifecycleResult = {
    action: "delete-stackset",
    stackSetName,
    callAs,
    region,
    operationId: "",
    status: "SUCCEEDED",
    statusReason: "",
    regions: [],
    deploymentTargets: {
      organizationalUnitIds: [],
      accounts: [],
      accountFilterType: "",
    },
    retainStacks: false,
    startedAt,
    finishedAt,
  };
  const handle = await context.writeResource(
    "result",
    `delete-stackset-${stackSetName}`,
    result,
  );
  return { ...result, dataHandles: [handle] };
}

// ---------------------------------------------------------------------------
// Credential + facade construction
// ---------------------------------------------------------------------------

function apiFromGlobals(g: GlobalArgs, signal?: AbortSignal): LifecycleApi {
  const credentials = g.profile.length > 0
    ? fromIni({ profile: g.profile })
    : undefined;
  return sdkApi(credentials, g.region, g.callAs, g.stackSetName, signal);
}

// ---------------------------------------------------------------------------
// Model export
// ---------------------------------------------------------------------------

/**
 * The `@jentz/aws-stackset-lifecycle` model — mutating retirement operations
 * (`deleteInstances`, `deleteStackSet`) that the Cloud Control type cannot
 * express with batching and retain control.
 */
export const model = {
  type: "@jentz/aws-stackset-lifecycle",
  version: "2026.06.17.1",
  globalArguments: GlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.06.17.1",
      description: "Initial publish",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    result: {
      description:
        "Outcome of one lifecycle operation: action, operation id, terminal " +
        "status/reason, the deployment targets + regions + retainStacks used, " +
        "and timing.",
      schema: ResultSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
  },
  methods: {
    deleteInstances: {
      description:
        "MUTATING. DeleteStackInstances for an explicit batch of deployment " +
        "targets + regions with an explicit retainStacks flag; polls to a " +
        "terminal state. Safety-guarded against whole-OU/root deletes unless " +
        "confirmWholeTarget=true. Needs cloudformation:DeleteStackInstances + " +
        "the stackset admin role (a read-only profile cannot run it).",
      arguments: DeleteInstancesArgsSchema,
      execute: (
        args: z.infer<typeof DeleteInstancesArgsSchema>,
        // deno-lint-ignore no-explicit-any
        context: any,
      ): Promise<LifecycleResult & { dataHandles: unknown[] }> => {
        const g = GlobalArgsSchema.parse(context.globalArgs);
        return runDeleteInstances({
          api: apiFromGlobals(g, context.signal),
          stackSetName: g.stackSetName,
          callAs: g.callAs,
          region: g.region,
          args,
          context,
        });
      },
    },
    deleteStackSet: {
      description:
        "MUTATING. DeleteStackSet for the configured stackset (it must already " +
        "be empty — run deleteInstances over all targets first). Needs " +
        "cloudformation:DeleteStackSet + the stackset admin role.",
      arguments: DeleteStackSetArgsSchema,
      execute: (
        _args: z.infer<typeof DeleteStackSetArgsSchema>,
        // deno-lint-ignore no-explicit-any
        context: any,
      ): Promise<LifecycleResult & { dataHandles: unknown[] }> => {
        const g = GlobalArgsSchema.parse(context.globalArgs);
        return runDeleteStackSet({
          api: apiFromGlobals(g, context.signal),
          stackSetName: g.stackSetName,
          callAs: g.callAs,
          region: g.region,
          context,
        });
      },
    },
  },
};
