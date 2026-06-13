/**
 * `@jentz/aws-stackset-drift-detect` — the **write-side** sibling of
 * `@jentz/aws-stackset-audit`. It triggers a CloudFormation StackSet
 * drift-detection run and records its outcome, from the management /
 * delegated-admin account.
 *
 * The single `detect` method is **mutating** (it needs
 * `cloudformation:DetectStackSetDrift` plus the stackset admin role — a
 * `*-readonly` profile deliberately cannot run it). In one locked execution it:
 *
 *   1. calls `DetectStackSetDrift` for the configured stackset (honoring
 *      `callAs`) to start an operation and obtain its operation id, then
 *   2. polls `DescribeStackSetOperation` until the operation reaches a terminal
 *      state (`SUCCEEDED` | `FAILED` | `STOPPED`) or the poll budget
 *      (`maxPolls`) is exhausted, and
 *   3. writes exactly one `operation` resource capturing the outcome.
 *
 * It does **not** audit or re-read stack instances and writes no `summary` /
 * `instance` resources — that is `@jentz/aws-stackset-audit`'s job. Compose the
 * two in a swamp workflow: run this `detect` step first, then the audit step
 * with `dependsOn: [<detect-step>: succeeded]`, so the audit reads the refreshed
 * per-instance `driftStatus` straight from AWS. No CEL data handoff is required
 * — the ordering edge is sufficient.
 *
 * Reaching a terminal `FAILED` / `STOPPED` state does **not** throw: that is a
 * legitimate operation outcome and is recorded on the `operation` resource. Only
 * exhausting the poll budget throws, naming the last observed status.
 *
 * Auth mirrors the audit sibling: an optional named `profile` (`fromIni`) or the
 * ambient credential chain (`AWS_PROFILE`/env). The global-args shape is kept
 * identical to `@jentz/aws-stackset-audit` so a workflow wires the same inputs
 * into both steps.
 *
 * @module
 */

import { z } from "npm:zod@4";
import {
  CloudFormationClient,
  DescribeStackSetOperationCommand,
  DetectStackSetDriftCommand,
} from "npm:@aws-sdk/client-cloudformation@3.1021.0";
import { fromIni } from "npm:@aws-sdk/credential-providers@3.1021.0";

/** Credential provider as returned by `fromIni`; `undefined` means the ambient chain. */
type CredentialProvider = ReturnType<typeof fromIni>;

// ---------------------------------------------------------------------------
// Global arguments — identical shape to @jentz/aws-stackset-audit so a workflow
// wires the same inputs into both the detect step and the audit step.
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  stackSetName: z.string().min(1).describe(
    "The name of the CloudFormation StackSet to run drift detection on " +
      "(e.g. 'ExampleOrgBaseline').",
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
// Resource schema
// ---------------------------------------------------------------------------

const OperationSchema = z.object({
  stackSetName: z.string(),
  operationId: z.string(),
  action: z.string(),
  status: z.string(),
  creationTimestamp: z.string(),
  endTimestamp: z.string(),
  statusReason: z.string(),
});

// ---------------------------------------------------------------------------
// Public resource shape (explicit interface — deno doc --lint friendly)
// ---------------------------------------------------------------------------

// The helpers below are exported as test seams. Their public signatures use
// explicit interfaces (rather than `z.infer<typeof …>`) so the public API does
// not reference the private schema constants — required for `deno doc --lint`.
// The zod schema above remains the runtime validation source for the resource.

/** The outcome of one drift-detection operation, written as the `operation` resource. */
export interface OperationRecord {
  /** StackSet the operation ran on (echoed from the global args). */
  stackSetName: string;
  /** Operation id returned by `DetectStackSetDrift`; the resource key. */
  operationId: string;
  /** CREATE | UPDATE | DELETE | DETECT_DRIFT (DETECT_DRIFT for this model). */
  action: string;
  /** Terminal status reached: SUCCEEDED | FAILED | STOPPED. */
  status: string;
  /** ISO 8601 start time, or `""`. */
  creationTimestamp: string;
  /** ISO 8601 end time, or `""`. */
  endTimestamp: string;
  /** Status reason, or `""`. */
  statusReason: string;
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit-test access)
// ---------------------------------------------------------------------------

/** Coerce an SDK timestamp (Date | string | undefined) to an ISO string or "". */
export function isoOrEmpty(ts: unknown): string {
  if (ts instanceof Date) return ts.toISOString();
  if (typeof ts === "string" && ts.length > 0) return ts;
  return "";
}

// ---------------------------------------------------------------------------
// AWS facade — minimal surface so the poll loop stays testable without the SDK
// ---------------------------------------------------------------------------

/**
 * Minimal stackset-operation shape this extension reads from
 * `DescribeStackSetOperation`. The same shape the audit sibling uses, so a
 * mock can satisfy both.
 */
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

/** Facade over the two CloudFormation calls this extension makes. */
export interface DriftApi {
  /** Start a drift-detection operation for the stackset; returns its operation id. */
  detectDrift(): Promise<string>;
  /**
   * Describe the current state of a stackset operation, returning the full
   * operation summary (action, status, timestamps, reason) — not just the
   * status string — so the `operation` resource can be populated.
   */
  describeOperation(operationId: string): Promise<AwsOperationSummary>;
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
): DriftApi {
  const client = new CloudFormationClient({
    region,
    credentials,
    ...CLIENT_RETRY,
  });
  const opts = { abortSignal: signal };

  return {
    detectDrift: async () => {
      const resp = await client.send(
        new DetectStackSetDriftCommand({
          StackSetName: stackSetName,
          CallAs: callAs,
        }),
        opts,
      );
      if (!resp.OperationId) {
        throw new Error("DetectStackSetDrift returned no OperationId");
      }
      return resp.OperationId;
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
      return (resp.StackSetOperation ?? {}) as AwsOperationSummary;
    },
  };
}

// ---------------------------------------------------------------------------
// Sleep seam — real timer by default, injectable so the poll loop tests run at
// zero wall-clock time.
// ---------------------------------------------------------------------------

/** Sleep for `ms` milliseconds, rejecting if `signal` aborts first. */
export function realSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      reject(new Error("aborted"));
    }, { once: true });
  });
}

// ---------------------------------------------------------------------------
// Core detect logic — parameterized on its AWS facade, sleep, and context
// ---------------------------------------------------------------------------

/** Terminal stackset-operation states the poll loop stops on. */
const TERMINAL = new Set(["SUCCEEDED", "FAILED", "STOPPED"]);

/** Dependencies for {@link runDetect}. */
export interface DetectDeps {
  /** AWS facade bound to the admin account's credentials. */
  api: DriftApi;
  /** StackSet name (echoed onto the operation record). */
  stackSetName: string;
  /** Seconds between operation-status polls. */
  pollSeconds: number;
  /** Maximum status polls before the poll budget is exhausted. */
  maxPolls: number;
  /**
   * Sleep between polls. Defaults to {@link realSleep}; tests inject a no-op so
   * the poll-budget-exhausted path runs at zero wall-clock time.
   */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  /** Optional abort signal forwarded to the facade and the sleep. */
  signal?: AbortSignal;
  /** Swamp method-execution context (host-injected; typed `any`). */
  // deno-lint-ignore no-explicit-any
  context: any;
}

/** Result of {@link runDetect}. */
export interface DetectResult {
  /** Data handles produced (exactly one `operation` handle). */
  dataHandles: unknown[];
  /** The operation id that was started. */
  operationId: string;
  /** The terminal status the operation reached. */
  status: string;
}

/**
 * Core `detect` logic. Starts a StackSet drift-detection operation, polls it to
 * a terminal state, and writes exactly one `operation` resource keyed by the
 * operation id.
 *
 * Throws only when the poll budget (`maxPolls`) is exhausted before a terminal
 * state is reached — naming the last observed status. A terminal `FAILED` /
 * `STOPPED` is a legitimate outcome and is recorded, not thrown.
 *
 * @param deps API facade, stackset name, poll knobs, injectable sleep, and
 *   runtime context.
 * @returns Data handles, the operation id, and the terminal status.
 */
export async function runDetect(deps: DetectDeps): Promise<DetectResult> {
  const { api, stackSetName, pollSeconds, maxPolls, signal, context } = deps;
  const sleep = deps.sleep ?? realSleep;

  const operationId = await api.detectDrift();
  context.logger.info(
    "Started drift detection on {name}: operation {op}",
    { name: stackSetName, op: operationId },
  );

  let op: AwsOperationSummary = {};
  let status = "RUNNING";
  for (let poll = 0; poll < maxPolls; poll++) {
    op = await api.describeOperation(operationId);
    status = op.Status ?? "UNKNOWN";
    if (TERMINAL.has(status)) break;
    context.logger.info(
      "Drift operation {op} is {status} (poll {poll}/{max})",
      { op: operationId, status, poll: poll + 1, max: maxPolls },
    );
    await sleep(pollSeconds * 1000, signal);
  }

  if (!TERMINAL.has(status)) {
    throw new Error(
      `drift detection for ${stackSetName} did not finish within ` +
        `${maxPolls} polls (last status ${status})`,
    );
  }

  const record: OperationRecord = {
    stackSetName,
    operationId,
    action: op.Action ?? "DETECT_DRIFT",
    status,
    creationTimestamp: isoOrEmpty(op.CreationTimestamp),
    endTimestamp: isoOrEmpty(op.EndTimestamp),
    statusReason: op.StatusReason ?? "",
  };

  const handle = await context.writeResource("operation", operationId, record);

  context.logger.info(
    "Drift operation {op} finished: {status}",
    { op: operationId, status },
  );

  return { dataHandles: [handle], operationId, status };
}

// ---------------------------------------------------------------------------
// Credential + facade construction
// ---------------------------------------------------------------------------

function apiFromGlobals(g: GlobalArgs, signal?: AbortSignal): DriftApi {
  const credentials = g.profile.length > 0
    ? fromIni({ profile: g.profile })
    : undefined;
  return sdkApi(credentials, g.region, g.callAs, g.stackSetName, signal);
}

// ---------------------------------------------------------------------------
// Model export
// ---------------------------------------------------------------------------

/**
 * The `@jentz/aws-stackset-drift-detect` model.
 *
 * A single **mutating** method, `detect`, starts a StackSet drift-detection
 * operation (`DetectStackSetDrift`), polls it to a terminal state
 * (`DescribeStackSetOperation`), and writes one `operation` resource capturing
 * the outcome. It performs no instance audit and writes no summary/instance
 * resources — that is the read-only sibling `@jentz/aws-stackset-audit`.
 * Compose the two in a swamp workflow (this `detect` step first, then the audit
 * step with `dependsOn: succeeded`).
 */
export const model = {
  type: "@jentz/aws-stackset-drift-detect",
  version: "2026.06.13.0",
  globalArguments: GlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.06.13.0",
      description: "Initial publish",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    operation: {
      description:
        "Outcome of one StackSet drift-detection operation: stackSetName, " +
        "operationId, action, terminal status, creation/end timestamps, and " +
        "statusReason. Keyed by operation id.",
      schema: OperationSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    detect: {
      description:
        "MUTATING (needs cloudformation:DetectStackSetDrift + the stackset " +
        "admin role; a read-only profile cannot run this). Starts StackSet " +
        "drift detection, polls the operation to a terminal state (bounded by " +
        "pollSeconds / maxPolls), and writes one operation resource. Performs " +
        "no instance audit (that is the @jentz/aws-stackset-audit sibling).",
      arguments: z.object({
        pollSeconds: z.number().int().min(5).max(300).default(20)
          .describe("Seconds between operation status polls."),
        maxPolls: z.number().int().min(1).max(360).default(90)
          .describe("Maximum status polls before timing out."),
      }),
      execute: (
        args: { pollSeconds: number; maxPolls: number },
        // deno-lint-ignore no-explicit-any
        context: any,
      ): Promise<DetectResult> => {
        const g = GlobalArgsSchema.parse(context.globalArgs);
        return runDetect({
          api: apiFromGlobals(g, context.signal),
          stackSetName: g.stackSetName,
          pollSeconds: args.pollSeconds ?? 20,
          maxPolls: args.maxPolls ?? 90,
          signal: context.signal,
          context,
        });
      },
    },
  },
};
