/**
 * Shared primitives for the `@jentz/aws-stackset-*` sibling trio
 * (`aws-stackset-audit`, `aws-stackset-drift-detect`,
 * `aws-stackset-lifecycle`).
 *
 * The three extensions are deliberate siblings over one domain — a read-only
 * auditor plus two mutating operators — and this module carries exactly the
 * primitives they duplicated:
 *
 *   - {@link CredentialProvider} / {@link selectCredentials} — the
 *     `fromIni`-vs-ambient credential branch.
 *   - {@link STACKSET_RETRY} — the shared SDK client retry config.
 *   - {@link GlobalArgs} — the runtime shape of the trio's identical
 *     global-argument set (each package keeps its own zod schema so the
 *     per-package `describe()` wording stays user-facing interface text).
 *   - {@link AwsOperationSummary} — the minimal `DescribeStackSetOperation` /
 *     `ListStackSetOperations` summary shape the siblings read.
 *   - {@link TERMINAL} / {@link pollToTerminal} — the poll-to-terminal loop
 *     with its exact budget semantics (`maxPolls` fetches, at most
 *     `maxPolls - 1` inter-poll waits, no trailing wait).
 *   - {@link delay} — the abort-aware sleep the poll loop waits with.
 *   - {@link isoOrEmpty} — SDK timestamp coercion.
 *
 * Deliberately self-contained: it does not import `_lib/aws_credentials.ts`
 * (which would drag that module's SSO pre-flight machinery and its
 * `_lib/scan_error.ts` twin into three packages that never use them), so it
 * re-declares the tiny credential selection here with a cross-reference.
 *
 * @module
 */

import { fromIni } from "npm:@aws-sdk/credential-providers@3.1073.0";

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/**
 * Credential provider as returned by `fromIni`. A client built with
 * `undefined` instead resolves via the SDK's ambient default chain.
 *
 * @internal The alias resolves to the SDK's `fromIni` return type, which the
 * repo doc-lint gate treats as a private (non-re-exported) reference;
 * consumers use it as an opaque provider handle.
 */
export type CredentialProvider = ReturnType<typeof fromIni>;

/**
 * Resolve the credential provider for the trio's `profile` global argument.
 *
 * A non-empty profile yields a lazy `fromIni({ profile })` provider; an empty
 * profile yields `undefined`, opting into the SDK ambient default chain
 * (whatever `AWS_PROFILE` / env is set).
 *
 * Cross-reference: `_lib/aws_credentials.ts` carries the fleet-scanner
 * variant with an explicit credential *mode*; the stackset trio has no mode
 * knob, so this profile-only branch is re-declared here to keep the twin
 * self-contained.
 */
export function selectCredentials(
  profile: string,
): CredentialProvider | undefined {
  return profile.length > 0 ? fromIni({ profile }) : undefined;
}

// ---------------------------------------------------------------------------
// Retry config
// ---------------------------------------------------------------------------

/**
 * Retry config spread into every CloudFormation client across the trio.
 *
 * `maxAttempts: 8` keeps the SDK's standard retry mode but widens the attempt
 * budget: StackSet admin-endpoint calls are low-volume and throttle-prone
 * (one endpoint fans out over many accounts), so a wider bound rides out
 * throttling bursts without any client-side rate limiting. Deliberately not
 * the fleet scanners' adaptive `SHARED_RETRY` — aligning the two would be a
 * behavior change, not a dedup.
 */
export const STACKSET_RETRY = { maxAttempts: 8 } as const;

// ---------------------------------------------------------------------------
// Global arguments — runtime shape only
// ---------------------------------------------------------------------------

/**
 * Runtime shape of the trio's identical global-argument set.
 *
 * Shared as a *type* only: each package keeps its own zod
 * `GlobalArgsSchema` because the per-field `describe()` strings are
 * deliberately per-package interface text (audit / drift-detect / lifecycle
 * each phrase the same field for their own operation).
 */
export interface GlobalArgs {
  /** Name of the CloudFormation StackSet the model operates on. */
  stackSetName: string;
  /** Whether the caller is the org management account or a delegated admin. */
  callAs: "SELF" | "DELEGATED_ADMIN";
  /** Region of the CloudFormation admin endpoint to talk to. */
  region: string;
  /** Named AWS profile (via `fromIni`), or empty for the ambient chain. */
  profile: string;
}

// ---------------------------------------------------------------------------
// Operation summary
// ---------------------------------------------------------------------------

/**
 * Minimal stackset-operation shape the siblings read from
 * `DescribeStackSetOperation` / `ListStackSetOperations`. One shape across
 * the trio, so a mock can satisfy every facade.
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

// ---------------------------------------------------------------------------
// Abort-aware sleep
// ---------------------------------------------------------------------------

/** Sleep for `ms` milliseconds, rejecting if `signal` aborts first. */
export function delay(ms: number, signal?: AbortSignal): Promise<void> {
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

// ---------------------------------------------------------------------------
// Poll to terminal
// ---------------------------------------------------------------------------

/** Terminal stackset-operation states the poll loop stops on. */
export const TERMINAL: ReadonlySet<string> = new Set([
  "SUCCEEDED",
  "FAILED",
  "STOPPED",
]);

/** Knobs and seams for {@link pollToTerminal}. */
export interface PollOptions {
  /** Seconds between polls. */
  pollSeconds: number;
  /** Maximum polls (fetches) before the budget is exhausted. */
  maxPolls: number;
  /**
   * Sleep between polls. Defaults to {@link delay}; tests inject a no-op so
   * the budget-exhausted path runs at zero wall-clock time.
   */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  /** Optional abort signal forwarded to the sleep. */
  signal?: AbortSignal;
  /**
   * Called after each non-terminal poll with the observed status, the
   * 1-based poll number, and `maxPolls` — the seam each caller logs its own
   * per-poll wording through.
   */
  onPoll?: (status: string, poll: number, maxPolls: number) => void;
  /**
   * Subject of the budget-exhausted error message, e.g. an operation or a
   * stackset description; the throw reads
   * `<label> did not finish within <maxPolls> polls (last status <status>)`.
   */
  label: string;
}

/**
 * Poll `fetch` until `statusOf` reports a {@link TERMINAL} status, returning
 * the last fetched value, or throw once the poll budget is exhausted.
 *
 * Budget semantics: exactly up to `maxPolls` fetches with at most
 * `maxPolls - 1` inter-poll waits — the wait after the final allowed poll is
 * skipped because there is no next poll it gates, and it would only delay
 * the timeout.
 *
 * Generic over the fetched shape `T` so a caller can poll the raw
 * {@link AwsOperationSummary} (and keep the full summary for its record) or
 * any mapped status shape; `statusOf` extracts the status string either way.
 *
 * @param fetch Fetch the operation's current state.
 * @param statusOf Extract the status string from a fetched state.
 * @param opts Poll knobs, seams, and the error-message label.
 * @returns The last fetched state, whose status is terminal.
 */
export async function pollToTerminal<T>(
  fetch: () => Promise<T>,
  statusOf: (state: T) => string,
  opts: PollOptions,
): Promise<T> {
  const sleep = opts.sleep ?? delay;
  let status = "UNKNOWN";
  for (let poll = 0; poll < opts.maxPolls; poll++) {
    const state = await fetch();
    status = statusOf(state);
    if (TERMINAL.has(status)) return state;
    opts.onPoll?.(status, poll + 1, opts.maxPolls);
    // Don't wait after the final allowed poll — there is no next poll to wait
    // for, and we'd only delay the timeout. The budget is maxPolls polls with
    // at most maxPolls-1 inter-poll waits.
    if (poll < opts.maxPolls - 1) {
      await sleep(opts.pollSeconds * 1000, opts.signal);
    }
  }
  throw new Error(
    `${opts.label} did not finish within ${opts.maxPolls} polls ` +
      `(last status ${status})`,
  );
}

// ---------------------------------------------------------------------------
// Timestamp coercion
// ---------------------------------------------------------------------------

/** Coerce an SDK timestamp (Date | string | undefined) to an ISO string or an empty string. */
export function isoOrEmpty(ts: unknown): string {
  if (ts instanceof Date) return ts.toISOString();
  if (typeof ts === "string" && ts.length > 0) return ts;
  return "";
}
