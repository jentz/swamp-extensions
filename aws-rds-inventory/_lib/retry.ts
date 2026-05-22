/**
 * Exponential-backoff retry helper for AWS RDS API calls.
 *
 * Modeled on the `withRetry` helper shipped by `@swamp/aws/rds`. The AWS SDK
 * has its own retry logic, but on busy accounts the paginated
 * DescribeDBClusters/DescribeDBInstances calls can outpace the SDK's defaults,
 * so we layer our own throttling-aware retry on top.
 *
 * @module
 */

/**
 * Pluggable surface a `RetryConfig` consumer needs from the runtime. Kept
 * minimal so unit tests can pass deterministic fakes (no real waiting, no
 * Math.random).
 */
export interface RetryDeps {
  /**
   * Returns a jitter factor in `[0, 1)` — multiplied into the exponential
   * delay so retries don't synchronize across concurrent callers.
   */
  random: () => number;
  /** Resolves after `ms` milliseconds. */
  delay: (ms: number) => Promise<void>;
  /** Called once per retry with structured fields. */
  onRetry?: (event: RetryEvent) => void;
}

/** Information about a single retry decision, surfaced via `onRetry`. */
export interface RetryEvent {
  operationName: string;
  attempt: number;
  delayMs: number;
  error: unknown;
}

/** Tunable retry behaviour. Defaults mirror the upstream helper. */
export interface RetryConfig {
  /** Max attempts including the initial try. Default 20. */
  maxAttempts?: number;
  /** Initial delay in ms before the first retry. Default 1000. */
  baseDelayMs?: number;
  /** Upper bound on the exponential delay. Default 90000. */
  maxDelayMs?: number;
}

const DEFAULT_DEPS: RetryDeps = {
  random: () => Math.random(),
  delay: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

/**
 * Returns `true` if `error` looks like an AWS throttling failure. Prefers
 * matching by the error's `name` (set by the AWS SDK on actual throttling
 * faults) and only falls back to message substrings for SDK versions that
 * surface the throttle as a generic Error.
 *
 * The `name`-based match list is the authoritative AWS surface; the message
 * fallback uses word-boundary patterns to avoid false positives on user
 * input that happens to embed one of the throttling tokens.
 */
export function isThrottlingError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  switch (error.name) {
    case "ThrottlingException":
    case "Throttling":
    case "TooManyRequestsException":
    case "RequestLimitExceeded":
    case "RequestThrottledException":
      return true;
  }
  // Message fallback — anchored on word boundaries so the SDK's generic
  // Error wrappers still match but arbitrary user text containing
  // "throttling" embedded in another word does not. The token list must
  // stay in sync with the name-switch above; `(?:Exception)?` keeps both
  // bare and `*Exception`-suffixed forms in one branch per family.
  return /\b(?:Throttling(?:Exception)?|TooManyRequests(?:Exception)?|RequestLimitExceeded|RequestThrottled(?:Exception)?)\b/
    .test(error.message);
}

/**
 * Run `operation` with exponential backoff and **full jitter** on throttling
 * errors.
 *
 * Non-throttling errors propagate immediately. Throttling errors are retried
 * up to `maxAttempts` times. The delay for retry `n` is uniformly sampled
 * from `[0, min(baseDelay * 2 ** n, maxDelay)]`. Full jitter (as opposed to
 * a tight 0–30% additive jitter) is the AWS-documented recommendation for
 * decorrelating concurrent callers, and the spread is what prevents two
 * processes hitting `DescribeDBClusters` simultaneously from re-colliding
 * after each retry.
 *
 * @typeParam T Return type of `operation`.
 * @param operation The async work to attempt.
 * @param operationName Short name surfaced via `onRetry`.
 * @param config Retry tunables. Defaults: 20 attempts, 1s base, 90s ceiling.
 * @param deps Injected dependencies — exposed so tests can substitute
 *   deterministic `random`, `delay`, and observe `onRetry` events.
 */
export async function withRetry<T>(
  operation: () => Promise<T>,
  operationName: string,
  config: RetryConfig = {},
  deps: RetryDeps = DEFAULT_DEPS,
): Promise<T> {
  const maxAttempts = config.maxAttempts ?? 20;
  const baseDelayMs = config.baseDelayMs ?? 1000;
  const maxDelayMs = config.maxDelayMs ?? 90000;

  let lastError: unknown;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (!isThrottlingError(error) || attempt >= maxAttempts - 1) {
        throw error;
      }
      const ceiling = Math.min(
        baseDelayMs * 2 ** attempt,
        maxDelayMs,
      );
      // Full jitter: uniform sample of [0, ceiling].
      const delayMs = Math.round(deps.random() * ceiling);
      deps.onRetry?.({
        operationName,
        attempt: attempt + 1,
        delayMs,
        error,
      });
      await deps.delay(delayMs);
    }
  }
  throw lastError ??
    new Error(`${operationName} failed after ${maxAttempts} attempts`);
}
