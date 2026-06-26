/**
 * Shared `scan_error` library for the `@jentz/aws-*` fleet-scanner family.
 *
 * Mirrors the `_lib/coverage.ts` precedent: zod schema + pure functions, no
 * model/report export and no AWS SDK dependency, so it is unit-testable in
 * isolation and importable from both models (`./_lib/scan_error.ts`) and
 * reports (`../models/_lib/scan_error.ts`).
 *
 * The canonical home for the error-handling machinery shared across the
 * `@jentz/aws-*` fleet-scanner family:
 *
 *   - {@link ScanErrorSchema} — the stored-row shape, keyed by `profile`.
 *   - {@link scanErrorKey} — the deterministic storage key.
 *   - {@link classifyError} — coarse `kind` classification, with a `network`
 *     bucket checked *before* `auth_expired`.
 *   - {@link errorBucket} — `kind` → operator-facing remediation bucket,
 *     homed next to the `kind` enum it maps.
 *   - {@link reconcileScanErrors} + {@link ScanErrorStore} — source-side
 *     reconcile that deletes recovered `scan_error` rows at the end of a clean
 *     sweep, so a stale row never counts as a phantom coverage gap.
 *
 * @module
 */

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/** Coarse failure classification a `scan_error` row carries. */
export type ScanErrorKind =
  | "network"
  | "auth_expired"
  | "access_denied"
  | "other";

/**
 * Stored `scan_error` row. Carries `profile` so source-side reconcile can scope
 * deletions by profile without decoding row contents. `region`/`service` are
 * `""` for account-level failures.
 *
 * `service` defaults to `""` on reads so rows written by earlier scanners that
 * predate the field still parse (back-compat); new writes always set it.
 *
 * @internal The concrete zod type transitively references zod's private
 * internals, which the repo doc-lint gate rejects in the public API. The plain
 * {@link ScanError} interface is the documented public shape; this schema is the
 * runtime validator consumers import to parse rows.
 */
export const ScanErrorSchema = z.object({
  profile: z.string(),
  accountId: z.string(),
  region: z.string(),
  service: z.string().default(""),
  phase: z.string(),
  kind: z.enum(["network", "auth_expired", "access_denied", "other"]),
  message: z.string(),
  scannedAt: z.iso.datetime(),
});

/** A `(profile, region, service)` unit that could not be assessed. */
export interface ScanError {
  /** Profile being swept; `""` for ambient. */
  profile: string;
  /** Account id if known by failure time; `""` otherwise. */
  accountId: string;
  /** Region being scanned; `""` for account-level failures. */
  region: string;
  /** AWS service that failed. */
  service: string;
  /** Stage that failed. */
  phase: string;
  /** Coarse classification. */
  kind: ScanErrorKind;
  /** Error detail. */
  message: string;
  /** ISO 8601 timestamp. */
  scannedAt: string;
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/** Deterministic storage key for a `scan_error` row. */
export function scanErrorKey(
  profileLabel: string,
  region: string,
  service: string,
  phase: string,
): string {
  return `error-${profileLabel || "ambient"}-${
    region || "account"
  }-${service}-${phase}`;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/**
 * Network/transport-layer error signatures. These are DNS/socket failures that
 * are *transient* — they must never be misread as expired credentials, because
 * the SDK wraps a `getaddrinfo`/`ETIMEDOUT` failure during credential
 * resolution in a `CredentialsProviderError` ("Could not load credentials…"),
 * which would otherwise classify as `auth_expired` and short-circuit the sweep.
 * `network` is therefore checked *before* `auth_expired` and wins ties.
 */
const NETWORK_SIGNATURES = [
  "getaddrinfo",
  "enotfound",
  "etimedout",
  "econnreset",
  "econnrefused",
  "socket hang up",
] as const;

/**
 * Classify an AWS SDK error into the coarse `kind` the report buckets by.
 *
 * Order matters:
 *   1. `network` — transient DNS/socket failures, even when wrapped in a
 *      "could not load credentials" credentials-provider error.
 *   2. `auth_expired` — genuine token-expiry / SSO-session signatures.
 *   3. `access_denied` — IAM/SCP denials.
 *   4. `other` — everything else.
 *
 * The `AWSReservedSSO_…`-ARN → `access_denied` case is guarded: a bare `"sso"`
 * substring is intentionally never matched (an SSO role ARN appears in
 * unrelated `AccessDenied` messages); only genuine `"sso session"` /
 * `"session associated with this profile has expired"` phrasing maps to
 * `auth_expired`.
 */
export function classifyError(err: unknown): {
  kind: ScanErrorKind;
  message: string;
} {
  const message = err instanceof Error ? err.message : String(err);
  const name = (err as { name?: string } | null)?.name ?? "";

  // Walk the full message + cause chain so a network failure wrapped inside a
  // credentials-provider error is still seen.
  const haystack = collectHaystack(err, name, message);

  const isNetwork = NETWORK_SIGNATURES.some((sig) => haystack.includes(sig));
  if (isNetwork) return { kind: "network", message };

  const isAuthExpired = name.toLowerCase().includes("expiredtoken") ||
    name.toLowerCase().includes("credentialsprovidererror") ||
    haystack.includes("token has expired") ||
    haystack.includes("token is expired") ||
    haystack.includes("token included in the request is expired") ||
    haystack.includes("sso session") ||
    haystack.includes("session associated with this profile has expired") ||
    haystack.includes("could not load credentials") ||
    haystack.includes("failed to refresh");
  if (isAuthExpired) return { kind: "auth_expired", message };

  const isAccessDenied = haystack.includes("not authorized") ||
    haystack.includes("unauthorizedoperation") ||
    haystack.includes("accessdenied") ||
    haystack.includes("access denied") ||
    haystack.includes("explicit deny") ||
    haystack.includes("forbidden");
  if (isAccessDenied) return { kind: "access_denied", message };

  return { kind: "other", message };
}

/**
 * Build a lowercased search string spanning an error's `name`/`message` and its
 * `cause` chain, so signatures buried in a wrapped cause (e.g. a `getaddrinfo`
 * `cause` under a `CredentialsProviderError`) are still matched.
 */
function collectHaystack(
  err: unknown,
  name: string,
  message: string,
): string {
  const parts: string[] = [name, message];
  let cause: unknown = (err as { cause?: unknown } | null)?.cause;
  // Bounded walk; cause chains are short and we guard against cycles by depth.
  for (let depth = 0; depth < 8 && cause != null; depth++) {
    const cName = (cause as { name?: string } | null)?.name ?? "";
    const cMessage = cause instanceof Error
      ? cause.message
      : typeof cause === "string"
      ? cause
      : "";
    parts.push(cName, cMessage);
    cause = (cause as { cause?: unknown } | null)?.cause;
  }
  return parts.join(" ").toLowerCase();
}

// ---------------------------------------------------------------------------
// Report-side remediation bucket (homed next to the `kind` enum it maps)
// ---------------------------------------------------------------------------

/** Map a `scan_error` `kind` to an operator-facing remediation bucket. */
export function errorBucket(kind: string): string {
  if (kind === "network") return "transient-network-error";
  if (kind === "auth_expired") return "needs-aws-sso-login";
  if (kind === "access_denied") return "blocked-by-SCP-IAM";
  return "other";
}

// ---------------------------------------------------------------------------
// Source-side reconcile
// ---------------------------------------------------------------------------

/**
 * Narrow port over the stored `scan_error` rows for one model. Injected so
 * {@link reconcileScanErrors} can be unit-tested with an in-memory fake; the
 * runtime adapter wraps `context.dataRepository.findAllForModel`/`delete`.
 */
export interface ScanErrorStore {
  /** List every stored `scan_error` row as `{ name, profile }`. */
  list(): Promise<Array<{ name: string; profile: string }>>;
  /** Hard-delete the stored `scan_error` row with the given name. */
  delete(name: string): Promise<void>;
}

/**
 * Delete recovered `scan_error` rows at the end of a clean sweep.
 *
 * For every stored row whose `profile` was *attempted* this run but whose key
 * is *not* among the fresh errors just written, the unit recovered — so the
 * stale row is deleted and no longer counts as a phantom coverage gap. Rows for
 * profiles outside `attemptedProfiles` (e.g. not in this run's profile set) are
 * left untouched.
 *
 * Crash-safe ordering: callers must write all fresh errors *before* calling
 * this, so a crash mid-sweep leaves stale rows intact rather than deleting a
 * row whose replacement was never written.
 *
 * @param store Injected list/delete port over the model's `scan_error` rows.
 * @param attemptedProfiles Profiles whose credentials resolved this run.
 * @param freshErrorKeys Keys ({@link scanErrorKey}) of errors written this run.
 */
export async function reconcileScanErrors(
  store: ScanErrorStore,
  attemptedProfiles: Set<string>,
  freshErrorKeys: Set<string>,
): Promise<void> {
  const rows = await store.list();
  for (const row of rows) {
    if (!attemptedProfiles.has(row.profile)) continue;
    if (freshErrorKeys.has(row.name)) continue;
    await store.delete(row.name);
  }
}
