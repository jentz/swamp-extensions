/**
 * Shared credential machinery for the `@jentz/aws-*` fleet-scanner family.
 *
 * Mirrors the `_lib/coverage.ts` / `_lib/scan_error.ts` precedent: a thin,
 * dependency-light module that the fleet-scanner models import instead of
 * carrying private copies. Credential resolution itself stays delegated to the
 * AWS SDK — these helpers only standardize the pieces every model duplicated:
 *
 *   - {@link CredentialProvider} — the provider type returned by `fromIni`.
 *   - {@link SHARED_RETRY} — one bounded adaptive retry config, spread into
 *     every SDK client so a transient blip can't balloon a fleet-wide sweep.
 *   - {@link credentialModeField} — the `credentialMode` schema fragment.
 *   - {@link selectCredentials} — the `profile` vs `env`/ambient branch.
 *   - {@link preflightSso} — a single pre-flight resolve of the shared SSO
 *     session token, so a genuinely expired token short-circuits the per-profile
 *     loop with one actionable error instead of failing every profile.
 *   - {@link preflightSsoGate} — the pre-flight *policy* on top of
 *     {@link preflightSso}: only `expired` aborts the sweep, a `network` blip
 *     proceeds, and no configured session skips the check entirely.
 *   - {@link resolveBootstrapRegion} — the region chain for the account-level
 *     bootstrap calls that must target *some* region before scanning begins.
 *
 * @module
 */

import { z } from "npm:zod@4";
import { fromIni } from "npm:@aws-sdk/credential-providers@3.1073.0";
import { getSSOTokenFromFile } from "npm:@smithy/shared-ini-file-loader@4.6.1";
import { classifyError } from "./scan_error.ts";

// ---------------------------------------------------------------------------
// Credential provider
// ---------------------------------------------------------------------------

/**
 * Credential provider as returned by `fromIni`. A client built with
 * `undefined` instead resolves via the SDK's ambient default chain.
 *
 * @internal The alias resolves to the SDK's `fromIni` return type, which the
 * repo doc-lint gate treats as a private (non-re-exported) reference; consumers
 * use it as an opaque provider handle.
 */
export type CredentialProvider = ReturnType<typeof fromIni>;

// ---------------------------------------------------------------------------
// Retry config
// ---------------------------------------------------------------------------

/**
 * Bounded adaptive retry config spread into every SDK client across the family.
 *
 * `adaptive` mode adds client-side rate limiting on top of standard retries so
 * sustained throttling backs off rather than hammering. `maxAttempts: 3` (one
 * initial call plus up to two retries) keeps a single transient failure from
 * compounding across the fleet's many profiles × regions × services.
 *
 * This governs per-API-call failures only. Credential-resolution failures are
 * not retried — a DNS/network failure during resolution is classified `network`
 * and fails that profile immediately, to be cleared by reconcile on a clean
 * re-sweep.
 */
export const SHARED_RETRY = {
  retryMode: "adaptive",
  maxAttempts: 3,
} as const;

// ---------------------------------------------------------------------------
// credentialMode
// ---------------------------------------------------------------------------

/** How a profile's credentials are resolved. */
export type CredentialMode = "profile" | "env";

/**
 * The shared `credentialMode` global-argument schema fragment.
 *
 * @internal The concrete zod type transitively references zod's private
 * internals, which the repo doc-lint gate rejects in the public API; consumers
 * spread this fragment into their global-args schema as a runtime value.
 */
export const credentialModeField = z.enum(["profile", "env"]).default("profile")
  .describe(
    "'profile' resolves each profile via fromIni (SSO token cache). 'env' " +
      "uses ambient env credentials and treats profiles[] as labels only.",
  );

/**
 * Resolve the credential provider for a profile under a given mode.
 *
 * - `profile` → a lazy `fromIni({ profile })` provider (reads the profile's
 *   credentials / SSO token cache on first use).
 * - `env` → `undefined`, opting into the SDK ambient default chain; the profile
 *   name is then a label only.
 *
 * An empty profile always yields `undefined` (the ambient chain), regardless of
 * mode.
 */
export function selectCredentials(
  mode: CredentialMode,
  profile: string,
): CredentialProvider | undefined {
  if (mode === "env" || profile.length === 0) return undefined;
  return fromIni({ profile });
}

// ---------------------------------------------------------------------------
// Pre-flight SSO check
// ---------------------------------------------------------------------------

/** Outcome of a {@link preflightSso} resolve. */
export type PreflightResult =
  | { status: "ok"; message: string }
  | { status: "expired"; message: string }
  | { status: "network"; message: string };

/**
 * Resolve the shared SSO session token once, before the per-profile loop.
 *
 * A single SSO session backs every read-only profile, so a genuinely
 * expired/missing token would fail every profile identically. Resolving it once
 * up front lets the caller emit one actionable error and skip the wasteful loop:
 *
 * - `ok` — the token resolved; run the per-profile loop normally.
 * - `expired` — the token is genuinely expired or missing; the caller records a
 *   single `scan_error` ("run `aws sso login`") and skips the loop. `session`
 *   is used only to phrase that remediation message; an empty `session` yields
 *   the generic form.
 * - `network` — a transient DNS/socket failure; the caller proceeds with the
 *   loop. A network result must never short-circuit, since the same blip would
 *   otherwise abort the entire sweep and demand a needless re-login.
 *
 * Token resolution is delegated to the SDK token provider, exactly as `fromIni`
 * delegates credential resolution. The provider is injectable so the branch is
 * unit-testable without touching the on-disk token cache.
 *
 * @param session SSO session name (used only for the remediation message).
 * @param region SSO region for the token provider.
 * @param resolveToken Token resolver; defaults to reading the cached SSO
 *   session token from disk.
 */
export async function preflightSso(
  session: string,
  region: string,
  resolveToken: (session: string, region: string) => Promise<unknown> =
    defaultResolveToken,
): Promise<PreflightResult> {
  try {
    await resolveToken(session, region);
    return { status: "ok", message: "" };
  } catch (err) {
    const { kind, message } = classifyError(err);
    if (kind === "network") return { status: "network", message };
    return { status: "expired", message: ssoRemediation(session) };
  }
}

/**
 * Resolve the cached SSO session token by session name.
 *
 * Reads the token the AWS CLI's `aws sso login --sso-session <name>` writes to
 * `~/.aws/sso/cache/<sha1(name)>.json`, via the same shared-config loader the
 * SDK token provider uses. A missing/corrupt cache file throws (surfacing as an
 * expired token), and a token already past its `expiresAt` is rejected here so
 * the caller treats it as expired rather than handing a stale token downstream.
 *
 * `region` is unused for the cache read; it is accepted to keep the resolver
 * signature stable for callers and fakes.
 */
async function defaultResolveToken(
  session: string,
  _region: string,
): Promise<unknown> {
  const token = await getSSOTokenFromFile(session);
  const expiresAt = token?.expiresAt;
  if (typeof expiresAt === "string") {
    const expiry = new Date(expiresAt).getTime();
    if (Number.isFinite(expiry) && expiry <= Date.now()) {
      throw new Error("SSO session token is expired");
    }
  }
  return token;
}

/** Operator-facing remediation message for an expired/missing SSO token. */
export function ssoRemediation(session: string): string {
  return session.length > 0
    ? `SSO session token expired or missing; run \`aws sso login --sso-session ${session}\``
    : "SSO session token expired or missing; run `aws sso login`";
}

// ---------------------------------------------------------------------------
// Pre-flight SSO gate (policy on top of preflightSso)
// ---------------------------------------------------------------------------

/**
 * Minimal logger surface {@link preflightSsoGate} needs. The swamp runtime
 * `context.logger` satisfies this structurally.
 */
export interface PreflightSsoLogger {
  /** Structured warn: a message template plus named fields. */
  warn(message: string, fields?: Record<string, unknown>): void;
}

/**
 * Canonical `scan_error` fragment for an aborted SSO pre-flight. Callers spread
 * it into their own row schema (each scanner keys rows differently — e.g. the
 * IAM audit stores `roleName` instead of `region`) and append their own row
 * prefix and `scannedAt`.
 */
export interface PreflightSsoErrorFragment {
  /** Always `sso` — the pre-flight talks to the SSO token cache, not AWS APIs. */
  service: "sso";
  /** Always `preflight_sso` — the shared pre-flight phase name. */
  phase: "preflight_sso";
  /** Always `auth_expired` — the only kind that aborts the sweep. */
  kind: "auth_expired";
  /** Operator-facing remediation message ({@link ssoRemediation}). */
  message: string;
}

/**
 * Decision returned by {@link preflightSsoGate}: proceed with the sweep, or
 * abort with the canonical error fragment to record.
 */
export type PreflightSsoDecision =
  | { abort: false }
  | { abort: true; error: PreflightSsoErrorFragment };

/** Arguments for {@link preflightSsoGate}. */
export interface PreflightSsoGateArgs {
  /** Shared SSO session name; `""` skips the pre-flight entirely. */
  ssoSession: string;
  /** SSO region for the token resolve. */
  ssoRegion: string;
  /**
   * SSO-token resolver injected into the pre-flight. Defaults (when omitted) to
   * the on-disk cache reader; tests pass a fake to drive the expired/ok/network
   * branches without touching disk or the SDK.
   */
  resolveSsoToken?: (session: string, region: string) => Promise<unknown>;
  /** Runtime logger for the shared warn messages. */
  logger: PreflightSsoLogger;
}

/**
 * Pre-flight the shared SSO session once, before the per-profile loop, and
 * decide whether the sweep may proceed. This is the *policy* layer every fleet
 * scanner previously re-assembled inline around {@link preflightSso}:
 *
 * - No configured session (`ssoSession === ""`) skips the check — proceed.
 * - `ok` — the token resolved; proceed.
 * - `network` — a transient DNS/socket blip; warn and proceed. A network
 *   result must never short-circuit, since the same blip would otherwise abort
 *   the entire sweep and demand a needless re-login.
 * - `expired` — the token is genuinely expired or missing; warn and abort with
 *   the canonical {@link PreflightSsoErrorFragment}. The caller spreads the
 *   fragment into its own `scan_error` row, logs its own completion summary,
 *   and returns early.
 *
 * @param args Session, region, optional injected resolver, and logger.
 * @returns The proceed/abort decision, with the error fragment on abort.
 */
export async function preflightSsoGate(
  args: PreflightSsoGateArgs,
): Promise<PreflightSsoDecision> {
  const { ssoSession, ssoRegion, resolveSsoToken, logger } = args;
  if (ssoSession.length === 0) return { abort: false };
  const pre = await preflightSso(ssoSession, ssoRegion, resolveSsoToken);
  if (pre.status === "expired") {
    logger.warn(
      "SSO pre-flight failed for session {session}: {message}",
      { session: ssoSession, message: pre.message },
    );
    return {
      abort: true,
      error: {
        service: "sso",
        phase: "preflight_sso",
        kind: "auth_expired",
        message: ssoRemediation(ssoSession),
      },
    };
  }
  if (pre.status === "network") {
    logger.warn(
      "SSO pre-flight hit a transient network error; proceeding with the " +
        "per-profile sweep: {message}",
      { message: pre.message },
    );
  }
  return { abort: false };
}

// ---------------------------------------------------------------------------
// Bootstrap region
// ---------------------------------------------------------------------------

/**
 * Strict bootstrap-region resolver for the account-level calls
 * (sts:GetCallerIdentity, ec2:DescribeRegions) that must target *some* region
 * before per-region scanning begins. Order: first configured region →
 * `AWS_REGION` → `AWS_DEFAULT_REGION` → `us-east-1` (a global-ish default that
 * is enabled on every account, used only for these bootstrap calls).
 * Whitespace-only values are treated as unset.
 */
export function resolveBootstrapRegion(
  regions: string[],
  env: (name: string) => string | undefined = (name) => Deno.env.get(name),
): string {
  const candidates = [
    regions[0],
    env("AWS_REGION"),
    env("AWS_DEFAULT_REGION"),
  ];
  for (const c of candidates) {
    if (typeof c === "string" && c.trim().length > 0) return c.trim();
  }
  return "us-east-1";
}
