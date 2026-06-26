/**
 * Unit tests for the shared `_lib/scan_error.ts` module.
 *
 * Pure classification (network vs auth_expired vs access_denied vs other,
 * including the wrapped-in-credentials and SSO-role-ARN regressions),
 * `errorBucket` mapping, and the `reconcileScanErrors` source-side reconcile
 * driven by a fake in-memory {@link ScanErrorStore}.
 *
 * @module
 */

import { assertEquals } from "jsr:@std/assert@1";
import {
  classifyError,
  errorBucket,
  reconcileScanErrors,
  ScanErrorSchema,
  type ScanErrorStore,
} from "./scan_error.ts";

// ---------------------------------------------------------------------------
// ScanErrorSchema
// ---------------------------------------------------------------------------

Deno.test("ScanErrorSchema: row without service parses with service defaulting to ''", () => {
  // Back-compat: rows written by earlier scanners predate the `service` field,
  // so a service-less row must still parse and read back as `service === ""`.
  const result = ScanErrorSchema.safeParse({
    profile: "prod-readonly",
    accountId: "123456789012",
    region: "eu-west-1",
    phase: "credentials",
    kind: "auth_expired",
    message: "Token is expired",
    scannedAt: "2026-06-26T00:00:00Z",
  });
  assertEquals(result.success, true);
  assertEquals(result.success && result.data.service, "");
});

Deno.test("ScanErrorSchema: row with an unknown kind is rejected", () => {
  // Strict enum: an unknown `kind` must be REJECTED, never coerced to "other".
  const result = ScanErrorSchema.safeParse({
    profile: "prod-readonly",
    accountId: "123456789012",
    region: "eu-west-1",
    service: "sts",
    phase: "credentials",
    kind: "totally-unknown",
    message: "Token is expired",
    scannedAt: "2026-06-26T00:00:00Z",
  });
  assertEquals(result.success, false);
});

// ---------------------------------------------------------------------------
// classifyError
// ---------------------------------------------------------------------------

Deno.test("classifyError: DNS failure wrapped in credentials error => network", () => {
  // The SDK wraps a getaddrinfo failure during credential resolution in a
  // CredentialsProviderError "Could not load credentials …". network must win.
  const err = Object.assign(
    new Error("Could not load credentials from any providers"),
    { name: "CredentialsProviderError" },
  );
  // deno-lint-ignore no-explicit-any
  (err as any).cause = Object.assign(
    new Error("getaddrinfo ENOTFOUND sts.eu-west-1.amazonaws.com"),
    { name: "Error" },
  );
  assertEquals(classifyError(err).kind, "network");
});

Deno.test("classifyError: bare ETIMEDOUT => network", () => {
  assertEquals(
    classifyError(new Error("connect ETIMEDOUT 10.0.0.1:443")).kind,
    "network",
  );
});

Deno.test("classifyError: socket hang up => network", () => {
  assertEquals(classifyError(new Error("socket hang up")).kind, "network");
});

Deno.test("classifyError: ExpiredTokenException => auth_expired", () => {
  assertEquals(
    classifyError({
      name: "ExpiredTokenException",
      message: "The security token included in the request is expired",
    }).kind,
    "auth_expired",
  );
});

Deno.test("classifyError: plain 'Token is expired' => auth_expired", () => {
  assertEquals(
    classifyError(new Error("Token is expired")).kind,
    "auth_expired",
  );
});

Deno.test("classifyError: AccessDenied w/ AWSReservedSSO ARN => access_denied", () => {
  // Regression: an SSO role ARN must NOT be misread as auth_expired.
  assertEquals(
    classifyError({
      name: "AccessDeniedException",
      message:
        "arn:aws:sts::1234:assumed-role/AWSReservedSSO_RO_x/y is not authorized",
    }).kind,
    "access_denied",
  );
});

Deno.test("classifyError: unknown error => other", () => {
  assertEquals(
    classifyError(new Error("some unrelated failure")).kind,
    "other",
  );
});

Deno.test("classifyError: returns the original message", () => {
  assertEquals(
    classifyError(new Error("Token is expired")).message,
    "Token is expired",
  );
});

// ---------------------------------------------------------------------------
// errorBucket
// ---------------------------------------------------------------------------

Deno.test("errorBucket maps each kind to its remediation bucket", () => {
  assertEquals(errorBucket("network"), "transient-network-error");
  assertEquals(errorBucket("auth_expired"), "needs-aws-sso-login");
  assertEquals(errorBucket("access_denied"), "blocked-by-SCP-IAM");
  assertEquals(errorBucket("other"), "other");
  assertEquals(errorBucket("anything-else"), "other");
});

// ---------------------------------------------------------------------------
// reconcileScanErrors
// ---------------------------------------------------------------------------

/** A fake in-memory store that records every delete call. */
function fakeStore(
  rows: Array<{ name: string; profile: string }>,
): ScanErrorStore & { deleted: string[] } {
  const deleted: string[] = [];
  return {
    deleted,
    list: () => Promise.resolve(rows),
    delete: (name: string) => {
      deleted.push(name);
      return Promise.resolve();
    },
  };
}

Deno.test("reconcileScanErrors deletes a recovered unit's stale row", async () => {
  const store = fakeStore([
    {
      name: "error-prod-readonly-eu-west-1-sts-credentials",
      profile: "prod-readonly",
    },
  ]);
  await reconcileScanErrors(
    store,
    new Set(["prod-readonly"]), // attempted (and it recovered)
    new Set(), // no fresh errors written this run
  );
  assertEquals(store.deleted, [
    "error-prod-readonly-eu-west-1-sts-credentials",
  ]);
});

Deno.test("reconcileScanErrors keeps a still-failing unit's row", async () => {
  const key = "error-prod-readonly-eu-west-1-sts-credentials";
  const store = fakeStore([{ name: key, profile: "prod-readonly" }]);
  await reconcileScanErrors(
    store,
    new Set(["prod-readonly"]),
    new Set([key]), // re-written this run => still failing
  );
  assertEquals(store.deleted, []);
});

Deno.test("reconcileScanErrors leaves rows for un-attempted profiles untouched", async () => {
  const store = fakeStore([
    {
      name: "error-other-readonly-eu-west-1-sts-credentials",
      profile: "other-readonly",
    },
  ]);
  await reconcileScanErrors(
    store,
    new Set(["prod-readonly"]), // 'other-readonly' was not attempted this run
    new Set(),
  );
  assertEquals(store.deleted, []);
});
