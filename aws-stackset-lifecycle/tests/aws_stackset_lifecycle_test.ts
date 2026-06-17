/**
 * Unit tests for `@jentz/aws-stackset-lifecycle`.
 *
 * Pure-logic coverage exercised without any swamp context or live AWS:
 *   - `validateDeleteInstances` — every guard branch (no regions, no targets,
 *     whole-OU/root delete without confirmation, valid request, and the
 *     `confirmWholeTarget` bypass).
 *   - `pollToTerminal` — reaches a terminal status, and throws on timeout after
 *     `maxPolls`, driven by a fake `LifecycleApi` with a scripted status
 *     progression.
 *   - `isoOrEmpty` — Date, string, and empty/garbage input.
 *
 * No network or filesystem I/O.
 */

import { assertEquals, assertRejects } from "jsr:@std/assert@1";

import {
  isoOrEmpty,
  type LifecycleApi,
  pollToTerminal,
  validateDeleteInstances,
} from "../aws_stackset_lifecycle.ts";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const silentLogger = {
  info: () => {},
  debug: () => {},
  warn: () => {},
  error: () => {},
};

/** A minimal swamp-context stand-in: a silent logger and no abort signal. */
function fakeContext(): unknown {
  return { logger: silentLogger, signal: undefined };
}

/**
 * A fake LifecycleApi whose `describeOperation` returns a scripted progression
 * of statuses, advancing one step per call and holding the final entry. The
 * mutating calls are unused by these tests.
 */
function scriptedApi(statuses: string[]): LifecycleApi {
  let i = 0;
  return {
    deleteInstances: () => Promise.resolve("op-unused"),
    deleteStackSet: () => Promise.resolve(),
    describeOperation: () => {
      const status = statuses[Math.min(i, statuses.length - 1)];
      i++;
      return Promise.resolve({
        status,
        reason: status === "FAILED" ? "boom" : "",
      });
    },
  };
}

// ---------------------------------------------------------------------------
// validateDeleteInstances
// ---------------------------------------------------------------------------

Deno.test("validateDeleteInstances: no regions is an error", () => {
  const err = validateDeleteInstances({
    organizationalUnitIds: [],
    accounts: ["111111111111"],
    accountFilterType: "INTERSECTION",
    regions: [],
    confirmWholeTarget: false,
  });
  assertEquals(err, "at least one region is required");
});

Deno.test("validateDeleteInstances: no targets is an error", () => {
  const err = validateDeleteInstances({
    organizationalUnitIds: [],
    accounts: [],
    accountFilterType: "INTERSECTION",
    regions: ["us-east-1"],
    confirmWholeTarget: false,
  });
  assertEquals(
    err,
    "deploymentTargets must include organizationalUnitIds and/or accounts",
  );
});

Deno.test("validateDeleteInstances: whole-OU/root delete without confirmation is refused", () => {
  // OUs only, no explicit accounts, default-but-non-INTERSECTION combination →
  // a whole-OU/root shape that must be confirmed.
  const err = validateDeleteInstances({
    organizationalUnitIds: ["ou-root-abc123"],
    accounts: [],
    accountFilterType: "NONE",
    regions: ["us-east-1"],
    confirmWholeTarget: false,
  });
  assertEquals(err !== null, true);
  assertEquals(err?.includes("refusing a whole-OU/root delete"), true);
});

Deno.test("validateDeleteInstances: account-scoped INTERSECTION batch is valid", () => {
  const err = validateDeleteInstances({
    organizationalUnitIds: ["ou-root-abc123"],
    accounts: ["111111111111", "222222222222"],
    accountFilterType: "INTERSECTION",
    regions: ["us-east-1", "eu-west-1"],
    confirmWholeTarget: false,
  });
  assertEquals(err, null);
});

Deno.test("validateDeleteInstances: confirmWholeTarget=true bypasses the guard", () => {
  // OUs only, no explicit accounts — refused above, but allowed once confirmed.
  const err = validateDeleteInstances({
    organizationalUnitIds: ["ou-root-abc123"],
    accounts: [],
    accountFilterType: "UNION",
    regions: ["us-east-1"],
    confirmWholeTarget: true,
  });
  assertEquals(err, null);
});

Deno.test("validateDeleteInstances: accounts present but non-INTERSECTION still needs confirmation", () => {
  // Listing accounts under UNION is not the safe batched shape, so it is still
  // treated as a whole-target delete and must be confirmed.
  const err = validateDeleteInstances({
    organizationalUnitIds: ["ou-root-abc123"],
    accounts: ["111111111111"],
    accountFilterType: "UNION",
    regions: ["us-east-1"],
    confirmWholeTarget: false,
  });
  assertEquals(err !== null, true);
  assertEquals(err?.includes("refusing a whole-OU/root delete"), true);
});

// ---------------------------------------------------------------------------
// pollToTerminal
// ---------------------------------------------------------------------------

Deno.test("pollToTerminal: returns immediately on a terminal status", async () => {
  const api = scriptedApi(["SUCCEEDED"]);
  const result = await pollToTerminal(api, "op-1", 5, 10, fakeContext());
  assertEquals(result.status, "SUCCEEDED");
});

Deno.test("pollToTerminal: progresses RUNNING → SUCCEEDED", async () => {
  // First poll RUNNING (sleeps a real but tiny interval), second SUCCEEDED.
  const api = scriptedApi(["RUNNING", "SUCCEEDED"]);
  const result = await pollToTerminal(api, "op-2", 0.001, 10, fakeContext());
  assertEquals(result.status, "SUCCEEDED");
});

Deno.test("pollToTerminal: surfaces a FAILED terminal status and reason", async () => {
  const api = scriptedApi(["FAILED"]);
  const result = await pollToTerminal(api, "op-3", 5, 10, fakeContext());
  assertEquals(result.status, "FAILED");
  assertEquals(result.reason, "boom");
});

Deno.test("pollToTerminal: throws after maxPolls when never terminal", async () => {
  const api = scriptedApi(["RUNNING"]);
  await assertRejects(
    () => pollToTerminal(api, "op-4", 0.001, 3, fakeContext()),
    Error,
    "did not finish within 3 polls",
  );
});

// ---------------------------------------------------------------------------
// isoOrEmpty
// ---------------------------------------------------------------------------

Deno.test("isoOrEmpty: Date, string, and empty/garbage input", () => {
  const d = new Date("2026-06-17T00:00:00.000Z");
  assertEquals(isoOrEmpty(d), "2026-06-17T00:00:00.000Z");
  assertEquals(
    isoOrEmpty("2026-06-17T00:00:00.000Z"),
    "2026-06-17T00:00:00.000Z",
  );
  assertEquals(isoOrEmpty(""), "");
  assertEquals(isoOrEmpty(undefined), "");
  assertEquals(isoOrEmpty(12345), "");
});
