/**
 * Unit tests for `@jentz/aws-stackset-lifecycle`.
 *
 * Pure-logic coverage exercised without any swamp context or live AWS:
 * `validateDeleteInstances` across every guard branch (no regions, no
 * targets, whole-OU/root delete without confirmation, valid request, and the
 * `confirmWholeTarget` bypass).
 *
 * The poll-to-terminal budget semantics and `isoOrEmpty` this suite used to
 * cover are owned by the canonical `_lib/stackset_test.ts`; the polling glue
 * through `runDeleteInstances` is covered by the smoke suite.
 *
 * No network or filesystem I/O.
 */

import { assertEquals } from "jsr:@std/assert@1";

import { validateDeleteInstances } from "../aws_stackset_lifecycle.ts";

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
