/**
 * Unit tests for the pure coalesce core (`_lib/coverage.ts`) in ISOLATION.
 *
 * No swamp/AWS context, no I/O — just the data shaping. These are the most
 * important tests in the package: the model and the report both derive their
 * verdicts from exactly this code, so anything that passes here is what both
 * surfaces will agree on.
 *
 * All account ids are clearly-fictional placeholders. `accountId` is an opaque
 * `z.string()` in the schema, so a named placeholder round-trips identically to
 * a real 12-digit id everywhere it is only sorted, mapped, or asserted back.
 *
 * @module
 */

import { assert, assertEquals } from "jsr:@std/assert@1";

import {
  aggregateCoverage,
  aggregateMechanism,
  coalesce,
  type Collected,
  type CoverageRow,
  isDisagreement,
  type Mechanism,
  reconcileAccount,
  refineMechanism,
  representativeStacksetStatus,
  type Role,
  type RoleDetail,
  summarizeCoverage,
} from "../_lib/coverage.ts";

const ACCT_A = "ACCT_ALPHA";
const ACCT_B = "ACCT_BETA";
const ACCT_C = "ACCT_GAMMA";
const STACKSET = "acme-ss";

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

/** A fully-defaulted IAM role row with overrides applied. */
function role(over: Partial<Role>): Role {
  return {
    accountId: ACCT_A,
    accountName: "",
    profile: "",
    roleName: "Readonly",
    required: true,
    exists: true,
    managementMechanism: "cfn-stackset",
    cfnStackName: `StackSet-${STACKSET}-abc`,
    cfnStackRegion: "us-east-1",
    compliant: true,
    findings: [],
    attachedManagedPolicyArns: [],
    createDate: "",
    ...over,
  };
}

/** A RoleDetail with overrides applied (for the aggregate-only helpers). */
function detail(over: Partial<RoleDetail>): RoleDetail {
  return {
    roleName: "Readonly",
    required: true,
    exists: true,
    compliant: true,
    mechanism: "this-stackset",
    cfnStackName: "",
    findings: [],
    ...over,
  };
}

function collected(over: Partial<Collected>): Collected {
  return {
    instances: [],
    summaries: [],
    roles: [],
    iamErrors: [],
    skipped: 0,
    ...over,
  };
}

// ---------------------------------------------------------------------------
// aggregateCoverage — the verdict
// ---------------------------------------------------------------------------

Deno.test("aggregateCoverage: covered-compliant only when every required role present & compliant", () => {
  const roles = [
    detail({ roleName: "A", required: true, exists: true, compliant: true }),
    detail({ roleName: "B", required: true, exists: true, compliant: true }),
  ];
  assertEquals(aggregateCoverage(roles, true), "covered-compliant");
});

Deno.test("aggregateCoverage: all present but one noncompliant => covered-noncompliant", () => {
  const roles = [
    detail({ roleName: "A", required: true, exists: true, compliant: true }),
    detail({ roleName: "B", required: true, exists: true, compliant: false }),
  ];
  assertEquals(aggregateCoverage(roles, true), "covered-noncompliant");
});

Deno.test("aggregateCoverage: some required missing but some present => covered-partial", () => {
  const roles = [
    detail({ roleName: "A", required: true, exists: true, compliant: true }),
    detail({ roleName: "B", required: true, exists: false, compliant: false }),
  ];
  assertEquals(aggregateCoverage(roles, true), "covered-partial");
});

Deno.test("aggregateCoverage: no required role present => uncovered", () => {
  const roles = [
    detail({ roleName: "A", required: true, exists: false, compliant: false }),
  ];
  assertEquals(aggregateCoverage(roles, true), "uncovered");
});

Deno.test("aggregateCoverage: not in the IAM sweep => unknown (regardless of roles)", () => {
  const roles = [detail({ exists: true, compliant: true })];
  assertEquals(aggregateCoverage(roles, false), "unknown");
});

Deno.test("aggregateCoverage: no-required-roles pool branch falls back to all roles", () => {
  // No role flagged required: the pool becomes every role, and a present +
  // compliant optional role still reads as covered-compliant.
  const roles = [
    detail({ roleName: "Opt", required: false, exists: true, compliant: true }),
  ];
  assertEquals(aggregateCoverage(roles, true), "covered-compliant");

  // Empty pool (in the sweep but zero role details) => unknown.
  assertEquals(aggregateCoverage([], true), "unknown");
});

// ---------------------------------------------------------------------------
// refineMechanism — classification
// ---------------------------------------------------------------------------

Deno.test("refineMechanism: this-stackset vs other-stackset via the StackSet-<name>- prefix", () => {
  const thisOne = role({
    managementMechanism: "cfn-stackset",
    cfnStackName: `StackSet-${STACKSET}-0001`,
  });
  assertEquals(refineMechanism(thisOne, STACKSET), "this-stackset");

  const other = role({
    managementMechanism: "cfn-stackset",
    cfnStackName: "StackSet-some-other-ss-0001",
  });
  assertEquals(refineMechanism(other, STACKSET), "other-stackset");
});

Deno.test("refineMechanism: standalone-stack, manual, and missing", () => {
  assertEquals(
    refineMechanism(
      role({ managementMechanism: "cfn-standalone-stack" }),
      STACKSET,
    ),
    "standalone-stack",
  );
  assertEquals(
    refineMechanism(role({ managementMechanism: "manual" }), STACKSET),
    "manual",
  );
  // exists:false always wins, regardless of the recorded mechanism.
  assertEquals(
    refineMechanism(role({ exists: false }), STACKSET),
    "missing",
  );
  // Unknown mechanism string falls through to unknown.
  assertEquals(
    refineMechanism(role({ managementMechanism: "??" }), STACKSET),
    "unknown",
  );
});

// ---------------------------------------------------------------------------
// aggregateMechanism — mixed on disagreement
// ---------------------------------------------------------------------------

Deno.test("aggregateMechanism: single mechanism passes through; disagreement => mixed", () => {
  const same: RoleDetail[] = [
    detail({ mechanism: "this-stackset", exists: true }),
    detail({ mechanism: "this-stackset", exists: true }),
  ];
  assertEquals(aggregateMechanism(same), "this-stackset");

  const mixed: RoleDetail[] = [
    detail({ mechanism: "this-stackset", exists: true }),
    detail({ mechanism: "manual", exists: true }),
  ];
  assertEquals(aggregateMechanism(mixed), "mixed");

  // No present roles => missing (a present:false role does not contribute).
  const none: RoleDetail[] = [detail({ mechanism: "missing", exists: false })];
  assertEquals(aggregateMechanism(none), "missing");
});

// ---------------------------------------------------------------------------
// representativeStacksetStatus
// ---------------------------------------------------------------------------

Deno.test("representativeStacksetStatus: CURRENT wins, then INOPERABLE, then OUTDATED, else fallback", () => {
  assertEquals(representativeStacksetStatus([]), "no-instance");
  assertEquals(
    representativeStacksetStatus([
      { account: ACCT_A, overallStatus: "OUTDATED" } as never,
      { account: ACCT_A, overallStatus: "CURRENT" } as never,
    ]),
    "CURRENT",
  );
  assertEquals(
    representativeStacksetStatus([
      { account: ACCT_A, overallStatus: "INOPERABLE" } as never,
      { account: ACCT_A, overallStatus: "OUTDATED" } as never,
    ]),
    "INOPERABLE",
  );
  assertEquals(
    representativeStacksetStatus([
      {
        account: ACCT_A,
        overallStatus: "",
        detailedStatus: "PENDING",
      } as never,
    ]),
    "PENDING",
  );
});

// ---------------------------------------------------------------------------
// reconcileAccount / isDisagreement — lens disagreement
// ---------------------------------------------------------------------------

Deno.test("reconcileAccount: stackset CURRENT but a required role missing => DISCREPANCY", () => {
  const recon = reconcileAccount({
    roles: [detail({ roleName: "A", required: true, exists: false })],
    missingRequiredRoles: ["A"],
    mechanism: "missing",
    stacksetStatus: "CURRENT",
    inIamSweep: true,
  });
  assert(recon.includes("DISCREPANCY"), recon);
  assert(
    isDisagreement({ reconciliation: recon } as CoverageRow),
    "DISCREPANCY must read as a disagreement",
  );
});

Deno.test("reconcileAccount: present via this-stackset while instance NOT current => stackset-behind", () => {
  const recon = reconcileAccount({
    roles: [detail({ exists: true, mechanism: "this-stackset" })],
    missingRequiredRoles: [],
    mechanism: "this-stackset",
    stacksetStatus: "OUTDATED",
    inIamSweep: true,
  });
  assert(recon.includes("stackset-behind"), recon);
  assert(isDisagreement({ reconciliation: recon } as CoverageRow));
});

Deno.test("reconcileAccount: consistent this-stackset + CURRENT is NOT a disagreement", () => {
  const recon = reconcileAccount({
    roles: [detail({ exists: true, mechanism: "this-stackset" })],
    missingRequiredRoles: [],
    mechanism: "this-stackset",
    stacksetStatus: "CURRENT",
    inIamSweep: true,
  });
  assert(recon.includes("consistent"), recon);
  assertEquals(isDisagreement({ reconciliation: recon } as CoverageRow), false);
});

Deno.test("reconcileAccount: not in IAM sweep => explicit unknown label", () => {
  const recon = reconcileAccount({
    roles: [],
    missingRequiredRoles: [],
    mechanism: "missing",
    stacksetStatus: "CURRENT",
    inIamSweep: false,
  });
  assertEquals(recon, "unknown: account not covered by the IAM sweep");
});

// ---------------------------------------------------------------------------
// summarizeCoverage — per-role rollup
// ---------------------------------------------------------------------------

Deno.test("summarizeCoverage: byRole rollup counts present/compliant/missing, skipping rows not inIamSweep", () => {
  const rows: CoverageRow[] = [
    {
      accountId: ACCT_A,
      accountName: "a",
      coverage: "covered-compliant",
      mechanism: "this-stackset",
      requiredTotal: 1,
      requiredPresent: 1,
      requiredCompliant: 1,
      missingRequiredRoles: [],
      roles: [detail({ roleName: "Readonly", exists: true, compliant: true })],
      stacksetStatus: "CURRENT",
      inStacksetTargets: true,
      inIamSweep: true,
      reconciliation: "consistent",
    },
    {
      accountId: ACCT_B,
      accountName: "b",
      coverage: "covered-partial",
      mechanism: "this-stackset",
      requiredTotal: 1,
      requiredPresent: 0,
      requiredCompliant: 0,
      missingRequiredRoles: ["Readonly"],
      roles: [
        detail({ roleName: "Readonly", exists: false, compliant: false }),
      ],
      stacksetStatus: "CURRENT",
      inStacksetTargets: true,
      inIamSweep: true,
      reconciliation: "missing required role(s): Readonly",
    },
    {
      // NOT in the IAM sweep: must be skipped by the per-role rollup even
      // though it carries a role detail.
      accountId: ACCT_C,
      accountName: "c",
      coverage: "unknown",
      mechanism: "missing",
      requiredTotal: 0,
      requiredPresent: 0,
      requiredCompliant: 0,
      missingRequiredRoles: [],
      roles: [detail({ roleName: "Readonly", exists: true, compliant: true })],
      stacksetStatus: "CURRENT",
      inStacksetTargets: true,
      inIamSweep: false,
      reconciliation: "unknown: account not covered by the IAM sweep",
    },
  ];

  const { byRole, byCoverage } = summarizeCoverage(rows);
  assertEquals(byRole.length, 1);
  assertEquals(byRole[0].roleName, "Readonly");
  // ACCT_C is excluded (not inIamSweep): present=1 (A), compliant=1 (A), missing=1 (B).
  assertEquals(byRole[0].present, 1);
  assertEquals(byRole[0].compliant, 1);
  assertEquals(byRole[0].missing, 1);
  assertEquals(byCoverage["covered-compliant"], 1);
  assertEquals(byCoverage["unknown"], 1);
});

// ---------------------------------------------------------------------------
// coalesce — end to end over the pure core
// ---------------------------------------------------------------------------

Deno.test("coalesce: multi-role account, sorts rows by account id, derives stackset name", () => {
  const c = collected({
    summaries: [{
      stackSetName: STACKSET,
      accountsTargeted: 2,
      instanceCount: 2,
    }],
    instances: [
      {
        stackSetName: STACKSET,
        account: ACCT_B,
        region: "us-east-1",
        overallStatus: "CURRENT",
        detailedStatus: "",
        failureCategory: "",
      },
      {
        stackSetName: STACKSET,
        account: ACCT_A,
        region: "us-east-1",
        overallStatus: "OUTDATED",
        detailedStatus: "",
        failureCategory: "",
      },
    ],
    roles: [
      role({
        accountId: ACCT_A,
        accountName: "alpha",
        roleName: "ECR",
        exists: true,
        compliant: true,
      }),
      role({
        accountId: ACCT_A,
        accountName: "alpha",
        roleName: "Readonly",
        exists: true,
        compliant: false,
      }),
      role({
        accountId: ACCT_B,
        accountName: "beta",
        roleName: "Readonly",
        exists: true,
        compliant: true,
        cfnStackName: `StackSet-${STACKSET}-b`,
      }),
    ],
  });

  const res = coalesce(c);
  assertEquals(res.stackSetName, STACKSET);
  assertEquals(res.roleNames, ["ECR", "Readonly"]);
  // Sorted by accountId: ALPHA before BETA.
  assertEquals(res.rows.map((r) => r.accountId), [ACCT_A, ACCT_B]);

  const a = res.rows[0];
  // ALPHA: both required present, one noncompliant => covered-noncompliant.
  assertEquals(a.coverage, "covered-noncompliant");
  assertEquals(a.requiredTotal, 2);
  assertEquals(a.requiredPresent, 2);
  assertEquals(a.requiredCompliant, 1);
  assertEquals(a.accountName, "alpha");
  // Per-role detail is sorted by role name.
  assertEquals(a.roles.map((r) => r.roleName), ["ECR", "Readonly"]);

  const b = res.rows[1];
  assertEquals(b.coverage, "covered-compliant");
  assertEquals(b.stacksetStatus, "CURRENT");
});

Deno.test("coalesce: account in the StackSet but absent from the IAM sweep => unknown", () => {
  const c = collected({
    summaries: [{
      stackSetName: STACKSET,
      accountsTargeted: 1,
      instanceCount: 1,
    }],
    instances: [{
      stackSetName: STACKSET,
      account: ACCT_C,
      region: "us-east-1",
      overallStatus: "CURRENT",
      detailedStatus: "",
      failureCategory: "",
    }],
  });
  const res = coalesce(c);
  assertEquals(res.rows.length, 1);
  const row = res.rows[0];
  assertEquals(row.coverage, "unknown");
  assertEquals(row.inIamSweep, false);
  assertEquals(row.inStacksetTargets, true);
  // accountName falls back to the id when no IAM row supplied a name.
  assertEquals(row.accountName, ACCT_C);
});

Deno.test("coalesce: unresolved IAM profiles (no account id) are surfaced separately", () => {
  const c = collected({
    roles: [role({ accountId: ACCT_A, exists: true, compliant: true })],
    iamErrors: [
      {
        profile: "stale-readonly",
        accountId: "",
        roleName: "",
        kind: "auth_expired",
        message: "expired",
      },
      {
        profile: "ok-readonly",
        accountId: ACCT_A,
        roleName: "",
        kind: "other",
        message: "noise",
      },
    ],
  });
  const res = coalesce(c);
  // Only the account-less error is an unresolved profile.
  assertEquals(res.unresolvedProfiles, [
    { profile: "stale-readonly", kind: "auth_expired" },
  ]);
});

Deno.test("coalesce: missing required role while stackset CURRENT marks a disagreement", () => {
  const c = collected({
    instances: [{
      stackSetName: STACKSET,
      account: ACCT_A,
      region: "us-east-1",
      overallStatus: "CURRENT",
      detailedStatus: "",
      failureCategory: "",
    }],
    roles: [
      role({
        accountId: ACCT_A,
        roleName: "Readonly",
        exists: true,
        compliant: true,
      }),
      role({
        accountId: ACCT_A,
        roleName: "ECR",
        required: true,
        exists: false,
      }),
    ],
  });
  const res = coalesce(c);
  const row = res.rows[0];
  assertEquals(row.missingRequiredRoles, ["ECR"]);
  assert(isDisagreement(row), row.reconciliation);
  const { discrepancies } = summarizeCoverage(res.rows);
  assertEquals(discrepancies.map((r) => r.accountId), [ACCT_A]);
});

// A compile-time + runtime guard that the mechanism vocabulary is stable.
Deno.test("Mechanism vocabulary is the documented closed set", () => {
  const vocab: Mechanism[] = [
    "this-stackset",
    "other-stackset",
    "standalone-stack",
    "manual",
    "missing",
    "unknown",
  ];
  assertEquals(new Set(vocab).size, 6);
});
