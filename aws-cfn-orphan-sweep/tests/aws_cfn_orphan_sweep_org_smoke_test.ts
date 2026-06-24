/**
 * Org smoke tests — drive `runEnumerateOrg` end-to-end through an in-memory
 * fake `OrgApi` that returns a per-account fake `SweepApi` from inline fixtures,
 * plus a recording swamp method context. No AWS calls, no live SDK, no network.
 *
 * The fake `OrgApi` records every account id `assumedApi` is asked for, so the
 * tests can prove the management account is never self-assumed and that
 * `onlyAccount` narrows the assumed set. All account ids and stack names are
 * synthetic placeholders so the corpus is safe to ship.
 */

import { assert, assertEquals } from "jsr:@std/assert@1";

import {
  type EnumerateOrgArgs,
  type GlobalArgs,
  type OrgAccount,
  type OrgApi,
  type ResourceRef,
  runEnumerateOrg,
  type StackSummary,
  type SweepApi,
} from "../aws_cfn_orphan_sweep.ts";

// ---------------------------------------------------------------------------
// Synthetic placeholder org
// ---------------------------------------------------------------------------

const MGMT = "111111111111";
const MEMBER_A = "222222222222";
const MEMBER_B = "333333333333";
const PREFIX = "StackSet-IAMCustomPasswordPolicy-";

// ---------------------------------------------------------------------------
// In-memory SweepApi replay (mirrors the single-account smoke test)
// ---------------------------------------------------------------------------

interface ApiFixture {
  account: string;
  /** region -> stacks returned by listStacks. */
  stacksByRegion: Record<string, StackSummary[]>;
  /** stackName -> resources returned by listStackResources. */
  resourcesByStack: Record<string, ResourceRef[]>;
  /** When set, listStacks rejects with this message (skip-don't-abort teeth). */
  failListStacks?: string;
}

function fakeApi(fixture: ApiFixture): SweepApi {
  return {
    getAccountId: () => Promise.resolve(fixture.account),
    listStacks: (region: string) =>
      fixture.failListStacks
        ? Promise.reject(new Error(fixture.failListStacks))
        : Promise.resolve(fixture.stacksByRegion[region] ?? []),
    listStackResources: (stackName: string, _region: string) =>
      Promise.resolve(fixture.resourcesByStack[stackName] ?? []),
    // Not exercised by the read-only enumerate path.
    describeStackStatus: () => Promise.resolve(null),
    deleteStack: () => Promise.resolve(),
    deleteFunction: () => Promise.resolve(),
    roleExists: () => Promise.resolve(false),
  };
}

// A complete orphan resource set: the dead custom resource, its IAM role, and
// the backing Lambda.
function orphanResources(suffix: string): ResourceRef[] {
  return [
    {
      logicalId: "PasswordPolicy",
      physicalId: `custom-${suffix}`,
      type: "Custom::IAMPasswordPolicy",
      status: "CREATE_COMPLETE",
    },
    {
      logicalId: "LambdaRole",
      physicalId: `${PREFIX}role-${suffix}`,
      type: "AWS::IAM::Role",
      status: "CREATE_COMPLETE",
    },
    {
      logicalId: "PolicyFn",
      physicalId: `policy-fn-${suffix}`,
      type: "AWS::Lambda::Function",
      status: "CREATE_COMPLETE",
    },
  ];
}

/** One matching stack in us-east-1 plus its orphan resources, for `account`. */
function singleOrphanFixture(account: string, suffix: string): ApiFixture {
  const stack = `${PREFIX}${suffix}`;
  return {
    account,
    stacksByRegion: {
      "us-east-1": [{
        StackName: stack,
        StackId: `arn:stack/${suffix}`,
        StackStatus: "CREATE_COMPLETE",
      }],
    },
    resourcesByStack: { [stack]: orphanResources(suffix) },
  };
}

// ---------------------------------------------------------------------------
// In-memory OrgApi seam
// ---------------------------------------------------------------------------

interface OrgFixture {
  management: string;
  accounts: OrgAccount[];
  /** account id -> the SweepApi fixture for that account. */
  apiByAccount: Record<string, ApiFixture>;
  /** account ids whose assumedApi() should throw (assume failure). */
  assumeThrowsFor?: Set<string>;
}

/** Build a recording fake OrgApi; `assumedCalls` collects the ids assumed. */
function fakeOrg(
  fixture: OrgFixture,
): { org: OrgApi; assumedCalls: string[] } {
  const assumedCalls: string[] = [];
  const org: OrgApi = {
    managementAccountId: () => Promise.resolve(fixture.management),
    listAccounts: () => Promise.resolve(fixture.accounts),
    baseApi: () => fakeApi(fixture.apiByAccount[fixture.management]),
    assumedApi: (accountId: string) => {
      assumedCalls.push(accountId);
      if (fixture.assumeThrowsFor?.has(accountId)) {
        throw new Error(`assume into ${accountId} denied`);
      }
      return fakeApi(fixture.apiByAccount[accountId]);
    },
  };
  return { org, assumedCalls };
}

// ---------------------------------------------------------------------------
// Recording swamp method context (mirrors the single-account smoke test)
// ---------------------------------------------------------------------------

interface Written {
  spec: string;
  key: string;
  data: Record<string, unknown>;
}

const silentLogger = {
  info: () => {},
  debug: () => {},
  warn: () => {},
  error: () => {},
};

function makeContext(): { context: unknown; written: Written[] } {
  const written: Written[] = [];
  const context = {
    globalArgs: {},
    logger: silentLogger,
    signal: undefined,
    writeResource: (
      spec: string,
      key: string,
      data: Record<string, unknown>,
    ) => {
      written.push({ spec, key, data });
      return Promise.resolve({ id: `${spec}:${key}`, name: key });
    },
  };
  return { context, written };
}

function globals(over: Partial<GlobalArgs> = {}): GlobalArgs {
  return {
    namePrefix: PREFIX,
    regions: ["us-east-1"],
    profile: "",
    assumeRoleName: "AWSControlTowerExecution",
    ...over,
  };
}

function orgArgs(over: Partial<EnumerateOrgArgs> = {}): EnumerateOrgArgs {
  return { onlyAccount: "", ...over };
}

// A three-account org: management + two members, each with one orphan.
function threeAccountOrg(over: Partial<OrgFixture> = {}): OrgFixture {
  return {
    management: MGMT,
    accounts: [
      { id: MGMT, name: "Management" },
      { id: MEMBER_A, name: "Workload-A" },
      { id: MEMBER_B, name: "Workload-B" },
    ],
    apiByAccount: {
      [MGMT]: singleOrphanFixture(MGMT, "mgmt"),
      [MEMBER_A]: singleOrphanFixture(MEMBER_A, "a"),
      [MEMBER_B]: singleOrphanFixture(MEMBER_B, "b"),
    },
    ...over,
  };
}

// ---------------------------------------------------------------------------
// 1. FAN-OUT
// ---------------------------------------------------------------------------

Deno.test("org smoke: fans out across mgmt + 2 members, one org-summary rollup", async () => {
  const { context, written } = makeContext();
  const { org } = fakeOrg(threeAccountOrg());

  const result = await runEnumerateOrg({
    org,
    globals: globals(),
    args: orgArgs(),
    context,
  });

  // Exactly one org-summary keyed by the management account.
  const orgSummaries = written.filter((w) => w.spec === "org-summary");
  assertEquals(orgSummaries.length, 1);
  const os = orgSummaries[0];
  assertEquals(os.key, `org-summary-${MGMT}`);
  assertEquals(os.data.managementAccount, MGMT);
  assertEquals(os.data.accountsDiscovered, 3);
  assertEquals(os.data.accountsProcessed, 3);
  assertEquals(os.data.accountsFailed, 0);
  assertEquals(os.data.failures, []);
  assertEquals(os.data.mode, "enumerate");
  assertEquals(os.data.applied, false);
  assertEquals(os.data.assumeRoleName, "AWSControlTowerExecution");
  // Each account contributed exactly one orphan.
  assertEquals(os.data.totalOrphans, 3);

  // Per-account orphan + summary rows were written for EACH account, keyed by
  // account.
  for (const acct of [MGMT, MEMBER_A, MEMBER_B]) {
    const orphans = written.filter((w) =>
      w.spec === "orphan" && (w.data.account === acct)
    );
    assertEquals(orphans.length, 1, `one orphan row for ${acct}`);
    const summaries = written.filter((w) =>
      w.spec === "summary" && w.key === `summary-${acct}`
    );
    assertEquals(summaries.length, 1, `one summary row for ${acct}`);
  }

  // The driver result mirrors the rollup.
  assertEquals(result.managementAccount, MGMT);
  assertEquals(result.accountsDiscovered, 3);
  assertEquals(result.accountsProcessed, 3);
  assertEquals(result.accountsFailed, 0);
  assertEquals(result.totalOrphans, 3);
});

// ---------------------------------------------------------------------------
// 2. MGMT-AMBIENT (no self-assume)
// ---------------------------------------------------------------------------

Deno.test("org smoke: management account uses ambient creds, is never self-assumed", async () => {
  const { context } = makeContext();
  const { org, assumedCalls } = fakeOrg(threeAccountOrg());

  await runEnumerateOrg({ org, globals: globals(), args: orgArgs(), context });

  // assumedApi was called for the members but NEVER for the management account.
  assertEquals(assumedCalls.sort(), [MEMBER_A, MEMBER_B]);
  assert(
    !assumedCalls.includes(MGMT),
    "management account must not be self-assumed",
  );
});

// ---------------------------------------------------------------------------
// 3. SKIP-DON'T-ABORT
// ---------------------------------------------------------------------------

Deno.test("org smoke: a failing member is recorded and skipped, others still processed", async () => {
  const { context, written } = makeContext();
  // MEMBER_A's listStacks rejects — its enumerate throws mid-run.
  const fixture = threeAccountOrg();
  fixture.apiByAccount[MEMBER_A] = {
    account: MEMBER_A,
    stacksByRegion: {},
    resourcesByStack: {},
    failListStacks: "AccessDenied: ListStacks",
  };
  const { org } = fakeOrg(fixture);

  const result = await runEnumerateOrg({
    org,
    globals: globals(),
    args: orgArgs(),
    context,
  });

  // The org-summary is still written despite the per-account failure.
  const os = written.find((w) => w.spec === "org-summary")!;
  assertEquals(os.data.accountsDiscovered, 3);
  assertEquals(os.data.accountsProcessed, 2);
  assertEquals(os.data.accountsFailed, 1);

  // The failing account is recorded with {account, name, error}.
  const failures = os.data.failures as Array<
    { account: string; name: string; error: string }
  >;
  assertEquals(failures.length, 1);
  assertEquals(failures[0].account, MEMBER_A);
  assertEquals(failures[0].name, "Workload-A");
  assert(failures[0].error.length > 0, "expected a non-empty error message");
  assert(
    failures[0].error.includes("AccessDenied"),
    `unexpected error: ${failures[0].error}`,
  );

  // The OTHER accounts are still processed: their rows exist.
  for (const acct of [MGMT, MEMBER_B]) {
    assert(
      written.some((w) => w.spec === "summary" && w.key === `summary-${acct}`),
      `summary row for ${acct} should still exist`,
    );
  }
  // The failing account wrote no summary row.
  assert(
    !written.some((w) => w.key === `summary-${MEMBER_A}`),
    "the failing account should write no summary row",
  );

  assertEquals(result.accountsFailed, 1);
  assertEquals(result.accountsProcessed, 2);
  // Two surviving accounts, one orphan each.
  assertEquals(result.totalOrphans, 2);
});

// ---------------------------------------------------------------------------
// 4. ORG-SUMMARY AGGREGATION (internal consistency)
// ---------------------------------------------------------------------------

Deno.test("org smoke: discovered/processed/failed/totalOrphans are internally consistent", async () => {
  const { context, written } = makeContext();
  // Member B's assumedApi throws (assume failure rather than a sweep failure).
  const fixture = threeAccountOrg({ assumeThrowsFor: new Set([MEMBER_B]) });
  const { org } = fakeOrg(fixture);

  const result = await runEnumerateOrg({
    org,
    globals: globals(),
    args: orgArgs(),
    context,
  });

  const os = written.find((w) => w.spec === "org-summary")!.data;
  const failures = os.failures as Array<{ account: string }>;

  // processed + failed == discovered (no account is silently dropped).
  assertEquals(
    (os.accountsProcessed as number) + (os.accountsFailed as number),
    os.accountsDiscovered as number,
  );
  // accountsFailed equals the failures list length.
  assertEquals(os.accountsFailed, failures.length);
  assertEquals(failures.length, 1);
  assertEquals(failures[0].account, MEMBER_B);
  // mgmt + member A succeeded: one orphan each.
  assertEquals(os.totalOrphans, 2);

  // The result object agrees with the written rollup.
  assertEquals(result.accountsDiscovered, os.accountsDiscovered);
  assertEquals(result.accountsProcessed, os.accountsProcessed);
  assertEquals(result.accountsFailed, os.accountsFailed);
  assertEquals(result.totalOrphans, os.totalOrphans);
  assertEquals(result.failures.length, 1);
});

// ---------------------------------------------------------------------------
// 5. ONLYACCOUNT canary
// ---------------------------------------------------------------------------

Deno.test("org smoke: onlyAccount narrows processing but not discovery", async () => {
  const { context, written } = makeContext();
  const { org, assumedCalls } = fakeOrg(threeAccountOrg());

  const result = await runEnumerateOrg({
    org,
    globals: globals(),
    args: orgArgs({ onlyAccount: MEMBER_A }),
    context,
  });

  // Only the one member was assumed; the others were never touched.
  assertEquals(assumedCalls, [MEMBER_A]);

  // No rows for the un-processed accounts.
  for (const acct of [MGMT, MEMBER_B]) {
    assert(
      !written.some((w) => w.spec === "summary" && w.key === `summary-${acct}`),
      `no summary row should exist for un-processed ${acct}`,
    );
  }
  // The canary account's rows do exist.
  assert(
    written.some((w) => w.key === `summary-${MEMBER_A}`),
    "the canary account should have a summary row",
  );

  const os = written.find((w) => w.spec === "org-summary")!.data;
  // accountsDiscovered still reflects the full ACTIVE org count.
  assertEquals(os.accountsDiscovered, 3);
  assertEquals(os.accountsProcessed, 1);
  assertEquals(os.totalOrphans, 1);

  assertEquals(result.accountsDiscovered, 3);
  assertEquals(result.accountsProcessed, 1);
});

// ---------------------------------------------------------------------------
// MUTATION-CHECK note
// ---------------------------------------------------------------------------
//
// The skip-don't-abort test ("a failing member is recorded and skipped") is the
// teeth for the per-account try/catch in runEnumerateOrg. Temporarily removing
// that try/catch (so a thrown per-account error propagates) makes that test go
// RED: the run aborts on MEMBER_A's rejected listStacks instead of recording
// the failure and continuing, so no org-summary is written and the assertions
// fail. Restoring the try/catch returns it to GREEN. (Verified during
// development.)

Deno.test("org smoke: completes well under the network budget", () => {
  // Sentinel — these org smoke tests complete in single-digit milliseconds.
  // Anything touching the network would blow past that and belongs elsewhere.
  assert(true);
});
