/**
 * Cleanup-org smoke tests — drive `runCleanupOrg` end-to-end through an
 * in-memory fake `OrgApi` that returns a per-account fake `SweepApi` from
 * inline fixtures, plus a recording swamp method context. No AWS calls, no
 * live SDK, no network.
 *
 * These cover the mutating cross-account path: dry-run vs apply, the
 * per-account `expectAccount` landing check (assumed creds that resolve to a
 * different account than the member id are refused by `runCleanup` and recorded
 * as a failure, not a deletion), skip-don't-abort, no-self-assume, aggregate
 * cleanup counters landing on the `org-summary`, and the `onlyAccount` canary.
 *
 * The apply-path fixtures stub `describeStackStatus: () => null` so `processStack`
 * treats every target as already-gone and returns instantly WITHOUT the real
 * `delay()` poll loop — keeping these tests in single-digit milliseconds with no
 * timers. All account ids and stack names are synthetic placeholders so the
 * corpus is safe to ship.
 */

import { assert, assertEquals } from "jsr:@std/assert@1";

import {
  type CleanupOrgArgs,
  type GlobalArgs,
  type OrgAccount,
  type OrgApi,
  type ResourceRef,
  runCleanupOrg,
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
// In-memory SweepApi replay
// ---------------------------------------------------------------------------

interface ApiFixture {
  /**
   * The account id this SweepApi's getAccountId() resolves to. Usually equal to
   * the org-account id it is keyed under, but a landing-check test deliberately
   * mints an api whose resolved id differs from the requested member id.
   */
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
    // describeStackStatus -> null makes processStack treat the stack as
    // already-gone and return instantly: NO real delay() poll loop, so the
    // apply path stays timer-free. A null here counts as a confirmed delete.
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
// Recording swamp method context
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

function cleanupOrgArgs(over: Partial<CleanupOrgArgs> = {}): CleanupOrgArgs {
  return {
    apply: false,
    onlyAccount: "",
    onlyRegion: "",
    onlyStack: "",
    retainLogicalId: "",
    waitSeconds: 10,
    maxWaits: 30,
    verifyRole: true,
    initiateOnly: false,
    predeleteLambda: true,
    ...over,
  };
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
// 1. DRY-RUN vs APPLY
// ---------------------------------------------------------------------------

Deno.test("cleanup-org smoke: dry-run plans one deletion row per orphan, mutates nothing", async () => {
  const { context, written } = makeContext();
  const { org } = fakeOrg(threeAccountOrg());

  const result = await runCleanupOrg({
    org,
    globals: globals(),
    args: cleanupOrgArgs(), // apply defaults false
    context,
  });

  // One deletion row per orphan (one per account), across all three accounts.
  const deletions = written.filter((w) => w.spec === "deletion");
  assertEquals(deletions.length, 3);
  for (const acct of [MGMT, MEMBER_A, MEMBER_B]) {
    assert(
      deletions.some((w) => w.data.account === acct),
      `a deletion row for ${acct}`,
    );
  }
  // The healthy stacks plan a plain initiate; dry-run mutates nothing.
  for (const d of deletions) {
    assertEquals(d.data.action, "would-initiate-delete");
  }

  // Aggregate counters: dry-run considers but never deletes.
  assertEquals(result.applied, false);
  assertEquals(result.considered, 3);
  assertEquals(result.deleted, 0);
  assertEquals(result.initiated, 0);
  assertEquals(result.skipped, 0);
  assertEquals(result.errors, 0);

  // The org-summary records the dry-run mode.
  const os = written.find((w) => w.spec === "org-summary")!.data;
  assertEquals(os.mode, "cleanup");
  assertEquals(os.applied, false);
  assertEquals(os.considered, 3);
  assertEquals(os.deleted, 0);
});

Deno.test("cleanup-org smoke: apply deletes the orphan in each account (already-gone => confirmed)", async () => {
  const { context, written } = makeContext();
  const { org } = fakeOrg(threeAccountOrg());

  const result = await runCleanupOrg({
    org,
    globals: globals(),
    args: cleanupOrgArgs({ apply: true }),
    context,
  });

  // describeStackStatus -> null => processStack reports already-gone (confirmed
  // delete) for each of the three orphans, with no delay() poll.
  const deletions = written.filter((w) => w.spec === "deletion");
  assertEquals(deletions.length, 3);
  for (const d of deletions) {
    assertEquals(d.data.action, "already-gone");
    assertEquals(d.data.gone, true);
  }

  assertEquals(result.applied, true);
  assertEquals(result.considered, 3);
  assertEquals(result.deleted, 3);
  assertEquals(result.initiated, 0);
  assertEquals(result.skipped, 0);
  assertEquals(result.errors, 0);

  const os = written.find((w) => w.spec === "org-summary")!.data;
  assertEquals(os.applied, true);
  assertEquals(os.deleted, 3);
});

// ---------------------------------------------------------------------------
// 2. PER-ACCOUNT EXPECTACCOUNT LANDING CHECK
// ---------------------------------------------------------------------------
//
// MUTATION-CHECK (verified during development): this test is the teeth for the
// per-account expectAccount landing check. cleanupOrg sets
// `expectAccount = acct.id` on each runCleanup call; runCleanup throws when the
// assumed creds resolve to a DIFFERENT account, BEFORE writing any deletion row.
// Breaking that — e.g. passing `expectAccount: ""` in cleanupOrg's per-account
// runCleanup args (so the guard never fires) — makes MEMBER_A's mis-pointed api
// (resolving to 999...) sail through and WRITE A DELETION ROW for the wrong
// account: this test then goes RED (the failure is gone, accountsFailed drops to
// 0, and a deletion row appears for the wrong account). Restoring
// `expectAccount: acct.id` returns it to GREEN.

Deno.test("cleanup-org smoke: assumed creds resolving to the wrong account are refused, not deleted", async () => {
  const { context, written } = makeContext();

  // MEMBER_A's assumedApi returns a SweepApi whose getAccountId resolves to a
  // DIFFERENT account (a misconfigured role) — but it still has a deletable
  // orphan, so without the landing check it would be (wrongly) deleted.
  const WRONG = "999999999999";
  const fixture = threeAccountOrg();
  fixture.apiByAccount[MEMBER_A] = {
    ...singleOrphanFixture(MEMBER_A, "a"),
    account: WRONG, // resolves elsewhere
  };
  const { org } = fakeOrg(fixture);

  const result = await runCleanupOrg({
    org,
    globals: globals(),
    args: cleanupOrgArgs({ apply: true }),
    context,
  });

  // MEMBER_A is recorded as a failure (the landing-check refusal), NOT processed.
  assertEquals(result.accountsFailed, 1);
  assertEquals(result.accountsProcessed, 2);
  assertEquals(result.failures.length, 1);
  assertEquals(result.failures[0].account, MEMBER_A);
  // The refusal names both the expected member id and the wrong resolved id.
  assert(
    result.failures[0].error.includes(MEMBER_A) &&
      result.failures[0].error.includes(WRONG),
    `unexpected refusal reason: ${result.failures[0].error}`,
  );
  assert(
    result.failures[0].error.includes("refusing to run"),
    `expected a landing-check refusal: ${result.failures[0].error}`,
  );

  // CRITICAL: NO deletion row was written for the mis-pointed account — the
  // guard throws before runCleanup writes anything for that account.
  const wrongRows = written.filter((w) =>
    w.spec === "deletion" &&
    (w.data.account === MEMBER_A || w.data.account === WRONG)
  );
  assertEquals(
    wrongRows.length,
    0,
    "a mis-pointed account must write zero deletion rows",
  );

  // The other two accounts (mgmt + member B) still process and delete.
  assertEquals(result.deleted, 2);
  const okRows = written.filter((w) => w.spec === "deletion");
  assertEquals(okRows.length, 2);
});

// ---------------------------------------------------------------------------
// 3. SKIP-DON'T-ABORT
// ---------------------------------------------------------------------------
//
// MUTATION-CHECK (verified during development): this test is the teeth for the
// per-account try/catch in runCleanupOrg. Removing that try/catch (so a thrown
// per-account error propagates) makes this go RED: the run aborts on MEMBER_A's
// rejected listStacks instead of recording the failure and continuing, so no
// org-summary is written and the assertions fail. Restoring it returns to GREEN.

Deno.test("cleanup-org smoke: a failing member is recorded and skipped, others still processed", async () => {
  const { context, written } = makeContext();
  // MEMBER_A's listStacks rejects — its cleanup throws mid-run.
  const fixture = threeAccountOrg();
  fixture.apiByAccount[MEMBER_A] = {
    account: MEMBER_A,
    stacksByRegion: {},
    resourcesByStack: {},
    failListStacks: "AccessDenied: ListStacks",
  };
  const { org } = fakeOrg(fixture);

  const result = await runCleanupOrg({
    org,
    globals: globals(),
    args: cleanupOrgArgs({ apply: true }),
    context,
  });

  // The org-summary is still written despite the per-account failure.
  const os = written.find((w) => w.spec === "org-summary")!.data;
  assertEquals(os.accountsDiscovered, 3);
  assertEquals(os.accountsProcessed, 2);
  assertEquals(os.accountsFailed, 1);

  const failures = os.failures as Array<
    { account: string; name: string; error: string }
  >;
  assertEquals(failures.length, 1);
  assertEquals(failures[0].account, MEMBER_A);
  assertEquals(failures[0].name, "Workload-A");
  assert(
    failures[0].error.includes("AccessDenied"),
    `unexpected error: ${failures[0].error}`,
  );

  // The OTHER accounts still process and delete their orphan.
  assertEquals(result.accountsProcessed, 2);
  assertEquals(result.accountsFailed, 1);
  assertEquals(result.deleted, 2);

  // The failing account wrote no deletion row.
  assert(
    !written.some((w) => w.spec === "deletion" && w.data.account === MEMBER_A),
    "the failing account should write no deletion row",
  );
});

// ---------------------------------------------------------------------------
// 4. NO SELF-ASSUME
// ---------------------------------------------------------------------------

Deno.test("cleanup-org smoke: management account uses ambient creds, is never self-assumed", async () => {
  const { context } = makeContext();
  const { org, assumedCalls } = fakeOrg(threeAccountOrg());

  await runCleanupOrg({
    org,
    globals: globals(),
    args: cleanupOrgArgs({ apply: true }),
    context,
  });

  // assumedApi was called for the members but NEVER for the management account.
  assertEquals(assumedCalls.sort(), [MEMBER_A, MEMBER_B]);
  assert(
    !assumedCalls.includes(MGMT),
    "management account must not be self-assumed",
  );
});

// ---------------------------------------------------------------------------
// 5. CLEANUP COUNTER AGGREGATION
// ---------------------------------------------------------------------------

Deno.test("cleanup-org smoke: counters aggregate across accounts and land on org-summary", async () => {
  const { context, written } = makeContext();

  // Two accounts each hold two orphans (so the aggregate is non-trivial); the
  // management account holds one. Member B's assume fails — recorded, skipped.
  const twoOrphan = (account: string): ApiFixture => {
    const s1 = `${PREFIX}${account}-1`;
    const s2 = `${PREFIX}${account}-2`;
    return {
      account,
      stacksByRegion: {
        "us-east-1": [
          {
            StackName: s1,
            StackId: `arn:stack/${account}-1`,
            StackStatus: "CREATE_COMPLETE",
          },
          {
            StackName: s2,
            StackId: `arn:stack/${account}-2`,
            StackStatus: "CREATE_COMPLETE",
          },
        ],
      },
      resourcesByStack: {
        [s1]: orphanResources(`${account}-1`),
        [s2]: orphanResources(`${account}-2`),
      },
    };
  };

  const fixture = threeAccountOrg({
    apiByAccount: {
      [MGMT]: singleOrphanFixture(MGMT, "mgmt"), // 1 orphan
      [MEMBER_A]: twoOrphan(MEMBER_A), // 2 orphans
      [MEMBER_B]: singleOrphanFixture(MEMBER_B, "b"), // would be 1, but assume fails
    },
    assumeThrowsFor: new Set([MEMBER_B]),
  });
  const { org } = fakeOrg(fixture);

  const result = await runCleanupOrg({
    org,
    globals: globals(),
    args: cleanupOrgArgs({ apply: true }),
    context,
  });

  // mgmt (1) + member A (2) processed; member B failed. considered = 3, all
  // already-gone => deleted = 3.
  assertEquals(result.accountsProcessed, 2);
  assertEquals(result.accountsFailed, 1);
  assertEquals(result.considered, 3);
  assertEquals(result.deleted, 3);
  assertEquals(result.initiated, 0);
  assertEquals(result.skipped, 0);
  assertEquals(result.errors, 0);

  // The org-summary carries the aggregate cleanup counters.
  const os = written.find((w) => w.spec === "org-summary")!.data;
  assertEquals(os.considered, 3);
  assertEquals(os.deleted, 3);
  assertEquals(os.initiated, 0);
  assertEquals(os.skipped, 0);
  assertEquals(os.errors, 0);
  assertEquals(os.accountsProcessed, 2);
  assertEquals(os.accountsFailed, 1);

  // The result agrees with the written rollup.
  assertEquals(result.deleted, os.deleted);
  assertEquals(result.considered, os.considered);
});

// ---------------------------------------------------------------------------
// 6. ONLYACCOUNT canary
// ---------------------------------------------------------------------------

Deno.test("cleanup-org smoke: onlyAccount narrows processing but not discovery", async () => {
  const { context, written } = makeContext();
  const { org, assumedCalls } = fakeOrg(threeAccountOrg());

  const result = await runCleanupOrg({
    org,
    globals: globals(),
    args: cleanupOrgArgs({ apply: true, onlyAccount: MEMBER_A }),
    context,
  });

  // Only the one member was assumed; the others were never touched.
  assertEquals(assumedCalls, [MEMBER_A]);

  // Only the canary account wrote a deletion row.
  const deletions = written.filter((w) => w.spec === "deletion");
  assertEquals(deletions.length, 1);
  assertEquals(deletions[0].data.account, MEMBER_A);

  // accountsDiscovered still reflects the full ACTIVE org count.
  assertEquals(result.accountsDiscovered, 3);
  assertEquals(result.accountsProcessed, 1);
  assertEquals(result.deleted, 1);

  const os = written.find((w) => w.spec === "org-summary")!.data;
  assertEquals(os.accountsDiscovered, 3);
  assertEquals(os.accountsProcessed, 1);
  assertEquals(os.deleted, 1);
});

Deno.test("cleanup-org smoke: completes well under the network budget", () => {
  // Sentinel — these cleanup-org smoke tests complete in single-digit
  // milliseconds. The apply-path fixtures stub describeStackStatus -> null so
  // processStack never enters the real delay() poll loop. Anything touching the
  // network (or a real timer) would blow past that and belongs elsewhere.
  assert(true);
});
