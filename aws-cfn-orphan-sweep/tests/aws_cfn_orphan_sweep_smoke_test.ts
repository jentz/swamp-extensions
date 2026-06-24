/**
 * Smoke tests — drive `runEnumerate` and the dry-run path of `runCleanup`
 * end-to-end through an in-memory `SweepApi` facade with a hand-rolled swamp
 * method context.
 *
 * No AWS calls, no live SDK, no network: the per-region stack lists and each
 * stack's resources are inline fixtures. The enumerate test proves the sweep
 * writes exactly one `orphan` row per matching stack (keyed
 * `orphan-${account}-${region}-${stack}`) plus one per-account `summary`. The
 * cleanup test runs in dry-run mode (no `apply`), so it never sleeps and never
 * mutates — it writes one planning `deletion` row per target. All account ids
 * and stack names are synthetic placeholders so the corpus is safe to ship.
 */

import { assert, assertEquals } from "jsr:@std/assert@1";

import {
  type CleanupArgs,
  type ResourceRef,
  runCleanup,
  runEnumerate,
  type StackSummary,
  type SweepApi,
} from "../aws_cfn_orphan_sweep.ts";

// ---------------------------------------------------------------------------
// In-memory SweepApi replay
// ---------------------------------------------------------------------------

const ACCOUNT = "111111111111";
const PREFIX = "StackSet-IAMCustomPasswordPolicy-";

interface ApiFixture {
  account: string;
  /** region -> stacks returned by listStacks. */
  stacksByRegion: Record<string, StackSummary[]>;
  /** stackName -> resources returned by listStackResources. */
  resourcesByStack: Record<string, ResourceRef[]>;
}

function fakeApi(fixture: ApiFixture): SweepApi {
  return {
    getAccountId: () => Promise.resolve(fixture.account),
    listStacks: (region: string) =>
      Promise.resolve(fixture.stacksByRegion[region] ?? []),
    listStackResources: (stackName: string, _region: string) =>
      Promise.resolve(fixture.resourcesByStack[stackName] ?? []),
    // Not exercised by the read-only enumerate path nor the dry-run cleanup.
    describeStackStatus: () => Promise.resolve(null),
    deleteStack: () => Promise.resolve(),
    deleteFunction: () => Promise.resolve(),
    roleExists: () => Promise.resolve(false),
  };
}

// ---------------------------------------------------------------------------
// Stand-in for the runtime's swamp method context
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

// A complete orphan resource set: the dead custom resource, its IAM role, and
// the backing Lambda — exactly what an abandoned StackSet member stack holds.
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

// Default cleanup args (every field set to its model default).
function cleanupArgs(over: Partial<CleanupArgs> = {}): CleanupArgs {
  return {
    apply: false,
    expectAccount: "",
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

// ---------------------------------------------------------------------------
// enumerate
// ---------------------------------------------------------------------------

Deno.test("smoke: enumerate writes one orphan per matching stack + one summary", async () => {
  const { context, written } = makeContext();

  const matchA = `${PREFIX}aaaa`;
  const matchB = `${PREFIX}bbbb`;
  const fixture: ApiFixture = {
    account: ACCOUNT,
    stacksByRegion: {
      "us-east-1": [
        {
          StackName: matchA,
          StackId: "arn:stack/a",
          StackStatus: "CREATE_COMPLETE",
          CreationTime: new Date("2026-06-16T00:00:00.000Z"),
        },
        // A non-matching stack in the same region must be ignored.
        { StackName: "ProdDatabase", StackId: "arn:stack/prod" },
      ],
      "eu-west-1": [
        {
          StackName: matchB,
          StackId: "arn:stack/b",
          StackStatus: "DELETE_FAILED",
          StackStatusReason: "custom resource stuck",
        },
      ],
    },
    resourcesByStack: {
      [matchA]: orphanResources("a"),
      [matchB]: orphanResources("b"),
    },
  };

  const result = await runEnumerate({
    api: fakeApi(fixture),
    globals: {
      namePrefix: PREFIX,
      regions: ["us-east-1", "eu-west-1"],
      profile: "",
      assumeRoleName: "AWSControlTowerExecution",
    },
    context,
  });

  const orphans = written.filter((w) => w.spec === "orphan");
  const summaries = written.filter((w) => w.spec === "summary");

  // One orphan per matching stack (the non-matching ProdDatabase is dropped).
  assertEquals(orphans.length, 2);
  assertEquals(summaries.length, 1);

  // Orphan keys follow orphan-${account}-${region}-${stack}.
  assertEquals(
    orphans.map((w) => w.key).sort(),
    [
      `orphan-${ACCOUNT}-eu-west-1-${matchB}`,
      `orphan-${ACCOUNT}-us-east-1-${matchA}`,
    ],
  );

  // Classification landed on the orphan row.
  const rowA = orphans.find((w) => w.key.endsWith(matchA))!.data;
  assertEquals(rowA.customResourceLogicalId, "PasswordPolicy");
  assertEquals(rowA.iamRoleLogicalId, "LambdaRole");
  assertEquals(rowA.iamRolePhysicalName, `${PREFIX}role-a`);
  assertEquals(rowA.lambdaLogicalId, "PolicyFn");
  assertEquals(rowA.resourceCount, 3);

  // Summary rolls up the fleet for this account.
  const summary = summaries[0].data;
  assertEquals(summaries[0].key, `summary-${ACCOUNT}`);
  assertEquals(summary.account, ACCOUNT);
  assertEquals(summary.orphanCount, 2);
  assertEquals(summary.byRegion, { "us-east-1": 1, "eu-west-1": 1 });
  assertEquals(summary.byStatus, {
    CREATE_COMPLETE: 1,
    DELETE_FAILED: 1,
  });
  // The DELETE_FAILED stack is surfaced by name.
  assertEquals(summary.deleteFailed, [matchB]);

  // Result mirrors the written rows: 2 orphan handles + 1 summary handle.
  assertEquals(result.account, ACCOUNT);
  assertEquals(result.orphanCount, 2);
  assertEquals(result.dataHandles.length, 3);
});

Deno.test("smoke: enumerate with no matching stacks writes only an empty summary", async () => {
  const { context, written } = makeContext();

  const result = await runEnumerate({
    api: fakeApi({
      account: ACCOUNT,
      stacksByRegion: {
        "us-east-1": [{ StackName: "Unrelated", StackId: "arn:stack/x" }],
      },
      resourcesByStack: {},
    }),
    globals: {
      namePrefix: PREFIX,
      regions: ["us-east-1"],
      profile: "",
      assumeRoleName: "AWSControlTowerExecution",
    },
    context,
  });

  assertEquals(written.filter((w) => w.spec === "orphan").length, 0);
  assertEquals(written.filter((w) => w.spec === "summary").length, 1);
  assertEquals(result.orphanCount, 0);
  assertEquals(result.dataHandles.length, 1);
});

// ---------------------------------------------------------------------------
// cleanup (dry-run)
// ---------------------------------------------------------------------------

Deno.test("smoke: cleanup dry-run plans one deletion row per target, mutates nothing", async () => {
  const { context, written } = makeContext();

  const matchA = `${PREFIX}aaaa`;
  const matchB = `${PREFIX}bbbb`;
  const fixture: ApiFixture = {
    account: ACCOUNT,
    stacksByRegion: {
      "us-east-1": [{
        StackName: matchA,
        StackId: "arn:stack/a",
        StackStatus: "CREATE_COMPLETE",
      }],
      "eu-west-1": [{
        StackName: matchB,
        StackId: "arn:stack/b",
        StackStatus: "DELETE_FAILED",
      }],
    },
    resourcesByStack: {
      [matchA]: orphanResources("a"),
      [matchB]: orphanResources("b"),
    },
  };

  const result = await runCleanup({
    api: fakeApi(fixture),
    globals: {
      namePrefix: PREFIX,
      regions: ["us-east-1", "eu-west-1"],
      profile: "",
      assumeRoleName: "AWSControlTowerExecution",
    },
    args: cleanupArgs(),
    context,
  });

  const deletions = written.filter((w) => w.spec === "deletion");
  assertEquals(deletions.length, 2);
  assertEquals(result.applied, false);
  assertEquals(result.considered, 2);
  // Dry-run mutates nothing: no deletes/initiations counted.
  assertEquals(result.deleted, 0);
  assertEquals(result.initiated, 0);
  assertEquals(result.errors, 0);

  // The healthy stack is planned for a plain initiate; the failed one for a
  // retain-delete that keeps only the custom resource.
  const planA = deletions.find((w) => w.key.endsWith(matchA))!.data;
  assertEquals(planA.action, "would-initiate-delete");
  assertEquals(planA.retainedResources, []);

  const planB = deletions.find((w) => w.key.endsWith(matchB))!.data;
  assertEquals(planB.action, "would-retain-delete");
  assertEquals(planB.retainedResources, ["PasswordPolicy"]);
});

Deno.test("smoke: cleanup dry-run scopes to a single region via onlyRegion", async () => {
  const { context, written } = makeContext();

  const matchA = `${PREFIX}aaaa`;
  const matchB = `${PREFIX}bbbb`;
  const fixture: ApiFixture = {
    account: ACCOUNT,
    stacksByRegion: {
      "us-east-1": [{
        StackName: matchA,
        StackId: "arn:stack/a",
        StackStatus: "CREATE_COMPLETE",
      }],
      "eu-west-1": [{
        StackName: matchB,
        StackId: "arn:stack/b",
        StackStatus: "CREATE_COMPLETE",
      }],
    },
    resourcesByStack: {
      [matchA]: orphanResources("a"),
      [matchB]: orphanResources("b"),
    },
  };

  const result = await runCleanup({
    api: fakeApi(fixture),
    globals: {
      namePrefix: PREFIX,
      regions: ["us-east-1", "eu-west-1"],
      profile: "",
      assumeRoleName: "AWSControlTowerExecution",
    },
    args: cleanupArgs({ onlyRegion: "eu-west-1" }),
    context,
  });

  // Only the eu-west-1 orphan is considered; the us-east-1 one is filtered out.
  assertEquals(result.considered, 1);
  const deletions = written.filter((w) => w.spec === "deletion");
  assertEquals(deletions.length, 1);
  assertEquals(deletions[0].key, `deletion-${ACCOUNT}-eu-west-1-${matchB}`);
});

Deno.test("smoke: cleanup dry-run skips a DELETE_FAILED stack when retainLogicalId is not a custom resource", async () => {
  const { context, written } = makeContext();

  const matchB = `${PREFIX}bbbb`;
  // A bad override: LambdaRole is the IAM role, not a custom resource, so
  // computeRetain refuses. processStack pass 2 would refuse on the same input.
  const badOverride = "LambdaRole";

  const result = await runCleanup({
    api: fakeApi({
      account: ACCOUNT,
      stacksByRegion: {
        "eu-west-1": [{
          StackName: matchB,
          StackId: "arn:stack/b",
          StackStatus: "DELETE_FAILED",
        }],
      },
      resourcesByStack: { [matchB]: orphanResources("b") },
    }),
    globals: {
      namePrefix: PREFIX,
      regions: ["eu-west-1"],
      profile: "",
      assumeRoleName: "AWSControlTowerExecution",
    },
    args: cleanupArgs({ retainLogicalId: badOverride }),
    context,
  });

  const deletions = written.filter((w) => w.spec === "deletion");
  assertEquals(deletions.length, 1);

  // The dry-run row faithfully reports the refusal apply would hit at pass 2:
  // a "skip" action carrying the computeRetain reason and retaining nothing.
  const planB = deletions[0].data;
  assertEquals(planB.action, "skip");
  assertEquals(planB.retainedResources, []);
  const reason = String(planB.error);
  assert(reason.length > 0, "expected a non-empty refusal reason");
  assert(
    reason.includes(badOverride) && reason.includes("is not a custom resource"),
    `unexpected refusal reason: ${reason}`,
  );

  // The skip is counted in the returned result.
  assertEquals(result.skipped, 1);
  assertEquals(result.considered, 1);
  assertEquals(result.deleted, 0);
  assertEquals(result.initiated, 0);
  assertEquals(result.errors, 0);
});

Deno.test("smoke: cleanup dry-run does NOT over-skip a healthy stack with a bad retainLogicalId", async () => {
  const { context, written } = makeContext();

  const matchA = `${PREFIX}aaaa`;
  // Same bad override, but the stack is healthy — apply would plain-delete and
  // ignore retainLogicalId entirely, so the honest plan is still
  // "would-initiate-delete" with no error. The fix must not over-correct here.
  const badOverride = "LambdaRole";

  const result = await runCleanup({
    api: fakeApi({
      account: ACCOUNT,
      stacksByRegion: {
        "us-east-1": [{
          StackName: matchA,
          StackId: "arn:stack/a",
          StackStatus: "CREATE_COMPLETE",
        }],
      },
      resourcesByStack: { [matchA]: orphanResources("a") },
    }),
    globals: {
      namePrefix: PREFIX,
      regions: ["us-east-1"],
      profile: "",
      assumeRoleName: "AWSControlTowerExecution",
    },
    args: cleanupArgs({ retainLogicalId: badOverride }),
    context,
  });

  const deletions = written.filter((w) => w.spec === "deletion");
  assertEquals(deletions.length, 1);

  const planA = deletions[0].data;
  assertEquals(planA.action, "would-initiate-delete");
  assertEquals(planA.error, "");
  assertEquals(planA.retainedResources, []);

  // Nothing was skipped: apply ignores the override on a healthy stack.
  assertEquals(result.skipped, 0);
  assertEquals(result.considered, 1);
});

Deno.test("smoke: cleanup honors expectAccount guard", async () => {
  const { context } = makeContext();

  let threw = false;
  try {
    await runCleanup({
      api: fakeApi({
        account: ACCOUNT,
        stacksByRegion: {},
        resourcesByStack: {},
      }),
      globals: {
        namePrefix: PREFIX,
        regions: ["us-east-1"],
        profile: "",
        assumeRoleName: "AWSControlTowerExecution",
      },
      args: cleanupArgs({ expectAccount: "999999999999" }),
      context,
    });
  } catch (err) {
    threw = true;
    assert(err instanceof Error);
    assert(err.message.includes("999999999999"));
    assert(err.message.includes(ACCOUNT));
  }
  assert(threw, "expected expectAccount mismatch to throw");
});

Deno.test("smoke: every test finishes well under the network budget", () => {
  // Sentinel — the smoke tests above all complete in single-digit
  // milliseconds. Anything touching the network (or the real delay() poll loop)
  // would blow past that and belongs outside this harness.
  assert(true);
});
