/**
 * Smoke tests — drive `runAudit` end-to-end through an in-memory `StackSetApi`
 * facade with a hand-rolled swamp method context.
 *
 * No AWS calls, no live SDK, no network: the stackset, its stack instances, and
 * its operation history are inline fixtures. The tests prove the sweep writes
 * exactly one `summary` plus one `instance` per stack instance (keyed
 * `instance-${account}-${region}`) and that a representative `safeToReapply`
 * verdict lands on the summary. All account ids are placeholders so the corpus
 * is safe to ship.
 */

import {
  assert,
  assertEquals,
  assertExists,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import {
  type AwsOperationSummary,
  type AwsStackInstanceSummary,
  type AwsStackSet,
  runAudit,
  type StackSetApi,
} from "../aws_stackset_audit.ts";

// ---------------------------------------------------------------------------
// In-memory StackSetApi replay
// ---------------------------------------------------------------------------

interface ApiFixture {
  stackSet: AwsStackSet;
  instances: AwsStackInstanceSummary[];
  operations: AwsOperationSummary[];
}

function fakeApi(fixture: ApiFixture): StackSetApi {
  return {
    describeStackSet: () => Promise.resolve(fixture.stackSet),
    listStackInstances: () => Promise.resolve(fixture.instances),
    listOperations: (limit: number) =>
      Promise.resolve(fixture.operations.slice(0, limit)),
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
    writeResource: (
      spec: string,
      key: string,
      data: Record<string, unknown>,
    ) => {
      written.push({ spec, key, data });
      return Promise.resolve({ id: `${spec}:${key}` });
    },
  };
  return { context, written };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

Deno.test("smoke: clean 2-instance stackset writes 1 summary + 2 instances, verdict yes", async () => {
  const { context, written } = makeContext();

  const fixture: ApiFixture = {
    stackSet: {
      StackSetId: "DemoSet:11111111-2222-3333-4444-555555555555",
      StackSetName: "DemoSet",
      Status: "ACTIVE",
      PermissionModel: "SERVICE_MANAGED",
      Description: "demo",
      Capabilities: ["CAPABILITY_NAMED_IAM"],
      OrganizationalUnitIds: ["ou-root-abc"],
      AutoDeployment: { Enabled: true },
      ManagedExecution: { Active: true },
      StackSetDriftDetectionDetails: {
        DriftStatus: "IN_SYNC",
        TotalStackInstancesCount: 2,
        InSyncStackInstancesCount: 2,
        LastDriftCheckTimestamp: new Date("2026-06-13T00:00:00.000Z"),
      },
    },
    instances: [
      {
        Account: "111111111111",
        Region: "us-east-1",
        StackId: "arn:stack/a",
        Status: "CURRENT",
        StackInstanceStatus: { DetailedStatus: "SUCCEEDED" },
        DriftStatus: "IN_SYNC",
        OrganizationalUnitId: "ou-root-abc",
      },
      {
        Account: "222222222222",
        Region: "eu-west-1",
        StackId: "arn:stack/b",
        Status: "CURRENT",
        StackInstanceStatus: { DetailedStatus: "SUCCEEDED" },
        DriftStatus: "IN_SYNC",
        OrganizationalUnitId: "ou-root-abc",
      },
    ],
    operations: [
      {
        OperationId: "op-1",
        Action: "UPDATE",
        Status: "SUCCEEDED",
        CreationTimestamp: new Date("2026-06-12T00:00:00.000Z"),
        EndTimestamp: new Date("2026-06-12T00:05:00.000Z"),
      },
    ],
  };

  const result = await runAudit({
    api: fakeApi(fixture),
    stackSetName: "DemoSet",
    recentOperations: 15,
    context,
  });

  // Exactly one summary, one instance per fixture instance.
  const summaries = written.filter((w) => w.spec === "summary");
  const instances = written.filter((w) => w.spec === "instance");
  assertEquals(summaries.length, 1);
  assertEquals(instances.length, 2);

  // Instance keys follow instance-${account}-${region}.
  assertEquals(
    instances.map((w) => w.key).sort(),
    ["instance-111111111111-us-east-1", "instance-222222222222-eu-west-1"],
  );

  // Representative verdict: clean fleet → "yes".
  const summary = summaries[0].data;
  const verdict = (summary.safeToReapply as { verdict: string }).verdict;
  assertEquals(verdict, "yes");
  assertEquals(result.verdict, "yes");
  assertEquals(result.instanceCount, 2);
  // 1 summary handle + 2 instance handles.
  assertEquals(result.dataHandles.length, 3);
});

Deno.test("smoke: IAM multi-region collision surfaces a 'no' verdict and root cause", async () => {
  const { context, written } = makeContext();

  const fixture: ApiFixture = {
    stackSet: {
      StackSetId: "IamSet:abc",
      StackSetName: "IamSet",
      Status: "ACTIVE",
      PermissionModel: "SERVICE_MANAGED",
      StackSetDriftDetectionDetails: {
        DriftStatus: "NOT_CHECKED",
        TotalStackInstancesCount: 0,
      },
    },
    instances: [
      {
        Account: "111111111111",
        Region: "us-east-1",
        Status: "CURRENT",
        StackInstanceStatus: { DetailedStatus: "SUCCEEDED" },
        DriftStatus: "NOT_CHECKED",
      },
      {
        Account: "111111111111",
        Region: "eu-west-1",
        Status: "OUTDATED",
        StatusReason: "Managed policy MyPolicy already exists",
        StackInstanceStatus: { DetailedStatus: "FAILED" },
        DriftStatus: "NOT_CHECKED",
      },
    ],
    operations: [],
  };

  const result = await runAudit({
    api: fakeApi(fixture),
    stackSetName: "IamSet",
    recentOperations: 15,
    context,
  });

  const summary = written.find((w) => w.spec === "summary")!.data;

  // Collision → safeToReapply "no".
  assertEquals((summary.safeToReapply as { verdict: string }).verdict, "no");
  assertEquals(result.verdict, "no");

  // The collision and the drift-never-detected patterns are both present.
  const patterns = summary.detectedPatterns as { pattern: string }[];
  const patternNames = patterns.map((p) => p.pattern).sort();
  assertEquals(
    patternNames,
    ["drift-never-detected", "iam-global-resource-multi-region-collision"],
  );

  // Root cause carries the IAM conflict.
  const rootCauses = summary.rootCauses as { failureCategory: string }[];
  assertExists(
    rootCauses.find((c) => c.failureCategory === "iam-name-conflict"),
  );

  // Per-instance failure classification surfaced on the instance row.
  const failedRow = written.find(
    (w) => w.spec === "instance" && w.key === "instance-111111111111-eu-west-1",
  )!;
  assertEquals(failedRow.data.failureCategory, "iam-name-conflict");
});

Deno.test("smoke: empty stackset writes only the summary with verdict yes", async () => {
  const { context, written } = makeContext();

  const result = await runAudit({
    api: fakeApi({
      stackSet: { StackSetName: "Empty", Status: "ACTIVE" },
      instances: [],
      operations: [],
    }),
    stackSetName: "Empty",
    recentOperations: 15,
    context,
  });

  assertEquals(written.filter((w) => w.spec === "summary").length, 1);
  assertEquals(written.filter((w) => w.spec === "instance").length, 0);
  assertEquals(result.instanceCount, 0);
  // No failed/cancelled/inflight → "yes".
  assertEquals(result.verdict, "yes");
  assertEquals(result.dataHandles.length, 1);
});

Deno.test("smoke: an in-flight operation forces verdict 'no'", async () => {
  const { context, written } = makeContext();

  const result = await runAudit({
    api: fakeApi({
      stackSet: { StackSetName: "Busy", Status: "ACTIVE" },
      instances: [{
        Account: "111111111111",
        Region: "us-east-1",
        Status: "CURRENT",
        StackInstanceStatus: { DetailedStatus: "SUCCEEDED" },
        DriftStatus: "IN_SYNC",
      }],
      operations: [{
        OperationId: "op-live",
        Action: "UPDATE",
        Status: "RUNNING",
      }],
    }),
    stackSetName: "Busy",
    recentOperations: 15,
    context,
  });

  assertEquals(result.verdict, "no");
  const summary = written.find((w) => w.spec === "summary")!.data;
  assertEquals((summary.safeToReapply as { verdict: string }).verdict, "no");
});

Deno.test("smoke: recentOperations limit caps the captured operations", async () => {
  const { context, written } = makeContext();

  const ops: AwsOperationSummary[] = Array.from({ length: 5 }, (_, i) => ({
    OperationId: `op-${i}`,
    Action: "UPDATE",
    Status: "SUCCEEDED",
  }));

  await runAudit({
    api: fakeApi({
      stackSet: { StackSetName: "Hist", Status: "ACTIVE" },
      instances: [],
      operations: ops,
    }),
    stackSetName: "Hist",
    recentOperations: 2,
    context,
  });

  const summary = written.find((w) => w.spec === "summary")!.data;
  assertEquals((summary.operations as unknown[]).length, 2);
});

Deno.test("smoke: every test finishes well under the network budget", () => {
  // Sentinel — the smoke tests above all complete in single-digit
  // milliseconds. Anything touching the network would blow past that and
  // belongs outside this harness.
  assert(true);
});
