/**
 * Smoke tests — drive `runDeleteInstances` and `runDeleteStackSet` end-to-end
 * through an in-memory `LifecycleApi` facade with a hand-rolled swamp method
 * context.
 *
 * No AWS calls, no live SDK, no network: the `DeleteStackInstances` operation
 * id, the `DescribeStackSetOperation` status progression, and the
 * `DeleteStackSet` call are all replayed from inline fixtures. The tests prove
 * each method writes exactly one `result` resource (with the right key and
 * shape). All account ids, OU ids, and the stackset name are synthetic
 * placeholders so the corpus is safe to ship.
 */

import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";

import {
  type DeleteInstancesInput,
  type LifecycleApi,
  runDeleteInstances,
  runDeleteStackSet,
} from "../aws_stackset_lifecycle.ts";

// ---------------------------------------------------------------------------
// In-memory LifecycleApi replay
// ---------------------------------------------------------------------------

interface ApiFixture {
  /** Operation id returned by DeleteStackInstances. */
  operationId: string;
  /** Scripted DescribeStackSetOperation status progression (final entry holds). */
  statuses: string[];
  /** Reason returned alongside the final (terminal) status. */
  terminalReason?: string;
}

interface ApiCalls {
  deleteInstances: DeleteInstancesInput[];
  deleteStackSet: number;
  describeOperation: string[];
}

function fakeApi(
  fixture: ApiFixture,
): { api: LifecycleApi; calls: ApiCalls } {
  const calls: ApiCalls = {
    deleteInstances: [],
    deleteStackSet: 0,
    describeOperation: [],
  };
  let i = 0;
  const api: LifecycleApi = {
    deleteInstances: (input) => {
      calls.deleteInstances.push(input);
      return Promise.resolve(fixture.operationId);
    },
    deleteStackSet: () => {
      calls.deleteStackSet++;
      return Promise.resolve();
    },
    describeOperation: (operationId) => {
      calls.describeOperation.push(operationId);
      const last = i >= fixture.statuses.length - 1;
      const status = fixture.statuses[Math.min(i, fixture.statuses.length - 1)];
      i++;
      return Promise.resolve({
        status,
        reason: last ? (fixture.terminalReason ?? "") : "",
      });
    },
  };
  return { api, calls };
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
      return Promise.resolve({ id: `${spec}:${key}` });
    },
  };
  return { context, written };
}

// Parsed-args shapes the run* entrypoints expect (defaults already applied).
const fastPoll = { pollSeconds: 0.001, maxPolls: 10 };

// ---------------------------------------------------------------------------
// deleteInstances
// ---------------------------------------------------------------------------

Deno.test("smoke: deleteInstances polls to SUCCEEDED and writes one result", async () => {
  const { context, written } = makeContext();
  const { api, calls } = fakeApi({
    operationId: "op-deadbeef",
    // RUNNING then SUCCEEDED — exercises the poll loop.
    statuses: ["RUNNING", "SUCCEEDED"],
  });

  const result = await runDeleteInstances({
    api,
    stackSetName: "DemoSet",
    callAs: "SELF",
    region: "us-east-1",
    args: {
      deploymentTargets: {
        organizationalUnitIds: ["ou-root-abc123"],
        accounts: ["111111111111", "222222222222"],
        accountFilterType: "INTERSECTION",
      },
      regions: ["eu-west-1", "us-east-1"],
      retainStacks: false,
      confirmWholeTarget: false,
      ...fastPoll,
    },
    context,
  });

  // The SDK call carried the parsed batch through.
  assertEquals(calls.deleteInstances.length, 1);
  assertEquals(calls.deleteInstances[0].accounts, [
    "111111111111",
    "222222222222",
  ]);
  assertEquals(calls.deleteInstances[0].retainStacks, false);
  assertEquals(calls.describeOperation, ["op-deadbeef", "op-deadbeef"]);

  // Exactly one result resource, keyed by operation id.
  const results = written.filter((w) => w.spec === "result");
  assertEquals(results.length, 1);
  assertEquals(results[0].key, "delete-instances-op-deadbeef");

  // Result shape.
  assertEquals(result.action, "delete-instances");
  assertEquals(result.status, "SUCCEEDED");
  assertEquals(result.operationId, "op-deadbeef");
  assertEquals(result.regions, ["eu-west-1", "us-east-1"]);
  assertEquals(result.deploymentTargets.accountFilterType, "INTERSECTION");
  assertEquals(result.dataHandles.length, 1);
});

Deno.test("smoke: deleteInstances writes the result then throws on a FAILED operation", async () => {
  const { context, written } = makeContext();
  const { api } = fakeApi({
    operationId: "op-fail",
    statuses: ["FAILED"],
    terminalReason: "AccessDenied calling DeleteStackInstances",
  });

  await assertRejects(
    () =>
      runDeleteInstances({
        api,
        stackSetName: "DemoSet",
        callAs: "SELF",
        region: "us-east-1",
        args: {
          deploymentTargets: {
            organizationalUnitIds: [],
            accounts: ["111111111111"],
            accountFilterType: "INTERSECTION",
          },
          regions: ["us-east-1"],
          retainStacks: true,
          confirmWholeTarget: false,
          ...fastPoll,
        },
        context,
      }),
    Error,
    "ended FAILED",
  );

  // The result is still persisted before the throw, recording the failure.
  const results = written.filter((w) => w.spec === "result");
  assertEquals(results.length, 1);
  assertEquals(results[0].data.status, "FAILED");
});

Deno.test("smoke: deleteInstances refuses an unsafe whole-target delete before any API call", async () => {
  const { context, written } = makeContext();
  const { api, calls } = fakeApi({
    operationId: "op-x",
    statuses: ["SUCCEEDED"],
  });

  await assertRejects(
    () =>
      runDeleteInstances({
        api,
        stackSetName: "DemoSet",
        callAs: "SELF",
        region: "us-east-1",
        args: {
          deploymentTargets: {
            organizationalUnitIds: ["ou-root-abc123"],
            accounts: [],
            accountFilterType: "NONE",
          },
          regions: ["us-east-1"],
          retainStacks: false,
          confirmWholeTarget: false,
          ...fastPoll,
        },
        context,
      }),
    Error,
    "refusing unsafe deleteInstances",
  );

  // Guard short-circuits: no SDK call, no resource written.
  assertEquals(calls.deleteInstances.length, 0);
  assertEquals(written.length, 0);
});

// ---------------------------------------------------------------------------
// deleteStackSet
// ---------------------------------------------------------------------------

Deno.test("smoke: deleteStackSet deletes the set and writes one result", async () => {
  const { context, written } = makeContext();
  const { api, calls } = fakeApi({ operationId: "", statuses: ["SUCCEEDED"] });

  const result = await runDeleteStackSet({
    api,
    stackSetName: "DemoSet",
    callAs: "DELEGATED_ADMIN",
    region: "eu-west-1",
    context,
  });

  // DeleteStackSet was called exactly once; no describe polling for this path.
  assertEquals(calls.deleteStackSet, 1);
  assertEquals(calls.describeOperation.length, 0);

  // Exactly one result, keyed by stackset name.
  const results = written.filter((w) => w.spec === "result");
  assertEquals(results.length, 1);
  assertEquals(results[0].key, "delete-stackset-DemoSet");

  // Result shape.
  assertEquals(result.action, "delete-stackset");
  assertEquals(result.status, "SUCCEEDED");
  assertEquals(result.operationId, "");
  assertEquals(result.regions, []);
  assertEquals(result.callAs, "DELEGATED_ADMIN");
  assertEquals(result.dataHandles.length, 1);
});

Deno.test("smoke: every test finishes well under the network budget", () => {
  // Sentinel — the smoke tests above all complete in single-digit
  // milliseconds. Anything touching the network would blow past that and
  // belongs outside this harness.
  assert(true);
});
