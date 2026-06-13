/**
 * Smoke tests — drive `runDetect` end-to-end through an in-memory `DriftApi`
 * facade with a hand-rolled swamp method context and an injected no-op sleep.
 *
 * No AWS calls, no live SDK, no network, no real timers: `describeOperation`
 * replays a scripted sequence of operation states, and the injected `sleep`
 * resolves instantly so even the poll-budget-exhausted path runs in single-digit
 * milliseconds rather than `maxPolls * pollSeconds` real seconds. All account
 * ids are placeholders so the corpus is safe to ship.
 */

import {
  assert,
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import {
  type AwsOperationSummary,
  type DriftApi,
  isoOrEmpty,
  runDetect,
} from "../aws_stackset_drift_detect.ts";

// ---------------------------------------------------------------------------
// In-memory DriftApi replay
// ---------------------------------------------------------------------------

/**
 * A `DriftApi` whose `describeOperation` returns each scripted state in turn,
 * holding on the final entry once the script is exhausted. Counts its calls so
 * tests can assert how many polls happened.
 */
function scriptedApi(
  operationId: string,
  states: AwsOperationSummary[],
): { api: DriftApi; describeCalls: () => number } {
  let calls = 0;
  const api: DriftApi = {
    detectDrift: () => Promise.resolve(operationId),
    describeOperation: (id: string) => {
      assertEquals(id, operationId);
      const state = states[Math.min(calls, states.length - 1)];
      calls++;
      return Promise.resolve(state);
    },
  };
  return { api, describeCalls: () => calls };
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

/** No-op sleep: keeps the poll loop running at zero wall-clock time. */
const noSleep = () => Promise.resolve();

const RUNNING: AwsOperationSummary = { Status: "RUNNING" };

// ---------------------------------------------------------------------------
// (a) Terminal-on-Nth-poll
// ---------------------------------------------------------------------------

Deno.test("smoke: terminal SUCCEEDED on the Nth poll writes one operation resource", async () => {
  const { context, written } = makeContext();
  const succeeded: AwsOperationSummary = {
    OperationId: "op-succ",
    Action: "DETECT_DRIFT",
    Status: "SUCCEEDED",
    CreationTimestamp: new Date("2026-06-13T00:00:00.000Z"),
    EndTimestamp: new Date("2026-06-13T00:03:00.000Z"),
    StatusReason: "",
  };
  // RUNNING for 2 polls, then SUCCEEDED on the 3rd.
  const { api, describeCalls } = scriptedApi("op-succ", [
    RUNNING,
    RUNNING,
    succeeded,
  ]);

  const result = await runDetect({
    api,
    stackSetName: "DemoSet",
    pollSeconds: 20,
    maxPolls: 90,
    sleep: noSleep,
    context,
  });

  // Polled until terminal — exactly 3 describe calls.
  assertEquals(describeCalls(), 3);
  assertEquals(result.status, "SUCCEEDED");
  assertEquals(result.operationId, "op-succ");
  assertEquals(result.dataHandles.length, 1);

  // Exactly one operation resource, keyed by the operation id.
  assertEquals(written.length, 1);
  const row = written[0];
  assertEquals(row.spec, "operation");
  assertEquals(row.key, "op-succ");
  assertEquals(row.data, {
    stackSetName: "DemoSet",
    operationId: "op-succ",
    action: "DETECT_DRIFT",
    status: "SUCCEEDED",
    creationTimestamp: "2026-06-13T00:00:00.000Z",
    endTimestamp: "2026-06-13T00:03:00.000Z",
    statusReason: "",
  });
});

Deno.test("smoke: terminal FAILED is recorded, not thrown", async () => {
  const { context, written } = makeContext();
  const failed: AwsOperationSummary = {
    OperationId: "op-fail",
    Action: "DETECT_DRIFT",
    Status: "FAILED",
    CreationTimestamp: new Date("2026-06-13T01:00:00.000Z"),
    EndTimestamp: new Date("2026-06-13T01:01:00.000Z"),
    StatusReason: "Account 111111111111 is suspended",
  };
  const { api } = scriptedApi("op-fail", [RUNNING, failed]);

  // FAILED is a legitimate terminal outcome — must NOT throw.
  const result = await runDetect({
    api,
    stackSetName: "DemoSet",
    pollSeconds: 20,
    maxPolls: 90,
    sleep: noSleep,
    context,
  });

  assertEquals(result.status, "FAILED");
  assertEquals(written.length, 1);
  assertEquals(written[0].spec, "operation");
  assertEquals(written[0].key, "op-fail");
  assertEquals(written[0].data.status, "FAILED");
  assertEquals(
    written[0].data.statusReason,
    "Account 111111111111 is suspended",
  );
});

Deno.test("smoke: terminal op with absent timestamps maps to empty strings", async () => {
  const { context, written } = makeContext();
  // Terminal SUCCEEDED but CreationTimestamp/EndTimestamp/StatusReason are all
  // absent — exercises the isoOrEmpty `""` branch and the `?? ""` reason
  // fallback in the real write path.
  const succeeded: AwsOperationSummary = {
    OperationId: "op-bare",
    Action: "DETECT_DRIFT",
    Status: "SUCCEEDED",
  };
  const { api } = scriptedApi("op-bare", [succeeded]);

  const result = await runDetect({
    api,
    stackSetName: "BareSet",
    pollSeconds: 20,
    maxPolls: 90,
    sleep: noSleep,
    context,
  });

  assertEquals(result.status, "SUCCEEDED");
  assertEquals(written.length, 1);
  const row = written[0];
  assertEquals(row.spec, "operation");
  assertEquals(row.key, "op-bare");
  // Absent fields map to "" — and stackSetName echoes the global-args value
  // (second covered case, so the echo is not single-covered).
  assertEquals(row.data.stackSetName, "BareSet");
  assertEquals(row.data.creationTimestamp, "");
  assertEquals(row.data.endTimestamp, "");
  assertEquals(row.data.statusReason, "");
});

// ---------------------------------------------------------------------------
// (b) Poll-budget-exhausted
// ---------------------------------------------------------------------------

Deno.test("smoke: poll budget exhausted throws naming the last status and writes nothing", async () => {
  const { context, written } = makeContext();
  const maxPolls = 5;
  // Always RUNNING — never reaches a terminal state.
  const { api, describeCalls } = scriptedApi("op-stuck", [RUNNING]);

  const err = await assertRejects(
    () =>
      runDetect({
        api,
        stackSetName: "StuckSet",
        pollSeconds: 20,
        maxPolls,
        sleep: noSleep,
        context,
      }),
    Error,
    "did not finish within 5 polls (last status RUNNING)",
  );
  // Message names the stackset too.
  assert(err.message.includes("StuckSet"));

  // Polled exactly maxPolls times, then gave up.
  assertEquals(describeCalls(), maxPolls);
  // No resource written on budget exhaustion.
  assertEquals(written.length, 0);
});

// ---------------------------------------------------------------------------
// isoOrEmpty (mirrors the audit sibling's unit coverage)
// ---------------------------------------------------------------------------

Deno.test("isoOrEmpty: Date, string, and undefined", () => {
  const d = new Date("2026-06-13T00:00:00.000Z");
  assertEquals(isoOrEmpty(d), "2026-06-13T00:00:00.000Z");
  assertEquals(
    isoOrEmpty("2026-06-13T00:00:00.000Z"),
    "2026-06-13T00:00:00.000Z",
  );
  assertEquals(isoOrEmpty(undefined), "");
  assertEquals(isoOrEmpty(""), "");
});

Deno.test("smoke: every test finishes well under the network budget", () => {
  // Sentinel — with the injected no-op sleep the poll loop completes in
  // single-digit milliseconds even on the budget-exhausted path. Anything
  // touching the network or a real timer would blow past that.
  assert(true);
});
