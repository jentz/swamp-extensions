/**
 * Unit tests for the canonical `_lib/stackset.ts`.
 *
 * Owns the trio-shared primitives once, at the canonical source: the
 * `pollToTerminal` budget semantics (exactly `maxPolls` fetches, at most
 * `maxPolls - 1` inter-poll waits, no trailing wait), the abort-aware `delay`
 * (including listener detach on normal completion), the `selectCredentials`
 * branch, the `STACKSET_RETRY` pin, and `isoOrEmpty` edge cases.
 *
 * No network, no filesystem I/O, no real timers on the poll paths — sleeps
 * are injected no-ops so even the budget-exhausted path runs at zero
 * wall-clock time.
 */

import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";

import {
  type AwsOperationSummary,
  delay,
  isoOrEmpty,
  pollToTerminal,
  selectCredentials,
  STACKSET_RETRY,
  TERMINAL,
} from "./stackset.ts";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/**
 * A fetch whose results replay a scripted sequence, holding on the final
 * entry once the script is exhausted. Counts its calls so tests can assert
 * how many polls happened.
 */
function scriptedFetch<T>(
  states: T[],
): { fetch: () => Promise<T>; calls: () => number } {
  let calls = 0;
  return {
    fetch: () => {
      const state = states[Math.min(calls, states.length - 1)];
      calls++;
      return Promise.resolve(state);
    },
    calls: () => calls,
  };
}

/** A no-op sleep that counts invocations and records its arguments. */
function countingSleep(): {
  sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
  count: () => number;
  lastMs: () => number | undefined;
  lastSignal: () => AbortSignal | undefined;
} {
  let count = 0;
  let lastMs: number | undefined;
  let lastSignal: AbortSignal | undefined;
  return {
    sleep: (ms, signal) => {
      count++;
      lastMs = ms;
      lastSignal = signal;
      return Promise.resolve();
    },
    count: () => count,
    lastMs: () => lastMs,
    lastSignal: () => lastSignal,
  };
}

// ---------------------------------------------------------------------------
// pollToTerminal — budget semantics
// ---------------------------------------------------------------------------

Deno.test("pollToTerminal: terminal on the first poll returns after 1 fetch and 0 sleeps", async () => {
  const { fetch, calls } = scriptedFetch([{ status: "SUCCEEDED" }]);
  const { sleep, count } = countingSleep();

  const last = await pollToTerminal(fetch, (s) => s.status, {
    pollSeconds: 5,
    maxPolls: 10,
    sleep,
    label: "Operation op-1",
  });

  assertEquals(last.status, "SUCCEEDED");
  assertEquals(calls(), 1);
  assertEquals(count(), 0);
});

Deno.test("pollToTerminal: progresses RUNNING to SUCCEEDED and returns the last state", async () => {
  const { fetch, calls } = scriptedFetch([
    { status: "RUNNING", reason: "" },
    { status: "SUCCEEDED", reason: "done" },
  ]);
  const { sleep, count } = countingSleep();

  const last = await pollToTerminal(fetch, (s) => s.status, {
    pollSeconds: 5,
    maxPolls: 10,
    sleep,
    label: "Operation op-2",
  });

  // The full last state comes back, not just the status string.
  assertEquals(last, { status: "SUCCEEDED", reason: "done" });
  assertEquals(calls(), 2);
  assertEquals(count(), 1);
});

Deno.test("pollToTerminal: FAILED and STOPPED are terminal returns, not throws", async () => {
  for (const status of ["FAILED", "STOPPED"]) {
    const { fetch } = scriptedFetch([{ status }]);
    const last = await pollToTerminal(fetch, (s) => s.status, {
      pollSeconds: 5,
      maxPolls: 10,
      sleep: () => Promise.resolve(),
      label: "Operation op-3",
    });
    assertEquals(last.status, status);
    assert(TERMINAL.has(last.status));
  }
});

Deno.test("pollToTerminal: budget exhaustion does exactly maxPolls fetches and maxPolls-1 sleeps", async () => {
  const maxPolls = 5;
  const { fetch, calls } = scriptedFetch([{ status: "RUNNING" }]);
  const { sleep, count } = countingSleep();

  const err = await assertRejects(
    () =>
      pollToTerminal(fetch, (s) => s.status, {
        pollSeconds: 20,
        maxPolls,
        sleep,
        label: "drift detection for StuckSet",
      }),
    Error,
    "did not finish within 5 polls (last status RUNNING)",
  );
  // The caller's label is the subject of the message.
  assert(err.message.startsWith("drift detection for StuckSet"));

  // Polled exactly maxPolls times, then gave up.
  assertEquals(calls(), maxPolls);
  // Waited at most maxPolls-1 times — no wasted sleep after the final poll.
  assertEquals(count(), maxPolls - 1);
});

Deno.test("pollToTerminal: maxPolls of 1 never sleeps", async () => {
  const { fetch, calls } = scriptedFetch([{ status: "RUNNING" }]);
  const { sleep, count } = countingSleep();

  await assertRejects(
    () =>
      pollToTerminal(fetch, (s) => s.status, {
        pollSeconds: 20,
        maxPolls: 1,
        sleep,
        label: "Operation op-solo",
      }),
    Error,
    "did not finish within 1 polls (last status RUNNING)",
  );
  assertEquals(calls(), 1);
  assertEquals(count(), 0);
});

Deno.test("pollToTerminal: forwards pollSeconds (as ms) and the signal to the sleep", async () => {
  const controller = new AbortController();
  const { fetch } = scriptedFetch([
    { status: "RUNNING" },
    { status: "SUCCEEDED" },
  ]);
  const { sleep, lastMs, lastSignal } = countingSleep();

  await pollToTerminal(fetch, (s) => s.status, {
    pollSeconds: 20,
    maxPolls: 10,
    sleep,
    signal: controller.signal,
    label: "Operation op-fwd",
  });

  assertEquals(lastMs(), 20_000);
  assertEquals(lastSignal(), controller.signal);
});

Deno.test("pollToTerminal: onPoll sees each non-terminal poll, never the terminal one", async () => {
  const { fetch } = scriptedFetch([
    { status: "QUEUED" },
    { status: "RUNNING" },
    { status: "SUCCEEDED" },
  ]);
  const seen: [string, number, number][] = [];

  await pollToTerminal(fetch, (s) => s.status, {
    pollSeconds: 5,
    maxPolls: 10,
    sleep: () => Promise.resolve(),
    onPoll: (status, poll, maxPolls) => seen.push([status, poll, maxPolls]),
    label: "Operation op-log",
  });

  // 1-based poll numbers with the budget, matching the callers' log wording;
  // the terminal SUCCEEDED poll produces no onPoll call.
  assertEquals(seen, [["QUEUED", 1, 10], ["RUNNING", 2, 10]]);
});

Deno.test("pollToTerminal: polls a raw AwsOperationSummary via statusOf", async () => {
  // The drift caller polls the raw SDK summary and keeps the whole record.
  const succeeded: AwsOperationSummary = {
    OperationId: "op-raw",
    Action: "DETECT_DRIFT",
    Status: "SUCCEEDED",
    EndTimestamp: new Date("2026-07-04T00:00:00.000Z"),
  };
  const { fetch } = scriptedFetch<AwsOperationSummary>([
    { Status: "RUNNING" },
    succeeded,
  ]);

  const last = await pollToTerminal(fetch, (op) => op.Status ?? "UNKNOWN", {
    pollSeconds: 5,
    maxPolls: 10,
    sleep: () => Promise.resolve(),
    label: "drift detection for DemoSet",
  });

  assertEquals(last, succeeded);
});

// ---------------------------------------------------------------------------
// delay
// ---------------------------------------------------------------------------

Deno.test("delay: resolves after the wait", async () => {
  await delay(1);
});

Deno.test("delay: rejects immediately when the signal is already aborted", async () => {
  const controller = new AbortController();
  controller.abort();
  await assertRejects(
    () => delay(10_000, controller.signal),
    Error,
    "aborted",
  );
});

Deno.test("delay: rejects (and clears its timer) when aborted mid-wait", async () => {
  const controller = new AbortController();
  const pending = assertRejects(
    () => delay(10_000, controller.signal),
    Error,
    "aborted",
  );
  controller.abort();
  // The rejection lands promptly and the cleared timer leaks no op — Deno's
  // test sanitizer would fail this test on a dangling 10s timer.
  await pending;
});

Deno.test("delay: detaches its abort listener on normal completion", async () => {
  let added = 0;
  let removed = 0;
  // Minimal AbortSignal stand-in that records listener churn.
  const signal = {
    aborted: false,
    addEventListener: () => {
      added++;
    },
    removeEventListener: () => {
      removed++;
    },
  } as unknown as AbortSignal;
  await delay(0, signal);
  // The listener added for the wait must be removed once the timer fires, so a
  // long poll loop sharing one signal does not leak a listener per sleep.
  assertEquals(added, 1);
  assertEquals(removed, 1);
});

// ---------------------------------------------------------------------------
// selectCredentials
// ---------------------------------------------------------------------------

Deno.test("selectCredentials: empty profile opts into the ambient chain", () => {
  assertEquals(selectCredentials(""), undefined);
});

Deno.test("selectCredentials: a named profile yields a lazy fromIni provider", () => {
  // fromIni is lazy — building the provider performs no I/O, so asserting it
  // is a callable provider is safe without any AWS config present.
  const provider = selectCredentials("audit-readonly");
  assertEquals(typeof provider, "function");
});

// ---------------------------------------------------------------------------
// STACKSET_RETRY
// ---------------------------------------------------------------------------

Deno.test("STACKSET_RETRY: stays the trio's exact historical retry config", () => {
  // Byte-for-byte today's behavior: standard retry mode, widened attempt
  // budget, no adaptive rate limiting (that would be a behavior change).
  assertEquals(STACKSET_RETRY, { maxAttempts: 8 });
});

// ---------------------------------------------------------------------------
// isoOrEmpty
// ---------------------------------------------------------------------------

Deno.test("isoOrEmpty: Date, string, and empty/garbage input", () => {
  const d = new Date("2026-06-13T00:00:00.000Z");
  assertEquals(isoOrEmpty(d), "2026-06-13T00:00:00.000Z");
  assertEquals(
    isoOrEmpty("2026-06-13T00:00:00.000Z"),
    "2026-06-13T00:00:00.000Z",
  );
  assertEquals(isoOrEmpty(""), "");
  assertEquals(isoOrEmpty(undefined), "");
  assertEquals(isoOrEmpty(12345), "");
});
