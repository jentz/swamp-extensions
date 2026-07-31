/**
 * Tests for the pure helpers of `@jentz/triage-snapshot`.
 *
 * @module
 */

import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import {
  classifyQueryArtifact,
  collect,
  MAX_TABLE_ROWS,
  mdCell,
  renderMarkdown,
  report,
} from "./triage_snapshot.ts";

const LAMBDA_SCAN = {
  functions: [
    {
      functionName: "svc-http",
      invocations: 428,
      errors: 0,
      errorRate: 0,
      deterministic: false,
    },
    {
      functionName: "svc-events",
      invocations: 12,
      errors: 12,
      errorRate: 1,
      deterministic: true,
    },
  ],
  window: { start: "2026-07-30T00:00:00Z", end: "2026-07-31T00:00:00Z" },
  note: "horizon note",
};

const QUEUE_DEPTH = {
  queues: [
    {
      queueName: "svc-events",
      visibleMessages: 0,
      notVisibleMessages: 1,
      oldestMessageAgeSeconds: 0,
    },
    {
      queueName: "svc-events-dlq",
      visibleMessages: 3,
      notVisibleMessages: 0,
      oldestMessageAgeSeconds: 7200,
    },
  ],
  window: null,
};

const GROUPED = {
  table: "svc-table",
  groups: [
    { key: { eshopId: "2", status: "pending" }, count: 9 },
    { key: { eshopId: "3", status: "resolved" }, count: 20 },
  ],
  items: [],
  itemCount: 29,
  note: "ttl note",
};

const ITEMS_ONLY = {
  table: "svc-settings",
  groups: [],
  items: [
    { eshopId: 3, state: "enabled" },
    { eshopId: 2, state: "enabled" },
  ],
  itemCount: 2,
};

const LOGS_QUERY = {
  results: [
    { "@timestamp": "2026-07-30 10:00:00.000", status: "500", n: "4" },
  ],
  status: "Complete",
  statistics: { recordsMatched: 4, recordsScanned: 100, bytesScanned: 5000 },
};

/** Build a fake report context around encoded artifacts. */
function fakeContext(
  artifacts: Array<
    { spec: string; value: unknown; unreadable?: boolean; step?: string }
  >,
) {
  const enc = new TextEncoder();
  return {
    workflowName: "wf-test",
    logger: { info: () => {}, warn: () => {} },
    stepExecutions: artifacts.map((a, i) => ({
      stepName: a.step ?? `step-${i}`,
      modelType: "@test/source",
      modelId: "m1",
      dataHandles: [
        {
          name: `h${i}`,
          version: 1,
          metadata: { tags: { specName: a.spec } },
        },
      ],
    })),
    dataRepository: {
      getContent: (
        _type: string,
        _id: string,
        name: string,
        _version: number,
      ) => {
        const idx = Number(name.slice(1));
        if (artifacts[idx]?.unreadable) throw new Error("unreadable");
        return Promise.resolve(
          enc.encode(JSON.stringify(artifacts[idx].value)),
        );
      },
    },
  };
}

Deno.test("classifyQueryArtifact tells grouped counts from logs rows", () => {
  assertEquals(classifyQueryArtifact(GROUPED)?.kind, "grouped_counts");
  assertEquals(classifyQueryArtifact(ITEMS_ONLY)?.kind, "grouped_counts");
  // an ungrouped query stores groups: null — normalized to []
  const nullGroups = classifyQueryArtifact({
    ...ITEMS_ONLY,
    groups: null,
    note: null,
  });
  assertEquals(nullGroups?.kind, "grouped_counts");
  assertEquals(
    nullGroups?.kind === "grouped_counts" ? nullGroups.parsed.groups : null,
    [],
  );
  assertEquals(classifyQueryArtifact(LOGS_QUERY)?.kind, "logs_query");
  assertEquals(classifyQueryArtifact({ nope: true }), null);
});

Deno.test("collect gathers recognized artifacts in step order", async () => {
  const collected = await collect(fakeContext([
    { spec: "lambda_failure_scan", value: LAMBDA_SCAN },
    { spec: "queue_depth", value: QUEUE_DEPTH },
    { spec: "query_results", value: GROUPED },
    { spec: "query_results", value: LOGS_QUERY },
    { spec: "log_groups", value: { ignored: true } },
  ]));
  assertEquals(collected.sections.map((s) => s.kind), [
    "lambda_scan",
    "queue_depth",
    "grouped_counts",
    "logs_query",
  ]);
  assertEquals(collected.skipped, 0);
  assertEquals(collected.incomplete, []);
});

Deno.test("collect counts unreadable and malformed artifacts as skipped", async () => {
  const collected = await collect(fakeContext([
    { spec: "lambda_failure_scan", value: LAMBDA_SCAN, unreadable: true },
    { spec: "queue_depth", value: { wrong: "shape" } },
    { spec: "query_results", value: { also: "wrong" } },
  ]));
  assertEquals(collected.sections, []);
  assertEquals(collected.skipped, 3);
});

Deno.test("collect flags a non-Complete logs query as incomplete", async () => {
  const collected = await collect(fakeContext([
    {
      spec: "query_results",
      value: { ...LOGS_QUERY, status: "Running" },
      step: "http-errors",
    },
  ]));
  assertEquals(collected.incomplete, [
    { step: "http-errors", artifact: "h0", status: "Running" },
  ]);
});

Deno.test("renderMarkdown renders every section kind", () => {
  const markdown = renderMarkdown(
    {
      sections: [
        {
          step: "a",
          artifact: "lambdas",
          kind: "lambda_scan",
          lambdaScan: LAMBDA_SCAN,
        },
        {
          step: "b",
          artifact: "queues",
          kind: "queue_depth",
          queueDepth: QUEUE_DEPTH,
        },
        {
          step: "c",
          artifact: "counts",
          kind: "grouped_counts",
          groupedCounts: GROUPED,
        },
        {
          step: "d",
          artifact: "roster",
          kind: "grouped_counts",
          groupedCounts: ITEMS_ONLY,
        },
        {
          step: "e",
          artifact: "http",
          kind: "logs_query",
          logsQuery: LOGS_QUERY,
        },
      ],
      incomplete: [],
      skipped: 0,
    },
    "2026-07-31T09:00:00.000Z",
    "health-sweep",
  );
  assertStringIncludes(markdown, "# Triage snapshot — health-sweep");
  assertStringIncludes(markdown, "**1 deterministic failure(s):** svc-events");
  assertStringIncludes(markdown, "| svc-events-dlq | 3 | 0 | 7200 |");
  assertStringIncludes(markdown, "29 record(s) in 2 group(s)");
  assertStringIncludes(markdown, "| 2 | pending | 9 |");
  assertStringIncludes(markdown, "## Query rows — roster");
  assertStringIncludes(markdown, "| 3 | enabled |");
  assertStringIncludes(markdown, "| 2026-07-30 10:00:00.000 | 500 | 4 |");
  assertStringIncludes(markdown, "_horizon note_");
});

Deno.test("renderMarkdown stamps the incomplete-query warning first", () => {
  const markdown = renderMarkdown(
    {
      sections: [],
      incomplete: [{ step: "http-errors", artifact: "h0", status: "Running" }],
      skipped: 0,
    },
    "2026-07-31T09:00:00.000Z",
    "health-sweep",
  );
  assertStringIncludes(markdown, "never reached Complete status");
  assertStringIncludes(markdown, "`h0` (Running, step `http-errors`)");
});

Deno.test("renderMarkdown caps table rows at MAX_TABLE_ROWS", () => {
  const groups = Array.from({ length: MAX_TABLE_ROWS + 5 }, (_, i) => ({
    key: { id: String(i) },
    count: 1,
  }));
  const markdown = renderMarkdown(
    {
      sections: [
        {
          step: "s",
          artifact: "big",
          kind: "grouped_counts",
          groupedCounts: { groups, items: [] },
        },
      ],
      incomplete: [],
      skipped: 0,
    },
    "2026-07-31T09:00:00.000Z",
    "wf",
  );
  assertStringIncludes(markdown, "…and 5 more row(s).");
});

Deno.test("mdCell escapes pipes and newlines", () => {
  assertEquals(mdCell("a|b\nc"), "a\\|b c");
});

Deno.test("report.execute returns markdown plus structured json", async () => {
  const result = await report.execute(fakeContext([
    { spec: "lambda_failure_scan", value: LAMBDA_SCAN },
    { spec: "query_results", value: { ...LOGS_QUERY, status: "Running" } },
  ]));
  assertEquals(result.json.report, "@jentz/triage-snapshot");
  assertEquals(result.json.sectionCount, 2);
  assertEquals(result.json.incompleteQueryCount, 1);
  assertEquals(result.json.degraded, false);
  assertStringIncludes(result.markdown, "Triage snapshot — wf-test");
});

Deno.test("report.execute never throws on a broken context", async () => {
  const result = await report.execute({
    workflowName: "wf-broken",
    logger: {},
    stepExecutions: [{
      stepName: "s",
      modelType: "t",
      modelId: "m",
      dataHandles: [{
        name: "h0",
        version: 1,
        metadata: { tags: { specName: "lambda_failure_scan" } },
      }],
    }],
    dataRepository: {
      getContent: () => {
        throw new Error("boom");
      },
    },
  });
  assertEquals(result.json.degraded, false);
  assertEquals(result.json.skipped, 1);
});
