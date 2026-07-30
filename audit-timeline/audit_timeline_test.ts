/**
 * Tests for the pure helpers of `@jentz/audit-timeline`.
 *
 * @module
 */

import { assertEquals } from "jsr:@std/assert@1";
import {
  buildResolutionSql,
  type ChangeEvent,
  collect,
  datasetRowToFailedAttempt,
  eventToFailedAttempt,
  guidToHex,
  methodToVerb,
  report,
  rowToEvent,
  siteFromPath,
  statusPartition,
  summarizeActors,
  toIsoUtc,
} from "./audit_timeline.ts";

const FIELDS = {
  timestamp: "@timestamp",
  actor: "user_id",
  account: "account_id",
  requestId: "request_id",
  service: "service",
  method: "http.method",
  path: "http.path",
  status: "http.status",
  body: "http.body",
  sourceIp: "",
};

function event(overrides: Partial<ChangeEvent>): ChangeEvent {
  return {
    timestamp: "2026-06-11T08:40:04.097Z",
    actor: "{AAAA1111-BBBB-2222-CCCC-333344445555}",
    account: "1001",
    requestId: "r1",
    service: "widgets",
    verb: "update",
    method: "PUT",
    path: "/sites/2/widgets/7",
    site: "2",
    status: "200",
    body: "",
    origin: "",
    ...overrides,
  };
}

Deno.test("toIsoUtc converts Logs Insights timestamps as UTC", () => {
  assertEquals(toIsoUtc("2026-06-11 08:40:04.097"), "2026-06-11T08:40:04.097Z");
  assertEquals(toIsoUtc("2026-06-11 08:40:04"), "2026-06-11T08:40:04.000Z");
  assertEquals(
    toIsoUtc("2026-06-11T08:40:04.097Z"),
    "2026-06-11T08:40:04.097Z",
  );
  assertEquals(toIsoUtc("not a date"), "not a date");
});

Deno.test("methodToVerb maps HTTP methods to change verbs", () => {
  assertEquals(methodToVerb("POST"), "add");
  assertEquals(methodToVerb("PUT"), "update");
  assertEquals(methodToVerb("PATCH"), "update");
  assertEquals(methodToVerb("DELETE"), "delete");
  assertEquals(methodToVerb("get"), "get");
  assertEquals(methodToVerb(""), "other");
});

Deno.test("siteFromPath extracts the /sites/{site}/ segment", () => {
  assertEquals(siteFromPath("/acct/api/sites/2/widgets/7"), "2");
  assertEquals(
    siteFromPath("/sites/{AAAA1111-BBBB-2222-CCCC-333344445555}/widgets"),
    "{AAAA1111-BBBB-2222-CCCC-333344445555}",
  );
  assertEquals(siteFromPath("/health"), "");
});

Deno.test("guidToHex strips braces and dashes", () => {
  assertEquals(
    guidToHex("{AAAA1111-BBBB-2222-CCCC-333344445555}"),
    "AAAA1111BBBB2222CCCC333344445555",
  );
});

Deno.test("rowToEvent maps fields and annotates origin from natMap", () => {
  const row = {
    "@timestamp": "2026-06-11 08:40:04.097",
    user_id: "{AAAA1111-BBBB-2222-CCCC-333344445555}",
    account_id: "1001",
    request_id: "r1",
    service: "widgets",
    "http.method": "PUT",
    "http.path": "/sites/2/widgets/7",
    "http.status": "200",
    "http.body": '{"name":"CA"}',
    src_ip: "198.51.100.7",
  };
  const e = rowToEvent(row, { ...FIELDS, sourceIp: "src_ip" }, {
    "198.51.100.7": { account: "prod-x", service: "worker" },
  });
  assertEquals(e.timestamp, "2026-06-11T08:40:04.097Z");
  assertEquals(e.verb, "update");
  assertEquals(e.site, "2");
  assertEquals(e.origin, "prod-x / worker");
  assertEquals(e.body, '{"name":"CA"}');
});

Deno.test("summarizeActors rolls up counts and first/last seen", () => {
  const actors = summarizeActors([
    event({ timestamp: "2026-06-11T08:40:04.097Z" }),
    event({ timestamp: "2026-06-11T08:42:03.556Z" }),
    event({
      actor: "{DDDD1111-BBBB-2222-CCCC-333344445555}",
      timestamp: "2026-06-10T08:49:21.606Z",
    }),
    event({ actor: "" }),
  ]);
  assertEquals(actors.length, 2);
  assertEquals(actors[0].changes, 2);
  assertEquals(actors[0].firstSeen, "2026-06-11T08:40:04.097Z");
  assertEquals(actors[0].lastSeen, "2026-06-11T08:42:03.556Z");
});

Deno.test("buildResolutionSql emits one statement per account", () => {
  const config = {
    identityResolution: {
      sqlTemplate:
        "SELECT email FROM db{account}.users WHERE id IN ({userid_list});",
      useridTerm: "UNHEX('{guid_hex}')",
    },
  };
  const sql = buildResolutionSql(
    [
      event({}),
      event({ actor: "{DDDD1111-BBBB-2222-CCCC-333344445555}" }),
      event({ account: "1002" }),
    ],
    config,
  );
  assertEquals(sql.length, 2);
  assertEquals(
    sql[0],
    "SELECT email FROM db1001.users WHERE id IN " +
      "(UNHEX('AAAA1111BBBB2222CCCC333344445555'), " +
      "UNHEX('DDDD1111BBBB2222CCCC333344445555'));",
  );
  assertEquals(
    sql[1],
    "SELECT email FROM db1002.users WHERE id IN " +
      "(UNHEX('AAAA1111BBBB2222CCCC333344445555'));",
  );
});

Deno.test("buildResolutionSql returns empty without a template", () => {
  assertEquals(buildResolutionSql([event({})], {}), []);
});

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
      stepName: a.step ?? "s0",
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
        const i = Number(name.slice(1));
        if (artifacts[i].unreadable) return Promise.reject(new Error("boom"));
        return Promise.resolve(enc.encode(JSON.stringify(artifacts[i].value)));
      },
    },
  };
}

Deno.test("collect merges query rows with config and counts skips", async () => {
  const context = fakeContext([
    {
      spec: "config",
      value: {
        identityResolution: {
          sqlTemplate:
            "SELECT 1 FROM db{account}.t WHERE u IN ({userid_list});",
          useridTerm: "UNHEX('{guid_hex}')",
        },
      },
    },
    {
      spec: "query_results",
      value: {
        results: [
          {
            "@timestamp": "2026-06-11 08:40:04.097",
            user_id: "{AAAA1111-BBBB-2222-CCCC-333344445555}",
            account_id: "1001",
            service: "widgets",
            "http.method": "PUT",
            "http.path": "/sites/2/widgets/7",
            "http.status": "200",
          },
        ],
      },
    },
    { spec: "query_results", value: { nope: true }, unreadable: false },
    { spec: "query_results", value: {}, unreadable: true },
    { spec: "other_spec", value: { ignored: true } },
  ]);
  const collected = await collect(context);
  assertEquals(collected.events.length, 1);
  assertEquals(collected.events[0].verb, "update");
  assertEquals(collected.events[0].timestamp, "2026-06-11T08:40:04.097Z");
  assertEquals(collected.skipped, 2);
});

Deno.test("report.execute emits markdown, SQL, and json payload", async () => {
  const context = fakeContext([
    {
      spec: "config",
      value: {
        identityResolution: {
          sqlTemplate:
            "SELECT 1 FROM db{account}.t WHERE u IN ({userid_list});",
          useridTerm: "UNHEX('{guid_hex}')",
        },
      },
    },
    {
      spec: "query_results",
      value: {
        results: [
          {
            "@timestamp": "2026-06-11 08:40:04.097",
            user_id: "{AAAA1111-BBBB-2222-CCCC-333344445555}",
            account_id: "1001",
            service: "widgets",
            "http.method": "DELETE",
            "http.path": "/sites/2/widgets/7",
            "http.status": "200",
          },
        ],
      },
    },
  ]);
  const { markdown, json } = await report.execute(context);
  assertEquals(json.degraded, false);
  assertEquals(json.eventCount, 1);
  assertEquals(json.actors.length, 1);
  assertEquals(
    json.resolutionSql[0],
    "SELECT 1 FROM db1001.t WHERE u IN " +
      "(UNHEX('AAAA1111BBBB2222CCCC333344445555'));",
  );
  assertEquals(markdown.includes("## Timeline"), true);
  assertEquals(markdown.includes("delete"), true);
  assertEquals(markdown.includes("```sql"), true);
});

Deno.test("statusPartition splits ok, rejected, and no-response", () => {
  assertEquals(statusPartition("200"), "ok");
  assertEquals(statusPartition("399"), "ok");
  assertEquals(statusPartition("400"), "rejected");
  assertEquals(statusPartition("503"), "rejected");
  assertEquals(statusPartition(undefined), "no-response");
  assertEquals(statusPartition(""), "no-response");
  assertEquals(statusPartition("not-a-number"), "no-response");
});

Deno.test("eventToFailedAttempt keeps actor and builds the operation", () => {
  const f = eventToFailedAttempt(event({ status: "403" }), "rejected");
  assertEquals(f.family, "rejected");
  assertEquals(f.actor, "{AAAA1111-BBBB-2222-CCCC-333344445555}");
  assertEquals(f.operation, "PUT /sites/2/widgets/7");
  assertEquals(f.detail, "403");
});

Deno.test("datasetRowToFailedAttempt maps configured fields", () => {
  const f = datasetRowToFailedAttempt(
    {
      "@timestamp": "2026-06-11 08:40:04.097",
      operationName: "UpdateWidget",
      extensions: '{"code":"FORBIDDEN"}',
    },
    "graphql-error",
    {
      timestamp: "@timestamp",
      actor: "",
      operation: "operationName",
      detail: "extensions",
    },
  );
  assertEquals(f.timestamp, "2026-06-11T08:40:04.097Z");
  assertEquals(f.family, "graphql-error");
  assertEquals(f.actor, "");
  assertEquals(f.operation, "UpdateWidget");
  assertEquals(f.detail, '{"code":"FORBIDDEN"}');
});

const FAILED_CONFIG = {
  identityResolution: {
    sqlTemplate: "SELECT 1 FROM db{account}.t WHERE u IN ({userid_list});",
    useridTerm: "UNHEX('{guid_hex}')",
  },
  auditTimeline: {
    failedAttempts: {
      rejectedFamily: "platform-rejected",
      noResponseFamily: "no-response",
      datasets: {
        "query-failed-graphql": {
          family: "graphql-error",
          fields: { operation: "operationName", detail: "extensions" },
        },
      },
    },
  },
};

function primaryRow(overrides: Record<string, string>) {
  return {
    "@timestamp": "2026-06-11 08:40:04.097",
    user_id: "{AAAA1111-BBBB-2222-CCCC-333344445555}",
    account_id: "1001",
    service: "widgets",
    "http.method": "PUT",
    "http.path": "/sites/2/widgets/7",
    "http.status": "200",
    ...overrides,
  };
}

Deno.test("collect partitions primary rows and routes failed datasets", async () => {
  const context = fakeContext([
    { spec: "config", value: FAILED_CONFIG },
    {
      spec: "query_results",
      step: "query-changes",
      value: {
        results: [
          primaryRow({}),
          primaryRow({
            "@timestamp": "2026-06-11 09:00:00.000",
            "http.status": "403",
          }),
          primaryRow({
            "@timestamp": "2026-06-11 10:00:00.000",
            "http.status": "",
          }),
        ],
      },
    },
    {
      spec: "query_results",
      step: "query-failed-graphql",
      value: {
        results: [
          {
            "@timestamp": "2026-06-11 08:30:00.000",
            operationName: "UpdateWidget",
            extensions: '{"code":"FORBIDDEN"}',
          },
        ],
      },
    },
  ]);
  const collected = await collect(context);
  assertEquals(collected.events.length, 1);
  assertEquals(collected.events[0].status, "200");
  assertEquals(collected.failedPrimary.length, 2);
  assertEquals(collected.failedAttempts.length, 3);
  assertEquals(
    collected.failedAttempts.map((f) => f.family),
    ["graphql-error", "platform-rejected", "no-response"],
  );
});

Deno.test("collect without failedAttempts config keeps all rows on the timeline", async () => {
  const context = fakeContext([
    {
      spec: "query_results",
      value: { results: [primaryRow({ "http.status": "403" })] },
    },
  ]);
  const collected = await collect(context);
  assertEquals(collected.events.length, 1);
  assertEquals(collected.failedAttempts.length, 0);
  assertEquals(collected.failedConfig, null);
});

Deno.test("report.execute renders failed attempts and keeps graphql rows out of roster and SQL", async () => {
  const context = fakeContext([
    { spec: "config", value: FAILED_CONFIG },
    {
      spec: "query_results",
      step: "query-changes",
      value: {
        results: [
          primaryRow({}),
          primaryRow({
            "@timestamp": "2026-06-11 09:00:00.000",
            user_id: "{DDDD1111-BBBB-2222-CCCC-333344445555}",
            "http.status": "403",
          }),
        ],
      },
    },
    {
      spec: "query_results",
      step: "query-failed-graphql",
      value: {
        results: [
          {
            "@timestamp": "2026-06-11 08:30:00.000",
            operationName: "UpdateWidget",
            extensions: '{"code":"FORBIDDEN"}',
          },
        ],
      },
    },
  ]);
  const { markdown, json } = await report.execute(context);
  assertEquals(json.degraded, false);
  assertEquals(json.eventCount, 1);
  assertEquals(json.failedAttemptCount, 2);
  // The rejected actor still resolves; the graphql row adds no actor.
  assertEquals(json.actors.length, 2);
  assertEquals(json.resolutionSql.length, 1);
  assertEquals(
    json.resolutionSql[0].includes("DDDD1111BBBB2222CCCC333344445555"),
    true,
  );
  assertEquals(markdown.includes("## Failed attempts"), true);
  assertEquals(markdown.includes("platform-rejected"), true);
  assertEquals(markdown.includes("graphql-error"), true);
  assertEquals(markdown.includes("`unknown`"), true);
  assertEquals(markdown.includes("UpdateWidget"), true);
});

Deno.test("report.execute renders 'None found.' with config but no failures", async () => {
  const context = fakeContext([
    { spec: "config", value: FAILED_CONFIG },
    {
      spec: "query_results",
      step: "query-changes",
      value: { results: [primaryRow({})] },
    },
  ]);
  const { markdown, json } = await report.execute(context);
  assertEquals(json.failedAttemptCount, 0);
  assertEquals(markdown.includes("## Failed attempts"), true);
  assertEquals(markdown.includes("_None found._"), true);
});

Deno.test("report.execute omits the section without failedAttempts config", async () => {
  const context = fakeContext([
    {
      spec: "query_results",
      value: { results: [primaryRow({})] },
    },
  ]);
  const { markdown } = await report.execute(context);
  assertEquals(markdown.includes("## Failed attempts"), false);
});

Deno.test("collect flags query artifacts that did not complete", async () => {
  const context = fakeContext([
    {
      spec: "query_results",
      step: "query-changes",
      value: { results: [], status: "Running" },
    },
    {
      spec: "query_results",
      step: "query-ok",
      value: { results: [primaryRow({})], status: "Complete" },
    },
    {
      spec: "query_results",
      step: "query-legacy",
      value: { results: [primaryRow({})] },
    },
  ]);
  const collected = await collect(context);
  assertEquals(collected.incomplete, [
    { step: "query-changes", status: "Running" },
  ]);
  assertEquals(collected.events.length, 2);
  assertEquals(collected.skipped, 0);
});

Deno.test("report.execute surfaces incomplete queries instead of silent zero rows", async () => {
  const context = fakeContext([
    {
      spec: "query_results",
      step: "query-changes",
      value: { results: [], status: "Running" },
    },
  ]);
  const { markdown, json } = await report.execute(context);
  assertEquals(json.degraded, false);
  assertEquals(json.incompleteQueryCount, 1);
  assertEquals(json.incompleteQueries, [
    { step: "query-changes", status: "Running" },
  ]);
  assertEquals(markdown.includes("Warning — incomplete results"), true);
  assertEquals(markdown.includes("`query-changes`: Running"), true);
  assertEquals(markdown.includes("not evidence of no changes"), true);
  assertEquals(
    markdown.includes("No changes matched the query window"),
    false,
  );
});

Deno.test("report.execute omits the incomplete warning when queries complete", async () => {
  const context = fakeContext([
    {
      spec: "query_results",
      step: "query-changes",
      value: { results: [primaryRow({})], status: "Complete" },
    },
  ]);
  const { markdown, json } = await report.execute(context);
  assertEquals(json.incompleteQueryCount, 0);
  assertEquals(markdown.includes("Warning — incomplete results"), false);
});

Deno.test("report.execute degrades on a broken context", async () => {
  const { markdown, json } = await report.execute({
    workflowName: "wf-test",
    logger: {},
    get stepExecutions(): never {
      throw new Error("context exploded");
    },
    dataRepository: {},
  });
  assertEquals(json.degraded, true);
  assertEquals(json.eventCount, 0);
  assertEquals(markdown.includes("degraded"), true);
});
