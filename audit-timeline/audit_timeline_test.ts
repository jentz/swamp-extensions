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
  guidToHex,
  methodToVerb,
  report,
  rowToEvent,
  siteFromPath,
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
  artifacts: Array<{ spec: string; value: unknown; unreadable?: boolean }>,
) {
  const enc = new TextEncoder();
  return {
    workflowName: "wf-test",
    logger: { info: () => {}, warn: () => {} },
    stepExecutions: [
      {
        modelType: "@test/source",
        modelId: "m1",
        dataHandles: artifacts.map((a, i) => ({
          name: `h${i}`,
          version: 1,
          metadata: { tags: { specName: a.spec } },
        })),
      },
    ],
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
