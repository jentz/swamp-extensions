/**
 * Tests for the pure helpers of `@jentz/audit-timeline`.
 *
 * @module
 */

import { assertEquals } from "jsr:@std/assert@1";
import {
  buildResolutionSql,
  type ChangeEvent,
  guidToHex,
  methodToVerb,
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
    account: "92613",
    requestId: "r1",
    service: "salestaxes",
    verb: "update",
    method: "PUT",
    path: "/sites/2/salestaxes/7",
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
  assertEquals(siteFromPath("/acct/api/sites/2/salestaxes/7"), "2");
  assertEquals(
    siteFromPath("/sites/{AAAA1111-BBBB-2222-CCCC-333344445555}/salestaxes"),
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
    account_id: "92613",
    request_id: "r1",
    service: "salestaxes",
    "http.method": "PUT",
    "http.path": "/sites/2/salestaxes/7",
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
      event({ account: "92700" }),
    ],
    config,
  );
  assertEquals(sql.length, 2);
  assertEquals(
    sql[0],
    "SELECT email FROM db92613.users WHERE id IN " +
      "(UNHEX('AAAA1111BBBB2222CCCC333344445555'), " +
      "UNHEX('DDDD1111BBBB2222CCCC333344445555'));",
  );
  assertEquals(
    sql[1],
    "SELECT email FROM db92700.users WHERE id IN " +
      "(UNHEX('AAAA1111BBBB2222CCCC333344445555'));",
  );
});

Deno.test("buildResolutionSql returns empty without a template", () => {
  assertEquals(buildResolutionSql([event({})], {}), []);
});
