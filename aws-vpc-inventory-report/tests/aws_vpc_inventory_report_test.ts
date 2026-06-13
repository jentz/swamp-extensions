/**
 * Unit tests for `@jentz/aws-vpc-inventory-report`.
 *
 * Four layers:
 *
 *   1. Collection / decoding — `collect` walks `context.stepExecutions`,
 *      matches the upstream model type, and decodes `vpc` / `scan_error`
 *      artifacts. Malformed (bad-JSON) and schema-mismatched artifacts are
 *      counted into `skipped`, never thrown.
 *   2. Markdown rendering — `renderMarkdown` produces the summary, the full
 *      inventory table in stable sort order, and the coverage-gaps sections.
 *   3. The coverage-gaps section — auth_expired → needs-aws-sso-login,
 *      access_denied → blocked-by-SCP/IAM, other → counted.
 *   4. The JSON payload — `report.execute` carries a structured `vpcs[]` rows
 *      array (in `compareVpcs` order), summary counts, a per-kind error
 *      breakdown, the skipped count, and the `degraded` flag — and NO
 *      `csv` / `columns` keys.
 *
 * @module
 */

import {
  assert,
  assertEquals,
  assertExists,
  assertFalse,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import {
  collect,
  type Collected,
  compareVpcs,
  INVENTORY_MODEL_TYPE,
  renderMarkdown,
  report,
  SCAN_ERROR_SPEC,
  type ScanError,
  VPC_SPEC,
  type VpcRecord,
} from "../aws_vpc_inventory_report.ts";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ISO = "2026-06-13T00:00:00.000Z";

function vpc(overrides: Partial<VpcRecord> = {}): VpcRecord {
  return {
    accountId: "111111111111",
    accountName: "prod",
    profile: "prod-readonly",
    region: "eu-west-1",
    vpcId: "vpc-aaa",
    vpcName: "prod-main",
    vpcIsDefault: false,
    ownerAccountId: "111111111111",
    isSharedIn: false,
    cidrBlocks: ["10.0.0.0/16"],
    vpcTags: { Name: "prod-main" },
    scannedAt: ISO,
    ...overrides,
  };
}

function scanError(overrides: Partial<ScanError> = {}): ScanError {
  return {
    profile: "prod-readonly",
    accountId: "111111111111",
    region: "eu-west-1",
    phase: "describe_vpcs",
    kind: "other",
    message: "boom",
    scannedAt: ISO,
    ...overrides,
  };
}

const ENCODER = new TextEncoder();

/** A data-handle plus the bytes the repository should return for it. */
interface Artifact {
  specName: string;
  /** JSON-encoded bytes, or a raw string for malformed-payload tests. */
  payload: unknown | string;
  /** When true, `payload` is treated as a literal (possibly invalid) string. */
  raw?: boolean;
  /** When true, getContent rejects for this handle (storage read failure). */
  failRead?: boolean;
}

function silentLogger() {
  return { info: () => {}, debug: () => {}, warn: () => {}, error: () => {} };
}

/**
 * Build a workflow report context whose single step is an
 * `@jentz/aws-vpc-inventory` step exposing `artifacts`. `getContent` returns
 * the bytes for the matching handle.
 */
function contextFor(
  artifacts: Artifact[],
  opts: { modelType?: string; workflowName?: string } = {},
) {
  const modelType = opts.modelType ?? INVENTORY_MODEL_TYPE;
  const handles = artifacts.map((a, i) => ({
    name: `handle-${i}`,
    version: 1,
    specName: a.specName,
    _payload: a,
  }));
  const bytesByHandle = new Map<string, Uint8Array>();
  const failNames = new Set<string>();
  for (const h of handles) {
    const a = h._payload;
    if (a.failRead) {
      failNames.add(h.name);
      continue;
    }
    const text = a.raw ? (a.payload as string) : JSON.stringify(a.payload);
    bytesByHandle.set(h.name, ENCODER.encode(text));
  }
  return {
    workflowName: opts.workflowName ?? "vpc-workflow",
    logger: silentLogger(),
    stepExecutions: [
      {
        modelType,
        modelId: "vpc-inv-1",
        dataHandles: handles.map((h) => ({
          name: h.name,
          version: h.version,
          specName: h.specName,
        })),
      },
    ],
    dataRepository: {
      getContent: (
        _type: string,
        _id: string,
        name: string,
        _version: number,
      ): Promise<Uint8Array | null> => {
        if (failNames.has(name)) {
          return Promise.reject(new Error("storage read failed"));
        }
        return Promise.resolve(bytesByHandle.get(name) ?? null);
      },
    },
  };
}

// ---------------------------------------------------------------------------
// compareVpcs
// ---------------------------------------------------------------------------

Deno.test("compareVpcs: orders by account, then region, then VPC id", () => {
  const rows = [
    vpc({ accountId: "222", region: "eu-west-1", vpcId: "vpc-z" }),
    vpc({ accountId: "111", region: "eu-west-1", vpcId: "vpc-b" }),
    vpc({ accountId: "111", region: "eu-north-1", vpcId: "vpc-a" }),
    vpc({ accountId: "111", region: "eu-west-1", vpcId: "vpc-a" }),
  ];
  const sorted = [...rows].sort(compareVpcs).map((v) =>
    `${v.accountId}/${v.region}/${v.vpcId}`
  );
  assertEquals(sorted, [
    "111/eu-north-1/vpc-a",
    "111/eu-west-1/vpc-a",
    "111/eu-west-1/vpc-b",
    "222/eu-west-1/vpc-z",
  ]);
});

// ---------------------------------------------------------------------------
// collect — decoding and skip-on-malformed
// ---------------------------------------------------------------------------

Deno.test("collect: decodes vpc and scan_error rows from a matching step", async () => {
  const ctx = contextFor([
    { specName: VPC_SPEC, payload: vpc({ vpcId: "vpc-aaa" }) },
    { specName: VPC_SPEC, payload: vpc({ vpcId: "vpc-bbb" }) },
    { specName: SCAN_ERROR_SPEC, payload: scanError({ kind: "auth_expired" }) },
  ]);
  const out = await collect(ctx);
  assertEquals(out.vpcs.length, 2);
  assertEquals(out.errors.length, 1);
  assertEquals(out.skipped, 0);
});

Deno.test("collect: ignores steps of an unrelated model type", async () => {
  const ctx = contextFor(
    [{ specName: VPC_SPEC, payload: vpc() }],
    { modelType: "@swamp/aws/ec2/vpc" },
  );
  const out = await collect(ctx);
  assertEquals(out.vpcs.length, 0);
  assertEquals(out.errors.length, 0);
  assertEquals(out.skipped, 0);
});

Deno.test("collect: a getContent read failure is counted as skipped, never thrown", async () => {
  const ctx = contextFor([
    { specName: VPC_SPEC, payload: vpc(), failRead: true },
    { specName: VPC_SPEC, payload: vpc({ vpcId: "vpc-ok" }) },
  ]);
  // A storage read that rejects must not abort the whole report — it is
  // counted as one skip and the healthy row is still collected.
  const out = await collect(ctx);
  assertEquals(out.vpcs.length, 1);
  assertEquals(out.skipped, 1);
});

Deno.test("collect: a bad-JSON artifact is counted as skipped, never thrown", async () => {
  const ctx = contextFor([
    { specName: VPC_SPEC, payload: "{ not valid json", raw: true },
    { specName: VPC_SPEC, payload: vpc({ vpcId: "vpc-ok" }) },
  ]);
  const out = await collect(ctx);
  assertEquals(out.vpcs.length, 1);
  assertEquals(out.vpcs[0].vpcId, "vpc-ok");
  assertEquals(out.skipped, 1);
});

Deno.test("collect: a schema-mismatched artifact is counted as skipped, never thrown", async () => {
  const ctx = contextFor([
    // Missing required fields (cidrBlocks, vpcIsDefault, ...) → safeParse fails.
    { specName: VPC_SPEC, payload: { accountId: "111", vpcId: "vpc-bad" } },
    // A scan_error with an invalid kind enum → safeParse fails.
    {
      specName: SCAN_ERROR_SPEC,
      payload: { ...scanError(), kind: "not-a-kind" },
    },
    { specName: VPC_SPEC, payload: vpc({ vpcId: "vpc-good" }) },
  ]);
  const out = await collect(ctx);
  assertEquals(out.vpcs.length, 1);
  assertEquals(out.vpcs[0].vpcId, "vpc-good");
  assertEquals(out.errors.length, 0);
  assertEquals(out.skipped, 2);
});

Deno.test("collect: handles with an unrelated spec name are ignored, not skipped", async () => {
  const ctx = contextFor([
    { specName: "something_else", payload: { whatever: true } },
    { specName: VPC_SPEC, payload: vpc() },
  ]);
  const out = await collect(ctx);
  assertEquals(out.vpcs.length, 1);
  assertEquals(out.skipped, 0);
});

// ---------------------------------------------------------------------------
// renderMarkdown
// ---------------------------------------------------------------------------

Deno.test("renderMarkdown: empty collection renders the header, summary, and an empty table", () => {
  const md = renderMarkdown(
    { vpcs: [], errors: [], skipped: 0 },
    ISO,
    "vpc-workflow",
  );
  assert(md.includes("# AWS VPC Inventory"));
  assert(md.includes("- VPCs inventoried: **0**"));
  assert(md.includes("_None._"));
});

Deno.test("renderMarkdown: table lists VPCs in stable sort order with default/shared markers", () => {
  const collected: Collected = {
    vpcs: [
      vpc({
        accountId: "222222222222",
        vpcId: "vpc-late",
        region: "eu-west-1",
      }),
      vpc({
        accountId: "111111111111",
        vpcId: "vpc-shared",
        region: "eu-west-1",
        isSharedIn: true,
        ownerAccountId: "999999999999",
      }),
      vpc({
        accountId: "111111111111",
        vpcId: "vpc-default",
        region: "eu-west-1",
        vpcIsDefault: true,
      }),
    ],
    errors: [],
    skipped: 0,
  };
  const md = renderMarkdown(collected, ISO, "vpc-workflow");
  assert(md.includes("- Accounts seen: **2**"));
  assert(md.includes("- VPCs inventoried: **3**"));
  assert(md.includes("default VPCs: **1**, shared-in via RAM: **1**"));
  // Shared-in marker points at the owner; default marker shows "yes".
  assert(md.includes("from 999999999999"));
  // Stable sort: account 111... rows precede 222...; within an account vpc id
  // ordering puts vpc-default before vpc-shared.
  const firstIdx = md.indexOf("vpc-default");
  const secondIdx = md.indexOf("vpc-shared");
  const thirdIdx = md.indexOf("vpc-late");
  assert(
    firstIdx < secondIdx && secondIdx < thirdIdx,
    "rows not in sort order",
  );
});

// ---------------------------------------------------------------------------
// coverage-gaps section
// ---------------------------------------------------------------------------

Deno.test("renderMarkdown: auth_expired errors produce the needs-aws-sso-login section", () => {
  const collected: Collected = {
    vpcs: [],
    errors: [
      scanError({
        profile: "acct-a-readonly",
        kind: "auth_expired",
        phase: "credentials",
      }),
      scanError({
        profile: "acct-a-readonly",
        kind: "auth_expired",
        region: "eu-north-1",
      }),
      scanError({ profile: "acct-b-readonly", kind: "auth_expired" }),
    ],
    skipped: 0,
  };
  const md = renderMarkdown(collected, ISO, "vpc-workflow");
  assert(md.includes("Needs `aws sso login`"));
  assert(md.includes("`acct-a-readonly` — 2 region(s) unassessed"));
  assert(md.includes("`acct-b-readonly` — 1 region(s) unassessed"));
  // Counts the unique accounts touched by errors even with no VPCs.
  assert(md.includes("region(s) need `aws sso login`"));
});

Deno.test("renderMarkdown: access_denied errors produce the blocked-by-SCP/IAM section", () => {
  const collected: Collected = {
    vpcs: [],
    errors: [
      scanError({ kind: "access_denied", region: "ap-south-1" }),
      scanError({ kind: "access_denied", region: "sa-east-1" }),
    ],
    skipped: 0,
  };
  const md = renderMarkdown(collected, ISO, "vpc-workflow");
  assert(md.includes("Blocked by SCP/IAM"));
  assert(md.includes("`ap-south-1`"));
  assert(md.includes("`sa-east-1`"));
});

Deno.test("renderMarkdown: 'other' errors surface in the summary count line", () => {
  const collected: Collected = {
    vpcs: [],
    errors: [scanError({ kind: "other" }), scanError({ kind: "other" })],
    skipped: 0,
  };
  const md = renderMarkdown(collected, ISO, "vpc-workflow");
  assert(md.includes("**2** other error(s)"));
});

// ---------------------------------------------------------------------------
// report.execute — JSON payload
// ---------------------------------------------------------------------------

Deno.test("report.execute: JSON payload carries structured vpcs[] rows in sort order", async () => {
  const ctx = contextFor([
    { specName: VPC_SPEC, payload: vpc({ accountId: "222", vpcId: "vpc-z" }) },
    { specName: VPC_SPEC, payload: vpc({ accountId: "111", vpcId: "vpc-a" }) },
    {
      specName: VPC_SPEC,
      payload: vpc({
        accountId: "111",
        vpcId: "vpc-shared",
        isSharedIn: true,
        ownerAccountId: "999",
      }),
    },
    {
      specName: VPC_SPEC,
      payload: vpc({
        accountId: "111",
        vpcId: "vpc-default",
        vpcIsDefault: true,
      }),
    },
  ]);
  const out = await report.execute(ctx);

  assertEquals(out.json.report, "@jentz/aws-vpc-inventory-report");
  assertEquals(out.json.workflow, "vpc-workflow");
  assertEquals(out.json.vpcCount, 4);
  assertEquals(out.json.accountCount, 2);
  assertEquals(out.json.regionCount, 1);
  assertEquals(out.json.defaultVpcCount, 1);
  assertEquals(out.json.sharedVpcCount, 1);
  assertEquals(out.json.skipped, 0);
  assertEquals(out.json.degraded, false);

  // The structured rows array mirrors the model's VPC fields one-per-VPC, in
  // the same stable compareVpcs order as the markdown table.
  assertEquals(out.json.vpcs.length, 4);
  assertEquals(
    out.json.vpcs.map((v) => `${v.accountId}/${v.vpcId}`),
    ["111/vpc-a", "111/vpc-default", "111/vpc-shared", "222/vpc-z"],
  );
  // Each row object carries the model's row fields.
  const first = out.json.vpcs[0];
  assertExists(first.cidrBlocks);
  assertExists(first.vpcTags);
  assertEquals(typeof first.vpcIsDefault, "boolean");
  assertEquals(typeof first.isSharedIn, "boolean");
});

Deno.test("report.execute: JSON payload breaks errors down by kind and counts skipped", async () => {
  const ctx = contextFor([
    { specName: SCAN_ERROR_SPEC, payload: scanError({ kind: "auth_expired" }) },
    {
      specName: SCAN_ERROR_SPEC,
      payload: scanError({ kind: "access_denied" }),
    },
    {
      specName: SCAN_ERROR_SPEC,
      payload: scanError({ kind: "access_denied" }),
    },
    { specName: SCAN_ERROR_SPEC, payload: scanError({ kind: "other" }) },
    // A malformed artifact bumps skipped.
    { specName: VPC_SPEC, payload: "not json", raw: true },
  ]);
  const out = await report.execute(ctx);
  assertEquals(out.json.errorsByKind, {
    auth_expired: 1,
    access_denied: 2,
    other: 1,
  });
  assertEquals(out.json.skipped, 1);
  assertEquals(out.json.vpcCount, 0);
});

Deno.test("report.execute: never throws on an empty context and reports degraded=false", async () => {
  const out = await report.execute({
    workflowName: "empty",
    stepExecutions: [],
    logger: silentLogger(),
    dataRepository: {
      getContent: (): Promise<Uint8Array | null> => Promise.resolve(null),
    },
  });
  assertExists(out.markdown);
  assertEquals(out.json.vpcs.length, 0);
  assertEquals(out.json.degraded, false);
});

Deno.test("report.execute: an unexpected collection failure degrades to a valid report", async () => {
  // A context whose stepExecutions getter throws forces the outer guard.
  const ctx = {
    workflowName: "boom-workflow",
    logger: silentLogger(),
    get stepExecutions(): unknown[] {
      throw new Error("stepExecutions exploded");
    },
    dataRepository: {
      getContent: (): Promise<Uint8Array | null> => Promise.resolve(null),
    },
  };
  const out = await report.execute(ctx);
  assertEquals(out.json.degraded, true);
  assertEquals(out.json.vpcs.length, 0);
  assert(out.markdown.includes("degraded"));
});

Deno.test("report.execute: JSON payload carries NO csv or columns keys", async () => {
  const ctx = contextFor([
    { specName: VPC_SPEC, payload: vpc() },
  ]);
  const out = await report.execute(ctx);
  const keys = Object.keys(out.json);
  assertFalse(keys.includes("csv"), "JSON payload must not carry a csv key");
  assertFalse(
    keys.includes("columns"),
    "JSON payload must not carry a columns key",
  );
  // And the markdown body must not contain a CSV recipe or header line.
  assertFalse(out.markdown.includes("jq -r .csv"));
});
