/**
 * Unit tests for `@jentz/aws-default-sg-audit-report`.
 *
 * Four layers:
 *
 *   1. Collection / decoding — `collect` walks `context.stepExecutions`,
 *      matches the upstream model type, and decodes `finding` / `scan_error`
 *      artifacts. Malformed (bad-JSON) and schema-mismatched artifacts are
 *      counted into `skipped`, never thrown.
 *   2. Verdict bucketing + markdown rendering — `renderMarkdown` splits
 *      findings into the safe-to-strip / in-use / compliant groups, renders the
 *      two action tables in stable sort order, and surfaces the coverage gaps.
 *   3. The coverage-gaps section — auth_expired → needs-aws-sso-login,
 *      access_denied → blocked-by-SCP/IAM.
 *   4. The JSON payload — `report.execute` carries findingCount, byVerdict,
 *      errorsByKind, the skipped count, and the `degraded` flag — and NO
 *      `csv` / `columns` keys.
 *
 * @module
 */

import {
  assert,
  assertEquals,
  assertExists,
  assertFalse,
} from "jsr:@std/assert@1";

import {
  AUDIT_MODEL_TYPE,
  collect,
  type Collected,
  compareFindings,
  type Finding,
  FINDING_SPEC,
  renderMarkdown,
  report,
  SCAN_ERROR_SPEC,
  type ScanError,
} from "../aws_default_sg_audit_report.ts";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ISO = "2026-06-13T00:00:00.000Z";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    accountId: "111111111111",
    profile: "prod-readonly",
    region: "eu-west-1",
    vpcId: "vpc-aaa",
    vpcName: "prod-main",
    vpcIsDefault: false,
    defaultSgId: "sg-aaa",
    ingressRuleCount: 1,
    egressRuleCount: 1,
    compliant: false,
    eniCount: 0,
    enis: [],
    verdict: "safe_to_remediate",
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
    phase: "describe_security_groups",
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
 * `@jentz/aws-default-sg-audit` step exposing `dataHandles`. `getContent`
 * returns the bytes for the matching handle.
 */
function contextFor(
  artifacts: Artifact[],
  opts: { modelType?: string; workflowName?: string } = {},
) {
  const modelType = opts.modelType ?? AUDIT_MODEL_TYPE;
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
    workflowName: opts.workflowName ?? "sg-workflow",
    logger: silentLogger(),
    stepExecutions: [
      {
        modelType,
        modelId: "default-sg-1",
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
// compareFindings — verdict-severity-first ordering
// ---------------------------------------------------------------------------

Deno.test("compareFindings: in-use first, then safe, then compliant; ties by account/region/sg", () => {
  const rows = [
    finding({ verdict: "compliant", defaultSgId: "sg-c" }),
    finding({ verdict: "safe_to_remediate", defaultSgId: "sg-s" }),
    finding({ verdict: "in_use_needs_migration", defaultSgId: "sg-i" }),
    finding({
      verdict: "in_use_needs_migration",
      accountId: "222222222222",
      defaultSgId: "sg-i2",
    }),
  ];
  const sorted = [...rows].sort(compareFindings).map((f) =>
    `${f.verdict}/${f.accountId}/${f.defaultSgId}`
  );
  assertEquals(sorted, [
    "in_use_needs_migration/111111111111/sg-i",
    "in_use_needs_migration/222222222222/sg-i2",
    "safe_to_remediate/111111111111/sg-s",
    "compliant/111111111111/sg-c",
  ]);
});

// ---------------------------------------------------------------------------
// collect — decoding and skip-on-malformed
// ---------------------------------------------------------------------------

Deno.test("collect: decodes finding and scan_error rows from a matching step", async () => {
  const ctx = contextFor([
    { specName: FINDING_SPEC, payload: finding({ defaultSgId: "sg-aaa" }) },
    { specName: FINDING_SPEC, payload: finding({ defaultSgId: "sg-bbb" }) },
    { specName: SCAN_ERROR_SPEC, payload: scanError({ kind: "auth_expired" }) },
  ]);
  const out = await collect(ctx);
  assertEquals(out.findings.length, 2);
  assertEquals(out.errors.length, 1);
  assertEquals(out.skipped, 0);
});

Deno.test("collect: ignores steps of an unrelated model type", async () => {
  const ctx = contextFor(
    [{ specName: FINDING_SPEC, payload: finding() }],
    { modelType: "@swamp/aws/ec2/security-group" },
  );
  const out = await collect(ctx);
  assertEquals(out.findings.length, 0);
  assertEquals(out.errors.length, 0);
  assertEquals(out.skipped, 0);
});

Deno.test("collect: a getContent read failure is counted as skipped, never thrown", async () => {
  const ctx = contextFor([
    { specName: FINDING_SPEC, payload: finding(), failRead: true },
    { specName: FINDING_SPEC, payload: finding({ defaultSgId: "sg-ok" }) },
  ]);
  // A storage read that rejects must not abort the whole report — it is
  // counted as one skip and the healthy row is still collected.
  const out = await collect(ctx);
  assertEquals(out.findings.length, 1);
  assertEquals(out.findings[0].defaultSgId, "sg-ok");
  assertEquals(out.skipped, 1);
});

Deno.test("collect: a bad-JSON artifact is counted as skipped, never thrown", async () => {
  const ctx = contextFor([
    { specName: FINDING_SPEC, payload: "{ not valid json", raw: true },
    { specName: FINDING_SPEC, payload: finding({ defaultSgId: "sg-ok" }) },
  ]);
  const out = await collect(ctx);
  assertEquals(out.findings.length, 1);
  assertEquals(out.findings[0].defaultSgId, "sg-ok");
  assertEquals(out.skipped, 1);
});

Deno.test("collect: a schema-drifted artifact is skipped-counted, never thrown", async () => {
  const ctx = contextFor([
    // Missing required fields (enis, verdict, ...) → safeParse fails.
    { specName: FINDING_SPEC, payload: { accountId: "111", vpcId: "vpc-bad" } },
    // A scan_error with an invalid kind enum → safeParse fails.
    {
      specName: SCAN_ERROR_SPEC,
      payload: { ...scanError(), kind: "not-a-kind" },
    },
    { specName: FINDING_SPEC, payload: finding({ defaultSgId: "sg-good" }) },
  ]);
  const out = await collect(ctx);
  assertEquals(out.findings.length, 1);
  assertEquals(out.findings[0].defaultSgId, "sg-good");
  assertEquals(out.errors.length, 0);
  assertEquals(out.skipped, 2);
});

Deno.test("collect: handles with an unrelated spec name are ignored, not skipped", async () => {
  const ctx = contextFor([
    { specName: "something_else", payload: { whatever: true } },
    { specName: FINDING_SPEC, payload: finding() },
  ]);
  const out = await collect(ctx);
  assertEquals(out.findings.length, 1);
  assertEquals(out.skipped, 0);
});

// ---------------------------------------------------------------------------
// renderMarkdown — verdict bucketing + representative finding
// ---------------------------------------------------------------------------

Deno.test("renderMarkdown: empty collection renders the header, summary, and empty tables", () => {
  const md = renderMarkdown(
    { findings: [], errors: [], skipped: 0 },
    ISO,
    "sg-workflow",
  );
  assert(md.includes("# EC2.2 — Default Security Group Audit"));
  assert(md.includes("- Default SGs audited: **0**"));
  assert(md.includes("Safe to remediate now"));
  assert(md.includes("In use — migrate workload first"));
  assert(md.includes("_None._"));
});

Deno.test("renderMarkdown: buckets findings into safe / in-use tables and counts compliant", () => {
  const collected: Collected = {
    findings: [
      finding({
        defaultSgId: "sg-safe",
        verdict: "safe_to_remediate",
        eniCount: 0,
        enis: [],
        vpcName: "safe-vpc",
      }),
      finding({
        defaultSgId: "sg-inuse",
        verdict: "in_use_needs_migration",
        eniCount: 1,
        vpcName: "redis-vpc",
        vpcTags: { Name: "redis-vpc", team: "fullstack", Owner: "alice" },
        enis: [{
          id: "eni-1",
          interfaceType: "interface",
          description: "redis",
          requesterId: "amazon-elasticache",
          requesterManaged: true,
          category: "amazon-elasticache",
          attachedInstanceId: "",
        }],
      }),
      finding({
        defaultSgId: "sg-clean",
        verdict: "compliant",
        compliant: true,
        ingressRuleCount: 0,
        egressRuleCount: 0,
      }),
    ],
    errors: [],
    skipped: 0,
  };
  const md = renderMarkdown(collected, ISO, "sg-workflow");

  assert(md.includes("- Default SGs audited: **3**"));
  assert(md.includes("needs migration: **1**"));
  assert(md.includes("safe to strip now: ") && md.includes("**1**"));
  assert(md.includes("already compliant: **1**"));

  // The in-use SG renders with its owner/team and the elasticache ENI category.
  assert(md.includes("sg-inuse"));
  assert(md.includes("redis-vpc"));
  assert(md.includes("alice"));
  assert(md.includes("fullstack"));
  assert(md.includes("amazon-elasticache"));

  // The safe SG appears under the safe-to-remediate table, which precedes the
  // in-use table in the document.
  const safeHeaderIdx = md.indexOf("Safe to remediate now");
  const inUseHeaderIdx = md.indexOf("In use — migrate workload first");
  const safeRowIdx = md.indexOf("sg-safe");
  const inUseRowIdx = md.indexOf("sg-inuse");
  assert(safeHeaderIdx < inUseHeaderIdx, "safe table should precede in-use");
  assert(
    safeHeaderIdx < safeRowIdx && safeRowIdx < inUseHeaderIdx,
    "the zero-ENI SG belongs in the safe table",
  );
  assert(
    inUseHeaderIdx < inUseRowIdx,
    "the ENI SG belongs in the in-use table",
  );
});

// ---------------------------------------------------------------------------
// coverage-gaps section
// ---------------------------------------------------------------------------

Deno.test("renderMarkdown: auth_expired errors produce the needs-aws-sso-login section", () => {
  const collected: Collected = {
    findings: [],
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
  const md = renderMarkdown(collected, ISO, "sg-workflow");
  assert(md.includes("Needs `aws sso login`"));
  assert(md.includes("`acct-a-readonly` — 2 region(s) unassessed"));
  assert(md.includes("`acct-b-readonly` — 1 region(s) unassessed"));
  assert(md.includes("region(s) need `aws sso login`"));
});

Deno.test("renderMarkdown: access_denied errors produce the blocked-by-SCP/IAM section", () => {
  const collected: Collected = {
    findings: [],
    errors: [
      scanError({ kind: "access_denied", region: "ap-south-1" }),
      scanError({ kind: "access_denied", region: "sa-east-1" }),
    ],
    skipped: 0,
  };
  const md = renderMarkdown(collected, ISO, "sg-workflow");
  assert(md.includes("Blocked by SCP/IAM"));
  assert(md.includes("`ap-south-1`"));
  assert(md.includes("`sa-east-1`"));
});

Deno.test("renderMarkdown: 'other' errors surface in the summary count line", () => {
  const collected: Collected = {
    findings: [],
    errors: [scanError({ kind: "other" }), scanError({ kind: "other" })],
    skipped: 0,
  };
  const md = renderMarkdown(collected, ISO, "sg-workflow");
  assert(md.includes("**2** other error(s)"));
});

// ---------------------------------------------------------------------------
// report.execute — JSON payload
// ---------------------------------------------------------------------------

Deno.test("report.execute: JSON payload carries findingCount and byVerdict counts", async () => {
  const ctx = contextFor([
    { specName: FINDING_SPEC, payload: finding({ verdict: "compliant" }) },
    {
      specName: FINDING_SPEC,
      payload: finding({ verdict: "safe_to_remediate" }),
    },
    {
      specName: FINDING_SPEC,
      payload: finding({ verdict: "in_use_needs_migration", eniCount: 2 }),
    },
    {
      specName: FINDING_SPEC,
      payload: finding({ verdict: "in_use_needs_migration", eniCount: 1 }),
    },
  ]);
  const out = await report.execute(ctx);

  assertEquals(out.json.report, "@jentz/aws-default-sg-audit-report");
  assertEquals(out.json.workflow, "sg-workflow");
  assertEquals(out.json.findingCount, 4);
  assertEquals(out.json.byVerdict, {
    compliant: 1,
    safe_to_remediate: 1,
    in_use_needs_migration: 2,
  });
  assertEquals(out.json.skipped, 0);
  assertEquals(out.json.degraded, false);
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
    { specName: FINDING_SPEC, payload: "not json", raw: true },
  ]);
  const out = await report.execute(ctx);
  assertEquals(out.json.errorsByKind, {
    auth_expired: 1,
    access_denied: 2,
    other: 1,
  });
  assertEquals(out.json.skipped, 1);
  assertEquals(out.json.findingCount, 0);
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
  assertEquals(out.json.findingCount, 0);
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
  assertEquals(out.json.findingCount, 0);
  assert(out.markdown.includes("degraded"));
});

Deno.test("report.execute: JSON payload carries NO csv or columns keys", async () => {
  const ctx = contextFor([
    { specName: FINDING_SPEC, payload: finding() },
  ]);
  const out = await report.execute(ctx);
  const keys = Object.keys(out.json);
  assertFalse(keys.includes("csv"), "JSON payload must not carry a csv key");
  assertFalse(
    keys.includes("columns"),
    "JSON payload must not carry a columns key",
  );
  // And the markdown body must not contain a CSV recipe.
  assertFalse(out.markdown.includes("jq -r .csv"));
});
