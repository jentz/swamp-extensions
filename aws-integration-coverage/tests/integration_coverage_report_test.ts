/**
 * Report collect+render tests for `@jentz/integration-coverage`.
 *
 * Exercises:
 *   - `collect` walking a mocked `stepExecutions`: correct modelType filtering
 *     (StackSet/IAM steps in, unrelated steps out), spec routing, and skip
 *     counting for undecodable / schema-mismatched artifacts;
 *   - `renderMarkdown` section presence (per-role table, by-mechanism table,
 *     lens-disagreements section, per-account matrix);
 *   - the report's never-throws degraded path (degraded:true + stub markdown);
 *   - the JSON payload counts and the contract that there is NO `csv` key.
 *
 * Account ids are clearly-fictional placeholders.
 *
 * @module
 */

import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";

import {
  collect,
  renderMarkdown,
  report,
} from "../integration_coverage_report.ts";
import { coalesce } from "../_lib/coverage.ts";

const ACCT_A = "ACCT_ALPHA";
const ACCT_B = "ACCT_BETA";
const STACKSET = "acme-ss";
const STACKSET_TYPE = "@jentz/aws-stackset-audit";
const IAM_TYPE = "@jentz/aws-iam-role-audit";

const enc = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));

interface StubHandle {
  name: string;
  version: number;
  specName: string;
  json: unknown;
  /** When true, getContent returns null for this handle (undecodable). */
  noBytes?: boolean;
  /** When true, getContent rejects for this handle (storage read failure). */
  failRead?: boolean;
}

interface StubStep {
  modelType: string;
  modelId: string;
  handles: StubHandle[];
}

/** Build a collect()-compatible context from steps. */
function stubContext(steps: StubStep[], workflowName = "wf"): unknown {
  const byKey = new Map<string, Uint8Array>();
  const failKeys = new Set<string>();
  for (const s of steps) {
    for (const h of s.handles) {
      const key = `${s.modelId}/${h.name}/${h.version}`;
      if (h.failRead) failKeys.add(key);
      else if (!h.noBytes) byKey.set(key, enc(h.json));
    }
  }
  return {
    workflowName,
    logger: {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: () => {},
    },
    stepExecutions: steps.map((s) => ({
      modelType: s.modelType,
      modelId: s.modelId,
      dataHandles: s.handles.map((h) => ({
        name: h.name,
        version: h.version,
        metadata: { tags: { specName: h.specName } },
      })),
    })),
    dataRepository: {
      getContent: (
        _modelType: string,
        modelId: string,
        name: string,
        version: number,
      ): Promise<Uint8Array | null> => {
        const key = `${modelId}/${name}/${version}`;
        if (failKeys.has(key)) {
          return Promise.reject(new Error("storage read failed"));
        }
        return Promise.resolve(byKey.get(key) ?? null);
      },
    },
  };
}

function instanceJson(account: string, overallStatus: string) {
  return {
    stackSetName: STACKSET,
    account,
    region: "us-east-1",
    overallStatus,
    detailedStatus: "",
    failureCategory: "",
  };
}

function roleJson(
  accountId: string,
  roleName: string,
  exists: boolean,
  compliant: boolean,
) {
  return {
    accountId,
    accountName: accountId === ACCT_A ? "alpha" : "beta",
    profile: `${accountId}-readonly`,
    roleName,
    required: true,
    exists,
    managementMechanism: "cfn-stackset",
    cfnStackName: `StackSet-${STACKSET}-x`,
    cfnStackRegion: "us-east-1",
    compliant,
    findings: [],
    attachedManagedPolicyArns: [],
    createDate: "",
  };
}

// ---------------------------------------------------------------------------
// collect — modelType filtering + skip counting
// ---------------------------------------------------------------------------

Deno.test("collect: filters by modelType, routes by spec, ignores unrelated steps", async () => {
  const ctx = stubContext([
    {
      modelType: STACKSET_TYPE,
      modelId: "ss-1",
      handles: [
        {
          name: "summary",
          version: 1,
          specName: "summary",
          json: {
            stackSetName: STACKSET,
            accountsTargeted: 1,
            instanceCount: 1,
          },
        },
        {
          name: "inst-a",
          version: 1,
          specName: "instance",
          json: instanceJson(ACCT_A, "CURRENT"),
        },
      ],
    },
    {
      modelType: IAM_TYPE,
      modelId: "iam-1",
      handles: [
        {
          name: "role-a",
          version: 1,
          specName: "role",
          json: roleJson(ACCT_A, "Readonly", true, true),
        },
        {
          name: "err-a",
          version: 1,
          specName: "scan_error",
          json: {
            profile: "p",
            accountId: "",
            roleName: "",
            kind: "auth_expired",
            message: "x",
          },
        },
      ],
    },
    {
      // An unrelated step: must be ignored entirely.
      modelType: "@swamp/aws/s3/bucket",
      modelId: "s3-1",
      handles: [
        { name: "b", version: 1, specName: "bucket", json: { whatever: true } },
      ],
    },
  ]);

  const c = await collect(ctx);
  assertEquals(c.instances.length, 1);
  assertEquals(c.summaries.length, 1);
  assertEquals(c.roles.length, 1);
  assertEquals(c.iamErrors.length, 1);
  assertEquals(c.skipped, 0);
});

Deno.test("collect: undecodable bytes and schema-mismatched rows are counted as skipped", async () => {
  const ctx = stubContext([
    {
      modelType: STACKSET_TYPE,
      modelId: "ss-1",
      handles: [
        // null bytes => skipped
        {
          name: "inst-null",
          version: 1,
          specName: "instance",
          json: {},
          noBytes: true,
        },
        // schema-invalid instance (missing required `account`) => skipped
        {
          name: "inst-bad",
          version: 1,
          specName: "instance",
          json: { stackSetName: STACKSET },
        },
        // good
        {
          name: "inst-ok",
          version: 1,
          specName: "instance",
          json: instanceJson(ACCT_A, "CURRENT"),
        },
      ],
    },
    {
      modelType: IAM_TYPE,
      modelId: "iam-1",
      // a handle with no specName tag at all is silently skipped (not counted).
      handles: [
        {
          name: "role-ok",
          version: 1,
          specName: "role",
          json: roleJson(ACCT_A, "Readonly", true, true),
        },
      ],
    },
  ]);

  const c = await collect(ctx);
  assertEquals(c.instances.length, 1);
  assertEquals(c.roles.length, 1);
  // null-bytes + schema-invalid instance.
  assertEquals(c.skipped, 2);
});

Deno.test("collect: a getContent read failure is a per-handle skip, not a whole-report throw", async () => {
  const ctx = stubContext([
    {
      modelType: STACKSET_TYPE,
      modelId: "ss-1",
      handles: [
        // one handle whose stored bytes fail to read (storage error)
        {
          name: "instance-fail",
          version: 1,
          specName: "instance",
          json: {},
          failRead: true,
        },
        // a healthy instance alongside it
        {
          name: "instance-ok",
          version: 1,
          specName: "instance",
          json: instanceJson(ACCT_B, "CURRENT"),
        },
      ],
    },
  ]);
  // collect must NOT throw on a read failure; the bad read is counted as one
  // skip and the healthy row is still collected.
  const c = await collect(ctx);
  assertEquals(c.skipped, 1);
  assertEquals(c.instances.length, 1);
});

Deno.test("collect: warns when steps exist but none match the upstream audit types", async () => {
  const warns: string[] = [];
  const ctx = {
    workflowName: "wf",
    logger: {
      info: () => {},
      warn: (m: string) => warns.push(m),
      debug: () => {},
      error: () => {},
    },
    stepExecutions: [
      { modelType: "@other/unrelated", modelId: "x", dataHandles: [] },
    ],
    dataRepository: { getContent: () => Promise.resolve(null) },
  };
  const c = await collect(ctx);
  assertEquals(c.instances.length, 0);
  // A miswired workflow (steps present, none matched) is flagged, not silent.
  assert(warns.some((m) => m.includes("No step matched")));
});

// ---------------------------------------------------------------------------
// renderMarkdown — section presence
// ---------------------------------------------------------------------------

Deno.test("renderMarkdown: contains per-role, by-mechanism, lens-disagreements, and per-account matrix", () => {
  const c = {
    instances: [
      instanceJson(ACCT_A, "CURRENT"),
      instanceJson(ACCT_B, "CURRENT"),
    ].map((j) => ({
      ...j,
    })) as never,
    summaries: [{
      stackSetName: STACKSET,
      accountsTargeted: 2,
      instanceCount: 2,
    }] as never,
    roles: [
      // ACCT_A consistent compliant
      roleJson(ACCT_A, "Readonly", true, true),
      // ACCT_B: stackset CURRENT but the required role missing => disagreement
      { ...roleJson(ACCT_B, "Readonly", false, false), required: true },
    ] as never,
    iamErrors: [] as never,
    skipped: 1,
  };
  const res = coalesce(c);
  const md = renderMarkdown(res, c, "2026-06-13T00:00:00.000Z", "wf");

  assertStringIncludes(md, "## Coverage (per account, over required roles)");
  assertStringIncludes(md, "### Per role (across accounts in the IAM sweep)");
  assertStringIncludes(
    md,
    "| Role | Required | Present | Compliant | Missing |",
  );
  assertStringIncludes(md, "### Account coverage, by mechanism");
  assertStringIncludes(md, "## ⚠️ Lens disagreements");
  assertStringIncludes(md, "## Per-account matrix");
  // skipped footnote present
  assertStringIncludes(md, "1 upstream artifact(s) skipped");
});

Deno.test("renderMarkdown: unresolved-profile remediation matches the scan_error kind", () => {
  // Profiles with no accountId become unresolvedProfiles, carrying the upstream
  // IAM scan_error kind. The remediation hint must follow the kind, not always
  // tell the operator to re-login.
  const c = {
    instances: [] as never,
    summaries: [] as never,
    roles: [] as never,
    iamErrors: [
      { profile: "p-expired", kind: "auth_expired" },
      { profile: "p-denied", kind: "access_denied" },
      { profile: "p-other", kind: "weird" },
    ] as never,
    skipped: 0,
  };
  const md = renderMarkdown(
    coalesce(c),
    c,
    "2026-06-13T00:00:00.000Z",
    "wf",
  );
  assertStringIncludes(md, "`p-expired` — auth_expired (run `aws sso login`)");
  assertStringIncludes(
    md,
    "`p-denied` — access_denied (check the role's IAM permissions / SCPs)",
  );
  assertStringIncludes(
    md,
    "`p-other` — weird (investigate the upstream scan error)",
  );
});

// ---------------------------------------------------------------------------
// report.execute — JSON payload + degraded path
// ---------------------------------------------------------------------------

Deno.test("report.execute: emits markdown + json only (no csv) with correct counts", async () => {
  const ctx = stubContext([
    {
      modelType: STACKSET_TYPE,
      modelId: "ss-1",
      handles: [
        {
          name: "inst-a",
          version: 1,
          specName: "instance",
          json: instanceJson(ACCT_A, "CURRENT"),
        },
        {
          name: "inst-b",
          version: 1,
          specName: "instance",
          json: instanceJson(ACCT_B, "CURRENT"),
        },
      ],
    },
    {
      modelType: IAM_TYPE,
      modelId: "iam-1",
      handles: [
        {
          name: "role-a",
          version: 1,
          specName: "role",
          json: roleJson(ACCT_A, "Readonly", true, true),
        },
        // ACCT_B missing required role while CURRENT => discrepancy
        {
          name: "role-b",
          version: 1,
          specName: "role",
          json: roleJson(ACCT_B, "Readonly", false, false),
        },
      ],
    },
  ]);

  const out = await report.execute(ctx);

  // {markdown, json} ONLY — no csv key on the output or in the json payload.
  assertEquals(Object.keys(out).sort(), ["json", "markdown"]);
  assert(!("csv" in out));
  assert(!("csv" in (out.json as unknown as Record<string, unknown>)));

  const json = out.json;
  assertEquals(json.report, "@jentz/integration-coverage");
  assertEquals(json.workflow, "wf");
  assertEquals(json.degraded, false);
  assertEquals(json.accounts.length, 2);
  assertEquals(json.stackSetName, STACKSET);
  // ACCT_B is a discrepancy (CURRENT + missing required role).
  assertEquals(json.discrepancies.map((r) => r.accountId), [ACCT_B]);
  assert(json.byCoverage["covered-compliant"] >= 1);
});

Deno.test("report.execute: never throws — a collect failure yields a degraded report", async () => {
  // A context whose stepExecutions getter throws drives the outer guard.
  const exploding = {
    workflowName: "wf",
    logger: {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: () => {},
    },
    get stepExecutions(): never {
      throw new Error("boom: storage unavailable");
    },
    dataRepository: { getContent: () => Promise.resolve(null) },
  };

  const out = await report.execute(exploding);
  assertEquals(out.json.degraded, true);
  assertStringIncludes(out.markdown, "Report degraded");
  assertStringIncludes(out.markdown, "boom: storage unavailable");
  // Degraded payload is still structurally valid.
  assertEquals(out.json.accounts.length, 0);
  assert(!("csv" in (out.json as unknown as Record<string, unknown>)));
});
