/**
 * Producer↔consumer schema-agreement and rendering tests for
 * `@jentz/aws-rds-reservation-coverage`.
 *
 * Two surfaces that the existing unit suite does not cover:
 *
 *   A. **Schema drift tripwire.** The report hand-mirrors the producer model's
 *      public shapes into private Zod schemas (`InstanceRecordSchema`, …). If
 *      the producer (`@jentz/aws-rds-reservations`) renames or retypes a field,
 *      every artifact would `safeParse`-fail and the report silently empties out
 *      (only a logged warning). These tests build fixtures **typed as the
 *      producer's exported interfaces**, then push them through the report's
 *      real `collect()` via a stub context. A producer rename breaks compilation
 *      (the type-level tripwire); a producer retype that still compiles but the
 *      consumer schema rejects shows up as `skipped > 0` (the runtime tripwire).
 *
 *   B. **CSV / markdown escaping.** `csvField`, `renderCsv`, and `renderMarkdown`
 *      had zero direct coverage. These exercise RFC4180 quoting, the always-present
 *      CSV header + trailing newline, and the markdown rendering path including
 *      `|` escaping inside table cells.
 *
 * @module
 */

import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";

import {
  ACCOUNT_COLUMNS,
  type AccountBucket,
  aggregate,
  type Bucket,
  collect,
  type Collected,
  COLUMNS,
  countAccountsRegions,
  csvField,
  gapLargeEq,
  INSTANCE_SPEC,
  type InstanceRecord,
  renderCsv,
  renderCsvByAccount,
  renderMarkdown,
  report,
  RESERVATIONS_MODEL_TYPE,
  RESERVED_SPEC,
  rollupByPool,
  SCAN_ERROR_SPEC,
} from "../aws_rds_reservation_coverage.ts";

// The producer's PUBLIC shapes. Importing them as the fixture types makes a
// producer-side rename/retype a COMPILE error here — the drift tripwire.
import type {
  InstanceRecord as ModelInstanceRecord,
  ReservedRecord as ModelReservedRecord,
  ScanError as ModelScanError,
} from "../../aws-rds-reservations/aws_rds_reservations.ts";

// ---------------------------------------------------------------------------
// Fake account identifiers. `accountId` is an opaque `z.string()`, so these
// named placeholders stand in for 12-digit account-id-shaped literals in the
// fixtures. The one test that asserts an exact CSV byte string keeps a
// documented numeric literal inline, because the numeric (comma-free) cell is
// the very thing under test there.
// ---------------------------------------------------------------------------

const ACCOUNT_ALPHA = "ACCT_ALPHA";
const ACCOUNT_BETA = "ACCT_BETA";
const ACCOUNT_GAMMA = "ACCT_GAMMA";
const ACCOUNT_EPSILON = "ACCT_EPSILON";
const ACCOUNT_ZETA = "ACCT_ZETA";
const ACCOUNT_OMEGA = "ACCT_OMEGA";

// ---------------------------------------------------------------------------
// Stub context that mirrors what collect() reads:
//   context.stepExecutions[].modelType / .modelId / .dataHandles[]
//   handle.metadata.tags.specName, handle.name, handle.version
//   context.dataRepository.getContent(modelType, modelId, name, version) -> bytes
//   context.logger
// ---------------------------------------------------------------------------

interface StubHandle {
  name: string;
  version: number;
  specName: string;
  /** Raw JSON the repository should return for this handle. */
  json: unknown;
  /**
   * When set, getContent REJECTS for this handle instead of returning bytes —
   * simulating a transient storage error or one corrupt/missing blob.
   */
  rejectWith?: Error;
}

const enc = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));

/**
 * Build a collect()-compatible context with a single step of
 * RESERVATIONS_MODEL_TYPE whose data handles each carry a `specName` tag.
 * getContent looks the bytes up by handle name.
 */
function stubContext(handles: StubHandle[]): {
  context: unknown;
  logs: Array<{ level: string; message: string }>;
} {
  const logs: Array<{ level: string; message: string }> = [];
  const log = (level: string) => (message: string) =>
    logs.push({ level, message });

  const byName = new Map<string, Uint8Array>(
    handles.filter((h) => !h.rejectWith).map((h) => [h.name, enc(h.json)]),
  );
  const rejectByName = new Map<string, Error>(
    handles.filter((h) => h.rejectWith).map((h) => [h.name, h.rejectWith!]),
  );

  const context = {
    logger: {
      info: log("info"),
      debug: log("debug"),
      warn: log("warn"),
      error: log("error"),
    },
    stepExecutions: [
      {
        modelType: RESERVATIONS_MODEL_TYPE,
        modelId: "step-1",
        dataHandles: handles.map((h) => ({
          name: h.name,
          version: h.version,
          metadata: { tags: { specName: h.specName } },
        })),
      },
    ],
    dataRepository: {
      getContent: (
        _modelType: string,
        _modelId: string,
        name: string,
        _version: number,
      ): Promise<Uint8Array | null> => {
        const err = rejectByName.get(name);
        if (err) return Promise.reject(err);
        return Promise.resolve(byName.get(name) ?? null);
      },
    },
  };

  return { context, logs };
}

// Representative fixtures TYPED AS THE PRODUCER INTERFACES. A producer rename
// (e.g. multiAZ -> multiAz) makes these object literals fail to compile.
const instanceFixture: ModelInstanceRecord = {
  accountId: ACCOUNT_ALPHA,
  accountName: "prod",
  profile: "prod-readonly",
  region: "us-east-1",
  dbInstanceIdentifier: "orders-db",
  dbInstanceClass: "db.r7g.2xlarge",
  engine: "postgres",
  engineVersion: "16.3",
  licenseModel: "postgresql-license",
  multiAZ: true,
  status: "available",
  clusterId: "orders-cluster",
  storageType: "aurora",
  instanceTags: { Name: "orders", env: "prod" },
  scannedAt: "2026-06-05T00:00:00.000Z",
};

const reservedFixture: ModelReservedRecord = {
  accountId: ACCOUNT_ALPHA,
  accountName: "prod",
  profile: "prod-readonly",
  region: "us-east-1",
  reservedDBInstanceId: "ri-a-east",
  dbInstanceClass: "db.r7g.large",
  productDescription: "postgresql",
  multiAZ: true,
  dbInstanceCount: 2,
  state: "active",
  offeringType: "All Upfront",
  durationSeconds: 31536000,
  startTime: "2026-01-01T00:00:00.000Z",
  scannedAt: "2026-06-05T00:00:00.000Z",
};

const scanErrorFixture: ModelScanError = {
  profile: "stale-readonly",
  accountId: ACCOUNT_BETA,
  region: "ap-southeast-2",
  phase: "describe_db_instances",
  kind: "access_denied",
  message: "User is not authorized to perform rds:DescribeDBInstances",
  scannedAt: "2026-06-05T00:00:00.000Z",
};

// ---------------------------------------------------------------------------
// A. Producer↔consumer schema agreement
// ---------------------------------------------------------------------------

Deno.test("collect: producer-shaped instance/reserved/error rows all decode with zero skipped", async () => {
  const { context } = stubContext([
    {
      name: "instance-1",
      version: 1,
      specName: INSTANCE_SPEC,
      json: instanceFixture,
    },
    {
      name: "reserved-1",
      version: 1,
      specName: RESERVED_SPEC,
      json: reservedFixture,
    },
    {
      name: "error-1",
      version: 1,
      specName: SCAN_ERROR_SPEC,
      json: scanErrorFixture,
    },
  ]);

  const collected = await collect(context);

  assertEquals(collected.instances.length, 1);
  assertEquals(collected.reserved.length, 1);
  assertEquals(collected.errors.length, 1);
  // skipped === 0 is the agreement assertion: the consumer schema accepted
  // every producer-shaped record. Any drift would have skipped them.
  assertEquals(collected.skipped, 0);
});

Deno.test("collect: decoded field values survive the round-trip", async () => {
  const { context } = stubContext([
    {
      name: "instance-1",
      version: 1,
      specName: INSTANCE_SPEC,
      json: instanceFixture,
    },
    {
      name: "reserved-1",
      version: 1,
      specName: RESERVED_SPEC,
      json: reservedFixture,
    },
  ]);

  const collected = await collect(context);

  const inst = collected.instances[0];
  assertEquals(inst.multiAZ, true);
  assertEquals(inst.dbInstanceClass, "db.r7g.2xlarge");
  assertEquals(inst.engine, "postgres");
  assertEquals(inst.instanceTags, { Name: "orders", env: "prod" });

  const res = collected.reserved[0];
  assertEquals(res.state, "active");
  assertEquals(res.dbInstanceCount, 2);
  assertEquals(res.productDescription, "postgresql");
});

Deno.test("collect: a malformed record is safely skipped, not thrown", async () => {
  // Drop the required `multiAZ` boolean from an otherwise producer-shaped row.
  const { multiAZ: _omit, ...broken } = instanceFixture;

  const { context } = stubContext([
    {
      name: "good",
      version: 1,
      specName: INSTANCE_SPEC,
      json: instanceFixture,
    },
    { name: "bad", version: 1, specName: INSTANCE_SPEC, json: broken },
  ]);

  const collected = await collect(context);

  assertEquals(collected.instances.length, 1);
  assertEquals(collected.instances[0].dbInstanceIdentifier, "orders-db");
  // The malformed row is counted in skipped and absent from instances.
  assertEquals(collected.skipped, 1);
});

Deno.test("collect: an instance artifact missing licenseModel decodes (back-compat default), not skipped", async () => {
  // Rows swept before @jentz/aws-rds-reservations 2026.06.06.2 carry no
  // `licenseModel`. The consumer schema's `.default("")` must admit them rather
  // than safeParse-fail and silently empty the report. Build a row with the key
  // genuinely ABSENT (not just empty) and push it through collect().
  const { licenseModel: _omit, ...preLicenseModel } = instanceFixture;

  const { context } = stubContext([
    {
      name: "old",
      version: 1,
      specName: INSTANCE_SPEC,
      json: preLicenseModel,
    },
  ]);

  const collected = await collect(context);

  assertEquals(collected.skipped, 0); // admitted, not skipped
  assertEquals(collected.instances.length, 1);
  assertEquals(collected.instances[0].licenseModel, ""); // backfilled default
});

Deno.test("collect: a wrong-typed field is skipped (documents the guard)", async () => {
  // dbInstanceCount as a string instead of a number.
  const broken = {
    ...reservedFixture,
    dbInstanceCount: "2" as unknown as number,
  };

  const { context } = stubContext([
    { name: "bad", version: 1, specName: RESERVED_SPEC, json: broken },
  ]);

  const collected = await collect(context);

  assertEquals(collected.reserved.length, 0);
  assertEquals(collected.skipped, 1);
});

Deno.test("collect: a non-ISO scannedAt is rejected (the ISO datetime contract is intentional)", async () => {
  // The consumer schema validates scannedAt with z.iso.datetime(), stricter than
  // the producer's `string` TYPE. The producer's own schema also enforces ISO, so
  // in practice they agree — this test pins that tightening as deliberate: a row
  // with a non-ISO scannedAt is skipped rather than silently admitted.
  const broken = { ...instanceFixture, scannedAt: "2026-06-05 (not iso)" };

  const { context } = stubContext([
    {
      name: "good",
      version: 1,
      specName: INSTANCE_SPEC,
      json: instanceFixture,
    },
    { name: "bad", version: 1, specName: INSTANCE_SPEC, json: broken },
  ]);

  const collected = await collect(context);

  assertEquals(collected.instances.length, 1);
  assertEquals(collected.skipped, 1);
});

Deno.test("collect: a getContent rejection skips one artifact, not the whole sweep", async () => {
  // One handle's read REJECTS (transient storage error / corrupt blob) while
  // sibling instance and reserved handles read fine. The rejection must be
  // treated as a per-artifact skip — the surviving rows still land.
  const { context, logs } = stubContext([
    {
      name: "instance-1",
      version: 1,
      specName: INSTANCE_SPEC,
      json: instanceFixture,
    },
    {
      name: "instance-broken-read",
      version: 1,
      specName: INSTANCE_SPEC,
      json: instanceFixture,
      rejectWith: new Error("transient storage error"),
    },
    {
      name: "reserved-1",
      version: 1,
      specName: RESERVED_SPEC,
      json: reservedFixture,
    },
  ]);

  const collected = await collect(context);

  // The surviving instance and reserved rows are not lost to the bad read.
  assertEquals(collected.instances.length, 1);
  assertEquals(collected.reserved.length, 1);
  // The bad read is counted as a skip, exactly like a decode failure.
  assertEquals(collected.skipped, 1);
  // And it is observable: a warning names the failing handle.
  const warned = logs.find(
    (l) =>
      l.level === "warn" && l.message.includes("Could not read") &&
      l.message.includes("{handle}"),
  );
  assert(warned, "expected a warn log for the failed read");
});

Deno.test("collect: a getContent rejection for the only handle leaves an empty-but-not-thrown result", async () => {
  // Even when the single artifact's read rejects, collect() must NOT throw —
  // it degrades to an empty result with the skip counted.
  const { context } = stubContext([
    {
      name: "instance-only",
      version: 1,
      specName: INSTANCE_SPEC,
      json: instanceFixture,
      rejectWith: new Error("blob gone"),
    },
  ]);

  const collected = await collect(context);

  assertEquals(collected.instances.length, 0);
  assertEquals(collected.reserved.length, 0);
  assertEquals(collected.errors.length, 0);
  assertEquals(collected.skipped, 1);
});

Deno.test("collect: collect() never throws even when the logger itself throws", async () => {
  // The logger is observability, not correctness: a throwing logger must not
  // surface as a thrown collect(). Combine a rejecting read (which logs) and a
  // schema failure (which also logs) against a logger that always throws.
  const { multiAZ: _omit, ...broken } = instanceFixture;
  const context = {
    logger: {
      info: () => {
        throw new Error("logger down");
      },
      debug: () => {
        throw new Error("logger down");
      },
      warn: () => {
        throw new Error("logger down");
      },
      error: () => {
        throw new Error("logger down");
      },
    },
    stepExecutions: [
      {
        modelType: RESERVATIONS_MODEL_TYPE,
        modelId: "step-1",
        dataHandles: [
          {
            name: "bad-read",
            version: 1,
            metadata: { tags: { specName: INSTANCE_SPEC } },
          },
          {
            name: "bad-schema",
            version: 1,
            metadata: { tags: { specName: INSTANCE_SPEC } },
          },
          {
            name: "good",
            version: 1,
            metadata: { tags: { specName: INSTANCE_SPEC } },
          },
        ],
      },
    ],
    dataRepository: {
      getContent: (
        _modelType: string,
        _modelId: string,
        name: string,
        _version: number,
      ): Promise<Uint8Array | null> => {
        if (name === "bad-read") return Promise.reject(new Error("read fail"));
        if (name === "bad-schema") return Promise.resolve(enc(broken));
        return Promise.resolve(enc(instanceFixture));
      },
    },
  };

  const collected = await collect(context);

  assertEquals(collected.instances.length, 1);
  assertEquals(collected.skipped, 2);
});

Deno.test("collect: collect() never throws when getContent throws SYNCHRONOUSLY", async () => {
  // A getContent that throws synchronously (rather than returning a rejected
  // promise) must also be caught by the per-handle guard — await on a thrown
  // synchronous call still routes through try/catch.
  const context = {
    logger: {
      info: () => {},
      debug: () => {},
      warn: () => {},
      error: () => {},
    },
    stepExecutions: [
      {
        modelType: RESERVATIONS_MODEL_TYPE,
        modelId: "step-1",
        dataHandles: [
          {
            name: "sync-throw",
            version: 1,
            metadata: { tags: { specName: INSTANCE_SPEC } },
          },
          {
            name: "good",
            version: 1,
            metadata: { tags: { specName: INSTANCE_SPEC } },
          },
        ],
      },
    ],
    dataRepository: {
      getContent: (
        _modelType: string,
        _modelId: string,
        name: string,
        _version: number,
      ): Promise<Uint8Array | null> => {
        if (name === "sync-throw") throw new Error("synchronous boom");
        return Promise.resolve(enc(instanceFixture));
      },
    },
  };

  const collected = await collect(context);

  assertEquals(collected.instances.length, 1);
  assertEquals(collected.skipped, 1);
});

Deno.test("collect: a malformed scan_error row logs a field-level warning (not dropped silently)", async () => {
  // A malformed scan_error artifact means a real region-scan failure would
  // vanish from errorsByKind. The branch must warn with the failing field
  // paths, matching the instance/reserved branches.
  const broken = { ...scanErrorFixture, kind: 42 as unknown as string };

  const { context, logs } = stubContext([
    {
      name: "error-good",
      version: 1,
      specName: SCAN_ERROR_SPEC,
      json: scanErrorFixture,
    },
    {
      name: "error-bad",
      version: 1,
      specName: SCAN_ERROR_SPEC,
      json: broken,
    },
  ]);

  const collected = await collect(context);

  assertEquals(collected.errors.length, 1);
  assertEquals(collected.skipped, 1);
  const warned = logs.find(
    (l) =>
      l.level === "warn" && l.message.includes("scan_error row") &&
      l.message.includes("failed schema"),
  );
  assert(
    warned,
    "expected a field-level warn log for the malformed scan_error",
  );
});

Deno.test("collect: ignores steps whose modelType is not the reservations model", async () => {
  const logs: Array<{ level: string; message: string }> = [];
  const log = (level: string) => (message: string) =>
    logs.push({ level, message });
  const context = {
    logger: {
      info: log("info"),
      debug: log("debug"),
      warn: log("warn"),
      error: log("error"),
    },
    stepExecutions: [
      {
        modelType: "@some/other-model",
        modelId: "x",
        dataHandles: [{
          name: "n",
          version: 1,
          metadata: { tags: { specName: INSTANCE_SPEC } },
        }],
      },
    ],
    dataRepository: {
      getContent: () => Promise.resolve(enc(instanceFixture)),
    },
  };

  const collected = await collect(context);
  assertEquals(collected.instances.length, 0);
  assertEquals(collected.skipped, 0);
});

// ---------------------------------------------------------------------------
// B. csvField — RFC4180 escaping
// ---------------------------------------------------------------------------

Deno.test("csvField: a plain value is unchanged", () => {
  assertEquals(csvField("us-east-1"), "us-east-1");
  assertEquals(csvField("r7g"), "r7g");
});

Deno.test("csvField: a comma forces quoting", () => {
  assertEquals(csvField("a,b"), '"a,b"');
});

Deno.test("csvField: a double-quote is doubled and the field wrapped", () => {
  assertEquals(csvField('he said "hi"'), '"he said ""hi"""');
});

Deno.test("csvField: a newline forces quoting", () => {
  assertEquals(csvField("line1\nline2"), '"line1\nline2"');
  assertEquals(csvField("cr\rlf"), '"cr\rlf"');
});

// ---------------------------------------------------------------------------
// B. renderCsv — header always present, trailing newline, quoted cells
// ---------------------------------------------------------------------------

Deno.test("renderCsv: header row present even for an empty bucket list", () => {
  const out = renderCsv([]);
  assertEquals(out, COLUMNS.join(",") + "\n");
  // Trailing newline present.
  assert(out.endsWith("\n"));
});

Deno.test("renderCsv: a field containing a comma is quoted in the cell", () => {
  // engine carries a comma so the produced CSV cell must be quoted.
  const bucket: Bucket = {
    region: "us-east-1",
    family: "r7g",
    generation: "7g",
    engine: "postgres,extra",
    deployment: "Single-AZ",
    runningLargeEq: 4,
    reservedLargeEq: 1,
    runningInstances: 1,
    reservedInstances: 1,
  };
  const out = renderCsv([bucket]);
  const lines = out.split("\n");
  assertEquals(lines[0], COLUMNS.join(","));
  assertStringIncludes(lines[1], '"postgres,extra"');
  // gap = running - reserved = 3 appears as a bare numeric cell.
  assertStringIncludes(lines[1], ",3,");
  assert(out.endsWith("\n"));
});

// ---------------------------------------------------------------------------
// B. renderMarkdown — exercise the rendering path; light assertions
// ---------------------------------------------------------------------------

Deno.test("report.execute: account and region counts include reserved and scan_error-only rows", async () => {
  const reservedOnly: ModelReservedRecord = {
    ...reservedFixture,
    accountId: ACCOUNT_GAMMA,
    accountName: "reserved-only",
    region: "eu-west-1",
  };
  const errorOnly: ModelScanError = {
    ...scanErrorFixture,
    accountId: ACCOUNT_EPSILON,
    region: "ap-southeast-2",
  };
  const { context } = stubContext([
    {
      name: "reserved-only",
      version: 1,
      specName: RESERVED_SPEC,
      json: reservedOnly,
    },
    {
      name: "error-only",
      version: 1,
      specName: SCAN_ERROR_SPEC,
      json: errorOnly,
    },
  ]);

  const result = await report.execute({
    ...(context as Record<string, unknown>),
    workflowName: "coverage-test",
  });

  assertEquals(result.json.accountCount, 2);
  assertEquals(result.json.regionCount, 2);
  assertStringIncludes(result.markdown, "- Accounts seen: **2**");
  assertStringIncludes(result.markdown, "- Regions covered: **2**");
});

Deno.test("renderMarkdown: non-empty doc with expected section headers", () => {
  const instances: InstanceRecord[] = [{
    accountId: ACCOUNT_ALPHA,
    accountName: "prod",
    profile: "prod-readonly",
    region: "us-east-1",
    dbInstanceIdentifier: "orders-db",
    dbInstanceClass: "db.r7g.2xlarge",
    engine: "postgres",
    engineVersion: "16",
    licenseModel: "",
    multiAZ: false,
    status: "available",
    clusterId: "",
    storageType: "gp3",
    instanceTags: {},
    scannedAt: "2026-06-05T00:00:00.000Z",
  }];
  const agg = aggregate(instances, []);
  const rollup = rollupByPool(agg.buckets);
  const collected: Collected = {
    instances,
    reserved: [],
    errors: [],
    skipped: 0,
    matchingSteps: 0,
    observedModelTypes: [],
  };

  const md = renderMarkdown(
    collected,
    agg,
    rollup,
    {
      buckets: [],
      burstable: [],
      serverless: [],
      unparseable: [],
      nonSizeFlex: [],
      inactiveReserved: [],
    },
    "2026-06-06T00:00:00.000Z",
    "rds-coverage-nightly",
  );

  assert(md.length > 0);
  assertStringIncludes(md, "# RDS Large-Equivalent Reservation Gap");
  assertStringIncludes(md, "## Summary");
  assertStringIncludes(md, "## Coverage by reservation pool");
  assertStringIncludes(md, "## Purchasable buckets");
  assertStringIncludes(md, "rds-coverage-nightly");
  // The single running r7g 2xlarge = 4 large-eq shows up in the summary.
  assertStringIncludes(md, "**4** large-eq");
  assert(md.endsWith("\n"));
});

Deno.test("renderMarkdown: a pipe in a table cell is escaped", () => {
  // `region` flows verbatim into the table (unlike `engine`, which is
  // canonicalized and stripped of punctuation), so a pipe here reaches
  // mdEscape and must be backslash-escaped in the rendered table.
  const instances: InstanceRecord[] = [{
    accountId: "1",
    accountName: "acct",
    profile: "p",
    region: "weird|region",
    dbInstanceIdentifier: "id",
    dbInstanceClass: "db.r7g.large",
    engine: "postgres",
    engineVersion: "1",
    licenseModel: "",
    multiAZ: false,
    status: "available",
    clusterId: "",
    storageType: "gp3",
    instanceTags: {},
    scannedAt: "2026-06-05T00:00:00.000Z",
  }];
  const agg = aggregate(instances, []);
  const rollup = rollupByPool(agg.buckets);
  const collected: Collected = {
    instances,
    reserved: [],
    errors: [],
    skipped: 0,
    matchingSteps: 0,
    observedModelTypes: [],
  };

  const md = renderMarkdown(
    collected,
    agg,
    rollup,
    {
      buckets: [],
      burstable: [],
      serverless: [],
      unparseable: [],
      nonSizeFlex: [],
      inactiveReserved: [],
    },
    "2026-06-06T00:00:00.000Z",
    "wf",
  );

  // The escaped form must appear in the rendered table.
  assertStringIncludes(md, "weird\\|region");
});

// ---------------------------------------------------------------------------
// C. Degraded coherence — a degraded payload must never read as healthy
// ---------------------------------------------------------------------------

Deno.test("report.execute: a post-collect throw yields a coherent, all-empty degraded payload", async () => {
  // collect() succeeds and populates rows, then renderMarkdown throws when it
  // coerces a hostile workflowName in its template literal — a genuine
  // post-collect failure. The catch must reset EVERY source so the JSON cannot
  // read "N instances, 0 buckets, fully covered" with degraded=true.
  const reserved: ModelReservedRecord = {
    ...reservedFixture,
    accountId: ACCOUNT_ZETA,
    region: "eu-central-1",
  };
  const { context } = stubContext([
    {
      name: "inst",
      version: 1,
      specName: INSTANCE_SPEC,
      json: instanceFixture,
    },
    { name: "resv", version: 1, specName: RESERVED_SPEC, json: reserved },
    {
      name: "err",
      version: 1,
      specName: SCAN_ERROR_SPEC,
      json: {
        ...scanErrorFixture,
        accountId: ACCOUNT_OMEGA,
        region: "sa-east-1",
      },
    },
  ]);

  // An object whose primitive coercion throws: the only thing it touches is the
  // `${workflowName}` interpolation inside renderMarkdown, after collect and the
  // aggregations have already populated `collected`/`agg`/`accountAgg`.
  const explodingWorkflowName = {
    [Symbol.toPrimitive]() {
      throw new Error("boom during render");
    },
  };

  const result = await report.execute({
    ...(context as Record<string, unknown>),
    workflowName: explodingWorkflowName,
  });

  const j = result.json;
  assertEquals(j.degraded, true);
  // Counts (derived from `collected`) and totals/buckets (derived from `agg`)
  // must agree: all zero/empty. No "N instances but 0 buckets" contradiction.
  assertEquals(j.instanceCount, 0);
  assertEquals(j.reservedCount, 0);
  assertEquals(j.accountCount, 0);
  assertEquals(j.regionCount, 0);
  assertEquals(j.skipped, 0);
  assertEquals(j.errorsByKind, { auth_expired: 0, access_denied: 0, other: 0 });
  assertEquals(j.totalRunningLargeEq, 0);
  assertEquals(j.totalReservedLargeEq, 0);
  assertEquals(j.largeEqToBuy, 0);
  assertEquals(j.buckets, []);
  assertEquals(j.reservationPools, []);
  assertEquals(j.accountBuckets, []);
  // CSV bodies are reset to header-only.
  assertEquals(j.csv, renderCsv([]));
  assertEquals(j.csvByAccount.split("\n").length, 2); // header + trailing ""
  // The markdown is the degraded notice, not a healthy report.
  assertStringIncludes(result.markdown, "_Report degraded:");
});

Deno.test("report.execute: a no_regions scan_error degrades the report, no healthy zero-buy render", async () => {
  // The sweep refused to run (empty regions) and wrote a single no_regions
  // scan_error with zero instances/reserved. Aggregating that produces a
  // healthy-looking "Large-equivalents to buy: 0, fully covered" report. The
  // report must treat it as degraded instead, so a JSON consumer never sees
  // degraded=false + toBuy:0.
  const noRegionsError: ModelScanError = {
    profile: "",
    accountId: "",
    region: "",
    phase: "no_regions",
    kind: "other",
    message:
      "No regions configured: 'regions' is empty, so no RDS instances or " +
      "reservations were swept. Set the 'regions' global argument.",
    scannedAt: "2026-06-05T00:00:00.000Z",
  };
  const { context } = stubContext([
    {
      name: "err",
      version: 1,
      specName: SCAN_ERROR_SPEC,
      json: noRegionsError,
    },
  ]);

  const result = await report.execute({
    ...(context as Record<string, unknown>),
    workflowName: "nightly",
  });

  const j = result.json;
  // The machine-readable signal: degraded, with the coherent-empty payload.
  assertEquals(j.degraded, true);
  assertEquals(j.instanceCount, 0);
  assertEquals(j.reservedCount, 0);
  assertEquals(j.largeEqToBuy, 0);
  assertEquals(j.buckets, []);

  // No healthy zero-buy headline; the markdown is the degraded notice.
  assert(
    !result.markdown.includes("Large-equivalents to buy: 0"),
    "degraded no_regions report must not render the healthy zero-buy headline",
  );
  assertStringIncludes(result.markdown, "_Report degraded:");
  assertStringIncludes(result.markdown, "regions");
});

/** A logger that records levels + messages, like stubContext's. */
function recordingLogger(): {
  logger: Record<string, (m: string) => void>;
  logs: Array<{ level: string; message: string }>;
} {
  const logs: Array<{ level: string; message: string }> = [];
  const log = (level: string) => (message: string) =>
    logs.push({ level, message });
  return {
    logger: {
      info: log("info"),
      debug: log("debug"),
      warn: log("warn"),
      error: log("error"),
    },
    logs,
  };
}

Deno.test("report.execute: steps ran but none matched the reservations model degrades", async () => {
  // A workflow wiring mistake — an upstream step exists, but none carries the
  // @jentz/aws-rds-reservations modelType. The report has no input and must
  // degrade rather than render a healthy "0 large-equivalents to buy" report.
  const { logger } = recordingLogger();
  const context = {
    logger,
    workflowName: "nightly",
    stepExecutions: [
      {
        modelType: "@some/other-model",
        modelId: "x",
        dataHandles: [],
      },
      {
        modelType: "@another/unrelated-model",
        modelId: "y",
        dataHandles: [],
      },
    ],
    dataRepository: {
      getContent: () => Promise.resolve(null),
    },
  };

  const result = await report.execute(context);
  const j = result.json;

  assertEquals(j.degraded, true);
  assertEquals(j.instanceCount, 0);
  assertEquals(j.reservedCount, 0);
  assertEquals(j.largeEqToBuy, 0);
  assertEquals(j.buckets, []);

  // The markdown is the degraded notice naming the missing collector and the
  // observed (non-matching) model types, so an operator can fix the wiring.
  assertStringIncludes(result.markdown, "_Report degraded:");
  assertStringIncludes(result.markdown, RESERVATIONS_MODEL_TYPE);
  assertStringIncludes(result.markdown, "@another/unrelated-model");
  assertStringIncludes(result.markdown, "@some/other-model");
  assert(
    !result.markdown.includes("Large-equivalents to buy: 0"),
    "missing-step report must not render the healthy zero-buy headline",
  );
});

Deno.test("report.execute: empty or absent stepExecutions degrades", async () => {
  // No upstream step ran at all. matchingSteps===0 covers this just as it
  // covers steps-but-no-match. Observed model types render as "none".
  for (const stepExecutions of [[], undefined]) {
    const { logger } = recordingLogger();
    const context = {
      logger,
      workflowName: "nightly",
      stepExecutions,
      dataRepository: { getContent: () => Promise.resolve(null) },
    };

    const result = await report.execute(context);
    const j = result.json;

    assertEquals(j.degraded, true);
    assertEquals(j.instanceCount, 0);
    assertEquals(j.largeEqToBuy, 0);
    assertStringIncludes(result.markdown, "_Report degraded:");
    assertStringIncludes(result.markdown, RESERVATIONS_MODEL_TYPE);
    assertStringIncludes(result.markdown, "none");
  }
});

Deno.test("report.execute: a matching step with rows renders a healthy report", async () => {
  // Sanity that the missing-step trigger does not over-fire: a matching
  // reservations step carrying real rows must produce a normal, non-degraded
  // report.
  const { context } = stubContext([
    {
      name: "inst",
      version: 1,
      specName: INSTANCE_SPEC,
      json: instanceFixture,
    },
    {
      name: "resv",
      version: 1,
      specName: RESERVED_SPEC,
      json: reservedFixture,
    },
  ]);

  const result = await report.execute({
    ...(context as Record<string, unknown>),
    workflowName: "nightly",
  });
  const j = result.json;

  assertEquals(j.degraded, false);
  assertEquals(j.instanceCount, 1);
  assertEquals(j.reservedCount, 1);
  assert(
    !result.markdown.includes("_Report degraded:"),
    "a healthy report must not carry the degraded notice",
  );
});

Deno.test("report.execute: a matching step with zero rows stays healthy (empty fleet)", async () => {
  // REGRESSION GUARD: the degraded signal is matchingSteps, NOT row count. A
  // matching collector step that legitimately swept and found zero instances
  // and zero reservations is a genuinely-empty healthy fleet. It MUST stay
  // degraded=false — otherwise the trigger would conflate "no input" with "no
  // capacity".
  const { logger } = recordingLogger();
  const context = {
    logger,
    workflowName: "nightly",
    stepExecutions: [
      {
        modelType: RESERVATIONS_MODEL_TYPE,
        modelId: "step-1",
        dataHandles: [],
      },
    ],
    dataRepository: { getContent: () => Promise.resolve(null) },
  };

  const result = await report.execute(context);
  const j = result.json;

  assertEquals(j.degraded, false);
  assertEquals(j.instanceCount, 0);
  assertEquals(j.reservedCount, 0);
  assertEquals(j.largeEqToBuy, 0);
  assertEquals(j.buckets, []);
  assert(
    !result.markdown.includes("_Report degraded:"),
    "an empty healthy fleet must not be reported as degraded",
  );
});

// ---------------------------------------------------------------------------
// D. Shared helpers — countAccountsRegions, gapLargeEq, accountColumns
// ---------------------------------------------------------------------------

Deno.test("countAccountsRegions: unions accounts/regions across instances, reserved, and errors", () => {
  const collected: Collected = {
    instances: [{ ...instanceFixture, accountId: "a1", region: "r1" }],
    reserved: [{ ...reservedFixture, accountId: "a2", region: "r2" }],
    errors: [
      // account-only error (no region) contributes an account, not a region.
      { ...scanErrorFixture, accountId: "a3", region: "" },
      // region-only credential failure with empty account contributes a region.
      { ...scanErrorFixture, accountId: "", region: "r3" },
    ],
    skipped: 0,
    matchingSteps: 0,
    observedModelTypes: [],
  };
  assertEquals(countAccountsRegions(collected), {
    accountCount: 3,
    regionCount: 3,
  });
});

Deno.test("countAccountsRegions: JSON counts equal the markdown summary (shared source)", async () => {
  const reservedOnly: ModelReservedRecord = {
    ...reservedFixture,
    accountId: ACCOUNT_GAMMA,
    accountName: "reserved-only",
    region: "eu-west-1",
  };
  const { context } = stubContext([
    { name: "r", version: 1, specName: RESERVED_SPEC, json: reservedOnly },
    {
      name: "i",
      version: 1,
      specName: INSTANCE_SPEC,
      json: instanceFixture,
    },
  ]);
  const result = await report.execute({
    ...(context as Record<string, unknown>),
    workflowName: "coverage-test",
  });
  // The markdown summary and the JSON counts are now fed by one helper.
  assertStringIncludes(
    result.markdown,
    `- Accounts seen: **${result.json.accountCount}**`,
  );
  assertStringIncludes(
    result.markdown,
    `- Regions covered: **${result.json.regionCount}**`,
  );
});

Deno.test("renderCsvByAccount: exact bytes — header, per-cell escaping, gap, trailing newline", () => {
  const bucket: AccountBucket = {
    // Intentional 12-digit literal (documented exception): this test asserts
    // exact CSV bytes, and the point is the numeric, comma-free account-id cell
    // rendering UNQUOTED next to the quoted "team, alpha" cell. A non-numeric
    // placeholder would weaken the unquoted-vs-quoted contrast under test.
    accountId: "111122223333",
    // A comma forces RFC4180 quoting in this cell only.
    accountName: "team, alpha",
    region: "us-east-1",
    family: "r7g",
    generation: "7g",
    engine: "postgres",
    deployment: "Single-AZ",
    runningLargeEq: 4,
    reservedLargeEq: 1.5,
    runningInstances: 2,
    reservedInstances: 1,
  };
  const out = renderCsvByAccount([bucket]);
  const expected = ACCOUNT_COLUMNS.join(",") + "\n" +
    '"team, alpha",111122223333,us-east-1,r7g,7g,postgres,Single-AZ,4,1.5,2.5,2,1' +
    "\n";
  // Locks the consolidated emitter's exact output: quoting of the comma cell,
  // gap = 4 - 1.5 = 2.5 via gapLargeEq, and the trailing newline.
  assertEquals(out, expected);
});

Deno.test("renderCsvByAccount: empty list emits header-only with trailing newline", () => {
  assertEquals(renderCsvByAccount([]), ACCOUNT_COLUMNS.join(",") + "\n");
});

Deno.test("gapLargeEq: gap is running minus reserved, rounded to 2 decimals", () => {
  assertEquals(gapLargeEq({ runningLargeEq: 4, reservedLargeEq: 1.5 }), 2.5);
  assertEquals(gapLargeEq({ runningLargeEq: 1, reservedLargeEq: 3 }), -2);
  // Floating-point noise is rounded away.
  assertEquals(gapLargeEq({ runningLargeEq: 0.1, reservedLargeEq: 0.2 }), -0.1);
});

Deno.test("report.execute: accountColumns surfaces the csvByAccount header order", async () => {
  const { context } = stubContext([
    { name: "i", version: 1, specName: INSTANCE_SPEC, json: instanceFixture },
  ]);
  const result = await report.execute({
    ...(context as Record<string, unknown>),
    workflowName: "coverage-test",
  });
  // The declared accountColumns must exactly match the emitted CSV header so a
  // consumer can parse csvByAccount from the structured output alone.
  assertEquals(result.json.accountColumns, [...ACCOUNT_COLUMNS]);
  const header = result.json.csvByAccount.split("\n")[0];
  assertEquals(header, result.json.accountColumns.join(","));
});
