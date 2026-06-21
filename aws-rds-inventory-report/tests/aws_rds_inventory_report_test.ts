/**
 * Unit tests for `@jentz/aws-rds-inventory-report`.
 *
 * Four layers:
 *
 *   1. Collection / decoding — `collect` walks `context.stepExecutions`,
 *      matches the upstream model type, and decodes `cluster` / `instance`
 *      artifacts. Malformed (bad-JSON) and schema-mismatched artifacts are
 *      counted into `skipped`, never thrown.
 *   2. Sort comparators — `compareClusters` and `compareInstances` impose a
 *      stable ordering on the rows.
 *   3. Markdown rendering — `renderMarkdown` produces the summary and the full
 *      inventory table in stable sort order.
 *   4. The JSON payload — `report.execute` carries structured `clusters[]` and
 *      `instances[]` rows (in sort order), summary counts, the skipped count,
 *      and the `degraded` flag — and NO `csv` / `columns` keys.
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
  CLUSTER_SPEC,
  type ClusterRecord,
  collect,
  type Collected,
  compareClusters,
  compareInstances,
  INSTANCE_SPEC,
  type InstanceRecord,
  INVENTORY_MODEL_TYPE,
  renderMarkdown,
  report,
} from "../aws_rds_inventory_report.ts";

const ISO = "2026-06-20T00:00:00.000Z";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function cluster(overrides: Partial<ClusterRecord> = {}): ClusterRecord {
  return {
    DBClusterIdentifier: "prod-aurora",
    Engine: "aurora-postgresql",
    EngineVersion: "15.4",
    Status: "available",
    Endpoint: "prod-aurora.cluster-abc.eu-west-1.rds.amazonaws.com",
    ReaderEndpoint: "prod-aurora.cluster-ro-abc.eu-west-1.rds.amazonaws.com",
    MultiAZ: true,
    tags: { Environment: "prod" },
    ...overrides,
  };
}

function instance(overrides: Partial<InstanceRecord> = {}): InstanceRecord {
  return {
    DBInstanceIdentifier: "prod-aurora-writer",
    DBClusterIdentifier: "prod-aurora",
    DBInstanceClass: "db.r7g.large",
    Role: "writer",
    AvailabilityZone: "eu-west-1a",
    Engine: "aurora-postgresql",
    EngineVersion: "15.4",
    Status: "available",
    PromotionTier: 0,
    DBClusterParameterGroupStatus: "in-sync",
    tags: { Environment: "prod" },
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
 * `@jentz/aws-rds-inventory` step exposing `dataHandles`. `getContent` returns
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
    workflowName: opts.workflowName ?? "rds-workflow",
    logger: silentLogger(),
    stepExecutions: [
      {
        modelType,
        modelId: "rds-inv-1",
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
// collect — decoding and skip-on-malformed
// ---------------------------------------------------------------------------

Deno.test("collect: decodes cluster and instance rows from a matching step", async () => {
  const ctx = contextFor([
    { specName: CLUSTER_SPEC, payload: cluster({ DBClusterIdentifier: "c1" }) },
    { specName: CLUSTER_SPEC, payload: cluster({ DBClusterIdentifier: "c2" }) },
    {
      specName: INSTANCE_SPEC,
      payload: instance({ DBInstanceIdentifier: "c1-writer" }),
    },
    {
      specName: INSTANCE_SPEC,
      payload: instance({
        DBInstanceIdentifier: "c1-reader",
        Role: "reader",
      }),
    },
  ]);
  const out = await collect(ctx);
  assertEquals(out.clusters.length, 2);
  assertEquals(out.instances.length, 2);
  assertEquals(out.skipped, 0);
});

Deno.test("collect: ignores steps of an unrelated model type", async () => {
  const ctx = contextFor(
    [{ specName: CLUSTER_SPEC, payload: cluster() }],
    { modelType: "@swamp/aws/rds/cluster" },
  );
  const out = await collect(ctx);
  assertEquals(out.clusters.length, 0);
  assertEquals(out.instances.length, 0);
  assertEquals(out.skipped, 0);
});

Deno.test("collect: a getContent read failure is counted as skipped, never thrown", async () => {
  const ctx = contextFor([
    { specName: CLUSTER_SPEC, payload: cluster(), failRead: true },
    {
      specName: CLUSTER_SPEC,
      payload: cluster({ DBClusterIdentifier: "c-ok" }),
    },
  ]);
  // A storage read that rejects must not abort the whole report — it is
  // counted as one skip and the healthy row is still collected.
  const out = await collect(ctx);
  assertEquals(out.clusters.length, 1);
  assertEquals(out.clusters[0].DBClusterIdentifier, "c-ok");
  assertEquals(out.skipped, 1);
});

Deno.test("collect: a bad-JSON artifact is counted as skipped, never thrown", async () => {
  const ctx = contextFor([
    { specName: CLUSTER_SPEC, payload: "{ not valid json", raw: true },
    {
      specName: CLUSTER_SPEC,
      payload: cluster({ DBClusterIdentifier: "c-ok" }),
    },
  ]);
  const out = await collect(ctx);
  assertEquals(out.clusters.length, 1);
  assertEquals(out.clusters[0].DBClusterIdentifier, "c-ok");
  assertEquals(out.skipped, 1);
});

Deno.test("collect: a schema-mismatched artifact is counted as skipped, never thrown", async () => {
  const ctx = contextFor([
    // Missing required fields (Engine, ...) → safeParse fails.
    { specName: CLUSTER_SPEC, payload: { DBClusterIdentifier: "c-bad" } },
    // An instance with an invalid Role enum → safeParse fails.
    {
      specName: INSTANCE_SPEC,
      payload: { ...instance(), Role: "standby" },
    },
    {
      specName: CLUSTER_SPEC,
      payload: cluster({ DBClusterIdentifier: "c-good" }),
    },
  ]);
  const out = await collect(ctx);
  assertEquals(out.clusters.length, 1);
  assertEquals(out.clusters[0].DBClusterIdentifier, "c-good");
  assertEquals(out.instances.length, 0);
  assertEquals(out.skipped, 2);
});

Deno.test("collect: handles with an unrelated spec name are ignored, not skipped", async () => {
  const ctx = contextFor([
    { specName: "something_else", payload: { whatever: true } },
    { specName: CLUSTER_SPEC, payload: cluster() },
  ]);
  const out = await collect(ctx);
  assertEquals(out.clusters.length, 1);
  assertEquals(out.skipped, 0);
});

Deno.test("collect: optional cluster/instance fields may be omitted and still parse", async () => {
  // A minimal cluster and instance carrying only the required fields — every
  // optional field absent — must decode rather than getting skipped.
  const ctx = contextFor([
    {
      specName: CLUSTER_SPEC,
      payload: { DBClusterIdentifier: "c-min", Engine: "mysql" },
    },
    {
      specName: INSTANCE_SPEC,
      payload: {
        DBInstanceIdentifier: "c-min-1",
        DBClusterIdentifier: "c-min",
        DBInstanceClass: "db.r7g.large",
        Role: "reader",
        Engine: "mysql",
      },
    },
  ]);
  const out = await collect(ctx);
  assertEquals(out.clusters.length, 1);
  assertEquals(out.instances.length, 1);
  assertEquals(out.skipped, 0);
  // The defaulted tags map is present even when absent on the wire.
  assertEquals(out.clusters[0].tags, {});
  assertEquals(out.instances[0].tags, {});
});

Deno.test("collect: emits no rows and no skips when no step matches the model type", async () => {
  const ctx = contextFor(
    [{ specName: CLUSTER_SPEC, payload: cluster() }],
    { modelType: "@some/other-model" },
  );
  const out = await collect(ctx);
  assertEquals(out.clusters.length, 0);
  assertEquals(out.instances.length, 0);
  assertEquals(out.skipped, 0);
});

// ---------------------------------------------------------------------------
// compareClusters / compareInstances
// ---------------------------------------------------------------------------

Deno.test("compareClusters: orders by cluster identifier", () => {
  const rows = [
    cluster({ DBClusterIdentifier: "c-zeta" }),
    cluster({ DBClusterIdentifier: "c-alpha" }),
    cluster({ DBClusterIdentifier: "c-mu" }),
  ];
  const sorted = [...rows].sort(compareClusters).map((c) =>
    c.DBClusterIdentifier
  );
  assertEquals(sorted, ["c-alpha", "c-mu", "c-zeta"]);
});

Deno.test("compareInstances: orders by cluster, then writer-before-reader, then instance id", () => {
  const rows = [
    instance({
      DBClusterIdentifier: "c-b",
      DBInstanceIdentifier: "b-reader",
      Role: "reader",
    }),
    instance({
      DBClusterIdentifier: "c-a",
      DBInstanceIdentifier: "a-reader-2",
      Role: "reader",
    }),
    instance({
      DBClusterIdentifier: "c-a",
      DBInstanceIdentifier: "a-reader-1",
      Role: "reader",
    }),
    instance({
      DBClusterIdentifier: "c-a",
      DBInstanceIdentifier: "a-writer",
      Role: "writer",
    }),
  ];
  const sorted = [...rows].sort(compareInstances).map((i) =>
    i.DBInstanceIdentifier
  );
  assertEquals(sorted, ["a-writer", "a-reader-1", "a-reader-2", "b-reader"]);
});

// ---------------------------------------------------------------------------
// renderMarkdown
// ---------------------------------------------------------------------------

Deno.test("renderMarkdown: empty collection renders the header, summary, and an empty table", () => {
  const md = renderMarkdown(
    { clusters: [], instances: [], skipped: 0 },
    ISO,
    "rds-workflow",
  );
  assert(md.includes("# AWS RDS Inventory"));
  assert(md.includes("- Clusters inventoried: **0**"));
  assert(md.includes("- Instances inventoried: **0**"));
  assert(md.includes("- Skipped artifacts: **0**"));
  assert(md.includes("_None._"));
});

Deno.test("renderMarkdown: a non-zero skipped count is flagged in the summary", () => {
  const md = renderMarkdown(
    {
      clusters: [cluster({ DBClusterIdentifier: "c-aurora" })],
      instances: [],
      skipped: 3,
    },
    ISO,
    "rds-workflow",
  );
  assert(md.includes("⚠️ Skipped artifacts: **3**"));
  // The clean-run phrasing must not also appear.
  assert(!md.includes("- Skipped artifacts: **0**"));
});

Deno.test("renderMarkdown: summary reports engines, writer/reader split, and multi-AZ count", () => {
  const collected: Collected = {
    clusters: [
      cluster({ DBClusterIdentifier: "c-aurora", Engine: "aurora-mysql" }),
      cluster({
        DBClusterIdentifier: "c-pg",
        Engine: "aurora-postgresql",
        MultiAZ: false,
      }),
    ],
    instances: [
      instance({
        DBClusterIdentifier: "c-aurora",
        DBInstanceIdentifier: "c-aurora-w",
        Role: "writer",
      }),
      instance({
        DBClusterIdentifier: "c-aurora",
        DBInstanceIdentifier: "c-aurora-r",
        Role: "reader",
      }),
      instance({
        DBClusterIdentifier: "c-pg",
        DBInstanceIdentifier: "c-pg-w",
        Role: "writer",
      }),
    ],
    skipped: 0,
  };
  const md = renderMarkdown(collected, ISO, "rds-workflow");
  assert(md.includes("- Clusters inventoried: **2**"));
  assert(md.includes("- Instances inventoried: **3**"));
  assert(md.includes("writers: **2**, readers: **1**"));
  assert(md.includes("`aurora-mysql`"));
  assert(md.includes("`aurora-postgresql`"));
  // Only c-aurora keeps the default MultiAZ: true; c-pg is false.
  assert(md.includes("- Multi-AZ clusters: **1**"));
});

Deno.test("renderMarkdown: table lists instances in stable sort order", () => {
  const collected: Collected = {
    clusters: [cluster({ DBClusterIdentifier: "c-a" })],
    instances: [
      instance({
        DBClusterIdentifier: "c-b",
        DBInstanceIdentifier: "b-writer",
        Role: "writer",
      }),
      instance({
        DBClusterIdentifier: "c-a",
        DBInstanceIdentifier: "a-reader",
        Role: "reader",
      }),
      instance({
        DBClusterIdentifier: "c-a",
        DBInstanceIdentifier: "a-writer",
        Role: "writer",
      }),
    ],
    skipped: 0,
  };
  const md = renderMarkdown(collected, ISO, "rds-workflow");
  // Stable sort: cluster c-a before c-b; within c-a, writer before reader.
  const firstIdx = md.indexOf("a-writer");
  const secondIdx = md.indexOf("a-reader");
  const thirdIdx = md.indexOf("b-writer");
  assert(
    firstIdx < secondIdx && secondIdx < thirdIdx,
    "rows not in sort order",
  );
});

// ---------------------------------------------------------------------------
// report.execute — JSON payload
// ---------------------------------------------------------------------------

Deno.test("report.execute: JSON payload carries structured rows in sort order", async () => {
  const ctx = contextFor([
    {
      specName: CLUSTER_SPEC,
      payload: cluster({ DBClusterIdentifier: "c-z" }),
    },
    {
      specName: CLUSTER_SPEC,
      payload: cluster({ DBClusterIdentifier: "c-a" }),
    },
    {
      specName: INSTANCE_SPEC,
      payload: instance({
        DBClusterIdentifier: "c-a",
        DBInstanceIdentifier: "c-a-reader",
        Role: "reader",
      }),
    },
    {
      specName: INSTANCE_SPEC,
      payload: instance({
        DBClusterIdentifier: "c-a",
        DBInstanceIdentifier: "c-a-writer",
        Role: "writer",
      }),
    },
  ]);
  const out = await report.execute(ctx);

  assertEquals(out.json.report, "@jentz/aws-rds-inventory-report");
  assertEquals(out.json.workflow, "rds-workflow");
  assertEquals(out.json.clusterCount, 2);
  assertEquals(out.json.instanceCount, 2);
  assertEquals(out.json.skipped, 0);
  assertEquals(out.json.degraded, false);

  // Cluster rows in compareClusters order.
  assertEquals(
    out.json.clusters.map((c) => c.DBClusterIdentifier),
    ["c-a", "c-z"],
  );
  // Instance rows in compareInstances order (writer before reader).
  assertEquals(
    out.json.instances.map((i) => i.DBInstanceIdentifier),
    ["c-a-writer", "c-a-reader"],
  );
  // Each row object carries the model's row fields.
  const firstCluster = out.json.clusters[0];
  assertExists(firstCluster.tags);
  assertEquals(typeof firstCluster.Engine, "string");
  const firstInstance = out.json.instances[0];
  assertExists(firstInstance.tags);
  assertEquals(typeof firstInstance.DBInstanceClass, "string");
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
  assertEquals(out.json.clusters.length, 0);
  assertEquals(out.json.instances.length, 0);
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
  assertEquals(out.json.clusters.length, 0);
  assertEquals(out.json.instances.length, 0);
  assert(out.markdown.includes("degraded"));
});

Deno.test("report.execute: JSON payload carries NO csv or columns keys", async () => {
  const ctx = contextFor([
    { specName: CLUSTER_SPEC, payload: cluster() },
    { specName: INSTANCE_SPEC, payload: instance() },
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
