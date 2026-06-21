/**
 * Unit tests for `@jentz/aws-rds-inventory-report`.
 *
 * Collection / decoding — `collect` walks `context.stepExecutions`, matches the
 * upstream model type, and decodes `cluster` / `instance` artifacts. Malformed
 * (bad-JSON) and schema-mismatched artifacts are counted into `skipped`, never
 * thrown.
 *
 * @module
 */

import { assertEquals } from "jsr:@std/assert@1";

import {
  CLUSTER_SPEC,
  type ClusterRecord,
  collect,
  INSTANCE_SPEC,
  type InstanceRecord,
  INVENTORY_MODEL_TYPE,
} from "../aws_rds_inventory_report.ts";

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
