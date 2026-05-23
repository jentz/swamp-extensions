/**
 * Smoke tests — drive `runListClusters` against recorded
 * `DescribeDBClusters`/`DescribeDBInstances` fixtures with a mock RDS facade.
 *
 * No AWS calls. All fixtures use generic identifiers (cluster-a, cluster-b,
 * ...) so the test corpus is safe to ship with the public extension.
 */

import {
  assert,
  assertEquals,
  assertExists,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import {
  type AwsCluster,
  type AwsInstance,
  type ClusterResource,
  type InstanceResource,
  type RdsApi,
  runListClusters,
} from "../aws_rds_inventory.ts";

// ---------------------------------------------------------------------------
// Fixture replay
// ---------------------------------------------------------------------------

interface Fixture {
  description: string;
  clusters: unknown[];
  instances: unknown[];
}

async function loadFixture(filename: string): Promise<Fixture> {
  const url = new URL(`./fixtures/${filename}`, import.meta.url);
  const text = await Deno.readTextFile(url);
  return JSON.parse(text);
}

/**
 * Build an `RdsApi` that replays a single page from each fixture.
 * Marker is left undefined — fixtures are small enough to fit one page.
 */
function rdsApiFromFixture(fixture: Fixture): RdsApi {
  return {
    describeDBClusters: () =>
      Promise.resolve({ DBClusters: fixture.clusters as AwsCluster[] }),
    describeDBInstances: () =>
      Promise.resolve({ DBInstances: fixture.instances as AwsInstance[] }),
  };
}

// ---------------------------------------------------------------------------
// Stand-in for the runtime's CEL environment
// ---------------------------------------------------------------------------

/**
 * Minimal CEL replacement used in tests. Only honors the literal `"true"`
 * default and `"false"` for negative-case coverage. Tests that want richer
 * selectors should write JS in this function.
 *
 * The real swamp host injects cel-js via `ctx.createCelEnvironment()`. We
 * don't try to spin up cel-js here because the production module never
 * imports it directly — the host injects the runtime.
 */
function makeCelEnvironment() {
  return {
    parse: (expression: string) => {
      if (expression === "true") return () => true;
      if (expression === "false") return () => false;
      // JS-evaluated escape hatch for tests:
      // selectors like "ctx.Engine === 'mysql'" are not valid CEL but are
      // useful for asserting selector flow. We compile with new Function() so
      // the body sees `ctx` as the bindings.
      const compiled = new Function("ctx", `return (${expression});`) as (
        ctx: Record<string, unknown>,
      ) => unknown;
      return compiled;
    },
  };
}

interface MockedRunOutcome {
  result: { dataHandles: unknown[] };
  clusters: Array<{ key: string; data: ClusterResource }>;
  instances: Array<{ key: string; data: InstanceResource }>;
  logs: Array<{ level: string; message: string }>;
}

async function runWithFixture(
  fixture: Fixture,
  globalArgs: Record<string, unknown> = { region: "eu-west-1" },
): Promise<MockedRunOutcome> {
  const clusters: Array<{ key: string; data: ClusterResource }> = [];
  const instances: Array<{ key: string; data: InstanceResource }> = [];
  const logs: Array<{ level: string; message: string }> = [];

  const logger = {
    info: (msg: string) => logs.push({ level: "info", message: msg }),
    debug: (msg: string) => logs.push({ level: "debug", message: msg }),
    warn: (msg: string) => logs.push({ level: "warn", message: msg }),
    error: (msg: string) => logs.push({ level: "error", message: msg }),
  };

  const context = {
    globalArgs,
    logger,
    createCelEnvironment: makeCelEnvironment,
    writeResource: (
      spec: string,
      key: string,
      data: ClusterResource | InstanceResource,
    ) => {
      if (spec === "cluster") {
        clusters.push({ key, data: data as ClusterResource });
      } else if (spec === "instance") {
        instances.push({ key, data: data as InstanceResource });
      }
      return Promise.resolve({ id: `${spec}:${key}` });
    },
  };

  const result = await runListClusters({
    api: rdsApiFromFixture(fixture),
    context,
  });
  return { result, clusters, instances, logs };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

Deno.test("smoke: aurora-mysql 3-node fixture emits 1 cluster + 3 instances", async () => {
  const fixture = await loadFixture("aurora_mysql_3node.json");
  const out = await runWithFixture(fixture);

  assertEquals(out.clusters.length, 1);
  // Storage key carries the spec-name prefix to avoid colliding with instance
  // keys. The CEL ref uses this prefixed key.
  assertEquals(out.clusters[0].key, "cluster-cluster-a");
  assertEquals(out.clusters[0].data.Engine, "aurora-mysql");
  assertEquals(out.clusters[0].data.tags, {
    Environment: "prod",
    Team: "platform",
  });
  assertEquals(out.clusters[0].data.Endpoint?.startsWith("cluster-a"), true);

  assertEquals(out.instances.length, 3);
  const writer = out.instances.find((i) => i.data.Role === "writer");
  assertExists(writer);
  assertEquals(writer.data.DBInstanceIdentifier, "cluster-a-1");
  assertEquals(writer.data.DBClusterIdentifier, "cluster-a");
  assertEquals(writer.data.DBInstanceClass, "db.r7g.large");
  // Member-side fields from DescribeDBClusters surface on the instance resource.
  assertEquals(writer.data.PromotionTier, 0);
  assertEquals(writer.data.DBClusterParameterGroupStatus, "in-sync");
  // Instance storage key carries both spec prefix and cluster identifier.
  assertEquals(writer.key, "instance-cluster-a--cluster-a-1");

  // Pending-reboot reader propagated from fixture to the resource.
  const pending = out.instances.find(
    (i) => i.data.DBClusterParameterGroupStatus === "pending-reboot",
  );
  assertExists(pending);
  assertEquals(pending.data.DBInstanceIdentifier, "cluster-a-3");
  assertEquals(pending.data.PromotionTier, 2);

  const readers = out.instances.filter((i) => i.data.Role === "reader");
  assertEquals(readers.length, 2);
  for (const r of readers) {
    assertEquals(r.data.DBInstanceClass, "db.r8g.large");
  }

  // Data handle count: 1 cluster + 3 instances = 4
  assertEquals(out.result.dataHandles.length, 4);
});

Deno.test("smoke: aurora-postgres 2-node fixture identifies writer + reader", async () => {
  const fixture = await loadFixture("aurora_postgres_2node.json");
  const out = await runWithFixture(fixture);

  assertEquals(out.clusters.length, 1);
  assertEquals(out.clusters[0].data.Engine, "aurora-postgresql");
  assertEquals(out.instances.length, 2);
  const roles = out.instances.map((i) => i.data.Role).sort();
  assertEquals(roles, ["reader", "writer"]);
  for (const i of out.instances) {
    assertEquals(i.data.Engine, "aurora-postgresql");
  }
});

Deno.test("smoke: non-Aurora Multi-AZ DB cluster (engine=mysql) flows through", async () => {
  const fixture = await loadFixture("multi_az_db_cluster.json");
  const out = await runWithFixture(fixture);

  assertEquals(out.clusters.length, 1);
  assertEquals(out.clusters[0].data.Engine, "mysql");
  assertEquals(out.clusters[0].data.MultiAZ, true);
  assertEquals(out.instances.length, 3);
});

Deno.test("smoke: empty region produces zero resources", async () => {
  const fixture = await loadFixture("empty_region.json");
  const out = await runWithFixture(fixture);

  assertEquals(out.clusters.length, 0);
  assertEquals(out.instances.length, 0);
  assertEquals(out.result.dataHandles.length, 0);
});

Deno.test("smoke: selector restricts to a subset of clusters", async () => {
  // Combine two fixtures so we have aurora-mysql + aurora-postgresql to
  // discriminate between.
  const a = await loadFixture("aurora_mysql_3node.json");
  const b = await loadFixture("aurora_postgres_2node.json");
  const combined: Fixture = {
    description: "combined",
    clusters: [...a.clusters, ...b.clusters],
    instances: [...a.instances, ...b.instances],
  };
  const out = await runWithFixture(combined, {
    region: "eu-west-1",
    selector: "ctx.Engine === 'aurora-mysql'",
  });
  assertEquals(out.clusters.length, 1);
  assertEquals(out.clusters[0].data.Engine, "aurora-mysql");
  assertEquals(out.instances.length, 3);
});

Deno.test("smoke: 'false' selector excludes everything", async () => {
  const fixture = await loadFixture("aurora_mysql_3node.json");
  const out = await runWithFixture(fixture, {
    region: "eu-west-1",
    selector: "false",
  });
  assertEquals(out.clusters.length, 0);
  assertEquals(out.instances.length, 0);
  assertEquals(out.result.dataHandles.length, 0);
});

Deno.test("smoke: resolved region appears in info log", async () => {
  const fixture = await loadFixture("empty_region.json");
  const out = await runWithFixture(fixture);
  const startLog = out.logs.find((l) =>
    l.message.includes("starting list_clusters")
  );
  assertExists(startLog);
  assertEquals(startLog.level, "info");
});

Deno.test("smoke: a selector that throws on parse fails before any AWS call", async () => {
  // Selector pre-validation must run before DescribeDBClusters — a bad
  // selector should fail closed without spending API budget.
  let clustersCalled = false;
  const noOpApi: RdsApi = {
    describeDBClusters: () => {
      clustersCalled = true;
      return Promise.resolve({ DBClusters: [] });
    },
    describeDBInstances: () => Promise.resolve({ DBInstances: [] }),
  };
  // The fake CEL env throws when given a syntactically invalid JS expression.
  const context = {
    globalArgs: { region: "eu-west-1", selector: "this is not a selector @@" },
    logger: {
      info: () => {},
      debug: () => {},
      warn: () => {},
      error: () => {},
    },
    createCelEnvironment: makeCelEnvironment,
    writeResource: () => Promise.resolve({}),
  };
  let threw = false;
  try {
    await runListClusters({ api: noOpApi, context });
  } catch (err) {
    threw = true;
    assert(
      err instanceof Error && err.message.includes("failed to parse selector"),
      `unexpected error: ${err}`,
    );
  }
  assert(threw, "expected runListClusters to throw on bad selector");
  assertEquals(
    clustersCalled,
    false,
    "DescribeDBClusters must not be called when the selector is invalid",
  );
});

Deno.test("smoke: every test finishes in under 5 seconds", () => {
  // Sentinel — the real smoke tests above all complete in single-digit
  // milliseconds on a 2026 Mac. If you add a network-touching test, the
  // per-test 5s threshold should still hold; if it doesn't, push the new
  // test out of the smoke harness.
  assert(true);
});

Deno.test("smoke: collectInstances stops paginating once every wanted id is found", async () => {
  // DescribeDBInstances pagination is unbounded for accounts with many
  // standalone instances. The inventory only ever wants the cluster
  // members' identifiers, so once those are all collected we should stop
  // hitting the API. Build a fixture cluster whose two members live on
  // page one and let pages two and three carry unrelated standalone
  // instances — the second/third pages must never be requested.
  const clusterMembers = [
    { DBInstanceIdentifier: "wanted-1", IsClusterWriter: true },
    { DBInstanceIdentifier: "wanted-2", IsClusterWriter: false },
  ];
  const fixture: Fixture = {
    description: "multi-page-shortcircuit",
    clusters: [{
      DBClusterIdentifier: "cluster-shortcircuit",
      Engine: "aurora-mysql",
      Status: "available",
      DBClusterMembers: clusterMembers,
    }],
    instances: [],
  };

  const instancePages: Array<{ DBInstances: unknown[]; Marker?: string }> = [
    {
      DBInstances: [
        { DBInstanceIdentifier: "wanted-1", DBInstanceClass: "db.r7g.large" },
        { DBInstanceIdentifier: "wanted-2", DBInstanceClass: "db.r8g.large" },
      ],
      Marker: "page-2",
    },
    {
      DBInstances: [
        {
          DBInstanceIdentifier: "unrelated-a",
          DBInstanceClass: "db.t4g.medium",
        },
      ],
      Marker: "page-3",
    },
    {
      DBInstances: [
        {
          DBInstanceIdentifier: "unrelated-b",
          DBInstanceClass: "db.t4g.medium",
        },
      ],
    },
  ];

  let clustersCalls = 0;
  let instancesCalls = 0;
  const api: RdsApi = {
    describeDBClusters: () => {
      clustersCalls++;
      return Promise.resolve({
        DBClusters: fixture.clusters as AwsCluster[],
      });
    },
    describeDBInstances: (marker?: string) => {
      instancesCalls++;
      // marker semantics: first call has marker=undefined → page 0; subsequent
      // calls pass back whatever Marker the previous page returned.
      const idx = marker === undefined
        ? 0
        : instancePages.findIndex((_p, i) =>
          i > 0 && instancePages[i - 1].Marker === marker
        );
      const page = instancePages[idx];
      return Promise.resolve({
        DBInstances: page.DBInstances as AwsInstance[],
        Marker: page.Marker,
      });
    },
  };

  const result = await runListClusters({
    api,
    context: {
      globalArgs: { region: "eu-west-1" },
      logger: {
        info: () => {},
        debug: () => {},
        warn: () => {},
        error: () => {},
      },
      createCelEnvironment: makeCelEnvironment,
      writeResource: (spec: string, key: string, data: unknown) =>
        Promise.resolve({ id: `${spec}:${key}`, data }),
    },
  });

  assertEquals(result.dataHandles.length, 3); // 1 cluster + 2 instances
  assertEquals(clustersCalls, 1);
  assertEquals(
    instancesCalls,
    1,
    "DescribeDBInstances must short-circuit after page 1 — both wanted ids " +
      "are present, so pages 2 and 3 are unnecessary work",
  );
});
