/**
 * Smoke test for `@jentz/aws-rds-inventory-csv` — replays a recorded
 * workflow inventory through `report.execute` and asserts the CSV
 * output end-to-end. No filesystem mocks; a fake report context drives
 * `dataRepository.getContent` from an in-memory map.
 *
 * Fixture identifiers are anonymized (cluster-a..d, cluster-a-1..3, ...)
 * so the test corpus is safe to ship with a public extension.
 */

import {
  assert,
  assertEquals,
  assertStringIncludes,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import { report } from "../aws_rds_inventory_csv.ts";

// Clear any inherited override from the developer's or CI shell so the
// column-count assertions below don't flake on a non-default env value.
// The column-override test explicitly captures and restores this var
// inside its own try/finally; tests that do not touch it can rely on
// this module-scope reset.
Deno.env.delete("AWS_RDS_INVENTORY_CSV_COLUMNS");

interface ClusterFixture {
  specName: "cluster";
  handle: string;
  body: Record<string, unknown>;
}

interface InstanceFixture {
  specName: "instance";
  handle: string;
  body: Record<string, unknown>;
}

interface MalformedFixture {
  specName: "cluster" | "instance";
  handle: string;
  rawText: string;
}

interface Fixture {
  description: string;
  workflowName: string;
  modelId: string;
  clusterArtifacts: ClusterFixture[];
  instanceArtifacts: InstanceFixture[];
  malformedArtifact: MalformedFixture;
}

const ENCODER = new TextEncoder();

async function loadFixture(filename: string): Promise<Fixture> {
  const url = new URL(`./fixtures/${filename}`, import.meta.url);
  const text = await Deno.readTextFile(url);
  return JSON.parse(text);
}

interface CapturedLog {
  level: string;
  message: string;
  props?: Record<string, unknown>;
}

interface WorkflowHandle {
  name: string;
  version: number;
  metadata: { tags: { specName: string } };
}

// deno-lint-ignore no-explicit-any
function buildContext(fixture: Fixture): { context: any; logs: CapturedLog[] } {
  const logs: CapturedLog[] = [];
  const logger = {
    info: (msg: string, props?: Record<string, unknown>) =>
      logs.push({ level: "info", message: msg, props }),
    warn: (msg: string, props?: Record<string, unknown>) =>
      logs.push({ level: "warn", message: msg, props }),
    debug: (msg: string, props?: Record<string, unknown>) =>
      logs.push({ level: "debug", message: msg, props }),
    error: (msg: string, props?: Record<string, unknown>) =>
      logs.push({ level: "error", message: msg, props }),
  };

  const dataBytes = new Map<string, Uint8Array | null>();
  const handles: WorkflowHandle[] = [];
  for (const c of fixture.clusterArtifacts) {
    dataBytes.set(c.handle, ENCODER.encode(JSON.stringify(c.body)));
    handles.push({
      name: c.handle,
      version: 1,
      metadata: { tags: { specName: c.specName } },
    });
  }
  for (const i of fixture.instanceArtifacts) {
    dataBytes.set(i.handle, ENCODER.encode(JSON.stringify(i.body)));
    handles.push({
      name: i.handle,
      version: 1,
      metadata: { tags: { specName: i.specName } },
    });
  }
  const bad = fixture.malformedArtifact;
  dataBytes.set(bad.handle, ENCODER.encode(bad.rawText));
  handles.push({
    name: bad.handle,
    version: 1,
    metadata: { tags: { specName: bad.specName } },
  });

  const context = {
    logger,
    workflowName: fixture.workflowName,
    dataRepository: {
      getContent: (
        _type: string,
        _modelId: string,
        dataName: string,
        _version: number,
      ) => Promise.resolve(dataBytes.get(dataName) ?? null),
    },
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: fixture.modelId,
      dataHandles: handles,
    }],
  };
  return { context, logs };
}

// ---------------------------------------------------------------------------
// Smoke test
// ---------------------------------------------------------------------------

Deno.test("smoke: recorded workflow fixture renders complete CSV", async () => {
  const fixture = await loadFixture("workflow_inventory.json");
  const { context, logs } = buildContext(fixture);

  const start = performance.now();
  const result = await report.execute(context);
  const elapsedMs = performance.now() - start;

  // Per the v1.0 acceptance criteria the smoke test must complete in
  // under 5 seconds even with the full fixture replay.
  assert(elapsedMs < 5000, `smoke too slow: ${elapsedMs.toFixed(0)}ms`);

  // The report returns identical CSV in markdown (for `swamp report get`)
  // and json.csv (for machine consumers).
  assertEquals(typeof result.markdown, "string");
  assertEquals(result.markdown, result.json.csv);

  const lines = result.markdown.trim().split("\n");
  // 10 instance rows + 1 header
  assertEquals(lines.length, 11);
  assertEquals(
    lines[0],
    "cluster_id,instance_id,instance_class,role,az,engine,engine_version,tags",
  );

  // First data row is cluster-a's writer (writers come before readers).
  assertStringIncludes(lines[1], "cluster-a,cluster-a-1,db.r7g.large,writer,");

  // Spot-check that rows from every cluster appear.
  for (const id of ["cluster-a", "cluster-b", "cluster-c", "cluster-d"]) {
    assert(
      lines.some((l) => l.startsWith(`${id},`)),
      `expected at least one row for ${id}`,
    );
  }

  // Multi-AZ DB cluster (cluster-c) had three members with engine=mysql.
  const cluster_c_rows = lines.filter((l) => l.startsWith("cluster-c,"));
  assertEquals(cluster_c_rows.length, 3);
  for (const row of cluster_c_rows) {
    assertStringIncludes(row, ",mysql,");
  }

  // cluster-d's writer carries the multi-key tag set; verify keys are
  // alphabetically sorted in the JSON.
  const cluster_d_writer = lines.find((l) =>
    l.startsWith("cluster-d,cluster-d-1,")
  )!;
  assertStringIncludes(
    cluster_d_writer,
    '"{""Environment"":""prod"",""Owner"":""data-platform""}"',
  );

  // The malformed artifact triggered a warn-log without aborting.
  const malformedWarn = logs.find((l) =>
    l.level === "warn" && l.message.startsWith("Could not parse")
  );
  assert(
    malformedWarn,
    "expected a parse-failure warn for the malformed artifact",
  );

  // JSON metadata mirrors the body.
  assertEquals(result.json.rowCount, 10);
  assertEquals(result.json.clusterCount, 4);
  // Fixture has 4 cluster artifacts and 10 instances across 4 clusters,
  // so clusterArtifactCount and clusterCount agree — no partial failure.
  assertEquals(result.json.clusterArtifactCount, 4);
  assertEquals(result.json.skipped, 1);
  assertEquals(result.json.duplicates, 0);
  assertEquals(result.json.degraded, false);
  assertEquals(result.json.report, "@jentz/aws-rds-inventory-csv");
  assertEquals(result.json.workflow, "rds-inventory-smoke");
  assertEquals(result.json.columns.length, 8);
  // The generatedAt timestamp is computed inside the never-throws envelope.
  assertEquals(typeof result.json.generatedAt, "string");
  assert(result.json.generatedAt.length > 0, "generatedAt should be populated");
});

Deno.test("smoke: when dataRepository returns null for every instance handle, the report logs a swamp-runtime diagnostic instead of a misleading partial-failure warn", async () => {
  // Reproduces the failure mode from TASK-45 / GitHub issue: every
  // upstream instance handle is iterated but getContent returns null for
  // each. The upstream actually succeeded — the bytes are on disk and in
  // the catalog — but the workflow-scope report's dataRepository did not
  // return them. The diagnostic warn names the runtime issue and points
  // at the `swamp model create --global-arg` workaround.
  const warns: string[] = [];
  const context = {
    logger: {
      info: () => {},
      warn: (msg: string) => warns.push(msg),
      debug: () => {},
      error: () => {},
    },
    workflowName: "all-null-reads",
    dataRepository: { getContent: () => Promise.resolve(null) },
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "stale-model",
      modelName: "rds-inv",
      dataHandles: [
        {
          name: "cluster-cluster-a",
          version: 1,
          metadata: { tags: { specName: "cluster" } },
        },
        {
          name: "instance-cluster-a--inst-1",
          version: 1,
          metadata: { tags: { specName: "instance" } },
        },
        {
          name: "instance-cluster-a--inst-2",
          version: 1,
          metadata: { tags: { specName: "instance" } },
        },
      ],
    }],
  };
  const result = await report.execute(context);
  // CSV is header-only because no instance bodies could be decoded.
  assertEquals(result.json.rowCount, 0);
  assertEquals(result.json.skipped, 2);
  // The fresh diagnostic warn fires with the swamp-runtime + workaround text.
  const diagnostic = warns.find((w) =>
    w.includes("dataRepository returned no bytes") &&
    w.includes("swamp model create")
  );
  assert(
    diagnostic !== undefined,
    "expected the swamp-runtime diagnostic warn; got: " + warns.join("\n"),
  );
  // The misleading "partial upstream failure" warn must NOT fire here —
  // the upstream succeeded fully; reads from dataRepository are what
  // failed.
  const misleading = warns.find((w) => w.includes("partial upstream failure"));
  assertEquals(
    misleading,
    undefined,
    "the partial-upstream warn should be suppressed when every read returned null",
  );
});

Deno.test("smoke: workflow with no inventory step produces header-only CSV", async () => {
  const context = {
    logger: {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: () => {},
    },
    workflowName: "empty-workflow",
    dataRepository: { getContent: () => Promise.resolve(null) },
    stepExecutions: [{
      jobName: "other",
      stepName: "noop",
      modelType: "@swamp/other",
      modelId: "x",
      dataHandles: [],
    }],
  };
  const result = await report.execute(context);
  assertEquals(
    result.markdown.trim(),
    "cluster_id,instance_id,instance_class,role,az,engine,engine_version,tags",
  );
  assertEquals(result.json.rowCount, 0);
  assertEquals(result.json.clusterCount, 0);
});

Deno.test("smoke: column override via env var changes the output header", async () => {
  const restore = Deno.env.get("AWS_RDS_INVENTORY_CSV_COLUMNS");
  Deno.env.set(
    "AWS_RDS_INVENTORY_CSV_COLUMNS",
    "instance_id,cluster_id,instance_class",
  );
  try {
    const fixture = await loadFixture("workflow_inventory.json");
    const { context } = buildContext(fixture);
    const result = await report.execute(context);
    const header = result.markdown.split("\n")[0];
    assertEquals(header, "instance_id,cluster_id,instance_class");
    assertEquals(result.json.columns, [
      "instance_id",
      "cluster_id",
      "instance_class",
    ]);
  } finally {
    if (restore === undefined) {
      Deno.env.delete("AWS_RDS_INVENTORY_CSV_COLUMNS");
    } else {
      Deno.env.set("AWS_RDS_INVENTORY_CSV_COLUMNS", restore);
    }
  }
});

Deno.test("smoke: a logger that throws on every call does not break the report", async () => {
  // Per the never-throws contract, a host logger that raises on every
  // call must not escape execute. The dataHandles here include both a
  // valid instance and a malformed one, so the bare logger paths inside
  // collectInventory (decode warn, schema warn, summary info) actually
  // fire — proving tryLog's coverage in real conditions, not just on
  // an empty handle list.
  const explodingLogger = {
    info: () => {
      throw new Error("logger.info exploded");
    },
    warn: () => {
      throw new Error("logger.warn exploded");
    },
    debug: () => {
      throw new Error("logger.debug exploded");
    },
    error: () => {
      throw new Error("logger.error exploded");
    },
  };

  const validBody = {
    DBInstanceIdentifier: "inst-1",
    DBClusterIdentifier: "cluster-a",
    DBInstanceClass: "db.r7g.large",
    Role: "writer",
    AvailabilityZone: "eu-west-1a",
    Engine: "aurora-mysql",
    EngineVersion: "8.0",
    tags: {},
  };
  const validBytes = ENCODER.encode(JSON.stringify(validBody));
  const malformedBytes = ENCODER.encode("{not json");
  const dataMap = new Map<string, Uint8Array>([
    ["instance-cluster-a--inst-1", validBytes],
    ["instance-broken", malformedBytes],
  ]);

  const context = {
    logger: explodingLogger,
    workflowName: "wf-bad-logger",
    dataRepository: {
      getContent: (
        _type: string,
        _modelId: string,
        dataName: string,
      ) => Promise.resolve(dataMap.get(dataName) ?? null),
    },
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [
        {
          name: "instance-cluster-a--inst-1",
          version: 1,
          metadata: { tags: { specName: "instance" } },
        },
        {
          name: "instance-broken",
          version: 1,
          metadata: { tags: { specName: "instance" } },
        },
      ],
    }],
  };
  const result = await report.execute(context);
  // The valid instance survived the throwing-logger gauntlet — tryLog
  // swallowed the decode warn, the schema warn, and the summary info,
  // and collection still produced one row.
  assertEquals(result.json.rowCount, 1);
  assertEquals(result.json.skipped, 1);
  assertEquals(result.json.degraded, false);
});

Deno.test("smoke: dataRepository.getContent that rejects is caught and degrades", async () => {
  const context = {
    logger: {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: () => {},
    },
    workflowName: "wf-reject",
    dataRepository: {
      getContent: () => Promise.reject(new Error("connection reset")),
    },
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [{
        name: "instance-x",
        version: 1,
        metadata: { tags: { specName: "instance" } },
      }],
    }],
  };
  const result = await report.execute(context);
  assertEquals(result.json.rowCount, 0);
});

Deno.test("smoke: getContent returning null for a matching handle is treated as a missing-bytes skip", async () => {
  const logs: CapturedLog[] = [];
  const context = {
    logger: {
      info: (m: string, p?: Record<string, unknown>) =>
        logs.push({ level: "info", message: m, props: p }),
      warn: (m: string, p?: Record<string, unknown>) =>
        logs.push({ level: "warn", message: m, props: p }),
      debug: () => {},
      error: () => {},
    },
    workflowName: "wf-null-content",
    dataRepository: { getContent: () => Promise.resolve(null) },
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [{
        name: "instance-x",
        version: 1,
        metadata: { tags: { specName: "instance" } },
      }],
    }],
  };
  const result = await report.execute(context);
  assertEquals(result.json.skipped, 1);
  assertEquals(result.json.rowCount, 0);
  // Distinct from the parse-failure warn — operator can tell datastore
  // miss apart from upstream-malformed JSON.
  const warn = logs.find((l) =>
    l.level === "warn" && l.message.startsWith("No bytes for")
  );
  assert(warn, "expected a missing-bytes warn");
});

Deno.test("smoke: handle.specName fallback is honored when metadata.tags is missing", async () => {
  // Older / forked upstreams might surface specName directly on the
  // handle instead of nested under metadata.tags. Cover that shape.
  const body = {
    DBInstanceIdentifier: "inst-1",
    DBClusterIdentifier: "cluster-a",
    DBInstanceClass: "db.r7g.large",
    Role: "writer",
    AvailabilityZone: "eu-west-1a",
    Engine: "aurora-mysql",
    EngineVersion: "8.0",
    tags: {},
  };
  const bytes = ENCODER.encode(JSON.stringify(body));
  const context = {
    logger: {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: () => {},
    },
    workflowName: "wf-alt-shape",
    dataRepository: { getContent: () => Promise.resolve(bytes) },
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      // Top-level specName, no metadata.tags.
      dataHandles: [{
        name: "instance-cluster-a--inst-1",
        version: 1,
        specName: "instance",
      }],
    }],
  };
  const result = await report.execute(context);
  assertEquals(result.json.rowCount, 1);
});

Deno.test("smoke: a thrown collector failure is caught and degrades with degraded=true", async () => {
  // Force collectInventory's per-artifact catch to miss by giving back a
  // dataRepository that throws on getContent. The execute-level catch
  // is the last-resort never-throws guarantee.
  const context = {
    logger: {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: () => {},
    },
    workflowName: "wf-error",
    dataRepository: {
      getContent: () => {
        throw new Error("simulated repo failure");
      },
    },
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [{
        name: "instance-x",
        version: 1,
        metadata: { tags: { specName: "instance" } },
      }],
    }],
  };
  const result = await report.execute(context);
  // Header-only CSV, no rows. `degraded` flag is the signal operators
  // should key automation off when the CSV body is empty for unexpected
  // reasons.
  assertEquals(result.markdown.split("\n").length, 2);
  assertEquals(result.json.rowCount, 0);
  assertEquals(result.json.degraded, true);
});

Deno.test("smoke: cluster artifact without matching instances surfaces as clusterArtifactCount > clusterCount", async () => {
  // Partial upstream failure: cluster artifact written but
  // DescribeDBInstances failed → no instance artifact for that cluster.
  const validBody = {
    DBInstanceIdentifier: "inst-1",
    DBClusterIdentifier: "cluster-a",
    DBInstanceClass: "db.r7g.large",
    Role: "writer",
    AvailabilityZone: "eu-west-1a",
    Engine: "aurora-mysql",
    EngineVersion: "8.0",
    tags: {},
  };
  const validBytes = ENCODER.encode(JSON.stringify(validBody));
  const logs: CapturedLog[] = [];

  const context = {
    logger: {
      info: (m: string, p?: Record<string, unknown>) =>
        logs.push({ level: "info", message: m, props: p }),
      warn: (m: string, p?: Record<string, unknown>) =>
        logs.push({ level: "warn", message: m, props: p }),
      debug: () => {},
      error: () => {},
    },
    workflowName: "wf-partial",
    dataRepository: {
      getContent: (
        _type: string,
        _modelId: string,
        dataName: string,
      ) =>
        Promise.resolve(
          dataName === "instance-cluster-a--inst-1" ? validBytes : null,
        ),
    },
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [
        // cluster-a has an instance.
        {
          name: "cluster-cluster-a",
          version: 1,
          metadata: { tags: { specName: "cluster" } },
        },
        {
          name: "instance-cluster-a--inst-1",
          version: 1,
          metadata: { tags: { specName: "instance" } },
        },
        // cluster-b has NO instance (partial failure).
        {
          name: "cluster-cluster-b",
          version: 1,
          metadata: { tags: { specName: "cluster" } },
        },
      ],
    }],
  };
  const result = await report.execute(context);
  assertEquals(result.json.rowCount, 1);
  assertEquals(result.json.clusterCount, 1);
  assertEquals(result.json.clusterArtifactCount, 2);
  const warn = logs.find((l) =>
    l.level === "warn" && l.message.startsWith("Upstream wrote")
  );
  assert(warn, "expected a partial-failure warn");
});
