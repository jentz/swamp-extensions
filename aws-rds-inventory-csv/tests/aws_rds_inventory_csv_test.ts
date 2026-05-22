/**
 * Unit tests for `@jentz/aws-rds-inventory-csv`.
 *
 * Pure data-shaping tests — no swamp runtime, no real network. Fixtures
 * are constructed inline with generic identifiers (cluster-a, inst-1, ...)
 * so the test corpus is safe to ship with a public extension.
 */

import {
  assert,
  assertEquals,
  assertStringIncludes,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import {
  collectInventory,
  COLUMNS_ENV,
  csvField,
  DEFAULT_COLUMNS,
  type Instance,
  renderCsv,
  resolveColumns,
  stableTagJson,
} from "../aws_rds_inventory_csv.ts";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

interface CapturedLog {
  level: "info" | "warn" | "debug" | "error";
  message: string;
  props?: Record<string, unknown>;
}

function makeLogger(): {
  // deno-lint-ignore no-explicit-any
  logger: any;
  logs: CapturedLog[];
} {
  const logs: CapturedLog[] = [];
  const logger = {
    info: (message: string, props?: Record<string, unknown>) =>
      logs.push({ level: "info", message, props }),
    warn: (message: string, props?: Record<string, unknown>) =>
      logs.push({ level: "warn", message, props }),
    debug: (message: string, props?: Record<string, unknown>) =>
      logs.push({ level: "debug", message, props }),
    error: (message: string, props?: Record<string, unknown>) =>
      logs.push({ level: "error", message, props }),
  };
  return { logger, logs };
}

const ENCODER = new TextEncoder();

interface StoredArtifact {
  modelType: string;
  modelId: string;
  dataName: string;
  version: number;
  bytes: Uint8Array | null;
}

interface FakeRepo {
  dataRepository: {
    getContent: (
      type: string,
      modelId: string,
      dataName: string,
      version: number,
    ) => Promise<Uint8Array | null>;
  };
}

function makeRepo(artifacts: StoredArtifact[]): FakeRepo {
  return {
    dataRepository: {
      getContent: (type, modelId, dataName, version) => {
        const found = artifacts.find((a) =>
          a.modelType === type && a.modelId === modelId &&
          a.dataName === dataName && a.version === version
        );
        return Promise.resolve(found?.bytes ?? null);
      },
    },
  };
}

function instance(
  clusterId: string,
  instanceId: string,
  overrides: Partial<Instance> = {},
): Instance {
  return {
    DBInstanceIdentifier: instanceId,
    DBClusterIdentifier: clusterId,
    DBInstanceClass: overrides.DBInstanceClass ?? "db.r8g.large",
    Role: overrides.Role ?? "reader",
    AvailabilityZone: overrides.AvailabilityZone ?? "eu-west-1a",
    Engine: overrides.Engine ?? "aurora-mysql",
    EngineVersion: overrides.EngineVersion ?? "8.0.mysql_aurora.3.08.2",
    Status: overrides.Status,
    tags: overrides.tags ?? {},
  };
}

function stepArtifact(
  spec: "instance",
  name: string,
  body: unknown,
  version: number = 1,
): {
  handle: {
    name: string;
    version: number;
    metadata: { tags: { specName: string } };
  };
  stored: StoredArtifact;
} {
  const bytes = body === null
    ? null
    : ENCODER.encode(typeof body === "string" ? body : JSON.stringify(body));
  return {
    handle: { name, version, metadata: { tags: { specName: spec } } },
    stored: {
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataName: name,
      version,
      bytes,
    },
  };
}

// ---------------------------------------------------------------------------
// csvField
// ---------------------------------------------------------------------------

Deno.test("csvField passes through values without special characters", () => {
  assertEquals(csvField("simple"), "simple");
  assertEquals(csvField("db.r7g.large"), "db.r7g.large");
});

Deno.test("csvField wraps and escapes commas, quotes, and newlines", () => {
  assertEquals(csvField("a,b"), '"a,b"');
  assertEquals(csvField('he said "hi"'), '"he said ""hi"""');
  assertEquals(csvField("line\nbreak"), '"line\nbreak"');
  assertEquals(csvField("carriage\rreturn"), '"carriage\rreturn"');
});

// ---------------------------------------------------------------------------
// stableTagJson
// ---------------------------------------------------------------------------

Deno.test("stableTagJson sorts keys for deterministic output", () => {
  const a = stableTagJson({ Environment: "prod", CostCenter: "platform" });
  const b = stableTagJson({ CostCenter: "platform", Environment: "prod" });
  assertEquals(a, b);
  assertEquals(a, '{"CostCenter":"platform","Environment":"prod"}');
});

Deno.test("stableTagJson handles empty tags", () => {
  assertEquals(stableTagJson({}), "{}");
});

// ---------------------------------------------------------------------------
// renderCsv
// ---------------------------------------------------------------------------

Deno.test("renderCsv: empty input produces header-only CSV", () => {
  const out = renderCsv([]);
  assertEquals(
    out,
    "cluster_id,instance_id,instance_class,role,az,engine,engine_version,tags\n",
  );
});

Deno.test("renderCsv: single cluster writer-then-reader ordering", () => {
  const out = renderCsv([
    instance("cluster-a", "inst-2", { Role: "reader" }),
    instance("cluster-a", "inst-3", { Role: "reader" }),
    instance("cluster-a", "inst-1", { Role: "writer" }),
  ]);
  const rows = out.trim().split("\n").slice(1);
  assertEquals(rows.length, 3);
  // Writer first, then readers in id order.
  assertEquals(rows[0].startsWith("cluster-a,inst-1,"), true);
  assertEquals(rows[1].startsWith("cluster-a,inst-2,"), true);
  assertEquals(rows[2].startsWith("cluster-a,inst-3,"), true);
});

Deno.test("renderCsv: multi-cluster ordering sorts by cluster id first", () => {
  const out = renderCsv([
    instance("cluster-b", "inst-x", { Role: "writer" }),
    instance("cluster-a", "inst-y", { Role: "writer" }),
  ]);
  const rows = out.trim().split("\n").slice(1);
  assertEquals(rows[0].startsWith("cluster-a,"), true);
  assertEquals(rows[1].startsWith("cluster-b,"), true);
});

Deno.test("renderCsv: tag column is deterministic JSON with sorted keys", () => {
  const out = renderCsv([
    instance("cluster-a", "inst-1", {
      Role: "writer",
      tags: { Owner: "team", App: "store" },
    }),
  ]);
  const row = out.trim().split("\n")[1];
  // The tag JSON contains double quotes, so the whole field is RFC-4180
  // wrapped and the internal quotes are doubled.
  assertStringIncludes(row, '"{""App"":""store"",""Owner"":""team""}"');
});

Deno.test("renderCsv: special chars in identifiers are RFC 4180-escaped", () => {
  // AWS does not allow commas/quotes in identifiers, but the renderer
  // must defend against the case anyway — a forked extension or a
  // hand-crafted fixture could feed surprising input.
  const out = renderCsv([
    instance("clu,ster", 'in"st', { Role: "writer" }),
  ]);
  const row = out.trim().split("\n")[1];
  assertStringIncludes(row, '"clu,ster"');
  assertStringIncludes(row, '"in""st"');
});

Deno.test("renderCsv: column override changes header and row contents", () => {
  const out = renderCsv(
    [
      instance("cluster-a", "inst-1", {
        Role: "writer",
        AvailabilityZone: "eu-west-1a",
      }),
    ],
    { columns: ["instance_id", "cluster_id", "az"] },
  );
  const [header, row] = out.trim().split("\n");
  assertEquals(header, "instance_id,cluster_id,az");
  assertEquals(row, "inst-1,cluster-a,eu-west-1a");
});

Deno.test("renderCsv: writers from different clusters are interleaved by cluster id", () => {
  const out = renderCsv([
    instance("cluster-b", "inst-w", { Role: "writer" }),
    instance("cluster-a", "inst-r", { Role: "reader" }),
    instance("cluster-a", "inst-w", { Role: "writer" }),
  ]);
  const rows = out.trim().split("\n").slice(1);
  // cluster-a's writer first, then cluster-a's reader, then cluster-b's writer.
  assertEquals(rows[0].startsWith("cluster-a,inst-w,"), true);
  assertEquals(rows[1].startsWith("cluster-a,inst-r,"), true);
  assertEquals(rows[2].startsWith("cluster-b,inst-w,"), true);
});

// ---------------------------------------------------------------------------
// resolveColumns
// ---------------------------------------------------------------------------

Deno.test("resolveColumns: undefined returns the default list", () => {
  assertEquals(resolveColumns(undefined), [...DEFAULT_COLUMNS]);
});

Deno.test("resolveColumns: empty string returns defaults", () => {
  assertEquals(resolveColumns(""), [...DEFAULT_COLUMNS]);
  assertEquals(resolveColumns("   "), [...DEFAULT_COLUMNS]);
});

Deno.test("resolveColumns: subset is returned in the requested order", () => {
  assertEquals(
    resolveColumns("instance_id,cluster_id,az"),
    ["instance_id", "cluster_id", "az"],
  );
});

Deno.test("resolveColumns: unknown names warn and are skipped", () => {
  const { logger, logs } = makeLogger();
  const out = resolveColumns("instance_id,bogus,role,nope", logger);
  assertEquals(out, ["instance_id", "role"]);
  const warn = logs.find((l) => l.level === "warn");
  assert(warn, "expected a warn log");
  // Swamp uses structured placeholders; the env name lands in props.
  assertEquals(warn.props?.env, COLUMNS_ENV);
  const unknown = String(warn.props?.unknown ?? "");
  assertStringIncludes(unknown, "bogus");
  assertStringIncludes(unknown, "nope");
});

Deno.test("resolveColumns: all-unknown input falls back to defaults with explicit warn", () => {
  const { logger, logs } = makeLogger();
  const out = resolveColumns("foo,bar,baz", logger);
  assertEquals(out, [...DEFAULT_COLUMNS]);
  // Two warns: the unknown-list, then an explicit fallback notice so the
  // operator who asked for a narrow CSV isn't silently given the full
  // 8-column default set.
  const warns = logs.filter((l) => l.level === "warn");
  assertEquals(warns.length, 2);
  assertStringIncludes(warns[0].message, "Ignoring unknown column(s)");
  assertStringIncludes(warns[1].message, "resolved to zero recognized columns");
});

Deno.test("resolveColumns: duplicates in input are de-duplicated", () => {
  const out = resolveColumns("role,role,role");
  assertEquals(out, ["role"]);
});

// ---------------------------------------------------------------------------
// collectInventory
// ---------------------------------------------------------------------------

Deno.test("collectInventory: happy path collects every instance artifact", async () => {
  const i1 = stepArtifact(
    "instance",
    "instance-cluster-a--inst-1",
    instance("cluster-a", "inst-1", { Role: "writer" }),
  );
  const i2 = stepArtifact(
    "instance",
    "instance-cluster-a--inst-2",
    instance("cluster-a", "inst-2", { Role: "reader" }),
  );
  const i3 = stepArtifact(
    "instance",
    "instance-cluster-b--inst-1",
    instance("cluster-b", "inst-1", { Role: "writer" }),
  );

  const { logger, logs } = makeLogger();
  const context = {
    ...makeRepo([i1.stored, i2.stored, i3.stored]),
    logger,
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [i1.handle, i2.handle, i3.handle],
    }],
  };
  const result = await collectInventory(context);
  assertEquals(result.instances.length, 3);
  assertEquals(result.skipped, 0);
  const summary = logs.find((l) =>
    l.message.startsWith("Collected") && l.level === "info"
  );
  assert(summary, "expected an info summary log");
});

Deno.test("collectInventory: malformed JSON in one artifact warns and skips", async () => {
  const good = stepArtifact(
    "instance",
    "instance-cluster-a--inst-1",
    instance("cluster-a", "inst-1", { Role: "writer" }),
  );
  const bad = stepArtifact("instance", "instance-broken", "not valid json {");
  const { logger, logs } = makeLogger();
  const context = {
    ...makeRepo([good.stored, bad.stored]),
    logger,
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [good.handle, bad.handle],
    }],
  };
  const result = await collectInventory(context);
  assertEquals(result.instances.length, 1);
  assertEquals(result.skipped, 1);
  // Parse failure now logs a distinct message from "no bytes" so operators
  // can tell upstream-malformed-JSON apart from a missing artifact.
  const warn = logs.find((l) =>
    l.level === "warn" && l.message.startsWith("Could not parse")
  );
  assert(warn, "expected a parse-failure warning");
});

Deno.test("collectInventory: null bytes for a matching handle log distinct from parse failure", async () => {
  const nullHandle = {
    name: "instance-cluster-a--inst-1",
    version: 1,
    metadata: { tags: { specName: "instance" } },
  };
  const { logger, logs } = makeLogger();
  const context = {
    dataRepository: {
      getContent: () => Promise.resolve(null),
    },
    logger,
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [nullHandle],
    }],
  };
  const result = await collectInventory(context);
  assertEquals(result.instances.length, 0);
  assertEquals(result.skipped, 1);
  const warn = logs.find((l) =>
    l.level === "warn" && l.message.startsWith("No bytes for")
  );
  assert(warn, "expected a missing-bytes warning");
});

Deno.test("collectInventory: missing upstream step returns empty inventory", async () => {
  const { logger } = makeLogger();
  const context = {
    ...makeRepo([]),
    logger,
    stepExecutions: [{
      jobName: "other",
      stepName: "noop",
      modelType: "@swamp/other",
      modelId: "x",
      dataHandles: [],
    }],
  };
  const result = await collectInventory(context);
  assertEquals(result.instances.length, 0);
  assertEquals(result.skipped, 0);
});

Deno.test("collectInventory: zod validation failure warns and skips", async () => {
  // Drop required fields to fail the schema.
  const invalid = stepArtifact("instance", "instance-broken", {
    DBInstanceIdentifier: "x",
  });
  const { logger, logs } = makeLogger();
  const context = {
    ...makeRepo([invalid.stored]),
    logger,
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [invalid.handle],
    }],
  };
  const result = await collectInventory(context);
  assertEquals(result.instances.length, 0);
  assertEquals(result.skipped, 1);
  const warn = logs.find((l) =>
    l.level === "warn" && l.message.includes("schema validation")
  );
  assert(warn, "expected a schema-validation warning");
});

Deno.test("collectInventory: empty stepExecutions does not throw", async () => {
  const { logger } = makeLogger();
  const context = {
    ...makeRepo([]),
    logger,
    stepExecutions: [],
  };
  const result = await collectInventory(context);
  assertEquals(result.instances.length, 0);
});

Deno.test("collectInventory: cluster artifacts contribute to clusterArtifactIds only", async () => {
  // The inventory model writes cluster + instance + csv handles. Cluster
  // handles are counted (so partial-failure clusters surface in JSON)
  // but not decoded. csv handles and any other spec are silently skipped.
  const csvHandle = {
    name: "main",
    version: 1,
    metadata: { tags: { specName: "csv" } },
  };
  const clusterHandleA = {
    name: "cluster-cluster-a",
    version: 1,
    metadata: { tags: { specName: "cluster" } },
  };
  const clusterHandleB = {
    name: "cluster-cluster-b",
    version: 1,
    metadata: { tags: { specName: "cluster" } },
  };
  const i1 = stepArtifact(
    "instance",
    "instance-cluster-a--inst-1",
    instance("cluster-a", "inst-1", { Role: "writer" }),
  );
  const { logger } = makeLogger();
  const context = {
    ...makeRepo([i1.stored]),
    logger,
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [csvHandle, clusterHandleA, clusterHandleB, i1.handle],
    }],
  };
  const result = await collectInventory(context);
  assertEquals(result.instances.length, 1);
  assertEquals(result.skipped, 0);
  // Both cluster handle names were recorded — even though only cluster-a
  // has an instance row, cluster-b will surface as a partial-failure
  // signal via clusterArtifactCount > clusterCount at the execute level.
  assertEquals(result.clusterArtifactIds.size, 2);
  assert(result.clusterArtifactIds.has("cluster-cluster-a"));
  assert(result.clusterArtifactIds.has("cluster-cluster-b"));
});

Deno.test("collectInventory: duplicate (cluster_id, instance_id) artifacts dedupe with last-wins", async () => {
  // Same identity from two retried writes — keep one row, count one
  // duplicate, log a warn. Mirrors what an upstream retry path can do.
  const first = stepArtifact(
    "instance",
    "instance-cluster-a--inst-1",
    instance("cluster-a", "inst-1", {
      Role: "writer",
      DBInstanceClass: "db.r7g.large",
    }),
    1,
  );
  const second = stepArtifact(
    "instance",
    "instance-cluster-a--inst-1-rev2",
    instance("cluster-a", "inst-1", {
      Role: "writer",
      DBInstanceClass: "db.r8g.large",
    }),
    1,
  );
  const { logger, logs } = makeLogger();
  const context = {
    ...makeRepo([first.stored, second.stored]),
    logger,
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [first.handle, second.handle],
    }],
  };
  const result = await collectInventory(context);
  assertEquals(result.instances.length, 1);
  assertEquals(result.duplicates, 1);
  assertEquals(result.instances[0].DBInstanceClass, "db.r8g.large");
  const warn = logs.find((l) =>
    l.level === "warn" && l.message.startsWith("Duplicate instance")
  );
  assert(warn, "expected a duplicate-instance warning");
});

Deno.test("collectInventory: warns when stepExecutions had steps but none matched the inventory modelType", async () => {
  const { logger, logs } = makeLogger();
  const context = {
    ...makeRepo([]),
    logger,
    stepExecutions: [
      {
        jobName: "guard",
        stepName: "verify",
        modelType: "@jentz/aws-context-guard",
        modelId: "g",
        dataHandles: [],
      },
      {
        jobName: "other",
        stepName: "noop",
        modelType: "@swamp/some-other-model",
        modelId: "x",
        dataHandles: [],
      },
    ],
  };
  const result = await collectInventory(context);
  assertEquals(result.instances.length, 0);
  const warn = logs.find((l) =>
    l.level === "warn" && l.message.startsWith("No step matched modelType")
  );
  assert(warn, "expected a no-matching-step warning");
  const observed = String(warn?.props?.observed ?? "");
  assertStringIncludes(observed, "@jentz/aws-context-guard");
  assertStringIncludes(observed, "@swamp/some-other-model");
});

Deno.test("collectInventory: throwing logger does NOT abort collection (tryLog swallows)", async () => {
  // The exploding-logger smoke test in the smoke suite covers the
  // execute-level path; this unit test pins the contract that
  // collectInventory itself does not propagate logger exceptions even
  // when dataHandles is populated.
  const i1 = stepArtifact(
    "instance",
    "instance-cluster-a--inst-1",
    instance("cluster-a", "inst-1", { Role: "writer" }),
  );
  const bad = stepArtifact("instance", "instance-broken", "{not json");
  const explodingLogger = {
    info: () => {
      throw new Error("logger.info boom");
    },
    warn: () => {
      throw new Error("logger.warn boom");
    },
    debug: () => {},
    error: () => {},
  };
  const context = {
    ...makeRepo([i1.stored, bad.stored]),
    logger: explodingLogger,
    stepExecutions: [{
      jobName: "inventory",
      stepName: "list_clusters",
      modelType: "@jentz/aws-rds-inventory",
      modelId: "inv-1",
      dataHandles: [i1.handle, bad.handle],
    }],
  };
  const result = await collectInventory(context);
  // The good instance survived even though the malformed one triggered
  // a logger.warn that threw — proving the contract.
  assertEquals(result.instances.length, 1);
  assertEquals(result.skipped, 1);
});
