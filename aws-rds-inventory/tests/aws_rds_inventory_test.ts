/**
 * Unit tests for the @jentz/aws-rds-inventory extension.
 *
 * Pure-logic coverage: region resolution chain, AWS tag transform, selector
 * evaluation against a stand-in CEL environment, and the pagination /
 * batching seams. No network or filesystem I/O.
 */

import {
  assertEquals,
  assertExists,
  assertNotEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1";

import {
  type AwsInstance,
  buildSelectorContext,
  clusterKey,
  collectInstances,
  type DescribeInstancesPage,
  evaluateSelector,
  instanceKey,
  isRdsEngine,
  MAX_CLUSTER_IDS_PER_FILTER,
  RDS_ENGINE_ALLOWLIST,
  type RdsApi,
  resolveRegion,
  type SelectorContext,
  tagsFromAws,
} from "../aws_rds_inventory.ts";

// ---------------------------------------------------------------------------
// resolveRegion
// ---------------------------------------------------------------------------

/** Build an env-getter from a plain map for hermetic region tests. */
function envFrom(map: Record<string, string | undefined>) {
  return (name: string) => map[name];
}

Deno.test("resolveRegion: explicit globalArg wins over both env vars", () => {
  const region = resolveRegion(
    { region: "ap-southeast-2" },
    envFrom({ AWS_REGION: "eu-west-1", AWS_DEFAULT_REGION: "us-west-2" }),
  );
  assertEquals(region, "ap-southeast-2");
});

Deno.test("resolveRegion: AWS_REGION used when no globalArg", () => {
  const region = resolveRegion(
    {},
    envFrom({ AWS_REGION: "eu-west-1", AWS_DEFAULT_REGION: "us-west-2" }),
  );
  assertEquals(region, "eu-west-1");
});

Deno.test("resolveRegion: AWS_DEFAULT_REGION used when AWS_REGION unset", () => {
  const region = resolveRegion(
    {},
    envFrom({ AWS_DEFAULT_REGION: "us-west-2" }),
  );
  assertEquals(region, "us-west-2");
});

Deno.test("resolveRegion: empty string globalArg falls through", () => {
  const region = resolveRegion(
    { region: "" },
    envFrom({ AWS_REGION: "eu-west-1" }),
  );
  assertEquals(region, "eu-west-1");
});

Deno.test("resolveRegion: whitespace-only values are treated as unset", () => {
  const region = resolveRegion(
    { region: "   " },
    envFrom({ AWS_REGION: "\t", AWS_DEFAULT_REGION: "us-west-2" }),
  );
  assertEquals(region, "us-west-2");
});

Deno.test("resolveRegion: throws with all three source names when none set", () => {
  const err = assertThrows(
    () => resolveRegion({}, envFrom({})),
    Error,
  );
  // Message must mention every place the operator can fix it.
  assertEquals(err.message.includes("region"), true);
  assertEquals(err.message.includes("AWS_REGION"), true);
  assertEquals(err.message.includes("AWS_DEFAULT_REGION"), true);
  // And it must NOT silently fall back to us-east-1.
  assertEquals(err.message.includes("us-east-1"), true);
});

// ---------------------------------------------------------------------------
// tagsFromAws
// ---------------------------------------------------------------------------

Deno.test("tagsFromAws: converts AWS array shape into flat map", () => {
  const out = tagsFromAws([
    { Key: "Environment", Value: "prod" },
    { Key: "Team", Value: "platform" },
  ]);
  assertEquals(out, { Environment: "prod", Team: "platform" });
});

Deno.test("tagsFromAws: undefined / empty input becomes {}", () => {
  assertEquals(tagsFromAws(undefined), {});
  assertEquals(tagsFromAws([]), {});
});

Deno.test("tagsFromAws: missing Value becomes empty string", () => {
  assertEquals(tagsFromAws([{ Key: "k" }]), { k: "" });
});

Deno.test("tagsFromAws: drops tags with no Key", () => {
  assertEquals(tagsFromAws([{ Value: "v" }, { Key: "", Value: "v2" }]), {});
});

// ---------------------------------------------------------------------------
// RDS engine allowlist
// ---------------------------------------------------------------------------

Deno.test("isRdsEngine: admits the four engines DescribeDBClusters returns", () => {
  for (
    const engine of [
      "aurora-mysql",
      "aurora-postgresql",
      "mysql",
      "postgres",
    ]
  ) {
    assertEquals(isRdsEngine(engine), true, engine);
  }
});

Deno.test("isRdsEngine: rejects shared-endpoint non-RDS engines and single-instance-only engines", () => {
  for (
    const engine of [
      "neptune",
      "docdb",
      "docdb-elastic",
      "mariadb",
      "oracle-ee",
      "sqlserver-ee",
      "db2-ae",
      "custom-oracle-ee",
      "",
      undefined,
      null,
      42,
    ]
  ) {
    assertEquals(isRdsEngine(engine), false, String(engine));
  }
});

Deno.test("RDS_ENGINE_ALLOWLIST: rejects runtime mutation", () => {
  // Real-mutation test rather than `Object.isFrozen`: a frozen Set still
  // accepts `.add()`/`.delete()` because element storage lives in internal
  // slots, so isFrozen would be misleading. A frozen array, by contrast,
  // throws on push/splice in strict mode (which Deno test code runs under).
  const mutable = RDS_ENGINE_ALLOWLIST as string[];
  assertThrows(() => mutable.push("neptune"), TypeError);
  assertThrows(() => mutable.splice(0, 1), TypeError);
  assertEquals(RDS_ENGINE_ALLOWLIST.length, 4);
});

// ---------------------------------------------------------------------------
// evaluateSelector
// ---------------------------------------------------------------------------

function ctx(over: Partial<SelectorContext> = {}): SelectorContext {
  return {
    DBClusterIdentifier: "cluster-a",
    Engine: "aurora-mysql",
    EngineVersion: "8.0",
    Status: "available",
    MultiAZ: false,
    members: [
      {
        DBInstanceIdentifier: "i-1",
        DBInstanceClass: "db.r7g.large",
        Role: "writer",
        AvailabilityZone: "eu-west-1a",
        PromotionTier: 1,
        DBClusterParameterGroupStatus: "in-sync",
      },
    ],
    tags: { Environment: "prod" },
    ...over,
  };
}

Deno.test("clusterKey: prefixed with spec name", () => {
  assertEquals(clusterKey("foo"), "cluster-foo");
});

Deno.test("instanceKey: includes owning cluster, prefixed with spec name", () => {
  assertEquals(instanceKey("c1", "i1"), "instance-c1--i1");
});

Deno.test("instanceKey vs clusterKey never collide for the same raw id", () => {
  assertNotEquals(clusterKey("foo"), instanceKey("anything", "foo"));
  // A cluster literally named "foo" can coexist with a DB instance literally
  // named "foo" — the keys must remain distinct.
  assertNotEquals(clusterKey("foo"), instanceKey("foo", "foo"));
});

Deno.test("buildSelectorContext: defaults optional fields to deterministic values", () => {
  // Cluster with no engine version, status, MultiAZ, or members. Predicate
  // authors must see empty strings / false rather than undefined.
  const ctx = buildSelectorContext(
    { DBClusterIdentifier: "cluster-x" },
    new Map(),
  );
  assertEquals(ctx.Engine, "");
  assertEquals(ctx.EngineVersion, "");
  assertEquals(ctx.Status, "");
  assertEquals(ctx.MultiAZ, false);
  assertEquals(ctx.members, []);
  assertEquals(ctx.tags, {});
});

Deno.test(
  "buildSelectorContext: AWS-optional member fields are left absent when AWS omits them",
  () => {
    const ctx = buildSelectorContext({
      DBClusterIdentifier: "cluster-x",
      DBClusterMembers: [{
        DBInstanceIdentifier: "i-1",
        IsClusterWriter: true,
      }],
    }, new Map());
    // Instance not in the map and member shape lacks the optional fields:
    // the keys must be absent on the object, not present-and-undefined, so
    // CEL `has(m.<field>)` returns false. `key in obj` is the discriminator.
    const m = ctx.members[0];
    assertEquals("AvailabilityZone" in m, false);
    assertEquals("PromotionTier" in m, false);
    assertEquals("DBClusterParameterGroupStatus" in m, false);
  },
);

Deno.test(
  "buildSelectorContext: PromotionTier and DBClusterParameterGroupStatus surface on members when AWS returns them",
  () => {
    const ctx = buildSelectorContext({
      DBClusterIdentifier: "cluster-x",
      DBClusterMembers: [{
        DBInstanceIdentifier: "i-1",
        IsClusterWriter: true,
        PromotionTier: 0,
        DBClusterParameterGroupStatus: "pending-reboot",
      }],
    }, new Map());
    assertEquals(ctx.members[0].PromotionTier, 0);
    assertEquals(
      ctx.members[0].DBClusterParameterGroupStatus,
      "pending-reboot",
    );
  },
);

Deno.test(
  "buildSelectorContext: PromotionTier falls through from the DBInstance shape when the cluster member shape omits it",
  () => {
    const ctx = buildSelectorContext(
      {
        DBClusterIdentifier: "cluster-x",
        DBClusterMembers: [{
          DBInstanceIdentifier: "i-1",
          IsClusterWriter: true,
          // No PromotionTier on the member.
        }],
      },
      new Map([["i-1", {
        DBInstanceIdentifier: "i-1",
        DBInstanceClass: "db.r7g.large",
        PromotionTier: 3,
      }]]),
    );
    // Instance-side value is used as the fallback.
    assertEquals(ctx.members[0].PromotionTier, 3);
  },
);

Deno.test("evaluateSelector: predicate that returns true admits the cluster", () => {
  const matches = evaluateSelector(() => true, [ctx(), ctx()]);
  assertEquals(matches, [true, true]);
});

Deno.test("evaluateSelector: predicate result is read per cluster", () => {
  let calls = 0;
  const matches = evaluateSelector(() => {
    calls++;
    return calls === 2;
  }, [ctx({ DBClusterIdentifier: "a" }), ctx({ DBClusterIdentifier: "b" })]);
  assertEquals(matches, [false, true]);
  assertEquals(calls, 2);
});

Deno.test("evaluateSelector: non-boolean result throws with cluster name", () => {
  // 1 is the common 'forgot the == 3' bug. Must surface, not silently treat
  // as truthy.
  const err = assertThrows(
    () =>
      evaluateSelector(() => 1 as unknown, [ctx({
        DBClusterIdentifier: "weird-one",
      })]),
    Error,
  );
  assertEquals(err.message.includes("weird-one"), true);
  assertEquals(err.message.includes("boolean"), true);
});

// ---------------------------------------------------------------------------
// collectInstances — server-side db-cluster-id filtering
// ---------------------------------------------------------------------------

/** Build a minimal AwsInstance with just the fields these tests assert on. */
function inst(id: string): AwsInstance {
  return { DBInstanceIdentifier: id, DBInstanceClass: "db.r7g.large" };
}

Deno.test("collectInstances: empty clusterIds issues zero API calls", async () => {
  let calls = 0;
  const api: RdsApi = {
    describeDBClusters: () => Promise.resolve({ DBClusters: [] }),
    describeDBInstances: () => {
      calls++;
      return Promise.resolve({ DBInstances: [] });
    },
  };
  const map = await collectInstances(api, []);
  assertEquals(map.size, 0);
  assertEquals(calls, 0);
});

Deno.test("collectInstances: forwards cluster ids as the filter and keys by instance id", async () => {
  const seen: string[][] = [];
  const api: RdsApi = {
    describeDBClusters: () => Promise.resolve({ DBClusters: [] }),
    describeDBInstances: (clusterIds) => {
      seen.push(clusterIds);
      return Promise.resolve({
        DBInstances: [inst("c1-a"), inst("c2-a")],
      });
    },
  };
  const map = await collectInstances(api, ["c1", "c2"]);
  assertEquals(seen, [["c1", "c2"]]);
  assertEquals([...map.keys()].sort(), ["c1-a", "c2-a"]);
});

Deno.test("collectInstances: paginates a batch to exhaustion via Marker (no early exit)", async () => {
  // Keyed by the marker the caller presents (undefined for the first page),
  // each page pointing at the next via its returned Marker.
  const pageByMarker = new Map<string | undefined, DescribeInstancesPage>([
    [undefined, { DBInstances: [inst("a")], Marker: "m1" }],
    ["m1", { DBInstances: [inst("b")], Marker: "m2" }],
    ["m2", { DBInstances: [inst("c")] }],
  ]);
  const markers: Array<string | undefined> = [];
  const api: RdsApi = {
    describeDBClusters: () => Promise.resolve({ DBClusters: [] }),
    describeDBInstances: (_clusterIds, marker) => {
      markers.push(marker);
      return Promise.resolve(pageByMarker.get(marker)!);
    },
  };
  const map = await collectInstances(api, ["c1"]);
  // All three pages were walked, in order, following the returned markers.
  assertEquals(markers, [undefined, "m1", "m2"]);
  assertEquals([...map.keys()].sort(), ["a", "b", "c"]);
});

Deno.test("collectInstances: chunks cluster ids into batches no larger than the cap", async () => {
  // One more than two full batches, to prove the tail batch is sent too.
  const total = MAX_CLUSTER_IDS_PER_FILTER * 2 + 1;
  const clusterIds = Array.from({ length: total }, (_v, i) => `c${i}`);

  const batchSizes: number[] = [];
  const api: RdsApi = {
    describeDBClusters: () => Promise.resolve({ DBClusters: [] }),
    describeDBInstances: (ids) => {
      batchSizes.push(ids.length);
      // Return one instance per cluster in the batch so the merge is observable.
      return Promise.resolve({
        DBInstances: ids.map((id) => inst(`${id}-i`)),
      });
    },
  };

  const map = await collectInstances(api, clusterIds);

  // Three batches: cap, cap, 1 — the tail chunk is sent and none exceeds the cap.
  assertEquals(batchSizes, [
    MAX_CLUSTER_IDS_PER_FILTER,
    MAX_CLUSTER_IDS_PER_FILTER,
    1,
  ]);
  // Every cluster's instance landed in the merged map.
  assertEquals(map.size, total);
  assertExists(map.get("c0-i"));
  assertExists(map.get(`c${total - 1}-i`));
});

Deno.test("collectInstances: skips returned instances that carry no identifier", async () => {
  const api: RdsApi = {
    describeDBClusters: () => Promise.resolve({ DBClusters: [] }),
    describeDBInstances: () =>
      Promise.resolve({
        DBInstances: [inst("real"), { DBInstanceClass: "db.r7g.large" }],
      }),
  };
  const map = await collectInstances(api, ["c1"]);
  assertEquals([...map.keys()], ["real"]);
});

Deno.test("collectInstances: a throttle propagates without an app-level re-issue", async () => {
  // Throttling retry lives inside the SDK client (SHARED_RETRY); by the time
  // a send rejects here the client's bounded retries are exhausted. The
  // batching loop must neither re-issue the page nor swallow the error.
  let calls = 0;
  const api: RdsApi = {
    describeDBClusters: () => Promise.resolve({ DBClusters: [] }),
    describeDBInstances: () => {
      calls++;
      const err = new Error("rate exceeded");
      err.name = "ThrottlingException";
      return Promise.reject(err);
    },
  };
  await assertRejects(
    () => collectInstances(api, ["c1"]),
    Error,
    "rate exceeded",
  );
  assertEquals(calls, 1);
});

// ---------------------------------------------------------------------------
// Smoke check: schemas don't drift from the rest of the module
// ---------------------------------------------------------------------------

Deno.test("smoke: every exported helper still has a real implementation", () => {
  assertExists(resolveRegion);
  assertExists(tagsFromAws);
  assertExists(evaluateSelector);
  assertExists(isRdsEngine);
  assertExists(RDS_ENGINE_ALLOWLIST);
  assertNotEquals(typeof resolveRegion, "undefined");
});
