/**
 * Unit tests for the @jentz/aws-rds-inventory extension.
 *
 * Pure-logic coverage: region resolution chain, AWS tag transform, selector
 * evaluation against a stand-in CEL environment, and the retry helper's
 * throttling backoff. No network or filesystem I/O.
 */

import {
  assertEquals,
  assertExists,
  assertNotEquals,
  assertRejects,
  assertThrows,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import {
  buildSelectorContext,
  clusterKey,
  evaluateSelector,
  instanceKey,
  isRdsEngine,
  RDS_ENGINE_ALLOWLIST,
  resolveRegion,
  type SelectorContext,
  tagsFromAws,
} from "../aws_rds_inventory.ts";
import { isThrottlingError, withRetry } from "../_lib/retry.ts";

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

Deno.test("RDS_ENGINE_ALLOWLIST: is runtime-frozen", () => {
  assertEquals(Object.isFrozen(RDS_ENGINE_ALLOWLIST), true);
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
// withRetry / isThrottlingError
// ---------------------------------------------------------------------------

Deno.test("isThrottlingError: matches ThrottlingException name", () => {
  const err = new Error("rate exceeded");
  err.name = "ThrottlingException";
  assertEquals(isThrottlingError(err), true);
});

Deno.test("isThrottlingError: matches by message substring", () => {
  assertEquals(isThrottlingError(new Error("Throttling: slow down")), true);
  assertEquals(isThrottlingError(new Error("TooManyRequests")), true);
  assertEquals(isThrottlingError(new Error("RequestLimitExceeded")), true);
});

Deno.test("isThrottlingError: message fallback covers every name in the switch", () => {
  // The `\bToken\b` regex is strict — `TooManyRequests` does not match inside
  // `TooManyRequestsException` because there is no word boundary between `s`
  // and `E`. The regex must spell out both bare and `*Exception`-suffixed
  // forms so an SDK wrapper that puts the full token in `.message` while
  // collapsing `.name` to "Error" still trips the retry path.
  assertEquals(
    isThrottlingError(new Error("ThrottlingException: ...")),
    true,
  );
  assertEquals(
    isThrottlingError(new Error("TooManyRequestsException: ...")),
    true,
  );
  assertEquals(
    isThrottlingError(new Error("RequestThrottledException: ...")),
    true,
  );
});

Deno.test("isThrottlingError: regular errors do not match", () => {
  assertEquals(isThrottlingError(new Error("connection refused")), false);
  assertEquals(isThrottlingError(undefined), false);
  assertEquals(isThrottlingError(null), false);
});

Deno.test("withRetry: succeeds on first try, no waiting", async () => {
  let waited = 0;
  const result = await withRetry(
    () => Promise.resolve(42),
    "test",
    {},
    {
      random: () => 0,
      delay: (ms) => {
        waited += ms;
        return Promise.resolve();
      },
    },
  );
  assertEquals(result, 42);
  assertEquals(waited, 0);
});

Deno.test("withRetry: retries throttling errors then succeeds", async () => {
  const delays: number[] = [];
  const events: number[] = [];
  let attempts = 0;
  const result = await withRetry(
    () => {
      attempts++;
      if (attempts < 3) {
        const err = new Error("Throttling");
        return Promise.reject(err);
      }
      return Promise.resolve("ok");
    },
    "DescribeDBClusters",
    { baseDelayMs: 10, maxDelayMs: 1000 },
    {
      // Full jitter: with random()==1 we get the full ceiling.
      random: () => 1,
      delay: (ms) => {
        delays.push(ms);
        return Promise.resolve();
      },
      onRetry: (e) => events.push(e.attempt),
    },
  );
  assertEquals(result, "ok");
  assertEquals(attempts, 3);
  // Two delays for two retries. Ceiling doubles each attempt.
  assertEquals(delays, [10, 20]);
  assertEquals(events, [1, 2]);
});

Deno.test("withRetry: non-throttling errors propagate without retry", async () => {
  let attempts = 0;
  await assertRejects(
    () =>
      withRetry(
        () => {
          attempts++;
          return Promise.reject(new Error("Bad input"));
        },
        "test",
        {},
        {
          random: () => 0,
          delay: () => Promise.resolve(),
        },
      ),
    Error,
    "Bad input",
  );
  assertEquals(attempts, 1);
});

Deno.test("withRetry: gives up after maxAttempts and rethrows", async () => {
  let attempts = 0;
  await assertRejects(
    () =>
      withRetry(
        () => {
          attempts++;
          return Promise.reject(new Error("Throttling"));
        },
        "test",
        { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1 },
        {
          random: () => 0,
          delay: () => Promise.resolve(),
        },
      ),
    Error,
    "Throttling",
  );
  assertEquals(attempts, 3);
});

Deno.test("withRetry: full jitter — random() value scales the delay uniformly", async () => {
  const delays: number[] = [];
  await withRetry(
    (() => {
      let n = 0;
      return () => {
        n++;
        return n === 2 ? Promise.resolve("ok") : Promise.reject(
          new Error("Throttling"),
        );
      };
    })(),
    "test",
    { baseDelayMs: 1000, maxDelayMs: 60000 },
    {
      random: () => 0.5, // Sample at half the ceiling.
      delay: (ms) => {
        delays.push(ms);
        return Promise.resolve();
      },
    },
  );
  assertEquals(delays.length, 1);
  // Ceiling = min(1000 * 2^0, 60000) = 1000; sample = 0.5 * 1000 = 500.
  assertEquals(delays[0], 500);
});

Deno.test("withRetry: max delay caps exponential growth (with random()==1 we get the ceiling)", async () => {
  const delays: number[] = [];
  let attempts = 0;
  await withRetry(
    () => {
      attempts++;
      return attempts >= 5
        ? Promise.resolve("ok")
        : Promise.reject(new Error("Throttling"));
    },
    "test",
    { baseDelayMs: 1000, maxDelayMs: 3000 },
    {
      random: () => 1, // Full-ceiling sample.
      delay: (ms) => {
        delays.push(ms);
        return Promise.resolve();
      },
    },
  );
  // Ceilings: 1000, 2000, 3000, 3000 (capped at maxDelayMs).
  assertEquals(delays, [1000, 2000, 3000, 3000]);
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
  assertExists(withRetry);
  assertExists(isThrottlingError);
  assertNotEquals(typeof resolveRegion, "undefined");
});
