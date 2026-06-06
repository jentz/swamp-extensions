/**
 * Unit tests for `@jentz/aws-rds-reservation-coverage`.
 *
 * The correctness-critical surface here is the classification + normalization
 * math: parsing instance classes, the large-equivalent size factor, engine
 * canonicalization that lets running `postgres` net against reserved
 * `postgresql`, and the bucket aggregation + generation rollup including the
 * burstable / serverless / unparseable carve-outs and the active-only reserved
 * rule.
 *
 * @module
 */

import { assertEquals } from "jsr:@std/assert@1";
import {
  aggregate,
  aggregateByAccount,
  canonicalEngine,
  type InstanceRecord,
  parseInstanceClass,
  type ReservedRecord,
  rollupByGeneration,
  sizeFactor,
} from "../aws_rds_reservation_coverage.ts";

// ---------------------------------------------------------------------------
// parseInstanceClass
// ---------------------------------------------------------------------------

Deno.test("parseInstanceClass: db.r7g.2xlarge -> family r7g, gen 7g, size 2xlarge", () => {
  const p = parseInstanceClass("db.r7g.2xlarge");
  assertEquals(p.family, "r7g");
  assertEquals(p.classLetter, "r");
  assertEquals(p.generation, "7g");
  assertEquals(p.size, "2xlarge");
  assertEquals(p.isBurstable, false);
  assertEquals(p.isServerless, false);
  assertEquals(p.unparseable, false);
});

Deno.test("parseInstanceClass: t-class is flagged burstable", () => {
  const p = parseInstanceClass("db.t4g.medium");
  assertEquals(p.family, "t4g");
  assertEquals(p.isBurstable, true);
});

Deno.test("parseInstanceClass: db.serverless is Aurora Serverless v2", () => {
  const p = parseInstanceClass("db.serverless");
  assertEquals(p.isServerless, true);
  assertEquals(p.unparseable, false);
  assertEquals(p.size, "");
});

Deno.test("parseInstanceClass: leading db. is optional", () => {
  assertEquals(parseInstanceClass("m5.large").family, "m5");
});

Deno.test("parseInstanceClass: garbage is unparseable", () => {
  assertEquals(parseInstanceClass("nonsense").unparseable, true);
  assertEquals(parseInstanceClass("").unparseable, true);
});

// ---------------------------------------------------------------------------
// sizeFactor — doubling per step, anchored at large = 1
// ---------------------------------------------------------------------------

Deno.test("sizeFactor: anchor and fractional sizes", () => {
  assertEquals(sizeFactor("large"), 1);
  assertEquals(sizeFactor("medium"), 0.5);
  assertEquals(sizeFactor("small"), 0.25);
  assertEquals(sizeFactor("micro"), 0.125);
  assertEquals(sizeFactor("nano"), 0.0625);
});

Deno.test("sizeFactor: xlarge ladder doubles per step", () => {
  assertEquals(sizeFactor("xlarge"), 2);
  assertEquals(sizeFactor("2xlarge"), 4);
  assertEquals(sizeFactor("4xlarge"), 8);
  assertEquals(sizeFactor("8xlarge"), 16);
  assertEquals(sizeFactor("12xlarge"), 24);
  assertEquals(sizeFactor("16xlarge"), 32);
  assertEquals(sizeFactor("24xlarge"), 48);
});

Deno.test("sizeFactor: unknown / metal returns null", () => {
  assertEquals(sizeFactor("metal"), null);
  assertEquals(sizeFactor("gigantic"), null);
});

// ---------------------------------------------------------------------------
// canonicalEngine — running Engine and reserved ProductDescription collapse
// ---------------------------------------------------------------------------

Deno.test("canonicalEngine: postgres and postgresql collapse together", () => {
  assertEquals(canonicalEngine("postgres"), "postgres");
  assertEquals(canonicalEngine("postgresql"), "postgres");
});

Deno.test("canonicalEngine: aurora variants stay distinct", () => {
  assertEquals(canonicalEngine("aurora-postgresql"), "aurora-postgresql");
  assertEquals(canonicalEngine("aurora postgresql"), "aurora-postgresql");
  assertEquals(canonicalEngine("aurora-mysql"), "aurora-mysql");
});

Deno.test("canonicalEngine: oracle / sqlserver editions collapse to base engine", () => {
  assertEquals(canonicalEngine("oracle-ee"), "oracle");
  assertEquals(canonicalEngine("oracle"), "oracle");
  assertEquals(canonicalEngine("sqlserver-se"), "sqlserver");
  assertEquals(canonicalEngine("sqlserver-ee(li)"), "sqlserver");
});

// ---------------------------------------------------------------------------
// aggregate + rollup — the headline math
// ---------------------------------------------------------------------------

function inst(over: Partial<InstanceRecord>): InstanceRecord {
  return {
    accountId: "1",
    accountName: "acct",
    profile: "p",
    region: "us-east-1",
    dbInstanceIdentifier: "id",
    dbInstanceClass: "db.r7g.large",
    engine: "postgres",
    engineVersion: "16",
    multiAZ: false,
    status: "available",
    clusterId: "",
    storageType: "gp3",
    instanceTags: {},
    scannedAt: "2026-06-05T00:00:00.000Z",
    ...over,
  };
}

function ri(over: Partial<ReservedRecord>): ReservedRecord {
  return {
    accountId: "1",
    accountName: "acct",
    profile: "p",
    region: "us-east-1",
    reservedDBInstanceId: "ri",
    dbInstanceClass: "db.r7g.large",
    productDescription: "postgresql",
    multiAZ: false,
    dbInstanceCount: 1,
    state: "active",
    offeringType: "All Upfront",
    durationSeconds: 31536000,
    startTime: "",
    scannedAt: "2026-06-05T00:00:00.000Z",
    ...over,
  };
}

Deno.test("aggregate: running large-eq sums by size factor within a bucket", () => {
  // r7g/postgres/Single-AZ: 2xlarge (4) + large (1) = 5 running large-eq.
  const agg = aggregate(
    [
      inst({ dbInstanceClass: "db.r7g.2xlarge", dbInstanceIdentifier: "a" }),
      inst({ dbInstanceClass: "db.r7g.large", dbInstanceIdentifier: "b" }),
    ],
    [],
  );
  assertEquals(agg.buckets.length, 1);
  assertEquals(agg.buckets[0].runningLargeEq, 5);
  assertEquals(agg.buckets[0].runningInstances, 2);
  assertEquals(agg.buckets[0].reservedLargeEq, 0);
});

Deno.test("aggregate: reserved nets against running with engine collapse and count multiply", () => {
  // running 2xlarge = 4 large-eq; reserved: large(1) x count 2 = 2 large-eq.
  const agg = aggregate(
    [inst({ dbInstanceClass: "db.r7g.2xlarge" })],
    [ri({ dbInstanceClass: "db.r7g.large", dbInstanceCount: 2 })],
  );
  assertEquals(agg.buckets.length, 1);
  const b = agg.buckets[0];
  assertEquals(b.runningLargeEq, 4);
  assertEquals(b.reservedLargeEq, 2);
  assertEquals(b.engine, "postgres");
  // gap surfaces in the rollup.
  const rollup = rollupByGeneration(agg.buckets);
  assertEquals(rollup[0].gapLargeEq, 2);
});

Deno.test("aggregate: Multi-AZ and Single-AZ are separate buckets", () => {
  const agg = aggregate(
    [
      inst({ multiAZ: true, dbInstanceIdentifier: "m" }),
      inst({ multiAZ: false, dbInstanceIdentifier: "s" }),
    ],
    [],
  );
  assertEquals(agg.buckets.length, 2);
  const deployments = agg.buckets.map((b) => b.deployment).sort();
  assertEquals(deployments, ["Multi-AZ", "Single-AZ"]);
});

Deno.test("aggregate: 7g and 8g are separate buckets (generation not collapsed)", () => {
  const agg = aggregate(
    [
      inst({ dbInstanceClass: "db.r7g.large", dbInstanceIdentifier: "a" }),
      inst({ dbInstanceClass: "db.r8g.large", dbInstanceIdentifier: "b" }),
    ],
    [],
  );
  assertEquals(agg.buckets.length, 2);
  assertEquals(agg.buckets.map((b) => b.family).sort(), ["r7g", "r8g"]);
});

Deno.test("aggregate: burstable goes to its own counted bucket, not large-eq", () => {
  const agg = aggregate(
    [inst({ dbInstanceClass: "db.t4g.medium" })],
    [ri({ dbInstanceClass: "db.t4g.medium", dbInstanceCount: 3 })],
  );
  assertEquals(agg.buckets.length, 0);
  assertEquals(agg.burstable.length, 1);
  assertEquals(agg.burstable[0].family, "t4g");
  assertEquals(agg.burstable[0].runningInstances, 1);
  assertEquals(agg.burstable[0].reservedInstances, 3);
});

Deno.test("aggregate: serverless is carved out, not normalized", () => {
  const agg = aggregate([inst({ dbInstanceClass: "db.serverless" })], []);
  assertEquals(agg.buckets.length, 0);
  assertEquals(agg.serverless.length, 1);
  assertEquals(agg.serverless[0].count, 1);
});

Deno.test("aggregate: a reserved serverless row is dropped, not recorded as a zero-count entry", () => {
  // Aurora Serverless v2 is not traditionally reservable. A reserved serverless
  // row must not bucket and must not pollute the serverless table with an empty
  // entry; the serverless table counts running instances only.
  const agg = aggregate(
    [],
    [ri({ dbInstanceClass: "db.serverless", dbInstanceCount: 3, state: "active" })],
  );
  assertEquals(agg.buckets.length, 0);
  assertEquals(agg.serverless.length, 0);
});

Deno.test("aggregate: inactive reservations do not count toward coverage", () => {
  const agg = aggregate(
    [inst({ dbInstanceClass: "db.r7g.large" })],
    [
      ri({ state: "retired", dbInstanceCount: 5 }),
      ri({ state: "payment-pending", dbInstanceCount: 5 }),
    ],
  );
  assertEquals(agg.buckets.length, 1);
  assertEquals(agg.buckets[0].reservedLargeEq, 0);
  assertEquals(agg.inactiveReserved, 2);
});

Deno.test("aggregate: unparseable class is surfaced, not silently dropped", () => {
  const agg = aggregate(
    [inst({ dbInstanceClass: "db.r7g.metal" })],
    [],
  );
  assertEquals(agg.buckets.length, 0);
  assertEquals(agg.unparseable.length, 1);
  assertEquals(agg.unparseable[0].dbInstanceClass, "db.r7g.metal");
});

Deno.test("aggregateByAccount: same family in two accounts stays split by owner", () => {
  const acctBuckets = aggregateByAccount(
    [
      inst({ accountId: "111", accountName: "account-alpha", dbInstanceClass: "db.r8g.2xlarge", dbInstanceIdentifier: "a" }),
      inst({ accountId: "222", accountName: "account-beta", dbInstanceClass: "db.r8g.large", dbInstanceIdentifier: "b" }),
    ],
    // reservation owned only by account-alpha must not cover account-beta here.
    [ri({ accountId: "111", accountName: "account-alpha", dbInstanceClass: "db.r8g.large", dbInstanceCount: 1 })],
  );
  assertEquals(acctBuckets.length, 2);
  const alpha = acctBuckets.find((b) => b.accountName === "account-alpha")!;
  const beta = acctBuckets.find((b) => b.accountName === "account-beta")!;
  assertEquals(alpha.runningLargeEq, 4);
  assertEquals(alpha.reservedLargeEq, 1);
  assertEquals(beta.runningLargeEq, 1);
  assertEquals(beta.reservedLargeEq, 0); // not covered when sharing is off
});

Deno.test("aggregateByAccount: excludes burstable / serverless / inactive, like org-wide", () => {
  const acctBuckets = aggregateByAccount(
    [
      inst({ accountName: "x", dbInstanceClass: "db.t4g.medium", dbInstanceIdentifier: "t" }),
      inst({ accountName: "x", dbInstanceClass: "db.serverless", dbInstanceIdentifier: "s" }),
      inst({ accountName: "x", dbInstanceClass: "db.r8g.large", dbInstanceIdentifier: "r" }),
    ],
    [ri({ accountName: "x", state: "retired", dbInstanceCount: 9 })],
  );
  assertEquals(acctBuckets.length, 1);
  assertEquals(acctBuckets[0].runningLargeEq, 1);
  assertEquals(acctBuckets[0].reservedLargeEq, 0);
});

Deno.test("rollupByGeneration: collapses engine and deployment within region x family", () => {
  const agg = aggregate(
    [
      inst({ engine: "postgres", multiAZ: true, dbInstanceIdentifier: "a" }),
      inst({ engine: "mysql", multiAZ: false, dbInstanceIdentifier: "b" }),
    ],
    [],
  );
  // Two buckets (different engine+deployment) collapse to one rollup row.
  assertEquals(agg.buckets.length, 2);
  const rollup = rollupByGeneration(agg.buckets);
  assertEquals(rollup.length, 1);
  assertEquals(rollup[0].family, "r7g");
  assertEquals(rollup[0].runningLargeEq, 2);
});
