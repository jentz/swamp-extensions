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
  deploymentFor,
  type InstanceRecord,
  normalizedUnits,
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
// normalizedUnits — Multi-AZ doubles, Single-AZ equals sizeFactor
// ---------------------------------------------------------------------------

Deno.test("normalizedUnits: Multi-AZ is exactly 2x the Single-AZ units", () => {
  assertEquals(normalizedUnits("large", "Single-AZ"), 1);
  assertEquals(normalizedUnits("large", "Multi-AZ"), 2);
  assertEquals(normalizedUnits("2xlarge", "Single-AZ"), 4);
  assertEquals(normalizedUnits("2xlarge", "Multi-AZ"), 8);
});

Deno.test("normalizedUnits: unnormalizable size stays null at either deployment", () => {
  assertEquals(normalizedUnits("metal", "Single-AZ"), null);
  assertEquals(normalizedUnits("metal", "Multi-AZ"), null);
});

// ---------------------------------------------------------------------------
// deploymentFor — Aurora is forced Single-AZ; everything else passes through
// ---------------------------------------------------------------------------

Deno.test("deploymentFor: non-Aurora engines pass the multiAZ flag through", () => {
  assertEquals(deploymentFor("postgres", true), "Multi-AZ");
  assertEquals(deploymentFor("postgres", false), "Single-AZ");
  assertEquals(deploymentFor("sqlserver", true), "Multi-AZ");
  assertEquals(deploymentFor("oracle", true), "Multi-AZ");
});

Deno.test("deploymentFor: every Aurora engine is forced Single-AZ even when multiAZ", () => {
  assertEquals(deploymentFor("aurora", true), "Single-AZ");
  assertEquals(deploymentFor("aurora-mysql", true), "Single-AZ");
  assertEquals(deploymentFor("aurora-postgresql", true), "Single-AZ");
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
    [ri({
      dbInstanceClass: "db.serverless",
      dbInstanceCount: 3,
      state: "active",
    })],
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
      inst({
        accountId: "111",
        accountName: "account-alpha",
        dbInstanceClass: "db.r8g.2xlarge",
        dbInstanceIdentifier: "a",
      }),
      inst({
        accountId: "222",
        accountName: "account-beta",
        dbInstanceClass: "db.r8g.large",
        dbInstanceIdentifier: "b",
      }),
    ],
    // reservation owned only by account-alpha must not cover account-beta here.
    [ri({
      accountId: "111",
      accountName: "account-alpha",
      dbInstanceClass: "db.r8g.large",
      dbInstanceCount: 1,
    })],
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
      inst({
        accountName: "x",
        dbInstanceClass: "db.t4g.medium",
        dbInstanceIdentifier: "t",
      }),
      inst({
        accountName: "x",
        dbInstanceClass: "db.serverless",
        dbInstanceIdentifier: "s",
      }),
      inst({
        accountName: "x",
        dbInstanceClass: "db.r8g.large",
        dbInstanceIdentifier: "r",
      }),
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
  // postgres Multi-AZ large = 1×2 = 2 normalized units; mysql Single-AZ large
  // = 1; the rollup sums the now-commensurable units to 3.
  assertEquals(agg.buckets.length, 2);
  const rollup = rollupByGeneration(agg.buckets);
  assertEquals(rollup.length, 1);
  assertEquals(rollup[0].family, "r7g");
  assertEquals(rollup[0].runningLargeEq, 3);
});

// ---------------------------------------------------------------------------
// Multi-AZ 2x weighting — mixed fleet, the ticket worked example
// ---------------------------------------------------------------------------

Deno.test("aggregate: mixed Single-AZ/Multi-AZ fleet — per-bucket and rollup match AWS normalized units", () => {
  // us-east-1 / r7g / postgres, all db.r7g.large:
  //   running: 2× Single-AZ large, 1× Multi-AZ large
  //   reserved: 1× Single-AZ large RI (count 1); 0 Multi-AZ RIs
  const agg = aggregate(
    [
      inst({ multiAZ: false, dbInstanceIdentifier: "sa1" }),
      inst({ multiAZ: false, dbInstanceIdentifier: "sa2" }),
      inst({ multiAZ: true, dbInstanceIdentifier: "ma1" }),
    ],
    [ri({ multiAZ: false, dbInstanceCount: 1 })],
  );

  assertEquals(agg.buckets.length, 2);
  const sa = agg.buckets.find((b) => b.deployment === "Single-AZ")!;
  const ma = agg.buckets.find((b) => b.deployment === "Multi-AZ")!;

  // Single-AZ: 2× large = 2 running; 1 large RI = 1 reserved; gap 1.
  assertEquals(sa.runningLargeEq, 2);
  assertEquals(sa.reservedLargeEq, 1);
  // Multi-AZ: 1× large at 2× = 2 running; 0 reserved; gap 2.
  assertEquals(ma.runningLargeEq, 2);
  assertEquals(ma.reservedLargeEq, 0);

  // Rollup folds the commensurable units: running 4, reserved 1, gap 3 —
  // matching AWS's normalized-unit arithmetic (16 demand − 4 supply = 12
  // units = 3 Single-AZ-large-equivalents).
  const rollup = rollupByGeneration(agg.buckets);
  assertEquals(rollup.length, 1);
  assertEquals(rollup[0].runningLargeEq, 4);
  assertEquals(rollup[0].reservedLargeEq, 1);
  assertEquals(rollup[0].gapLargeEq, 3);
});

Deno.test("aggregate: a reserved Multi-AZ RI is weighted 2x", () => {
  // One Multi-AZ large RI supplies 2 normalized units (large=1 × 2 for MA).
  const agg = aggregate(
    [inst({ multiAZ: true, dbInstanceClass: "db.r7g.xlarge" })],
    [ri({
      multiAZ: true,
      dbInstanceClass: "db.r7g.large",
      dbInstanceCount: 1,
    })],
  );
  assertEquals(agg.buckets.length, 1);
  const b = agg.buckets[0];
  assertEquals(b.deployment, "Multi-AZ");
  // running xlarge Multi-AZ = 2 × 2 = 4; reserved large Multi-AZ = 1 × 2 = 2.
  assertEquals(b.runningLargeEq, 4);
  assertEquals(b.reservedLargeEq, 2);
});

// ---------------------------------------------------------------------------
// Aurora — no Multi-AZ DB instance reservation; forced to a single Single-AZ
// bucket at 1×, even when the upstream multiAZ flag is set.
// ---------------------------------------------------------------------------

Deno.test("aggregate: an Aurora instance with multiAZ=true lands in one Single-AZ bucket at 1x", () => {
  const agg = aggregate(
    [
      inst({
        engine: "aurora-postgresql",
        multiAZ: true,
        dbInstanceClass: "db.r7g.large",
        clusterId: "orders-cluster",
        dbInstanceIdentifier: "writer",
      }),
      inst({
        engine: "aurora-postgresql",
        multiAZ: false,
        dbInstanceClass: "db.r7g.large",
        clusterId: "orders-cluster",
        dbInstanceIdentifier: "reader",
      }),
    ],
    [],
  );

  // No Multi-AZ Aurora bucket exists: both members collapse to one Single-AZ
  // bucket, each weighted 1× (large = 1) → 2 running large-eq.
  assertEquals(agg.buckets.length, 1);
  assertEquals(agg.buckets[0].deployment, "Single-AZ");
  assertEquals(agg.buckets[0].engine, "aurora-postgresql");
  assertEquals(agg.buckets[0].runningLargeEq, 2);
  assertEquals(agg.buckets[0].runningInstances, 2);
});

Deno.test("aggregate: a reserved Aurora RI flagged multiAZ still nets in the Single-AZ bucket", () => {
  const agg = aggregate(
    [inst({
      engine: "aurora-mysql",
      multiAZ: false,
      dbInstanceClass: "db.r7g.large",
    })],
    [
      ri({
        productDescription: "aurora mysql",
        multiAZ: true,
        dbInstanceClass: "db.r7g.large",
        dbInstanceCount: 1,
      }),
    ],
  );
  // Aurora reserved is forced Single-AZ and weighted 1×, so it nets against the
  // running Aurora instance in the same Single-AZ bucket (no phantom MA bucket).
  assertEquals(agg.buckets.length, 1);
  assertEquals(agg.buckets[0].deployment, "Single-AZ");
  assertEquals(agg.buckets[0].runningLargeEq, 1);
  assertEquals(agg.buckets[0].reservedLargeEq, 1);
});

Deno.test("aggregateByAccount: Multi-AZ doubles and Aurora stays Single-AZ 1x", () => {
  const acctBuckets = aggregateByAccount(
    [
      inst({
        accountName: "x",
        engine: "postgres",
        multiAZ: true,
        dbInstanceClass: "db.r7g.large",
        dbInstanceIdentifier: "p",
      }),
      inst({
        accountName: "x",
        engine: "aurora-postgresql",
        multiAZ: true,
        dbInstanceClass: "db.r7g.large",
        dbInstanceIdentifier: "a",
      }),
    ],
    [],
  );
  const pg = acctBuckets.find((b) => b.engine === "postgres")!;
  const au = acctBuckets.find((b) => b.engine === "aurora-postgresql")!;
  assertEquals(pg.deployment, "Multi-AZ");
  assertEquals(pg.runningLargeEq, 2); // large × 2 for Multi-AZ
  assertEquals(au.deployment, "Single-AZ");
  assertEquals(au.runningLargeEq, 1); // Aurora never doubles
});
