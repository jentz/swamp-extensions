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
  largeEqToBuy,
  normalizedUnits,
  normalizeLicense,
  parseEngineIdentity,
  parseInstanceClass,
  type ReservedRecord,
  rollupByPool,
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
// normalizeLicense — reserved suffix and running LicenseModel onto one token
// ---------------------------------------------------------------------------

Deno.test("normalizeLicense: maps both suffix and LicenseModel spellings", () => {
  assertEquals(normalizeLicense("byol"), "byol");
  assertEquals(normalizeLicense("bring-your-own-license"), "byol");
  assertEquals(normalizeLicense("li"), "li");
  assertEquals(normalizeLicense("license-included"), "li");
  assertEquals(normalizeLicense("mpl"), "mpl");
  assertEquals(normalizeLicense("marketplace-license"), "mpl");
  // single-license engines carry no bucketing info
  assertEquals(normalizeLicense("general-public-license"), "");
  assertEquals(normalizeLicense("postgresql-license"), "");
  assertEquals(normalizeLicense(""), "");
});

// ---------------------------------------------------------------------------
// parseEngineIdentity — edition + license preserved; size-flex eligibility
// ---------------------------------------------------------------------------

Deno.test("parseEngineIdentity: open-source and Aurora collapse to a base token", () => {
  assertEquals(parseEngineIdentity("postgres").token, "postgres");
  assertEquals(parseEngineIdentity("postgresql").token, "postgres");
  assertEquals(
    parseEngineIdentity("aurora-postgresql").token,
    "aurora-postgresql",
  );
  assertEquals(parseEngineIdentity("mysql").token, "mysql");
  // Legacy Aurora MySQL 5.6 reports a bare `aurora` on both sides — it must net
  // with itself and stay size-flexible.
  assertEquals(parseEngineIdentity("aurora").token, "aurora");
  for (const e of ["postgres", "mysql", "mariadb", "aurora-mysql", "aurora"]) {
    assertEquals(parseEngineIdentity(e).sizeFlexEligible, true);
  }
});

Deno.test("parseEngineIdentity: reserved-side (byol)/(li) suffix parsed, including whitespace", () => {
  const eeByol = parseEngineIdentity("oracle-ee(byol)");
  assertEquals(eeByol.engine, "oracle");
  assertEquals(eeByol.edition, "ee");
  assertEquals(eeByol.license, "byol");
  assertEquals(eeByol.token, "oracle-ee-byol");
  assertEquals(eeByol.sizeFlexEligible, true);

  // The live value set includes a space before the paren: "oracle-se2 (byol)".
  const se2Byol = parseEngineIdentity("oracle-se2 (byol)");
  assertEquals(se2Byol.edition, "se2");
  assertEquals(se2Byol.license, "byol");
  assertEquals(se2Byol.token, "oracle-se2-byol");
  assertEquals(se2Byol.sizeFlexEligible, true);

  const se2Li = parseEngineIdentity("oracle-se2(li)");
  assertEquals(se2Li.token, "oracle-se2-li");
  assertEquals(se2Li.sizeFlexEligible, false); // Oracle LI is not size-flexible
});

Deno.test("parseEngineIdentity: SQL Server is never size-flexible, edition preserved", () => {
  const seLi = parseEngineIdentity("sqlserver-se(li)");
  assertEquals(seLi.engine, "sqlserver");
  assertEquals(seLi.edition, "se");
  assertEquals(seLi.token, "sqlserver-se-li");
  assertEquals(seLi.sizeFlexEligible, false);
  // running-side sqlserver-ee with no license model infers LI (standard RDS).
  const eeRunning = parseEngineIdentity("sqlserver-ee");
  assertEquals(eeRunning.token, "sqlserver-ee-li");
  assertEquals(eeRunning.sizeFlexEligible, false);
});

Deno.test("parseEngineIdentity: running LicenseModel drives Oracle SE2 BYOL-vs-LI routing", () => {
  const byol = parseEngineIdentity("oracle-se2", "bring-your-own-license");
  assertEquals(byol.token, "oracle-se2-byol");
  assertEquals(byol.sizeFlexEligible, true);

  const li = parseEngineIdentity("oracle-se2", "license-included");
  assertEquals(li.token, "oracle-se2-li");
  assertEquals(li.sizeFlexEligible, false);

  // Unknown license: SE2 is genuinely ambiguous (LI and BYOL both exist), so it
  // stays out of the size-flex netting rather than risk a false net.
  const unknown = parseEngineIdentity("oracle-se2", "");
  assertEquals(unknown.license, "");
  assertEquals(unknown.token, "oracle-se2");
  assertEquals(unknown.sizeFlexEligible, false);
});

Deno.test("parseEngineIdentity: Oracle EE is BYOL-only even when license unknown", () => {
  // EE has no License-Included offering, so a missing license infers BYOL and
  // EE stays size-flexible.
  const ee = parseEngineIdentity("oracle-ee", "");
  assertEquals(ee.license, "byol");
  assertEquals(ee.token, "oracle-ee-byol");
  assertEquals(ee.sizeFlexEligible, true);
});

Deno.test("parseEngineIdentity: RDS Custom keeps a distinct engine and is not size-flexible", () => {
  const custOra = parseEngineIdentity("custom-oracle-ee-cdb");
  assertEquals(custOra.engine, "custom-oracle");
  assertEquals(custOra.edition, "ee");
  assertEquals(custOra.sizeFlexEligible, false);

  const custSql = parseEngineIdentity("custom-sqlserver-se(byol)");
  assertEquals(custSql.engine, "custom-sqlserver");
  assertEquals(custSql.token, "custom-sqlserver-se-byol");
  assertEquals(custSql.sizeFlexEligible, false);
});

Deno.test("parseEngineIdentity: spaced 'sql server' fallback does not invent a 'se' edition", () => {
  // The "se" inside "server" must not be mistaken for Standard Edition when the
  // base keyword can't be located (the editionAfter idx<0 guard).
  const id = parseEngineIdentity("sql server");
  assertEquals(id.engine, "sqlserver");
  assertEquals(id.edition, "");
  assertEquals(id.token, "sqlserver");
  assertEquals(id.sizeFlexEligible, false);
});

Deno.test("parseEngineIdentity: Db2 preserves edition and license; stays size-flexible", () => {
  const ae = parseEngineIdentity("db2-ae(byol)");
  assertEquals(ae.engine, "db2");
  assertEquals(ae.edition, "ae");
  assertEquals(ae.token, "db2-ae-byol");
  assertEquals(ae.sizeFlexEligible, true);
  // marketplace vs byol must not cross-net.
  assertEquals(parseEngineIdentity("db2-se(mpl)").token, "db2-se-mpl");
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
    licenseModel: "",
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
  const rollup = rollupByPool(agg.buckets);
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
  const { buckets: acctBuckets } = aggregateByAccount(
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

Deno.test("aggregateByAccount: surfaces burstable / serverless / inactive per account, like org-wide", () => {
  // Previously these classes were silently dropped on the per-account path. They
  // must now appear in the per-account carve-out structures, not vanish.
  const acct = aggregateByAccount(
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
  // The size-flex bucket is still the only large-eq line.
  assertEquals(acct.buckets.length, 1);
  assertEquals(acct.buckets[0].runningLargeEq, 1);
  assertEquals(acct.buckets[0].reservedLargeEq, 0);
  // ...but burstable, serverless, and the inactive reservation are now surfaced.
  assertEquals(acct.burstable.length, 1);
  assertEquals(acct.burstable[0].family, "t4g");
  assertEquals(acct.burstable[0].runningInstances, 1);
  assertEquals(acct.serverless.length, 1);
  assertEquals(acct.serverless[0].count, 1);
  assertEquals(acct.inactiveReserved.length, 1);
  assertEquals(acct.inactiveReserved[0].count, 1); // one retired RI row
});

Deno.test("aggregateByAccount: an all-burstable account and an all-serverless account are not dropped", () => {
  // The ticket's worked example: three accounts, RI sharing OFF, all running.
  // prod runs size-flex r7g; burst runs only t4g; server runs only serverless.
  // Pre-fix, burst and server produced zero rows and vanished entirely.
  const acct = aggregateByAccount(
    [
      inst({
        accountId: "111111111111",
        accountName: "prod",
        dbInstanceClass: "db.r7g.2xlarge",
        engine: "postgres",
        dbInstanceIdentifier: "p1",
      }),
      inst({
        accountId: "222222222222",
        accountName: "burst",
        dbInstanceClass: "db.t4g.medium",
        engine: "mysql",
        dbInstanceIdentifier: "b1",
      }),
      inst({
        accountId: "222222222222",
        accountName: "burst",
        dbInstanceClass: "db.t4g.medium",
        engine: "mysql",
        dbInstanceIdentifier: "b2",
      }),
      inst({
        accountId: "333333333333",
        accountName: "server",
        dbInstanceClass: "db.serverless",
        engine: "aurora-postgresql",
        dbInstanceIdentifier: "s1",
      }),
    ],
    [],
  );
  // prod is the only large-eq bucket.
  assertEquals(acct.buckets.length, 1);
  assertEquals(acct.buckets[0].accountName, "prod");
  // burst's two t4g.medium surface in the per-account burstable table.
  const burst = acct.burstable.find((l) => l.accountName === "burst")!;
  assertEquals(burst.family, "t4g");
  assertEquals(burst.size, "medium");
  assertEquals(burst.runningInstances, 2);
  // server's Aurora Serverless v2 surfaces in the per-account serverless table.
  const server = acct.serverless.find((s) => s.accountName === "server")!;
  assertEquals(server.engine, "aurora-postgresql");
  assertEquals(server.count, 1);
});

Deno.test("aggregateByAccount: a parseable-but-unnormalizable size (.metal) surfaces per account", () => {
  // AC#8 — natural result of the shared classifier; no path-specific branch.
  const acct = aggregateByAccount(
    [
      inst({
        accountName: "x",
        dbInstanceClass: "db.r7g.metal",
        dbInstanceIdentifier: "m",
      }),
    ],
    [],
  );
  assertEquals(acct.buckets.length, 0);
  assertEquals(acct.unparseable.length, 1);
  assertEquals(acct.unparseable[0].dbInstanceClass, "db.r7g.metal");
  assertEquals(acct.unparseable[0].source, "instance");
  assertEquals(acct.unparseable[0].count, 1);
});

Deno.test("aggregateByAccount: a reserved serverless row is dropped, mirroring org-wide", () => {
  // AC#7 — the per-account serverless tally counts running only; an active
  // reserved serverless row must neither bucket nor inflate the serverless table.
  const acct = aggregateByAccount(
    [],
    [ri({
      accountName: "x",
      dbInstanceClass: "db.serverless",
      dbInstanceCount: 3,
      state: "active",
    })],
  );
  assertEquals(acct.buckets.length, 0);
  assertEquals(acct.serverless.length, 0);
  assertEquals(acct.inactiveReserved.length, 0); // it was active, just dropped
});

Deno.test("rollupByPool: keeps engines distinct (deployment collapsed) and the buy figure does not net across engines", () => {
  // Same region × family (r7g), two engines with OPPOSITE gaps:
  //   postgres: 1× large running (1 large-eq), reserved large × count 2 (2) ->
  //             gap −1 (over-reserved)
  //   mysql:    2× large running (2 large-eq), no reservation -> gap +2
  //             (under-reserved)
  const agg = aggregate(
    [
      inst({ engine: "postgres", dbInstanceIdentifier: "pg1" }),
      inst({ engine: "mysql", dbInstanceIdentifier: "my1" }),
      inst({ engine: "mysql", dbInstanceIdentifier: "my2" }),
    ],
    [ri({ productDescription: "postgresql", dbInstanceCount: 2 })],
  );

  // Engine is a hard reservation boundary: two pools, not one collapsed row.
  const rollup = rollupByPool(agg.buckets);
  assertEquals(rollup.length, 2);
  const pg = rollup.find((r) => r.engine === "postgres")!;
  const my = rollup.find((r) => r.engine === "mysql")!;
  assertEquals(pg.family, "r7g");
  assertEquals(pg.gapLargeEq, -1); // over-reserved
  assertEquals(my.gapLargeEq, 2); // under-reserved

  // The buy figure sums only the POSITIVE pool gaps: the postgres surplus must
  // NOT offset the mysql deficit across the engine boundary. A naive
  // all-running-minus-all-reserved net would read (3 − 2) = 1 and under-buy.
  assertEquals(largeEqToBuy(rollup), 2);
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
  const rollup = rollupByPool(agg.buckets);
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
  const { buckets: acctBuckets } = aggregateByAccount(
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

// ---------------------------------------------------------------------------
// Edition / license non-collapse + non-size-flex carve-out (task-58)
// ---------------------------------------------------------------------------

Deno.test("aggregate: an SE2 License-Included RI does not cover an EE BYOL instance (task example)", () => {
  // us-east-1 / r6i / Single-AZ: 1× oracle-ee BYOL xlarge running; 1× oracle-se2
  // LI xlarge reserved. The old code collapsed both to `oracle` and reported
  // gap 0 ("fully covered"). They must not net.
  const agg = aggregate(
    [
      inst({
        region: "us-east-1",
        dbInstanceClass: "db.r6i.xlarge",
        engine: "oracle-ee",
        licenseModel: "bring-your-own-license",
      }),
    ],
    [
      ri({
        region: "us-east-1",
        dbInstanceClass: "db.r6i.xlarge",
        productDescription: "oracle-se2(li)",
        dbInstanceCount: 1,
      }),
    ],
  );
  // EE BYOL is size-flex eligible → a large-eq bucket with NO reservation.
  assertEquals(agg.buckets.length, 1);
  const b = agg.buckets[0];
  assertEquals(b.engine, "oracle-ee-byol");
  assertEquals(b.runningLargeEq, 2); // xlarge
  assertEquals(b.reservedLargeEq, 0); // the SE2 LI RI cannot cover it
  // The SE2 LI reservation lands unmatched in the non-size-flex carve-out.
  assertEquals(agg.nonSizeFlex.length, 1);
  const c = agg.nonSizeFlex[0];
  assertEquals(c.engine, "oracle-se2-li");
  assertEquals(c.runningInstances, 0);
  assertEquals(c.reservedInstances, 1);
  // The EE instance now surfaces as uncovered (gap 2), not "fully covered".
  const rollup = rollupByPool(agg.buckets);
  assertEquals(rollup[0].gapLargeEq, 2);
});

Deno.test("aggregate: SQL Server is not size-flexible — an xlarge RI does not cover two large", () => {
  const agg = aggregate(
    [
      inst({
        dbInstanceClass: "db.r6i.large",
        engine: "sqlserver-se",
        licenseModel: "license-included",
        dbInstanceIdentifier: "a",
      }),
      inst({
        dbInstanceClass: "db.r6i.large",
        engine: "sqlserver-se",
        licenseModel: "license-included",
        dbInstanceIdentifier: "b",
      }),
    ],
    [
      ri({
        dbInstanceClass: "db.r6i.xlarge",
        productDescription: "sqlserver-se(li)",
        dbInstanceCount: 1,
      }),
    ],
  );
  // Nothing in the size-flex buckets; everything in the carve-out.
  assertEquals(agg.buckets.length, 0);
  const large = agg.nonSizeFlex.find((l) => l.size === "large")!;
  const xlarge = agg.nonSizeFlex.find((l) => l.size === "xlarge")!;
  assertEquals(large.engine, "sqlserver-se-li");
  assertEquals(large.runningInstances, 2);
  assertEquals(large.reservedInstances, 0); // xlarge RI does not cover large
  assertEquals(xlarge.runningInstances, 0);
  assertEquals(xlarge.reservedInstances, 1);
});

Deno.test("aggregate: Oracle BYOL keeps large-eq netting split by edition", () => {
  // ee and se2, both BYOL — separate buckets; an SE2 RI never nets against EE.
  const agg = aggregate(
    [
      inst({
        dbInstanceClass: "db.r6i.large",
        engine: "oracle-ee",
        licenseModel: "bring-your-own-license",
        dbInstanceIdentifier: "ee",
      }),
      inst({
        dbInstanceClass: "db.r6i.large",
        engine: "oracle-se2",
        licenseModel: "bring-your-own-license",
        dbInstanceIdentifier: "se2",
      }),
    ],
    [
      ri({
        dbInstanceClass: "db.r6i.large",
        productDescription: "oracle-se2 (byol)",
        dbInstanceCount: 1,
      }),
    ],
  );
  assertEquals(agg.buckets.length, 2);
  const ee = agg.buckets.find((b) => b.engine === "oracle-ee-byol")!;
  const se2 = agg.buckets.find((b) => b.engine === "oracle-se2-byol")!;
  assertEquals(ee.reservedLargeEq, 0); // SE2 RI must not cover EE
  assertEquals(se2.reservedLargeEq, 1); // SE2 RI covers the SE2 instance
  assertEquals(agg.nonSizeFlex.length, 0); // both BYOL → both size-flex eligible
});

Deno.test("aggregate: Oracle License-Included capacity is carved out, not normalized", () => {
  const agg = aggregate(
    [
      inst({
        dbInstanceClass: "db.r6i.xlarge",
        engine: "oracle-se2",
        licenseModel: "license-included",
      }),
    ],
    [],
  );
  assertEquals(agg.buckets.length, 0);
  assertEquals(agg.nonSizeFlex.length, 1);
  assertEquals(agg.nonSizeFlex[0].engine, "oracle-se2-li");
  assertEquals(agg.nonSizeFlex[0].size, "xlarge");
  assertEquals(agg.nonSizeFlex[0].runningInstances, 1);
});

Deno.test("aggregateByAccount: SQL Server and Oracle LI surface in the per-account non-size-flex table", () => {
  const acct = aggregateByAccount(
    [
      inst({
        accountName: "x",
        dbInstanceClass: "db.r6i.large",
        engine: "sqlserver-se",
        licenseModel: "license-included",
        dbInstanceIdentifier: "s",
      }),
      inst({
        accountName: "x",
        dbInstanceClass: "db.r6i.large",
        engine: "oracle-se2",
        licenseModel: "license-included",
        dbInstanceIdentifier: "o",
      }),
      inst({
        accountName: "x",
        dbInstanceClass: "db.r6i.large",
        engine: "oracle-ee",
        licenseModel: "bring-your-own-license",
        dbInstanceIdentifier: "e",
      }),
    ],
    [],
  );
  // Only the EE BYOL instance is size-flex eligible — the one large-eq bucket.
  assertEquals(acct.buckets.length, 1);
  assertEquals(acct.buckets[0].engine, "oracle-ee-byol");
  assertEquals(acct.buckets[0].runningLargeEq, 1);
  // ...but the SQL Server LI and Oracle SE2 LI capacity is no longer dropped:
  // it surfaces in the per-account non-size-flex table, attributable to "x".
  assertEquals(acct.nonSizeFlex.length, 2);
  const sql = acct.nonSizeFlex.find((l) => l.engine === "sqlserver-se-li")!;
  const ora = acct.nonSizeFlex.find((l) => l.engine === "oracle-se2-li")!;
  assertEquals(sql.accountName, "x");
  assertEquals(sql.size, "large");
  assertEquals(sql.runningInstances, 1);
  assertEquals(ora.runningInstances, 1);
});

Deno.test("aggregateByAccount: an all-SQL-Server account is not silently dropped", () => {
  // The non-size-flex analogue of the all-burstable / all-serverless case: an
  // account that runs ONLY SQL Server would otherwise produce zero per-account
  // rows and vanish from the RI-sharing-OFF view entirely.
  const acct = aggregateByAccount(
    [
      inst({
        accountId: "444444444444",
        accountName: "winsql",
        dbInstanceClass: "db.r6i.xlarge",
        engine: "sqlserver-ee",
        licenseModel: "license-included",
        dbInstanceIdentifier: "w1",
      }),
    ],
    [
      ri({
        accountId: "444444444444",
        accountName: "winsql",
        dbInstanceClass: "db.r6i.xlarge",
        productDescription: "sqlserver-ee(li)",
        dbInstanceCount: 1,
      }),
    ],
  );
  assertEquals(acct.buckets.length, 0);
  assertEquals(acct.nonSizeFlex.length, 1);
  const l = acct.nonSizeFlex[0];
  assertEquals(l.accountName, "winsql");
  assertEquals(l.engine, "sqlserver-ee-li");
  assertEquals(l.size, "xlarge");
  assertEquals(l.deployment, "Single-AZ");
  assertEquals(l.runningInstances, 1);
  assertEquals(l.reservedInstances, 1); // same-row reservation nets visibly
});

// ---------------------------------------------------------------------------
// Org-wide regression snapshot (AC#6) — pins the full Aggregation across all
// five classify() kinds so the shared-classifier refactor cannot change the
// org-wide outputs. A representative fleet hits bucket / burstable / serverless
// / nonSizeFlex / unparseable plus an inactive reservation.
// ---------------------------------------------------------------------------

Deno.test("aggregate: full-fleet snapshot is unchanged by the shared classifier", () => {
  const agg = aggregate(
    [
      inst({
        dbInstanceClass: "db.r7g.large",
        engine: "postgres",
        dbInstanceIdentifier: "pg",
      }),
      inst({
        dbInstanceClass: "db.t4g.medium",
        engine: "mysql",
        dbInstanceIdentifier: "bu",
      }),
      inst({
        dbInstanceClass: "db.serverless",
        engine: "aurora-postgresql",
        dbInstanceIdentifier: "sv",
      }),
      inst({
        dbInstanceClass: "db.r6i.large",
        engine: "sqlserver-se",
        licenseModel: "license-included",
        dbInstanceIdentifier: "ms",
      }),
      inst({
        dbInstanceClass: "db.r7g.metal",
        engine: "postgres",
        dbInstanceIdentifier: "mt",
      }),
    ],
    [
      ri({
        dbInstanceClass: "db.r7g.large",
        productDescription: "postgresql",
        dbInstanceCount: 1,
      }),
      ri({ state: "retired", dbInstanceCount: 9 }),
    ],
  );

  assertEquals(agg, {
    buckets: [
      {
        region: "us-east-1",
        family: "r7g",
        generation: "7g",
        engine: "postgres",
        deployment: "Single-AZ",
        runningLargeEq: 1,
        reservedLargeEq: 1,
        runningInstances: 1,
        reservedInstances: 1,
      },
    ],
    burstable: [
      {
        region: "us-east-1",
        family: "t4g",
        size: "medium",
        runningInstances: 1,
        reservedInstances: 0,
      },
    ],
    nonSizeFlex: [
      {
        region: "us-east-1",
        family: "r6i",
        engine: "sqlserver-se-li",
        size: "large",
        deployment: "Single-AZ",
        runningInstances: 1,
        reservedInstances: 0,
      },
    ],
    serverless: [
      { region: "us-east-1", engine: "aurora-postgresql", count: 1 },
    ],
    unparseable: [
      {
        region: "us-east-1",
        dbInstanceClass: "db.r7g.metal",
        source: "instance",
        count: 1,
      },
    ],
    inactiveReserved: 1,
  });
});
