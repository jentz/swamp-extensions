/**
 * Swamp workflow-scope report: `@jentz/aws-rds-reservation-coverage`.
 *
 * Consumes the `instance`, `reserved`, and `scan_error` resources produced
 * earlier in the workflow by `@jentz/aws-rds-reservations` and answers the
 * RDS reserved-instance planning question: **how many "large equivalents" of
 * capacity, per family-generation, are running but not yet covered by a
 * reservation?** Pure data shaping — no AWS API access.
 *
 * ## Normalization
 *
 * Each instance class is parsed into `family` (e.g. `r7g`), `generation`
 * (`7g`), and `size` (`2xlarge`). Size is converted to a **large-equivalent**
 * factor that doubles per size step, anchored at Single-AZ `large = 1`:
 *
 *   nano .0625 · micro .125 · small .25 · medium .5 · large 1 · xlarge 2 ·
 *   2xlarge 4 · 4xlarge 8 · 8xlarge 16 · 12xlarge 24 · 16xlarge 32 · 24xlarge 48
 *
 * (an `Nxlarge` is `2 × N`). A **Multi-AZ instance deployment then counts 2×**
 * the same-size Single-AZ deployment — this is AWS's normalized-unit table,
 * rescaled so a Single-AZ `large` is one unit. RI size-flexibility applies by
 * these units within a family and crosses the Multi-AZ/Single-AZ boundary, so
 * the units are commensurable: a Multi-AZ and a Single-AZ large-eq can be
 * summed. **Aurora is the exception** — see Bucketing.
 *
 * ## Bucketing
 *
 * Non-burstable, non-serverless capacity is summed into buckets keyed by
 * `region × family × engine × deployment(Multi-AZ|Single-AZ)` — the dimensions
 * an actual RDS reservation is scoped to, so each row maps to a purchasable
 * line item. For each bucket: `running_large_eq − reserved_large_eq = gap`. A
 * positive gap is under-covered capacity to buy; negative is over-coverage.
 *
 * **Aurora has no Multi-AZ DB instance reservation option** (the purchase
 * console pins the Single-AZ radio for Aurora; its availability comes from
 * cluster replicas, not a Multi-AZ instance deployment). So any Aurora engine
 * is forced to the `Single-AZ` deployment and never picks up the 2× weight —
 * an Aurora row never produces a Multi-AZ bucket, even if its upstream
 * `multiAZ` flag is set.
 *
 * Netting is **bucket-local**: a Single-AZ RI nets only Single-AZ running, a
 * Multi-AZ RI only Multi-AZ running. AWS in fact lets a Single-AZ RI spill
 * onto Multi-AZ usage (one family-wide normalized-unit pool); the per-bucket
 * gaps do not model that spill, so when a Single-AZ RI exceeds Single-AZ demand
 * one bucket can read over-reserved while another reads under — the **rollup
 * total is unaffected** (spill changes attribution, never the family total).
 *
 * A region × family **generation rollup** collapses engine and deployment for
 * the headline "large equivalents per generation" view. Because the units are
 * now commensurable (Multi-AZ folded in at 2×), this sum is meaningful and is
 * the authoritative cross-deployment gap.
 *
 * **Known limitation — Multi-AZ DB cluster (3-node):** the newer Multi-AZ DB
 * *cluster* deployment (1 primary + 2 readable standbys) consumes 3× normalized
 * units, but is not modeled here: upstream carries only a `multiAZ` boolean and
 * a `clusterId`, no reliable cluster-type signal. AWS reports each cluster
 * member through `DescribeDBInstances` (typically `MultiAZ=false`), so the
 * three members fall through as three individual Single-AZ instances —
 * approximately the 3× footprint by headcount, at 1× each.
 *
 * ## Carve-outs (never silently dropped)
 *
 *   - **Burstable** (`t`-class: t2/t3/t4g) capacity is reported separately as
 *     raw counts — burstable reservations are not size-flexible, so folding
 *     them into large-equivalents would mislead.
 *   - **Serverless** (`db.serverless`, Aurora Serverless v2) is counted
 *     separately (ACU-billed, not instance-class capacity).
 *   - **Unparseable** classes are listed with a warning.
 *
 * ## Caveats
 *
 * Engine is canonicalized (e.g. running `postgres` and reserved `postgresql`
 * collapse to `postgres`); Oracle/SQL-Server license models (LI vs BYOL) are
 * NOT distinguished, so those buckets are advisory. Note that SQL Server and
 * Oracle License-Included are not size-flexible at all, so normalizing them
 * into large-equivalents is itself advisory for those engines (a separate
 * concern from the Multi-AZ 2× weighting, which does apply to them). Only
 * `active` reservations count toward coverage.
 *
 * The report never throws — a missing upstream step, malformed artifact, or
 * schema drift degrades to a logged warning and a still-useful (possibly
 * empty) report.
 *
 * @module
 */

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Model type whose outputs this report consumes. */
export const RESERVATIONS_MODEL_TYPE = "@jentz/aws-rds-reservations";

/** Instance spec name on the upstream reservations model. */
export const INSTANCE_SPEC = "instance";
/** Reserved spec name on the upstream reservations model. */
export const RESERVED_SPEC = "reserved";
/** Scan-error spec name on the upstream reservations model. */
export const SCAN_ERROR_SPEC = "scan_error";

/** CSV columns for the actionable per-bucket gap table, in header order. */
export const COLUMNS = [
  "region",
  "family",
  "generation",
  "engine",
  "deployment",
  "running_large_eq",
  "reserved_large_eq",
  "gap_large_eq",
  "running_instances",
  "reserved_instances",
] as const;

// ---------------------------------------------------------------------------
// Schemas — hand-mirror of the producer's public shapes. If upstream tightens
// a field, artifacts fail safeParse here and are skipped with a logged warning.
// ---------------------------------------------------------------------------

const TagsSchema = z.record(z.string(), z.string()).default({});

const InstanceRecordSchema = z.object({
  accountId: z.string(),
  accountName: z.string(),
  profile: z.string(),
  region: z.string(),
  dbInstanceIdentifier: z.string(),
  dbInstanceClass: z.string(),
  engine: z.string(),
  engineVersion: z.string(),
  multiAZ: z.boolean(),
  status: z.string(),
  clusterId: z.string(),
  storageType: z.string(),
  instanceTags: TagsSchema,
  scannedAt: z.iso.datetime(),
});

const ReservedRecordSchema = z.object({
  accountId: z.string(),
  accountName: z.string(),
  profile: z.string(),
  region: z.string(),
  reservedDBInstanceId: z.string(),
  dbInstanceClass: z.string(),
  productDescription: z.string(),
  multiAZ: z.boolean(),
  dbInstanceCount: z.number(),
  state: z.string(),
  offeringType: z.string(),
  durationSeconds: z.number(),
  startTime: z.string(),
  scannedAt: z.iso.datetime(),
});

const ScanErrorSchema = z.object({
  profile: z.string(),
  accountId: z.string(),
  region: z.string(),
  phase: z.string(),
  kind: z.enum(["auth_expired", "access_denied", "other"]),
  message: z.string(),
  scannedAt: z.iso.datetime(),
});

// Explicit interfaces (not `z.infer`) keep the public API free of slow types:
// a `z.infer` export leaks the private schema const and zod's internal `output`
// type, which `deno doc --lint` rejects. The schemas above remain the runtime
// validators; these interfaces are their hand-mirrored public shape.

/** A decoded provisioned-instance row. */
export interface InstanceRecord {
  /** 12-digit AWS account id of the sweeping credentials. */
  accountId: string;
  /** Friendly account label: profile minus the configured suffix, or the account id for the ambient chain. */
  accountName: string;
  /** Profile that produced this row; `""` for the ambient chain. */
  profile: string;
  /** AWS region. */
  region: string;
  /** DB instance identifier. */
  dbInstanceIdentifier: string;
  /** Instance class, e.g. `db.r7g.2xlarge`. */
  dbInstanceClass: string;
  /** Engine, e.g. `postgres`, `aurora-postgresql`, `mysql`. */
  engine: string;
  /** Engine version string. */
  engineVersion: string;
  /** Whether the instance is a Multi-AZ deployment. */
  multiAZ: boolean;
  /** Lifecycle status, e.g. `available`. */
  status: string;
  /** Owning DB cluster id, or `""` for a standalone instance. */
  clusterId: string;
  /** Storage type, e.g. `gp3`, `io1`, `aurora`. */
  storageType: string;
  /** All instance tags, flattened. */
  instanceTags: Record<string, string>;
  /** ISO 8601 sweep timestamp. */
  scannedAt: string;
}

/** A decoded reserved-instance row. */
export interface ReservedRecord {
  /** 12-digit AWS account id of the sweeping credentials. */
  accountId: string;
  /** Friendly account label: profile minus the configured suffix, or the account id for the ambient chain. */
  accountName: string;
  /** Profile that produced this row; `""` for the ambient chain. */
  profile: string;
  /** AWS region. */
  region: string;
  /** Reservation id. */
  reservedDBInstanceId: string;
  /** Reserved instance class, e.g. `db.r7g.xlarge`. */
  dbInstanceClass: string;
  /** Product description (the RI's engine), e.g. `postgresql`. */
  productDescription: string;
  /** Whether the reservation covers Multi-AZ deployments. */
  multiAZ: boolean;
  /** Number of instances this reservation covers. */
  dbInstanceCount: number;
  /** Reservation state, e.g. `active`, `payment-pending`, `retired`. */
  state: string;
  /** Offering type, e.g. `All Upfront`, `No Upfront`. */
  offeringType: string;
  /** Reservation term length in seconds. */
  durationSeconds: number;
  /** ISO 8601 reservation start time, or `""` if unknown. */
  startTime: string;
  /** ISO 8601 sweep timestamp. */
  scannedAt: string;
}

/** A decoded scan-error row. */
export interface ScanError {
  /** Profile being swept; `""` for ambient. */
  profile: string;
  /** Account id if known by the time of failure; `""` otherwise. */
  accountId: string;
  /** Region being swept; `""` for account-level failures. */
  region: string;
  /** Stage that failed: `credentials`, `describe_db_instances`, … */
  phase: string;
  /** Coarse classification driving the operator's next action. */
  kind: "auth_expired" | "access_denied" | "other";
  /** Error detail. */
  message: string;
  /** ISO 8601 timestamp. */
  scannedAt: string;
}

/** Everything collected from upstream reservations steps. */
export interface Collected {
  /** Decoded provisioned-instance rows. */
  instances: InstanceRecord[];
  /** Decoded reserved-instance rows. */
  reserved: ReservedRecord[];
  /** Decoded scan errors. */
  errors: ScanError[];
  /** Artifacts that failed to decode or validate. */
  skipped: number;
}

// ---------------------------------------------------------------------------
// Classification + normalization (pure, exported for unit-test access)
// ---------------------------------------------------------------------------

/** Parsed components of an RDS instance class. */
export interface ParsedClass {
  /** Instance family, e.g. `r7g`, `t4g`, `m5`. `""` if unparseable. */
  family: string;
  /** Leading class letters, e.g. `r`, `t`, `m`. */
  classLetter: string;
  /** Family minus the class letter, e.g. `7g`, `4g`, `5`. */
  generation: string;
  /** Size token, e.g. `2xlarge`, `large`, `medium`. `""` for serverless. */
  size: string;
  /** True for `t`-class burstable families. */
  isBurstable: boolean;
  /** True for Aurora Serverless v2 (`db.serverless`). */
  isServerless: boolean;
  /** True when the class could not be parsed into family + size. */
  unparseable: boolean;
}

/**
 * Parse an RDS instance class such as `db.r7g.2xlarge` into its components.
 * The leading `db.` is optional. `db.serverless` is recognized as Aurora
 * Serverless v2. Anything without a recognizable `family.size` shape (and not
 * serverless) is flagged `unparseable`.
 *
 * @param dbInstanceClass The raw class string from AWS.
 * @returns The parsed components; never throws.
 */
export function parseInstanceClass(dbInstanceClass: string): ParsedClass {
  const empty: ParsedClass = {
    family: "",
    classLetter: "",
    generation: "",
    size: "",
    isBurstable: false,
    isServerless: false,
    unparseable: true,
  };
  if (typeof dbInstanceClass !== "string" || dbInstanceClass.trim() === "") {
    return empty;
  }
  let rest = dbInstanceClass.trim().toLowerCase();
  if (rest.startsWith("db.")) rest = rest.slice(3);

  if (rest === "serverless") {
    return {
      family: "serverless",
      classLetter: "serverless",
      generation: "",
      size: "",
      isBurstable: false,
      isServerless: true,
      unparseable: false,
    };
  }

  const parts = rest.split(".");
  if (parts.length < 2 || parts[0] === "" || parts[1] === "") return empty;
  const family = parts[0];
  const size = parts.slice(1).join(".");
  const classLetter = (family.match(/^[a-z]+/)?.[0]) ?? "";
  const generation = family.slice(classLetter.length);
  return {
    family,
    classLetter,
    generation,
    size,
    isBurstable: classLetter === "t",
    isServerless: false,
    unparseable: false,
  };
}

/**
 * Large-equivalent factor for a size token: capacity relative to a `large`,
 * doubling per size step. Returns `null` for sizes that cannot be normalized
 * (unknown tokens, `metal`, or the empty serverless size) so callers route
 * them to a carve-out rather than silently scoring them as zero.
 *
 * @param size A size token such as `large`, `2xlarge`, `medium`.
 * @returns The factor (e.g. `2xlarge` → 4), or `null` if not normalizable.
 */
export function sizeFactor(size: string): number | null {
  const fixed: Record<string, number> = {
    nano: 0.0625,
    micro: 0.125,
    small: 0.25,
    medium: 0.5,
    large: 1,
    xlarge: 2,
  };
  if (size in fixed) return fixed[size];
  const m = size.match(/^(\d+)xlarge$/);
  if (m) {
    const n = Number(m[1]);
    if (Number.isFinite(n) && n > 0) return 2 * n;
  }
  return null;
}

/**
 * AWS normalized units for a size at a given deployment, anchored so a
 * Single-AZ `large` is 1. A **Multi-AZ instance deployment consumes exactly
 * 2x** the units of the same-size Single-AZ deployment — AWS's normalized-unit
 * table — and RI size-flexibility crosses the Multi-AZ/Single-AZ boundary by
 * these units. Single-AZ factors equal {@link sizeFactor}; Multi-AZ doubles.
 *
 * Aurora is never Multi-AZ here (see {@link deploymentFor}), so it never
 * doubles — the x2 keys purely off the resolved `deployment` label, keeping
 * engine-awareness confined to deployment resolution.
 *
 * @param size A size token such as `large`, `2xlarge`, `medium`.
 * @param deployment The resolved deployment dimension (`Multi-AZ` doubles).
 * @returns The normalized units, or `null` if the size is not normalizable.
 */
export function normalizedUnits(
  size: string,
  deployment: string,
): number | null {
  const base = sizeFactor(size);
  if (base === null) return null;
  return deployment === "Multi-AZ" ? base * 2 : base;
}

/**
 * Collapse a running `Engine` or a reserved `ProductDescription` onto a single
 * canonical token so the two sides bucket together (e.g. running `postgres`
 * and reserved `postgresql` both become `postgres`). Aurora variants are kept
 * distinct from their provisioned counterparts.
 *
 * @param raw The raw engine / product-description string.
 * @returns A canonical engine token.
 */
export function canonicalEngine(raw: string): string {
  const s = (raw ?? "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  if (s === "") return "unknown";
  const has = (needle: string) => s.includes(needle);
  if (has("aurora") && has("postgres")) return "aurora-postgresql";
  if (has("aurora") && has("mysql")) return "aurora-mysql";
  if (has("aurora")) return "aurora";
  if (has("postgres")) return "postgres";
  if (has("maria")) return "mariadb";
  if (has("mysql")) return "mysql";
  if (has("oracle")) return "oracle";
  if (has("sqlserver") || (has("sql") && has("server"))) return "sqlserver";
  if (has("db2")) return "db2";
  return s.split(" ")[0];
}

/** Deployment dimension label from the Multi-AZ flag. */
export function deploymentLabel(multiAZ: boolean): "Multi-AZ" | "Single-AZ" {
  return multiAZ ? "Multi-AZ" : "Single-AZ";
}

/**
 * Resolve the deployment dimension a bucket is scoped to, accounting for the
 * fact that **Aurora has no Multi-AZ DB instance reservation option**: the AWS
 * Reserved DB Instance purchase console pins the Single-AZ radio for Aurora
 * engines (Aurora's availability comes from cluster replicas, not a Multi-AZ
 * instance deployment). So any Aurora engine (canonical engine starting
 * `aurora`) is forced to `Single-AZ` regardless of the upstream `multiAZ`
 * flag — it must never create a Multi-AZ bucket nor pick up the Multi-AZ x2
 * weight. Every other engine maps straight through {@link deploymentLabel}.
 *
 * @param engine The canonical engine (see {@link canonicalEngine}).
 * @param multiAZ The upstream Multi-AZ flag.
 * @returns The deployment dimension; `Single-AZ` for any Aurora engine.
 */
export function deploymentFor(
  engine: string,
  multiAZ: boolean,
): "Multi-AZ" | "Single-AZ" {
  if (engine.startsWith("aurora")) return "Single-AZ";
  return deploymentLabel(multiAZ);
}

/** Bucket key for a large-equivalent row: region × family × engine × deployment. */
export function bucketKey(
  region: string,
  family: string,
  engine: string,
  deployment: string,
): string {
  return `${region} ${family} ${engine} ${deployment}`;
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

/** One large-equivalent bucket: running vs reserved capacity for an RI line item. */
export interface Bucket {
  /** AWS region. */
  region: string;
  /** Instance family, e.g. `r7g`. */
  family: string;
  /** Generation, e.g. `7g`. */
  generation: string;
  /** Canonical engine. */
  engine: string;
  /** Deployment dimension. */
  deployment: string;
  /** Running capacity in large-equivalents. */
  runningLargeEq: number;
  /** Reserved (active) capacity in large-equivalents. */
  reservedLargeEq: number;
  /** Number of running instances summed into this bucket. */
  runningInstances: number;
  /** Number of reserved instances (sum of DBInstanceCount) in this bucket. */
  reservedInstances: number;
}

/** A burstable (t-class) line, reported as raw counts (not normalized). */
export interface BurstableLine {
  /** AWS region. */
  region: string;
  /** Family, e.g. `t4g`. */
  family: string;
  /** Size token, e.g. `medium`. */
  size: string;
  /** Running instance count. */
  runningInstances: number;
  /** Reserved instance count (sum of DBInstanceCount, active only). */
  reservedInstances: number;
}

/** An unparseable class, surfaced rather than dropped. */
export interface UnparseableLine {
  /** AWS region. */
  region: string;
  /** Raw instance class. */
  dbInstanceClass: string;
  /** `instance` or `reserved`. */
  source: "instance" | "reserved";
  /** Count of rows with this class. */
  count: number;
}

/** Full aggregation result. */
export interface Aggregation {
  /** Large-equivalent buckets, sorted. */
  buckets: Bucket[];
  /** Burstable lines, sorted. */
  burstable: BurstableLine[];
  /** Serverless instance count by `region engine`. */
  serverless: Array<{ region: string; engine: string; count: number }>;
  /** Unparseable class lines. */
  unparseable: UnparseableLine[];
  /** Reserved rows skipped because they were not `active`. */
  inactiveReserved: number;
}

function emptyBucket(
  region: string,
  family: string,
  generation: string,
  engine: string,
  deployment: string,
): Bucket {
  return {
    region,
    family,
    generation,
    engine,
    deployment,
    runningLargeEq: 0,
    reservedLargeEq: 0,
    runningInstances: 0,
    reservedInstances: 0,
  };
}

/** Stable bucket order: region, then family, then engine, then deployment. */
export function compareBuckets(a: Bucket, b: Bucket): number {
  if (a.region !== b.region) return a.region < b.region ? -1 : 1;
  if (a.family !== b.family) return a.family < b.family ? -1 : 1;
  if (a.engine !== b.engine) return a.engine < b.engine ? -1 : 1;
  return a.deployment < b.deployment ? -1 : a.deployment > b.deployment ? 1 : 0;
}

/**
 * Aggregate decoded instance and reserved rows into large-equivalent buckets
 * plus the burstable / serverless / unparseable carve-outs.
 *
 * @param instances Decoded provisioned-instance rows.
 * @param reserved Decoded reserved-instance rows.
 * @returns The full aggregation.
 */
export function aggregate(
  instances: InstanceRecord[],
  reserved: ReservedRecord[],
): Aggregation {
  const buckets = new Map<string, Bucket>();
  const burstable = new Map<string, BurstableLine>();
  const serverless = new Map<
    string,
    { region: string; engine: string; count: number }
  >();
  const unparseable = new Map<string, UnparseableLine>();
  let inactiveReserved = 0;

  const bumpBucket = (
    region: string,
    parsed: ParsedClass,
    engine: string,
    deployment: string,
    largeEq: number,
    instances: number,
    side: "running" | "reserved",
  ) => {
    const key = bucketKey(region, parsed.family, engine, deployment);
    let b = buckets.get(key);
    if (!b) {
      b = emptyBucket(
        region,
        parsed.family,
        parsed.generation,
        engine,
        deployment,
      );
      buckets.set(key, b);
    }
    if (side === "running") {
      b.runningLargeEq += largeEq;
      b.runningInstances += instances;
    } else {
      b.reservedLargeEq += largeEq;
      b.reservedInstances += instances;
    }
  };

  const bumpBurstable = (
    region: string,
    family: string,
    size: string,
    count: number,
    side: "running" | "reserved",
  ) => {
    const key = `${region} ${family} ${size}`;
    let l = burstable.get(key);
    if (!l) {
      l = { region, family, size, runningInstances: 0, reservedInstances: 0 };
      burstable.set(key, l);
    }
    if (side === "running") l.runningInstances += count;
    else l.reservedInstances += count;
  };

  const bumpUnparseable = (
    region: string,
    dbInstanceClass: string,
    source: "instance" | "reserved",
    count: number,
  ) => {
    const key = `${region} ${dbInstanceClass} ${source}`;
    let l = unparseable.get(key);
    if (!l) {
      l = { region, dbInstanceClass, source, count: 0 };
      unparseable.set(key, l);
    }
    l.count += count;
  };

  for (const i of instances) {
    const parsed = parseInstanceClass(i.dbInstanceClass);
    const engine = canonicalEngine(i.engine);
    if (parsed.isServerless) {
      const key = `${i.region} ${engine}`;
      const s = serverless.get(key) ?? { region: i.region, engine, count: 0 };
      s.count += 1;
      serverless.set(key, s);
      continue;
    }
    if (parsed.isBurstable) {
      bumpBurstable(i.region, parsed.family, parsed.size, 1, "running");
      continue;
    }
    const deployment = deploymentFor(engine, i.multiAZ);
    const units = parsed.unparseable
      ? null
      : normalizedUnits(parsed.size, deployment);
    if (units === null) {
      bumpUnparseable(i.region, i.dbInstanceClass, "instance", 1);
      continue;
    }
    bumpBucket(
      i.region,
      parsed,
      engine,
      deployment,
      units,
      1,
      "running",
    );
  }

  for (const r of reserved) {
    if (r.state !== "active") {
      inactiveReserved += 1;
      continue;
    }
    const parsed = parseInstanceClass(r.dbInstanceClass);
    const engine = canonicalEngine(r.productDescription);
    const count = r.dbInstanceCount;
    if (parsed.isServerless) {
      // Aurora Serverless v2 is ACU-billed and not traditionally reservable, so
      // a reserved serverless row is dropped rather than counted. The serverless
      // table counts running instances only; creating a zero-count entry here
      // (the previous behavior) just polluted it with empty rows.
      continue;
    }
    if (parsed.isBurstable) {
      bumpBurstable(r.region, parsed.family, parsed.size, count, "reserved");
      continue;
    }
    const deployment = deploymentFor(engine, r.multiAZ);
    const units = parsed.unparseable
      ? null
      : normalizedUnits(parsed.size, deployment);
    if (units === null) {
      bumpUnparseable(r.region, r.dbInstanceClass, "reserved", count);
      continue;
    }
    bumpBucket(
      r.region,
      parsed,
      engine,
      deployment,
      units * count,
      count,
      "reserved",
    );
  }

  return {
    buckets: [...buckets.values()].sort(compareBuckets),
    burstable: [...burstable.values()].sort((a, b) =>
      a.region !== b.region
        ? (a.region < b.region ? -1 : 1)
        : a.family !== b.family
        ? (a.family < b.family ? -1 : 1)
        : a.size < b.size
        ? -1
        : a.size > b.size
        ? 1
        : 0
    ),
    serverless: [...serverless.values()].sort((a, b) =>
      a.region !== b.region
        ? (a.region < b.region ? -1 : 1)
        : a.engine < b.engine
        ? -1
        : a.engine > b.engine
        ? 1
        : 0
    ),
    unparseable: [...unparseable.values()].sort((a, b) =>
      a.region !== b.region
        ? (a.region < b.region ? -1 : 1)
        : a.dbInstanceClass < b.dbInstanceClass
        ? -1
        : 1
    ),
    inactiveReserved,
  };
}

/** A region × family generation-rollup row (engine & deployment collapsed). */
export interface GenerationRollup {
  /** AWS region. */
  region: string;
  /** Family / generation, e.g. `r7g`. */
  family: string;
  /** Generation, e.g. `7g`. */
  generation: string;
  /** Total running large-equivalents. */
  runningLargeEq: number;
  /** Total reserved (active) large-equivalents. */
  reservedLargeEq: number;
  /** Net gap: running − reserved (positive = buy this many large-eq). */
  gapLargeEq: number;
}

/**
 * Roll buckets up to region × family, collapsing engine and deployment, for
 * the headline "large equivalents per generation" view.
 *
 * @param buckets The per-bucket aggregation.
 * @returns Sorted generation-rollup rows.
 */
export function rollupByGeneration(buckets: Bucket[]): GenerationRollup[] {
  const map = new Map<string, GenerationRollup>();
  for (const b of buckets) {
    const key = `${b.region} ${b.family}`;
    let r = map.get(key);
    if (!r) {
      r = {
        region: b.region,
        family: b.family,
        generation: b.generation,
        runningLargeEq: 0,
        reservedLargeEq: 0,
        gapLargeEq: 0,
      };
      map.set(key, r);
    }
    r.runningLargeEq += b.runningLargeEq;
    r.reservedLargeEq += b.reservedLargeEq;
  }
  for (const r of map.values()) {
    r.gapLargeEq = round2(r.runningLargeEq - r.reservedLargeEq);
    r.runningLargeEq = round2(r.runningLargeEq);
    r.reservedLargeEq = round2(r.reservedLargeEq);
  }
  return [...map.values()].sort((a, b) =>
    a.region !== b.region
      ? (a.region < b.region ? -1 : 1)
      : a.family < b.family
      ? -1
      : a.family > b.family
      ? 1
      : 0
  );
}

// ---------------------------------------------------------------------------
// Per-account aggregation — the purchase list when RI discount sharing is OFF
// ---------------------------------------------------------------------------

/** A large-equivalent bucket scoped to a single owning account. */
export interface AccountBucket {
  /** 12-digit owning account id. */
  accountId: string;
  /** Friendly account label. */
  accountName: string;
  /** AWS region. */
  region: string;
  /** Instance family, e.g. `r8g`. */
  family: string;
  /** Generation, e.g. `8g`. */
  generation: string;
  /** Canonical engine. */
  engine: string;
  /** Deployment dimension. */
  deployment: string;
  /** Running capacity in large-equivalents. */
  runningLargeEq: number;
  /** Reserved (active) capacity in large-equivalents. */
  reservedLargeEq: number;
  /** Running instances summed into this bucket. */
  runningInstances: number;
  /** Reserved instances (sum of DBInstanceCount) in this bucket. */
  reservedInstances: number;
}

/** Stable order: account, region, family, engine, deployment. */
export function compareAccountBuckets(
  a: AccountBucket,
  b: AccountBucket,
): number {
  if (a.accountName !== b.accountName) {
    return a.accountName < b.accountName ? -1 : 1;
  }
  if (a.region !== b.region) return a.region < b.region ? -1 : 1;
  if (a.family !== b.family) return a.family < b.family ? -1 : 1;
  if (a.engine !== b.engine) return a.engine < b.engine ? -1 : 1;
  return a.deployment < b.deployment ? -1 : a.deployment > b.deployment ? 1 : 0;
}

/**
 * Aggregate the large-equivalent buckets **with the owning account as an extra
 * dimension** — the purchasable line items when RI discount sharing is
 * disabled and a reservation only benefits the account that bought it. Same
 * normalization and carve-out rules as {@link aggregate} (burstable,
 * serverless, unparseable, and inactive reservations are excluded here).
 *
 * @param instances Decoded provisioned-instance rows.
 * @param reserved Decoded reserved-instance rows.
 * @returns Sorted per-account buckets.
 */
export function aggregateByAccount(
  instances: InstanceRecord[],
  reserved: ReservedRecord[],
): AccountBucket[] {
  const map = new Map<string, AccountBucket>();
  const bump = (
    accountId: string,
    accountName: string,
    region: string,
    parsed: ParsedClass,
    engine: string,
    deployment: string,
    count: number,
    side: "running" | "reserved",
  ) => {
    if (parsed.isServerless || parsed.isBurstable || parsed.unparseable) return;
    const units = normalizedUnits(parsed.size, deployment);
    if (units === null) return;
    const key =
      `${accountId} ${region} ${parsed.family} ${engine} ${deployment}`;
    let b = map.get(key);
    if (!b) {
      b = {
        accountId,
        accountName,
        region,
        family: parsed.family,
        generation: parsed.generation,
        engine,
        deployment,
        runningLargeEq: 0,
        reservedLargeEq: 0,
        runningInstances: 0,
        reservedInstances: 0,
      };
      map.set(key, b);
    }
    if (side === "running") {
      b.runningLargeEq += units * count;
      b.runningInstances += count;
    } else {
      b.reservedLargeEq += units * count;
      b.reservedInstances += count;
    }
  };

  for (const i of instances) {
    const engine = canonicalEngine(i.engine);
    bump(
      i.accountId,
      i.accountName,
      i.region,
      parseInstanceClass(i.dbInstanceClass),
      engine,
      deploymentFor(engine, i.multiAZ),
      1,
      "running",
    );
  }
  for (const r of reserved) {
    if (r.state !== "active") continue;
    const engine = canonicalEngine(r.productDescription);
    bump(
      r.accountId,
      r.accountName,
      r.region,
      parseInstanceClass(r.dbInstanceClass),
      engine,
      deploymentFor(engine, r.multiAZ),
      r.dbInstanceCount,
      "reserved",
    );
  }

  return [...map.values()].sort(compareAccountBuckets);
}

// ---------------------------------------------------------------------------
// Never-throws helpers
// ---------------------------------------------------------------------------

function tryLog(
  // deno-lint-ignore no-explicit-any
  logger: any,
  level: "info" | "warn" | "debug" | "error",
  message: string,
  props?: Record<string, unknown>,
): void {
  try {
    logger?.[level]?.(message, props);
  } catch {
    // swallow — logging is observability, not correctness
  }
}

const TEXT_DECODER = new TextDecoder();

function decodeJson(bytes: Uint8Array | null): unknown | undefined {
  if (!bytes || bytes.length === 0) return undefined;
  try {
    return JSON.parse(TEXT_DECODER.decode(bytes));
  } catch {
    return undefined;
  }
}

/** Round to 2 decimals, dropping floating-point noise. */
export function round2(n: number): number {
  return Math.round((n + Number.EPSILON) * 100) / 100;
}

/** Format a number for display: rounded to at most 2 decimals, integers bare. */
export function fmtNum(n: number): string {
  return String(round2(n));
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

/**
 * Walk `context.stepExecutions`, find steps whose `modelType` is
 * {@link RESERVATIONS_MODEL_TYPE}, and decode their `instance`, `reserved`, and
 * `scan_error` artifacts. Malformed or schema-mismatched artifacts are counted
 * and skipped, never thrown.
 *
 * @param context The report execution context supplied by the swamp runtime.
 * @returns The decoded instance / reserved / error rows and a skipped count.
 */
export async function collect(
  // deno-lint-ignore no-explicit-any
  context: any,
): Promise<Collected> {
  const logger = context.logger;
  const instances: InstanceRecord[] = [];
  const reserved: ReservedRecord[] = [];
  const errors: ScanError[] = [];
  let skipped = 0;
  let matchingSteps = 0;
  const observed = new Set<string>();

  for (const step of context.stepExecutions ?? []) {
    if (typeof step?.modelType === "string") observed.add(step.modelType);
    if (step.modelType !== RESERVATIONS_MODEL_TYPE) continue;
    matchingSteps++;

    for (const handle of step.dataHandles ?? []) {
      const specName: string | undefined = handle.metadata?.tags?.specName ??
        handle.specName;
      if (
        specName !== INSTANCE_SPEC && specName !== RESERVED_SPEC &&
        specName !== SCAN_ERROR_SPEC
      ) continue;

      const bytes: Uint8Array | null = await context.dataRepository.getContent(
        step.modelType,
        step.modelId,
        handle.name,
        handle.version,
      );
      const value = decodeJson(bytes);
      if (value === undefined) {
        skipped++;
        tryLog(logger, "warn", "Could not decode {spec} artifact {handle}", {
          spec: specName,
          handle: handle.name,
        });
        continue;
      }

      if (specName === INSTANCE_SPEC) {
        const res = InstanceRecordSchema.safeParse(value);
        if (!res.success) {
          skipped++;
          tryLog(
            logger,
            "warn",
            "instance row {handle} failed schema: {fields}",
            {
              handle: handle.name,
              fields: res.error.issues.map((i) => i.path.join(".") || "<root>")
                .join(", "),
            },
          );
          continue;
        }
        instances.push(res.data);
      } else if (specName === RESERVED_SPEC) {
        const res = ReservedRecordSchema.safeParse(value);
        if (!res.success) {
          skipped++;
          tryLog(
            logger,
            "warn",
            "reserved row {handle} failed schema: {fields}",
            {
              handle: handle.name,
              fields: res.error.issues.map((i) => i.path.join(".") || "<root>")
                .join(", "),
            },
          );
          continue;
        }
        reserved.push(res.data);
      } else {
        const res = ScanErrorSchema.safeParse(value);
        if (!res.success) {
          skipped++;
          continue;
        }
        errors.push(res.data);
      }
    }
  }

  const hadSteps = (context.stepExecutions ?? []).length > 0;
  if (hadSteps && matchingSteps === 0) {
    tryLog(
      logger,
      "warn",
      "No step matched modelType={expected}; observed: {observed}",
      {
        expected: RESERVATIONS_MODEL_TYPE,
        observed: [...observed].sort().join(", ") || "<none>",
      },
    );
  }

  tryLog(
    logger,
    "info",
    "Collected {instances} instance(s), {reserved} reservation(s), {errors} error(s) " +
      "from {steps} step(s); {skipped} skipped",
    {
      instances: instances.length,
      reserved: reserved.length,
      errors: errors.length,
      steps: matchingSteps,
      skipped,
    },
  );

  return { instances, reserved, errors, skipped };
}

// ---------------------------------------------------------------------------
// CSV + markdown rendering
// ---------------------------------------------------------------------------

/** RFC 4180-ish CSV field escaping. */
export function csvField(value: string): string {
  if (/[",\r\n]/.test(value)) return '"' + value.replaceAll('"', '""') + '"';
  return value;
}

function bucketRowValues(b: Bucket): string[] {
  return [
    b.region,
    b.family,
    b.generation,
    b.engine,
    b.deployment,
    fmtNum(b.runningLargeEq),
    fmtNum(b.reservedLargeEq),
    fmtNum(round2(b.runningLargeEq - b.reservedLargeEq)),
    String(b.runningInstances),
    String(b.reservedInstances),
  ];
}

/** Render the actionable per-bucket gap table as CSV (header always present). */
export function renderCsv(buckets: Bucket[]): string {
  const header = COLUMNS.join(",");
  const rows = buckets.map((b) => bucketRowValues(b).map(csvField).join(","));
  return [header, ...rows].join("\n") + "\n";
}

/** CSV columns for the per-account gap table, in header order. */
export const ACCOUNT_COLUMNS = [
  "account_name",
  "account_id",
  "region",
  "family",
  "generation",
  "engine",
  "deployment",
  "running_large_eq",
  "reserved_large_eq",
  "gap_large_eq",
  "running_instances",
  "reserved_instances",
] as const;

/** Render the per-account gap table as CSV (header always present). */
export function renderCsvByAccount(buckets: AccountBucket[]): string {
  const header = ACCOUNT_COLUMNS.join(",");
  const rows = buckets.map((b) =>
    [
      b.accountName,
      b.accountId,
      b.region,
      b.family,
      b.generation,
      b.engine,
      b.deployment,
      fmtNum(b.runningLargeEq),
      fmtNum(b.reservedLargeEq),
      fmtNum(round2(b.runningLargeEq - b.reservedLargeEq)),
      String(b.runningInstances),
      String(b.reservedInstances),
    ].map(csvField).join(",")
  );
  return [header, ...rows].join("\n") + "\n";
}

function mdEscape(value: string): string {
  return value.replaceAll("|", "\\|");
}

function mdTable(header: string[], rows: string[][]): string {
  if (rows.length === 0) return "_None._\n";
  const head = `| ${header.join(" | ")} |`;
  const sep = `| ${header.map(() => "---").join(" | ")} |`;
  const body = rows.map((r) => `| ${r.map(mdEscape).join(" | ")} |`);
  return [head, sep, ...body].join("\n") + "\n";
}

/**
 * Render the operator markdown report.
 *
 * @param collected Decoded rows from {@link collect}.
 * @param agg Aggregation from {@link aggregate}.
 * @param rollup Generation rollup from {@link rollupByGeneration}.
 * @param generatedAt ISO timestamp for the header.
 * @param workflowName Originating workflow name.
 * @returns The full markdown document.
 */
export function renderMarkdown(
  collected: Collected,
  agg: Aggregation,
  rollup: GenerationRollup[],
  accountBuckets: AccountBucket[],
  generatedAt: string,
  workflowName: string,
): string {
  const { errors } = collected;
  const authExpired = errors.filter((e) => e.kind === "auth_expired");
  const accessDenied = errors.filter((e) => e.kind === "access_denied");
  const otherErrors = errors.filter((e) => e.kind === "other");

  const accounts = new Set<string>();
  for (const i of collected.instances) accounts.add(i.accountId);
  for (const r of collected.reserved) accounts.add(r.accountId);
  for (const e of errors) if (e.accountId) accounts.add(e.accountId);
  const regions = new Set(collected.instances.map((i) => i.region));

  const totalRunning = round2(
    agg.buckets.reduce((s, b) => s + b.runningLargeEq, 0),
  );
  const totalReserved = round2(
    agg.buckets.reduce((s, b) => s + b.reservedLargeEq, 0),
  );
  const totalGap = round2(totalRunning - totalReserved);

  const lines: string[] = [];
  lines.push("# RDS Large-Equivalent Reservation Gap");
  lines.push("");
  lines.push(`_Generated ${generatedAt} · workflow \`${workflowName}\`_`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Accounts seen: **${accounts.size}**`);
  lines.push(`- Regions covered: **${regions.size}**`);
  lines.push(
    `- Non-burstable running capacity: **${fmtNum(totalRunning)}** large-eq`,
  );
  lines.push(
    `- Reserved (active) capacity: **${fmtNum(totalReserved)}** large-eq`,
  );
  lines.push(
    `- **Net uncovered: ${fmtNum(totalGap)} large-eq** ` +
      (totalGap > 0
        ? "(buy reservations to cover)"
        : totalGap < 0
        ? "(over-reserved)"
        : "(fully covered)"),
  );
  lines.push(
    `- Coverage gaps: **${authExpired.length}** scan(s) need ` +
      "`aws sso login`, " +
      `**${accessDenied.length}** blocked by SCP/IAM` +
      (otherErrors.length ? `, **${otherErrors.length}** other error(s)` : ""),
  );
  lines.push("");

  // Headline: per-generation rollup.
  lines.push("## Large equivalents per generation (region × family)");
  lines.push("");
  lines.push(
    "Headline view — engine and deployment collapsed. `gap = running − " +
      "reserved`; a positive gap is capacity to cover.",
  );
  lines.push("");
  lines.push(
    mdTable(
      ["region", "family", "gen", "running", "reserved", "gap (buy)"],
      rollup.map((r) => [
        r.region,
        r.family,
        r.generation,
        fmtNum(r.runningLargeEq),
        fmtNum(r.reservedLargeEq),
        fmtNum(r.gapLargeEq),
      ]),
    ),
  );

  // Actionable: per-bucket (purchasable RI line items).
  lines.push("## Purchasable buckets (region × family × engine × deployment)");
  lines.push("");
  lines.push(
    "Each row is the granularity an RDS reservation is scoped to. " +
      "`gap` large-equivalents is the size-flexible coverage to buy.",
  );
  lines.push("");
  lines.push(
    mdTable(
      [
        "region",
        "family",
        "engine",
        "deployment",
        "running",
        "reserved",
        "gap (buy)",
        "inst",
      ],
      agg.buckets.map((b) => [
        b.region,
        b.family,
        b.engine,
        b.deployment,
        fmtNum(b.runningLargeEq),
        fmtNum(b.reservedLargeEq),
        fmtNum(round2(b.runningLargeEq - b.reservedLargeEq)),
        String(b.runningInstances),
      ]),
    ),
  );

  // Per-account purchase list (for the RI-sharing-OFF case).
  lines.push("## Per-account purchase list (if RI discount sharing is OFF)");
  lines.push("");
  lines.push(
    "Same large-equivalents, but split by the **owning account**. Under " +
      "AWS Organizations consolidated billing, RI discount sharing is ON by " +
      "default and a reservation floats org-wide — in that case use the " +
      "org-wide buckets above. If sharing is disabled, buy each account's " +
      "`gap` in that account.",
  );
  lines.push("");
  lines.push(
    mdTable(
      [
        "account",
        "region",
        "family",
        "engine",
        "deployment",
        "running",
        "reserved",
        "gap (buy)",
      ],
      accountBuckets.map((b) => [
        b.accountName,
        b.region,
        b.family,
        b.engine,
        b.deployment,
        fmtNum(b.runningLargeEq),
        fmtNum(b.reservedLargeEq),
        fmtNum(round2(b.runningLargeEq - b.reservedLargeEq)),
      ]),
    ),
  );

  // Burstable carve-out.
  lines.push("## Burstable (t-class) — counted separately, not normalized");
  lines.push("");
  lines.push(
    mdTable(
      ["region", "family", "size", "running", "reserved"],
      agg.burstable.map((l) => [
        l.region,
        l.family,
        l.size,
        String(l.runningInstances),
        String(l.reservedInstances),
      ]),
    ),
  );

  // Serverless carve-out.
  if (agg.serverless.length > 0) {
    lines.push("## Serverless (Aurora Serverless v2) — informational");
    lines.push("");
    lines.push(
      mdTable(
        ["region", "engine", "instances"],
        agg.serverless.map((s) => [s.region, s.engine, String(s.count)]),
      ),
    );
  }

  // Unparseable carve-out.
  if (agg.unparseable.length > 0) {
    lines.push("## ⚠️ Unparseable instance classes (excluded from large-eq)");
    lines.push("");
    lines.push(
      mdTable(
        ["region", "class", "source", "count"],
        agg.unparseable.map((u) => [
          u.region,
          u.dbInstanceClass,
          u.source,
          String(u.count),
        ]),
      ),
    );
  }

  // Coverage gaps.
  if (authExpired.length > 0) {
    lines.push("## 🔑 Needs `aws sso login` (could not assess)");
    lines.push("");
    const byProfile = new Map<string, number>();
    for (const e of authExpired) {
      const k = e.profile || "<ambient>";
      byProfile.set(k, (byProfile.get(k) ?? 0) + 1);
    }
    for (const [p, n] of [...byProfile.entries()].sort()) {
      lines.push(`- \`${p}\` — ${n} scan(s) unassessed`);
    }
    lines.push("");
  }

  if (accessDenied.length > 0) {
    const blockedRegions = [
      ...new Set(accessDenied.map((e) => e.region).filter(Boolean)),
    ].sort();
    lines.push("## 🚫 Blocked by SCP/IAM (expected for out-of-scope regions)");
    lines.push("");
    lines.push(
      `${accessDenied.length} scan(s) were denied — typically a region your ` +
        "org's SCP does not permit. Regions: " +
        (blockedRegions.length
          ? blockedRegions.map((r) => `\`${r}\``).join(", ")
          : "—"),
    );
    lines.push("");
  }

  return lines.join("\n") + "\n";
}

// ---------------------------------------------------------------------------
// Report export
// ---------------------------------------------------------------------------

/** Structured JSON payload returned alongside the markdown body. */
export interface ReportJson {
  /** Stable report name. */
  report: string;
  /** Originating workflow. */
  workflow: string;
  /** ISO timestamp taken at report start; `""` only if the report degraded before the timestamp was captured. */
  generatedAt: string;
  /** CSV columns, in header order. */
  columns: string[];
  /** Accounts represented. */
  accountCount: number;
  /** Regions represented. */
  regionCount: number;
  /** Provisioned instances seen. */
  instanceCount: number;
  /** Reserved rows seen. */
  reservedCount: number;
  /** Total non-burstable running large-equivalents. */
  totalRunningLargeEq: number;
  /** Total reserved (active) large-equivalents. */
  totalReservedLargeEq: number;
  /** Net uncovered large-equivalents (running − reserved). */
  netGapLargeEq: number;
  /** Per-generation rollup rows. */
  generationRollup: GenerationRollup[];
  /** Per-bucket (purchasable) rows. */
  buckets: Bucket[];
  /** Per-account buckets (purchase list when RI sharing is off). */
  accountBuckets: AccountBucket[];
  /** Per-account CSV body (header + rows + trailing newline). */
  csvByAccount: string;
  /** Burstable lines. */
  burstable: BurstableLine[];
  /** Serverless lines. */
  serverless: Array<{ region: string; engine: string; count: number }>;
  /** Unparseable class lines. */
  unparseable: UnparseableLine[];
  /** Reserved rows skipped as inactive. */
  inactiveReserved: number;
  /** Scan errors by kind. */
  errorsByKind: Record<string, number>;
  /** Artifacts skipped during collection. */
  skipped: number;
  /** True when the outer guard absorbed an unexpected failure. */
  degraded: boolean;
  /** The CSV body (header + per-bucket rows + trailing newline). */
  csv: string;
}

/**
 * The `@jentz/aws-rds-reservation-coverage` workflow-scope report. Returns
 * `{ markdown, json }`; swamp persists them as `report-{name}` (text/markdown)
 * and `report-{name}-json` (application/json).
 */
export const report = {
  name: "@jentz/aws-rds-reservation-coverage",
  description:
    "Normalizes running and reserved RDS capacity into size-flexible " +
    "large-equivalent units and reports the running-minus-reserved coverage " +
    "gap per region × family × engine × deployment, with a per-account " +
    "breakdown for the RI-discount-sharing-disabled case. Burstable and " +
    "serverless capacity are carved out. Consumes @jentz/aws-rds-reservations " +
    "rows collected earlier in the workflow.",
  scope: "workflow" as const,
  labels: ["aws", "rds", "cost", "finops", "reserved-instances"],
  // deno-lint-ignore no-explicit-any
  execute: async (context: any): Promise<{
    markdown: string;
    json: ReportJson;
  }> => {
    const workflowName = context.workflowName ?? "<unknown-workflow>";
    const logger = context.logger;
    tryLog(
      logger,
      "info",
      "Running aws-rds-reservation-coverage for {workflow}",
      {
        workflow: workflowName,
      },
    );

    let collected: Collected = {
      instances: [],
      reserved: [],
      errors: [],
      skipped: 0,
    };
    let agg: Aggregation = {
      buckets: [],
      burstable: [],
      serverless: [],
      unparseable: [],
      inactiveReserved: 0,
    };
    let rollup: GenerationRollup[] = [];
    let accountBuckets: AccountBucket[] = [];
    let generatedAt = "";
    let degraded = false;
    let markdown = "";
    let csv = renderCsv([]);
    let csvByAccount = renderCsvByAccount([]);

    try {
      generatedAt = new Date().toISOString();
      collected = await collect(context);
      agg = aggregate(collected.instances, collected.reserved);
      rollup = rollupByGeneration(agg.buckets);
      accountBuckets = aggregateByAccount(
        collected.instances,
        collected.reserved,
      );
      csv = renderCsv(agg.buckets);
      csvByAccount = renderCsvByAccount(accountBuckets);
      markdown = renderMarkdown(
        collected,
        agg,
        rollup,
        accountBuckets,
        generatedAt,
        workflowName,
      );
    } catch (err) {
      degraded = true;
      const detail = err instanceof Error ? err.message : String(err);
      tryLog(logger, "warn", "report degraded: {detail}", { detail });
      markdown =
        `# RDS Large-Equivalent Reservation Gap\n\n_Report degraded: ${detail}_\n`;
      csv = renderCsv([]);
    }

    const errorsByKind: Record<string, number> = {
      auth_expired: 0,
      access_denied: 0,
      other: 0,
    };
    for (const e of collected.errors) errorsByKind[e.kind]++;

    const accounts = new Set<string>();
    for (const i of collected.instances) accounts.add(i.accountId);
    for (const r of collected.reserved) accounts.add(r.accountId);
    const regions = new Set(collected.instances.map((i) => i.region));
    const totalRunning = round2(
      agg.buckets.reduce((s, b) => s + b.runningLargeEq, 0),
    );
    const totalReserved = round2(
      agg.buckets.reduce((s, b) => s + b.reservedLargeEq, 0),
    );

    const json: ReportJson = {
      report: "@jentz/aws-rds-reservation-coverage",
      workflow: workflowName,
      generatedAt,
      columns: [...COLUMNS],
      accountCount: accounts.size,
      regionCount: regions.size,
      instanceCount: collected.instances.length,
      reservedCount: collected.reserved.length,
      totalRunningLargeEq: totalRunning,
      totalReservedLargeEq: totalReserved,
      netGapLargeEq: round2(totalRunning - totalReserved),
      generationRollup: rollup,
      buckets: agg.buckets.map((b) => ({
        ...b,
        runningLargeEq: round2(b.runningLargeEq),
        reservedLargeEq: round2(b.reservedLargeEq),
      })),
      accountBuckets: accountBuckets.map((b) => ({
        ...b,
        runningLargeEq: round2(b.runningLargeEq),
        reservedLargeEq: round2(b.reservedLargeEq),
      })),
      csvByAccount,
      burstable: agg.burstable,
      serverless: agg.serverless,
      unparseable: agg.unparseable,
      inactiveReserved: agg.inactiveReserved,
      errorsByKind,
      skipped: collected.skipped,
      degraded,
      csv,
    };

    tryLog(logger, "info", "report finished: {buckets} bucket(s){degraded}", {
      buckets: agg.buckets.length,
      degraded: degraded ? " (degraded)" : "",
    });

    return { markdown, json };
  },
};
