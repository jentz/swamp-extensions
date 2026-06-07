/**
 * Swamp workflow-scope report: `@jentz/aws-rds-reservation-coverage`.
 *
 * Consumes the `instance`, `reserved`, and `scan_error` resources produced
 * earlier in the workflow by `@jentz/aws-rds-reservations` and answers the
 * RDS reserved-instance planning question: **how many "large equivalents" of
 * size-flexible capacity must I still buy?** — the uncovered gap summed across
 * each reservation pool (region × family × engine). Pure data shaping — no AWS
 * API access.
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
 * A **reservation-pool rollup** groups buckets by region × family × engine,
 * collapsing only deployment (Single-AZ and Multi-AZ net together — Multi-AZ
 * folds in at 2×, so the units are commensurable). Engine is kept, because a
 * reservation cannot cover a different engine. The headline **large-equivalents
 * to buy** is the sum of the positive pool gaps: over-reserved pools never
 * offset under-reserved ones across the hard engine / family / region boundary.
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
 *   - **Non-size-flex commercial** — **SQL Server** (all editions), **Oracle
 *     License-Included**, and **RDS Custom** (`custom-oracle-*`,
 *     `custom-sqlserver-*`). RDS size flexibility does not apply to these, so
 *     they are NOT folded into large-equivalents; they are reported as raw
 *     counts at `region × family × engine × size × deployment`, with edition
 *     and license preserved in the engine token.
 *   - **Serverless** (`db.serverless`, Aurora Serverless v2) is counted
 *     separately (ACU-billed, not instance-class capacity).
 *   - **Unparseable** classes are listed with a warning.
 *
 * A single shared {@link classify} routes every row for both the org-wide
 * {@link aggregate} and the per-account {@link aggregateByAccount}, so these
 * carve-outs surface per account too — the RI-discount-sharing-OFF purchase
 * list never silently drops an account whose footprint is entirely burstable,
 * serverless, or unparseable. The one exception is the non-size-flex commercial
 * carve-out, which has no per-account large-eq line and is surfaced org-wide.
 *
 * ## Engine, edition, and license
 *
 * The engine token preserves the dimensions an RDS reservation is actually
 * scoped to. Open-source and Aurora engines collapse to a base token (running
 * `postgres` and reserved `postgresql` both become `postgres`; Aurora variants
 * stay distinct). The **commercial** engines additionally carry edition and
 * license — `oracle-ee-byol`, `oracle-se2-li`, `sqlserver-se-li`,
 * `db2-ae-byol` — because a reservation matches on edition AND license: an
 * `oracle-se2` reservation does not cover an `oracle-ee` instance, and a
 * License-Included reservation does not cover a BYOL one. The running side's
 * license comes from the upstream `licenseModel` field; the reserved side's
 * from the product-description `(byol)`/`(li)` suffix. See
 * {@link parseEngineIdentity}.
 *
 * Size flexibility — and therefore large-equivalent netting — is applied only
 * to the engines AWS grants it to: MySQL, MariaDB, PostgreSQL, Db2, Aurora, and
 * Oracle **BYOL**. SQL Server, Oracle License-Included, and RDS Custom go to
 * the non-size-flex carve-out instead.
 *
 * ## Caveats
 *
 * Only `active` reservations count toward coverage. When the upstream
 * `licenseModel` is absent (rows swept before the field existed, or Aurora /
 * RDS Custom which do not report one), Oracle SE2 cannot be proven BYOL and is
 * routed conservatively to the non-size-flex carve-out rather than netted —
 * Oracle EE (BYOL-only) and standard RDS SQL Server (LI-only) are inferred from
 * the engine and remain unaffected. A re-sweep on the upstream model populates
 * the real license model.
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
  // Optional with an empty default: `licenseModel` was added to the upstream
  // `instance` resource in @jentz/aws-rds-reservations 2026.06.06.2. Rows swept
  // before that release lack the field — accept them (default "") rather than
  // failing safeParse and skipping the instance. Oracle BYOL-vs-LI routing
  // simply degrades to the conservative carve-out for "" license (see
  // {@link parseEngineIdentity}). A re-sweep populates the real value.
  licenseModel: z.string().default(""),
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
  /** Engine, e.g. `postgres`, `aurora-postgresql`, `mysql`, `oracle-ee`, `sqlserver-se`. */
  engine: string;
  /** Engine version string. */
  engineVersion: string;
  /**
   * License model, e.g. `license-included`, `bring-your-own-license`,
   * `general-public-license`; `""` when unreported (Aurora / RDS Custom) or
   * when collected before the upstream field existed. Decisive for Oracle
   * (size-flex applies to BYOL only); see {@link parseEngineIdentity}.
   */
  licenseModel: string;
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
 * Normalize a raw license token — from a reserved `ProductDescription` suffix
 * (`byol`, `li`, `mpl`) or a running `LicenseModel`
 * (`bring-your-own-license`, `license-included`, `marketplace-license`,
 * `general-public-license`, `postgresql-license`) — onto one of `byol`, `li`,
 * `mpl`, or `""`. Single-license engines (open-source / Aurora) and unknown
 * tokens map to `""` so they never split a bucket.
 *
 * Db2 is offered both BYOL and through AWS Marketplace, and an RDS Db2 RI is
 * scoped to one of them (separate RIs per license model), so the two must NOT
 * cross-net. The substring matches below cover both the running `LicenseModel`
 * (`bring-your-own-license`, `marketplace-license`) and whatever license suffix
 * AWS appends to a Db2 `ProductDescription` — short (`byol`, `mpl`) or worded
 * (`marketplace`) — so a running and a reserved Db2 row for the same real
 * license land on the same `mpl`/`byol` value.
 *
 * @param raw The raw license string from either side.
 * @returns `byol`, `li`, `mpl`, or `""`.
 */
export function normalizeLicense(raw: string): string {
  const s = (raw ?? "").toLowerCase().trim();
  if (s === "") return "";
  if (s.includes("byol") || s.includes("bring")) return "byol";
  if (s === "li" || s.includes("included")) return "li";
  if (s === "mpl" || s.includes("marketplace")) return "mpl";
  // general-public-license, postgresql-license, … — a single license per
  // engine, so it carries no bucketing information.
  return "";
}

/**
 * Edition token from the part of a commercial engine string after its base
 * keyword (e.g. `oracle-se2-cdb` after `oracle` → `se2`). Returns `""` when the
 * base keyword is absent — only the spaced `sql server` fallback hits this, and
 * scanning the whole string there would spuriously match `se` inside `server`.
 */
function editionAfter(core: string, base: string, order: string[]): string {
  const idx = core.indexOf(base);
  if (idx < 0) return "";
  const tail = core.slice(idx + base.length).replace(/^-/, "");
  for (const e of order) if (tail.includes(e)) return e;
  return "";
}

/**
 * Parsed engine identity for bucketing: the base engine, edition, and license
 * model, plus the bucket token both sides must agree on and whether RDS
 * size-flexible reservations apply.
 *
 * Unlike a flat canonicalization, this **preserves edition and license**, which
 * an RDS reservation is scoped to for the commercial engines: an `oracle-se2`
 * reservation does not cover an `oracle-ee` instance, and a License-Included
 * reservation does not cover a BYOL one. The running side carries the license
 * in a separate `LicenseModel` field; the reserved side carries it as a
 * `(byol)`/`(li)` suffix on the product description (with optional whitespace,
 * e.g. `oracle-se2 (byol)`) — both resolve to the same {@link token}.
 *
 * Two well-grounded inferences fill an unknown license: Oracle **Enterprise
 * Edition is BYOL-only** (no LI offering exists), and standard RDS **SQL Server
 * is License-Included only** (BYOL SQL Server is RDS Custom, kept distinct as
 * `custom-sqlserver`). Oracle SE2 stays genuinely ambiguous when the license is
 * unknown and routes to the conservative non-size-flex carve-out.
 */
export interface EngineIdentity {
  /**
   * Base engine, kept distinct: `postgres`, `mysql`, `mariadb`, `db2`,
   * `oracle`, `sqlserver`, `custom-oracle`, `custom-sqlserver`, `aurora-mysql`,
   * `aurora-postgresql`, `aurora`, or `unknown`.
   */
  engine: string;
  /** Edition for commercial engines: `ee`, `se`, `se2`, `ex`, `web`, `ae`, `dev`; `""` otherwise. */
  edition: string;
  /** License: `byol`, `li`, `mpl`, or `""` (single-license / unknown). */
  license: string;
  /** Bucket token: the base engine for open-source/Aurora, else `base-edition[-license]`. */
  token: string;
  /** True when RDS size-flexible reservations apply, so large-equivalent netting is valid. */
  sizeFlexEligible: boolean;
}

/**
 * Parse a running `Engine` (with its separate `LicenseModel`) or a reserved
 * `ProductDescription` (with an embedded `(byol)`/`(li)` suffix) into an
 * {@link EngineIdentity}. Running `postgres` and reserved `postgresql` collapse
 * to the same `postgres` token; Aurora variants and RDS Custom engines stay
 * distinct so they never net against their non-Custom counterparts.
 *
 * @param raw The raw engine / product-description string.
 * @param licenseModel The running-side `LicenseModel`; `""` for the reserved
 *   side (its license rides the product-description suffix instead).
 * @returns The parsed identity; never throws.
 */
export function parseEngineIdentity(
  raw: string,
  licenseModel = "",
): EngineIdentity {
  const input = (raw ?? "").toLowerCase().trim();
  // Pull a trailing license suffix off the reserved-side product description,
  // tolerating whitespace before the paren ("oracle-se2 (byol)").
  let licenseFromSuffix = "";
  let head = input;
  const m = input.match(/^(.*?)\s*\(([^)]*)\)\s*$/);
  if (m) {
    head = m[1].trim();
    licenseFromSuffix = m[2].trim();
  }
  const s = head.replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  if (s === "") {
    return {
      engine: "unknown",
      edition: "",
      license: "",
      token: "unknown",
      sizeFlexEligible: false,
    };
  }

  const isCustom = s.startsWith("custom-");
  const core = isCustom ? s.slice("custom-".length) : s;

  let engine: string;
  let edition = "";
  if (core.includes("aurora") && core.includes("postgres")) {
    engine = "aurora-postgresql";
  } else if (core.includes("aurora") && core.includes("mysql")) {
    engine = "aurora-mysql";
  } else if (core.includes("aurora")) {
    engine = "aurora";
  } else if (core.includes("postgres")) {
    engine = "postgres";
  } else if (core.includes("maria")) {
    engine = "mariadb";
  } else if (core.includes("mysql")) {
    engine = "mysql";
  } else if (core.includes("oracle")) {
    engine = "oracle";
    edition = editionAfter(core, "oracle", ["se2", "ee", "se"]);
  } else if (
    core.includes("sqlserver") ||
    (core.includes("sql") && core.includes("server"))
  ) {
    engine = "sqlserver";
    edition = editionAfter(core, "sqlserver", ["web", "ex", "dev", "ee", "se"]);
  } else if (core.includes("db2")) {
    engine = "db2";
    edition = editionAfter(core, "db2", ["ae", "se", "ce"]);
  } else {
    engine = core.split("-")[0] || "unknown";
  }

  // RDS Custom keeps its own engine token for the commercial engines so a Custom
  // instance never nets against a regular RDS reservation (and vice versa).
  if (isCustom && (engine === "oracle" || engine === "sqlserver")) {
    engine = "custom-" + engine;
  }

  let license = normalizeLicense(licenseFromSuffix || licenseModel);
  // Oracle Enterprise Edition is BYOL-only; standard RDS SQL Server is
  // License-Included only. Fill an unknown license from that fact so pre-license
  // -model rows still route and bucket consistently. Oracle SE2 has both LI and
  // BYOL offerings, so it is left ambiguous when the license is unknown. The
  // `sqlserver` inference deliberately does NOT cover `custom-sqlserver` (RDS
  // Custom SQL Server is BYOL, not LI) — Custom is non-size-flex regardless, so
  // an unknown-license Custom row simply keeps a license-less token.
  //
  // Db2 (db2-ae / db2-se) is offered BOTH BYOL and via AWS Marketplace, and an
  // RDS Db2 RI is scoped to one of them, so — unlike Oracle EE / SQL Server —
  // the license CANNOT be inferred from the edition. We therefore rely on each
  // side carrying its own license and resolving it identically through
  // {@link normalizeLicense}: the running side via `LicenseModel`
  // (`bring-your-own-license` -> byol, `marketplace-license` -> mpl) and the
  // reserved side via the `ProductDescription` suffix that AWS appends for
  // multi-license engines (assumed present, as for Oracle/SQL Server; the live
  // Db2 suffix spelling is unconfirmed but `normalizeLicense` accepts both the
  // short `(byol)`/`(mpl)` and worded `(marketplace)` forms). If a reserved Db2
  // row ever arrives with no suffix it keeps a license-less token (`db2-ae`)
  // and stays in its own conservative bucket rather than guessing byol-vs-mpl
  // and risking a cross-license over-credit — the same conservative stance as
  // unknown-license Oracle SE2.
  if (license === "") {
    if (engine === "oracle" && edition === "ee") license = "byol";
    else if (engine === "sqlserver") license = "li";
  }

  const sizeFlexEligible = (() => {
    switch (engine) {
      case "postgres":
      case "mysql":
      case "mariadb":
      case "db2":
      case "aurora":
      case "aurora-mysql":
      case "aurora-postgresql":
        return true;
      case "oracle":
        // Size flexibility applies to Oracle BYOL only, never License-Included.
        return license === "byol";
      default:
        // sqlserver (any edition/license), custom-*, unknown.
        return false;
    }
  })();

  const token = edition === ""
    ? engine
    : [engine, edition, license].filter((p) => p !== "").join("-");

  return { engine, edition, license, token, sizeFlexEligible };
}

/**
 * Base engine token (edition and license stripped), e.g. `oracle-ee` →
 * `oracle`, `postgresql` → `postgres`. A thin wrapper over
 * {@link parseEngineIdentity} kept for consumers that only need the family.
 * Bucketing uses {@link parseEngineIdentity} directly so editions and licenses
 * are not collapsed.
 *
 * @param raw The raw engine / product-description string.
 * @returns The base engine token.
 */
export function canonicalEngine(raw: string): string {
  return parseEngineIdentity(raw).engine;
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

/**
 * The single classify-then-route decision for one running or reserved row,
 * shared by {@link aggregate} and {@link aggregateByAccount} so the two views
 * can never drift. The discriminant names exactly the carve-out / bucket
 * destination; the aggregators differ only in how they key and accumulate each
 * kind (and, for `serverless`, that the reserved side drops it — Aurora
 * Serverless v2 is not reservable, so the serverless tally is running-only).
 *
 * `unparseable` covers both a class that fails {@link parseInstanceClass} and a
 * parseable-but-unnormalizable size (e.g. `db.r7g.metal`, where
 * {@link normalizedUnits} returns `null`) — the same fold {@link aggregate} has
 * always done, now applied identically per account.
 */
export type Classification =
  | { kind: "serverless"; engine: string }
  | { kind: "burstable"; family: string; size: string }
  | { kind: "unparseable"; dbInstanceClass: string }
  | {
    kind: "nonSizeFlex";
    family: string;
    engine: string;
    size: string;
    deployment: string;
  }
  | {
    kind: "bucket";
    family: string;
    generation: string;
    engine: string;
    deployment: string;
    units: number;
  };

/**
 * Classify one row by its raw instance class and parsed {@link EngineIdentity}
 * into the destination both aggregations route it to. Pure; never throws.
 *
 * @param dbInstanceClass The raw class string (e.g. `db.r7g.large`).
 * @param id The parsed engine identity (carries the bucket token and size-flex eligibility).
 * @param multiAZ The upstream Multi-AZ flag (Aurora is forced Single-AZ in {@link deploymentFor}).
 * @returns The routing decision.
 */
export function classify(
  dbInstanceClass: string,
  id: EngineIdentity,
  multiAZ: boolean,
): Classification {
  const parsed = parseInstanceClass(dbInstanceClass);
  if (parsed.isServerless) return { kind: "serverless", engine: id.engine };
  if (parsed.isBurstable) {
    return { kind: "burstable", family: parsed.family, size: parsed.size };
  }
  if (parsed.unparseable) return { kind: "unparseable", dbInstanceClass };
  const deployment = deploymentFor(id.engine, multiAZ);
  if (!id.sizeFlexEligible) {
    return {
      kind: "nonSizeFlex",
      family: parsed.family,
      engine: id.token,
      size: parsed.size,
      deployment,
    };
  }
  const units = normalizedUnits(parsed.size, deployment);
  if (units === null) return { kind: "unparseable", dbInstanceClass };
  return {
    kind: "bucket",
    family: parsed.family,
    generation: parsed.generation,
    engine: id.token,
    deployment,
    units,
  };
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

/**
 * A non-size-flexible commercial line, reported as raw counts (not normalized).
 *
 * RDS size flexibility does **not** apply to SQL Server, Oracle
 * License-Included, or RDS Custom, so an `xlarge` reservation does not cover two
 * `large` instances the way it would for a size-flex engine — folding these
 * into large-equivalents would invent coverage that AWS does not grant. They
 * are kept here as raw running-vs-reserved counts at the exact granularity a
 * reservation matches: `region × family × engine × size × deployment`, where
 * `engine` preserves the edition and license (e.g. `oracle-se2-li`,
 * `sqlserver-ee-li`, `custom-sqlserver-se-byol`).
 */
export interface NonSizeFlexLine {
  /** AWS region. */
  region: string;
  /** Family, e.g. `r6i`. */
  family: string;
  /** Engine token with edition and license, e.g. `sqlserver-se-li`, `oracle-ee-li`. */
  engine: string;
  /** Size token, e.g. `xlarge`. */
  size: string;
  /** Deployment dimension (`Multi-AZ` | `Single-AZ`). */
  deployment: string;
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
  /** Non-size-flex commercial lines (SQL Server, Oracle LI, RDS Custom), sorted. */
  nonSizeFlex: NonSizeFlexLine[];
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
 * The owning-account dimension carried through the shared aggregation core.
 * Both views accumulate account-tagged lines internally; the org-wide
 * {@link aggregate} collapses every account into one entry (empty key prefix)
 * and strips the tag in its projection, while {@link aggregateByAccount} keys by
 * `accountId` and keeps it. Centralizing the tag here lets one routing routine
 * serve both, so a new carve-out kind or key dimension is added once.
 */
interface AccountTag {
  accountId: string;
  accountName: string;
}

/** Account-tagged intermediate lines accumulated by {@link routeRows}. */
interface CoreBucket extends AccountTag, Bucket {}
interface CoreBurstable extends AccountTag, BurstableLine {}
interface CoreServerless extends AccountTag {
  region: string;
  engine: string;
  count: number;
}
interface CoreUnparseable extends AccountTag, UnparseableLine {}
interface CoreNonSizeFlex extends AccountTag, NonSizeFlexLine {}

/** The account-tagged maps the shared core fills. */
interface CoreAggregation {
  buckets: Map<string, CoreBucket>;
  burstable: Map<string, CoreBurstable>;
  serverless: Map<string, CoreServerless>;
  unparseable: Map<string, CoreUnparseable>;
  nonSizeFlex: Map<string, CoreNonSizeFlex>;
  inactiveReserved: Map<string, AccountInactiveReserved>;
}

/**
 * Route every running and reserved row through {@link classify} into
 * account-tagged maps. `keyPrefix` selects the grouping: `""` collapses all
 * accounts into one entry (org-wide), an `accountId` keeps them separate
 * (per account). Every carve-out — the reserved-serverless drop, inactive
 * tracking, and all five kinds — lives here once so the two public views can
 * never drift.
 */
function routeRows(
  instances: InstanceRecord[],
  reserved: ReservedRecord[],
  keyPrefix: (rec: AccountTag) => string,
): CoreAggregation {
  const core: CoreAggregation = {
    buckets: new Map(),
    burstable: new Map(),
    serverless: new Map(),
    unparseable: new Map(),
    nonSizeFlex: new Map(),
    inactiveReserved: new Map(),
  };

  // Prepend the (non-empty) account prefix so org-wide keys stay byte-identical
  // to the un-prefixed originals.
  const withPrefix = (prefix: string, base: string) =>
    prefix ? `${prefix} ${base}` : base;

  const bumpBucket = (
    tag: AccountTag,
    region: string,
    family: string,
    generation: string,
    engine: string,
    deployment: string,
    largeEq: number,
    count: number,
    side: "running" | "reserved",
  ) => {
    const key = withPrefix(
      keyPrefix(tag),
      bucketKey(region, family, engine, deployment),
    );
    let b = core.buckets.get(key);
    if (!b) {
      b = {
        ...tag,
        ...emptyBucket(region, family, generation, engine, deployment),
      };
      core.buckets.set(key, b);
    }
    if (side === "running") {
      b.runningLargeEq += largeEq;
      b.runningInstances += count;
    } else {
      b.reservedLargeEq += largeEq;
      b.reservedInstances += count;
    }
  };

  const bumpBurstable = (
    tag: AccountTag,
    region: string,
    family: string,
    size: string,
    count: number,
    side: "running" | "reserved",
  ) => {
    const key = withPrefix(keyPrefix(tag), `${region} ${family} ${size}`);
    let l = core.burstable.get(key);
    if (!l) {
      l = {
        ...tag,
        region,
        family,
        size,
        runningInstances: 0,
        reservedInstances: 0,
      };
      core.burstable.set(key, l);
    }
    if (side === "running") l.runningInstances += count;
    else l.reservedInstances += count;
  };

  const bumpServerless = (
    tag: AccountTag,
    region: string,
    engine: string,
  ) => {
    const key = withPrefix(keyPrefix(tag), `${region} ${engine}`);
    const l = core.serverless.get(key) ??
      { ...tag, region, engine, count: 0 };
    l.count += 1;
    core.serverless.set(key, l);
  };

  const bumpUnparseable = (
    tag: AccountTag,
    region: string,
    dbInstanceClass: string,
    source: "instance" | "reserved",
    count: number,
  ) => {
    const key = withPrefix(
      keyPrefix(tag),
      `${region} ${dbInstanceClass} ${source}`,
    );
    let l = core.unparseable.get(key);
    if (!l) {
      l = { ...tag, region, dbInstanceClass, source, count: 0 };
      core.unparseable.set(key, l);
    }
    l.count += count;
  };

  const bumpNonSizeFlex = (
    tag: AccountTag,
    region: string,
    family: string,
    engine: string,
    size: string,
    deployment: string,
    count: number,
    side: "running" | "reserved",
  ) => {
    const key = withPrefix(
      keyPrefix(tag),
      `${region} ${family} ${engine} ${size} ${deployment}`,
    );
    let l = core.nonSizeFlex.get(key);
    if (!l) {
      l = {
        ...tag,
        region,
        family,
        engine,
        size,
        deployment,
        runningInstances: 0,
        reservedInstances: 0,
      };
      core.nonSizeFlex.set(key, l);
    }
    if (side === "running") l.runningInstances += count;
    else l.reservedInstances += count;
  };

  const bumpInactive = (tag: AccountTag, count: number) => {
    // Inactive reservations are always tracked per account; the org-wide view
    // sums these counts into a single number in its projection.
    const key = tag.accountId;
    const l = core.inactiveReserved.get(key) ?? { ...tag, count: 0 };
    l.count += count;
    core.inactiveReserved.set(key, l);
  };

  for (const i of instances) {
    const tag: AccountTag = {
      accountId: i.accountId,
      accountName: i.accountName,
    };
    const id = parseEngineIdentity(i.engine, i.licenseModel);
    const c = classify(i.dbInstanceClass, id, i.multiAZ);
    switch (c.kind) {
      case "serverless":
        bumpServerless(tag, i.region, c.engine);
        break;
      case "burstable":
        bumpBurstable(tag, i.region, c.family, c.size, 1, "running");
        break;
      case "unparseable":
        bumpUnparseable(tag, i.region, c.dbInstanceClass, "instance", 1);
        break;
      case "nonSizeFlex":
        // SQL Server, Oracle License-Included, RDS Custom: size flexibility does
        // not apply, so these are kept as raw counts, never folded into large-eq.
        bumpNonSizeFlex(
          tag,
          i.region,
          c.family,
          c.engine,
          c.size,
          c.deployment,
          1,
          "running",
        );
        break;
      case "bucket":
        bumpBucket(
          tag,
          i.region,
          c.family,
          c.generation,
          c.engine,
          c.deployment,
          c.units,
          1,
          "running",
        );
        break;
    }
  }

  for (const r of reserved) {
    const tag: AccountTag = {
      accountId: r.accountId,
      accountName: r.accountName,
    };
    if (r.state !== "active") {
      bumpInactive(tag, 1);
      continue;
    }
    const id = parseEngineIdentity(r.productDescription);
    const c = classify(r.dbInstanceClass, id, r.multiAZ);
    const count = r.dbInstanceCount;
    switch (c.kind) {
      case "serverless":
        // Aurora Serverless v2 is ACU-billed and not traditionally reservable, so
        // a reserved serverless row is dropped rather than counted. The serverless
        // table counts running instances only; creating a zero-count entry here
        // (the previous behavior) just polluted it with empty rows.
        break;
      case "burstable":
        bumpBurstable(tag, r.region, c.family, c.size, count, "reserved");
        break;
      case "unparseable":
        bumpUnparseable(tag, r.region, c.dbInstanceClass, "reserved", count);
        break;
      case "nonSizeFlex":
        bumpNonSizeFlex(
          tag,
          r.region,
          c.family,
          c.engine,
          c.size,
          c.deployment,
          count,
          "reserved",
        );
        break;
      case "bucket":
        bumpBucket(
          tag,
          r.region,
          c.family,
          c.generation,
          c.engine,
          c.deployment,
          c.units * count,
          count,
          "reserved",
        );
        break;
    }
  }

  return core;
}

/**
 * Aggregate decoded instance and reserved rows into large-equivalent buckets
 * plus the burstable / serverless / unparseable carve-outs.
 *
 * A thin org-wide projection of {@link routeRows}: an empty key prefix collapses
 * every account into one entry, and the account tag is dropped from each line.
 *
 * @param instances Decoded provisioned-instance rows.
 * @param reserved Decoded reserved-instance rows.
 * @returns The full aggregation.
 */
export function aggregate(
  instances: InstanceRecord[],
  reserved: ReservedRecord[],
): Aggregation {
  const core = routeRows(instances, reserved, () => "");

  return {
    buckets: [...core.buckets.values()]
      .map(({ accountId: _id, accountName: _name, ...b }) => b)
      .sort(compareBuckets),
    burstable: [...core.burstable.values()]
      .map(({ accountId: _id, accountName: _name, ...l }) => l)
      .sort((a, b) =>
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
    serverless: [...core.serverless.values()]
      .map(({ accountId: _id, accountName: _name, ...s }) => s)
      .sort((a, b) =>
        a.region !== b.region
          ? (a.region < b.region ? -1 : 1)
          : a.engine < b.engine
          ? -1
          : a.engine > b.engine
          ? 1
          : 0
      ),
    nonSizeFlex: [...core.nonSizeFlex.values()]
      .map(({ accountId: _id, accountName: _name, ...l }) => l)
      .sort((a, b) =>
        a.region !== b.region
          ? (a.region < b.region ? -1 : 1)
          : a.family !== b.family
          ? (a.family < b.family ? -1 : 1)
          : a.engine !== b.engine
          ? (a.engine < b.engine ? -1 : 1)
          : a.size !== b.size
          ? (a.size < b.size ? -1 : 1)
          : a.deployment < b.deployment
          ? -1
          : a.deployment > b.deployment
          ? 1
          : 0
      ),
    unparseable: [...core.unparseable.values()]
      .map(({ accountId: _id, accountName: _name, ...l }) => l)
      .sort((a, b) =>
        a.region !== b.region
          ? (a.region < b.region ? -1 : 1)
          : a.dbInstanceClass < b.dbInstanceClass
          ? -1
          : 1
      ),
    inactiveReserved: [...core.inactiveReserved.values()]
      .reduce((sum, l) => sum + l.count, 0),
  };
}

/**
 * One reservation-pool rollup row: region × family × engine-token, with the
 * deployment dimension collapsed. This is the hard scope an RDS reservation
 * buys into — size flexibility pools normalized units within a single engine,
 * family, and region, and Single-AZ / Multi-AZ capacity is commensurable
 * (Multi-AZ folds in at 2×), so the two deployments net together here. Engine
 * is NOT collapsed: a postgres RI can never cover a mysql instance, so netting
 * across engines would invent coverage AWS does not grant.
 */
export interface PoolRollup {
  /** AWS region. */
  region: string;
  /** Family / generation, e.g. `r7g`. */
  family: string;
  /** Generation, e.g. `7g`. */
  generation: string;
  /** Bucket engine token (base engine, plus edition+license for commercial engines) — the hard RI boundary. */
  engine: string;
  /** Total running large-equivalents in this pool (both deployments). */
  runningLargeEq: number;
  /** Total reserved (active) large-equivalents in this pool. */
  reservedLargeEq: number;
  /** Net gap: running − reserved. Positive = under-covered; negative = over-reserved. */
  gapLargeEq: number;
}

/**
 * Roll buckets up to region × family × engine-token, collapsing only the
 * deployment dimension (Single-AZ and Multi-AZ net together — they are
 * commensurable because Multi-AZ folds in at 2×). Engine is kept: it is a hard
 * reservation boundary, so netting across it would invent coverage AWS does not
 * grant. Each row is one reservation pool.
 *
 * @param buckets The per-bucket aggregation.
 * @returns Sorted reservation-pool rows.
 */
export function rollupByPool(buckets: Bucket[]): PoolRollup[] {
  const map = new Map<string, PoolRollup>();
  for (const b of buckets) {
    const key = `${b.region} ${b.family} ${b.engine}`;
    let r = map.get(key);
    if (!r) {
      r = {
        region: b.region,
        family: b.family,
        generation: b.generation,
        engine: b.engine,
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
    r.gapLargeEq = gapLargeEq(r);
    r.runningLargeEq = round2(r.runningLargeEq);
    r.reservedLargeEq = round2(r.reservedLargeEq);
  }
  return [...map.values()].sort((a, b) =>
    a.region !== b.region
      ? (a.region < b.region ? -1 : 1)
      : a.family !== b.family
      ? (a.family < b.family ? -1 : 1)
      : a.engine < b.engine
      ? -1
      : a.engine > b.engine
      ? 1
      : 0
  );
}

/**
 * The actionable purchase figure: the positive coverage gap summed over
 * reservation pools (region × family × engine, deployment collapsed). Pools
 * that are over-reserved (negative gap) contribute zero — an over-reservation
 * in one engine/family/region cannot cover an under-reservation in another,
 * because a reservation is scoped to exactly one pool. This is why the headline
 * is NOT a single net of all running minus all reserved: that would silently
 * offset deficits with surpluses across hard boundaries and understate the buy.
 *
 * @param pools The reservation-pool rollup from {@link rollupByPool}.
 * @returns Large-equivalents to purchase.
 */
export function largeEqToBuy(pools: PoolRollup[]): number {
  return round2(pools.reduce((s, p) => s + Math.max(0, p.gapLargeEq), 0));
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

/**
 * A burstable (t-class) line scoped to a single owning account — the
 * per-account mirror of {@link BurstableLine}, so burstable capacity is visible
 * per account on the RI-discount-sharing-OFF path, not silently dropped.
 */
export interface AccountBurstableLine {
  /** 12-digit owning account id. */
  accountId: string;
  /** Friendly account label. */
  accountName: string;
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

/**
 * A serverless line scoped to a single owning account (running instances only,
 * mirroring the org-wide serverless tally — reserved serverless is dropped on
 * both paths).
 */
export interface AccountServerlessLine {
  /** 12-digit owning account id. */
  accountId: string;
  /** Friendly account label. */
  accountName: string;
  /** AWS region. */
  region: string;
  /** Canonical engine. */
  engine: string;
  /** Running serverless instance count. */
  count: number;
}

/** An unparseable class scoped to a single owning account. */
export interface AccountUnparseableLine {
  /** 12-digit owning account id. */
  accountId: string;
  /** Friendly account label. */
  accountName: string;
  /** AWS region. */
  region: string;
  /** Raw instance class. */
  dbInstanceClass: string;
  /** `instance` or `reserved`. */
  source: "instance" | "reserved";
  /** Count of rows with this class. */
  count: number;
}

/**
 * A non-size-flexible commercial line (SQL Server, Oracle LI, RDS Custom) scoped
 * to a single owning account — the per-account mirror of {@link NonSizeFlexLine}.
 * Like the org-wide carve-out these are raw running-vs-reserved counts at
 * `region × family × engine × size × deployment` (never folded into
 * large-equivalents), now attributable to the owning account for the
 * RI-discount-sharing-OFF purchasing case.
 */
export interface AccountNonSizeFlexLine {
  /** 12-digit owning account id. */
  accountId: string;
  /** Friendly account label. */
  accountName: string;
  /** AWS region. */
  region: string;
  /** Family, e.g. `r6i`. */
  family: string;
  /** Engine token with edition and license, e.g. `sqlserver-se-li`, `oracle-ee-li`. */
  engine: string;
  /** Size token, e.g. `xlarge`. */
  size: string;
  /** Deployment dimension (`Multi-AZ` | `Single-AZ`). */
  deployment: string;
  /** Running instance count. */
  runningInstances: number;
  /** Reserved instance count (sum of DBInstanceCount, active only). */
  reservedInstances: number;
}

/** Per-account count of reservations skipped because they were not `active`. */
export interface AccountInactiveReserved {
  /** 12-digit owning account id. */
  accountId: string;
  /** Friendly account label. */
  accountName: string;
  /** Inactive reservation rows owned by this account. */
  count: number;
}

/**
 * Full per-account aggregation — the per-account mirror of {@link Aggregation}.
 * `buckets` is the large-equivalent purchase list; the remaining fields are the
 * per-account carve-outs that {@link aggregate} surfaces org-wide, so the
 * "never silently dropped" promise holds per account too.
 */
export interface AccountAggregation {
  /** Per-account large-equivalent buckets, sorted. */
  buckets: AccountBucket[];
  /** Per-account burstable lines, sorted. */
  burstable: AccountBurstableLine[];
  /** Per-account serverless lines (running only), sorted. */
  serverless: AccountServerlessLine[];
  /** Per-account unparseable class lines, sorted. */
  unparseable: AccountUnparseableLine[];
  /** Per-account non-size-flex commercial lines (SQL Server, Oracle LI, RDS Custom), sorted. */
  nonSizeFlex: AccountNonSizeFlexLine[];
  /** Per-account inactive-reservation counts, sorted. */
  inactiveReserved: AccountInactiveReserved[];
}

/**
 * Stable order: account name, region, family, engine, deployment, then
 * accountId. Buckets are keyed by `accountId`, so two distinct accounts sharing
 * a display name (blank labels, or two profiles both named `prod`) are separate
 * rows whose first five keys can be identical; without the trailing `accountId`
 * tie-break their order would fall to Map-insertion order (instance arrival
 * across steps) and not be byte-stable across runs.
 */
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
  if (a.deployment !== b.deployment) {
    return a.deployment < b.deployment ? -1 : 1;
  }
  return a.accountId < b.accountId ? -1 : a.accountId > b.accountId ? 1 : 0;
}

/**
 * Aggregate running and reserved rows **with the owning account as an extra
 * dimension** — the purchasable line items when RI discount sharing is disabled
 * and a reservation only benefits the account that bought it. Routes through the
 * same shared {@link classify} as {@link aggregate}, so the per-account view
 * surfaces the identical burstable / serverless / unparseable / non-size-flex /
 * inactive carve-outs org-wide does — none is silently dropped. Non-size-flex
 * commercial capacity (SQL Server, Oracle LI, RDS Custom) has no large-eq line
 * on either path, but is surfaced per account as raw counts (in `nonSizeFlex`)
 * so an account running only such capacity is still attributable for the
 * RI-sharing-OFF purchasing case. Reserved serverless is dropped on both paths.
 *
 * @param instances Decoded provisioned-instance rows.
 * @param reserved Decoded reserved-instance rows.
 * @returns The per-account buckets plus per-account carve-outs.
 */
export function aggregateByAccount(
  instances: InstanceRecord[],
  reserved: ReservedRecord[],
): AccountAggregation {
  const core = routeRows(instances, reserved, (rec) => rec.accountId);
  const buckets = core.buckets;
  const burstable = core.burstable;
  const serverless = core.serverless;
  const unparseable = core.unparseable;
  const nonSizeFlex = core.nonSizeFlex;
  const inactiveReserved = core.inactiveReserved;

  const byAccountRegion = (a: { accountName: string; region: string }, b: {
    accountName: string;
    region: string;
  }) =>
    a.accountName !== b.accountName
      ? (a.accountName < b.accountName ? -1 : 1)
      : a.region !== b.region
      ? (a.region < b.region ? -1 : 1)
      : 0;

  // Final tie-break: every carve-out map is keyed with `accountId` as its
  // prefix, so two rows that compare equal on all display keys but carry a
  // different `accountId` are genuinely distinct entries (same-named accounts:
  // blank labels, two profiles both `prod`). Without this their order would
  // fall to Map-insertion (instance arrival) order and not be byte-stable —
  // the same defect compareAccountBuckets fixes for the bucket table. It only
  // disambiguates already-equal rows; distinct keys are never reordered.
  const byAccountId = (a: { accountId: string }, b: { accountId: string }) =>
    a.accountId < b.accountId ? -1 : a.accountId > b.accountId ? 1 : 0;

  return {
    buckets: [...buckets.values()].sort(compareAccountBuckets),
    burstable: [...burstable.values()].sort((a, b) => {
      const ar = byAccountRegion(a, b);
      if (ar !== 0) return ar;
      if (a.family !== b.family) return a.family < b.family ? -1 : 1;
      if (a.size !== b.size) return a.size < b.size ? -1 : 1;
      return byAccountId(a, b);
    }),
    serverless: [...serverless.values()].sort((a, b) => {
      const ar = byAccountRegion(a, b);
      if (ar !== 0) return ar;
      if (a.engine !== b.engine) return a.engine < b.engine ? -1 : 1;
      return byAccountId(a, b);
    }),
    unparseable: [...unparseable.values()].sort((a, b) => {
      const ar = byAccountRegion(a, b);
      if (ar !== 0) return ar;
      if (a.dbInstanceClass !== b.dbInstanceClass) {
        return a.dbInstanceClass < b.dbInstanceClass ? -1 : 1;
      }
      if (a.source !== b.source) return a.source < b.source ? -1 : 1;
      return byAccountId(a, b);
    }),
    nonSizeFlex: [...nonSizeFlex.values()].sort((a, b) => {
      const ar = byAccountRegion(a, b);
      if (ar !== 0) return ar;
      if (a.family !== b.family) return a.family < b.family ? -1 : 1;
      if (a.engine !== b.engine) return a.engine < b.engine ? -1 : 1;
      if (a.size !== b.size) return a.size < b.size ? -1 : 1;
      if (a.deployment !== b.deployment) {
        return a.deployment < b.deployment ? -1 : 1;
      }
      return byAccountId(a, b);
    }),
    inactiveReserved: [...inactiveReserved.values()].sort((a, b) =>
      a.accountName !== b.accountName
        ? (a.accountName < b.accountName ? -1 : 1)
        : byAccountId(a, b)
    ),
  };
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

      // A single read failure (transient storage error, one corrupt/missing
      // blob) must skip just this artifact, not unwind the whole sweep. Guard
      // getContent and this handle's decode/validate together so a rejection
      // is treated exactly like a decode failure: increment skipped, continue.
      let bytes: Uint8Array | null;
      try {
        bytes = await context.dataRepository.getContent(
          step.modelType,
          step.modelId,
          handle.name,
          handle.version,
        );
      } catch (err) {
        skipped++;
        tryLog(
          logger,
          "warn",
          "Could not read {spec} artifact {handle}: {error}",
          {
            spec: specName,
            handle: handle.name,
            error: err instanceof Error ? err.message : String(err),
          },
        );
        continue;
      }

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
          tryLog(
            logger,
            "warn",
            "scan_error row {handle} failed schema: {fields}",
            {
              handle: handle.name,
              fields: res.error.issues.map((i) => i.path.join(".") || "<root>")
                .join(", "),
            },
          );
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

/**
 * The coverage gap for a bucket: running minus reserved large-equivalents,
 * rounded. The single source of truth for `gap = running − reserved` used by
 * both CSV and markdown render sites and the pool rollup, so the figure cannot
 * drift between emitters.
 *
 * @param b Any row carrying large-equivalent running/reserved totals.
 * @returns The rounded gap (positive = under-reserved, negative = over).
 */
export function gapLargeEq(
  b: { runningLargeEq: number; reservedLargeEq: number },
): number {
  return round2(b.runningLargeEq - b.reservedLargeEq);
}

/**
 * Count the distinct accounts and regions represented across collected
 * instances, reservations, and scan errors. Errors contribute only when they
 * carry a non-empty account / region (account- and credential-level failures
 * have no region). The single source of truth used by both the JSON counts in
 * {@link report} and the markdown summary in {@link renderMarkdown}, so the two
 * cannot drift.
 *
 * @param collected Decoded rows from {@link collect}.
 * @returns The distinct account and region counts.
 */
export function countAccountsRegions(
  collected: Collected,
): { accountCount: number; regionCount: number } {
  const accounts = new Set<string>();
  const regions = new Set<string>();
  for (const i of collected.instances) {
    accounts.add(i.accountId);
    regions.add(i.region);
  }
  for (const r of collected.reserved) {
    accounts.add(r.accountId);
    regions.add(r.region);
  }
  for (const e of collected.errors) {
    if (e.accountId) accounts.add(e.accountId);
    if (e.region) regions.add(e.region);
  }
  return { accountCount: accounts.size, regionCount: regions.size };
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
    fmtNum(gapLargeEq(b)),
    String(b.runningInstances),
    String(b.reservedInstances),
  ];
}

/**
 * Render a gap table as CSV: a header row plus one comma-joined, field-escaped
 * row per entry, with a trailing newline. The single CSV emitter shared by the
 * per-bucket and per-account tables; the entry points below differ only by
 * column set and row projection.
 *
 * @param columns Header columns, in order.
 * @param rows Pre-projected string cells per row (before CSV escaping).
 * @returns The CSV body (header + rows + trailing newline).
 */
function renderCsvTable(
  columns: readonly string[],
  rows: string[][],
): string {
  const header = columns.join(",");
  const body = rows.map((r) => r.map(csvField).join(","));
  return [header, ...body].join("\n") + "\n";
}

/** Render the actionable per-bucket gap table as CSV (header always present). */
export function renderCsv(buckets: Bucket[]): string {
  return renderCsvTable(COLUMNS, buckets.map(bucketRowValues));
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

function accountBucketRowValues(b: AccountBucket): string[] {
  return [
    b.accountName,
    b.accountId,
    b.region,
    b.family,
    b.generation,
    b.engine,
    b.deployment,
    fmtNum(b.runningLargeEq),
    fmtNum(b.reservedLargeEq),
    fmtNum(gapLargeEq(b)),
    String(b.runningInstances),
    String(b.reservedInstances),
  ];
}

/** Render the per-account gap table as CSV (header always present). */
export function renderCsvByAccount(buckets: AccountBucket[]): string {
  return renderCsvTable(ACCOUNT_COLUMNS, buckets.map(accountBucketRowValues));
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
 * @param rollup Reservation-pool rollup from {@link rollupByPool}.
 * @param generatedAt ISO timestamp for the header.
 * @param workflowName Originating workflow name.
 * @returns The full markdown document.
 */
export function renderMarkdown(
  collected: Collected,
  agg: Aggregation,
  rollup: PoolRollup[],
  accountAgg: AccountAggregation,
  generatedAt: string,
  workflowName: string,
): string {
  const { errors } = collected;
  const authExpired = errors.filter((e) => e.kind === "auth_expired");
  const accessDenied = errors.filter((e) => e.kind === "access_denied");
  const otherErrors = errors.filter((e) => e.kind === "other");

  const { accountCount, regionCount } = countAccountsRegions(collected);

  const totalRunning = round2(
    agg.buckets.reduce((s, b) => s + b.runningLargeEq, 0),
  );
  const totalReserved = round2(
    agg.buckets.reduce((s, b) => s + b.reservedLargeEq, 0),
  );
  const toBuy = largeEqToBuy(rollup);

  const lines: string[] = [];
  lines.push("# RDS Large-Equivalent Reservation Gap");
  lines.push("");
  lines.push(`_Generated ${generatedAt} · workflow \`${workflowName}\`_`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Accounts seen: **${accountCount}**`);
  lines.push(`- Regions covered: **${regionCount}**`);
  lines.push(
    `- Size-flexible running capacity: **${fmtNum(totalRunning)}** large-eq ` +
      "(burstable, serverless, and SQL Server / Oracle-LI / RDS Custom carved " +
      "out below)",
  );
  lines.push(
    `- Reserved (active) capacity: **${fmtNum(totalReserved)}** large-eq`,
  );
  lines.push(
    `- **Large-equivalents to buy: ${fmtNum(toBuy)}** ` +
      (toBuy > 0
        ? "(sum of the positive per-pool gaps below; over-reserved pools do " +
          "not offset under-reserved ones across the engine boundary)"
        : "(no pool is under-covered — nothing to buy; see the per-pool table " +
          "below for any over-reserved pools)"),
  );
  if (agg.nonSizeFlex.length > 0) {
    const nsfRunning = agg.nonSizeFlex.reduce(
      (s, l) => s + l.runningInstances,
      0,
    );
    const nsfReserved = agg.nonSizeFlex.reduce(
      (s, l) => s + l.reservedInstances,
      0,
    );
    lines.push(
      `- SQL Server / Oracle-LI / RDS Custom (not size-flexible, **excluded** ` +
        `from the figure above): **${nsfRunning}** running, **${nsfReserved}** ` +
        "reserved instance(s) — see the dedicated table below",
    );
  }
  if (agg.inactiveReserved > 0) {
    lines.push(
      `- Inactive reservations (not \`active\`, **excluded** from coverage): ` +
        `**${agg.inactiveReserved}**`,
    );
  }
  lines.push(
    `- Coverage gaps: **${authExpired.length}** scan(s) need ` +
      "`aws sso login`, " +
      `**${accessDenied.length}** blocked by SCP/IAM` +
      (otherErrors.length ? `, **${otherErrors.length}** other error(s)` : ""),
  );
  lines.push("");

  // Headline: per reservation-pool rollup (region × family × engine).
  lines.push("## Coverage by reservation pool (region × family × engine)");
  lines.push("");
  lines.push(
    "Each row is a reservation pool — the hard scope an RI buys into. " +
      "Single-AZ and Multi-AZ are netted together (Multi-AZ counted 2×); " +
      "engine is kept distinct. `gap = running − reserved`; the **to buy** " +
      "headline is the sum of the positive gaps.",
  );
  lines.push("");
  lines.push(
    mdTable(
      ["region", "family", "engine", "running", "reserved", "gap (buy)"],
      rollup.map((r) => [
        r.region,
        r.family,
        r.engine,
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
        fmtNum(gapLargeEq(b)),
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
      "`gap` in that account. Every carve-out the org-wide view surfaces is " +
      "broken out per account below — burstable, serverless, non-size-flex " +
      "commercial (SQL Server / Oracle-LI / RDS Custom, raw counts), " +
      "unparseable, and inactive reservations — so nothing an account runs is " +
      "hidden here.",
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
      accountAgg.buckets.map((b) => [
        b.accountName,
        b.region,
        b.family,
        b.engine,
        b.deployment,
        fmtNum(b.runningLargeEq),
        fmtNum(b.reservedLargeEq),
        fmtNum(gapLargeEq(b)),
      ]),
    ),
  );

  // Per-account non-size-flex carve-out (always rendered, mirroring org-wide).
  lines.push("");
  lines.push("### Per-account SQL Server / Oracle-LI / RDS Custom");
  lines.push("");
  lines.push(
    mdTable(
      [
        "account",
        "region",
        "family",
        "engine",
        "size",
        "deployment",
        "running",
        "reserved",
      ],
      accountAgg.nonSizeFlex.map((l) => [
        l.accountName,
        l.region,
        l.family,
        l.engine,
        l.size,
        l.deployment,
        String(l.runningInstances),
        String(l.reservedInstances),
      ]),
    ),
  );

  // Per-account burstable carve-out (always rendered, mirroring org-wide).
  lines.push("");
  lines.push("### Per-account burstable (t-class)");
  lines.push("");
  lines.push(
    mdTable(
      ["account", "region", "family", "size", "running", "reserved"],
      accountAgg.burstable.map((l) => [
        l.accountName,
        l.region,
        l.family,
        l.size,
        String(l.runningInstances),
        String(l.reservedInstances),
      ]),
    ),
  );

  // Per-account serverless carve-out (running only; shown when present).
  if (accountAgg.serverless.length > 0) {
    lines.push("");
    lines.push("### Per-account serverless (Aurora Serverless v2)");
    lines.push("");
    lines.push(
      mdTable(
        ["account", "region", "engine", "instances"],
        accountAgg.serverless.map((s) => [
          s.accountName,
          s.region,
          s.engine,
          String(s.count),
        ]),
      ),
    );
  }

  // Per-account unparseable carve-out (shown when present).
  if (accountAgg.unparseable.length > 0) {
    lines.push("");
    lines.push("### Per-account unparseable classes (excluded from large-eq)");
    lines.push("");
    lines.push(
      mdTable(
        ["account", "region", "class", "source", "count"],
        accountAgg.unparseable.map((u) => [
          u.accountName,
          u.region,
          u.dbInstanceClass,
          u.source,
          String(u.count),
        ]),
      ),
    );
  }

  // Per-account inactive reservations (shown when present).
  if (accountAgg.inactiveReserved.length > 0) {
    lines.push("");
    lines.push(
      "### Per-account inactive reservations (excluded from coverage)",
    );
    lines.push("");
    lines.push(
      mdTable(
        ["account", "inactive reservations"],
        accountAgg.inactiveReserved.map((r) => [
          r.accountName,
          String(r.count),
        ]),
      ),
    );
  }

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

  // Non-size-flex commercial carve-out.
  lines.push(
    "## SQL Server / Oracle-LI / RDS Custom — counted separately, " +
      "not normalized",
  );
  lines.push("");
  lines.push(
    "Size flexibility does **not** apply to these engines, so an `xlarge` " +
      "reservation does not cover two `large` instances — folding them into " +
      "large-equivalents would invent coverage AWS does not grant. Counted " +
      "raw at the granularity a reservation matches: " +
      "`region × family × engine × size × deployment`, with edition and " +
      "license preserved in `engine` (e.g. `oracle-se2-li`, `sqlserver-ee-li`). " +
      "A reservation only covers a running instance on the **same** row. " +
      "These rows are **excluded** from the large-eq totals and rollup above.",
  );
  lines.push("");
  lines.push(
    mdTable(
      [
        "region",
        "family",
        "engine",
        "size",
        "deployment",
        "running",
        "reserved",
      ],
      agg.nonSizeFlex.map((l) => [
        l.region,
        l.family,
        l.engine,
        l.size,
        l.deployment,
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
  /** Per-bucket CSV columns (`csv`), in header order. */
  columns: string[];
  /** Per-account CSV columns (`csvByAccount`), in header order. */
  accountColumns: string[];
  /** Accounts represented. */
  accountCount: number;
  /** Regions represented. */
  regionCount: number;
  /** Provisioned instances seen. */
  instanceCount: number;
  /** Reserved rows seen. */
  reservedCount: number;
  /** Total running large-equivalents in the size-flex buckets (excludes burstable, serverless, and the non-size-flex commercial carve-out). Gross capacity only — not the buy figure. */
  totalRunningLargeEq: number;
  /** Total reserved (active) large-equivalents. Gross capacity only — not the buy figure. */
  totalReservedLargeEq: number;
  /**
   * Large-equivalents to purchase: the sum of the positive per-pool gaps (see
   * {@link largeEqToBuy}). The actionable headline. This is deliberately NOT
   * `totalRunningLargeEq − totalReservedLargeEq`: an over-reservation in one
   * pool cannot cover an under-reservation in another across the hard engine /
   * family / region boundary, so a single net would understate the buy.
   */
  largeEqToBuy: number;
  /** Per reservation-pool rows: region × family × engine, deployment collapsed (the hard RI scope). */
  reservationPools: PoolRollup[];
  /** Per-bucket (purchasable) rows. */
  buckets: Bucket[];
  /** Per-account buckets (purchase list when RI sharing is off). */
  accountBuckets: AccountBucket[];
  /** Per-account CSV body (header + rows + trailing newline). */
  csvByAccount: string;
  /** Per-account burstable lines (carve-out, mirrors org-wide `burstable`). */
  accountBurstable: AccountBurstableLine[];
  /** Per-account serverless lines (running only). */
  accountServerless: AccountServerlessLine[];
  /** Per-account unparseable class lines. */
  accountUnparseable: AccountUnparseableLine[];
  /** Per-account non-size-flex commercial lines (SQL Server, Oracle LI, RDS Custom). */
  accountNonSizeFlex: AccountNonSizeFlexLine[];
  /** Per-account inactive-reservation counts. */
  accountInactiveReserved: AccountInactiveReserved[];
  /** Burstable lines. */
  burstable: BurstableLine[];
  /** Non-size-flex commercial lines (SQL Server, Oracle LI, RDS Custom). */
  nonSizeFlex: NonSizeFlexLine[];
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

/** An empty {@link Collected} — no rows seen. */
function emptyCollected(): Collected {
  return { instances: [], reserved: [], errors: [], skipped: 0 };
}

/** An empty {@link Aggregation} — no buckets or carve-out lines. */
function emptyAggregation(): Aggregation {
  return {
    buckets: [],
    burstable: [],
    nonSizeFlex: [],
    serverless: [],
    unparseable: [],
    inactiveReserved: 0,
  };
}

/** An empty {@link AccountAggregation} — no per-account rows. */
function emptyAccountAggregation(): AccountAggregation {
  return {
    buckets: [],
    burstable: [],
    serverless: [],
    unparseable: [],
    nonSizeFlex: [],
    inactiveReserved: [],
  };
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
    "breakdown for the RI-discount-sharing-disabled case. Engine preserves " +
    "edition and license for commercial engines; SQL Server, Oracle " +
    "License-Included, and RDS Custom are not size-flexible and are carved out " +
    "as raw counts alongside burstable and serverless capacity. Consumes " +
    "@jentz/aws-rds-reservations rows collected earlier in the workflow.",
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

    let collected: Collected = emptyCollected();
    let agg: Aggregation = emptyAggregation();
    let rollup: PoolRollup[] = [];
    let accountAgg: AccountAggregation = emptyAccountAggregation();
    let generatedAt = "";
    let degraded = false;
    let markdown = "";
    let csv = renderCsv([]);
    let csvByAccount = renderCsvByAccount([]);

    try {
      generatedAt = new Date().toISOString();
      collected = await collect(context);
      agg = aggregate(collected.instances, collected.reserved);
      rollup = rollupByPool(agg.buckets);
      accountAgg = aggregateByAccount(
        collected.instances,
        collected.reserved,
      );
      csv = renderCsv(agg.buckets);
      csvByAccount = renderCsvByAccount(accountAgg.buckets);
      markdown = renderMarkdown(
        collected,
        agg,
        rollup,
        accountAgg,
        generatedAt,
        workflowName,
      );
    } catch (err) {
      degraded = true;
      const detail = err instanceof Error ? err.message : String(err);
      tryLog(logger, "warn", "report degraded: {detail}", { detail });
      markdown =
        `# RDS Large-Equivalent Reservation Gap\n\n_Report degraded: ${detail}_\n`;
      // Reset EVERY derived field to a coherent empty state. The count fields
      // (instanceCount/reservedCount/accountCount/regionCount/errorsByKind) are
      // derived from `collected`, while the totals/buckets/rollup come from
      // `agg`/`accountAgg`; if a step after `collect` threw, the populated
      // `collected` would otherwise pair with empty `agg`, emitting a payload
      // that reads "N instances, 0 buckets, fully covered" with degraded=true —
      // a consumer ignoring the flag would misread it as healthy. Zeroing all
      // sources together makes a degraded payload unambiguously empty.
      collected = emptyCollected();
      agg = emptyAggregation();
      rollup = [];
      accountAgg = emptyAccountAggregation();
      csv = renderCsv([]);
      csvByAccount = renderCsvByAccount([]);
    }

    const errorsByKind: Record<string, number> = {
      auth_expired: 0,
      access_denied: 0,
      other: 0,
    };
    for (const e of collected.errors) errorsByKind[e.kind]++;

    const { accountCount, regionCount } = countAccountsRegions(collected);
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
      accountColumns: [...ACCOUNT_COLUMNS],
      accountCount,
      regionCount,
      instanceCount: collected.instances.length,
      reservedCount: collected.reserved.length,
      totalRunningLargeEq: totalRunning,
      totalReservedLargeEq: totalReserved,
      largeEqToBuy: largeEqToBuy(rollup),
      reservationPools: rollup,
      buckets: agg.buckets.map((b) => ({
        ...b,
        runningLargeEq: round2(b.runningLargeEq),
        reservedLargeEq: round2(b.reservedLargeEq),
      })),
      accountBuckets: accountAgg.buckets.map((b) => ({
        ...b,
        runningLargeEq: round2(b.runningLargeEq),
        reservedLargeEq: round2(b.reservedLargeEq),
      })),
      csvByAccount,
      accountBurstable: accountAgg.burstable,
      accountServerless: accountAgg.serverless,
      accountUnparseable: accountAgg.unparseable,
      accountNonSizeFlex: accountAgg.nonSizeFlex,
      accountInactiveReserved: accountAgg.inactiveReserved,
      burstable: agg.burstable,
      nonSizeFlex: agg.nonSizeFlex,
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
