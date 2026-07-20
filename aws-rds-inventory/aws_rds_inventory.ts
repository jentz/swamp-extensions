/**
 * `@jentz/aws-rds-inventory` — list RDS DB clusters with per-member detail.
 *
 * Calls `DescribeDBClusters` and `DescribeDBInstances` against the configured
 * AWS region, drops shared-endpoint non-RDS engines, applies a user-supplied
 * CEL selector to each remaining cluster, and emits:
 *
 *   - one `cluster` resource per matched cluster
 *   - one `instance` resource per cluster member, with a back-reference to its
 *     cluster via `DBClusterIdentifier`
 *
 * Covers both Aurora (`aurora-mysql`, `aurora-postgresql`) and the non-Aurora
 * Multi-AZ DB cluster variants returned by `DescribeDBClusters`. Standalone
 * single-instance RDS instances (no cluster) are out of scope.
 *
 * Designed to run downstream of `@jentz/aws-context-guard` in a workflow so a
 * misconfigured AWS profile or account can never reach the RDS APIs.
 *
 * @module
 */

import { z } from "npm:zod@4.4.3";
import {
  DescribeDBClustersCommand,
  DescribeDBInstancesCommand,
  RDSClient,
} from "npm:@aws-sdk/client-rds@3.1073.0";
import { SHARED_RETRY } from "./_lib/aws_credentials.ts";

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  region: z.string().optional().describe(
    "AWS region to query. Resolution order: this globalArg, then AWS_REGION, " +
      "then AWS_DEFAULT_REGION. If none are set the method throws — there is " +
      "no silent us-east-1 fallback, since the wrong region for an inventory " +
      "tool means listing the wrong account's resources.",
  ),
  selector: z.string().default("true").describe(
    "CEL predicate evaluated per RDS cluster after the built-in engine " +
      "allowlist drops shared-endpoint non-RDS engines. Default 'true' " +
      "includes every allowlisted RDS cluster. See the README for the full context shape " +
      "(cluster-level fields, the members[] array, and the tags map). " +
      "Examples: " +
      "'Engine.startsWith(\"aurora\") && members.size() == 3', " +
      "'tags.Environment == \"prod\"', " +
      "'members.exists(m, m.DBInstanceClass.startsWith(\"db.r7g\"))', " +
      "'members.exists(m, has(m.PromotionTier) && m.PromotionTier == 0)'.",
  ),
});

const TagsSchema = z.record(z.string(), z.string()).default({});

const ClusterSchema = z.object({
  DBClusterIdentifier: z.string(),
  Engine: z.string(),
  EngineVersion: z.string().optional(),
  Status: z.string().optional(),
  Endpoint: z.string().optional(),
  ReaderEndpoint: z.string().optional(),
  MultiAZ: z.boolean().optional(),
  tags: TagsSchema,
});

const InstanceSchema = z.object({
  DBInstanceIdentifier: z.string(),
  DBClusterIdentifier: z.string(),
  DBInstanceClass: z.string(),
  Role: z.enum(["writer", "reader"]),
  AvailabilityZone: z.string().optional(),
  Engine: z.string(),
  EngineVersion: z.string().optional(),
  Status: z.string().optional(),
  PromotionTier: z.number().optional(),
  DBClusterParameterGroupStatus: z.string().optional(),
  tags: TagsSchema,
});

/**
 * Shape of a single cluster resource written by `list_clusters`. Kept as an
 * explicit interface (instead of `z.infer<>`) so the public API doesn't depend
 * on a private schema constant — required for `deno doc --lint` to pass.
 */
export interface ClusterResource {
  /** AWS cluster identifier; also the resource instance name. */
  DBClusterIdentifier: string;
  /** AWS engine string (`aurora-mysql`, `mysql`, ...). */
  Engine: string;
  /** Engine version, if returned. */
  EngineVersion?: string;
  /** Cluster lifecycle status (`available`, `creating`, ...). */
  Status?: string;
  /** Writer endpoint, if returned. */
  Endpoint?: string;
  /** Reader endpoint, if returned. */
  ReaderEndpoint?: string;
  /** Whether the cluster is multi-AZ. */
  MultiAZ?: boolean;
  /** Cluster tags, flattened from AWS's `[{Key,Value},...]` array. */
  tags: Record<string, string>;
}

/**
 * Shape of a single instance resource written by `list_clusters`. Back-
 * references its cluster via `DBClusterIdentifier`.
 */
export interface InstanceResource {
  /** AWS instance identifier; also the resource instance name. */
  DBInstanceIdentifier: string;
  /** Back-reference to the owning cluster. */
  DBClusterIdentifier: string;
  /** AWS instance class (e.g. `db.r7g.large`). */
  DBInstanceClass: string;
  /** Whether this member is the cluster writer or a reader. */
  Role: "writer" | "reader";
  /** Availability zone of the instance, if returned. */
  AvailabilityZone?: string;
  /** Engine string (falls back to the cluster's engine if absent on instance). */
  Engine: string;
  /** Engine version, if returned. */
  EngineVersion?: string;
  /** Instance lifecycle status (`available`, ...). */
  Status?: string;
  /**
   * Failover priority, 0 (highest) – 15 (lowest). AWS returns this on both
   * the cluster-member and the DB-instance shape; we prefer the instance
   * value when present (matching the Engine/EngineVersion/Status pattern).
   * Undefined when AWS omits the field on both sides.
   */
  PromotionTier?: number;
  /**
   * Whether the cluster's parameter group has been applied to this member.
   * Typical values: `in-sync`, `applying`, `pending-reboot`, `removing`.
   * Sourced from the cluster member shape (not available on the instance
   * shape). Undefined when AWS omits the field.
   */
  DBClusterParameterGroupStatus?: string;
  /** Per-instance tags, flattened from AWS's `[{Key,Value},...]` array. */
  tags: Record<string, string>;
}

/**
 * One member's selector-context view. The three "always-present" fields
 * (`DBInstanceIdentifier`, `DBInstanceClass`, `Role`) are always populated —
 * the resolver fills `"unknown"` / `""` so basic selectors don't need `has()`
 * guards. Fields that AWS can legitimately omit (`AvailabilityZone`,
 * `PromotionTier`, `DBClusterParameterGroupStatus`) are left absent on the
 * object when AWS didn't return them; selectors should use `has(m.<field>)`
 * to test presence, matching the documented `has(tags.X)` pattern.
 *
 * The absent-rather-than-sentinel choice is deliberate for the AWS-optional
 * fields: a `-1` sentinel for `PromotionTier` silently passes range
 * predicates (e.g. `m.PromotionTier <= 1` matches absent members), and a
 * `""` sentinel for the status string can't distinguish "AWS omitted" from
 * "AWS returned empty".
 */
export interface SelectorMember {
  /** AWS instance identifier of this member; empty if the API omitted it. */
  DBInstanceIdentifier: string;
  /** Resolved instance class, or `"unknown"` if the instance was not returned. */
  DBInstanceClass: string;
  /** Writer or reader role, derived from `IsClusterWriter`. */
  Role: "writer" | "reader";
  /**
   * Availability zone of the instance. Absent (not `""`) when AWS omitted
   * the field. Use `has(m.AvailabilityZone)` in CEL to test presence.
   */
  AvailabilityZone?: string;
  /**
   * Failover priority, 0 (highest) – 15 (lowest). Absent when AWS omitted
   * the field. Use `has(m.PromotionTier)` in CEL before any comparison —
   * an unguarded range predicate (`m.PromotionTier <= 1`) throws when the
   * field is absent.
   */
  PromotionTier?: number;
  /**
   * Parameter-group apply status: `in-sync`, `applying`, `pending-reboot`,
   * `removing`, etc. Absent when AWS omitted the field; use
   * `has(m.DBClusterParameterGroupStatus)` to test presence.
   */
  DBClusterParameterGroupStatus?: string;
}

/**
 * Per-cluster predicate context. Exposed to the CEL selector as a flat object.
 * The shape is part of the public contract — selector authors depend on these
 * field names. Every field is always populated with a concrete value (empty
 * string / `false`) so the CEL selector never sees `undefined`, which would
 * be a runtime-CEL error.
 */
export interface SelectorContext {
  /** AWS cluster identifier. */
  DBClusterIdentifier: string;
  /** AWS engine string, or `""` if absent. */
  Engine: string;
  /** Engine version, or `""` if absent. */
  EngineVersion: string;
  /** Cluster lifecycle status, or `""` if absent. */
  Status: string;
  /** Whether the cluster is multi-AZ. Defaults to `false` when AWS omits the field. */
  MultiAZ: boolean;
  /** Per-member rollup. Empty when the cluster has no members. */
  members: SelectorMember[];
  /** Cluster tag map. Always an object (possibly empty). */
  tags: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit-test access)
// ---------------------------------------------------------------------------

/**
 * Built-in RDS engine allowlist for `DescribeDBClusters`, which is a shared
 * endpoint that also returns Neptune and DocumentDB clusters. Only the engines
 * AWS actually surfaces through `DescribeDBClusters` are included: Aurora
 * (`aurora-mysql`, `aurora-postgresql`) and the two Multi-AZ DB Cluster
 * engines AWS supports (`mysql`, `postgres`). Single-instance engines such as
 * Oracle, SQL Server, MariaDB, Db2, and RDS Custom surface through
 * `DescribeDBInstances` instead and are out of scope for this extension.
 *
 * Held as a `readonly string[]` rather than a `Set` so `Object.freeze` is
 * load-bearing at runtime — frozen arrays reject `push`/`splice`, whereas
 * `Object.freeze(new Set(...))` would still allow `.add()`/`.delete()` because
 * `Set` element storage lives in internal slots that `freeze` doesn't cover.
 */
export const RDS_ENGINE_ALLOWLIST: readonly string[] = Object.freeze([
  "aurora-mysql",
  "aurora-postgresql",
  "mysql",
  "postgres",
]);

/** Return true when an AWS engine string belongs to an RDS engine family. */
export function isRdsEngine(engine: unknown): boolean {
  if (typeof engine !== "string") return false;
  return RDS_ENGINE_ALLOWLIST.includes(engine.toLowerCase());
}

/**
 * Build the swamp storage key for a `cluster` resource. Prefixing with the
 * spec name disambiguates from `instance` keys — swamp storage is keyed by
 * instance name across all specs in a model, so an AWS cluster named `foo`
 * and an AWS DB instance named `foo` would otherwise collide on disk.
 */
export function clusterKey(dbClusterIdentifier: string): string {
  return `cluster-${dbClusterIdentifier}`;
}

/**
 * Build the swamp storage key for an `instance` resource. Includes the
 * owning cluster identifier so the key is unique even if two clusters in
 * different regions ever happened to converge in a future deployment.
 */
export function instanceKey(
  dbClusterIdentifier: string,
  dbInstanceIdentifier: string,
): string {
  return `instance-${dbClusterIdentifier}--${dbInstanceIdentifier}`;
}

/** AWS-style tag tuple as returned by `DescribeDBClusters`/`DescribeDBInstances`. */
export interface AwsTag {
  /** Tag key. */
  Key?: string;
  /** Tag value. */
  Value?: string;
}

/**
 * Convert AWS's `[{Key, Value}, ...]` tag array into a flat
 * `{key: value}` map. Missing/empty input becomes `{}`. Tags with no `Key`
 * (theoretically possible per the SDK types) are dropped. A `Value` of
 * `undefined` is stored as the empty string so the schema stays
 * `Record<string,string>`.
 */
export function tagsFromAws(
  tagList: AwsTag[] | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const t of tagList ?? []) {
    if (typeof t.Key !== "string" || t.Key.length === 0) continue;
    out[t.Key] = typeof t.Value === "string" ? t.Value : "";
  }
  return out;
}

/**
 * Strict region-resolution chain. Returns the resolved region or throws with a
 * message naming every source the caller can adjust.
 *
 * Order: explicit `globalArgs.region` → `AWS_REGION` env → `AWS_DEFAULT_REGION`
 * env. A whitespace-only value at any step is treated as unset.
 *
 * @param globalArgs Validated global arguments object.
 * @param env Env-var accessor; defaults to `Deno.env.get`. Override in tests.
 */
export function resolveRegion(
  globalArgs: { region?: string },
  env: (name: string) => string | undefined = (name) => Deno.env.get(name),
): string {
  const candidates: Array<[string, string | undefined]> = [
    ["globalArg.region", globalArgs.region],
    ["AWS_REGION env", env("AWS_REGION")],
    ["AWS_DEFAULT_REGION env", env("AWS_DEFAULT_REGION")],
  ];
  for (const [, value] of candidates) {
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }
  throw new Error(
    "aws-rds-inventory: no AWS region configured. Set one of: " +
      "the 'region' global argument (e.g. " +
      "`--global-arg region=eu-west-1`), the AWS_REGION env var, or the " +
      "AWS_DEFAULT_REGION env var. There is no silent us-east-1 fallback.",
  );
}

/**
 * Evaluate a CEL predicate against every cluster's selector context. Throws
 * eagerly if the predicate doesn't return a boolean — surfacing
 * `'count(...)' instead of 'count(...) == 3'` style mistakes before any
 * AWS-side work happens.
 *
 * @param parsed Compiled predicate from `env.parse(selector)`.
 * @param contexts Per-cluster contexts to evaluate against.
 * @returns A boolean array aligned with `contexts` (same length, same order).
 */
export function evaluateSelector(
  parsed: (ctx: Record<string, unknown>) => unknown,
  contexts: SelectorContext[],
): boolean[] {
  return contexts.map((ctx) => {
    const result = parsed(ctx as unknown as Record<string, unknown>);
    if (typeof result !== "boolean") {
      // String() instead of JSON.stringify() so BigInt-returning CEL
      // expressions (`1 + 2` evaluates to a BigInt under cel-js) don't
      // crash the error path.
      throw new Error(
        `aws-rds-inventory: selector must return a boolean, got ` +
          `${typeof result} (value: ${String(result)}) for cluster ` +
          `'${ctx.DBClusterIdentifier}'.`,
      );
    }
    return result;
  });
}

// ---------------------------------------------------------------------------
// AWS-shape internals
// ---------------------------------------------------------------------------

/** Minimal member shape from `DescribeDBClusters` we depend on. */
export interface AwsClusterMember {
  /** AWS instance identifier. */
  DBInstanceIdentifier?: string;
  /** True when this member is the cluster writer. */
  IsClusterWriter?: boolean;
  /** Failover priority, 0 (highest) – 15 (lowest). */
  PromotionTier?: number;
  /** Parameter-group apply status (e.g. `in-sync`, `pending-reboot`). */
  DBClusterParameterGroupStatus?: string;
}

/**
 * Minimal cluster shape from `DescribeDBClusters` we depend on. Exported so
 * test scaffolding can replay fixtures without importing the full AWS SDK
 * types.
 */
export interface AwsCluster {
  /** Cluster identifier. */
  DBClusterIdentifier?: string;
  /** Engine string. */
  Engine?: string;
  /** Engine version. */
  EngineVersion?: string;
  /** Lifecycle status. */
  Status?: string;
  /** Writer endpoint. */
  Endpoint?: string;
  /** Reader endpoint. */
  ReaderEndpoint?: string;
  /** Multi-AZ flag. */
  MultiAZ?: boolean;
  /** Cluster members. */
  DBClusterMembers?: AwsClusterMember[];
  /** Tag list from the API. */
  TagList?: AwsTag[];
}

/**
 * Minimal instance shape from `DescribeDBInstances` we depend on. Exported so
 * tests can replay fixtures without importing the full AWS SDK types.
 */
export interface AwsInstance {
  /** Instance identifier. */
  DBInstanceIdentifier?: string;
  /** AWS instance class. */
  DBInstanceClass?: string;
  /** Availability zone. */
  AvailabilityZone?: string;
  /** Engine string. */
  Engine?: string;
  /** Engine version. */
  EngineVersion?: string;
  /** Instance status (note the AWS field name). */
  DBInstanceStatus?: string;
  /**
   * Failover priority. AWS exposes this on both `DBClusterMember` and
   * `DBInstance`. `buildSelectorContext` prefers this instance-side value
   * and falls back to the member-side value when the instance omits it —
   * mirrors the Engine / EngineVersion precedence used elsewhere in the
   * writer. Either source is documented by AWS as authoritative, so the
   * choice is style consistency rather than correctness.
   */
  PromotionTier?: number;
  /** Tag list from the API. */
  TagList?: AwsTag[];
}

/** Page returned by the `describeDBClusters` facade method. */
export interface DescribeClustersPage {
  /** Clusters returned on this page. */
  DBClusters?: AwsCluster[];
  /** Pagination cursor; absent on the final page. */
  Marker?: string;
}

/** Page returned by the `describeDBInstances` facade method. */
export interface DescribeInstancesPage {
  /** Instances returned on this page. */
  DBInstances?: AwsInstance[];
  /** Pagination cursor; absent on the final page. */
  Marker?: string;
}

/**
 * Minimal facade over the bits of `RDSClient` this extension uses. Lets unit
 * tests substitute an in-memory replay without monkey-patching the SDK.
 */
export interface RdsApi {
  /** List clusters; one page per call. */
  describeDBClusters(marker?: string): Promise<DescribeClustersPage>;
  /**
   * List instances belonging to the given clusters; one page per call. AWS
   * narrows the result server-side via the `db-cluster-id` filter, so only
   * members of `clusterIds` are returned — never the account's standalone
   * (non-clustered) instances. An empty `clusterIds` is the caller's
   * responsibility to avoid (it would be an unfiltered scan); {@link
   * collectInstances} short-circuits before ever calling with one.
   */
  describeDBInstances(
    clusterIds: string[],
    marker?: string,
  ): Promise<DescribeInstancesPage>;
}

function rdsApiFromSdk(client: RDSClient): RdsApi {
  return {
    describeDBClusters: async (marker) => {
      const resp = await client.send(
        new DescribeDBClustersCommand({ Marker: marker, MaxRecords: 100 }),
      );
      return { DBClusters: resp.DBClusters, Marker: resp.Marker };
    },
    describeDBInstances: async (clusterIds, marker) => {
      const resp = await client.send(
        new DescribeDBInstancesCommand({
          Filters: [{ Name: "db-cluster-id", Values: clusterIds }],
          Marker: marker,
          MaxRecords: 100,
        }),
      );
      return { DBInstances: resp.DBInstances, Marker: resp.Marker };
    },
  };
}

/**
 * Iterate paginated `DescribeDBClusters` to exhaustion. Returns the raw AWS
 * shapes so caller-side logic can pick them apart. Throttling retry lives
 * inside the SDK client (`SHARED_RETRY`), not here.
 */
async function collectClusters(api: RdsApi): Promise<AwsCluster[]> {
  const all: AwsCluster[] = [];
  let marker: string | undefined;
  do {
    const resp = await api.describeDBClusters(marker);
    all.push(...(resp.DBClusters ?? []));
    marker = resp.Marker;
  } while (marker);
  return all;
}

/**
 * Maximum number of cluster identifiers sent in a single `db-cluster-id`
 * filter. AWS accepts a list of values on each filter, but an unbounded list
 * risks an oversized request, so {@link collectInstances} chunks the cluster
 * set into batches no larger than this. 200 is comfortably under AWS request
 * limits while keeping the round-trip count low for typical accounts (which
 * have far fewer than 200 clusters in a region).
 */
export const MAX_CLUSTER_IDS_PER_FILTER = 200;

/**
 * Fetch the DB instances belonging to `clusterIds`, narrowed server-side by
 * the `db-cluster-id` filter so AWS returns only cluster members — never the
 * account's standalone (non-clustered) instances. This replaces the old
 * full-region scan + client-side identifier match: in accounts with thousands
 * of standalone instances the unfiltered scan paginated through rows the
 * extension never cared about.
 *
 * The cluster set is chunked into batches of at most
 * {@link MAX_CLUSTER_IDS_PER_FILTER}; each batch is paginated to exhaustion by
 * `Marker` (no early exit — every member of every requested cluster matters,
 * since a member may live on any page). Throttling retry lives inside the SDK
 * client (`SHARED_RETRY`), not here. Results merge into a single `Map` keyed
 * by `DBInstanceIdentifier`; only returned instances carrying an identifier
 * are keyed.
 *
 * An empty `clusterIds` returns an empty map without issuing any API call.
 */
export async function collectInstances(
  api: RdsApi,
  clusterIds: string[],
): Promise<Map<string, AwsInstance>> {
  const map = new Map<string, AwsInstance>();
  if (clusterIds.length === 0) return map;
  for (
    let start = 0;
    start < clusterIds.length;
    start += MAX_CLUSTER_IDS_PER_FILTER
  ) {
    const batch = clusterIds.slice(start, start + MAX_CLUSTER_IDS_PER_FILTER);
    let marker: string | undefined;
    do {
      const resp = await api.describeDBInstances(batch, marker);
      for (const inst of resp.DBInstances ?? []) {
        if (inst.DBInstanceIdentifier) {
          map.set(inst.DBInstanceIdentifier, inst);
        }
      }
      marker = resp.Marker;
    } while (marker);
  }
  return map;
}

/**
 * Roll an AWS cluster + its members into a selector-context object.
 *
 * Cluster-level fields and the three always-present member fields
 * (`DBInstanceIdentifier`, `DBInstanceClass`, `Role`) are filled with empty
 * defaults (`""` / `false` / `"unknown"`) so simple equality predicates
 * don't need `has()` guards. The AWS-optional member fields
 * (`AvailabilityZone`, `PromotionTier`, `DBClusterParameterGroupStatus`)
 * are left absent on the object when AWS didn't return them — selectors
 * use `has(m.<field>)` to test presence. See {@link SelectorMember} for
 * the rationale.
 */
export function buildSelectorContext(
  cluster: AwsCluster,
  instances: Map<string, AwsInstance>,
): SelectorContext {
  const members: SelectorMember[] = (cluster.DBClusterMembers ?? []).map(
    (m) => {
      const id = m.DBInstanceIdentifier ?? "";
      const inst = instances.get(id);
      const member: SelectorMember = {
        DBInstanceIdentifier: id,
        DBInstanceClass: inst?.DBInstanceClass ?? "unknown",
        Role: (m.IsClusterWriter ? "writer" : "reader") as "writer" | "reader",
      };
      // AvailabilityZone: prefer the instance shape (canonical) but fall
      // through to undefined when neither side returned it.
      if (inst?.AvailabilityZone !== undefined) {
        member.AvailabilityZone = inst.AvailabilityZone;
      }
      // PromotionTier: prefer the instance-side value, then the
      // cluster-member-side value — both AWS shapes carry it; the writer
      // pattern for Engine/EngineVersion is the same.
      const promotionTier = inst?.PromotionTier ?? m.PromotionTier;
      if (promotionTier !== undefined) {
        member.PromotionTier = promotionTier;
      }
      // DBClusterParameterGroupStatus: cluster-member-side only.
      if (m.DBClusterParameterGroupStatus !== undefined) {
        member.DBClusterParameterGroupStatus = m.DBClusterParameterGroupStatus;
      }
      return member;
    },
  );
  return {
    DBClusterIdentifier: cluster.DBClusterIdentifier ?? "",
    Engine: cluster.Engine ?? "",
    EngineVersion: cluster.EngineVersion ?? "",
    Status: cluster.Status ?? "",
    MultiAZ: cluster.MultiAZ ?? false,
    members,
    tags: tagsFromAws(cluster.TagList),
  };
}

// ---------------------------------------------------------------------------
// Method body — exposed for the smoke test to drive without a real RDSClient
// ---------------------------------------------------------------------------

/**
 * Dependencies for {@link runListClusters}. Exported so the smoke test can
 * inject its own AWS-facade replay and a fake runtime context.
 */
export interface ListClustersDeps {
  /** Facade over the RDS SDK calls this method needs. */
  api: RdsApi;
  /**
   * Swamp method-execution context. Typed `any` because the host injects the
   * real type at runtime and `MethodContext` is not part of the
   * extension-author-facing surface.
   */
  // deno-lint-ignore no-explicit-any
  context: any;
}

/** Shape returned by {@link runListClusters}. */
export interface ListClustersResult {
  /** Data handles produced during the run, in write order. */
  dataHandles: unknown[];
}

/**
 * Core list_clusters logic, parameterized on its AWS facade and runtime
 * context. The real model.execute wraps this with a default-configured
 * RDSClient; the smoke test injects a replay-from-fixtures `RdsApi` instead.
 *
 * Returns the data handles produced during writes; surfaced for assertions.
 */
export async function runListClusters(
  deps: ListClustersDeps,
): Promise<ListClustersResult> {
  const { api, context } = deps;
  const globalArgs = GlobalArgsSchema.parse(context.globalArgs);
  const region = resolveRegion(globalArgs);

  context.logger.info(
    "aws-rds-inventory: starting list_clusters (region={region})",
    { region },
  );

  // Compile the selector BEFORE any AWS work — a bad selector should fail
  // closed without spending API budget.
  const env = context.createCelEnvironment();
  let predicate: (ctx: Record<string, unknown>) => unknown;
  try {
    predicate = env.parse(globalArgs.selector);
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    throw new Error(
      `aws-rds-inventory: failed to parse selector ` +
        `${JSON.stringify(globalArgs.selector)}: ${detail}`,
    );
  }

  const rawClusters = await collectClusters(api);
  context.logger.info(
    "Fetched {count} DescribeDBClusters rows from {region}",
    { count: rawClusters.length, region },
  );

  const clusters = rawClusters.filter((c) => isRdsEngine(c.Engine));
  const droppedCount = rawClusters.length - clusters.length;
  if (droppedCount > 0) {
    context.logger.info(
      "Dropped {droppedCount} non-RDS clusters; {kept} RDS clusters remain " +
        "before selector evaluation",
      { droppedCount, kept: clusters.length },
    );
  }

  // Fetch instances for every allowlisted cluster (not just selector-matched
  // ones): the selector may inspect member-level fields, so its context must
  // be built from the real instance data for every candidate it evaluates.
  const clusterIds: string[] = [];
  for (const c of clusters) {
    if (c.DBClusterIdentifier) clusterIds.push(c.DBClusterIdentifier);
  }
  const instances = await collectInstances(api, clusterIds);

  const selectorContexts = clusters.map((c) =>
    buildSelectorContext(c, instances)
  );
  const matches = evaluateSelector(predicate, selectorContexts);

  const matchedClusters: AwsCluster[] = [];
  const matchedContexts: SelectorContext[] = [];
  for (let i = 0; i < clusters.length; i++) {
    if (matches[i]) {
      matchedClusters.push(clusters[i]);
      matchedContexts.push(selectorContexts[i]);
    }
  }
  context.logger.info(
    "{count} clusters match selector",
    { count: matchedClusters.length },
  );

  const handles: unknown[] = [];
  let clusterCount = 0;
  let instanceCount = 0;

  for (let i = 0; i < matchedClusters.length; i++) {
    const cluster = matchedClusters[i];
    const ctx = matchedContexts[i];
    const clusterId = cluster.DBClusterIdentifier ?? "";
    if (clusterId === "") {
      context.logger.warn(
        "Skipping cluster with no DBClusterIdentifier (engine={engine})",
        { engine: cluster.Engine ?? "<unknown>" },
      );
      continue;
    }
    clusterCount++;

    const clusterResource: ClusterResource = {
      DBClusterIdentifier: clusterId,
      Engine: cluster.Engine ?? "unknown",
      EngineVersion: cluster.EngineVersion,
      Status: cluster.Status,
      Endpoint: cluster.Endpoint,
      ReaderEndpoint: cluster.ReaderEndpoint,
      MultiAZ: cluster.MultiAZ,
      tags: ctx.tags,
    };
    handles.push(
      await context.writeResource(
        "cluster",
        clusterKey(clusterId),
        clusterResource,
      ),
    );

    for (const m of ctx.members) {
      if (!m.DBInstanceIdentifier) continue;
      const awsInst = instances.get(m.DBInstanceIdentifier);
      const instanceResource: InstanceResource = {
        DBInstanceIdentifier: m.DBInstanceIdentifier,
        DBClusterIdentifier: clusterId,
        DBInstanceClass: m.DBInstanceClass,
        Role: m.Role,
        // SelectorMember already left these absent when AWS omitted, so the
        // straight passthrough preserves the no-undefined-keys property of
        // the JSON-serialized resource.
        AvailabilityZone: m.AvailabilityZone,
        Engine: awsInst?.Engine ?? cluster.Engine ?? "unknown",
        EngineVersion: awsInst?.EngineVersion ?? cluster.EngineVersion,
        Status: awsInst?.DBInstanceStatus,
        PromotionTier: m.PromotionTier,
        DBClusterParameterGroupStatus: m.DBClusterParameterGroupStatus,
        tags: tagsFromAws(awsInst?.TagList),
      };
      instanceCount++;
      handles.push(
        await context.writeResource(
          "instance",
          instanceKey(clusterId, m.DBInstanceIdentifier),
          instanceResource,
        ),
      );
    }
  }

  context.logger.info(
    "Wrote {clusters} cluster resources and {instances} instance resources",
    {
      clusters: clusterCount,
      instances: instanceCount,
    },
  );

  return { dataHandles: handles };
}

// ---------------------------------------------------------------------------
// Model export
// ---------------------------------------------------------------------------

/**
 * The `@jentz/aws-rds-inventory` model.
 *
 * Single method `list_clusters` discovers RDS DB clusters via the SDK, drops
 * shared-endpoint non-RDS engines, filters the remaining clusters with a CEL
 * selector, and writes one `cluster` + N `instance` factory resources.
 */
export const model = {
  type: "@jentz/aws-rds-inventory",
  version: "2026.07.20.0",
  globalArguments: GlobalArgsSchema,
  // The 2026.06.05.1, 2026.06.06.1, 2026.06.07.1, and 2026.06.07.2 releases
  // changed only internals (server-side DescribeDBInstances filtering, AWS SDK
  // bump) and docs/metadata — the globalArguments schema (region, selector) is
  // unchanged from 2026.05.24.1. Each no-op upgrade still advances the stored
  // typeVersion on existing instances so any future schema-changing upgrade
  // chains cleanly from here instead of skipping them.
  upgrades: [
    {
      toVersion: "2026.06.05.1",
      description: "Version bump, no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.06.1",
      description: "Docs-only release (see-also cross-link); no schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.07.1",
      description: "Version bump, no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.07.2",
      description: "Version bump, no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.08.1",
      description:
        "Docs-only release (account-id placeholder scrub); no schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.22.0",
      description: "Dependency refresh, no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.26.0",
      description:
        "Shared retry helper regenerated from canonical _lib (generated " +
        "header only); no globalArguments schema or runtime changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.03.0",
      description:
        "Retire the app-level retry layer for the SDK adaptive retry " +
        "(shared bounded config on the RDS client); no globalArguments " +
        "schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.19.0",
      description:
        "Docs-only accuracy fix (selector Engine is never empty post-allowlist); no schema change",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.20.0",
      description:
        "Regenerate shared scan_error _lib twin: harden message extraction " +
        "for non-Error object errors; no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    cluster: {
      description:
        "RDS DB cluster summary. One resource per cluster the selector " +
        "admits; instance-level details live on the sibling 'instance' spec.",
      schema: ClusterSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    instance: {
      description:
        "RDS DB cluster member instance. Back-references its cluster via " +
        "DBClusterIdentifier. One resource per member.",
      schema: InstanceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    list_clusters: {
      description:
        "List RDS DB clusters matching the CEL selector, plus their members.",
      arguments: z.object({}),
      execute: (
        _args: Record<string, never>,
        // deno-lint-ignore no-explicit-any
        context: any,
      ): Promise<{ dataHandles: unknown[] }> => {
        const globalArgs = GlobalArgsSchema.parse(context.globalArgs);
        const region = resolveRegion(globalArgs);
        const client = new RDSClient({ region, ...SHARED_RETRY });
        return runListClusters({ api: rdsApiFromSdk(client), context });
      },
    },
  },
};
