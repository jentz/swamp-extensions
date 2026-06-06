/**
 * `@jentz/aws-rds-reservations` — fleet-wide RDS instance + reserved-instance
 * inventory across `profiles × regions`.
 *
 * The single `sweep` method fans out over every configured profile and region
 * in one execution (one model lock, all output in one pass — see repo rule 6).
 * For each (account, region) it lists, via the RDS API:
 *
 *   - every provisioned DB instance (`DescribeDBInstances` — this returns
 *     Aurora cluster members AND standalone single-instance RDS, so nothing is
 *     missed), emitting one `instance` resource per DB instance carrying the
 *     instance class, engine, license model, Multi-AZ flag, status, and owning
 *     cluster id (the license model is decisive for Oracle, where size-flexible
 *     reservations apply to BYOL only — see the coverage report);
 *   - every reserved DB instance (`DescribeReservedDBInstances`), emitting one
 *     `reserved` resource per reservation carrying the offered class, product
 *     description (engine), Multi-AZ flag, instance count, and state.
 *
 * Classification and the large-equivalent normalization deliberately live
 * downstream in the companion report `@jentz/aws-rds-reservation-coverage` —
 * this model is a dumb collector that records the raw AWS facts, mirroring the
 * `@jentz/aws-vpc-inventory` convention.
 *
 * Per-(profile, region) failures become `scan_error` rows instead of aborting
 * the sweep: an expired SSO token, an SCP-denied region, or a malformed
 * response is reported, never silenced.
 *
 * Read-only: only `Describe*` and `sts:GetCallerIdentity` are called.
 *
 * @module
 */

import { z } from "npm:zod@4";
import {
  DescribeDBInstancesCommand,
  DescribeReservedDBInstancesCommand,
  RDSClient,
} from "npm:@aws-sdk/client-rds@3.1021.0";
import {
  GetCallerIdentityCommand,
  STSClient,
} from "npm:@aws-sdk/client-sts@3.1021.0";
import { fromIni } from "npm:@aws-sdk/credential-providers@3.1021.0";
import { type RetryDeps, withRetry } from "./_lib/retry.ts";

// Re-exported so the public `paginate` signature does not leak private types
// (`RetryDeps.onRetry` carries a `RetryEvent`).
export type { RetryDeps, RetryEvent } from "./_lib/retry.ts";

/** Minimal AWS credential shape a {@link CredentialProvider} resolves. */
export interface AwsCredentials {
  /** Access key id. */
  accessKeyId: string;
  /** Secret access key. */
  secretAccessKey: string;
  /** Session token for temporary (SSO/STS) credentials. */
  sessionToken?: string;
  /** Expiry of temporary credentials. */
  expiration?: Date;
}

/**
 * AWS credential provider — a function resolving credentials on demand, the
 * shape `fromIni` returns and the RDS/STS clients accept. A self-contained
 * structural type (rather than `ReturnType<typeof fromIni>`) so this public
 * export does not leak the SDK's private credential types. `undefined` (not a
 * value of this type) means the ambient credential chain.
 */
export type CredentialProvider = () => Promise<AwsCredentials>;

/** Factory for constructing an AWS API facade bound to one credential source. */
export type ApiFactory = (
  credentials: CredentialProvider | undefined,
  bootstrapRegion: string,
  logger: unknown,
) => AwsApi;

/** Factory for constructing a credential provider for a named AWS profile. */
export type CredentialFactory = (
  args: { profile: string },
) => CredentialProvider;

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  profiles: z.array(z.string().min(1)).default([]).describe(
    "Named AWS profiles to sweep, one account each. Empty (default) uses the " +
      "ambient credential chain (whatever AWS_PROFILE / env is set) as a " +
      "single account — handy for testing one account before scaling out.",
  ),
  regions: z.array(z.string().min(1)).default([]).describe(
    "Regions to sweep per account. Required — RDS describe calls are " +
      "region-scoped and there is no enabled-region discovery here (an " +
      "SCP-denied region simply becomes a scan_error). Pass the org's " +
      "approved regions.",
  ),
  requiredProfileSuffix: z.string().default("").describe(
    "If set, every named profile must end with this suffix or it is refused " +
      "before any AWS call. Set to '-readonly' to enforce read-only profiles. " +
      "Ambient credentials have no reliable profile label, so leave this empty " +
      "when profiles is [] or pass an explicit named profile instead. Default " +
      "'' disables the check.",
  ),
});

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

// ---------------------------------------------------------------------------
// Public resource shapes (explicit interfaces — deno doc --lint friendly)
// ---------------------------------------------------------------------------

/** One provisioned DB instance observed in one (account, region). */
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
   * `general-public-license`, `postgresql-license`, `marketplace-license`;
   * `""` if AWS did not report one (e.g. Aurora / RDS Custom). Decisive for
   * Oracle, where size-flexible reservations apply to BYOL only and an
   * `oracle-se2` engine can be either BYOL or License-Included — the engine
   * string alone cannot tell them apart. Consumed by the companion coverage
   * report to keep License-Included capacity out of the size-flex netting.
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

/** One reserved DB instance offering observed in one (account, region). */
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
  /** Product description (the RI's engine), e.g. `postgresql`, `aurora postgresql`. */
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

/** A (profile, region) pair that could not be assessed. */
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

// ---------------------------------------------------------------------------
// Pure helpers (exported for unit-test access)
// ---------------------------------------------------------------------------

/** AWS-style tag tuple as returned by RDS describe calls. */
export interface AwsTag {
  /** Tag key. */
  Key?: string;
  /** Tag value. */
  Value?: string;
}

/**
 * Convert AWS's `[{Key, Value}, ...]` tag array into a flat `{key: value}` map.
 * Missing input becomes `{}`; tags with no `Key` are dropped; a missing `Value`
 * becomes `""` so the result stays `Record<string,string>`.
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
 * Derive a friendly account label from a profile name by stripping the
 * configured suffix (typically `-readonly`). When `profile` is empty
 * (ambient), or when it does not end with the suffix, the profile is returned
 * unchanged. An empty `suffix` is a no-op.
 */
export function accountNameFromProfile(
  profile: string,
  suffix: string,
): string {
  if (profile.length === 0) return "";
  if (suffix.length === 0) return profile;
  return profile.endsWith(suffix)
    ? profile.slice(0, profile.length - suffix.length)
    : profile;
}

/**
 * Classify an AWS SDK error into the coarse `kind` the operator report uses to
 * decide a next action. SSO/token/credential failures map to `auth_expired`
 * (operator runs `aws sso login`); authorization failures map to
 * `access_denied` (the role lacks a describe permission, or an SCP denies the
 * region); everything else is `other`.
 */
export function classifyError(err: unknown): {
  kind: "auth_expired" | "access_denied" | "other";
  message: string;
} {
  const message = err instanceof Error ? err.message : String(err);
  const name = (err as { name?: string } | null)?.name ?? "";
  const haystack = `${name} ${message}`.toLowerCase();
  const isAuthExpired = name.toLowerCase().includes("expiredtoken") ||
    name.toLowerCase().includes("credentialsprovidererror") ||
    haystack.includes("token has expired") ||
    haystack.includes("token is expired") ||
    haystack.includes("token included in the request is expired") ||
    haystack.includes("sso session") ||
    haystack.includes("session associated with this profile has expired") ||
    haystack.includes("could not load credentials") ||
    haystack.includes("failed to refresh");
  const isAccessDenied = haystack.includes("not authorized") ||
    haystack.includes("unauthorizedoperation") ||
    haystack.includes("accessdenied") ||
    haystack.includes("access denied") ||
    haystack.includes("explicit deny") ||
    haystack.includes("forbidden");
  if (isAuthExpired) return { kind: "auth_expired", message };
  if (isAccessDenied) return { kind: "access_denied", message };
  return { kind: "other", message };
}

/**
 * Resolve the bootstrap region for the per-account sts:GetCallerIdentity call.
 * Order: first configured region → `AWS_REGION` → `AWS_DEFAULT_REGION` →
 * `us-east-1` (a global-ish default enabled on every account, used only for
 * that one bootstrap call).
 */
export function resolveBootstrapRegion(
  regions: string[],
  env: (name: string) => string | undefined = (name) => Deno.env.get(name),
): string {
  const candidates = [regions[0], env("AWS_REGION"), env("AWS_DEFAULT_REGION")];
  for (const c of candidates) {
    if (typeof c === "string" && c.trim().length > 0) return c.trim();
  }
  return "us-east-1";
}

// Storage-key separator convention (locked task-57, before first publish).
// Free identifiers are joined with a DOUBLE hyphen `--`, adopting the same
// separator token as the sibling `@jentz/aws-rds-inventory`
// (`instance-<cluster>--<instance>`); the overall key shapes differ (we also
// carry account id and region), so this is the shared convention, not an
// identical layout.
//
// Why each key is unambiguous — the argument is per-key, not "no component ever
// contains `--`":
//   - instanceKey / reservedKey: account id is fixed 12 digits and region is a
//     closed AWS set (both self-delimiting with single `-`); the only free
//     component is the trailing identifier, and RDS forbids consecutive hyphens
//     in identifiers, so the lone `--` marks its boundary unambiguously.
//   - scanErrorKey: `profile` IS a free operator string and MAY contain `--`,
//     so safety does not come from the separator. It comes from position: the
//     two trailing fields `region` (closed set) and `phase` (internal constant,
//     underscore-only, hyphen-free) contain no `--`, so the value decodes
//     unambiguously from the right regardless of `profile`. This holds ONLY
//     while region/phase stay closed-set — do not move a free field to the tail.
//     Empty segments (not word-sentinels) mark the ambient chain / account-level
//     failure, so a profile literally named `ambient` cannot impersonate them.

/** Build a stable storage key for an instance row (unique across account/region). */
export function instanceKey(
  accountId: string,
  region: string,
  dbInstanceIdentifier: string,
): string {
  return `instance-${accountId}-${region}--${dbInstanceIdentifier}`;
}

/** Build a stable storage key for a reserved-instance row. */
export function reservedKey(
  accountId: string,
  region: string,
  reservedDBInstanceId: string,
): string {
  return `reserved-${accountId}-${region}--${reservedDBInstanceId}`;
}

/** Build a stable storage key for a scan error. */
export function scanErrorKey(
  profileLabel: string,
  region: string,
  phase: string,
): string {
  return `error--${profileLabel}--${region}--${phase}`;
}

// ---------------------------------------------------------------------------
// AWS facade — minimal surface so the smoke test can replay without the SDK
// ---------------------------------------------------------------------------

/** Minimal DB instance shape this extension depends on. */
export interface AwsDBInstance {
  /** DB instance identifier. */
  DBInstanceIdentifier?: string;
  /** Instance class, e.g. `db.r7g.2xlarge`. */
  DBInstanceClass?: string;
  /** Engine, e.g. `postgres`. */
  Engine?: string;
  /** Engine version. */
  EngineVersion?: string;
  /** License model, e.g. `license-included`, `bring-your-own-license`. */
  LicenseModel?: string;
  /** Lifecycle status. */
  DBInstanceStatus?: string;
  /** Multi-AZ deployment flag. */
  MultiAZ?: boolean;
  /** Owning cluster id (Aurora / Multi-AZ DB cluster members). */
  DBClusterIdentifier?: string;
  /** Storage type. */
  StorageType?: string;
  /** Instance tags. */
  TagList?: AwsTag[];
}

/** Minimal reserved DB instance shape this extension depends on. */
export interface AwsReservedDBInstance {
  /** Reservation id. */
  ReservedDBInstanceId?: string;
  /** Reserved class. */
  DBInstanceClass?: string;
  /** Product description (engine). */
  ProductDescription?: string;
  /** Multi-AZ flag. */
  MultiAZ?: boolean;
  /** Number of instances covered. */
  DBInstanceCount?: number;
  /** State, e.g. `active`. */
  State?: string;
  /** Offering type. */
  OfferingType?: string;
  /** Term in seconds. */
  Duration?: number;
  /** Reservation start time. */
  StartTime?: Date;
}

/**
 * Facade over the bits of RDS/STS this extension uses, for one account's
 * credentials. Lets the smoke test substitute an in-memory replay.
 */
export interface AwsApi {
  /** Resolve the account id for the active credentials. */
  getAccountId(): Promise<string>;
  /** Every provisioned DB instance in `region`. */
  describeDBInstances(region: string): Promise<AwsDBInstance[]>;
  /** Every reserved DB instance in `region`. */
  describeReservedDBInstances(region: string): Promise<AwsReservedDBInstance[]>;
}

// ---------------------------------------------------------------------------
// SDK-backed facade
// ---------------------------------------------------------------------------

const CLIENT_RETRY = { maxAttempts: 5 } as const;

/**
 * Build the {@link RetryDeps} the {@link paginate} loop uses for production
 * (real `Math.random` jitter, real `setTimeout` waits), logging each retry at
 * `debug` so a throttled sweep is observable. Mirrors the sibling
 * `@jentz/aws-rds-inventory`'s `retryDeps`.
 */
// deno-lint-ignore no-explicit-any
function retryDeps(logger: any): RetryDeps {
  return {
    random: () => Math.random(),
    delay: (ms: number) => new Promise<void>((r) => setTimeout(r, ms)),
    onRetry: (e: { operationName: string; attempt: number; delayMs: number }) =>
      logger.debug(
        "Throttled on {op} attempt {attempt}, waiting {delayMs}ms",
        { op: e.operationName, attempt: e.attempt, delayMs: e.delayMs },
      ),
  };
}

/**
 * One page of a `Marker`-paginated RDS describe call: the items on this page
 * plus the `Marker` for the next page (`undefined` once the last page is
 * reached).
 *
 * @typeParam T Element type of the page.
 */
export interface Page<T> {
  /** Items returned on this page. */
  items: T[];
  /** Opaque marker for the next page, or `undefined` when exhausted. */
  marker: string | undefined;
}

/**
 * Drain a `Marker`-paginated RDS describe call to exhaustion, retrying each
 * page on throttling with full-jitter backoff. `fetchPage(marker)` issues one
 * `rds.send` for the page starting at `marker` and returns that page's items
 * plus the next marker.
 *
 * The retry wraps each individual page send — NOT the whole drain — so a
 * throttle deep in the pagination re-issues only the current page (with the
 * same marker) rather than resetting to the first page and re-fetching
 * everything, which would worsen the throttle. No early exit and no page cap:
 * every page matters, and a silent truncation is the exact data-completeness
 * bug this seam exists to prevent.
 *
 * Owning the loop+retry wiring here (rather than in `_lib/retry.ts`) keeps the
 * retry twin byte-identical with the sibling and makes the wiring unit-testable
 * with a fake `fetchPage` — no AWS SDK fake required.
 *
 * @typeParam T Element type accumulated across pages.
 * @param fetchPage Issues one page request for the given marker.
 * @param operationName Short op name surfaced via `onRetry` (e.g. `DescribeDBInstances`).
 * @param deps Retry dependencies — injectable for deterministic tests.
 * @returns Every item across every page, in page order.
 */
export async function paginate<T>(
  fetchPage: (marker: string | undefined) => Promise<Page<T>>,
  operationName: string,
  deps: RetryDeps,
): Promise<T[]> {
  const out: T[] = [];
  let marker: string | undefined;
  do {
    const page = await withRetry(
      () => fetchPage(marker),
      operationName,
      undefined,
      deps,
    );
    out.push(...page.items);
    marker = page.marker;
  } while (marker);
  return out;
}

/** Minimal shape returned by `sts:GetCallerIdentity` for account-id lookup. */
export interface CallerIdentity {
  /** 12-digit AWS account id, or undefined if the service response omits it. */
  Account?: string;
}

/**
 * Fetch the current caller's AWS account id, retrying throttled STS bootstrap
 * calls with the same full-jitter retry policy used by the RDS describe paths.
 * A post-exhaustion throttle is deliberately allowed to propagate so
 * `runSweep` records the existing credentials-phase `scan_error`.
 *
 * @param send Issues one `sts:GetCallerIdentity` request.
 * @param deps Retry dependencies — injectable for deterministic tests.
 * @returns The reported account id, or `""` if AWS omitted it.
 */
export async function getCallerAccountId(
  send: () => Promise<CallerIdentity>,
  deps: RetryDeps,
): Promise<string> {
  const resp = await withRetry(
    send,
    "GetCallerIdentity",
    undefined,
    deps,
  );
  return resp.Account ?? "";
}

function sdkApi(
  credentials: CredentialProvider | undefined,
  bootstrapRegion: string,
  // deno-lint-ignore no-explicit-any
  logger: any,
): AwsApi {
  const rdsFor = (region: string) =>
    new RDSClient({ region, credentials, ...CLIENT_RETRY });
  const deps = retryDeps(logger);

  return {
    getAccountId: () => {
      const sts = new STSClient({
        region: bootstrapRegion,
        credentials,
        ...CLIENT_RETRY,
      });
      return getCallerAccountId(
        () => sts.send(new GetCallerIdentityCommand({})),
        deps,
      );
    },
    describeDBInstances: (region) => {
      const rds = rdsFor(region);
      return paginate<AwsDBInstance>(
        async (marker) => {
          const resp = await rds.send(
            new DescribeDBInstancesCommand({ Marker: marker, MaxRecords: 100 }),
          );
          return { items: resp.DBInstances ?? [], marker: resp.Marker };
        },
        "DescribeDBInstances",
        deps,
      );
    },
    describeReservedDBInstances: (region) => {
      const rds = rdsFor(region);
      return paginate<AwsReservedDBInstance>(
        async (marker) => {
          const resp = await rds.send(
            new DescribeReservedDBInstancesCommand({
              Marker: marker,
              MaxRecords: 100,
            }),
          );
          return { items: resp.ReservedDBInstances ?? [], marker: resp.Marker };
        },
        "DescribeReservedDBInstances",
        deps,
      );
    },
  };
}

// ---------------------------------------------------------------------------
// Core sweep logic — parameterized on its AWS facade and runtime context
// ---------------------------------------------------------------------------

/** Arguments for {@link buildTargets}. */
export interface BuildTargetsArgs {
  /** Named AWS profiles to sweep. Empty means one ambient-credential target. */
  profiles: string[];
  /** Region used for bootstrap/account-identity API calls. */
  bootstrapRegion: string;
  /** Runtime logger passed through to the API facade. */
  logger: unknown;
  /** Factory for constructing the AWS API facade. Defaults to the real SDK facade. */
  apiFactory?: ApiFactory;
  /** Factory for constructing named-profile credentials. Defaults to `fromIni`. */
  credentialFactory?: CredentialFactory;
}

/**
 * Build one sweep target per configured profile, or one ambient target when no
 * profiles are configured. This is the production `execute` credential-mapping
 * seam, exported so tests can pin ambient-vs-profile behavior without touching
 * real AWS SDK clients.
 *
 * @param args Profiles, bootstrap region, logger, and optional factories.
 * @returns Ordered sweep targets matching the configured profile order.
 */
export function buildTargets(args: BuildTargetsArgs): SweepTarget[] {
  const {
    profiles,
    bootstrapRegion,
    logger,
    apiFactory = sdkApi,
    credentialFactory = fromIni,
  } = args;

  return profiles.length === 0
    ? [{
      profile: "",
      api: apiFactory(undefined, bootstrapRegion, logger),
    }]
    : profiles.map((profile) => ({
      profile,
      api: apiFactory(
        credentialFactory({ profile }),
        bootstrapRegion,
        logger,
      ),
    }));
}

/** One account's sweep target: a label and the API facade. */
export interface SweepTarget {
  /** Profile name, or `""` for the ambient credential chain. */
  profile: string;
  /** API facade bound to this account's credentials. */
  api: AwsApi;
}

/** Dependencies for {@link runSweep}. */
export interface SweepDeps {
  /** Ordered sweep targets, one per account. */
  targets: SweepTarget[];
  /** Regions to sweep per account. */
  regions: string[];
  /** Required profile suffix; `""` disables the check. */
  requiredProfileSuffix: string;
  /**
   * Swamp method-execution context. Typed `any` because the host injects the
   * real type at runtime.
   */
  // deno-lint-ignore no-explicit-any
  context: any;
  /** Clock used to stamp all rows from a single sweep. Defaults to `new Date()`. */
  now?: () => Date;
}

/** Result of {@link runSweep}. */
export interface SweepResult {
  /** Data handles produced during the run, in write order. */
  dataHandles: unknown[];
  /** Count of instance rows written. */
  instanceCount: number;
  /** Count of reserved rows written. */
  reservedCount: number;
  /** Count of scan errors written. */
  errorCount: number;
}

/**
 * Core `sweep` logic. Iterates targets (accounts) × regions, writing one
 * `instance` resource per provisioned DB instance, one `reserved` resource per
 * reservation, and one `scan_error` per (profile, region) phase that fails.
 * Per-target and per-region failures are caught and recorded — a single
 * expired SSO token or denied call never aborts the wider sweep.
 *
 * @param deps Targets, configuration, and the runtime context.
 * @returns Data handles plus instance / reserved / error counts.
 */
export async function runSweep(deps: SweepDeps): Promise<SweepResult> {
  const {
    targets,
    regions,
    requiredProfileSuffix,
    context,
    now = () => new Date(),
  } = deps;
  const handles: unknown[] = [];
  let instanceCount = 0;
  let reservedCount = 0;
  let errorCount = 0;
  const scannedAt = now().toISOString();

  const writeError = async (e: ScanError): Promise<void> => {
    errorCount++;
    handles.push(
      await context.writeResource(
        "scan_error",
        scanErrorKey(e.profile, e.region, e.phase),
        e,
      ),
    );
  };

  for (const target of targets) {
    const profileLabel = target.profile;
    let accountName = accountNameFromProfile(
      profileLabel,
      requiredProfileSuffix,
    );

    if (
      requiredProfileSuffix.length > 0 &&
      !profileLabel.endsWith(requiredProfileSuffix)
    ) {
      context.logger.warn(
        "Skipping profile {profile}: does not end with required suffix {suffix}",
        { profile: profileLabel || "<ambient>", suffix: requiredProfileSuffix },
      );
      await writeError({
        profile: profileLabel,
        accountId: "",
        region: "",
        phase: "profile_suffix_check",
        kind: "other",
        message:
          `Profile '${profileLabel}' does not end with required suffix ` +
          `'${requiredProfileSuffix}'; skipped before any AWS call.`,
        scannedAt,
      });
      continue;
    }

    // Resolve account id (also validates the credentials work at all).
    let accountId = "";
    try {
      accountId = await target.api.getAccountId();
    } catch (err) {
      const { kind, message } = classifyError(err);
      context.logger.warn(
        "Credentials failed for profile {profile}: {message}",
        { profile: profileLabel || "<ambient>", message },
      );
      await writeError({
        profile: profileLabel,
        accountId: "",
        region: "",
        phase: "credentials",
        kind,
        message,
        scannedAt,
      });
      continue;
    }

    // The ambient credential chain has no profile to derive a label from, so
    // accountNameFromProfile returned "". Fall back to the resolved account id
    // so the companion report's per-account view is never labeled blank.
    if (profileLabel.length === 0) accountName = accountId;

    context.logger.info(
      "Sweeping account {account} (profile={profile}) across {count} region(s)",
      {
        account: accountId,
        profile: profileLabel || "<ambient>",
        count: regions.length,
      },
    );

    for (const region of regions) {
      // Provisioned DB instances.
      try {
        const dbInstances = await target.api.describeDBInstances(region);
        for (const db of dbInstances) {
          const id = db.DBInstanceIdentifier ?? "";
          if (id === "") {
            context.logger.warn(
              "DB instance with no identifier in {region}; skipped",
              { region },
            );
            continue;
          }
          const row: InstanceRecord = {
            accountId,
            accountName,
            profile: profileLabel,
            region,
            dbInstanceIdentifier: id,
            dbInstanceClass: db.DBInstanceClass ?? "",
            engine: db.Engine ?? "",
            engineVersion: db.EngineVersion ?? "",
            licenseModel: db.LicenseModel ?? "",
            multiAZ: db.MultiAZ ?? false,
            status: db.DBInstanceStatus ?? "",
            clusterId: db.DBClusterIdentifier ?? "",
            storageType: db.StorageType ?? "",
            instanceTags: tagsFromAws(db.TagList),
            scannedAt,
          };
          instanceCount++;
          handles.push(
            await context.writeResource(
              "instance",
              instanceKey(accountId, region, id),
              row,
            ),
          );
        }
      } catch (err) {
        const { kind, message } = classifyError(err);
        context.logger.warn(
          "DescribeDBInstances failed in {region} for account {account}: {message}",
          { region, account: accountId, message },
        );
        await writeError({
          profile: profileLabel,
          accountId,
          region,
          phase: "describe_db_instances",
          kind,
          message,
          scannedAt,
        });
      }

      // Reserved DB instances.
      try {
        const reserved = await target.api.describeReservedDBInstances(region);
        for (const r of reserved) {
          const rid = r.ReservedDBInstanceId ?? "";
          if (rid === "") {
            context.logger.warn(
              "Reserved DB instance with no id in {region}; skipped",
              { region },
            );
            continue;
          }
          const row: ReservedRecord = {
            accountId,
            accountName,
            profile: profileLabel,
            region,
            reservedDBInstanceId: rid,
            dbInstanceClass: r.DBInstanceClass ?? "",
            productDescription: r.ProductDescription ?? "",
            multiAZ: r.MultiAZ ?? false,
            dbInstanceCount: r.DBInstanceCount ?? 0,
            state: r.State ?? "",
            offeringType: r.OfferingType ?? "",
            durationSeconds: r.Duration ?? 0,
            startTime: r.StartTime instanceof Date
              ? r.StartTime.toISOString()
              : "",
            scannedAt,
          };
          reservedCount++;
          handles.push(
            await context.writeResource(
              "reserved",
              reservedKey(accountId, region, rid),
              row,
            ),
          );
        }
      } catch (err) {
        const { kind, message } = classifyError(err);
        context.logger.warn(
          "DescribeReservedDBInstances failed in {region} for account {account}: {message}",
          { region, account: accountId, message },
        );
        await writeError({
          profile: profileLabel,
          accountId,
          region,
          phase: "describe_reserved_db_instances",
          kind,
          message,
          scannedAt,
        });
      }
    }
  }

  context.logger.info(
    "aws-rds-reservations sweep complete: {instances} instance(s), {reserved} reservation(s), {errors} error(s)",
    {
      instances: instanceCount,
      reserved: reservedCount,
      errors: errorCount,
    },
  );

  return {
    dataHandles: handles,
    instanceCount,
    reservedCount,
    errorCount,
  };
}

// ---------------------------------------------------------------------------
// Model export
// ---------------------------------------------------------------------------

/**
 * The `@jentz/aws-rds-reservations` model.
 *
 * Single method `sweep` inventories every provisioned DB instance and every
 * reserved DB instance across the configured `profiles × regions`, emitting one
 * `instance` row per DB instance, one `reserved` row per reservation, and one
 * `scan_error` per (profile, region) phase that could not be assessed.
 */
export const model = {
  type: "@jentz/aws-rds-reservations",
  version: "2026.06.06.2",
  globalArguments: GlobalArgsSchema,
  // Still pre-publish, but the upgrade chain is maintained from the start
  // (matching the sibling @jentz/aws-rds-inventory convention) so existing
  // instances advance their stored typeVersion cleanly.
  upgrades: [
    {
      toVersion: "2026.06.06.2",
      description:
        "Add licenseModel to the instance resource (decisive for Oracle " +
        "BYOL-vs-LI size-flex routing in the coverage report). Additive; " +
        'existing instance rows backfill licenseModel to "". A re-sweep is ' +
        "required to populate the real value on already-collected rows.",
      upgradeAttributes: (old: Record<string, unknown>) => ({
        ...old,
        licenseModel: typeof old.licenseModel === "string"
          ? old.licenseModel
          : "",
      }),
    },
  ] as Array<{
    toVersion: string;
    description: string;
    upgradeAttributes: (
      old: Record<string, unknown>,
    ) => Record<string, unknown>;
  }>,
  resources: {
    instance: {
      description:
        "One provisioned DB instance (Aurora member or standalone) observed " +
        "in one (account, region): class, engine, Multi-AZ, status, cluster.",
      schema: InstanceRecordSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    reserved: {
      description:
        "One reserved DB instance offering observed in one (account, " +
        "region): class, product description, Multi-AZ, instance count, state.",
      schema: ReservedRecordSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    scan_error: {
      description:
        "A (profile, region) phase that could not be assessed — expired SSO " +
        "token, denied describe call, etc. Surfaces coverage gaps in the " +
        "companion report.",
      schema: ScanErrorSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    sweep: {
      description:
        "Inventory every provisioned and reserved DB instance across " +
        "profiles × regions, capturing account id, region, instance class, " +
        "engine, Multi-AZ deployment, status, and reservation counts.",
      arguments: z.object({}),
      execute: (
        _args: Record<string, never>,
        // deno-lint-ignore no-explicit-any
        context: any,
      ): Promise<SweepResult> => {
        const g = GlobalArgsSchema.parse(context.globalArgs);
        const bootstrapRegion = resolveBootstrapRegion(g.regions);

        const targets = buildTargets({
          profiles: g.profiles,
          bootstrapRegion,
          logger: context.logger,
        });

        return runSweep({
          targets,
          regions: g.regions,
          requiredProfileSuffix: g.requiredProfileSuffix,
          context,
        });
      },
    },
  },
};
