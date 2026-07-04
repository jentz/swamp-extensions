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

import { z } from "npm:zod@4.4.3";
import {
  DescribeDBInstancesCommand,
  DescribeReservedDBInstancesCommand,
  RDSClient,
} from "npm:@aws-sdk/client-rds@3.1073.0";
import {
  GetCallerIdentityCommand,
  STSClient,
} from "npm:@aws-sdk/client-sts@3.1073.0";
import { fromIni } from "npm:@aws-sdk/credential-providers@3.1073.0";
import {
  classifyError,
  type ScanError,
  scanErrorKey,
  ScanErrorSchema,
} from "./_lib/scan_error.ts";
import {
  preflightSsoGate,
  resolveBootstrapRegion,
  SHARED_RETRY,
} from "./_lib/aws_credentials.ts";

export { classifyError, scanErrorKey };
export type { ScanError };

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
      "approved regions. If empty or omitted, the sweep makes no AWS calls " +
      "and writes a single 'no_regions' scan_error instead of zero rows, " +
      "so the misconfiguration is visible rather than a silent empty result.",
  ),
  requiredProfileSuffix: z.string().default("").describe(
    "If set, every named profile must end with this suffix or it is refused " +
      "before any AWS call. Set to '-readonly' to enforce read-only profiles. " +
      "Ambient credentials have no reliable profile label, so leave this empty " +
      "when profiles is [] or pass an explicit named profile instead. Default " +
      "'' disables the check.",
  ),
  ssoSession: z.string().default("").describe(
    "Name of the shared AWS SSO session backing the swept profiles (the " +
      "`[sso-session <name>]` block in ~/.aws/config). When set, the sweep " +
      "pre-flights this session's cached token once before the per-profile " +
      "loop: a genuinely expired token short-circuits the whole sweep with a " +
      "single 'run aws sso login' error rather than failing every profile. " +
      "Empty (default) skips the pre-flight entirely.",
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

// The `scan_error` stored-row shape (schema + `ScanError` interface) is the
// canonical fleet shape imported from `./_lib/scan_error.ts` above: it carries a
// `service` tag and a `network` kind on top of the original auth_expired /
// access_denied / other classification. RDS is region-scoped, so the canonical
// `(profile, accountId, region, service, phase, kind, message, scannedAt)` shape
// maps cleanly with no local fields to add.

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

// Storage-key separator convention (locked task-57, before first publish).
// `instance`/`reserved` free identifiers are joined with a DOUBLE hyphen `--`,
// adopting the same separator token as the sibling `@jentz/aws-rds-inventory`
// (`instance-<cluster>--<instance>`); the overall key shapes differ (we also
// carry account id and region), so this is the shared convention, not an
// identical layout. account id is fixed 12 digits and region is a closed AWS
// set (both self-delimiting with single `-`); the only free component is the
// trailing identifier, and RDS forbids consecutive hyphens in identifiers, so
// the lone `--` marks its boundary unambiguously.
//
// `scan_error` rows are keyed by the canonical fleet `scanErrorKey`
// (`error-<profile|ambient>-<region|account>-<service>-<phase>`, single-hyphen,
// imported from `./_lib/scan_error.ts`), NOT this `--` convention. The per-row
// malformed phases — which fire once PER ROW and would otherwise collide on the
// shared (profile, region, service, phase) tuple — preserve per-row uniqueness
// by folding a row discriminator into the `phase` segment (see
// `discriminatedPhase` / `writeError` below) rather than by appending a key
// suffix, since the canonical key has no discriminator slot.

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

/**
 * Build the discriminated `phase` value for a per-row malformed `scan_error`.
 *
 * The per-row malformed phases (`malformed_db_instance`,
 * `malformed_reserved_db_instance`) fire ONCE PER ROW, so without a per-row
 * discriminator every malformed row in one (profile, region) would collide on
 * the shared canonical key and the keyed store would collapse N rows into one
 * (last-write-wins). The canonical {@link scanErrorKey} has no discriminator
 * slot, so uniqueness is folded into the `phase` segment instead: the returned
 * value is used BOTH as the `phase` argument to `scanErrorKey` (making the key
 * distinct) AND as the stored `phase` attribute on the row (so the operator can
 * see which row was malformed).
 *
 * The discriminator is `${ordinal}:${rowId}` where `ordinal` is the loop index
 * (digits-only) and `rowId` is the RDS identifier (or `noid` when the missing
 * field IS the identifier). The leading `ordinal` keeps two id-less rows in the
 * same region distinct. A `:` joins the base phase to the discriminator — it
 * does not appear in the closed-set base phases, so the discriminated value
 * stays unambiguous and human-readable (`malformed_db_instance:0:orders-db`).
 *
 * @param basePhase The malformed phase name (closed-set constant).
 * @param ordinal The row's loop index.
 * @param rowId The row's RDS identifier, or `"noid"` when absent.
 */
export function discriminatedPhase(
  basePhase: string,
  ordinal: number,
  rowId: string,
): string {
  return `${basePhase}:${ordinal}:${rowId}`;
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

// ---------------------------------------------------------------------------
// Raw-response validators (exported for unit-test access)
//
// The companion coverage report (aws-rds-reservation-coverage) hand-mirrors the
// public InstanceRecord / ReservedRecord schemas and treats every field as real
// AWS data: an empty `dbInstanceClass` routes to the "unparseable" carve-out, an
// empty `engine`/`productDescription` is coerced to "unknown", a reserved row
// whose `state !== "active"` is silently dropped from coverage, and a
// `dbInstanceCount` of 0 contributes zero reserved capacity. Writing placeholder
// defaults for missing AWS fields therefore launders malformed / API-shifted
// responses into apparently-valid resources and understates coverage before
// publish. These validators reject the raw AWS shape BEFORE a record is built so
// the sweep can emit a scan_error instead (see runSweep). The public record
// schemas are intentionally left unchanged.
// ---------------------------------------------------------------------------

/** Outcome of validating a raw AWS row: the typed input, or the offending fields. */
export type ValidationResult<T> =
  | { ok: true; value: T }
  | { ok: false; missing: string[] };

/**
 * Validate the coverage-critical fields of a raw {@link AwsDBInstance} before a
 * record is built. Returns the same object narrowed when every required field is
 * present and non-empty, or the list of missing/invalid field names otherwise.
 *
 * Required (each is real data the coverage report depends on):
 *   - `DBInstanceIdentifier` — storage-key component and the row's identity.
 *   - `DBInstanceClass` — an empty class routes coverage to "unparseable".
 *   - `Engine` — an empty engine is coerced to "unknown", hiding the real fleet.
 *   - `DBInstanceStatus` — surfaced as `status`; "" misrepresents lifecycle state.
 *
 * Intentionally optional (may stay `""`/`false` when AWS omits them — they are
 * not coverage-critical, so a default does not launder a malformed response):
 *   - `EngineVersion`, `LicenseModel`, `StorageType` — descriptive metadata; AWS
 *     legitimately omits `LicenseModel` for Aurora / RDS Custom.
 *   - `MultiAZ` — booleans have no "missing" sentinel; absent reads as `false`.
 *   - `DBClusterIdentifier`, `TagList` — only present for cluster members / when
 *     tags exist.
 */
export function validateDBInstance(
  db: AwsDBInstance,
): ValidationResult<AwsDBInstance> {
  const missing: string[] = [];
  if (
    typeof db.DBInstanceIdentifier !== "string" ||
    db.DBInstanceIdentifier.length === 0
  ) {
    missing.push("DBInstanceIdentifier");
  }
  if (
    typeof db.DBInstanceClass !== "string" ||
    db.DBInstanceClass.length === 0
  ) {
    missing.push("DBInstanceClass");
  }
  if (typeof db.Engine !== "string" || db.Engine.length === 0) {
    missing.push("Engine");
  }
  if (
    typeof db.DBInstanceStatus !== "string" ||
    db.DBInstanceStatus.length === 0
  ) {
    missing.push("DBInstanceStatus");
  }
  return missing.length === 0
    ? { ok: true, value: db }
    : { ok: false, missing };
}

/**
 * Validate the coverage-critical fields of a raw {@link AwsReservedDBInstance}
 * before a record is built. Returns the same object narrowed when every required
 * field is present and valid, or the list of missing/invalid field names.
 *
 * Required (each is real data the coverage report depends on):
 *   - `ReservedDBInstanceId` — storage-key component and the row's identity.
 *   - `DBInstanceClass` — empty class routes coverage to "unparseable".
 *   - `ProductDescription` — empty value is coerced to "unknown".
 *   - `DBInstanceCount` — must be present and > 0; a 0 contributes zero reserved
 *     capacity and silently understates coverage.
 *   - `State` — a row whose state is not `active` is dropped from coverage, so a
 *     placeholder `""` makes the reservation vanish rather than count.
 *   - `MultiAZ` — must be present (a boolean): netting size-flex capacity differs
 *     for Multi-AZ reservations, so an assumed `false` would misstate coverage.
 *
 * Intentionally optional metadata (may stay `""`/`0` when AWS omits them):
 *   - `OfferingType` — reporting/grouping label, not used to compute coverage.
 *   - `Duration` — term length is informational; coverage nets active capacity
 *     regardless of remaining term.
 *   - `StartTime` — informational timestamp, not coverage-critical.
 */
export function validateReservedDBInstance(
  r: AwsReservedDBInstance,
): ValidationResult<AwsReservedDBInstance> {
  const missing: string[] = [];
  if (
    typeof r.ReservedDBInstanceId !== "string" ||
    r.ReservedDBInstanceId.length === 0
  ) {
    missing.push("ReservedDBInstanceId");
  }
  if (
    typeof r.DBInstanceClass !== "string" ||
    r.DBInstanceClass.length === 0
  ) {
    missing.push("DBInstanceClass");
  }
  if (
    typeof r.ProductDescription !== "string" ||
    r.ProductDescription.length === 0
  ) {
    missing.push("ProductDescription");
  }
  if (typeof r.DBInstanceCount !== "number" || !(r.DBInstanceCount > 0)) {
    missing.push("DBInstanceCount");
  }
  if (typeof r.State !== "string" || r.State.length === 0) {
    missing.push("State");
  }
  if (typeof r.MultiAZ !== "boolean") {
    missing.push("MultiAZ");
  }
  return missing.length === 0 ? { ok: true, value: r } : { ok: false, missing };
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
 * Drain a `Marker`-paginated RDS describe call to exhaustion. `fetchPage(marker)`
 * issues one `rds.send` for the page starting at `marker` and returns that
 * page's items plus the next marker.
 *
 * Throttling retry lives inside the SDK client (the `SHARED_RETRY` adaptive
 * config every client is constructed with), not here — a single retry
 * mechanism, so a sustained throttle can never compound across two layers.
 * A throttle that survives the client's bounded retries propagates to the
 * caller, where `runSweep` records it as a `scan_error`. No early exit and no
 * page cap: every page matters, and a silent truncation is the exact
 * data-completeness bug this seam exists to prevent.
 *
 * @typeParam T Element type accumulated across pages.
 * @param fetchPage Issues one page request for the given marker.
 * @returns Every item across every page, in page order.
 */
export async function paginate<T>(
  fetchPage: (marker: string | undefined) => Promise<Page<T>>,
): Promise<T[]> {
  const out: T[] = [];
  let marker: string | undefined;
  do {
    const page = await fetchPage(marker);
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
 * Fetch the current caller's AWS account id. Throttling retry lives inside the
 * STS client (`SHARED_RETRY`); a throttle that survives the client's bounded
 * retries propagates so `runSweep` records the existing credentials-phase
 * `scan_error`.
 *
 * @param send Issues one `sts:GetCallerIdentity` request.
 * @returns The reported account id, or `""` if AWS omitted it.
 */
export async function getCallerAccountId(
  send: () => Promise<CallerIdentity>,
): Promise<string> {
  const resp = await send();
  return resp.Account ?? "";
}

/**
 * The slice of an AWS SDK v3 client this extension drives: `send` to issue a
 * command, and the synchronous `destroy` to release the underlying socket /
 * handle pool. Both `RDSClient` and `STSClient` satisfy this structurally, so
 * tests can inject a fake that records `send` calls and `destroy` invocations.
 *
 * @typeParam C Command type accepted by `send`.
 * @typeParam R Response type resolved by `send`.
 */
export interface SdkClient<C, R> {
  /** Issue one command. */
  send(command: C): Promise<R>;
  /** Release the client's connection resources. Synchronous (returns void). */
  destroy(): void;
}

/**
 * Constructs the per-region RDS client driving the describe paths. The command
 * accepted by `send` is opaque (`unknown`) at this seam boundary so the
 * exported type stays free of private AWS SDK command classes; the concrete
 * `DescribeDBInstancesCommand` / `DescribeReservedDBInstancesCommand` instances
 * are constructed internally by the default factory in `sdkApi`. `SdkClient.send`
 * is a method, so its parameter is checked bivariantly — both the real
 * `RDSClient` and narrow test fakes remain assignable.
 */
export type RdsClientFactory = (
  region: string,
) => SdkClient<
  unknown,
  {
    DBInstances?: AwsDBInstance[];
    ReservedDBInstances?: AwsReservedDBInstance[];
    Marker?: string;
  }
>;

/**
 * Constructs the bootstrap STS client driving the account-id lookup. The
 * command accepted by `send` is opaque (`unknown`) at this seam boundary so the
 * exported type stays free of the private `GetCallerIdentityCommand`; that
 * command is constructed internally by the default factory in `sdkApi`.
 */
export type StsClientFactory = () => SdkClient<unknown, CallerIdentity>;

/**
 * Call `client.destroy()` if present, swallowing and logging any failure at
 * `debug`. SDK `destroy()` is synchronous and best-effort cleanup: a failure
 * here must never mask the operation's original outcome — neither turning a
 * successful sweep into a failure nor replacing a real thrown error. Lives
 * outside the operation's try/finally chain so it is the last thing to run.
 */
export function safeDestroy(
  client: { destroy?: () => void } | undefined,
  // deno-lint-ignore no-explicit-any
  logger?: any,
): void {
  try {
    client?.destroy?.();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger?.debug?.(
      "Ignoring AWS SDK client destroy() failure during cleanup: {message}",
      { message },
    );
  }
}

function sdkApi(
  credentials: CredentialProvider | undefined,
  bootstrapRegion: string,
  // deno-lint-ignore no-explicit-any
  logger: any,
  rdsClientFactory: RdsClientFactory = (region) =>
    new RDSClient({ region, credentials, ...SHARED_RETRY }),
  stsClientFactory: StsClientFactory = () =>
    new STSClient({ region: bootstrapRegion, credentials, ...SHARED_RETRY }),
): AwsApi {
  return {
    getAccountId: async () => {
      const sts = stsClientFactory();
      try {
        return await getCallerAccountId(
          () => sts.send(new GetCallerIdentityCommand({})),
        );
      } finally {
        safeDestroy(sts, logger);
      }
    },
    describeDBInstances: async (region) => {
      const rds = rdsClientFactory(region);
      try {
        return await paginate<AwsDBInstance>(
          async (marker) => {
            const resp = await rds.send(
              new DescribeDBInstancesCommand({
                Marker: marker,
                MaxRecords: 100,
              }),
            );
            return { items: resp.DBInstances ?? [], marker: resp.Marker };
          },
        );
      } finally {
        safeDestroy(rds, logger);
      }
    },
    describeReservedDBInstances: async (region) => {
      const rds = rdsClientFactory(region);
      try {
        return await paginate<AwsReservedDBInstance>(
          async (marker) => {
            const resp = await rds.send(
              new DescribeReservedDBInstancesCommand({
                Marker: marker,
                MaxRecords: 100,
              }),
            );
            return {
              items: resp.ReservedDBInstances ?? [],
              marker: resp.Marker,
            };
          },
        );
      } finally {
        safeDestroy(rds, logger);
      }
    },
  };
}

/**
 * Construct the production SDK-backed {@link AwsApi} with optional injected
 * client factories. The default factories build real `RDSClient` / `STSClient`
 * instances, so production behavior is identical to calling {@link sdkApi}
 * directly. Tests pass fakes to assert each client's `destroy()` runs exactly
 * once on success and thrown-error paths without touching the public
 * {@link AwsApi} / {@link ApiFactory} surface.
 *
 * @param credentials Credential provider, or `undefined` for the ambient chain.
 * @param bootstrapRegion Region for the STS bootstrap call.
 * @param logger Runtime logger.
 * @param rdsClientFactory Builds the per-region RDS client. Defaults to a real `RDSClient`.
 * @param stsClientFactory Builds the bootstrap STS client. Defaults to a real `STSClient`.
 * @returns An {@link AwsApi} facade that destroys each client after use.
 */
export function sdkApiWithFactories(
  credentials: CredentialProvider | undefined,
  bootstrapRegion: string,
  // deno-lint-ignore no-explicit-any
  logger: any,
  rdsClientFactory?: RdsClientFactory,
  stsClientFactory?: StsClientFactory,
): AwsApi {
  return sdkApi(
    credentials,
    bootstrapRegion,
    logger,
    rdsClientFactory,
    stsClientFactory,
  );
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
   * Shared AWS SSO session name to pre-flight once before the per-profile loop;
   * `""` (default) skips the pre-flight entirely.
   */
  ssoSession?: string;
  /** SSO region for the pre-flight token resolve (derived from the regions). */
  ssoRegion?: string;
  /**
   * SSO-token resolver injected into the pre-flight. Defaults (when omitted) to
   * the lib's on-disk cache reader; tests pass a fake to drive the
   * expired/ok/network branches without touching disk or the SDK.
   */
  resolveSsoToken?: (session: string, region: string) => Promise<unknown>;
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
 * reservation, and `scan_error` rows for failures. The once-per-(profile,
 * region) phases (credentials, describe_db_instances, …) emit at most one
 * `scan_error` each; the per-row malformed phases (malformed_db_instance,
 * malformed_reserved_db_instance) emit one `scan_error` PER malformed row, each
 * with a unique key (see scanErrorKey) so co-located malformed rows are never
 * collapsed into one stored error.
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
  const ssoSession = deps.ssoSession ?? "";
  const ssoRegion = deps.ssoRegion ?? "";
  const handles: unknown[] = [];
  let instanceCount = 0;
  let reservedCount = 0;
  let errorCount = 0;
  const scannedAt = now().toISOString();

  // Per-row uniqueness is folded into the row's `phase` (see
  // `discriminatedPhase`) BEFORE writeError, so the canonical key built from
  // (profile, region, service, phase) is already distinct per malformed row and
  // writeError needs no separate discriminator argument.
  const writeError = async (e: ScanError): Promise<void> => {
    errorCount++;
    handles.push(
      await context.writeResource(
        "scan_error",
        scanErrorKey(e.profile, e.region, e.service, e.phase),
        e,
      ),
    );
  };

  // Pre-flight the shared SSO session once, before the per-profile loop. The
  // shared gate owns the policy: only `expired` aborts, a `network` blip
  // proceeds, and no configured session skips the check.
  const gate = await preflightSsoGate({
    ssoSession,
    ssoRegion,
    resolveSsoToken: deps.resolveSsoToken,
    logger: context.logger,
  });
  if (gate.abort) {
    await writeError({
      profile: "",
      accountId: "",
      region: "",
      ...gate.error,
      scannedAt,
    });
    context.logger.info(
      "aws-rds-reservations sweep complete: {instances} instance(s), " +
        "{reserved} reservation(s), {errors} error(s)",
      {
        instances: instanceCount,
        reserved: reservedCount,
        errors: errorCount,
      },
    );
    return { dataHandles: handles, instanceCount, reservedCount, errorCount };
  }

  // Regions are required: RDS describe calls are region-scoped and there is no
  // enabled-region discovery here. An empty list would otherwise resolve each
  // account, never enter the per-region loop, and write zero rows — a silent
  // "healthy empty" sweep the companion report cannot distinguish from a real
  // zero-fleet result. Surface the misconfiguration as one scan_error and
  // return before any AWS call (mirrors the profile_suffix_check refusal).
  if (regions.length === 0) {
    await writeError({
      profile: "",
      accountId: "",
      region: "",
      // No AWS service is involved — the sweep refuses before any call.
      service: "",
      phase: "no_regions",
      kind: "other",
      message:
        "No regions configured: 'regions' is empty, so no RDS instances or " +
        "reservations were swept. Set the 'regions' global argument to your " +
        "approved regions.",
      scannedAt,
    });
    return { dataHandles: handles, instanceCount, reservedCount, errorCount };
  }

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
        // No AWS service is involved — the profile is refused before any call.
        service: "",
        phase: "profile_suffix_check",
        kind: "other",
        message:
          `Profile '${
            profileLabel || "<ambient>"
          }' does not end with required suffix ` +
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
        // sts:GetCallerIdentity is what failed (also the credential probe).
        service: "sts",
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
        for (const [index, db] of dbInstances.entries()) {
          // Reject malformed rows BEFORE building a record: a placeholder
          // default for a coverage-critical field would launder a malformed
          // AWS response into an apparently-valid resource.
          const valid = validateDBInstance(db);
          if (!valid.ok) {
            const hasId = typeof db.DBInstanceIdentifier === "string" &&
              db.DBInstanceIdentifier.length > 0;
            const label = hasId ? db.DBInstanceIdentifier! : "<unknown>";
            context.logger.warn(
              "Malformed DB instance {id} in {region}; missing {fields}",
              { id: label, region, fields: valid.missing.join(", ") },
            );
            // Per-row uniqueness: the row id discriminates rows, but when the
            // missing field IS the identifier there is no id, so the loop
            // ordinal is a stable fallback that keeps two id-less rows distinct.
            // The discriminator is folded into the `phase` (see
            // `discriminatedPhase`), which is used both for the canonical key
            // and as the stored `phase` so the operator sees which row failed.
            await writeError({
              profile: profileLabel,
              accountId,
              region,
              service: "rds",
              phase: discriminatedPhase(
                "malformed_db_instance",
                index,
                hasId ? db.DBInstanceIdentifier! : "noid",
              ),
              kind: "other",
              message: `Malformed DB instance in account ${accountId} region ` +
                `${region} (id=${label}): missing or invalid required ` +
                `field(s): ${valid.missing.join(", ")}. Row not written as a ` +
                `resource to avoid laundering an empty/placeholder instance.`,
              scannedAt,
            });
            continue;
          }
          const id = db.DBInstanceIdentifier ?? "";
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
          service: "rds",
          phase: "describe_db_instances",
          kind,
          message,
          scannedAt,
        });
      }

      // Reserved DB instances.
      try {
        const reserved = await target.api.describeReservedDBInstances(region);
        for (const [index, r] of reserved.entries()) {
          // Reject malformed rows BEFORE building a record: a placeholder
          // state:"" / dbInstanceCount:0 would make the reservation vanish from
          // coverage or contribute zero capacity, silently understating it.
          const valid = validateReservedDBInstance(r);
          if (!valid.ok) {
            const hasId = typeof r.ReservedDBInstanceId === "string" &&
              r.ReservedDBInstanceId.length > 0;
            const label = hasId ? r.ReservedDBInstanceId! : "<unknown>";
            context.logger.warn(
              "Malformed reserved DB instance {id} in {region}; missing {fields}",
              { id: label, region, fields: valid.missing.join(", ") },
            );
            // Per-row uniqueness: see the provisioned-instance phase above. The
            // id discriminates rows; the loop ordinal is the id-less fallback so
            // two id-less reserved rows in the same region stay distinct. The
            // discriminator is folded into the `phase` (see `discriminatedPhase`).
            await writeError({
              profile: profileLabel,
              accountId,
              region,
              service: "rds",
              phase: discriminatedPhase(
                "malformed_reserved_db_instance",
                index,
                hasId ? r.ReservedDBInstanceId! : "noid",
              ),
              kind: "other",
              message:
                `Malformed reserved DB instance in account ${accountId} ` +
                `region ${region} (id=${label}): missing or invalid required ` +
                `field(s): ${valid.missing.join(", ")}. Row not written as a ` +
                `resource to avoid understating reservation coverage.`,
              scannedAt,
            });
            continue;
          }
          const rid = r.ReservedDBInstanceId ?? "";
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
          service: "rds",
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
 * `instance` row per DB instance, one `reserved` row per reservation, and
 * `scan_error` rows for failures — at most one per (profile, region) phase that
 * could not be assessed, plus one per malformed row for the per-row malformed
 * phases.
 */
export const model = {
  type: "@jentz/aws-rds-reservations",
  version: "2026.07.03.0",
  globalArguments: GlobalArgsSchema,
  // swamp model upgrades transform stored globalArguments, not historical
  // resource artifacts, so there is nothing to migrate here. The no-op chain
  // mirrors the sibling @jentz/aws-rds-inventory convention so any future
  // schema-changing upgrade chains cleanly from this baseline. New resource
  // fields such as instance.licenseModel — and the new scan_error `service`
  // tag, which defaults to "" on reads so stored rows still parse — are
  // populated by re-sweeping, never by an upgrade.
  upgrades: [
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
      description: "Version bump, no globalArguments schema changes",
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
      toVersion: "2026.06.26.1",
      description:
        "Adopt shared scan-error/credential libs: add `service` tag to " +
        "scan_error, `network` classification, optional ssoSession pre-flight, " +
        "and adaptive retry. `service` reads default '' so stored rows still " +
        "parse; no row migration needed.",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.03.0",
      description:
        "Centralize the SSO pre-flight policy into the shared gate and " +
        "retire the app-level retry layer (the SDK adaptive retry is the " +
        "single mechanism); no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
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
          // Pre-flight the shared SSO session (if configured) once, against the
          // same bootstrap region the account-level calls target. The default
          // (disk-cache) resolver is used in production; tests inject a fake.
          ssoSession: g.ssoSession,
          ssoRegion: bootstrapRegion,
          context,
        });
      },
    },
  },
};
