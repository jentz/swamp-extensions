/**
 * `@jentz/aws-vpc-inventory` — fleet-wide VPC inventory across
 * `profiles × regions`.
 *
 * The single `scan` method fans out over every configured profile and region
 * in one execution (one model lock, all output in one pass — see repo rule 6).
 * For each (account, region) it lists every VPC and emits one `vpc` resource
 * per VPC carrying:
 *
 *   - the AWS account id (from sts:GetCallerIdentity) and a derived
 *     "account name" (the profile with `-readonly` stripped — pragmatic
 *     because STS does not expose account names),
 *   - the VPC id, `Name` tag, default-VPC flag,
 *   - all IPv4 CIDR blocks (primary + every associated CIDR in
 *     `associated` state — secondary CIDRs in `failed`/`disassociating`
 *     state are skipped),
 *   - the owning account id and an `isSharedIn` flag — VPCs shared into
 *     this account via RAM are kept (so the operator sees them once where
 *     consumed) and flagged so they can be reconciled against the owning
 *     account's row,
 *   - and the full VPC tag map.
 *
 * Per-(profile, region) failures become `scan_error` rows instead of
 * aborting the sweep: an expired SSO token, an SCP-denied region, or a
 * malformed VPC response is reported, never silenced.
 *
 * Read-only: only `Describe*` and `sts:GetCallerIdentity` are called. Pair
 * with the companion report extension `@jentz/aws-vpc-inventory-report` for an
 * operator-friendly markdown + JSON summary.
 *
 * @module
 */

import { z } from "npm:zod@4.4.3";
import {
  DescribeRegionsCommand,
  DescribeVpcsCommand,
  EC2Client,
} from "npm:@aws-sdk/client-ec2@3.1073.0";
import {
  GetCallerIdentityCommand,
  STSClient,
} from "npm:@aws-sdk/client-sts@3.1073.0";
import { fromIni } from "npm:@aws-sdk/credential-providers@3.1073.0";

/** Credential provider as returned by `fromIni`; `undefined` means the ambient chain. */
type CredentialProvider = ReturnType<typeof fromIni>;

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
    "Regions to scan per account. Empty (default) discovers each account's " +
      "enabled regions via ec2:DescribeRegions.",
  ),
  requiredProfileSuffix: z.string().default("").describe(
    "If set, every profile (and the ambient AWS_PROFILE) must end with this " +
      "suffix or the profile is refused before any AWS call. Set to " +
      "'-readonly' to enforce read-only profiles for the inventory. Default " +
      "'' disables the check.",
  ),
});

const TagsSchema = z.record(z.string(), z.string()).default({});

const VpcRecordSchema = z.object({
  accountId: z.string(),
  accountName: z.string(),
  profile: z.string(),
  region: z.string(),
  vpcId: z.string(),
  vpcName: z.string(),
  vpcIsDefault: z.boolean(),
  ownerAccountId: z.string(),
  isSharedIn: z.boolean(),
  cidrBlocks: z.array(z.string()),
  vpcTags: TagsSchema,
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

/** One VPC observed in one (account, region). */
export interface VpcRecord {
  /** 12-digit AWS account id of the scanning credentials (from sts:GetCallerIdentity). */
  accountId: string;
  /**
   * Friendly account label, derived from the profile by stripping the
   * configured suffix (default `-readonly`). `""` when ambient (no profile)
   * or when the profile is already the bare account name.
   */
  accountName: string;
  /** Profile that produced this row; `""` for the ambient credential chain. */
  profile: string;
  /** AWS region. */
  region: string;
  /** VPC id. */
  vpcId: string;
  /** VPC `Name` tag, or `""`. */
  vpcName: string;
  /** Whether this is the AWS-created default VPC. */
  vpcIsDefault: boolean;
  /** Account that owns the VPC; differs from `accountId` for VPCs shared via RAM. */
  ownerAccountId: string;
  /** True when the VPC is shared into this account (ownerAccountId !== accountId). */
  isSharedIn: boolean;
  /**
   * All IPv4 CIDR blocks for the VPC — the primary `CidrBlock` first,
   * followed by every `CidrBlockAssociationSet` entry currently in
   * `associated` state, deduplicated and in describe-order.
   */
  cidrBlocks: string[];
  /** All VPC tags, flattened. */
  vpcTags: Record<string, string>;
  /** ISO 8601 scan timestamp. */
  scannedAt: string;
}

/** A (profile, region) pair that could not be assessed. */
export interface ScanError {
  /** Profile being swept; `""` for ambient. */
  profile: string;
  /** Account id if known by the time of failure; `""` otherwise. */
  accountId: string;
  /** Region being scanned; `""` for account-level failures. */
  region: string;
  /** Stage that failed: `credentials`, `describe_regions`, `describe_vpcs`, … */
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

/** AWS-style tag tuple as returned by EC2 describe calls. */
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
 * (ambient), or when it does not end with the suffix, the profile is
 * returned unchanged. An empty `suffix` is a no-op.
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
  // Credential / SSO-token expiry — operator action is `aws sso login`. Match
  // precise signals only: a bare "sso" substring misfires because an SSO role
  // ARN (`...AWSReservedSSO...`) appears verbatim in unrelated AccessDenied
  // messages. Authorization denials are checked first for the same reason.
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
  // Access-denied wins: an AccessDenied/SCP message can embed an SSO role ARN,
  // and the operator action differs (fix permissions, not `aws sso login`).
  if (isAccessDenied) return { kind: "access_denied", message };
  if (isAuthExpired) return { kind: "auth_expired", message };
  return { kind: "other", message };
}

/**
 * Strict bootstrap-region resolver for the account-level calls
 * (sts:GetCallerIdentity, ec2:DescribeRegions) that must target *some*
 * region before per-region scanning begins. Order: first configured region →
 * `AWS_REGION` → `AWS_DEFAULT_REGION` → `us-east-1` (a global-ish default
 * that is enabled on every account, used only for these bootstrap calls).
 */
export function resolveBootstrapRegion(
  regions: string[],
  env: (name: string) => string | undefined = (name) => Deno.env.get(name),
): string {
  const candidates = [
    regions[0],
    env("AWS_REGION"),
    env("AWS_DEFAULT_REGION"),
  ];
  for (const c of candidates) {
    if (typeof c === "string" && c.trim().length > 0) return c.trim();
  }
  return "us-east-1";
}

/** Build a stable storage key for a VPC row (unique across account/region). */
export function vpcKey(
  accountId: string,
  region: string,
  vpcId: string,
): string {
  return `vpc-${accountId}-${region}-${vpcId}`;
}

/** Build a stable storage key for a scan error. */
export function scanErrorKey(
  profileLabel: string,
  region: string,
  phase: string,
): string {
  return `error-${profileLabel || "ambient"}-${region || "account"}-${phase}`;
}

// ---------------------------------------------------------------------------
// AWS facade — minimal surface so the smoke test can replay without the SDK
// ---------------------------------------------------------------------------

/** Secondary CIDR association entry on a VPC. */
export interface AwsCidrBlockAssociation {
  /** The associated IPv4 CIDR. */
  CidrBlock?: string;
  /** State of the association; only `associated` is counted. */
  CidrBlockState?: { State?: string };
}

/** Minimal VPC shape this extension depends on. */
export interface AwsVpc {
  /** VPC id. */
  VpcId?: string;
  /** Whether this is the AWS-created default VPC. */
  IsDefault?: boolean;
  /** Owning account id; differs from caller for VPCs shared via RAM. */
  OwnerId?: string;
  /** Primary IPv4 CIDR block. */
  CidrBlock?: string;
  /** Associated IPv4 CIDR blocks (primary + secondary, each with its own state). */
  CidrBlockAssociationSet?: AwsCidrBlockAssociation[];
  /** VPC tags. */
  Tags?: AwsTag[];
}

/**
 * Facade over the bits of EC2/STS this extension uses, for one account's
 * credentials. Lets the smoke test substitute an in-memory replay.
 */
export interface AwsApi {
  /** Resolve the account id for the active credentials. */
  getAccountId(): Promise<string>;
  /** Enabled region names for the account. */
  describeEnabledRegions(): Promise<string[]>;
  /** Every VPC in `region`. */
  describeVpcs(region: string): Promise<AwsVpc[]>;
}

// ---------------------------------------------------------------------------
// SDK-backed facade
// ---------------------------------------------------------------------------

const CLIENT_RETRY = { maxAttempts: 5 } as const;

function sdkApi(
  credentials: CredentialProvider | undefined,
  bootstrapRegion: string,
): AwsApi {
  const ec2For = (region: string) =>
    new EC2Client({ region, credentials, ...CLIENT_RETRY });

  return {
    getAccountId: async () => {
      const sts = new STSClient({
        region: bootstrapRegion,
        credentials,
        ...CLIENT_RETRY,
      });
      const resp = await sts.send(new GetCallerIdentityCommand({}));
      return resp.Account ?? "";
    },
    describeEnabledRegions: async () => {
      const ec2 = ec2For(bootstrapRegion);
      const resp = await ec2.send(
        new DescribeRegionsCommand({ AllRegions: false }),
      );
      return (resp.Regions ?? [])
        .map((r) => r.RegionName)
        .filter((n): n is string => typeof n === "string" && n.length > 0);
    },
    describeVpcs: async (region) => {
      const ec2 = ec2For(region);
      const out: AwsVpc[] = [];
      let token: string | undefined;
      do {
        const resp = await ec2.send(
          new DescribeVpcsCommand({ NextToken: token, MaxResults: 100 }),
        );
        out.push(...(resp.Vpcs ?? []));
        token = resp.NextToken;
      } while (token);
      return out;
    },
  };
}

// ---------------------------------------------------------------------------
// CIDR extraction
// ---------------------------------------------------------------------------

/**
 * Collect every IPv4 CIDR for a VPC: the primary `CidrBlock` first, then
 * every `CidrBlockAssociationSet` entry whose state is exactly `associated`.
 * Duplicates are removed (the primary CIDR is usually echoed in the
 * association set). CIDRs with no/empty `CidrBlock` are dropped.
 */
export function collectCidrBlocks(vpc: AwsVpc): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const add = (c: string | undefined) => {
    if (typeof c !== "string") return;
    const v = c.trim();
    if (v.length === 0 || seen.has(v)) return;
    seen.add(v);
    out.push(v);
  };
  add(vpc.CidrBlock);
  for (const a of vpc.CidrBlockAssociationSet ?? []) {
    if (a.CidrBlockState?.State !== "associated") continue;
    add(a.CidrBlock);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Core scan logic — parameterized on its AWS facade and runtime context
// ---------------------------------------------------------------------------

/** One account's scan target: a label and the API facade. */
export interface ScanTarget {
  /** Profile name, or `""` for the ambient credential chain. */
  profile: string;
  /** API facade bound to this account's credentials. */
  api: AwsApi;
}

/** Dependencies for {@link runScan}. */
export interface ScanDeps {
  /** Ordered scan targets, one per account. */
  targets: ScanTarget[];
  /** Configured regions; empty means "discover per account". */
  configuredRegions: string[];
  /** Required profile suffix; `""` disables the check. */
  requiredProfileSuffix: string;
  /**
   * The AWS_PROFILE the ambient credential chain would use, used only for the
   * suffix gate on the ambient target; `""` when unknown.
   */
  ambientProfile: string;
  /**
   * Swamp method-execution context. Typed `any` because the host injects the
   * real type at runtime.
   */
  // deno-lint-ignore no-explicit-any
  context: any;
}

/** Result of {@link runScan}. */
export interface ScanResult {
  /** Data handles produced during the run, in write order. */
  dataHandles: unknown[];
  /** Count of VPC rows written. */
  vpcCount: number;
  /** Count of scan errors written. */
  errorCount: number;
}

/**
 * Core `scan` logic. Iterates targets (accounts) × regions, writing one
 * `vpc` resource per VPC observed and one `scan_error` per (profile, region)
 * that fails. Per-target and per-region failures are caught and recorded —
 * a single expired SSO token or denied call never aborts the wider sweep.
 *
 * @param deps Targets, configuration, and the runtime context.
 * @returns Data handles plus VPC / error counts.
 */
export async function runScan(deps: ScanDeps): Promise<ScanResult> {
  const { targets, configuredRegions, requiredProfileSuffix, context } = deps;
  const ambientProfile = deps.ambientProfile ?? "";
  const handles: unknown[] = [];
  let vpcCount = 0;
  let errorCount = 0;
  const scannedAt = new Date().toISOString();

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
    const accountName = accountNameFromProfile(
      profileLabel,
      requiredProfileSuffix,
    );

    // The ambient target has no profile label; gate it on the AWS_PROFILE the
    // ambient chain would use instead, so a suffix policy still applies (and
    // still fails closed when AWS_PROFILE is unset).
    const labelForSuffix = profileLabel.length > 0
      ? profileLabel
      : ambientProfile;
    if (
      requiredProfileSuffix.length > 0 &&
      !labelForSuffix.endsWith(requiredProfileSuffix)
    ) {
      const shownLabel = labelForSuffix || "<ambient:no AWS_PROFILE>";
      context.logger.warn(
        "Skipping profile {profile}: does not end with required suffix {suffix}",
        { profile: shownLabel, suffix: requiredProfileSuffix },
      );
      await writeError({
        profile: profileLabel,
        accountId: "",
        region: "",
        phase: "profile_suffix_check",
        kind: "other",
        message: `Profile '${shownLabel}' does not end with required suffix ` +
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

    // Determine the regions to scan for this account.
    let regions = configuredRegions;
    if (regions.length === 0) {
      try {
        regions = await target.api.describeEnabledRegions();
      } catch (err) {
        const { kind, message } = classifyError(err);
        await writeError({
          profile: profileLabel,
          accountId,
          region: "",
          phase: "describe_regions",
          kind,
          message,
          scannedAt,
        });
        continue;
      }
    }

    context.logger.info(
      "Inventorying account {account} (profile={profile}) across {count} region(s)",
      {
        account: accountId,
        profile: profileLabel || "<ambient>",
        count: regions.length,
      },
    );

    for (const region of regions) {
      try {
        const vpcs = await target.api.describeVpcs(region);
        for (const v of vpcs) {
          const vpcId = v.VpcId ?? "";
          if (vpcId === "") {
            context.logger.warn(
              "VPC with no VpcId in {region}; skipped",
              { region },
            );
            continue;
          }
          const vpcTags = tagsFromAws(v.Tags);
          const ownerAccountId = (v.OwnerId ?? "").trim();
          const row: VpcRecord = {
            accountId,
            accountName,
            profile: profileLabel,
            region,
            vpcId,
            vpcName: vpcTags["Name"] ?? "",
            vpcIsDefault: v.IsDefault ?? false,
            ownerAccountId,
            isSharedIn: ownerAccountId.length > 0 &&
              ownerAccountId !== accountId,
            cidrBlocks: collectCidrBlocks(v),
            vpcTags,
            scannedAt,
          };
          vpcCount++;
          handles.push(
            await context.writeResource(
              "vpc",
              vpcKey(accountId, region, vpcId),
              row,
            ),
          );
        }
      } catch (err) {
        const { kind, message } = classifyError(err);
        context.logger.warn(
          "VPC inventory failed in {region} for account {account}: {message}",
          { region, account: accountId, message },
        );
        await writeError({
          profile: profileLabel,
          accountId,
          region,
          phase: "describe_vpcs",
          kind,
          message,
          scannedAt,
        });
      }
    }
  }

  context.logger.info(
    "vpc-inventory complete: {vpcs} VPC(s), {errors} error(s)",
    { vpcs: vpcCount, errors: errorCount },
  );

  return { dataHandles: handles, vpcCount, errorCount };
}

// ---------------------------------------------------------------------------
// Model export
// ---------------------------------------------------------------------------

/**
 * The `@jentz/aws-vpc-inventory` model.
 *
 * Single method `scan` inventories every VPC across the configured
 * `profiles × regions`, emitting one `vpc` row per VPC and one
 * `scan_error` per (profile, region) that could not be assessed.
 */
export const model = {
  type: "@jentz/aws-vpc-inventory",
  version: "2026.06.22.0",
  globalArguments: GlobalArgsSchema,
  // First published release. The single no-op upgrade advances the stored
  // typeVersion on existing instances so any future schema-changing upgrade
  // chains cleanly from here. swamp registry/host loading also rejects a model
  // whose final upgrades entry toVersion drifts from model.version, so this
  // entry must stay equal to version above.
  upgrades: [
    {
      toVersion: "2026.06.13.0",
      description: "Initial publish",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.22.0",
      description: "Dependency refresh, no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    vpc: {
      description:
        "One VPC observed in one (account, region), with all IPv4 CIDR " +
        "blocks, default-VPC flag, owner account id, and tags.",
      schema: VpcRecordSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    scan_error: {
      description:
        "A (profile, region) pair that could not be assessed — expired SSO " +
        "token, denied describe call, etc. Surfaces coverage gaps in the " +
        "companion @jentz/aws-vpc-inventory-report report.",
      schema: ScanErrorSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    scan: {
      description:
        "Inventory every VPC across profiles × regions, capturing account " +
        "id, account name (derived from profile), region, VPC id, VPC " +
        "name, default-VPC flag, owner account, shared-in flag, and all " +
        "IPv4 CIDR blocks.",
      arguments: z.object({}),
      execute: (
        _args: Record<string, never>,
        // deno-lint-ignore no-explicit-any
        context: any,
      ): Promise<ScanResult> => {
        const g = GlobalArgsSchema.parse(context.globalArgs);
        const bootstrapRegion = resolveBootstrapRegion(g.regions);

        const isAmbient = g.profiles.length === 0;
        // For an ambient run the suffix gate has no profile label to check, so
        // it falls back to the AWS_PROFILE the ambient chain would use.
        const ambientProfile = isAmbient
          ? (Deno.env.get("AWS_PROFILE") ?? "")
          : "";

        const targets: ScanTarget[] = isAmbient
          ? [{ profile: "", api: sdkApi(undefined, bootstrapRegion) }]
          : g.profiles.map((profile) => ({
            profile,
            api: sdkApi(fromIni({ profile }), bootstrapRegion),
          }));

        return runScan({
          targets,
          configuredRegions: g.regions,
          requiredProfileSuffix: g.requiredProfileSuffix,
          ambientProfile,
          context,
        });
      },
    },
  },
};
