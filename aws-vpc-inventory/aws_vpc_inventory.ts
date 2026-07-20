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
import {
  classifyError,
  type ScanError,
  scanErrorKey,
  ScanErrorSchema,
} from "./_lib/scan_error.ts";
import {
  type CredentialProvider,
  preflightSsoGate,
  resolveBootstrapRegion,
  SHARED_RETRY,
} from "./_lib/aws_credentials.ts";

export { classifyError, scanErrorKey };
export type { ScanError };

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
  ssoSession: z.string().default("").describe(
    "Name of the shared AWS SSO session backing the swept profiles (the " +
      "`[sso-session <name>]` block in ~/.aws/config). When set, the scan " +
      "pre-flights this session's cached token once before the per-profile " +
      "loop: a genuinely expired token short-circuits the whole sweep with a " +
      "single 'run aws sso login' error rather than failing every profile. " +
      "Empty (default) skips the pre-flight entirely.",
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

// ---------------------------------------------------------------------------
// Public resource shapes (explicit interfaces — deno doc --lint friendly)
// ---------------------------------------------------------------------------

/** One VPC observed in one (account, region). */
export interface VpcRecord {
  /** 12-digit AWS account id of the scanning credentials (from sts:GetCallerIdentity). */
  accountId: string;
  /**
   * Friendly account label, derived from the profile by stripping the
   * configured `requiredProfileSuffix` (for example `-readonly`). The suffix
   * defaults to `""`, which strips nothing and leaves the profile unchanged.
   * `""` only when ambient (no profile); a profile that does not end with the
   * configured suffix is returned unchanged (not `""`).
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

/** Build a stable storage key for a VPC row (unique across account/region). */
export function vpcKey(
  accountId: string,
  region: string,
  vpcId: string,
): string {
  return `vpc-${accountId}-${region}-${vpcId}`;
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

function sdkApi(
  credentials: CredentialProvider | undefined,
  bootstrapRegion: string,
): AwsApi {
  const ec2For = (region: string) =>
    new EC2Client({ region, credentials, ...SHARED_RETRY });

  return {
    getAccountId: async () => {
      const sts = new STSClient({
        region: bootstrapRegion,
        credentials,
        ...SHARED_RETRY,
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
  const ssoSession = deps.ssoSession ?? "";
  const ssoRegion = deps.ssoRegion ?? "";
  const handles: unknown[] = [];
  let vpcCount = 0;
  let errorCount = 0;
  const scannedAt = new Date().toISOString();

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
      "vpc-inventory complete: {vpcs} VPC(s), {errors} error(s)",
      { vpcs: vpcCount, errors: errorCount },
    );
    return { dataHandles: handles, vpcCount, errorCount };
  }

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
        // No AWS service is involved — the profile is refused before any call.
        service: "",
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
        // sts:GetCallerIdentity is what failed (also the credential probe).
        service: "sts",
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
          // ec2:DescribeRegions is what failed.
          service: "ec2",
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
          // ec2:DescribeVpcs is what failed.
          service: "ec2",
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
  version: "2026.07.20.1",
  globalArguments: GlobalArgsSchema,
  // The upgrade chain's tail toVersion must equal model.version — swamp
  // registry/host loading rejects a model where the two drift. The no-op
  // upgrades advance the stored typeVersion on existing instances so the chain
  // stays clean: the new `service` field on `scan_error` defaults to `""` on
  // reads, so pre-existing stored rows still parse without a data migration.
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
        "Centralize the SSO pre-flight policy into the shared gate; no " +
        "globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.19.0",
      description:
        "Docs-only: README documents the `service` scan_error field, the " +
        "`network` kind, the `preflight_sso` phase, and the `ssoSession` " +
        "argument; accountName JSDoc default corrected to empty string; no " +
        "resource schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.20.0",
      description:
        "Regenerate shared scan_error _lib twin: harden message extraction " +
        "for non-Error object errors; no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.07.20.1",
      description:
        "Regenerate shared scan_error _lib twin: make scanErrorKey injective " +
        "by percent-encoding each key segment; no globalArguments schema changes",
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
