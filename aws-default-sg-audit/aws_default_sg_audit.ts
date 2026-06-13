/**
 * `@jentz/aws-default-sg-audit` — fleet audit for AWS Security Hub control
 * EC2.2 ("VPC default security groups should not allow inbound or outbound
 * traffic"), with a remediation-safety verdict per default security group.
 *
 * The single `scan` method fans out over `profiles × regions` in one execution
 * (one model lock, all output in one pass — see repo rule 6). For each account
 * it discovers the enabled regions (or uses the configured `regions`), then in
 * every region:
 *
 *   1. Lists every VPC's `default` security group (the EC2.2 scope) and counts
 *      its ingress / egress rules. A default SG is EC2.2-**compliant** only when
 *      both rule lists are empty.
 *   2. Enumerates the ENIs that reference each default SG and classifies them
 *      (plain instance, NAT gateway, `amazon-elasticache`, `amazon-elb`, …).
 *      ENIs are the universal "is this in use?" signal — a non-compliant default
 *      SG with **zero** ENIs is safe to strip; one with ENIs needs the attached
 *      workload migrated to a dedicated SG *first*.
 *   3. Reads the VPC's tags (so the operator report can name an owner/team).
 *
 * It emits one `finding` resource per default SG and one `scan_error` resource
 * per (profile, region) that could not be assessed — an expired SSO token or a
 * denied describe call becomes a reported row, never an aborted sweep.
 *
 * Read-only: only `Describe*` and `sts:GetCallerIdentity` are called. Pair with
 * `@jentz/aws-context-guard` in a workflow to fail closed on the wrong account,
 * and with the companion report extension for an operator worklist.
 *
 * @module
 */

import { z } from "npm:zod@4";
import {
  DescribeNetworkInterfacesCommand,
  DescribeRegionsCommand,
  DescribeSecurityGroupsCommand,
  DescribeVpcsCommand,
  EC2Client,
} from "npm:@aws-sdk/client-ec2@3.1021.0";
import {
  GetCallerIdentityCommand,
  STSClient,
} from "npm:@aws-sdk/client-sts@3.1021.0";
import { fromIni } from "npm:@aws-sdk/credential-providers@3.1021.0";

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
      "enabled regions via ec2:DescribeRegions, so default VPCs in regions " +
      "where Security Hub is NOT evaluating EC2.2 are still caught.",
  ),
  requiredProfileSuffix: z.string().default("").describe(
    "If set, every profile (and the ambient AWS_PROFILE) must end with this " +
      "suffix or the profile is refused before any AWS call. Set to " +
      "'-readonly' to enforce read-only profiles for the audit. Default '' " +
      "disables the check.",
  ),
});

const TagsSchema = z.record(z.string(), z.string()).default({});

const EniSchema = z.object({
  id: z.string(),
  interfaceType: z.string(),
  description: z.string(),
  requesterId: z.string(),
  requesterManaged: z.boolean(),
  category: z.string(),
  attachedInstanceId: z.string(),
});

/** EC2.2 verdict for a default security group. */
const VerdictSchema = z.enum([
  "compliant",
  "safe_to_remediate",
  "in_use_needs_migration",
]);

const FindingSchema = z.object({
  accountId: z.string(),
  profile: z.string(),
  region: z.string(),
  vpcId: z.string(),
  vpcName: z.string(),
  vpcIsDefault: z.boolean(),
  defaultSgId: z.string(),
  ingressRuleCount: z.number(),
  egressRuleCount: z.number(),
  compliant: z.boolean(),
  eniCount: z.number(),
  enis: z.array(EniSchema),
  verdict: VerdictSchema,
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

/** EC2.2 remediation verdict for a default security group. */
export type Verdict =
  | "compliant"
  | "safe_to_remediate"
  | "in_use_needs_migration";

/** A single ENI that references a default security group. */
export interface Eni {
  /** ENI id (`eni-...`). */
  id: string;
  /** AWS interface type: `interface`, `nat_gateway`, `vpc_endpoint`, `lambda`, … */
  interfaceType: string;
  /** AWS-supplied description (often names the owning workload). */
  description: string;
  /** Requester principal for service-managed ENIs (`amazon-elasticache`, …); `""` for plain ENIs. */
  requesterId: string;
  /** Whether AWS (a managed service) owns this ENI rather than the customer. */
  requesterManaged: boolean;
  /** Derived bucket used by the operator report (`amazon-elasticache`, `nat_gateway`, `ec2-instance`, …). */
  category: string;
  /** Instance id when the ENI is attached to an EC2 instance; `""` otherwise. */
  attachedInstanceId: string;
}

/** One default security group's EC2.2 finding plus its remediation-safety verdict. */
export interface Finding {
  /** 12-digit AWS account id (from sts:GetCallerIdentity). */
  accountId: string;
  /** Profile that produced this finding; `""` for the ambient credential chain. */
  profile: string;
  /** AWS region. */
  region: string;
  /** VPC the default SG belongs to. */
  vpcId: string;
  /** VPC `Name` tag, or `""`. */
  vpcName: string;
  /** Whether this is the AWS-created default VPC. */
  vpcIsDefault: boolean;
  /** The default security group id (the EC2.2 resource). */
  defaultSgId: string;
  /** Number of inbound (ingress) rules; EC2.2 wants 0. */
  ingressRuleCount: number;
  /** Number of outbound (egress) rules; EC2.2 wants 0. */
  egressRuleCount: number;
  /** True when both rule counts are 0 — EC2.2 compliant. */
  compliant: boolean;
  /** Number of ENIs that reference this default SG. */
  eniCount: number;
  /** The referencing ENIs, classified. */
  enis: Eni[];
  /**
   * Remediation verdict:
   * - `compliant` — no rules; nothing to do.
   * - `safe_to_remediate` — non-compliant but zero ENIs; revoke all rules.
   * - `in_use_needs_migration` — non-compliant and in use; migrate the
   *   attached workload to a dedicated SG before stripping.
   */
  verdict: Verdict;
  /** All VPC tags, flattened. Surfaces owner/team/service for the operator. */
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
  /** Region being scanned; `""` for account-level failures (credentials / region discovery). */
  region: string;
  /** Stage that failed: `credentials`, `describe_regions`, `describe_security_groups`, … */
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
 * Classify an ENI into a coarse category for the operator report. Service-
 * managed ENIs (RequesterId like `amazon-elasticache`) keep that requester as
 * the category since it names the remediation path; otherwise the AWS
 * interface type is used, with plain instance-attached ENIs reported as
 * `ec2-instance`.
 */
export function classifyEni(
  requesterId: string | undefined,
  interfaceType: string | undefined,
  attachedInstanceId: string,
): string {
  const rid = (requesterId ?? "").trim();
  if (rid.startsWith("amazon-")) return rid;
  const it = (interfaceType ?? "").trim();
  if (it.length > 0 && it !== "interface") return it;
  if (attachedInstanceId.length > 0) return "ec2-instance";
  return it.length > 0 ? it : "interface";
}

/**
 * Derive the EC2.2 verdict from rule compliance and ENI usage. A compliant SG
 * needs no action; a non-compliant SG is safe to strip only when nothing uses
 * it, otherwise the attached workload must be migrated first.
 */
export function deriveVerdict(
  compliant: boolean,
  eniCount: number,
): Verdict {
  if (compliant) return "compliant";
  return eniCount === 0 ? "safe_to_remediate" : "in_use_needs_migration";
}

/**
 * Classify an AWS SDK error into the coarse `kind` the operator report uses to
 * decide a next action. SSO/token/credential failures map to `auth_expired`
 * (operator runs `aws sso login`); authorization failures map to
 * `access_denied` (the role lacks a describe permission); everything else is
 * `other`.
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
  // Authorization denial — IAM or an SCP explicit deny (e.g. a region the org
  // does not permit). Expected and benign for out-of-scope regions.
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
 * (sts:GetCallerIdentity, ec2:DescribeRegions) that must target *some* region
 * before per-region scanning begins. Order: first configured region →
 * `AWS_REGION` → `AWS_DEFAULT_REGION` → `us-east-1` (a global-ish default that
 * is enabled on every account, used only for these bootstrap calls).
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

/** Build a stable storage key for a finding (unique across account/region). */
export function findingKey(
  accountId: string,
  region: string,
  defaultSgId: string,
): string {
  return `finding-${accountId}-${region}-${defaultSgId}`;
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

/** Minimal SG shape this extension depends on. */
export interface AwsSecurityGroup {
  /** Security group id. */
  GroupId?: string;
  /** Group name; the default SG is always named `default`. */
  GroupName?: string;
  /** Owning VPC id. */
  VpcId?: string;
  /** Inbound rules. */
  IpPermissions?: unknown[];
  /** Outbound rules. */
  IpPermissionsEgress?: unknown[];
}

/** Minimal VPC shape this extension depends on. */
export interface AwsVpc {
  /** VPC id. */
  VpcId?: string;
  /** Whether this is the AWS-created default VPC. */
  IsDefault?: boolean;
  /** VPC tags. */
  Tags?: AwsTag[];
}

/** Minimal ENI shape this extension depends on. */
export interface AwsNetworkInterface {
  /** ENI id. */
  NetworkInterfaceId?: string;
  /** Interface type. */
  InterfaceType?: string;
  /** Description. */
  Description?: string;
  /** Requester principal for service-managed ENIs. */
  RequesterId?: string;
  /** Whether a managed service owns the ENI. */
  RequesterManaged?: boolean;
  /** Attachment, when attached to an instance. */
  Attachment?: { InstanceId?: string };
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
  /** Every VPC's `default` security group in `region`. */
  describeDefaultSecurityGroups(region: string): Promise<AwsSecurityGroup[]>;
  /** VPCs by id in `region` (for IsDefault + tags). */
  describeVpcs(region: string, vpcIds: string[]): Promise<AwsVpc[]>;
  /** ENIs referencing `groupId` in `region`. */
  describeEnisForGroup(
    region: string,
    groupId: string,
  ): Promise<AwsNetworkInterface[]>;
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
    describeDefaultSecurityGroups: async (region) => {
      const ec2 = ec2For(region);
      const out: AwsSecurityGroup[] = [];
      let token: string | undefined;
      do {
        const resp = await ec2.send(
          new DescribeSecurityGroupsCommand({
            Filters: [{ Name: "group-name", Values: ["default"] }],
            NextToken: token,
            MaxResults: 100,
          }),
        );
        out.push(...(resp.SecurityGroups ?? []));
        token = resp.NextToken;
      } while (token);
      return out;
    },
    describeVpcs: async (region, vpcIds) => {
      if (vpcIds.length === 0) return [];
      const ec2 = ec2For(region);
      const out: AwsVpc[] = [];
      let token: string | undefined;
      do {
        const resp = await ec2.send(
          new DescribeVpcsCommand({ VpcIds: vpcIds, NextToken: token }),
        );
        out.push(...(resp.Vpcs ?? []));
        token = resp.NextToken;
      } while (token);
      return out;
    },
    describeEnisForGroup: async (region, groupId) => {
      const ec2 = ec2For(region);
      const out: AwsNetworkInterface[] = [];
      let token: string | undefined;
      do {
        const resp = await ec2.send(
          new DescribeNetworkInterfacesCommand({
            Filters: [{ Name: "group-id", Values: [groupId] }],
            NextToken: token,
            MaxResults: 1000,
          }),
        );
        out.push(...(resp.NetworkInterfaces ?? []));
        token = resp.NextToken;
      } while (token);
      return out;
    },
  };
}

// ---------------------------------------------------------------------------
// Core scan logic — parameterized on its AWS facade and runtime context
// ---------------------------------------------------------------------------

/** One account's scan target: a label, the API facade, and the regions to scan. */
export interface ScanTarget {
  /** Profile name, or `""` for the ambient credential chain. */
  profile: string;
  /** API facade bound to this account's credentials. */
  api: AwsApi;
}

/** Dependencies for {@link runScan}. */
export interface ScanDeps {
  /**
   * Resolve the ordered scan targets. Each is one account. Implemented by the
   * real execute (one target per profile, or one ambient target); the smoke
   * test supplies replay facades directly.
   */
  targets: ScanTarget[];
  /** Configured regions; empty means "discover per account". */
  configuredRegions: string[];
  /** Optional required profile suffix; `""` disables the check. */
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
  /** Count of findings written. */
  findingCount: number;
  /** Count of scan errors written. */
  errorCount: number;
}

/**
 * Core `scan` logic. Iterates targets (accounts) × regions, writing one
 * `finding` per default SG and one `scan_error` per (profile, region) that
 * fails. Per-target and per-region failures are caught and recorded — a single
 * expired SSO token or denied call never aborts the wider sweep.
 *
 * @param deps Targets, configuration, and the runtime context.
 * @returns Data handles plus finding / error counts.
 */
export async function runScan(deps: ScanDeps): Promise<ScanResult> {
  const { targets, configuredRegions, requiredProfileSuffix, context } = deps;
  const ambientProfile = deps.ambientProfile ?? "";
  const handles: unknown[] = [];
  let findingCount = 0;
  let errorCount = 0;
  const scannedAt = new Date().toISOString();

  const writeError = async (
    e: ScanError,
  ): Promise<void> => {
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
      "Scanning account {account} (profile={profile}) across {count} region(s)",
      {
        account: accountId,
        profile: profileLabel || "<ambient>",
        count: regions.length,
      },
    );

    for (const region of regions) {
      try {
        const sgs = await target.api.describeDefaultSecurityGroups(region);
        const defaultSgs = sgs.filter((sg) => sg.GroupName === "default");
        if (defaultSgs.length === 0) continue;

        const vpcIds = [
          ...new Set(
            defaultSgs
              .map((sg) => sg.VpcId)
              .filter((v): v is string =>
                typeof v === "string" && v.length > 0
              ),
          ),
        ];
        const vpcs = await target.api.describeVpcs(region, vpcIds);
        const vpcById = new Map<string, AwsVpc>();
        for (const v of vpcs) {
          if (v.VpcId) vpcById.set(v.VpcId, v);
        }

        for (const sg of defaultSgs) {
          const sgId = sg.GroupId ?? "";
          const vpcId = sg.VpcId ?? "";
          if (sgId === "") {
            context.logger.warn(
              "Default SG with no GroupId in {region} (vpc={vpc}); skipped",
              { region, vpc: vpcId || "<unknown>" },
            );
            continue;
          }

          const ingressRuleCount = (sg.IpPermissions ?? []).length;
          const egressRuleCount = (sg.IpPermissionsEgress ?? []).length;
          const compliant = ingressRuleCount === 0 && egressRuleCount === 0;

          const rawEnis = await target.api.describeEnisForGroup(region, sgId);
          const enis: Eni[] = rawEnis.map((eni) => {
            const attachedInstanceId = eni.Attachment?.InstanceId ?? "";
            return {
              id: eni.NetworkInterfaceId ?? "",
              interfaceType: eni.InterfaceType ?? "interface",
              description: eni.Description ?? "",
              requesterId: eni.RequesterId ?? "",
              requesterManaged: eni.RequesterManaged ?? false,
              category: classifyEni(
                eni.RequesterId,
                eni.InterfaceType,
                attachedInstanceId,
              ),
              attachedInstanceId,
            };
          });
          const eniCount = enis.length;

          const vpc = vpcById.get(vpcId);
          const vpcTags = tagsFromAws(vpc?.Tags);

          const finding: Finding = {
            accountId,
            profile: profileLabel,
            region,
            vpcId,
            vpcName: vpcTags["Name"] ?? "",
            vpcIsDefault: vpc?.IsDefault ?? false,
            defaultSgId: sgId,
            ingressRuleCount,
            egressRuleCount,
            compliant,
            eniCount,
            enis,
            verdict: deriveVerdict(compliant, eniCount),
            vpcTags,
            scannedAt,
          };
          findingCount++;
          handles.push(
            await context.writeResource(
              "finding",
              findingKey(accountId, region, sgId),
              finding,
            ),
          );
        }
      } catch (err) {
        const { kind, message } = classifyError(err);
        context.logger.warn(
          "Scan failed in {region} for account {account}: {message}",
          { region, account: accountId, message },
        );
        await writeError({
          profile: profileLabel,
          accountId,
          region,
          phase: "describe_security_groups",
          kind,
          message,
          scannedAt,
        });
      }
    }
  }

  context.logger.info(
    "default-sg-audit complete: {findings} finding(s), {errors} error(s)",
    { findings: findingCount, errors: errorCount },
  );

  return { dataHandles: handles, findingCount, errorCount };
}

// ---------------------------------------------------------------------------
// Model export
// ---------------------------------------------------------------------------

/**
 * The `@jentz/aws-default-sg-audit` model.
 *
 * Single method `scan` audits every VPC's default security group across the
 * configured `profiles × regions` for AWS Security Hub control EC2.2, attaching
 * a remediation-safety verdict (driven by ENI usage) to each.
 */
export const model = {
  type: "@jentz/aws-default-sg-audit",
  version: "2026.06.13.0",
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
  ],
  resources: {
    finding: {
      description:
        "One VPC default security group audited for EC2.2, with rule counts, " +
        "referencing ENIs, and a remediation-safety verdict.",
      schema: FindingSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    scan_error: {
      description:
        "A (profile, region) pair that could not be assessed — expired SSO " +
        "token, denied describe call, etc. Doubles as the operator's " +
        "'needs attention before we can scan' list.",
      schema: ScanErrorSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    scan: {
      description:
        "Audit default security groups for EC2.2 across profiles × regions, " +
        "classifying each as compliant, safe_to_remediate, or " +
        "in_use_needs_migration.",
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
