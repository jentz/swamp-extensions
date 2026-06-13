/**
 * `@jentz/aws-iam-role-audit` — fleet-wide IAM lens for an integration's roles
 * across many accounts.
 *
 * Where `@jentz/aws-stackset-audit` answers "what did the StackSet deploy", this
 * model answers "what is *actually* in IAM right now, and how did it get there"
 * — by reading the role(s) directly in each account.
 *
 * An integration can define **several roles** (e.g. a compliance scanner's
 * Readonly + ECR + EBS scanning roles), each with its own expected policies /
 * trust / external id and a `required` flag. The single `audit` method is the
 * **fan-out sweep** (repo rule 6): in one locked execution it iterates the
 * configured `profiles`
 * (one account each) and, for each configured role, emits one `role` resource
 * carrying:
 *
 *   - existence, ARN, path, create date, tags, and whether it is `required`,
 *   - the **management mechanism**, determined authoritatively by asking
 *     CloudFormation which stack owns the role
 *     (`DescribeStackResources --physical-resource-id <roleName>` across the
 *     configured regions): `cfn-stackset` / `cfn-standalone-stack` / `manual` /
 *     `missing`. (Role *tags* are recorded but NOT used — CloudFormation does
 *     not reliably tag the IAM roles it creates.)
 *   - attached managed-policy ARNs and inline policy names,
 *   - trust-policy principals and any `sts:ExternalId` conditions,
 *   - a `compliant` flag + `findings` vs that role's expectations.
 *
 * Configuration is **multi-role only**: set `roles: [{ roleName, expected*,
 * required }, ...]`. A run with no roles configured throws a descriptive error.
 *
 * `stackLookupRegions` is **required with no default**: the regions are searched
 * in order for the CloudFormation stack that owns each role, and the wrong
 * region misclassifies a CFN-managed role as `manual`, so there is no safe
 * fallback. An unset or empty `stackLookupRegions` throws before any AWS call.
 *
 * Per-account failures become `scan_error` rows instead of aborting the sweep.
 * Read-only: only `iam:Get*`/`iam:List*`,
 * `cloudformation:DescribeStackResources`, and `sts:GetCallerIdentity`. Pair
 * with `@jentz/integration-coverage` / `@jentz/aws-integration-coverage` to
 * coalesce this IAM lens with the StackSet lens.
 *
 * @module
 */

import { z } from "npm:zod@4";
import {
  GetRoleCommand,
  IAMClient,
  ListAttachedRolePoliciesCommand,
  ListRolePoliciesCommand,
} from "npm:@aws-sdk/client-iam@3.1021.0";
import {
  CloudFormationClient,
  DescribeStackResourcesCommand,
} from "npm:@aws-sdk/client-cloudformation@3.1021.0";
import {
  GetCallerIdentityCommand,
  STSClient,
} from "npm:@aws-sdk/client-sts@3.1021.0";
import { fromIni } from "npm:@aws-sdk/credential-providers@3.1021.0";

/** Credential provider as returned by `fromIni`; `undefined` means the ambient chain. */
type CredentialProvider = ReturnType<typeof fromIni>;

// ---------------------------------------------------------------------------
// Global arguments
// ---------------------------------------------------------------------------

/** One role's expectations within an integration. */
const RoleSpecSchema = z.object({
  roleName: z.string().min(1).describe("IAM role name to look for."),
  expectedManagedPolicyArns: z.array(z.string()).default([]).describe(
    "Managed-policy ARNs the role must have attached (exact match).",
  ),
  expectedCustomerPolicyNames: z.array(z.string()).default([]).describe(
    "Customer-managed policy NAMES the role must have attached (name match).",
  ),
  expectedTrustPrincipals: z.array(z.string()).default([]).describe(
    "Principals that must be allowed to assume the role.",
  ),
  expectedExternalId: z.string().default("").describe(
    "Required sts:ExternalId, or '' to skip.",
  ),
  required: z.boolean().default(true).describe(
    "Whether this role is expected to be deployed (false = optional / not " +
      "enabled; its absence is not a coverage gap).",
  ),
});

/** One role's expectations within an integration. */
export interface RoleSpec {
  /** IAM role name to look for. */
  roleName: string;
  /** Managed-policy ARNs the role must have attached (exact match). */
  expectedManagedPolicyArns: string[];
  /** Customer-managed policy NAMES the role must have attached (name match). */
  expectedCustomerPolicyNames: string[];
  /** Principals that must be allowed to assume the role. */
  expectedTrustPrincipals: string[];
  /** Required sts:ExternalId, or "" to skip. */
  expectedExternalId: string;
  /** Whether this role is expected to be deployed. */
  required: boolean;
}

const GlobalArgsSchema = z.object({
  roles: z.array(RoleSpecSchema).default([]).describe(
    "The integration's roles, each with its own expectations and required " +
      "flag. At least one role must be configured.",
  ),
  profiles: z.array(z.string().min(1)).default([]).describe(
    "Named AWS profiles to sweep, one account each. Empty uses the ambient " +
      "credential chain as a single account.",
  ),
  stackLookupRegions: z.array(z.string().min(1)).optional().describe(
    "REQUIRED. Regions searched (in order) for the CloudFormation stack that " +
      "owns a role, to classify the management mechanism. No default: the " +
      "wrong region misclassifies a CFN-managed role as 'manual', so the audit " +
      "fails closed (descriptive throw) when this is unset or empty.",
  ),
  requiredProfileSuffix: z.string().default("").describe(
    "If set, every profile must end with this suffix or it is refused before " +
      "any AWS call (e.g. '-readonly'). Default '' disables the check.",
  ),
  region: z.string().min(1).default("us-east-1").describe(
    "Region for the IAM/STS client endpoint. IAM is global; us-east-1 is safe.",
  ),
});

/** Resolved global arguments after schema parsing. */
export interface GlobalArgs {
  /** The integration's roles, each with its own expectations. */
  roles: RoleSpec[];
  /** Named AWS profiles to sweep, one account each. */
  profiles: string[];
  /**
   * Regions searched in order for the owning CloudFormation stack. Required at
   * runtime: `audit` throws before any AWS call when this is unset or empty.
   */
  stackLookupRegions?: string[];
  /** Required profile suffix; "" disables the check. */
  requiredProfileSuffix: string;
  /** Region for the IAM/STS client endpoint. */
  region: string;
}

/**
 * Resolve the effective role list. Configuration is multi-role only: this
 * returns the configured `roles` when non-empty, and throws a descriptive "no
 * roles configured" error when empty.
 */
export function effectiveRoles(g: { roles: RoleSpec[] }): RoleSpec[] {
  if (g.roles.length > 0) return g.roles;
  throw new Error(
    "No roles configured — set `roles: [{ roleName, expected*, required }, ...]`.",
  );
}

// ---------------------------------------------------------------------------
// Resource schemas
// ---------------------------------------------------------------------------

const TagsSchema = z.record(z.string(), z.string()).default({});

const RoleRecordSchema = z.object({
  accountId: z.string(),
  accountName: z.string(),
  profile: z.string(),
  roleName: z.string(),
  required: z.boolean(),
  exists: z.boolean(),
  arn: z.string(),
  path: z.string(),
  createDate: z.string(),
  managementMechanism: z.enum([
    "cfn-stackset",
    "cfn-standalone-stack",
    "manual",
    "missing",
  ]),
  cfnStackName: z.string(),
  cfnStackId: z.string(),
  cfnStackRegion: z.string(),
  attachedManagedPolicyArns: z.array(z.string()),
  inlinePolicyNames: z.array(z.string()),
  trustPrincipals: z.array(z.string()),
  trustExternalIds: z.array(z.string()),
  tags: TagsSchema,
  compliant: z.boolean(),
  findings: z.array(z.string()),
  scannedAt: z.iso.datetime(),
});

const ScanErrorSchema = z.object({
  profile: z.string(),
  accountId: z.string(),
  roleName: z.string(),
  phase: z.string(),
  kind: z.enum(["auth_expired", "access_denied", "other"]),
  message: z.string(),
  scannedAt: z.iso.datetime(),
});

// ---------------------------------------------------------------------------
// Public resource shapes
// ---------------------------------------------------------------------------

/** One integration role observed (or absent) in one account. */
export interface RoleRecord {
  /** Account id from sts:GetCallerIdentity. */
  accountId: string;
  /** Friendly label: profile with the required suffix stripped, or "". */
  accountName: string;
  /** Profile that produced this row; "" for ambient. */
  profile: string;
  /** Role name that was looked up. */
  roleName: string;
  /** Whether this role is expected to be deployed for the integration. */
  required: boolean;
  /** Whether the role exists in this account. */
  exists: boolean;
  /** Role ARN, or "". */
  arn: string;
  /** Role path, or "". */
  path: string;
  /** ISO 8601 role create date, or "". */
  createDate: string;
  /** How the role was created, from the owning CloudFormation stack (or none). */
  managementMechanism:
    | "cfn-stackset"
    | "cfn-standalone-stack"
    | "manual"
    | "missing";
  /** Owning CloudFormation stack name, or "". */
  cfnStackName: string;
  /** Owning CloudFormation stack id, or "". */
  cfnStackId: string;
  /** Region where the owning stack was found, or "". */
  cfnStackRegion: string;
  /** Attached managed-policy ARNs. */
  attachedManagedPolicyArns: string[];
  /** Inline policy names. */
  inlinePolicyNames: string[];
  /** Principals allowed to assume the role (AWS + Service). */
  trustPrincipals: string[];
  /** sts:ExternalId values required by the trust policy. */
  trustExternalIds: string[];
  /** Role tags, flattened (recorded for reference; not used to classify). */
  tags: Record<string, string>;
  /** True when the role exists and meets every configured expectation. */
  compliant: boolean;
  /** Human-readable list of unmet expectations (empty when compliant). */
  findings: string[];
  /** ISO 8601 scan timestamp. */
  scannedAt: string;
}

/** A profile that could not be assessed. */
export interface ScanError {
  /** Profile being swept; "" for ambient. */
  profile: string;
  /** Account id if known by the time of failure; "" otherwise. */
  accountId: string;
  /** Role name being looked up; "" for account-level (credentials) failures. */
  roleName: string;
  /** Stage that failed: credentials, get_role, etc. */
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

/** AWS-style tag tuple. */
export interface AwsTag {
  /** Tag key. */
  Key?: string;
  /** Tag value. */
  Value?: string;
}

/** Flatten AWS `[{Key, Value}]` tags into a `{key: value}` map. */
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

/** Strip the configured suffix (typically `-readonly`) to a friendly label. */
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

/** Classify an AWS SDK error into the coarse kind the report groups on. */
export function classifyError(err: unknown): {
  kind: "auth_expired" | "access_denied" | "other";
  message: string;
} {
  const message = err instanceof Error ? err.message : String(err);
  const name = (err as { name?: string } | null)?.name ?? "";
  const haystack = `${name} ${message}`.toLowerCase();
  const isAccessDenied = haystack.includes("not authorized") ||
    haystack.includes("accessdenied") ||
    haystack.includes("access denied") ||
    haystack.includes("explicit deny") ||
    haystack.includes("forbidden");
  const isAuthExpired = name.toLowerCase().includes("expiredtoken") ||
    name.toLowerCase().includes("credentialsprovidererror") ||
    haystack.includes("token has expired") ||
    haystack.includes("token is expired") ||
    haystack.includes("token included in the request is expired") ||
    haystack.includes("sso session") ||
    haystack.includes("session associated with this profile has expired") ||
    haystack.includes("could not load credentials") ||
    haystack.includes("failed to refresh");
  // Access-denied wins over auth-expired: a denied call that happens to carry an
  // SSO role ARN in its message is an authorization problem, not a stale token.
  if (isAccessDenied) return { kind: "access_denied", message };
  if (isAuthExpired) return { kind: "auth_expired", message };
  return { kind: "other", message };
}

/** The CloudFormation stack that owns a resource, as found by the lookup. */
export interface ManagingStack {
  /** Stack name. */
  stackName: string;
  /** Stack id. */
  stackId: string;
  /** Region the stack was found in. */
  region: string;
}

/**
 * Determine how a role was created from its owning CloudFormation stack.
 * StackSet-deployed stacks are named `StackSet-<StackSetName>-<guid>`, so a
 * `StackSet-` prefix is the stackset fingerprint; any other owning stack is a
 * standalone stack; no owning stack at all means the role was made by hand or
 * by a non-CloudFormation tool.
 */
export function inferMechanism(
  exists: boolean,
  managingStack: ManagingStack | null,
): RoleRecord["managementMechanism"] {
  if (!exists) return "missing";
  if (!managingStack) return "manual";
  return managingStack.stackName.startsWith("StackSet-")
    ? "cfn-stackset"
    : "cfn-standalone-stack";
}

/** Parsed trust-policy facts. */
export interface TrustFacts {
  /** Principals (AWS arns/account ids and Service principals), deduped. */
  principals: string[];
  /** sts:ExternalId values found in StringEquals conditions, deduped. */
  externalIds: string[];
}

/**
 * Parse an IAM AssumeRolePolicyDocument (URL-encoded JSON) into the principals
 * allowed to assume the role and any `sts:ExternalId` conditions. Tolerant of
 * the string-or-array shapes IAM uses; returns empty facts on any parse error.
 */
export function parseTrustPolicy(doc: string | undefined): TrustFacts {
  const principals = new Set<string>();
  const externalIds = new Set<string>();
  if (!doc) return { principals: [], externalIds: [] };
  let parsed: unknown;
  try {
    parsed = JSON.parse(decodeURIComponent(doc));
  } catch {
    try {
      parsed = JSON.parse(doc);
    } catch {
      return { principals: [], externalIds: [] };
    }
  }
  const asArray = (v: unknown): unknown[] =>
    Array.isArray(v) ? v : v === undefined || v === null ? [] : [v];
  const statements = asArray(
    (parsed as { Statement?: unknown } | null)?.Statement,
  );
  for (const stRaw of statements) {
    const st = stRaw as Record<string, unknown>;
    const principal = st.Principal as
      | Record<string, unknown>
      | string
      | undefined;
    if (typeof principal === "string") {
      principals.add(principal);
    } else if (principal && typeof principal === "object") {
      for (const key of ["AWS", "Service", "Federated"]) {
        for (const p of asArray(principal[key])) {
          if (typeof p === "string") principals.add(p);
        }
      }
    }
    const cond = st.Condition as Record<string, unknown> | undefined;
    const stringEquals = cond?.["StringEquals"] as
      | Record<string, unknown>
      | undefined;
    const ext = stringEquals?.["sts:ExternalId"];
    for (const e of asArray(ext)) {
      if (typeof e === "string") externalIds.add(e);
    }
  }
  return { principals: [...principals], externalIds: [...externalIds] };
}

/** Final segment (policy name) of a managed-policy ARN, or "". */
export function policyNameFromArn(arn: string): string {
  const idx = arn.lastIndexOf("/");
  return idx >= 0 ? arn.slice(idx + 1) : arn;
}

/**
 * Measure a role against one role spec's expectations, producing a `compliant`
 * flag and a list of unmet-expectation findings. A missing role is never
 * compliant.
 */
export function evaluateCompliance(input: {
  exists: boolean;
  attachedManagedPolicyArns: string[];
  trustPrincipals: string[];
  trustExternalIds: string[];
  spec: RoleSpec;
}): { compliant: boolean; findings: string[] } {
  const findings: string[] = [];
  if (!input.exists) {
    return { compliant: false, findings: ["role does not exist"] };
  }
  const attachedNames = new Set(
    input.attachedManagedPolicyArns.map(policyNameFromArn),
  );
  const attachedArns = new Set(input.attachedManagedPolicyArns);
  for (const arn of input.spec.expectedManagedPolicyArns) {
    if (!attachedArns.has(arn)) {
      findings.push(`missing expected managed policy ${arn}`);
    }
  }
  for (const name of input.spec.expectedCustomerPolicyNames) {
    if (!attachedNames.has(name)) {
      findings.push(`missing expected customer-managed policy '${name}'`);
    }
  }
  const principals = new Set(input.trustPrincipals);
  for (const p of input.spec.expectedTrustPrincipals) {
    if (!principals.has(p)) findings.push(`trust principal '${p}' not allowed`);
  }
  if (input.spec.expectedExternalId.length > 0) {
    if (!input.trustExternalIds.includes(input.spec.expectedExternalId)) {
      findings.push(
        `trust policy does not require expected externalId '${input.spec.expectedExternalId}'`,
      );
    }
  }
  return { compliant: findings.length === 0, findings };
}

/** Stable storage key for a role row (one per account × role). */
export function roleKey(accountId: string, roleName: string): string {
  return `role-${accountId || "unknown"}-${roleName}`;
}

/** Stable storage key for a scan error (unique per profile × role × phase). */
export function scanErrorKey(
  profileLabel: string,
  roleName: string,
  phase: string,
): string {
  return `error-${profileLabel || "ambient"}-${roleName || "_"}-${phase}`;
}

// ---------------------------------------------------------------------------
// AWS facade — minimal surface so logic stays testable without the SDK
// ---------------------------------------------------------------------------

/** Minimal IAM role shape this extension reads from GetRole. */
export interface AwsRole {
  /** Role ARN. */
  Arn?: string;
  /** Role path. */
  Path?: string;
  /** Create date. */
  CreateDate?: Date | string;
  /** URL-encoded trust policy JSON. */
  AssumeRolePolicyDocument?: string;
  /** Role tags. */
  Tags?: AwsTag[];
}

/** Facade over the IAM/STS/CFN calls this extension uses, for one account. */
export interface IamApi {
  /** Resolve the account id for the active credentials. */
  getAccountId(): Promise<string>;
  /** GetRole; `null` when the role does not exist (NoSuchEntity). */
  getRole(roleName: string): Promise<AwsRole | null>;
  /** Attached managed-policy ARNs for the role. */
  listAttachedPolicyArns(roleName: string): Promise<string[]>;
  /** Inline policy names for the role. */
  listInlinePolicyNames(roleName: string): Promise<string[]>;
  /** The CloudFormation stack that owns the role, or `null` if none. */
  findManagingStack(roleName: string): Promise<ManagingStack | null>;
}

// ---------------------------------------------------------------------------
// SDK-backed facade
// ---------------------------------------------------------------------------

const CLIENT_RETRY = { maxAttempts: 6 } as const;

function isNoSuchEntity(err: unknown): boolean {
  const name = (err as { name?: string } | null)?.name ?? "";
  const msg = err instanceof Error ? err.message : String(err);
  return name === "NoSuchEntityException" ||
    msg.toLowerCase().includes("cannot be found") ||
    msg.toLowerCase().includes("does not exist");
}

/** True for the `Stack for <id> does not exist` ValidationError from CFN. */
function isStackNotFound(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return msg.includes("does not exist");
}

function sdkApi(
  credentials: CredentialProvider | undefined,
  region: string,
  stackLookupRegions: string[],
  signal?: AbortSignal,
): IamApi {
  const iam = new IAMClient({ region, credentials, ...CLIENT_RETRY });
  const opts = { abortSignal: signal };
  return {
    getAccountId: async () => {
      const sts = new STSClient({ region, credentials, ...CLIENT_RETRY });
      const resp = await sts.send(new GetCallerIdentityCommand({}), opts);
      return resp.Account ?? "";
    },
    getRole: async (roleName: string) => {
      try {
        const resp = await iam.send(
          new GetRoleCommand({ RoleName: roleName }),
          opts,
        );
        return (resp.Role ?? null) as AwsRole | null;
      } catch (err) {
        if (isNoSuchEntity(err)) return null;
        throw err;
      }
    },
    listAttachedPolicyArns: async (roleName: string) => {
      const out: string[] = [];
      let marker: string | undefined;
      do {
        const resp = await iam.send(
          new ListAttachedRolePoliciesCommand({
            RoleName: roleName,
            Marker: marker,
          }),
          opts,
        );
        for (const p of resp.AttachedPolicies ?? []) {
          if (p.PolicyArn) out.push(p.PolicyArn);
        }
        marker = resp.IsTruncated ? resp.Marker : undefined;
      } while (marker);
      return out;
    },
    listInlinePolicyNames: async (roleName: string) => {
      const out: string[] = [];
      let marker: string | undefined;
      do {
        const resp = await iam.send(
          new ListRolePoliciesCommand({ RoleName: roleName, Marker: marker }),
          opts,
        );
        out.push(...(resp.PolicyNames ?? []));
        marker = resp.IsTruncated ? resp.Marker : undefined;
      } while (marker);
      return out;
    },
    findManagingStack: async (roleName: string) => {
      // CloudFormation stacks are regional; the role is global. Search the
      // configured regions in order and return the first owning stack. CFN
      // raises a ValidationError ("Stack for <id> does not exist") when no
      // stack in a region owns the resource — a miss, not a failure.
      for (const r of stackLookupRegions) {
        const cfn = new CloudFormationClient({
          region: r,
          credentials,
          ...CLIENT_RETRY,
        });
        try {
          const resp = await cfn.send(
            new DescribeStackResourcesCommand({ PhysicalResourceId: roleName }),
            opts,
          );
          const sr = (resp.StackResources ?? [])[0];
          if (sr?.StackName) {
            return {
              stackName: sr.StackName,
              stackId: sr.StackId ?? "",
              region: r,
            };
          }
        } catch (err) {
          if (isStackNotFound(err)) continue;
          continue; // best-effort: treat any region error as a miss
        }
      }
      return null;
    },
  };
}

// ---------------------------------------------------------------------------
// Core audit logic — parameterized on its AWS facade and runtime context
// ---------------------------------------------------------------------------

/** One account's scan target: a label and the API facade. */
export interface ScanTarget {
  /** Profile name, or "" for the ambient credential chain. */
  profile: string;
  /** API facade bound to this account's credentials. */
  api: IamApi;
}

/** Dependencies for {@link runAudit}. */
export interface AuditDeps {
  /** Ordered scan targets, one per account. */
  targets: ScanTarget[];
  /** Effective role specs to evaluate per account. */
  roles: RoleSpec[];
  /** Required profile suffix; "" disables the check. */
  requiredProfileSuffix: string;
  /**
   * The AWS_PROFILE the ambient credential chain would use, used only for the
   * suffix gate on the ambient target; "" when unknown.
   */
  ambientProfile: string;
  /** Swamp method-execution context (host-injected; typed `any`). */
  // deno-lint-ignore no-explicit-any
  context: any;
}

/** Result of {@link runAudit}. */
export interface AuditResult {
  /** Data handles produced, in write order. */
  dataHandles: unknown[];
  /** Count of role rows written (accounts × roles). */
  roleCount: number;
  /** Count of role rows where the role exists. */
  presentCount: number;
  /** Count of scan errors written. */
  errorCount: number;
}

/**
 * Core `audit` logic. For each account (one STS call), evaluate every configured
 * role — existence, policies, trust, owning stack, compliance — and write one
 * `role` row per (account, role). Per-account credential failures and per-role
 * read failures become `scan_error` rows and never abort the sweep.
 *
 * @param deps Targets, role specs, suffix policy, and the runtime context.
 * @returns Data handles plus role / present / error counts.
 */
export async function runAudit(deps: AuditDeps): Promise<AuditResult> {
  const { targets, roles, requiredProfileSuffix, context } = deps;
  const handles: unknown[] = [];
  let roleCount = 0;
  let presentCount = 0;
  let errorCount = 0;
  const scannedAt = new Date().toISOString();
  const suffix = requiredProfileSuffix;
  const ambientProfile = deps.ambientProfile ?? "";

  const writeError = async (e: ScanError): Promise<void> => {
    errorCount++;
    handles.push(
      await context.writeResource(
        "scan_error",
        scanErrorKey(e.profile, e.roleName, e.phase),
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
    if (suffix.length > 0 && !labelForSuffix.endsWith(suffix)) {
      const shownLabel = labelForSuffix || "<ambient:no AWS_PROFILE>";
      context.logger.warn(
        "Skipping profile {profile}: does not end with required suffix {suffix}",
        { profile: shownLabel, suffix },
      );
      await writeError({
        profile: profileLabel,
        accountId: "",
        roleName: "",
        phase: "profile_suffix_check",
        kind: "other",
        message:
          `Profile '${shownLabel}' does not end with required suffix '${suffix}'.`,
        scannedAt,
      });
      continue;
    }

    let accountId = "";
    try {
      accountId = await target.api.getAccountId();
    } catch (err) {
      const { kind, message } = classifyError(err);
      context.logger.warn("Credentials failed for {profile}: {message}", {
        profile: profileLabel || "<ambient>",
        message,
      });
      await writeError({
        profile: profileLabel,
        accountId: "",
        roleName: "",
        phase: "credentials",
        kind,
        message,
        scannedAt,
      });
      continue;
    }

    const accountName = accountNameFromProfile(profileLabel, suffix);

    for (const spec of roles) {
      try {
        const role = await target.api.getRole(spec.roleName);
        const exists = role !== null;

        let attachedManagedPolicyArns: string[] = [];
        let inlinePolicyNames: string[] = [];
        let managingStack: ManagingStack | null = null;
        if (exists) {
          attachedManagedPolicyArns = await target.api.listAttachedPolicyArns(
            spec.roleName,
          );
          inlinePolicyNames = await target.api.listInlinePolicyNames(
            spec.roleName,
          );
          managingStack = await target.api.findManagingStack(spec.roleName);
        }

        const tags = tagsFromAws(role?.Tags);
        const mechanism = inferMechanism(exists, managingStack);
        const trust = parseTrustPolicy(role?.AssumeRolePolicyDocument);
        const { compliant, findings } = evaluateCompliance({
          exists,
          attachedManagedPolicyArns,
          trustPrincipals: trust.principals,
          trustExternalIds: trust.externalIds,
          spec,
        });

        const createDate = role?.CreateDate instanceof Date
          ? role.CreateDate.toISOString()
          : typeof role?.CreateDate === "string"
          ? role.CreateDate
          : "";

        const row: RoleRecord = {
          accountId,
          accountName,
          profile: profileLabel,
          roleName: spec.roleName,
          required: spec.required,
          exists,
          arn: role?.Arn ?? "",
          path: role?.Path ?? "",
          createDate,
          managementMechanism: mechanism,
          cfnStackName: managingStack?.stackName ?? "",
          cfnStackId: managingStack?.stackId ?? "",
          cfnStackRegion: managingStack?.region ?? "",
          attachedManagedPolicyArns,
          inlinePolicyNames,
          trustPrincipals: trust.principals,
          trustExternalIds: trust.externalIds,
          tags,
          compliant,
          findings,
          scannedAt,
        };
        roleCount++;
        if (exists) presentCount++;
        handles.push(
          await context.writeResource(
            "role",
            roleKey(accountId, spec.roleName),
            row,
          ),
        );
      } catch (err) {
        const { kind, message } = classifyError(err);
        context.logger.warn(
          "Role {role} audit failed for account {account} ({profile}): {message}",
          {
            role: spec.roleName,
            account: accountId,
            profile: profileLabel || "<ambient>",
            message,
          },
        );
        await writeError({
          profile: profileLabel,
          accountId,
          roleName: spec.roleName,
          phase: "get_role",
          kind,
          message,
          scannedAt,
        });
      }
    }
  }

  context.logger.info(
    "iam-role-audit complete: {roles} role row(s) ({present} present), {errors} error(s)",
    { roles: roleCount, present: presentCount, errors: errorCount },
  );

  return { dataHandles: handles, roleCount, presentCount, errorCount };
}

// ---------------------------------------------------------------------------
// Model export
// ---------------------------------------------------------------------------

/**
 * The `@jentz/aws-iam-role-audit` model. Single method `audit` reads one or more
 * named roles across every configured account, capturing each role's policies,
 * trust, tags, management mechanism (from the owning CloudFormation stack), and
 * compliance against that role's expectations.
 *
 * Configuration is multi-role only (set `roles: [...]`), and `stackLookupRegions`
 * is required with no default — both surfaces fail closed with a descriptive
 * error before any AWS call.
 */
export const model = {
  type: "@jentz/aws-iam-role-audit",
  version: "2026.06.13.0",
  globalArguments: GlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.06.13.0",
      description: "Initial publish",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    role: {
      description:
        "One integration role observed (or absent) in one account, with its " +
        "policies, trust principals, external ids, management mechanism " +
        "(stackset/standalone/manual/missing, from the owning CFN stack), " +
        "required flag, and compliance findings.",
      schema: RoleRecordSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    scan_error: {
      description:
        "A profile (or profile × role) that could not be assessed — expired " +
        "SSO token, denied call, etc. Surfaces coverage gaps in the report.",
      schema: ScanErrorSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    audit: {
      description:
        "Read-only fan-out: for each configured role, sweep every profile " +
        "(account) and capture existence, attached/inline policies, trust " +
        "principals + external ids, the owning CloudFormation stack (to " +
        "classify mechanism), and compliance against the role's expectations. " +
        "One role row per (account, role).",
      arguments: z.object({}),
      execute: (
        _args: Record<string, never>,
        // deno-lint-ignore no-explicit-any
        context: any,
      ): Promise<AuditResult> => {
        const g = GlobalArgsSchema.parse(context.globalArgs);
        const roles = effectiveRoles(g);
        const stackLookupRegions = g.stackLookupRegions ?? [];
        if (stackLookupRegions.length === 0) {
          throw new Error(
            "stackLookupRegions is required and must be non-empty — the wrong " +
              "region misclassifies a CFN-managed role as 'manual', so there " +
              "is no safe default.",
          );
        }
        const isAmbient = g.profiles.length === 0;
        // For an ambient run the suffix gate has no profile label to check, so
        // it falls back to the AWS_PROFILE the ambient chain would use.
        const ambientProfile = isAmbient
          ? (Deno.env.get("AWS_PROFILE") ?? "")
          : "";

        const targets: ScanTarget[] = isAmbient
          ? [{
            profile: "",
            api: sdkApi(
              undefined,
              g.region,
              stackLookupRegions,
              context.signal,
            ),
          }]
          : g.profiles.map((profile) => ({
            profile,
            api: sdkApi(
              fromIni({ profile }),
              g.region,
              stackLookupRegions,
              context.signal,
            ),
          }));
        return runAudit({
          targets,
          roles,
          requiredProfileSuffix: g.requiredProfileSuffix,
          ambientProfile,
          context,
        });
      },
    },
  },
};
