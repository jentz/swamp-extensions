/**
 * Swamp workflow-scope report: `@jentz/aws-s3-bucket-audit`.
 *
 * Audits S3 buckets that were fetched during the workflow run against
 * standard security best practices. Designed to be paired with a workflow
 * whose steps invoke `@swamp/aws/s3/bucket` (for bucket state) and
 * `@swamp/aws/s3/bucket-policy` (for the bucket policy document); the
 * report finds those step outputs in `context.stepExecutions`, matches
 * them by bucket name, and produces lint-shaped findings.
 *
 * Findings are emitted as both human-readable markdown and a machine-
 * readable JSON object with shape:
 *
 *   {
 *     summary: { buckets, errors, warns, infos, pass, fail, skip },
 *     buckets: [ { name, findings: Finding[] }, ... ],
 *     findings: Finding[]    // flat list across all buckets
 *   }
 *
 * The report itself never throws; missing or unparseable data produces a
 * `skip` status finding instead of failing the workflow.
 *
 * @module
 */

import { z } from "npm:zod@4";

/** Severity attached to a rule. `error` factors trip the gate at the default threshold. */
export type Severity = "error" | "warn" | "info";

/** Per-finding outcome. `skip` indicates the rule could not evaluate (e.g. missing data). */
export type Status = "pass" | "fail" | "warn" | "skip";

/** One rule's verdict for one bucket, with the observed and expected values that produced it. */
export interface Finding {
  /** Stable rule identifier (e.g. `bucket-versioning-enabled`). */
  id: string;
  /** Severity attached to the rule that produced this finding. */
  severity: Severity;
  /** Outcome of the rule for this bucket. */
  status: Status;
  /** Name of the audited bucket. */
  bucket: string;
  /** Observed values the rule inspected. */
  actual: Record<string, unknown>;
  /** Target values the rule expected. */
  expected: Record<string, unknown>;
  /** Human-readable summary of the finding. */
  message: string;
  /** URLs to AWS documentation supporting the rule. */
  references: string[];
}

const BUCKET_TYPE = "@swamp/aws/s3/bucket";
const POLICY_TYPE = "@swamp/aws/s3/bucket-policy";

const SECURITY_S3 =
  "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html";

const VALID_SSE_ALGORITHMS: readonly string[] = [
  "AES256",
  "aws:kms",
  "aws:kms:dsse",
];

const BucketStateSchema = z.object({
  BucketName: z.string(),
}).passthrough();

/**
 * Shape of an `@swamp/aws/s3/bucket.get` data record after parsing. Only
 * `BucketName` is required; every other field is read defensively because
 * the upstream CloudControl shape varies by service and region.
 */
export interface BucketState {
  /** Bucket name. */
  BucketName: string;
  /** Any additional CloudControl fields (e.g. `VersioningConfiguration`, `BucketEncryption`, `Tags`). */
  [key: string]: unknown;
}

// CloudControl returns `PolicyDocument` as a parsed object (despite the
// upstream @swamp/aws/s3 schema declaring it `z.string()`), so we accept
// either shape and normalize to a string in `checkTLSOnlyPolicy`.
const BucketPolicyStateSchema = z.object({
  Bucket: z.string(),
  PolicyDocument: z.union([z.string(), z.record(z.string(), z.unknown())])
    .optional(),
}).passthrough();

/**
 * Shape of an `@swamp/aws/s3/bucket-policy.get` data record. `PolicyDocument`
 * may arrive as a JSON string (legacy upstream behavior) or a parsed object
 * (CloudControl); the TLS-policy check normalizes both.
 */
export interface BucketPolicyState {
  /** Bucket the policy is attached to. */
  Bucket: string;
  /** Policy document as JSON string (legacy upstream) or parsed object (CloudControl). */
  PolicyDocument?: string | Record<string, unknown>;
  /** Any additional CloudControl fields. */
  [key: string]: unknown;
}

/**
 * Per-bucket state collected from workflow step outputs. Missing `state` or
 * `policy` (or a populated `stateError` / `policyError`) trigger `skip`-status
 * findings rather than workflow failures.
 */
export interface BucketBundle {
  /** Bucket name (the join key for state + policy). */
  name: string;
  /** Parsed `@swamp/aws/s3/bucket.get` data, when the upstream step succeeded. */
  state?: BucketState;
  /** Diagnostic message when the bucket-state lookup failed. */
  stateError?: string;
  /** Parsed `@swamp/aws/s3/bucket-policy.get` data, when the upstream step succeeded. */
  policy?: BucketPolicyState;
  /** Diagnostic message when the bucket-policy lookup failed. */
  policyError?: string;
}

const TEXT_DECODER = new TextDecoder();

function decodeJson<T>(bytes: Uint8Array | null): T | null {
  if (!bytes) return null;
  try {
    return JSON.parse(TEXT_DECODER.decode(bytes)) as T;
  } catch {
    return null;
  }
}

async function readDataFile(
  // deno-lint-ignore no-explicit-any
  context: any,
  modelType: string,
  modelId: string,
  dataName: string,
  version: number,
): Promise<Uint8Array | null> {
  const path =
    `${context.repoDir}/.swamp/data/${modelType}/${modelId}/${dataName}/${version}/raw`;
  try {
    return await Deno.readFile(path);
  } catch (err) {
    if (err instanceof Deno.errors.NotFound) return null;
    throw err;
  }
}

// deno-lint-ignore no-explicit-any
async function collectBundles(context: any): Promise<BucketBundle[]> {
  const bundles = new Map<string, BucketBundle>();

  const upsert = (name: string): BucketBundle => {
    let b = bundles.get(name);
    if (!b) {
      b = { name };
      bundles.set(name, b);
    }
    return b;
  };

  for (const step of context.stepExecutions ?? []) {
    const typeStr = typeof step.modelType === "string"
      ? step.modelType
      : (step.modelType?.toString?.() ?? "");
    const isBucket = typeStr === BUCKET_TYPE;
    const isPolicy = typeStr === POLICY_TYPE;
    if (!isBucket && !isPolicy) continue;

    // Best-effort recovery: when we can't pull the bucket name out of the
    // parsed data, fall back to the step's method argument so the bucket
    // still appears in the report as an explicit failure rather than
    // silently disappearing.
    const fallbackIdent = (step.methodArgs?.identifier as string | undefined) ??
      "";
    const recordUnknown = (reason: string) => {
      if (!fallbackIdent) return;
      const b = upsert(fallbackIdent);
      if (isBucket) b.stateError ??= reason;
      if (isPolicy) b.policyError ??= reason;
    };

    for (const handle of step.dataHandles ?? []) {
      const bytes = await readDataFile(
        context,
        typeStr,
        step.modelId,
        handle.name,
        handle.version,
      );
      const parsed = decodeJson<Record<string, unknown>>(bytes);
      if (!parsed) {
        const stepLabel = `${step.jobName}.${step.stepName}`;
        context.logger.warn(
          "Could not parse {modelType} data for step {step} (handle {handle})",
          { modelType: step.modelType, step: stepLabel, handle: handle.name },
        );
        recordUnknown(
          isBucket
            ? "bucket data file missing or unparseable"
            : "bucket-policy data file missing or unparseable",
        );
        continue;
      }

      if (isBucket) {
        const stateRes = BucketStateSchema.safeParse(parsed);
        if (!stateRes.success) {
          context.logger.warn(
            "Bucket state did not match expected shape (step {step})",
            { step: `${step.jobName}.${step.stepName}` },
          );
          recordUnknown("bucket state did not match expected shape");
          continue;
        }
        const state = stateRes.data;
        const b = upsert(state.BucketName);
        b.state = state;
        if (step.status === "failed") {
          b.stateError = "bucket lookup step failed";
        }
      } else if (isPolicy) {
        const polRes = BucketPolicyStateSchema.safeParse(parsed);
        if (!polRes.success) {
          context.logger.warn(
            "Bucket-policy state did not match expected shape (step {step})",
            { step: `${step.jobName}.${step.stepName}` },
          );
          recordUnknown("bucket-policy state did not match expected shape");
          continue;
        }
        const policy = polRes.data;
        const b = upsert(policy.Bucket);
        b.policy = policy;
        if (step.status === "failed") {
          b.policyError = "bucket-policy lookup step failed";
        }
      }
    }

    // Last-resort: if the step failed AND produced no handles at all, the
    // inner loop never ran. Surface the bucket via methodArgs.identifier so
    // it doesn't silently disappear. Other failure modes (no file, unparseable
    // JSON, schema mismatch) are already recorded inside the inner loop.
    if (step.status === "failed" && (step.dataHandles?.length ?? 0) === 0) {
      recordUnknown(
        isBucket
          ? "bucket lookup step failed"
          : "bucket-policy lookup step failed",
      );
    }
  }

  return [...bundles.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function makeFinding(
  partial: Omit<Finding, "actual" | "expected" | "references"> & {
    actual?: Record<string, unknown>;
    expected?: Record<string, unknown>;
    references?: string[];
  },
): Finding {
  return {
    ...partial,
    actual: partial.actual ?? {},
    expected: partial.expected ?? {},
    references: partial.references ?? [SECURITY_S3],
  };
}

/**
 * Build a `skip`-status finding for a rule that needs `b.state` but the
 * step that should have provided it didn't (no data, parse error, or
 * step failure). Centralises the seven copies of the same boilerplate.
 */
function skipNoState(
  b: BucketBundle,
  id: string,
  severity: Severity,
): Finding {
  return makeFinding({
    id,
    severity,
    status: "skip",
    bucket: b.name,
    message: b.stateError ?? "no bucket state available",
  });
}

/** Rule: bucket-versioning-enabled. `error`, passes iff `VersioningConfiguration.Status` is `Enabled`. */
export function checkVersioning(b: BucketBundle): Finding {
  const id = "bucket-versioning-enabled";
  const severity: Severity = "error";
  if (!b.state) return skipNoState(b, id, severity);
  const status = (b.state.VersioningConfiguration as
    | { Status?: string }
    | undefined)?.Status;
  const ok = status === "Enabled";
  return makeFinding({
    id,
    severity,
    status: ok ? "pass" : "fail",
    bucket: b.name,
    actual: { Status: status ?? null },
    expected: { Status: "Enabled" },
    message: ok
      ? "Versioning is enabled."
      : `Versioning is not enabled (actual: ${status ?? "unset"}).`,
  });
}

/** Rule: bucket-encryption-enabled. `error`, passes iff a default encryption rule is configured. */
export function checkEncryption(b: BucketBundle): Finding {
  const id = "bucket-encryption-enabled";
  const severity: Severity = "error";
  if (!b.state) return skipNoState(b, id, severity);
  const rules = (b.state.BucketEncryption as
    | {
      ServerSideEncryptionConfiguration?: Array<{
        ServerSideEncryptionByDefault?: { SSEAlgorithm?: string };
      }>;
    }
    | undefined)?.ServerSideEncryptionConfiguration ?? [];
  const algs = rules
    .map((r) => r.ServerSideEncryptionByDefault?.SSEAlgorithm)
    .filter((x): x is string => typeof x === "string");
  const validAlgs = algs.filter((a) => VALID_SSE_ALGORITHMS.includes(a));
  const ok = validAlgs.length > 0;
  let message: string;
  if (ok) {
    message = `Default encryption is configured (${validAlgs.join(", ")}).`;
  } else if (algs.length > 0) {
    message = `Default encryption uses unrecognized algorithm(s): ${
      algs.join(", ")
    }.`;
  } else {
    message = "No default encryption is configured on the bucket.";
  }
  return makeFinding({
    id,
    severity,
    status: ok ? "pass" : "fail",
    bucket: b.name,
    actual: { algorithms: algs },
    expected: { algorithms: [...VALID_SSE_ALGORITHMS] },
    message,
  });
}

/** Rule: bucket-public-access-blocked. `error`, passes iff all four Block Public Access flags are true. */
export function checkPublicAccessBlock(b: BucketBundle): Finding {
  const id = "bucket-public-access-blocked";
  const severity: Severity = "error";
  if (!b.state) return skipNoState(b, id, severity);
  const bpa = b.state.PublicAccessBlockConfiguration as
    | {
      BlockPublicAcls?: boolean;
      BlockPublicPolicy?: boolean;
      IgnorePublicAcls?: boolean;
      RestrictPublicBuckets?: boolean;
    }
    | undefined;
  const allOn = !!bpa &&
    bpa.BlockPublicAcls === true &&
    bpa.BlockPublicPolicy === true &&
    bpa.IgnorePublicAcls === true &&
    bpa.RestrictPublicBuckets === true;
  return makeFinding({
    id,
    severity,
    status: allOn ? "pass" : "fail",
    bucket: b.name,
    actual: bpa ?? {},
    expected: {
      BlockPublicAcls: true,
      BlockPublicPolicy: true,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true,
    },
    message: allOn
      ? "All four Block Public Access settings are enabled."
      : "One or more Block Public Access settings are not enabled.",
  });
}

/** Rule: bucket-ownership-enforced. `error`, passes iff `OwnershipControls` selects `BucketOwnerEnforced` (ACLs disabled). */
export function checkOwnershipEnforced(b: BucketBundle): Finding {
  const id = "bucket-ownership-enforced";
  const severity: Severity = "error";
  if (!b.state) return skipNoState(b, id, severity);
  const rules = (b.state.OwnershipControls as
    | { Rules?: Array<{ ObjectOwnership?: string }> }
    | undefined)?.Rules ?? [];
  const settings = rules.map((r) => r.ObjectOwnership).filter(Boolean);
  const ok = settings.includes("BucketOwnerEnforced");
  return makeFinding({
    id,
    severity,
    status: ok ? "pass" : "fail",
    bucket: b.name,
    actual: { ObjectOwnership: settings },
    expected: { ObjectOwnership: "BucketOwnerEnforced" },
    message: ok
      ? "Object Ownership is BucketOwnerEnforced (ACLs disabled)."
      : `Object Ownership is not BucketOwnerEnforced (actual: ${
        settings.join(", ") || "unset"
      }).`,
  });
}

/**
 * Minimal IAM policy statement shape the TLS-only check evaluates. Fields are
 * optional because real-world bucket policies emit only the keys they need.
 */
export interface PolicyStatement {
  /** `Allow` or `Deny`. */
  Effect?: string;
  /** Single action or array (e.g. `s3:*`, `["s3:GetObject", "s3:PutObject"]`). */
  Action?: string | string[];
  /** Principal can be the wildcard `*`, an object like `{ AWS: "..." }`, or service-specific shapes. */
  Principal?: unknown;
  /** Single ARN or array of ARNs. */
  Resource?: string | string[];
  /** Per-operator condition map (e.g. `{ Bool: { "aws:SecureTransport": "false" } }`). */
  Condition?: Record<string, Record<string, unknown>>;
}

/**
 * Returns true if `principal` is the everyone-wildcard. Accepts the string
 * form `"*"`, the object form `{AWS: "*"}`, and the array object form
 * `{AWS: ["*"]}` (all three are legal IAM).
 */
function isPrincipalWildcard(principal: unknown): boolean {
  if (principal === "*") return true;
  if (
    principal !== null &&
    typeof principal === "object" &&
    !Array.isArray(principal)
  ) {
    const aws = (principal as Record<string, unknown>).AWS;
    if (aws === "*") return true;
    if (Array.isArray(aws) && aws.includes("*")) return true;
  }
  return false;
}

/**
 * Returns true if the Action field covers all S3 operations — either via
 * the S3-scoped wildcard `s3:*` or the all-services wildcard `*`. Both
 * forms satisfy "denies every S3 operation under the condition".
 */
function actionCoversAllS3(action: string | string[] | undefined): boolean {
  if (action === undefined) return false;
  const actions = Array.isArray(action) ? action : [action];
  return actions.some((a) => a === "s3:*" || a === "*");
}

/**
 * Returns true if the Resource field covers BOTH the bucket root ARN and
 * the bucket content ARN, across all AWS partitions (`aws`, `aws-cn`,
 * `aws-us-gov`). A plain `*` wildcard is also accepted.
 */
function resourceCoversBucket(
  resource: string | string[] | undefined,
  bucketName: string,
): boolean {
  if (resource === undefined) return false;
  const resources = Array.isArray(resource) ? resource : [resource];
  // Bare wildcard covers everything.
  if (resources.includes("*")) return true;
  // Bucket names allow dots and dashes; escape them so they're literal in
  // the regex (cheap; both are valid S3 name chars).
  const escapedName = bucketName.replace(/[.\-]/g, "\\$&");
  const rootRe = new RegExp(`^arn:aws[^:]*:s3:::${escapedName}$`);
  const contentRe = new RegExp(`^arn:aws[^:]*:s3:::${escapedName}/\\*$`);
  const hasRoot = resources.some((r) =>
    typeof r === "string" && rootRe.test(r)
  );
  const hasContent = resources.some((r) =>
    typeof r === "string" && contentRe.test(r)
  );
  return hasRoot && hasContent;
}

/**
 * Find the `aws:SecureTransport` condition value, treating the IAM
 * condition key as case-insensitive (IAM matches keys case-insensitively;
 * `aws:securetransport` and `AWS:SecureTransport` are the same condition).
 * The operator (`Bool`) IS case-sensitive in IAM.
 */
function findSecureTransportValue(
  condBool: Record<string, unknown>,
): unknown {
  const key = Object.keys(condBool).find((k) =>
    k.toLowerCase() === "aws:securetransport"
  );
  return key ? condBool[key] : undefined;
}

/**
 * Returns true when `stmt` is a properly-scoped TLS-enforcing Deny:
 *   - Effect: Deny
 *   - Principal: covers everyone (`*`, `{AWS: "*"}`, or `{AWS: ["*"]}`)
 *   - Action: covers all S3 operations (`s3:*` or `*`)
 *   - Resource: covers both the bucket root and `bucket/*` (any AWS partition)
 *   - Condition: Bool with aws:SecureTransport (case-insensitive) = false
 */
export function statementDeniesInsecureTransport(
  stmt: PolicyStatement,
  bucketName: string,
): boolean {
  if (stmt.Effect !== "Deny") return false;
  if (!isPrincipalWildcard(stmt.Principal)) return false;
  if (!actionCoversAllS3(stmt.Action)) return false;
  if (!resourceCoversBucket(stmt.Resource, bucketName)) return false;
  const condBool = stmt.Condition?.Bool;
  if (!condBool) return false;
  const value = findSecureTransportValue(condBool);
  if (value === undefined) return false;
  const flagged = Array.isArray(value)
    ? value.map((v) => String(v).toLowerCase())
    : [String(value).toLowerCase()];
  return flagged.includes("false");
}

/** Rule: bucket-tls-only-policy. `error`. Verifies the bucket policy contains a canonical TLS-enforcing Deny (see {@link statementDeniesInsecureTransport}). */
export function checkTLSOnlyPolicy(b: BucketBundle): Finding {
  const id = "bucket-tls-only-policy";
  const severity: Severity = "error";
  if (b.policyError && !b.policy?.PolicyDocument) {
    return makeFinding({
      id,
      severity,
      status: "fail",
      bucket: b.name,
      actual: { policy: null, error: b.policyError },
      expected: {
        statement:
          "Deny on aws:SecureTransport=false (TLS-only access enforced).",
      },
      message:
        "No bucket policy attached or policy lookup failed; TLS-only access cannot be enforced.",
    });
  }
  const raw = b.policy?.PolicyDocument;
  if (raw === undefined || raw === null || raw === "") {
    return makeFinding({
      id,
      severity,
      status: "fail",
      bucket: b.name,
      actual: { policy: null },
      expected: {
        statement:
          "Deny on aws:SecureTransport=false (TLS-only access enforced).",
      },
      message: "No bucket policy attached; TLS-only access cannot be enforced.",
    });
  }
  let doc: { Statement?: PolicyStatement | PolicyStatement[] };
  if (typeof raw === "string") {
    try {
      doc = JSON.parse(raw);
    } catch {
      return makeFinding({
        id,
        severity,
        status: "skip",
        bucket: b.name,
        actual: { policy: "<unparseable>" },
        expected: {
          statement:
            "Deny on aws:SecureTransport=false (TLS-only access enforced).",
        },
        message: "Bucket policy is not valid JSON; cannot evaluate.",
      });
    }
  } else {
    doc = raw as { Statement?: PolicyStatement | PolicyStatement[] };
  }
  const stmts = Array.isArray(doc.Statement)
    ? doc.Statement
    : doc.Statement
    ? [doc.Statement]
    : [];
  const ok = stmts.some((s) => statementDeniesInsecureTransport(s, b.name));
  return makeFinding({
    id,
    severity,
    status: ok ? "pass" : "fail",
    bucket: b.name,
    actual: { statementsEvaluated: stmts.length, secureTransportDeny: ok },
    expected: {
      statement:
        "Deny on aws:SecureTransport=false (TLS-only access enforced).",
    },
    message: ok
      ? "Bucket policy denies non-TLS access."
      : "Bucket policy does not include a Deny on aws:SecureTransport=false.",
  });
}

/** Rule: bucket-lifecycle-expires-noncurrent-versions. `warn`. Passes when at least one enabled lifecycle rule expires noncurrent versions. */
export function checkLifecycleExpiresNoncurrent(b: BucketBundle): Finding {
  const id = "bucket-lifecycle-expires-noncurrent-versions";
  const severity: Severity = "warn";
  if (!b.state) return skipNoState(b, id, severity);
  const rules = (b.state.LifecycleConfiguration as
    | {
      Rules?: Array<{
        Status?: string;
        NoncurrentVersionExpiration?: { NoncurrentDays?: number };
        NoncurrentVersionExpirationInDays?: number;
      }>;
    }
    | undefined)?.Rules ?? [];
  const matching = rules.filter((r) =>
    r.Status === "Enabled" &&
    (r.NoncurrentVersionExpiration?.NoncurrentDays !== undefined ||
      r.NoncurrentVersionExpirationInDays !== undefined)
  );
  const ok = matching.length > 0;
  return makeFinding({
    id,
    severity,
    status: ok ? "pass" : "warn",
    bucket: b.name,
    actual: { matchingRules: matching.length, totalRules: rules.length },
    expected: { hasNoncurrentVersionExpiration: true },
    message: ok
      ? `Found ${matching.length} enabled lifecycle rule(s) that expire noncurrent versions.`
      : "No enabled lifecycle rule expires noncurrent versions; stale versions may accumulate.",
  });
}

/** Rule: bucket-server-access-logging. `warn`. Logging must be enabled and the destination must differ from the source bucket. */
export function checkServerAccessLogging(b: BucketBundle): Finding {
  const id = "bucket-server-access-logging";
  const severity: Severity = "warn";
  if (!b.state) return skipNoState(b, id, severity);
  const cfg = b.state.LoggingConfiguration as
    | { DestinationBucketName?: string; LogFilePrefix?: string }
    | undefined;
  const dest = cfg?.DestinationBucketName ?? "";
  const enabled = dest.length > 0;
  const separate = enabled && dest !== b.name;
  let status: Status;
  let message: string;
  if (!enabled) {
    status = "warn";
    message = "Server access logging is not configured.";
  } else if (!separate) {
    status = "warn";
    message =
      "Server access logging targets the same bucket; use a separate log bucket.";
  } else {
    status = "pass";
    message = `Server access logging is enabled (destination: ${dest}).`;
  }
  return makeFinding({
    id,
    severity,
    status,
    bucket: b.name,
    actual: {
      DestinationBucketName: dest || null,
      LogFilePrefix: cfg?.LogFilePrefix ?? null,
    },
    expected: { DestinationBucketName: "<separate log bucket>" },
    message,
  });
}

/** Rule: bucket-tag-inventory. `info`. Reports tag presence; emits a `warn` status when there are no tags. */
export function inventoryTags(b: BucketBundle): Finding {
  const id = "bucket-tag-inventory";
  const severity: Severity = "info";
  if (!b.state) return skipNoState(b, id, severity);
  const tags =
    (b.state.Tags as Array<{ Key?: string; Value?: string }> | undefined) ??
      [];
  const flat = tags.reduce<Record<string, string>>((acc, t) => {
    if (typeof t.Key === "string") acc[t.Key] = t.Value ?? "";
    return acc;
  }, {});
  return makeFinding({
    id,
    severity,
    status: tags.length > 0 ? "pass" : "warn",
    bucket: b.name,
    actual: { tagCount: tags.length, tags: flat },
    expected: { tags: "any (informational)" },
    message: tags.length > 0
      ? `Bucket has ${tags.length} tag(s).`
      : "Bucket has no tags.",
  });
}

const RULES: Array<(b: BucketBundle) => Finding> = [
  checkVersioning,
  checkEncryption,
  checkPublicAccessBlock,
  checkOwnershipEnforced,
  checkTLSOnlyPolicy,
  // bucket-dynamodb-lock-table — reserved id, deferred to v1.1 (lives in .tf backend).
  checkLifecycleExpiresNoncurrent,
  checkServerAccessLogging,
  inventoryTags,
];

interface Summary {
  buckets: number;
  pass: number;
  fail: number;
  warn: number;
  skip: number;
  errors: number;
  warns: number;
  infos: number;
}

/**
 * Severity threshold for the `failOn` gate.
 *
 *   none   never throws (report-only mode)
 *   error  throws if any error-severity finding is fail or warn (default)
 *   warn   throws if any error-or-warn-severity finding is fail or warn
 *   info   throws if any finding is fail or warn
 *
 * Reads `S3_BUCKET_AUDIT_FAILON` env var; defaults to "error". Reports run
 * as part of a workflow, and a thrown error fails the workflow run — callers
 * that want report-only behavior set `S3_BUCKET_AUDIT_FAILON=none`.
 */
export type FailOnThreshold = "none" | "error" | "warn" | "info";

const SEVERITY_RANK: Record<Severity, number> = { error: 3, warn: 2, info: 1 };
const THRESHOLD_RANK: Record<FailOnThreshold, number> = {
  none: Number.POSITIVE_INFINITY,
  error: 3,
  warn: 2,
  info: 1,
};

/** Parse the `S3_BUCKET_AUDIT_FAILON` env value to a {@link FailOnThreshold}. Defaults to `error` for unset/garbage input. */
export function parseFailOnThreshold(raw: string | undefined): FailOnThreshold {
  const value = (raw ?? "error").trim().toLowerCase();
  if (
    value === "none" || value === "error" || value === "warn" ||
    value === "info"
  ) {
    return value;
  }
  return "error";
}

/** Filter `findings` down to those that cross the given severity threshold. `none` always returns empty. */
export function findGateTrippers(
  findings: Finding[],
  threshold: FailOnThreshold,
): Finding[] {
  if (threshold === "none") return [];
  const min = THRESHOLD_RANK[threshold];
  return findings.filter((f) =>
    (f.status === "fail" || f.status === "warn") &&
    SEVERITY_RANK[f.severity] >= min
  );
}

function summarize(findings: Finding[], bucketCount: number): Summary {
  const s: Summary = {
    buckets: bucketCount,
    pass: 0,
    fail: 0,
    warn: 0,
    skip: 0,
    errors: 0,
    warns: 0,
    infos: 0,
  };
  for (const f of findings) {
    s[f.status]++;
    if (f.severity === "error") s.errors++;
    else if (f.severity === "warn") s.warns++;
    else s.infos++;
  }
  return s;
}

function statusGlyph(status: Status): string {
  switch (status) {
    case "pass":
      return "PASS";
    case "fail":
      return "FAIL";
    case "warn":
      return "WARN";
    case "skip":
      return "SKIP";
  }
}

function renderMarkdown(
  workflowName: string,
  buckets: Array<{ name: string; findings: Finding[] }>,
  summary: Summary,
): string {
  const lines: string[] = [];
  lines.push(`# S3 Bucket Audit — ${workflowName}`);
  lines.push("");
  lines.push(`- Buckets audited: ${summary.buckets}`);
  lines.push(
    `- Findings: ${summary.fail} fail · ${summary.warn} warn · ${summary.skip} skip · ${summary.pass} pass`,
  );
  lines.push(
    `- By severity: ${summary.errors} error · ${summary.warns} warn · ${summary.infos} info`,
  );
  lines.push("");

  if (buckets.length === 0) {
    lines.push("_No S3 bucket data was found in the workflow run._");
    lines.push("");
    return lines.join("\n");
  }

  for (const b of buckets) {
    lines.push(`## Bucket: \`${b.name}\``);
    lines.push("");
    lines.push("| Check | Severity | Status | Message |");
    lines.push("| --- | --- | --- | --- |");
    for (const f of b.findings) {
      const msg = f.message.replace(/\|/g, "\\|");
      lines.push(
        `| ${f.id} | ${f.severity} | ${statusGlyph(f.status)} | ${msg} |`,
      );
    }
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * The `@jentz/aws-s3-bucket-audit` workflow-scope report. Runs once after
 * all workflow steps complete, collects `@swamp/aws/s3/bucket` and
 * `@swamp/aws/s3/bucket-policy` data, applies eight rules per bucket, and
 * emits markdown plus JSON (including a `failOn` gate). Never throws —
 * missing or unparseable data becomes `skip`-status findings.
 */
export const report = {
  name: "@jentz/aws-s3-bucket-audit",
  description:
    "Audit S3 buckets against standard security best practices (versioning, encryption, public-access block, ownership, TLS-only policy, lifecycle, logging) plus tag inventory. Operates on bucket state and bucket-policy data produced earlier in the workflow.",
  scope: "workflow" as const,
  labels: ["security", "s3", "audit"],
  // deno-lint-ignore no-explicit-any
  execute: async (context: any) => {
    const workflowName = context.workflowName ?? "<unknown-workflow>";
    context.logger.info(
      "Running S3 bucket audit for workflow {workflow}",
      { workflow: workflowName },
    );

    const bundles = await collectBundles(context);

    const buckets: Array<{ name: string; findings: Finding[] }> = [];
    const flatFindings: Finding[] = [];

    for (const bundle of bundles) {
      const findings = RULES.map((rule) => rule(bundle));
      buckets.push({ name: bundle.name, findings });
      flatFindings.push(...findings);
    }

    const summary = summarize(flatFindings, bundles.length);

    context.logger.info(
      "S3 bucket audit produced findings for {buckets} bucket(s): {fail} fail, {warn} warn, {skip} skip, {pass} pass",
      {
        buckets: summary.buckets,
        fail: summary.fail,
        warn: summary.warn,
        skip: summary.skip,
        pass: summary.pass,
      },
    );

    // failOn is advisory inside the report — swamp catches and logs thrown
    // report errors but does not fail the workflow run, and on a throw the
    // report's data is not persisted. So we surface gate state in the JSON
    // and log a clear warning; the shell helper bin/audit-gate.sh reads this
    // and exits non-zero for CI/script integration.
    const threshold = parseFailOnThreshold(
      Deno.env.get("S3_BUCKET_AUDIT_FAILON"),
    );
    const trippers = findGateTrippers(flatFindings, threshold);

    if (trippers.length > 0) {
      const sample = trippers.slice(0, 5).map((f) =>
        `${f.bucket}:${f.id} (${f.severity}/${f.status})`
      );
      const more = trippers.length > 5 ? ` + ${trippers.length - 5} more` : "";
      context.logger.warn(
        "S3 bucket audit gate tripped (failOn={threshold}): {count} finding(s) at/above threshold — {sample}{more}. Run bin/audit-gate.sh after `swamp workflow run` for a non-zero exit.",
        {
          threshold,
          count: trippers.length,
          sample: sample.join("; "),
          more,
        },
      );
    }

    return {
      markdown: renderMarkdown(workflowName, buckets, summary),
      json: {
        report: "@jentz/aws-s3-bucket-audit",
        workflow: workflowName,
        generatedAt: new Date().toISOString(),
        failOn: threshold,
        gateTripped: trippers.length > 0,
        tripperCount: trippers.length,
        trippers: trippers.map((f) => ({
          bucket: f.bucket,
          id: f.id,
          severity: f.severity,
          status: f.status,
        })),
        summary,
        buckets,
        findings: flatFindings,
      },
    };
  },
};
