/**
 * Unit tests for `@jentz/aws-default-sg-audit`.
 *
 * Two layers:
 *
 *   1. Pure helpers — exercised without any swamp context. The
 *      `classifyError` block is intentionally heavy: it locks in the regression
 *      where an SSO **role ARN** in an unrelated `AccessDenied` message would
 *      misclassify the error as `auth_expired`.
 *   2. `runScan` integration paths — driven through `createModelTestContext`
 *      with a hand-rolled `AwsApi` replay so the SDK is never touched. Asserts
 *      what was written, in which order, and that per-target / per-region
 *      failures degrade to recorded errors rather than aborted sweeps.
 *
 * @module
 */

import { assertEquals, assertNotEquals } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260525.18";
import {
  type AwsApi,
  type AwsNetworkInterface,
  type AwsSecurityGroup,
  type AwsVpc,
  classifyEni,
  classifyError,
  deriveVerdict,
  findingKey,
  resolveBootstrapRegion,
  runScan,
  scanErrorKey,
  type ScanTarget,
  tagsFromAws,
} from "../aws_default_sg_audit.ts";

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

Deno.test("tagsFromAws: undefined input becomes empty map", () => {
  assertEquals(tagsFromAws(undefined), {});
});

Deno.test("tagsFromAws: drops tags with no Key, defaults missing Value to ''", () => {
  const out = tagsFromAws([
    { Key: "team", Value: "fullstack" },
    { Value: "orphan" }, // no Key
    { Key: "no-value" }, // no Value
    { Key: "", Value: "empty-key" }, // empty Key
  ]);
  assertEquals(out, { team: "fullstack", "no-value": "" });
});

Deno.test("classifyEni: amazon-* requester wins over interface type", () => {
  assertEquals(
    classifyEni("amazon-elasticache", "interface", ""),
    "amazon-elasticache",
  );
  assertEquals(classifyEni("amazon-elb", "interface", "i-1"), "amazon-elb");
});

Deno.test("classifyEni: non-'interface' AWS interface types are used as the category", () => {
  assertEquals(classifyEni(undefined, "nat_gateway", ""), "nat_gateway");
  assertEquals(classifyEni("", "vpc_endpoint", ""), "vpc_endpoint");
});

Deno.test("classifyEni: bare 'interface' attached to an instance is reported as ec2-instance", () => {
  assertEquals(classifyEni(undefined, "interface", "i-0abc"), "ec2-instance");
});

Deno.test("classifyEni: bare 'interface' with no attachment stays 'interface'", () => {
  assertEquals(classifyEni(undefined, "interface", ""), "interface");
  assertEquals(classifyEni(undefined, undefined, ""), "interface");
});

Deno.test("deriveVerdict: compliant = no action regardless of ENIs", () => {
  assertEquals(deriveVerdict(true, 0), "compliant");
  assertEquals(deriveVerdict(true, 7), "compliant");
});

Deno.test("deriveVerdict: non-compliant + zero ENIs is safe_to_remediate", () => {
  assertEquals(deriveVerdict(false, 0), "safe_to_remediate");
});

Deno.test("deriveVerdict: non-compliant + ENIs is in_use_needs_migration", () => {
  assertEquals(deriveVerdict(false, 1), "in_use_needs_migration");
  assertEquals(deriveVerdict(false, 42), "in_use_needs_migration");
});

// classifyError — the regression bed.

Deno.test("classifyError: SSO role ARN in unrelated AccessDenied does NOT trip auth_expired (regression)", () => {
  // This is the exact shape that misfired before the fix: the message has
  // `AWSReservedSSO_<…>` substring but the failure is an SCP region deny, not
  // a token expiry. Must classify as access_denied so the operator doesn't
  // get sent to run `aws sso login` for nothing.
  const err = new Error(
    "You are not authorized to perform this operation. User: " +
      "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_ReadOnlyAccess_abc123/alice@example.com " +
      "is not authorized to perform: ec2:DescribeSecurityGroups with an " +
      "explicit deny in a service control policy: arn:aws:organizations::...",
  );
  (err as { name?: string }).name = "UnauthorizedOperation";
  assertEquals(classifyError(err).kind, "access_denied");
});

Deno.test("classifyError: access_denied wins when a message matches BOTH access-denied and expiry signals (precedence regression)", () => {
  // Trips BOTH predicates at once: the name yields "accessdenied" and the
  // message carries "not authorized" (access-denied) while also containing
  // "sso session" and "token has expired" (auth-expired). Access-denied must
  // win. If the returns are reordered to auth-expired first, this flips to
  // "auth_expired" and the test goes red — pinning the precedence with teeth.
  const err = Object.assign(
    new Error(
      "User is not authorized to perform ec2:DescribeSecurityGroups; the sso session token has expired",
    ),
    { name: "AccessDeniedException" },
  );
  assertEquals(classifyError(err).kind, "access_denied");
});

Deno.test("classifyError: real expired-token signals are auth_expired", () => {
  const expired = new Error(
    "The security token included in the request is expired",
  );
  (expired as { name?: string }).name = "ExpiredTokenException";
  assertEquals(classifyError(expired).kind, "auth_expired");

  const sso = new Error("SSO session associated with this profile has expired");
  assertEquals(classifyError(sso).kind, "auth_expired");

  const refresh = new Error("Failed to refresh credentials");
  assertEquals(classifyError(refresh).kind, "auth_expired");
});

Deno.test("classifyError: plain IAM AccessDenied is access_denied", () => {
  const err = new Error(
    "AccessDenied: not authorized to perform ec2:DescribeVpcs",
  );
  assertEquals(classifyError(err).kind, "access_denied");
});

Deno.test("classifyError: unknown failures fall through to 'other'", () => {
  assertEquals(
    classifyError(new Error("connection reset by peer")).kind,
    "other",
  );
  assertEquals(classifyError("string error").kind, "other");
});

Deno.test("classifyError: message is preserved verbatim for the report", () => {
  const err = new Error("specific upstream message");
  assertEquals(classifyError(err).message, "specific upstream message");
});

Deno.test("resolveBootstrapRegion: first configured region wins", () => {
  const env = (_: string) => undefined;
  assertEquals(
    resolveBootstrapRegion(["eu-west-1", "us-east-1"], env),
    "eu-west-1",
  );
});

Deno.test("resolveBootstrapRegion: env chain when no regions configured", () => {
  const env = (n: string) => n === "AWS_REGION" ? "eu-north-1" : undefined;
  assertEquals(resolveBootstrapRegion([], env), "eu-north-1");

  const envDefault = (n: string) =>
    n === "AWS_DEFAULT_REGION" ? "eu-central-1" : undefined;
  assertEquals(resolveBootstrapRegion([], envDefault), "eu-central-1");
});

Deno.test("resolveBootstrapRegion: us-east-1 final fallback when nothing is set", () => {
  assertEquals(resolveBootstrapRegion([], () => undefined), "us-east-1");
});

Deno.test("resolveBootstrapRegion: whitespace-only values are treated as unset", () => {
  const env = (n: string) =>
    n === "AWS_REGION"
      ? "   "
      : n === "AWS_DEFAULT_REGION"
      ? "eu-west-1"
      : undefined;
  assertEquals(resolveBootstrapRegion([], env), "eu-west-1");
});

Deno.test("findingKey: stable and unique across (account, region, sg)", () => {
  const a = findingKey("111111111111", "eu-west-1", "sg-aaa");
  const b = findingKey("111111111111", "eu-west-1", "sg-bbb");
  const c = findingKey("222222222222", "eu-west-1", "sg-aaa");
  assertEquals(a, "finding-111111111111-eu-west-1-sg-aaa");
  assertNotEquals(a, b);
  assertNotEquals(a, c);
});

Deno.test("scanErrorKey: ambient and account-level fallbacks", () => {
  assertEquals(
    scanErrorKey("", "", "credentials"),
    "error-ambient-account-credentials",
  );
  assertEquals(
    scanErrorKey("acct-readonly", "eu-west-1", "describe_security_groups"),
    "error-acct-readonly-eu-west-1-describe_security_groups",
  );
});

// ---------------------------------------------------------------------------
// runScan — integration via createModelTestContext + injected AwsApi
// ---------------------------------------------------------------------------

/** Per-region spec for {@link fakeApi}. Any field omitted yields an empty list. */
interface RegionSpec {
  /** Default SGs returned for `describeDefaultSecurityGroups(region)`. */
  sgs?: AwsSecurityGroup[];
  /** Replace the SGs call with a throw — simulates `access_denied` / SCP. */
  sgsError?: Error;
  /** VPCs returned for `describeVpcs(region, ids)`; lookups are by `VpcId`. */
  vpcs?: AwsVpc[];
  /** Replace the VPCs call with a throw. */
  vpcsError?: Error;
  /** ENIs keyed by `groupId`; missing keys resolve to `[]`. */
  enisByGroup?: Record<string, AwsNetworkInterface[]>;
  /** Replace the ENIs call with a throw. */
  enisError?: Error;
}

/** Full replay spec for {@link fakeApi}. */
interface FakeSpec {
  /** Account id returned by `sts:GetCallerIdentity`. */
  accountId?: string;
  /** Replace `getAccountId` with a throw — simulates expired credentials. */
  accountIdError?: Error;
  /** Regions returned by `ec2:DescribeRegions(AllRegions=false)`. */
  enabledRegions?: string[];
  /** Replace `describeEnabledRegions` with a throw. */
  enabledRegionsError?: Error;
  /** Per-region behaviour. */
  perRegion?: Record<string, RegionSpec>;
}

function fakeApi(spec: FakeSpec): AwsApi {
  return {
    getAccountId: () =>
      spec.accountIdError
        ? Promise.reject(spec.accountIdError)
        : Promise.resolve(spec.accountId ?? "000000000000"),
    describeEnabledRegions: () =>
      spec.enabledRegionsError
        ? Promise.reject(spec.enabledRegionsError)
        : Promise.resolve(spec.enabledRegions ?? []),
    describeDefaultSecurityGroups: (region) => {
      const r = spec.perRegion?.[region];
      if (r?.sgsError) return Promise.reject(r.sgsError);
      return Promise.resolve(r?.sgs ?? []);
    },
    describeVpcs: (region, ids) => {
      const r = spec.perRegion?.[region];
      if (r?.vpcsError) return Promise.reject(r.vpcsError);
      const wanted = new Set(ids);
      return Promise.resolve(
        (r?.vpcs ?? []).filter((v) => v.VpcId && wanted.has(v.VpcId)),
      );
    },
    describeEnisForGroup: (region, groupId) => {
      const r = spec.perRegion?.[region];
      if (r?.enisError) return Promise.reject(r.enisError);
      return Promise.resolve(r?.enisByGroup?.[groupId] ?? []);
    },
  };
}

/** Build a `ScanTarget` over `fakeApi(spec)` for `profile`. */
function target(profile: string, spec: FakeSpec): ScanTarget {
  return { profile, api: fakeApi(spec) };
}

// ---- happy path ------------------------------------------------------------

Deno.test("runScan: happy path writes one finding per default SG with correct verdicts", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });

  const safeSg: AwsSecurityGroup = {
    GroupId: "sg-safe",
    GroupName: "default",
    VpcId: "vpc-1",
    IpPermissions: [{}], // 1 ingress rule
    IpPermissionsEgress: [{}], // 1 egress rule
  };
  const inUseSg: AwsSecurityGroup = {
    GroupId: "sg-inuse",
    GroupName: "default",
    VpcId: "vpc-2",
    IpPermissions: [{}],
    IpPermissionsEgress: [{}],
  };

  const result = await runScan({
    targets: [target("", {
      accountId: "111111111111",
      perRegion: {
        "eu-west-1": {
          sgs: [safeSg, inUseSg],
          vpcs: [
            {
              VpcId: "vpc-1",
              IsDefault: false,
              Tags: [{ Key: "Name", Value: "safe-vpc" }],
            },
            {
              VpcId: "vpc-2",
              IsDefault: false,
              Tags: [
                { Key: "Name", Value: "redis-vpc" },
                { Key: "team", Value: "fullstack" },
              ],
            },
          ],
          enisByGroup: {
            "sg-inuse": [{
              NetworkInterfaceId: "eni-1",
              InterfaceType: "interface",
              Description: "ElastiCache redis-test",
              RequesterId: "amazon-elasticache",
              RequesterManaged: true,
            }],
          },
        },
      },
    })],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context,
  });

  assertEquals(result.findingCount, 2);
  assertEquals(result.errorCount, 0);

  const written = getWrittenResources();
  const findings = written.filter((w) => w.specName === "finding").map((w) =>
    w.data
  );
  assertEquals(findings.length, 2);

  const byId = new Map(
    findings.map((f) => [(f as { defaultSgId: string }).defaultSgId, f]),
  );

  const safe = byId.get("sg-safe") as Record<string, unknown>;
  assertEquals(safe.verdict, "safe_to_remediate");
  assertEquals(safe.eniCount, 0);
  assertEquals(safe.vpcName, "safe-vpc");
  assertEquals(safe.compliant, false);

  const inUse = byId.get("sg-inuse") as Record<string, unknown>;
  assertEquals(inUse.verdict, "in_use_needs_migration");
  assertEquals(inUse.eniCount, 1);
  assertEquals(inUse.vpcName, "redis-vpc");
  assertEquals((inUse.vpcTags as Record<string, string>).team, "fullstack");
  const inUseEnis = inUse.enis as Array<{ category: string }>;
  assertEquals(inUseEnis[0].category, "amazon-elasticache");
});

Deno.test("runScan: compliant default SG (no rules) is emitted with verdict=compliant", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  await runScan({
    targets: [target("", {
      accountId: "111111111111",
      perRegion: {
        "eu-west-1": {
          sgs: [{
            GroupId: "sg-clean",
            GroupName: "default",
            VpcId: "vpc-1",
            IpPermissions: [],
            IpPermissionsEgress: [],
          }],
          vpcs: [{ VpcId: "vpc-1", IsDefault: true, Tags: [] }],
          enisByGroup: {},
        },
      },
    })],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context,
  });
  const f = getWrittenResources()[0].data as Record<string, unknown>;
  assertEquals(f.compliant, true);
  assertEquals(f.verdict, "compliant");
  assertEquals(f.vpcIsDefault, true);
});

Deno.test("runScan: region with no default SGs writes nothing", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const result = await runScan({
    targets: [target("", {
      accountId: "111111111111",
      perRegion: { "eu-west-1": { sgs: [] } },
    })],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context,
  });
  assertEquals(result.findingCount, 0);
  assertEquals(result.errorCount, 0);
  assertEquals(getWrittenResources().length, 0);
});

// ---- failure paths ---------------------------------------------------------

Deno.test("runScan: credential failure writes one scan_error and skips the account", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const expired = new Error(
    "The security token included in the request is expired",
  );
  (expired as { name?: string }).name = "ExpiredTokenException";

  const result = await runScan({
    targets: [
      target("acct-a-readonly", { accountIdError: expired }),
      target("acct-b-readonly", {
        accountId: "222222222222",
        perRegion: { "eu-west-1": { sgs: [] } },
      }),
    ],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context,
  });

  assertEquals(result.findingCount, 0);
  assertEquals(result.errorCount, 1);
  const written = getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "scan_error");
  const err = written[0].data as Record<string, unknown>;
  assertEquals(err.profile, "acct-a-readonly");
  assertEquals(err.phase, "credentials");
  assertEquals(err.kind, "auth_expired");
});

Deno.test("runScan: per-region access_denied is recorded but other regions still scanned", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const denied = new Error(
    "You are not authorized to perform this operation. explicit deny in a service control policy",
  );
  (denied as { name?: string }).name = "UnauthorizedOperation";

  await runScan({
    targets: [target("", {
      accountId: "111111111111",
      perRegion: {
        "eu-west-2": { sgsError: denied },
        "eu-west-1": {
          sgs: [{
            GroupId: "sg-a",
            GroupName: "default",
            VpcId: "vpc-1",
            IpPermissions: [{}],
            IpPermissionsEgress: [{}],
          }],
          vpcs: [{ VpcId: "vpc-1", Tags: [] }],
        },
      },
    })],
    configuredRegions: ["eu-west-2", "eu-west-1"],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context,
  });

  const written = getWrittenResources();
  assertEquals(written.length, 2);
  const err = written.find((w) => w.specName === "scan_error")?.data as Record<
    string,
    unknown
  >;
  assertEquals(err.region, "eu-west-2");
  assertEquals(err.kind, "access_denied");
  const finding = written.find((w) => w.specName === "finding")?.data as Record<
    string,
    unknown
  >;
  assertEquals(finding.region, "eu-west-1");
  assertEquals(finding.defaultSgId, "sg-a");
});

Deno.test("runScan: auto-discovers regions when configuredRegions is empty", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  await runScan({
    targets: [target("", {
      accountId: "111111111111",
      enabledRegions: ["eu-west-1", "us-east-1"],
      perRegion: {
        "eu-west-1": {
          sgs: [{
            GroupId: "sg-eu",
            GroupName: "default",
            VpcId: "vpc-eu",
            IpPermissions: [{}],
            IpPermissionsEgress: [{}],
          }],
          vpcs: [{ VpcId: "vpc-eu", Tags: [] }],
        },
        "us-east-1": { sgs: [] },
      },
    })],
    configuredRegions: [],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context,
  });
  const findings = getWrittenResources().filter((w) =>
    w.specName === "finding"
  );
  assertEquals(findings.length, 1);
  assertEquals(
    (findings[0].data as Record<string, unknown>).region,
    "eu-west-1",
  );
});

Deno.test("runScan: describe_regions failure records a single error and skips the account", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  await runScan({
    targets: [target("", {
      accountId: "111111111111",
      enabledRegionsError: new Error("AccessDenied for ec2:DescribeRegions"),
    })],
    configuredRegions: [],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context,
  });
  const written = getWrittenResources();
  assertEquals(written.length, 1);
  const err = written[0].data as Record<string, unknown>;
  assertEquals(err.phase, "describe_regions");
  assertEquals(err.kind, "access_denied");
  assertEquals(err.accountId, "111111111111"); // creds resolved first
});

Deno.test("runScan: requiredProfileSuffix mismatch skips the profile before any AWS call", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  // Spy: if the API is called, this throws — proves no call happened.
  const tripwire: AwsApi = {
    getAccountId: () => Promise.reject(new Error("must not call")),
    describeEnabledRegions: () => Promise.reject(new Error("must not call")),
    describeDefaultSecurityGroups: () =>
      Promise.reject(new Error("must not call")),
    describeVpcs: () => Promise.reject(new Error("must not call")),
    describeEnisForGroup: () => Promise.reject(new Error("must not call")),
  };
  await runScan({
    targets: [{ profile: "ops-admin", api: tripwire }],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "-readonly",
    ambientProfile: "",
    context,
  });
  const written = getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written[0].specName, "scan_error");
  const err = written[0].data as Record<string, unknown>;
  assertEquals(err.phase, "profile_suffix_check");
});

Deno.test("runScan: ambient target whose AWS_PROFILE matches the suffix is NOT refused", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const result = await runScan({
    // Ambient target — no profile label. The suffix gate falls back to the
    // ambient AWS_PROFILE, which DOES end with the suffix, so the sweep runs.
    targets: [target("", {
      accountId: "111111111111",
      perRegion: { "eu-west-1": { sgs: [] } },
    })],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "-readonly",
    ambientProfile: "prod-platform-readonly",
    context,
  });
  assertEquals(result.findingCount, 0);
  const suffixErrs = getWrittenResources().filter((w) =>
    w.specName === "scan_error" &&
    (w.data as Record<string, unknown>).phase === "profile_suffix_check"
  );
  assertEquals(suffixErrs.length, 0);
  assertEquals(result.errorCount, 0);
});

Deno.test("runScan: ambient target with no AWS_PROFILE is refused (fail-closed) when a suffix is required", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const result = await runScan({
    targets: [target("", {
      accountId: "111111111111",
      perRegion: { "eu-west-1": { sgs: [] } },
    })],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "-readonly",
    ambientProfile: "", // AWS_PROFILE unset
    context,
  });
  assertEquals(result.findingCount, 0);
  assertEquals(result.errorCount, 1);
  const written = getWrittenResources();
  assertEquals(written.length, 1);
  const err = written[0].data as Record<string, unknown>;
  assertEquals(err.phase, "profile_suffix_check");
  // AWS_PROFILE is used only for the gate, never leaked into the resource.
  assertEquals(err.profile, "");
});

Deno.test("runScan: stable keys make re-runs idempotent (same key, same content)", async () => {
  const ctxA = createModelTestContext({});
  const ctxB = createModelTestContext({});
  const spec: FakeSpec = {
    accountId: "111111111111",
    perRegion: {
      "eu-west-1": {
        sgs: [{
          GroupId: "sg-a",
          GroupName: "default",
          VpcId: "vpc-1",
          IpPermissions: [{}],
          IpPermissionsEgress: [],
        }],
        vpcs: [{ VpcId: "vpc-1", Tags: [] }],
      },
    },
  };
  await runScan({
    targets: [target("", spec)],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context: ctxA.context,
  });
  await runScan({
    targets: [target("", spec)],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context: ctxB.context,
  });
  const nameA = ctxA.getWrittenResources()[0].name;
  const nameB = ctxB.getWrittenResources()[0].name;
  assertEquals(nameA, nameB);
  assertEquals(nameA, "finding-111111111111-eu-west-1-sg-a");
});
