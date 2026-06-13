/**
 * Unit tests for `@jentz/aws-vpc-inventory`.
 *
 * Two layers:
 *
 *   1. Pure helpers — exercised without any swamp context. The
 *      `classifyError` block keeps the SSO-role-ARN regression locked in
 *      (the same shape the default-sg-audit guards against). The
 *      `collectCidrBlocks` block pins down secondary-CIDR handling and
 *      state filtering.
 *   2. `runScan` integration paths — driven through `createModelTestContext`
 *      with a hand-rolled `AwsApi` replay so the SDK is never touched.
 *      Verifies the shape of `vpc` rows (account name derivation,
 *      shared-VPC flagging, CIDR collection) and that per-target /
 *      per-region failures degrade to recorded errors rather than
 *      aborted sweeps.
 *
 * @module
 */

import { assertEquals, assertNotEquals } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260525.18";
import {
  accountNameFromProfile,
  type AwsApi,
  type AwsVpc,
  classifyError,
  collectCidrBlocks,
  resolveBootstrapRegion,
  runScan,
  scanErrorKey,
  type ScanTarget,
  tagsFromAws,
  vpcKey,
} from "../aws_vpc_inventory.ts";

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

Deno.test("tagsFromAws: undefined input becomes empty map", () => {
  assertEquals(tagsFromAws(undefined), {});
});

Deno.test("tagsFromAws: drops tags with no Key, defaults missing Value to ''", () => {
  const out = tagsFromAws([
    { Key: "team", Value: "fullstack" },
    { Value: "orphan" },
    { Key: "no-value" },
    { Key: "", Value: "empty-key" },
  ]);
  assertEquals(out, { team: "fullstack", "no-value": "" });
});

Deno.test("accountNameFromProfile: strips matching suffix", () => {
  assertEquals(
    accountNameFromProfile("prod-platform-readonly", "-readonly"),
    "prod-platform",
  );
});

Deno.test("accountNameFromProfile: returns profile unchanged when suffix does not match", () => {
  assertEquals(
    accountNameFromProfile("prod-platform-admin", "-readonly"),
    "prod-platform-admin",
  );
});

Deno.test("accountNameFromProfile: empty profile (ambient) yields empty name", () => {
  assertEquals(accountNameFromProfile("", "-readonly"), "");
});

Deno.test("accountNameFromProfile: empty suffix is a no-op", () => {
  assertEquals(
    accountNameFromProfile("anything-goes", ""),
    "anything-goes",
  );
});

// collectCidrBlocks — CIDR collection rules.

Deno.test("collectCidrBlocks: primary CIDR alone, no associations", () => {
  assertEquals(collectCidrBlocks({ CidrBlock: "10.0.0.0/16" }), [
    "10.0.0.0/16",
  ]);
});

Deno.test("collectCidrBlocks: includes secondary associations in 'associated' state, primary first", () => {
  const vpc: AwsVpc = {
    CidrBlock: "10.0.0.0/16",
    CidrBlockAssociationSet: [
      {
        CidrBlock: "10.0.0.0/16",
        CidrBlockState: { State: "associated" },
      },
      {
        CidrBlock: "10.1.0.0/16",
        CidrBlockState: { State: "associated" },
      },
      {
        CidrBlock: "10.2.0.0/16",
        CidrBlockState: { State: "associated" },
      },
    ],
  };
  // Primary first, dedupe the echoed primary, preserve association order.
  assertEquals(collectCidrBlocks(vpc), [
    "10.0.0.0/16",
    "10.1.0.0/16",
    "10.2.0.0/16",
  ]);
});

Deno.test("collectCidrBlocks: skips associations not in 'associated' state", () => {
  const vpc: AwsVpc = {
    CidrBlock: "10.0.0.0/16",
    CidrBlockAssociationSet: [
      {
        CidrBlock: "10.1.0.0/16",
        CidrBlockState: { State: "associating" },
      },
      {
        CidrBlock: "10.2.0.0/16",
        CidrBlockState: { State: "failed" },
      },
      {
        CidrBlock: "10.3.0.0/16",
        CidrBlockState: { State: "disassociating" },
      },
      {
        CidrBlock: "10.4.0.0/16",
        CidrBlockState: { State: "associated" },
      },
    ],
  };
  assertEquals(collectCidrBlocks(vpc), ["10.0.0.0/16", "10.4.0.0/16"]);
});

Deno.test("collectCidrBlocks: tolerates missing primary and empty/whitespace CIDRs", () => {
  const vpc: AwsVpc = {
    CidrBlockAssociationSet: [
      { CidrBlock: "", CidrBlockState: { State: "associated" } },
      { CidrBlock: "   ", CidrBlockState: { State: "associated" } },
      { CidrBlock: "10.5.0.0/16", CidrBlockState: { State: "associated" } },
    ],
  };
  assertEquals(collectCidrBlocks(vpc), ["10.5.0.0/16"]);
});

// classifyError — the regression bed (mirrored from the SG audit).

Deno.test("classifyError: SSO role ARN in unrelated AccessDenied does NOT trip auth_expired (regression)", () => {
  const err = new Error(
    "You are not authorized to perform this operation. User: " +
      "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_ReadOnlyAccess_abc123/alice@example.com " +
      "is not authorized to perform: ec2:DescribeVpcs with an " +
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
      "User is not authorized to perform ec2:DescribeVpcs; the sso session token has expired",
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

  const sso = new Error(
    "SSO session associated with this profile has expired",
  );
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

Deno.test("vpcKey: stable and unique across (account, region, vpc)", () => {
  const a = vpcKey("111111111111", "eu-west-1", "vpc-aaa");
  const b = vpcKey("111111111111", "eu-west-1", "vpc-bbb");
  const c = vpcKey("222222222222", "eu-west-1", "vpc-aaa");
  assertEquals(a, "vpc-111111111111-eu-west-1-vpc-aaa");
  assertNotEquals(a, b);
  assertNotEquals(a, c);
});

Deno.test("scanErrorKey: ambient and account-level fallbacks", () => {
  assertEquals(
    scanErrorKey("", "", "credentials"),
    "error-ambient-account-credentials",
  );
  assertEquals(
    scanErrorKey("acct-readonly", "eu-west-1", "describe_vpcs"),
    "error-acct-readonly-eu-west-1-describe_vpcs",
  );
});

// ---------------------------------------------------------------------------
// runScan — integration via createModelTestContext + injected AwsApi
// ---------------------------------------------------------------------------

/** Per-region spec for {@link fakeApi}. */
interface RegionSpec {
  /** VPCs returned for `describeVpcs(region)`. */
  vpcs?: AwsVpc[];
  /** Replace the VPCs call with a throw. */
  vpcsError?: Error;
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
    describeVpcs: (region) => {
      const r = spec.perRegion?.[region];
      if (r?.vpcsError) return Promise.reject(r.vpcsError);
      return Promise.resolve(r?.vpcs ?? []);
    },
  };
}

/** Build a `ScanTarget` over `fakeApi(spec)` for `profile`. */
function target(profile: string, spec: FakeSpec): ScanTarget {
  return { profile, api: fakeApi(spec) };
}

// ---- happy path ------------------------------------------------------------

Deno.test("runScan: writes one vpc row per VPC, derives account name, collects all CIDRs", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });

  const result = await runScan({
    targets: [target("prod-platform-readonly", {
      accountId: "111111111111",
      perRegion: {
        "eu-west-1": {
          vpcs: [
            {
              VpcId: "vpc-main",
              IsDefault: false,
              OwnerId: "111111111111",
              CidrBlock: "10.0.0.0/16",
              CidrBlockAssociationSet: [
                {
                  CidrBlock: "10.0.0.0/16",
                  CidrBlockState: { State: "associated" },
                },
                {
                  CidrBlock: "10.1.0.0/16",
                  CidrBlockState: { State: "associated" },
                },
              ],
              Tags: [
                { Key: "Name", Value: "prod-main" },
                { Key: "team", Value: "platform" },
              ],
            },
            {
              VpcId: "vpc-default",
              IsDefault: true,
              OwnerId: "111111111111",
              CidrBlock: "172.31.0.0/16",
              Tags: [],
            },
          ],
        },
      },
    })],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "-readonly",
    context,
  });

  assertEquals(result.vpcCount, 2);
  assertEquals(result.errorCount, 0);

  const rows = getWrittenResources().filter((w) => w.specName === "vpc").map(
    (w) => w.data as Record<string, unknown>,
  );
  assertEquals(rows.length, 2);
  const byId = new Map(rows.map((r) => [r.vpcId as string, r]));

  const main = byId.get("vpc-main")!;
  assertEquals(main.accountId, "111111111111");
  assertEquals(main.accountName, "prod-platform");
  assertEquals(main.profile, "prod-platform-readonly");
  assertEquals(main.region, "eu-west-1");
  assertEquals(main.vpcName, "prod-main");
  assertEquals(main.vpcIsDefault, false);
  assertEquals(main.ownerAccountId, "111111111111");
  assertEquals(main.isSharedIn, false);
  assertEquals(main.cidrBlocks, ["10.0.0.0/16", "10.1.0.0/16"]);
  assertEquals((main.vpcTags as Record<string, string>).team, "platform");

  const def = byId.get("vpc-default")!;
  assertEquals(def.vpcIsDefault, true);
  assertEquals(def.vpcName, "");
  assertEquals(def.cidrBlocks, ["172.31.0.0/16"]);
});

Deno.test("runScan: shared-in VPC (OwnerId != accountId) is flagged isSharedIn=true", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  await runScan({
    targets: [target("shared-acct-readonly", {
      accountId: "222222222222",
      perRegion: {
        "eu-west-1": {
          vpcs: [{
            VpcId: "vpc-shared",
            IsDefault: false,
            OwnerId: "999999999999",
            CidrBlock: "10.50.0.0/16",
            Tags: [{ Key: "Name", Value: "core-shared" }],
          }],
        },
      },
    })],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "-readonly",
    context,
  });
  const row = getWrittenResources()[0].data as Record<string, unknown>;
  assertEquals(row.ownerAccountId, "999999999999");
  assertEquals(row.isSharedIn, true);
});

Deno.test("runScan: VPC with no VpcId is skipped (logged warning, not an error row)", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const result = await runScan({
    targets: [target("", {
      accountId: "111111111111",
      perRegion: {
        "eu-west-1": {
          vpcs: [
            { IsDefault: false, CidrBlock: "10.0.0.0/16" },
            {
              VpcId: "vpc-ok",
              IsDefault: false,
              OwnerId: "111111111111",
              CidrBlock: "10.1.0.0/16",
            },
          ],
        },
      },
    })],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "",
    context,
  });
  assertEquals(result.vpcCount, 1);
  assertEquals(result.errorCount, 0);
  const rows = getWrittenResources();
  assertEquals(rows.length, 1);
  assertEquals(
    (rows[0].data as Record<string, unknown>).vpcId,
    "vpc-ok",
  );
});

Deno.test("runScan: region with no VPCs writes nothing", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const result = await runScan({
    targets: [target("", {
      accountId: "111111111111",
      perRegion: { "eu-west-1": { vpcs: [] } },
    })],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "",
    context,
  });
  assertEquals(result.vpcCount, 0);
  assertEquals(result.errorCount, 0);
  assertEquals(getWrittenResources().length, 0);
});

// ---- failure paths ---------------------------------------------------------

Deno.test("runScan: profile that fails the required-suffix check is skipped with a scan_error", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const result = await runScan({
    targets: [target("admin-write-access", {
      accountId: "111111111111",
    })],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "-readonly",
    context,
  });
  assertEquals(result.vpcCount, 0);
  assertEquals(result.errorCount, 1);
  const written = getWrittenResources();
  assertEquals(written.length, 1);
  const err = written[0].data as Record<string, unknown>;
  assertEquals(err.phase, "profile_suffix_check");
  assertEquals(err.profile, "admin-write-access");
});

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
        perRegion: { "eu-west-1": { vpcs: [] } },
      }),
    ],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "-readonly",
    context,
  });

  assertEquals(result.vpcCount, 0);
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
    "AccessDenied: not authorized to perform ec2:DescribeVpcs",
  );

  const result = await runScan({
    targets: [target("acct-readonly", {
      accountId: "111111111111",
      perRegion: {
        "eu-west-1": { vpcsError: denied },
        "eu-north-1": {
          vpcs: [{
            VpcId: "vpc-north",
            IsDefault: false,
            OwnerId: "111111111111",
            CidrBlock: "10.0.0.0/16",
          }],
        },
      },
    })],
    configuredRegions: ["eu-west-1", "eu-north-1"],
    requiredProfileSuffix: "-readonly",
    context,
  });

  assertEquals(result.vpcCount, 1);
  assertEquals(result.errorCount, 1);
  const written = getWrittenResources();
  const errs = written.filter((w) => w.specName === "scan_error");
  assertEquals(errs.length, 1);
  const err = errs[0].data as Record<string, unknown>;
  assertEquals(err.region, "eu-west-1");
  assertEquals(err.kind, "access_denied");
  const vpcs = written.filter((w) => w.specName === "vpc");
  assertEquals(vpcs.length, 1);
  assertEquals((vpcs[0].data as Record<string, unknown>).region, "eu-north-1");
});

Deno.test("runScan: describe_regions failure surfaces and the account is skipped", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const denied = new Error("AccessDenied for ec2:DescribeRegions");
  const result = await runScan({
    targets: [target("acct-readonly", {
      accountId: "111111111111",
      enabledRegionsError: denied,
    })],
    configuredRegions: [], // forces per-account discovery
    requiredProfileSuffix: "-readonly",
    context,
  });
  assertEquals(result.vpcCount, 0);
  assertEquals(result.errorCount, 1);
  const err = getWrittenResources()[0].data as Record<string, unknown>;
  assertEquals(err.phase, "describe_regions");
  assertEquals(err.kind, "access_denied");
});
