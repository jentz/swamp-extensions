/**
 * Smoke tests — drive the default-SG audit end-to-end through an in-memory
 * `AwsApi` facade with a swamp method context from `createModelTestContext`.
 *
 * No AWS calls, no live SDK, no network: every account's EC2/STS surface is an
 * in-memory replay. The first tests drive the core `runScan` (which the model's
 * `scan.execute` delegates to) with the facade swapped in, asserting findings
 * land and that a per-target failure degrades to a recorded `scan_error`
 * without aborting the sweep. A final test exercises the real
 * `model.methods.scan.execute` entry path to prove it wires global args →
 * targets → `runScan` and still never throws when credentials cannot resolve.
 *
 * All identifiers are placeholders so the corpus is safe to ship.
 */

import { assert, assertEquals } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260525.18";

import {
  type AwsApi,
  type AwsNetworkInterface,
  type AwsSecurityGroup,
  type AwsVpc,
  model,
  runScan,
  type ScanTarget,
} from "../aws_default_sg_audit.ts";

// ---------------------------------------------------------------------------
// In-memory AWS facade replay
// ---------------------------------------------------------------------------

/** Per-region replay spec. */
interface RegionSpec {
  sgs?: AwsSecurityGroup[];
  sgsError?: Error;
  vpcs?: AwsVpc[];
  enisByGroup?: Record<string, AwsNetworkInterface[]>;
}

/** Whole-account replay spec. */
interface AccountSpec {
  accountId?: string;
  accountIdError?: Error;
  enabledRegions?: string[];
  perRegion?: Record<string, RegionSpec>;
}

function fakeApi(spec: AccountSpec): AwsApi {
  return {
    getAccountId: () =>
      spec.accountIdError
        ? Promise.reject(spec.accountIdError)
        : Promise.resolve(spec.accountId ?? "000000000000"),
    describeEnabledRegions: () => Promise.resolve(spec.enabledRegions ?? []),
    describeDefaultSecurityGroups: (region) => {
      const r = spec.perRegion?.[region];
      if (r?.sgsError) return Promise.reject(r.sgsError);
      return Promise.resolve(r?.sgs ?? []);
    },
    describeVpcs: (region, ids) => {
      const r = spec.perRegion?.[region];
      const wanted = new Set(ids);
      return Promise.resolve(
        (r?.vpcs ?? []).filter((v) => v.VpcId && wanted.has(v.VpcId)),
      );
    },
    describeEnisForGroup: (region, groupId) => {
      const r = spec.perRegion?.[region];
      return Promise.resolve(r?.enisByGroup?.[groupId] ?? []);
    },
  };
}

function target(profile: string, spec: AccountSpec): ScanTarget {
  return { profile, api: fakeApi(spec) };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

Deno.test("smoke: fan-out across two accounts × two regions in one execution", async () => {
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: {},
  });

  const result = await runScan({
    targets: [
      target("acct-prod-readonly", {
        accountId: "111111111111",
        perRegion: {
          "eu-west-1": {
            sgs: [{
              GroupId: "sg-prod-clean",
              GroupName: "default",
              VpcId: "vpc-prod-default",
              IpPermissions: [],
              IpPermissionsEgress: [],
            }],
            vpcs: [{ VpcId: "vpc-prod-default", IsDefault: true, Tags: [] }],
          },
          "eu-north-1": {
            sgs: [{
              GroupId: "sg-prod-open",
              GroupName: "default",
              VpcId: "vpc-prod-app",
              IpPermissions: [{}],
              IpPermissionsEgress: [{}],
            }],
            vpcs: [{
              VpcId: "vpc-prod-app",
              IsDefault: false,
              Tags: [{ Key: "Name", Value: "prod-app" }],
            }],
            enisByGroup: {
              "sg-prod-open": [{
                NetworkInterfaceId: "eni-nat",
                InterfaceType: "nat_gateway",
                Description: "NAT gateway",
                RequesterId: "amazon-vpc-nat",
                RequesterManaged: true,
              }],
            },
          },
        },
      }),
      target("acct-stage-readonly", {
        accountId: "222222222222",
        perRegion: {
          "eu-west-1": {
            sgs: [{
              GroupId: "sg-stage-open",
              GroupName: "default",
              VpcId: "vpc-stage",
              IpPermissions: [{}],
              IpPermissionsEgress: [],
            }],
            vpcs: [{ VpcId: "vpc-stage", IsDefault: false, Tags: [] }],
          },
          "eu-north-1": { sgs: [] },
        },
      }),
    ],
    configuredRegions: ["eu-west-1", "eu-north-1"],
    requiredProfileSuffix: "-readonly",
    context,
  });

  // 1 compliant prod + 1 in-use prod + 1 safe stage default SG, no errors.
  assertEquals(result.findingCount, 3);
  assertEquals(result.errorCount, 0);

  const findings = getWrittenResources().filter((w) =>
    w.specName === "finding"
  );
  assertEquals(findings.length, 3);
  assertEquals(
    getWrittenResources().filter((w) => w.specName === "scan_error").length,
    0,
  );

  const byId = new Map(
    findings.map((w) => [
      (w.data as { defaultSgId: string }).defaultSgId,
      w.data as Record<string, unknown>,
    ]),
  );

  // Compliant default VPC SG: nothing to do.
  assertEquals(byId.get("sg-prod-clean")?.verdict, "compliant");
  // In-use SG referenced by a NAT-gateway ENI: migrate first.
  assertEquals(byId.get("sg-prod-open")?.verdict, "in_use_needs_migration");
  assertEquals(byId.get("sg-prod-open")?.eniCount, 1);
  // Open SG with no ENIs: safe to strip now.
  assertEquals(byId.get("sg-stage-open")?.verdict, "safe_to_remediate");
});

Deno.test("smoke: one expired account does not abort the rest of the fleet", async () => {
  const { context, getWrittenResources } = createModelTestContext({});

  const expired = new Error(
    "The security token included in the request is expired",
  );
  (expired as { name?: string }).name = "ExpiredTokenException";

  const result = await runScan({
    targets: [
      // Account 1: credentials expired — recorded, account skipped.
      target("acct-expired-readonly", { accountIdError: expired }),
      // Account 2: healthy, one default SG that is safe to remediate.
      target("acct-healthy-readonly", {
        accountId: "333333333333",
        perRegion: {
          "eu-west-1": {
            sgs: [{
              GroupId: "sg-healthy",
              GroupName: "default",
              VpcId: "vpc-healthy",
              IpPermissions: [{}],
              IpPermissionsEgress: [],
            }],
            vpcs: [{ VpcId: "vpc-healthy", IsDefault: false, Tags: [] }],
          },
        },
      }),
    ],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "-readonly",
    context,
  });

  assertEquals(result.findingCount, 1);
  assertEquals(result.errorCount, 1);

  const written = getWrittenResources();
  const err = written.find((w) => w.specName === "scan_error")?.data as Record<
    string,
    unknown
  >;
  assertEquals(err.kind, "auth_expired");
  assertEquals(err.phase, "credentials");

  // Despite the expired account, the healthy account still produced a finding.
  const finding = written.find((w) => w.specName === "finding")?.data as Record<
    string,
    unknown
  >;
  assertEquals(finding.defaultSgId, "sg-healthy");
  assertEquals(finding.verdict, "safe_to_remediate");
});

Deno.test("smoke: data handle count equals findings plus scan errors", async () => {
  const { context } = createModelTestContext({});
  const denied = new Error("AccessDenied");

  const result = await runScan({
    targets: [
      target("acct-readonly", {
        accountId: "444444444444",
        perRegion: {
          "eu-west-1": {
            sgs: [{
              GroupId: "sg-x",
              GroupName: "default",
              VpcId: "vpc-x",
              IpPermissions: [{}],
              IpPermissionsEgress: [{}],
            }],
            vpcs: [{ VpcId: "vpc-x", Tags: [] }],
          },
          "eu-north-1": { sgsError: denied },
        },
      }),
    ],
    configuredRegions: ["eu-west-1", "eu-north-1"],
    requiredProfileSuffix: "-readonly",
    context,
  });

  assertEquals(
    result.dataHandles.length,
    result.findingCount + result.errorCount,
  );
  assertEquals(result.dataHandles.length, 2);
});

Deno.test("smoke: model.methods.scan.execute wires global args and never throws without AWS", async () => {
  // Drives the real entrypoint: scan.execute parses global args, builds the
  // ambient SDK target, and delegates to runScan. With no real AWS reachable
  // the credential resolution fails inside runScan — which must degrade to a
  // recorded scan_error rather than throwing out of execute.
  const { context, getWrittenResources } = createModelTestContext({
    globalArgs: { regions: ["eu-west-1"] },
  });

  const result = await model.methods.scan.execute({}, context);

  assertEquals(result.findingCount, 0);
  // Exactly one account (the ambient chain) was attempted; its failure is one
  // recorded scan_error, and the sweep returned normally.
  assert(result.errorCount >= 1);
  const errors = getWrittenResources().filter((w) =>
    w.specName === "scan_error"
  );
  assert(errors.length >= 1, "expected a recorded scan_error from the sweep");
});
