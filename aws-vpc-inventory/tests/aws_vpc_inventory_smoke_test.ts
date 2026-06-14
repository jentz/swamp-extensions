/**
 * Smoke tests — drive a fleet-wide `runScan` end-to-end through an in-memory
 * `AwsApi` facade with a hand-rolled swamp method context.
 *
 * No AWS calls, no live SDK, no network: every account's EC2/STS surface is
 * an in-memory replay. The tests prove the fan-out walks all configured
 * profiles × regions in one execution (one write stream) and that the `vpc`
 * and `scan_error` rows that come out the other side carry the expected
 * shape. All identifiers are placeholders so the corpus is safe to ship.
 */

import { assert, assertEquals } from "jsr:@std/assert@1";

import {
  type AwsApi,
  type AwsVpc,
  runScan,
  type ScanTarget,
} from "../aws_vpc_inventory.ts";

// ---------------------------------------------------------------------------
// In-memory AWS facade replay
// ---------------------------------------------------------------------------

/** Per-region replay spec. */
interface RegionSpec {
  vpcs?: AwsVpc[];
  vpcsError?: Error;
}

/** Whole-account replay spec. */
interface AccountSpec {
  accountId?: string;
  accountIdError?: Error;
  enabledRegions?: string[];
  enabledRegionsError?: Error;
  perRegion?: Record<string, RegionSpec>;
}

function fakeApi(spec: AccountSpec): AwsApi {
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

function target(profile: string, spec: AccountSpec): ScanTarget {
  return { profile, api: fakeApi(spec) };
}

// ---------------------------------------------------------------------------
// Stand-in for the runtime's swamp method context
// ---------------------------------------------------------------------------

interface Written {
  specName: string;
  key: string;
  data: Record<string, unknown>;
}

const silentLogger = {
  info: () => {},
  debug: () => {},
  warn: () => {},
  error: () => {},
};

function makeContext(): { context: unknown; written: Written[] } {
  const written: Written[] = [];
  const context = {
    globalArgs: {},
    logger: silentLogger,
    writeResource: (
      specName: string,
      key: string,
      data: Record<string, unknown>,
    ) => {
      written.push({ specName, key, data });
      return Promise.resolve({ id: `${specName}:${key}` });
    },
  };
  return { context, written };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

Deno.test("smoke: fan-out across two accounts × two regions in one execution", async () => {
  const { context, written } = makeContext();

  const result = await runScan({
    targets: [
      target("acct-prod-readonly", {
        accountId: "111111111111",
        perRegion: {
          "eu-west-1": {
            vpcs: [
              {
                VpcId: "vpc-prod-a",
                IsDefault: false,
                OwnerId: "111111111111",
                CidrBlock: "10.0.0.0/16",
                Tags: [{ Key: "Name", Value: "prod-a" }],
              },
              {
                VpcId: "vpc-prod-default",
                IsDefault: true,
                OwnerId: "111111111111",
                CidrBlock: "172.31.0.0/16",
              },
            ],
          },
          "eu-north-1": {
            vpcs: [{
              VpcId: "vpc-prod-north",
              IsDefault: false,
              OwnerId: "111111111111",
              CidrBlock: "10.10.0.0/16",
            }],
          },
        },
      }),
      target("acct-stage-readonly", {
        accountId: "222222222222",
        perRegion: {
          "eu-west-1": {
            vpcs: [{
              VpcId: "vpc-stage-shared",
              IsDefault: false,
              // Owned elsewhere → shared into this account via RAM.
              OwnerId: "999999999999",
              CidrBlock: "10.20.0.0/16",
            }],
          },
          "eu-north-1": { vpcs: [] },
        },
      }),
    ],
    configuredRegions: ["eu-west-1", "eu-north-1"],
    requiredProfileSuffix: "-readonly",
    ambientProfile: "",
    context,
  });

  // 3 prod VPCs + 1 stage VPC, no errors.
  assertEquals(result.vpcCount, 4);
  assertEquals(result.errorCount, 0);

  const vpcRows = written.filter((w) => w.specName === "vpc");
  assertEquals(vpcRows.length, 4);
  assertEquals(written.filter((w) => w.specName === "scan_error").length, 0);

  // The shared-in VPC is flagged and attributed to its owner account.
  const shared = vpcRows.find((w) => w.data.vpcId === "vpc-stage-shared")!;
  assertEquals(shared.data.isSharedIn, true);
  assertEquals(shared.data.ownerAccountId, "999999999999");
  assertEquals(shared.data.accountName, "acct-stage");

  // The default VPC carries the default flag and no Name tag.
  const def = vpcRows.find((w) => w.data.vpcId === "vpc-prod-default")!;
  assertEquals(def.data.vpcIsDefault, true);
  assertEquals(def.data.vpcName, "");
});

Deno.test("smoke: one expired account does not abort the rest of the fleet", async () => {
  const { context, written } = makeContext();

  const expired = new Error(
    "The security token included in the request is expired",
  );
  (expired as { name?: string }).name = "ExpiredTokenException";
  const denied = new Error(
    "AccessDenied: not authorized to perform ec2:DescribeVpcs",
  );

  const result = await runScan({
    targets: [
      // Account 1: credentials expired — recorded, account skipped.
      target("acct-expired-readonly", { accountIdError: expired }),
      // Account 2: one region denied, one healthy.
      target("acct-mixed-readonly", {
        accountId: "333333333333",
        perRegion: {
          "eu-west-1": { vpcsError: denied },
          "eu-north-1": {
            vpcs: [{
              VpcId: "vpc-healthy",
              IsDefault: false,
              OwnerId: "333333333333",
              CidrBlock: "10.30.0.0/16",
            }],
          },
        },
      }),
    ],
    configuredRegions: ["eu-west-1", "eu-north-1"],
    requiredProfileSuffix: "-readonly",
    ambientProfile: "",
    context,
  });

  assertEquals(result.vpcCount, 1);
  // One credential error + one per-region denial.
  assertEquals(result.errorCount, 2);

  const errs = written.filter((w) => w.specName === "scan_error");
  const kinds = errs.map((e) => e.data.kind).sort();
  assertEquals(kinds, ["access_denied", "auth_expired"]);

  // Despite both failures, the healthy region still produced its VPC.
  const vpcs = written.filter((w) => w.specName === "vpc");
  assertEquals(vpcs.length, 1);
  assertEquals(vpcs[0].data.vpcId, "vpc-healthy");
});

Deno.test("smoke: per-account region discovery when no regions are configured", async () => {
  const { context, written } = makeContext();

  const result = await runScan({
    targets: [
      target("acct-discover-readonly", {
        accountId: "444444444444",
        enabledRegions: ["eu-west-1", "us-east-1"],
        perRegion: {
          "eu-west-1": {
            vpcs: [{
              VpcId: "vpc-west",
              IsDefault: false,
              OwnerId: "444444444444",
              CidrBlock: "10.40.0.0/16",
            }],
          },
          "us-east-1": {
            vpcs: [{
              VpcId: "vpc-east",
              IsDefault: false,
              OwnerId: "444444444444",
              CidrBlock: "10.41.0.0/16",
            }],
          },
        },
      }),
    ],
    configuredRegions: [], // forces per-account ec2:DescribeRegions discovery
    requiredProfileSuffix: "-readonly",
    ambientProfile: "",
    context,
  });

  assertEquals(result.vpcCount, 2);
  assertEquals(result.errorCount, 0);
  const regions = written
    .filter((w) => w.specName === "vpc")
    .map((w) => w.data.region as string)
    .sort();
  assertEquals(regions, ["eu-west-1", "us-east-1"]);
});

Deno.test("smoke: a profile failing the required-suffix gate never reaches the API", async () => {
  const { context, written } = makeContext();

  let apiTouched = false;
  const trippedApi: AwsApi = {
    getAccountId: () => {
      apiTouched = true;
      return Promise.resolve("555555555555");
    },
    describeEnabledRegions: () => {
      apiTouched = true;
      return Promise.resolve([]);
    },
    describeVpcs: () => {
      apiTouched = true;
      return Promise.resolve([]);
    },
  };

  const result = await runScan({
    targets: [{ profile: "acct-admin-write", api: trippedApi }],
    configuredRegions: ["eu-west-1"],
    requiredProfileSuffix: "-readonly",
    ambientProfile: "",
    context,
  });

  assertEquals(result.vpcCount, 0);
  assertEquals(result.errorCount, 1);
  assert(!apiTouched, "AWS facade must not be called for a refused profile");
  const err = written[0].data;
  assertEquals(err.phase, "profile_suffix_check");
});

Deno.test("smoke: data handle count equals vpc rows plus scan errors", async () => {
  const { context } = makeContext();
  const denied = new Error("AccessDenied");

  const result = await runScan({
    targets: [
      target("acct-readonly", {
        accountId: "666666666666",
        perRegion: {
          "eu-west-1": {
            vpcs: [{
              VpcId: "vpc-x",
              IsDefault: false,
              OwnerId: "666666666666",
              CidrBlock: "10.60.0.0/16",
            }],
          },
          "eu-north-1": { vpcsError: denied },
        },
      }),
    ],
    configuredRegions: ["eu-west-1", "eu-north-1"],
    requiredProfileSuffix: "-readonly",
    ambientProfile: "",
    context,
  });

  assertEquals(
    result.dataHandles.length,
    result.vpcCount + result.errorCount,
  );
  assertEquals(result.dataHandles.length, 2);
});
