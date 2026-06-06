/**
 * Unit tests for `@jentz/aws-rds-reservations`.
 *
 * Two layers:
 *
 *   1. Pure helpers — `classifyError` (SSO-role-ARN regression locked in),
 *      `accountNameFromProfile`, `resolveBootstrapRegion`, `tagsFromAws`.
 *   2. `runSweep` integration paths — driven through `createModelTestContext`
 *      with a hand-rolled `AwsApi` replay so the SDK is never touched.
 *      Verifies `instance` / `reserved` row shape and that per-(profile,
 *      region) failures degrade to recorded `scan_error` rows rather than
 *      aborting the sweep.
 *
 * @module
 */

import { assertEquals } from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260525.18";
import {
  accountNameFromProfile,
  type AwsApi,
  type AwsDBInstance,
  type AwsReservedDBInstance,
  classifyError,
  resolveBootstrapRegion,
  runSweep,
  type SweepTarget,
  tagsFromAws,
} from "../aws_rds_reservations.ts";

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

Deno.test("tagsFromAws: drops keyless tags, defaults missing value", () => {
  assertEquals(
    tagsFromAws([
      { Key: "env", Value: "prod" },
      { Value: "orphan" },
      { Key: "novalue" },
    ]),
    { env: "prod", novalue: "" },
  );
});

Deno.test("accountNameFromProfile: strips -readonly suffix", () => {
  assertEquals(
    accountNameFromProfile("sandbox-readonly", "-readonly"),
    "sandbox",
  );
});

Deno.test("classifyError: expired SSO token -> auth_expired", () => {
  const err = new Error("The SSO session associated with this profile has expired");
  assertEquals(classifyError(err).kind, "auth_expired");
});

Deno.test("classifyError: SSO role ARN in AccessDenied does NOT misfire to auth_expired", () => {
  const err = new Error(
    "User: arn:aws:sts::1:assumed-role/AWSReservedSSO_ro/x is not authorized to perform rds:DescribeDBInstances",
  );
  assertEquals(classifyError(err).kind, "access_denied");
});

Deno.test("resolveBootstrapRegion: first configured region wins", () => {
  assertEquals(resolveBootstrapRegion(["us-east-1"], () => undefined), "us-east-1");
});

Deno.test("resolveBootstrapRegion: falls back to us-east-1 when nothing set", () => {
  assertEquals(resolveBootstrapRegion([], () => undefined), "us-east-1");
});

// ---------------------------------------------------------------------------
// runSweep — integration via createModelTestContext + injected AwsApi
// ---------------------------------------------------------------------------

interface RegionSpec {
  instances?: AwsDBInstance[];
  instancesError?: Error;
  reserved?: AwsReservedDBInstance[];
  reservedError?: Error;
}

interface FakeSpec {
  accountId?: string;
  accountIdError?: Error;
  perRegion?: Record<string, RegionSpec>;
}

function fakeApi(spec: FakeSpec): AwsApi {
  return {
    getAccountId: () =>
      spec.accountIdError
        ? Promise.reject(spec.accountIdError)
        : Promise.resolve(spec.accountId ?? "000000000000"),
    describeDBInstances: (region) => {
      const r = spec.perRegion?.[region];
      if (r?.instancesError) return Promise.reject(r.instancesError);
      return Promise.resolve(r?.instances ?? []);
    },
    describeReservedDBInstances: (region) => {
      const r = spec.perRegion?.[region];
      if (r?.reservedError) return Promise.reject(r.reservedError);
      return Promise.resolve(r?.reserved ?? []);
    },
  };
}

function target(profile: string, spec: FakeSpec): SweepTarget {
  return { profile, api: fakeApi(spec) };
}

Deno.test("runSweep: writes one instance + one reserved row, derives account name", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const result = await runSweep({
    targets: [target("prod-readonly", {
      accountId: "111122223333",
      perRegion: {
        "us-east-1": {
          instances: [{
            DBInstanceIdentifier: "orders-db",
            DBInstanceClass: "db.r7g.2xlarge",
            Engine: "postgres",
            EngineVersion: "16.3",
            DBInstanceStatus: "available",
            MultiAZ: true,
            DBClusterIdentifier: "orders-cluster",
            StorageType: "aurora",
            TagList: [{ Key: "Name", Value: "orders" }],
          }],
          reserved: [{
            ReservedDBInstanceId: "ri-1",
            DBInstanceClass: "db.r7g.large",
            ProductDescription: "postgresql",
            MultiAZ: true,
            DBInstanceCount: 2,
            State: "active",
            OfferingType: "All Upfront",
            Duration: 31536000,
          }],
        },
      },
    })],
    regions: ["us-east-1"],
    requiredProfileSuffix: "-readonly",
    context,
  });

  assertEquals(result.instanceCount, 1);
  assertEquals(result.reservedCount, 1);
  assertEquals(result.errorCount, 0);

  const written = getWrittenResources();
  const inst = written.find((w) => w.specName === "instance")!
    .data as Record<string, unknown>;
  assertEquals(inst.accountId, "111122223333");
  assertEquals(inst.accountName, "prod");
  assertEquals(inst.dbInstanceClass, "db.r7g.2xlarge");
  assertEquals(inst.multiAZ, true);
  assertEquals(inst.clusterId, "orders-cluster");

  const res = written.find((w) => w.specName === "reserved")!
    .data as Record<string, unknown>;
  assertEquals(res.dbInstanceClass, "db.r7g.large");
  assertEquals(res.dbInstanceCount, 2);
  assertEquals(res.state, "active");
});

Deno.test("runSweep: DescribeDBInstances error in one region does not abort; reserved still scanned", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const denied = new Error("AccessDenied");
  denied.name = "AccessDeniedException";
  const result = await runSweep({
    targets: [target("app-readonly", {
      accountId: "444455556666",
      perRegion: {
        "us-west-2": {
          instancesError: denied,
          reserved: [{
            ReservedDBInstanceId: "ri-x",
            DBInstanceClass: "db.m6g.large",
            ProductDescription: "mysql",
            MultiAZ: false,
            DBInstanceCount: 1,
            State: "active",
          }],
        },
      },
    })],
    regions: ["us-west-2"],
    requiredProfileSuffix: "",
    context,
  });

  assertEquals(result.instanceCount, 0);
  assertEquals(result.reservedCount, 1);
  assertEquals(result.errorCount, 1);
  const err = getWrittenResources().find((w) => w.specName === "scan_error")!
    .data as Record<string, unknown>;
  assertEquals(err.phase, "describe_db_instances");
  assertEquals(err.kind, "access_denied");
});

Deno.test("runSweep: credential failure writes one scan_error and skips the account", async () => {
  const { context } = createModelTestContext({});
  const expired = new Error("Token has expired");
  expired.name = "ExpiredTokenException";
  const result = await runSweep({
    targets: [target("stale-readonly", { accountIdError: expired })],
    regions: ["us-east-1"],
    requiredProfileSuffix: "",
    context,
  });
  assertEquals(result.instanceCount, 0);
  assertEquals(result.reservedCount, 0);
  assertEquals(result.errorCount, 1);
});

Deno.test("runSweep: profile failing required-suffix is skipped before any AWS call", async () => {
  const { context } = createModelTestContext({});
  const result = await runSweep({
    targets: [target("admin-profile", { accountId: "123456789012" })],
    regions: ["us-east-1"],
    requiredProfileSuffix: "-readonly",
    context,
  });
  assertEquals(result.instanceCount, 0);
  assertEquals(result.errorCount, 1);
});
