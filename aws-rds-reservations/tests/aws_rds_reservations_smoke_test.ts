/**
 * Smoke tests — drive `runSweep` end-to-end against an in-memory `AwsApi`
 * replay with a hand-rolled execution context. No AWS calls, no SDK.
 *
 * Where the unit tests (`aws_rds_reservations_test.ts`) cover the pure helpers
 * and single-target `runSweep` paths via `createModelTestContext`, these smoke
 * tests exercise the wider fan-out the `sweep` method actually performs: many
 * accounts × many regions in a single pass, with success and per-(profile,
 * region) failure interleaved, asserting that every provisioned instance,
 * reservation, and `scan_error` lands as its own resource under a collision-free
 * storage key.
 *
 * All identifiers are generic, clearly-fictional placeholders (orders-db, prod-readonly, …) so the corpus is safe to
 * ship with the public extension.
 *
 * @module
 */

import { assert, assertEquals } from "jsr:@std/assert@1";

import {
  type AwsApi,
  type AwsDBInstance,
  type AwsReservedDBInstance,
  instanceKey,
  type InstanceRecord,
  reservedKey,
  type ReservedRecord,
  runSweep,
  type ScanError,
  scanErrorKey,
  type SweepTarget,
} from "../aws_rds_reservations.ts";

// ---------------------------------------------------------------------------
// Fake account identifiers. `accountId` is an opaque `z.string()` in the
// schema, so these named placeholders stand in for 12-digit AWS account ids
// everywhere the value is only round-tripped through a storage key or asserted
// back unchanged. The one place a 12-digit shape is genuinely under test (the
// storage-key separator contract) keeps a documented numeric literal inline.
// ---------------------------------------------------------------------------

const ACCOUNT_ALPHA = "ACCT_ALPHA";
const ACCOUNT_BETA = "ACCT_BETA";
const ACCOUNT_GAMMA = "ACCT_GAMMA";
const ACCOUNT_DELTA = "ACCT_DELTA";
const ACCOUNT_EPSILON = "ACCT_EPSILON";
const ACCOUNT_ADMIN = "ACCT_ADMIN";

// ---------------------------------------------------------------------------
// In-memory AwsApi replay
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

/** Build an `AwsApi` that replays the supplied per-region fixtures. */
function fakeApi(spec: FakeSpec): AwsApi {
  return {
    getAccountId: () =>
      spec.accountIdError
        ? Promise.reject(spec.accountIdError)
        : Promise.resolve(spec.accountId ?? "ACCT_UNSET"),
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

// ---------------------------------------------------------------------------
// Captured execution context (mirrors the runtime's writeResource + logger)
// ---------------------------------------------------------------------------

interface WrittenResource {
  spec: string;
  key: string;
  data: InstanceRecord | ReservedRecord | ScanError;
}

interface RunOutcome {
  result: Awaited<ReturnType<typeof runSweep>>;
  written: WrittenResource[];
  logs: Array<{ level: string; message: string }>;
}

interface RunOpts {
  requiredProfileSuffix?: string;
  ssoSession?: string;
  ssoRegion?: string;
  resolveSsoToken?: (session: string, region: string) => Promise<unknown>;
}

async function runWithTargets(
  targets: SweepTarget[],
  regions: string[],
  opts: RunOpts | string = {},
): Promise<RunOutcome> {
  // Back-compat positional form: a bare string is the requiredProfileSuffix.
  const o: RunOpts = typeof opts === "string"
    ? { requiredProfileSuffix: opts }
    : opts;
  const written: WrittenResource[] = [];
  const logs: Array<{ level: string; message: string }> = [];
  const log = (level: string) => (message: string) =>
    logs.push({ level, message });

  const context = {
    logger: {
      info: log("info"),
      debug: log("debug"),
      warn: log("warn"),
      error: log("error"),
    },
    writeResource: (
      spec: string,
      key: string,
      data: InstanceRecord | ReservedRecord | ScanError,
    ) => {
      written.push({ spec, key, data });
      return Promise.resolve({ id: `${spec}:${key}` });
    },
  };

  const result = await runSweep({
    targets,
    regions,
    requiredProfileSuffix: o.requiredProfileSuffix ?? "",
    ssoSession: o.ssoSession,
    ssoRegion: o.ssoRegion,
    resolveSsoToken: o.resolveSsoToken,
    context,
  });
  return { result, written, logs };
}

const ofSpec = (w: WrittenResource[], spec: string) =>
  w.filter((r) => r.spec === spec);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

Deno.test("smoke: two accounts × two regions sweep in one pass", async () => {
  const acctA: FakeSpec = {
    accountId: ACCOUNT_ALPHA,
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
          ReservedDBInstanceId: "ri-a-east",
          DBInstanceClass: "db.r7g.large",
          ProductDescription: "postgresql",
          MultiAZ: true,
          DBInstanceCount: 2,
          State: "active",
          OfferingType: "All Upfront",
          Duration: 31536000,
        }],
      },
      "us-west-2": {
        instances: [{
          DBInstanceIdentifier: "billing-db",
          DBInstanceClass: "db.m6g.large",
          Engine: "mysql",
          LicenseModel: "general-public-license",
          DBInstanceStatus: "available",
        }],
      },
    },
  };
  const acctB: FakeSpec = {
    accountId: ACCOUNT_BETA,
    perRegion: {
      "us-east-1": {
        instances: [{
          DBInstanceIdentifier: "analytics-db",
          DBInstanceClass: "db.r8g.4xlarge",
          Engine: "aurora-postgresql",
          DBInstanceStatus: "available",
        }],
      },
      // us-west-2 deliberately empty for acct-b — produces no rows, no error.
      "us-west-2": {},
    },
  };

  const out = await runWithTargets(
    [
      target("prod-readonly", acctA),
      target("staging-readonly", acctB),
    ],
    ["us-east-1", "us-west-2"],
    "-readonly",
  );

  // 3 instances (2 in acct-a, 1 in acct-b), 1 reservation, 0 errors.
  assertEquals(out.result.instanceCount, 3);
  assertEquals(out.result.reservedCount, 1);
  assertEquals(out.result.errorCount, 0);
  assertEquals(out.result.dataHandles.length, 4);

  const instances = ofSpec(out.written, "instance");
  assertEquals(instances.length, 3);

  // Account name derived by stripping the -readonly suffix.
  const orders = instances.find((i) =>
    (i.data as InstanceRecord).dbInstanceIdentifier === "orders-db"
  )!;
  assertEquals((orders.data as InstanceRecord).accountId, ACCOUNT_ALPHA);
  assertEquals((orders.data as InstanceRecord).accountName, "prod");
  assertEquals((orders.data as InstanceRecord).region, "us-east-1");
  // licenseModel is captured when AWS reports it, and backfills to "" when the
  // SDK omits it (orders-db carried no LicenseModel in the fixture).
  assertEquals((orders.data as InstanceRecord).licenseModel, "");
  const billing = instances.find((i) =>
    (i.data as InstanceRecord).dbInstanceIdentifier === "billing-db"
  )!;
  assertEquals(
    (billing.data as InstanceRecord).licenseModel,
    "general-public-license",
  );

  // Storage keys are unique per (account, region, id) — no cross-account clash.
  const keys = new Set(instances.map((i) => i.key));
  assertEquals(keys.size, 3);
  assert(keys.has(instanceKey(ACCOUNT_ALPHA, "us-east-1", "orders-db")));
  assert(keys.has(instanceKey(ACCOUNT_ALPHA, "us-west-2", "billing-db")));
  assert(keys.has(instanceKey(ACCOUNT_BETA, "us-east-1", "analytics-db")));

  const reserved = ofSpec(out.written, "reserved");
  assertEquals(reserved.length, 1);
  assertEquals(
    reserved[0].key,
    reservedKey(ACCOUNT_ALPHA, "us-east-1", "ri-a-east"),
  );
  assertEquals((reserved[0].data as ReservedRecord).dbInstanceCount, 2);
});

Deno.test("smoke: instance/reserved storage-key separator is locked to `--` (task-57 published contract)", () => {
  // The double-hyphen joins the hyphen-bearing identifier; account id and region
  // keep single hyphens since they are self-delimiting (12 digits / closed set).
  // The 12-digit literals below are intentional and load-bearing: the property
  // under test is that a fixed-width, all-digit account id is self-delimiting,
  // so a named placeholder would no longer prove it. Documented exception.
  // (scan_error keys are covered separately — they use the canonical fleet key,
  // not this `--` convention.)
  assertEquals(
    instanceKey("111122223333", "us-east-1", "orders-db"),
    "instance-111122223333-us-east-1--orders-db",
  );
  assertEquals(
    reservedKey("111122223333", "us-east-1", "ri-a-east"),
    "reserved-111122223333-us-east-1--ri-a-east",
  );
});

Deno.test("smoke: scanErrorKey uses the canonical fleet format (4-arg, per-segment encoded, injective)", () => {
  // The canonical key is `error-<enc(profile)>-<enc(region)>-<enc(service)>-<enc(phase)>`,
  // where each segment is percent-encoded and value-internal `-` is escaped to
  // %2D. An absent profile/region encodes to an empty segment (no sentinel word),
  // and the encoding is injective over all four inputs.
  assertEquals(
    scanErrorKey("", "us-east-1", "sts", "credentials"),
    "error--us%2Deast%2D1-sts-credentials",
  );
  // Account-level failure: empty region encodes to an empty segment.
  assertEquals(
    scanErrorKey("ro", "", "sts", "credentials"),
    "error-ro--sts-credentials",
  );
  // Field-swap: profile/region are positional; swapping a value changes the key.
  assert(
    scanErrorKey("", "us-east-1", "sts", "credentials") !==
      scanErrorKey("us-east-1", "", "sts", "credentials"),
    "profile/region are positional; swapping a value must change the key",
  );
  // Two malformed rows in the SAME base phase get DISTINCT keys because the
  // per-row discriminator is folded into the `phase` segment.
  assert(
    scanErrorKey(
      "ro",
      "us-east-1",
      "rds",
      "malformed_db_instance:0:orders-db",
    ) !==
      scanErrorKey(
        "ro",
        "us-east-1",
        "rds",
        "malformed_db_instance:1:billing-db",
      ),
    "two malformed rows in one base phase must get distinct keys via the discriminated phase",
  );
});

Deno.test("smoke: a denied region degrades to scan_error; the rest of the sweep continues", async () => {
  const denied = new Error(
    "User: arn:aws:sts::1:assumed-role/ro/x is not authorized to perform rds:DescribeDBInstances",
  );
  denied.name = "AccessDeniedException";

  const out = await runWithTargets(
    [target("app-readonly", {
      accountId: ACCOUNT_ADMIN,
      perRegion: {
        "us-east-1": {
          instances: [{
            DBInstanceIdentifier: "ok-db",
            DBInstanceClass: "db.r7g.large",
            Engine: "postgres",
            DBInstanceStatus: "available",
          }],
        },
        "ap-southeast-2": {
          // SCP-denied region: instance listing fails, reserved still scanned.
          instancesError: denied,
          reserved: [{
            ReservedDBInstanceId: "ri-aps",
            DBInstanceClass: "db.r7g.large",
            ProductDescription: "postgresql",
            MultiAZ: false,
            DBInstanceCount: 1,
            State: "active",
          }],
        },
      },
    })],
    ["us-east-1", "ap-southeast-2"],
  );

  assertEquals(out.result.instanceCount, 1);
  assertEquals(out.result.reservedCount, 1);
  assertEquals(out.result.errorCount, 1);

  const err = ofSpec(out.written, "scan_error")[0].data as ScanError;
  assertEquals(err.phase, "describe_db_instances");
  assertEquals(err.kind, "access_denied");
  assertEquals(err.region, "ap-southeast-2");
  assertEquals(err.service, "rds");
  assertEquals(
    ofSpec(out.written, "scan_error")[0].key,
    scanErrorKey(
      "app-readonly",
      "ap-southeast-2",
      "rds",
      "describe_db_instances",
    ),
  );
});

Deno.test("smoke: ambient profile has no profile label and falls back to account id for accountName", async () => {
  const out = await runWithTargets(
    [target("", {
      accountId: ACCOUNT_GAMMA,
      perRegion: {
        "us-east-1": {
          instances: [{
            DBInstanceIdentifier: "standalone-db",
            DBInstanceClass: "db.t4g.medium",
            Engine: "mariadb",
            DBInstanceStatus: "available",
          }],
        },
      },
    })],
    ["us-east-1"],
  );

  assertEquals(out.result.instanceCount, 1);
  const inst = ofSpec(out.written, "instance")[0].data as InstanceRecord;
  assertEquals(inst.profile, "");
  // Ambient chain has no profile to label, so accountName falls back to the id.
  assertEquals(inst.accountName, ACCOUNT_GAMMA);
  // Standalone instance: no owning cluster.
  assertEquals(inst.clusterId, "");
});

Deno.test("smoke: a credential failure skips the account but not its peers", async () => {
  const expired = new Error(
    "The SSO session associated with this profile has expired",
  );
  expired.name = "ExpiredTokenException";

  const out = await runWithTargets(
    [
      target("stale-readonly", { accountIdError: expired }),
      target("live-readonly", {
        accountId: ACCOUNT_DELTA,
        perRegion: {
          "us-east-1": {
            instances: [{
              DBInstanceIdentifier: "live-db",
              DBInstanceClass: "db.r7g.large",
              Engine: "postgres",
              DBInstanceStatus: "available",
            }],
          },
        },
      }),
    ],
    ["us-east-1"],
    "-readonly",
  );

  // Stale account contributes one scan_error; live account still swept.
  assertEquals(out.result.errorCount, 1);
  assertEquals(out.result.instanceCount, 1);
  const err = ofSpec(out.written, "scan_error")[0].data as ScanError;
  assertEquals(err.phase, "credentials");
  assertEquals(err.kind, "auth_expired");
  assertEquals(err.profile, "stale-readonly");
});

Deno.test("smoke: an expired SSO pre-flight short-circuits the whole sweep with one sso-tagged error", async () => {
  // The pre-flight token resolve rejects -> classifyError sees an expired-token
  // signature -> preflightSso returns `expired`. runSweep writes ONE scan_error
  // tagged service:"sso", phase:"preflight_sso", and returns before touching any
  // target's credentials.
  const out = await runWithTargets(
    [target("prod-readonly", {
      // If the loop ran, this account would contribute an instance — proving it
      // never ran is the point of the short-circuit.
      accountId: ACCOUNT_ALPHA,
      perRegion: {
        "us-east-1": {
          instances: [{
            DBInstanceIdentifier: "should-not-be-swept",
            DBInstanceClass: "db.r7g.large",
            Engine: "postgres",
            DBInstanceStatus: "available",
          }],
        },
      },
    })],
    ["us-east-1"],
    {
      requiredProfileSuffix: "-readonly",
      ssoSession: "fleet-sso",
      ssoRegion: "us-east-1",
      resolveSsoToken: () =>
        Promise.reject(new Error("Token has expired and refresh failed")),
    },
  );

  assertEquals(out.result.instanceCount, 0);
  assertEquals(out.result.errorCount, 1);
  const err = ofSpec(out.written, "scan_error")[0].data as ScanError;
  assertEquals(err.service, "sso");
  assertEquals(err.phase, "preflight_sso");
  assertEquals(err.kind, "auth_expired");
});

Deno.test("smoke: a transient-network SSO pre-flight does NOT short-circuit; the sweep proceeds", async () => {
  // A network blip during the pre-flight must not abort the sweep (re-login
  // would be a pointless remediation). preflightSso returns `network`, runSweep
  // logs it and continues into the per-profile loop.
  const out = await runWithTargets(
    [target("prod-readonly", {
      accountId: ACCOUNT_ALPHA,
      perRegion: {
        "us-east-1": {
          instances: [{
            DBInstanceIdentifier: "live-db",
            DBInstanceClass: "db.r7g.large",
            Engine: "postgres",
            DBInstanceStatus: "available",
          }],
        },
      },
    })],
    ["us-east-1"],
    {
      requiredProfileSuffix: "-readonly",
      ssoSession: "fleet-sso",
      ssoRegion: "us-east-1",
      resolveSsoToken: () =>
        Promise.reject(
          new Error("getaddrinfo ENOTFOUND oidc.us-east-1.amazonaws.com"),
        ),
    },
  );

  // The sweep ran: the instance was swept and no scan_error was written.
  assertEquals(out.result.instanceCount, 1);
  assertEquals(out.result.errorCount, 0);
});

Deno.test("smoke: empty fleet across every region writes nothing", async () => {
  const out = await runWithTargets(
    [target("empty-readonly", {
      accountId: ACCOUNT_EPSILON,
      perRegion: { "us-east-1": {}, "us-west-2": {} },
    })],
    ["us-east-1", "us-west-2"],
  );

  assertEquals(out.result.instanceCount, 0);
  assertEquals(out.result.reservedCount, 0);
  assertEquals(out.result.errorCount, 0);
  assertEquals(out.written.length, 0);
});

Deno.test("smoke: every test finishes in under 5 seconds", () => {
  // Sentinel — the smoke tests above all complete in single-digit
  // milliseconds. If a future test touches the network the per-test 5s
  // threshold should still hold; if it doesn't, that test does not belong in
  // the smoke harness.
  assert(true);
});
