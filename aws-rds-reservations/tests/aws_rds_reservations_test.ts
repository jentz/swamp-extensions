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

import {
  assertEquals,
  assertRejects,
  assertStrictEquals,
} from "jsr:@std/assert@1";
import { createModelTestContext } from "jsr:@systeminit/swamp-testing@0.20260525.18";
import {
  accountNameFromProfile,
  type AwsApi,
  type AwsDBInstance,
  type AwsReservedDBInstance,
  buildTargets,
  classifyError,
  type CredentialProvider,
  getCallerAccountId,
  type Page,
  paginate,
  resolveBootstrapRegion,
  runSweep,
  safeDestroy,
  sdkApiWithFactories,
  type SdkClient,
  type SweepTarget,
  tagsFromAws,
} from "../aws_rds_reservations.ts";
import { isThrottlingError, type RetryDeps, withRetry } from "../_lib/retry.ts";

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
  const err = new Error(
    "The SSO session associated with this profile has expired",
  );
  assertEquals(classifyError(err).kind, "auth_expired");
});

Deno.test("classifyError: SSO role ARN in AccessDenied does NOT misfire to auth_expired", () => {
  const err = new Error(
    "User: arn:aws:sts::1:assumed-role/AWSReservedSSO_ro/x is not authorized to perform rds:DescribeDBInstances",
  );
  assertEquals(classifyError(err).kind, "access_denied");
});

Deno.test("resolveBootstrapRegion: first configured region wins", () => {
  assertEquals(
    resolveBootstrapRegion(["us-east-1"], () => undefined),
    "us-east-1",
  );
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

Deno.test("buildTargets: empty profiles produce one ambient target", () => {
  const logger = {};
  const api = fakeApi({ accountId: "111122223333" });
  const calls: Array<{
    credentials: CredentialProvider | undefined;
    bootstrapRegion: string;
    logger: unknown;
  }> = [];

  const targets = buildTargets({
    profiles: [],
    bootstrapRegion: "eu-north-1",
    logger,
    apiFactory: (credentials, bootstrapRegion, gotLogger) => {
      calls.push({ credentials, bootstrapRegion, logger: gotLogger });
      return api;
    },
    credentialFactory: () => {
      throw new Error("ambient target must not construct profile credentials");
    },
  });

  assertEquals(targets.length, 1);
  assertEquals(targets[0].profile, "");
  assertStrictEquals(targets[0].api, api);
  assertEquals(calls.length, 1);
  assertStrictEquals(calls[0].credentials, undefined);
  assertEquals(calls[0].bootstrapRegion, "eu-north-1");
  assertStrictEquals(calls[0].logger, logger);
});

Deno.test("buildTargets: named profiles use credentialFactory and preserve order", () => {
  const logger = {};
  const prodCredential = (() =>
    Promise.resolve({
      accessKeyId: "prod-access-key",
      secretAccessKey: "prod-secret-key",
    })) as CredentialProvider;
  const devCredential = (() =>
    Promise.resolve({
      accessKeyId: "dev-access-key",
      secretAccessKey: "dev-secret-key",
    })) as CredentialProvider;
  const credentialsByProfile: Record<string, CredentialProvider> = {
    "prod-readonly": prodCredential,
    "dev-readonly": devCredential,
  };
  const credentialCalls: string[] = [];
  const apiCalls: Array<{
    credentials: CredentialProvider | undefined;
    bootstrapRegion: string;
    logger: unknown;
  }> = [];
  const apis = [
    fakeApi({ accountId: "111122223333" }),
    fakeApi({ accountId: "444455556666" }),
  ];

  const targets = buildTargets({
    profiles: ["prod-readonly", "dev-readonly"],
    bootstrapRegion: "us-west-2",
    logger,
    credentialFactory: ({ profile }) => {
      credentialCalls.push(profile);
      return credentialsByProfile[profile];
    },
    apiFactory: (credentials, bootstrapRegion, gotLogger) => {
      apiCalls.push({ credentials, bootstrapRegion, logger: gotLogger });
      return apis[apiCalls.length - 1];
    },
  });

  assertEquals(credentialCalls, ["prod-readonly", "dev-readonly"]);
  assertEquals(targets.map((t) => t.profile), [
    "prod-readonly",
    "dev-readonly",
  ]);
  assertStrictEquals(targets[0].api, apis[0]);
  assertStrictEquals(targets[1].api, apis[1]);
  assertEquals(apiCalls.length, 2);
  assertStrictEquals(apiCalls[0].credentials, prodCredential);
  assertStrictEquals(apiCalls[1].credentials, devCredential);
  assertEquals(apiCalls.map((c) => c.bootstrapRegion), [
    "us-west-2",
    "us-west-2",
  ]);
  assertStrictEquals(apiCalls[0].logger, logger);
  assertStrictEquals(apiCalls[1].logger, logger);
});

Deno.test("runSweep: injected clock propagates to instance, reserved, and scan_error rows", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  const fixedNow = new Date("2026-01-02T03:04:05.006Z");
  await runSweep({
    targets: [
      target("prod-readonly", {
        accountId: "111122223333",
        perRegion: {
          "us-east-1": {
            instances: [{
              DBInstanceIdentifier: "orders-db",
              DBInstanceClass: "db.r7g.large",
            }],
            reserved: [{
              ReservedDBInstanceId: "ri-1",
              DBInstanceClass: "db.r7g.large",
            }],
          },
        },
      }),
      target("admin", { accountId: "444455556666" }),
    ],
    regions: ["us-east-1"],
    requiredProfileSuffix: "-readonly",
    context,
    now: () => fixedNow,
  });

  const scannedAtValues = getWrittenResources().map((w) =>
    (w.data as Record<string, unknown>).scannedAt
  );
  assertEquals(scannedAtValues, [
    "2026-01-02T03:04:05.006Z",
    "2026-01-02T03:04:05.006Z",
    "2026-01-02T03:04:05.006Z",
  ]);
});

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

Deno.test("runSweep: empty regions writes one no_regions scan_error and makes no AWS call", async () => {
  const { context, getWrittenResources } = createModelTestContext({});
  // A spying facade that fails loudly if any AWS call slips through, so the
  // test proves the guard returns before getAccountId / describe* run.
  const aws = { accountId: false, instances: false, reserved: false };
  const spyApi: AwsApi = {
    getAccountId: () => {
      aws.accountId = true;
      return Promise.resolve("111122223333");
    },
    describeDBInstances: (_region) => {
      aws.instances = true;
      return Promise.resolve([]);
    },
    describeReservedDBInstances: (_region) => {
      aws.reserved = true;
      return Promise.resolve([]);
    },
  };

  const result = await runSweep({
    targets: [{ profile: "prod-readonly", api: spyApi }],
    regions: [],
    requiredProfileSuffix: "-readonly",
    context,
  });

  // Counts: exactly one error, zero data rows.
  assertEquals(result.instanceCount, 0);
  assertEquals(result.reservedCount, 0);
  assertEquals(result.errorCount, 1);

  // No AWS work happened — the guard short-circuits before the targets loop.
  assertEquals(aws.accountId, false);
  assertEquals(aws.instances, false);
  assertEquals(aws.reserved, false);

  // Exactly one scan_error, none of any other spec.
  const written = getWrittenResources();
  assertEquals(written.length, 1);
  assertEquals(written.filter((w) => w.specName === "instance").length, 0);
  assertEquals(written.filter((w) => w.specName === "reserved").length, 0);
  const errs = written.filter((w) => w.specName === "scan_error");
  assertEquals(errs.length, 1);

  const err = errs[0].data as Record<string, unknown>;
  assertEquals(err.phase, "no_regions");
  assertEquals(err.kind, "other");
  assertEquals(err.profile, "");
  assertEquals(err.accountId, "");
  assertEquals(err.region, "");
});

// ---------------------------------------------------------------------------
// Throttling retry — withRetry / isThrottlingError (ported verbatim from the
// sibling @jentz/aws-rds-inventory test, since _lib/retry.ts is a byte-identical
// twin) plus a paginate() loop+retry wiring test specific to this model.
// ---------------------------------------------------------------------------

Deno.test("isThrottlingError: matches ThrottlingException name", () => {
  const err = new Error("rate exceeded");
  err.name = "ThrottlingException";
  assertEquals(isThrottlingError(err), true);
});

Deno.test("isThrottlingError: matches by message substring", () => {
  assertEquals(isThrottlingError(new Error("Throttling: slow down")), true);
  assertEquals(isThrottlingError(new Error("TooManyRequests")), true);
  assertEquals(isThrottlingError(new Error("RequestLimitExceeded")), true);
});

Deno.test("isThrottlingError: message fallback covers every name in the switch", () => {
  // The word-boundary regex is strict — `TooManyRequests` does not match inside
  // `TooManyRequestsException` because there is no word boundary between `s`
  // and `E`. The regex must spell out both bare and `*Exception`-suffixed
  // forms so an SDK wrapper that puts the full token in `.message` while
  // collapsing `.name` to "Error" still trips the retry path.
  assertEquals(
    isThrottlingError(new Error("ThrottlingException: ...")),
    true,
  );
  assertEquals(
    isThrottlingError(new Error("TooManyRequestsException: ...")),
    true,
  );
  assertEquals(
    isThrottlingError(new Error("RequestThrottledException: ...")),
    true,
  );
});

Deno.test("isThrottlingError: regular errors do not match", () => {
  assertEquals(isThrottlingError(new Error("connection refused")), false);
  assertEquals(isThrottlingError(undefined), false);
  assertEquals(isThrottlingError(null), false);
});

Deno.test("getCallerAccountId: retries throttled STS call then returns account id", async () => {
  const throttled = new Error("rate exceeded");
  throttled.name = "ThrottlingException";
  let calls = 0;
  const retryEvents: Array<
    { operationName: string; attempt: number; delayMs: number }
  > = [];
  const deps: RetryDeps = {
    random: () => 0.25,
    delay: () => Promise.resolve(),
    onRetry: (event) => {
      retryEvents.push({
        operationName: event.operationName,
        attempt: event.attempt,
        delayMs: event.delayMs,
      });
    },
  };

  const accountId = await getCallerAccountId(() => {
    calls++;
    if (calls === 1) return Promise.reject(throttled);
    return Promise.resolve({ Account: "111122223333" });
  }, deps);

  assertEquals(accountId, "111122223333");
  assertEquals(calls, 2);
  assertEquals(retryEvents, [{
    operationName: "GetCallerIdentity",
    attempt: 1,
    delayMs: 250,
  }]);
});

Deno.test("withRetry: succeeds on first try, no waiting", async () => {
  let waited = 0;
  const result = await withRetry(
    () => Promise.resolve(42),
    "test",
    {},
    {
      random: () => 0,
      delay: (ms) => {
        waited += ms;
        return Promise.resolve();
      },
    },
  );
  assertEquals(result, 42);
  assertEquals(waited, 0);
});

Deno.test("withRetry: retries throttling errors then succeeds", async () => {
  const delays: number[] = [];
  const events: number[] = [];
  let attempts = 0;
  const result = await withRetry(
    () => {
      attempts++;
      if (attempts < 3) {
        const err = new Error("Throttling");
        return Promise.reject(err);
      }
      return Promise.resolve("ok");
    },
    "DescribeReservedDBInstances",
    { baseDelayMs: 10, maxDelayMs: 1000 },
    {
      // Full jitter: with random()==1 we get the full ceiling.
      random: () => 1,
      delay: (ms) => {
        delays.push(ms);
        return Promise.resolve();
      },
      onRetry: (e) => events.push(e.attempt),
    },
  );
  assertEquals(result, "ok");
  assertEquals(attempts, 3);
  // Two delays for two retries. Ceiling doubles each attempt.
  assertEquals(delays, [10, 20]);
  assertEquals(events, [1, 2]);
});

Deno.test("withRetry: non-throttling errors propagate without retry", async () => {
  let attempts = 0;
  await assertRejects(
    () =>
      withRetry(
        () => {
          attempts++;
          return Promise.reject(new Error("Bad input"));
        },
        "test",
        {},
        {
          random: () => 0,
          delay: () => Promise.resolve(),
        },
      ),
    Error,
    "Bad input",
  );
  assertEquals(attempts, 1);
});

Deno.test("withRetry: gives up after maxAttempts and rethrows", async () => {
  let attempts = 0;
  await assertRejects(
    () =>
      withRetry(
        () => {
          attempts++;
          return Promise.reject(new Error("Throttling"));
        },
        "test",
        { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 1 },
        {
          random: () => 0,
          delay: () => Promise.resolve(),
        },
      ),
    Error,
    "Throttling",
  );
  assertEquals(attempts, 3);
});

Deno.test("paginate: drains every page in order, no retry on the happy path", async () => {
  const pages: Record<string, Page<number>> = {
    "": { items: [1, 2], marker: "m1" },
    "m1": { items: [3, 4], marker: "m2" },
    "m2": { items: [5], marker: undefined },
  };
  const seen: (string | undefined)[] = [];
  let waited = 0;
  const out = await paginate<number>(
    (marker) => {
      seen.push(marker);
      return Promise.resolve(pages[marker ?? ""]);
    },
    "DescribeDBInstances",
    {
      random: () => 0,
      delay: (ms) => {
        waited += ms;
        return Promise.resolve();
      },
    },
  );
  assertEquals(out, [1, 2, 3, 4, 5]);
  // First page uses marker=undefined, then follows each returned marker.
  assertEquals(seen, [undefined, "m1", "m2"]);
  assertEquals(waited, 0);
});

Deno.test("paginate: a throttled page is retried then succeeds (loop+retry wired)", async () => {
  // The first send for the SECOND page throttles once, then succeeds — proving
  // the retry wraps the per-page send and resumes at the same marker rather
  // than restarting the drain from page one.
  let throttledSecondPage = 0;
  const events: string[] = [];
  const out = await paginate<number>(
    (marker) => {
      if (marker === undefined) {
        return Promise.resolve({ items: [1, 2], marker: "m1" });
      }
      if (marker === "m1" && throttledSecondPage === 0) {
        throttledSecondPage++;
        const err = new Error("Throttling: slow down");
        err.name = "ThrottlingException";
        return Promise.reject(err);
      }
      return Promise.resolve({ items: [3, 4], marker: undefined });
    },
    "DescribeReservedDBInstances",
    {
      random: () => 1,
      delay: () => Promise.resolve(),
      onRetry: (e) => events.push(`${e.operationName}#${e.attempt}`),
    },
  );
  assertEquals(out, [1, 2, 3, 4]);
  assertEquals(throttledSecondPage, 1);
  // Exactly one retry, on the reserved describe op.
  assertEquals(events, ["DescribeReservedDBInstances#1"]);
});

Deno.test("paginate: post-exhaustion throttle propagates to the caller", async () => {
  // After maxAttempts the throttle is rethrown — runSweep's try/catch then
  // turns it into a scan_error. We assert the error escapes paginate rather
  // than being swallowed.
  await assertRejects(
    () =>
      paginate<number>(
        () => {
          const err = new Error("Throttling");
          err.name = "ThrottlingException";
          return Promise.reject(err);
        },
        "DescribeDBInstances",
        {
          random: () => 0,
          delay: () => Promise.resolve(),
        },
      ),
    Error,
    "Throttling",
  );
});

// ---------------------------------------------------------------------------
// SDK client lifetime — injected client factories prove every RDSClient /
// STSClient is destroyed exactly once on success, throttle-then-success, and
// thrown-error paths, without resetting pagination or masking the error
// (task-82). Driven through sdkApiWithFactories so the public AwsApi /
// ApiFactory surface and production defaults stay untouched.
// ---------------------------------------------------------------------------

// A no-throttle, no-wait retry surface so sdkApiWithFactories' internal
// retryDeps (real Math.random / setTimeout) is bypassed deterministically only
// where the fake send drives the throttle. The factory clients still go through
// the model's own retryDeps, so we keep the throttle on the FIRST send and rely
// on the standard full-jitter retry to re-issue — matching how paginate /
// getCallerAccountId tests simulate throttle-then-success.

/**
 * Build a fake SDK client recording send + destroy, with scripted send behavior.
 *
 * `send` first asserts the client has NOT been destroyed yet. This gives the
 * fake teeth against a premature-destroy regression: if `destroy()` ever fires
 * before the pagination drain completes (e.g. a lost `await` on
 * `return await paginate(...)`, so the `finally` runs while a later page is
 * still in flight), the next page's `send` lands after `destroyCount` has been
 * bumped and trips this assertion — turning a silent ordering bug into a red
 * test. A counter-only `destroy` cannot catch this, since the post-drain
 * `destroyCount === 1` assertion stays green either way.
 */
function fakeClient<C, R>(
  send: (command: C) => Promise<R>,
): SdkClient<C, R> & { destroyCount: number; sendCount: number } {
  const client = {
    sendCount: 0,
    destroyCount: 0,
    send(command: C): Promise<R> {
      assertEquals(
        client.destroyCount,
        0,
        "send() called after destroy() — client destroyed before the drain finished",
      );
      client.sendCount++;
      return send(command);
    },
    destroy(): void {
      client.destroyCount++;
    },
  };
  return client;
}

/** Minimal view of an AWS SDK command — its `input` carries the `Marker`. */
interface DescribeDBInstancesCommandLike {
  input?: { Marker?: string };
}

function throttle(): Error {
  const err = new Error("Throttling: slow down");
  err.name = "ThrottlingException";
  return err;
}

const noopLogger = { debug() {}, info() {}, warn() {} };

Deno.test("safeDestroy: invokes destroy once and swallows a destroy() failure", () => {
  let destroyed = 0;
  safeDestroy({
    destroy() {
      destroyed++;
    },
  });
  assertEquals(destroyed, 1);

  // A throwing destroy must not propagate; the debug logger is invoked.
  const logs: string[] = [];
  safeDestroy(
    {
      destroy() {
        throw new Error("socket already closed");
      },
    },
    { debug: (msg: string) => logs.push(msg) },
  );
  assertEquals(logs.length, 1);
  // Tolerates a missing client / missing destroy.
  safeDestroy(undefined);
  safeDestroy({});
});

Deno.test("sdkApi getAccountId: destroys the STS client once on success", async () => {
  const sts = fakeClient(() => Promise.resolve({ Account: "111122223333" }));
  const api = sdkApiWithFactories(
    undefined,
    "us-east-1",
    noopLogger,
    undefined,
    () => sts,
  );
  const accountId = await api.getAccountId();
  assertEquals(accountId, "111122223333");
  assertEquals(sts.sendCount, 1);
  assertEquals(sts.destroyCount, 1);
});

Deno.test("sdkApi getAccountId: destroys the STS client once after throttle-then-success", async () => {
  let calls = 0;
  const sts = fakeClient(() => {
    calls++;
    if (calls === 1) return Promise.reject(throttle());
    return Promise.resolve({ Account: "444455556666" });
  });
  const api = sdkApiWithFactories(
    undefined,
    "us-east-1",
    noopLogger,
    undefined,
    () => sts,
  );
  const accountId = await api.getAccountId();
  assertEquals(accountId, "444455556666");
  assertEquals(calls, 2);
  // Destroyed exactly once even though send retried — destroy is per-client,
  // after the whole drain, never per-attempt.
  assertEquals(sts.destroyCount, 1);
});

Deno.test("sdkApi getAccountId: destroys the STS client once on thrown error, error propagates", async () => {
  const boom = new Error("AccessDenied");
  boom.name = "AccessDeniedException";
  const sts = fakeClient(() => Promise.reject(boom));
  const api = sdkApiWithFactories(
    undefined,
    "us-east-1",
    noopLogger,
    undefined,
    () => sts,
  );
  await assertRejects(() => api.getAccountId(), Error, "AccessDenied");
  assertEquals(sts.destroyCount, 1);
});

Deno.test("sdkApi describeDBInstances: destroys the RDS client once on multi-page success, after the drain", async () => {
  // Two pages on the happy path. The fake's send asserts destroyCount === 0,
  // so if a lost `await` on `return await paginate(...)` let the finally's
  // safeDestroy fire before the second page's send, that send would land
  // post-destroy and trip the in-send assertion — catching the ordering bug a
  // counter-only fake misses. destroy still runs exactly once, after the drain.
  const rds = fakeClient((
    command: DescribeDBInstancesCommandLike,
  ): Promise<{ DBInstances: AwsDBInstance[]; Marker: string | undefined }> => {
    const marker = command.input?.Marker;
    if (marker === undefined) {
      return Promise.resolve({
        DBInstances: [{ DBInstanceIdentifier: "orders-db" }],
        Marker: "m1",
      });
    }
    return Promise.resolve({
      DBInstances: [{ DBInstanceIdentifier: "carts-db" }],
      Marker: undefined,
    });
  });
  const created: string[] = [];
  const api = sdkApiWithFactories(
    undefined,
    "us-east-1",
    noopLogger,
    (region) => {
      created.push(region);
      return rds;
    },
  );
  const out = await api.describeDBInstances("eu-north-1");
  assertEquals(out.map((d) => d.DBInstanceIdentifier), [
    "orders-db",
    "carts-db",
  ]);
  assertEquals(rds.sendCount, 2);
  assertEquals(created, ["eu-north-1"]);
  assertEquals(rds.destroyCount, 1);
});

Deno.test("sdkApi describeDBInstances: destroys the RDS client once after throttle-then-success, no pagination reset", async () => {
  // The first send throttles, then the drain proceeds across two real pages.
  // destroy must run exactly once after the full drain, and the marker loop
  // must NOT restart from page one. The fake's send also asserts
  // destroyCount === 0, so a lost `await` on `return await paginate(...)` that
  // let safeDestroy fire mid-drain would trip the in-send guard on the second
  // page rather than passing silently.
  let firstThrottled = false;
  const markersSeen: (string | undefined)[] = [];
  const rds = fakeClient((
    command: DescribeDBInstancesCommandLike,
  ): Promise<{ DBInstances: AwsDBInstance[]; Marker: string | undefined }> => {
    const marker = command.input?.Marker;
    if (marker === undefined && !firstThrottled) {
      firstThrottled = true;
      return Promise.reject(throttle());
    }
    markersSeen.push(marker);
    if (marker === undefined) {
      return Promise.resolve({
        DBInstances: [{ DBInstanceIdentifier: "a" }],
        Marker: "m1",
      });
    }
    return Promise.resolve({
      DBInstances: [{ DBInstanceIdentifier: "b" }],
      Marker: undefined,
    });
  });
  const api = sdkApiWithFactories(
    undefined,
    "us-east-1",
    noopLogger,
    () => rds,
  );
  const out = await api.describeDBInstances("us-east-1");
  assertEquals(out.map((d) => d.DBInstanceIdentifier), ["a", "b"]);
  // Successful page sends saw the first page once then the second marker once —
  // proving the retry resumed at the same marker, not a drain restart.
  assertEquals(markersSeen, [undefined, "m1"]);
  assertEquals(rds.destroyCount, 1);
});

Deno.test("sdkApi describeReservedDBInstances: destroys the RDS client once on thrown error, error propagates", async () => {
  const boom = new Error("AccessDenied");
  boom.name = "AccessDeniedException";
  const rds = fakeClient(() => Promise.reject(boom));
  const api = sdkApiWithFactories(
    undefined,
    "us-east-1",
    noopLogger,
    () => rds,
  );
  await assertRejects(
    () => api.describeReservedDBInstances("us-east-1"),
    Error,
    "AccessDenied",
  );
  assertEquals(rds.destroyCount, 1);
});
