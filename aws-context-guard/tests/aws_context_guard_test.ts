/**
 * Unit tests for the @jentz/aws-context-guard extension model.
 *
 * STS is mocked by replacing `STSClient.prototype.send` so no real AWS calls
 * are made. Env vars are set/restored per-test in try/finally blocks.
 */

import {
  assertEquals,
  assertExists,
  assertRejects,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import { STSClient } from "npm:@aws-sdk/client-sts@3.1063.0";
import { model } from "../aws_context_guard.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface FakeStsResponse {
  Account?: string;
  Arn?: string;
  UserId?: string;
}

interface RunVerifyOptions {
  profile?: string;
  region?: string;
  globalArgs?: {
    expectedAccountId?: string;
    requiredProfileSuffix?: string;
  };
  stsResponse?: FakeStsResponse | Error;
}

/**
 * Minimal fake runtime context accepted by the verify method.
 * Captures the last `writeResource` call so tests can assert on it.
 */
function makeContext(globalArgs: Record<string, unknown>) {
  let lastWrite: { name: string; key: string; data: unknown } | undefined;
  return {
    context: {
      globalArgs,
      logger: {
        info: () => {},
        debug: () => {},
        warn: () => {},
        error: () => {},
      },
      writeResource: (
        name: string,
        key: string,
        data: unknown,
      ) => {
        lastWrite = { name, key, data };
        return Promise.resolve({ id: "fake-handle" });
      },
    },
    getLastWrite: () => lastWrite,
  };
}

/**
 * Run the verify method with mocked STS and env vars.
 * Restores everything in finally, regardless of outcome.
 */
async function runVerify(opts: RunVerifyOptions = {}) {
  const {
    profile = "prod-readonly",
    region = "eu-west-1",
    globalArgs: rawArgs = {},
    stsResponse = {
      Account: "123456789012",
      Arn: "arn:aws:iam::123456789012:user/testuser",
      UserId: "AIDAXXXXXXXXXXXXXXXXX",
    },
  } = opts;

  const mergedArgs = {
    expectedAccountId: "123456789012",
    requiredProfileSuffix: "-readonly",
    ...rawArgs,
  };

  // Save env state.
  const prevProfile = Deno.env.get("AWS_PROFILE");
  const prevRegion = Deno.env.get("AWS_REGION");

  // Save STS send.
  const originalSend = STSClient.prototype.send;

  try {
    // Set env.
    Deno.env.set("AWS_PROFILE", profile);
    if (region !== undefined) {
      Deno.env.set("AWS_REGION", region);
    } else {
      Deno.env.delete("AWS_REGION");
    }

    // Install STS mock.
    STSClient.prototype.send = function () {
      if (stsResponse instanceof Error) {
        return Promise.reject(stsResponse);
      }
      return Promise.resolve(stsResponse);
    } as typeof originalSend;

    const { context, getLastWrite } = makeContext(mergedArgs);
    const result = await model.methods.verify.execute({} as never, context);
    return { result, lastWrite: getLastWrite() };
  } finally {
    // Restore env.
    if (prevProfile !== undefined) {
      Deno.env.set("AWS_PROFILE", prevProfile);
    } else {
      Deno.env.delete("AWS_PROFILE");
    }
    if (prevRegion !== undefined) {
      Deno.env.set("AWS_REGION", prevRegion);
    } else {
      Deno.env.delete("AWS_REGION");
    }

    // Restore STS.
    STSClient.prototype.send = originalSend;
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

Deno.test("profile suffix mismatch — throws", async () => {
  await assertRejects(
    () =>
      runVerify({
        profile: "dev-admin",
        globalArgs: { requiredProfileSuffix: "-readonly" },
      }),
    Error,
    "does not end with required suffix",
  );
});

Deno.test("profile suffix match — no profile error", async () => {
  const { result } = await runVerify({
    profile: "prod-readonly",
    globalArgs: { requiredProfileSuffix: "-readonly" },
  });
  assertExists(result);
});

Deno.test("empty suffix bypass — suffix check skipped", async () => {
  // Profile that would normally fail the suffix check passes when suffix is "".
  const { result } = await runVerify({
    profile: "dev-admin",
    globalArgs: { requiredProfileSuffix: "" },
  });
  assertExists(result);
});

Deno.test("account mismatch — throws", async () => {
  await assertRejects(
    () =>
      runVerify({
        globalArgs: { expectedAccountId: "222222222222" },
        stsResponse: {
          Account: "111111111111",
          Arn: "arn:aws:iam::111111111111:user/testuser",
          UserId: "AIDAXXXXXXXXXXXXXXXXX",
        },
      }),
    Error,
    "expected 222222222222",
  );
});

Deno.test("account match (full success) — returns context with all fields", async () => {
  const expectedAccountId = "123456789012";
  const expectedArn = "arn:aws:iam::123456789012:user/testuser";
  const expectedUserId = "AIDAXXXXXXXXXXXXXXXXX";
  const expectedProfile = "prod-readonly";
  const expectedRegion = "eu-west-1";

  const { result, lastWrite } = await runVerify({
    profile: expectedProfile,
    region: expectedRegion,
    globalArgs: {
      expectedAccountId,
      requiredProfileSuffix: "-readonly",
    },
    stsResponse: {
      Account: expectedAccountId,
      Arn: expectedArn,
      UserId: expectedUserId,
    },
  });

  // Method must return dataHandles.
  assertExists(result);
  assertExists(result.dataHandles);
  assertEquals(result.dataHandles.length, 1);

  // writeResource must have been called with correct context.
  assertExists(lastWrite);
  assertEquals(lastWrite.name, "context");
  assertEquals(lastWrite.key, "current");

  const data = lastWrite.data as Record<string, string>;
  assertEquals(data.accountId, expectedAccountId);
  assertEquals(data.arn, expectedArn);
  assertEquals(data.userId, expectedUserId);
  assertEquals(data.profile, expectedProfile);
  assertEquals(data.region, expectedRegion);
  assertExists(data.verifiedAt); // ISO datetime — just check presence
});

Deno.test("STS error propagation — throws with sensible message", async () => {
  await assertRejects(
    () =>
      runVerify({
        stsResponse: new Error("Network failure: connection refused"),
      }),
    Error,
    "Network failure",
  );
});

Deno.test("AWS_PROFILE unset — throws before any AWS call", async () => {
  await assertRejects(
    () => runVerify({ profile: "" }),
    Error,
    "AWS_PROFILE is not set",
  );
});

Deno.test("STS returns empty Account — throws", async () => {
  await assertRejects(
    () =>
      runVerify({
        stsResponse: {
          Account: "",
          Arn: "arn:aws:iam::000000000000:user/testuser",
          UserId: "AIDAXXXXXXXXXXXXXXXXX",
        },
      }),
    Error,
    "returned no Account",
  );
});

Deno.test("globalArgs schema-parse failure — throws with field detail", async () => {
  // The runtime would normally validate at instance-create, but the
  // execute path also safeParses as defense in depth. Pass an
  // expectedAccountId that doesn't match /^\d{12}$/.
  await assertRejects(
    () =>
      runVerify({
        globalArgs: { expectedAccountId: "not-12-digits" },
      }),
    Error,
    "invalid globalArgs",
  );
});
