/**
 * Colocated smoke tests for the @jentz/aws-s3-bucket-audit report extension.
 *
 * This file sits beside the report entrypoint (`s3_bucket_audit.ts`) and
 * covers the three behaviors that matter most for a report extension: a
 * representative rule PASS, a representative rule FAIL, and the
 * never-throws SKIP path of `report.execute` when no step data is present.
 *
 * The exhaustive per-rule matrix (117 cases across every rule and edge
 * case) lives in `tests/s3_bucket_audit_test.ts`. This file deliberately
 * does NOT duplicate that matrix — it exercises a single pass/fail/skip
 * triad so the report's success and failure paths are visible right next
 * to the entrypoint.
 */

import {
  assert,
  assertEquals,
  assertExists,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import {
  type BucketBundle,
  checkEncryption,
  checkVersioning,
  report,
} from "./s3_bucket_audit.ts";

// ---------------------------------------------------------------------------
// Representative PASS — a compliant bucket
// ---------------------------------------------------------------------------

/** A bucket whose state satisfies the versioning and encryption rules. */
function compliantBundle(): BucketBundle {
  return {
    name: "compliant-bucket",
    state: {
      BucketName: "compliant-bucket",
      VersioningConfiguration: { Status: "Enabled" },
      BucketEncryption: {
        ServerSideEncryptionConfiguration: [
          { ServerSideEncryptionByDefault: { SSEAlgorithm: "AES256" } },
        ],
      },
    } as unknown as BucketBundle["state"],
  };
}

Deno.test("checkVersioning: PASS on a compliant bucket", () => {
  const f = checkVersioning(compliantBundle());
  assertEquals(f.id, "bucket-versioning-enabled");
  assertEquals(f.status, "pass");
});

Deno.test("checkEncryption: PASS on a compliant bucket", () => {
  const f = checkEncryption(compliantBundle());
  assertEquals(f.id, "bucket-encryption-enabled");
  assertEquals(f.status, "pass");
});

// ---------------------------------------------------------------------------
// Representative FAIL — a noncompliant bucket
// ---------------------------------------------------------------------------

Deno.test("checkVersioning: FAIL when versioning is not enabled", () => {
  const b: BucketBundle = {
    name: "noncompliant-bucket",
    state: {
      BucketName: "noncompliant-bucket",
      VersioningConfiguration: { Status: "Suspended" },
    } as unknown as BucketBundle["state"],
  };
  const f = checkVersioning(b);
  assertEquals(f.status, "fail");
});

Deno.test("checkEncryption: FAIL when no default encryption is configured", () => {
  const b: BucketBundle = {
    name: "noncompliant-bucket",
    state: {
      BucketName: "noncompliant-bucket",
    } as unknown as BucketBundle["state"],
  };
  const f = checkEncryption(b);
  assertEquals(f.status, "fail");
});

// ---------------------------------------------------------------------------
// SKIP / never-throws — report.execute with no step data
// ---------------------------------------------------------------------------

function silentLogger() {
  return {
    info: () => {},
    debug: () => {},
    warn: () => {},
    error: () => {},
  };
}

/** Minimal workflow-scope report context with no bucket/policy step data. */
function emptyContext() {
  return {
    workflowName: "smoke-workflow",
    stepExecutions: [],
    logger: silentLogger(),
    dataRepository: {
      getContent: (): Promise<Uint8Array | null> => Promise.resolve(null),
    },
  };
}

Deno.test(
  "report.execute: returns markdown + JSON and does not throw when no step data is present",
  async () => {
    const out = await report.execute(emptyContext());
    assertExists(out.markdown);
    assert(out.markdown.includes("S3 Bucket Audit"));
    assertEquals(out.json.report, "@jentz/aws-s3-bucket-audit");
    assertEquals(out.json.workflow, "smoke-workflow");
    // No buckets were found, so no findings and an empty bucket list.
    assertEquals(out.json.summary.buckets, 0);
    assertEquals(out.json.buckets.length, 0);
    assertEquals(out.json.findings.length, 0);
  },
);

Deno.test(
  "report.execute: a bucket with no policy lookup yields skip findings, never throws",
  async () => {
    // A bucket-state step succeeds but no bucket-policy step ran, so the
    // policy rules cannot evaluate and must SKIP rather than throw or fail.
    const state = JSON.stringify({
      BucketName: "skip-policy-bucket",
      VersioningConfiguration: { Status: "Enabled" },
    });
    const enc = new TextEncoder();
    const ctx = {
      workflowName: "smoke-workflow",
      stepExecutions: [
        {
          jobName: "lookup",
          stepName: "bucket-state",
          modelType: "@swamp/aws/s3/bucket",
          modelId: "audit-skip-policy",
          status: "succeeded",
          methodArgs: { identifier: "skip-policy-bucket" },
          dataHandles: [{ name: "default", version: 1 }],
        },
      ],
      logger: silentLogger(),
      dataRepository: {
        getContent: (): Promise<Uint8Array | null> =>
          Promise.resolve(enc.encode(state)),
      },
    };
    const out = await report.execute(ctx);
    assertEquals(out.json.summary.buckets, 1);
    const tls = out.json.findings.find((f) =>
      f.id === "bucket-tls-only-policy"
    );
    assertExists(tls);
    assertEquals(tls.status, "skip");
    assert(out.json.summary.skip > 0);
  },
);
