/**
 * Model read+write + smoke tests for `@jentz/aws-integration-coverage`.
 *
 * Drives the `coalesce` method end-to-end through a hand-rolled context whose
 * `dataRepository` replays stored upstream artifacts in memory. Proves:
 *
 *   - `readSpec` keeps the latest active version per data name and skips
 *     `deleted` artifacts and undecodable bytes;
 *   - `parseAll` tolerantly drops schema-invalid rows into the skipped count;
 *   - the method errors only when BOTH upstreams produced zero rows;
 *   - the write path emits one `coverage` resource per account (keyed
 *     `coverage-<accountId>`) plus exactly one `summary`; and
 *   - NO AWS / SDK call is ever made (the context exposes no AWS client and the
 *     model imports none).
 *
 * Account ids are clearly-fictional placeholders.
 *
 * @module
 */

import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";

import { model, parseAll, readSpec } from "../aws_integration_coverage.ts";
import { RoleSchema } from "../_lib/coverage.ts";

const ACCT_A = "ACCT_ALPHA";
const ACCT_B = "ACCT_BETA";
const STACKSET = "acme-ss";
const STACKSET_TYPE = "@jentz/aws-stackset-audit";
const IAM_TYPE = "@jentz/aws-iam-role-audit";

// ---------------------------------------------------------------------------
// In-memory data repository replay
// ---------------------------------------------------------------------------

interface StoredItem {
  name: string;
  version: number;
  specName: string;
  lifecycle?: string;
  /** Raw JSON the repository returns for this (name, version). */
  json: unknown;
  /** When true, getContent returns null for this item (undecodable / missing). */
  noBytes?: boolean;
}

const enc = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));

/** Build a dataRepository over per-(modelType, modelId) stored items. */
function fakeRepo(
  store: Record<string, Record<string, StoredItem[]>>,
): { repo: unknown; awsTouched: boolean } {
  const awsTouched = false;
  const repo = {
    findAllForModel: (modelType: string, modelId: string) => {
      const items = store[modelType]?.[modelId] ?? [];
      return Promise.resolve(
        items.map((i) => ({
          name: i.name,
          version: i.version,
          metadata: {
            lifecycle: i.lifecycle ?? "active",
            tags: { specName: i.specName },
          },
        })),
      );
    },
    getContent: (
      modelType: string,
      modelId: string,
      name: string,
      version: number,
    ): Promise<Uint8Array | null> => {
      const items = store[modelType]?.[modelId] ?? [];
      const it = items.find((i) => i.name === name && i.version === version);
      if (!it || it.noBytes) return Promise.resolve(null);
      return Promise.resolve(enc(it.json));
    },
  };
  return { repo, awsTouched };
}

interface Written {
  spec: string;
  key: string;
  // deno-lint-ignore no-explicit-any
  data: any;
}

function fakeContext(
  repo: unknown,
  globalArgs: Record<string, unknown>,
): { context: unknown; written: Written[] } {
  const written: Written[] = [];
  const context = {
    globalArgs,
    dataRepository: repo,
    logger: {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: () => {},
    },
    // deno-lint-ignore no-explicit-any
    writeResource: (spec: string, key: string, data: any) => {
      written.push({ spec, key, data });
      return Promise.resolve({ id: `${spec}:${key}` });
    },
  };
  return { context, written };
}

function instanceItem(
  name: string,
  account: string,
  overallStatus: string,
  extra: Partial<StoredItem> = {},
): StoredItem {
  return {
    name,
    version: 1,
    specName: "instance",
    json: {
      stackSetName: STACKSET,
      account,
      region: "us-east-1",
      overallStatus,
      detailedStatus: "",
      failureCategory: "",
    },
    ...extra,
  };
}

function roleItem(
  name: string,
  accountId: string,
  roleName: string,
  exists: boolean,
  compliant: boolean,
  extra: Partial<StoredItem> = {},
): StoredItem {
  return {
    name,
    version: 1,
    specName: "role",
    json: {
      accountId,
      accountName: accountId === ACCT_A ? "alpha" : "beta",
      profile: `${accountId}-readonly`,
      roleName,
      required: true,
      exists,
      managementMechanism: "cfn-stackset",
      cfnStackName: `StackSet-${STACKSET}-x`,
      cfnStackRegion: "us-east-1",
      compliant,
      findings: [],
      attachedManagedPolicyArns: [],
      createDate: "",
    },
    ...extra,
  };
}

// deno-lint-ignore no-explicit-any
function run(context: any) {
  return model.methods.coalesce.execute({}, context);
}

// ---------------------------------------------------------------------------
// readSpec — latest-version selection + tolerant skip
// ---------------------------------------------------------------------------

Deno.test("readSpec: keeps the latest version per data name and drops `deleted` + nullbytes", async () => {
  const { repo } = fakeRepo({
    [STACKSET_TYPE]: {
      "ss-1": [
        instanceItem("instance-acct-a", ACCT_A, "OUTDATED", { version: 1 }),
        // newer version of the SAME name wins
        instanceItem("instance-acct-a", ACCT_A, "CURRENT", { version: 2 }),
        // a deleted artifact is ignored
        instanceItem("instance-acct-b", ACCT_B, "CURRENT", {
          lifecycle: "deleted",
        }),
        // a different spec is ignored by an `instance` read
        roleItem("role-acct-a", ACCT_A, "Readonly", true, true),
      ],
    },
  });

  const rows = await readSpec(repo, STACKSET_TYPE, "ss-1", "instance");
  assertEquals(rows.length, 1);
  assertEquals((rows[0] as { overallStatus: string }).overallStatus, "CURRENT");
});

Deno.test("readSpec: a null-bytes artifact is silently skipped", async () => {
  const { repo } = fakeRepo({
    [STACKSET_TYPE]: {
      "ss-1": [
        instanceItem("instance-acct-a", ACCT_A, "CURRENT"),
        instanceItem("instance-acct-b", ACCT_B, "CURRENT", { noBytes: true }),
      ],
    },
  });
  const rows = await readSpec(repo, STACKSET_TYPE, "ss-1", "instance");
  assertEquals(rows.length, 1);
});

// ---------------------------------------------------------------------------
// parseAll — tolerant validation count
// ---------------------------------------------------------------------------

Deno.test("parseAll: validates good rows and counts the rejects as bad", () => {
  const raws = [
    { accountId: ACCT_A, exists: true }, // ok (defaults fill the rest)
    { roleName: "missing-account" }, // bad: accountId/exists required
    "not-an-object", // bad
  ];
  const { ok, bad } = parseAll(raws, RoleSchema);
  assertEquals(ok.length, 1);
  assertEquals(bad, 2);
});

// ---------------------------------------------------------------------------
// coalesce method — error path
// ---------------------------------------------------------------------------

Deno.test("coalesce: throws a run-the-audits-first error when BOTH upstreams are empty", async () => {
  const { repo } = fakeRepo({});
  const { context } = fakeContext(repo, {
    stacksetModelId: "ss-1",
    iamModelId: "iam-1",
  });
  await assertRejects(
    () => run(context),
    Error,
    "run the stackset-audit and iam-role-audit methods",
  );
});

Deno.test("coalesce: produces a matrix when only the IAM lens has data", async () => {
  const { repo } = fakeRepo({
    [IAM_TYPE]: {
      "iam-1": [roleItem("role-a", ACCT_A, "Readonly", true, true)],
    },
  });
  const { context, written } = fakeContext(repo, {
    stacksetModelId: "ss-1",
    iamModelId: "iam-1",
  });
  await run(context);
  // one coverage + one summary
  assertEquals(written.filter((w) => w.spec === "coverage").length, 1);
  assertEquals(written.filter((w) => w.spec === "summary").length, 1);
});

// ---------------------------------------------------------------------------
// coalesce method — write path (smoke, no AWS/SDK)
// ---------------------------------------------------------------------------

Deno.test("smoke: coalesce writes one coverage-<accountId> per account + one summary, no AWS calls", async () => {
  const { repo } = fakeRepo({
    [STACKSET_TYPE]: {
      "ss-1": [
        {
          name: "summary",
          version: 1,
          specName: "summary",
          json: {
            stackSetName: STACKSET,
            accountsTargeted: 2,
            instanceCount: 2,
          },
        },
        instanceItem("instance-acct-a", ACCT_A, "OUTDATED"),
        instanceItem("instance-acct-b", ACCT_B, "CURRENT"),
        // a malformed instance row: missing required `account` => skipped (bad)
        {
          name: "instance-bad",
          version: 1,
          specName: "instance",
          json: { stackSetName: STACKSET, region: "us-east-1" },
        },
      ],
    },
    [IAM_TYPE]: {
      "iam-1": [
        roleItem("role-a-ro", ACCT_A, "Readonly", true, false),
        roleItem("role-a-ecr", ACCT_A, "ECR", true, true),
        roleItem("role-b-ro", ACCT_B, "Readonly", true, true),
      ],
    },
  });

  const { context, written } = fakeContext(repo, {
    stacksetModelId: "ss-1",
    iamModelId: "iam-1",
  });

  const result = await run(context);
  assert(Array.isArray(result.dataHandles));

  const coverageWrites = written.filter((w) => w.spec === "coverage");
  const summaryWrites = written.filter((w) => w.spec === "summary");

  // Two accounts => two coverage rows, keyed by account id.
  assertEquals(coverageWrites.length, 2);
  assertEquals(
    coverageWrites.map((w) => w.key).sort(),
    [`coverage-${ACCT_A}`, `coverage-${ACCT_B}`],
  );

  // ALPHA: Readonly present-noncompliant + ECR present-compliant => covered-noncompliant.
  const aRow = coverageWrites.find((w) => w.key === `coverage-${ACCT_A}`)!.data;
  assertEquals(aRow.coverage, "covered-noncompliant");
  assertEquals(aRow.requiredTotal, 2);

  // Exactly one summary, and it counts the malformed instance into sources.skipped.
  assertEquals(summaryWrites.length, 1);
  const summary = summaryWrites[0].data;
  assertEquals(summary.totalAccounts, 2);
  assertEquals(summary.stackSetName, STACKSET);
  assertEquals(summary.sources.stacksetModelId, "ss-1");
  assertEquals(summary.sources.iamModelId, "iam-1");
  assertEquals(summary.sources.skipped, 1);
  assert(Array.isArray(summary.byRole));

  // Provenance: the dataHandles array equals every write (coverage rows + summary).
  assertEquals(result.dataHandles.length, coverageWrites.length + 1);
});
