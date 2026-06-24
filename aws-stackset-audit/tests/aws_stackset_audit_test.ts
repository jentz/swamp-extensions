/**
 * Unit tests for `@jentz/aws-stackset-audit`.
 *
 * Pure-logic coverage exercised without any swamp context: failure
 * classification across its status/reason branches, count-by tallying,
 * root-cause grouping (exclusions + ranking), cross-instance anti-pattern
 * detection (IAM multi-region collision and drift-never-detected), and the
 * conservative safe-to-reapply derivation. No network or filesystem I/O.
 */

import { assertEquals } from "jsr:@std/assert@1";

import {
  buildRootCauses,
  classifyFailure,
  classifyStackPresence,
  countBy,
  deriveSafeToReapply,
  detectPatterns,
  instanceKey,
  type InstanceRecord,
  isoOrEmpty,
} from "../aws_stackset_audit.ts";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/** Build an InstanceRecord with sensible defaults overridden by `over`. */
function inst(over: Partial<InstanceRecord>): InstanceRecord {
  return {
    stackSetName: "ss",
    account: "111111111111",
    region: "us-east-1",
    detailedStatus: "SUCCEEDED",
    overallStatus: "CURRENT",
    statusReason: "",
    driftStatus: "IN_SYNC",
    lastDriftCheckTimestamp: "",
    stackId: "",
    organizationalUnitId: "",
    failureCategory: "none",
    stackPresenceHint: "unknown",
    auditedAt: "2026-06-13T00:00:00.000Z",
    ...over,
  };
}

function emptyDrift(over: Partial<{
  driftStatus: string;
  totalStackInstancesCount: number;
}> = {}) {
  return {
    driftStatus: "IN_SYNC",
    totalStackInstancesCount: 1,
    driftedStackInstancesCount: 0,
    inSyncStackInstancesCount: 1,
    inProgressStackInstancesCount: 0,
    failedStackInstancesCount: 0,
    lastDriftCheckTimestamp: "2026-06-13T00:00:00.000Z",
    ...over,
  };
}

// ---------------------------------------------------------------------------
// classifyFailure
// ---------------------------------------------------------------------------

Deno.test("classifyFailure: SUCCEEDED is 'none'", () => {
  assertEquals(classifyFailure("SUCCEEDED", ""), "none");
});

Deno.test("classifyFailure: suspended account", () => {
  assertEquals(
    classifyFailure("SKIPPED_SUSPENDED_ACCOUNT", ""),
    "suspended-account",
  );
});

Deno.test("classifyFailure: cancelled with failure-tolerance reason", () => {
  assertEquals(
    classifyFailure("CANCELLED", "Operation hit failure tolerance"),
    "cancelled-tolerance",
  );
});

Deno.test("classifyFailure: plain cancelled", () => {
  assertEquals(
    classifyFailure("CANCELLED", "operator stopped it"),
    "cancelled",
  );
});

Deno.test("classifyFailure: IAM name conflict (AlreadyExists + iam keyword)", () => {
  // The fingerprint case: a fixed-name managed policy already exists.
  assertEquals(
    classifyFailure(
      "FAILED",
      "Resource MyManagedPolicy already exists in stack; ManagedPolicy name taken",
    ),
    "iam-name-conflict",
  );
});

Deno.test("classifyFailure: AlreadyExists without IAM keyword is resource-already-exists", () => {
  assertEquals(
    classifyFailure("FAILED", "S3 bucket already exists"),
    "resource-already-exists",
  );
});

Deno.test("classifyFailure: access-denied variants", () => {
  assertEquals(
    classifyFailure(
      "FAILED",
      "User is not authorized to perform cfn:CreateStack",
    ),
    "access-denied",
  );
  assertEquals(
    classifyFailure("INOPERABLE", "AccessDenied calling sts:AssumeRole"),
    "access-denied",
  );
  assertEquals(
    classifyFailure("FAILED_IMPORT", "explicit deny in SCP"),
    "access-denied",
  );
});

Deno.test("classifyFailure: unrecognized failure reason is other-failure", () => {
  assertEquals(
    classifyFailure("FAILED", "template validation error"),
    "other-failure",
  );
});

Deno.test("classifyFailure: in-progress states", () => {
  assertEquals(classifyFailure("PENDING", ""), "in-progress");
  assertEquals(classifyFailure("RUNNING", ""), "in-progress");
  assertEquals(classifyFailure("QUEUED", ""), "in-progress");
});

Deno.test("classifyFailure: unknown status is 'other'", () => {
  assertEquals(classifyFailure("WEIRD_STATUS", ""), "other");
});

// ---------------------------------------------------------------------------
// classifyStackPresence — full (detailedStatus, stackId) truth table
// ---------------------------------------------------------------------------

const SID = "arn:aws:cloudformation:us-east-1:111111111111:stack/s/abc";

Deno.test("classifyStackPresence: rule 1 — empty stackId is likely-absent (wins over SUCCEEDED)", () => {
  // Rule 1 fires before the SUCCEEDED check, so a success with no stackId is
  // still likely-absent.
  assertEquals(classifyStackPresence("SUCCEEDED", ""), "likely-absent");
  assertEquals(classifyStackPresence("FAILED", ""), "likely-absent");
  assertEquals(classifyStackPresence("CANCELLED", ""), "likely-absent");
  assertEquals(
    classifyStackPresence("SKIPPED_SUSPENDED_ACCOUNT", ""),
    "likely-absent",
  );
  assertEquals(classifyStackPresence("", ""), "likely-absent");
});

Deno.test("classifyStackPresence: rule 2 — SUCCEEDED with a stackId is present", () => {
  assertEquals(classifyStackPresence("SUCCEEDED", SID), "present");
});

Deno.test("classifyStackPresence: rule 3 — suspended account is present (exists but inaccessible)", () => {
  assertEquals(
    classifyStackPresence("SKIPPED_SUSPENDED_ACCOUNT", SID),
    "present",
  );
});

Deno.test("classifyStackPresence: rule 4 — create-failure with a stackId is likely-absent (rolled back)", () => {
  assertEquals(classifyStackPresence("FAILED", SID), "likely-absent");
  assertEquals(classifyStackPresence("FAILED_IMPORT", SID), "likely-absent");
  assertEquals(classifyStackPresence("INOPERABLE", SID), "likely-absent");
});

Deno.test("classifyStackPresence: rule 5 — CANCELLED with a stackId is unknown", () => {
  assertEquals(classifyStackPresence("CANCELLED", SID), "unknown");
});

Deno.test("classifyStackPresence: rule 5 — in-progress states with a stackId are unknown", () => {
  assertEquals(classifyStackPresence("PENDING", SID), "unknown");
  assertEquals(classifyStackPresence("RUNNING", SID), "unknown");
  assertEquals(classifyStackPresence("QUEUED", SID), "unknown");
});

Deno.test("classifyStackPresence: rule 5 — unrecognized status with a stackId is unknown", () => {
  assertEquals(classifyStackPresence("WEIRD_STATUS", SID), "unknown");
});

// ---------------------------------------------------------------------------
// countBy
// ---------------------------------------------------------------------------

Deno.test("countBy: tallies by key", () => {
  const items = [{ k: "a" }, { k: "a" }, { k: "b" }];
  assertEquals(countBy(items, (i) => i.k), { a: 2, b: 1 });
});

Deno.test("countBy: empty input is empty map", () => {
  assertEquals(countBy([] as { k: string }[], (i) => i.k), {});
});

// ---------------------------------------------------------------------------
// buildRootCauses
// ---------------------------------------------------------------------------

Deno.test("buildRootCauses: excludes none and in-progress, ranks by count", () => {
  const instances: InstanceRecord[] = [
    inst({ failureCategory: "none" }),
    inst({
      account: "111111111111",
      failureCategory: "in-progress",
      detailedStatus: "RUNNING",
    }),
    inst({
      account: "222222222222",
      failureCategory: "access-denied",
      detailedStatus: "FAILED",
      statusReason: "not authorized",
    }),
    inst({
      account: "333333333333",
      failureCategory: "iam-name-conflict",
      detailedStatus: "FAILED",
      statusReason: "policy already exists",
    }),
    inst({
      account: "444444444444",
      failureCategory: "iam-name-conflict",
      detailedStatus: "FAILED",
      statusReason: "role already exists",
    }),
  ];

  const causes = buildRootCauses(instances);

  // none + in-progress excluded → 2 categories remain.
  assertEquals(causes.length, 2);
  // Ranked by count desc: iam-name-conflict (2) before access-denied (1).
  assertEquals(causes[0].failureCategory, "iam-name-conflict");
  assertEquals(causes[0].count, 2);
  assertEquals(causes[0].affectedAccounts, 2);
  assertEquals(causes[0].accounts, ["333333333333", "444444444444"]);
  assertEquals(causes[0].exampleReason, "policy already exists");
  assertEquals(causes[1].failureCategory, "access-denied");
  assertEquals(causes[1].count, 1);
});

Deno.test("buildRootCauses: all-clean stackset yields no root causes", () => {
  const instances = [
    inst({ account: "111111111111" }),
    inst({ account: "222222222222" }),
  ];
  assertEquals(buildRootCauses(instances), []);
});

// ---------------------------------------------------------------------------
// detectPatterns
// ---------------------------------------------------------------------------

Deno.test("detectPatterns: IAM multi-region collision detected", () => {
  // Same account succeeds in one region, hits IAM conflict in another.
  const instances: InstanceRecord[] = [
    inst({
      account: "111111111111",
      region: "us-east-1",
      detailedStatus: "SUCCEEDED",
      failureCategory: "none",
    }),
    inst({
      account: "111111111111",
      region: "eu-west-1",
      detailedStatus: "FAILED",
      failureCategory: "iam-name-conflict",
      statusReason: "managed policy already exists",
    }),
  ];

  const patterns = detectPatterns(instances, emptyDrift());
  const collision = patterns.find(
    (p) => p.pattern === "iam-global-resource-multi-region-collision",
  );
  assertEquals(collision !== undefined, true);
  assertEquals(collision?.affectedAccounts, 1);
});

Deno.test("detectPatterns: no collision when account never succeeds elsewhere", () => {
  const instances: InstanceRecord[] = [
    inst({
      account: "111111111111",
      region: "eu-west-1",
      detailedStatus: "FAILED",
      failureCategory: "iam-name-conflict",
    }),
  ];
  const patterns = detectPatterns(instances, emptyDrift());
  assertEquals(
    patterns.some(
      (p) => p.pattern === "iam-global-resource-multi-region-collision",
    ),
    false,
  );
});

Deno.test("detectPatterns: drift-never-detected when NOT_CHECKED", () => {
  const instances = [inst({})];
  const patterns = detectPatterns(
    instances,
    emptyDrift({ driftStatus: "NOT_CHECKED" }),
  );
  const drift = patterns.find((p) => p.pattern === "drift-never-detected");
  assertEquals(drift !== undefined, true);
  // The reworded narrative must point at the sibling extension, not an in-code
  // detectDrift method.
  assertEquals(drift?.description.includes("sibling extension"), true);
  assertEquals(drift?.description.toLowerCase().includes("detectdrift"), false);
});

Deno.test("detectPatterns: drift-never-detected when zero instances measured", () => {
  const patterns = detectPatterns(
    [inst({})],
    emptyDrift({ driftStatus: "IN_SYNC", totalStackInstancesCount: 0 }),
  );
  assertEquals(
    patterns.some((p) => p.pattern === "drift-never-detected"),
    true,
  );
});

Deno.test("detectPatterns: clean drift posture yields no drift pattern", () => {
  const patterns = detectPatterns([inst({})], emptyDrift());
  assertEquals(
    patterns.some((p) => p.pattern === "drift-never-detected"),
    false,
  );
});

// ---------------------------------------------------------------------------
// deriveSafeToReapply
// ---------------------------------------------------------------------------

Deno.test("deriveSafeToReapply: in-flight operation blocks with 'no'", () => {
  const verdict = deriveSafeToReapply({
    operations: [{
      operationId: "op-1",
      action: "UPDATE",
      status: "RUNNING",
      creationTimestamp: "",
      endTimestamp: "",
      statusReason: "",
    }],
    byDetailedStatus: {},
    byOverallStatus: {},
    patterns: [],
  });
  assertEquals(verdict.verdict, "no");
  assertEquals(verdict.reasons.length, 1);
});

Deno.test("deriveSafeToReapply: known structural IAM collision is 'no' with remediation", () => {
  const verdict = deriveSafeToReapply({
    operations: [],
    byDetailedStatus: { SUCCEEDED: 1, FAILED: 1 },
    byOverallStatus: {},
    patterns: [{
      pattern: "iam-global-resource-multi-region-collision",
      description: "...",
      affectedAccounts: 1,
      evidence: "...",
    }],
  });
  assertEquals(verdict.verdict, "no");
  assertEquals(verdict.remediation.length > 0, true);
});

Deno.test("deriveSafeToReapply: INOPERABLE without collision is 'caution'", () => {
  const verdict = deriveSafeToReapply({
    operations: [],
    byDetailedStatus: {},
    byOverallStatus: { INOPERABLE: 2 },
    patterns: [],
  });
  assertEquals(verdict.verdict, "caution");
});

Deno.test("deriveSafeToReapply: clean fleet is 'yes'", () => {
  const verdict = deriveSafeToReapply({
    operations: [{
      operationId: "op-0",
      action: "UPDATE",
      status: "SUCCEEDED",
      creationTimestamp: "",
      endTimestamp: "",
      statusReason: "",
    }],
    byDetailedStatus: { SUCCEEDED: 3 },
    byOverallStatus: { CURRENT: 3 },
    patterns: [],
  });
  assertEquals(verdict.verdict, "yes");
});

Deno.test("deriveSafeToReapply: failed/cancelled instances are 'caution'", () => {
  const verdict = deriveSafeToReapply({
    operations: [],
    byDetailedStatus: { SUCCEEDED: 2, FAILED: 1, CANCELLED: 1 },
    byOverallStatus: { CURRENT: 2, OUTDATED: 2 },
    patterns: [],
  });
  assertEquals(verdict.verdict, "caution");
});

// ---------------------------------------------------------------------------
// instanceKey + isoOrEmpty
// ---------------------------------------------------------------------------

Deno.test("instanceKey: composes account and region", () => {
  assertEquals(
    instanceKey("111111111111", "us-east-1"),
    "instance-111111111111-us-east-1",
  );
});

Deno.test("isoOrEmpty: Date, string, and undefined", () => {
  const d = new Date("2026-06-13T00:00:00.000Z");
  assertEquals(isoOrEmpty(d), "2026-06-13T00:00:00.000Z");
  assertEquals(
    isoOrEmpty("2026-06-13T00:00:00.000Z"),
    "2026-06-13T00:00:00.000Z",
  );
  assertEquals(isoOrEmpty(undefined), "");
  assertEquals(isoOrEmpty(""), "");
});
