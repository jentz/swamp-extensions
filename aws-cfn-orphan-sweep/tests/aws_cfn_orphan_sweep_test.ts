/**
 * Unit tests for `@jentz/aws-cfn-orphan-sweep`.
 *
 * Pure-logic coverage exercised without any swamp context or AWS SDK: the
 * prefix-refusal guard, the retain computation (custom-resource detection,
 * DELETE_FAILED preference, override validation, and the non-custom refusal),
 * salient-resource classification, count-by tallying, the data-name slug, the
 * orphan storage key, and the timestamp coercion. No network or filesystem I/O.
 */

import { assertEquals } from "jsr:@std/assert@1";

import {
  classifyResources,
  computeRetain,
  countBy,
  isoOrEmpty,
  orphanKey,
  type ResourceRef,
  safeNameSegment,
  stackRefusalReason,
} from "../aws_cfn_orphan_sweep.ts";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/** Build a ResourceRef with sensible defaults overridden by `over`. */
function res(over: Partial<ResourceRef>): ResourceRef {
  return {
    logicalId: "Res",
    physicalId: "res-phys",
    type: "AWS::S3::Bucket",
    status: "CREATE_COMPLETE",
    ...over,
  };
}

// A representative orphan resource set: a custom resource, its backing Lambda,
// and the IAM execution role — the shape this model is built to clean up.
const CUSTOM = res({
  logicalId: "PasswordPolicy",
  type: "Custom::IAMPasswordPolicy",
  physicalId: "custom-phys",
});
const ROLE = res({
  logicalId: "LambdaRole",
  type: "AWS::IAM::Role",
  physicalId: "StackSet-IAMCustomPasswordPolicy-role-ABCDEF",
});
const LAMBDA = res({
  logicalId: "PolicyFn",
  type: "AWS::Lambda::Function",
  physicalId: "policy-fn",
});

// ---------------------------------------------------------------------------
// stackRefusalReason (prefix-refusal guard)
// ---------------------------------------------------------------------------

Deno.test("stackRefusalReason: matching prefix is allowed (empty reason)", () => {
  assertEquals(
    stackRefusalReason(
      "StackSet-IAMCustomPasswordPolicy-abc123",
      "StackSet-IAMCustomPasswordPolicy-",
    ),
    "",
  );
});

Deno.test("stackRefusalReason: non-matching name is refused with a reason", () => {
  const reason = stackRefusalReason(
    "ProdDatabase",
    "StackSet-IAMCustomPasswordPolicy-",
  );
  assertEquals(reason.length > 0, true);
  assertEquals(reason.includes("ProdDatabase"), true);
  assertEquals(reason.includes("StackSet-IAMCustomPasswordPolicy-"), true);
});

Deno.test("stackRefusalReason: a name equal to the prefix is allowed", () => {
  // startsWith is satisfied by an exact match.
  assertEquals(stackRefusalReason("StackSet-X-", "StackSet-X-"), "");
});

// ---------------------------------------------------------------------------
// computeRetain (retain computation)
// ---------------------------------------------------------------------------

Deno.test("computeRetain: retains the sole custom resource, nothing else", () => {
  const { retain, reason } = computeRetain([CUSTOM, ROLE, LAMBDA], "");
  assertEquals(reason, "");
  assertEquals(retain, ["PasswordPolicy"]);
});

Deno.test("computeRetain: prefers the DELETE_FAILED custom resource", () => {
  const ok = res({ logicalId: "CustomA", type: "Custom::Thing" });
  const failed = res({
    logicalId: "CustomB",
    type: "Custom::Thing",
    status: "DELETE_FAILED",
  });
  const { retain, reason } = computeRetain([ok, failed, ROLE], "");
  assertEquals(reason, "");
  assertEquals(retain, ["CustomB"]);
});

Deno.test("computeRetain: recognizes AWS::CloudFormation::CustomResource", () => {
  const generic = res({
    logicalId: "GenericCustom",
    type: "AWS::CloudFormation::CustomResource",
  });
  const { retain, reason } = computeRetain([generic, ROLE], "");
  assertEquals(reason, "");
  assertEquals(retain, ["GenericCustom"]);
});

Deno.test("computeRetain: no custom resource means retain nothing", () => {
  const { retain, reason } = computeRetain([ROLE, LAMBDA], "");
  assertEquals(reason, "");
  assertEquals(retain, []);
});

Deno.test("computeRetain: honored override that matches a custom resource", () => {
  const c1 = res({ logicalId: "CustomA", type: "Custom::Thing" });
  const c2 = res({ logicalId: "CustomB", type: "Custom::Thing" });
  const { retain, reason } = computeRetain([c1, c2], "CustomB");
  assertEquals(reason, "");
  assertEquals(retain, ["CustomB"]);
});

Deno.test("computeRetain: override that is not a custom resource is refused", () => {
  const { retain, reason } = computeRetain([CUSTOM, ROLE], "LambdaRole");
  assertEquals(retain, []);
  assertEquals(reason.includes("LambdaRole"), true);
  assertEquals(reason.includes("not a custom resource"), true);
});

Deno.test("computeRetain: override refusal lists the detected custom ids", () => {
  const { reason } = computeRetain([CUSTOM, ROLE], "Nope");
  assertEquals(reason.includes("PasswordPolicy"), true);
});

Deno.test("computeRetain: override refusal reports 'none' when no custom resource", () => {
  const { retain, reason } = computeRetain([ROLE, LAMBDA], "LambdaRole");
  assertEquals(retain, []);
  assertEquals(reason.includes("none"), true);
});

// ---------------------------------------------------------------------------
// classifyResources (salient-resource classification)
// ---------------------------------------------------------------------------

Deno.test("classifyResources: picks custom resource, IAM role, and Lambda", () => {
  const c = classifyResources([CUSTOM, ROLE, LAMBDA]);
  assertEquals(c.customResourceLogicalId, "PasswordPolicy");
  assertEquals(c.customResourceType, "Custom::IAMPasswordPolicy");
  assertEquals(c.iamRoleLogicalId, "LambdaRole");
  assertEquals(
    c.iamRolePhysicalName,
    "StackSet-IAMCustomPasswordPolicy-role-ABCDEF",
  );
  assertEquals(c.lambdaLogicalId, "PolicyFn");
});

Deno.test("classifyResources: empty resource list yields all empty strings", () => {
  const c = classifyResources([]);
  assertEquals(c, {
    customResourceLogicalId: "",
    customResourceType: "",
    iamRoleLogicalId: "",
    iamRolePhysicalName: "",
    lambdaLogicalId: "",
  });
});

Deno.test("classifyResources: AWS::CloudFormation::CustomResource counts as custom", () => {
  const generic = res({
    logicalId: "Provisioner",
    type: "AWS::CloudFormation::CustomResource",
  });
  const c = classifyResources([generic]);
  assertEquals(c.customResourceLogicalId, "Provisioner");
  assertEquals(c.customResourceType, "AWS::CloudFormation::CustomResource");
});

// ---------------------------------------------------------------------------
// countBy (tally helper)
// ---------------------------------------------------------------------------

Deno.test("countBy: tallies by key", () => {
  const items = [{ k: "a" }, { k: "a" }, { k: "b" }];
  assertEquals(countBy(items, (i) => i.k), { a: 2, b: 1 });
});

Deno.test("countBy: empty input is empty map", () => {
  assertEquals(countBy([] as { k: string }[], (i) => i.k), {});
});

// ---------------------------------------------------------------------------
// safeNameSegment (data-name slug)
// ---------------------------------------------------------------------------

Deno.test("safeNameSegment: leaves a safe segment untouched", () => {
  assertEquals(
    safeNameSegment("StackSet-IAMCustomPasswordPolicy-abc.def_123"),
    "StackSet-IAMCustomPasswordPolicy-abc.def_123",
  );
});

Deno.test("safeNameSegment: collapses unsafe runs to a single dash", () => {
  assertEquals(safeNameSegment("a/b  c:::d"), "a-b-c-d");
});

Deno.test("safeNameSegment: trims leading/trailing separators", () => {
  assertEquals(safeNameSegment("--a.b--"), "a.b");
  assertEquals(safeNameSegment("..x.."), "x");
});

Deno.test("safeNameSegment: empty / fully-stripped input falls back to 'x'", () => {
  assertEquals(safeNameSegment(""), "x");
  assertEquals(safeNameSegment("///"), "x");
});

Deno.test("safeNameSegment: caps the slug at 90 characters", () => {
  assertEquals(safeNameSegment("a".repeat(200)).length, 90);
});

// ---------------------------------------------------------------------------
// orphanKey (storage key)
// ---------------------------------------------------------------------------

Deno.test("orphanKey: composes account, region, and a safe stack segment", () => {
  assertEquals(
    orphanKey({
      account: "111111111111",
      region: "us-east-1",
      stackName: "StackSet-IAMCustomPasswordPolicy-abc",
    }),
    "orphan-111111111111-us-east-1-StackSet-IAMCustomPasswordPolicy-abc",
  );
});

Deno.test("orphanKey: sanitizes an unsafe stack name", () => {
  assertEquals(
    orphanKey({
      account: "111111111111",
      region: "eu-west-1",
      stackName: "weird/name with spaces",
    }),
    "orphan-111111111111-eu-west-1-weird-name-with-spaces",
  );
});

// ---------------------------------------------------------------------------
// isoOrEmpty (timestamp coercion)
// ---------------------------------------------------------------------------

Deno.test("isoOrEmpty: Date, string, and undefined", () => {
  const d = new Date("2026-06-16T00:00:00.000Z");
  assertEquals(isoOrEmpty(d), "2026-06-16T00:00:00.000Z");
  assertEquals(
    isoOrEmpty("2026-06-16T00:00:00.000Z"),
    "2026-06-16T00:00:00.000Z",
  );
  assertEquals(isoOrEmpty(undefined), "");
  assertEquals(isoOrEmpty(""), "");
});
