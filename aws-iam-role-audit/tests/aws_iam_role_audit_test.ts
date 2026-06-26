/**
 * Unit tests for `@jentz/aws-iam-role-audit`.
 *
 * Pure-logic coverage exercised without any swamp context, with passing AND
 * failing cases: compliance evaluation, mechanism inference, trust-policy
 * parsing, effective-role resolution (multi-role only), and the transform
 * helpers (tag flattening, account-name suffix stripping, error classification,
 * storage-key construction). No network or filesystem I/O.
 */

import { assertEquals, assertThrows } from "jsr:@std/assert@1";

import {
  accountNameFromProfile,
  classifyError,
  effectiveRoles,
  evaluateCompliance,
  inferMechanism,
  type ManagingStack,
  parseTrustPolicy,
  policyNameFromArn,
  roleKey,
  type RoleSpec,
  scanErrorKey,
  tagsFromAws,
} from "../aws_iam_role_audit.ts";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/** Build a RoleSpec with sensible defaults overridden by `over`. */
function spec(over: Partial<RoleSpec> = {}): RoleSpec {
  return {
    roleName: "DemoRole",
    expectedManagedPolicyArns: [],
    expectedCustomerPolicyNames: [],
    expectedTrustPrincipals: [],
    expectedExternalId: "",
    required: true,
    ...over,
  };
}

// ---------------------------------------------------------------------------
// evaluateCompliance
// ---------------------------------------------------------------------------

Deno.test("evaluateCompliance: missing role is never compliant", () => {
  const r = evaluateCompliance({
    exists: false,
    attachedManagedPolicyArns: [],
    trustPrincipals: [],
    trustExternalIds: [],
    spec: spec(),
  });
  assertEquals(r.compliant, false);
  assertEquals(r.findings, ["role does not exist"]);
});

Deno.test("evaluateCompliance: fully-satisfied role is compliant with no findings", () => {
  const r = evaluateCompliance({
    exists: true,
    attachedManagedPolicyArns: [
      "arn:aws:iam::aws:policy/ReadOnlyAccess",
      "arn:aws:iam::123456789012:policy/CustomScan",
    ],
    trustPrincipals: ["arn:aws:iam::999999999999:root"],
    trustExternalIds: ["ext-abc"],
    spec: spec({
      expectedManagedPolicyArns: ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
      expectedCustomerPolicyNames: ["CustomScan"],
      expectedTrustPrincipals: ["arn:aws:iam::999999999999:root"],
      expectedExternalId: "ext-abc",
    }),
  });
  assertEquals(r.compliant, true);
  assertEquals(r.findings, []);
});

Deno.test("evaluateCompliance: missing managed-policy ARN (exact match)", () => {
  const r = evaluateCompliance({
    exists: true,
    // Same name, different ARN — exact-ARN match must still flag it.
    attachedManagedPolicyArns: [
      "arn:aws:iam::123456789012:policy/ReadOnlyAccess",
    ],
    trustPrincipals: [],
    trustExternalIds: [],
    spec: spec({
      expectedManagedPolicyArns: ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
    }),
  });
  assertEquals(r.compliant, false);
  assertEquals(r.findings, [
    "missing expected managed policy arn:aws:iam::aws:policy/ReadOnlyAccess",
  ]);
});

Deno.test("evaluateCompliance: missing customer-managed policy by name", () => {
  const r = evaluateCompliance({
    exists: true,
    attachedManagedPolicyArns: [
      "arn:aws:iam::123456789012:policy/SomethingElse",
    ],
    trustPrincipals: [],
    trustExternalIds: [],
    spec: spec({ expectedCustomerPolicyNames: ["CustomScan"] }),
  });
  assertEquals(r.compliant, false);
  assertEquals(r.findings, [
    "missing expected customer-managed policy 'CustomScan'",
  ]);
});

Deno.test("evaluateCompliance: customer-managed policy matched by name across ARNs", () => {
  const r = evaluateCompliance({
    exists: true,
    attachedManagedPolicyArns: [
      "arn:aws:iam::123456789012:policy/path/CustomScan",
    ],
    trustPrincipals: [],
    trustExternalIds: [],
    spec: spec({ expectedCustomerPolicyNames: ["CustomScan"] }),
  });
  assertEquals(r.compliant, true);
  assertEquals(r.findings, []);
});

Deno.test("evaluateCompliance: missing trust principal", () => {
  const r = evaluateCompliance({
    exists: true,
    attachedManagedPolicyArns: [],
    trustPrincipals: ["arn:aws:iam::111111111111:root"],
    trustExternalIds: [],
    spec: spec({
      expectedTrustPrincipals: ["arn:aws:iam::999999999999:root"],
    }),
  });
  assertEquals(r.compliant, false);
  assertEquals(r.findings, [
    "trust principal 'arn:aws:iam::999999999999:root' not allowed",
  ]);
});

Deno.test("evaluateCompliance: missing required external id", () => {
  const r = evaluateCompliance({
    exists: true,
    attachedManagedPolicyArns: [],
    trustPrincipals: [],
    trustExternalIds: ["other-id"],
    spec: spec({ expectedExternalId: "required-id" }),
  });
  assertEquals(r.compliant, false);
  assertEquals(r.findings, [
    "trust policy does not require expected externalId 'required-id'",
  ]);
});

Deno.test("evaluateCompliance: empty expectedExternalId skips the external-id check", () => {
  const r = evaluateCompliance({
    exists: true,
    attachedManagedPolicyArns: [],
    trustPrincipals: [],
    trustExternalIds: [],
    spec: spec({ expectedExternalId: "" }),
  });
  assertEquals(r.compliant, true);
  assertEquals(r.findings, []);
});

Deno.test("evaluateCompliance: multiple unmet expectations accumulate", () => {
  const r = evaluateCompliance({
    exists: true,
    attachedManagedPolicyArns: [],
    trustPrincipals: [],
    trustExternalIds: [],
    spec: spec({
      expectedManagedPolicyArns: ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
      expectedCustomerPolicyNames: ["CustomScan"],
      expectedTrustPrincipals: ["arn:aws:iam::999999999999:root"],
      expectedExternalId: "ext",
    }),
  });
  assertEquals(r.compliant, false);
  assertEquals(r.findings.length, 4);
});

// ---------------------------------------------------------------------------
// inferMechanism
// ---------------------------------------------------------------------------

function stack(name: string): ManagingStack {
  return { stackName: name, stackId: `arn:stack/${name}`, region: "eu-west-1" };
}

Deno.test("inferMechanism: absent role is 'missing'", () => {
  assertEquals(inferMechanism(false, null), "missing");
  // Even if a stale stack handle is passed, absence dominates.
  assertEquals(inferMechanism(false, stack("StackSet-foo-guid")), "missing");
});

Deno.test("inferMechanism: existing role with no owning stack is 'manual'", () => {
  assertEquals(inferMechanism(true, null), "manual");
});

Deno.test("inferMechanism: standalone owning stack is 'cfn-standalone-stack'", () => {
  assertEquals(
    inferMechanism(true, stack("my-handcrafted-stack")),
    "cfn-standalone-stack",
  );
});

Deno.test("inferMechanism: StackSet- prefix is 'cfn-stackset'", () => {
  assertEquals(
    inferMechanism(true, stack("StackSet-IntegrationRoles-abc123")),
    "cfn-stackset",
  );
});

// ---------------------------------------------------------------------------
// parseTrustPolicy
// ---------------------------------------------------------------------------

const PLAIN_TRUST = JSON.stringify({
  Version: "2012-10-17",
  Statement: [
    {
      Effect: "Allow",
      Principal: { AWS: "arn:aws:iam::999999999999:root" },
      Action: "sts:AssumeRole",
      Condition: { StringEquals: { "sts:ExternalId": "ext-123" } },
    },
  ],
});

Deno.test("parseTrustPolicy: plain JSON document", () => {
  const facts = parseTrustPolicy(PLAIN_TRUST);
  assertEquals(facts.principals, ["arn:aws:iam::999999999999:root"]);
  assertEquals(facts.externalIds, ["ext-123"]);
});

Deno.test("parseTrustPolicy: URL-encoded document (as IAM returns it)", () => {
  const facts = parseTrustPolicy(encodeURIComponent(PLAIN_TRUST));
  assertEquals(facts.principals, ["arn:aws:iam::999999999999:root"]);
  assertEquals(facts.externalIds, ["ext-123"]);
});

Deno.test("parseTrustPolicy: string-or-array principals across AWS/Service/Federated", () => {
  const doc = JSON.stringify({
    Statement: [
      {
        Principal: {
          AWS: [
            "arn:aws:iam::111111111111:root",
            "arn:aws:iam::222222222222:root",
          ],
          Service: "ec2.amazonaws.com",
          Federated: "arn:aws:iam::333333333333:saml-provider/Okta",
        },
      },
      // A bare string Principal (e.g. "*").
      { Principal: "*" },
    ],
  });
  const facts = parseTrustPolicy(doc);
  assertEquals(facts.principals.sort(), [
    "*",
    "arn:aws:iam::111111111111:root",
    "arn:aws:iam::222222222222:root",
    "arn:aws:iam::333333333333:saml-provider/Okta",
    "ec2.amazonaws.com",
  ]);
});

Deno.test("parseTrustPolicy: external-id array is flattened and deduped", () => {
  const doc = JSON.stringify({
    Statement: [
      {
        Principal: { AWS: "arn:aws:iam::999999999999:root" },
        Condition: { StringEquals: { "sts:ExternalId": ["a", "b", "a"] } },
      },
    ],
  });
  const facts = parseTrustPolicy(doc);
  assertEquals(facts.externalIds.sort(), ["a", "b"]);
});

Deno.test("parseTrustPolicy: undefined and unparseable documents yield empty facts", () => {
  assertEquals(parseTrustPolicy(undefined), {
    principals: [],
    externalIds: [],
  });
  assertEquals(parseTrustPolicy(""), { principals: [], externalIds: [] });
  assertEquals(parseTrustPolicy("{not json"), {
    principals: [],
    externalIds: [],
  });
});

// ---------------------------------------------------------------------------
// effectiveRoles (multi-role only)
// ---------------------------------------------------------------------------

Deno.test("effectiveRoles: returns the configured list", () => {
  const roles = [spec({ roleName: "A" }), spec({ roleName: "B" })];
  assertEquals(effectiveRoles({ roles }), roles);
});

Deno.test("effectiveRoles: empty list throws a descriptive error", () => {
  assertThrows(
    () => effectiveRoles({ roles: [] }),
    Error,
    "No roles configured",
  );
});

// ---------------------------------------------------------------------------
// tagsFromAws
// ---------------------------------------------------------------------------

Deno.test("tagsFromAws: flattens tuples, tolerates missing value, drops keyless", () => {
  assertEquals(
    tagsFromAws([
      { Key: "env", Value: "prod" },
      { Key: "owner" }, // missing value -> ""
      { Value: "orphan" }, // missing key -> dropped
      { Key: "" }, // empty key -> dropped
    ]),
    { env: "prod", owner: "" },
  );
});

Deno.test("tagsFromAws: undefined input is an empty map", () => {
  assertEquals(tagsFromAws(undefined), {});
});

// ---------------------------------------------------------------------------
// accountNameFromProfile
// ---------------------------------------------------------------------------

Deno.test("accountNameFromProfile: strips a matching suffix", () => {
  assertEquals(
    accountNameFromProfile("acme-prod-readonly", "-readonly"),
    "acme-prod",
  );
});

Deno.test("accountNameFromProfile: leaves a non-matching profile intact", () => {
  assertEquals(accountNameFromProfile("acme-prod", "-readonly"), "acme-prod");
});

Deno.test("accountNameFromProfile: empty suffix returns the profile; ambient returns ''", () => {
  assertEquals(accountNameFromProfile("acme-prod", ""), "acme-prod");
  assertEquals(accountNameFromProfile("", "-readonly"), "");
});

// ---------------------------------------------------------------------------
// classifyError
// ---------------------------------------------------------------------------

Deno.test("classifyError: expired SSO token is auth_expired", () => {
  const err = Object.assign(
    new Error("The security token included in the request is expired"),
    {
      name: "ExpiredTokenException",
    },
  );
  assertEquals(classifyError(err).kind, "auth_expired");
});

Deno.test("classifyError: SSO-session expiry message is auth_expired", () => {
  const err = new Error(
    "The SSO session associated with this profile has expired",
  );
  assertEquals(classifyError(err).kind, "auth_expired");
});

Deno.test("classifyError: not-authorized is access_denied", () => {
  const err = new Error(
    "User: arn:aws:iam::123456789012:role/scan is not authorized to perform iam:GetRole",
  );
  assertEquals(classifyError(err).kind, "access_denied");
});

Deno.test("classifyError: AccessDenied carrying an SSO role ARN is access_denied, not auth_expired", () => {
  // The phrase "sso" appears in the role ARN; access-denied must still win so
  // the operator fixes the permission, not the credentials.
  const err = Object.assign(
    new Error(
      "AccessDenied: arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/ReadOnly is not authorized",
    ),
    { name: "AccessDeniedException" },
  );
  assertEquals(classifyError(err).kind, "access_denied");
});

Deno.test("classifyError: a genuine expiry phrase wins over access-denied wording (shared-lib precedence)", () => {
  // The shared classifier checks network → auth_expired → access_denied. A
  // fixture that trips BOTH predicates at once — the name yields "accessdenied"
  // and the message reads "not authorized" (access-denied) while also carrying
  // the genuine expiry phrases "sso session" and "token has expired"
  // (auth-expired) — is therefore auth_expired: the actionable next step is
  // `aws sso login`, since an expired token surfaces as a permission-shaped
  // error. The narrowly-guarded case — a bare `AWSReservedSSO_`/sso role ARN
  // with NO expiry phrase — stays access_denied (the regression above).
  const err = Object.assign(
    new Error(
      "User is not authorized to perform iam:GetRole; the sso session token has expired",
    ),
    { name: "AccessDeniedException" },
  );
  assertEquals(classifyError(err).kind, "auth_expired");
});

Deno.test("classifyError: network failure classifies as network (before auth_expired)", () => {
  // A getaddrinfo/ENOTFOUND failure during credential resolution surfaces as a
  // "Could not load credentials" CredentialsProviderError — which would
  // otherwise trip auth_expired. The shared lib checks network first, so the
  // operator is not sent to `aws sso login` for a transient DNS blip.
  const wrapped = Object.assign(
    new Error("Could not load credentials from any providers"),
    {
      name: "CredentialsProviderError",
      cause: new Error("getaddrinfo ENOTFOUND iam.us-east-1.amazonaws.com"),
    },
  );
  assertEquals(classifyError(wrapped).kind, "network");
});

Deno.test("classifyError: unrelated failure is other", () => {
  assertEquals(classifyError(new Error("connection reset")).kind, "other");
  assertEquals(classifyError("plain string").kind, "other");
});

// ---------------------------------------------------------------------------
// policyNameFromArn / roleKey / scanErrorKey
// ---------------------------------------------------------------------------

Deno.test("policyNameFromArn: returns the final segment, or the input when no slash", () => {
  assertEquals(
    policyNameFromArn("arn:aws:iam::aws:policy/ReadOnlyAccess"),
    "ReadOnlyAccess",
  );
  assertEquals(
    policyNameFromArn("arn:aws:iam::123456789012:policy/path/Deep"),
    "Deep",
  );
  assertEquals(policyNameFromArn("BareName"), "BareName");
});

Deno.test("roleKey: composes account and role; falls back to 'unknown'", () => {
  assertEquals(
    roleKey("123456789012", "DemoRole"),
    "role-123456789012-DemoRole",
  );
  assertEquals(roleKey("", "DemoRole"), "role-unknown-DemoRole");
});

Deno.test("scanErrorKey: composes profile/role/phase; falls back for ambient + empty role", () => {
  assertEquals(
    scanErrorKey("acct-readonly", "DemoRole", "get_role"),
    "error-acct-readonly-DemoRole-get_role",
  );
  assertEquals(
    scanErrorKey("", "", "credentials"),
    "error-ambient-_-credentials",
  );
});
