/**
 * Unit tests for the @jentz/aws-s3-bucket-audit report extension.
 *
 * Bundles are constructed directly from fixture JSON (no filesystem I/O)
 * so every test is synchronous and self-contained.
 */

import {
  assert,
  assertEquals,
  assertExists,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import {
  type BucketBundle,
  checkEncryption,
  checkLifecycleExpiresNoncurrent,
  checkNoOverbroadAllow,
  checkOwnershipEnforced,
  checkPublicAccessBlock,
  checkServerAccessLogging,
  checkTLSMinVersion12,
  checkTLSOnlyPolicy,
  checkVersioning,
  findGateTrippers,
  inventoryTags,
  parseFailOnThreshold,
  type PolicyStatement,
  report,
  statementDeniesBelowTls12,
  statementDeniesInsecureTransport,
  statementGrantsOverbroadAllow,
} from "../s3_bucket_audit.ts";

// ---------------------------------------------------------------------------
// Fixture data — matches shapes from .swamp/data raw files
// ---------------------------------------------------------------------------

/** clean-bucket bucket state (clean: all checks pass). */
const cleanBucketState = {
  BucketName: "example-iac-state-alpha",
  BucketEncryption: {
    ServerSideEncryptionConfiguration: [
      { ServerSideEncryptionByDefault: { SSEAlgorithm: "AES256" } },
    ],
  },
  VersioningConfiguration: { Status: "Enabled" },
  PublicAccessBlockConfiguration: {
    BlockPublicAcls: true,
    BlockPublicPolicy: true,
    IgnorePublicAcls: true,
    RestrictPublicBuckets: true,
  },
  OwnershipControls: { Rules: [{ ObjectOwnership: "BucketOwnerEnforced" }] },
  LifecycleConfiguration: {
    Rules: [
      {
        Status: "Enabled",
        Id: "expire-noncurrent-versions",
        NoncurrentVersionExpiration: { NoncurrentDays: 90 },
      },
    ],
  },
  // LoggingConfiguration absent (matches real fixture)
  Tags: [
    { Key: "Environment", Value: "production" },
    { Key: "ManagedBy", Value: "terraform" },
  ],
};

/** noncompliant fixture bucket state (missing OwnershipControls, no Lifecycle, no Tags). */
const noncompliantBucketState = {
  BucketName: "example-tfstate-noncompliant",
  BucketEncryption: {
    ServerSideEncryptionConfiguration: [
      {
        ServerSideEncryptionByDefault: {
          SSEAlgorithm: "aws:kms",
          KMSMasterKeyID: "arn:aws:kms:eu-west-1:222222222222:alias/aws/s3",
        },
      },
    ],
  },
  VersioningConfiguration: { Status: "Enabled" },
  PublicAccessBlockConfiguration: {
    BlockPublicAcls: true,
    BlockPublicPolicy: true,
    IgnorePublicAcls: true,
    RestrictPublicBuckets: true,
  },
  // No OwnershipControls
  // No LifecycleConfiguration
  // No Tags
  // No LoggingConfiguration
};

/** clean-bucket bucket-policy (TLS Deny, object form, both ARNs). */
const cleanBucketPolicy = {
  Bucket: "example-iac-state-alpha",
  PolicyDocument: {
    Version: "2012-10-17",
    Statement: [
      {
        Condition: { Bool: { "aws:SecureTransport": "false" } },
        Action: "s3:*",
        Resource: [
          "arn:aws:s3:::example-iac-state-alpha/*",
          "arn:aws:s3:::example-iac-state-alpha",
        ],
        Effect: "Deny",
        Principal: "*",
        Sid: "DenyInsecureTransport",
      },
    ],
  },
};

/** noncompliant fixture bucket-policy (TLS Deny + RootAccess Allow; object form). */
const noncompliantBucketPolicy = {
  Bucket: "example-tfstate-noncompliant",
  PolicyDocument: {
    Version: "2012-10-17",
    Statement: [
      {
        Condition: { Bool: { "aws:SecureTransport": "false" } },
        Action: "s3:*",
        Resource: [
          "arn:aws:s3:::example-tfstate-noncompliant",
          "arn:aws:s3:::example-tfstate-noncompliant/*",
        ],
        Effect: "Deny",
        Principal: "*",
        Sid: "EnforcedTLS",
      },
      {
        Action: "s3:*",
        Resource: [
          "arn:aws:s3:::example-tfstate-noncompliant",
          "arn:aws:s3:::example-tfstate-noncompliant/*",
        ],
        Effect: "Allow",
        Principal: { AWS: "arn:aws:iam::222222222222:root" },
        Sid: "RootAccess",
      },
    ],
  },
};

/**
 * synthetic-narrow-deny bucket-policy — Deny is scoped only to
 * s3:DeleteObject on a specific path.  Should FAIL the tightened check.
 */
const narrowDenyPolicy = {
  Bucket: "my-bucket",
  PolicyDocument: {
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Deny",
        Principal: "*",
        Action: "s3:DeleteObject",
        Resource: "arn:aws:s3:::my-bucket/sensitive-path/*",
        Condition: { Bool: { "aws:SecureTransport": "false" } },
        Sid: "NarrowDenyNotTLSEnforcing",
      },
    ],
  },
};

// ---------------------------------------------------------------------------
// Helper bundle factories
// ---------------------------------------------------------------------------

/** Build a BucketBundle from a state object (name taken from `BucketName`). */
function stateOnly(state: Record<string, unknown>): BucketBundle {
  return {
    name: state.BucketName as string,
    state: state as unknown as BucketBundle["state"],
  };
}

/** Build a BucketBundle from a state and a policy object. */
function statePolicy(
  state: Record<string, unknown>,
  policy: Record<string, unknown>,
): BucketBundle {
  return {
    name: state.BucketName as string,
    state: state as unknown as BucketBundle["state"],
    policy: policy as unknown as BucketBundle["policy"],
  };
}

function cleanBundle(): BucketBundle {
  return statePolicy(cleanBucketState, cleanBucketPolicy);
}

function noncompliantBundle(): BucketBundle {
  return statePolicy(noncompliantBucketState, noncompliantBucketPolicy);
}

function noStateBundle(): BucketBundle {
  return { name: "no-state-bucket" };
}

function noPolicyBundle(): BucketBundle {
  return stateOnly(cleanBucketState);
}

// ---------------------------------------------------------------------------
// Rule 1 — bucket-versioning-enabled
// ---------------------------------------------------------------------------

Deno.test("checkVersioning: PASS when Status=Enabled", () => {
  const f = checkVersioning(cleanBundle());
  assertEquals(f.id, "bucket-versioning-enabled");
  assertEquals(f.status, "pass");
});

Deno.test("checkVersioning: FAIL when VersioningConfiguration absent", () => {
  const b: BucketBundle = {
    name: "no-versioning",
    state: {
      BucketName: "no-versioning",
    } as unknown as BucketBundle["state"],
  };
  const f = checkVersioning(b);
  assertEquals(f.status, "fail");
});

Deno.test("checkVersioning: FAIL when Status=Suspended", () => {
  const b: BucketBundle = {
    name: "suspended",
    state: {
      BucketName: "suspended",
      VersioningConfiguration: { Status: "Suspended" },
    } as unknown as BucketBundle["state"],
  };
  const f = checkVersioning(b);
  assertEquals(f.status, "fail");
  assertEquals((f.actual as { Status: unknown }).Status, "Suspended");
});

Deno.test("checkVersioning: SKIP when state missing", () => {
  const f = checkVersioning(noStateBundle());
  assertEquals(f.status, "skip");
  assertExists(f.message);
});

Deno.test("checkVersioning: SKIP message uses stateError when set", () => {
  const b: BucketBundle = {
    name: "err-bucket",
    stateError: "bucket lookup step failed",
  };
  const f = checkVersioning(b);
  assertEquals(f.status, "skip");
  assertEquals(f.message, "bucket lookup step failed");
});

// ---------------------------------------------------------------------------
// Rule 2 — bucket-encryption-enabled
// ---------------------------------------------------------------------------

Deno.test("checkEncryption: PASS with AES256", () => {
  const f = checkEncryption(cleanBundle());
  assertEquals(f.id, "bucket-encryption-enabled");
  assertEquals(f.status, "pass");
  assert((f.actual as { algorithms: string[] }).algorithms.includes("AES256"));
});

Deno.test("checkEncryption: PASS with aws:kms (noncompliant fixture)", () => {
  const f = checkEncryption(noncompliantBundle());
  assertEquals(f.status, "pass");
  assert(
    (f.actual as { algorithms: string[] }).algorithms.includes("aws:kms"),
  );
});

Deno.test("checkEncryption: FAIL when no encryption configured", () => {
  const b: BucketBundle = {
    name: "no-enc",
    state: { BucketName: "no-enc" } as unknown as BucketBundle["state"],
  };
  const f = checkEncryption(b);
  assertEquals(f.status, "fail");
  assertEquals((f.actual as { algorithms: string[] }).algorithms.length, 0);
});

Deno.test("checkEncryption: SKIP when state missing", () => {
  assertEquals(checkEncryption(noStateBundle()).status, "skip");
});

// ---------------------------------------------------------------------------
// Rule 3 — bucket-public-access-blocked
// ---------------------------------------------------------------------------

Deno.test("checkPublicAccessBlock: PASS when all four flags true", () => {
  const f = checkPublicAccessBlock(cleanBundle());
  assertEquals(f.id, "bucket-public-access-blocked");
  assertEquals(f.status, "pass");
});

const publicAccessCases = [
  {
    name: "BlockPublicAcls=false",
    bpa: {
      BlockPublicAcls: false,
      BlockPublicPolicy: true,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true,
    },
  },
  {
    name: "BlockPublicPolicy=false",
    bpa: {
      BlockPublicAcls: true,
      BlockPublicPolicy: false,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true,
    },
  },
  {
    name: "all flags absent",
    bpa: undefined,
  },
];

for (const c of publicAccessCases) {
  Deno.test(`checkPublicAccessBlock: FAIL when ${c.name}`, () => {
    const b: BucketBundle = {
      name: "bad-pab",
      state: {
        BucketName: "bad-pab",
        PublicAccessBlockConfiguration: c.bpa,
      } as unknown as BucketBundle["state"],
    };
    assertEquals(checkPublicAccessBlock(b).status, "fail");
  });
}

Deno.test("checkPublicAccessBlock: SKIP when state missing", () => {
  assertEquals(checkPublicAccessBlock(noStateBundle()).status, "skip");
});

// ---------------------------------------------------------------------------
// Rule 4 — bucket-ownership-enforced
// ---------------------------------------------------------------------------

Deno.test("checkOwnershipEnforced: PASS with BucketOwnerEnforced", () => {
  const f = checkOwnershipEnforced(cleanBundle());
  assertEquals(f.id, "bucket-ownership-enforced");
  assertEquals(f.status, "pass");
});

Deno.test(
  "checkOwnershipEnforced: FAIL when OwnershipControls absent (noncompliant fixture)",
  () => {
    const f = checkOwnershipEnforced(noncompliantBundle());
    assertEquals(f.status, "fail");
  },
);

Deno.test("checkOwnershipEnforced: FAIL with ObjectOwnership=ObjectWriter", () => {
  const b: BucketBundle = {
    name: "writer",
    state: {
      BucketName: "writer",
      OwnershipControls: {
        Rules: [{ ObjectOwnership: "ObjectWriter" }],
      },
    } as unknown as BucketBundle["state"],
  };
  assertEquals(checkOwnershipEnforced(b).status, "fail");
});

Deno.test("checkOwnershipEnforced: SKIP when state missing", () => {
  assertEquals(checkOwnershipEnforced(noStateBundle()).status, "skip");
});

// ---------------------------------------------------------------------------
// Rule 5 — bucket-tls-only-policy (including PolicyDocument union-schema tests)
// ---------------------------------------------------------------------------

Deno.test(
  "checkTLSOnlyPolicy: PASS with object-form PolicyDocument (clean-bucket)",
  () => {
    const f = checkTLSOnlyPolicy(cleanBundle());
    assertEquals(f.id, "bucket-tls-only-policy");
    assertEquals(f.status, "pass");
  },
);

Deno.test(
  "checkTLSOnlyPolicy: PASS with object-form PolicyDocument (noncompliant fixture — multi-statement)",
  () => {
    assertEquals(checkTLSOnlyPolicy(noncompliantBundle()).status, "pass");
  },
);

Deno.test(
  "checkTLSOnlyPolicy: PASS with string-form PolicyDocument (same content as clean-bucket)",
  () => {
    // Serialize the policy document to a JSON string — simulates the original
    // upstream CloudControl behavior where PolicyDocument arrives as a string.
    const stringFormPolicy = {
      Bucket: cleanBucketState.BucketName,
      PolicyDocument: JSON.stringify(cleanBucketPolicy.PolicyDocument),
    };
    const b: BucketBundle = {
      name: cleanBucketState.BucketName,
      state: cleanBucketState as unknown as BucketBundle["state"],
      policy: stringFormPolicy as unknown as BucketBundle["policy"],
    };
    assertEquals(checkTLSOnlyPolicy(b).status, "pass");
  },
);

Deno.test(
  "checkTLSOnlyPolicy: identical findings for string vs object PolicyDocument",
  () => {
    const objectBundle: BucketBundle = {
      name: cleanBucketState.BucketName,
      state: cleanBucketState as unknown as BucketBundle["state"],
      policy: cleanBucketPolicy as unknown as BucketBundle["policy"],
    };
    const stringBundle: BucketBundle = {
      name: cleanBucketState.BucketName,
      state: cleanBucketState as unknown as BucketBundle["state"],
      policy: {
        Bucket: cleanBucketState.BucketName,
        PolicyDocument: JSON.stringify(cleanBucketPolicy.PolicyDocument),
      } as unknown as BucketBundle["policy"],
    };
    const fo = checkTLSOnlyPolicy(objectBundle);
    const fs = checkTLSOnlyPolicy(stringBundle);
    assertEquals(fo.status, fs.status);
    assertEquals(fo.id, fs.id);
    assertEquals(fo.severity, fs.severity);
  },
);

Deno.test(
  "checkTLSOnlyPolicy: SKIP when no policy data and no policyError (workflow missing the bucket-policy lookup step)",
  () => {
    // noPolicyBundle has state but neither `policy` nor `policyError`.
    // The audit can't conclude the bucket lacks a TLS policy — it never
    // looked — so the result is SKIP, not FAIL.
    const f = checkTLSOnlyPolicy(noPolicyBundle());
    assertEquals(f.status, "skip");
    assert(f.message.includes("@swamp/aws/s3/bucket-policy"));
  },
);

Deno.test(
  "checkTLSOnlyPolicy: FAIL when policy lookup ran and returned a policy with no PolicyDocument",
  () => {
    // Policy lookup succeeded (so `policy` is present) but the bucket has
    // no PolicyDocument attached. That is a real audit failure: we looked
    // and there's no TLS-enforcing policy.
    const b: BucketBundle = {
      name: "explicit-no-policy",
      state: cleanBucketState as unknown as BucketBundle["state"],
      policy: {
        Bucket: "explicit-no-policy",
      } as unknown as BucketBundle["policy"],
    };
    assertEquals(checkTLSOnlyPolicy(b).status, "fail");
  },
);

Deno.test("checkTLSOnlyPolicy: FAIL when PolicyDocument is empty string", () => {
  const b: BucketBundle = {
    name: "empty-policy",
    state: cleanBucketState as unknown as BucketBundle["state"],
    policy: {
      Bucket: "empty-policy",
      PolicyDocument: "",
    } as unknown as BucketBundle["policy"],
  };
  assertEquals(checkTLSOnlyPolicy(b).status, "fail");
});

Deno.test("checkTLSOnlyPolicy: SKIP on unparseable string PolicyDocument", () => {
  const b: BucketBundle = {
    name: "bad-json",
    state: cleanBucketState as unknown as BucketBundle["state"],
    policy: {
      Bucket: "bad-json",
      PolicyDocument: "NOT VALID JSON {{{",
    } as unknown as BucketBundle["policy"],
  };
  assertEquals(checkTLSOnlyPolicy(b).status, "skip");
});

Deno.test("checkTLSOnlyPolicy: FAIL on empty Statement array", () => {
  const b: BucketBundle = {
    name: "empty-stmts",
    state: cleanBucketState as unknown as BucketBundle["state"],
    policy: {
      Bucket: "empty-stmts",
      PolicyDocument: { Version: "2012-10-17", Statement: [] },
    } as unknown as BucketBundle["policy"],
  };
  assertEquals(checkTLSOnlyPolicy(b).status, "fail");
});

// --- Tightened check tests ---

Deno.test(
  "checkTLSOnlyPolicy: FAIL for narrow Deny (scoped action/resource — synthetic fixture)",
  () => {
    const b: BucketBundle = {
      name: narrowDenyPolicy.Bucket,
      state: {
        BucketName: narrowDenyPolicy.Bucket,
      } as unknown as BucketBundle["state"],
      policy: narrowDenyPolicy as unknown as BucketBundle["policy"],
    };
    assertEquals(checkTLSOnlyPolicy(b).status, "fail");
  },
);

Deno.test(
  "checkTLSOnlyPolicy: FAIL when Principal is scoped (not wildcard)",
  () => {
    const b: BucketBundle = {
      name: "scoped-principal",
      state: {
        BucketName: "scoped-principal",
      } as unknown as BucketBundle["state"],
      policy: {
        Bucket: "scoped-principal",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Deny",
              Principal: { AWS: "arn:aws:iam::123456789012:root" },
              Action: "s3:*",
              Resource: [
                "arn:aws:s3:::scoped-principal",
                "arn:aws:s3:::scoped-principal/*",
              ],
              Condition: { Bool: { "aws:SecureTransport": "false" } },
            },
          ],
        },
      } as unknown as BucketBundle["policy"],
    };
    assertEquals(checkTLSOnlyPolicy(b).status, "fail");
  },
);

Deno.test(
  "checkTLSOnlyPolicy: PASS when Principal is {AWS: '*'} (object wildcard)",
  () => {
    const b: BucketBundle = {
      name: "obj-wildcard",
      state: {
        BucketName: "obj-wildcard",
      } as unknown as BucketBundle["state"],
      policy: {
        Bucket: "obj-wildcard",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Deny",
              Principal: { AWS: "*" },
              Action: "s3:*",
              Resource: [
                "arn:aws:s3:::obj-wildcard",
                "arn:aws:s3:::obj-wildcard/*",
              ],
              Condition: { Bool: { "aws:SecureTransport": "false" } },
            },
          ],
        },
      } as unknown as BucketBundle["policy"],
    };
    assertEquals(checkTLSOnlyPolicy(b).status, "pass");
  },
);

Deno.test(
  "checkTLSOnlyPolicy: FAIL when Action is list without s3:*",
  () => {
    const b: BucketBundle = {
      name: "partial-action",
      state: {
        BucketName: "partial-action",
      } as unknown as BucketBundle["state"],
      policy: {
        Bucket: "partial-action",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Deny",
              Principal: "*",
              Action: ["s3:GetObject", "s3:PutObject"],
              Resource: [
                "arn:aws:s3:::partial-action",
                "arn:aws:s3:::partial-action/*",
              ],
              Condition: { Bool: { "aws:SecureTransport": "false" } },
            },
          ],
        },
      } as unknown as BucketBundle["policy"],
    };
    assertEquals(checkTLSOnlyPolicy(b).status, "fail");
  },
);

Deno.test(
  "checkTLSOnlyPolicy: PASS when Action is list containing s3:*",
  () => {
    const b: BucketBundle = {
      name: "list-with-star",
      state: {
        BucketName: "list-with-star",
      } as unknown as BucketBundle["state"],
      policy: {
        Bucket: "list-with-star",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Deny",
              Principal: "*",
              Action: ["s3:GetObject", "s3:*"],
              Resource: [
                "arn:aws:s3:::list-with-star",
                "arn:aws:s3:::list-with-star/*",
              ],
              Condition: { Bool: { "aws:SecureTransport": "false" } },
            },
          ],
        },
      } as unknown as BucketBundle["policy"],
    };
    assertEquals(checkTLSOnlyPolicy(b).status, "pass");
  },
);

Deno.test(
  "checkTLSOnlyPolicy: FAIL when Resource covers only bucket/* (missing bucket root)",
  () => {
    const b: BucketBundle = {
      name: "content-only",
      state: {
        BucketName: "content-only",
      } as unknown as BucketBundle["state"],
      policy: {
        Bucket: "content-only",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Deny",
              Principal: "*",
              Action: "s3:*",
              Resource: "arn:aws:s3:::content-only/*",
              Condition: { Bool: { "aws:SecureTransport": "false" } },
            },
          ],
        },
      } as unknown as BucketBundle["policy"],
    };
    assertEquals(checkTLSOnlyPolicy(b).status, "fail");
  },
);

Deno.test(
  "checkTLSOnlyPolicy: PASS with Resource wildcard *",
  () => {
    const b: BucketBundle = {
      name: "wildcard-resource",
      state: {
        BucketName: "wildcard-resource",
      } as unknown as BucketBundle["state"],
      policy: {
        Bucket: "wildcard-resource",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Deny",
              Principal: "*",
              Action: "s3:*",
              Resource: "*",
              Condition: { Bool: { "aws:SecureTransport": "false" } },
            },
          ],
        },
      } as unknown as BucketBundle["policy"],
    };
    assertEquals(checkTLSOnlyPolicy(b).status, "pass");
  },
);

Deno.test(
  "checkTLSOnlyPolicy: FAIL when policyError and no PolicyDocument",
  () => {
    const b: BucketBundle = {
      name: "err-bucket",
      policyError: "bucket-policy lookup step failed",
    };
    assertEquals(checkTLSOnlyPolicy(b).status, "fail");
  },
);

// --- statementDeniesInsecureTransport unit tests ---

Deno.test("statementDeniesInsecureTransport: true for canonical statement", () => {
  const stmt: PolicyStatement = {
    Effect: "Deny",
    Principal: "*",
    Action: "s3:*",
    Resource: [
      "arn:aws:s3:::my-bucket",
      "arn:aws:s3:::my-bucket/*",
    ],
    Condition: { Bool: { "aws:SecureTransport": "false" } },
  };
  assert(statementDeniesInsecureTransport(stmt, "my-bucket"));
});

Deno.test(
  "statementDeniesInsecureTransport: true when condition value is boolean false",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*",
      ],
      Condition: {
        Bool: { "aws:SecureTransport": false as unknown as string },
      },
    };
    assert(statementDeniesInsecureTransport(stmt, "my-bucket"));
  },
);

Deno.test(
  "statementDeniesInsecureTransport: false when Effect is Allow",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Allow",
      Principal: "*",
      Action: "s3:*",
      Resource: ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
      Condition: { Bool: { "aws:SecureTransport": "false" } },
    };
    assert(!statementDeniesInsecureTransport(stmt, "b"));
  },
);

Deno.test(
  "statementDeniesInsecureTransport: false when Action is scoped",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:DeleteObject",
      Resource: ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
      Condition: { Bool: { "aws:SecureTransport": "false" } },
    };
    assert(!statementDeniesInsecureTransport(stmt, "b"));
  },
);

Deno.test(
  "statementDeniesInsecureTransport: false when Resource is path-scoped",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: "arn:aws:s3:::b/sensitive/*",
      Condition: { Bool: { "aws:SecureTransport": "false" } },
    };
    assert(!statementDeniesInsecureTransport(stmt, "b"));
  },
);

// ---------------------------------------------------------------------------
// Rule — bucket-tls-min-version-1.2 (warn)
// ---------------------------------------------------------------------------

/**
 * clean-bucket-with-tls12 — bucket policy with both the canonical TLS-only
 * Deny AND a separate NumericLessThan Deny on s3:TlsVersion. Mirrors what
 * a fully-hardened bucket policy looks like; both rules pass.
 */
const cleanBucketWithTls12Policy = {
  Bucket: "tls12-bucket",
  PolicyDocument: {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "DenyInsecureTransport",
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: [
          "arn:aws:s3:::tls12-bucket",
          "arn:aws:s3:::tls12-bucket/*",
        ],
        Condition: { Bool: { "aws:SecureTransport": "false" } },
      },
      {
        Sid: "DenyBelowTls12",
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: [
          "arn:aws:s3:::tls12-bucket",
          "arn:aws:s3:::tls12-bucket/*",
        ],
        Condition: { NumericLessThan: { "s3:TlsVersion": "1.2" } },
      },
    ],
  },
};

Deno.test("checkTLSMinVersion12: PASS with NumericLessThan 1.2", () => {
  const b = statePolicy(
    { BucketName: "tls12-bucket" },
    cleanBucketWithTls12Policy,
  );
  const f = checkTLSMinVersion12(b);
  assertEquals(f.id, "bucket-tls-min-version-1.2");
  assertEquals(f.severity, "warn");
  assertEquals(f.status, "pass");
});

Deno.test("checkTLSMinVersion12: PASS with NumericLessThanIfExists 1.2", () => {
  const b = statePolicy(
    { BucketName: "ifexists-bucket" },
    {
      Bucket: "ifexists-bucket",
      PolicyDocument: {
        Statement: [
          {
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [
              "arn:aws:s3:::ifexists-bucket",
              "arn:aws:s3:::ifexists-bucket/*",
            ],
            Condition: {
              NumericLessThanIfExists: { "s3:TlsVersion": "1.2" },
            },
          },
        ],
      },
    },
  );
  assertEquals(checkTLSMinVersion12(b).status, "pass");
});

Deno.test("checkTLSMinVersion12: PASS when configured TLS floor is 1.3", () => {
  // A NumericLessThan 1.3 Deny enforces a higher floor than 1.2 and so
  // still satisfies the rule's >= 1.2 requirement.
  const b = statePolicy(
    { BucketName: "tls13-bucket" },
    {
      Bucket: "tls13-bucket",
      PolicyDocument: {
        Statement: [
          {
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [
              "arn:aws:s3:::tls13-bucket",
              "arn:aws:s3:::tls13-bucket/*",
            ],
            Condition: { NumericLessThan: { "s3:TlsVersion": "1.3" } },
          },
        ],
      },
    },
  );
  assertEquals(checkTLSMinVersion12(b).status, "pass");
});

Deno.test(
  "checkTLSMinVersion12: PASS when condition key is mixed-case 's3:tlsversion'",
  () => {
    // IAM condition keys are case-insensitive, mirroring the existing
    // aws:SecureTransport handling.
    const b = statePolicy(
      { BucketName: "mixed-case-key" },
      {
        Bucket: "mixed-case-key",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Deny",
              Principal: "*",
              Action: "s3:*",
              Resource: [
                "arn:aws:s3:::mixed-case-key",
                "arn:aws:s3:::mixed-case-key/*",
              ],
              Condition: { NumericLessThan: { "s3:tlsversion": "1.2" } },
            },
          ],
        },
      },
    );
    assertEquals(checkTLSMinVersion12(b).status, "pass");
  },
);

Deno.test(
  "checkTLSMinVersion12: WARN when only the generic TLS Deny is present (no min-version Deny)",
  () => {
    // cleanBundle has a TLS-only Deny but no s3:TlsVersion Deny.
    // bucket-tls-only-policy passes; bucket-tls-min-version-1.2 must warn.
    const f = checkTLSMinVersion12(cleanBundle());
    assertEquals(f.status, "warn");
  },
);

Deno.test("checkTLSMinVersion12: WARN when min-version floor is 1.0", () => {
  const b = statePolicy(
    { BucketName: "tls10-bucket" },
    {
      Bucket: "tls10-bucket",
      PolicyDocument: {
        Statement: [
          {
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [
              "arn:aws:s3:::tls10-bucket",
              "arn:aws:s3:::tls10-bucket/*",
            ],
            Condition: { NumericLessThan: { "s3:TlsVersion": "1.0" } },
          },
        ],
      },
    },
  );
  assertEquals(checkTLSMinVersion12(b).status, "warn");
});

Deno.test(
  "checkTLSMinVersion12: SKIP when no policy lookup step (no policy, no policyError)",
  () => {
    const f = checkTLSMinVersion12(noPolicyBundle());
    assertEquals(f.status, "skip");
    assert(f.message.includes("@swamp/aws/s3/bucket-policy"));
  },
);

Deno.test(
  "checkTLSMinVersion12: SKIP on unparseable string PolicyDocument",
  () => {
    const b: BucketBundle = {
      name: "bad-json-tls12",
      state: cleanBucketState as unknown as BucketBundle["state"],
      policy: {
        Bucket: "bad-json-tls12",
        PolicyDocument: "NOT VALID JSON {{{",
      } as unknown as BucketBundle["policy"],
    };
    assertEquals(checkTLSMinVersion12(b).status, "skip");
  },
);

// Regression: the existing TLS-only rule must continue to PASS on cleanBundle
// after the new rule lands. cleanBundle's policy has the canonical TLS Deny
// but no s3:TlsVersion Deny, so the two rules diverge — guard against any
// accidental coupling between them.
Deno.test(
  "checkTLSOnlyPolicy: still PASSES on cleanBundle after adding checkTLSMinVersion12",
  () => {
    assertEquals(checkTLSOnlyPolicy(cleanBundle()).status, "pass");
  },
);

// --- statementDeniesBelowTls12 unit tests ---

Deno.test(
  "statementDeniesBelowTls12: true for canonical NumericLessThan 1.2",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*",
      ],
      Condition: { NumericLessThan: { "s3:TlsVersion": "1.2" } },
    };
    assert(statementDeniesBelowTls12(stmt, "my-bucket"));
  },
);

Deno.test(
  "statementDeniesBelowTls12: true when value is numeric (not string)",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
      Condition: {
        NumericLessThan: { "s3:TlsVersion": 1.2 as unknown as string },
      },
    };
    assert(statementDeniesBelowTls12(stmt, "b"));
  },
);

Deno.test("statementDeniesBelowTls12: false when Effect is Allow", () => {
  const stmt: PolicyStatement = {
    Effect: "Allow",
    Principal: "*",
    Action: "s3:*",
    Resource: ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
    Condition: { NumericLessThan: { "s3:TlsVersion": "1.2" } },
  };
  assert(!statementDeniesBelowTls12(stmt, "b"));
});

Deno.test(
  "statementDeniesBelowTls12: false when operator is Bool (wrong operator type)",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
      Condition: { Bool: { "s3:TlsVersion": "1.2" } },
    };
    assert(!statementDeniesBelowTls12(stmt, "b"));
  },
);

// ---------------------------------------------------------------------------
// Rule — bucket-no-overbroad-allow (error)
// ---------------------------------------------------------------------------

/**
 * overbroad-allow-bucket — bucket policy containing a canonical TLS-only
 * Deny AND a wide-open Allow s3:* Principal:* on bucket+bucket/* with no
 * narrowing Condition. This is the exact false-PASS case that the new
 * rule exists to catch: bucket-tls-only-policy passes (TLS Deny present),
 * but bucket-no-overbroad-allow must FAIL.
 */
const overbroadAllowPolicy = {
  Bucket: "overbroad-bucket",
  PolicyDocument: {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "DenyInsecureTransport",
        Effect: "Deny",
        Principal: "*",
        Action: "s3:*",
        Resource: [
          "arn:aws:s3:::overbroad-bucket",
          "arn:aws:s3:::overbroad-bucket/*",
        ],
        Condition: { Bool: { "aws:SecureTransport": "false" } },
      },
      {
        Sid: "WideOpenAllow",
        Effect: "Allow",
        Principal: "*",
        Action: "s3:*",
        Resource: [
          "arn:aws:s3:::overbroad-bucket",
          "arn:aws:s3:::overbroad-bucket/*",
        ],
      },
    ],
  },
};

Deno.test(
  "checkNoOverbroadAllow: PASS on cleanBundle (no Allow at all)",
  () => {
    const f = checkNoOverbroadAllow(cleanBundle());
    assertEquals(f.id, "bucket-no-overbroad-allow");
    assertEquals(f.severity, "error");
    assertEquals(f.status, "pass");
  },
);

Deno.test(
  "checkNoOverbroadAllow: PASS on noncompliantBundle (Allow is scoped to a specific Principal)",
  () => {
    // noncompliantBucketPolicy's Allow targets a specific AWS account ARN,
    // not Principal:*. Not overbroad.
    assertEquals(checkNoOverbroadAllow(noncompliantBundle()).status, "pass");
  },
);

Deno.test(
  "checkNoOverbroadAllow: FAIL on overbroad Allow (s3:* Principal:* no Condition) — false-PASS gap closed",
  () => {
    // Closes the audit gap: checkTLSOnlyPolicy still PASSes on this
    // fixture (TLS Deny is present), but checkNoOverbroadAllow must FAIL.
    const b = statePolicy(
      { BucketName: "overbroad-bucket" },
      overbroadAllowPolicy,
    );
    assertEquals(checkTLSOnlyPolicy(b).status, "pass");
    const f = checkNoOverbroadAllow(b);
    assertEquals(f.status, "fail");
    assertEquals(
      (f.actual as { overbroadCount: number }).overbroadCount,
      1,
    );
    assertEquals(
      (f.actual as { overbroadStatements: string[] }).overbroadStatements,
      ["WideOpenAllow"],
    );
    assert(f.message.includes("WideOpenAllow"));
  },
);

Deno.test(
  "checkNoOverbroadAllow: FAIL when only Condition is aws:SecureTransport (TLS Condition does not narrow)",
  () => {
    // A TLS-only Condition on an otherwise-overbroad Allow leaves the
    // bucket effectively public for any TLS request. Must FAIL.
    const b = statePolicy(
      { BucketName: "tls-only-allow" },
      {
        Bucket: "tls-only-allow",
        PolicyDocument: {
          Statement: [
            {
              Sid: "TlsOnlyButOverbroad",
              Effect: "Allow",
              Principal: "*",
              Action: "s3:*",
              Resource: [
                "arn:aws:s3:::tls-only-allow",
                "arn:aws:s3:::tls-only-allow/*",
              ],
              Condition: { Bool: { "aws:SecureTransport": "true" } },
            },
          ],
        },
      },
    );
    assertEquals(checkNoOverbroadAllow(b).status, "fail");
  },
);

Deno.test(
  "checkNoOverbroadAllow: FAIL with Action wildcard '*' (all-services form)",
  () => {
    const b = statePolicy(
      { BucketName: "star-action" },
      {
        Bucket: "star-action",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Action: "*",
              Resource: [
                "arn:aws:s3:::star-action",
                "arn:aws:s3:::star-action/*",
              ],
            },
          ],
        },
      },
    );
    assertEquals(checkNoOverbroadAllow(b).status, "fail");
  },
);

Deno.test(
  "checkNoOverbroadAllow: PASS when narrowed by aws:PrincipalOrgID",
  () => {
    const b = statePolicy(
      { BucketName: "org-scoped" },
      {
        Bucket: "org-scoped",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Action: "s3:*",
              Resource: [
                "arn:aws:s3:::org-scoped",
                "arn:aws:s3:::org-scoped/*",
              ],
              Condition: {
                StringEquals: { "aws:PrincipalOrgID": "o-1234567890" },
              },
            },
          ],
        },
      },
    );
    assertEquals(checkNoOverbroadAllow(b).status, "pass");
  },
);

Deno.test(
  "checkNoOverbroadAllow: PASS when narrowed by aws:SourceVpce",
  () => {
    const b = statePolicy(
      { BucketName: "vpce-scoped" },
      {
        Bucket: "vpce-scoped",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Action: "s3:*",
              Resource: [
                "arn:aws:s3:::vpce-scoped",
                "arn:aws:s3:::vpce-scoped/*",
              ],
              Condition: {
                StringEquals: { "aws:SourceVpce": "vpce-0abc123def456" },
              },
            },
          ],
        },
      },
    );
    assertEquals(checkNoOverbroadAllow(b).status, "pass");
  },
);

Deno.test(
  "checkNoOverbroadAllow: PASS when narrowed by aws:SourceIp (IpAddress operator)",
  () => {
    const b = statePolicy(
      { BucketName: "ip-scoped" },
      {
        Bucket: "ip-scoped",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Action: "s3:*",
              Resource: [
                "arn:aws:s3:::ip-scoped",
                "arn:aws:s3:::ip-scoped/*",
              ],
              Condition: {
                IpAddress: { "aws:SourceIp": "203.0.113.0/24" },
              },
            },
          ],
        },
      },
    );
    assertEquals(checkNoOverbroadAllow(b).status, "pass");
  },
);

Deno.test(
  "checkNoOverbroadAllow: PASS when narrowing-key is in mixed case (case-insensitive matching)",
  () => {
    const b = statePolicy(
      { BucketName: "mixed-case-narrow" },
      {
        Bucket: "mixed-case-narrow",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Action: "s3:*",
              Resource: [
                "arn:aws:s3:::mixed-case-narrow",
                "arn:aws:s3:::mixed-case-narrow/*",
              ],
              Condition: {
                StringEquals: { "AWS:PrincipalOrgID": "o-mixedcase" },
              },
            },
          ],
        },
      },
    );
    assertEquals(checkNoOverbroadAllow(b).status, "pass");
  },
);

Deno.test(
  "checkNoOverbroadAllow: PASS when Resource is narrower than bucket+bucket/*",
  () => {
    // Allow scoped to a prefix below the bucket root does not match
    // resourceCoversBucket, so the statement isn't overbroad.
    const b = statePolicy(
      { BucketName: "prefix-scoped" },
      {
        Bucket: "prefix-scoped",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Allow",
              Principal: "*",
              Action: "s3:*",
              Resource: "arn:aws:s3:::prefix-scoped/public/*",
            },
          ],
        },
      },
    );
    assertEquals(checkNoOverbroadAllow(b).status, "pass");
  },
);

Deno.test(
  "checkNoOverbroadAllow: SKIP when no policy lookup step (no policy, no policyError)",
  () => {
    const f = checkNoOverbroadAllow(noPolicyBundle());
    assertEquals(f.status, "skip");
    assert(f.message.includes("@swamp/aws/s3/bucket-policy"));
  },
);

Deno.test(
  "checkNoOverbroadAllow: SKIP when policy lookup step failed (policyError, no PolicyDocument)",
  () => {
    // bucket-tls-only-policy already FAILs the same bucket (correctly --
    // absence of a TLS-only Deny is a posture finding). This rule asks
    // the opposite question, so a failed lookup is "unknown", not a
    // finding. SKIP eliminates the duplicate-tripper noise that would
    // otherwise appear in the trippers list and the gate.sh output.
    const b: BucketBundle = {
      name: "policy-lookup-failed",
      policyError: "bucket-policy lookup step failed",
    };
    const f = checkNoOverbroadAllow(b);
    assertEquals(f.status, "skip");
    assert(f.message.includes("lookup failed"));
  },
);

// Sister assertion: the existing tls-only-policy behavior on the same
// bundle stays unchanged (FAIL). This pins the asymmetry as deliberate.
Deno.test(
  "checkTLSOnlyPolicy: still FAILs on policyError (pinned vs the no-overbroad-allow SKIP)",
  () => {
    const b: BucketBundle = {
      name: "policy-lookup-failed",
      policyError: "bucket-policy lookup step failed",
    };
    assertEquals(checkTLSOnlyPolicy(b).status, "fail");
  },
);

Deno.test(
  "checkNoOverbroadAllow: SKIP on unparseable string PolicyDocument",
  () => {
    const b: BucketBundle = {
      name: "bad-json-overbroad",
      state: cleanBucketState as unknown as BucketBundle["state"],
      policy: {
        Bucket: "bad-json-overbroad",
        PolicyDocument: "NOT VALID JSON {{{",
      } as unknown as BucketBundle["policy"],
    };
    assertEquals(checkNoOverbroadAllow(b).status, "skip");
  },
);

Deno.test(
  "checkNoOverbroadAllow: PASS when PolicyDocument is empty (no Allow can exist)",
  () => {
    // No PolicyDocument at all means no overbroad Allow can be present.
    // bucket-tls-only-policy FAILs the bucket for this case; this rule
    // PASSes cleanly since there's nothing to flag.
    const b: BucketBundle = {
      name: "empty-policy-allow",
      state: cleanBucketState as unknown as BucketBundle["state"],
      policy: {
        Bucket: "empty-policy-allow",
      } as unknown as BucketBundle["policy"],
    };
    assertEquals(checkNoOverbroadAllow(b).status, "pass");
  },
);

// Regression: existing cleanBundle and noncompliantBundle outcomes
// for every other rule must be unchanged after this rule lands.
Deno.test(
  "regression: cleanBundle TLS-only-policy still PASSES after bucket-no-overbroad-allow added",
  () => {
    assertEquals(checkTLSOnlyPolicy(cleanBundle()).status, "pass");
  },
);

Deno.test(
  "regression: noncompliantBundle TLS-only-policy still PASSES after bucket-no-overbroad-allow added",
  () => {
    assertEquals(checkTLSOnlyPolicy(noncompliantBundle()).status, "pass");
  },
);

// --- statementGrantsOverbroadAllow unit tests ---

Deno.test(
  "statementGrantsOverbroadAllow: true for canonical wide-open Allow",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Allow",
      Principal: "*",
      Action: "s3:*",
      Resource: ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
    };
    assert(statementGrantsOverbroadAllow(stmt, "b"));
  },
);

Deno.test(
  "statementGrantsOverbroadAllow: false when Effect is Deny",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
    };
    assert(!statementGrantsOverbroadAllow(stmt, "b"));
  },
);

Deno.test(
  "statementGrantsOverbroadAllow: false when Principal is a specific account ARN",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Allow",
      Principal: { AWS: "arn:aws:iam::123456789012:root" },
      Action: "s3:*",
      Resource: ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
    };
    assert(!statementGrantsOverbroadAllow(stmt, "b"));
  },
);

Deno.test(
  "statementGrantsOverbroadAllow: false when Condition narrows via aws:SourceArn",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Allow",
      Principal: "*",
      Action: "s3:*",
      Resource: ["arn:aws:s3:::b", "arn:aws:s3:::b/*"],
      Condition: {
        ArnLike: {
          "aws:SourceArn":
            "arn:aws:cloudfront::123456789012:distribution/E1234567",
        },
      },
    };
    assert(!statementGrantsOverbroadAllow(stmt, "b"));
  },
);

// ---------------------------------------------------------------------------
// Rule 6 — bucket-lifecycle-expires-noncurrent-versions
// ---------------------------------------------------------------------------

Deno.test("checkLifecycleExpiresNoncurrent: PASS when rule with NoncurrentDays exists", () => {
  const f = checkLifecycleExpiresNoncurrent(cleanBundle());
  assertEquals(f.id, "bucket-lifecycle-expires-noncurrent-versions");
  assertEquals(f.status, "pass");
});

Deno.test("checkLifecycleExpiresNoncurrent: WARN when no lifecycle rules (noncompliant fixture)", () => {
  assertEquals(
    checkLifecycleExpiresNoncurrent(noncompliantBundle()).status,
    "warn",
  );
});

Deno.test("checkLifecycleExpiresNoncurrent: WARN when rules exist but none Enabled with NoncurrentVersionExpiration", () => {
  const b: BucketBundle = {
    name: "disabled-rule",
    state: {
      BucketName: "disabled-rule",
      LifecycleConfiguration: {
        Rules: [
          {
            Status: "Disabled",
            NoncurrentVersionExpiration: { NoncurrentDays: 90 },
          },
        ],
      },
    } as unknown as BucketBundle["state"],
  };
  assertEquals(checkLifecycleExpiresNoncurrent(b).status, "warn");
});

Deno.test("checkLifecycleExpiresNoncurrent: PASS with NoncurrentVersionExpirationInDays", () => {
  const b: BucketBundle = {
    name: "old-style",
    state: {
      BucketName: "old-style",
      LifecycleConfiguration: {
        Rules: [
          { Status: "Enabled", NoncurrentVersionExpirationInDays: 30 },
        ],
      },
    } as unknown as BucketBundle["state"],
  };
  assertEquals(checkLifecycleExpiresNoncurrent(b).status, "pass");
});

Deno.test("checkLifecycleExpiresNoncurrent: SKIP when state missing", () => {
  assertEquals(checkLifecycleExpiresNoncurrent(noStateBundle()).status, "skip");
});

// ---------------------------------------------------------------------------
// Rule 7 — bucket-server-access-logging
// ---------------------------------------------------------------------------

Deno.test("checkServerAccessLogging: PASS when separate log bucket configured", () => {
  const b: BucketBundle = {
    name: "my-bucket",
    state: {
      BucketName: "my-bucket",
      LoggingConfiguration: {
        DestinationBucketName: "my-logs-bucket",
        LogFilePrefix: "access/",
      },
    } as unknown as BucketBundle["state"],
  };
  const f = checkServerAccessLogging(b);
  assertEquals(f.id, "bucket-server-access-logging");
  assertEquals(f.status, "pass");
});

Deno.test("checkServerAccessLogging: WARN when logging not configured", () => {
  // noncompliant fixture fixture has no LoggingConfiguration
  assertEquals(checkServerAccessLogging(noncompliantBundle()).status, "warn");
});

Deno.test("checkServerAccessLogging: WARN when destination equals source bucket", () => {
  const name = "self-logging";
  const b: BucketBundle = {
    name,
    state: {
      BucketName: name,
      LoggingConfiguration: {
        DestinationBucketName: name,
        LogFilePrefix: "logs/",
      },
    } as unknown as BucketBundle["state"],
  };
  const f = checkServerAccessLogging(b);
  assertEquals(f.status, "warn");
  assert(f.message.includes("same bucket"));
});

Deno.test("checkServerAccessLogging: SKIP when state missing", () => {
  assertEquals(checkServerAccessLogging(noStateBundle()).status, "skip");
});

// ---------------------------------------------------------------------------
// Rule 8 — bucket-tag-inventory
// ---------------------------------------------------------------------------

Deno.test("inventoryTags: PASS when bucket has tags", () => {
  const f = inventoryTags(cleanBundle());
  assertEquals(f.id, "bucket-tag-inventory");
  assertEquals(f.status, "pass");
  assert((f.actual as { tagCount: number }).tagCount >= 2);
});

Deno.test("inventoryTags: PASS when no tags (noncompliant fixture)", () => {
  const f = inventoryTags(noncompliantBundle());
  assertEquals(f.status, "pass");
  assertEquals((f.actual as { tagCount: number }).tagCount, 0);
});

Deno.test("inventoryTags: PASS when Tags field absent", () => {
  const f = inventoryTags(stateOnly({ BucketName: "no-tags" }));
  assertEquals(f.status, "pass");
  assertEquals((f.actual as { tagCount: number }).tagCount, 0);
});

Deno.test("inventoryTags: SKIP when state missing", () => {
  assertEquals(inventoryTags(noStateBundle()).status, "skip");
});

// ---------------------------------------------------------------------------
// Real fixture round-trips — all four production buckets
// ---------------------------------------------------------------------------

const realBuckets: Array<{
  label: string;
  state: unknown;
  policy: unknown;
  expected: {
    versioning: "pass" | "fail" | "skip";
    encryption: "pass" | "fail" | "skip";
    publicAccess: "pass" | "fail" | "skip";
    ownership: "pass" | "fail" | "skip";
    tls: "pass" | "fail" | "skip";
    lifecycle: "pass" | "warn" | "skip";
    logging: "pass" | "warn" | "skip";
    tags: "pass" | "warn" | "skip";
  };
}> = [
  {
    label: "clean-bucket",
    state: cleanBucketState,
    policy: cleanBucketPolicy,
    expected: {
      versioning: "pass",
      encryption: "pass",
      publicAccess: "pass",
      ownership: "pass",
      tls: "pass",
      lifecycle: "pass",
      logging: "warn", // no LoggingConfiguration in real fixture
      tags: "pass",
    },
  },
  {
    label: "noncompliant-bucket",
    state: noncompliantBucketState,
    policy: noncompliantBucketPolicy,
    expected: {
      versioning: "pass",
      encryption: "pass",
      publicAccess: "pass",
      ownership: "fail", // no OwnershipControls
      tls: "pass",
      lifecycle: "warn", // no LifecycleConfiguration
      logging: "warn", // no LoggingConfiguration
      tags: "pass", // tag inventory is informational; no Tags is not a finding
    },
  },
];

for (const fix of realBuckets) {
  Deno.test(`real fixture ${fix.label}: versioning`, () => {
    const b: BucketBundle = {
      name: (fix.state as { BucketName: string }).BucketName,
      state: fix.state as BucketBundle["state"],
      policy: fix.policy as BucketBundle["policy"],
    };
    assertEquals(checkVersioning(b).status, fix.expected.versioning);
  });

  Deno.test(`real fixture ${fix.label}: encryption`, () => {
    const b: BucketBundle = {
      name: (fix.state as { BucketName: string }).BucketName,
      state: fix.state as BucketBundle["state"],
      policy: fix.policy as BucketBundle["policy"],
    };
    assertEquals(checkEncryption(b).status, fix.expected.encryption);
  });

  Deno.test(`real fixture ${fix.label}: publicAccess`, () => {
    const b: BucketBundle = {
      name: (fix.state as { BucketName: string }).BucketName,
      state: fix.state as BucketBundle["state"],
      policy: fix.policy as BucketBundle["policy"],
    };
    assertEquals(checkPublicAccessBlock(b).status, fix.expected.publicAccess);
  });

  Deno.test(`real fixture ${fix.label}: ownership`, () => {
    const b: BucketBundle = {
      name: (fix.state as { BucketName: string }).BucketName,
      state: fix.state as BucketBundle["state"],
      policy: fix.policy as BucketBundle["policy"],
    };
    assertEquals(checkOwnershipEnforced(b).status, fix.expected.ownership);
  });

  Deno.test(`real fixture ${fix.label}: TLS policy`, () => {
    const b: BucketBundle = {
      name: (fix.state as { BucketName: string }).BucketName,
      state: fix.state as BucketBundle["state"],
      policy: fix.policy as BucketBundle["policy"],
    };
    assertEquals(checkTLSOnlyPolicy(b).status, fix.expected.tls);
  });

  Deno.test(`real fixture ${fix.label}: lifecycle`, () => {
    const b: BucketBundle = {
      name: (fix.state as { BucketName: string }).BucketName,
      state: fix.state as BucketBundle["state"],
      policy: fix.policy as BucketBundle["policy"],
    };
    assertEquals(
      checkLifecycleExpiresNoncurrent(b).status,
      fix.expected.lifecycle,
    );
  });

  Deno.test(`real fixture ${fix.label}: logging`, () => {
    const b: BucketBundle = {
      name: (fix.state as { BucketName: string }).BucketName,
      state: fix.state as BucketBundle["state"],
      policy: fix.policy as BucketBundle["policy"],
    };
    assertEquals(checkServerAccessLogging(b).status, fix.expected.logging);
  });

  Deno.test(`real fixture ${fix.label}: tags`, () => {
    const b: BucketBundle = {
      name: (fix.state as { BucketName: string }).BucketName,
      state: fix.state as BucketBundle["state"],
      policy: fix.policy as BucketBundle["policy"],
    };
    assertEquals(inventoryTags(b).status, fix.expected.tags);
  });
}

// ---------------------------------------------------------------------------
// failOn gate
// ---------------------------------------------------------------------------

Deno.test("parseFailOnThreshold defaults to 'error' when unset", () => {
  assertEquals(parseFailOnThreshold(undefined), "error");
});

Deno.test("parseFailOnThreshold accepts all four values, case-insensitive", () => {
  assertEquals(parseFailOnThreshold("none"), "none");
  assertEquals(parseFailOnThreshold(" ERROR "), "error");
  assertEquals(parseFailOnThreshold("Warn"), "warn");
  assertEquals(parseFailOnThreshold("info"), "info");
});

Deno.test("parseFailOnThreshold falls back to 'error' on garbage input", () => {
  assertEquals(parseFailOnThreshold("bogus"), "error");
  assertEquals(parseFailOnThreshold(""), "error");
});

function mkFinding(
  status: "pass" | "fail" | "warn" | "skip",
  severity: "error" | "warn" | "info",
  id = `rule-${status}-${severity}`,
): import("../s3_bucket_audit.ts").Finding {
  return {
    id,
    severity,
    status,
    bucket: "b",
    actual: {},
    expected: {},
    message: "",
    references: [],
  };
}

Deno.test("findGateTrippers — none threshold never trips", () => {
  const findings = [
    mkFinding("fail", "error"),
    mkFinding("fail", "warn"),
    mkFinding("warn", "info"),
  ];
  assertEquals(findGateTrippers(findings, "none").length, 0);
});

Deno.test("findGateTrippers — error threshold only counts error-severity fail/warn", () => {
  const findings = [
    mkFinding("fail", "error"), // counted
    mkFinding("warn", "error"), // counted
    mkFinding("fail", "warn"), // not counted (below threshold)
    mkFinding("warn", "info"), // not counted
    mkFinding("pass", "error"), // not counted (passing)
    mkFinding("skip", "error"), // not counted (skipped)
  ];
  const trippers = findGateTrippers(findings, "error");
  assertEquals(trippers.length, 2);
});

Deno.test("findGateTrippers — warn threshold counts error+warn severity fail/warn", () => {
  const findings = [
    mkFinding("fail", "error"), // counted
    mkFinding("warn", "warn"), // counted
    mkFinding("warn", "info"), // not counted
    mkFinding("pass", "warn"), // not counted
  ];
  assertEquals(findGateTrippers(findings, "warn").length, 2);
});

Deno.test("findGateTrippers — info threshold counts every fail/warn", () => {
  const findings = [
    mkFinding("fail", "error"),
    mkFinding("warn", "warn"),
    mkFinding("warn", "info"),
    mkFinding("pass", "info"), // not counted
    mkFinding("skip", "info"), // not counted
  ];
  assertEquals(findGateTrippers(findings, "info").length, 3);
});

// Regression: a tag-less bucket must not trip the gate under any threshold,
// including failOn=info. Tag inventory is pure metadata; tagCount=0 is the
// sentinel for "no tags", not an audit finding.
Deno.test("inventoryTags: never trips gate, even under failOn=info", () => {
  const findings = [inventoryTags(noncompliantBundle())];
  assertEquals(findGateTrippers(findings, "info"), []);
  assertEquals(findGateTrippers(findings, "warn"), []);
  assertEquals(findGateTrippers(findings, "error"), []);
});

// ---------------------------------------------------------------------------
// Encryption allowlist
// ---------------------------------------------------------------------------

Deno.test("checkEncryption: FAIL when algorithm is an unrecognized string", () => {
  const b = stateOnly({
    BucketName: "typo-enc",
    BucketEncryption: {
      ServerSideEncryptionConfiguration: [
        { ServerSideEncryptionByDefault: { SSEAlgorithm: "AS256" } },
      ],
    },
  });
  const f = checkEncryption(b);
  assertEquals(f.status, "fail");
  // The message must surface the unrecognized algorithm so the operator
  // can see what slipped through.
  assert(f.message.includes("AS256"));
});

// ---------------------------------------------------------------------------
// TLS-only policy: Action: "*" (everyone-actions wildcard)
// ---------------------------------------------------------------------------

Deno.test("checkTLSOnlyPolicy: PASS when Action is the all-services wildcard '*'", () => {
  // A Deny with Action: "*" is broader than Action: "s3:*" and just as
  // valid for blocking insecure transport on S3 specifically.
  const b = statePolicy(
    { BucketName: "star-action" },
    {
      Bucket: "star-action",
      PolicyDocument: {
        Statement: [
          {
            Effect: "Deny",
            Principal: "*",
            Action: "*",
            Resource: [
              "arn:aws:s3:::star-action",
              "arn:aws:s3:::star-action/*",
            ],
            Condition: { Bool: { "aws:SecureTransport": "false" } },
          },
        ],
      },
    },
  );
  assertEquals(checkTLSOnlyPolicy(b).status, "pass");
});

// ---------------------------------------------------------------------------
// TLS-only policy: Principal { AWS: ["*"] } array form
// ---------------------------------------------------------------------------

Deno.test("checkTLSOnlyPolicy: PASS when Principal is { AWS: ['*'] } (array wildcard)", () => {
  // IAM allows {AWS: ["*"]} as an array form of the wildcard. Equivalent
  // to {AWS: "*"} and to "*".
  const b = statePolicy(
    { BucketName: "array-wildcard" },
    {
      Bucket: "array-wildcard",
      PolicyDocument: {
        Statement: [
          {
            Effect: "Deny",
            Principal: { AWS: ["*"] },
            Action: "s3:*",
            Resource: [
              "arn:aws:s3:::array-wildcard",
              "arn:aws:s3:::array-wildcard/*",
            ],
            Condition: { Bool: { "aws:SecureTransport": "false" } },
          },
        ],
      },
    },
  );
  assertEquals(checkTLSOnlyPolicy(b).status, "pass");
});

// ---------------------------------------------------------------------------
// TLS-only policy: case-insensitive aws:SecureTransport condition key
// ---------------------------------------------------------------------------

Deno.test(
  "checkTLSOnlyPolicy: PASS when Condition operator is BoolIfExists",
  () => {
    // BoolIfExists is strictly stronger than Bool (denies the request when
    // the key is absent too) and is the form AWS docs and most Terraform
    // modules use. Treating it as PASS prevents false-FAILs on widespread,
    // valid TLS-enforcing policies.
    const b = statePolicy(
      { BucketName: "bool-if-exists-bucket" },
      {
        Bucket: "bool-if-exists-bucket",
        PolicyDocument: {
          Statement: [
            {
              Effect: "Deny",
              Principal: "*",
              Action: "s3:*",
              Resource: [
                "arn:aws:s3:::bool-if-exists-bucket",
                "arn:aws:s3:::bool-if-exists-bucket/*",
              ],
              Condition: { BoolIfExists: { "aws:SecureTransport": "false" } },
            },
          ],
        },
      },
    );
    assertEquals(checkTLSOnlyPolicy(b).status, "pass");
  },
);

Deno.test(
  "statementDeniesInsecureTransport: true for BoolIfExists operator",
  () => {
    const stmt: PolicyStatement = {
      Effect: "Deny",
      Principal: "*",
      Action: "s3:*",
      Resource: [
        "arn:aws:s3:::b",
        "arn:aws:s3:::b/*",
      ],
      Condition: { BoolIfExists: { "aws:SecureTransport": "false" } },
    };
    assert(statementDeniesInsecureTransport(stmt, "b"));
  },
);

Deno.test("checkTLSOnlyPolicy: PASS when condition key is lowercase 'aws:securetransport'", () => {
  // IAM condition keys are case-insensitive per AWS docs. The operator
  // (`Bool`) is case-sensitive but the key inside it is not.
  const b = statePolicy(
    { BucketName: "lowercase-key" },
    {
      Bucket: "lowercase-key",
      PolicyDocument: {
        Statement: [
          {
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [
              "arn:aws:s3:::lowercase-key",
              "arn:aws:s3:::lowercase-key/*",
            ],
            Condition: { Bool: { "aws:securetransport": "false" } },
          },
        ],
      },
    },
  );
  assertEquals(checkTLSOnlyPolicy(b).status, "pass");
});

// ---------------------------------------------------------------------------
// TLS-only policy: non-default AWS partitions (China, GovCloud)
// ---------------------------------------------------------------------------

Deno.test("checkTLSOnlyPolicy: PASS for China partition (arn:aws-cn:s3:::...)", () => {
  const b = statePolicy(
    { BucketName: "china-bucket" },
    {
      Bucket: "china-bucket",
      PolicyDocument: {
        Statement: [
          {
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [
              "arn:aws-cn:s3:::china-bucket",
              "arn:aws-cn:s3:::china-bucket/*",
            ],
            Condition: { Bool: { "aws:SecureTransport": "false" } },
          },
        ],
      },
    },
  );
  assertEquals(checkTLSOnlyPolicy(b).status, "pass");
});

Deno.test("checkTLSOnlyPolicy: PASS for GovCloud partition (arn:aws-us-gov:s3:::...)", () => {
  const b = statePolicy(
    { BucketName: "gov-bucket" },
    {
      Bucket: "gov-bucket",
      PolicyDocument: {
        Statement: [
          {
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [
              "arn:aws-us-gov:s3:::gov-bucket",
              "arn:aws-us-gov:s3:::gov-bucket/*",
            ],
            Condition: { Bool: { "aws:SecureTransport": "false" } },
          },
        ],
      },
    },
  );
  assertEquals(checkTLSOnlyPolicy(b).status, "pass");
});

// ---------------------------------------------------------------------------
// collectBundles recovery paths (via report.execute integration)
//
// collectBundles is internal; drive it through report.execute() with a
// faked context whose dataRepository.getContent is backed by an in-memory
// map. When an upstream step succeeds but its data is unparseable or
// schema-mismatched, the bucket name must still surface via
// methodArgs.identifier so the bucket appears in the report rather than
// silently disappearing.
// ---------------------------------------------------------------------------

interface FakeStepExecution {
  jobName: string;
  stepName: string;
  modelType: string;
  modelId: string;
  status: "succeeded" | "failed";
  // deno-lint-ignore no-explicit-any
  methodArgs?: Record<string, any>;
  dataHandles?: Array<{ name: string; version: number }>;
}

/** Pre-seeded data artifact: [modelType, modelId, dataName, version, content]. */
type DataEntry = [string, string, string, number, string];

function makeDataRepository(entries: DataEntry[]) {
  const enc = new TextEncoder();
  const key = (t: string, i: string, n: string, v: number) =>
    `${t}|${i}|${n}|${v}`;
  const store = new Map(
    entries.map(([t, i, n, v, c]) => [key(t, i, n, v), enc.encode(c)]),
  );
  return {
    getContent: (
      type: string,
      modelId: string,
      dataName: string,
      version: number,
    ): Promise<Uint8Array | null> =>
      Promise.resolve(store.get(key(type, modelId, dataName, version)) ?? null),
  };
}

function silentLogger() {
  return {
    info: () => {},
    debug: () => {},
    warn: () => {},
    error: () => {},
  };
}

async function runReport(
  dataEntries: DataEntry[],
  stepExecutions: FakeStepExecution[],
) {
  const ctx = {
    workflowName: "test-workflow",
    stepExecutions,
    logger: silentLogger(),
    dataRepository: makeDataRepository(dataEntries),
  };
  return await report.execute(ctx);
}

Deno.test("collectBundles: failed step with no data surfaces via methodArgs.identifier", async () => {
  const out = await runReport([], [
    {
      jobName: "lookup",
      stepName: "bucket-state-x",
      modelType: "@swamp/aws/s3/bucket",
      modelId: "audit-bucket-x",
      status: "failed",
      methodArgs: { identifier: "x" },
      dataHandles: [],
    },
  ]);
  const j = out.json;
  assertEquals(j.summary.buckets, 1);
  assertEquals(j.buckets[0].name, "x");
  // Every state-dependent rule should emit `skip` with the stateError reason.
  const versioning = j.findings.find((f) =>
    f.id === "bucket-versioning-enabled"
  );
  assertExists(versioning);
  assertEquals(versioning.status, "skip");
  assertEquals(versioning.message, "bucket lookup step failed");
});

Deno.test("collectBundles: succeeded step with unparseable JSON surfaces with parse-error reason", async () => {
  const out = await runReport(
    [[
      "@swamp/aws/s3/bucket",
      "audit-bucket-y",
      "default",
      1,
      "this is not valid json {{{",
    ]],
    [
      {
        jobName: "lookup",
        stepName: "bucket-state-y",
        modelType: "@swamp/aws/s3/bucket",
        modelId: "audit-bucket-y",
        status: "succeeded",
        methodArgs: { identifier: "y" },
        dataHandles: [{ name: "default", version: 1 }],
      },
    ],
  );
  const j = out.json;
  assertEquals(j.summary.buckets, 1);
  assertEquals(j.buckets[0].name, "y");
  const versioning = j.findings.find((f) =>
    f.id === "bucket-versioning-enabled"
  );
  assertExists(versioning);
  assertEquals(versioning.status, "skip");
  assert(versioning.message.includes("data file"));
});

Deno.test("collectBundles: succeeded step with schema-mismatched data surfaces via fallback identifier", async () => {
  // Valid JSON but missing the required BucketName field. The bucket must
  // still surface via methodArgs.identifier rather than disappearing.
  const out = await runReport(
    [[
      "@swamp/aws/s3/bucket",
      "audit-bucket-z",
      "default",
      1,
      JSON.stringify({ NotBucketName: "wrong-shape" }),
    ]],
    [
      {
        jobName: "lookup",
        stepName: "bucket-state-z",
        modelType: "@swamp/aws/s3/bucket",
        modelId: "audit-bucket-z",
        status: "succeeded",
        methodArgs: { identifier: "z" },
        dataHandles: [{ name: "default", version: 1 }],
      },
    ],
  );
  const j = out.json;
  assertEquals(j.summary.buckets, 1);
  assertEquals(j.buckets[0].name, "z");
  const versioning = j.findings.find((f) =>
    f.id === "bucket-versioning-enabled"
  );
  assertExists(versioning);
  assertEquals(versioning.status, "skip");
  assert(versioning.message.includes("did not match expected shape"));
});

Deno.test(
  "report.execute does not throw on unparseable PolicyDocument; emits skip findings for TLS rules",
  async () => {
    // Locks in the post-swamp#1394 skip-not-throw policy: a malformed
    // PolicyDocument must surface as per-rule skip findings, not collapse
    // into swamp's generic error fallback artifact.
    const stateJson = JSON.stringify({ BucketName: "bad-policy-bucket" });
    const policyJson = JSON.stringify({
      Bucket: "bad-policy-bucket",
      PolicyDocument: "NOT VALID JSON {{{",
    });
    const out = await runReport(
      [
        ["@swamp/aws/s3/bucket", "audit-state", "default", 1, stateJson],
        [
          "@swamp/aws/s3/bucket-policy",
          "audit-policy",
          "default",
          1,
          policyJson,
        ],
      ],
      [
        {
          jobName: "lookup",
          stepName: "bucket-state",
          modelType: "@swamp/aws/s3/bucket",
          modelId: "audit-state",
          status: "succeeded",
          methodArgs: { identifier: "bad-policy-bucket" },
          dataHandles: [{ name: "default", version: 1 }],
        },
        {
          jobName: "lookup",
          stepName: "bucket-policy",
          modelType: "@swamp/aws/s3/bucket-policy",
          modelId: "audit-policy",
          status: "succeeded",
          methodArgs: { identifier: "bad-policy-bucket" },
          dataHandles: [{ name: "default", version: 1 }],
        },
      ],
    );
    const j = out.json;
    assertEquals(j.summary.buckets, 1);
    assertEquals(j.buckets[0].name, "bad-policy-bucket");
    const tlsOnly = j.findings.find((f) => f.id === "bucket-tls-only-policy");
    const tlsMinVersion = j.findings.find((f) =>
      f.id === "bucket-tls-min-version-1.2"
    );
    assertExists(tlsOnly);
    assertExists(tlsMinVersion);
    assertEquals(tlsOnly.status, "skip");
    assertEquals(tlsMinVersion.status, "skip");
  },
);

Deno.test("checkTLSOnlyPolicy: bucket name with dots is matched literally (regex escape)", () => {
  // S3 bucket names allow dots (`my.bucket.example`). The regex must
  // treat them as literal characters, not "any char". Wrong-bucket ARNs
  // must still fail.
  const matching = statePolicy(
    { BucketName: "my.bucket.example" },
    {
      Bucket: "my.bucket.example",
      PolicyDocument: {
        Statement: [
          {
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [
              "arn:aws:s3:::my.bucket.example",
              "arn:aws:s3:::my.bucket.example/*",
            ],
            Condition: { Bool: { "aws:SecureTransport": "false" } },
          },
        ],
      },
    },
  );
  assertEquals(checkTLSOnlyPolicy(matching).status, "pass");

  // A different-bucket ARN that matches via greedy-dot would be
  // `myXbucketXexample` — verify that doesn't pass.
  const wrongBucket = statePolicy(
    { BucketName: "my.bucket.example" },
    {
      Bucket: "my.bucket.example",
      PolicyDocument: {
        Statement: [
          {
            Effect: "Deny",
            Principal: "*",
            Action: "s3:*",
            Resource: [
              "arn:aws:s3:::myXbucketXexample",
              "arn:aws:s3:::myXbucketXexample/*",
            ],
            Condition: { Bool: { "aws:SecureTransport": "false" } },
          },
        ],
      },
    },
  );
  assertEquals(checkTLSOnlyPolicy(wrongBucket).status, "fail");
});
