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
  checkOwnershipEnforced,
  checkPublicAccessBlock,
  checkServerAccessLogging,
  checkTLSOnlyPolicy,
  checkVersioning,
  findGateTrippers,
  inventoryTags,
  parseFailOnThreshold,
  type PolicyStatement,
  report,
  statementDeniesInsecureTransport,
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
  const versioning = j.findings.find((f) => f.id === "bucket-versioning-enabled");
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
  const versioning = j.findings.find((f) => f.id === "bucket-versioning-enabled");
  assertExists(versioning);
  assertEquals(versioning.status, "skip");
  assert(versioning.message.includes("did not match expected shape"));
});

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
