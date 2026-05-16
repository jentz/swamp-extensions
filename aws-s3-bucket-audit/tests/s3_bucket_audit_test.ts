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

function cleanBundle(): BucketBundle {
  return {
    name: cleanBucketState.BucketName,
    state: cleanBucketState as unknown as BucketBundle["state"],
    policy: cleanBucketPolicy as unknown as BucketBundle["policy"],
  };
}

function noncompliantBundle(): BucketBundle {
  return {
    name: noncompliantBucketState.BucketName,
    state: noncompliantBucketState as unknown as BucketBundle["state"],
    policy: noncompliantBucketPolicy as unknown as BucketBundle["policy"],
  };
}

function noStateBundle(): BucketBundle {
  return { name: "no-state-bucket" };
}

function noPolicyBundle(): BucketBundle {
  return {
    name: cleanBucketState.BucketName,
    state: cleanBucketState as unknown as BucketBundle["state"],
    // no policy
  };
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

Deno.test("checkTLSOnlyPolicy: FAIL when PolicyDocument absent", () => {
  assertEquals(checkTLSOnlyPolicy(noPolicyBundle()).status, "fail");
});

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

Deno.test("inventoryTags: WARN when no tags (noncompliant fixture)", () => {
  assertEquals(inventoryTags(noncompliantBundle()).status, "warn");
});

Deno.test("inventoryTags: WARN when Tags field absent", () => {
  const b: BucketBundle = {
    name: "no-tags",
    state: { BucketName: "no-tags" } as unknown as BucketBundle["state"],
  };
  assertEquals(inventoryTags(b).status, "warn");
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
      tags: "warn", // no Tags
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
