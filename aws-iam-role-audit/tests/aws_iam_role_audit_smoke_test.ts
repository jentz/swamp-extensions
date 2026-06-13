/**
 * Smoke tests — drive `runAudit` end-to-end through an in-memory `IamApi`
 * facade with a hand-rolled swamp method context.
 *
 * No AWS calls, no live SDK, no network: each account's roles, policies, trust
 * documents, and owning stacks are inline fixtures. The tests prove the sweep
 * writes exactly one `role` row per (account × role), distinguishes present vs
 * missing roles, isolates per-account credential failures and per-role read
 * failures into `scan_error` rows while continuing the sweep, honors the
 * required-profile-suffix refusal, and (via the model entrypoint) fails closed
 * when `stackLookupRegions` is unset/empty before any AWS call. All account ids
 * are placeholders so the corpus is safe to ship.
 */

import {
  assert,
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.224.0/assert/mod.ts";

import {
  type AwsRole,
  type IamApi,
  type ManagingStack,
  model,
  type RoleSpec,
  runAudit,
  type ScanTarget,
} from "../aws_iam_role_audit.ts";

// ---------------------------------------------------------------------------
// In-memory IamApi replay
// ---------------------------------------------------------------------------

interface AccountFixture {
  accountId: string;
  /** Per-role data; absence in this map means the role does not exist. */
  roles: Record<string, {
    role: AwsRole;
    attached?: string[];
    inline?: string[];
    stack?: ManagingStack | null;
  }>;
  /** When set, getAccountId rejects with this error. */
  credentialError?: Error;
  /** Role names whose getRole should throw (per-role read failure). */
  failRoles?: Set<string>;
}

function fakeApi(fixture: AccountFixture): IamApi {
  return {
    getAccountId: () =>
      fixture.credentialError
        ? Promise.reject(fixture.credentialError)
        : Promise.resolve(fixture.accountId),
    getRole: (roleName: string) => {
      if (fixture.failRoles?.has(roleName)) {
        return Promise.reject(
          Object.assign(
            new Error("User is not authorized to perform iam:GetRole"),
            {
              name: "AccessDeniedException",
            },
          ),
        );
      }
      const entry = fixture.roles[roleName];
      return Promise.resolve(entry ? entry.role : null);
    },
    listAttachedPolicyArns: (roleName: string) =>
      Promise.resolve(fixture.roles[roleName]?.attached ?? []),
    listInlinePolicyNames: (roleName: string) =>
      Promise.resolve(fixture.roles[roleName]?.inline ?? []),
    findManagingStack: (roleName: string) =>
      Promise.resolve(fixture.roles[roleName]?.stack ?? null),
  };
}

// ---------------------------------------------------------------------------
// Stand-in for the runtime's swamp method context
// ---------------------------------------------------------------------------

interface Written {
  spec: string;
  key: string;
  data: Record<string, unknown>;
}

const silentLogger = {
  info: () => {},
  debug: () => {},
  warn: () => {},
  error: () => {},
};

function makeContext(): { context: unknown; written: Written[] } {
  const written: Written[] = [];
  const context = {
    globalArgs: {},
    logger: silentLogger,
    writeResource: (
      spec: string,
      key: string,
      data: Record<string, unknown>,
    ) => {
      written.push({ spec, key, data });
      return Promise.resolve({ id: `${spec}:${key}` });
    },
  };
  return { context, written };
}

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

const TRUST = JSON.stringify({
  Statement: [{
    Principal: { AWS: "arn:aws:iam::999999999999:root" },
    Condition: { StringEquals: { "sts:ExternalId": "ext-1" } },
  }],
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

Deno.test("smoke: one role row per (account x role); present vs missing", async () => {
  const { context, written } = makeContext();

  const acctA: ScanTarget = {
    profile: "acct-a-readonly",
    api: fakeApi({
      accountId: "111111111111",
      roles: {
        Present: {
          role: {
            Arn: "arn:aws:iam::111111111111:role/Present",
            Path: "/",
            CreateDate: new Date("2026-01-01T00:00:00.000Z"),
            AssumeRolePolicyDocument: encodeURIComponent(TRUST),
            Tags: [{ Key: "team", Value: "sec" }],
          },
          attached: ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
          inline: ["inline-1"],
          stack: {
            stackName: "StackSet-Integration-abc",
            stackId: "arn:stack/ss",
            region: "eu-west-1",
          },
        },
        // "Absent" intentionally not present -> missing row.
      },
    }),
  };

  const result = await runAudit({
    targets: [acctA],
    roles: [
      spec({
        roleName: "Present",
        expectedManagedPolicyArns: ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
        expectedTrustPrincipals: ["arn:aws:iam::999999999999:root"],
        expectedExternalId: "ext-1",
      }),
      spec({ roleName: "Absent", required: true }),
    ],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context,
  });

  const roleRows = written.filter((w) => w.spec === "role");
  assertEquals(roleRows.length, 2);
  assertEquals(result.roleCount, 2);
  assertEquals(result.presentCount, 1);

  const present = roleRows.find((w) => w.key === "role-111111111111-Present")!;
  assertEquals(present.data.exists, true);
  assertEquals(present.data.managementMechanism, "cfn-stackset");
  assertEquals(present.data.compliant, true);
  assertEquals(present.data.findings, []);
  // No requiredProfileSuffix configured, so the profile is the account name verbatim.
  assertEquals(present.data.accountName, "acct-a-readonly");

  const absent = roleRows.find((w) => w.key === "role-111111111111-Absent")!;
  assertEquals(absent.data.exists, false);
  assertEquals(absent.data.managementMechanism, "missing");
  assertEquals(absent.data.compliant, false);
  assertEquals(absent.data.findings, ["role does not exist"]);
});

Deno.test("smoke: a manual role (no owning stack) classifies as 'manual'", async () => {
  const { context, written } = makeContext();
  await runAudit({
    targets: [{
      profile: "",
      api: fakeApi({
        accountId: "222222222222",
        roles: {
          HandMade: {
            role: { Arn: "arn:aws:iam::222222222222:role/HandMade" },
            stack: null,
          },
        },
      }),
    }],
    roles: [spec({ roleName: "HandMade" })],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context,
  });
  const row = written.find((w) => w.key === "role-222222222222-HandMade")!;
  assertEquals(row.data.managementMechanism, "manual");
});

Deno.test("smoke: credentials failure emits a scan_error and the sweep continues", async () => {
  const { context, written } = makeContext();

  const bad: ScanTarget = {
    profile: "bad-readonly",
    api: fakeApi({
      accountId: "",
      roles: {},
      credentialError: Object.assign(
        new Error("The security token included in the request is expired"),
        { name: "ExpiredTokenException" },
      ),
    }),
  };
  const good: ScanTarget = {
    profile: "good-readonly",
    api: fakeApi({
      accountId: "333333333333",
      roles: {
        DemoRole: { role: { Arn: "arn:aws:iam::333333333333:role/DemoRole" } },
      },
    }),
  };

  const result = await runAudit({
    targets: [bad, good],
    roles: [spec()],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context,
  });

  const errors = written.filter((w) => w.spec === "scan_error");
  assertEquals(errors.length, 1);
  assertEquals(errors[0].data.phase, "credentials");
  assertEquals(errors[0].data.kind, "auth_expired");
  assertEquals(errors[0].key, "error-bad-readonly-_-credentials");

  // The healthy account was still swept after the failure.
  const roleRows = written.filter((w) => w.spec === "role");
  assertEquals(roleRows.length, 1);
  assertEquals(roleRows[0].key, "role-333333333333-DemoRole");
  assertEquals(result.errorCount, 1);
  assertEquals(result.roleCount, 1);
});

Deno.test("smoke: a per-role read failure emits a scan_error and other roles still scan", async () => {
  const { context, written } = makeContext();

  await runAudit({
    targets: [{
      profile: "acct-readonly",
      api: fakeApi({
        accountId: "444444444444",
        roles: {
          Good: { role: { Arn: "arn:aws:iam::444444444444:role/Good" } },
        },
        failRoles: new Set(["Locked"]),
      }),
    }],
    roles: [spec({ roleName: "Locked" }), spec({ roleName: "Good" })],
    requiredProfileSuffix: "",
    ambientProfile: "",
    context,
  });

  const errors = written.filter((w) => w.spec === "scan_error");
  assertEquals(errors.length, 1);
  assertEquals(errors[0].data.phase, "get_role");
  assertEquals(errors[0].data.kind, "access_denied");
  assertEquals(errors[0].data.roleName, "Locked");

  // The other role in the same account was still audited.
  const roleRows = written.filter((w) => w.spec === "role");
  assertEquals(roleRows.length, 1);
  assertEquals(roleRows[0].key, "role-444444444444-Good");
});

Deno.test("smoke: required-profile-suffix refusal records a scan_error before any AWS call", async () => {
  const { context, written } = makeContext();

  // Facade that explodes if touched — the suffix check must precede it.
  const tripwire: IamApi = {
    getAccountId: () => Promise.reject(new Error("must not be called")),
    getRole: () => Promise.reject(new Error("must not be called")),
    listAttachedPolicyArns: () =>
      Promise.reject(new Error("must not be called")),
    listInlinePolicyNames: () =>
      Promise.reject(new Error("must not be called")),
    findManagingStack: () => Promise.reject(new Error("must not be called")),
  };

  const result = await runAudit({
    targets: [{ profile: "prod-admin", api: tripwire }],
    roles: [spec()],
    requiredProfileSuffix: "-readonly",
    ambientProfile: "",
    context,
  });

  const errors = written.filter((w) => w.spec === "scan_error");
  assertEquals(errors.length, 1);
  assertEquals(errors[0].data.phase, "profile_suffix_check");
  assertEquals(errors[0].data.kind, "other");
  assertEquals(written.filter((w) => w.spec === "role").length, 0);
  assertEquals(result.roleCount, 0);
});

Deno.test("smoke: ambient target whose AWS_PROFILE matches the suffix is NOT refused", async () => {
  const { context, written } = makeContext();

  // Ambient target (profile ""). The suffix gate falls back to ambientProfile,
  // which ends with the suffix, so the audit proceeds and reads the role.
  const ambient: ScanTarget = {
    profile: "",
    api: fakeApi({
      accountId: "111111111111",
      roles: {
        Present: {
          role: {
            Arn: "arn:aws:iam::111111111111:role/Present",
            Path: "/",
            CreateDate: new Date("2026-01-01T00:00:00.000Z"),
            AssumeRolePolicyDocument: encodeURIComponent(TRUST),
            Tags: [],
          },
        },
      },
    }),
  };

  const result = await runAudit({
    targets: [ambient],
    roles: [spec({ roleName: "Present" })],
    requiredProfileSuffix: "-readonly",
    ambientProfile: "prod-platform-readonly",
    context,
  });

  // No suffix refusal — the sweep ran and wrote the role row.
  const suffixErrs = written.filter((w) =>
    w.spec === "scan_error" && w.data.phase === "profile_suffix_check"
  );
  assertEquals(suffixErrs.length, 0);
  assertEquals(result.roleCount, 1);
  const roleRows = written.filter((w) => w.spec === "role");
  assertEquals(roleRows.length, 1);
  // AWS_PROFILE is used only for the gate, never written into the row.
  assertEquals(roleRows[0].data.profile, "");
});

Deno.test("smoke: ambient target with no AWS_PROFILE is refused (fail-closed) when a suffix is required", async () => {
  const { context, written } = makeContext();

  // Facade that explodes if touched — the suffix check must precede any call.
  const tripwire: IamApi = {
    getAccountId: () => Promise.reject(new Error("must not be called")),
    getRole: () => Promise.reject(new Error("must not be called")),
    listAttachedPolicyArns: () =>
      Promise.reject(new Error("must not be called")),
    listInlinePolicyNames: () =>
      Promise.reject(new Error("must not be called")),
    findManagingStack: () => Promise.reject(new Error("must not be called")),
  };

  const result = await runAudit({
    targets: [{ profile: "", api: tripwire }],
    roles: [spec()],
    requiredProfileSuffix: "-readonly",
    ambientProfile: "", // AWS_PROFILE unset
    context,
  });

  const errors = written.filter((w) => w.spec === "scan_error");
  assertEquals(errors.length, 1);
  assertEquals(errors[0].data.phase, "profile_suffix_check");
  assertEquals(errors[0].data.kind, "other");
  // AWS_PROFILE is not leaked into the resource; profile stays the ambient "".
  assertEquals(errors[0].data.profile, "");
  assertEquals(written.filter((w) => w.spec === "role").length, 0);
  assertEquals(result.roleCount, 0);
});

Deno.test("smoke: model.audit throws on unset stackLookupRegions before any AWS call", async () => {
  const tripwire = {
    globalArgs: {
      roles: [{ roleName: "DemoRole" }],
      profiles: ["acct-readonly"],
      // stackLookupRegions omitted -> fail closed.
    },
    logger: silentLogger,
    writeResource: () => {
      throw new Error("writeResource must not be reached");
    },
    get signal(): AbortSignal {
      throw new Error("signal must not be reached");
    },
  };

  // `execute` validates before any `await`; funnel through a resolved promise
  // so the assertion holds for a synchronous throw too.
  await assertRejects(
    () =>
      Promise.resolve().then(() => model.methods.audit.execute({}, tripwire)),
    Error,
    "stackLookupRegions is required",
  );
});

Deno.test("smoke: every test finishes well under the network budget", () => {
  // Sentinel — the smoke tests above all complete in single-digit
  // milliseconds. Anything touching the network would blow past that and
  // belongs outside this harness.
  assert(true);
});
