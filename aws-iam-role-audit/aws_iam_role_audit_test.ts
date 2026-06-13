/**
 * Colocated publication-sanity tests for `@jentz/aws-iam-role-audit`.
 *
 * The full unit and smoke suites live under `tests/`; this sibling file keeps
 * the extension's entrypoint visibly paired with a test entrypoint for publish
 * review tooling without duplicating that larger suite. It also pins the two
 * sanctioned fail-closed surfaces — no roles configured, and unset/empty
 * `stackLookupRegions` — to the entrypoint.
 */

import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import { effectiveRoles, model } from "./aws_iam_role_audit.ts";

function manifestScalar(manifest: string, key: string): string {
  const match = manifest.match(
    new RegExp(`^${key}:\\s*["']?([^"'\\n]+)["']?$`, "m"),
  );
  if (match === null) {
    throw new Error(`manifest.yaml is missing scalar key ${key}`);
  }
  return match[1].trim();
}

Deno.test("model metadata: entrypoint stays in sync with manifest", async () => {
  const manifest = await Deno.readTextFile(
    new URL("./manifest.yaml", import.meta.url),
  );

  assertEquals(model.type, manifestScalar(manifest, "name"));
  assertEquals(model.version, manifestScalar(manifest, "version"));
  assertEquals(Object.keys(model.resources).sort(), ["role", "scan_error"]);
  // Read-only surface: exactly one method, no mutating / remediation method.
  assertEquals(Object.keys(model.methods), ["audit"]);
});

Deno.test("model metadata: upgrade chain ends at model.version", () => {
  // swamp registry/host loading rejects a model whose final upgrades entry
  // toVersion drifts from model.version. Guard the invariant locally so an
  // SDK-bump batch that advances model.version without appending the matching
  // no-op upgrade fails here instead of at publish time.
  const upgrades = model.upgrades;
  assertEquals(
    Array.isArray(upgrades),
    true,
    "model.upgrades must be an array",
  );
  assertEquals(
    upgrades.length > 0,
    true,
    "expected at least one upgrade entry to assert the invariant on",
  );
  assertEquals(
    upgrades.at(-1)?.toVersion,
    model.version,
    "final upgrades entry toVersion must equal model.version",
  );
});

Deno.test("deviation 1: effectiveRoles throws when no roles are configured", () => {
  assertThrows(
    () => effectiveRoles({ roles: [] }),
    Error,
    "No roles configured",
  );
});

Deno.test("deviation 2: audit throws on empty stackLookupRegions before any AWS call", async () => {
  // A context whose facade would explode the instant it is touched: the throw
  // must precede any AWS construction/call, so this method body never reaches
  // an account.
  const tripwire = {
    globalArgs: {
      roles: [{ roleName: "DemoRole" }],
      profiles: ["acct-readonly"],
      stackLookupRegions: [],
    },
    logger: { info() {}, debug() {}, warn() {}, error() {} },
    writeResource() {
      throw new Error("writeResource must not be reached");
    },
    get signal(): AbortSignal {
      throw new Error("signal must not be reached");
    },
  };

  // `execute` validates before any `await`, so the throw is synchronous;
  // funnel it through a resolved promise so the assertion holds for either
  // a synchronous throw or a rejected promise.
  await assertRejects(
    () =>
      Promise.resolve().then(() => model.methods.audit.execute({}, tripwire)),
    Error,
    "stackLookupRegions is required",
  );
});

Deno.test("deviation 2: audit throws when stackLookupRegions is unset", async () => {
  const tripwire = {
    globalArgs: {
      roles: [{ roleName: "DemoRole" }],
      profiles: ["acct-readonly"],
      // stackLookupRegions intentionally omitted.
    },
    logger: { info() {}, debug() {}, warn() {}, error() {} },
    writeResource() {
      throw new Error("writeResource must not be reached");
    },
    get signal(): AbortSignal {
      throw new Error("signal must not be reached");
    },
  };

  await assertRejects(
    () =>
      Promise.resolve().then(() => model.methods.audit.execute({}, tripwire)),
    Error,
    "stackLookupRegions is required",
  );
});
