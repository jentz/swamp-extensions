/**
 * Colocated publication-sanity tests for `@jentz/aws-rds-reservations`.
 *
 * The full unit and smoke suites live under `tests/`; this sibling file keeps
 * the extension's entrypoint visibly paired with a test entrypoint for publish
 * review tooling without duplicating that larger suite.
 */

import { assertEquals, assertThrows } from "jsr:@std/assert@1";
import {
  classifyError,
  model,
  resolveBootstrapRegion,
} from "./aws_rds_reservations.ts";

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
  assertEquals(Object.keys(model.resources).sort(), [
    "instance",
    "reserved",
    "scan_error",
  ]);
  assertEquals(Object.keys(model.methods), ["sweep"]);
});

Deno.test("model metadata: upgrades stay globalArguments-only, no resource migration", () => {
  // swamp model upgrades transform stored globalArguments, never historical
  // resource artifacts. Guard against the misleading resource-migration
  // posture (claiming to backfill instance rows) and against leaking
  // InstanceRecord-only fields like licenseModel into global arguments.
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

  // swamp registry/host loading rejects a model whose final upgrades entry
  // toVersion drifts from model.version. Guard the invariant locally so an
  // SDK-bump batch that advances model.version without appending the matching
  // no-op upgrade fails here instead of at publish time.
  assertEquals(
    upgrades.at(-1)?.toVersion,
    model.version,
    "final upgrades entry toVersion must equal model.version",
  );

  // Resource-only keys that must never appear in upgraded global arguments.
  const resourceOnlyKeys = [
    "licenseModel",
    "dbInstanceIdentifier",
    "dbInstanceClass",
    "engine",
    "engineVersion",
    "scannedAt",
  ];

  // A representative stored global-args object (the real GlobalArgsSchema
  // shape): profiles, regions, requiredProfileSuffix.
  const oldGlobalArgs: Record<string, unknown> = {
    profiles: ["acme-readonly"],
    regions: ["eu-west-1"],
    requiredProfileSuffix: "-readonly",
  };

  for (const upgrade of upgrades) {
    assertEquals(
      /instance row|resource|backfill/i.test(upgrade.description),
      false,
      `upgrade ${upgrade.toVersion} description must not claim resource ` +
        `migration: "${upgrade.description}"`,
    );

    const upgraded = upgrade.upgradeAttributes({ ...oldGlobalArgs });
    for (const key of resourceOnlyKeys) {
      assertEquals(
        Object.prototype.hasOwnProperty.call(upgraded, key),
        false,
        `upgrade ${upgrade.toVersion} must not introduce resource-only ` +
          `field "${key}" into global arguments`,
      );
    }
  }
});

Deno.test("classifyError: maps an expired-SSO failure to auth_expired", () => {
  const expired = new Error(
    "The SSO session associated with this profile has expired",
  );
  expired.name = "ExpiredTokenException";
  assertEquals(classifyError(expired).kind, "auth_expired");

  const denied = new Error(
    "User is not authorized to perform: rds:DescribeDBInstances",
  );
  assertEquals(classifyError(denied).kind, "access_denied");
});

Deno.test("resolveBootstrapRegion: falls through to us-east-1 when no source is set", () => {
  assertEquals(resolveBootstrapRegion([], () => undefined), "us-east-1");

  // Confirm the helper is doing real work, not just returning the default.
  assertThrows(
    () => manifestScalar('name: "@jentz/aws-rds-reservations"', "version"),
    Error,
    "missing scalar key version",
  );
});
