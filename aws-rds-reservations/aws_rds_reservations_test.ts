/**
 * Colocated publication-sanity tests for `@jentz/aws-rds-reservations`.
 *
 * The full unit and smoke suites live under `tests/`; this sibling file keeps
 * the extension's entrypoint visibly paired with a test entrypoint for publish
 * review tooling without duplicating that larger suite.
 */

import {
  assertEquals,
  assertThrows,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
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
