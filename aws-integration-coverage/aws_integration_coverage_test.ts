/**
 * Colocated publication-sanity tests for `@jentz/aws-integration-coverage`.
 *
 * The full unit and smoke suites live under `tests/`; this sibling file keeps
 * the combined package's entrypoints (the model AND the report) visibly paired
 * with a test entrypoint for publish review tooling without duplicating that
 * larger suite.
 */

import { assertEquals } from "jsr:@std/assert@1";
import { model } from "./aws_integration_coverage.ts";
import { report } from "./integration_coverage_report.ts";

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

  // The package name matches the model type (the report name is independently
  // @jentz/integration-coverage); manifest `name` keys off the model type.
  assertEquals(model.type, manifestScalar(manifest, "name"));
  assertEquals(model.type, "@jentz/aws-integration-coverage");
  assertEquals(model.version, manifestScalar(manifest, "version"));
  assertEquals(Object.keys(model.resources).sort(), ["coverage", "summary"]);
  // Read-only coalesce surface: exactly one method, no mutating method.
  assertEquals(Object.keys(model.methods), ["coalesce"]);
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

Deno.test("report metadata: name and scope are the published contract", () => {
  // The report name is independent of the model type / package name; downstream
  // workflows key off this exact string.
  assertEquals(report.name, "@jentz/integration-coverage");
  assertEquals(report.scope, "workflow");
  assertEquals(report.labels.length > 0, true);
});
