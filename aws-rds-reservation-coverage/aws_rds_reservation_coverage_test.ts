/**
 * Colocated publication-sanity tests for `@jentz/aws-rds-reservation-coverage`.
 *
 * The full unit and collect/render suites live under `tests/`; this sibling
 * file keeps the report entrypoint visibly paired with a test entrypoint for
 * publish review tooling without duplicating that larger suite.
 */

import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  normalizedUnits,
  parseInstanceClass,
  report,
  sizeFactor,
} from "./aws_rds_reservation_coverage.ts";

function manifestScalar(manifest: string, key: string): string {
  const match = manifest.match(
    new RegExp(`^${key}:\\s*["']?([^"'\\n]+)["']?$`, "m"),
  );
  if (match === null) {
    throw new Error(`manifest.yaml is missing scalar key ${key}`);
  }
  return match[1].trim();
}

Deno.test("report metadata: entrypoint stays in sync with manifest", async () => {
  const manifest = await Deno.readTextFile(
    new URL("./manifest.yaml", import.meta.url),
  );

  assertEquals(report.name, manifestScalar(manifest, "name"));
  assertEquals(report.scope, "workflow");
  // A report carries no version field; key off name/scope, and assert the
  // labels surfaced to publish tooling are non-empty.
  assertEquals(report.labels.length > 0, true);
});

Deno.test("sizeFactor: unparseable size tokens route to a carve-out, not zero", () => {
  // Unknown tokens, `metal`, and the empty serverless size are not normalizable
  // and must return null so callers carve them out rather than scoring zero.
  assertEquals(sizeFactor("bogus"), null);
  assertEquals(sizeFactor("metal"), null);
  assertEquals(sizeFactor(""), null);
  assertEquals(normalizedUnits("bogus", "Single-AZ"), null);
});

Deno.test("parseInstanceClass: malformed class is flagged unparseable", () => {
  const bad = parseInstanceClass("db.");
  assertEquals(bad.unparseable, true);
  assertEquals(bad.family, "");

  const empty = parseInstanceClass("");
  assertEquals(empty.unparseable, true);
});
