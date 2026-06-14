/**
 * Colocated publication-sanity tests for the report entry point of
 * `@jentz/aws-integration-coverage` (the report `@jentz/integration-coverage`).
 *
 * The full collect/render suite lives under `tests/`; this sibling file keeps
 * the report entrypoint visibly paired with a test entrypoint for publish
 * review tooling without duplicating that larger suite. It also asserts the
 * report's success AND failure (degraded) paths at a glance.
 */

import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
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

Deno.test("report metadata: name and workflow scope are the published contract", async () => {
  const manifest = await Deno.readTextFile(
    new URL("./manifest.yaml", import.meta.url),
  );

  // The report name is independent of the package/model name; downstream
  // workflows key off this exact string. The package name (model type) lives
  // under manifest `name`; the report name does not appear there.
  assertEquals(report.name, "@jentz/integration-coverage");
  assert(report.name !== manifestScalar(manifest, "name"));
  assertEquals(report.scope, "workflow");
  assertEquals(report.labels.length > 0, true);
});

Deno.test("report success path: no upstream steps yields a healthy empty report", async () => {
  const out = await report.execute({
    workflowName: "wf",
    logger: {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: () => {},
    },
    stepExecutions: [],
    dataRepository: { getContent: () => Promise.resolve(null) },
  });
  assertEquals(Object.keys(out).sort(), ["json", "markdown"]);
  assertEquals(out.json.degraded, false);
  assertEquals(out.json.accounts.length, 0);
  // No CSV artifact, ever.
  assert(!("csv" in out));
});

Deno.test("report failure path: an exploding context degrades, never throws", async () => {
  const out = await report.execute({
    workflowName: "wf",
    logger: {
      info: () => {},
      warn: () => {},
      debug: () => {},
      error: () => {},
    },
    get stepExecutions(): never {
      throw new Error("boom");
    },
    dataRepository: { getContent: () => Promise.resolve(null) },
  });
  assertEquals(out.json.degraded, true);
  assertStringIncludes(out.markdown, "Report degraded");
});
