/**
 * Colocated smoke tests for the @jentz/aws-vpc-inventory-report extension.
 *
 * This file sits beside the report entrypoint (`aws_vpc_inventory_report.ts`)
 * and covers the handful of behaviors that matter most for publish review: the
 * report name stays in sync with the manifest, the scope is `workflow`, and
 * `report.execute` never throws on an empty context.
 *
 * The exhaustive collection / rendering / JSON-payload matrix lives in
 * `tests/aws_vpc_inventory_report_test.ts`. This file deliberately does NOT
 * duplicate that matrix.
 */

import { assert, assertEquals, assertExists } from "jsr:@std/assert@1";

import { report } from "./aws_vpc_inventory_report.ts";

function manifestScalar(manifest: string, key: string): string {
  const match = manifest.match(
    new RegExp(`^${key}:\\s*["']?([^"'\\n]+)["']?$`, "m"),
  );
  if (match === null) {
    throw new Error(`manifest.yaml is missing scalar key ${key}`);
  }
  return match[1].trim();
}

function silentLogger() {
  return {
    info: () => {},
    debug: () => {},
    warn: () => {},
    error: () => {},
  };
}

/** Minimal workflow-scope report context with no upstream step data. */
function emptyContext() {
  return {
    workflowName: "smoke-workflow",
    stepExecutions: [],
    logger: silentLogger(),
    dataRepository: {
      getContent: (): Promise<Uint8Array | null> => Promise.resolve(null),
    },
  };
}

Deno.test("report metadata: entrypoint name stays in sync with manifest", async () => {
  const manifest = await Deno.readTextFile(
    new URL("./manifest.yaml", import.meta.url),
  );
  assertEquals(report.name, manifestScalar(manifest, "name"));
});

Deno.test("report metadata: scope is workflow", () => {
  assertEquals(report.scope, "workflow");
});

Deno.test(
  "report.execute: returns markdown + JSON and does not throw when no step data is present",
  async () => {
    const out = await report.execute(emptyContext());
    assertExists(out.markdown);
    assert(out.markdown.includes("AWS VPC Inventory"));
    assertEquals(out.json.report, "@jentz/aws-vpc-inventory-report");
    assertEquals(out.json.workflow, "smoke-workflow");
    // No VPCs were found, so the rows array and counts are empty.
    assertEquals(out.json.vpcs.length, 0);
    assertEquals(out.json.vpcCount, 0);
    assertEquals(out.json.degraded, false);
    assertEquals(out.json.skipped, 0);
  },
);
