/**
 * Colocated publication-sanity tests for `@jentz/aws-cfn-orphan-sweep`.
 *
 * The full unit and smoke suites live under `tests/`; this sibling file keeps
 * the extension's entrypoint visibly paired with a test entrypoint for publish
 * review tooling without duplicating that larger suite.
 *
 * This directory deliberately ships no `manifest.yaml` yet (homed now, published
 * later), so — unlike the sibling extensions — these assertions read the model
 * metadata directly instead of cross-checking a manifest. The model also has no
 * `upgrades` chain, so there is no upgrade-invariant assertion here.
 */

import { assertEquals } from "jsr:@std/assert@1";
import { model } from "./aws_cfn_orphan_sweep.ts";

Deno.test("model metadata: type and version are the published values", () => {
  assertEquals(model.type, "@jentz/aws-cfn-orphan-sweep");
  assertEquals(model.version, "2026.06.16.3");
});

Deno.test("model metadata: resource and method surface is stable", () => {
  assertEquals(
    Object.keys(model.resources).sort(),
    ["deletion", "org-summary", "orphan", "summary"],
  );
  // enumerate / enumerateOrg are read-only; cleanup is the mutating (dry-run by
  // default) method.
  assertEquals(
    Object.keys(model.methods).sort(),
    ["cleanup", "enumerate", "enumerateOrg"],
  );
});
