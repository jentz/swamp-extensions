/**
 * Code-generation for the shared `_lib` foundation.
 *
 * The fleet-scanner extensions each bundle from their own root, so a module
 * shared across them cannot be imported across package boundaries — each
 * package needs its own physical copy. This script keeps those copies
 * byte-for-byte in sync with one canonical source under the repo-root `_lib/`
 * directory (which is intentionally *not* under any `manifest.yaml`, so the
 * per-extension gates never sweep it as an extension).
 *
 * Each generated copy is stamped with an auto-generated header (mirroring the
 * `@swamp/aws` `_lib/aws.ts` precedent) so a human who opens the file knows not
 * to hand-edit it and how to regenerate.
 *
 * Usage (invoked directly, not as a `deno task`, on purpose — see below):
 *   deno run --allow-read --allow-write scripts/sync-lib.ts            # regenerate
 *   deno run --allow-read scripts/sync-lib.ts --check                  # drift gate (read-only)
 *
 * Why a direct invocation rather than a `deno task`: swamp derives each
 * extension's package content hash from the manifest, every referenced source
 * file, AND the repo-root `deno.json` configuration. Editing `deno.json` (e.g.
 * to add a task entry) therefore invalidates the committed `.swamp-reviews/`
 * adversarial review of *every* extension at once. Keeping `deno.json` untouched
 * lets this codegen ship without forcing a fleet-wide review regeneration.
 *
 * Adding a new generated copy is a one-line edit to {@link TARGETS}.
 *
 * @module
 */

import { dirname, fromFileUrl, join, relative } from "jsr:@std/path@1";

/** Repo root, derived from this script's location (`<root>/scripts/`). */
const ROOT = dirname(dirname(fromFileUrl(import.meta.url)));

/**
 * Canonical-source → generated-copies map.
 *
 * The key is a canonical file under `_lib/`; the value lists the per-package
 * paths generated from it. All paths are repo-root-relative.
 *
 * SCOPE: a canonical module is generated only into the packages that actually
 * import it, so an SDK-bearing module never leaks into an SDK-free bundle. The
 * pure `scan_error.ts` is generated into the producer + report pairs (the
 * `aws-default-sg-audit` and `aws-vpc-inventory` families) and into the
 * `aws-iam-role-audit` producer (which imports `classifyError` but keeps
 * its own role-scoped stored-row schema); the SDK-bearing
 * `aws_credentials.ts` is generated into the producers only (the report bundles
 * stay SDK-free, and the `aws-integration-coverage` consumer reads the stored
 * rows tolerantly so it needs no twin). Add a key/target here when a package
 * starts consuming a canonical module.
 */
const TARGETS: Record<string, readonly string[]> = {
  "_lib/retry.ts": [
    "aws-rds-inventory/_lib/retry.ts",
    "aws-rds-reservations/_lib/retry.ts",
  ],
  "_lib/scan_error.ts": [
    "aws-default-sg-audit/_lib/scan_error.ts",
    "aws-default-sg-audit-report/_lib/scan_error.ts",
    "aws-vpc-inventory/_lib/scan_error.ts",
    "aws-vpc-inventory-report/_lib/scan_error.ts",
    "aws-iam-role-audit/_lib/scan_error.ts",
  ],
  "_lib/aws_credentials.ts": [
    "aws-default-sg-audit/_lib/aws_credentials.ts",
    "aws-vpc-inventory/_lib/aws_credentials.ts",
    "aws-iam-role-audit/_lib/aws_credentials.ts",
  ],
};

/**
 * Auto-generated header prepended to every generated copy.
 *
 * Mirrors the `@swamp/aws` `_lib/aws.ts` header style: a leading `//` banner
 * stating the file is generated, must not be hand-edited, and how to
 * regenerate it. A blank line separates the banner from the canonical content.
 */
function header(canonicalRelPath: string): string {
  return [
    "// Auto-generated from " + canonicalRelPath + " by scripts/sync-lib.ts.",
    "// Do not edit manually. Re-generate with:",
    "//   deno run --allow-read --allow-write scripts/sync-lib.ts",
    "",
    "",
  ].join("\n");
}

/** Render the full generated content for one target from its canonical file. */
async function render(canonicalRelPath: string): Promise<string> {
  const canonical = await Deno.readTextFile(join(ROOT, canonicalRelPath));
  return header(canonicalRelPath) + canonical;
}

/** Write every target from its canonical source. */
async function write(): Promise<void> {
  for (const [canonicalRelPath, targets] of Object.entries(TARGETS)) {
    const content = await render(canonicalRelPath);
    for (const target of targets) {
      const abs = join(ROOT, target);
      await Deno.mkdir(dirname(abs), { recursive: true });
      await Deno.writeTextFile(abs, content);
      console.log(`wrote ${relative(ROOT, abs)}`);
    }
  }
}

/**
 * Compare every target against its freshly rendered content. Returns the list
 * of targets that have drifted (missing, or different bytes on disk).
 */
async function drifted(): Promise<string[]> {
  const out: string[] = [];
  for (const [canonicalRelPath, targets] of Object.entries(TARGETS)) {
    const expected = await render(canonicalRelPath);
    for (const target of targets) {
      const abs = join(ROOT, target);
      let actual: string | null = null;
      try {
        actual = await Deno.readTextFile(abs);
      } catch {
        actual = null;
      }
      if (actual !== expected) out.push(target);
    }
  }
  return out;
}

if (import.meta.main) {
  const check = Deno.args.includes("--check");
  if (check) {
    const stale = await drifted();
    if (stale.length > 0) {
      console.error(
        "sync-lib drift detected — these generated _lib copies are out of " +
          "sync with their canonical source under _lib/:",
      );
      for (const s of stale) console.error(`  - ${s}`);
      console.error(
        "Run `deno run --allow-read --allow-write scripts/sync-lib.ts` and " +
          "commit the result.",
      );
      Deno.exit(1);
    }
    console.log("sync-lib: all generated _lib copies are in sync.");
  } else {
    await write();
  }
}
