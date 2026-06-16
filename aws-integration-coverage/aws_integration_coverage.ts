/**
 * `@jentz/aws-integration-coverage` — first-class, queryable coalesce of the
 * StackSet lens and the IAM lens for one integration role.
 *
 * This is the model counterpart to the `@jentz/integration-coverage`
 * workflow-scope report (shipped in the same package): instead of rendering
 * markdown inside a workflow run, it writes the per-account coverage matrix as
 * model data, so you can query and wire it like any other swamp resource:
 *
 *   swamp data query 'modelName == "acme-coverage-model" &&
 *     specName == "coverage" && attributes.coverage == "uncovered"'
 *
 * The single `coalesce` method reads the stored output of two other model
 * instances — a `@jentz/aws-stackset-audit` (its `instance`/`summary` rows) and
 * a `@jentz/aws-iam-role-audit` (its `role`/`scan_error` rows) — via
 * `dataRepository.findAllForModel`, runs the shared coalesce core
 * (`./_lib/coverage.ts`, identical to the report's), and writes:
 *
 *   - one `coverage` resource per account (covered? by which way? reconciled
 *     against the StackSet's own bookkeeping), and
 *   - one `summary` resource with the rollups (by coverage, by mechanism,
 *     discrepancy / uncovered / unknown / manual account lists).
 *
 * Read-only with respect to AWS — it consumes already-captured audit data, makes
 * no API calls. Run the two audits first (directly or via a coverage workflow),
 * then run this. Generic: point it at any stackset-audit + role-audit pair.
 *
 * @module
 */

import { z } from "npm:zod@4";
import {
  coalesce,
  type Collected,
  CoverageRowSchema,
  IAM_ERROR_SPEC,
  IAM_ROLE_SPEC,
  IamErrorSchema,
  InstanceSchema,
  isDisagreement,
  RoleSchema,
  STACKSET_INSTANCE_SPEC,
  STACKSET_SUMMARY_SPEC,
  summarizeCoverage,
  SummarySchema,
} from "./_lib/coverage.ts";

// ---------------------------------------------------------------------------
// Global arguments
// ---------------------------------------------------------------------------

const GlobalArgsSchema = z.object({
  stacksetModelId: z.string().min(1).describe(
    "Model id of the @jentz/aws-stackset-audit instance whose data to read " +
      "(from `swamp model get <name> --json` .id).",
  ),
  iamModelId: z.string().min(1).describe(
    "Model id of the @jentz/aws-iam-role-audit instance whose data to read.",
  ),
  stacksetModelType: z.string().min(1).default("@jentz/aws-stackset-audit")
    .describe("Type of the stackset-audit model (override only if forked)."),
  iamModelType: z.string().min(1).default("@jentz/aws-iam-role-audit")
    .describe("Type of the iam-role-audit model (override only if forked)."),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

// ---------------------------------------------------------------------------
// Summary resource schema
// ---------------------------------------------------------------------------

const SummaryResourceSchema = z.object({
  stackSetName: z.string(),
  roleNames: z.array(z.string()),
  totalAccounts: z.number(),
  coveredCompliant: z.number(),
  coveredNoncompliant: z.number(),
  coveredPartial: z.number(),
  uncovered: z.number(),
  unknown: z.number(),
  byCoverage: z.record(z.string(), z.number()),
  byMechanism: z.record(z.string(), z.number()),
  byRole: z.array(z.object({
    roleName: z.string(),
    required: z.boolean(),
    present: z.number(),
    compliant: z.number(),
    missing: z.number(),
  })),
  discrepancyAccounts: z.array(z.string()),
  uncoveredAccounts: z.array(z.string()),
  unknownAccounts: z.array(z.string()),
  manualAccounts: z.array(z.string()),
  sources: z.object({
    stacksetModelId: z.string(),
    iamModelId: z.string(),
    instanceRows: z.number(),
    roleRows: z.number(),
    skipped: z.number(),
  }),
  generatedAt: z.iso.datetime(),
});

// ---------------------------------------------------------------------------
// Cross-model data reading
// ---------------------------------------------------------------------------

/** Minimal shape of a stored data item as returned by findAllForModel. */
interface StoredData {
  name?: string;
  version?: number;
  specName?: string;
  lifecycle?: string;
  tags?: { specName?: string };
  metadata?: { lifecycle?: string; tags?: { specName?: string } };
}

function specNameOf(d: StoredData): string | undefined {
  return d.tags?.specName ?? d.metadata?.tags?.specName ?? d.specName;
}

function lifecycleOf(d: StoredData): string | undefined {
  return d.lifecycle ?? d.metadata?.lifecycle;
}

/**
 * Read every active artifact of one spec for a model instance, keeping the
 * latest version per data name, and JSON-decode each. Returns raw values for
 * the caller to schema-validate.
 *
 * @param dataRepo The swamp data repository (findAllForModel + getContent).
 * @param modelType Upstream model type to read.
 * @param modelId Upstream model instance id to read.
 * @param specName The resource spec name to keep.
 * @returns The decoded raw JSON values (one per latest-active artifact) plus a
 *   `decodeSkipped` count of artifacts dropped because their stored bytes were
 *   missing or failed to JSON-parse, so the caller can fold them into the
 *   reported `skipped` total.
 */
export async function readSpec(
  // deno-lint-ignore no-explicit-any
  dataRepo: any,
  modelType: string,
  modelId: string,
  specName: string,
): Promise<{ values: unknown[]; decodeSkipped: number }> {
  const all: StoredData[] =
    (await dataRepo.findAllForModel(modelType, modelId)) ??
      [];
  const latest = new Map<string, { name: string; version: number }>();
  for (const d of all) {
    if (specNameOf(d) !== specName) continue;
    if (lifecycleOf(d) === "deleted") continue;
    if (typeof d.name !== "string") continue;
    const version = typeof d.version === "number" ? d.version : 0;
    const prev = latest.get(d.name);
    if (!prev || version > prev.version) {
      latest.set(d.name, { name: d.name, version });
    }
  }
  const decoder = new TextDecoder();
  const out: unknown[] = [];
  let decodeSkipped = 0;
  for (const { name, version } of latest.values()) {
    let bytes: Uint8Array | null;
    try {
      bytes = await dataRepo.getContent(modelType, modelId, name, version);
    } catch {
      // A storage read failure is the same class as missing bytes — count it
      // and skip, rather than aborting the whole coalesce on one bad read.
      decodeSkipped++;
      continue;
    }
    if (!bytes) {
      decodeSkipped++;
      continue;
    }
    try {
      out.push(JSON.parse(decoder.decode(bytes)));
    } catch {
      // Tolerant: an undecodable artifact is counted, never thrown.
      decodeSkipped++;
    }
  }
  return { values: out, decodeSkipped };
}

/** Validation outcome for a batch of raw values. */
export interface ParseBatch<T> {
  /** Values that validated against the schema. */
  ok: T[];
  /** Count of values that failed validation. */
  bad: number;
}

/**
 * The minimal slice of a zod schema {@link parseAll} needs: a tolerant
 * `safeParse`. Declared locally so the public signature does not reference a
 * private zod-internal type (keeps `deno doc --lint` clean).
 */
export interface SafeParser<T> {
  /** Validate one value, returning a discriminated success/failure result. */
  safeParse(
    value: unknown,
  ): { success: true; data: T } | { success: false };
}

/** Validate a batch of raw values against a schema; count the rejects. */
export function parseAll<T>(
  raws: unknown[],
  schema: SafeParser<T>,
): ParseBatch<T> {
  const ok: T[] = [];
  let bad = 0;
  for (const r of raws) {
    const p = schema.safeParse(r);
    if (p.success) ok.push(p.data);
    else bad++;
  }
  return { ok, bad };
}

// ---------------------------------------------------------------------------
// Model export
// ---------------------------------------------------------------------------

/**
 * The `@jentz/aws-integration-coverage` model. Single method `coalesce` reads
 * the two upstream audit models' stored data and writes a queryable per-account
 * coverage matrix plus a rollup summary.
 */
export const model = {
  type: "@jentz/aws-integration-coverage",
  version: "2026.06.16.0",
  globalArguments: GlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.06.13.0",
      description: "Initial publish",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.16.0",
      description:
        "Doc-lint release (explicit schema type annotations); no schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    coverage: {
      description:
        "One account's coalesced coverage: is the integration role present & " +
        "compliant, by which mechanism, and how it reconciles with the " +
        "StackSet's own bookkeeping.",
      schema: CoverageRowSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
    summary: {
      description:
        "Coverage rollups: counts by coverage verdict and mechanism, plus the " +
        "discrepancy / uncovered / unknown / manual account lists.",
      schema: SummaryResourceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    coalesce: {
      description:
        "Read the stackset-audit and iam-role-audit model data, coalesce into a " +
        "per-account coverage matrix, and write one coverage row per account " +
        "plus a rollup summary. Run the two audits first.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        // deno-lint-ignore no-explicit-any
        context: any,
      ): Promise<{ dataHandles: unknown[] }> => {
        const g: GlobalArgs = GlobalArgsSchema.parse(context.globalArgs);
        const repo = context.dataRepository;

        const instRaw = await readSpec(
          repo,
          g.stacksetModelType,
          g.stacksetModelId,
          STACKSET_INSTANCE_SPEC,
        );
        const sumRaw = await readSpec(
          repo,
          g.stacksetModelType,
          g.stacksetModelId,
          STACKSET_SUMMARY_SPEC,
        );
        const roleRaw = await readSpec(
          repo,
          g.iamModelType,
          g.iamModelId,
          IAM_ROLE_SPEC,
        );
        const errRaw = await readSpec(
          repo,
          g.iamModelType,
          g.iamModelId,
          IAM_ERROR_SPEC,
        );

        const instances = parseAll(instRaw.values, InstanceSchema);
        const summaries = parseAll(sumRaw.values, SummarySchema);
        const roles = parseAll(roleRaw.values, RoleSchema);
        const iamErrors = parseAll(errRaw.values, IamErrorSchema);
        // skipped folds both decode failures (missing/undecodable bytes) and
        // schema-validation rejects, so the count reflects every tolerantly
        // dropped artifact — matching the report's collect path and the README.
        const skipped = instRaw.decodeSkipped + sumRaw.decodeSkipped +
          roleRaw.decodeSkipped + errRaw.decodeSkipped +
          instances.bad + summaries.bad + roles.bad + iamErrors.bad;

        if (instances.ok.length === 0 && roles.ok.length === 0) {
          if (skipped > 0) {
            throw new Error(
              `No usable stackset instance or IAM role data found for the ` +
                `configured source models — all ${skipped} upstream artifact(s) ` +
                `were skipped (decode / schema-validation failures). Check that ` +
                `the upstream models produced valid output and that their types ` +
                `match the configured stacksetModelType / iamModelType.`,
            );
          }
          throw new Error(
            "No stackset instance or IAM role data found for the configured " +
              "source models — run the stackset-audit and iam-role-audit methods " +
              "first (check stacksetModelId / iamModelId).",
          );
        }

        const collected: Collected = {
          instances: instances.ok,
          summaries: summaries.ok,
          roles: roles.ok,
          iamErrors: iamErrors.ok,
          skipped,
        };

        const result = coalesce(collected);
        const rollup = summarizeCoverage(result.rows);
        const generatedAt = new Date().toISOString();

        context.logger.info(
          "Coalesced {n} account(s) from {inst} instance + {role} role row(s)",
          {
            n: result.rows.length,
            inst: instances.ok.length,
            role: roles.ok.length,
          },
        );

        const handles: unknown[] = [];
        for (const row of result.rows) {
          handles.push(
            await context.writeResource(
              "coverage",
              `coverage-${row.accountId}`,
              row,
            ),
          );
        }

        const summary = {
          stackSetName: result.stackSetName,
          roleNames: result.roleNames,
          totalAccounts: result.rows.length,
          coveredCompliant: rollup.byCoverage["covered-compliant"] ?? 0,
          coveredNoncompliant: rollup.byCoverage["covered-noncompliant"] ?? 0,
          coveredPartial: rollup.byCoverage["covered-partial"] ?? 0,
          uncovered: rollup.byCoverage["uncovered"] ?? 0,
          unknown: rollup.byCoverage["unknown"] ?? 0,
          byCoverage: rollup.byCoverage,
          byMechanism: rollup.byMechanism,
          byRole: rollup.byRole,
          discrepancyAccounts: result.rows.filter(isDisagreement).map((r) =>
            r.accountId
          ),
          uncoveredAccounts: result.rows.filter((r) =>
            r.coverage === "uncovered"
          ).map((r) => r.accountId),
          unknownAccounts: result.rows.filter((r) => r.coverage === "unknown")
            .map((r) => r.accountId),
          manualAccounts: result.rows.filter((r) => r.mechanism === "manual")
            .map((r) => r.accountId),
          sources: {
            stacksetModelId: g.stacksetModelId,
            iamModelId: g.iamModelId,
            instanceRows: instances.ok.length,
            roleRows: roles.ok.length,
            skipped,
          },
          generatedAt,
        };
        handles.push(
          await context.writeResource("summary", "summary", summary),
        );

        return { dataHandles: handles };
      },
    },
  },
};
