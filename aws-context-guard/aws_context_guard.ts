/**
 * Swamp extension model: `@jentz/aws-context-guard`.
 *
 * A workflow-safety primitive that fails closed before any AWS work runs.
 * Asserts, in order:
 *   1. `AWS_PROFILE` env var ends with a required suffix (e.g. `-readonly`).
 *   2. `sts:GetCallerIdentity` returns the expected account ID.
 *
 * On success, persists the verified caller-identity context so downstream
 * workflow steps can reference it via CEL.
 *
 * On any failure the `verify` method throws, aborting the workflow.
 *
 * @module
 */

import { z } from "npm:zod@4.4.3";
import {
  GetCallerIdentityCommand,
  STSClient,
} from "npm:@aws-sdk/client-sts@3.1073.0";

const GlobalArgsSchema = z.object({
  expectedAccountId: z.string().regex(/^\d{12}$/).describe(
    "The 12-digit AWS account ID this workflow expects to be operating against. " +
      "Workflow aborts if sts:GetCallerIdentity returns a different account.",
  ),
  requiredProfileSuffix: z.string().default("-readonly").describe(
    "AWS_PROFILE must end with this suffix. Set to empty string to disable " +
      "the check. Default '-readonly' enforces read-only profiles for audit " +
      "workflows.",
  ),
});

const ContextSchema = z.object({
  accountId: z.string(),
  arn: z.string(),
  userId: z.string(),
  profile: z.string(),
  region: z.string(),
  verifiedAt: z.iso.datetime(),
});

/**
 * Call `client.destroy()` if present, swallowing and logging any failure at
 * `debug`. SDK `destroy()` is synchronous and best-effort cleanup: a failure
 * here must never mask the operation's original outcome — neither turning a
 * successful verify into a failure nor replacing a real thrown error. Lives
 * in the verify method's `finally` so it is the last thing to run on both the
 * success and error paths. Inlined (rather than imported across extension
 * boundaries) to keep this model self-contained, mirroring the sibling
 * `@jentz/aws-rds-reservations` helper.
 */
export function safeDestroy(
  client: { destroy?: () => void } | undefined,
  // deno-lint-ignore no-explicit-any
  logger?: any,
): void {
  try {
    client?.destroy?.();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger?.debug?.(
      "Ignoring AWS SDK client destroy() failure during cleanup: {message}",
      { message },
    );
  }
}

/**
 * The `@jentz/aws-context-guard` model.
 *
 * Provides a single `verify` method that checks `AWS_PROFILE` suffix and
 * `sts:GetCallerIdentity` account ID, then persists the verified caller
 * identity as a `context` resource. Throws on any failure so the workflow
 * step (with `allowFailure: false`) aborts before downstream work runs.
 */
export const model = {
  type: "@jentz/aws-context-guard",
  version: "2026.06.22.0",
  globalArguments: GlobalArgsSchema,
  // swamp model upgrades transform stored globalArguments, not the per-run
  // derived context resource. The guard's globalArguments shape
  // (expectedAccountId, requiredProfileSuffix) has been unchanged since the
  // 2026.05.17.1 baseline, so every entry is a no-op. Each one still advances
  // the stored typeVersion on existing instances so any future
  // schema-changing upgrade chains cleanly instead of skipping releases. The
  // chain mirrors the sibling @jentz/aws-rds-inventory / aws-rds-reservations
  // convention: one entry per published release after the baseline, ending at
  // the current model.version. (The 2026.06.08.2 entry is intentionally
  // absent — it was committed but never published, so no stored instance ever
  // carried it.)
  upgrades: [
    {
      toVersion: "2026.06.07.1",
      description: "Version bump, no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.08.1",
      description: "Version bump, no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.09.1",
      description: "Version bump, no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.06.22.0",
      description: "Dependency refresh, no globalArguments schema changes",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ] as Array<{
    toVersion: string;
    description: string;
    upgradeAttributes: (
      old: Record<string, unknown>,
    ) => Record<string, unknown>;
  }>,
  resources: {
    context: {
      description: "Verified AWS caller-identity context",
      schema: ContextSchema,
      lifetime: "infinite" as const,
      garbageCollection: 10,
    },
  },
  methods: {
    verify: {
      description:
        "Verify AWS profile suffix and caller-identity account match " +
        "expected values. Fails closed.",
      arguments: z.object({}),
      // deno-lint-ignore no-explicit-any
      execute: async (_args: Record<string, never>, context: any) => {
        // Defense in depth: parse, don't cast. The swamp runtime is expected
        // to validate globalArgs at model-instance creation, but this is the
        // last line of defense if something gets past that — and the cost is
        // a single safeParse call.
        const parsed = GlobalArgsSchema.safeParse(context.globalArgs);
        if (!parsed.success) {
          throw new Error(
            "aws-context-guard refuses to proceed: invalid globalArgs " +
              `(${parsed.error.issues.map((i) => i.message).join("; ")}).`,
          );
        }
        const g = parsed.data;
        const profile = Deno.env.get("AWS_PROFILE") ?? "";
        const region = Deno.env.get("AWS_REGION") ?? "";

        context.logger.info(
          "Verifying AWS context (profile={profile}, region={region}, expectedAccount={expectedAccount})",
          {
            profile: profile || "<unset>",
            region: region || "<unset>",
            expectedAccount: g.expectedAccountId,
          },
        );

        if (!profile) {
          throw new Error(
            "AWS_PROFILE is not set. aws-context-guard refuses to proceed.",
          );
        }
        if (
          g.requiredProfileSuffix &&
          !profile.endsWith(g.requiredProfileSuffix)
        ) {
          throw new Error(
            `AWS_PROFILE='${profile}' does not end with required suffix ` +
              `'${g.requiredProfileSuffix}'. aws-context-guard refuses to proceed.`,
          );
        }

        context.logger.debug("Calling sts:GetCallerIdentity");
        const client = new STSClient({ region: region || "us-east-1" });
        let resp;
        try {
          resp = await client.send(new GetCallerIdentityCommand({}));
        } finally {
          // Free the STS client's socket pool on both the success and error
          // paths. safeDestroy never throws, so it cannot mask the original
          // send() outcome.
          safeDestroy(client, context.logger);
        }
        const accountId = resp.Account ?? "";
        const arn = resp.Arn ?? "";
        const userId = resp.UserId ?? "";

        if (!accountId) {
          throw new Error(
            "sts:GetCallerIdentity returned no Account. " +
              "aws-context-guard refuses to proceed.",
          );
        }
        if (accountId !== g.expectedAccountId) {
          throw new Error(
            `sts:GetCallerIdentity returned account ${accountId}, ` +
              `expected ${g.expectedAccountId}. aws-context-guard refuses to proceed.`,
          );
        }

        context.logger.info(
          "AWS context verified (account={account}, arn={arn})",
          { account: accountId, arn },
        );

        const handle = await context.writeResource("context", "current", {
          accountId,
          arn,
          userId,
          profile,
          region,
          verifiedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
