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

import { z } from "npm:zod@4";
import {
  GetCallerIdentityCommand,
  STSClient,
} from "npm:@aws-sdk/client-sts@3.1021.0";

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
 * The `@jentz/aws-context-guard` model.
 *
 * Provides a single `verify` method that checks `AWS_PROFILE` suffix and
 * `sts:GetCallerIdentity` account ID, then persists the verified caller
 * identity as a `context` resource. Throws on any failure so the workflow
 * step (with `allowFailure: false`) aborts before downstream work runs.
 */
export const model = {
  type: "@jentz/aws-context-guard",
  version: "2026.05.17.1",
  globalArguments: GlobalArgsSchema,
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
        const g = context.globalArgs as z.infer<typeof GlobalArgsSchema>;
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
        const resp = await client.send(new GetCallerIdentityCommand({}));
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
