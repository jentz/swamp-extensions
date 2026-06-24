# @jentz/aws-cfn-orphan-sweep

Find and (optionally) clean up the standalone CloudFormation stacks a retired
StackSet leaves behind, fleet-wide and one account at a time.

When a StackSet is retired with `delete-stack-instances --retain-stacks`, the
StackSet records are dropped but the per-account/region member stacks remain as
ordinary standalone stacks named `StackSet-<setname>-<guid>`. The official
[`@swamp/aws/cloudformation/stack`](https://github.com/systeminit/swamp-extensions)
type is single-stack CRUD with no list-by-prefix and no `RetainResources` on
delete, and `@jentz/aws-stackset-audit` only sees instances of a *live*
StackSet — neither can find or safely remove these orphans. This model fills
that gap.

It is account-scoped: it runs against whatever credentials are in the ambient
chain (or a named `profile`), resolves its own account id via STS, and fans out
across the configured `regions` in one locked execution. Run it once per
account; each run writes rows keyed by account + region + stack, so a single
model instance accumulates the whole fleet, queryable with CEL.

## What it does

Two methods:

### `enumerate` (read-only)

In one locked, fan-out execution:

1. `ListStacks` per region (every status except `DELETE_COMPLETE`).
2. Keep only stacks whose name starts with `namePrefix`.
3. `ListStackResources` on each match, classifying the salient resources: the
   custom resource to retain on delete, the IAM role (logical id + physical
   name — the audit smell the cleanup removes), and the backing Lambda.

It writes one **`orphan`** resource per matching stack plus one per-account
**`summary`**. Only `List*` is ever called, so it is safe under a `*-readonly`
profile.

### `cleanup` (mutating; dry-run unless `apply=true`)

Re-enumerates orphans live, applies the optional `onlyRegion` / `onlyStack`
scoping, and for each target:

- **dry-run (`apply=false`, the default):** writes a `deletion` planning row
  (`would-initiate-delete`, `would-retain-delete`, or `would-wait`) and mutates
  nothing.
- **apply (`apply=true`):** by default predeletes the dead backing Lambda, then
  issues one plain `DeleteStack`. With the function gone, the custom resource's
  delete has no provider to invoke, so CloudFormation removes the whole stack
  (custom resource, Lambda, IAM role) in one pass instead of hanging on the
  missing callback. If `predeleteLambda` is off, it falls back to a two-pass
  retain-delete: a plain delete drives the stack to `DELETE_FAILED`, then a
  second delete retaining only the failed custom resource lets the rest
  complete. It polls to a terminal state and, when `verifyRole` is on,
  confirms the captured IAM role is gone via `GetRole`.

Two guardrails are always enforced: it refuses any stack whose name does not
start with `namePrefix`, and it refuses to retain anything that is not the
detected custom resource (so the IAM role and Lambda are always deleted).

### `orphan` resource

One row per matching stack, keyed `orphan-${account}-${region}-${stack}`:

- `account`, `region`, `stackName`, `stackId`, `stackStatus`, `statusReason`,
  `creationTime`
- `customResourceLogicalId`, `customResourceType` — the dead custom resource to
  retain on delete (or `""`)
- `iamRoleLogicalId`, `iamRolePhysicalName` — the role the cleanup removes and
  the handle used to verify it is gone
- `lambdaLogicalId`
- `resourceCount`, `resources` (every `{logicalId, physicalId, type, status}`)
- `scannedAt` — ISO-8601 timestamp

### `summary` resource

One per-account rollup, keyed `summary-${account}`:

- `account`, `regionsScanned`, `orphanCount`
- `byRegion`, `byStatus` — per-dimension counts
- `deleteFailed` — names of any `DELETE_FAILED` stacks
- `scannedAt`

### `deletion` resource

One row per delete attempt or dry-run plan, keyed
`deletion-${account}-${region}-${stack}`:

- `account`, `region`, `stackName`, `stackId`
- `action` — e.g. `would-initiate-delete`, `would-retain-delete`,
  `delete-initiated`, `delete-retain`, `already-gone`, `skip`, `error`
- `retainedResources`, `finalStatus`, `gone`
- `roleChecked`, `roleGone`, `iamRolePhysicalName`
- `error`, `startedAt`, `finishedAt`

## Global arguments

| Argument     | Type                            | Default                              | Meaning                                                                                              |
| ------------ | ------------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| `namePrefix` | `string` (required, non-empty)  | `StackSet-IAMCustomPasswordPolicy-`  | Only stacks whose name starts with this prefix are enumerated or ever considered for deletion.       |
| `regions`    | `string[]` (required, non-empty) | `us-east-1`, `eu-west-1`, `eu-central-1`, `eu-north-1` | Regions to fan out across in one execution.                                                          |
| `profile`    | `string`                        | `""` (ambient)                       | Named AWS profile (resolved via `fromIni`). Empty uses the ambient credential chain (`AWS_*` env).   |

The `cleanup` method takes these arguments:

| Argument          | Type             | Default | Meaning                                                                                          |
| ----------------- | ---------------- | ------- | ------------------------------------------------------------------------------------------------ |
| `apply`           | `boolean`        | `false` | When false, dry-run: write plan rows, mutate nothing. Set true to actually delete.               |
| `expectAccount`   | `string`         | `""`    | If set, refuse to run unless the resolved account id matches — a wrong-account guardrail.         |
| `onlyRegion`      | `string`         | `""`    | If set, only act on orphans in this region (canary scoping).                                     |
| `onlyStack`       | `string`         | `""`    | If set, only act on this exact stack name (single-stack canary).                                 |
| `retainLogicalId` | `string`         | `""`    | Override the retained logical id; honored only if it equals the detected custom resource.        |
| `waitSeconds`     | `int` (2–60)     | `10`    | Seconds between `DescribeStacks` polls while waiting for deletion.                                |
| `maxWaits`        | `int` (1–120)    | `30`    | Maximum polls before giving up on a delete.                                                       |
| `verifyRole`      | `boolean`        | `true`  | After delete, `GetRole` on the captured role name to confirm removal.                            |
| `initiateOnly`    | `boolean`        | `false` | Fire the delete and return without polling to completion — for fast fleet fan-out.               |
| `predeleteLambda` | `boolean`        | `true`  | Delete the backing Lambda first so the custom resource deletes cleanly in one plain pass.        |

## Running a sweep

The `enumerate` method is read-only, so run it under a `*-readonly` profile.

```sh
swamp model create org-orphan-sweep \
  --type @jentz/aws-cfn-orphan-sweep \
  --global-args '{
    "namePrefix": "StackSet-IAMCustomPasswordPolicy-",
    "regions": ["us-east-1", "eu-west-1"],
    "profile": "account-readonly"
  }'

swamp model method run org-orphan-sweep enumerate
swamp model get org-orphan-sweep --json
```

Then preview a cleanup (dry-run, the default) before applying it from a profile
that can mutate:

```sh
# Dry-run: writes plan rows, touches nothing.
swamp model method run org-orphan-sweep cleanup

# Single-stack canary, then apply for real:
swamp model method run org-orphan-sweep cleanup \
  --args '{ "apply": true, "onlyStack": "StackSet-IAMCustomPasswordPolicy-111111111111-abc", "expectAccount": "111111111111" }'
```

## Required IAM permissions

`enumerate` is read-only — a `*-readonly` profile is sufficient:

- `cloudformation:ListStacks`
- `cloudformation:ListStackResources`
- `sts:GetCallerIdentity`

`cleanup` mutates, so run it from a `*-devops` (admin) profile that adds:

- `cloudformation:DeleteStack`
- `cloudformation:DescribeStacks`
- `lambda:DeleteFunction`
- `iam:GetRole`

A read-only profile deliberately cannot run `cleanup` with `apply=true`.

## Composing enumerate and cleanup in a workflow

Because each model run resolves its own `profile`, you can chain a read-only
inventory step and a mutating cleanup step in a swamp workflow under
least-privilege per step. Put any safety gate (e.g. a manual-approval step)
ahead of the cleanup, not inside this model.

```yaml
# workflow.yaml (illustrative)
steps:
  - name: enumerate
    model: org-orphan-sweep
    method: enumerate
    # runs under a *-readonly profile

  - name: cleanup
    model: org-orphan-sweep
    method: cleanup
    # apply=true; runs under a *-devops profile that can DeleteStack
    dependsOn:
      - step: enumerate
        on: succeeded
```

## Querying the output

Resources are written with infinite lifetime (the last 10 retained). Reference
a row from a downstream model or report via CEL:

```text
data.latest("<sweep-name>", "summary-<account>").attributes.orphanCount
data.latest("<sweep-name>", "orphan-<account>-<region>-<stack>").attributes.iamRolePhysicalName
data.latest("<sweep-name>", "deletion-<account>-<region>-<stack>").attributes.roleGone
```

## Out of scope

- Multi-account fan-out — the model is account-scoped; run it once per account
  (compose accounts in a workflow).
- Removing stacks outside the configured `namePrefix` — the guard refuses them.
- Retaining anything but the detected custom resource — the IAM role and Lambda
  are always deleted.
- Any analysis beyond the documented `orphan` / `summary` / `deletion` rows.
