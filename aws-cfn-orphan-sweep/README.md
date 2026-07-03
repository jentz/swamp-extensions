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

Four methods:

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

### `enumerateOrg` (read-only, cross-account)

The recommended first action for an org-wide inventory. Run it **once** from the
management account. It:

1. Discovers the org's ACTIVE member accounts via Organizations `ListAccounts`
   (paginated, `ACTIVE`-only).
2. For each account, builds a per-account credential set and reuses the same
   `enumerate` logic to sweep it. The **management account uses the ambient (or
   `profile`) credentials directly — it is never self-assumed**; every other
   member is reached by assuming the uniformly-named `assumeRoleName` role
   (default `AWSControlTowerExecution`) into it.
3. Writes the same per-account `orphan` / `summary` rows (keyed by account) plus
   one **`org-summary`** rollup.

It is read-only — `enumerate`'s `List*` permissions plus
`organizations:ListAccounts` and `sts:AssumeRole` into the member role.

Failure handling is **skip, don't abort**: if assuming into a member account or
sweeping it fails, that account is recorded in `org-summary.failures` and the
run continues with the rest. Only a failure to discover the org itself
(`GetCallerIdentity` or `ListAccounts`) is fatal — you cannot iterate an org you
cannot enumerate.

The `onlyAccount` argument restricts the sweep to a single member account (a
canary); `accountsDiscovered` still reports the full ACTIVE org count even when
narrowed.

> Accounts are swept **sequentially** today. Bounded concurrency is a future
> optimization.

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

### `cleanupOrg` (mutating, cross-account; dry-run unless `apply=true`)

The org-wide sibling of `cleanup`. Run it **once** from the management account;
it discovers the org's ACTIVE member accounts (like `enumerateOrg`), assumes
`assumeRoleName` into each member (the management account uses the ambient or
`profile` creds directly — never self-assumed), and reuses the per-account
`cleanup` to delete the orphans fleet-wide.

Each member account is run with an internal `expectAccount` landing check set to
that account's id, so if the assumed credentials resolve to a *different*
account the per-account cleanup refuses before writing any deletion row — a
misconfigured role can never delete in the wrong account. Per-account failures
are recorded in `org-summary.failures` and skipped, never fatal.

It takes the same tuning knobs as `cleanup` (minus `expectAccount`, which the
driver owns) plus the `onlyAccount` canary. It writes the per-account `deletion`
rows plus one `org-summary` rollup with aggregate cleanup counters
(`considered` / `deleted` / `initiated` / `skipped` / `errors`).

Run `enumerateOrg` first to inventory the fleet, then `cleanupOrg` with
`apply=false` (the default) to preview, then — ideally after an `onlyAccount`
canary — `apply=true` to delete. Accounts are swept sequentially today.

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

### `org-summary` resource

One cross-account rollup written by `enumerateOrg` or `cleanupOrg`, keyed
`org-summary-${managementAccount}`:

- `managementAccount` — the account the run was driven from
- `assumeRoleName` — the role assumed into each member account
- `accountsDiscovered` — ACTIVE accounts found in the org (full count, even when
  `onlyAccount` narrows the run)
- `accountsProcessed` — accounts actually swept
- `accountsFailed` — accounts whose assume/sweep failed and were skipped
- `failures` — `[{ account, name, error }]` for each skipped account
- `totalOrphans` — orphan stacks found across every processed account (for
  `cleanupOrg`, the scoped targets considered)
- `regionsScanned`, `mode` (`"enumerate"` or `"cleanup"`), `applied`
- `scannedAt` — ISO-8601 timestamp

`cleanupOrg` additionally writes the aggregate cleanup counters `considered`,
`deleted`, `initiated`, `skipped`, and `errors`; `enumerateOrg` omits them. The
schema is a passthrough, so either writer can add fields without a breaking
change.

## Global arguments

| Argument     | Type                            | Default                              | Meaning                                                                                              |
| ------------ | ------------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| `namePrefix` | `string` (required, non-empty)  | `StackSet-IAMCustomPasswordPolicy-`  | Only stacks whose name starts with this prefix are enumerated or ever considered for deletion.       |
| `regions`    | `string[]` (required, non-empty) | `us-east-1`, `eu-west-1`, `eu-central-1`, `eu-north-1` | Regions to fan out across in one execution.                                                          |
| `profile`    | `string`                        | `""` (ambient)                       | Named AWS profile (resolved via `fromIni`). Empty uses the ambient credential chain (`AWS_*` env).   |
| `assumeRoleName` | `string` (required, non-empty) | `AWSControlTowerExecution`        | Role name `enumerateOrg` assumes into each member account (must exist with this name in every member). Unused by the single-account methods. |

The `enumerateOrg` method takes one argument:

| Argument      | Type     | Default | Meaning                                                                                              |
| ------------- | -------- | ------- | ---------------------------------------------------------------------------------------------------- |
| `onlyAccount` | `string` | `""`    | If set, restrict the sweep to this one member account (canary). `accountsDiscovered` still reflects the full ACTIVE org count. |

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

The `cleanupOrg` method takes the same arguments as `cleanup` except
`expectAccount` (the driver sets it internally per member account), plus
`onlyAccount` with the same canary semantics as on `enumerateOrg`.

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

For an org-wide inventory, run `enumerateOrg` once from the management account
instead. Set `profile` to the management account's read-only creds and
`assumeRoleName` to a role that exists in every member account:

```sh
swamp model create org-orphan-sweep \
  --type @jentz/aws-cfn-orphan-sweep \
  --global-args '{
    "namePrefix": "StackSet-IAMCustomPasswordPolicy-",
    "regions": ["us-east-1", "eu-west-1"],
    "profile": "management-readonly",
    "assumeRoleName": "AWSControlTowerExecution"
  }'

# Sweep the whole org (sequential per account):
swamp model method run org-orphan-sweep enumerateOrg

# Canary one member account first:
swamp model method run org-orphan-sweep enumerateOrg \
  --args '{ "onlyAccount": "222222222222" }'
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

For an org-wide cleanup, run `cleanupOrg` from the management account with a
profile that can mutate. Preview first, canary one account, then apply:

```sh
# Dry-run across the whole org (the default): plan rows only.
swamp model method run org-orphan-sweep cleanupOrg

# Apply in a single canary account first:
swamp model method run org-orphan-sweep cleanupOrg \
  --args '{ "apply": true, "onlyAccount": "222222222222" }'

# Then apply fleet-wide:
swamp model method run org-orphan-sweep cleanupOrg --args '{ "apply": true }'
```

## Required IAM permissions

`enumerate` is read-only — a `*-readonly` profile is sufficient:

- `cloudformation:ListStacks`
- `cloudformation:ListStackResources`
- `sts:GetCallerIdentity`

`enumerateOrg` is also read-only. The management-account profile adds, on top of
the `enumerate` permissions:

- `organizations:ListAccounts`
- `sts:AssumeRole` into `assumeRoleName` in each member account

and the assumed role in each member account needs the `enumerate` read-only
permissions above.

`cleanup` mutates, so run it from a `*-devops` (admin) profile that adds:

- `cloudformation:DeleteStack`
- `cloudformation:DescribeStacks`
- `lambda:DeleteFunction`
- `iam:GetRole`

`cleanupOrg` mutates fleet-wide. The management-account profile needs the
`cleanup` permissions plus `organizations:ListAccounts` and `sts:AssumeRole`
into `assumeRoleName` in each member account, and the assumed role in each
member account needs the `cleanup` permissions above.

A read-only profile deliberately cannot run `cleanup` or `cleanupOrg` with
`apply=true`.

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
data.latest("<sweep-name>", "org-summary-<management-account>").attributes.totalOrphans
```

## Out of scope

- Bounded-concurrency org sweeps — `enumerateOrg` and `cleanupOrg` iterate
  accounts sequentially today; parallelism is a future optimization.
- Removing stacks outside the configured `namePrefix` — the guard refuses them.
- Retaining anything but the detected custom resource — the IAM role and Lambda
  are always deleted.
- Any analysis beyond the documented `orphan` / `summary` / `deletion` /
  `org-summary` rows.
