# @jentz/aws-stackset-lifecycle

Write-side retirement operations for a CloudFormation StackSet, run from the
management / delegated-admin account. Two **mutating** methods —
`deleteInstances` and `deleteStackSet` — each a single locked execution that
polls its operation to a terminal state and writes one `result` resource.

The official [`@swamp/aws/cloudformation/stack-set`](https://github.com/systeminit/swamp-extensions)
(Cloud Control) type can create/update/delete a StackSet, but its delete tears
down **every** instance at once with **no batching and no `RetainStacks`
control** — unusable for a staged, low-blast-radius retirement. This model fills
that gap with the native CloudFormation StackSets API, as the mutating sibling
to the read-only [`@jentz/aws-stackset-audit`](../aws-stackset-audit) and
[`@jentz/aws-stackset-drift-detect`](../aws-stackset-drift-detect).

## Installing

The package is published to the swamp registry. Pull it into your repo:

```sh
swamp extension pull @jentz/aws-stackset-lifecycle
```

## What it does

### `deleteInstances` — batched `DeleteStackInstances`

Deletes the stack instances for an explicit set of deployment targets (OUs +
accounts) and regions, with an explicit `retainStacks` flag, then polls the
operation to a terminal state (`SUCCEEDED` | `FAILED` | `STOPPED`). Run it
batch-by-batch — a handful of accounts per run — so each member is only briefly
affected. The method throws (and records a `result` with the failure) if the
operation does not end `SUCCEEDED`.

A **safety guard** makes a fat-fingered fleet-wide delete impossible: an
account-scoped batch must list explicit accounts under
`accountFilterType=INTERSECTION`. Operating on a whole OU/root (no explicit
accounts, or a non-`INTERSECTION` filter) is refused unless you pass
`confirmWholeTarget: true`.

### `deleteStackSet` — `DeleteStackSet`

Deletes the stackset itself. It must already be empty, so run `deleteInstances`
over all targets first. Writes a single `result` resource recording the
deletion.

Each method writes one **`result`** resource: the `action`, `operationId`,
terminal `status` / `statusReason`, the `deploymentTargets` + `regions` +
`retainStacks` used, and `startedAt` / `finishedAt` timing — all queryable with
CEL.

## Global arguments

| Argument       | Type                          | Default        | Meaning                                                                                              |
| -------------- | ----------------------------- | -------------- | ---------------------------------------------------------------------------------------------------- |
| `stackSetName` | `string` (required, non-empty) | —              | The CloudFormation StackSet to operate on.                                                           |
| `callAs`       | `SELF` \| `DELEGATED_ADMIN`   | `SELF`         | `SELF` from the org management account; `DELEGATED_ADMIN` from a delegated administrator account.    |
| `region`       | `string`                      | `us-east-1`    | Region of the CloudFormation endpoint — the stackset admin region where the stackset object is homed (NOT the instance regions). |
| `profile`      | `string`                      | `""` (ambient) | Named AWS profile (resolved via `fromIni`). Empty uses the ambient credential chain.                 |

### `deleteInstances` arguments

| Argument                            | Type                                          | Default          | Meaning                                                                                          |
| ----------------------------------- | --------------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------ |
| `deploymentTargets.organizationalUnitIds` | `string[]`                              | `[]`             | Target OU ids (service-managed). For an INTERSECTION batch, the OU(s) the accounts live under.   |
| `deploymentTargets.accounts`        | `string[]` (each 12 digits)                   | `[]`             | Explicit 12-digit member account ids for this batch.                                             |
| `deploymentTargets.accountFilterType` | `NONE` \| `UNION` \| `INTERSECTION` \| `DIFFERENCE` | `INTERSECTION` | How accounts and OUs combine. `INTERSECTION` is the safe batched shape.                          |
| `regions`                           | `string[]` (≥ 1)                              | —                | Instance regions to delete in this account set.                                                  |
| `retainStacks`                      | `boolean` (required)                          | —                | `false` = delete member stacks and their resources; `true` = keep resources, only detach.        |
| `confirmWholeTarget`                | `boolean`                                     | `false`          | Safety guard. Must be `true` to delete a whole OU/root with no explicit account list.            |
| `pollSeconds`                       | `int` (5–300)                                 | `15`             | Seconds between operation status polls.                                                          |
| `maxPolls`                          | `int` (1–360)                                 | `120`            | Maximum status polls before timing out.                                                          |

### `deleteStackSet` arguments

| Argument      | Type          | Default | Meaning                                  |
| ------------- | ------------- | ------- | ---------------------------------------- |
| `pollSeconds` | `int` (5–300) | `15`    | Seconds between operation status polls.  |
| `maxPolls`    | `int` (1–360) | `120`   | Maximum status polls before timing out.  |

## Running a retirement

Retire the fleet batch-by-batch, then delete the empty stackset.

```sh
swamp model create my-stackset-lifecycle \
  --type @jentz/aws-stackset-lifecycle \
  --global-args '{
    "stackSetName": "DemoSet",
    "callAs": "SELF",
    "profile": "org-management-admin"
  }'

# Delete one batch of accounts (the safe INTERSECTION shape).
swamp model method run my-stackset-lifecycle deleteInstances \
  --args '{
    "deploymentTargets": {
      "organizationalUnitIds": ["ou-root-abc123"],
      "accounts": ["111111111111", "222222222222"],
      "accountFilterType": "INTERSECTION"
    },
    "regions": ["eu-west-1", "us-east-1"],
    "retainStacks": false
  }'

# Repeat for each batch, then delete the empty stackset.
swamp model method run my-stackset-lifecycle deleteStackSet
swamp model get my-stackset-lifecycle --json
```

To delete a whole OU/root in one shot (rather than an account-scoped batch), you
must opt in explicitly:

```sh
swamp model method run my-stackset-lifecycle deleteInstances \
  --args '{
    "deploymentTargets": {
      "organizationalUnitIds": ["ou-root-abc123"],
      "accountFilterType": "UNION"
    },
    "regions": ["us-east-1"],
    "retainStacks": false,
    "confirmWholeTarget": true
  }'
```

## Required IAM permissions

These methods are **mutating** — a `*-readonly` profile cannot run them, by
design. The profile needs the stackset admin role plus:

- `cloudformation:DeleteStackInstances`
- `cloudformation:DescribeStackSetOperation` (to poll the operation)
- `cloudformation:DeleteStackSet`

## Credentials

Auth mirrors the [`@jentz/aws-stackset-audit`](../aws-stackset-audit) sibling: an
optional named `profile` (resolved via `fromIni`) or the ambient credential
chain.

### SSO: export credentials into the env first

`fromIni` does **not** read the AWS SSO token cache. If your admin credentials
come from SSO, export them into the environment first and leave `profile` empty
(so the model picks up the ambient chain):

```sh
eval "$(aws configure export-credentials --profile <your-sso-profile> --format env)"
# then leave "profile": "" in the model's global arguments
```

If instead you use a static or assumed-role profile recorded in
`~/.aws/credentials` / `~/.aws/config`, set `profile` to that profile name and
`fromIni` resolves it directly.

### Read vs. write profile split

These methods need write permissions (`cloudformation:DeleteStackInstances` /
`DeleteStackSet`) plus the stackset admin role. The read-only audit and
drift-detect siblings run under a `*-readonly` profile; this lifecycle model
deliberately cannot. When composing them in a swamp workflow, give each step its
own `profile` so the audit step stays least-privilege while only the
delete step carries the admin profile.

## Querying the output

Resources are written with infinite lifetime (the last 20 retained). Reference a
row from a downstream model or report via CEL:

```text
data.latest("<lifecycle-name>", "delete-instances-<operationId>").attributes.status
data.latest("<lifecycle-name>", "delete-stackset-<stackSetName>").attributes.finishedAt
```

## Out of scope

- Any read/list/describe of the stackset or its instances — that is the
  read-only [`@jentz/aws-stackset-audit`](../aws-stackset-audit) sibling.
- Creating or updating a StackSet — use the official
  `@swamp/aws/cloudformation/stack-set` Cloud Control type.
- Triggering fresh drift detection — that is the separate
  [`@jentz/aws-stackset-drift-detect`](../aws-stackset-drift-detect) sibling.
- A composing retire-then-verify workflow — author it as a swamp workflow that
  wires these methods together with per-step profiles.
