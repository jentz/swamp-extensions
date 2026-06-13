# @jentz/aws-stackset-drift-detect

Trigger CloudFormation StackSet drift detection and record its outcome — the
**write-side** sibling of
[`@jentz/aws-stackset-audit`](../aws-stackset-audit). A single mutating `detect`
method starts a `DetectStackSetDrift` operation, polls it to a terminal state,
and writes one `operation` resource capturing the result.

It does **not** audit or re-read stack instances. Measuring drift (write) and
reading the result (read) are deliberately split into two extensions that
compose in a swamp workflow — see
[Workflow composition](#workflow-composition-with-the-audit-sibling).

## What it does

The `detect` method, in one locked execution:

1. `DetectStackSetDrift` — starts a drift-detection operation for the configured
   stackset (honoring `callAs`) and obtains its operation id.
2. `DescribeStackSetOperation` — polls the operation until it reaches a terminal
   state (`SUCCEEDED` | `FAILED` | `STOPPED`) or the poll budget (`maxPolls`) is
   exhausted.
3. Writes exactly one **`operation`** resource capturing the outcome.

Reaching a terminal `FAILED` / `STOPPED` state does **not** error — that is a
legitimate operation outcome and is recorded on the `operation` resource. Only
exhausting the poll budget errors, naming the last observed status.

This model performs **no** instance audit and writes **no** `summary` /
`instance` resources — that is the read-only `@jentz/aws-stackset-audit`.

### `operation` resource

One row per drift-detection run, keyed by the operation id:

- `stackSetName` — the stackset the operation ran on (echoed from the global
  args)
- `operationId` — the id returned by `DetectStackSetDrift` (also the resource
  key)
- `action` — the operation action (`DETECT_DRIFT`)
- `status` — the terminal status reached (`SUCCEEDED` | `FAILED` | `STOPPED`)
- `creationTimestamp`, `endTimestamp` — ISO-8601, or `""` when absent
- `statusReason` — human-readable reason, or `""`

## Global arguments

The global-args shape is **identical** to `@jentz/aws-stackset-audit`, so a
workflow wires the same inputs into both the detect step and the audit step.

| Argument       | Type                           | Default        | Meaning                                                                                              |
| -------------- | ------------------------------ | -------------- | ---------------------------------------------------------------------------------------------------- |
| `stackSetName` | `string` (required, non-empty) | —              | The CloudFormation StackSet to run drift detection on.                                               |
| `callAs`       | `SELF` \| `DELEGATED_ADMIN`    | `SELF`         | `SELF` from the org management account; `DELEGATED_ADMIN` from a delegated administrator account.    |
| `region`       | `string`                       | `us-east-1`    | Region of the CloudFormation endpoint. StackSet metadata is global to the admin account.             |
| `profile`      | `string`                       | `""` (ambient) | Named AWS profile (resolved via `fromIni`). Empty uses the ambient credential chain (`AWS_PROFILE`). |

The `detect` method takes two arguments:

| Argument      | Type           | Default | Meaning                                            |
| ------------- | -------------- | ------- | -------------------------------------------------- |
| `pollSeconds` | `int` (5–300)  | `20`    | Seconds between operation status polls.            |
| `maxPolls`    | `int` (1–360)  | `90`    | Maximum status polls before the run times out.     |

## Running drift detection

This method is **mutating** — run it under an admin profile that can call
`DetectStackSetDrift` (see [Required IAM permissions](#required-iam-permissions)).

```sh
swamp model create my-stackset-drift-detect \
  --type @jentz/aws-stackset-drift-detect \
  --global-args '{
    "stackSetName": "DemoOrgSetup",
    "callAs": "SELF",
    "profile": "org-management-admin"
  }'

swamp model method run my-stackset-drift-detect detect
swamp model get my-stackset-drift-detect --json
```

## Required IAM permissions

This is a **mutating** extension. It needs **write** credentials plus the
stackset admin role — a `*-readonly` profile **cannot** run it, by design:

- `cloudformation:DetectStackSetDrift`
- `cloudformation:DescribeStackSetOperation`
- the StackSet administration role (and, for self-managed stacksets, the
  per-account execution role) that drift detection assumes into each member
  account

If the profile lacks these, the `detect` method fails closed and surfaces the
AWS error rather than masking it.

## Workflow composition with the audit sibling

Measuring drift (this extension, write) and reading the result
(`@jentz/aws-stackset-audit`, read) are split so the audit stays runnable under
a `*-readonly` profile. Compose them in a swamp workflow: run this `detect` step
**first**, then the audit step with a `succeeded` dependency edge, so the audit
reads the refreshed per-instance `driftStatus` straight from AWS.

No CEL data handoff is required for correctness — the ordering edge is
sufficient. Because each model resolves its own `profile`, the detect step runs
under an admin profile while the audit step runs under a `*-readonly` profile —
least privilege per step. Any safety gate (e.g. a manual-approval step) belongs
in the workflow, ahead of this mutating step, not in the extension.

```yaml
# workflow.yaml (illustrative)
steps:
  - name: detect-drift
    model: my-stackset-drift-detect      # @jentz/aws-stackset-drift-detect (this extension)
    method: detect
    # runs under an admin profile that can call DetectStackSetDrift

  - name: audit
    model: my-stackset-audit             # @jentz/aws-stackset-audit (read-only sibling)
    method: audit
    dependsOn:
      - step: detect-drift
        on: succeeded
    # runs under a *-readonly profile
```

## Querying the output

The `operation` resource is written with infinite lifetime (the last 10
retained), keyed by its operation id. Because that key is generated at run time,
reference the operations by spec from a downstream model or report — `findBySpec`
returns the recorded operation rows, each carrying `status`, `statusReason`,
`action`, and the timestamps:

```text
data.findBySpec("<detect-name>", "operation")
```

## Out of scope

- Reading / auditing stack instances or writing `summary` / `instance`
  resources — that is `@jentz/aws-stackset-audit`.
- Stack-level drift (`DetectStackDrift`) or any non-StackSet drift — **StackSet
  drift only**.
- Authoring the composing workflow itself — this extension ships the model; a
  workflow that chains detect → audit is separate.
