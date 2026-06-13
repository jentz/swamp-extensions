# @jentz/aws-stackset-audit

Read-only operational audit of a CloudFormation StackSet and all of its stack
instances across accounts and regions. A single `audit` method fans out in one
execution and writes one `summary` resource plus one `instance` resource per
stack instance — deployment status, drift, operation history, root causes, and
a derived safe-to-reapply verdict, all queryable with CEL.

The official [`@swamp/aws/cloudformation/stack-set`](https://github.com/systeminit/swamp-extensions)
type wraps the Cloud Control API, so it only sees the StackSet *resource*
(config + template) — not per-instance deployment status, operation history, or
drift. This model fills that gap using the native CloudFormation API.

## What it does

The `audit` method, in one locked execution:

1. `DescribeStackSet` — reads the stackset config and the drift-detection
   rollup.
2. `ListStackInstances` — paginates every stack instance across every
   `account × region` the stackset targets (no account ids are ever hardcoded;
   targeting is derived from the stackset).
3. `ListStackSetOperations` — reads the most recent operations (capped by the
   `recentOperations` method argument).

It then classifies each instance, rolls everything up, and writes:

- one **`summary`** resource, and
- one **`instance`** resource per stack instance.

Read-only: only `Describe*` / `List*` are ever called. The audit reports each
instance's **existing** drift status exactly as the StackSet API returns it — it
**never** triggers a fresh drift-detection run. See
[Drift detection is a separate extension](#drift-detection-is-a-separate-extension).

### `summary` resource

One row per audit:

- StackSet config: `stackSetId`, `status`, `permissionModel`, `description`,
  `organizationalUnitIds`, `capabilities`, `autoDeploymentEnabled`,
  `managedExecutionActive`, `parameters`
- `drift` — the StackSet-level drift-detection rollup as last measured
- `regions`, `accountsTargeted`, `instanceCount`
- per-dimension counts: `byDetailedStatus`, `byOverallStatus`, `byRegion`,
  `byDriftStatus`, `byFailureCategory`
- `operations` — recent stackset operations
- `rootCauses` — failed instances grouped by normalized failure category,
  ranked by count
- `detectedPatterns` — cross-instance anti-patterns the per-instance view
  cannot express (e.g. a global IAM resource colliding across regions, or drift
  never having been measured)
- `safeToReapply` — a conservative `{ verdict, reasons, remediation }` verdict
- `auditedAt` — ISO-8601 timestamp

The `safeToReapply.verdict` is one of `yes` | `no` | `caution` | `unknown`. An
in-flight operation or a known structural conflict (such as a global IAM-name
multi-region collision) blocks a clean `yes`.

### `instance` resource

One row per stack instance, keyed `instance-${account}-${region}`:

- `account`, `region`, `detailedStatus`, `overallStatus`, `statusReason`
- `driftStatus`, `lastDriftCheckTimestamp` (the existing drift status, as read)
- `stackId`, `organizationalUnitId`
- `failureCategory` — a normalized classification (`none`, `iam-name-conflict`,
  `resource-already-exists`, `access-denied`, `cancelled`, `in-progress`, …)
- `auditedAt`

## Global arguments

| Argument       | Type                          | Default       | Meaning                                                                                              |
| -------------- | ----------------------------- | ------------- | ---------------------------------------------------------------------------------------------------- |
| `stackSetName` | `string` (required, non-empty) | —             | The CloudFormation StackSet to audit.                                                                |
| `callAs`       | `SELF` \| `DELEGATED_ADMIN`   | `SELF`        | `SELF` from the org management account; `DELEGATED_ADMIN` from a delegated administrator account.    |
| `region`       | `string`                      | `us-east-1`   | Region of the CloudFormation endpoint. StackSet metadata is global to the admin account.             |
| `profile`      | `string`                      | `""` (ambient) | Named AWS profile (resolved via `fromIni`). Empty uses the ambient credential chain (`AWS_PROFILE`). |

The `audit` method takes one argument:

| Argument           | Type                  | Default | Meaning                                          |
| ------------------ | --------------------- | ------- | ------------------------------------------------ |
| `recentOperations` | `int` (1–100)         | `15`    | How many recent stackset operations to capture.  |

## Running an audit

Create the model with global arguments, then run the single `audit` method. The
audit is read-only, so run it under a `*-readonly` profile.

```sh
swamp model create my-stackset-audit \
  --type @jentz/aws-stackset-audit \
  --global-args '{
    "stackSetName": "DemoOrgSetup",
    "callAs": "SELF",
    "profile": "org-management-readonly"
  }'

swamp model method run my-stackset-audit audit
swamp model get my-stackset-audit --json
```

## Required IAM permissions

Read-only — a `*-readonly` profile is sufficient:

- `cloudformation:DescribeStackSet`
- `cloudformation:ListStackInstances`
- `cloudformation:ListStackSetOperations`

This model never calls `cloudformation:DetectStackSetDrift` or any other
mutating API.

## Drift detection is a separate extension

This audit **reads** each instance's existing drift status; it does **not**
measure drift. Triggering a fresh drift-detection run is a **mutating**
capability — it requires `cloudformation:DetectStackSetDrift` plus the stackset
admin role, which a read-only profile deliberately cannot do. That capability
ships as a separate, sibling drift-detection extension.

When per-instance `driftStatus` is `NOT_CHECKED`, the audit emits the
`drift-never-detected` anti-pattern: the drift posture is *unknown*, which is not
the same as "in sync".

To refresh drift before auditing, compose the two extensions in a swamp workflow:
run the drift-detection step first, then this audit step with a `succeeded`
dependency edge, so the audit reads the refreshed status. Because each model
resolves its own `profile`, the drift-detect step can run under an admin profile
while this audit step runs under a `*-readonly` profile — least privilege per
step. Any safety gate (e.g. a manual-approval step) belongs in the workflow,
ahead of the mutating drift-detect step, not in this read-only model.

```yaml
# workflow.yaml (illustrative — the drift-detect type is the sibling extension)
steps:
  - name: detect-drift
    model: stackset-drift-detect       # @jentz/aws-stackset-drift-detect (sibling)
    method: detect_drift
    # runs under an admin profile that can call DetectStackSetDrift

  - name: audit
    model: my-stackset-audit           # @jentz/aws-stackset-audit (this extension)
    method: audit
    dependsOn:
      - step: detect-drift
        on: succeeded
    # runs under a *-readonly profile
```

## Querying the output

Resources are written with infinite lifetime (the last 10 retained). Reference a
row from a downstream model or report via CEL:

```text
data.latest("<audit-name>", "summary").attributes.safeToReapply.verdict
data.latest("<audit-name>", "instance-<account>-<region>").attributes.driftStatus
```

## Out of scope

- Any AWS write or mutation — the model is strictly read-only.
- Triggering fresh drift detection — that is the separate sibling extension.
- Multi-stackset fan-out or org-wide discovery — one StackSet per run,
  parameterized via global arguments.
- Any new analysis beyond the documented summary dimensions and verdict.
