# @jentz/aws-s3-bucket-audit

Workflow-scope swamp report that audits S3 buckets against standard security
best practices. Pairs with the upstream `@swamp/aws/s3` extension: earlier
workflow steps fetch bucket state and bucket policies; this report consumes
those step outputs and produces structured, lint-style findings.

## What it checks

Eight rules across three severities:

| Rule ID                                        | Severity | Pass condition                                                                                                                                                                |
| ---------------------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bucket-versioning-enabled`                    | error    | `VersioningConfiguration.Status == "Enabled"`                                                                                                                                 |
| `bucket-encryption-enabled`                    | error    | At least one default encryption rule (`AES256`, `aws:kms`, or `aws:kms:dsse`)                                                                                                 |
| `bucket-public-access-blocked`                 | error    | All four BPA flags `true` (`BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets`)                                                               |
| `bucket-ownership-enforced`                    | error    | `OwnershipControls.Rules` contains `ObjectOwnership: BucketOwnerEnforced` (ACLs disabled)                                                                                     |
| `bucket-tls-only-policy`                       | error    | Bucket policy includes a Deny with `Principal: *`, `Action: s3:*`, `Resource` covering both bucket ARN and `bucket/*`, and `Condition: Bool { aws:SecureTransport: "false" }` |
| `bucket-lifecycle-expires-noncurrent-versions` | warn     | At least one enabled lifecycle rule expires noncurrent object versions                                                                                                        |
| `bucket-server-access-logging`                 | warn     | Logging configured with a destination bucket that is NOT the source bucket                                                                                                    |
| `bucket-tag-inventory`                         | info     | Tag presence is reported; absence emits a `warn` status (informational, see notes)                                                                                            |

References for all rules:
[AWS S3 security best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html).

## Installation

```sh
swamp extension pull @jentz/aws-s3-bucket-audit
```

## Required IAM permissions

The report does not call AWS APIs directly — it reads data produced by upstream
workflow steps. Grant these to the principal running the **upstream**
`@swamp/aws/s3/bucket` and `@swamp/aws/s3/bucket-policy` lookups:

- `s3:GetBucketVersioning`
- `s3:GetEncryptionConfiguration`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetBucketOwnershipControls`
- `s3:GetBucketPolicy`
- `s3:GetLifecycleConfiguration`
- `s3:GetBucketLogging`
- `s3:GetBucketTagging`

The AWS-managed `ReadOnlyAccess` and `SecurityAudit` policies cover the full
set.

## Quick example

A complete audit workflow fans bucket lookups out via `forEach`, then attaches
this report via `reports: require:`:

```yaml
name: audit-tf-state-buckets
inputs:
  properties:
    expectedAccountId:
      type: string
      default: "123456789012"
    bucketNames:
      type: array
      items: { type: string }
      minItems: 1
      default:
        - my-iac-state-bucket
jobs:
  - name: guard
    steps:
      - name: verify-context
        task:
          type: model_method
          modelIdOrName: aws-guard
          methodName: verify
        allowFailure: false
  - name: lookup
    steps:
      - name: bucket-state-${{ self.bucketName }}
        forEach: { item: bucketName, in: ${{ inputs.bucketNames }} }
        task:
          type: model_method
          modelType: "@swamp/aws/s3/bucket"
          modelName: "audit-bucket-${{ self.bucketName }}"
          methodName: get
          inputs:
            identifier: ${{ self.bucketName }}
      - name: bucket-policy-${{ self.bucketName }}
        forEach: { item: bucketName, in: ${{ inputs.bucketNames }} }
        task:
          type: model_method
          modelIdOrName: audit-bucket-policy
          methodName: get
          inputs:
            identifier: ${{ self.bucketName }}
        allowFailure: true  # buckets with no policy still get audited
    dependsOn:
      - { job: guard, condition: { type: succeeded } }
reports:
  require:
    - "@jentz/aws-s3-bucket-audit"
```

The first job uses [`@jentz/aws-context-guard`](../aws-context-guard/) to fail
closed if `AWS_PROFILE`/account don't match. The second job fans out one
`audit-bucket-*` instance per bucket so they run in parallel. The report at the
bottom is workflow-scope: it runs once after all step output is collected.

## How the report finds data

The report iterates `context.stepExecutions` and matches by `modelType`:

- Bucket state: steps whose `modelType == "@swamp/aws/s3/bucket"`
- Bucket policy: steps whose `modelType == "@swamp/aws/s3/bucket-policy"`

State and policy are paired by bucket name (`BucketName` from state, `Bucket`
from policy). If a bucket has state but no policy (or vice versa), the missing
side becomes a `skip`-status finding rather than a workflow failure. If a step
failed entirely, the bucket name is recovered from the step's
`methodArgs.identifier` so a failed lookup still produces a finding.

## Output

The report emits two artifacts:

**Markdown** — human-readable, one section per bucket with a findings table.
Suitable for posting in a PR or saving as evidence.

**JSON** — machine-readable. Shape:

```ts
{
  report: "@jentz/aws-s3-bucket-audit",
  workflow: string,
  generatedAt: string,           // ISO-8601
  failOn: "none" | "error" | "warn" | "info",
  gateTripped: boolean,
  tripperCount: number,
  trippers: Array<{
    bucket: string,
    id: string,                  // rule id
    severity: "error" | "warn" | "info",
    status: "fail" | "warn",
  }>,
  summary: {
    buckets: number,
    pass: number,
    fail: number,
    warn: number,
    skip: number,
    errors: number,
    warns: number,
    infos: number,
  },
  buckets: Array<{ name: string, findings: Finding[] }>,
  findings: Finding[],           // flat list across buckets
}
```

A `Finding` carries `id`, `severity`, `status`, `bucket`, `actual` (observed
values), `expected` (target values), `message`, and `references` (AWS docs
URLs).

## The `failOn` gate

The report is workflow-scope; swamp catches and logs thrown report errors but
does **not** fail the workflow run (and discards the report's data on throw). So
the gate is surfaced in the JSON output instead of as an exception.

Threshold is configured via the `S3_BUCKET_AUDIT_FAILON` env var:

| Value             | Trips on                                                         |
| ----------------- | ---------------------------------------------------------------- |
| `none`            | never trips (report-only)                                        |
| `error` (default) | any error-severity finding with status `fail` or `warn`          |
| `warn`            | any error- or warn-severity finding with status `fail` or `warn` |
| `info`            | any finding with status `fail` or `warn`                         |

```sh
S3_BUCKET_AUDIT_FAILON=warn swamp workflow run audit-tf-state-buckets
```

When the gate trips, the JSON output sets `gateTripped: true` and populates
`trippers` with the first 5 findings that crossed the threshold; the workflow
logs include a WARN line naming them.

### Failing CI/CD on gate trips

To turn a tripped gate into a non-zero exit code (so CI fails the build), pair
this report with a small shell wrapper that reads the JSON output. Example:

```sh
#!/usr/bin/env bash
# audit-gate.sh — exit 1 when the report's gate tripped
set -euo pipefail
workflow="${1:?usage: audit-gate.sh <workflow-name>}"
output=$(swamp data get reports "$workflow" 2>/dev/null | jq -r '.json')
gate_tripped=$(echo "$output" | jq -r '.gateTripped')
if [ "$gate_tripped" = "true" ]; then
  echo "$output" | jq -r '.trippers[]' >&2
  exit 1
fi
```

```sh
swamp workflow run audit-tf-state-buckets \
  && audit-gate.sh audit-tf-state-buckets
```

## Failure modes

| Symptom                                      | Likely cause                                                                                                                                         | Fix                                                                                                                         |
| -------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Report runs but finds no buckets             | No step in the workflow has `modelType == "@swamp/aws/s3/bucket"` (or `"@swamp/aws/s3/bucket-policy"`).                                              | Add the bucket-state / bucket-policy lookup steps before the report.                                                        |
| Every finding is `skip`                      | Step ran but data file is missing or unparseable.                                                                                                    | Check `.swamp/data/` for the rendered `raw` files; verify upstream extension version.                                       |
| TLS-only-policy passes despite a narrow Deny | The Deny statement is properly scoped (Principal `*`, Action `s3:*`, Resource covers both ARNs, Condition matches). The check is strict on all four. | Read the rule definition in `reports/s3_bucket_audit.ts` — if your policy looks correct, file an issue with the policy doc. |
| Report data is empty after a `throw`         | A previous version of the report threw on gate trip; current behavior surfaces the gate via JSON only.                                               | Upgrade to the current version.                                                                                             |

## Versioning

Uses swamp Calendar Versioning (`YYYY.MM.DD.MICRO`). Breaking changes — adding a
new rule with default `error` severity, renaming a rule id, removing a field
from the JSON output — bump the date and carry release notes. Adding info/warn
rules, tightening a check's semantics, or extending the JSON output additively
is not considered breaking.

## Issues, contributing, license

- Bugs and feature requests: <https://github.com/jentz/swamp-extensions/issues>
- Source:
  <https://github.com/jentz/swamp-extensions/tree/main/aws-s3-bucket-audit>
- License: MIT (see [LICENSE.md](LICENSE.md))
