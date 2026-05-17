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

## What this does NOT check

A passing audit is necessary but not sufficient. The following controls are
deliberately out of scope for this extension and must be evaluated separately:

- **MFA Delete** — strongly recommended for state buckets and other
  irreplaceable data. Cannot be enabled via the console and requires the root
  account or a dedicated tool to configure; not exposed via the bucket-state
  lookups this report consumes.
- **Object Lock / retention configuration** — required for several compliance
  regimes (SEC 17a-4, HIPAA). Not evaluated here.
- **KMS key rotation** — when `bucket-encryption-enabled` passes with `aws:kms`,
  this audit does not check whether the key is customer-managed (vs. AWS-managed
  `aws/s3`) nor whether automatic rotation is enabled. Both checks would require
  a separate KMS lookup.
- **Replication configuration** — cross-region replication and same-region
  replication are not evaluated.
- **Minimum TLS version** — `bucket-tls-only-policy` ensures _some_ TLS is
  required (`aws:SecureTransport=false` is denied) but does not enforce TLS 1.2+
  via `aws:SecureTransportVersion`. AWS guidance is trending toward an explicit
  minimum-version requirement.
- **Over-broad `Allow` statements** — the TLS check confirms the presence of a
  Deny, but does not flag bucket policies that grant `s3:*` to `Principal: *`
  outside that Deny pattern.
- **CloudTrail data events / server-access logging analytics** — logging is
  checked for existence only; whether it is actually being ingested and alerted
  on is out of scope.
- **`Public` ACL / object ownership at the object level** — this audit evaluates
  the bucket-level controls (Object Ownership = BucketOwnerEnforced disables
  ACLs entirely) but does not enumerate per-object ACLs.

A "PASS" from this audit means the eight evaluated controls match recommended
values for the audited bucket — not that the bucket is secure under every threat
model.

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
          modelType: "@swamp/aws/s3/bucket-policy"
          modelName: "audit-bucket-policy-${{ self.bucketName }}"
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
from policy). Missing data is handled per-rule:

- If bucket **state** is missing or unparseable, every state-dependent rule
  emits `skip` (no data to evaluate against).
- If the bucket **policy** lookup failed or returned no policy, the
  `bucket-tls-only-policy` rule emits `fail`. No policy means no TLS enforcement
  exists, which is a real audit failure rather than an unknown.
- If a step failed entirely (or its data is missing / schema-mismatched), the
  bucket name is recovered from the step's `methodArgs.identifier` so the bucket
  still appears in the report with a populated `stateError` or `policyError`,
  rather than silently disappearing.

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
`trippers` with **every** finding that crossed the threshold. The workflow log
includes a single WARN line naming the first five (the JSON is the
machine-readable source of truth).

### Failing CI/CD on gate trips

To turn a tripped gate into a non-zero exit code (so CI fails the build), pair
this report with a small shell wrapper that reads the JSON output. The wrapper
below distinguishes a tripped gate (`exit 1`) from infrastructure problems
(`exit 2`) — silencing errors hides bugs in CI, so we let them surface.

```sh
#!/usr/bin/env bash
# audit-gate.sh — exit non-zero when the S3 bucket audit gate tripped.
#   exit 0  gate did not trip
#   exit 1  gate tripped
#   exit 2  report data could not be read (missing workflow, bad JSON, etc.)
set -euo pipefail

workflow="${1:?usage: audit-gate.sh <workflow-name>}"

if ! output=$(swamp data get reports "$workflow"); then
  echo "audit-gate: failed to read report output for workflow '$workflow'" >&2
  exit 2
fi
if [ -z "$output" ]; then
  echo "audit-gate: empty report output for workflow '$workflow'" >&2
  exit 2
fi

# `// "missing"` makes a null/absent field detectable instead of silently
# comparing as the string "null".
gate_tripped=$(printf '%s' "$output" | jq -r '.json.gateTripped // "missing"')

case "$gate_tripped" in
  true)
    echo "audit-gate: S3 bucket audit gate tripped:" >&2
    printf '%s' "$output" \
      | jq -r '.json.trippers[] | "  - \(.bucket): \(.id) (\(.severity)/\(.status))"' >&2
    exit 1
    ;;
  false)
    exit 0
    ;;
  *)
    echo "audit-gate: 'json.gateTripped' missing from report output for workflow '$workflow'" >&2
    exit 2
    ;;
esac
```

```sh
swamp workflow run audit-tf-state-buckets \
  && audit-gate.sh audit-tf-state-buckets
```

## Failure modes

| Symptom                                      | Likely cause                                                                                                                                                                  | Fix                                                                                                                          |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Report runs but finds no buckets             | No step in the workflow has `modelType == "@swamp/aws/s3/bucket"` (or `"@swamp/aws/s3/bucket-policy"`).                                                                       | Add the bucket-state / bucket-policy lookup steps before the report.                                                         |
| Every finding is `skip`                      | Step ran but data file is missing or unparseable.                                                                                                                             | Check `.swamp/data/` for the rendered `raw` files; verify upstream extension version.                                        |
| TLS-only-policy passes despite a narrow Deny | The Deny statement is properly scoped (Principal `*`, Action `s3:*`, Resource covers both ARNs, Condition `Bool` or `BoolIfExists` matches). The check is strict on all four. | Read the rule definition in `reports/s3_bucket_audit.ts` — if your policy looks correct, file via `swamp issue bug --extension @jentz/aws-s3-bucket-audit` with the policy doc.  |
| TLS-only-policy is `skip` for every bucket   | Workflow has bucket-state lookups but no `@swamp/aws/s3/bucket-policy` lookup step. Without policy data the audit can't evaluate TLS enforcement.                             | Add a `forEach` step that runs `@swamp/aws/s3/bucket-policy.get` for each bucket alongside the existing bucket-state lookup. |
| Report data is empty after a `throw`         | A previous version of the report threw on gate trip; current behavior surfaces the gate via JSON only.                                                                        | Upgrade to the current version.                                                                                              |

## Versioning

Uses swamp Calendar Versioning (`YYYY.MM.DD.MICRO`). Breaking changes — adding a
new rule with default `error` severity, renaming a rule id, removing a field
from the JSON output — bump the date and carry release notes. Adding info/warn
rules, tightening a check's semantics, or extending the JSON output additively
is not considered breaking.

## Issues, contributing, license

- Bugs, features, security: `swamp issue bug --extension @jentz/aws-s3-bucket-audit`
- Source:
  <https://github.com/jentz/swamp-extensions/tree/main/aws-s3-bucket-audit>
- License: MIT (see [LICENSE.md](LICENSE.md))
