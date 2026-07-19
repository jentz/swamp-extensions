# @jentz/aws-default-sg-audit-report

Workflow-scope swamp report that renders an operator worklist for AWS Security
Hub control **EC2.2** from the `finding` and `scan_error` rows produced earlier
in the workflow by [`@jentz/aws-default-sg-audit`](../aws-default-sg-audit/).
Pure data shaping — no AWS API access. Follows the markdown + JSON pattern of
[`@jentz/aws-s3-bucket-audit`](../aws-s3-bucket-audit/).

## Upstream compatibility

This report has no runtime dependency on AWS — it parses step output emitted by
the upstream `@jentz/aws-default-sg-audit` model. It requires that model type in
the workflow and decodes its `finding` / `scan_error` artifacts against a
hand-mirrored copy of the producer's row schemas. Artifacts that fail to decode
(bad JSON) or validate (schema drift) are counted into a `skipped` total and
left out — they never crash the report.

## Using it in a workflow

Run the audit model in a step, then attach this report to the same workflow. The
report runs once after the steps complete and collects every
`@jentz/aws-default-sg-audit` step's `finding` / `scan_error` artifacts:

```yaml
name: default-sg-audit
jobs:
  - name: audit
    steps:
      - name: scan-fleet
        task:
          type: model_method
          modelType: "@jentz/aws-default-sg-audit"
          modelName: default-sg-fleet
          methodName: scan
reports:
  require:
    - "@jentz/aws-default-sg-audit-report"
```

## What it emits

### Markdown

- A header and a summary: accounts seen, default SGs audited, the non-compliant
  vs compliant split (needs-migration vs safe-to-strip-now), and a one-line
  coverage-gaps tally.
- A **"safe to remediate now"** table — non-compliant default SGs with zero
  referencing ENIs, so all rules can be revoked immediately.
- An **"in use — migrate first"** table — non-compliant default SGs referenced
  by live ENIs, where the attached workload must move to a dedicated SG before
  stripping rules.
- A coverage-gaps section that groups failed `(profile, region)` pairs by kind:
  - which profiles need `aws sso login` (expired token, `auth_expired`),
  - which regions were blocked by SCP/IAM (`access_denied`),
  - which scans hit a transient DNS/socket failure (`network`).

Findings sort in-use-first, then safe, then compliant; ties break by account,
region, then default SG id. Owner / team columns are derived from VPC tags.

### JSON

A structured payload (`report-<name>-json`) carrying:

- `findingCount` — the number of decoded findings.
- `byVerdict` — a per-verdict count (`compliant`, `safe_to_remediate`,
  `in_use_needs_migration`).
- `errorsByKind` — a per-`kind` breakdown of the scan errors (`network`,
  `auth_expired`, `access_denied`, `other`).
- `skipped` — artifacts skipped during collection.
- `degraded` — `true` when the report's outer guard absorbed an unexpected
  failure and fell back to a still-valid (possibly empty) report.

There is no flat `csv` field — the upstream model's `finding` rows already
expose every field, so any CSV a consumer wants is derivable downstream from the
model output. For example, to list every default SG that is safe to strip:

```sh
swamp model get default-sg-fleet --json \
  | jq '[.resources.finding[].attributes | select(.verdict == "safe_to_remediate")]'
```

## Never throws

A missing upstream step, a malformed artifact, schema drift, or an unexpected
runtime failure all degrade to a logged warning and a still-valid report rather
than failing the workflow run. When the outer guard fires, `degraded` is set in
the JSON.

## Pairs with

[`@jentz/aws-default-sg-audit`](../aws-default-sg-audit/) — the read-only model
that produces the `finding` and `scan_error` rows this report consumes.
