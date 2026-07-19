# @jentz/aws-vpc-inventory-report

Workflow-scope swamp report that renders an operator VPC inventory from the
`vpc` and `scan_error` rows produced earlier in the workflow by
[`@jentz/aws-vpc-inventory`](../aws-vpc-inventory/). Pure data shaping — no AWS
API access. Follows the markdown + JSON pattern of
[`@jentz/aws-s3-bucket-audit`](../aws-s3-bucket-audit/).

## Upstream compatibility

This report has no runtime dependency on AWS — it parses step output emitted by
the upstream `@jentz/aws-vpc-inventory` model. It requires that model type in
the workflow and decodes its `vpc` / `scan_error` artifacts against a
hand-mirrored copy of the producer's row schemas. Artifacts that fail to decode
(bad JSON) or validate (schema drift) are counted into a `skipped` total and
left out — they never crash the report.

## Using it in a workflow

Run the inventory model in a step, then attach this report to the same
workflow. The report runs once after the steps complete and collects every
`@jentz/aws-vpc-inventory` step's `vpc` / `scan_error` artifacts:

```yaml
name: vpc-inventory
jobs:
  - name: inventory
    steps:
      - name: scan-fleet
        task:
          type: model_method
          modelType: "@jentz/aws-vpc-inventory"
          modelName: vpc-fleet
          methodName: scan
reports:
  require:
    - "@jentz/aws-vpc-inventory-report"
```

## What it emits

### Markdown

- A header and a summary: accounts seen, regions covered, VPCs inventoried,
  default-VPC count, shared-in-via-RAM count, and a one-line coverage-gaps tally.
- The full inventory table, sorted by `(account, region, VPC id)`.
- A coverage-gaps section that groups failed `(profile, region)` pairs by kind,
  one subsection each for:
  - which profiles need `aws sso login` (expired token, `auth_expired`),
  - which regions were blocked by SCP/IAM (`access_denied`),
  - which scans hit a transient DNS/socket failure (`network`).

  Any `other`-kind errors are folded into the one-line summary tally only; they
  get no dedicated subsection.

### JSON

A structured payload (`report-<name>-json`) carrying:

- `vpcs[]` — one object per VPC, mirroring the model's `vpc` row fields, in the
  same stable sort order as the markdown table.
- `vpcCount`, `accountCount`, `regionCount`, `defaultVpcCount`, `sharedVpcCount`
  — the summary counts.
- `errorsByKind` — a per-`kind` breakdown of the scan errors.
- `skipped` — artifacts skipped during collection.
- `degraded` — `true` when the report's outer guard absorbed an unexpected
  failure and fell back to a still-valid (possibly empty) report.

There is no flat `csv` string field — consumers read the structured `vpcs[]`
rows directly. For example, to list every shared-in VPC across the fleet:

```sh
swamp data get --workflow <workflow> \
  report-aws-vpc-inventory-report-json --json \
  | jq '.vpcs[] | select(.isSharedIn) | {accountId, region, vpcId, ownerAccountId}'
```

## Never throws

A missing upstream step, a malformed artifact, schema drift, or an unexpected
runtime failure all degrade to a logged warning and a still-valid report rather
than failing the workflow run. When the outer guard fires, `degraded` is set in
the JSON.

## Pairs with

[`@jentz/aws-vpc-inventory`](../aws-vpc-inventory/) — the read-only model that
produces the `vpc` and `scan_error` rows this report consumes.
