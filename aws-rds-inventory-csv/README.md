# @jentz/aws-rds-inventory-csv

Workflow-scope report that emits a CSV summary of RDS DB clusters and their
members, consuming the resources produced earlier in the workflow by
[`@jentz/aws-rds-inventory`](../aws-rds-inventory/).

## Overview

One row per cluster member. Pure data shaping — no AWS API access, no mutation,
no fail gates. The CSV always has the header row; the body is empty when no
upstream inventory step is present.

## How it fits with @jentz/aws-rds-inventory upstream

This report consumes the `instance` factory resources written by
`@jentz/aws-rds-inventory`. It scans `context.stepExecutions` for steps whose
`modelType` is `@jentz/aws-rds-inventory`, decodes the instance JSON via
`dataRepository.getContent`, and renders the result. Cluster artifacts are
counted by identifier (for partial-failure observability — see
`clusterArtifactCount` in the JSON output below) but not decoded. The inventory
model remains the single source of truth — re-running the inventory regenerates
the resources and re-running the report regenerates the CSV.

```
@jentz/aws-context-guard   →   @jentz/aws-rds-inventory   →   @jentz/aws-rds-inventory-csv
   (verify account)              (list cluster + instance        (workflow-scope report —
                                 resources via DescribeDB*)        renders the CSV)
```

## Output

The swamp report runtime persists two artifacts per report (see
[swamp-report skill](../.agents/skills/swamp-report/SKILL.md)):

| Data name                           | Content type       | Body                                                      |
| ----------------------------------- | ------------------ | --------------------------------------------------------- |
| `report-aws-rds-inventory-csv`      | `text/markdown`    | The raw CSV body, so `swamp report get` renders the rows. |
| `report-aws-rds-inventory-csv-json` | `application/json` | `{ csv, rowCount, clusterCount, columns, skipped, ... }`. |

There is no separate CSV channel in the report API, so the CSV body is returned
in both places. Retrieval:

```sh
# Human-readable: see the CSV body
swamp report get aws-rds-inventory-csv --workflow <workflow-name>

# Machine-readable: extract the CSV string from the JSON artifact.
# Workflow-scope data needs --workflow, not a positional argument.
swamp data get --workflow <workflow-name> report-aws-rds-inventory-csv-json --json \
  | jq -r .csv > inventory.csv
```

The CSV header is always present, even when there are no data rows.

### JSON metadata fields

The `report-aws-rds-inventory-csv-json` artifact carries:

| Field                  | Meaning                                                                                                                                     |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `csv`                  | The CSV body — same string as the `markdown` artifact.                                                                                      |
| `columns`              | Resolved column order (mirrors the CSV header). Use this to confirm an `AWS_RDS_INVENTORY_CSV_COLUMNS` override actually took effect.       |
| `rowCount`             | Number of data rows.                                                                                                                        |
| `clusterCount`         | Distinct `DBClusterIdentifier` values represented in those rows.                                                                            |
| `clusterArtifactCount` | Distinct cluster identifiers seen in upstream `cluster` artifacts. If greater than `clusterCount`, a cluster had no instance artifacts.     |
| `skipped`              | Upstream artifacts that failed to decode, parse, or validate.                                                                               |
| `duplicates`           | (cluster_id, instance_id) pairs observed more than once across artifacts; the later write wins.                                             |
| `degraded`             | `true` when the outer never-throws envelope absorbed an unexpected failure — the CSV is then header-only and other counters may be partial. |
| `generatedAt`          | ISO 8601 timestamp; empty string if the host clock was unavailable.                                                                         |

## Configuration

### Column selection

Default columns, in order:

```
cluster_id,instance_id,instance_class,role,az,engine,engine_version,tags
```

Override with `AWS_RDS_INVENTORY_CSV_COLUMNS` — a comma-separated subset of the
defaults in any order. Unknown column names log a warning and are skipped; the
report does not throw.

```sh
# Only the columns a capacity-planning spreadsheet needs.
AWS_RDS_INVENTORY_CSV_COLUMNS=cluster_id,instance_id,instance_class,az \
  swamp workflow run rds-inventory
```

`AWS_RDS_INVENTORY_CSV_COLUMNS` unset or empty → defaults. Every value in the
override list that doesn't match a default column name is dropped with a
warning. If the entire override resolves to zero recognized columns, the report
falls back to the defaults rather than emitting a header-only, column-less CSV.

The `tags` column is JSON-encoded with **keys sorted alphabetically**, so the
same instance tag set always renders identically across runs.

### Row order

Rows are sorted deterministically:

1. `cluster_id` ascending
2. writers before readers
3. `instance_id` ascending

### Duplicate handling

The report dedupes by the natural identity `(cluster_id, instance_id)` — if the
same instance is written twice across upstream artifacts (typically a retry
replay or two inventory steps that touched overlapping data), the later write
wins. The `duplicates` field in the JSON output counts how many writes were
collapsed.

For pipelines that span regions or accounts where the same identifier might
genuinely refer to different physical instances, run a per-region inventory and
add a region or account column upstream (extending the instance schema) rather
than relying on the report to disambiguate. The report has no way to tell two
same-named instances in different regions apart without that context.

## Workflow Usage Example

```yaml
name: rds-3-node-inventory
inputs:
  properties:
    expectedAccountId:
      type: string
      description: 12-digit AWS account ID this workflow targets.
jobs:
  - name: guard
    steps:
      - name: verify
        task:
          type: model_method
          modelType: "@jentz/aws-context-guard"
          modelName: rds-inventory-guard
          methodName: verify
          inputs:
            expectedAccountId: ${{ inputs.expectedAccountId }}
        allowFailure: false
  - name: inventory
    steps:
      - name: list_clusters
        task:
          type: model_method
          modelType: "@jentz/aws-rds-inventory"
          modelName: rds-inv
          methodName: list_clusters
    dependsOn:
      - { job: guard, condition: { type: succeeded } }
reports:
  require:
    - "@jentz/aws-rds-inventory-csv"
```

`expectedAccountId` is threaded through `inputs.*` so the auto-created model
definition refreshes on each run. Alternatively, pre-create the model instances
once with the AWS context baked in:

```sh
swamp model create @jentz/aws-context-guard rds-inventory-guard \
  --global-arg expectedAccountId=000000000000

swamp model create @jentz/aws-rds-inventory rds-inv \
  --global-arg region=eu-west-1
```

Run the workflow:

```sh
AWS_PROFILE=<profile> AWS_REGION=eu-west-1 \
  swamp workflow run rds-3-node-inventory --input expectedAccountId=000000000000
```

## Versioning

Uses swamp Calendar Versioning (`YYYY.MM.DD.MICRO`). The CSV column set, column
ordering, and JSON shape are the contract; additive new columns are
non-breaking, renaming or removing them is and will bump the date.

## Issues, contributing, license

- Bug reports and feature requests:
  <https://github.com/jentz/swamp-extensions/issues>
- Security vulnerabilities (private report, not a public issue):
  <https://github.com/jentz/swamp-extensions/security/advisories/new>
- Source:
  <https://github.com/jentz/swamp-extensions/tree/main/aws-rds-inventory-csv>
- License: MIT (see [LICENSE.md](LICENSE.md))
