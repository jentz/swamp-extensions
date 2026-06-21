# @jentz/aws-rds-inventory-report

Workflow-scope swamp report that renders an operator RDS inventory from the
`cluster` and `instance` rows produced earlier in the workflow by
[`@jentz/aws-rds-inventory`](../aws-rds-inventory/). Pure data shaping — no AWS
API access. Follows the markdown + JSON pattern of
[`@jentz/aws-vpc-inventory-report`](../aws-vpc-inventory-report/).

## Upstream compatibility

This report has no runtime dependency on AWS — it parses step output emitted by
the upstream `@jentz/aws-rds-inventory` model. It requires that model type in
the workflow and decodes its `cluster` / `instance` artifacts against a
hand-mirrored copy of the producer's row schemas. The two packages are coupled
only by the `@jentz/aws-rds-inventory` model-type string — no manifest
`dependency` or shared library. Artifacts that fail to decode (bad JSON) or
validate (schema drift) are counted into a `skipped` total and left out — they
never crash the report.

## Using it in a workflow

Run the inventory model in a step, then attach this report to the same
workflow. The report runs once after the steps complete and collects every
`@jentz/aws-rds-inventory` step's `cluster` / `instance` artifacts:

```yaml
jobs:
  inventory:
    steps:
      - name: list-clusters
        model: rds-fleet
        method: list_clusters
reports:
  - "@jentz/aws-rds-inventory-report"
```

## What it emits

swamp persists two artifacts per run:

- `report-aws-rds-inventory-report` — the markdown body (`text/markdown`).
- `report-aws-rds-inventory-report-json` — the structured payload
  (`application/json`).

### Markdown

- A header and a summary: clusters inventoried, instances inventoried, the
  writer/reader split, the engines observed, multi-AZ cluster count, and a
  skipped-artifacts tally.
- The full inventory table, one row per instance, sorted by
  `(cluster, writer-before-reader, instance id)`.

The summary always carries a skipped-artifacts line. A clean run reports
`Skipped artifacts: 0`; any non-zero count is flagged with a warning so an
incomplete inventory is visible at a glance rather than silently short. The
skipped rows themselves are detailed in the run logs.

### JSON

A structured payload (`report-aws-rds-inventory-report-json`) carrying:

- `clusters[]` — one object per cluster, mirroring the model's `cluster` row
  fields, in stable sort order by cluster identifier.
- `instances[]` — one object per instance, mirroring the model's `instance` row
  fields, in the same stable sort order as the markdown table.
- `clusterCount`, `instanceCount` — the summary counts.
- `skipped` — artifacts skipped during collection.
- `degraded` — `true` when the report's outer guard absorbed an unexpected
  failure and fell back to a still-valid (possibly empty) report.

There is intentionally **no `csv` field** — consumers read the structured
`clusters[]` / `instances[]` rows directly. If you need CSV, derive it
downstream from the JSON artifact with `jq`. For example, to flatten every
instance across the fleet to CSV:

```sh
swamp data get --workflow <workflow> \
  report-aws-rds-inventory-report-json --json \
  | jq -r '.instances[]
      | [.DBClusterIdentifier, .DBInstanceIdentifier, .Role, .DBInstanceClass, .Engine]
      | @csv'
```

## Never throws

A missing upstream step, a malformed artifact, schema drift, or an unexpected
runtime failure all degrade to a logged warning and a still-valid report rather
than failing the workflow run. When the outer guard fires, `degraded` is set in
the JSON.

## Pairs with

[`@jentz/aws-rds-inventory`](../aws-rds-inventory/) — the read-only model that
produces the `cluster` and `instance` rows this report consumes.
