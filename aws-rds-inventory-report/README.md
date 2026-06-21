# @jentz/aws-rds-inventory-report

Workflow-scope report that renders an operator RDS inventory (markdown + JSON)
from the `cluster` and `instance` rows produced earlier in the workflow by
[`@jentz/aws-rds-inventory`](../aws-rds-inventory). Pure data shaping — no AWS
API access.

## What it does

The report walks the current workflow's step executions, decodes the `cluster`
and `instance` artifacts emitted by `@jentz/aws-rds-inventory`, and returns two
formats:

- a **markdown** body — a summary (cluster count, instance count, engines,
  writer/reader split, multi-AZ count) followed by the full inventory table;
- a **JSON** payload — structured `clusters[]` + `instances[]` rows plus the
  summary counts, the skipped-artifact count, and a `degraded` flag.

There is intentionally **no `csv` field** in the JSON payload. If you need CSV,
derive it downstream from the JSON artifact with `jq`:

```sh
# Flatten the instances[] rows of the JSON artifact to CSV.
jq -r '.instances[] | [.DBClusterIdentifier, .DBInstanceIdentifier, .Role, .DBInstanceClass] | @csv' \
  report-aws-rds-inventory-report-json.json
```

## Wiring it into a workflow

Reference the report from a workflow that already runs the inventory model
earlier in the same run:

```yaml
reports:
  - "@jentz/aws-rds-inventory-report"
```

The report consumes the upstream model's outputs by `modelType`, so no manifest
`dependency` or shared library couples the two packages — only the
`@jentz/aws-rds-inventory` model-type string.

## Never-throws posture

A missing upstream step, a malformed artifact, or schema drift degrades to a
logged warning and a still-valid (possibly empty) report with the `degraded`
flag set. The report never throws out of `execute`.
