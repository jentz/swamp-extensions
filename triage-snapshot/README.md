# @jentz/triage-snapshot

Workflow-scope swamp report that renders a **one-look snapshot** of the
service-triage artifacts collected earlier in the workflow — lambda failure
scans, queue depths, grouped DynamoDB counts, and Logs Insights rows — one
section per artifact, in step order.

## What it consumes

The report scans the workflow's step executions for three artifact specs:

- `lambda_failure_scan` — per-function invocations/errors with a
  `deterministic` flag, as produced by `@jentz/aws-metric-scan`
  `lambda_failure_scan`.
- `queue_depth` — per-queue visible/in-flight depth and oldest-message age,
  as produced by `@jentz/aws-metric-scan` `queue_depth`.
- `query_results` — either shape:
  - `{ groups: [{key, count}], items: [...] }` as produced by
    `@jentz/aws-dynamodb-query` `query` — rendered as a grouped-counts
    table, or as plain rows when the query had no grouping;
  - `{ results: [{field: value}], status }` as produced by
    `@webframp/aws/logs` `query` — rendered as a rows table.

Any model emitting the same shapes works. Unrecognized or malformed
artifacts are counted and skipped, never fatal.

## What it emits

- **Markdown** — a section per artifact. A Logs Insights artifact whose
  `status` is present but not `Complete` (e.g. a timed-out wait) is listed
  in a warning stamped at the top, so a cut-off query cannot read as
  all-clear.
- **JSON** — the structured `sections[]`, `incompleteQueries[]`, the
  skipped-artifact count, and a `degraded` flag.

## What it does not do

Verdicts. What counts as an anomaly (deterministic failure, DLQ depth,
count growth) belongs to the calling workflow's `assert` steps — this
report only shows the evidence. The report carries no environment
identifiers and never throws.

## Usage

```yaml
# in a workflow definition
reports:
  require:
    - "@jentz/triage-snapshot"
```

```sh
swamp report get @jentz/triage-snapshot --workflow <workflow-name>
```
