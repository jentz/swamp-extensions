# @jentz/aws-rds-reservation-coverage

Workflow-scope report that answers the RDS reserved-instance planning question:
**how much running capacity, per family-generation, is not yet covered by a
reservation?** It consumes the `instance`, `reserved`, and `scan_error`
resources produced earlier in the workflow by
[`@jentz/aws-rds-reservations`](../aws-rds-reservations/), normalizes running
and reserved capacity into size-flexible **large-equivalent** units, and reports
the running-minus-reserved coverage gap.

Pure data shaping — no AWS API access, no mutation.

## See also

This is the report half of the **instance + reservation** RDS pair. The
collector is [`@jentz/aws-rds-reservations`](../aws-rds-reservations/). For
**cluster-level** RDS work (Aurora / Multi-AZ DB clusters and their members)
see the sibling pair [`@jentz/aws-rds-inventory`](../aws-rds-inventory/) and its
CSV report [`@jentz/aws-rds-inventory-csv`](../aws-rds-inventory-csv/).

## The large-equivalent unit

Each instance class is parsed into `family` (e.g. `r7g`), `generation` (`7g`),
and `size` (`2xlarge`). Size is converted to a **large-equivalent** factor that
doubles per size step, anchored at a Single-AZ `large = 1`:

| size | nano | micro | small | medium | large | xlarge | 2xlarge | 4xlarge | 8xlarge | 16xlarge |
| ---- | ---- | ----- | ----- | ------ | ----- | ------ | ------- | ------- | ------- | -------- |
| factor | .0625 | .125 | .25 | .5 | **1** | 2 | 4 | 8 | 16 | 32 |

(an `Nxlarge` is `2 × N`.) A **Multi-AZ instance deployment counts 2×** the
same-size Single-AZ deployment. This is AWS's normalized-unit table rescaled so
a Single-AZ `large` is one unit — the granularity at which RDS **size-flexible**
reservations apply within a family, with Multi-AZ folded in at 2× exactly as AWS
bills it. So a reservation for one `db.r7g.2xlarge` (4 large-eq) covers, e.g.,
four Single-AZ `db.r7g.large` instances — or two same-size Multi-AZ ones — in
the same family and engine.

**Aurora is the exception.** Aurora has no Multi-AZ DB *instance* reservation
option — the AWS purchase console pins the Single-AZ radio for Aurora, because
Aurora's availability comes from cluster replicas rather than a Multi-AZ
instance deployment. So any Aurora engine is forced to the `Single-AZ`
deployment and **never** picks up the 2× weight, regardless of its upstream
`multiAZ` flag.

## Bucketing and the coverage gap

Non-burstable, non-serverless capacity is summed into buckets keyed by
`region × family × engine × deployment(Multi-AZ|Single-AZ)` — the dimensions an
actual RDS reservation is scoped to, so each row maps to a purchasable line
item. For each bucket:

```
running_large_eq − reserved_large_eq = gap
```

A **positive** gap is under-covered capacity to buy; a **negative** gap is
over-coverage. Engine is canonicalized so running `postgres` nets against
reserved `postgresql` (Aurora variants are kept distinct). Only `active`
reservations count toward coverage.

Netting is **bucket-local**: a Single-AZ RI nets only Single-AZ running, a
Multi-AZ RI only Multi-AZ running. AWS actually lets a Single-AZ RI spill onto
Multi-AZ usage (one family-wide normalized-unit pool); the per-bucket gaps do
not model that spill, so when a Single-AZ RI exceeds Single-AZ demand one bucket
can read over-reserved while another reads under. The **rollup total is
unaffected** — spill only moves the gap between buckets, never the family total.

A `region × family` **generation rollup** collapses engine and deployment for
the headline "large equivalents per generation" view. Because Multi-AZ is folded
in at 2×, Multi-AZ and Single-AZ large-equivalents are commensurable, so this
sum is the authoritative cross-deployment coverage gap.

> **Known limitation — Multi-AZ DB cluster (3-node).** The newer Multi-AZ DB
> *cluster* (1 primary + 2 readable standbys) consumes 3× normalized units, but
> is not modeled: the upstream data carries only a `multiAZ` boolean and a
> `clusterId`, no reliable cluster-type signal. AWS reports each cluster member
> through `DescribeDBInstances` (typically `MultiAZ=false`), so the three
> members fall through as three individual Single-AZ instances — roughly the 3×
> footprint by headcount, at 1× each.

### Per-account breakdown (RI discount sharing OFF)

Under AWS Organizations consolidated billing, RI discount sharing is **on** by
default and a reservation floats org-wide — use the org-wide buckets. If sharing
is **disabled**, a reservation only benefits the account that bought it, so the
report also emits the same large-equivalents split by **owning account**: buy
each account's gap in that account.

## Carve-outs (never silently dropped)

- **Burstable** (`t`-class: t2/t3/t4g) — both running **and reserved** t-class
  capacity is tracked, but as **raw instance counts** rather than
  large-equivalents. Burstable reservations are not size-flexible (a `t3.medium`
  reservation only ever covers `t3.medium`), so normalizing them into
  large-equivalents would mislead. Instead the report keeps a separate
  `region × family × size` table with running-vs-reserved counts, so burstable
  reservation coverage is still visible — just counted, not normalized.
- **Serverless** (`db.serverless`, Aurora Serverless v2) is counted separately
  (ACU-billed, not instance-class capacity).
- **Unparseable** classes are listed with a warning rather than dropped.

## Caveats

Oracle / SQL-Server license models (LI vs BYOL) are **not** distinguished, so
those buckets are advisory. SQL Server and Oracle License-Included are also not
size-flexible at all, so normalizing them into large-equivalents is advisory for
those engines (a separate concern from the Multi-AZ 2× weighting, which *does*
apply to them). The report **never throws** — a missing upstream step, malformed
artifact, or schema drift degrades to a logged warning and a still-useful
(possibly empty) report with `degraded: true` in the JSON.

## How it fits with @jentz/aws-rds-reservations upstream

```
@jentz/aws-rds-reservations          →   @jentz/aws-rds-reservation-coverage
  (sweep instances + reservations          (workflow-scope report — normalizes
   across profiles × regions)                to large-eq, reports coverage gap)
```

The report scans `context.stepExecutions` for steps whose `modelType` is
`@jentz/aws-rds-reservations`, decodes their `instance` / `reserved` /
`scan_error` artifacts via `dataRepository.getContent`, and aggregates the
result. The model remains the single source of truth — re-running the sweep
regenerates the rows and re-running the report regenerates the analysis.

## Output

The swamp report runtime persists two artifacts per report:

| Data name                                  | Content type       | Body |
| ------------------------------------------ | ------------------ | ---- |
| `report-aws-rds-reservation-coverage`      | `text/markdown`    | The operator markdown report (summary, per-generation rollup, purchasable buckets, per-account purchase list, carve-outs, coverage-gap callouts). |
| `report-aws-rds-reservation-coverage-json` | `application/json` | The full structured payload (see below), including per-bucket CSV in `csv` and per-account CSV in `csvByAccount`. |

Retrieval:

```sh
# Human-readable markdown
swamp report get aws-rds-reservation-coverage --workflow <workflow-name>

# Machine-readable: pull the per-bucket CSV out of the JSON artifact
swamp data get --workflow <workflow-name> \
  report-aws-rds-reservation-coverage-json --json | jq -r .csv > coverage.csv
```

### JSON fields

| Field | Meaning |
| ----- | ------- |
| `report`, `workflow`, `generatedAt` | Report name, originating workflow, ISO timestamp taken at report start (`""` only if the report degraded before the timestamp was captured). |
| `columns` | Per-bucket CSV column order. |
| `accountCount`, `regionCount` | Distinct accounts and regions represented. |
| `instanceCount`, `reservedCount` | Provisioned and reserved rows seen. |
| `totalRunningLargeEq`, `totalReservedLargeEq`, `netGapLargeEq` | Org-wide totals and the net coverage gap. |
| `generationRollup` | Per `region × family` rollup rows. |
| `buckets` | Per `region × family × engine × deployment` rows (the purchasable line items). |
| `accountBuckets`, `csvByAccount` | Per-account buckets and their CSV (the RI-sharing-OFF purchase list). |
| `burstable`, `serverless`, `unparseable` | The three carve-outs. |
| `inactiveReserved` | Reservation rows skipped because they were not `active`. |
| `errorsByKind` | Scan errors counted by `auth_expired` / `access_denied` / `other`. |
| `skipped` | Upstream artifacts that failed to decode, parse, or validate. |
| `degraded` | `true` when the never-throws envelope absorbed an unexpected failure. |
| `csv` | The per-bucket CSV body (header + rows + trailing newline). |

## Workflow usage

```yaml
name: rds-reservation-coverage
jobs:
  - name: collect
    steps:
      - name: sweep
        task:
          type: model_method
          modelType: "@jentz/aws-rds-reservations"
          modelName: rds-res
          methodName: sweep
reports:
  require:
    - "@jentz/aws-rds-reservation-coverage"
```

```sh
swamp model create @jentz/aws-rds-reservations rds-res \
  --global-arg 'profiles:json=["prod-readonly","staging-readonly"]' \
  --global-arg 'regions:json=["us-east-1","us-west-2"]' \
  --global-arg requiredProfileSuffix=-readonly

swamp workflow run rds-reservation-coverage
swamp report get aws-rds-reservation-coverage --workflow rds-reservation-coverage
```

## Versioning

Uses swamp Calendar Versioning (`YYYY.MM.DD.MICRO`). The JSON shape, CSV column
sets, and large-equivalent factors are the contract; additive changes are
non-breaking, renaming or removing fields is and will bump the date.

## Issues, contributing, license

- Bug reports and feature requests:
  <https://github.com/jentz/swamp-extensions/issues>
- Security vulnerabilities (private report, not a public issue):
  <https://github.com/jentz/swamp-extensions/security/advisories/new>
- Source:
  <https://github.com/jentz/swamp-extensions/tree/main/aws-rds-reservation-coverage>
- License: MIT (see [LICENSE.md](LICENSE.md))
