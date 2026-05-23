# @jentz/aws-rds-inventory

List RDS DB clusters in an AWS region and split per-member instances out as
their own resources. Designed for fleet audits where you want to query cluster
shape with CEL — engine, member count, instance class, tags — without scripting
around the SDK.

For a CSV summary of the inventory, see the companion report extension
[`@jentz/aws-rds-inventory-csv`](../aws-rds-inventory-csv/).

## What it does

A single method, `list_clusters`, calls `DescribeDBClusters` and
`DescribeDBInstances` against the configured region. For every cluster that
matches a user-supplied CEL selector it writes:

- one **`cluster`** factory resource per matched cluster
- one **`instance`** factory resource per cluster member, with a
  `DBClusterIdentifier` back-reference to its cluster

The cluster and instance resources are the stable shape consumers should depend
on. Downstream models and reports can reference them via CEL:
`data.latest("<inv-name>", "<DBClusterIdentifier>").attributes.<field>`.

Designed to run downstream of
[`@jentz/aws-context-guard`](../aws-context-guard/) in a workflow, so a
misconfigured profile or account can never reach RDS APIs.

## What is and is NOT in scope

| Surface                                                                             | In scope                                                                   |
| ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Aurora clusters (`aurora-mysql`, `aurora-postgresql`)                               | Yes                                                                        |
| Non-Aurora Multi-AZ DB clusters (`mysql`, `postgres`, `mariadb` in MAZ mode)        | Yes — flow through `DescribeDBClusters` the same way as Aurora             |
| Single-instance standalone RDS (no cluster, returned only by `DescribeDBInstances`) | **Out of scope** — a different API surface; not surfaced by this extension |
| RDS Proxy, Aurora Limitless, RDS Custom                                             | **Out of scope** — separate API surfaces                                   |

If you need standalone-RDS inventory, file an issue and we'll consider a sibling
extension.

**Caveat — Neptune / DocumentDB.** Amazon Neptune and DocumentDB also surface
through the same `DescribeDBClusters` endpoint as RDS, so they will appear in
the unfiltered output (default selector `"true"`). Filter them out with a
selector if you want pure RDS results:

```cel
Engine != "neptune" && !Engine.startsWith("docdb")
```

## Installation

```sh
swamp extension pull @jentz/aws-rds-inventory
```

## Required IAM permissions

Grant these to the principal behind `AWS_PROFILE`:

- `rds:DescribeDBClusters`
- `rds:DescribeDBInstances`

The AWS-managed `ReadOnlyAccess` and `SecurityAudit` policies cover both.

## Quick example

A complete workflow pairs the context guard with the inventory model:

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
```

Create the model instances once, baking in the AWS context:

```sh
swamp model create @jentz/aws-context-guard rds-inventory-guard \
  --global-arg expectedAccountId=111122223333

swamp model create @jentz/aws-rds-inventory rds-inv \
  --global-arg region=eu-west-1
```

## Global arguments

| Name       | Type             | Default  | Description                                                                                                                                                        |
| ---------- | ---------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `region`   | string, optional | (unset)  | AWS region to query. Resolution order: this global arg, then `AWS_REGION` env, then `AWS_DEFAULT_REGION` env. If none are set the method throws.                   |
| `selector` | string           | `"true"` | CEL predicate evaluated per cluster. Returns a boolean; non-boolean results throw before any AWS-side work. Default `"true"` admits every cluster the API returns. |

### Region resolution

There is **no silent us-east-1 fallback**. An inventory tool that lists
resources in the wrong region risks reporting on the wrong account-level
surface, so the resolution chain fails closed:

1. `globalArg.region` (e.g. `--global-arg region=eu-west-1`)
2. `AWS_REGION` environment variable
3. `AWS_DEFAULT_REGION` environment variable
4. Throw a descriptive error naming all three sources.

The resolved region is logged at `info` level on every run.

### Selector context

For each cluster, the selector sees an object with these fields:

| Field                 | Type                 | Notes                                                                                       |
| --------------------- | -------------------- | ------------------------------------------------------------------------------------------- |
| `DBClusterIdentifier` | `string`             | Cluster name from AWS.                                                                      |
| `Engine`              | `string`             | e.g. `aurora-mysql`, `aurora-postgresql`, `mysql`, `postgres`, `mariadb`. Empty if missing. |
| `EngineVersion`       | `string`             | Empty string if AWS omitted it; never `undefined`.                                          |
| `Status`              | `string`             | e.g. `available`, `creating`. Empty string if missing.                                      |
| `MultiAZ`             | `boolean`            | `true` for Multi-AZ DB clusters; defaults to `false` when AWS omits the field.              |
| `members`             | array of objects     | One element per cluster member; see fields below.                                           |
| `tags`                | `map<string,string>` | Cluster-level tags, converted from AWS's `[{Key,Value},...]` array to a flat map.           |

Each `members[i]` carries `DBInstanceIdentifier`, `DBInstanceClass`, `Role`
(`"writer"` or `"reader"`), and an optional `AvailabilityZone`.

### Selector examples

```cel
# 1. Include everything (default).
true

# 2. Aurora clusters with exactly three members.
Engine.startsWith("aurora") && members.size() == 3

# 3. Any cluster that still has an r7g-family member (migration audit).
members.exists(m, m.DBInstanceClass.startsWith("db.r7g"))

# 4. Production clusters only, by tag.
has(tags.Environment) && tags["Environment"] == "prod"

# 5. Non-Aurora Multi-AZ DB clusters with a mysql engine.
MultiAZ == true && Engine == "mysql"
```

**Tag access caveat.** The bundled CEL runtime throws when a selector accesses a
tag key that doesn't exist on the cluster. To admit clusters that may lack the
tag, guard with `has()`:

```cel
has(tags.Environment) && tags["Environment"] == "prod"
```

Bracket access is required for tag keys that contain hyphens, dots, or other
characters that aren't valid CEL identifiers — `tags["cost-center"]` works,
`tags.cost-center` does not.

**No `undefined` in the selector context.** Every cluster-level field above is
always populated — empty string for missing strings, `false` for missing
`MultiAZ`. The same goes for member-level `AvailabilityZone`: it's `""` when AWS
omits it, never `undefined`. Selectors can write `EngineVersion != ""` or
`m.AvailabilityZone == ""` without a `has()` guard.

**Non-boolean results are rejected.** A selector like `members.size()` (without
`== N`) evaluates to a number and is rejected with a clear error naming the
offending cluster, before any resource is written.

## Outputs

### `cluster` resource (factory)

Storage key: `cluster-<DBClusterIdentifier>` (the `cluster-` prefix prevents
collisions with `instance-` keys). Lifetime `infinite`, retain last 10 versions.

| Field                 | Type                 | Notes                                |
| --------------------- | -------------------- | ------------------------------------ |
| `DBClusterIdentifier` | `string`             | Identifier (also the instance name). |
| `Engine`              | `string`             |                                      |
| `EngineVersion`       | `string?`            |                                      |
| `Status`              | `string?`            |                                      |
| `Endpoint`            | `string?`            | Writer endpoint, if returned.        |
| `ReaderEndpoint`      | `string?`            | Reader endpoint, if returned.        |
| `MultiAZ`             | `boolean?`           |                                      |
| `tags`                | `map<string,string>` | Tag array flattened.                 |

CEL reference shape:

```cel
data.latest("rds-inv", "cluster-cluster-a").attributes.Engine
data.latest("rds-inv", "cluster-cluster-a").attributes.tags["Environment"]
```

### `instance` resource (factory)

Storage key: `instance-<DBClusterIdentifier>--<DBInstanceIdentifier>` (combined
so two different clusters can have member instances with the same short
identifier without colliding). Lifetime `infinite`, retain last 10 versions.

| Field                  | Type                  | Notes                                          |
| ---------------------- | --------------------- | ---------------------------------------------- |
| `DBInstanceIdentifier` | `string`              | Identifier (also the instance name).           |
| `DBClusterIdentifier`  | `string`              | Back-reference to the owning cluster.          |
| `DBInstanceClass`      | `string`              | e.g. `db.r7g.large`.                           |
| `Role`                 | `"writer"`/`"reader"` | Derived from `IsClusterWriter` in the API.     |
| `AvailabilityZone`     | `string?`             |                                                |
| `Engine`               | `string`              | Falls back to the cluster's engine on missing. |
| `EngineVersion`        | `string?`             |                                                |
| `Status`               | `string?`             | `DBInstanceStatus`.                            |
| `tags`                 | `map<string,string>`  | Per-instance tags.                             |

CEL reference shape:

```cel
data.latest("rds-inv", "instance-cluster-a--cluster-a-1").attributes.DBInstanceClass
```

## Throttling

`DescribeDBClusters` and `DescribeDBInstances` are paginated; on busy accounts
the AWS SDK's built-in retries can be insufficient. This extension wraps both
calls with a `withRetry` helper modeled on the upstream `@swamp/aws/rds` helper:
exponential backoff with **full jitter** — each retry delay is uniformly sampled
from `[0, min(baseDelay * 2 ** n, maxDelay)]` — base 1s, ceiling 90s, up to 20
attempts. Full jitter is the AWS-documented recommendation for decorrelating
concurrent callers. Each retry logs at `debug` level.

Throttling detection matches by SDK error `name` (`ThrottlingException`,
`TooManyRequestsException`, `RequestLimitExceeded`, `RequestThrottledException`,
`Throttling`) with a word-boundary message fallback for generic-Error SDK
wrappers. Non-throttling errors propagate immediately.

## Workflow ergonomics

If you want a single inventory shared across multiple downstream jobs, run this
model once and let later jobs reference the resources by CEL. The factory output
is GC-retained for 10 versions per instance name, so re-running the inventory
periodically is cheap.

## Versioning

Uses swamp Calendar Versioning (`YYYY.MM.DD.MICRO`). The cluster and instance
resource schemas are the contract — adding fields additively is not breaking;
renaming or removing them is and will bump the date.

## Issues, contributing, license

- Bug reports and feature requests:
  <https://github.com/jentz/swamp-extensions/issues>
- Security vulnerabilities (private report, not a public issue):
  <https://github.com/jentz/swamp-extensions/security/advisories/new>
- Source:
  <https://github.com/jentz/swamp-extensions/tree/main/aws-rds-inventory>
- License: MIT (see [LICENSE.md](LICENSE.md))
