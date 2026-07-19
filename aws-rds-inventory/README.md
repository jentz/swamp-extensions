# @jentz/aws-rds-inventory

List RDS DB clusters in an AWS region and split per-member instances out as
their own resources. Designed for fleet audits where you want to query cluster
shape with CEL — engine, member count, instance class, tags — without scripting
around the SDK.


> **See also — instance-level + reservation coverage.** This pair is
> **cluster-level** (one resource per Aurora / Multi-AZ DB cluster and per
> cluster member, in one region). For every running DB **instance** (Aurora
> members *and* standalone) plus every **reservation**, swept across many
> accounts and regions for reserved-instance coverage planning, use
> [`@jentz/aws-rds-reservations`](../aws-rds-reservations/) and its report
> [`@jentz/aws-rds-reservation-coverage`](../aws-rds-reservation-coverage/).

## What it does

A single method, `list_clusters`, calls `DescribeDBClusters` and
`DescribeDBInstances` against the configured region. Because
`DescribeDBClusters` is a shared AWS endpoint, the extension first drops
non-RDS engines such as Neptune and DocumentDB with a built-in RDS engine
allowlist. For every remaining RDS cluster that matches a user-supplied CEL
selector it writes:

- one **`cluster`** factory resource per matched cluster
- one **`instance`** factory resource per cluster member, with a
  `DBClusterIdentifier` back-reference to its cluster

The cluster and instance resources are the stable shape consumers should depend
on. Downstream models and reports can reference them via CEL:
`data.latest("<inv-name>", "<DBClusterIdentifier>").attributes.<field>`.

Designed to run downstream of
[`@jentz/aws-context-guard`](../aws-context-guard/) in a workflow, so a
misconfigured profile or account can never reach RDS APIs.

## Relationship to `@swamp/aws/rds`

The official [`@swamp/aws/rds`](https://github.com/systeminit/swamp-extensions)
`dbcluster` model ships a native `list` method (as of `@swamp/aws/rds`
`2026.06.06.1`). It looks similar to `list_clusters` here, but the two are built
for different jobs — reach for whichever matches yours:

| Aspect | `@swamp/aws/rds` `dbcluster.list` | `@jentz/aws-rds-inventory` `list_clusters` |
| ------ | --------------------------------- | ------------------------------------------ |
| **Purpose** | Lifecycle — feeds the cluster `create` / `get` / `update` / `sync` flow | Audit / inventory |
| **Output** | One `state` blob per cluster, written into the *same* resource space as the other lifecycle methods; members embedded straight from the `DescribeDBClusters` shape | Relational `cluster` + per-member `instance` factory resources |
| **Member detail** | As returned by `DescribeDBClusters` | Enriched with `DescribeDBInstances` — instance class, AZ, per-member engine |
| **Engine filtering** | None — returns whatever the shared endpoint lists, including Neptune and DocumentDB | Built-in allowlist drops shared-endpoint non-RDS engines |
| **Selection** | Raw server-side AWS `Filters` | A CEL selector over a rich computed context (cluster fields, `members[]`, tags), on top of server-side filtering |
| **Pagination** | `maxPages` cap (default 10), which can silently truncate large fleets | Unbounded — a complete inventory |
| **Region** | Standard AWS resolution | Strict resolution chain, no silent `us-east-1` fallback |

Use the native `dbcluster.list` when you are managing cluster lifecycle and want
raw state in the shared RDS resource space. Use this extension when you want a
complete, enriched, CEL-filterable audit of your cluster fleet — for example to
feed compliance checks or cost analysis.

## What is and is NOT in scope

| Surface                                                                                       | In scope                                                                   |
| --------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Aurora clusters (`aurora-mysql`, `aurora-postgresql`)                                         | Yes                                                                        |
| Non-Aurora Multi-AZ DB clusters (`mysql`, `postgres`)                                         | Yes — flow through `DescribeDBClusters` the same way as Aurora             |
| Single-instance standalone RDS (no cluster, returned only by `DescribeDBInstances`)           | **Out of scope** — a different API surface; not surfaced by this extension |
| Single-instance engines: RDS for Oracle / SQL Server / MariaDB / Db2 / RDS Custom             | **Out of scope** — these engines surface through `DescribeDBInstances`, not `DescribeDBClusters` |
| RDS Proxy                                                                                     | **Out of scope** — separate API surface                                    |

If you need standalone-RDS inventory, file an issue and we'll consider a sibling
extension.

The built-in allowlist admits exactly the four engines `DescribeDBClusters`
actually returns: `aurora-mysql`, `aurora-postgresql`, `mysql`, and `postgres`.
Shared-endpoint non-RDS engines such as `neptune`, `docdb`, and
`docdb-elastic` are dropped by default and never reach the user selector.

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
```

`expectedAccountId` is threaded through `inputs.*` so the auto-created model
definition refreshes on each run (`swamp workflow run rds-3-node-inventory
--input expectedAccountId=AWS_ACCOUNT_ID`). Alternatively, pre-create the model
instances once with the AWS context baked in:

```sh
swamp model create @jentz/aws-context-guard rds-inventory-guard \
  --global-arg expectedAccountId=AWS_ACCOUNT_ID

swamp model create @jentz/aws-rds-inventory rds-inv \
  --global-arg region=eu-west-1
```

## Global arguments

| Name       | Type             | Default  | Description                                                                                                                                                        |
| ---------- | ---------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `region`   | string, optional | (unset)  | AWS region to query. Resolution order: this global arg, then `AWS_REGION` env, then `AWS_DEFAULT_REGION` env. If none are set the method throws.                   |
| `selector` | string           | `"true"` | CEL predicate evaluated per allowlisted RDS cluster. Returns a boolean; non-boolean results throw before any resource is written. Default `"true"` admits every RDS cluster after the built-in engine allowlist drops shared-endpoint non-RDS engines. |

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

For each allowlisted RDS cluster, the selector sees an object with these fields.
Non-RDS engines are filtered out before this selector context is built:

| Field                 | Type                 | Notes                                                                                       |
| --------------------- | -------------------- | ------------------------------------------------------------------------------------------- |
| `DBClusterIdentifier` | `string`             | Cluster name from AWS.                                                                      |
| `Engine`              | `string`             | Always one of `aurora-mysql`, `aurora-postgresql`, `mysql`, `postgres` — the four engines the allowlist admits; never empty (the allowlist runs before the selector). |
| `EngineVersion`       | `string`             | Empty string if AWS omitted it; never `undefined`.                                          |
| `Status`              | `string`             | e.g. `available`, `creating`. Empty string if missing.                                      |
| `MultiAZ`             | `boolean`            | `true` for Multi-AZ DB clusters; defaults to `false` when AWS omits the field.              |
| `members`             | array of objects     | One element per cluster member; see fields below.                                           |
| `tags`                | `map<string,string>` | Cluster-level tags, converted from AWS's `[{Key,Value},...]` array to a flat map.           |

Each `members[i]` carries:

| Field                           | Type                     | Notes                                                                                                              |
| ------------------------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| `DBInstanceIdentifier`          | `string`                 | Member identifier. Empty string if AWS omitted it.                                                                 |
| `DBInstanceClass`               | `string`                 | e.g. `db.r7g.large`. `"unknown"` if the instance lookup returned nothing.                                          |
| `Role`                          | `"writer"` \| `"reader"` | Derived from `IsClusterWriter` on the cluster member shape.                                                        |
| `AvailabilityZone`              | `string?` (optional)     | Present only when AWS returned it. Use `has(m.AvailabilityZone)` to test presence.                                 |
| `PromotionTier`                 | `number?` (optional)     | Failover priority, `0` (highest) – `15` (lowest). Present only when AWS returned it. Use `has(m.PromotionTier)`.   |
| `DBClusterParameterGroupStatus` | `string?` (optional)     | `in-sync`, `applying`, `pending-reboot`, `removing`, etc. Present only when AWS returned it. Use `has(m.DBClusterParameterGroupStatus)`. |

**AWS-optional fields use `has()`.** The three always-present member fields
(`DBInstanceIdentifier`, `DBInstanceClass`, `Role`) are filled with
default-when-missing values so simple equality predicates work without
guards. The AWS-optional fields above are deliberately left absent on the
object when AWS didn't return them, so `has(m.PromotionTier)` returns
`false` and a CEL range predicate against a missing value throws — that's
the explicit behavior, not a footgun. An earlier design used `-1` / `""`
sentinels; both leaked through range and equality predicates in ways that
were surprising for selector authors, so the fields are now genuinely
absent when AWS omits them.

### Selector examples

```cel
# 1. Include every allowlisted RDS cluster (default).
true

# 2. Aurora clusters with exactly three members.
Engine.startsWith("aurora") && members.size() == 3

# 3. Any cluster that still has an r7g-family member (migration audit).
members.exists(m, m.DBInstanceClass.startsWith("db.r7g"))

# 4. Production clusters only, by tag.
has(tags.Environment) && tags["Environment"] == "prod"

# 5. Non-Aurora Multi-AZ DB clusters with a mysql engine.
MultiAZ == true && Engine == "mysql"

# 6. Failover topology audit — any reader at tier 0 races the writer.
#    has() is required because AWS may omit PromotionTier on legacy clusters.
members.exists(m,
  m.Role == "reader" && has(m.PromotionTier) && m.PromotionTier == 0)

# 7. Parameter-group drift — at least one member still applying the new group.
members.exists(m,
  has(m.DBClusterParameterGroupStatus) &&
  m.DBClusterParameterGroupStatus == "pending-reboot")
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

**Two presence conventions in the selector context.** Cluster-level fields
(`Engine`, `EngineVersion`, `Status`, `MultiAZ`) are always populated with
default-when-missing values — empty string for strings, `false` for
`MultiAZ`. Selectors can write `EngineVersion != ""` without a `has()`
guard. Member-level AWS-optional fields (`AvailabilityZone`, `PromotionTier`,
`DBClusterParameterGroupStatus`) are deliberately left absent when AWS
omits them — use `has(m.<field>)` to test presence, matching the `has(tags.X)`
pattern above. This avoids sentinel leak through range predicates and
ambiguous "AWS returned empty" semantics.

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

| Field                           | Type                  | Notes                                                                                                                                                                        |
| ------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DBInstanceIdentifier`          | `string`              | Identifier (also the instance name).                                                                                                                                         |
| `DBClusterIdentifier`           | `string`              | Back-reference to the owning cluster.                                                                                                                                        |
| `DBInstanceClass`               | `string`              | e.g. `db.r7g.large`.                                                                                                                                                         |
| `Role`                          | `"writer"`/`"reader"` | Derived from `IsClusterWriter` in the API.                                                                                                                                   |
| `AvailabilityZone`              | `string?`             |                                                                                                                                                                              |
| `Engine`                        | `string`              | Falls back to the cluster's engine on missing.                                                                                                                               |
| `EngineVersion`                 | `string?`             |                                                                                                                                                                              |
| `Status`                        | `string?`             | `DBInstanceStatus`.                                                                                                                                                          |
| `PromotionTier`                 | `number?`             | Failover priority, `0` (highest) – `15` (lowest). Absent when AWS didn't return the field.                                                                                  |
| `DBClusterParameterGroupStatus` | `string?`             | Parameter-group apply status. Omitted when AWS didn't return the field.                                                                                                      |
| `tags`                          | `map<string,string>`  | Per-instance tags.                                                                                                                                                           |

CEL reference shape:

```cel
data.latest("rds-inv", "instance-cluster-a--cluster-a-1").attributes.DBInstanceClass
```

## Throttling

`DescribeDBClusters` and `DescribeDBInstances` are paginated; on busy accounts
throttling bites exactly there. The RDS client is constructed with the shared
bounded retry config (`retryMode: "adaptive"`, `maxAttempts: 3`): the SDK's
adaptive mode adds client-side rate limiting on top of standard exponential
backoff, so sustained throttling backs off instead of hammering. This is the
single retry mechanism — there is deliberately no second app-level retry layer
wrapping the same calls, which would compound attempts under sustained
throttling. The client retries each individual page send, resuming at the same
`Marker`; a throttle that survives the bounded attempts propagates as the
method's error. Every page is drained to exhaustion — there is no page cap.

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
