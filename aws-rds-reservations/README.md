# @jentz/aws-rds-reservations

Fleet-wide inventory of **running RDS DB instances and reserved DB instances**
across `profiles × regions` — the read-only data behind reserved-instance
coverage planning. One `sweep` method lists, for every account and region:

- every **provisioned** DB instance via `DescribeDBInstances` (Aurora cluster
  members **and** standalone single-instance RDS, so nothing is missed), and
- every **reserved** DB instance via `DescribeReservedDBInstances`.

Read-only: only `Describe*` and `sts:GetCallerIdentity` are ever called.

This model is a dumb collector — it records the raw AWS facts. The
normalization and coverage math live downstream in the companion report
[`@jentz/aws-rds-reservation-coverage`](../aws-rds-reservation-coverage/), which
turns these rows into size-flexible "large-equivalent" units and reports the
running-minus-reserved coverage gap.

## See also: cluster-level vs instance-level scope

This repo ships two RDS extension pairs that work at **different levels** — pick
the one that matches your question:

| Pair | Level | Use it when you want… |
| ---- | ----- | --------------------- |
| [`@jentz/aws-rds-inventory`](../aws-rds-inventory/) (+ [`-csv`](../aws-rds-inventory-csv/)) | **Cluster** | A CEL-filterable audit of Aurora / Multi-AZ DB **clusters** and their members in one region — one resource per cluster, one per cluster member. |
| **`@jentz/aws-rds-reservations`** (this) (+ [`-reservation-coverage`](../aws-rds-reservation-coverage/)) | **Instance + reservation** | Every running DB **instance** (Aurora members *and* standalone) plus every **reservation**, swept across many accounts and regions, for reserved-instance coverage planning. |

`aws-rds-inventory` reads `DescribeDBClusters` (cluster shape, single region,
CEL selector). This model reads `DescribeDBInstances` (every instance,
standalone included) plus `DescribeReservedDBInstances`, fanned out over
`profiles × regions`. They are complementary, not duplicates.

## What it does

The single method `sweep` fans out over every configured profile and region in
**one execution** — one model lock, all output produced in a single pass (per
the repository's fan-out-over-loops convention). For each `(account, region)`
it writes:

- one **`instance`** resource per provisioned DB instance, carrying account id,
  region, instance class, engine, Multi-AZ flag, status, owning cluster id
  (empty for standalone instances), storage type, and tags;
- one **`reserved`** resource per reservation, carrying the offered class,
  product description (engine), Multi-AZ flag, instance count, state, offering
  type, and term;
- one **`scan_error`** resource per `(profile, region)` phase that fails.

### Failures become rows, never aborts

An expired SSO token, an SCP-denied region, or a malformed response is recorded
as a `scan_error` and the sweep continues. A single bad account or region can
never blank out the rest of the fleet. Errors are classified into
`auth_expired` (operator runs `aws sso login`), `access_denied` (IAM/SCP), and
`other`, so the companion report can tell "needs login" apart from "genuinely
denied".

## Installation

```sh
swamp extension pull @jentz/aws-rds-reservations
```

## Required IAM permissions

Grant these to every principal behind the swept profiles:

- `rds:DescribeDBInstances`
- `rds:DescribeReservedDBInstances`
- `sts:GetCallerIdentity`

The AWS-managed `ReadOnlyAccess` and `SecurityAudit` policies cover all three.

## Global arguments

| Name                    | Type              | Default | Description |
| ----------------------- | ----------------- | ------- | ----------- |
| `profiles`              | `string[]`        | `[]`    | Named AWS profiles to sweep, one account each. Empty uses the ambient credential chain (whatever `AWS_PROFILE` / env is set) as a single account — handy for testing one account before scaling out. |
| `regions`               | `string[]`        | `[]`    | Regions to sweep per account. Required for any output — RDS describe calls are region-scoped and there is no enabled-region discovery here (an SCP-denied region simply becomes a `scan_error`). Pass your org's approved regions. |
| `requiredProfileSuffix` | `string`          | `""`    | If set, every profile (and the ambient `AWS_PROFILE`) must end with this suffix or it is refused before any AWS call. Set to `-readonly` to enforce read-only profiles. The suffix is also stripped to derive the friendly `accountName`. Default `""` disables the check. |

`profiles` and `regions` are arrays — pass them with the `:json=` value suffix:

```sh
swamp model create @jentz/aws-rds-reservations rds-res \
  --global-arg 'profiles:json=["prod-readonly","staging-readonly"]' \
  --global-arg 'regions:json=["us-east-1","us-west-2"]' \
  --global-arg requiredProfileSuffix=-readonly

swamp model method run rds-res sweep
```

Leave `profiles` empty to sweep just the ambient credentials:

```sh
AWS_PROFILE=sandbox-readonly swamp model create @jentz/aws-rds-reservations rds-res \
  --global-arg 'regions:json=["us-east-1"]'
```

### Bootstrap region

The per-account `sts:GetCallerIdentity` call needs a region. Resolution order:
first configured region → `AWS_REGION` → `AWS_DEFAULT_REGION` → `us-east-1`
(used only for that one bootstrap call; the sweep itself only touches the
regions you list).

## Outputs

All three resources have lifetime `infinite` and retain the last 10 versions.

### `instance` resource (factory)

Storage key: `instance-<accountId>-<region>-<dbInstanceIdentifier>`.

| Field                  | Type                 | Notes |
| ---------------------- | -------------------- | ----- |
| `accountId`            | `string`             | 12-digit account id of the sweeping credentials. |
| `accountName`          | `string`             | Profile minus `requiredProfileSuffix`; falls back to the resolved account id when sweeping the ambient chain (no profile to label). |
| `profile`              | `string`             | Profile that produced the row; `""` for ambient. |
| `region`               | `string`             | AWS region. |
| `dbInstanceIdentifier` | `string`             | DB instance identifier. |
| `dbInstanceClass`      | `string`             | e.g. `db.r7g.2xlarge`. |
| `engine`               | `string`             | e.g. `postgres`, `aurora-postgresql`, `mysql`. |
| `engineVersion`        | `string`             | Engine version. |
| `multiAZ`              | `boolean`            | Multi-AZ deployment flag. |
| `status`               | `string`             | Lifecycle status, e.g. `available`. |
| `clusterId`            | `string`             | Owning DB cluster id, or `""` for a standalone instance. |
| `storageType`          | `string`             | e.g. `gp3`, `io1`, `aurora`. |
| `instanceTags`         | `map<string,string>` | All instance tags, flattened. |
| `scannedAt`            | `string`             | ISO 8601 sweep timestamp. |

### `reserved` resource (factory)

Storage key: `reserved-<accountId>-<region>-<reservedDBInstanceId>`.

| Field                  | Type      | Notes |
| ---------------------- | --------- | ----- |
| `accountId`            | `string`  | Owning account id. |
| `accountName`          | `string`  | Friendly account label. |
| `profile`              | `string`  | Producing profile; `""` for ambient. |
| `region`               | `string`  | AWS region. |
| `reservedDBInstanceId` | `string`  | Reservation id. |
| `dbInstanceClass`      | `string`  | Reserved class, e.g. `db.r7g.xlarge`. |
| `productDescription`   | `string`  | The RI's engine, e.g. `postgresql`, `aurora postgresql`. |
| `multiAZ`              | `boolean` | Whether the reservation covers Multi-AZ deployments. |
| `dbInstanceCount`      | `number`  | Number of instances this reservation covers. |
| `state`                | `string`  | e.g. `active`, `payment-pending`, `retired`. |
| `offeringType`         | `string`  | e.g. `All Upfront`, `No Upfront`. |
| `durationSeconds`      | `number`  | Reservation term in seconds. |
| `startTime`            | `string`  | ISO 8601 start time, or `""` if unknown. |
| `scannedAt`            | `string`  | ISO 8601 sweep timestamp. |

### `scan_error` resource (factory)

Storage key: `error-<profile|ambient>-<region|account>-<phase>`.

| Field       | Type                                          | Notes |
| ----------- | --------------------------------------------- | ----- |
| `profile`   | `string`                                      | Profile being swept; `""` for ambient. |
| `accountId` | `string`                                      | Account id if known by the time of failure; `""` otherwise. |
| `region`    | `string`                                      | Region being swept; `""` for account-level failures. |
| `phase`     | `string`                                      | `profile_suffix_check`, `credentials`, `describe_db_instances`, `describe_reserved_db_instances`. |
| `kind`      | `"auth_expired" \| "access_denied" \| "other"` | Coarse classification driving the operator's next action. |
| `message`   | `string`                                      | Error detail. |
| `scannedAt` | `string`                                      | ISO 8601 timestamp. |

CEL reference shape (downstream models / reports):

```cel
data.latest("rds-res", "instance-111122223333-us-east-1-orders-db").attributes.dbInstanceClass
```

## Pairing with the coverage report

Run this model inside a workflow, then require the companion report so the
coverage gap is computed from the rows in the same run:

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
swamp workflow run rds-reservation-coverage
swamp report get aws-rds-reservation-coverage --workflow rds-reservation-coverage
```

## Versioning

Uses swamp Calendar Versioning (`YYYY.MM.DD.MICRO`). The `instance`, `reserved`,
and `scan_error` resource schemas are the contract — adding fields additively is
non-breaking; renaming or removing them is, and will bump the date.

## Issues, contributing, license

- Bug reports and feature requests:
  <https://github.com/jentz/swamp-extensions/issues>
- Security vulnerabilities (private report, not a public issue):
  <https://github.com/jentz/swamp-extensions/security/advisories/new>
- Source:
  <https://github.com/jentz/swamp-extensions/tree/main/aws-rds-reservations>
- License: MIT (see [LICENSE.md](LICENSE.md))
