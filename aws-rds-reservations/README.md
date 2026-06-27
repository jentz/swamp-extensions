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

This repo ships RDS extensions that work at **different levels** — pick the
one that matches your question:

| Extension | Level | Use it when you want… |
| --------- | ----- | --------------------- |
| [`@jentz/aws-rds-inventory`](../aws-rds-inventory/) | **Cluster** | A CEL-filterable audit of Aurora / Multi-AZ DB **clusters** and their members in one region — one resource per cluster, one per cluster member. |
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
  region, instance class, engine, license model, Multi-AZ flag, status, owning
  cluster id (empty for standalone instances), storage type, and tags;
- one **`reserved`** resource per reservation, carrying the offered class,
  product description (engine), Multi-AZ flag, instance count, state, offering
  type, and term;
- **`scan_error`** resources for failures: at most one per `(profile, region)`
  phase that fails, plus one per malformed row for the per-row malformed phases
  (`malformed_db_instance` / `malformed_reserved_db_instance`).

### Failures become rows, never aborts

An expired SSO token, an SCP-denied region, or a malformed response is recorded
as a `scan_error` and the sweep continues. A single bad account or region can
never blank out the rest of the fleet. Errors are classified into `network`
(transient DNS/socket failure — re-run to clear), `auth_expired` (operator runs
`aws sso login`), `access_denied` (IAM/SCP), and `other`, so the companion
report can tell "needs login" apart from "genuinely denied" apart from "blip".
The `network` bucket is checked first, so a DNS/socket failure wrapped in a
"could not load credentials" error is not misread as an expired token. Each row
also carries the `service` that failed (`rds`, `sts`, `sso`, or `""`).

When the optional `ssoSession` argument names the shared SSO session, the sweep
pre-flights that session's cached token once before the per-profile loop: a
genuinely expired token short-circuits the whole sweep with a single
`service: "sso"` / `auth_expired` error ("run `aws sso login`") rather than
failing every profile identically. A transient network blip during the
pre-flight does **not** short-circuit — the sweep proceeds, since a re-login
would not fix a DNS hiccup.

Individual malformed AWS rows are handled the same way. The public `instance`
and `reserved` schemas treat every field as real data, so before a row is
written the sweep validates the coverage-critical fields of the raw AWS
response. A DB instance missing its identifier, class, engine, or status, or a
reservation missing its id, class, product description, instance count (`> 0`),
state, or Multi-AZ flag, is **not** written as a resource and is **not**
silently dropped. Instead it becomes a `scan_error` (`malformed_db_instance` or
`malformed_reserved_db_instance`) naming the account, region, and the
missing/invalid fields. Unlike the once-per-`(profile, region)` phases, these
per-row phases emit **one `scan_error` per malformed row**, each with a unique
key — the per-row discriminator is folded into the stored `phase` (e.g.
`malformed_db_instance:0:orders-db`) so when an API shift breaks every row in a
region they are all reported, not collapsed into one. This keeps a malformed or
API-shifted response from laundering into an apparently-valid resource with
empty/zero placeholders that would understate reservation coverage.

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
| `regions`               | `string[]`        | `[]`    | Regions to sweep per account. **Required** — RDS describe calls are region-scoped and there is no enabled-region discovery here (an SCP-denied region simply becomes a `scan_error`). Pass your org's approved regions. If empty or omitted, the sweep makes no AWS calls and writes a single `no_regions` `scan_error` (zero `instance`/`reserved` rows) so the misconfiguration is visible, not a silent empty result. |
| `requiredProfileSuffix` | `string`          | `""`    | If set, every named profile must end with this suffix or it is refused before any AWS call. Set to `-readonly` to enforce read-only profiles. Ambient credentials have no reliable profile label, so leave this empty when `profiles` is `[]` or pass an explicit named profile instead. The suffix is also stripped to derive the friendly `accountName`. Default `""` disables the check. |
| `ssoSession`            | `string`          | `""`    | Name of the shared AWS SSO session backing the swept profiles (the `[sso-session <name>]` block in `~/.aws/config`). When set, the sweep pre-flights this session's cached token once before the per-profile loop: a genuinely expired token short-circuits the whole sweep with a single `aws sso login` error rather than failing every profile. Empty (default) skips the pre-flight entirely. |

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

The `instance` / `reserved` storage keys join the free identifier with a double
hyphen `--` (the same separator the sibling `@jentz/aws-rds-inventory` uses). The
`accountId` (fixed 12 digits) and `region` (closed AWS set) prefixes keep single
hyphens because they are self-delimiting, and RDS forbids consecutive hyphens
inside an identifier — so the lone `--` always marks the identifier boundary.
`scan_error` rows use the shared `@jentz/aws-*` fleet key instead (single
hyphens, `ambient`/`account` sentinels — see below). Treat keys as opaque; the
format is a published contract, not something to parse.

### `instance` resource (factory)

Storage key: `instance-<accountId>-<region>--<dbInstanceIdentifier>`.

| Field                  | Type                 | Notes |
| ---------------------- | -------------------- | ----- |
| `accountId`            | `string`             | 12-digit account id of the sweeping credentials. |
| `accountName`          | `string`             | Profile minus `requiredProfileSuffix`; falls back to the resolved account id when sweeping the ambient chain (no profile to label). |
| `profile`              | `string`             | Profile that produced the row; `""` for ambient. |
| `region`               | `string`             | AWS region. |
| `dbInstanceIdentifier` | `string`             | DB instance identifier. |
| `dbInstanceClass`      | `string`             | e.g. `db.r7g.2xlarge`. |
| `engine`               | `string`             | e.g. `postgres`, `aurora-postgresql`, `mysql`, `oracle-ee`, `sqlserver-se`. |
| `engineVersion`        | `string`             | Engine version. |
| `licenseModel`         | `string`             | e.g. `license-included`, `bring-your-own-license`, `general-public-license`; `""` if unreported (Aurora / RDS Custom). Decisive for Oracle BYOL-vs-LI size-flex routing in the coverage report. |
| `multiAZ`              | `boolean`            | Multi-AZ deployment flag. |
| `status`               | `string`             | Lifecycle status, e.g. `available`. |
| `clusterId`            | `string`             | Owning DB cluster id, or `""` for a standalone instance. |
| `storageType`          | `string`             | e.g. `gp3`, `io1`, `aurora`. |
| `instanceTags`         | `map<string,string>` | All instance tags, flattened. |
| `scannedAt`            | `string`             | ISO 8601 sweep timestamp. |

### `reserved` resource (factory)

Storage key: `reserved-<accountId>-<region>--<reservedDBInstanceId>`.

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

Storage key: `error-<profile|ambient>-<region|account>-<service>-<phase>` — the
shared `@jentz/aws-*` fleet key, with the four segments joined by hyphens. An
absent profile renders as the `ambient` sentinel and an absent region as
`account`; a pre-call gate with no AWS service involved leaves the `service`
segment empty, so the key shows an empty segment there (e.g.
`error-ambient-account--no_regions`). The per-row malformed phases fold their row
discriminator into the `phase` segment (e.g.
`error-prod-readonly-us-east-1-rds-malformed_db_instance:0:orders-db`) so two
malformed rows in one (profile, region) get distinct keys.

| Field       | Type                                                        | Notes |
| ----------- | ----------------------------------------------------------- | ----- |
| `profile`   | `string`                                                    | Profile being swept; `""` for ambient. |
| `accountId` | `string`                                                    | Account id if known by the time of failure; `""` otherwise. |
| `region`    | `string`                                                    | Region being swept; `""` for account-level failures. |
| `service`   | `string`                                                    | AWS service that failed: `rds`, `sts`, `sso`, or `""` (no AWS call involved). Reads default `""` so rows written before this field existed still parse. |
| `phase`     | `string`                                                    | `preflight_sso`, `no_regions`, `profile_suffix_check`, `credentials`, `describe_db_instances`, `describe_reserved_db_instances`, `malformed_db_instance`, `malformed_reserved_db_instance`. `preflight_sso` is the single SSO short-circuit row; `no_regions` is the single account-less row written when `regions` is empty (see the `regions` argument). The two `malformed_*` phases are written per individual AWS row that is missing a coverage-critical field (the row is not emitted as an `instance`/`reserved` resource) and carry a `:ordinal:rowId` discriminator. |
| `kind`      | `"network" \| "auth_expired" \| "access_denied" \| "other"` | Coarse classification driving the operator's next action. `network` (checked first) is a transient DNS/socket failure. |
| `message`   | `string`                                                    | Error detail. |
| `scannedAt` | `string`                                                    | ISO 8601 timestamp. |

CEL reference shape (downstream models / reports):

```cel
data.latest("rds-res", "instance-<accountId>-us-east-1--orders-db").attributes.dbInstanceClass
```

## Throttling

`DescribeDBInstances` and `DescribeReservedDBInstances` are paginated, and a
fleet-wide sweep fans out across many `profiles × regions` — exactly where AWS
throttling bites. A throttled describe is otherwise caught and degrades that
(account, region) to a `scan_error`, silently dropping its capacity from the
coverage report (an under-count that skews the purchase recommendation). To
avoid that, each page request is wrapped in a `withRetry` helper — a
byte-identical twin of the sibling `@jentz/aws-rds-inventory`'s, modeled on the
upstream `@swamp/aws/rds` helper: exponential backoff with **full jitter** —
each retry delay is uniformly sampled from `[0, min(baseDelay * 2 ** n,
maxDelay)]` — base 1s, ceiling 90s, up to 20 attempts. Full jitter is the
AWS-documented recommendation for decorrelating concurrent callers. Each retry
logs at `debug` level.

The retry wraps each individual page send, resuming at the same `Marker` rather
than restarting pagination from the first page (which would re-fetch earlier
pages and worsen the throttle). Only a throttle that survives all attempts
reaches the `scan_error` path. There is no page cap: every page is drained,
because a silent truncation is the same data-completeness bug this retry
prevents.

Throttling detection matches by SDK error `name` (`ThrottlingException`,
`TooManyRequestsException`, `RequestLimitExceeded`, `RequestThrottledException`,
`Throttling`) with a word-boundary message fallback for generic-Error SDK
wrappers. Non-throttling errors propagate immediately.

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

Model upgrades transform stored `globalArguments`, not already-collected
resource rows. When a new resource field is added (for example
`instance.licenseModel`), previously collected rows are not rewritten by the
upgrade — they keep the field's schema default until you re-run `sweep`. Re-run
a sweep to populate new resource fields with their real values.

## Issues, contributing, license

- Bug reports and feature requests:
  <https://github.com/jentz/swamp-extensions/issues>
- Security vulnerabilities (private report, not a public issue):
  <https://github.com/jentz/swamp-extensions/security/advisories/new>
- Source:
  <https://github.com/jentz/swamp-extensions/tree/main/aws-rds-reservations>
- License: MIT (see [LICENSE.md](LICENSE.md))
