# @jentz/aws-vpc-inventory

Fleet-wide VPC inventory across `profiles × regions`. A single read-only `scan`
method fans out over every configured AWS profile and region in one execution
and emits one `vpc` resource per VPC, plus one `scan_error` for each
`(profile, region)` it could not assess.

Designed for cross-account network audits where you want every VPC — its CIDR
blocks, default-VPC flag, owner account, and tags — in one queryable place,
without scripting around the SDK or running one model per account.

## What it does

The `scan` method, for each account (one per profile, or the ambient credential
chain when no profiles are given):

1. Resolves the account id via `sts:GetCallerIdentity` (this also validates the
   credentials work at all).
2. Determines the regions to scan — the configured `regions`, or each account's
   enabled regions discovered via `ec2:DescribeRegions`.
3. Lists every VPC per region via `ec2:DescribeVpcs` and writes one `vpc` row.

Read-only: only `Describe*` and `sts:GetCallerIdentity` are ever called.

### `vpc` resource

One row per observed VPC:

- `accountId` — the scanning account id (from STS)
- `accountName` — the profile with `requiredProfileSuffix` stripped (`""` when
  ambient); STS does not expose human account names, so this is derived from the
  profile string
- `profile`, `region`, `vpcId`, `vpcName` (the `Name` tag or `""`)
- `vpcIsDefault` — whether this is the AWS-created default VPC
- `ownerAccountId` and `isSharedIn` — `isSharedIn` is true when the owner differs
  from the scanning account, i.e. the VPC is shared in via AWS RAM. Shared-in
  VPCs are kept (so they appear once where consumed) and flagged so they can be
  reconciled against the owning account's own row.
- `cidrBlocks` — the primary IPv4 CIDR followed by every secondary CIDR in
  `associated` state, deduplicated, in describe order
- `vpcTags` — the full tag map, flattened
- `scannedAt` — ISO-8601 timestamp

### `scan_error` resource

A single failure never aborts the wider sweep. Each `(profile, region)` that
cannot be assessed — an expired SSO token, an SCP-denied region, a malformed
response — produces one `scan_error` with `profile`, `accountId`, `region`,
`phase` (`profile_suffix_check`, `credentials`, `describe_regions`,
`describe_vpcs`), `kind` (`auth_expired` | `access_denied` | `other`),
`message`, and `scannedAt`. The companion report
[`@jentz/aws-vpc-inventory-report`](../aws-vpc-inventory-report/) groups these
into operator coverage-gaps.

## Global arguments

| Argument                | Type       | Default | Meaning                                                                                                                                                                |
| ----------------------- | ---------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `profiles`              | `string[]` | `[]`    | Named AWS profiles to sweep, one account each. Empty uses the ambient credential chain as a single account.                                                            |
| `regions`               | `string[]` | `[]`    | Regions to scan per account. Empty discovers each account's enabled regions via `ec2:DescribeRegions`.                                                                 |
| `requiredProfileSuffix` | `string`   | `""`    | If set, every profile (and the ambient `AWS_PROFILE`) must end with this suffix or the profile is refused before any AWS call and recorded as a `scan_error`. Disabled by default. |

Set `requiredProfileSuffix` to e.g. `-readonly` to enforce that the inventory
only ever runs under read-only profiles.

## Running a scan

Create the model with global arguments, then run the single `scan` method:

```sh
swamp model create vpc-fleet \
  --type @jentz/aws-vpc-inventory \
  --global-args '{
    "profiles": ["prod-platform-readonly", "stage-platform-readonly"],
    "requiredProfileSuffix": "-readonly"
  }'

swamp model method run vpc-fleet scan
swamp model get vpc-fleet --json
```

Leave `profiles` empty to inventory the ambient credential chain as a single
account, and leave `regions` empty to discover each account's enabled regions
automatically.

## Required IAM permissions

Read-only:

- `sts:GetCallerIdentity`
- `ec2:DescribeRegions`
- `ec2:DescribeVpcs`

## Querying the output

Resources are written with infinite lifetime. Reference a VPC row from a
downstream model or report via CEL:

```text
data.latest("<scan-name>", "vpc-<accountId>-<region>-<vpcId>").attributes.cidrBlocks
```

## Out of scope

- Any AWS write or mutation — the model is strictly read-only.
- IPv6 CIDRs, subnets, route tables, peering, or any VPC attribute beyond the
  documented `vpc` row.
- Resolving human-readable account names from an Organizations / account API —
  the friendly name is derived only from the profile string.

## Pairs with

[`@jentz/aws-vpc-inventory-report`](../aws-vpc-inventory-report/) — a
workflow-scope report that renders the `vpc` and `scan_error` rows as an
operator markdown table plus a structured JSON payload.
