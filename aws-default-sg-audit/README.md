# @jentz/aws-default-sg-audit

Fleet audit for AWS Security Hub control **EC2.2** — "VPC default security
groups should not allow inbound or outbound traffic". A single read-only `scan`
method fans out over `profiles × regions` in one execution and emits one
`finding` per VPC default security group, plus one `scan_error` for each
`(profile, region)` it could not assess.

The value-add over a plain compliance flag: each non-compliant default SG gets a
**remediation-safety verdict** driven by the ENIs that reference it, so an
operator knows which groups are safe to strip immediately versus which still
have a workload attached that must be migrated first.

## What it does

The `scan` method, for each account (one per profile, or the ambient credential
chain when no profiles are given):

1. Resolves the account id via `sts:GetCallerIdentity` (this also validates the
   credentials work at all).
2. Determines the regions to scan — the configured `regions`, or each account's
   enabled regions discovered via `ec2:DescribeRegions` (so default VPCs in
   regions Security Hub is not evaluating are still caught).
3. Lists every VPC's `default` security group via `ec2:DescribeSecurityGroups`
   and counts its ingress / egress rules. A default SG is EC2.2-compliant only
   when both rule lists are empty.
4. Enumerates the ENIs referencing each default SG via
   `ec2:DescribeNetworkInterfaces` and classifies them, then reads the VPC's
   tags via `ec2:DescribeVpcs` so the operator report can name an owner/team.

Read-only: only `Describe*` and `sts:GetCallerIdentity` are ever called.

### `finding` resource

One row per VPC default security group:

- `accountId` — the scanning account id (from STS)
- `profile` — the profile that produced this finding (`""` when ambient)
- `region`, `vpcId`, `vpcName` (the `Name` tag or `""`), `vpcIsDefault`
- `defaultSgId` — the default security group id (the EC2.2 resource)
- `ingressRuleCount`, `egressRuleCount` — EC2.2 wants both at 0
- `compliant` — true when both rule counts are 0
- `eniCount` and `enis[]` — the ENIs referencing the default SG, each classified
  into a coarse `category` (`amazon-elasticache`, `nat_gateway`, `ec2-instance`,
  …)
- `verdict` — the remediation-safety call (see below)
- `vpcTags` — the full tag map, flattened (surfaces owner/team/service)
- `scannedAt` — ISO-8601 timestamp

The storage key is `finding-<accountId>-<region>-<defaultSgId>`, stable and
unique per `(accountId, region, defaultSgId)`, so re-runs are idempotent.

### Remediation-safety verdict

ENIs referencing the default SG are the universal "is this in use?" signal:

- `compliant` — both rule counts are 0; nothing to do.
- `safe_to_remediate` — non-compliant but **zero** referencing ENIs; all rules
  can be revoked immediately.
- `in_use_needs_migration` — non-compliant and one or more ENIs; the attached
  workload must be moved to a dedicated SG **before** stripping rules, or
  connectivity breaks.

### `scan_error` resource

A single failure never aborts the wider sweep. Each `(profile, region)` that
cannot be assessed produces one `scan_error` with `profile`, `accountId`,
`region`, `service` (the AWS service that failed — `sts`, `ec2`, `sso`, or `""`
when no AWS call was involved), `phase` (`preflight_sso`, `profile_suffix_check`,
`credentials`, `describe_regions`, `describe_security_groups`), `kind`
(`network` | `auth_expired` | `access_denied` | `other`), `message`, and
`scannedAt`. Errors are classified into `network` (a transient DNS/socket
failure — re-run to clear; checked first so a network blip wrapped in a "could
not load credentials" error is not misread as an expired token), `auth_expired`
(operator runs `aws sso login`), `access_denied` (IAM/SCP), and `other`. The
companion report
[`@jentz/aws-default-sg-audit-report`](../aws-default-sg-audit-report/) groups
these into operator coverage-gaps (which profiles need `aws sso login`, which
regions an SCP/IAM policy blocked).

## Global arguments

| Argument                | Type       | Default | Meaning                                                                                                                                                                |
| ----------------------- | ---------- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `profiles`              | `string[]` | `[]`    | Named AWS profiles to sweep, one account each. Empty uses the ambient credential chain as a single account.                                                            |
| `regions`               | `string[]` | `[]`    | Regions to scan per account. Empty discovers each account's enabled regions via `ec2:DescribeRegions`.                                                                 |
| `requiredProfileSuffix` | `string`   | `""`    | If set, every profile (and the ambient `AWS_PROFILE`) must end with this suffix or the profile is refused before any AWS call and recorded as a `scan_error`. Disabled by default. |
| `ssoSession`            | `string`   | `""`    | Name of the shared AWS SSO session backing the swept profiles (the `[sso-session <name>]` block in `~/.aws/config`). When set, the scan pre-flights this session's cached token once before the per-profile loop: a genuinely expired token short-circuits the whole sweep with a single `aws sso login` error rather than failing every profile. Empty (default) skips the pre-flight entirely. |

Set `requiredProfileSuffix` to e.g. `-readonly` to enforce that the audit only
ever runs under read-only profiles.

## Running a scan

Create the model with global arguments, then run the single `scan` method:

```sh
swamp model create default-sg-fleet \
  --type @jentz/aws-default-sg-audit \
  --global-args '{
    "profiles": ["prod-platform-readonly", "stage-platform-readonly"],
    "requiredProfileSuffix": "-readonly"
  }'

swamp model method run default-sg-fleet scan
swamp model get default-sg-fleet --json
```

Leave `profiles` empty to audit the ambient credential chain as a single
account, and leave `regions` empty to discover each account's enabled regions
automatically.

To fail closed on the wrong account, pair the audit with
[`@jentz/aws-context-guard`](https://github.com/jentz/swamp-extensions) in a
workflow before the scan step.

## Required IAM permissions

Read-only:

- `sts:GetCallerIdentity`
- `ec2:DescribeRegions`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeVpcs`
- `ec2:DescribeNetworkInterfaces`

## Querying the output

Resources are written with infinite lifetime. Reference a finding from a
downstream model or report via CEL:

```text
data.latest("<scan-name>", "finding-<accountId>-<region>-<defaultSgId>").attributes.verdict
```

## Out of scope

- Any AWS write or mutation — the model is strictly read-only. It does not
  revoke rules, modify, or delete security groups.
- Security groups other than each VPC's `default` SG, and Security Hub controls
  other than EC2.2.

## Pairs with

[`@jentz/aws-default-sg-audit-report`](../aws-default-sg-audit-report/) — a
workflow-scope report that renders the `finding` and `scan_error` rows as an
operator worklist (safe-to-strip vs needs-migration tables plus coverage gaps)
with a structured JSON payload.
