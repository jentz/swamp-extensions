# @jentz/aws-iam-role-audit

Read-only fleet IAM lens for an integration's roles across many accounts. A
single `audit` method fans out in one execution: for each configured role it
reads the role directly in each account, determines how the role was created
from CloudFormation ownership, validates the role against its expectations, and
writes one `role` resource per (account, role) plus one `scan_error` per account
or phase that cannot be assessed — all queryable with CEL.

Where [`@jentz/aws-stackset-audit`](https://github.com/jentz/swamp-extensions/tree/main/aws-stackset-audit)
answers "what did the StackSet deploy", this model answers "what is *actually*
in IAM right now, and how did it get there" — by reading the role(s) directly in
each account. The two are companions; both feed an integration-coverage
coalescer.

## What it does

The `audit` method, in one locked execution, sweeps every configured account
(one per AWS profile, or the ambient credential chain when no profiles are
given). For each configured role in each account it:

1. `sts:GetCallerIdentity` — resolves the account id for the active
   credentials.
2. `iam:GetRole` — reads the role (or records its absence).
3. `iam:ListAttachedRolePolicies` / `iam:ListRolePolicies` — collects attached
   managed-policy ARNs and inline policy names.
4. `cloudformation:DescribeStackResources` (by physical-resource-id, across the
   configured `stackLookupRegions` in order) — finds the CloudFormation stack
   that owns the role; the first owning stack wins.

It then classifies the management mechanism, parses the trust policy, measures
the role against its expectations, and writes the two resources below.

Read-only: only `iam:Get*` / `iam:List*`,
`cloudformation:DescribeStackResources`, and `sts:GetCallerIdentity` are ever
called, so the audit runs under a `*-readonly` profile.

### Management mechanism

The mechanism is resolved **authoritatively from CloudFormation ownership**, not
from role tags (CloudFormation does not reliably tag the IAM roles it creates;
tags are recorded for reference but never used to classify):

| `managementMechanism`  | Meaning                                                                        |
| ---------------------- | ------------------------------------------------------------------------------ |
| `cfn-stackset`         | Owning stack name starts with `StackSet-` (the StackSet fingerprint).          |
| `cfn-standalone-stack` | Owned by any other CloudFormation stack.                                       |
| `manual`               | Role exists but no CloudFormation stack owns it (made by hand or another tool).|
| `missing`              | Role is absent from the account.                                               |

### Compliance

A **missing role is never compliant**. Otherwise a finding is emitted for each:

- expected managed-policy ARN not attached (exact ARN match),
- expected customer-managed policy not attached (matched by **name**),
- expected trust principal not allowed, and
- a required `sts:ExternalId` the trust policy does not require.

`compliant` is `true` only when the role exists and `findings` is empty.

### `role` resource

One row per (account, role), keyed `role-<account-id>-<roleName>`:

- `accountId`, `accountName` (profile with the required suffix stripped, or
  `""`), `profile` (`""` for ambient)
- `roleName`, `required`, `exists`
- `arn`, `path`, `createDate` (ISO 8601 or `""`)
- `managementMechanism` (the four-value enum above)
- `cfnStackName`, `cfnStackId`, `cfnStackRegion`
- `attachedManagedPolicyArns[]`, `inlinePolicyNames[]`
- `trustPrincipals[]`, `trustExternalIds[]`
- `tags` (map; recorded for reference, not used to classify)
- `compliant`, `findings[]`
- `scannedAt` (ISO 8601)

### `scan_error` resource

One row per account (or account × role) that could not be assessed, keyed
`error-<profile>-<role>-<phase>`:

- `profile` (`""` for ambient), `accountId` (if known), `roleName` (`""` for
  account-level failures)
- `service` — the AWS service that failed (`iam`, `sts`, `sso`, or `""` when no
  AWS call was involved); reads default `""` so rows written before this field
  existed still parse
- `phase` — e.g. `preflight_sso`, `credentials`, `get_role`,
  `profile_suffix_check`
- `kind` — `network` | `auth_expired` | `access_denied` | `other` (`network`, a
  transient DNS/socket failure, is checked first so it is never misread as an
  expired token)
- `message`, `scannedAt` (ISO 8601)

A per-account credential failure or a per-role read failure produces a
`scan_error` and **never aborts the sweep** — the remaining accounts and roles
are still audited.

## Global arguments

Configuration is **multi-role only**: define each role under `roles`. There is
no single-role shorthand.

| Argument                | Type            | Default       | Meaning                                                                                                       |
| ----------------------- | --------------- | ------------- | ------------------------------------------------------------------------------------------------------------- |
| `roles`                 | `RoleSpec[]`    | —             | The integration's roles. At least one is required; an empty list throws a descriptive error.                  |
| `profiles`              | `string[]`      | `[]` (ambient)| Named AWS profiles to sweep, one account each. Empty uses the ambient credential chain as a single account.   |
| `stackLookupRegions`    | `string[]`      | **required**  | Regions searched **in order** for the owning CloudFormation stack. No default — see below.                    |
| `requiredProfileSuffix` | `string`        | `""`          | If set, every profile must end with this suffix or it is refused before any AWS call (e.g. `-readonly`).      |
| `ssoSession`            | `string`        | `""`          | Name of the shared AWS SSO session backing the swept profiles (the `[sso-session <name>]` block in `~/.aws/config`). When set, the audit pre-flights this session's cached token once before the per-profile loop: a genuinely expired token short-circuits the whole sweep with a single `aws sso login` error rather than failing every profile. Empty (default) skips the pre-flight. |
| `region`                | `string`        | `us-east-1`   | Region for the IAM/STS client endpoint. IAM is global; `us-east-1` is safe.                                   |

Each entry in `roles` is a `RoleSpec`:

| Field                         | Type       | Default | Meaning                                                                  |
| ----------------------------- | ---------- | ------- | ------------------------------------------------------------------------ |
| `roleName`                    | `string`   | —       | IAM role name to look for (required, non-empty).                         |
| `expectedManagedPolicyArns`   | `string[]` | `[]`    | Managed-policy ARNs the role must have attached (exact match).           |
| `expectedCustomerPolicyNames` | `string[]` | `[]`    | Customer-managed policy **names** the role must have attached.           |
| `expectedTrustPrincipals`     | `string[]` | `[]`    | Principals that must be allowed to assume the role.                      |
| `expectedExternalId`          | `string`   | `""`    | Required `sts:ExternalId`; `""` skips the external-id check.             |
| `required`                    | `boolean`  | `true`  | Whether the role is expected to be deployed (`false` = its absence is OK).|

### `stackLookupRegions` is required and fails closed

`stackLookupRegions` has **no default**. CloudFormation stacks are regional
while IAM roles are global, so the audit must search the regions where the
owning stack could live. **The wrong region misclassifies a CFN-managed role as
`manual`** — there is no safe default. When `stackLookupRegions` is unset or
empty, the `audit` method throws a descriptive error **before any AWS call**.
List every region where your integration's stacks or StackSet instances live,
in priority order.

## Running an audit

Create the model with global arguments, then run the single `audit` method. The
audit is read-only, so run it under a `*-readonly` profile.

```sh
swamp model create my-iam-role-audit \
  --type @jentz/aws-iam-role-audit \
  --global-args '{
    "roles": [
      {
        "roleName": "AcmeScannerReadonly",
        "expectedManagedPolicyArns": ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
        "expectedCustomerPolicyNames": ["AcmeScannerExtras"],
        "expectedTrustPrincipals": ["arn:aws:iam::<vendor-account-id>:root"],
        "expectedExternalId": "acme-external-id",
        "required": true
      },
      { "roleName": "AcmeScannerEcr", "required": false }
    ],
    "profiles": ["acme-prod-readonly", "acme-staging-readonly"],
    "stackLookupRegions": ["eu-west-1", "us-east-1"],
    "requiredProfileSuffix": "-readonly"
  }'

swamp model method run my-iam-role-audit audit
swamp model get my-iam-role-audit --json
```

Use `<account-id>` and `<vendor-account-id>` above as placeholders for your real
12-digit AWS account ids; no real account ids appear in this README.

## Required IAM permissions

Read-only — a `*-readonly` profile is sufficient. The audit never calls a write,
remediation, or detection-triggering API:

- `sts:GetCallerIdentity`
- `iam:GetRole`
- `iam:ListAttachedRolePolicies`
- `iam:ListRolePolicies`
- `cloudformation:DescribeStackResources`

## Querying the output

Resources are written with infinite lifetime (the last 10 retained). Reference a
row from a downstream model or report via CEL:

```text
data.latest("<audit-name>", "role-<account-id>-<roleName>").attributes.compliant
data.latest("<audit-name>", "role-<account-id>-<roleName>").attributes.managementMechanism
```

## Out of scope

- Any AWS write, mutation, or remediation — the model is strictly read-only.
- Single-role shorthand configuration — define every role under `roles`.
- A default set of `stackLookupRegions` — it is required and fails closed.
- Any new analysis beyond the documented resources, the four-value mechanism
  enum, and the compliance contract.
