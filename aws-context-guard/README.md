# @jentz/aws-context-guard

Workflow-safety primitive that fails closed before any AWS work runs. Verifies
that the shell is pointed at the right AWS account, with the right class of
credentials, before a workflow touches a single API.

## What it does

The `verify` method runs two checks, in order:

1. **`AWS_PROFILE` suffix.** The env var must end with a configurable suffix.
   Default `-readonly` enforces read-only profiles for audit workflows. Set the
   suffix to the empty string to disable the check.
2. **`sts:GetCallerIdentity` account ID.** STS is called and the returned
   `Account` must equal the configured `expectedAccountId`.

If either check fails the method `throw`s, which aborts the workflow before any
downstream step runs. On success, the verified caller identity (account, ARN,
user ID, profile, region, timestamp) is persisted as a `context` resource that
later steps can reference.

Region is intentionally **not** checked. Region is a routing parameter, not an
identity property — a wrong-region call returns no findings (annoying); a
wrong-account call hits the wrong AWS estate (catastrophic). The guard checks
identity; the workflow's own logic should pin a region if it needs to.

## Installation

```sh
swamp extension pull @jentz/aws-context-guard
```

## Required IAM permissions

The principal behind `AWS_PROFILE` needs exactly one permission:

- `sts:GetCallerIdentity`

This is granted to every authenticated AWS identity by default and needs no
explicit policy.

## Quick example

Create the model instance once, with the expected account ID baked in:

```sh
swamp model create @jentz/aws-context-guard aws-guard \
  --global expectedAccountId=123456789012
```

Reference it as the first job in any AWS-touching workflow:

```yaml
jobs:
  - name: guard
    description: Verify AWS context before touching AWS APIs.
    steps:
      - name: verify-context
        task:
          type: model_method
          modelIdOrName: aws-guard
          methodName: verify
        dependsOn: []
        allowFailure: false
  - name: do-aws-work
    # ... real steps here
    dependsOn:
      - job: guard
        condition:
          type: succeeded
```

`allowFailure: false` is the whole point: when `verify` throws, `guard` fails,
and `do-aws-work` never starts because its `dependsOn` condition isn't met.

## Global arguments

| Name                    | Type               | Default     | Description                                                                                                      |
| ----------------------- | ------------------ | ----------- | ---------------------------------------------------------------------------------------------------------------- |
| `expectedAccountId`     | string (12 digits) | (required)  | The AWS account ID the workflow expects. Workflow aborts if `sts:GetCallerIdentity` returns a different account. |
| `requiredProfileSuffix` | string             | `-readonly` | `AWS_PROFILE` must end with this suffix. Set to `""` to disable.                                                 |

Set at model-instance creation time via `--global <key>=<value>`. The `verify`
method takes no per-call arguments.

## Methods

| Method   | Arguments | Returns                     | Side effects                                                                 |
| -------- | --------- | --------------------------- | ---------------------------------------------------------------------------- |
| `verify` | none      | `{ dataHandles: [handle] }` | Throws on failure. On success, writes a `context` resource at key `current`. |

## The `context` resource

On success, `verify` writes the verified caller-identity context so later steps
can reference it via CEL:

| Field        | Type              | Source                                              |
| ------------ | ----------------- | --------------------------------------------------- |
| `accountId`  | string            | `sts:GetCallerIdentity.Account`                     |
| `arn`        | string            | `sts:GetCallerIdentity.Arn`                         |
| `userId`     | string            | `sts:GetCallerIdentity.UserId`                      |
| `profile`    | string            | `AWS_PROFILE` env var                               |
| `region`     | string            | `AWS_REGION` env var (informational, not validated) |
| `verifiedAt` | ISO-8601 datetime | when verify completed                               |

Lifetime: `infinite`. Stored as one entry per model-instance lifetime,
garbage-collected after 10 versions.

## Failure modes

All errors are thrown synchronously and abort the workflow. The message tells
you which check failed:

| Message                                                      | Cause                                                                                   | Fix                                                                              |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `AWS_PROFILE is not set.`                                    | Env var unset.                                                                          | Export an `AWS_PROFILE` that matches your required suffix.                       |
| `AWS_PROFILE='<x>' does not end with required suffix '<y>'.` | Wrong credential class (e.g. admin profile against an audit workflow).                  | Use the read-only variant, or override `requiredProfileSuffix`.                  |
| `sts:GetCallerIdentity returned no Account.`                 | STS returned an empty `Account` field — typically expired SSO session or network issue. | `aws sso login` (or your auth equivalent), then retry.                           |
| `sts:GetCallerIdentity returned account <a>, expected <b>.`  | The profile is valid but points at the wrong account.                                   | Switch profiles, or update `expectedAccountId` if the workflow's target changed. |

Any other thrown error (network failure, signature error, etc.) is the
underlying SDK error, propagated as-is.

## Versioning

Uses swamp Calendar Versioning (`YYYY.MM.DD.MICRO`). Breaking changes to
argument names, the resource schema, or the failure-mode contract will bump the
date and carry release notes. The list of validated checks and their order is
part of the contract.

## Issues, contributing, license

- Bugs, features, security: `swamp issue bug --extension @jentz/aws-context-guard`
- Source:
  <https://github.com/jentz/swamp-extensions/tree/main/aws-context-guard>
- License: MIT (see [LICENSE.md](LICENSE.md))
