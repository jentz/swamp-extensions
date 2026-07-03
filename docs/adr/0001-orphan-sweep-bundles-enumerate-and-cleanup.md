# aws-cfn-orphan-sweep bundles read-only enumeration and mutating cleanup

The stackset extensions split read-only auditing (`@jentz/aws-stackset-audit`)
from mutating operations (`@jentz/aws-stackset-lifecycle`,
`@jentz/aws-stackset-drift-detect`) so a workflow can grant least-privilege
credentials per step. `@jentz/aws-cfn-orphan-sweep` deliberately does not follow
that split: it ships read-only `enumerate`/`enumerateOrg` alongside mutating
`cleanup`/`cleanupOrg` in one extension.

The cleanup's dry-run plan _is_ the enumeration output — both methods depend on
the same salient-resource classification (which custom resource to retain, which
IAM role and Lambda a deletion removes). Extensions cannot import code across
packages, so splitting would duplicate that classification core in two published
packages that must never drift. Least privilege is preserved per-method instead
of per-package: `enumerate`/`enumerateOrg` issue only read-only calls (`List*`,
`sts:GetCallerIdentity`, and `sts:AssumeRole` for the org variant) and run under
a `*-readonly` profile, while `cleanup`/`cleanupOrg` default to dry-run and
mutate nothing unless `apply: true` is set (with an `onlyAccount` canary for the
cross-account path).

## Consequences

- Architecture reviews should not re-propose extracting the mutating methods
  into a sibling extension; the bundling is the decision, not an oversight.
- The safety story lives in the method contracts (read-only defaults, explicit
  `apply`), not in package boundaries — changes to those contracts carry the
  weight the package split would otherwise carry.
