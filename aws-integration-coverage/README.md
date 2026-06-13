# @jentz/aws-integration-coverage

Coalesces two independent audit lenses into a single **per-account integration
coverage matrix** — for each account, *is the integration role deployed and
compliant, and by which mechanism?* — flagging where the two lenses disagree.

The two lenses are:

- the **StackSet lens**, [`@jentz/aws-stackset-audit`](../aws-stackset-audit/) —
  the CloudFormation StackSet's own view of which accounts it targets and
  whether each instance is `CURRENT`; and
- the **IAM lens**, [`@jentz/aws-iam-role-audit`](../aws-iam-role-audit/) — the
  on-the-ground view of whether the integration's role(s) actually exist in each
  account, whether they are compliant, and how they were created.

**No AWS calls.** This package never touches the AWS API. It consumes the audit
data the two upstream lenses already captured — so you run the audits first
(directly, or as steps in a workflow), then coalesce.

## A single package, two entry points, one core

This is a **combined model + report** package: one `manifest.yaml` declares both
a queryable model and a workflow-scope report, and both import the same pure
coalesce core (`_lib/coverage.ts`). Because the verdict logic lives in one source
file imported by both, the model and the report always derive **identical**
coverage verdicts — there is no second copy to drift.

`_lib/coverage.ts` is a local import; swamp auto-resolves and bundles it into each
entry point. It is listed in neither `models:` nor `reports:`, so it ships
bundled without surfacing as its own published model entry.

| Entry point | Kind | Reads from | Emits |
| ----------- | ---- | ---------- | ----- |
| `@jentz/aws-integration-coverage` | model | the **data repository** (stored upstream model data) | `coverage` + `summary` resources (CEL-queryable) |
| `@jentz/integration-coverage` | report (workflow scope) | the workflow's **step executions** | `markdown` + `json` artifacts |

## The model — `@jentz/aws-integration-coverage`

A first-class, queryable coalesce. Its single `coalesce` method reads the stored
output of two upstream model instances via the data repository (keeping the
latest active version per data name, tolerantly skipping any artifact that fails
to decode or schema-validate — those are counted, never thrown), runs the shared
core, and writes:

- one **`coverage`** resource per account — the per-account contract: the
  aggregate coverage verdict (`covered-compliant` | `covered-noncompliant` |
  `covered-partial` | `uncovered` | `unknown`), the aggregate mechanism, the
  required-role counts (total / present / compliant), the missing required
  roles, per-role detail, the representative StackSet status, the
  `inStacksetTargets` / `inIamSweep` flags, and a human-readable `reconciliation`
  string; and
- one **`summary`** resource — counts by coverage verdict and by mechanism, the
  per-role rollup (required / present / compliant / missing), the discrepancy /
  uncovered / unknown / manual account lists, and a `sources` provenance block.

It errors only when **neither** upstream produced any rows (a clear "run the
audits first" message); otherwise it produces a matrix over whatever is
available.

### Global arguments

| Argument | Required | Default | Purpose |
| -------- | -------- | ------- | ------- |
| `stacksetModelId` | **yes** | — | Model id of the `@jentz/aws-stackset-audit` instance to read (from `swamp model get <name> --json` `.id`). |
| `iamModelId` | **yes** | — | Model id of the `@jentz/aws-iam-role-audit` instance to read. |
| `stacksetModelType` | no | `@jentz/aws-stackset-audit` | Type of the stackset-audit model (override only if forked). |
| `iamModelType` | no | `@jentz/aws-iam-role-audit` | Type of the iam-role-audit model (override only if forked). |

### Querying it

Because the matrix is model data, you can wire and query it like any other swamp
resource:

```sh
# run the upstream audits, then coalesce
swamp model method run stackset-audit audit
swamp model method run iam-role-audit sweep
swamp model method run coverage coalesce

# every uncovered account
swamp data query 'modelName == "coverage" &&
  specName == "coverage" && attributes.coverage == "uncovered"'
```

(Account ids above are illustrative placeholders — use your own model
instance names.)

## The report — `@jentz/integration-coverage`

A **workflow-scope** report. Instead of reading the data repository, it collects
the same upstream rows from the workflow's **step executions** (matching the
StackSet and IAM steps by model type), runs the **identical** coalesce core, and
renders:

- a **per-account coverage matrix**,
- a **per-role rollup** (present / compliant / missing across accounts in the
  IAM sweep),
- the **account-by-mechanism distribution**, and
- an explicit **lens-disagreements** section.

It emits two artifacts — a human `markdown` document and a structured `json`
payload. **Markdown + JSON only — there is no CSV artifact.** The report
**never throws**: an unexpected failure yields a degraded-but-valid report
(`degraded: true` plus a stub markdown) rather than aborting the workflow.

The JSON payload shape (abbreviated):

```json
{
  "report": "@jentz/integration-coverage",
  "workflow": "acme-coverage",
  "generatedAt": "2026-06-13T00:00:00.000Z",
  "stackSetName": "acme-readonly",
  "roleNames": ["AcmeReadonly"],
  "accounts": [ /* one CoverageRow per account */ ],
  "byCoverage": { "covered-compliant": 12, "uncovered": 1 },
  "byMechanism": { "this-stackset": 12, "manual": 1 },
  "byRole": [ /* per-role rollup: present / compliant / missing */ ],
  "discrepancies": [ /* accounts where the two lenses disagree */ ],
  "unresolvedProfiles": [],
  "skipped": 0,
  "degraded": false
}
```

## How coverage is decided

- Coverage is **per account, aggregated over all of the integration's required
  roles**. An account is `covered-compliant` only when *every* required role is
  present **and** compliant; `covered-partial` when only some required roles are
  present; `covered-noncompliant` when all are present but not all compliant;
  `uncovered` when none are present; and `unknown` when the account is not in the
  IAM sweep at all. A single-role integration is just the one-role case.
- **Mechanism** is refined against the target stackset name — a role created by
  *this* stackset (its CloudFormation stack name carries the
  `StackSet-<name>-` prefix) vs *another* stackset, vs a standalone stack, vs
  manual, vs missing — and aggregates to `mixed` when an account's present roles
  disagree.
- A **lens disagreement** is where the two lenses contradict each other — for
  example the StackSet reports `CURRENT` but a required role is missing, or a
  role is present via this stackset while the instance is not `CURRENT`. These
  are surfaced both in the model `summary` (`discrepancyAccounts`) and in the
  report's dedicated section.

## See also

| Extension | Role in the set |
| --------- | --------------- |
| [`@jentz/aws-stackset-audit`](../aws-stackset-audit/) | Upstream StackSet lens — the StackSet's own view of its instances. |
| [`@jentz/aws-iam-role-audit`](../aws-iam-role-audit/) | Upstream IAM lens — whether the integration role(s) actually exist and comply. |

## License

MIT — see [LICENSE.md](./LICENSE.md).
