# @jentz/audit-timeline

Workflow-scope swamp report that renders a **change-audit timeline** from
CloudWatch Logs Insights query rows collected earlier in the workflow, plus an
optional **failed-attempts section**, an **actor roster**, and **ready-to-run
identity-resolution SQL**.

## What it consumes

The report scans the workflow's step executions for two artifact kinds:

- `query_results` — Logs Insights rows, as produced by `@webframp/aws/logs`
  `query` (any model emitting the same `{ results: [{field: value}] }` shape
  works).
- `config` — a parsed JSON config object, as produced by
  `@jentz/local-config` `load`. This is where every environment-specific
  detail lives; the published report contains none.

## Config contract

All keys are optional; without `identityResolution` no SQL is emitted, and
without overrides the default field names are used.

```jsonc
{
  "identityResolution": {
    // {account} and {userid_list} are substituted per distinct account
    "sqlTemplate": "SELECT LOWER(HEX(userid)) AS userid_hex, email FROM db{account}.admin_users WHERE userid IN ({userid_list});",
    // per-actor term; {guid_hex} = actor id with braces/dashes stripped
    "useridTerm": "UNHEX('{guid_hex}')"
  },
  // optional source-IP -> origin annotation (rows need a sourceIp field)
  "natMap": {
    "198.51.100.7": { "account": "prod-x", "service": "worker", "note": "NAT egress" }
  },
  "auditTimeline": {
    "fields": {
      // defaults shown; override to match your log shape
      "timestamp": "@timestamp",
      "actor": "user_id",
      "account": "account_id",
      "requestId": "request_id",
      "service": "service",
      "method": "http.method",
      "path": "http.path",
      "status": "http.status",
      "body": "http.body",
      "sourceIp": ""
    },
    // optional: presence enables the "Failed attempts" section
    "failedAttempts": {
      // partition field for primary rows; defaults to fields.status.
      // numeric >= 400 -> rejectedFamily, absent or non-numeric ->
      // noResponseFamily, anything else stays on the change timeline
      "statusField": "http.status",
      "rejectedFamily": "rejected",
      "noResponseFamily": "no-response",
      // extra datasets that are failed attempts in their entirety, keyed
      // by the workflow step name that produced them
      "datasets": {
        "query-failed-graphql": {
          "family": "graphql-error",
          "fields": {
            "timestamp": "@timestamp",
            "actor": "",              // "" renders as `unknown`
            "operation": "operationName",
            "detail": "extensions"
          }
        }
      }
    }
  }
}
```

### Failed-attempts semantics

- Primary rows (any `query_results` dataset not listed in `datasets`) are
  partitioned on `statusField`: numeric `>= 400` becomes a failed attempt
  labeled `rejectedFamily`; an absent or non-numeric status becomes
  `noResponseFamily`; everything else stays on the change timeline.
- Partitioned-out primary rows keep their identity, so they still feed the
  actor roster and the resolution SQL.
- Dataset rows are failed attempts in their entirety, labeled with the
  dataset's `family`, and never enter the timeline, the actor roster, or the
  resolution SQL.

## What it emits

- **Markdown**: timeline table (ISO-8601 UTC ms timestamps; actor, verb
  add/update/delete derived from the HTTP method, service, site parsed from
  `/sites/{site}/` paths, path, status, submitted body), an optional failed-
  attempts table (timestamp, family, actor or `unknown`, operation, detail;
  `None found.` when empty), actor roster with change counts and
  first/last-seen, and the identity-resolution SQL in a fenced block —
  intended for a human with database access to run; results never flow back
  into the toolkit.
- **JSON**: `events[]` (normalized rows), `failedAttempts[]`, `actors[]`,
  `resolutionSql[]`, `skipped`, `incompleteQueries[]`,
  `incompleteQueryCount`, `degraded`.

## Usage

Require it from a workflow whose steps produce the two artifacts:

```yaml
jobs:
  - name: forensics
    steps:
      - name: load-config   # @jentz/local-config `load`
        ...
      - name: query-changes # @webframp/aws/logs `query`
        ...
reports:
  require:
    - "@jentz/audit-timeline"
```

Then read it back:

```bash
swamp report get @jentz/audit-timeline --workflow <workflow> --markdown
```

## Guarantees

The report never throws: unreadable or schema-mismatched artifacts are counted
in `skipped`, and an unexpected failure degrades to a still-valid report with
`degraded: true`.

Incomplete queries are surfaced, never silent. A `query_results` artifact
whose `status` is present but not `Complete` — for example `Running` after a
timed-out Logs Insights wait — is listed in `incompleteQueries[]` and stamped
as a warning at the top of the markdown body. An empty timeline backed by a
cut-off query says so explicitly instead of reading as "no changes".
