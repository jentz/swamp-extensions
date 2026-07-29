# @jentz/audit-timeline

Workflow-scope swamp report that renders a **change-audit timeline** from
CloudWatch Logs Insights query rows collected earlier in the workflow, plus an
**actor roster** and **ready-to-run identity-resolution SQL**.

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
    }
  }
}
```

## What it emits

- **Markdown**: timeline table (ISO-8601 UTC ms timestamps; actor, verb
  add/update/delete derived from the HTTP method, service, site parsed from
  `/sites/{site}/` paths, path, status, submitted body), actor roster with
  change counts and first/last-seen, and the identity-resolution SQL in a
  fenced block — intended for a human with database access to run; results
  never flow back into the toolkit.
- **JSON**: `events[]` (normalized rows), `actors[]`, `resolutionSql[]`,
  `skipped`, `degraded`.

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
