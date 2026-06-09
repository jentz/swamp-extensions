# `.swamp-reviews/`

Committed, content-hash-bound adversarial review reports consumed by
`swamp extension push`.

`swamp extension push` checks for a recorded adversarial review of the extension
being published. The report path is bound to a **content hash** of the
extension's source and manifest. By default the lookup happens under the system
temp directory, so a clean CI runner never has the report and the push re-warns
with a MEDIUM `adversarial-review-report` `reviewRuleWarnings` entry.

Setting `SWAMP_EXTENSION_REVIEW_DIR` relocates that lookup to this committed
directory. The CI (`.github/workflows/ci.yml` `test` job) and publish
(`.github/workflows/publish.yml` `publish` job) workflows both set:

```yaml
env:
  SWAMP_EXTENSION_REVIEW_DIR: ${{ github.workspace }}/.swamp-reviews
```

so the dry-run and publish steps find the reports under
`.swamp-reviews/swamp-extension-review/<sanitized-name>-<hash>.json` and stay
warning-clean.

## The hash binds to source — regenerate after any change

**Any** change to an extension's source (`*.ts`) or `manifest.yaml` — including
a version bump — changes the content hash and moves the report path, so the
existing JSON no longer matches and the warning returns. When you change an
extension you must regenerate its review:

1. Run the dry-run with the env var set, against the changed manifest:

   ```sh
   SWAMP_EXTENSION_REVIEW_DIR="$PWD/.swamp-reviews" \
     swamp extension push <dir>/manifest.yaml --dry-run --json 2>/dev/null \
     | jq -c 'select(.reviewRuleWarnings)|.reviewRuleWarnings[]
              |select(.ruleId=="adversarial-review-report")'
   ```

   The emitted warning object carries `.file` (the exact new hash path to write
   to) and `.skeleton` (a JSON string of the report with every applicable
   dimension `"verdict": "pending"`).

2. Perform a **fresh, genuine** adversarial review of the changed extension
   against every applicable dimension. See
   [`.claude/skills/swamp/references/extension/references/adversarial-review.md`](../.claude/skills/swamp/references/extension/references/adversarial-review.md)
   for the dimensions and the mandatory mechanical checks. Do not fabricate
   verdicts — the sandbox rejects synthetic all-pass reports.

3. Fill the skeleton: set each dimension's `verdict` to `pass`, `issue` (with a
   concrete `note`), or `na` (with a note explaining why it doesn't apply); set
   `reviewedAt` to a real ISO-8601 timestamp (`date -u +%Y-%m-%dT%H:%M:%SZ`);
   keep `extension` and `version` exactly as the skeleton provides. Write the
   completed JSON to the `.file` path.

4. **Delete the stale report** at the old hash path (it no longer matches any
   manifest and is dead weight).

5. Re-run the dry-run from step 1 and confirm the `adversarial-review-report`
   warning is gone.

An `issue` verdict still clears the warning — the gate only objects to
`pending`/missing verdicts or a report that doesn't match the
name/version/dimension set. It is honest to record a real `issue`.
