# Run Tasks — Playbook

Reusable prompt templates and exact commands for the `run-tasks` workflow. Adapt
the bracketed parts per task; keep the structure.

## Why this shape works

- **Parallel read-only triage** surfaces ambiguity and irreversible decisions
  _before_ any code is written, so a `/grill-me` happens once, up front.
- **Sequential-on-branch for shared files** avoids merge conflicts that parallel
  worktrees would create; worktrees are only worth their cost for disjoint
  files.
- **An adversarial reviewer per task** catches the defects the implementer is
  blind to. In practice this is where the real bugs are found — key collisions,
  over-rejection, weak tests. Insist on **mutation-checking test teeth**.
- **Orchestrator stays lean:** subagents read and edit; you coordinate. Pass
  each subagent the prior findings so it starts warm, not cold.

## Triage-readiness subagent (Phase 1, one per task, read-only)

> You are reviewing backlog TASK-<id> for READINESS before an autonomous agent
> implements it. Do NOT implement anything — read-only. Repo:
> /Users/mark/code/jentz/swamp-extensions (swamp extensions, Deno). Load the
> `swamp` skill if you need extension context. TICKET: <paste title +
> description + acceptance criteria + plan>. Read the referenced code and
> decide: READY-FOR-AGENT (clear, unambiguous, safe to do autonomously) or
> NEEDS-INFO (ambiguous, or contains a HARD-TO-REVERSE decision the human should
> settle in a /grill-me first — public schema/contract changes, irreversible
> migrations, anything expensive to undo). RETURN exactly: VERDICT:
> ready-for-agent | needs-info CONFIDENCE: high|medium|low WHY: 2-4 sentences.
> HARD-TO-REVERSE: bullets, or "none". GAPS (if needs-info): specific questions
> for the human. IMPLEMENTATION NOTES: 2-5 concrete bullets (key functions, line
> areas, existing patterns to reuse, which fields/contracts matter). Keep it
> tight. Do not edit files.

For a publish-status crux (e.g. "is this extension published yet?"), tell the
subagent to verify with
`swamp extension version --manifest <dir>/manifest.yaml
--json` (look at
`currentPublished` / `nextVersion`) and `swamp extension info`.

## Implementation subagent (Phase 3 step 2)

> Implement backlog TASK-<id> in /Users/mark/code/jentz/swamp-extensions (swamp
> extensions, Deno). Make the changes, run checks, report. Work ONLY on the
> current branch — NO branches/worktrees, do NOT commit (orchestrator commits).
> NOTE: prior tasks already committed on this branch touched <file>; RE-READ the
> file, don't trust stale line numbers. TICKET + CONFIRMED TRIAGE FINDINGS:
> <paste the triage notes so it starts warm>. CHANGES:
> <enumerate against each AC>. Constraints: <e.g. don't change public schemas;
> keep public facade byte-identical>. VERIFY (repo root): <the Phase 4 gate
> block>. Then check satisfied ACs: `backlog task edit <id> --check-ac <n>` for
> each. RETURN: WHAT CHANGED (file-by-file), AC STATUS (incl. any N/A + why),
> GATE RESULTS (each gate pass/fail + key line), SURPRISES/DEVIATIONS, FILES
> TOUCHED. Do not commit. Do not push.

## Adversarial-review subagent (Phase 3 step 3)

> Adversarially review an UNCOMMITTED change in /Users/mark/code/jentz/swamp-
> extensions. Be skeptical — find defects, don't rubber-stamp. Do NOT edit. The
> change implements TASK-<id>: <summary + the decisions the implementer made>.
> Review ONLY the uncommitted diff (the branch has prior committed work — ignore
> it): `cd <repo> && git diff && git status`. CHECK: correctness on every path;
> OVER-rejection (does it wrongly reject valid inputs?) AND UNDER-rejection
> (does it catch what it claims?); error masking; public contract/schema
> unchanged; scope limited to intended files; and TEST TEETH — would the new
> tests FAIL if the bug were reintroduced? Mentally or actually MUTATE the
> source to confirm. Run all gates yourself. RETURN: VERDICT (approve |
> approve-with-nits | request-changes); BLOCKING ISSUES (file:line + concrete
> fix, or none); NITS; a one-line teeth assessment; and the gate/test summary
> lines you saw when YOU ran them.

When the reviewer flags a real test-teeth gap or bug, send the implementer back
to fix it and require a **mutation check** ("temporarily reintroduce the bug,
confirm the test goes red, restore") in the fix report.

## Gates (exact, swamp extension)

```sh
cd /Users/mark/code/jentz/swamp-extensions
deno fmt && deno fmt --check
deno lint
deno check <dir>/<model>.ts <dir>/tests/*.ts <dir>/*_test.ts
deno test --allow-read --allow-write --allow-env --allow-net --no-check \
  aws-rds-reservations/ aws-rds-reservation-coverage/   # mirror .github/workflows/ci.yml
deno doc --lint <dir>/<model>.ts
swamp extension quality <dir>/manifest.yaml             # want "14/14" and fast-check ✓
```

`deno doc --lint` + `swamp extension quality` are NOT covered by the test suite
and have slipped past test-only reviews. **Always run them on extension `.ts`
changes**, especially anything that adds an `export`ed type for a test seam — an
exported type must not reference private types (e.g. SDK command classes).
Prefer non-exported seam types, or widen generics to a public/`unknown` type.

## Commit & git hygiene

- One task per commit. Conventional commits: `feat|fix|refactor|test: <subject>`
  (≤50 chars, imperative, no trailing period). Body wrapped at 72, blank line
  after subject.
- Write as an external maintainer: describe the shipped change and why it
  matters. Do NOT mention task IDs, backlog, agents, reviews, or planning.
- `git add` only the intended files (confirm with `git status --porcelain`
  first). Stay on the working branch; do not push or open a PR unless asked.

## Hunk walkthrough (Phase 5)

```sh
hunk session list --json                       # find the live session
hunk session reload --repo . -- diff <baseline>...HEAD   # baseline = tip before your work
hunk session review --repo . --json            # file/hunk structure (add --include-patch only if needed)
hunk session comment apply --repo . --stdin     # batch notes: {"comments":[{filePath,newLine,summary,rationale}]}
hunk session navigate --repo . --file <f> --new-line <n>  # steer the user to the key hunk
```

Reload to **your** commit range (the existing session may show older work).
Comment only on the load-bearing hunks — the bug fixes, the contract decisions,
the gaps the user must weigh — not every change. Then narrate the story in chat:
order, what each review caught, and the open gaps.
