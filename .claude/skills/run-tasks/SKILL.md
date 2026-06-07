---
name: run-tasks
description: >
  Autonomously work one or more Backlog.md tasks end-to-end in this swamp
  extensions repo: triage readiness in parallel, order by file overlap, then
  per task implement -> adversarially review -> fix -> commit, and finish with a
  summary plus a Hunk walkthrough. Use when the user names one or more backlog
  task IDs (e.g. "tasks 80-83", "work TASK-84", "run these tickets") and wants
  them carried out with subagent review, not just a single direct edit. Do NOT
  use for a one-line fix the user wants done inline, for pure triage/grooming
  (use the backlog CLI directly), or for non-task ad-hoc coding.
---

# Run Tasks

Orchestrate a batch of Backlog.md tasks the way a careful tech lead would:
read-only readiness review first, then a per-task build/verify/review/commit
loop with adversarial checking. **Keep your own context lean — delegate reading
and editing to subagents, and embed prior findings in their prompts so they
don't re-investigate.** Detailed prompt templates and exact commands:
[references/playbook.md](references/playbook.md).

## Phase 0 — Setup

- [ ] Read `.backlog/INSTRUCTIONS.md` (source of truth for task management
      here).
- [ ] Read each task: `backlog task <id> --plain`. Note `References:` files.
- [ ] Map **file overlap** across the tasks — this decides Phase 3.

## Phase 1 — Triage readiness (parallel, read-only)

Spawn **one read-only subagent per task**, concurrently. Each reads the real
code and returns a verdict: `ready-for-agent` or `needs-info`. It must flag any
**hard-to-reverse decision** (public schema/contract change, irreversible data
migration, anything expensive to undo) and downgrade to `needs-info` when
unsure.

- [ ] Record each verdict in the task: `backlog task edit <id> --notes "..."`.
- [ ] Set status: `backlog task edit <id> -s ready-for-agent` (or `needs-info`).
- [ ] **Stop gate:** for any `needs-info`, surface it to the user for a separate
      `/grill-me` session. Do **not** implement it. Implement only ready tasks.

## Phase 2 — Order

Decide execution order from the file-overlap map:

- **Shared files** → run **sequentially on the current branch** (parallel
  worktrees would only manufacture merge conflicts).
- **Disjoint files** → may run in **parallel worktrees**
  (`isolation: worktree`).
- **Pure-hygiene/scrub tasks** that touch files other tasks grow → run **last**.

State the order and the reasoning before starting.

## Phase 3 — Per-task loop

For each ready task, in order, run these steps (the same bullets apply whether
sequential-on-branch or in a worktree):

1. [ ] `backlog task edit <id> -s in-progress`.
2. [ ] **Implement** (subagent): make the change on the branch, do NOT commit,
       run **all gates** (Phase 4), check satisfied ACs. Bake the triage
       findings into the prompt so it doesn't start cold.
3. [ ] **Adversarially review** (subagent): skeptical, hunt for defects — over-
       and under-rejection, error masking, scope creep, and **test teeth**
       (would the test fail if the bug were reintroduced? have it
       mutation-check). The reviewer runs the gates itself.
4. [ ] **Triage findings:** blocking → fix now (continue the implementer) or, if
       genuinely out of scope, `backlog task create` a follow-up and note it.
       Nits → fix if cheap, else record.
5. [ ] **Verify** diff scope (`git status --porcelain`) and that gates are
       green.
6. [ ] **Commit** — one task per commit, conventional commits,
       external-maintainer voice (no task IDs/agent mechanics in the message).
       See playbook.
7. [ ] `backlog task edit <id> -s done --notes "<what shipped + review outcome>"`.
       Report any blocker back to the user immediately.

## Phase 4 — Gates (swamp extension code)

Run from the repo root. **All must pass before commit** — the last two are
publish gates the test suite never exercises and are easy to forget:

```sh
deno fmt && deno fmt --check
deno lint
deno check <changed>.ts <changed>_test.ts
deno test --allow-read --allow-write --allow-env --allow-net --no-check <dir>/ ...
deno doc --lint <model>.ts                       # no private-type-ref / slow types
swamp extension quality <dir>/manifest.yaml      # target 14/14, fast-check ✓
```

## Phase 5 — Wrap-up

- [ ] Re-run the full gate suite across the stacked commits.
- [ ] Write a **summary**: what shipped per task, what the reviews caught/fixed.
- [ ] Call out **gaps the user must decide** (domain judgments, version/date
      pinning, soft contracts becoming public at publish).
- [ ] If a Hunk session is up, walk the user through it via `/hunk-review`:
      reload to your commit range, drop notes on the load-bearing hunks, and
      navigate them to the most important one. See playbook.
- [ ] Do not push or open a PR unless asked.
