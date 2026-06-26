#!/usr/bin/env bash
#
# Single local quality gate. Mirrors .github/workflows/ci.yml so that a local
# pass predicts a green CI run. Assumes `deno` and `swamp` are on PATH.
#
# Run from anywhere via `deno task check` (wired in deno.json).
#
# Gate order matches CI exactly:
#   1. deno fmt --check
#   2. deno lint
#   3. type check (deno check over every *.ts/*.tsx under extension manifests)
#   4. doc lint (deno doc --lint over the same files)
#   5. per-manifest swamp extension fmt --check
#   6. per-manifest swamp extension quality + push --dry-run --yes
#   7. deno test over the extension dirs
#
# Extension dirs/manifests are discovered automatically with the same
# `find ... -name manifest.yaml` query CI uses; no hardcoded list.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# 1. Format check (respects deno.json fmt excludes).
deno fmt --check

# 2. Lint.
deno lint

# 2b. Shared `_lib` codegen drift gate. Placed early, before the heavy
# per-extension gates, so a stale generated copy fails fast. Mirrors the
# `sync-lib drift` step in CI. Read-only (--check never writes), so a stale
# copy can only fail the gate, never be silently regenerated here.
deno run --allow-read scripts/sync-lib.ts --check

# Discover extension dirs (parent of each manifest.yaml), matching CI verbatim.
extension_dirs=()
while IFS= read -r -d '' manifest; do
  extension_dirs+=("$(dirname "$manifest")")
done < <(
  find . -mindepth 2 -maxdepth 2 -name manifest.yaml \
    -not -path './.swamp/*' \
    -print0 \
  | sort -z
)
if [ "${#extension_dirs[@]}" -eq 0 ]; then
  echo "No extension manifests found"
  exit 1
fi

# 3. Type check: every *.ts/*.tsx under extension dirs.
check_files="$(mktemp)"
doc_files="$(mktemp)"
push_out="$(mktemp)"
trap 'rm -f "$check_files" "$doc_files" "$push_out"' EXIT
find -- "${extension_dirs[@]}" -type f \( -name '*.ts' -o -name '*.tsx' \) \
  -print0 > "$check_files"
if [ ! -s "$check_files" ]; then
  echo "No TypeScript files found under extension manifests"
  exit 1
fi
xargs -0 -n 50 deno check < "$check_files"

# 3b. Type-check the canonical shared `_lib/` (repo-root, no manifest, so the
# per-extension enumeration above does not reach it). Mirrors CI's
# "canonical _lib check" step.
deno check _lib/*.ts

# 4. Doc lint: same enumeration, every exported symbol including `_lib`.
find -- "${extension_dirs[@]}" -type f \( -name '*.ts' -o -name '*.tsx' \) \
  -print0 > "$doc_files"
if [ ! -s "$doc_files" ]; then
  echo "No TypeScript files found under extension manifests"
  exit 1
fi
xargs -0 -n 50 deno doc --lint < "$doc_files"

# 4b. Doc lint the canonical shared `_lib/` source modules (test files carry no
# doc surface). Mirrors CI's "canonical _lib doc lint" step.
deno doc --lint _lib/scan_error.ts _lib/aws_credentials.ts _lib/retry.ts

# Discover manifests (the files themselves) for the swamp gates.
manifests=()
while IFS= read -r -d '' manifest; do
  manifests+=("$manifest")
done < <(
  find . -mindepth 2 -maxdepth 2 -name manifest.yaml \
    -not -path './.swamp/*' \
    -print0 \
  | sort -z
)
if [ "${#manifests[@]}" -eq 0 ]; then
  echo "No extension manifests found"
  exit 1
fi

# 5. Per-manifest formatting check.
for manifest in "${manifests[@]}"; do
  echo "Checking $manifest"
  swamp extension fmt "$manifest" --check
done

# 6. Per-manifest quality + dry-run push gates.
#
# CI sets SWAMP_EXTENSION_REVIEW_DIR at the job level; export the same value
# here so the dry-run push reads the committed .swamp-reviews. The dry-run
# only WARNS (exit 0) when a committed review is stale or missing, so — exactly
# like the CI "extension package gates" step — parse the JSON for
# adversarial-review-report warnings and fail the gate if any extension is
# stale. A genuine push error (non-zero exit) still fails immediately.
export SWAMP_EXTENSION_REVIEW_DIR="$(git rev-parse --show-toplevel)/.swamp-reviews"
stale_manifests=()
stale_packages=()
for manifest in "${manifests[@]}"; do
  echo "Quality $manifest"
  swamp extension quality "$manifest"

  echo "Dry-run push $manifest"
  push_status=0
  swamp extension push "$manifest" --dry-run --json --yes \
    >"$push_out" || push_status=$?
  if [ "$push_status" -ne 0 ]; then
    echo "Dry-run push failed for $manifest (exit $push_status)"
    cat "$push_out"
    exit "$push_status"
  fi
  review_file="$(
    jq -rc 'select(.reviewRuleWarnings)
            | .reviewRuleWarnings[]
            | select(.ruleId == "adversarial-review-report")
            | .file' "$push_out"
  )"
  if [ -n "$review_file" ]; then
    package_name="$(
      jq -rc -s 'first(.[] | select(.status == "dry_run") | .name)
                 // empty' "$push_out"
    )"
    [ -n "$package_name" ] || package_name="(unknown package)"
    echo "Stale or missing adversarial review for $manifest ($package_name)"
    stale_manifests+=("$manifest")
    stale_packages+=("$package_name")
  fi
done

if [ "${#stale_manifests[@]}" -ne 0 ]; then
  echo ""
  echo "Adversarial-review gate FAILED. Regenerate the committed review(s)"
  echo "under .swamp-reviews/ per .swamp-reviews/README.md for:"
  for i in "${!stale_manifests[@]}"; do
    echo "  - ${stale_manifests[$i]}  (${stale_packages[$i]})"
  done
  exit 1
fi

# 7. Tests. Keep --no-check (type checking is gate 3). Coverage is
# intentionally omitted: CI's --coverage/`deno coverage` step is
# observability-only and cannot fail the build, so it is not a gate here.
# The canonical `_lib/` is included explicitly (no manifest, so it is not in
# the enumerated extension dirs) so its unit suites run here and in CI.
deno test \
  --allow-read --allow-write --allow-env --allow-net --no-check \
  _lib/ "${extension_dirs[@]}"
