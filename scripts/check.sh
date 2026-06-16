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
find -- "${extension_dirs[@]}" -type f \( -name '*.ts' -o -name '*.tsx' \) \
  -print0 > "$check_files"
if [ ! -s "$check_files" ]; then
  echo "No TypeScript files found under extension manifests"
  exit 1
fi
xargs -0 -n 50 deno check < "$check_files"

# 4. Doc lint: same enumeration, every exported symbol including `_lib`.
doc_files="$(mktemp)"
find -- "${extension_dirs[@]}" -type f \( -name '*.ts' -o -name '*.tsx' \) \
  -print0 > "$doc_files"
if [ ! -s "$doc_files" ]; then
  echo "No TypeScript files found under extension manifests"
  exit 1
fi
xargs -0 -n 50 deno doc --lint < "$doc_files"

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
# here so the dry-run push reads the committed .swamp-reviews and does not
# surface a spurious adversarial-review warning that CI would not. The dry-run
# only WARNS on a stale review hash (e.g. aws-integration-coverage on this
# branch); that is non-fatal and we rely on the dry-run's own exit code.
export SWAMP_EXTENSION_REVIEW_DIR="$(git rev-parse --show-toplevel)/.swamp-reviews"
for manifest in "${manifests[@]}"; do
  echo "Quality $manifest"
  swamp extension quality "$manifest"
  echo "Dry-run push $manifest"
  swamp extension push "$manifest" --dry-run --yes
done

# 7. Tests. Keep --no-check (type checking is gate 3). Coverage is
# intentionally omitted: CI's --coverage/`deno coverage` step is
# observability-only and cannot fail the build, so it is not a gate here.
deno test \
  --allow-read --allow-write --allow-env --allow-net --no-check \
  "${extension_dirs[@]}"
