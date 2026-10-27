#!/usr/bin/env bash
# Vendor the Tasky sample app into app/src at a pinned commit, so a moving
# upstream branch can never change what we build (supply-chain hygiene).
set -euo pipefail
TASKY_COMMIT="${TASKY_COMMIT:-4c432729814c8056df37c31e5d18fa325fd862d1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
rm -rf "$ROOT/app/src"
git clone --quiet https://github.com/jeffthorne/tasky.git "$ROOT/app/src"
git -C "$ROOT/app/src" checkout --quiet "$TASKY_COMMIT"
rm -rf "$ROOT/app/src/.git" "$ROOT/app/src/.github" "$ROOT/app/src/Dockerfile" "$ROOT/app/src/.env"
echo "Vendored tasky@$TASKY_COMMIT into app/src"
