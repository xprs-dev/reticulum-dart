#!/bin/sh
# Reticulum for the browser: web/rns_browser.dart compiled to one JS file
# (portal/docs/plan-browser-reticulum.md).
#   tool/build_rns_js.sh [OUT.js]     default build/rns.js
set -e
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$HERE/build/rns.js}"
mkdir -p "$(dirname "$OUT")"
DART="$(command -v dart || echo "$HOME/flutter/bin/dart")"
cd "$HERE"
"$DART" compile js -O2 --no-source-maps -o "$OUT" web/rns_browser.dart
rm -f "$OUT.deps"
ls -l "$OUT"
