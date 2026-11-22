#!/usr/bin/env bash
# Run the versioned TEST-37 scorecard and refresh docs/coverage/<version>.json.
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
cargo test --test scorecard -- --nocapture
mkdir -p docs/coverage
cp target/scorecard.json "docs/coverage/${VERSION}.json"
echo "wrote docs/coverage/${VERSION}.json"
