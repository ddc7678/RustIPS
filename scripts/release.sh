#!/usr/bin/env bash
# Build the single-binary release artefact and its SHA-256 checksum.
set -euo pipefail
cd "$(dirname -- "${BASH_SOURCE[0]}")/.."

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
[[ -n "$VERSION" ]] || { echo "cannot read version from Cargo.toml" >&2; exit 1; }
ARCH="$(uname -m)"
NAME="rustips-${VERSION}-linux-${ARCH}"

cargo build --release --locked
mkdir -p dist
install -m 0755 target/release/rustips "dist/${NAME}"
(cd dist && sha256sum "${NAME}" > "${NAME}.sha256")
cp "docs/coverage/${VERSION}.json" "dist/${NAME}-scorecard.json" 2>/dev/null || true

echo
echo "artefact: dist/${NAME}"
echo "checksum: dist/${NAME}.sha256"
ls -lh "dist/${NAME}" "dist/${NAME}.sha256"
echo
echo "Install on a target host with only this file:"
echo "  scp dist/${NAME} user@host:/tmp/rustips"
echo "  ssh user@host 'sudo /tmp/rustips setup --non-interactive --install-service'"
echo "  ssh user@host 'sudo systemctl enable --now rustips'"
