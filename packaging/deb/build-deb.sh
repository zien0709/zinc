#!/usr/bin/env bash
# Build a .deb from a PyInstaller onefile binary.
# Usage: ./build-deb.sh <binary> <version> <arch> <output.deb>
# Example: ./build-deb.sh dist/zinc-linux-x64 0.1.0 amd64 zinc_0.1.0_amd64.deb
set -euo pipefail

BINARY="${1:?binary path required}"
VERSION="${2:?version required}"
ARCH="${3:-amd64}"
OUTPUT="${4:-zinc_${VERSION}_${ARCH}.deb}"

mkdir -p "$(dirname "$OUTPUT")"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Layout
mkdir -p "$STAGE/usr/local/bin"
cp "$BINARY" "$STAGE/usr/local/bin/zinc"
chmod 755 "$STAGE/usr/local/bin/zinc"

mkdir -p "$STAGE/DEBIAN"
sed "s/^Version: .*/Version: $VERSION/; s/^Architecture: .*/Architecture: $ARCH/" \
    "$(dirname "$0")/control" > "$STAGE/DEBIAN/control"

dpkg-deb --root-owner-group --build "$STAGE" "$OUTPUT"
echo "Built: $OUTPUT"
