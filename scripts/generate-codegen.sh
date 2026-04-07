#!/bin/bash
set -euo pipefail

# Generate native interfaces from TypeScript CodeGen spec.
# This is normally run automatically by React Native's build system,
# but can be invoked manually for debugging.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "==> Generating CodeGen artifacts from NativeFastCrypto.ts..."

cd "$PROJECT_ROOT"

# Run React Native CodeGen
npx react-native codegen --path "$PROJECT_ROOT" --outputPath "$PROJECT_ROOT/codegen"

echo "==> CodeGen complete. Generated files are in codegen/"
