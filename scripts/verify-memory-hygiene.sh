#!/bin/bash
set -euo pipefail

# Verify that all C++ functions handling sensitive data use SecureBuffer
# for intermediate storage and zero-fill on destruction.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CPP_DIR="$PROJECT_ROOT/cpp"

echo "==> Checking memory hygiene in C++ sources..."

ERRORS=0

# Check that memory_guard.h is included in all cpp files
for f in "$CPP_DIR"/*.cpp; do
  if ! grep -q '#include "memory_guard.h"' "$f"; then
    echo "WARNING: $f does not include memory_guard.h"
    ERRORS=$((ERRORS + 1))
  fi
done

# Check for raw new/malloc without SecureBuffer for key-related vars
if grep -rn 'new uint8_t\[' "$CPP_DIR"/*.cpp | grep -v 'SecureBuffer' | grep -iv 'test'; then
  echo "WARNING: Found raw heap allocations outside SecureBuffer"
  ERRORS=$((ERRORS + 1))
fi

# Check that no plaintext or key variables use std::string (which doesn't zero on dealloc)
if grep -rn 'std::string.*key\|std::string.*password\|std::string.*secret' "$CPP_DIR"/*.cpp; then
  echo "WARNING: Found std::string used for sensitive data — use SecureBuffer instead"
  ERRORS=$((ERRORS + 1))
fi

if [ "$ERRORS" -eq 0 ]; then
  echo "==> Memory hygiene checks passed."
else
  echo "==> Found $ERRORS memory hygiene warnings."
  exit 1
fi
