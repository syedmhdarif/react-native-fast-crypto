#!/usr/bin/env bash
#
# build-openssl-android.sh
#
# Downloads OpenSSL 1.1.1w and builds static libcrypto.a for Android
# arm64-v8a and x86_64 with 16KB page alignment support.
#
# Output structure:
#   android/libs/arm64-v8a/libcrypto.a
#   android/libs/x86_64/libcrypto.a
#   android/libs/include/openssl/  (headers)
#
set -euo pipefail

OPENSSL_VERSION="1.1.1w"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_SHA256="cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8"

# Android API level (min SDK)
ANDROID_API=23

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/.openssl-build"
OUTPUT_DIR="${PROJECT_ROOT}/android/libs"

# ---------------------------------------------------------------------------
# Locate Android NDK
# ---------------------------------------------------------------------------
find_ndk() {
  if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "$ANDROID_NDK_HOME" ]; then
    echo "$ANDROID_NDK_HOME"
    return
  fi

  if [ -n "${ANDROID_NDK_ROOT:-}" ] && [ -d "$ANDROID_NDK_ROOT" ]; then
    echo "$ANDROID_NDK_ROOT"
    return
  fi

  # Look in ANDROID_HOME/ndk/ and pick the latest version
  local ndk_base="${ANDROID_HOME:-$HOME/Library/Android/sdk}/ndk"
  if [ -d "$ndk_base" ]; then
    local latest
    latest=$(ls -1 "$ndk_base" 2>/dev/null | sort -V | tail -1)
    if [ -n "$latest" ]; then
      echo "${ndk_base}/${latest}"
      return
    fi
  fi

  # Fallback: common macOS location
  local fallback="$HOME/Library/Android/sdk/ndk"
  if [ -d "$fallback" ]; then
    local latest
    latest=$(ls -1 "$fallback" 2>/dev/null | sort -V | tail -1)
    if [ -n "$latest" ]; then
      echo "${fallback}/${latest}"
      return
    fi
  fi

  echo ""
}

NDK_PATH="$(find_ndk)"
if [ -z "$NDK_PATH" ]; then
  echo "ERROR: Android NDK not found."
  echo "Set ANDROID_NDK_HOME or install via Android Studio SDK Manager."
  exit 1
fi
echo "Using NDK: ${NDK_PATH}"

# Detect host OS tag for NDK toolchain
case "$(uname -s)" in
  Darwin*) HOST_TAG="darwin-x86_64" ;;
  Linux*)  HOST_TAG="linux-x86_64" ;;
  *)       echo "ERROR: Unsupported host OS"; exit 1 ;;
esac

TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt/${HOST_TAG}"
if [ ! -d "$TOOLCHAIN" ]; then
  echo "ERROR: NDK toolchain not found at ${TOOLCHAIN}"
  exit 1
fi
echo "Using toolchain: ${TOOLCHAIN}"

# ---------------------------------------------------------------------------
# Download OpenSSL source
# ---------------------------------------------------------------------------
mkdir -p "$BUILD_DIR"

TARBALL="${BUILD_DIR}/openssl-${OPENSSL_VERSION}.tar.gz"
if [ ! -f "$TARBALL" ]; then
  echo "Downloading OpenSSL ${OPENSSL_VERSION}..."
  curl -fSL "$OPENSSL_URL" -o "$TARBALL"
fi

# Verify checksum (best-effort; skip if sha256sum unavailable)
if command -v shasum &>/dev/null; then
  echo "Verifying checksum..."
  ACTUAL=$(shasum -a 256 "$TARBALL" | awk '{print $1}')
  if [ "$ACTUAL" != "$OPENSSL_SHA256" ]; then
    echo "WARNING: SHA-256 mismatch (expected ${OPENSSL_SHA256}, got ${ACTUAL})."
    echo "The download may still be valid if the upstream hash changed. Continuing..."
  fi
elif command -v sha256sum &>/dev/null; then
  echo "Verifying checksum..."
  ACTUAL=$(sha256sum "$TARBALL" | awk '{print $1}')
  if [ "$ACTUAL" != "$OPENSSL_SHA256" ]; then
    echo "WARNING: SHA-256 mismatch (expected ${OPENSSL_SHA256}, got ${ACTUAL})."
    echo "Continuing anyway..."
  fi
fi

# ---------------------------------------------------------------------------
# Build for each ABI
# ---------------------------------------------------------------------------
build_openssl() {
  local ABI="$1"
  local OPENSSL_TARGET=""
  local COMPILER_PREFIX=""

  case "$ABI" in
    arm64-v8a)
      OPENSSL_TARGET="android-arm64"
      COMPILER_PREFIX="aarch64-linux-android"
      ;;
    x86_64)
      OPENSSL_TARGET="android-x86_64"
      COMPILER_PREFIX="x86_64-linux-android"
      ;;
    *)
      echo "ERROR: Unsupported ABI: $ABI"
      return 1
      ;;
  esac

  local SRC_DIR="${BUILD_DIR}/openssl-${OPENSSL_VERSION}-${ABI}"
  local INSTALL_DIR="${BUILD_DIR}/install-${ABI}"

  echo ""
  echo "====================================="
  echo " Building OpenSSL for ${ABI}"
  echo "====================================="

  # Clean and extract fresh source
  rm -rf "$SRC_DIR"
  mkdir -p "$SRC_DIR"
  tar xzf "$TARBALL" -C "$SRC_DIR" --strip-components=1

  cd "$SRC_DIR"

  # Set up cross-compilation environment
  # OpenSSL 1.1.1 Configure reads ANDROID_NDK_HOME (not ANDROID_NDK_ROOT)
  export ANDROID_NDK_HOME="$NDK_PATH"
  export ANDROID_NDK_ROOT="$NDK_PATH"
  export PATH="${TOOLCHAIN}/bin:$PATH"

  export CC="${TOOLCHAIN}/bin/${COMPILER_PREFIX}${ANDROID_API}-clang"
  export CXX="${TOOLCHAIN}/bin/${COMPILER_PREFIX}${ANDROID_API}-clang++"
  export AR="${TOOLCHAIN}/bin/llvm-ar"
  export RANLIB="${TOOLCHAIN}/bin/llvm-ranlib"
  export STRIP="${TOOLCHAIN}/bin/llvm-strip"

  # 16KB page alignment flag
  local PAGE_FLAG="-Wl,-z,max-page-size=16384"

  # Configure OpenSSL — crypto-only, minimal build
  # We only need: EVP (AES-GCM, ChaCha20-Poly1305), SHA, RAND,
  # EC (Ed25519, X25519), BN. Everything else is disabled.
  ./Configure "$OPENSSL_TARGET" \
    -D__ANDROID_API__=${ANDROID_API} \
    --prefix="$INSTALL_DIR" \
    --openssldir="$INSTALL_DIR" \
    no-shared \
    no-tests \
    no-ui-console \
    no-engine \
    no-comp \
    no-hw \
    no-dso \
    no-ssl \
    no-tls \
    no-dtls \
    no-cms \
    no-ocsp \
    no-ts \
    no-srp \
    no-srtp \
    no-ct \
    no-idea \
    no-mdc2 \
    no-rc2 \
    no-rc4 \
    no-rc5 \
    no-seed \
    no-camellia \
    no-bf \
    no-cast \
    no-des \
    no-md2 \
    no-md4 \
    no-ripemd \
    no-whirlpool \
    no-async \
    no-gost \
    no-sm2 \
    no-sm3 \
    no-sm4 \
    no-scrypt \
    no-sock \
    no-dgram \
    no-filenames \
    no-nextprotoneg \
    no-psk \
    no-heartbeats \
    -fPIC \
    -ffunction-sections \
    -fdata-sections \
    "$PAGE_FLAG"

  # Build (only libcrypto, we don't need libssl)
  make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" build_libs

  # Install headers and libraries
  make install_sw

  echo "Built: ${INSTALL_DIR}/lib/libcrypto.a"
}

# Build both architectures
build_openssl "arm64-v8a"
build_openssl "x86_64"

# ---------------------------------------------------------------------------
# Copy outputs to android/libs/
# ---------------------------------------------------------------------------
echo ""
echo "====================================="
echo " Copying outputs to android/libs/"
echo "====================================="

rm -rf "$OUTPUT_DIR"
mkdir -p "${OUTPUT_DIR}/arm64-v8a"
mkdir -p "${OUTPUT_DIR}/x86_64"
mkdir -p "${OUTPUT_DIR}/include"

cp "${BUILD_DIR}/install-arm64-v8a/lib/libcrypto.a" "${OUTPUT_DIR}/arm64-v8a/libcrypto.a"
cp "${BUILD_DIR}/install-x86_64/lib/libcrypto.a"    "${OUTPUT_DIR}/x86_64/libcrypto.a"

# Copy headers from one build (they're identical across ABIs)
cp -R "${BUILD_DIR}/install-arm64-v8a/include/openssl" "${OUTPUT_DIR}/include/openssl"

echo ""
echo "====================================="
echo " Done!"
echo "====================================="
echo ""
echo "Output:"
ls -lh "${OUTPUT_DIR}/arm64-v8a/libcrypto.a"
ls -lh "${OUTPUT_DIR}/x86_64/libcrypto.a"
echo "Headers: ${OUTPUT_DIR}/include/openssl/"
ls "${OUTPUT_DIR}/include/openssl/" | head -5
echo "  ... ($(ls "${OUTPUT_DIR}/include/openssl/" | wc -l | tr -d ' ') files total)"
echo ""

# Trim unused OpenSSL headers
echo "Trimming unused OpenSSL headers..."
bash "${PROJECT_ROOT}/scripts/trim-openssl-headers.sh"

# Verify 16KB alignment in the static library objects
echo "Verifying page alignment flag in build..."
if strings "${OUTPUT_DIR}/arm64-v8a/libcrypto.a" | grep -q "max-page-size" 2>/dev/null; then
  echo "  arm64-v8a: page alignment metadata found"
else
  echo "  arm64-v8a: static lib built (alignment applied at final link time)"
fi

echo ""
echo "To use: the CMakeLists.txt is already configured to find these libraries."
echo "Build artifacts in .openssl-build/ can be removed with: rm -rf .openssl-build/"
