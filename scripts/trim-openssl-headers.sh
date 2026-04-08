#!/bin/bash
# trim-openssl-headers.sh
#
# Removes OpenSSL headers that are not needed by fast_crypto_core.cpp.
# This reduces the npm package size by ~1.3 MB.
#
# Run this before publishing: yarn trim-headers
#
# The C++ code only includes: crypto.h, err.h, evp.h, kdf.h, rand.h, sha.h
# These transitively require a small set of other headers (ossl_typ.h,
# opensslconf.h, opensslv.h, e_os2.h, bio.h, lhash.h, safestack.h,
# stack.h, buffer.h, objects.h, obj_mac.h, asn1.h, asn1t.h, bn.h,
# ec.h, symhacks.h, modes.h, hmac.h, rand_drbg.h).
#
# Everything else (SSL/TLS, CMS, OCSP, DES, etc.) is dead weight.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HEADER_DIR="${PROJECT_ROOT}/android/libs/include/openssl"

if [ ! -d "$HEADER_DIR" ]; then
  echo "Error: $HEADER_DIR not found. Run from project root."
  exit 1
fi

# Headers required by our code (direct + transitive dependencies)
KEEP_HEADERS=(
  # Directly included by fast_crypto_core.cpp
  crypto.h
  cryptoerr.h
  err.h
  evp.h
  evperr.h
  kdf.h
  kdferr.h
  rand.h
  rand_drbg.h
  randerr.h
  sha.h

  # Transitive dependencies (required by the headers above)
  opensslconf.h
  opensslv.h
  ossl_typ.h
  e_os2.h
  safestack.h
  stack.h
  bio.h
  bioerr.h
  buffer.h
  buffererr.h
  lhash.h
  objects.h
  objectserr.h
  obj_mac.h
  asn1.h
  asn1err.h
  asn1t.h
  bn.h
  bnerr.h
  ec.h
  ecdh.h
  ecdsa.h
  ecerr.h
  symhacks.h
  modes.h
  hmac.h
  pem.h
  pem2.h
  pemerr.h
  x509.h
  x509err.h
  x509_vfy.h
  x509v3.h
  x509v3err.h
  pkcs7.h
  pkcs7err.h
  rsa.h
  rsaerr.h
  conf.h
  conferr.h
)

echo "Trimming OpenSSL headers in $HEADER_DIR..."
echo "Keeping ${#KEEP_HEADERS[@]} required headers."

removed=0
for header in "$HEADER_DIR"/*.h; do
  basename=$(basename "$header")
  keep=false
  for keep_header in "${KEEP_HEADERS[@]}"; do
    if [ "$basename" = "$keep_header" ]; then
      keep=true
      break
    fi
  done
  if [ "$keep" = false ]; then
    rm "$header"
    ((removed++))
  fi
done

echo "Removed $removed unused headers."
echo "Done."
