#!/usr/bin/env bash
#
# Generate a self-signed localhost certificate for loopback tests.
# Regenerates on every run (cheap, and never expires under CI).
#
# Usage: gen_test_certs.sh <outdir>

set -euo pipefail

OUT="${1:?usage: gen_test_certs.sh <outdir>}"
mkdir -p "$OUT"

# -addext needs a newer openssl/libressl; fall back without the SAN
# (the loopback client skips verification anyway).
if ! openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
    -keyout "$OUT/key.pem" -out "$OUT/cert.pem" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    2>/dev/null; then
    openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
        -keyout "$OUT/key.pem" -out "$OUT/cert.pem" \
        -subj "/CN=localhost"
fi

echo "gen_test_certs: wrote $OUT/cert.pem + key.pem"
