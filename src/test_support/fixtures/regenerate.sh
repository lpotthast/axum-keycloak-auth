#!/usr/bin/env bash
# Regenerates the throwaway test keys and their public JWKs. See README.md.
#
# Usage: regenerate.sh [rsa_bits]   (default: 2048)

set -euo pipefail

readonly rsa_bits="${1:-2048}"
fixture_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly fixture_dir

if [[ ! "${rsa_bits}" =~ ^[0-9]+$ ]] || ((rsa_bits < 2048)); then
    echo "RSA size must be an integer of at least 2048 bits; got '${rsa_bits}'." >&2
    exit 2
fi

for tool in openssl xxd; do
    if ! command -v "${tool}" >/dev/null; then
        echo "Required tool '${tool}' was not found in PATH." >&2
        exit 127
    fi
done

# Generate into a private directory next to the fixtures, so that a failure leaves the committed
# fixtures untouched and the final move stays on one filesystem.
work_dir="$(mktemp -d "${fixture_dir}/.regenerate.XXXXXX")"
readonly work_dir
trap 'rm -rf -- "${work_dir}"' EXIT

# Writes a new, self-checked PKCS#8 private key to "$1", passing the remaining arguments to
# `openssl genpkey`.
generate_key() {
    local private_key="$1"
    shift
    openssl genpkey -quiet "$@" -out "${private_key}"
    openssl pkey -in "${private_key}" -check -noout >/dev/null
}

# Encodes the hex-encoded bytes on stdin as unpadded base64url, as JWKs require.
base64url_from_hex() {
    xxd -r -p | openssl base64 -A | tr '/+' '_-' | tr -d '='
}

for fixture in rsa_a rsa_b; do
    generate_key "${work_dir}/${fixture}.pem" \
        -algorithm RSA \
        -pkeyopt "rsa_keygen_bits:${rsa_bits}" \
        -pkeyopt rsa_keygen_pubexp:65537

    modulus_hex="$(openssl rsa -in "${work_dir}/${fixture}.pem" -noout -modulus)"
    n="$(base64url_from_hex <<<"${modulus_hex#Modulus=}")"
    # The public exponent is fixed at 65537 above, which is "AQAB" in base64url.
    printf '{"kty":"RSA","n":"%s","e":"AQAB"}\n' "${n}" >"${work_dir}/${fixture}.jwk.json"
done

# A P-256 key, for the tests covering realms whose published key material is a curve point rather
# than an RSA modulus (in particular the algorithm-confusion regression tests).
generate_key "${work_dir}/ec_a.pem" -algorithm EC -pkeyopt ec_paramgen_curve:P-256

# The DER SubjectPublicKeyInfo of a P-256 key ends with its 65-byte uncompressed point,
# 0x04 || X || Y. Reading it from there avoids parsing OpenSSL's human-readable text output.
point_hex="$(
    openssl pkey -in "${work_dir}/ec_a.pem" -pubout -outform DER | tail -c 65 | xxd -p -c 65
)"
if [[ ! "${point_hex}" =~ ^04[0-9a-f]{128}$ ]]; then
    echo "Unexpected P-256 public point encoding; refusing to write a bad JWK fixture." >&2
    exit 1
fi
x="$(base64url_from_hex <<<"${point_hex:2:64}")"
y="$(base64url_from_hex <<<"${point_hex:66:64}")"
printf '{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}\n' "${x}" "${y}" >"${work_dir}/ec_a.jwk.json"

mv -- "${work_dir}"/* "${fixture_dir}/"

echo "Regenerated two ${rsa_bits}-bit RSA fixtures and one P-256 EC fixture in ${fixture_dir}."
