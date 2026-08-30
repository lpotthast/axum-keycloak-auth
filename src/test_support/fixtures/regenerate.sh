#!/usr/bin/env bash

set -euo pipefail

readonly rsa_bits="${1:-2048}"
readonly fixture_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! "${rsa_bits}" =~ ^[0-9]+$ ]] || ((rsa_bits < 2048)); then
    echo "RSA size must be an integer of at least 2048 bits; got '${rsa_bits}'." >&2
    exit 2
fi

for tool in openssl xxd; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "Required tool '${tool}' was not found in PATH." >&2
        exit 127
    fi
done

temporary_dir="$(mktemp -d "${fixture_dir}/.regenerate.XXXXXX")"
readonly temporary_dir
trap 'rm -rf -- "${temporary_dir}"' EXIT
umask 077

for fixture in rsa_a rsa_b; do
    private_key="${temporary_dir}/${fixture}.pem"
    public_jwk="${temporary_dir}/${fixture}.jwk.json"

    openssl genpkey \
        -quiet \
        -algorithm RSA \
        -pkeyopt "rsa_keygen_bits:${rsa_bits}" \
        -pkeyopt rsa_keygen_pubexp:65537 \
        -out "${private_key}"
    openssl pkey -in "${private_key}" -check -noout >/dev/null

    modulus_hex="$(openssl rsa -in "${private_key}" -noout -modulus 2>/dev/null)"
    modulus_hex="${modulus_hex#Modulus=}"
    modulus_base64url="$(
        printf '%s' "${modulus_hex}" \
            | xxd -r -p \
            | openssl base64 -A \
            | tr '/+' '_-' \
            | tr -d '='
    )"
    printf '{"kty":"RSA","n":"%s","e":"AQAB"}\n' "${modulus_base64url}" >"${public_jwk}"
done

# A P-256 fixture, for the tests covering realms whose published key material is a curve point
# rather than an RSA modulus (in particular the algorithm-confusion regression tests).
ec_private_key="${temporary_dir}/ec_a.pem"
ec_public_jwk="${temporary_dir}/ec_a.jwk.json"

openssl genpkey \
    -quiet \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out "${ec_private_key}"
openssl pkey -in "${ec_private_key}" -check -noout >/dev/null

# The uncompressed point is read from the DER SubjectPublicKeyInfo rather than from OpenSSL's
# human-readable text, whose byte grouping is awkward to parse reliably. For P-256 that structure
# is a fixed 26-byte header followed by the 65-byte point (0x04 || X || Y).
ec_point_hex="$(
    openssl pkey -in "${ec_private_key}" -pubout -outform DER \
        | xxd -p -c 1000 \
        | cut -c 53-
)"
if ((${#ec_point_hex} != 130)) || [[ "${ec_point_hex:0:2}" != "04" ]]; then
    echo "Unexpected P-256 public point encoding; refusing to write a bad JWK fixture." >&2
    exit 1
fi

base64url_from_hex() {
    printf '%s' "$1" | xxd -r -p | openssl base64 -A | tr '/+' '_-' | tr -d '='
}
ec_x="$(base64url_from_hex "${ec_point_hex:2:64}")"
ec_y="$(base64url_from_hex "${ec_point_hex:66:64}")"
printf '{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}\n' "${ec_x}" "${ec_y}" >"${ec_public_jwk}"

chmod 0644 "${temporary_dir}"/*
for generated_file in rsa_a.pem rsa_a.jwk.json rsa_b.pem rsa_b.jwk.json ec_a.pem ec_a.jwk.json; do
    mv -- "${temporary_dir}/${generated_file}" "${fixture_dir}/${generated_file}"
done

echo "Regenerated two ${rsa_bits}-bit RSA fixtures and one P-256 EC fixture in ${fixture_dir}."
