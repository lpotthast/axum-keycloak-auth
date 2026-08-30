# Test key fixtures

These are throwaway private keys committed solely for tests. They are public, are not secrets, and
must never be used outside the test suite.

Two 2048-bit RSA keys (`rsa_a`, `rsa_b`) cover key selection and rotation. One P-256 EC key
(`ec_a`) covers the realms whose published key material is a curve point rather than an RSA
modulus, which the algorithm-confusion regression tests need.

Regeneration is an explicit maintainer action. Builds and tests never replace the files. From the
repository root, run:

```console
just regenerate-test-key-fixtures
```

The optional argument controls the RSA modulus size and defaults to 2048 bits (the EC
fixture is always P-256):

```console
just regenerate-test-key-fixtures 3072
```

The recipe requires OpenSSL and `xxd`. It generates each PKCS#8 PEM with OpenSSL's cryptographic
random-number generator, fixes the RSA public exponent at 65537, and derives the matching public
JWK metadata. Consequently, each run intentionally produces different keys. Review and commit all
six changed `rsa_*`/`ec_*` `.pem` and `.jwk.json` files together.

Two unit tests verify that the generated public JWKs match their respective private keys:
`test_support::tests::jwt_helpers_control_claims_algorithm_kid_and_key` for the RSA fixtures and
`test_support::tests::ec_fixture_jwk_matches_its_private_key_and_public_point` for the EC one.
