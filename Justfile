# Lists all available commands.
default:
    just --list

# Install tools required by other recipes.
install-tools:
    cargo +stable install cargo-minimal-versions --locked
    cargo install cargo-semver-checks --locked
    cargo +stable install cargo-msrv --locked
    cargo +stable install cargo-audit --locked
    cargo +stable install cargo-sort --locked

# Check if the current dependency version bounds are sufficient.
minimal-versions:
    cargo minimal-versions check --workspace --direct

# Find the minimum supported rust version.
msrv:
    cargo msrv find

# Check whether current changes require a breaking release.
semver-checks:
    cargo semver-checks

# Check the code.
check:
    cargo check --all-targets --all-features
    cargo check --all-targets --no-default-features

# Lint the code.
clippy:
    cargo clippy --all --all-targets --all-features -- -D warnings -W clippy::pedantic

# Run all tests, including integration tests (requires Podman to launch Keycloak containers).
# We pass the `--nocapture` flag to be able to see tracing output.
test:
    cargo test --all --all-features -- --nocapture

# Build the crate documentation.
build-docs:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Build and open the crate documentation for review.
open-docs:
    cargo doc --all-features --no-deps --open

# Run security auditing.
audit:
    cargo audit --deny warnings

# Update all deps; sort all Cargo.toml deps; format all code.
tidy:
    cargo update --workspace
    cargo sort --workspace
    cargo fmt --all

# Run the full non-mutating validation suite.
verify:
    cargo fmt --all -- --check
    just check
    just clippy
    just test
    just build-docs

# While sleeping overnight, the podman machine clock might drift... This can reset it without a restart.
fix-podman-clock:
    podman machine ssh "sudo date -u -s @$(date -u +%s)"

# Replace the throwaway RSA and EC test keys and their public JWK metadata.
regenerate-test-key-fixtures rsa_bits="2048":
    src/test_support/fixtures/regenerate.sh "{{rsa_bits}}"
