# Lists all available commands.
default:
    just --list

# Install tools required by other recipes.
install-tools:
    cargo +stable install cargo-minimal-versions --locked
    cargo install cargo-semver-checks --locked
    cargo +stable install cargo-msrv --locked

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
    cargo clippy --all --all-targets --all-features -- -W clippy::pedantic

# Run all tests, including integration tests (requires Podman to launch Keycloak containers).
# We pass the `--nocapture` flag to be able to see tracing output.
test:
    cargo test  --all --all-features -- --nocapture

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
    cargo doc --no-deps --all-features
