# Agents

The gate is `make gate` (`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`). Run it before opening a pull request.

Code and comments are in English.

Tests use fixtures in temporary directories. Never read a real vault or identity. Never print a secret value, and never put one in an error message.
