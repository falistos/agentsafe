# Contributing

```sh
make gate   # cargo fmt --check, cargo clippy -D warnings, cargo test
```

Commit subjects are [Conventional Commits](https://www.conventionalcommits.org/) in English.

Tests use fixtures in temporary directories. Never put a real secret in a test, an issue, or a log.
