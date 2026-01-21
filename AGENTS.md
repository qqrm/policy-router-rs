# Agent instructions

- Before creating a pull request, run the repository's required build, lint, formatting, and test commands.
- If any of these checks fail, fix the issues and rerun the relevant commands until they pass.
- Windows GNU release builds can be checked with `rustup target add x86_64-pc-windows-gnu` (first) and then `cargo build --release --target x86_64-pc-windows-gnu`.
