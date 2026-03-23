---
description: "Rust coding style: ownership, error handling, async safety, clippy enforcement"
globs: ["**/*.rs", "Cargo.toml"]
alwaysApply: false
---
# Rust Coding Style

## Ownership and Lifetimes

- Prefer `&str` over `String` in function parameters; use `impl AsRef<str>` for flexibility
- Prefer `&[T]` over `Vec<T>` in function parameters
- Use `Cow<'_, str>` when a function may or may not need to allocate
- Avoid unnecessary `.clone()` — restructure borrows instead
- Remove explicit lifetime annotations where elision rules apply

## Error Handling

- Use `?` operator — never `unwrap()` or `expect()` in production paths
- Add `.context()` or `.map_err()` for meaningful error messages (anyhow)
- Use `thiserror` for typed errors in library-style modules
- Never silently discard `#[must_use]` values with `let _ =`
- No `panic!()`, `todo!()`, or `unreachable!()` in production code paths

## Async Safety

- Never use `std::thread::sleep` or `std::fs` in async context — use tokio equivalents
- Prefer bounded channels (`tokio::sync::mpsc::channel(n)`) over unbounded
- Drop non-Send values before `.await` points
- Use `tokio::time::timeout` for all external I/O operations

## Code Quality

- Run `cargo clippy -- -D warnings` — fix all warnings, no `#[allow]` without justification
- Run `cargo fmt` — all code must be formatted
- Functions under 50 lines, files under 800 lines
- No deep nesting beyond 4 levels — extract helper functions
- Derive order: `Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize`
- Use `Vec::with_capacity(n)` when size is known
- Avoid `format!` for simple string concatenation

## Unsafe Code

- Never use `unsafe` to work around borrow checker errors
- Every `unsafe` block requires a `// SAFETY:` comment documenting invariants

## Build Troubleshooting

When build fails: run `cargo check` first, then `cargo clippy`, then `cargo test`.
Fix root cause over suppressing symptoms. Surgical fixes only — don't refactor unrelated code.
