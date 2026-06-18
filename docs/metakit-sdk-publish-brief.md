# Publish brief: switching gps-integrity-demo from path deps to crates.io

This brief is for the agent working in `~/git/gps-integrity-demo`. It is self-contained — no need to consult anyone after the metakit-sdk Rust crate is published.

## What's happening on the metakit-sdk side

The Rust SDK is being published to crates.io as **`constellation-metagraph-sdk`** version **`0.2.0`**. The 0.2.0 release is the first crates.io release — the version aligns with the TypeScript SDK (also 0.2.0). It includes both K1 (secp256k1) and the new R1 (secp256r1) API under `constellation_sdk::r1::*`.

The release flow is:

1. metakit-sdk maintainer pushes tag `rust-v0.2.0`.
2. `.github/workflows/release-rust.yml` runs tests and runs `cargo publish` using the `CRATES_TOKEN` secret.
3. Crate appears at <https://crates.io/crates/constellation-metagraph-sdk>.

You will know the publish succeeded when `cargo search constellation-metagraph-sdk` returns `0.2.0`, or when <https://crates.io/crates/constellation-metagraph-sdk/0.2.0> resolves.

## What you (the gps-integrity-demo agent) need to do once published

There are currently **four** path-dependency lines in this workspace pointing at the local checkout:

```
crates/collector/Cargo.toml
crates/executor/Cargo.toml
crates/gui-backend/Cargo.toml
crates/verifier/Cargo.toml
```

(Confirm with `grep -rn 'metakit-sdk/packages/rust' crates/*/Cargo.toml`.)

Each has a line like:

```toml
constellation-metagraph-sdk = { path = "../../../metakit-sdk/packages/rust", features = ["r1"] }
```

Replace each with:

```toml
constellation-metagraph-sdk = { version = "0.2.0", features = ["r1"] }
```

Preserve whatever feature set was already specified per crate (e.g. some may also want `network`). Only the source pointer changes — `path = "..."` becomes `version = "0.2.0"`. Do not rename the dependency or change the import paths in Rust source.

Then refresh the lockfile:

```bash
cargo update -p constellation-metagraph-sdk
```

Build and test to confirm:

```bash
cargo build --workspace
cargo test --workspace
```

## Sanity checks

- All Rust source already uses the new `constellation_sdk::r1::{sign,verify,wallet,signed_object}` paths. The pre-publish flat `sign_r1` / `verify_r1` / `wallet_r1` / `signed_object_r1` modules were removed in the release-prep cleanup, so any leftover imports of those would break — `grep -rn 'sign_r1\|verify_r1\|wallet_r1\|signed_object_r1' crates/` should return empty.
- The crate's lib name is `constellation_sdk` (not `constellation_metagraph_sdk`). Imports stay as `use constellation_sdk::…`.
- If `cargo update` reports a different version (e.g. 0.2.1 patched while you were working), that's fine — pinning to `0.2.0` exact is unnecessary; `version = "0.2.0"` already allows compatible 0.2.x.

## If publishing is delayed

If you need to keep building before crates.io has the package, the path dep is fine to leave in place. Don't add fallback / vendored copies — just wait. The cutover is a one-line change per Cargo.toml.

## What not to do

- Don't introduce a workspace-level `[patch.crates-io]` redirect — it complicates downstream consumers picking up this repo.
- Don't bump beyond `0.2.0` speculatively. Pin to `0.2.0` and wait for a deliberate metakit-sdk release before bumping.
- Don't import deprecated/removed modules. Specifically: `constellation_sdk::sign_r1`, `constellation_sdk::verify_r1`, `constellation_sdk::wallet_r1`, `constellation_sdk::signed_object_r1` do not exist on crates.io.
