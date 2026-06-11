# Releasing the SDK (npm + crates.io)

This document covers the unified release pipeline in
[`.github/workflows/release.yml`](../.github/workflows/release.yml): one `v*`
tag publishes the TypeScript package to npm and the three Rust crates to
crates.io, all stamped with the same version. It supersedes the per-language
`rust-v*` flow described in [PUBLISHING.md](PUBLISHING.md) for Rust and
TypeScript (the `typescript-v*` and `python-v*` workflows still exist for
one-off, single-language releases; prefer the unified flow).

Current state (2026-06): **nothing Rust has ever been published** — there are
no crates on crates.io — and npm `@constellation-network/metagraph-sdk` is
stale at a manually published 0.2.0. The first unified release is therefore a
first publish for all three crates, which makes the crate-naming decision
below a hard prerequisite.

## Step zero (decide BEFORE the first publish): crate names

`jlvm-core` and `poseidon-bn254` are almost certainly too generic for
crates.io — they squat obvious names in the global namespace, invite
confusion with unrelated projects (there are other Poseidon/BN254 crates),
and crates.io names are forever (no transfers of meaning, no renames — only
new crates). `constellation-metagraph-sdk` is already well-namespaced.

**Recommendation:** rename before first publish:

| today (Cargo.toml `name`) | recommended |
|---|---|
| `jlvm-core` | `constellation-jlvm-core` |
| `poseidon-bn254` | `constellation-poseidon-bn254` |
| `constellation-metagraph-sdk` | keep as is |

This is a ~10-line change, and **no Rust source changes**: both crates pin
their lib name explicitly (`[lib] name = "jlvm_core"` / `"poseidon_bn254"`),
so `use jlvm_core::...` paths keep working everywhere. What changes:

1. `rust/jlvm-core/Cargo.toml` — `[package] name = "constellation-jlvm-core"`
2. `rust/poseidon-bn254/Cargo.toml` — `[package] name = "constellation-poseidon-bn254"`
3. Path-dependency declarations gain `package = "..."` so the dep key (and
   therefore `use` paths) stay the same:
   - `rust/jlvm-core/Cargo.toml`:
     `poseidon-bn254 = { path = "../poseidon-bn254", version = "...", package = "constellation-poseidon-bn254" }`
   - `rust/zk-jlvm/program/Cargo.toml` and `rust/zk-jlvm/script/Cargo.toml`:
     `jlvm-core = { path = "../../jlvm-core", package = "constellation-jlvm-core" }`
   - `rust/zk-shielded/lib/Cargo.toml` and `rust/zk-shielded/script/Cargo.toml`:
     `poseidon-bn254 = { path = "../../poseidon-bn254", package = "constellation-poseidon-bn254" }`

The workflows need **zero changes** for the rename: they are parameterized by
crate *directory* and read the crate names out of each `Cargo.toml` at
runtime (the `CRATE_DIRS` env in `release.yml` and the matching list in the
`publish-dry-run` CI job).

Directory names can stay `rust/jlvm-core` / `rust/poseidon-bn254` (crate name
and directory name don't have to match).

## Required secrets

| Secret | Used by | Where to get it |
|---|---|---|
| `NPM_TOKEN` | `npm-publish` job | npmjs.com → Access Tokens → Automation token, with publish rights to the `@constellation-network` org |
| `CARGO_REGISTRY_TOKEN` | `cargo-publish` job | crates.io → Account Settings → API Tokens, scope `publish-new` + `publish-update` |

Add both at Settings → Secrets and variables → Actions. The npm publish also
passes `--provenance` (Sigstore attestation), which needs the `id-token:
write` permission already declared in the workflow — no extra secret.

Note: the first crates.io publish of each crate is what claims the name. Do
not hand the token to anything else before step zero is settled.

## Version-sync policy

- **The SDK version tracks the metakit minor line.** metakit (Scala) 1.8.x ↔
  SDK 1.8.x. Patch and rc numbers move independently — an SDK-only fix can
  ship 1.8.1 while metakit stays at 1.8.0; what must match is the
  major.minor, which identifies the protocol/opcode surface the SDK is
  byte-compatible with.
- **All packages released by `release.yml` carry the same version**: the
  TypeScript package and all three crates. The workflow enforces this (see
  tag flow below).
- **Shared test vectors (`/shared`) are versioned independently** — they are
  inputs to CI, not published artifacts, and carry their own protocol
  version inside the vector files.
- The other languages (Python, Go, Java) keep their independent per-language
  versioning and tag flows for now ([VERSIONING.md](VERSIONING.md)).

This is why the manifests currently say `1.8.0-rc.1`: metakit's released line
is 1.8.x, and the first unified SDK release is rehearsed as an rc.

## Tag format and flow

**Tag format: plain `vX.Y.Z` or `vX.Y.Z-rc.N`** — e.g. `v1.8.0-rc.1`. We
considered suffixing build metadata (`v1.8.0-rc.1+sdk`) to visually
distinguish SDK tags from metakit tags, and rejected it: metakit lives in a
different repository so there is no actual collision, npm and crates.io both
handle `+metadata` versions inconsistently (semver says it's ignored for
precedence, registries treat it as part of the string), and it complicates
the tag→version check for nothing. The legacy per-language tags
(`typescript-v*`, `python-v*`, `rust-v*`, `java-v*`, `packages/go/v*`) don't
start with `v`, so they never trigger `release.yml` and keep their own
workflows; `release.yml` additionally rejects any `v*` tag that isn't plain
semver.

Flow:

1. Open a PR that bumps the version **everywhere** it lives:
   - `packages/typescript/package.json` (+ `package-lock.json`, via
     `npm version X.Y.Z --no-git-tag-version`)
   - `rust/poseidon-bn254/Cargo.toml`
   - `rust/jlvm-core/Cargo.toml` — both `[package] version` **and** the
     `version` on its `poseidon-bn254` path dependency
   - `packages/rust/Cargo.toml`
2. CI's `publish-dry-run` job rehearses the release on the PR: `npm pack`
   (so the build must succeed) and `cargo publish --dry-run` per crate in
   dependency order. This is deliberate front-loading: metakit's Maven
   release once failed on scaladoc errors that only surfaced at publish
   time. Caveat: until `poseidon-bn254` has been published once, the
   jlvm-core dry-run is manifest-only — cargo refuses to rewrite a path
   dependency into a registry dependency that doesn't exist on crates.io
   (even `cargo package --no-verify` fails with "no matching package
   named"). The job detects that exact error, falls back to
   `cargo package --list` + a check that the path dep carries `version`,
   and emits a notice; it upgrades itself to a full dry-run automatically
   after the first publish.
3. Merge, then tag the merge commit and push the tag:

   ```bash
   git tag -a v1.8.0-rc.1 -m "SDK v1.8.0-rc.1"
   git push origin v1.8.0-rc.1
   ```

4. `release.yml` then:
   - **version-check** — derives the version from the tag and verifies every
     manifest above matches it. On mismatch it fails with a pointed error;
     it never rewrites versions (fix the manifests in a PR and re-tag).
   - **npm-publish** — `npm ci && npm run build && npm test`, then
     `npm publish --access public --provenance`.
   - **cargo-publish** — `cargo publish` (with full verify build, no
     `--no-verify`) in dependency order: `rust/poseidon-bn254` →
     `rust/jlvm-core` → `packages/rust`. cargo blocks until each crate is
     visible in the index before the next publish, so jlvm-core's verify
     build can resolve the just-published poseidon crate.
   - **release-summary** — job summary table of everything published + a
     GitHub Release with generated notes (marked prerelease for `-rc.N`).

   `cargo publish` is idempotent-unfriendly (a version can never be
   republished); if a release fails halfway, fix forward with a new rc/patch
   tag rather than retrying the same tag.

## Follow-ups after the first npm publish

- **ottochain-sdk**: switch it from the vendored `dist/` copy of this SDK to
  a real npm dependency on `@constellation-network/metagraph-sdk`, and
  delete the inlined copy of `dropNulls.ts` in ottochain's `e2e-test/lib/`
  (it duplicates the SDK's canonicalization helper and can silently drift).
- Consider retiring `release-typescript.yml` (and the `typescript-v*` tag
  format) once the unified flow has shipped a release, so there is exactly
  one way to publish the TS package.
- Wire Python/Go/Java into the unified flow if/when their registries get set
  up, reusing the version-check pattern.
