# Package tiers

The metakit SDK is split into three tiers in every language binding. The tiers
are a dependency ladder — each tier may depend only on the ones below it — and
the boundary is the same in all languages so that a consumer reasons about "what
do I need to pull in" identically whether they are on TypeScript, Rust, Go,
Java, or Python.

```
jlvm            (extension: JLVM evaluator + gas + zk/crypto opcodes)
  │  depends on
base package    (core + currency transactions + network client)
  │  depends on
core            (fully-offline signing kernel)
```

The middle "batteries-included" tier is the **unsuffixed base package** — there
is no `std` tier. In Go it lives at the module root, `packages/go`
(import path `github.com/Constellation-Labs/metakit-sdk/packages/go`); `core`
and `jlvm` are sub-packages beneath it.

## core — the fully-offline signing kernel (INCLUDING signing)

`core` (`packages/go/core`) is everything you need to canonicalize, hash, and
**sign / verify** data completely offline. It has **no** network dependency and
**no** currency / metagraph-transaction logic. Signing lives here, not in the
base package.

Contents:

- **Canonicalization** — RFC 8785 canonical JSON plus the drop-null-object-fields
  content-hash rule (array nulls preserved).
- **Binary / codec** — `DataUpdate` encoding (Constellation prefix + base64
  wrapping) and decoding.
- **Hashing** — SHA-256 content hash and the SHA-256→hex→SHA-512→truncate signing
  digest.
- **Signing** — sign, verify, signed-object construction (single / add / batch),
  and the wallet (key generation, key derivation, DAG address derivation, public
  key normalization).
- **Types** — `SignatureProof`, `Signed[T]`, `KeyPair`, `Hash`,
  `VerificationResult`, algorithm / prefix constants, and the shared error set.

Rule of thumb: if it can run with the network cable unplugged and does not know
what a "token transfer" is, it belongs in `core`.

## base package — core + currency + network

The base package (the module root, `packages/go`, package `constellation`)
builds on `core` and adds the two things that turn the offline kernel into a
usable metagraph client:

- **Currency transactions** — v2 metagraph token-transfer creation, batching,
  multi-sig, Kryo/`getEncoded` encoding, hashing, verification, and DAG-address
  validation. These reuse `core`'s signing digest, address derivation, and
  `SignatureProof` / `Signed` / `Hash` / `VerificationResult` types.
- **Network client** — the HTTP client and the layer-aware `MetagraphClient`
  (ML0 / CL1 / DL1) with its request/response types and network errors.

The base package imports `core` and references its symbols directly (e.g.
`core.Sign`, `core.SignatureProof`). It does not re-implement any signing
primitive.

## jlvm — extension placeholder

`jlvm` (`packages/go/jlvm`) is the reserved extension tier for the JSON Logic
Virtual Machine: the evaluator, the consensus gas schedule, and the zk / crypto
opcodes (Poseidon, sigma proofs, curve arithmetic). The extension is
deliberately independent of the signing kernel and the currency/network layer —
when ported it must depend on neither. In the Go binding this tier currently
holds only a placeholder package (no runnable source yet).

## Reference layouts (other languages)

The Go split mirrors the boundary already shipped in the reference bindings:

- **Rust** — `constellation-metagraph-sdk` fuses the offline signing kernel into
  a single offline crate (canonicalization + binary + hash + **signing**
  together); the network client is the layer above.
- **TypeScript** — `@constellation-network/metagraph-sdk-core` is the offline
  kernel and **includes signing** (`sign`, `verify`, `signed-object`, `wallet`).
  The unsuffixed `@constellation-network/metagraph-sdk` package is the base tier:
  it re-exports core and adds currency transactions + the network client, and
  `@constellation-network/metagraph-sdk-jlvm` is the JLVM extension.

In all three, **signing is part of the offline core, never the base/network
tier** — that is the boundary the Go packages follow.
