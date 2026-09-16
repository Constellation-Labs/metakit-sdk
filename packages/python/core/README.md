# constellation-metagraph-sdk-core

The **offline core kernel** of the Constellation metagraph Python SDK.

This distribution ships the `constellation_metagraph.core` namespace package and has
**no network** and **no currency-transaction** code. It contains everything needed to
build, canonicalize, hash, sign, and verify signed data offline:

- `binary`, `canonicalize`, `codec`, `hash`, `types` — encoding + canonical form (RFC 8785)
- `sign`, `verify`, `signed_object` — ECDSA/secp256k1 signing and verification
- `wallet` — key-pair generation and DAG address derivation

```python
from constellation_metagraph.core import generate_key_pair, sign, verify, create_signed_object

key_pair = generate_key_pair()
```

For currency transactions and network clients, install
[`constellation-metagraph-sdk`](../main) (the batteries-included tier), which depends on
this package and re-exports it.
