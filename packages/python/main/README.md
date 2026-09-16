# constellation-metagraph-sdk

The **batteries-included** Python SDK for Constellation data metagraphs built with metakit.

This distribution ships the `constellation_metagraph.main` namespace package. It depends on
[`constellation-metagraph-sdk-core`](../core) and **re-exports the entire offline core
kernel** (signing, verification, wallet, canonicalization, hashing, codecs), then adds:

- `currency_transaction`, `currency_types` — currency transaction build/sign/verify
- `network` — `MetagraphClient` and friends for ML0/CL1/DL1 nodes

```python
from constellation_metagraph.main import generate_key_pair, create_currency_transaction
from constellation_metagraph.main.network import create_metagraph_client, LayerType

dl1 = create_metagraph_client("http://localhost:9400", LayerType.DL1)
```

## Backward compatibility

The historical flat `constellation_sdk` import path is preserved by a compatibility shim
that ships in this distribution and re-exports the full flat public API:

```python
from constellation_sdk import sign, generate_key_pair, create_currency_transaction
from constellation_sdk.network import MetagraphClient
```

## Tiers

| Distribution | Namespace | Contents |
| --- | --- | --- |
| `constellation-metagraph-sdk-core` | `constellation_metagraph.core` | offline kernel incl. signing |
| `constellation-metagraph-sdk` | `constellation_metagraph.main` | core + currency + network |
| `constellation-metagraph-sdk-jlvm` | `constellation_metagraph.jlvm` | reserved placeholder |
