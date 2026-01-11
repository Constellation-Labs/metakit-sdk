# Constellation Metagraph SDK - Python

Python SDK for signing data and currency transactions on Constellation Network metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Scope:** This SDK supports both data transactions (state updates) and metagraph token transactions (value transfers). It implements the standardized serialization, hashing, and signing routines defined by metakit and may not be compatible with metagraphs using custom serialization.

## Installation

```bash
pip install constellation-metagraph-sdk
```

## Quick Start

```python
from constellation_sdk import (
    create_signed_object,
    verify,
    generate_key_pair,
)

# Generate a key pair
key_pair = generate_key_pair()
print(f'Address: {key_pair.address}')

# Sign data
data = {'action': 'UPDATE', 'payload': {'key': 'value'}}
signed = create_signed_object(data, key_pair.private_key)

# Verify
result = verify(signed)
print(f'Valid: {result.is_valid}')
```

## API Reference

### High-Level API

#### `create_signed_object(value, private_key, is_data_update=False)`

Create a signed object with a single signature.

```python
signed = create_signed_object(
    {'action': 'test'},
    private_key,
    is_data_update=True  # For L1 submission
)
```

#### `add_signature(signed, private_key, is_data_update=False)`

Add an additional signature to an existing signed object.

```python
signed = create_signed_object(data, party1_key)
signed = add_signature(signed, party2_key)
# len(signed.proofs) == 2
```

#### `batch_sign(value, private_keys, is_data_update=False)`

Create a signed object with multiple signatures at once.

```python
signed = batch_sign(data, [key1, key2, key3])
# len(signed.proofs) == 3
```

#### `verify(signed, is_data_update=False)`

Verify all signatures on a signed object.

```python
result = verify(signed)
if result.is_valid:
    print('All signatures valid')
else:
    print(f'Invalid proofs: {result.invalid_proofs}')
```

### Low-Level Primitives

#### `canonicalize(data)`

Canonicalize JSON data according to RFC 8785.

```python
canonical = canonicalize({'b': 2, 'a': 1})
# '{"a":1,"b":2}'
```

#### `to_bytes(data, is_data_update=False)`

Convert data to binary bytes for signing.

```python
# Regular encoding
bytes_data = to_bytes(data)

# DataUpdate encoding (with Constellation prefix)
update_bytes = to_bytes(data, is_data_update=True)
```

#### `hash_data(data)` / `hash_bytes(data)`

Compute SHA-256 hash.

```python
hash_result = hash_data(data)
print(hash_result.value)  # 64-char hex
print(hash_result.bytes)  # bytes
```

#### `sign(data, private_key)` / `sign_data_update(data, private_key)`

Sign data and return a proof.

```python
proof = sign(data, private_key)
# SignatureProof(id='...', signature='...')
```

#### `sign_hash(hash_hex, private_key)`

Sign a pre-computed hash.

```python
hash_result = hash_data(data)
signature = sign_hash(hash_result.value, private_key)
```

### Wallet Utilities

#### `generate_key_pair()`

Generate a new random key pair.

```python
key_pair = generate_key_pair()
# KeyPair(private_key, public_key, address)
```

#### `key_pair_from_private_key(private_key)`

Derive a key pair from an existing private key.

```python
key_pair = key_pair_from_private_key(existing_private_key)
```

#### `get_public_key_id(private_key)`

Get the public key ID (128 chars, no 04 prefix) for use in proofs.

```python
id = get_public_key_id(private_key)
```

### Currency Transactions

#### `create_currency_transaction(params, private_key, last_ref)`

Create a metagraph token transaction.

```python
from constellation_sdk.currency_transaction import create_currency_transaction
from constellation_sdk.currency_types import TransferParams, TransactionReference

tx = create_currency_transaction(
    TransferParams(
        destination='DAG88C9WDSKH5CYZTCEOZD...',
        amount=100.5,  # Tokens
        fee=0,
    ),
    private_key,
    TransactionReference(hash='parent_hash...', ordinal=5)
)
```

#### `verify_currency_transaction(transaction)`

Verify all signatures on a currency transaction.

```python
from constellation_sdk.currency_transaction import verify_currency_transaction

result = verify_currency_transaction(tx)
print(f'Valid: {result.is_valid}')
print(f'Valid proofs: {len(result.valid_proofs)}')
```

#### `sign_currency_transaction(transaction, private_key)`

Add an additional signature to a currency transaction (multi-sig).

```python
from constellation_sdk.currency_transaction import sign_currency_transaction

# Add second signature
tx_multi_sig = sign_currency_transaction(tx, private_key2)
# tx_multi_sig.proofs has 2 signatures now
```

#### `create_currency_transaction_batch(transfers, private_key, last_ref)`

Create multiple currency transactions in a batch.

```python
from constellation_sdk.currency_transaction import create_currency_transaction_batch

transactions = create_currency_transaction_batch(
    [
        TransferParams(destination='DAG...1', amount=10, fee=0),
        TransferParams(destination='DAG...2', amount=20, fee=0),
    ],
    private_key,
    last_ref
)
```

#### `hash_currency_transaction(transaction)`

Hash a currency transaction.

```python
from constellation_sdk.currency_transaction import hash_currency_transaction

hash_result = hash_currency_transaction(tx)
print(f'Hash: {hash_result.value}')
```

#### `is_valid_dag_address(address)`

Validate a DAG address format.

```python
from constellation_sdk.currency_transaction import is_valid_dag_address

if is_valid_dag_address('DAG88C9WDSKH5CYZTCEOZD...'):
    print('Valid address')
```

#### `token_to_units(amount)` / `units_to_token(units)`

Convert between token amounts and smallest units (1e-8).

```python
from constellation_sdk.currency_transaction import token_to_units, units_to_token

units = token_to_units(100.5)  # 10050000000
tokens = units_to_token(10050000000)  # 100.5
```

### Network Operations

#### `CurrencyL1Client`

Client for interacting with Currency L1 nodes.

```python
from constellation_sdk import CurrencyL1Client, NetworkConfig

config = NetworkConfig(
    l1_url='http://localhost:9010',
    timeout=30.0,  # optional, defaults to 30s
)

client = CurrencyL1Client(config)

# Get last transaction reference for an address
last_ref = client.get_last_reference('DAG...')

# Submit a signed transaction
result = client.post_transaction(signed_tx)
print(f'Transaction hash: {result.hash}')

# Check pending transaction status
pending = client.get_pending_transaction(result.hash)
if pending:
    print(f'Status: {pending.status}')  # 'Waiting' | 'InProgress' | 'Accepted'

# Check node health
is_healthy = client.check_health()
```

#### `DataL1Client`

Client for interacting with Data L1 nodes (metagraphs).

```python
from constellation_sdk import DataL1Client, NetworkConfig

config = NetworkConfig(data_l1_url='http://localhost:8080')

client = DataL1Client(config)

# Estimate fee for data submission
fee_info = client.estimate_fee(signed_data)
print(f'Fee: {fee_info.fee}, Address: {fee_info.address}')

# Submit signed data
result = client.post_data(signed_data)
print(f'Data hash: {result.hash}')

# Check node health
is_healthy = client.check_health()
```

#### Combined Configuration

```python
config = NetworkConfig(
    l1_url='http://localhost:9010',       # Currency L1
    data_l1_url='http://localhost:8080',  # Data L1
    timeout=30.0,
)

l1_client = CurrencyL1Client(config)
data_client = DataL1Client(config)
```

#### Network Types

```python
@dataclass
class NetworkConfig:
    l1_url: Optional[str] = None       # Currency L1 endpoint
    data_l1_url: Optional[str] = None  # Data L1 endpoint
    timeout: float = 30.0              # Request timeout in seconds

@dataclass
class PostTransactionResponse:
    hash: str

@dataclass
class PendingTransaction:
    hash: str
    status: Literal["Waiting", "InProgress", "Accepted"]
    transaction: CurrencyTransaction

@dataclass
class EstimateFeeResponse:
    fee: int
    address: str

@dataclass
class PostDataResponse:
    hash: str

class NetworkError(Exception):
    status_code: Optional[int]
    response: Optional[str]
```

## Types

```python
from dataclasses import dataclass
from typing import List, TypeVar, Generic

@dataclass(frozen=True)
class SignatureProof:
    id: str         # Public key (128 chars)
    signature: str  # DER signature hex

@dataclass
class Signed(Generic[T]):
    value: T
    proofs: List[SignatureProof]

@dataclass(frozen=True)
class KeyPair:
    private_key: str
    public_key: str
    address: str

@dataclass(frozen=True)
class Hash:
    value: str   # 64-char hex
    bytes: bytes # 32 bytes

@dataclass
class VerificationResult:
    is_valid: bool
    valid_proofs: List[SignatureProof]
    invalid_proofs: List[SignatureProof]
```

## Usage Examples

### Submit DataUpdate to L1

```python
from constellation_sdk import create_signed_object, DataL1Client, NetworkConfig

# Your metagraph data update
data_update = {
    'action': 'TRANSFER',
    'from': 'address1',
    'to': 'address2',
    'amount': 100
}

# Sign as DataUpdate
signed = create_signed_object(data_update, private_key, is_data_update=True)

# Submit to data-l1 using the client
client = DataL1Client(NetworkConfig(data_l1_url='http://l1-node:9300'))
result = client.post_data(signed)
print(f'Submitted with hash: {result.hash}')
```

### Multi-Signature Workflow

```python
from constellation_sdk import create_signed_object, add_signature, verify

# Party 1 creates and signs
signed = create_signed_object(data, party1_key)

# Party 2 adds signature
signed = add_signature(signed, party2_key)

# Party 3 adds signature
signed = add_signature(signed, party3_key)

# Verify all signatures
result = verify(signed)
print(f'{len(result.valid_proofs)} valid signatures')
```

### Working with Raw Bytes

```python
from constellation_sdk import canonicalize, to_bytes, hash_bytes

# Get canonical JSON
canonical = canonicalize(data)
print(f'Canonical: {canonical}')

# Get binary encoding
bytes_data = to_bytes(data)
print(f'Bytes: {bytes_data.hex()}')

# Hash
hash_result = hash_bytes(bytes_data)
print(f'Hash: {hash_result.value}')
```

## Development

### Setup with venv

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install with dev dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_cross_language.py

# Run with coverage
pytest --cov=constellation_sdk
```

### Code Quality

```bash
# Type checking
mypy src

# Format code
black src tests
isort src tests

# Lint
ruff check src tests
```

## License

Apache-2.0
