# Constellation Metagraph SDK

Official multi-language SDK for Constellation Metagraph signing operations.

[![CI](https://github.com/Constellation-Labs/metakit-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Constellation-Labs/metakit-sdk/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@constellation-network/metagraph-sdk.svg)](https://www.npmjs.com/package/@constellation-network/metagraph-sdk)
[![PyPI version](https://img.shields.io/pypi/v/constellation-metagraph-sdk.svg)](https://pypi.org/project/constellation-metagraph-sdk/)

## Packages

| Language | Package | Documentation |
|----------|---------|---------------|
| TypeScript | [@constellation-network/metagraph-sdk](https://www.npmjs.com/package/@constellation-network/metagraph-sdk) | [README](./packages/typescript/README.md) |
| Python | [constellation-metagraph-sdk](https://pypi.org/project/constellation-metagraph-sdk/) | [README](./packages/python/README.md) |

## Features

- **RFC 8785 Canonicalization**: Deterministic JSON encoding for consistent hashing
- **ECDSA on secp256k1**: Industry-standard cryptographic signatures compatible with Constellation Network
- **Multi-signature support**: Create and verify multi-party signatures
- **Cross-language compatibility**: Signatures created in one language verify in all others
- **DataUpdate support**: Sign data for direct submission to metagraph data-l1 endpoints

## Quick Start

### TypeScript

```bash
npm install @constellation-network/metagraph-sdk @stardust-collective/dag4
```

```typescript
import { createSignedObject, verify, generateKeyPair } from '@constellation-network/metagraph-sdk';

// Generate a key pair
const keyPair = generateKeyPair();
console.log('Address:', keyPair.address);

// Sign data
const data = { action: 'UPDATE', payload: { key: 'value' } };
const signed = await createSignedObject(data, keyPair.privateKey);

// Verify
const result = await verify(signed);
console.log('Valid:', result.isValid);
```

### Python

```bash
pip install constellation-metagraph-sdk
```

```python
from constellation_sdk import create_signed_object, verify, generate_key_pair

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

## Development

### Prerequisites

- Node.js 18+
- Python 3.10+

### Setup

```bash
# Clone the repository
git clone https://github.com/Constellation-Labs/metakit-sdk.git
cd metakit-sdk

# Install Node.js dependencies
npm install

# Install Python dependencies
cd packages/python
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
cd ../..
```

### Common Commands

```bash
# Run all tests
npm run test:all

# Run TypeScript tests only
npm run test:ts

# Run Python tests only
npm run test:py

# Lint all packages
npm run lint:all

# Build TypeScript
npm run build:ts

# Format all code
npm run format:all

# Validate versions
npm run validate:versions
```

## Cross-Language Compatibility

All SDKs are validated against shared test vectors in `/shared/test_vectors.json`. This ensures:

- Canonicalization produces identical output across all languages
- Hashing produces identical digests
- Signatures created in one language verify in all others

## Releasing

This repository uses independent versioning for each package. To release:

1. Update version in the package config (`package.json` or `pyproject.toml`)
2. Update CHANGELOG.md in the package
3. Create a PR and merge to main
4. Create a GitHub Release with the appropriate tag:
   - TypeScript: `typescript-v1.2.3`
   - Python: `python-v1.2.3`
5. GitHub Actions will automatically publish to npm/PyPI

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

Apache-2.0