# Constellation Metagraph SDK

Multi-language SDK for signing data transactions on Constellation Network data metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Scope:** Data transactions for metakit-based metagraphs. Currency transactions not yet supported (use [dag4.js](https://github.com/StardustCollective/dag4.js) for JavaScript). This SDK implements metakit's standardized serialization and may not be compatible with metagraphs using custom routines.

[![CI](https://github.com/Constellation-Labs/metakit-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Constellation-Labs/metakit-sdk/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@constellation-network/metagraph-sdk.svg)](https://www.npmjs.com/package/@constellation-network/metagraph-sdk)
[![PyPI version](https://img.shields.io/pypi/v/constellation-metagraph-sdk.svg)](https://pypi.org/project/constellation-metagraph-sdk/)
[![Crates.io](https://img.shields.io/crates/v/constellation-metagraph-sdk.svg)](https://crates.io/crates/constellation-metagraph-sdk)

## Overview

This SDK provides standard cryptographic operations (canonicalization, hashing, signing, verification) for data metagraphs built using the metakit framework. The metakit framework standardizes serialization, hashing, and signing routines for data metagraphs, and this SDK implements those standards.

**Scope:**
- **Data transactions** for metakit-based data metagraphs
- **Not included (yet):** Currency transaction support (for JavaScript, use [dag4.js](https://github.com/StardustCollective/dag4.js) directly)
- **Compatibility:** Designed for metakit metagraphs; may not be compatible with metagraphs using custom serialization

## Packages

| Language | Package | Documentation |
|----------|---------|---------------|
| TypeScript | [@constellation-network/metagraph-sdk](https://www.npmjs.com/package/@constellation-network/metagraph-sdk) | [README](./packages/typescript/README.md) |
| Python | [constellation-metagraph-sdk](https://pypi.org/project/constellation-metagraph-sdk/) | [README](./packages/python/README.md) |
| Rust | [constellation-metagraph-sdk](https://crates.io/crates/constellation-metagraph-sdk) | [README](./packages/rust/README.md) |
| Go | [github.com/Constellation-Labs/metakit-sdk/packages/go](https://pkg.go.dev/github.com/Constellation-Labs/metakit-sdk/packages/go) | [README](./packages/go/README.md) |
| Java | [io.constellationnetwork:metagraph-sdk](https://central.sonatype.com/artifact/io.constellationnetwork/metagraph-sdk) | [README](./packages/java/README.md) |

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

### Rust

```bash
cargo add constellation-metagraph-sdk
```

```rust
use constellation_sdk::{
    wallet::generate_key_pair,
    signed_object::create_signed_object,
    verify::verify,
};
use serde_json::json;

fn main() {
    // Generate a key pair
    let key_pair = generate_key_pair();
    println!("Address: {}", key_pair.address);

    // Sign data
    let data = json!({ "action": "UPDATE", "payload": { "key": "value" } });
    let signed = create_signed_object(&data, &key_pair.private_key, false).unwrap();

    // Verify
    let result = verify(&signed, false);
    println!("Valid: {}", result.is_valid);
}
```

### Go

```bash
go get github.com/Constellation-Labs/metakit-sdk/packages/go
```

```go
package main

import (
    "fmt"
    constellation "github.com/Constellation-Labs/metakit-sdk/packages/go"
)

func main() {
    // Generate a key pair
    keyPair, _ := constellation.GenerateKeyPair()
    fmt.Println("Address:", keyPair.Address)

    // Sign data
    data := map[string]interface{}{
        "action": "UPDATE",
        "payload": map[string]interface{}{"key": "value"},
    }
    signed, _ := constellation.CreateSignedObject(data, keyPair.PrivateKey, false)

    // Verify
    result := constellation.Verify(signed, false)
    fmt.Println("Valid:", result.IsValid)
}
```

### Java

```xml
<dependency>
    <groupId>io.constellationnetwork</groupId>
    <artifactId>metagraph-sdk</artifactId>
    <version>0.1.0</version>
</dependency>
```

```java
import io.constellationnetwork.metagraph.sdk.*;
import java.util.Map;

public class Example {
    public static void main(String[] args) {
        // Generate a key pair
        Types.KeyPair keyPair = Wallet.generateKeyPair();
        System.out.println("Address: " + keyPair.getAddress());

        // Sign data
        Map<String, Object> data = Map.of(
            "action", "UPDATE",
            "payload", Map.of("key", "value")
        );
        Types.Signed<Map<String, Object>> signed = SignedObject.createSignedObject(
            data, keyPair.getPrivateKey(), false
        );

        // Verify
        Types.VerificationResult result = SignedObject.verify(signed, false);
        System.out.println("Valid: " + result.isValid());
    }
}
```

## Development

### Prerequisites

- Node.js 18+ (TypeScript)
- Python 3.10+ (Python)
- Rust 1.70+ (Rust)
- Go 1.18+ (Go)
- Java 11+ and Maven 3.8+ (Java)
- Make (standard on Linux/macOS)

### Setup

```bash
# Clone the repository
git clone https://github.com/Constellation-Labs/metakit-sdk.git
cd metakit-sdk

# Install all dependencies
make install

# Or install individually
make install-ts      # TypeScript
make install-py      # Python (creates venv)
make install-go      # Go
make install-java    # Java (managed by Maven)
```

### Common Commands

```bash
make help            # Show all available commands

make test            # Run all tests
make test-ts         # TypeScript tests
make test-py         # Python tests
make test-rs         # Rust tests
make test-go         # Go tests
make test-java       # Java tests

make lint            # Lint all packages
make format          # Format all code
make build           # Build all packages
make clean           # Clean build artifacts
```

## Cross-Language Compatibility

All SDKs are validated against shared test vectors in `/shared/test_vectors.json`. This ensures:

- Canonicalization produces identical output across all languages
- Hashing produces identical digests
- Signatures created in one language verify in all others

## Releasing

Releases are triggered by pushing tags:

```bash
# TypeScript release
git tag -a typescript-v1.0.0 -m "TypeScript SDK v1.0.0"
git push origin typescript-v1.0.0

# Python release
git tag -a python-v1.0.0 -m "Python SDK v1.0.0"
git push origin python-v1.0.0
```

See [docs/PUBLISHING.md](./docs/PUBLISHING.md) for complete setup instructions.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License

Apache-2.0