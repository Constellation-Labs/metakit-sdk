# Constellation Metagraph SDK - TypeScript

TypeScript SDK for signing data transactions on Constellation Network data metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Note:** This SDK is for data transactions only. For currency transactions, use [dag4.js](https://github.com/StardustCollective/dag4.js) directly. This SDK implements the standardized serialization, hashing, and signing routines defined by metakit and may not be compatible with metagraphs using custom serialization.

## Installation

```bash
npm install @constellation-network/metagraph-sdk
```

**Peer dependency:** This SDK wraps `@stardust-collective/dag4` for signing operations.

## Quick Start

```typescript
import {
  createSignedObject,
  verify,
  generateKeyPair
} from '@constellation-network/metagraph-sdk';

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

## API Reference

### High-Level API

#### `createSignedObject<T>(value, privateKey, options?)`

Create a signed object with a single signature.

```typescript
const signed = await createSignedObject(
  { action: 'test' },
  privateKey,
  { isDataUpdate: true }  // For L1 submission
);
```

#### `addSignature<T>(signed, privateKey, options?)`

Add an additional signature to an existing signed object.

```typescript
let signed = await createSignedObject(data, party1Key);
signed = await addSignature(signed, party2Key);
// signed.proofs.length === 2
```

#### `batchSign<T>(value, privateKeys, options?)`

Create a signed object with multiple signatures at once.

```typescript
const signed = await batchSign(data, [key1, key2, key3]);
// signed.proofs.length === 3
```

#### `verify<T>(signed, isDataUpdate?)`

Verify all signatures on a signed object.

```typescript
const result = await verify(signed);
if (result.isValid) {
  console.log('All signatures valid');
} else {
  console.log('Invalid proofs:', result.invalidProofs);
}
```

### Low-Level Primitives

#### `canonicalize<T>(data)`

Canonicalize JSON data according to RFC 8785.

```typescript
const canonical = canonicalize({ b: 2, a: 1 });
// '{"a":1,"b":2}'
```

#### `toBytes<T>(data, isDataUpdate?)`

Convert data to binary bytes for signing.

```typescript
// Regular encoding
const bytes = toBytes(data);

// DataUpdate encoding (with Constellation prefix)
const updateBytes = toBytes(data, true);
```

#### `hash<T>(data)` / `hashBytes(bytes)`

Compute SHA-256 hash.

```typescript
const hashResult = hash(data);
console.log(hashResult.value);  // 64-char hex
console.log(hashResult.bytes);  // Uint8Array
```

#### `sign<T>(data, privateKey)` / `signDataUpdate<T>(data, privateKey)`

Sign data and return a proof.

```typescript
const proof = await sign(data, privateKey);
// { id: '...', signature: '...' }
```

#### `signHash(hashHex, privateKey)`

Sign a pre-computed hash.

```typescript
const hashResult = hash(data);
const signature = await signHash(hashResult.value, privateKey);
```

### Wallet Utilities

#### `generateKeyPair()`

Generate a new random key pair.

```typescript
const keyPair = generateKeyPair();
// { privateKey, publicKey, address }
```

#### `keyPairFromPrivateKey(privateKey)`

Derive a key pair from an existing private key.

```typescript
const keyPair = keyPairFromPrivateKey(existingPrivateKey);
```

#### `getPublicKeyId(privateKey)`

Get the public key ID (128 chars, no 04 prefix) for use in proofs.

```typescript
const id = getPublicKeyId(privateKey);
```

## Types

```typescript
interface SignatureProof {
  id: string;        // Public key (128 chars)
  signature: string; // DER signature hex
}

interface Signed<T> {
  value: T;
  proofs: SignatureProof[];
}

interface KeyPair {
  privateKey: string;
  publicKey: string;
  address: string;
}

interface Hash {
  value: string;      // 64-char hex
  bytes: Uint8Array;  // 32 bytes
}

interface VerificationResult {
  isValid: boolean;
  validProofs: SignatureProof[];
  invalidProofs: SignatureProof[];
}
```

## Usage Examples

### Submit DataUpdate to L1

```typescript
import { createSignedObject } from '@constellation-network/metagraph-sdk';

// Your metagraph data update
const dataUpdate = {
  action: 'TRANSFER',
  from: 'address1',
  to: 'address2',
  amount: 100
};

// Sign as DataUpdate
const signed = await createSignedObject(dataUpdate, privateKey, {
  isDataUpdate: true
});

// Submit to data-l1
const response = await fetch('http://l1-node:9300/data', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(signed)
});
```

### Multi-Signature Workflow

```typescript
import { createSignedObject, addSignature, verify } from '@constellation-network/metagraph-sdk';

// Party 1 creates and signs
let signed = await createSignedObject(data, party1Key);

// Party 2 adds signature
signed = await addSignature(signed, party2Key);

// Party 3 adds signature
signed = await addSignature(signed, party3Key);

// Verify all signatures
const result = await verify(signed);
console.log(`${result.validProofs.length} valid signatures`);
```

## Development

```bash
# Install dependencies
npm install

# Run tests
npm test

# Build
npm run build
```

## License

Apache-2.0
