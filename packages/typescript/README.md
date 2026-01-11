# Constellation Metagraph SDK - TypeScript

TypeScript SDK for signing data and currency transactions on Constellation Network metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Scope:** This SDK supports both data transactions (state updates) and metagraph token transactions (value transfers). This SDK implements the standardized serialization, hashing, and signing routines defined by metakit and may not be compatible with metagraphs using custom serialization.

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

## Features

- **Data Transactions**: Sign and verify metagraph state updates for submission to data L1 endpoints
- **Currency Transactions**: Create and sign metagraph token transfers (v2 format)
- **Network Operations**: Submit transactions and query L1 nodes directly
- **Multi-signature Support**: Add multiple signatures to transactions for multi-party authorization
- **Cross-language Compatible**: Works seamlessly with Python, Rust, Go, and Java implementations

## API Reference

### Data Transactions

#### High-Level API

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

interface TransactionReference {
  hash: string;
  ordinal: number;
}

interface CurrencyTransaction {
  value: {
    source: string;        // DAG address
    destination: string;   // DAG address
    amount: number;        // Amount in smallest units (1e-8)
    fee: number;           // Fee in smallest units
    parent: TransactionReference;
    salt: string;
  };
  proofs: SignatureProof[];
}

interface TransferParams {
  destination: string;     // DAG address
  amount: number;          // Amount in token units (e.g., 100.5)
  fee?: number;            // Fee in token units (defaults to 0)
}
```

### Currency Transactions

#### `createCurrencyTransaction(params, privateKey, lastRef)`

Create a metagraph token transaction.

```typescript
import { createCurrencyTransaction } from '@constellation-network/metagraph-sdk';

const tx = await createCurrencyTransaction(
  {
    destination: 'DAG...recipient',
    amount: 100.5,  // 100.5 tokens
    fee: 0,
  },
  privateKey,
  { hash: 'abc123...', ordinal: 5 }  // Last transaction reference
);
```

#### `createCurrencyTransactionBatch(transfers, privateKey, lastRef)`

Create multiple token transactions in a batch.

```typescript
const transfers = [
  { destination: 'DAG...1', amount: 10 },
  { destination: 'DAG...2', amount: 20 },
  { destination: 'DAG...3', amount: 30 },
];

const txns = await createCurrencyTransactionBatch(
  transfers,
  privateKey,
  { hash: 'abc123...', ordinal: 5 }
);
```

#### `signCurrencyTransaction(transaction, privateKey)`

Add an additional signature to a currency transaction (for multi-sig).

```typescript
let tx = await createCurrencyTransaction(params, key1, lastRef);
tx = await signCurrencyTransaction(tx, key2);
// tx.proofs.length === 2
```

#### `verifyCurrencyTransaction(transaction)`

Verify all signatures on a currency transaction.

```typescript
const result = await verifyCurrencyTransaction(tx);
console.log('Valid:', result.isValid);
```

#### `hashCurrencyTransaction(transaction)`

Hash a currency transaction.

```typescript
const hash = await hashCurrencyTransaction(tx);
console.log('Hash:', hash.value);
```

#### `getTransactionReference(transaction, ordinal)`

Get a transaction reference for chaining transactions.

```typescript
const ref = await getTransactionReference(tx, 6);
// Use ref as lastRef for next transaction
```

#### Utility Functions

```typescript
// Validate DAG address
isValidDagAddress('DAG...');  // true/false

// Convert between token units and smallest units
tokenToUnits(100.5);    // 10050000000
unitsToToken(10050000000);  // 100.5

// Token decimals constant
TOKEN_DECIMALS;  // 1e-8
```

### Network Operations

#### `CurrencyL1Client`

Client for interacting with Currency L1 nodes.

```typescript
import { CurrencyL1Client, NetworkConfig } from '@constellation-network/metagraph-sdk';

const config: NetworkConfig = {
  l1Url: 'http://localhost:9010',
  timeout: 30000,  // optional, defaults to 30s
};

const client = new CurrencyL1Client(config);

// Get last transaction reference for an address
const lastRef = await client.getLastReference('DAG...');

// Submit a signed transaction
const result = await client.postTransaction(signedTx);
console.log('Transaction hash:', result.hash);

// Check pending transaction status
const pending = await client.getPendingTransaction(result.hash);
if (pending) {
  console.log('Status:', pending.status);  // 'Waiting' | 'InProgress' | 'Accepted'
}

// Check node health
const isHealthy = await client.checkHealth();
```

#### `DataL1Client`

Client for interacting with Data L1 nodes (metagraphs).

```typescript
import { DataL1Client, NetworkConfig } from '@constellation-network/metagraph-sdk';

const config: NetworkConfig = {
  dataL1Url: 'http://localhost:8080',
};

const client = new DataL1Client(config);

// Estimate fee for data submission
const feeInfo = await client.estimateFee(signedData);
console.log('Fee:', feeInfo.fee, 'Address:', feeInfo.address);

// Submit signed data
const result = await client.postData(signedData);
console.log('Data hash:', result.hash);

// Check node health
const isHealthy = await client.checkHealth();
```

#### Combined Configuration

You can configure both L1 clients from a single config:

```typescript
const config: NetworkConfig = {
  l1Url: 'http://localhost:9010',      // Currency L1
  dataL1Url: 'http://localhost:8080',  // Data L1
  timeout: 30000,
};

const l1Client = new CurrencyL1Client(config);
const dataClient = new DataL1Client(config);
```

#### Network Types

```typescript
interface NetworkConfig {
  l1Url?: string;       // Currency L1 endpoint
  dataL1Url?: string;   // Data L1 endpoint
  timeout?: number;     // Request timeout in ms
}

interface PostTransactionResponse {
  hash: string;
}

interface PendingTransaction {
  hash: string;
  status: 'Waiting' | 'InProgress' | 'Accepted';
  transaction: CurrencyTransaction;
}

interface EstimateFeeResponse {
  fee: number;
  address: string;
}

interface PostDataResponse {
  hash: string;
}

class NetworkError extends Error {
  statusCode?: number;
  response?: string;
}
```

## Usage Examples

### Data Transactions

#### Submit DataUpdate to L1

```typescript
import { createSignedObject, DataL1Client } from '@constellation-network/metagraph-sdk';

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

// Submit to data-l1 using the client
const client = new DataL1Client({ dataL1Url: 'http://l1-node:9300' });
const result = await client.postData(signed);
console.log('Submitted with hash:', result.hash);
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

### Currency Transactions

#### Create and Submit Token Transaction

```typescript
import {
  generateKeyPair,
  createCurrencyTransaction,
  verifyCurrencyTransaction,
  CurrencyL1Client,
} from '@constellation-network/metagraph-sdk';

// Set up L1 client
const client = new CurrencyL1Client({ l1Url: 'http://localhost:9010' });

// Generate keys
const senderKey = generateKeyPair();
const recipientKey = generateKeyPair();

// Get last transaction reference from the network
const lastRef = await client.getLastReference(senderKey.address);

// Create transaction
const tx = await createCurrencyTransaction(
  {
    destination: recipientKey.address,
    amount: 100.5,  // 100.5 tokens
    fee: 0,
  },
  senderKey.privateKey,
  lastRef
);

// Verify locally before submitting
const result = await verifyCurrencyTransaction(tx);
console.log('Transaction valid:', result.isValid);

// Submit to network
const response = await client.postTransaction(tx);
console.log('Transaction hash:', response.hash);

// Poll for status
const pending = await client.getPendingTransaction(response.hash);
console.log('Status:', pending?.status);
```

#### Batch Token Transactions

```typescript
import { createCurrencyTransactionBatch } from '@constellation-network/metagraph-sdk';

const lastRef = { hash: 'abc123...', ordinal: 10 };

const transfers = [
  { destination: 'DAG...1', amount: 10, fee: 0 },
  { destination: 'DAG...2', amount: 20, fee: 0 },
  { destination: 'DAG...3', amount: 30, fee: 0 },
];

// Create batch (transactions are automatically chained)
const txns = await createCurrencyTransactionBatch(
  transfers,
  privateKey,
  lastRef
);

console.log(`Created ${txns.length} transactions`);
// Transaction 1 uses ordinal 10
// Transaction 2 uses ordinal 11
// Transaction 3 uses ordinal 12
```

#### Multi-Signature Token Transaction

```typescript
import {
  createCurrencyTransaction,
  signCurrencyTransaction,
  verifyCurrencyTransaction,
} from '@constellation-network/metagraph-sdk';

// Create transaction with first signature
let tx = await createCurrencyTransaction(
  { destination: 'DAG...', amount: 1000, fee: 0 },
  party1PrivateKey,
  lastRef
);

// Add second signature
tx = await signCurrencyTransaction(tx, party2PrivateKey);

// Add third signature
tx = await signCurrencyTransaction(tx, party3PrivateKey);

// Verify all signatures
const result = await verifyCurrencyTransaction(tx);
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
