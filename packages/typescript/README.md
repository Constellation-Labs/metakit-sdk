# Constellation Metagraph SDK - TypeScript

TypeScript SDK for signing data and currency transactions on Constellation Network metagraphs built with the [metakit](https://github.com/Constellation-Labs/metakit) framework.

> **Scope:** This SDK supports both data transactions (state updates) and metagraph token transactions (value transfers). This SDK implements the standardized serialization, hashing, and signing routines defined by metakit and may not be compatible with metagraphs using custom serialization.

## Installation

```bash
npm install @constellation-network/metagraph-sdk
```

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
const signed = createSignedObject(data, keyPair.privateKey);

// Verify
const result = verify(signed);
console.log('Valid:', result.isValid);
```

### Namespaced Imports

The SDK also provides organized namespaces for cleaner imports:

```typescript
import { wallet, data, currency, network, jlvm } from '@constellation-network/metagraph-sdk';

// Wallet operations
const kp = wallet.generateKeyPair();

// Data signing
const signed = data.createSignedObject({ action: 'test' }, kp.privateKey);
const result = data.verify(signed);

// Currency transactions (shorter names)
const tx = currency.createTransaction(params, kp.privateKey, lastRef);

// JSON Logic VM
const answer = jlvm.jsonLogic.apply({ '+': [1, 2] }, {});
```

## Features

- **Data Transactions**: Sign and verify metagraph state updates for submission to data L1 endpoints
- **Currency Transactions**: Create and sign metagraph token transfers (v2 format)
- **Network Operations**: Submit transactions and query metagraph nodes via `MetagraphClient` (supports ML0, CL1, DL1 layers)
- **Multi-signature Support**: Add multiple signatures to transactions for multi-party authorization
- **JSON Logic VM**: Evaluate JSON Logic expressions compatible with the Scala metakit implementation
- **Cross-language Compatible**: Works seamlessly with Python, Rust, Go, and Java implementations

## API Reference

### Data Transactions

#### High-Level API

#### `createSignedObject<T>(value, privateKey, options?)`

Create a signed object with a single signature. The returned object includes a `mode` field that enables auto-verification.

```typescript
// Standard signing
const signed = createSignedObject({ action: 'test' }, privateKey);

// DataUpdate signing (for L1 submission)
const signed = createSignedObject(
  { action: 'test' },
  privateKey,
  { mode: 'dataUpdate' }  // or legacy: { isDataUpdate: true }
);
```

#### `addSignature<T>(signed, privateKey, options?)`

Add an additional signature to an existing signed object. Inherits the signing mode from the existing object.

```typescript
let signed = createSignedObject(data, party1Key);
signed = addSignature(signed, party2Key);
// signed.proofs.length === 2
```

#### `batchSign<T>(value, privateKeys, options?)`

Create a signed object with multiple signatures at once.

```typescript
const signed = batchSign(data, [key1, key2, key3]);
// signed.proofs.length === 3
```

#### `verify<T>(signed, isDataUpdate?)`

Verify all signatures on a signed object. When the object has a `mode` field (set by `createSignedObject`/`addSignature`/`batchSign`), verification automatically uses the correct mode.

```typescript
const result = verify(signed);
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

#### `toBytes<T>(data, mode?)`

Convert data to binary bytes for signing. Accepts `SigningMode` (`'standard'` | `'dataUpdate'`) or `boolean`.

```typescript
// Regular encoding
const bytes = toBytes(data);

// DataUpdate encoding (with Constellation prefix)
const updateBytes = toBytes(data, 'dataUpdate');
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
const proof = sign(data, privateKey);
// { id: '...', signature: '...' }
```

#### `signHash(hashHex, privateKey)`

Sign a pre-computed hash.

```typescript
const hashResult = hash(data);
const signature = signHash(hashResult.value, privateKey);
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
type SigningMode = 'standard' | 'dataUpdate';

interface SignatureProof {
  id: string;        // Public key (128 chars)
  signature: string; // DER signature hex
}

interface Signed<T> {
  value: T;
  proofs: SignatureProof[];
  mode?: SigningMode;  // Auto-detected by verify()
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

interface TransferResult {
  hash: string;            // Hash returned by L1 node
  transaction: CurrencyTransaction;
  reference: TransactionReference;  // For chaining subsequent transfers
}
```

### Currency Transactions

#### `createCurrencyTransaction(params, privateKey, lastRef)`

Create a metagraph token transaction.

```typescript
import { createCurrencyTransaction } from '@constellation-network/metagraph-sdk';

const tx = createCurrencyTransaction(
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

const txns = createCurrencyTransactionBatch(
  transfers,
  privateKey,
  { hash: 'abc123...', ordinal: 5 }
);
```

#### `signCurrencyTransaction(transaction, privateKey)`

Add an additional signature to a currency transaction (for multi-sig).

```typescript
let tx = createCurrencyTransaction(params, key1, lastRef);
tx = signCurrencyTransaction(tx, key2);
// tx.proofs.length === 2
```

#### `verifyCurrencyTransaction(transaction)`

Verify all signatures on a currency transaction.

```typescript
const result = verifyCurrencyTransaction(tx);
console.log('Valid:', result.isValid);
```

#### `hashCurrencyTransaction(transaction)`

Hash a currency transaction.

```typescript
const hash = hashCurrencyTransaction(tx);
console.log('Hash:', hash.value);
```

#### `getTransactionReference(transaction, ordinal)`

Get a transaction reference for chaining transactions.

```typescript
const ref = getTransactionReference(tx, 6);
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

The SDK provides a unified `MetagraphClient` that targets any metagraph layer — Currency L1 (CL1), Data L1 (DL1), or Metagraph L0 (ML0). Available methods are guarded by layer type at runtime.

```typescript
import { MetagraphClient, createMetagraphClient } from '@constellation-network/metagraph-sdk/network';

// Currency L1 — token transfers
const cl1 = createMetagraphClient('http://localhost:9300', 'cl1');

// Data L1 — metagraph state updates
const dl1 = createMetagraphClient('http://localhost:9400', 'dl1');

// Metagraph L0 — cluster operations
const ml0 = createMetagraphClient('http://localhost:9200', 'ml0');
```

#### Currency Operations (CL1)

**High-level transfer API:**

```typescript
// Single transfer — fetches last ref, signs, and submits automatically
const result = await cl1.transfer(
  { destination: 'DAG...recipient', amount: 100.5 },
  privateKey
);
console.log('Submitted:', result.hash);

// Chain another transfer using the returned reference
const result2 = await cl1.transfer(
  { destination: 'DAG...other', amount: 50 },
  privateKey,
  { lastRef: result.reference }
);

// Batch transfers — auto-chained sequentially
const results = await cl1.transferBatch(
  [
    { destination: 'DAG...1', amount: 10 },
    { destination: 'DAG...2', amount: 20 },
  ],
  privateKey
);
```

**Low-level methods:**

```typescript
// Get last transaction reference for an address
const lastRef = await cl1.getLastReference('DAG...');

// Submit a signed transaction
const result = await cl1.postTransaction(signedTx);
console.log('Transaction hash:', result.hash);

// Check pending transaction status
const pending = await cl1.getPendingTransaction(result.hash);
if (pending) {
  console.log('Status:', pending.status);  // 'Waiting' | 'InProgress' | 'Accepted'
}
```

#### Data Operations (DL1)

```typescript
// Estimate fee for data submission
const feeInfo = await dl1.estimateFee(signedData);
console.log('Fee:', feeInfo.fee, 'Address:', feeInfo.address);

// Submit signed data
const result = await dl1.postData(signedData);
console.log('Data hash:', result.hash);
```

#### Common Operations (All Layers)

```typescript
// Check node health
const isHealthy = await cl1.checkHealth();

// Get cluster information
const info = await ml0.getClusterInfo();
```

#### Network Types

```typescript
type LayerType = 'ml0' | 'cl1' | 'dl1';

interface MetagraphClientConfig {
  baseUrl: string;    // Node URL
  layer: LayerType;   // Target layer
  timeout?: number;   // Request timeout in ms (default: 30000)
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
import { createSignedObject } from '@constellation-network/metagraph-sdk';
import { createMetagraphClient } from '@constellation-network/metagraph-sdk/network';

// Your metagraph data update
const dataUpdate = {
  action: 'TRANSFER',
  from: 'address1',
  to: 'address2',
  amount: 100
};

// Sign as DataUpdate
const signed = createSignedObject(dataUpdate, privateKey, {
  mode: 'dataUpdate'
});

// Submit to data-l1 using the client
const dl1 = createMetagraphClient('http://l1-node:9300', 'dl1');
const result = await dl1.postData(signed);
console.log('Submitted with hash:', result.hash);
```

### Multi-Signature Workflow

```typescript
import { createSignedObject, addSignature, verify } from '@constellation-network/metagraph-sdk';

// Party 1 creates and signs
let signed = createSignedObject(data, party1Key);

// Party 2 adds signature
signed = addSignature(signed, party2Key);

// Party 3 adds signature
signed = addSignature(signed, party3Key);

// Verify all signatures — mode auto-detected
const result = verify(signed);
console.log(`${result.validProofs.length} valid signatures`);
```

### Currency Transactions

#### High-Level Transfer

```typescript
import { generateKeyPair } from '@constellation-network/metagraph-sdk';
import { createMetagraphClient } from '@constellation-network/metagraph-sdk/network';

const cl1 = createMetagraphClient('http://localhost:9300', 'cl1');
const sender = generateKeyPair();

// One-line transfer
const result = await cl1.transfer(
  { destination: 'DAG...recipient', amount: 100.5 },
  sender.privateKey
);
console.log('Transaction hash:', result.hash);
```

#### Low-Level Transaction Creation

```typescript
import {
  generateKeyPair,
  createCurrencyTransaction,
  verifyCurrencyTransaction,
} from '@constellation-network/metagraph-sdk';
import { createMetagraphClient } from '@constellation-network/metagraph-sdk/network';

// Set up CL1 client
const cl1 = createMetagraphClient('http://localhost:9300', 'cl1');

// Generate keys
const senderKey = generateKeyPair();
const recipientKey = generateKeyPair();

// Get last transaction reference from the network
const lastRef = await cl1.getLastReference(senderKey.address);

// Create transaction
const tx = createCurrencyTransaction(
  {
    destination: recipientKey.address,
    amount: 100.5,  // 100.5 tokens
    fee: 0,
  },
  senderKey.privateKey,
  lastRef
);

// Verify locally before submitting
const result = verifyCurrencyTransaction(tx);
console.log('Transaction valid:', result.isValid);

// Submit to network
const response = await cl1.postTransaction(tx);
console.log('Transaction hash:', response.hash);

// Poll for status
const pending = await cl1.getPendingTransaction(response.hash);
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
const txns = createCurrencyTransactionBatch(
  transfers,
  privateKey,
  lastRef
);

console.log(`Created ${txns.length} transactions`);
```

#### Multi-Signature Token Transaction

```typescript
import {
  createCurrencyTransaction,
  signCurrencyTransaction,
  verifyCurrencyTransaction,
} from '@constellation-network/metagraph-sdk';

// Create transaction with first signature
let tx = createCurrencyTransaction(
  { destination: 'DAG...', amount: 1000, fee: 0 },
  party1PrivateKey,
  lastRef
);

// Add second signature
tx = signCurrencyTransaction(tx, party2PrivateKey);

// Add third signature
tx = signCurrencyTransaction(tx, party3PrivateKey);

// Verify all signatures
const result = verifyCurrencyTransaction(tx);
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
