# @constellation-network/metagraph-sdk-core

The core kernel of the Constellation metagraph SDK: hashing, RFC 8785 canonical
serialization, and secp256k1 signing/verification primitives. Generic and fully
offline — no currency-transaction layer, no network client, no JSON Logic VM.

Most applications should depend on
[`@constellation-network/metagraph-sdk`](https://github.com/Constellation-Labs/metakit-sdk/tree/main/packages/typescript)
(which re-exports this kernel and adds the currency-transaction layer plus the
network client). Depend on `-core` directly only when you need just the signing
primitives.

## Installation

```bash
npm install @constellation-network/metagraph-sdk-core
```

## Quick Start

```typescript
import {
  createSignedObject,
  verify,
  generateKeyPair,
} from '@constellation-network/metagraph-sdk-core';

const keyPair = generateKeyPair();
const signed = createSignedObject({ action: 'UPDATE', payload: { key: 'value' } }, keyPair.privateKey);
const result = verify(signed);
console.log('Valid:', result.isValid);
```

## What's included

- **Canonicalization** — `canonicalize`, `dropNullFields` (RFC 8785)
- **Binary encoding** — `toBytes`, `encodeDataUpdate`
- **Hashing** — `hash`, `hashBytes`, `hashData`, `computeDigest`
- **Codec** — `decodeDataUpdate`
- **Signing** — `sign`, `signDataUpdate`, `signHash`
- **Verification** — `verify`, `verifyHash`, `verifySignature`
- **High-level API** — `createSignedObject`, `addSignature`, `batchSign`
- **Wallet** — `generateKeyPair`, `keyPairFromPrivateKey`, `getAddress`, …
- **Crypto primitives** — `ecdsaSign`, `ecdsaVerify`, `constellationDigest`,
  `getPublicKeyFromPrivate`, `getDagAddressFromPublicKey`, …
- **Namespaces** — `wallet`, `data`

## License

Apache-2.0
