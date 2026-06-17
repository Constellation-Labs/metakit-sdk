/**
 * Constellation Metagraph SDK
 *
 * TypeScript SDK for signing operations on Constellation Network metagraphs.
 *
 * This package = the offline signing kernel (re-exported from
 * `@constellation-network/metagraph-sdk-core`) PLUS the metagraph
 * currency-transaction layer and the network client. It works fully offline
 * for signing; the network client is an optional subpath import.
 *
 * ```typescript
 * // Network client (ML0/CL1/DL1 nodes)
 * import { createMetagraphClient } from '@constellation-network/metagraph-sdk/network';
 * ```
 *
 * @packageDocumentation
 */

// Re-export the entire core signing kernel (types, canonicalize, binary,
// hash, codec, sign, verify, signed-object, wallet, crypto primitives, and
// the core `wallet`/`data` namespaces).
export * from '@constellation-network/metagraph-sdk-core';

// Currency transaction types
export type {
  TransactionReference,
  CurrencyTransactionValue,
  CurrencyTransaction,
  TransferParams,
  TransferResult,
} from './currency-types';

export { TOKEN_DECIMALS } from './currency-types';

// Currency transaction operations
export {
  createCurrencyTransaction,
  createCurrencyTransactionBatch,
  signCurrencyTransaction,
  verifyCurrencyTransaction,
  encodeCurrencyTransaction,
  hashCurrencyTransaction,
  getTransactionReference,
  isValidDagAddress,
  tokenToUnits,
  unitsToToken,
} from './currency-transaction';

// Namespaced exports. `wallet` and `data` come from core (re-exported via the
// `export *` above); `currency` and `network` are this package's own namespaces.
// Network is also available as a separate subpath import.
export { currency, network } from './namespaces';
