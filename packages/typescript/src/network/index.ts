/**
 * Network operations for Metagraph L1 node interactions
 *
 * This module provides clients for interacting with Constellation Network
 * metagraph nodes at various layers:
 *
 * - **ML0** (Metagraph L0): State channel operations
 * - **CL1** (Currency L1): Currency transactions
 * - **DL1** (Data L1): Data/update submissions
 *
 * @example
 * ```typescript
 * // Import network module separately (optional dependency)
 * import { MetagraphClient, createMetagraphClient } from '@constellation-network/metagraph-sdk/network';
 *
 * // Generic client for any layer
 * const dl1 = createMetagraphClient('http://localhost:9400', 'dl1');
 * await dl1.postData(signedData);
 *
 * // Or use convenience clients
 * import { CurrencyL1Client, DataL1Client } from '@constellation-network/metagraph-sdk/network';
 *
 * const currencyClient = new CurrencyL1Client({ l1Url: 'http://localhost:9300' });
 * const dataClient = new DataL1Client({ dataL1Url: 'http://localhost:9400' });
 * ```
 *
 * @packageDocumentation
 */

// Generic metagraph client
export {
  MetagraphClient,
  createMetagraphClient,
  type MetagraphClientConfig,
  type LayerType,
  type ClusterInfo,
} from './metagraph-client';

// Convenience clients (backwards compatible)
export { CurrencyL1Client } from './currency-l1-client';
export { DataL1Client } from './data-l1-client';

// HTTP client (for custom implementations)
export { HttpClient } from './client';

// Types and errors
export { NetworkError } from './types';
export type {
  NetworkConfig,
  RequestOptions,
  TransactionStatus,
  PendingTransaction,
  PostTransactionResponse,
  EstimateFeeResponse,
  PostDataResponse,
} from './types';
