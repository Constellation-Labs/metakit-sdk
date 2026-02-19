/**
 * Network operations for Metagraph L1 node interactions
 *
 * This module provides a unified client for interacting with Constellation Network
 * metagraph nodes at various layers:
 *
 * - **ML0** (Metagraph L0): State channel operations
 * - **CL1** (Currency L1): Currency transactions
 * - **DL1** (Data L1): Data/update submissions
 *
 * @example
 * ```typescript
 * import { MetagraphClient, createMetagraphClient } from '@constellation-network/metagraph-sdk/network';
 *
 * // Currency L1 client
 * const cl1 = createMetagraphClient('http://localhost:9300', 'cl1');
 * const ref = await cl1.getLastReference(address);
 * await cl1.postTransaction(signedTx);
 *
 * // Data L1 client
 * const dl1 = createMetagraphClient('http://localhost:9400', 'dl1');
 * const fee = await dl1.estimateFee(signedData);
 * await dl1.postData(signedData);
 *
 * // Metagraph L0 client
 * const ml0 = createMetagraphClient('http://localhost:9200', 'ml0');
 * const info = await ml0.getClusterInfo();
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

// HTTP client (for custom implementations)
export { HttpClient } from './client';

// Types and errors
export { NetworkError } from './types';
export type {
  RequestOptions,
  TransactionStatus,
  PendingTransaction,
  PostTransactionResponse,
  EstimateFeeResponse,
  PostDataResponse,
} from './types';
