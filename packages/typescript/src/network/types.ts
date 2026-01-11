/**
 * Network types for L1 client operations
 *
 * @packageDocumentation
 */

import type { CurrencyTransaction } from '../currency-types';

/**
 * Network configuration for connecting to L1 nodes
 */
export interface NetworkConfig {
  /** Currency L1 endpoint URL (e.g., 'http://localhost:9010') */
  l1Url?: string;
  /** Data L1 endpoint URL (e.g., 'http://localhost:8080') */
  dataL1Url?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
}

/**
 * HTTP request options
 */
export interface RequestOptions {
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Additional headers */
  headers?: Record<string, string>;
}

/**
 * Transaction status in the network
 */
export type TransactionStatus =
  | 'Waiting'
  | 'InProgress'
  | 'Accepted';

/**
 * Pending transaction response from L1
 */
export interface PendingTransaction {
  /** Transaction hash */
  hash: string;
  /** Current status */
  status: TransactionStatus;
  /** The transaction value */
  transaction: CurrencyTransaction;
}

/**
 * Response from posting a transaction
 */
export interface PostTransactionResponse {
  /** Transaction hash */
  hash: string;
}

/**
 * Response from estimating data transaction fee
 */
export interface EstimateFeeResponse {
  /** Estimated fee in smallest units */
  fee: number;
  /** Fee destination address */
  address: string;
}

/**
 * Response from posting data
 */
export interface PostDataResponse {
  /** Data hash */
  hash: string;
}

/**
 * Network error with status code and response details
 */
export class NetworkError extends Error {
  /** HTTP status code if applicable */
  statusCode?: number;
  /** Raw response body */
  response?: string;

  constructor(message: string, statusCode?: number, response?: string) {
    super(message);
    this.name = 'NetworkError';
    this.statusCode = statusCode;
    this.response = response;
  }
}
