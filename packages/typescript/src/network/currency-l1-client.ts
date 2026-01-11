/**
 * Currency L1 client for submitting and querying transactions
 *
 * @packageDocumentation
 */

import { HttpClient } from './client';
import type {
  NetworkConfig,
  PendingTransaction,
  PostTransactionResponse,
  RequestOptions,
} from './types';
import { NetworkError } from './types';
import type { TransactionReference, CurrencyTransaction } from '../currency-types';

/**
 * Client for interacting with Currency L1 nodes
 *
 * @example
 * ```typescript
 * const client = new CurrencyL1Client({ l1Url: 'http://localhost:9010' });
 *
 * // Get last reference for an address
 * const lastRef = await client.getLastReference('DAG...');
 *
 * // Submit a transaction
 * const result = await client.postTransaction(signedTx);
 *
 * // Check transaction status
 * const pending = await client.getPendingTransaction(result.hash);
 * ```
 */
export class CurrencyL1Client {
  private client: HttpClient;

  /**
   * Create a new CurrencyL1Client
   *
   * @param config - Network configuration with l1Url
   * @throws Error if l1Url is not provided
   */
  constructor(config: NetworkConfig) {
    if (!config.l1Url) {
      throw new Error('l1Url is required for CurrencyL1Client');
    }
    this.client = new HttpClient(config.l1Url, config.timeout);
  }

  /**
   * Get the last accepted transaction reference for an address
   *
   * This is needed to create a new transaction that chains from
   * the address's most recent transaction.
   *
   * @param address - DAG address to query
   * @param options - Request options
   * @returns Transaction reference with hash and ordinal
   */
  async getLastReference(
    address: string,
    options?: RequestOptions
  ): Promise<TransactionReference> {
    return this.client.get<TransactionReference>(
      `/transactions/last-reference/${address}`,
      options
    );
  }

  /**
   * Submit a signed currency transaction to the L1 network
   *
   * @param transaction - Signed currency transaction
   * @param options - Request options
   * @returns Response containing the transaction hash
   */
  async postTransaction(
    transaction: CurrencyTransaction,
    options?: RequestOptions
  ): Promise<PostTransactionResponse> {
    return this.client.post<PostTransactionResponse>(
      '/transactions',
      transaction,
      options
    );
  }

  /**
   * Get a pending transaction by hash
   *
   * Use this to poll for transaction status after submission.
   * Returns null if the transaction is not found (already confirmed or invalid).
   *
   * @param hash - Transaction hash
   * @param options - Request options
   * @returns Pending transaction details or null if not found
   */
  async getPendingTransaction(
    hash: string,
    options?: RequestOptions
  ): Promise<PendingTransaction | null> {
    try {
      return await this.client.get<PendingTransaction>(
        `/transactions/${hash}`,
        options
      );
    } catch (error) {
      if (error instanceof NetworkError && error.statusCode === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Check the health/availability of the L1 node
   *
   * @param options - Request options
   * @returns True if the node is healthy
   */
  async checkHealth(options?: RequestOptions): Promise<boolean> {
    try {
      await this.client.get('/cluster/info', options);
      return true;
    } catch {
      return false;
    }
  }
}
