/**
 * Generic Metagraph Client for any L1 layer type
 *
 * Works with ML0 (Metagraph L0), CL1 (Currency L1), and DL1 (Data L1) nodes.
 *
 * @packageDocumentation
 */

import { HttpClient } from './client';
import type {
  RequestOptions,
  PendingTransaction,
  PostTransactionResponse,
  EstimateFeeResponse,
  PostDataResponse,
} from './types';
import { NetworkError } from './types';
import type { TransactionReference, CurrencyTransaction } from '../currency-types';
import type { Signed } from '../types';

/**
 * Supported L1 layer types
 */
export type LayerType = 'ml0' | 'cl1' | 'dl1';

/**
 * Configuration for MetagraphClient
 */
export interface MetagraphClientConfig {
  /** Base URL of the L1 node (e.g., 'http://localhost:9200') */
  baseUrl: string;
  /** Layer type for API path selection */
  layer: LayerType;
  /** Request timeout in milliseconds (default: 30000) */
  timeout?: number;
}

/**
 * Cluster information from any L1 node
 */
export interface ClusterInfo {
  /** Cluster node count */
  size?: number;
  /** Cluster ID */
  clusterId?: string;
  /** Additional info (varies by layer) */
  [key: string]: unknown;
}

/**
 * Generic client for interacting with any Metagraph L1 layer
 *
 * This client provides a unified interface for ML0, CL1, and DL1 nodes,
 * automatically selecting the correct API paths based on layer type.
 *
 * @example
 * ```typescript
 * // Connect to a Currency L1 node
 * const cl1 = new MetagraphClient({
 *   baseUrl: 'http://localhost:9300',
 *   layer: 'cl1'
 * });
 *
 * // Connect to a Data L1 node
 * const dl1 = new MetagraphClient({
 *   baseUrl: 'http://localhost:9400',
 *   layer: 'dl1'
 * });
 *
 * // Connect to a Metagraph L0 node
 * const ml0 = new MetagraphClient({
 *   baseUrl: 'http://localhost:9200',
 *   layer: 'ml0'
 * });
 * ```
 */
export class MetagraphClient {
  private client: HttpClient;
  private layer: LayerType;

  /**
   * Create a new MetagraphClient
   *
   * @param config - Client configuration
   */
  constructor(config: MetagraphClientConfig) {
    if (!config.baseUrl) {
      throw new Error('baseUrl is required for MetagraphClient');
    }
    if (!config.layer) {
      throw new Error('layer is required for MetagraphClient');
    }
    this.client = new HttpClient(config.baseUrl, config.timeout);
    this.layer = config.layer;
  }

  /**
   * Get the layer type of this client
   */
  getLayer(): LayerType {
    return this.layer;
  }

  // ============================================
  // Common operations (all layers)
  // ============================================

  /**
   * Check the health/availability of the node
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

  /**
   * Get cluster information
   *
   * @param options - Request options
   * @returns Cluster information
   */
  async getClusterInfo(options?: RequestOptions): Promise<ClusterInfo> {
    return this.client.get<ClusterInfo>('/cluster/info', options);
  }

  // ============================================
  // Currency operations (CL1 and ML0)
  // ============================================

  /**
   * Get the last accepted transaction reference for an address
   *
   * This is needed to create a new transaction that chains from
   * the address's most recent transaction.
   *
   * Available on: CL1, ML0 (if currency enabled)
   *
   * @param address - DAG address to query
   * @param options - Request options
   * @returns Transaction reference with hash and ordinal
   */
  async getLastReference(
    address: string,
    options?: RequestOptions
  ): Promise<TransactionReference> {
    this.assertLayer(['cl1', 'ml0'], 'getLastReference');
    return this.client.get<TransactionReference>(
      `/transactions/last-reference/${address}`,
      options
    );
  }

  /**
   * Submit a signed currency transaction
   *
   * Available on: CL1
   *
   * @param transaction - Signed currency transaction
   * @param options - Request options
   * @returns Response containing the transaction hash
   */
  async postTransaction(
    transaction: CurrencyTransaction,
    options?: RequestOptions
  ): Promise<PostTransactionResponse> {
    this.assertLayer(['cl1'], 'postTransaction');
    return this.client.post<PostTransactionResponse>(
      '/transactions',
      transaction,
      options
    );
  }

  /**
   * Get a pending transaction by hash
   *
   * Available on: CL1
   *
   * @param hash - Transaction hash
   * @param options - Request options
   * @returns Pending transaction details or null if not found
   */
  async getPendingTransaction(
    hash: string,
    options?: RequestOptions
  ): Promise<PendingTransaction | null> {
    this.assertLayer(['cl1'], 'getPendingTransaction');
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

  // ============================================
  // Data operations (DL1)
  // ============================================

  /**
   * Estimate the fee for submitting data
   *
   * Available on: DL1
   *
   * @param data - Signed data object to estimate fee for
   * @param options - Request options
   * @returns Fee estimate with amount and destination address
   */
  async estimateFee<T>(
    data: Signed<T>,
    options?: RequestOptions
  ): Promise<EstimateFeeResponse> {
    this.assertLayer(['dl1'], 'estimateFee');
    return this.client.post<EstimateFeeResponse>(
      '/data/estimate-fee',
      data,
      options
    );
  }

  /**
   * Submit signed data to the Data L1 node
   *
   * Available on: DL1
   *
   * @param data - Signed data object to submit
   * @param options - Request options
   * @returns Response containing the data hash
   */
  async postData<T>(
    data: Signed<T>,
    options?: RequestOptions
  ): Promise<PostDataResponse> {
    this.assertLayer(['dl1'], 'postData');
    return this.client.post<PostDataResponse>('/data', data, options);
  }

  // ============================================
  // Raw HTTP access
  // ============================================

  /**
   * Make a raw GET request to the node
   *
   * @param path - API path
   * @param options - Request options
   * @returns Response data
   */
  async get<T>(path: string, options?: RequestOptions): Promise<T> {
    return this.client.get<T>(path, options);
  }

  /**
   * Make a raw POST request to the node
   *
   * @param path - API path
   * @param body - Request body
   * @param options - Request options
   * @returns Response data
   */
  async post<T>(path: string, body?: unknown, options?: RequestOptions): Promise<T> {
    return this.client.post<T>(path, body, options);
  }

  // ============================================
  // Helpers
  // ============================================

  private assertLayer(allowed: LayerType[], method: string): void {
    if (!allowed.includes(this.layer)) {
      throw new Error(
        `${method}() is not available on ${this.layer.toUpperCase()} layer. ` +
        `Available on: ${allowed.map(l => l.toUpperCase()).join(', ')}`
      );
    }
  }
}

/**
 * Create a MetagraphClient for a specific layer
 *
 * @param baseUrl - Node URL
 * @param layer - Layer type
 * @param timeout - Request timeout
 */
export function createMetagraphClient(
  baseUrl: string,
  layer: LayerType,
  timeout?: number
): MetagraphClient {
  return new MetagraphClient({ baseUrl, layer, timeout });
}
