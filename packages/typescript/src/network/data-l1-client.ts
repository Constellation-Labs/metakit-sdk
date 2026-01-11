/**
 * Data L1 client for submitting data transactions to metagraphs
 *
 * @packageDocumentation
 */

import { HttpClient } from './client';
import type {
  NetworkConfig,
  EstimateFeeResponse,
  PostDataResponse,
  RequestOptions,
} from './types';
import type { Signed } from '../types';

/**
 * Client for interacting with Data L1 nodes (metagraphs)
 *
 * @example
 * ```typescript
 * const client = new DataL1Client({ dataL1Url: 'http://localhost:8080' });
 *
 * // Estimate fee for data submission
 * const feeInfo = await client.estimateFee(signedData);
 *
 * // Submit data
 * const result = await client.postData(signedData);
 * ```
 */
export class DataL1Client {
  private client: HttpClient;

  /**
   * Create a new DataL1Client
   *
   * @param config - Network configuration with dataL1Url
   * @throws Error if dataL1Url is not provided
   */
  constructor(config: NetworkConfig) {
    if (!config.dataL1Url) {
      throw new Error('dataL1Url is required for DataL1Client');
    }
    this.client = new HttpClient(config.dataL1Url, config.timeout);
  }

  /**
   * Estimate the fee for submitting data
   *
   * Some metagraphs charge fees for data submissions.
   * Call this before postData to know the required fee.
   *
   * @param data - Signed data object to estimate fee for
   * @param options - Request options
   * @returns Fee estimate with amount and destination address
   */
  async estimateFee<T>(
    data: Signed<T>,
    options?: RequestOptions
  ): Promise<EstimateFeeResponse> {
    return this.client.post<EstimateFeeResponse>(
      '/data/estimate-fee',
      data,
      options
    );
  }

  /**
   * Submit signed data to the Data L1 node
   *
   * @param data - Signed data object to submit
   * @param options - Request options
   * @returns Response containing the data hash
   */
  async postData<T>(
    data: Signed<T>,
    options?: RequestOptions
  ): Promise<PostDataResponse> {
    return this.client.post<PostDataResponse>('/data', data, options);
  }

  /**
   * Check the health/availability of the Data L1 node
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
