/**
 * Currency transaction types for metagraph token transfers
 *
 * @packageDocumentation
 */

import type { Signed } from './types';

/**
 * Reference to a previous transaction for chaining
 */
export interface TransactionReference {
  /** Transaction hash */
  hash: string;
  /** Transaction ordinal number */
  ordinal: number;
}

/**
 * Currency transaction value structure (v2)
 * Contains the actual transaction data before signing
 */
export interface CurrencyTransactionValue {
  /** Source DAG address */
  source: string;
  /** Destination DAG address */
  destination: string;
  /** Amount in smallest units (1e-8) */
  amount: number;
  /** Fee in smallest units (1e-8) */
  fee: number;
  /** Reference to parent transaction */
  parent: TransactionReference;
  /** Random salt for uniqueness (as string) */
  salt: string;
}

/**
 * Currency transaction structure (v2)
 * A signed currency transaction value
 * Used for metagraph token transfers
 */
export type CurrencyTransaction = Signed<CurrencyTransactionValue>;

/**
 * Parameters for creating a token transfer
 */
export interface TransferParams {
  /** Destination DAG address */
  destination: string;
  /** Amount in token units (e.g., 100.5 tokens) */
  amount: number;
  /** Fee in token units (defaults to 0) */
  fee?: number;
}

/**
 * Result of a high-level transfer operation
 */
export interface TransferResult {
  /** Transaction hash returned by the L1 node */
  hash: string;
  /** The signed transaction that was submitted */
  transaction: CurrencyTransaction;
  /** Reference for chaining subsequent transactions */
  reference: TransactionReference;
}

/**
 * Token decimals constant (1e-8)
 * Same as DAG_DECIMALS from dag4.js
 */
export const TOKEN_DECIMALS = 1e-8;
