/**
 * Currency namespace — metagraph token transaction operations
 *
 * Provides shorter aliases for currency-specific functions:
 *   createCurrencyTransaction → createTransaction
 *   createCurrencyTransactionBatch → createTransactionBatch
 *   signCurrencyTransaction → signTransaction
 *   verifyCurrencyTransaction → verifyTransaction
 *   encodeCurrencyTransaction → encodeTransaction
 *   hashCurrencyTransaction → hashTransaction
 */

export {
  createCurrencyTransaction as createTransaction,
  createCurrencyTransactionBatch as createTransactionBatch,
  signCurrencyTransaction as signTransaction,
  verifyCurrencyTransaction as verifyTransaction,
  encodeCurrencyTransaction as encodeTransaction,
  hashCurrencyTransaction as hashTransaction,
  getTransactionReference,
  isValidDagAddress,
  tokenToUnits,
  unitsToToken,
} from '../currency-transaction';

export { TOKEN_DECIMALS } from '../currency-types';

export type {
  TransactionReference,
  CurrencyTransactionValue,
  CurrencyTransaction,
  TransferParams,
  TransferResult,
} from '../currency-types';
