/**
 * Namespaced exports (metagraph-sdk)
 *
 * Surfaces the metagraph-specific `currency` and `network` namespaces, and
 * re-exports the core `wallet` and `data` namespaces so consumers get the
 * full set from one place.
 *
 * @example
 * ```typescript
 * import { wallet, currency, network } from '@constellation-network/metagraph-sdk';
 *
 * const kp = wallet.generateKeyPair();
 * const tx = currency.createTransaction(params, kp.privateKey, lastRef);
 * ```
 */

import * as currency from './currency';
import * as network from './network';
import { wallet, data } from '@constellation-network/metagraph-sdk-core';

export { wallet, data, currency, network };
