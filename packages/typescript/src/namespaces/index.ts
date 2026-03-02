/**
 * Namespaced exports
 *
 * Provides organized namespace objects alongside the existing flat exports.
 *
 * @example
 * ```typescript
 * import { wallet, currency, network } from '@constellation-network/metagraph-sdk';
 *
 * const kp = wallet.generateKeyPair();
 * const tx = currency.createTransaction(params, kp.privateKey, lastRef);
 * ```
 */

import * as wallet from './wallet';
import * as data from './data';
import * as currency from './currency';
import * as network from './network';
import * as jlvm from './jlvm';

export { wallet, data, currency, network, jlvm };
