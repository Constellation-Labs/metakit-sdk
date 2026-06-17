/**
 * Namespaced exports (core)
 *
 * Provides organized namespace objects alongside the existing flat exports.
 *
 * @example
 * ```typescript
 * import { wallet, data } from '@constellation-network/metagraph-sdk-core';
 *
 * const kp = wallet.generateKeyPair();
 * const signed = data.createSignedObject({ action: 'test' }, kp.privateKey);
 * ```
 */

import * as wallet from './wallet';
import * as data from './data';

export { wallet, data };
