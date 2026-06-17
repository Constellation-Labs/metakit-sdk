/**
 * Wallet namespace — key generation and management
 */
export {
  generateKeyPair,
  keyPairFromPrivateKey,
  getPublicKeyHex,
  getPublicKeyId,
  getAddress,
  isValidPrivateKey,
  isValidPublicKey,
} from '../wallet';

export type { KeyPair } from '../types';
