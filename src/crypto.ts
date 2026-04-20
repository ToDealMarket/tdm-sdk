import bs58 from 'bs58';
import nacl from 'tweetnacl';

export interface Ed25519KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  format: 'webcrypto-pkcs8' | 'tweetnacl-secret';
}

const ED25519_ALGORITHM_NAME = 'Ed25519';
let webCryptoEd25519SupportPromise: Promise<boolean> | null = null;

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function getSubtleCrypto(): SubtleCrypto | null {
  if (typeof globalThis.crypto === 'undefined') {
    return null;
  }
  return globalThis.crypto.subtle;
}

async function supportsWebCryptoEd25519(subtle: SubtleCrypto): Promise<boolean> {
  try {
    const pair = (await subtle.generateKey(
      { name: ED25519_ALGORITHM_NAME },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    await subtle.exportKey('raw', pair.publicKey);
    return true;
  } catch {
    return false;
  }
}

async function canUseWebCryptoEd25519(
  subtle: SubtleCrypto | null,
): Promise<boolean> {
  if (!subtle) {
    return false;
  }
  if (!webCryptoEd25519SupportPromise) {
    webCryptoEd25519SupportPromise = supportsWebCryptoEd25519(subtle);
  }
  return await webCryptoEd25519SupportPromise;
}

export function base58Encode(value: Uint8Array): string {
  return bs58.encode(value);
}

export function base58Decode(value: string): Uint8Array {
  return bs58.decode(value);
}

/**
 * Generates Ed25519 keypair with WebCrypto when available, otherwise falls back to tweetnacl.
 */
export async function generateEd25519KeyPair(): Promise<Ed25519KeyPair> {
  const subtle = getSubtleCrypto();
  if (await canUseWebCryptoEd25519(subtle)) {
    const webCrypto = subtle as SubtleCrypto;
    const pair = (await webCrypto.generateKey(
      { name: ED25519_ALGORITHM_NAME },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;

    const publicKey = new Uint8Array(
      await webCrypto.exportKey('raw', pair.publicKey),
    );
    const privateKey = new Uint8Array(
      await webCrypto.exportKey('pkcs8', pair.privateKey),
    );

    return {
      publicKey,
      privateKey,
      format: 'webcrypto-pkcs8',
    };
  }

  const pair = nacl.sign.keyPair();
  return {
    publicKey: pair.publicKey,
    privateKey: pair.secretKey,
    format: 'tweetnacl-secret',
  };
}

/**
 * Signs bytes with Ed25519 private key.
 * If key is 64 bytes, it's treated as tweetnacl secret key.
 * Otherwise it is interpreted as PKCS8 for WebCrypto.
 */
export async function signEd25519(
  message: Uint8Array,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  if (privateKey.byteLength === 64) {
    return nacl.sign.detached(message, privateKey);
  }

  const subtle = getSubtleCrypto();
  if (!subtle) {
    throw new Error('WebCrypto is required for PKCS8 Ed25519 keys');
  }

  const cryptoKey = await subtle.importKey(
    'pkcs8',
    toArrayBuffer(privateKey),
    { name: ED25519_ALGORITHM_NAME },
    false,
    ['sign'],
  );
  const signature = await subtle.sign(
    { name: ED25519_ALGORITHM_NAME },
    cryptoKey,
    toArrayBuffer(message),
  );
  return new Uint8Array(signature);
}

/**
 * Verifies Ed25519 signature against message.
 * Supports raw 32-byte public keys and SPKI public keys.
 */
export async function verifyEd25519(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (publicKey.byteLength === nacl.sign.publicKeyLength) {
    return nacl.sign.detached.verify(message, signature, publicKey);
  }

  const subtle = getSubtleCrypto();
  if (!subtle) {
    throw new Error('WebCrypto is required for non-raw Ed25519 public keys');
  }

  const cryptoKey = await subtle.importKey(
    'spki',
    toArrayBuffer(publicKey),
    { name: ED25519_ALGORITHM_NAME },
    false,
    ['verify'],
  );
  return subtle.verify(
    { name: ED25519_ALGORITHM_NAME },
    cryptoKey,
    toArrayBuffer(signature),
    toArrayBuffer(message),
  );
}
