import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from 'node:crypto';

export const FORMAT_VERSION = 1;

export const DEFAULT_KDF = Object.freeze({
  name: 'scrypt',
  N: 1 << 15,
  r: 8,
  p: 1,
  keylen: 32,
});

const CIPHER_NAME = 'aes-256-gcm';
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const MAX_MEMORY = 64 * 1024 * 1024;

export class VaultCryptoError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'VaultCryptoError';
    this.code = code;
  }
}

function buildAad(kdf) {
  return Buffer.from(
    JSON.stringify({
      v: FORMAT_VERSION,
      kdf: { name: kdf.name, N: kdf.N, r: kdf.r, p: kdf.p, keylen: kdf.keylen },
    }),
    'utf8',
  );
}

function normalizeKdf(kdf) {
  if (!kdf || kdf.name !== DEFAULT_KDF.name) {
    throw new VaultCryptoError('Unsupported key derivation function.', 'FORMAT');
  }
  const { N, r, p, keylen } = kdf;
  if (![N, r, p, keylen].every(Number.isSafeInteger)) {
    throw new VaultCryptoError('Invalid KDF parameters.', 'FORMAT');
  }
  if (N < 1 << 12 || N > 1 << 18 || r < 1 || r > 64 || p < 1 || p > 16 || keylen !== 32) {
    throw new VaultCryptoError('KDF parameters are outside the allowed range.', 'FORMAT');
  }
  return { name: kdf.name, N, r, p, keylen };
}

export function deriveKey(masterPassword, salt, kdf = DEFAULT_KDF) {
  const params = normalizeKdf(kdf);
  return scryptSync(masterPassword, salt, params.keylen, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: MAX_MEMORY,
  });
}

export function encrypt(plaintext, masterPassword, kdf = DEFAULT_KDF) {
  if (typeof masterPassword !== 'string' || masterPassword.length === 0) {
    throw new VaultCryptoError('Master password must not be empty.', 'PASSWORD');
  }

  const params = normalizeKdf(kdf);
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const key = deriveKey(masterPassword, salt, params);

  const cipher = createCipheriv(CIPHER_NAME, key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(buildAad(params));

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);

  return {
    version: FORMAT_VERSION,
    kdf: { ...params, salt: salt.toString('base64') },
    cipher: {
      name: CIPHER_NAME,
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    },
    data: ciphertext.toString('base64'),
  };
}

export function decrypt(envelope, masterPassword) {
  if (!envelope || typeof envelope !== 'object') {
    throw new VaultCryptoError('Vault file is not a valid object.', 'FORMAT');
  }
  if (envelope.version !== FORMAT_VERSION) {
    throw new VaultCryptoError('Unsupported vault format version.', 'FORMAT');
  }
  if (!envelope.cipher || envelope.cipher.name !== CIPHER_NAME) {
    throw new VaultCryptoError('Unsupported cipher.', 'FORMAT');
  }
  if (!envelope.kdf || !envelope.kdf.salt || !envelope.cipher.iv || !envelope.cipher.tag) {
    throw new VaultCryptoError('Vault file is missing required fields.', 'FORMAT');
  }

  const params = normalizeKdf(envelope.kdf);
  const salt = Buffer.from(envelope.kdf.salt, 'base64');
  const iv = Buffer.from(envelope.cipher.iv, 'base64');
  const tag = Buffer.from(envelope.cipher.tag, 'base64');
  const data = Buffer.from(envelope.data, 'base64');

  if (salt.length !== SALT_BYTES || iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new VaultCryptoError('Vault file has invalid cryptographic field sizes.', 'FORMAT');
  }

  const key = deriveKey(masterPassword, salt, params);
  const decipher = createDecipheriv(CIPHER_NAME, key, iv, { authTagLength: TAG_BYTES });
  decipher.setAAD(buildAad(params));
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  } catch {
    throw new VaultCryptoError(
      'Unable to unlock vault: wrong master password or the file was modified.',
      'AUTH',
    );
  }
}
