import { randomBytes } from 'node:crypto';
import { access, chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { decrypt, encrypt, DEFAULT_KDF } from './crypto.js';
import { generatePassword, newEntryId } from './password.js';

export class VaultError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'VaultError';
    this.code = code;
  }
}

function requireText(value, label, max = 500) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new VaultError(`${label} must not be empty.`, 'VALIDATION');
  }
  if (value.length > max) {
    throw new VaultError(`${label} must be at most ${max} characters.`, 'VALIDATION');
  }
  return value.trim();
}

function optionalText(value, label, max = 2000) {
  if (value === undefined || value === null) return '';
  if (typeof value !== 'string') {
    throw new VaultError(`${label} must be a string.`, 'VALIDATION');
  }
  if (value.length > max) {
    throw new VaultError(`${label} must be at most ${max} characters.`, 'VALIDATION');
  }
  return value;
}

export function defaultVaultPath() {
  return resolve(process.cwd(), 'vault.json');
}

export class Vault {
  constructor(filePath = defaultVaultPath()) {
    this.filePath = resolve(filePath);
  }

  async exists() {
    try {
      await access(this.filePath);
      return true;
    } catch {
      return false;
    }
  }

  async init(masterPassword) {
    if (await this.exists()) {
      throw new VaultError('A vault already exists at this path.', 'EXISTS');
    }
    await this.#write([], masterPassword, DEFAULT_KDF);
  }

  async #readEnvelope() {
    let text;
    try {
      text = await readFile(this.filePath, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') {
        throw new VaultError('Vault not found. Run "init" first.', 'NOT_FOUND');
      }
      throw error;
    }
    try {
      return JSON.parse(text);
    } catch {
      throw new VaultError('Vault file is corrupted (invalid JSON).', 'FORMAT');
    }
  }

  async #write(entries, masterPassword, kdf = DEFAULT_KDF) {
    const envelope = encrypt(JSON.stringify(entries), masterPassword, kdf);
    const tempPath = `${this.filePath}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    await mkdir(dirname(this.filePath), { recursive: true });
    await writeFile(tempPath, `${JSON.stringify(envelope, null, 2)}\n`, { mode: 0o600 });
    try {
      await chmod(tempPath, 0o600);
    } catch {}
    await rename(tempPath, this.filePath);
  }

  async #unlock(masterPassword) {
    const envelope = await this.#readEnvelope();
    const plaintext = decrypt(envelope, masterPassword);
    let entries;
    try {
      entries = JSON.parse(plaintext);
    } catch {
      throw new VaultError('Decrypted vault contents are invalid.', 'FORMAT');
    }
    if (!Array.isArray(entries)) {
      throw new VaultError('Decrypted vault contents must be a list.', 'FORMAT');
    }
    return { envelope, entries };
  }

  async #commit(entries, masterPassword, kdf) {
    await this.#write(entries, masterPassword, kdf);
  }

  #find(entries, id) {
    const needle = String(id).trim().toLowerCase();
    if (!needle) throw new VaultError('An entry id is required.', 'VALIDATION');
    const matches = entries.filter((entry) => entry.id.toLowerCase().startsWith(needle));
    if (matches.length === 0) throw new VaultError('No matching entry found.', 'NOT_FOUND');
    if (matches.length > 1) throw new VaultError('Ambiguous id; use more characters.', 'AMBIGUOUS');
    return matches[0];
  }

  async list(masterPassword) {
    return (await this.#unlock(masterPassword)).entries;
  }

  async add(masterPassword, input) {
    const service = requireText(input.service, 'Service', 200);
    const username = requireText(input.username, 'Username', 320);
    const notes = optionalText(input.notes, 'Notes');
    let password = input.password;
    if (password === undefined || password === null || password === '') {
      password = generatePassword();
    } else if (typeof password !== 'string' || password.length > 1024) {
      throw new VaultError('Password must be a string of at most 1024 characters.', 'VALIDATION');
    }

    const { entries } = await this.#unlock(masterPassword);
    const now = new Date().toISOString();
    const entry = {
      id: newEntryId(),
      service,
      username,
      password,
      notes,
      createdAt: now,
      updatedAt: now,
    };
    entries.push(entry);
    await this.#commit(entries, masterPassword);
    return entry;
  }

  async get(masterPassword, id) {
    const { entries } = await this.#unlock(masterPassword);
    return this.#find(entries, id);
  }

  async search(masterPassword, query) {
    const needle = requireText(query, 'Search query', 200).toLowerCase();
    const { entries } = await this.#unlock(masterPassword);
    return entries.filter((entry) =>
      [entry.service, entry.username, entry.notes]
        .some((field) => String(field ?? '').toLowerCase().includes(needle)),
    );
  }

  async delete(masterPassword, id) {
    const { entries } = await this.#unlock(masterPassword);
    const target = this.#find(entries, id);
    await this.#commit(entries.filter((entry) => entry.id !== target.id), masterPassword);
    return target;
  }

  async changeMaster(currentPassword, newPassword) {
    const { entries, envelope } = await this.#unlock(currentPassword);
    await this.#commit(entries, newPassword, envelope.kdf);
  }
}
