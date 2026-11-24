import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { decrypt, encrypt, VaultCryptoError } from '../src/crypto.js';
import { generatePassword } from '../src/password.js';
import { Vault } from '../src/vault.js';

const dirs = [];
after(async () => {
  await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
});

async function tempVault() {
  const dir = await mkdtemp(join(tmpdir(), 'vault-test-'));
  dirs.push(dir);
  return new Vault(join(dir, 'vault.json'));
}

test('AES-GCM round trip and wrong password rejection', () => {
  const envelope = encrypt('secret message', 'correct horse battery staple');
  assert.equal(decrypt(envelope, 'correct horse battery staple'), 'secret message');
  assert.throws(
    () => decrypt(envelope, 'wrong password'),
    (error) => error instanceof VaultCryptoError && error.code === 'AUTH',
  );
});

test('tampering with ciphertext, tag or KDF params is detected', () => {
  const envelope = encrypt('hello vault', 'master-password');
  const tampered = structuredClone(envelope);
  const data = Buffer.from(tampered.data, 'base64');
  data[0] ^= 1;
  tampered.data = data.toString('base64');
  assert.throws(() => decrypt(tampered, 'master-password'), VaultCryptoError);

  const downgraded = structuredClone(envelope);
  downgraded.kdf.N = 16;
  assert.throws(() => decrypt(downgraded, 'master-password'), VaultCryptoError);
});

test('generated passwords are long, mixed and unique', () => {
  const a = generatePassword(20);
  const b = generatePassword(20);
  assert.equal(a.length, 20);
  assert.notEqual(a, b);
  assert.match(a, /[a-z]/);
  assert.match(a, /[A-Z]/);
  assert.match(a, /[0-9]/);
  assert.match(a, /[^A-Za-z0-9]/);
  assert.doesNotMatch(generatePassword(20, { noSymbols: true }), /[^A-Za-z0-9]/);
});

test('vault CRUD works and file contains no plaintext', async () => {
  const vault = await tempVault();
  await vault.init('master-password');

  const entry = await vault.add('master-password', {
    service: 'GitHub',
    username: 'dev@example.com',
    password: 'SuperSecret123!',
    notes: 'work account',
  });
  assert.equal(entry.service, 'GitHub');

  const all = await vault.list('master-password');
  assert.equal(all.length, 1);

  const found = await vault.search('master-password', 'github');
  assert.equal(found.length, 1);
  assert.equal((await vault.search('master-password', 'SuperSecret')).length, 0);

  const fetched = await vault.get('master-password', entry.id.slice(0, 8));
  assert.equal(fetched.username, 'dev@example.com');

  const raw = await readFile(vault.filePath, 'utf8');
  assert.doesNotMatch(raw, /GitHub|SuperSecret123!|dev@example\.com/);

  await vault.delete('master-password', entry.id);
  assert.equal((await vault.list('master-password')).length, 0);
});

test('change-master re-encrypts the vault', async () => {
  const vault = await tempVault();
  await vault.init('old-master-password');
  await vault.add('old-master-password', {
    service: 'Email',
    username: 'me@example.com',
    password: 'AnotherSecret!42',
  });

  await vault.changeMaster('old-master-password', 'new-master-password');

  await assert.rejects(() => vault.list('old-master-password'), VaultCryptoError);
  assert.equal((await vault.list('new-master-password')).length, 1);
});
