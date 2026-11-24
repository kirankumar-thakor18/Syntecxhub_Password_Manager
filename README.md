# Syntecxhub Password Manager

A local password manager that stores credentials **encrypted on disk** using AES-256-GCM.
Built with Node.js built-in `crypto` only — no external runtime dependencies.

## What it does

- Master password is never stored. A 32-byte key is derived from it with `scrypt` and a random salt.
- All entries are encrypted together as JSON into `vault.json` with a random 12-byte IV and a 16-byte auth tag.
- A wrong master password or any tampering (ciphertext, tag, or KDF parameters) makes decryption fail.
- Supports add, retrieve, delete, search, and changing the master password.
- Passwords are generated with `crypto.randomInt` (CSPRNG), never `Math.random`.

## Requirements

Node.js 18 or newer.

## Usage

```bash
npm run start -- init
npm run start -- add --service GitHub --username you@example.com
npm run start -- add --service Email --username you@example.com --password 'YourOwnPassword!' --notes 'personal'
npm run start -- list
npm run start -- search github
npm run start -- get <id> --show
npm run start -- delete <id>
npm run start -- change-master
npm run start -- generate --length 24 --no-symbols
```

Use `--vault <path>` with any command to store the vault somewhere else.

`add` generates a strong password when `--password` is omitted and prints it once.
`get` hides the password by default; `--show` reveals it.

## Tests

```bash
npm test
npm run check
```

Tests cover encryption round-trips, wrong-password and tamper rejection, generated password quality,
CRUD operations, absence of plaintext on disk, and master password rotation.

## Project layout

- `src/crypto.js` — scrypt key derivation, AES-256-GCM encrypt/decrypt, format validation
- `src/password.js` — secure password generation and entry IDs
- `src/vault.js` — encrypted JSON storage and CRUD operations
- `src/cli.js` — command-line interface with hidden master password input
- `test/vault.test.js` — security and functional tests

## Security notes

- The vault file contains only base64 ciphertext; no service name, username, or password is stored in plaintext.
- Writes are atomic (temporary file then rename) to avoid corruption after a crash.
- The authentication tag also binds the KDF parameters, so an attacker cannot weaken the work factor.
- A master password cannot be recovered if forgotten. Keep a backup of `vault.json` and remember the password.
