#!/usr/bin/env node
import { resolve } from 'node:path';
import { Vault, VaultError, defaultVaultPath } from './vault.js';
import { generatePassword } from './password.js';

const HELP = `Password Manager (AES-256-GCM + scrypt)

Usage:
  init                          Create a new encrypted vault
  add --service S --username U [--password P] [--notes N] [--length L] [--no-symbols]
  list                          Show all entries
  search <text>                 Search service, username and notes
  get <id> [--show]             Show one entry (password hidden by default)
  delete <id>                   Delete one entry
  change-master                 Re-encrypt the vault with a new master password
  generate [--length L] [--no-symbols]

Global option: --vault <path>   (default: ${defaultVaultPath()})
`;

function parseArgs(argv) {
  const positional = [];
  const options = {};
  const booleanFlags = new Set(['show', 'no-symbols', 'help']);

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      positional.push(token);
      continue;
    }
    const [name, inline] = token.slice(2).split('=', 2);
    if (inline !== undefined) {
      options[name] = inline;
    } else if (booleanFlags.has(name)) {
      options[name] = true;
    } else {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('--')) {
        throw new VaultError(`Missing value for --${name}.`, 'USAGE');
      }
      options[name] = next;
      i += 1;
    }
  }
  return { positional, options };
}

function askSecret(label) {
  return new Promise((resolveSecret, rejectSecret) => {
    process.stdout.write(label);
    const input = process.stdin;
    const isRaw = Boolean(input.isTTY);
    let value = '';

    if (isRaw) input.setRawMode(true);
    input.setEncoding('utf8');
    input.resume();

    const cleanup = () => {
      input.removeListener('data', onData);
      if (isRaw) input.setRawMode(false);
      input.pause();
    };

    function onData(chunk) {
      for (const char of chunk) {
        if (char === '\n' || char === '\r') {
          cleanup();
          process.stdout.write('\n');
          resolveSecret(value);
          return;
        }
        if (char === '\u0003') {
          cleanup();
          process.stdout.write('\n');
          rejectSecret(new VaultError('Cancelled.', 'CANCELLED'));
          return;
        }
        if (char === '\b' || char === '\u007f') {
          value = value.slice(0, -1);
          if (isRaw) process.stdout.write('\b \b');
          continue;
        }
        value += char;
        if (isRaw) process.stdout.write('*');
      }
    }

    input.on('data', onData);
  });
}

async function askNewMaster() {
  const first = await askSecret('New master password: ');
  if (first.length < 8) {
    throw new VaultError('Master password must be at least 8 characters.', 'VALIDATION');
  }
  const second = await askSecret('Confirm master password: ');
  if (first !== second) {
    throw new VaultError('Master passwords do not match.', 'VALIDATION');
  }
  return first;
}

function shortId(id) {
  return id.slice(0, 8);
}

function printEntries(entries) {
  if (entries.length === 0) {
    console.log('No entries.');
    return;
  }
  const idWidth = Math.max(8, ...entries.map((entry) => shortId(entry.id).length));
  const serviceWidth = Math.max(7, ...entries.map((entry) => entry.service.length));
  const userWidth = Math.max(8, ...entries.map((entry) => entry.username.length));
  console.log(`${'ID'.padEnd(idWidth)}  ${'SERVICE'.padEnd(serviceWidth)}  ${'USERNAME'.padEnd(userWidth)}  NOTES`);
  console.log('-'.repeat(idWidth + serviceWidth + userWidth + 12));
  for (const entry of entries) {
    console.log(
      `${shortId(entry.id).padEnd(idWidth)}  ${entry.service.padEnd(serviceWidth)}  ${entry.username.padEnd(userWidth)}  ${entry.notes || '-'}`,
    );
  }
}

function passwordOption(options) {
  if (options.length === undefined) return undefined;
  const length = Number(options.length);
  if (!Number.isInteger(length) || length < 12 || length > 128) {
    throw new VaultError('--length must be an integer between 12 and 128.', 'VALIDATION');
  }
  return length;
}

async function main() {
  const argv = process.argv.slice(2);
  const [command, ...rest] = argv;
  if (!command || command === '--help' || command === '-h') {
    console.log(HELP);
    return;
  }

  const { positional, options } = parseArgs(rest);
  if (options.help) {
    console.log(HELP);
    return;
  }

  const vault = new Vault(options.vault ? resolve(options.vault) : defaultVaultPath());

  switch (command) {
    case 'init': {
      const master = await askNewMaster();
      await vault.init(master);
      console.log(`Vault created: ${vault.filePath}`);
      break;
    }
    case 'add': {
      const service = options.service ?? positional[0];
      const username = options.username ?? positional[1];
      if (!service || !username) {
        throw new VaultError('Usage: add --service S --username U [--password P]', 'USAGE');
      }
      const master = await askSecret('Master password: ');
      const generated = options.password === undefined;
      const entry = await vault.add(master, {
        service,
        username,
        password: generated ? generatePassword(passwordOption(options), { noSymbols: options['no-symbols'] }) : options.password,
        notes: options.notes,
      });
      console.log(`Added ${entry.service} (id: ${shortId(entry.id)})`);
      if (generated) console.log(`Generated password: ${entry.password}`);
      break;
    }
    case 'list': {
      const master = await askSecret('Master password: ');
      printEntries(await vault.list(master));
      break;
    }
    case 'search': {
      const query = options.query ?? positional[0];
      if (!query) throw new VaultError('Usage: search <text>', 'USAGE');
      const master = await askSecret('Master password: ');
      printEntries(await vault.search(master, query));
      break;
    }
    case 'get': {
      const id = options.id ?? positional[0];
      if (!id) throw new VaultError('Usage: get <id> [--show]', 'USAGE');
      const master = await askSecret('Master password: ');
      const entry = await vault.get(master, id);
      console.log(`ID:       ${entry.id}`);
      console.log(`Service:  ${entry.service}`);
      console.log(`Username: ${entry.username}`);
      console.log(`Password: ${options.show ? entry.password : '*'.repeat(Math.min(entry.password.length, 16))}`);
      console.log(`Notes:    ${entry.notes || '-'}`);
      break;
    }
    case 'delete': {
      const id = options.id ?? positional[0];
      if (!id) throw new VaultError('Usage: delete <id>', 'USAGE');
      const master = await askSecret('Master password: ');
      const entry = await vault.delete(master, id);
      console.log(`Deleted ${entry.service} (id: ${shortId(entry.id)})`);
      break;
    }
    case 'change-master': {
      const current = await askSecret('Current master password: ');
      const next = await askNewMaster();
      await vault.changeMaster(current, next);
      console.log('Master password changed. Vault re-encrypted.');
      break;
    }
    case 'generate': {
      console.log(generatePassword(passwordOption(options) ?? 20, { noSymbols: options['no-symbols'] }));
      break;
    }
    default:
      throw new VaultError(`Unknown command: ${command}. Run with --help.`, 'USAGE');
  }
}

main().catch((error) => {
  console.error(`Error: ${error.message}`);
  process.exitCode = 1;
});
