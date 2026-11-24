import { randomInt, randomUUID } from 'node:crypto';

const SETS = Object.freeze({
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?',
});

function pick(pool) {
  return pool[randomInt(pool.length)];
}

function shuffle(chars) {
  for (let i = chars.length - 1; i > 0; i -= 1) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars;
}

export function generatePassword(length = 20, options = {}) {
  if (!Number.isInteger(length) || length < 12 || length > 128) {
    throw new RangeError('Password length must be an integer between 12 and 128.');
  }

  const disabled = { ...options };
  if (options.noSymbols) disabled.symbols = false;

  const enabled = Object.entries(SETS)
    .filter(([name]) => disabled[name] !== false)
    .map(([, chars]) => chars);

  if (enabled.length === 0) {
    throw new RangeError('At least one character set must be enabled.');
  }
  if (length < enabled.length) {
    throw new RangeError('Password length is too small for the selected character sets.');
  }

  const chars = enabled.map(pick);
  const pool = enabled.join('');
  while (chars.length < length) chars.push(pick(pool));

  return shuffle(chars).join('');
}

export function newEntryId() {
  return randomUUID();
}
