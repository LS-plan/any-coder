import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

function createHash(password) {
  const salt = randomBytes(16).toString('hex');
  const derived = scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verify(password, stored) {
  const [salt, expected] = String(stored).split(':');
  if (!salt || !expected) return false;
  const derived = scryptSync(password, salt, 64);
  const expectedBuf = Buffer.from(expected, 'hex');
  if (derived.length !== expectedBuf.length) return false;
  return timingSafeEqual(derived, expectedBuf);
}

const password = process.argv[2];
if (!password) {
  console.error('Usage: npm run hash-password -- <plain-password>');
  process.exit(1);
}

const hashed = createHash(password);
console.log('APP_PASSWORD_HASH=' + hashed);
console.log('Self-check=' + verify(password, hashed));
