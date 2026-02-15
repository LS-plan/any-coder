import { createServer } from 'node:http';
import { randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';

const execFileAsync = promisify(execFile);

const HOST = process.env.HOST ?? '0.0.0.0';
const PORT = Number(process.env.PORT ?? 8080);
const WORKSPACE_ROOT = path.resolve(process.env.WORKSPACE_ROOT ?? process.cwd());
const SESSION_FILE = path.resolve(process.env.SESSION_FILE ?? 'apps/server/data/sessions.json');
const APP_PASSWORD_HASH = process.env.APP_PASSWORD_HASH;
const ACCESS_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_BODY = 1024 * 1024;
const DEFAULT_SHELL = process.env.DEFAULT_SHELL ?? (process.platform === 'win32' ? 'powershell.exe' : 'bash');

if (!APP_PASSWORD_HASH) {
  console.error('[fatal] APP_PASSWORD_HASH is required. Generate via: npm run hash-password -- <password>');
  process.exit(1);
}

const lockMap = new Map();
const terminals = new Map();

async function ensureSessionStore() {
  await fs.mkdir(path.dirname(SESSION_FILE), { recursive: true });
  try {
    await fs.access(SESSION_FILE);
  } catch {
    await fs.writeFile(SESSION_FILE, JSON.stringify({ sessions: [] }, null, 2), 'utf8');
  }
}

async function readSessions() {
  await ensureSessionStore();
  const raw = await fs.readFile(SESSION_FILE, 'utf8');
  return JSON.parse(raw);
}

async function writeSessions(data) {
  await fs.writeFile(SESSION_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function createPasswordHash(password, salt) {
  return scryptSync(password, salt, 64);
}

function verifyPassword(password, stored) {
  const [salt, expectedHex] = String(stored).split(':');
  if (!salt || !expectedHex) return false;
  const expected = Buffer.from(expectedHex, 'hex');
  const derived = createPasswordHash(password, salt);
  if (expected.length !== derived.length) return false;
  return timingSafeEqual(expected, derived);
}

function now() {
  return Date.now();
}

function getClientKey(req) {
  return req.socket.remoteAddress ?? 'unknown';
}

function checkLocked(clientKey) {
  const state = lockMap.get(clientKey);
  if (!state) return { locked: false };
  if (state.lockUntil && state.lockUntil > now()) {
    return { locked: true, lockUntil: state.lockUntil };
  }
  return { locked: false };
}

function recordFailure(clientKey) {
  const state = lockMap.get(clientKey) ?? { failed: 0, lockUntil: 0 };
  state.failed += 1;

  if (state.failed >= 10) {
    state.lockUntil = now() + 30 * 60 * 1000;
  } else if (state.failed >= 5) {
    state.lockUntil = now() + 5 * 60 * 1000;
  }

  lockMap.set(clientKey, state);
  return state;
}

function resetFailure(clientKey) {
  lockMap.set(clientKey, { failed: 0, lockUntil: 0 });
}

function sendJson(res, code, payload) {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

async function readBody(req) {
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY) {
      throw new Error('Body too large');
    }
    chunks.push(chunk);
  }
  if (!chunks.length) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    const err = new Error('Invalid JSON body');
    err.statusCode = 400;
    throw err;
  }
}

function safeResolve(requestedPath = '.') {
  const full = path.resolve(WORKSPACE_ROOT, requestedPath);
  const normalizedRoot = WORKSPACE_ROOT.endsWith(path.sep) ? WORKSPACE_ROOT : WORKSPACE_ROOT + path.sep;
  if (full !== WORKSPACE_ROOT && !full.startsWith(normalizedRoot)) {
    const err = new Error('Path escapes workspace root');
    err.statusCode = 400;
    throw err;
  }
  return full;
}

function getBearer(req) {
  const auth = req.headers.authorization ?? '';
  if (!auth.startsWith('Bearer ')) return null;
  return auth.slice('Bearer '.length).trim();
}

async function requireSession(req) {
  const token = getBearer(req);
  if (!token) return null;

  const store = await readSessions();
  const active = store.sessions.find((x) => x.token === token && x.expiresAt > now());
  if (!active) return null;
  return active;
}

async function listTree(relativePath) {
  const full = safeResolve(relativePath);
  const entries = await fs.readdir(full, { withFileTypes: true });
  return entries
    .map((entry) => ({
      name: entry.name,
      type: entry.isDirectory() ? 'dir' : 'file'
    }))
    .sort((a, b) => a.type.localeCompare(b.type) || a.name.localeCompare(b.name));
}

function getQueryUrl(req) {
  return new URL(req.url, `http://${req.headers.host || 'localhost'}`);
}

function createTerminal({ shell = DEFAULT_SHELL, cwd = '.' } = {}) {
  const fullCwd = safeResolve(cwd);
  const child = spawn(shell, [], { cwd: fullCwd, env: process.env, stdio: 'pipe' });
  const id = randomBytes(8).toString('hex');
  const term = {
    id,
    shell,
    cwd,
    process: child,
    output: '',
    createdAt: now(),
    closedAt: null,
    exitCode: null
  };

  child.stdout.on('data', (chunk) => {
    term.output += chunk.toString('utf8');
    if (term.output.length > 1_000_000) {
      term.output = term.output.slice(-1_000_000);
    }
  });
  child.stderr.on('data', (chunk) => {
    term.output += chunk.toString('utf8');
    if (term.output.length > 1_000_000) {
      term.output = term.output.slice(-1_000_000);
    }
  });
  child.on('close', (code) => {
    term.exitCode = code;
    term.closedAt = now();
  });

  terminals.set(id, term);
  return { id, shell, cwd, createdAt: term.createdAt };
}

function getTerminal(id) {
  return terminals.get(id) ?? null;
}

function runGit(args) {
  return execFileAsync('git', args, { cwd: WORKSPACE_ROOT, maxBuffer: 5 * 1024 * 1024 });
}

const server = createServer(async (req, res) => {
  try {
    const url = getQueryUrl(req);

    if (req.method === 'GET' && url.pathname === '/health') {
      return sendJson(res, 200, {
        ok: true,
        mode: 'single-host',
        workspaceRoot: WORKSPACE_ROOT,
        auth: 'global-password-gate'
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/login') {
      const clientKey = getClientKey(req);
      const lock = checkLocked(clientKey);
      if (lock.locked) {
        return sendJson(res, 429, {
          error: 'Too many failed attempts. Try again later.',
          lockUntil: new Date(lock.lockUntil).toISOString()
        });
      }

      const body = await readBody(req);
      const ok = verifyPassword(String(body.password ?? ''), APP_PASSWORD_HASH);
      if (!ok) {
        const state = recordFailure(clientKey);
        return sendJson(res, 401, {
          error: 'Invalid password',
          failedAttempts: state.failed,
          lockUntil: state.lockUntil ? new Date(state.lockUntil).toISOString() : null
        });
      }

      resetFailure(clientKey);
      const token = randomBytes(32).toString('hex');
      const expiresAt = now() + ACCESS_TTL_MS;
      const store = await readSessions();
      store.sessions = store.sessions.filter((x) => x.expiresAt > now());
      store.sessions.push({ token, createdAt: now(), expiresAt, client: clientKey });
      await writeSessions(store);
      return sendJson(res, 200, { token, expiresAt });
    }

    if (req.method === 'GET' && url.pathname === '/api/auth/session') {
      const session = await requireSession(req);
      if (!session) return sendJson(res, 401, { error: 'Unauthorized' });
      return sendJson(res, 200, {
        ok: true,
        expiresAt: session.expiresAt,
        client: session.client
      });
    }

    const session = await requireSession(req);
    if (!session) {
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    if (req.method === 'GET' && url.pathname === '/api/workspace/tree') {
      const rel = url.searchParams.get('path') ?? '.';
      const entries = await listTree(rel);
      return sendJson(res, 200, { path: rel, entries });
    }

    if (req.method === 'GET' && url.pathname === '/api/workspace/file') {
      const rel = url.searchParams.get('path');
      if (!rel) return sendJson(res, 400, { error: 'path is required' });
      const full = safeResolve(rel);
      const content = await fs.readFile(full, 'utf8');
      return sendJson(res, 200, { path: rel, content });
    }

    if (req.method === 'PUT' && url.pathname === '/api/workspace/file') {
      const rel = url.searchParams.get('path');
      if (!rel) return sendJson(res, 400, { error: 'path is required' });
      const body = await readBody(req);
      const full = safeResolve(rel);
      await fs.mkdir(path.dirname(full), { recursive: true });
      await fs.writeFile(full, String(body.content ?? ''), 'utf8');
      return sendJson(res, 200, { ok: true, path: rel });
    }

    if (req.method === 'POST' && url.pathname === '/api/workspace/mkdir') {
      const rel = url.searchParams.get('path');
      if (!rel) return sendJson(res, 400, { error: 'path is required' });
      const full = safeResolve(rel);
      await fs.mkdir(full, { recursive: true });
      return sendJson(res, 200, { ok: true, path: rel });
    }

    if (req.method === 'POST' && url.pathname === '/api/workspace/move') {
      const body = await readBody(req);
      const from = String(body.from ?? '');
      const to = String(body.to ?? '');
      if (!from || !to) return sendJson(res, 400, { error: 'from/to are required' });
      const fromFull = safeResolve(from);
      const toFull = safeResolve(to);
      await fs.mkdir(path.dirname(toFull), { recursive: true });
      await fs.rename(fromFull, toFull);
      return sendJson(res, 200, { ok: true, from, to });
    }

    if (req.method === 'DELETE' && url.pathname === '/api/workspace/node') {
      const rel = url.searchParams.get('path');
      if (!rel) return sendJson(res, 400, { error: 'path is required' });
      const full = safeResolve(rel);
      await fs.rm(full, { recursive: true, force: true });
      return sendJson(res, 200, { ok: true, path: rel });
    }

    if (req.method === 'GET' && url.pathname === '/api/git/status') {
      const { stdout } = await runGit(['status', '--short', '--branch']);
      return sendJson(res, 200, { output: stdout });
    }

    if (req.method === 'GET' && url.pathname === '/api/git/diff') {
      const rel = url.searchParams.get('path');
      const args = rel ? ['diff', '--', rel] : ['diff'];
      const { stdout } = await runGit(args);
      return sendJson(res, 200, { output: stdout });
    }

    if (req.method === 'POST' && url.pathname === '/api/terminal/create') {
      const body = await readBody(req);
      const terminal = createTerminal({ shell: body.shell, cwd: body.cwd });
      return sendJson(res, 200, terminal);
    }

    if (req.method === 'POST' && /^\/api\/terminal\/[^/]+\/input$/.test(url.pathname)) {
      const id = url.pathname.split('/')[3];
      const term = getTerminal(id);
      if (!term) return sendJson(res, 404, { error: 'terminal not found' });
      const body = await readBody(req);
      const input = String(body.input ?? '');
      term.process.stdin.write(input);
      return sendJson(res, 200, { ok: true, id, bytes: Buffer.byteLength(input) });
    }

    if (req.method === 'GET' && /^\/api\/terminal\/[^/]+\/output$/.test(url.pathname)) {
      const id = url.pathname.split('/')[3];
      const term = getTerminal(id);
      if (!term) return sendJson(res, 404, { error: 'terminal not found' });
      const from = Number(url.searchParams.get('from') ?? 0);
      return sendJson(res, 200, {
        id,
        from,
        to: term.output.length,
        chunk: term.output.slice(from),
        closedAt: term.closedAt,
        exitCode: term.exitCode
      });
    }

    if (req.method === 'POST' && /^\/api\/terminal\/[^/]+\/close$/.test(url.pathname)) {
      const id = url.pathname.split('/')[3];
      const term = getTerminal(id);
      if (!term) return sendJson(res, 404, { error: 'terminal not found' });
      term.process.kill();
      return sendJson(res, 200, { ok: true, id });
    }

    return sendJson(res, 404, { error: 'Not found' });
  } catch (error) {
    if (error?.statusCode === 400) {
      return sendJson(res, 400, {
        error: 'Bad request',
        message: error?.message ?? 'Invalid request'
      });
    }
    return sendJson(res, 500, {
      error: 'Internal server error',
      message: error?.message ?? String(error)
    });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[server] listening on http://${HOST}:${PORT}`);
  console.log(`[server] workspace root: ${WORKSPACE_ROOT}`);
  console.log(`[server] default shell: ${DEFAULT_SHELL}`);
});
