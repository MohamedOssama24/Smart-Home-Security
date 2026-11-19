// Static server for the E2E tests: serves the production build with the SPA fallback.
// The API is never proxied: every /api call is answered by the [MOCK] routes of the tests.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';

const root = join(import.meta.dirname, '..', 'dist', 'angular-dashboard', 'browser');
const port = Number(process.env.E2E_PORT ?? 4300);
const types = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.png': 'image/png', '.woff2': 'font/woff2',
};

createServer(async (req, res) => {
  const path = normalize(decodeURIComponent(new URL(req.url, 'http://localhost').pathname)).replace(/^([/\\])+/, '');
  if (path.startsWith('..') || path.startsWith('api')) {
    res.writeHead(404).end();
    return;
  }
  try {
    const file = path || 'index.html';
    const body = await readFile(join(root, file));
    res.writeHead(200, { 'content-type': types[extname(file)] ?? 'application/octet-stream' }).end(body);
  } catch {
    res.writeHead(200, { 'content-type': types['.html'] }).end(await readFile(join(root, 'index.html')));
  }
}).listen(port, '127.0.0.1', () => console.log(`E2E server on http://127.0.0.1:${port}`));
