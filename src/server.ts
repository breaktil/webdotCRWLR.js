import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { runScan } from './scanner.js';
import { isPathInside, requestPathname, resolvePublicDir } from './paths.js';
import type { ScanRequest, ScanResponse, StreamLine } from './types.js';

const PUBLIC_DIR = resolvePublicDir();
const PORT = Number(process.env.PORT) || 3847;

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function sendJson(res: http.ServerResponse, status: number, data: unknown): void {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function parseBody(req: http.IncomingMessage): Promise<ScanRequest> {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk: Buffer) => {
      raw += chunk.toString();
      if (raw.length > 1e6) {
        req.destroy();
        reject(new Error('Body too large'));
      }
    });
    req.on('end', () => {
      if (!raw) {
        resolve({ url: '' });
        return;
      }
      try {
        resolve(JSON.parse(raw) as ScanRequest);
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

async function serveStatic(pathname: string, res: http.ServerResponse): Promise<void> {
  let rel = pathname === '/' ? '/index.html' : pathname;
  if (rel.includes('..')) {
    sendJson(res, 400, { error: 'Invalid path' });
    return;
  }

  const filePath = path.normalize(path.join(PUBLIC_DIR, rel.replace(/^\//, '')));
  if (!isPathInside(filePath, PUBLIC_DIR)) {
    sendJson(res, 403, { error: 'Forbidden' });
    return;
  }

  try {
    const data = await fs.readFile(filePath);
    const ext = path.extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] ?? 'application/octet-stream' });
    res.end(data);
  } catch {
    if (pathname === '/favicon.ico') {
      res.writeHead(204);
      res.end();
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(
      `<!DOCTYPE html><html><body style="font-family:monospace;background:#0a0a0a;color:#0f0;padding:2rem">
        <h1>404 — Not found</h1>
        <p>Missing: <code>${rel}</code></p>
        <p>Public root: <code>${PUBLIC_DIR}</code></p>
        <p><a href="/" style="color:#0ff">Back to scanner</a></p>
      </body></html>`,
    );
  }
}

async function handleScan(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const body = await parseBody(req);
  const url = typeof body.url === 'string' ? body.url.trim() : '';
  if (!url) {
    sendJson(res, 400, { error: 'Missing "url" in request body' });
    return;
  }

  const accept = req.headers.accept ?? '';
  const streamProgress = accept.includes('application/x-ndjson');

  if (streamProgress) {
    res.writeHead(200, {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    });
    const write = (obj: StreamLine) => res.write(`${JSON.stringify(obj)}\n`);
    try {
      const report = await runScan(url, (p) => write({ type: 'progress', message: p.message }));
      write({ type: 'complete', report });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      write({ type: 'error', message });
    }
    res.end();
    return;
  }

  const progress: ScanResponse['progress'] = [];
  const report = await runScan(url, (p) => progress.push(p));
  sendJson(res, 200, { report, progress } satisfies ScanResponse);
}

const server = http.createServer(async (req, res) => {
  const pathname = requestPathname(req.url);

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    if (req.method === 'POST' && pathname === '/api/scan') {
      await handleScan(req, res);
      return;
    }

    if (req.method === 'GET') {
      await serveStatic(pathname, res);
      return;
    }

    sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    sendJson(res, 500, { error: message });
  }
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('WP Security Scanner (TypeScript)');
  console.log(`  UI:     http://127.0.0.1:${PORT}/`);
  console.log(`  public: ${PUBLIC_DIR}`);
});
