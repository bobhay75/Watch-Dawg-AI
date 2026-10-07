import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const files = new Map([
  ['/', ['field-security-demo.html', 'text/html; charset=utf-8']],
  ['/field-security-demo.html', ['field-security-demo.html', 'text/html; charset=utf-8']],
  ...['field-security.js', 'field-security-app.js', 'field-security-store.js', 'field-security-export.js', 'field-security-files.js'].map((name) => [`/${name}`, [name, 'text/javascript; charset=utf-8']]),
  ['/field-security.css', ['field-security.css', 'text/css; charset=utf-8']],
]);
export function createPreviewServer() {
  return http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    let path;
    try { path = new URL(req.url, 'http://localhost').pathname; } catch { res.writeHead(400); res.end(); return; }
    const entry = files.get(path);
    if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405, { Allow: 'GET, HEAD' }); res.end('Method not allowed'); return; }
    if (!entry) { res.writeHead(404, { 'Content-Type': 'text/plain', 'X-Robots-Tag': 'noindex, nofollow' }); res.end('Not found'); return; }
    try {
      const body = await readFile(new URL(`../${entry[0]}`, import.meta.url));
      res.writeHead(200, { 'Content-Type': entry[1] }); res.end(req.method === 'HEAD' ? undefined : body);
    } catch { res.writeHead(500); res.end('Preview file unavailable'); }
  });
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const server = createPreviewServer();
  server.listen(Number(process.env.PORT || 4173), '127.0.0.1', () => console.log(`Watch-Dawg field desk: http://127.0.0.1:${server.address().port}`));
}
