import http from 'http';

const PORT = process.env.PORT || 8080;

const server = http.createServer((req, res) => {
  // Ambil host tujuan dari header (default ke speed.cloudflare.com)
  const targetHost = req.headers['host'] || 'speed.cloudflare.com';

  // Siapkan header forwarding untuk Cloudflare
  const headers = { ...req.headers };
  headers['host'] = targetHost;
  delete headers['connection'];

  const options = {
    hostname: targetHost,
    port: 80,
    path: req.url || '/',
    method: req.method,
    headers: headers,
    timeout: 5000
  };

  // Kirim HTTP request ke server Cloudflare
  const proxyReq = http.request(options, (proxyRes) => {
    // Teruskan semua header asli dari Cloudflare (cf-ray, cf-ipcountry, dll)
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end(`Bad Gateway: ${err.message}`);
  });

  proxyReq.on('timeout', () => {
    proxyReq.destroy();
    res.writeHead(504, { 'Content-Type': 'text/plain' });
    res.end('Gateway Timeout');
  });

  req.pipe(proxyReq);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Pure HTTP Proxy running on port ${PORT}`);
});
