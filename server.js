import net from 'net';
import dns from 'dns';

const PORT = process.env.PORT || 8080;

// Cache IP Cloudflare di awal agar koneksi instan
let cachedCfIp = '104.16.123.96';
function refreshDnsCache() {
  dns.lookup('speed.cloudflare.com', (err, addr) => {
    if (!err && addr) cachedCfIp = addr;
  });
}
refreshDnsCache();
setInterval(refreshDnsCache, 1000 * 60 * 10); // Refresh tiap 10 menit

const server = net.createServer((clientSocket) => {
  let isFirstPacket = true;
  let targetSocket = null;

  clientSocket.on('data', (chunk) => {
    if (isFirstPacket) {
      isFirstPacket = false;
      const dataStr = chunk.toString('utf-8');

      // 1. Scanner HTTP (Bot / Web Vercel)
      if (dataStr.startsWith('GET ') || dataStr.startsWith('POST ') || dataStr.startsWith('HEAD ')) {
        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1] : cachedCfIp;
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        targetSocket = net.connect(targetPort, targetHost === 'speed.cloudflare.com' ? cachedCfIp : targetHost, () => {
          targetSocket.write(chunk);
          targetSocket.pipe(clientSocket);
          clientSocket.pipe(targetSocket);
        });

        targetSocket.on('error', () => clientSocket.destroy());
        return;
      }

      // 2. Traffic VLESS / Trojan DarkTunnel (Pakai Cached IP Instan)
      targetSocket = net.connect(443, cachedCfIp, () => {
        targetSocket.write(chunk);
        targetSocket.pipe(clientSocket);
        clientSocket.pipe(targetSocket);
      });

      targetSocket.on('error', () => clientSocket.destroy());
    }
  });

  clientSocket.on('error', () => {
    if (targetSocket) targetSocket.destroy();
  });

  clientSocket.on('close', () => {
    if (targetSocket) targetSocket.destroy();
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Optimized ProxyIP running on port ${PORT}`);
});
