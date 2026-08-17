import net from 'net';
import http from 'http';

const PORT = process.env.PORT || 8080;

// Buat Server TCP Murni di Layer 4 (Mendukung VLESS, Trojan, HTTPS & HTTP)
const server = net.createServer((clientSocket) => {
  let isFirstPacket = true;
  let targetSocket = null;

  clientSocket.on('data', (chunk) => {
    if (isFirstPacket) {
      isFirstPacket = false;
      const dataStr = chunk.toString('utf-8');

      // 1. JIKA REQUEST ADALAH HTTP CHECKER (Untuk Bot / Web Scanner)
      if (dataStr.startsWith('GET ') || dataStr.startsWith('POST ') || dataStr.startsWith('HEAD ')) {
        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1] : 'speed.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        targetSocket = net.connect(targetPort, targetHost, () => {
          targetSocket.write(chunk);
          targetSocket.pipe(clientSocket);
          clientSocket.pipe(targetSocket);
        });

        targetSocket.on('error', () => clientSocket.destroy());
        return;
      }

      // 2. JIKA TRAFFIC ADALAH VLESS / TROJAN / ENCRYPTED STREAM (DarkTunnel)
      // Teruskan langsung ke Cloudflare Edge Port 443 / Target Outbound
      targetSocket = net.connect(443, '1.1.1.1', () => {
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
  console.log(`Cloudflare VLESS ProxyIP Engine running on port ${PORT}`);
});
