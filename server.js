import net from 'net';

const PORT = process.env.PORT || 8080;

const server = net.createServer((clientSocket) => {
  let isFirstPacket = true;
  let targetSocket = null;

  clientSocket.on('data', (chunk) => {
    if (isFirstPacket) {
      isFirstPacket = false;
      const dataStr = chunk.toString('utf-8');

      // 1. JIKA REQUEST ADALAH HTTP CHECKER (Scanner Bot / Vercel Web)
      if (
        dataStr.startsWith('GET ') ||
        dataStr.startsWith('POST ') ||
        dataStr.startsWith('HEAD ')
      ) {
        // Ekstrak Host tujuan asli dari request header
        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1] : 'cp.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        // Resolve langsung ke domain host tujuannya (bukan ke 1.1.1.1 agar bebas error 1034)
        targetSocket = net.connect(targetPort, targetHost, () => {
          targetSocket.write(chunk);
          targetSocket.pipe(clientSocket);
          clientSocket.pipe(targetSocket);
        });

        targetSocket.on('error', () => clientSocket.destroy());
        return;
      }

      // 2. JIKA TRAFFIC ADALAH VLESS / TROJAN / DATA STREAM (DarkTunnel)
      // Sambungkan langsung ke Cloudflare Edge Gateway via domain resmi
      targetSocket = net.connect(80, 'cp.cloudflare.com', () => {
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
  console.log(`ProxyIP Server running on port ${PORT}`);
});
