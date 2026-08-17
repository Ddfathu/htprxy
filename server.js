import net from 'net';
import dns from 'dns';

const PORT = process.env.PORT || 8080;

const server = net.createServer((clientSocket) => {
  let isFirstPacket = true;
  let targetSocket = null;

  clientSocket.on('data', (chunk) => {
    if (isFirstPacket) {
      isFirstPacket = false;
      const dataStr = chunk.toString('utf-8');

      // 1. JIKA REQUEST ADALAH SCANNER (HTTP GET/POST)
      if (dataStr.startsWith('GET ') || dataStr.startsWith('POST ') || dataStr.startsWith('HEAD ')) {
        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1] : 'speed.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        dns.lookup(targetHost, (err, address) => {
          if (err) return clientSocket.destroy();

          targetSocket = net.connect(targetPort, address, () => {
            targetSocket.write(chunk);
            targetSocket.pipe(clientSocket);
            clientSocket.pipe(targetSocket);
          });

          targetSocket.on('error', () => clientSocket.destroy());
        });
        return;
      }

      // 2. JIKA LALU LINTAS VLESS / TROJAN (DARKTUNNEL)
      // Resolve DNS dynamic Cloudflare Edge Anycast
      dns.lookup('speed.cloudflare.com', (err, address) => {
        if (err) address = '104.16.123.96'; // Fallback Cloudflare IP

        targetSocket = net.connect(443, address, () => {
          targetSocket.write(chunk);
          targetSocket.pipe(clientSocket);
          clientSocket.pipe(targetSocket);
        });

        targetSocket.on('error', () => clientSocket.destroy());
      });
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
  console.log(`Dynamic DNS ProxyIP running on port ${PORT}`);
});
