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

      // 1. REQUEST HTTP (Scanner / Web Browsing)
      if (dataStr.startsWith('GET ') || dataStr.startsWith('POST ') || dataStr.startsWith('HEAD ')) {
        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1].trim() : 'speed.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        // Resolve DNS resmi domain tersebut agar bebas Error 1034
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

      // 2. REQUEST HTTPS / HTTP CONNECT
      if (dataStr.startsWith('CONNECT ')) {
        const match = dataStr.match(/CONNECT\s+([^:\s]+):(\d+)/i);
        if (match) {
          const targetHost = match[1];
          const targetPort = parseInt(match[2], 10) || 443;

          dns.lookup(targetHost, (err, address) => {
            if (err) return clientSocket.destroy();

            targetSocket = net.connect(targetPort, address, () => {
              clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
              targetSocket.pipe(clientSocket);
              clientSocket.pipe(targetSocket);
            });

            targetSocket.on('error', () => clientSocket.destroy());
          });
          return;
        }
      }

      // 3. TRAFFIC STREAM VLESS / TROJAN (DARKTUNNEL)
      dns.lookup('speed.cloudflare.com', (err, address) => {
        const ipTarget = !err && address ? address : '104.16.123.96';

        targetSocket = net.connect(443, ipTarget, () => {
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
  console.log(`Dynamic DNS Proxy running on port ${PORT}`);
});
