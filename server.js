import net from 'net';
import dns from 'dns';

const PORT = process.env.PORT || 8080;

// 1. In-Memory Ultra-Fast DNS Cache
const dnsCache = new Map();

function fastResolve(hostname, callback) {
  const cached = dnsCache.get(hostname);
  const now = Date.now();

  if (cached && now - cached.timestamp < 1000 * 60 * 10) {
    return callback(null, cached.ip);
  }

  dns.lookup(hostname, (err, address) => {
    if (!err && address) {
      dnsCache.set(hostname, { ip: address, timestamp: now });
    }
    callback(err, address);
  });
}

// Pre-warm DNS cache untuk domain utama Cloudflare
fastResolve('speed.cloudflare.com', () => {});
fastResolve('cp.cloudflare.com', () => {});

const server = net.createServer({ noDelay: true }, (clientSocket) => {
  // Aktifkan TCP NoDelay & KeepAlive di sisi klien
  clientSocket.setNoDelay(true);
  clientSocket.setKeepAlive(true, 10000);

  let isFirstPacket = true;
  let targetSocket = null;

  clientSocket.on('data', (chunk) => {
    if (isFirstPacket) {
      isFirstPacket = false;
      const dataStr = chunk.toString('utf-8');

      // 1. SCANNER HTTP (Web Vercel / Bot)
      if (
        dataStr.startsWith('GET ') ||
        dataStr.startsWith('POST ') ||
        dataStr.startsWith('HEAD ')
      ) {
        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1].trim() : 'speed.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        fastResolve(targetHost, (err, address) => {
          if (err) return clientSocket.destroy();

          targetSocket = net.connect({ host: address, port: targetPort, noDelay: true }, () => {
            targetSocket.setNoDelay(true);
            targetSocket.setKeepAlive(true, 10000);
            targetSocket.write(chunk);
            targetSocket.pipe(clientSocket);
            clientSocket.pipe(targetSocket);
          });

          targetSocket.on('error', () => clientSocket.destroy());
        });
        return;
      }

      // 2. HTTPS CONNECT
      if (dataStr.startsWith('CONNECT ')) {
        const match = dataStr.match(/CONNECT\s+([^:\s]+):(\d+)/i);
        if (match) {
          const targetHost = match[1];
          const targetPort = parseInt(match[2], 10) || 443;

          fastResolve(targetHost, (err, address) => {
            if (err) return clientSocket.destroy();

            targetSocket = net.connect({ host: address, port: targetPort, noDelay: true }, () => {
              targetSocket.setNoDelay(true);
              targetSocket.setKeepAlive(true, 10000);
              clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
              targetSocket.pipe(clientSocket);
              clientSocket.pipe(targetSocket);
            });

            targetSocket.on('error', () => clientSocket.destroy());
          });
          return;
        }
      }

      // 3. STREAM TLS / VLESS / TROJAN (DarkTunnel)
      const sni = parseTlsSni(chunk);
      const destinationHost = sni || 'speed.cloudflare.com';
      const destinationPort = 443;

      fastResolve(destinationHost, (err, address) => {
        if (err) return clientSocket.destroy();

        targetSocket = net.connect({ host: address, port: destinationPort, noDelay: true }, () => {
          targetSocket.setNoDelay(true);
          targetSocket.setKeepAlive(true, 10000);
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

function parseTlsSni(buffer) {
  try {
    if (buffer[0] !== 0x16) return null;
    let pos = 43;
    if (pos >= buffer.length) return null;

    const sessionIdLen = buffer[pos];
    pos += 1 + sessionIdLen;

    const cipherSuitesLen = buffer.readUInt16BE(pos);
    pos += 2 + cipherSuitesLen;

    const compMethodsLen = buffer[pos];
    pos += 1 + compMethodsLen;

    if (pos >= buffer.length) return null;
    const extensionsLen = buffer.readUInt16BE(pos);
    pos += 2;

    const endExtensions = pos + extensionsLen;
    while (pos + 4 <= endExtensions && pos + 4 <= buffer.length) {
      const extType = buffer.readUInt16BE(pos);
      const extLen = buffer.readUInt16BE(pos + 2);
      pos += 4;

      if (extType === 0) {
        let sniPos = pos + 2;
        if (buffer[sniPos] === 0) {
          const nameLen = buffer.readUInt16BE(sniPos + 1);
          return buffer.toString('utf8', sniPos + 3, sniPos + 3 + nameLen);
        }
      }
      pos += extLen;
    }
  } catch (_) {
    return null;
  }
  return null;
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`High-Speed Boosted Proxy running on port ${PORT}`);
});
