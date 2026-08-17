import net from 'net';
import dns from 'dns';

const PORT = process.env.PORT || 8080;

const server = net.createServer((clientSocket) => {
  let isFirstPacket = true;
  let targetSocket = null;

  clientSocket.on('data', (chunk) => {
    if (isFirstPacket) {
      isFirstPacket = false;

      // Cek apakah request berupa teks HTTP Plain
      const dataStr = chunk.toString('utf-8');

      // 1. REQUEST HTTP BIASA (Scanner / Bot Vercel)
      if (
        dataStr.startsWith('GET ') ||
        dataStr.startsWith('POST ') ||
        dataStr.startsWith('HEAD ')
      ) {
        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1].trim() : 'speed.cloudflare.com';
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

      // 2. REQUEST HTTPS CONNECT
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

      // 3. STREAM TLS / VLESS / TROJAN (DARKTUNNEL)
      // Ekstrak SNI (Server Name Indication) dari paket TLS Client Hello
      const sni = parseTlsSni(chunk);
      const destinationHost = sni || 'speed.cloudflare.com';
      const destinationPort = 443;

      dns.lookup(destinationHost, (err, address) => {
        if (err) return clientSocket.destroy();

        targetSocket = net.connect(destinationPort, address, () => {
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

// Helper parser SNI domain dari Client Hello TLS
function parseTlsSni(buffer) {
  try {
    if (buffer[0] !== 0x16) return null; // Bukan Handshake TLS
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

      if (extType === 0) { // SNI Extension
        const sniListLen = buffer.readUInt16BE(pos);
        let sniPos = pos + 2;
        if (buffer[sniPos] === 0) { // Host Name type
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
  console.log(`Smart SNI Proxy running on port ${PORT}`);
});
