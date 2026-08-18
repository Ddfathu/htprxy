import net from 'net';
import dns from 'dns';

const PORT = process.env.PORT || 8080;

// State Konfigurasi DNS Aktif
let DNS_CONFIG = {
  mode: 'DOH',
  dohUrl: 'https://cloudflare-dns.com/dns-query',
  udpServer: '1.1.1.1',
  udpPort: 53
};

const PRESETS = {
  'cf-doh': { name: 'Cloudflare DoH', type: 'DOH', url: 'https://cloudflare-dns.com/dns-query' },
  'google-doh': { name: 'Google DoH', type: 'DOH', url: 'https://dns.google/dns-query' },
  'quad9-doh': { name: 'Quad9 DoH', type: 'DOH', url: 'https://dns.quad9.net/dns-query' },
  'adguard-doh': { name: 'AdGuard DoH', type: 'DOH', url: 'https://dns.adguard-dns.com/dns-query' },
  'cf-udp': { name: 'Cloudflare UDP (1.1.1.1)', type: 'UDP', host: '1.1.1.1', port: 53 },
  'google-udp': { name: 'Google UDP (8.8.8.8)', type: 'UDP', host: '8.8.8.8', port: 53 }
};

// Monitor Koneksi Aktif
const activeConnections = new Map();
let connectionIdCounter = 0;

// In-Memory Fast DNS Cache
const dnsCache = new Map();

async function resolveDomain(hostname) {
  const now = Date.now();
  const cached = dnsCache.get(hostname);
  if (cached && (now - cached.time < 1000 * 60 * 10)) {
    return cached.ip;
  }

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return hostname;
  }

  if (DNS_CONFIG.mode === 'DOH') {
    try {
      const url = new URL(DNS_CONFIG.dohUrl);
      url.searchParams.set('name', hostname);
      url.searchParams.set('type', 'A');

      const res = await fetch(url.toString(), {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(1800)
      });
      const data = await res.json();
      if (data.Answer && data.Answer.length > 0) {
        const aRecord = data.Answer.find(ans => ans.type === 1);
        if (aRecord && aRecord.data) {
          dnsCache.set(hostname, { ip: aRecord.data, time: now });
          return aRecord.data;
        }
      }
    } catch (_) {}
  }

  if (DNS_CONFIG.mode === 'UDP' && DNS_CONFIG.udpServer) {
    try {
      const resolver = new dns.Resolver();
      resolver.setServers([`${DNS_CONFIG.udpServer}:${DNS_CONFIG.udpPort || 53}`]);
      return await new Promise((resolve, reject) => {
        resolver.resolve4(hostname, (err, addresses) => {
          if (!err && addresses && addresses.length > 0) {
            dnsCache.set(hostname, { ip: addresses[0], time: now });
            resolve(addresses[0]);
          } else {
            reject(err);
          }
        });
      });
    } catch (_) {}
  }

  return new Promise((resolve) => {
    dns.lookup(hostname, (err, address) => {
      const ip = (!err && address) ? address : '104.16.123.96';
      dnsCache.set(hostname, { ip, time: now });
      resolve(ip);
    });
  });
}

// Server TCP Hybrid + Traffic Tracker
const server = net.createServer({ 
  noDelay: true,
  allowHalfOpen: false,
  pauseOnConnect: false
}, (clientSocket) => {
  clientSocket.setNoDelay(true);
  clientSocket.setKeepAlive(true, 5000);
  clientSocket.setMaxListeners(0);

  const connId = ++connectionIdCounter;
  const clientIp = clientSocket.remoteAddress || 'Unknown';
  const startTime = Date.now();

  const connData = {
    id: connId,
    clientIp,
    type: 'INITIALIZING',
    target: 'pending',
    startTime,
    bytesIn: 0,
    bytesOut: 0
  };

  let isFirstPacket = true;
  let targetSocket = null;

  const bridgeSockets = (sockA, sockB) => {
    sockA.on('data', (d) => { connData.bytesIn += d.length; });
    sockB.on('data', (d) => { connData.bytesOut += d.length; });

    sockA.pipe(sockB, { end: true });
    sockB.pipe(sockA, { end: true });

    const cleanup = () => {
      activeConnections.delete(connId);
      sockA.destroy();
      sockB.destroy();
    };

    sockA.on('error', cleanup);
    sockB.on('error', cleanup);
    sockA.on('close', cleanup);
    sockB.on('close', cleanup);
  };

  clientSocket.on('data', async (chunk) => {
    if (isFirstPacket) {
      isFirstPacket = false;
      const dataStr = chunk.toString('utf-8');

      // 1. CEK API MONITORING & DASHBOARD
      if (dataStr.startsWith('GET /') || dataStr.startsWith('POST /api/set-dns')) {
        const firstLine = dataStr.split('\r\n')[0];
        const path = firstLine.split(' ')[1] || '/';

        // Endpoint JSON Data Koneksi Aktif
        if (path === '/api/stats') {
          const activeList = Array.from(activeConnections.values()).map(c => ({
            id: c.id,
            clientIp: c.clientIp,
            type: c.type,
            target: c.target,
            uptime: Math.floor((Date.now() - c.startTime) / 1000),
            bytesIn: formatBytes(c.bytesIn),
            bytesOut: formatBytes(c.bytesOut)
          }));

          const resBody = JSON.stringify({
            totalActive: activeList.length,
            connections: activeList
          });

          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: ${Buffer.byteLength(resBody)}\r\nConnection: close\r\n\r\n${resBody}`);
          clientSocket.end();
          return;
        }

        // Endpoint Set DNS
        if (path.startsWith('/api/set-dns') && dataStr.startsWith('POST')) {
          try {
            const bodyStr = dataStr.split('\r\n\r\n')[1] || '{}';
            const body = JSON.parse(bodyStr);

            if (body.preset && PRESETS[body.preset]) {
              const p = PRESETS[body.preset];
              DNS_CONFIG.mode = p.type;
              if (p.type === 'DOH') DNS_CONFIG.dohUrl = p.url;
              else { DNS_CONFIG.udpServer = p.host; DNS_CONFIG.udpPort = p.port; }
            } else if (body.mode === 'DOH') {
              DNS_CONFIG.mode = 'DOH';
              DNS_CONFIG.dohUrl = body.dohUrl || 'https://cloudflare-dns.com/dns-query';
            } else if (body.mode === 'UDP') {
              DNS_CONFIG.mode = 'UDP';
              DNS_CONFIG.udpServer = body.udpServer || '1.1.1.1';
              DNS_CONFIG.udpPort = parseInt(body.udpPort, 10) || 53;
            }

            dnsCache.clear();
            const resBody = JSON.stringify({ success: true, config: DNS_CONFIG });
            clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${resBody.length}\r\nConnection: close\r\n\r\n${resBody}`);
          } catch (e) {
            const errBody = JSON.stringify({ success: false, error: e.message });
            clientSocket.write(`HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: ${errBody.length}\r\nConnection: close\r\n\r\n${errBody}`);
          }
          clientSocket.end();
          return;
        }

        // Tampilan Web UI
        if (path === '/' || path === '/index.html') {
          const html = renderDashboardHTML();
          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(html)}\r\nConnection: close\r\n\r\n${html}`);
          clientSocket.end();
          return;
        }

        // 2. SCANNER HTTP (speed.cloudflare.com / Bot)
        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1].trim() : 'speed.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        connData.type = 'HTTP SCANNER';
        connData.target = `${targetHost}:${targetPort}`;
        activeConnections.set(connId, connData);

        const resolvedIp = await resolveDomain(targetHost);
        targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
          targetSocket.setNoDelay(true);
          targetSocket.setKeepAlive(true, 5000);
          targetSocket.write(chunk);
          bridgeSockets(clientSocket, targetSocket);
        });

        targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
        return;
      }

      // 3. HTTPS CONNECT PROXY
      if (dataStr.startsWith('CONNECT ')) {
        const match = dataStr.match(/CONNECT\s+([^:\s]+):(\d+)/i);
        if (match) {
          const targetHost = match[1];
          const targetPort = parseInt(match[2], 10) || 443;

          connData.type = 'HTTPS TUNNEL';
          connData.target = `${targetHost}:${targetPort}`;
          activeConnections.set(connId, connData);

          const resolvedIp = await resolveDomain(targetHost);
          targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
            targetSocket.setNoDelay(true);
            targetSocket.setKeepAlive(true, 5000);
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            bridgeSockets(clientSocket, targetSocket);
          });

          targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
          return;
        }
      }

      // 4. TRAFIK VLESS / TROJAN STREAM (DARKTUNNEL)
      const sni = parseTlsSni(chunk);
      const destinationHost = sni || 'speed.cloudflare.com';

      connData.type = sni ? 'VLESS / TROJAN' : 'RAW TCP';
      connData.target = `${destinationHost}:443`;
      activeConnections.set(connId, connData);

      const resolvedIp = await resolveDomain(destinationHost);
      targetSocket = net.connect({ host: resolvedIp, port: 443, noDelay: true }, () => {
        targetSocket.setNoDelay(true);
        targetSocket.setKeepAlive(true, 5000);
        targetSocket.write(chunk);
        bridgeSockets(clientSocket, targetSocket);
      });

      targetSocket.on('error', () => { activeConnections.delete(connId); clientSocket.destroy(); });
    }
  });

  clientSocket.on('error', () => { activeConnections.delete(connId); if (targetSocket) targetSocket.destroy(); });
  clientSocket.on('close', () => { activeConnections.delete(connId); if (targetSocket) targetSocket.destroy(); });
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
  } catch (_) { return null; }
  return null;
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function renderDashboardHTML() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Proxy Monitor & DNS Control</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #06090e; color: #00ffcc; padding: 16px; margin: 0; display: flex; justify-content: center; }
    .card { background: #0d131f; border: 1px solid #00ffcc; box-shadow: 0 0 25px rgba(0,255,204,0.2); border-radius: 12px; max-width: 600px; width: 100%; padding: 20px; box-sizing: border-box; }
    h2 { margin-top: 0; color: #38bdf8; text-align: center; font-size: 1.25rem; }
    .badge-bar { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 16px; }
    .badge { flex: 1; background: #020408; border: 1px solid #38bdf8; border-radius: 8px; padding: 12px; text-align: center; }
    .badge h4 { margin: 0; font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; }
    .badge .val { font-size: 1.4rem; font-weight: bold; color: #39ff14; margin-top: 4px; }
    .section-title { font-size: 0.9rem; font-weight: bold; color: #38bdf8; margin-top: 18px; margin-bottom: 8px; border-bottom: 1px dashed #00ffcc; padding-bottom: 4px; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.75rem; font-family: monospace; }
    th, td { padding: 8px 6px; text-align: left; border-bottom: 1px solid #1e293b; word-break: break-all; }
    th { color: #38bdf8; background: #020408; }
    tr:hover { background: rgba(0, 255, 204, 0.05); }
    .tag { background: #032b17; color: #39ff14; padding: 2px 6px; border-radius: 4px; border: 1px solid #39ff14; font-size: 0.68rem; font-weight: bold; }
    select, input { width: 100%; padding: 10px; background: #020408; border: 1px solid #00ffcc; border-radius: 6px; color: #fff; margin-top: 6px; box-sizing: border-box; font-family: monospace; font-size: 0.82rem; }
    button { width: 100%; padding: 12px; background: #00ffcc; color: #000; font-weight: bold; border: none; border-radius: 6px; margin-top: 14px; cursor: pointer; }
    button:hover { background: #38bdf8; }
    .toast { display: none; padding: 8px; text-align: center; border-radius: 6px; margin-top: 10px; font-size: 0.8rem; font-weight: bold; }
    .toast.success { display: block; background: #052e16; color: #4ade80; border: 1px solid #4ade80; }
  </style>
</head>
<body>
  <div class="card">
    <h2>⚡ PROXY MONITOR & DNS PANEL</h2>
    
    <div class="badge-bar">
      <div class="badge">
        <h4>User / IP Konek</h4>
        <div class="val" id="active_count">0</div>
      </div>
      <div class="badge">
        <h4>Status DNS</h4>
        <div class="val" style="font-size:1rem; color:#38bdf8; line-height:2rem;" id="badge_dns">${DNS_CONFIG.mode}</div>
      </div>
    </div>

    <div class="section-title">🔴 DAFTAR KONEKSI AKTIF (LIVE REAL-TIME)</div>
    <div style="overflow-x: auto; max-height: 220px; overflow-y: auto;">
      <table>
        <thead>
          <tr>
            <th>IP Client</th>
            <th>Type</th>
            <th>Target Host</th>
            <th>Durasi</th>
            <th>Data (In/Out)</th>
          </tr>
        </thead>
        <tbody id="conn_table_body">
          <tr><td colspan="5" style="text-align:center; color:#64748b;">Belum ada perangkat terhubung...</td></tr>
        </tbody>
      </table>
    </div>

    <div class="section-title" style="margin-top:22px;">⚙️ PENGATURAN DNS RESOLVER</div>
    <select id="preset_select" onchange="applyPreset()">
      <option value="cf-doh" ${DNS_CONFIG.dohUrl.includes('cloudflare') ? 'selected' : ''}>Cloudflare DoH (Official)</option>
      <option value="google-doh" ${DNS_CONFIG.dohUrl.includes('google') ? 'selected' : ''}>Google DoH</option>
      <option value="quad9-doh" ${DNS_CONFIG.dohUrl.includes('quad9') ? 'selected' : ''}>Quad9 DoH (Security)</option>
      <option value="adguard-doh" ${DNS_CONFIG.dohUrl.includes('adguard') ? 'selected' : ''}>AdGuard DoH (Adblock)</option>
      <option value="cf-udp">Cloudflare UDP (1.1.1.1:53)</option>
      <option value="google-udp">Google UDP (8.8.8.8:53)</option>
      <option value="custom_doh">✏️ Custom DoH Pribadi (URL)</option>
      <option value="custom_udp">✏️ Custom DNS UDP Pribadi (IP + Port)</option>
    </select>

    <div id="box_custom_doh" style="display:none; margin-top:8px;">
      <input type="text" id="custom_doh_url" placeholder="https://dns.nextdns.io/xxxxxx" value="${DNS_CONFIG.dohUrl}">
    </div>

    <div id="box_custom_udp" style="display:none; margin-top:8px;">
      <input type="text" id="custom_udp_ip" placeholder="IP: 94.140.14.14" value="${DNS_CONFIG.udpServer}">
      <input type="number" id="custom_udp_port" placeholder="Port: 53" value="${DNS_CONFIG.udpPort || 53}">
    </div>

    <button onclick="saveDns()">💾 SIMPAN DNS</button>
    <div id="toast" class="toast"></div>
  </div>

  <script>
    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        document.getElementById('active_count').innerText = data.totalActive;

        const tbody = document.getElementById('conn_table_body');
        if (!data.connections || data.connections.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:#64748b;">Belum ada perangkat terhubung...</td></tr>';
          return;
        }

        tbody.innerHTML = data.connections.map(c => \`
          <tr>
            <td>\${c.clientIp.replace('::ffff:', '')}</td>
            <td><span class="tag">\${c.type}</span></td>
            <td>\${c.target}</td>
            <td>\${c.uptime}s</td>
            <td>\${c.bytesIn} / \${c.bytesOut}</td>
          </tr>
        \`).join('');
      } catch (e) {}
    }

    // Auto-Refresh Real-Time setiap 2 detik
    setInterval(fetchStats, 2000);
    fetchStats();

    function applyPreset() {
      const val = document.getElementById('preset_select').value;
      document.getElementById('box_custom_doh').style.display = (val === 'custom_doh') ? 'block' : 'none';
      document.getElementById('box_custom_udp').style.display = (val === 'custom_udp') ? 'block' : 'none';
    }

    async function saveDns() {
      const selected = document.getElementById('preset_select').value;
      let payload = {};

      if (selected === 'custom_doh') {
        payload = { mode: 'DOH', dohUrl: document.getElementById('custom_doh_url').value.trim() };
      } else if (selected === 'custom_udp') {
        payload = {
          mode: 'UDP',
          udpServer: document.getElementById('custom_udp_ip').value.trim(),
          udpPort: document.getElementById('custom_udp_port').value.trim()
        };
      } else {
        payload = { preset: selected };
      }

      const res = await fetch('/api/set-dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.success) {
        document.getElementById('badge_dns').innerText = data.config.mode;
        const toast = document.getElementById('toast');
        toast.innerText = '✅ DNS Berhasil Diterapkan!';
        toast.className = 'toast success';
        setTimeout(() => toast.style.display = 'none', 3000);
      }
    }
  </script>
</body>
</html>`;
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Live Traffic Monitor Proxy running on port ${PORT}`);
});
