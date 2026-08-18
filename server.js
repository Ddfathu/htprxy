import net from 'net';
import dns from 'dns';

const PORT = process.env.PORT || 8080;

const TCP_DOMAIN = process.env.RAILWAY_TCP_PROXY_DOMAIN || '';
const TCP_PORT = process.env.RAILWAY_TCP_PROXY_PORT || '';

let PROXY_SERVER_INFO = {
  domain: TCP_DOMAIN,
  port: TCP_PORT,
  ip: '',
  fullProxy: ''
};

function updateRailwayProxyIP() {
  if (TCP_DOMAIN) {
    dns.lookup(TCP_DOMAIN, (err, address) => {
      if (!err && address) {
        PROXY_SERVER_INFO.ip = address;
        PROXY_SERVER_INFO.fullProxy = `${address}:${TCP_PORT}`;
      } else {
        PROXY_SERVER_INFO.ip = TCP_DOMAIN;
        PROXY_SERVER_INFO.fullProxy = `${TCP_DOMAIN}:${TCP_PORT}`;
      }
    });
  } else {
    PROXY_SERVER_INFO.fullProxy = 'TCP Proxy Not Set';
  }
}
updateRailwayProxyIP();
setInterval(updateRailwayProxyIP, 1000 * 60 * 30);

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

const activeConnections = new Map();
let connectionIdCounter = 0;
let globalTotalBytesIn = 0;
let globalTotalBytesOut = 0;

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

const server = net.createServer({ 
  noDelay: true,
  allowHalfOpen: false,
  pauseOnConnect: false
}, (clientSocket) => {
  clientSocket.setNoDelay(true);
  clientSocket.setKeepAlive(true, 5000);
  clientSocket.setMaxListeners(0);

  const connId = ++connectionIdCounter;
  const rawIp = clientSocket.remoteAddress || 'Unknown';
  const clientIp = rawIp.replace('::ffff:', '');
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
    sockA.on('data', (d) => { 
      connData.bytesIn += d.length;
      globalTotalBytesIn += d.length;
    });
    sockB.on('data', (d) => { 
      connData.bytesOut += d.length;
      globalTotalBytesOut += d.length;
    });

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

        if (path === '/api/stats') {
          const activeList = Array.from(activeConnections.values())
            .filter(c => !c.target.includes('railway.com') && !c.target.includes('up.railway.app'))
            .map(c => ({
              id: c.id,
              clientIp: c.clientIp,
              type: c.type,
              target: c.target,
              uptime: Math.floor((Date.now() - c.startTime) / 1000),
              bytesIn: formatBytes(c.bytesIn),
              bytesOut: formatBytes(c.bytesOut)
            }));

          // Hitung Unique Device / Client IP Aktif
          const uniqueClients = new Set(activeList.map(c => c.clientIp)).size;

          const resBody = JSON.stringify({
            proxyInfo: PROXY_SERVER_INFO,
            totalActive: uniqueClients,
            globalTotalIn: formatBytes(globalTotalBytesIn),
            globalTotalOut: formatBytes(globalTotalBytesOut),
            connections: activeList
          });

          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: ${Buffer.byteLength(resBody)}\r\nConnection: close\r\n\r\n${resBody}`);
          clientSocket.end();
          return;
        }

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

        if (path === '/' || path === '/index.html') {
          const html = renderDashboardHTML();
          clientSocket.write(`HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(html)}\r\nConnection: close\r\n\r\n${html}`);
          clientSocket.end();
          return;
        }

        // 2. SCANNER HTTP
        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1].trim() : 'speed.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        if (!targetHost.includes('railway.com') && !targetHost.includes('up.railway.app')) {
          connData.type = 'HTTP SCAN';
          connData.target = `${targetHost}:${targetPort}`;
          activeConnections.set(connId, connData);
        }

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

          if (!targetHost.includes('railway.com') && !targetHost.includes('up.railway.app')) {
            connData.type = 'HTTPS TUNNEL';
            connData.target = `${targetHost}:${targetPort}`;
            activeConnections.set(connId, connData);
          }

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

      // 4. STREAM VLESS / TROJAN (DARKTUNNEL)
      const sni = parseTlsSni(chunk);
      const destinationHost = sni || 'speed.cloudflare.com';

      if (!destinationHost.includes('railway.com') && !destinationHost.includes('up.railway.app')) {
        connData.type = sni ? 'VLESS / TROJAN' : 'RAW TCP';
        connData.target = `${destinationHost}:443`;
        activeConnections.set(connId, connData);
      }

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
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function renderDashboardHTML() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Proxy Monitor & DNS Control</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #06090e; color: #00ffcc; padding: 14px; margin: 0; display: flex; justify-content: center; }
    .card { background: #0c121e; border: 1px solid #00ffcc; box-shadow: 0 0 20px rgba(0,255,204,0.15); border-radius: 14px; max-width: 480px; width: 100%; padding: 18px; }
    h2 { margin: 0 0 16px 0; color: #38bdf8; text-align: center; font-size: 1.15rem; letter-spacing: 0.5px; }
    
    .proxy-box { background: #030712; border: 1px solid #38bdf8; border-radius: 10px; padding: 12px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; }
    .proxy-title { font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; margin-bottom: 4px; }
    .proxy-val { font-family: monospace; font-size: 1.05rem; font-weight: bold; color: #39ff14; }
    .proxy-sub { font-family: monospace; font-size: 0.7rem; color: #64748b; margin-top: 2px; }
    .btn-copy { background: #1e293b; border: 1px solid #38bdf8; color: #38bdf8; padding: 8px 12px; border-radius: 6px; font-size: 0.75rem; font-weight: bold; cursor: pointer; }
    .btn-copy:active { background: #38bdf8; color: #000; }

    .badge-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 18px; }
    .badge { background: #030712; border: 1px solid #1e293b; border-radius: 10px; padding: 12px 10px; text-align: center; }
    .badge h4 { margin: 0; font-size: 0.72rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; }
    .badge .val { font-size: 1.3rem; font-weight: bold; margin-top: 5px; font-family: monospace; }
    
    .section-title { font-size: 0.85rem; font-weight: bold; color: #38bdf8; margin-top: 16px; margin-bottom: 10px; display: flex; align-items: center; gap: 6px; }
    
    .conn-list { display: flex; flex-direction: column; gap: 8px; max-height: 260px; overflow-y: auto; padding-right: 2px; }
    .conn-item { background: #030712; border: 1px solid #1e293b; border-left: 3px solid #39ff14; border-radius: 8px; padding: 10px 12px; }
    .conn-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .conn-ip { font-family: monospace; font-size: 0.85rem; font-weight: bold; color: #f8fafc; }
    .tag { background: #032b17; color: #39ff14; padding: 2px 6px; border-radius: 4px; border: 1px solid #39ff14; font-size: 0.65rem; font-weight: bold; }
    .conn-target { font-family: monospace; font-size: 0.75rem; color: #38bdf8; word-break: break-all; margin-bottom: 4px; }
    .conn-meta { display: flex; justify-content: space-between; font-size: 0.7rem; color: #94a3b8; border-top: 1px dashed #1e293b; padding-top: 4px; margin-top: 4px; }
    .empty-state { text-align: center; color: #64748b; font-size: 0.8rem; padding: 20px 0; background: #030712; border-radius: 8px; border: 1px dashed #1e293b; }
    
    select, input { width: 100%; padding: 10px 12px; background: #030712; border: 1px solid #1e293b; border-radius: 8px; color: #fff; margin-top: 6px; font-family: monospace; font-size: 0.82rem; outline: none; }
    select:focus, input:focus { border-color: #00ffcc; }
    button { width: 100%; padding: 12px; background: #00ffcc; color: #000; font-weight: bold; border: none; border-radius: 8px; margin-top: 12px; cursor: pointer; font-size: 0.85rem; }
    button:active { transform: scale(0.98); }
    .toast { display: none; padding: 8px; text-align: center; border-radius: 6px; margin-top: 10px; font-size: 0.8rem; font-weight: bold; }
    .toast.success { display: block; background: #052e16; color: #4ade80; border: 1px solid #4ade80; }
  </style>
</head>
<body>
  <div class="card">
    <h2>⚡ PROXY MONITOR & DNS</h2>
    
    <div class="proxy-box">
      <div>
        <div class="proxy-title">🚀 Active Proxy Server (IP:Port)</div>
        <div class="proxy-val" id="proxy_full_text">${PROXY_SERVER_INFO.fullProxy || 'Loading IP...'}</div>
        <div class="proxy-sub" id="proxy_sub_text">${PROXY_SERVER_INFO.domain ? PROXY_SERVER_INFO.domain + ':' + PROXY_SERVER_INFO.port : 'Railway Direct'}</div>
      </div>
      <button type="button" class="btn-copy" onclick="copyProxy()">📋 SALIN</button>
    </div>

    <div class="badge-grid">
      <div class="badge">
        <h4>User Konek</h4>
        <div class="val" style="color:#39ff14;" id="active_count">0</div>
      </div>
      <div class="badge">
        <h4>Status DNS</h4>
        <div class="val" style="color:#38bdf8;" id="badge_dns">${DNS_CONFIG.mode}</div>
      </div>
      <div class="badge">
        <h4>Total In (RX)</h4>
        <div class="val" style="color:#00ffcc;" id="total_rx">0 B</div>
      </div>
      <div class="badge">
        <h4>Total Out (TX)</h4>
        <div class="val" style="color:#f59e0b;" id="total_tx">0 B</div>
      </div>
    </div>

    <div class="section-title">🟢 KONEKSI AKTIF REAL-TIME</div>
    <div class="conn-list" id="conn_container">
      <div class="empty-state">Belum ada perangkat terhubung...</div>
    </div>

    <div class="section-title" style="margin-top:20px;">⚙️ PENGATURAN DNS RESOLVER</div>
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
    let currentProxyString = "${PROXY_SERVER_INFO.fullProxy}";

    async function fetchStats() {
      try {
        const res = await fetch('/api/stats');
        const data = await res.json();
        
        if (data.proxyInfo && data.proxyInfo.fullProxy) {
          currentProxyString = data.proxyInfo.fullProxy;
          document.getElementById('proxy_full_text').innerText = data.proxyInfo.fullProxy;
          if (data.proxyInfo.domain) {
            document.getElementById('proxy_sub_text').innerText = data.proxyInfo.domain + ':' + data.proxyInfo.port;
          }
        }

        document.getElementById('active_count').innerText = data.totalActive;
        document.getElementById('total_rx').innerText = data.globalTotalIn;
        document.getElementById('total_tx').innerText = data.globalTotalOut;

        const container = document.getElementById('conn_container');
        if (!data.connections || data.connections.length === 0) {
          container.innerHTML = '<div class="empty-state">Belum ada perangkat terhubung...</div>';
          return;
        }

        container.innerHTML = data.connections.map(c => \`
          <div class="conn-item">
            <div class="conn-head">
              <span class="conn-ip">\${c.clientIp}</span>
              <span class="tag">\${c.type}</span>
            </div>
            <div class="conn-target">🎯 \${c.target}</div>
            <div class="conn-meta">
              <span>⏱️ \${c.uptime} detik</span>
              <span>📊 RX: \${c.bytesIn} | TX: \${c.bytesOut}</span>
            </div>
          </div>
        \`).join('');
      } catch (e) {}
    }

    setInterval(fetchStats, 2000);
    fetchStats();

    function copyProxy() {
      if (!currentProxyString) return;
      navigator.clipboard.writeText(currentProxyString).then(() => {
        const toast = document.getElementById('toast');
        toast.innerText = '📋 IP:Port Berhasil Disalin: ' + currentProxyString;
        toast.className = 'toast success';
        setTimeout(() => toast.style.display = 'none', 2500);
      });
    }

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
