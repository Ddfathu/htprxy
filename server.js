import net from 'net';
import dns from 'dns';

const PORT = process.env.PORT || 8080;

// State Konfigurasi DNS Aktif
let DNS_CONFIG = {
  mode: 'DOH', // 'DOH' atau 'UDP'
  dohUrl: 'https://cloudflare-dns.com/dns-query',
  udpServer: '1.1.1.1',
  udpPort: 53
};

// Preset Resolver Bawaan
const PRESETS = {
  'cf-doh': { name: 'Cloudflare DoH', type: 'DOH', url: 'https://cloudflare-dns.com/dns-query' },
  'google-doh': { name: 'Google DoH', type: 'DOH', url: 'https://dns.google/dns-query' },
  'quad9-doh': { name: 'Quad9 DoH', type: 'DOH', url: 'https://dns.quad9.net/dns-query' },
  'adguard-doh': { name: 'AdGuard DoH', type: 'DOH', url: 'https://dns.adguard-dns.com/dns-query' },
  'cf-udp': { name: 'Cloudflare UDP (1.1.1.1)', type: 'UDP', host: '1.1.1.1', port: 53 },
  'google-udp': { name: 'Google UDP (8.8.8.8)', type: 'UDP', host: '8.8.8.8', port: 53 }
};

// In-Memory Fast Cache
const dnsCache = new Map();

async function resolveDomain(hostname) {
  const now = Date.now();
  const cached = dnsCache.get(hostname);
  if (cached && (now - cached.time < 1000 * 60 * 5)) {
    return cached.ip;
  }

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    return hostname;
  }

  // 1. RESOLVER JIKA MODE DOH (Termasuk Custom DoH)
  if (DNS_CONFIG.mode === 'DOH') {
    try {
      const url = new URL(DNS_CONFIG.dohUrl);
      url.searchParams.set('name', hostname);
      url.searchParams.set('type', 'A');

      const res = await fetch(url.toString(), {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(2000)
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

  // 2. RESOLVER JIKA MODE UDP (Termasuk Custom UDP)
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

  // Fallback System Lookup
  return new Promise((resolve) => {
    dns.lookup(hostname, (err, address) => {
      const ip = (!err && address) ? address : '104.16.123.96';
      dnsCache.set(hostname, { ip, time: now });
      resolve(ip);
    });
  });
}

// Server TCP Hybrid (Layer 4 Forwarder + HTTP Web Server)
const server = net.createServer({ noDelay: true }, (clientSocket) => {
  clientSocket.setNoDelay(true);
  clientSocket.setKeepAlive(true, 10000);

  let isFirstPacket = true;
  let targetSocket = null;

  clientSocket.on('data', async (chunk) => {
    if (isFirstPacket) {
      isFirstPacket = false;
      const dataStr = chunk.toString('utf-8');

      // 1. CEK REQUEST DASHBOARD ATAU API GANTI DNS
      if (dataStr.startsWith('GET /') || dataStr.startsWith('POST /api/set-dns')) {
        const firstLine = dataStr.split('\r\n')[0];
        const path = firstLine.split(' ')[1] || '/';

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

        // 2. SCANNER HTTP (speed.cloudflare.com / target scanner luar)
        const hostMatch = dataStr.match(/Host:\s*([^\r\n:]+)(?::(\d+))?/i);
        const targetHost = hostMatch ? hostMatch[1].trim() : 'speed.cloudflare.com';
        const targetPort = hostMatch && hostMatch[2] ? parseInt(hostMatch[2], 10) : 80;

        const resolvedIp = await resolveDomain(targetHost);
        targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
          targetSocket.setNoDelay(true);
          targetSocket.setKeepAlive(true, 10000);
          targetSocket.write(chunk);
          targetSocket.pipe(clientSocket);
          clientSocket.pipe(targetSocket);
        });

        targetSocket.on('error', () => clientSocket.destroy());
        return;
      }

      // 3. HTTPS CONNECT
      if (dataStr.startsWith('CONNECT ')) {
        const match = dataStr.match(/CONNECT\s+([^:\s]+):(\d+)/i);
        if (match) {
          const targetHost = match[1];
          const targetPort = parseInt(match[2], 10) || 443;
          const resolvedIp = await resolveDomain(targetHost);

          targetSocket = net.connect({ host: resolvedIp, port: targetPort, noDelay: true }, () => {
            targetSocket.setNoDelay(true);
            targetSocket.setKeepAlive(true, 10000);
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            targetSocket.pipe(clientSocket);
            clientSocket.pipe(targetSocket);
          });

          targetSocket.on('error', () => clientSocket.destroy());
          return;
        }
      }

      // 4. TRAFIK STREAM VLESS / TROJAN (DarkTunnel)
      const sni = parseTlsSni(chunk);
      const destinationHost = sni || 'speed.cloudflare.com';
      const resolvedIp = await resolveDomain(destinationHost);

      targetSocket = net.connect({ host: resolvedIp, port: 443, noDelay: true }, () => {
        targetSocket.setNoDelay(true);
        targetSocket.setKeepAlive(true, 10000);
        targetSocket.write(chunk);
        targetSocket.pipe(clientSocket);
        clientSocket.pipe(targetSocket);
      });

      targetSocket.on('error', () => clientSocket.destroy());
    }
  });

  clientSocket.on('error', () => { if (targetSocket) targetSocket.destroy(); });
  clientSocket.on('close', () => { if (targetSocket) targetSocket.destroy(); });
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
        const sniListLen = buffer.readUInt16BE(pos);
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

function renderDashboardHTML() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Proxy DNS Control Panel</title>
  <style>
    body { font-family: system-ui, -apple-system, sans-serif; background: #080c14; color: #00ffcc; padding: 20px; display: flex; justify-content: center; }
    .card { background: #0f172a; border: 1px solid #00ffcc; box-shadow: 0 0 25px rgba(0,255,204,0.2); border-radius: 12px; max-width: 480px; width: 100%; padding: 22px; box-sizing: border-box; }
    h2 { margin-top: 0; color: #38bdf8; text-align: center; font-size: 1.25rem; }
    label { font-size: 0.85rem; font-weight: bold; margin-top: 14px; display: block; }
    select, input { width: 100%; padding: 10px; background: #030712; border: 1px solid #00ffcc; border-radius: 6px; color: #fff; margin-top: 6px; box-sizing: border-box; font-family: monospace; font-size: 0.85rem; }
    button { width: 100%; padding: 12px; background: #00ffcc; color: #000; font-weight: bold; border: none; border-radius: 6px; margin-top: 20px; cursor: pointer; transition: 0.2s; }
    button:hover { background: #38bdf8; }
    .status-box { background: #030712; padding: 12px; border-radius: 6px; border: 1px dashed #38bdf8; margin-top: 15px; font-size: 0.82rem; }
    .custom-section { background: #030712; border: 1px solid #38bdf8; padding: 12px; border-radius: 6px; margin-top: 12px; }
    .toast { display: none; padding: 10px; text-align: center; border-radius: 6px; margin-top: 12px; font-size: 0.85rem; font-weight: bold; }
    .toast.success { display: block; background: #052e16; color: #4ade80; border: 1px solid #4ade80; }
  </style>
</head>
<body>
  <div class="card">
    <h2>⚡ PROXY DNS & DOH MANAGER</h2>
    <div class="status-box">
      <strong>Active Mode:</strong> <span id="cur_mode" style="color:#38bdf8;">${DNS_CONFIG.mode}</span><br>
      <strong>Target:</strong> <span id="cur_target" style="color:#4ade80; word-break:break-all;">${DNS_CONFIG.mode === 'DOH' ? DNS_CONFIG.dohUrl : DNS_CONFIG.udpServer + ':' + DNS_CONFIG.udpPort}</span>
    </div>

    <label>Pilih Preset / Mode Kustom:</label>
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

    <!-- FORM INPUT CUSTOM DOH -->
    <div id="box_custom_doh" class="custom-section" style="display:none;">
      <label style="margin-top:0;">DoH Endpoint URL Pribadi:</label>
      <input type="text" id="custom_doh_url" placeholder="https://dns.nextdns.io/xxxxxx" value="${DNS_CONFIG.dohUrl}">
      <small style="color:#94a3b8; font-size:0.75rem; margin-top:4px; display:block;">Mendukung NextDNS, AdGuard Home, Pi-hole DoH, dll.</small>
    </div>

    <!-- FORM INPUT CUSTOM UDP -->
    <div id="box_custom_udp" class="custom-section" style="display:none;">
      <label style="margin-top:0;">Server IP Address DNS Pribadi:</label>
      <input type="text" id="custom_udp_ip" placeholder="contoh: 94.140.14.14" value="${DNS_CONFIG.udpServer}">
      
      <label>Port DNS (Default: 53):</label>
      <input type="number" id="custom_udp_port" placeholder="53" value="${DNS_CONFIG.udpPort || 53}">
    </div>

    <button onclick="saveDns()">💾 SIMPAN & TERAPKAN DNS</button>
    <div id="toast" class="toast"></div>
  </div>

  <script>
    function applyPreset() {
      const val = document.getElementById('preset_select').value;
      const dohBox = document.getElementById('box_custom_doh');
      const udpBox = document.getElementById('box_custom_udp');

      dohBox.style.display = (val === 'custom_doh') ? 'block' : 'none';
      udpBox.style.display = (val === 'custom_udp') ? 'block' : 'none';
    }

    async function saveDns() {
      const selected = document.getElementById('preset_select').value;
      let payload = {};

      if (selected === 'custom_doh') {
        payload = {
          mode: 'DOH',
          dohUrl: document.getElementById('custom_doh_url').value.trim()
        };
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
        document.getElementById('cur_mode').innerText = data.config.mode;
        document.getElementById('cur_target').innerText = data.config.mode === 'DOH' ? data.config.dohUrl : data.config.udpServer + ':' + data.config.udpPort;
        const toast = document.getElementById('toast');
        toast.innerText = '✅ DNS Berhasil Diterapkan & Cache Direset!';
        toast.className = 'toast success';
        setTimeout(() => toast.style.display = 'none', 3000);
      }
    }
  </script>
</body>
</html>`;
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Universal Proxy + Custom DNS Dashboard running on port ${PORT}`);
});
