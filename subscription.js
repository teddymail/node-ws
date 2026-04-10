const axios = require('axios');
const crypto = require('crypto');
const { Buffer } = require('buffer');

const TLS_PORTS = [443, 8443, 2053, 2083, 2087, 2096];
const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com',
  'speedof.me', 'testmy.net', 'bandwidth.place', 'speed.io',
  'librespeed.org', 'speedcheck.org'
];

function splitLines(text) {
  return String(text || '').includes('\r\n') ? String(text).split('\r\n') : String(text).split('\n');
}

function isBlockedDomain(host) {
  if (!host) return false;
  const hostLower = String(host).toLowerCase();
  return BLOCKED_DOMAINS.some(blocked => hostLower === blocked || hostLower.endsWith('.' + blocked));
}

async function getISP() {
  try {
    const res = await axios.get('https://api.ip.sb/geoip', { timeout: 3000, headers: { 'User-Agent': 'Mozilla/5.0' } });
    const data = res.data || {};
    return `${data.country_code || 'XX'}-${String(data.isp || 'Unknown').replace(/ /g, '_')}`;
  } catch {
    try {
      const res2 = await axios.get('http://ip-api.com/json', { timeout: 3000, headers: { 'User-Agent': 'Mozilla/5.0' } });
      const data2 = res2.data || {};
      return `${data2.countryCode || 'XX'}-${String(data2.org || 'Unknown').replace(/ /g, '_')}`;
    } catch {
      return 'Unknown';
    }
  }
}

async function getPublicIP() {
  const res = await axios.get('https://api-ipv4.ip.sb/ip', { timeout: 5000 });
  return String(res.data || '').trim();
}

function buildLinks({ uuid, host, port, path, name, isp, tls, sni, hostHeader }) {
  const tlsParam = tls ? 'tls' : 'none';
  const ssTlsParam = tls ? 'tls;' : '';
  const remark = encodeURIComponent(name ? `${name}-${isp}` : isp);
  const wsPath = encodeURIComponent(path || '/');
  const finalSni = tls ? (sni || host) : '';
  const finalHost = hostHeader || host;

  const vless = `vless://${uuid}@${host}:${port}?encryption=none&security=${tlsParam}&sni=${encodeURIComponent(finalSni)}&fp=chrome&type=ws&host=${encodeURIComponent(finalHost)}&path=${wsPath}#${remark}`;
  const trojan = `trojan://${uuid}@${host}:${port}?security=${tlsParam}&sni=${encodeURIComponent(finalSni)}&fp=chrome&type=ws&host=${encodeURIComponent(finalHost)}&path=${wsPath}#${remark}`;
  const ssMethodPassword = Buffer.from(`none:${uuid}`).toString('base64');
  const ss = `ss://${ssMethodPassword}@${host}:${port}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${encodeURIComponent(finalHost)};path%3D${wsPath};${ssTlsParam}sni%3D${encodeURIComponent(finalSni || host)};#${remark}`;

  return [vless, trojan, ss];
}

async function generateSubscription(config, currentHost, currentPort, addTxt = '') {
  const isp = await getISP();
  const host = currentHost || config.domain || (await getPublicIP());
  const port = currentPort || (config.domain ? 443 : (config.port || 3000));
  const tls = Boolean(config.domain);
  const sni = config.sni || config.domain || host;
  const hostHeader = config.hostHeader || config.domain || host;
  const preferredList = await buildBestIpList(addTxt, config, host, port);
  const allTargets = preferredList.length > 0 ? preferredList : [`${host}:${port}#Default`];
  const links = [];
  const seen = new Set();

  for (const target of allTargets) {
    const [rawAddr, rawTag] = String(target).split('#');
    const parsed = parseHostPort(rawAddr, port);
    if (!parsed?.host) continue;
    const nodeName = config.name ? `${config.name}-${rawTag || parsed.host}` : (rawTag || parsed.host);
    const nodeLinks = buildLinks({
      uuid: config.uuid,
      host: parsed.host,
      port: parsed.port,
      path: config.path || '/ws',
      name: nodeName,
      isp,
      tls,
      sni,
      hostHeader,
    });
    for (const link of nodeLinks) {
      if (seen.has(link)) continue;
      seen.add(link);
      links.push(link);
    }
  }

  return Buffer.from(links.join('\n')).toString('base64') + '\n';
}

function parseHostPort(value, defaultPort = 443) {
  const str = String(value || '').trim();
  if (!str) return null;
  if (str.includes(']:')) {
    const [h, p] = str.split(']:');
    return { host: h + ']', port: parseInt(p, 10) || defaultPort };
  }
  const colonIndex = str.lastIndexOf(':');
  if (colonIndex > -1 && str.indexOf(':') === colonIndex) {
    const h = str.slice(0, colonIndex);
    const p = parseInt(str.slice(colonIndex + 1), 10);
    if (h && Number.isFinite(p)) return { host: h, port: p };
  }
  return { host: str, port: defaultPort };
}

function normalizeLines(text) {
  return splitLines(text).map(s => s.trim()).filter(Boolean);
}

async function buildBestIpList(addTxt, config, fallbackHost = '', fallbackPort = 443) {
  const lines = normalizeLines(addTxt);
  const result = [];
  const seen = new Set();
  const defaultPort = Number(fallbackPort) || 443;

  for (const line of lines) {
    if (seen.has(line)) continue;
    seen.add(line);
    if (line.startsWith('#')) continue;
    result.push(line);
  }

  if (result.length === 0) {
    if (fallbackHost) {
      result.push(`${fallbackHost}:${defaultPort}#Default`);
    } else {
      const count = Math.max(1, Number(config?.subscription?.randomIpCount || 4));
      for (let i = 0; i < count; i++) {
        const ip = `8.8.8.${Math.floor(Math.random() * 255)}`;
        result.push(`${ip}:${TLS_PORTS[Math.floor(Math.random() * TLS_PORTS.length)]}#Fallback`);
      }
    }
  }

  return result;
}

function safeBase64Decode(text) {
  try {
    return Buffer.from(String(text).trim(), 'base64').toString('utf8');
  } catch {
    return '';
  }
}

function safeBase64Encode(text) {
  return Buffer.from(String(text)).toString('base64');
}

function sha224(text) {
  return crypto.createHash('sha224').update(String(text)).digest('hex');
}

module.exports = {
  splitLines,
  isBlockedDomain,
  getISP,
  getPublicIP,
  buildLinks,
  generateSubscription,
  parseHostPort,
  normalizeLines,
  buildBestIpList,
  safeBase64Decode,
  safeBase64Encode,
  sha224,
};
