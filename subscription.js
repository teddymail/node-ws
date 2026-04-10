const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { Buffer } = require('buffer');

const DEFAULT_CIDRS = ['104.16.0.0/13'];
const DEFAULT_CF_PORTS = [443, 2053, 2083, 2087, 2096, 8443];

function splitLines(text) {
  return String(text || '').includes('\r\n') ? String(text).split('\r\n') : String(text).split('\n');
}

function isValidBase64(str) {
  if (typeof str !== 'string') return false;
  const clean = str.replace(/\s/g, '');
  if (!clean || clean.length % 4 !== 0) return false;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(clean)) return false;
  try { Buffer.from(clean, 'base64'); return true; } catch { return false; }
}

function base64Decode(str) {
  return Buffer.from(str, 'base64').toString('utf8');
}

function randomReplaceWildcard(host) {
  if (!host?.includes('*')) return host;
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return host.replace(/\*/g, () => {
    let s = '';
    const len = Math.floor(Math.random() * 14) + 3;
    for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
    return s;
  });
}

function randomPath(pathInput = '/') {
  const dirs = ['about', 'account', 'acg', 'api', 'app', 'archive', 'assets', 'blog', 'cdn', 'content', 'css', 'img', 'js', 'login', 'media', 'static', 'user'];
  const count = Math.floor(Math.random() * 3) + 1;
  const selected = dirs.sort(() => 0.5 - Math.random()).slice(0, count).join('/');
  if (pathInput === '/') return `/${selected}`;
  return `/${selected}${pathInput.startsWith('/') ? pathInput : '/' + pathInput}`;
}

async function getISP() {
  try {
    const r = await axios.get('https://api.ip.sb/geoip', { timeout: 3000, headers: { 'User-Agent': 'Mozilla/5.0' } });
    const d = r.data || {};
    return `${d.country_code || 'XX'}-${String(d.isp || 'Unknown').replace(/ /g, '_')}`;
  } catch {
    try {
      const r = await axios.get('http://ip-api.com/json', { timeout: 3000, headers: { 'User-Agent': 'Mozilla/5.0' } });
      const d = r.data || {};
      return `${d.countryCode || 'XX'}-${String(d.org || 'Unknown').replace(/ /g, '_')}`;
    } catch {
      return 'Unknown';
    }
  }
}

async function getPublicIP() {
  const r = await axios.get('https://api-ipv4.ip.sb/ip', { timeout: 5000 });
  return String(r.data || '').trim();
}

function buildNodeRemark(name, isp) {
  return name ? `${name}-${isp}` : isp;
}

function buildSubLinks({ uuid, host, port, path, name, isp, tls }) {
  const tlsParam = tls ? 'tls' : 'none';
  const ssTlsParam = tls ? 'tls;' : '';
  const remark = encodeURIComponent(buildNodeRemark(name, isp));
  const wsPath = encodeURIComponent(path);
  const vless = `vless://${uuid}@${host}:${port}?encryption=none&security=${tlsParam}&sni=${host}&fp=chrome&type=ws&host=${host}&path=${wsPath}#${remark}`;
  const trojan = `trojan://${uuid}@${host}:${port}?security=${tlsParam}&sni=${host}&fp=chrome&type=ws&host=${host}&path=${wsPath}#${remark}`;
  const ssMethodPassword = Buffer.from(`none:${uuid}`).toString('base64');
  const ss = `ss://${ssMethodPassword}@${host}:${port}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${host};path%3D${wsPath};${ssTlsParam}sni%3D${host};#${remark}`;
  return [vless, trojan, ss];
}

async function generateSubscription(config) {
  const isp = await getISP();
  const host = config.domain || (await getPublicIP());
  const port = config.domain ? 443 : (config.port || 3000);
  const tls = Boolean(config.domain);

  const [vless, trojan, ss] = buildSubLinks({
    uuid: config.uuid,
    host,
    port,
    path: config.path || '/',
    name: config.name || '',
    isp,
    tls,
  });

  const content = [vless, trojan, ss].join('\n');
  return Buffer.from(content).toString('base64') + '\n';
}

function mergeWithBestIPs(lines, addText, config) {
  const customIPs = splitLines(addText).map(s => s.trim()).filter(Boolean);
  const result = new Set();
  customIPs.forEach(item => result.add(item));
  lines.forEach(item => result.add(item));
  return [...result];
}

module.exports = {
  splitLines,
  isValidBase64,
  base64Decode,
  randomReplaceWildcard,
  randomPath,
  getISP,
  getPublicIP,
  buildNodeRemark,
  buildSubLinks,
  generateSubscription,
  mergeWithBestIPs,
};
