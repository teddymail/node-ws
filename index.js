#!/usr/bin/env node

const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { WebSocket, createWebSocketStream } = require('ws');

const storage = require('./localManagement');
const sub = require('./subscription');
const ADMIN_PAGE_URL = 'https://edt-pages.github.io/admin';

storage.initStorage();

let config = storage.loadConfig();
const UUID = process.env.UUID || config.uuid || '5efabea4-f6d4-91fd-b8f0-17e004c89c60';
const DOMAIN = process.env.DOMAIN || config.domain || '';
const WSPATH = process.env.WSPATH || (config.path ? config.path.replace(/^\//, '') : UUID.slice(0, 8));
const SUB_PATH = process.env.SUB_PATH || config.subPath || 'sub';
const PORT = Number(process.env.PORT || 7860);

let uuid = UUID.replace(/-/g, '');
let CurrentDomain = DOMAIN;
let CurrentPort = DOMAIN ? 443 : PORT;
let StableSubToken = '';
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];

function ensureStableSubToken() {
  const envToken = String(process.env.SUB_TOKEN || '').trim();
  if (envToken) return envToken;

  const persisted = storage.loadSubToken();
  if (persisted) return persisted;

  const generated = crypto.randomBytes(16).toString('hex');
  storage.saveSubToken(generated);
  return generated;
}

function reloadConfig() {
  config = storage.loadConfig();
  StableSubToken = ensureStableSubToken();
  CurrentDomain = config.domain || DOMAIN || CurrentDomain;
  uuid = String(config.uuid || UUID).replace(/-/g, '');
}

function getRuntimeSubPath() {
  return String(config.subPath || SUB_PATH || 'sub').replace(/^\/+/, '');
}

function getRuntimeWsPath() {
  const p = String(config.path || `/${WSPATH}` || '/ws');
  return p.startsWith('/') ? p : `/${p}`;
}

function isBlockedDomain(host) {
  return sub.isBlockedDomain(host);
}

async function getip() {
  reloadConfig();
  if (!CurrentDomain || CurrentDomain === 'your-domain.com') {
    try {
      const ip = await sub.getPublicIP();
      CurrentDomain = ip;
      CurrentPort = PORT;
    } catch (e) {
      CurrentDomain = 'change-your-domain.com';
      CurrentPort = 443;
    }
  } else {
    CurrentDomain = config.domain || DOMAIN;
    CurrentPort = 443;
  }
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const out = {};
  raw.split(';').forEach(item => {
    const [k, ...rest] = item.trim().split('=');
    if (k) out[k] = rest.join('=');
  });
  return out;
}

function sendText(res, text, status = 200, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8', ...headers });
  res.end(text);
}

function sendHtml(res, html, status = 200) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function sendJson(res, obj, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj, null, 2));
}

function normalizeHost(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
    const u = new URL(withScheme);
    return u.hostname;
  } catch {
    return raw.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
  }
}

function normalizeAdminConfigPayload(input, current) {
  const next = { ...current, ...(input || {}) };
  const src = input || {};

  const maybeUuid = src.uuid || src.UUID;
  if (maybeUuid) next.uuid = String(maybeUuid).trim();

  const hostsFromArray = Array.isArray(src.HOSTS) ? src.HOSTS.map(normalizeHost).filter(Boolean) : [];
  const maybeDomain = src.domain || src.DOMAIN || src.host || src.HOST || hostsFromArray[0];
  if (maybeDomain !== undefined) next.domain = normalizeHost(maybeDomain);

  const maybePath = src.path || src.PATH;
  if (maybePath) {
    const p = String(maybePath).trim();
    next.path = p.startsWith('/') ? p : `/${p}`;
  } else if (src.WSPATH) {
    const p = String(src.WSPATH).trim();
    if (p) next.path = p.startsWith('/') ? p : `/${p}`;
  }

  const maybeSubPath = src.subPath || src.SUB_PATH;
  if (maybeSubPath) next.subPath = String(maybeSubPath).replace(/^\/+/, '');

  const maybeName = src.name || src.NAME;
  if (maybeName !== undefined) next.name = String(maybeName);

  if (src.sni || src.SNI) next.sni = normalizeHost(src.sni || src.SNI);
  if (src.hostHeader || src.HOST_HEADER) next.hostHeader = normalizeHost(src.hostHeader || src.HOST_HEADER);

  // Keep legacy fields aligned to a single source-of-truth: domain.
  if (next.domain) {
    if (!next.sni) next.sni = next.domain;
    if (!next.hostHeader) next.hostHeader = next.domain;
  }

  if (src.subscription && typeof src.subscription === 'object') {
    next.subscription = { ...(next.subscription || {}), ...src.subscription };
  }

  if (src.proxy && typeof src.proxy === 'object') {
    next.proxy = { ...(next.proxy || {}), ...src.proxy };
  }

  return next;
}

function buildAdminConfigResponse(cfg, requestHost = '') {
  const pathValue = cfg.path || '/ws';
  const hostValue = cfg.domain || '';
  const portValue = hostValue ? 443 : PORT;
  const tlsValue = Boolean(hostValue);
  let linkValue = '';
  try {
    const links = sub.buildLinks({
      uuid: cfg.uuid || UUID,
      host: hostValue || 'example.com',
      port: portValue,
      path: pathValue,
      name: cfg.name || 'Node',
      isp: 'Node',
      tls: tlsValue,
      sni: cfg.sni || hostValue || 'example.com',
      hostHeader: cfg.hostHeader || hostValue || 'example.com',
    });
    linkValue = Array.isArray(links) && links.length > 0 ? links[0] : '';
  } catch {
    linkValue = '';
  }

  const subToken = StableSubToken || '';

  return {
    ...cfg,
    UUID: cfg.uuid || '',
    DOMAIN: hostValue,
    HOST: hostValue,
    HOSTS: hostValue ? [hostValue] : [],
    PATH: pathValue,
    WSPATH: String(pathValue).replace(/^\//, ''),
    SUB_PATH: cfg.subPath || 'sub',
    NAME: cfg.name || '',
    SNI: cfg.sni || hostValue || '',
    HOST_HEADER: cfg.hostHeader || hostValue || '',
    LINK: linkValue,
    优选订阅生成: {
      TOKEN: subToken
    }
  };
}

function parseHostPortLoose(value, defaultPort = 443) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  const withScheme = /^(socks5|https?):\/\//i.test(raw) ? raw : `socks5://${raw}`;
  try {
    const u = new URL(withScheme);
    return {
      host: u.hostname,
      port: Number(u.port) || defaultPort,
      protocol: u.protocol.replace(':', ''),
    };
  } catch {
    return sub.parseHostPort(raw, defaultPort);
  }
}

function checkTcpConnect(host, port, timeout = 3000) {
  return new Promise(resolve => {
    const socket = net.connect({ host, port });
    let done = false;
    const finish = ok => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeout);
    socket.on('connect', () => finish(true));
    socket.on('timeout', () => finish(false));
    socket.on('error', () => finish(false));
  });
}

async function loadUpstreamAdminHtml() {
  const response = await axios.get(ADMIN_PAGE_URL, {
    timeout: 8000,
    headers: { 'User-Agent': 'node-ws-admin' },
    responseType: 'text',
  });
  const html = String(response.data || '');
  const inject = `<script>(function(){
function hideNode(el){ if(!el) return; el.style.display='none'; el.setAttribute('aria-hidden','true'); }
function hideById(id){ hideNode(document.getElementById(id)); }
function removeByButtonOnclick(fnName){
  var btns=document.querySelectorAll('button[onclick]');
  btns.forEach(function(btn){
    var on=btn.getAttribute('onclick')||'';
    if(on.indexOf(fnName)>=0){
      var card=btn.closest('.section-card,.status-card,.config-card,.stat-card,.card,.module-card,.dashboard-card');
      if(card) hideNode(card); else hideNode(btn);
    }
  });
}
function removeByText(text){
  var nodes=document.querySelectorAll('h1,h2,h3,h4,h5,p,span,div,label,button');
  nodes.forEach(function(n){
    if((n.textContent||'').indexOf(text)>=0){
      var card=n.closest('.section-card,.status-card,.config-card,.stat-card,.card,.module-card,.dashboard-card');
      if(card) hideNode(card);
    }
  });
}
function run(){
  ['clearTelegramModal','telegramConfigModal','clearCloudflareModal','cloudflareConfigModal'].forEach(hideById);
  ['openTelegramConfigModal','clearTelegramConfig','openCloudflareConfigModal','clearCloudflareConfig','testTelegramConfig','confirmTelegramConfig','testCloudflareConfig','confirmCloudflareConfig','openNotificationConfigModal','clearNotificationConfig','testNotificationConfig','confirmNotificationConfig'].forEach(removeByButtonOnclick);
  ['Telegram Bot 通知设置','Cloudflare Workers/Pages 可用请求数统计','Telegram','消息通知设置','通知设置','🔔 消息通知设置'].forEach(removeByText);
}
function ensureTokenRegenerateButton(){
  if(document.getElementById('localTokenRegenerateBtn')) return;
  var btn=document.createElement('button');
  btn.id='localTokenRegenerateBtn';
  btn.type='button';
  btn.textContent='🔁 重置订阅Token';
  btn.style.cssText='position:fixed;right:16px;bottom:16px;z-index:99999;padding:10px 14px;border-radius:8px;border:none;background:#0f766e;color:#fff;cursor:pointer;';
  btn.onclick=async function(){
    if(!confirm('确定重新生成订阅Token吗？生成后旧订阅链接将失效。')) return;
    try{
      var r=await fetch('/admin/token/regenerate',{method:'POST'});
      var d=await r.json().catch(function(){return {};});
      if(!r.ok || !d.success){ alert(d.error || d.message || '重置失败'); return; }
      alert('Token已重置，请重新复制订阅链接');
      location.reload();
    }catch(_e){ alert('网络错误，重置失败'); }
  };
  document.body.appendChild(btn);
}
['openTelegramConfigModal','clearTelegramConfig','testTelegramConfig','confirmTelegramConfig','closeTelegramConfigModal','openCloudflareConfigModal','clearCloudflareConfig','testCloudflareConfig','confirmCloudflareConfig','closeCloudflareConfigModal','openNotificationConfigModal','clearNotificationConfig','testNotificationConfig','confirmNotificationConfig','closeNotificationConfigModal'].forEach(function(fn){
  if(typeof window[fn] !== 'function') window[fn] = function(){ return false; };
});
run();
ensureTokenRegenerateButton();
new MutationObserver(run).observe(document.documentElement,{childList:true,subtree:true});
})();</script>`;
  return html.includes('</body>') ? html.replace('</body>', `${inject}</body>`) : `${html}${inject}`;
}

function adminAuth(req) {
  const cookie = parseCookies(req).auth;
  const ua = req.headers['user-agent'] || 'null';
  reloadConfig();
  return storage.verifySession(cookie, ua, config);
}

function requireAdmin(req, res) {
  if (!adminAuth(req)) {
    res.writeHead(302, { Location: '/login' });
    res.end('Redirecting...');
    return false;
  }
  return true;
}

async function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }
    let attempts = 0;
    const tryNextDNS = () => {
      if (attempts >= DNS_SERVERS.length) return reject(new Error(`Failed to resolve ${host}`));
      attempts++;
      axios.get(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, {
        timeout: 5000,
        headers: { Accept: 'application/dns-json' }
      }).then(response => {
        const data = response.data;
        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
          const ip = data.Answer.find(record => record.type === 1);
          if (ip) return resolve(ip.data);
        }
        tryNextDNS();
      }).catch(() => tryNextDNS());
    };
    tryNextDNS();
  });
}

function buildExpectedPath() {
  return getRuntimeWsPath();
}

function handleVlsConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;

  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
      (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));

  if (isBlockedDomain(host)) {
    ws.close();
    return false;
  }

  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  resolveHost(host)
    .then(resolvedIP => {
      net.connect({ host: resolvedIP, port }, function () {
        this.write(msg.slice(i));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', () => { });
    })
    .catch(() => {
      net.connect({ host, port }, function () {
        this.write(msg.slice(i));
        duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
      }).on('error', () => { });
    });

  return true;
}

function handleTrojConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    const receivedPasswordHash = msg.slice(0, 56).toString();
    const possiblePasswords = [UUID];

    let matchedPassword = null;
    for (const pwd of possiblePasswords) {
      const hash = crypto.createHash('sha224').update(pwd).digest('hex');
      if (hash === receivedPasswordHash) {
        matchedPassword = pwd;
        break;
      }
    }
    if (!matchedPassword) return false;

    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;

    const cmd = msg[offset];
    if (cmd !== 0x01) return false;
    offset += 1;

    const atyp = msg[offset];
    offset += 1;
    let host, port;
    if (atyp === 0x01) {
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset];
      offset += 1;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16)).join(':');
      offset += 16;
    } else {
      return false;
    }

    port = msg.readUInt16BE(offset);
    offset += 2;
    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;

    if (isBlockedDomain(host)) {
      ws.close();
      return false;
    }

    const duplex = createWebSocketStream(ws);
    resolveHost(host)
      .then(resolvedIP => {
        net.connect({ host: resolvedIP, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      })
      .catch(() => {
        net.connect({ host, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      });

    return true;
  } catch {
    return false;
  }
}

function handleSsConnection(ws, msg) {
  try {
    let offset = 0;
    const atyp = msg[offset];
    offset += 1;

    let host, port;
    if (atyp === 0x01) {
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset];
      offset += 1;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16)).join(':');
      offset += 16;
    } else {
      return false;
    }

    port = msg.readUInt16BE(offset);
    offset += 2;

    if (isBlockedDomain(host)) {
      ws.close();
      return false;
    }

    const duplex = createWebSocketStream(ws);
    resolveHost(host)
      .then(resolvedIP => {
        net.connect({ host: resolvedIP, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      })
      .catch(() => {
        net.connect({ host, port }, function () {
          if (offset < msg.length) this.write(msg.slice(offset));
          duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex);
        }).on('error', () => { });
      });

    return true;
  } catch {
    return false;
  }
}

const httpServer = http.createServer(async (req, res) => {
  reloadConfig();
  const url = new URL(req.url, `http://${req.headers.host}`);
  const UA = req.headers['user-agent'] || 'null';

  if (url.pathname === '/login') {
    if (req.method === 'GET') {
      const html = fs.existsSync(path.join(__dirname, 'login.html'))
        ? fs.readFileSync(path.join(__dirname, 'login.html'), 'utf8')
        : `<!doctype html><html><body><form method="post"><input name="password" type="password"><button>Login</button></form></body></html>`;
      return sendHtml(res, html);
    }

    if (req.method === 'POST') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        const params = new URLSearchParams(body);
        const inputPassword = params.get('password') || '';
        const adminPassword = storage.getAdminPassword(config);
        const wantsJson = String(req.headers.accept || '').includes('application/json');
        if (inputPassword === adminPassword) {
          const auth = storage.createSession(UA, config);
          if (!wantsJson) {
            res.writeHead(302, {
              Location: '/admin',
              'Set-Cookie': `auth=${auth}; Path=/; Max-Age=86400; HttpOnly`
            });
            return res.end('Redirecting...');
          }
          res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'Set-Cookie': `auth=${auth}; Path=/; Max-Age=86400; HttpOnly`
          });
          return res.end(JSON.stringify({ success: true }));
        }
        return sendJson(res, { success: false, error: 'invalid password' }, 403);
      });
      return;
    }
  }

  if (url.pathname === '/logout') {
    res.writeHead(302, {
      Location: '/login',
      'Set-Cookie': 'auth=; Path=/; Max-Age=0; HttpOnly'
    });
    return res.end('Redirecting...');
  }

  if (url.pathname === '/') {
    const filePath = path.join(__dirname, 'index.html');
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      return sendHtml(res, content);
    } catch {
      return sendText(res, 'Hello world!');
    }
  }

  if (url.pathname === `/${getRuntimeSubPath()}`) {
    const expectedToken = StableSubToken;
    const providedToken = String(url.searchParams.get('token') || '').trim();
    if (!providedToken || providedToken !== expectedToken) {
      return sendJson(res, { success: false, error: 'invalid token' }, 403);
    }

    await getip();
    const addTxt = storage.loadAddTxt();
    const base64Content = await sub.generateSubscription({
      uuid: config.uuid || UUID,
      domain: CurrentDomain,
      path: config.path || `/${WSPATH}`,
      name: config.name || '',
      sni: config.sni || config.domain || CurrentDomain,
      hostHeader: config.hostHeader || config.domain || CurrentDomain,
      subscription: config.subscription || {},
    }, CurrentDomain, CurrentPort, addTxt);

    const rawContent = sub.safeBase64Decode(base64Content) || '';

    // Keep compatibility with admin-generated urls: /sub?token=...&b64|clash|sb
    if (url.searchParams.has('clash') || url.searchParams.has('sb') || url.searchParams.has('raw')) {
      return sendText(res, `${rawContent.trim()}\n`);
    }
    if (url.searchParams.has('b64')) {
      return sendText(res, base64Content);
    }

    return sendText(res, base64Content);
  }

  if (url.pathname === '/admin') {
    if (!requireAdmin(req, res)) return;
    try {
      const html = await loadUpstreamAdminHtml();
      return sendHtml(res, html);
    } catch {
      const html = fs.existsSync(path.join(__dirname, 'admin.html'))
        ? fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8')
        : `<html><body><h1>Admin</h1></body></html>`;
      return sendHtml(res, html);
    }
  }

  if (url.pathname === '/admin/init') {
    if (!requireAdmin(req, res)) return;
    storage.saveConfig(storage.defaultConfig());
    storage.saveAddTxt('');
    storage.saveLogs([]);
    return sendJson(res, { success: true, message: 'reset' });
  }

  if (url.pathname === '/admin/log.json') {
    if (!requireAdmin(req, res)) return;
    return sendJson(res, storage.loadLogs());
  }

  if (url.pathname === '/admin/config.json') {
    if (!requireAdmin(req, res)) return;
    if (req.method === 'GET') return sendJson(res, buildAdminConfigResponse(storage.loadConfig(), req.headers.host || ''));
    if (req.method === 'POST') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        try {
          const parsedBody = JSON.parse(body);
          const currentCfg = storage.loadConfig();
          const newConfig = normalizeAdminConfigPayload(parsedBody, currentCfg);
          storage.saveConfig(newConfig);
          return sendJson(res, { success: true, message: 'saved' });
        } catch (e) {
          return sendJson(res, { success: false, error: e.message }, 400);
        }
      });
      return;
    }
  }

  if (url.pathname === '/admin/token/regenerate') {
    if (!requireAdmin(req, res)) return;
    if (req.method !== 'POST') return sendJson(res, { success: false, error: 'method not allowed' }, 405);
    StableSubToken = crypto.randomBytes(16).toString('hex');
    storage.saveSubToken(StableSubToken);
    return sendJson(res, { success: true, token: StableSubToken, message: 'token regenerated' });
  }

  if (url.pathname === '/admin/ADD.txt') {
    if (!requireAdmin(req, res)) return;
    if (req.method === 'GET') return sendText(res, storage.loadAddTxt());
    if (req.method === 'POST') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        storage.saveAddTxt(body);
        return sendJson(res, { success: true, message: 'saved' });
      });
      return;
    }
  }

  if (url.pathname === '/admin/check') {
    if (!requireAdmin(req, res)) return;
    const raw = url.searchParams.get('socks5') || url.searchParams.get('http') || url.searchParams.get('https') || '';
    if (!raw) return sendJson(res, { success: false, error: 'missing proxy parameter' }, 400);
    const parsed = parseHostPortLoose(raw, url.searchParams.get('https') ? 443 : 1080);
    if (!parsed?.host || !parsed?.port) return sendJson(res, { success: false, error: 'invalid proxy address' }, 400);
    const ok = await checkTcpConnect(parsed.host, parsed.port, 4000);
    return sendJson(res, {
      success: ok,
      protocol: parsed.protocol || 'socks5',
      host: parsed.host,
      port: parsed.port,
      message: ok ? 'proxy reachable' : 'proxy unreachable'
    }, ok ? 200 : 503);
  }

  if (url.pathname === '/admin/getADDAPI') {
    if (!requireAdmin(req, res)) return;
    const apiUrl = url.searchParams.get('url') || '';
    const port = Number(url.searchParams.get('port') || 443);
    if (!apiUrl) return sendJson(res, { success: false, data: [], error: 'missing url' }, 400);
    try {
      const r = await axios.get(apiUrl, { timeout: 6000, responseType: 'text' });
      const lines = sub.normalizeLines(r.data).filter(line => !line.startsWith('#'));
      const parsed = lines.map(line => {
        const [addr, tag] = String(line).split('#');
        const hp = sub.parseHostPort(addr, port);
        if (!hp?.host) return null;
        return `${hp.host}:${hp.port}${tag ? `#${tag}` : ''}`;
      }).filter(Boolean);
      return sendJson(res, { success: true, data: parsed });
    } catch (e) {
      return sendJson(res, { success: false, data: [], error: e.message }, 500);
    }
  }

  if (url.pathname === '/admin/cf.json') {
    if (!requireAdmin(req, res)) return;
    if (req.method === 'GET') {
      return sendJson(res, {
        disabled: true,
        message: 'Cloudflare usage module is disabled in this build'
      });
    }
    return sendJson(res, {
      success: false,
      message: 'Cloudflare usage module is disabled in this build'
    }, 410);
  }

  if (url.pathname === '/admin/tg.json') {
    if (!requireAdmin(req, res)) return;
    if (req.method === 'GET') {
      return sendJson(res, {
        disabled: true,
        message: 'Telegram notify module is disabled in this build'
      });
    }
    return sendJson(res, {
      success: false,
      message: 'Telegram notify module is disabled in this build'
    }, 410);
  }

  if (url.pathname === '/admin/getCloudflareUsage') {
    if (!requireAdmin(req, res)) return;
    return sendJson(res, {
      success: false,
      message: 'Cloudflare usage module is disabled in this build'
    }, 410);
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found\n');
});

const wss = new WebSocket.Server({ server: httpServer });

wss.on('connection', (ws, req) => {
  const url = req.url || '';
  reloadConfig();
  const expectedPath = buildExpectedPath();
  if (!url.startsWith(expectedPath)) {
    ws.close();
    return;
  }

  ws.once('message', msg => {
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      const isVless = id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16));
      if (isVless) {
        if (!handleVlsConnection(ws, msg)) ws.close();
        return;
      }
    }

    if (msg.length >= 58 && handleTrojConnection(ws, msg)) return;
    if (msg.length > 0 && (msg[0] === 0x01 || msg[0] === 0x03 || msg[0] === 0x04) && handleSsConnection(ws, msg)) return;

    ws.close();
  }).on('error', () => {});
});

httpServer.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
