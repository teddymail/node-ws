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
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];

function reloadConfig() {
  config = storage.loadConfig();
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
        if (inputPassword === adminPassword) {
          const auth = storage.createSession(UA, config);
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
    return sendText(res, base64Content);
  }

  if (url.pathname === '/admin') {
    if (!requireAdmin(req, res)) return;
    const html = fs.existsSync(path.join(__dirname, 'admin.html'))
      ? fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8')
      : `<html><body><h1>Admin</h1></body></html>`;
    return sendHtml(res, html);
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
    if (req.method === 'GET') return sendJson(res, storage.loadConfig());
    if (req.method === 'POST') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        try {
          const newConfig = JSON.parse(body);
          storage.saveConfig(newConfig);
          return sendJson(res, { success: true, message: 'saved' });
        } catch (e) {
          return sendJson(res, { success: false, error: e.message }, 400);
        }
      });
      return;
    }
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
    return sendJson(res, { success: true, message: 'ok' });
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
