#!/usr/bin/env node

const os = require('os');
const http = require('http');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const net = require('net');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');

const storage = require('./localManagement');
const sub = require('./subscription');

storage.initStorage();

const config = storage.loadConfig();
const UUID = process.env.UUID || config.uuid || '5efabea4-f6d4-91fd-b8f0-17e004c89c60';
const DOMAIN = process.env.DOMAIN || config.domain || '';
const WSPATH = process.env.WSPATH || config.path?.replace(/^\//, '') || UUID.slice(0, 8);
const SUB_PATH = process.env.SUB_PATH || config.subPath || 'sub';
const NAME = process.env.NAME || config.name || '';
const PORT = process.env.PORT || 3000;

let uuid = UUID.replace(/-/g, '');
let CurrentDomain = DOMAIN;
let Tls = DOMAIN ? 'tls' : 'none';
let CurrentPort = DOMAIN ? 443 : PORT;
let ISP = '';

const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
  'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
];

function isBlockedDomain(host) {
  if (!host) return false;
  const hostLower = host.toLowerCase();
  return BLOCKED_DOMAINS.some(blocked => hostLower === blocked || hostLower.endsWith('.' + blocked));
}

async function getisp() {
  ISP = await sub.getISP();
}

async function getip() {
  if (!DOMAIN) {
    try {
      const ip = await sub.getPublicIP();
      CurrentDomain = ip;
      Tls = 'none';
      CurrentPort = PORT;
    } catch (e) {
      CurrentDomain = 'change-your-domain.com';
      Tls = 'tls';
      CurrentPort = 443;
    }
  } else {
    CurrentDomain = DOMAIN;
    Tls = 'tls';
    CurrentPort = 443;
  }
}

function readHtml(name, fallback) {
  const filePath = path.join(__dirname, name);
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return fallback;
  }
}

function sendHtml(res, html) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function sendJson(res, obj, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj, null, 2));
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

function getClientIP(req) {
  return req.headers['x-real-ip'] ||
    req.headers['cf-connecting-ip'] ||
    req.headers['x-forwarded-for'] ||
    req.headers['true-client-ip'] ||
    req.socket.remoteAddress ||
    '';
}

function adminAuth(req) {
  const configNow = storage.loadConfig();
  const ua = req.headers['user-agent'] || 'null';
  const cookie = parseCookies(req).auth;
  return storage.verifySession(cookie, ua, configNow);
}

function requireAdmin(req, res) {
  if (!adminAuth(req)) {
    res.writeHead(302, { Location: '/login' });
    res.end('Redirecting...');
    return false;
  }
  return true;
}

const httpServer = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const UA = req.headers['user-agent'] || 'null';
  const pathLower = url.pathname.toLowerCase();

  if (url.pathname === '/login') {
    if (req.method === 'GET') {
      return sendHtml(res, readHtml('login.html', `
        <!doctype html><html><body>
        <form method="post"><input name="password" type="password" placeholder="Password">
        <button type="submit">Login</button></form>
        </body></html>`));
    }
    if (req.method === 'POST') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        const params = new URLSearchParams(body);
        const inputPassword = params.get('password') || '';
        const configNow = storage.loadConfig();
        const adminPassword = storage.getAdminPassword(configNow);
        if (inputPassword === adminPassword) {
          const auth = storage.createSession(UA, configNow);
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
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(content);
    } catch {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Hello world!');
    }
    return;
  }

  if (url.pathname === `/${SUB_PATH}`) {
    await getisp();
    await getip();
    const configNow = storage.loadConfig();
    const subBase64 = await sub.generateSubscription({
      uuid: configNow.uuid || UUID,
      domain: CurrentDomain,
      path: configNow.path || '/',
      name: configNow.name || '',
      port: CurrentPort,
    });
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(subBase64);
  }

  if (url.pathname === '/admin') {
    if (!requireAdmin(req, res)) return;
    return sendHtml(res, readHtml('admin.html', '<html><body><h1>Admin</h1></body></html>'));
  }

  if (url.pathname === '/admin/init') {
    if (!requireAdmin(req, res)) return;
    const defaults = {
      adminPassword: 'change-me',
      uuid: UUID,
      domain: DOMAIN,
      path: `/${WSPATH}`,
      subPath: SUB_PATH,
      name: NAME,
      autoAccess: false,
      fingerprint: 'chrome',
      transport: 'ws',
      tls: Boolean(DOMAIN),
      enableEch: false,
      enableGrpc: false,
      enableXhttp: false,
      subscription: {
        subconverter: '',
        bestSubGenerator: '',
        randomIpCount: 16
      },
      proxy: {
        enabled: false,
        global: false,
        mode: 'socks5',
        account: '',
        whitelist: []
      }
    };
    storage.saveConfig(defaults);
    storage.saveAddTxt('');
    storage.saveLogs([]);
    return sendJson(res, { success: true, message: 'configuration reset' });
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
    if (req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end(storage.loadAddTxt());
    }
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
    return sendJson(res, { success: true, message: 'proxy check endpoint available' });
  }

  if (url.pathname === `/${SUB_PATH}`) return;

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found\n');
});

// WebSocket / proxy part should stay here using your current logic.
// I’m keeping this file focused on the management and subscription layer,
// and you can merge your existing handleVlsConnection / handleTrojConnection / handleSsConnection logic below.

const getDownloadUrl = () => {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return 'https://arm64.ssss.nyc.mn/v1';
  }
  return 'https://amd64.ssss.nyc.mn/v1';
};

const downloadFile = async () => {
  const configNow = storage.loadConfig();
  if (!configNow.nezhaServer && !configNow.nezhaKey) return;
  try {
    const url = getDownloadUrl();
    const response = await axios({ method: 'get', url, responseType: 'stream' });
    const writer = fs.createWriteStream('npm');
    response.data.pipe(writer);
    return new Promise((resolve, reject) => {
      writer.on('finish', () => {
        exec('chmod +x npm', err => err ? reject(err) : resolve());
      });
      writer.on('error', reject);
    });
  } catch (err) {
    throw err;
  }
};

const runnz = async () => {
  const configNow = storage.loadConfig();
  if (!configNow.nezhaServer && !configNow.nezhaKey) return;
  try {
    const status = execSync('ps aux | grep -v \"grep\" | grep \"./[n]pm\"', { encoding: 'utf-8' });
    if (status.trim() !== '') return;
  } catch {}

  await downloadFile();
  let command = '';
  const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
  if (configNow.nezhaServer && configNow.nezhaPort && configNow.nezhaKey) {
    const NEZHA_TLS = tlsPorts.includes(String(configNow.nezhaPort)) ? '--tls' : '';
    command = `setsid nohup ./npm -s ${configNow.nezhaServer}:${configNow.nezhaPort} -p ${configNow.nezhaKey} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
  }
  if (command) exec(command, { shell: '/bin/bash' }, () => {});
};

const addAccessTask = async () => {
  const configNow = storage.loadConfig();
  if (!configNow.autoAccess || !configNow.domain) return;
  try {
    await axios.post('https://oooo.serv00.net/add-url', { url: `https://${configNow.domain}/${configNow.subPath || SUB_PATH}` }, {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch {}
};

const delFiles = () => {
  ['npm', 'config.yaml'].forEach(file => fs.unlink(file, () => {}));
};

httpServer.listen(PORT, () => {
  runnz();
  setTimeout(delFiles, 180000);
  addAccessTask();
  console.log(`Server is running on port ${PORT}`);
});
