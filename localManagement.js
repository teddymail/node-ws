const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CONFIG_FILE = process.env.CONFIG_FILE || path.join(__dirname, 'config.json');
const LOG_FILE = process.env.LOG_FILE || path.join(__dirname, 'log.json');
const ADD_FILE = process.env.ADD_FILE || path.join(__dirname, 'ADD.txt');
const TOKEN_FILE = process.env.TOKEN_FILE || path.join(__dirname, 'subtoken.txt');

function ensureFile(filePath, defaultContent) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, defaultContent, 'utf8');
  }
}

function defaultConfig() {
  const defaultDomain = process.env.DOMAIN || '';
  return {
    adminPassword: process.env.ADMIN || process.env.PASSWORD || 'CHANGE_ME_ADMIN_PASSWORD',
    adminSecret: process.env.ADMIN_SECRET || process.env.KEY || 'CHANGE_ME_ADMIN_SECRET',
    uuid: process.env.UUID || '5efabea4-f6d4-91fd-b8f0-17e004c89c60',
    domain: defaultDomain,
    path: process.env.WSPATH ? `/${process.env.WSPATH}` : '/ws',
    subPath: process.env.SUB_PATH || 'sub',
    subToken: process.env.SUB_TOKEN || '',
    name: process.env.NAME || '',
    sni: process.env.SNI || process.env.DOMAIN || defaultDomain,
    hostHeader: process.env.HOST_HEADER || process.env.DOMAIN || defaultDomain,
    fingerprint: 'chrome',
    transport: 'ws',
    tls: Boolean(process.env.DOMAIN || defaultDomain),
    enableEch: false,
    enableGrpc: false,
    enableXhttp: false,
    subscription: {
      subconverter: '',
      bestSubGenerator: '',
      randomIpCount: 4,
      token: process.env.SUB_TOKEN || ''
    },
    proxy: {
      enabled: false,
      global: false,
      mode: 'socks5',
      account: '',
      whitelist: []
    }
  };
}

function initStorage() {
  ensureFile(CONFIG_FILE, JSON.stringify(defaultConfig(), null, 2));
  ensureFile(LOG_FILE, '[]');
  ensureFile(ADD_FILE, '');
  ensureFile(TOKEN_FILE, '');
}

function readJson(filePath, fallback) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8').trim();
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2), 'utf8');
}

function readText(filePath, fallback = '') {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return fallback;
  }
}

function writeText(filePath, text) {
  fs.writeFileSync(filePath, text, 'utf8');
}

function loadConfig() {
  initStorage();
  const cfg = readJson(CONFIG_FILE, defaultConfig());
  return { ...defaultConfig(), ...cfg };
}

function saveConfig(config) {
  initStorage();
  writeJson(CONFIG_FILE, { ...defaultConfig(), ...config });
}

function loadLogs() {
  initStorage();
  return readJson(LOG_FILE, []);
}

function saveLogs(logs) {
  initStorage();
  writeJson(LOG_FILE, logs);
}

function appendLog(entry) {
  const logs = loadLogs();
  logs.push(entry);
  while (logs.length > 1000) logs.shift();
  saveLogs(logs);
}

function loadAddTxt() {
  initStorage();
  return readText(ADD_FILE, '');
}

function saveAddTxt(text) {
  initStorage();
  writeText(ADD_FILE, text);
}

function loadSubToken() {
  initStorage();
  return readText(TOKEN_FILE, '').trim();
}

function saveSubToken(token) {
  initStorage();
  writeText(TOKEN_FILE, String(token || '').trim());
}

function md5md5(text) {
  const first = crypto.createHash('md5').update(String(text)).digest('hex');
  const second = crypto.createHash('md5').update(first.slice(7, 27)).digest('hex');
  return second.toLowerCase();
}

function maskSensitive(text, prefix = 3, suffix = 2) {
  if (!text || typeof text !== 'string') return text;
  if (text.length <= prefix + suffix) return text;
  return text.slice(0, prefix) + '*'.repeat(text.length - prefix - suffix) + text.slice(-suffix);
}

function getAdminPassword(config) {
  return process.env.ADMIN || process.env.PASSWORD || config.adminPassword || process.env.KEY || 'CHANGE_ME_ADMIN_PASSWORD';
}

function getAdminSecret(config) {
  return process.env.ADMIN_SECRET || config.adminSecret || process.env.KEY || 'CHANGE_ME_ADMIN_SECRET';
}

function createSession(userAgent, config) {
  return md5md5(String(userAgent || '') + getAdminSecret(config) + getAdminPassword(config));
}

function verifySession(cookieValue, userAgent, config) {
  return cookieValue && cookieValue === createSession(userAgent, config);
}

module.exports = {
  CONFIG_FILE,
  LOG_FILE,
  ADD_FILE,
  TOKEN_FILE,
  initStorage,
  defaultConfig,
  loadConfig,
  saveConfig,
  loadLogs,
  saveLogs,
  appendLog,
  loadAddTxt,
  saveAddTxt,
  loadSubToken,
  saveSubToken,
  md5md5,
  maskSensitive,
  getAdminPassword,
  getAdminSecret,
  createSession,
  verifySession,
};
