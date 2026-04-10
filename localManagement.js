const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const LOG_FILE = path.join(DATA_DIR, 'log.json');
const ADD_FILE = path.join(DATA_DIR, 'ADD.txt');

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function ensureFile(filePath, defaultContent) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, defaultContent, 'utf8');
  }
}

function initStorage() {
  ensureDir();

  ensureFile(CONFIG_FILE, JSON.stringify({
    adminPassword: 'change-me',
    uuid: '5efabea4-f6d4-91fd-b8f0-17e004c89c60',
    domain: '',
    path: '/ws',
    subPath: '/sub',
    name: '',
    autoAccess: false,
    fingerprint: 'chrome',
    transport: 'ws',
    tls: true,
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
  }, null, 2));

  ensureFile(LOG_FILE, '[]');
  ensureFile(ADD_FILE, '');
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
  return readJson(CONFIG_FILE, {});
}

function saveConfig(config) {
  initStorage();
  writeJson(CONFIG_FILE, config);
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

function authCookieValue(userAgent, secret, password) {
  return md5md5(String(userAgent || '') + String(secret || '') + String(password || ''));
}

function getAdminPassword(config) {
  return config.adminPassword || process.env.ADMIN || process.env.PASSWORD || process.env.KEY || 'change-me';
}

function getAdminSecret(config) {
  return config.adminSecret || process.env.ADMIN_SECRET || process.env.KEY || 'local-secret';
}

function createSession(userAgent, config) {
  return authCookieValue(userAgent, getAdminSecret(config), getAdminPassword(config));
}

function verifySession(cookieValue, userAgent, config) {
  return cookieValue && cookieValue === createSession(userAgent, config);
}

module.exports = {
  DATA_DIR,
  CONFIG_FILE,
  LOG_FILE,
  ADD_FILE,
  initStorage,
  loadConfig,
  saveConfig,
  loadLogs,
  saveLogs,
  appendLog,
  loadAddTxt,
  saveAddTxt,
  md5md5,
  maskSensitive,
  getAdminPassword,
  getAdminSecret,
  createSession,
  verifySession,
};
