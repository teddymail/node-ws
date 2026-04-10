const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function request({ port, path, method = 'GET', headers = {}, body = '' }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, res => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', chunk => (data += chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

(async () => {
  const port = 18765;
  const configPath = path.join(__dirname, '..', 'config.json');
  let adminPassword = 'yk123mm2008';
  try {
    const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    if (cfg && typeof cfg.adminPassword === 'string' && cfg.adminPassword.trim()) {
      adminPassword = cfg.adminPassword;
    }
  } catch {}

  const env = {
    ...process.env,
    PORT: String(port),
    DOMAIN: '',
    SUB_PATH: 'sub',
    ADMIN: adminPassword,
    ADMIN_SECRET: 'smoke-test-secret',
  };

  const child = spawn(process.execPath, ['index.js'], {
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let booted = false;
  child.stdout.on('data', chunk => {
    const line = String(chunk);
    if (line.includes('Server is running on port')) booted = true;
  });

  child.stderr.on('data', chunk => {
    process.stderr.write(String(chunk));
  });

  try {
    for (let i = 0; i < 30; i++) {
      if (booted) break;
      await sleep(200);
    }
    if (!booted) throw new Error('server did not start in time');

    const subRes = await request({ port, path: '/sub' });
    if (subRes.status !== 200) throw new Error(`/sub status=${subRes.status}`);
    if (!/^[A-Za-z0-9+/=\n]+$/.test(subRes.body)) throw new Error('/sub did not return base64 text');

    const adminRes = await request({ port, path: '/admin' });
    if (adminRes.status !== 302) throw new Error(`/admin should redirect before login, got ${adminRes.status}`);

    const loginBody = 'password=' + encodeURIComponent(adminPassword);
    const loginRes = await request({
      port,
      path: '/login',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(loginBody),
      },
      body: loginBody,
    });

    if (loginRes.status !== 200) throw new Error(`/login status=${loginRes.status}`);
    if (!String(loginRes.headers['set-cookie'] || '').includes('auth=')) {
      throw new Error('/login did not set auth cookie');
    }

    console.log('smoke test passed');
  } finally {
    child.kill('SIGTERM');
  }
})().catch(err => {
  console.error(err.message || err);
  process.exit(1);
});


