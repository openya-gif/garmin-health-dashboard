#!/usr/bin/env node
/**
 * Run this script ONCE locally to get long-lived Garmin OAuth tokens.
 * Supports accounts with MFA (email verification code) enabled.
 * Works on Mac, Linux, and Windows.
 *
 * Inspired by garth (https://github.com/matin/garth) — uses Garmin's mobile
 * JSON API instead of HTML form scraping, which makes MFA handling reliable.
 *
 * Usage:
 *   node scripts/get-garmin-tokens.js
 */

const readline = require('readline');

// ── Load .env.local ──────────────────────────────────────────────────────────
try {
  const fs = require('fs');
  const envPath = require('path').join(__dirname, '..', '.env.local');
  if (fs.existsSync(envPath)) {
    fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
      const m = line.match(/^([^#=]+)=(.*)$/);
      if (m) process.env[m[1].trim()] = m[2].trim().replace(/^["']|["']$/g, '');
    });
  }
} catch (_) { /* ignore */ }

// ── Prompt helper ────────────────────────────────────────────────────────────
async function prompt(question, hidden = false) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  if (hidden && process.stdout.isTTY) {
    process.stdout.write(question);
    process.stdin.setRawMode(true);
    return new Promise(resolve => {
      let input = '';
      process.stdin.on('data', (ch) => {
        ch = ch.toString();
        if (ch === '\r' || ch === '\n') {
          process.stdin.setRawMode(false);
          process.stdout.write('\n');
          rl.close();
          resolve(input);
        } else if (ch === '\u0003') {
          process.exit();
        } else if (ch === '\u007f') {
          input = input.slice(0, -1);
        } else {
          input += ch;
        }
      });
      process.stdin.resume();
    });
  }
  return new Promise(resolve => rl.question(question, ans => { rl.close(); resolve(ans.trim()); }));
}

// ── Garmin mobile API login (garth-inspired approach) ────────────────────────
// Uses Garmin's JSON mobile API instead of HTML form scraping.
// Endpoints and response structure from https://github.com/matin/garth
// Uses its own cookie jar (tough-cookie) so SSO session is always preserved.
async function loginWithMobileApi(username, password) {
  const axios = require('axios');
  const { CookieJar } = require('tough-cookie');

  const SSO     = 'https://sso.garmin.com';
  const SERVICE = 'https://mobile.integration.garmin.com/gcm/android';
  const CLIENT  = 'GCM_ANDROID_DARK';
  const SSO_UA  = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148';
  const BASE_HEADERS = {
    'User-Agent': SSO_UA,
    'Accept': 'application/json, text/html, */*',
    'Accept-Language': 'en-US,en;q=0.9',
  };
  const LOGIN_PARAMS = `clientId=${CLIENT}&locale=en-US&service=${encodeURIComponent(SERVICE)}`;

  // Own cookie jar — completely independent of garmin-connect's session
  const jar = new CookieJar();

  // Helper: GET or POST with automatic cookie send/receive
  async function req(method, url, { params, body, extraHeaders } = {}) {
    const fullUrl = params ? `${url}?${params}` : url;
    const cookies = await jar.getCookies(fullUrl);
    const cookieHeader = cookies.map(c => `${c.key}=${c.value}`).join('; ');

    const resp = await axios({
      method,
      url: fullUrl,
      data: body,
      headers: {
        ...BASE_HEADERS,
        ...(cookieHeader ? { Cookie: cookieHeader } : {}),
        ...(extraHeaders || {}),
      },
      validateStatus: (s) => s < 500,
      maxRedirects: 5,
    });

    // Store any new cookies from response
    const setCookies = resp.headers['set-cookie'] || [];
    for (const c of setCookies) {
      await jar.setCookie(c, fullUrl).catch(() => {});
    }

    return resp;
  }

  // Step 1: GET sign-in page — establishes session cookies
  await req('GET', `${SSO}/mobile/sso/en/sign-in`, { params: `clientId=${CLIENT}` });

  // Step 2: POST credentials as JSON
  const loginResp = await req('POST', `${SSO}/mobile/api/login`, {
    params: LOGIN_PARAMS,
    body: JSON.stringify({ username, password, rememberMe: false, captchaToken: '' }),
    extraHeaders: { 'Content-Type': 'application/json' },
  });

  const loginData = loginResp.data;
  const status = loginData?.responseStatus?.type || loginData?.type;

  if (!status) {
    throw new Error(
      'Unexpected response from Garmin. Check your email and password.\n' +
      'If correct, Garmin may be rate-limiting your account — wait 1-2 hours and try again.\n' +
      `(Raw response: ${JSON.stringify(loginData).slice(0, 200)})`
    );
  }

  // Step 3: Handle MFA if required
  if (status === 'MFA_REQUIRED') {
    const method = loginData?.customerMfaInfo?.mfaLastMethodUsed || 'email';
    console.log(`  MFA required (${method}) — a new code was sent to your email...`);

    const mfaCode = await prompt('\n📧  Enter the code from your email: ');
    if (!mfaCode) throw new Error('No code entered.');

    const mfaResp = await req('POST', `${SSO}/mobile/api/mfa/verifyCode`, {
      params: LOGIN_PARAMS,
      body: JSON.stringify({
        mfaMethod: method,
        mfaVerificationCode: mfaCode.trim(),
        rememberMyBrowser: false,
        reconsentList: [],
        mfaSetup: false,
      }),
      extraHeaders: { 'Content-Type': 'application/json' },
    });

    const mfaData = mfaResp.data;
    const mfaStatus = mfaData?.responseStatus?.type || mfaData?.type;
    if (mfaStatus !== 'SUCCESSFUL') {
      throw new Error(
        `MFA failed (${mfaStatus || 'unknown'}).\n` +
        '  • Use the code that arrived AFTER starting the script\n' +
        '  • Codes expire in ~5 minutes — run the script again if needed'
      );
    }
    return mfaData.serviceTicketId || mfaData.serviceTicketUrl || null;
  }

  if (status !== 'SUCCESSFUL') {
    throw new Error(`Login failed (${status}). Check your email and password.`);
  }

  return loginData.serviceTicketId || loginData.serviceTicketUrl || null;
}

// ── Save tokens to Vercel ────────────────────────────────────────────────────
function addVercelEnv(name, value, cwd) {
  const { execFileSync } = require('child_process');
  const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  execFileSync(npx, ['vercel', 'env', 'add', name, 'production', '--force'], {
    input: value + '\n',
    stdio: ['pipe', 'inherit', 'inherit'],
    cwd,
  });
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const { GarminConnect } = require('garmin-connect');

  let user = process.env.GARMIN_USERNAME;
  let pass = process.env.GARMIN_PASSWORD;

  if (!user) user = await prompt('Garmin username (email): ');
  if (!pass) pass = await prompt('Garmin password: ', true);

  if (!user || !pass) {
    console.error('❌  Username and password are required');
    process.exit(1);
  }

  console.log(`\n🔐  Logging in as ${user}...`);

  // Use garmin-connect's internal axios instance (already has cookie support)
  const client = new GarminConnect({ username: user, password: pass });
  const httpClient = client.client;
  const axiosInst = httpClient?.client;

  if (!axiosInst) {
    console.error('❌  Could not access internal HTTP client.');
    process.exit(1);
  }

  let serviceTicketUrl;
  try {
    serviceTicketUrl = await loginWithMobileApi(user, pass);
    console.log('  Login successful ✓');
  } catch (err) {
    console.error('\n❌ ', err.message);
    process.exit(1);
  }

  // serviceTicketUrl is either a bare ticket string or a URL containing ticket=
  let ticket;
  try {
    if (serviceTicketUrl) {
      const inUrl = String(serviceTicketUrl).match(/ticket=([^&\s"]+)/);
      ticket = inUrl ? inUrl[1] : String(serviceTicketUrl).trim();
    }

    if (ticket) {
      await httpClient.getOauth1Token(ticket);
      await httpClient.exchange(httpClient.oauth1Token);
    } else {
      // Fallback: standard garmin-connect login (no MFA)
      await client.login();
    }
  } catch (err) {
    console.error('\n❌  Failed to obtain OAuth tokens:', err.message);
    process.exit(1);
  }

  const oauth1 = httpClient.oauth1Token;
  const oauth2 = httpClient.oauth2Token;

  if (!oauth1 || !oauth2) {
    console.error('❌  Could not extract OAuth tokens. Try again.');
    process.exit(1);
  }

  const o1 = JSON.stringify(oauth1);
  const o2 = JSON.stringify(oauth2);

  console.log('\n✅  Tokens obtained!\n');

  // ── Save to Vercel ───────────────────────────────────────────────────────
  const cwd = require('path').join(__dirname, '..');
  const { execFileSync } = require('child_process');
  const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';

  try {
    console.log('Adding GARMIN_OAUTH1 to Vercel...');
    addVercelEnv('GARMIN_OAUTH1', o1, cwd);
    console.log('Adding GARMIN_OAUTH2 to Vercel...');
    addVercelEnv('GARMIN_OAUTH2', o2, cwd);
    console.log('\n✅  Tokens added to Vercel!');
    console.log('⚠️   Tokens expire in ~90 days — re-run this script when they do.\n');
    console.log('Deploying...');
    execFileSync(npx, ['vercel', '--prod'], { stdio: 'inherit', cwd });
    console.log('\n🎉  Done! Your dashboard should now show real Garmin data.\n');
  } catch (_) {
    console.log('\n⚠️  Could not save to Vercel automatically.');
    console.log('Add these manually in Vercel → Project → Settings → Environment Variables:\n');
    console.log('  Name:  GARMIN_OAUTH1');
    console.log('  Value:', o1);
    console.log('\n  Name:  GARMIN_OAUTH2');
    console.log('  Value:', o2);
    console.log('\nThen go to Vercel → Deployments → Redeploy.\n');
  }
}

main().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
