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
    const isRateLimit =
      loginResp.status === 429 ||
      JSON.stringify(loginData).includes('"429"') ||
      JSON.stringify(loginData).includes("429");
    if (isRateLimit) {
      throw new Error(
        'Garmin is blocking your account due to too many failed attempts (rate limit 429).\n' +
        '  • Wait 24–48 hours before trying again\n' +
        '  • Try from a different Wi-Fi network or mobile hotspot\n' +
        '  • Do NOT run the script again until the wait period is over\n' +
        `(Raw response: ${JSON.stringify(loginData).slice(0, 200)})`
      );
    }
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

// ── OAuth1→OAuth2 exchange (garth approach) ──────────────────────────────────
// Fetches the consumer key from Garmin's S3 bucket (same as garth does) and
// performs the OAuth1 preauth + OAuth2 exchange using oauth-1.0a.
async function exchangeTicketForTokens(ticket) {
  const axios  = require('axios');
  const OAuth  = require('oauth-1.0a');
  const crypto = require('crypto');

  const CONNECT_API = 'https://connectapi.garmin.com';
  const MOBILE_UA   = 'com.garmin.android.apps.connectmobile';
  const LOGIN_URL   = 'https://mobile.integration.garmin.com/gcm/android';

  // Step 4a: fetch consumer key/secret from garth's S3 bucket
  const consumerResp = await axios.get('https://thegarth.s3.amazonaws.com/oauth_consumer.json');
  const { consumer_key, consumer_secret } = consumerResp.data;

  // Step 4b: GET OAuth1 preauthorized token using consumer-only OAuth1 signature
  const oauth = OAuth({
    consumer: { key: consumer_key, secret: consumer_secret },
    signature_method: 'HMAC-SHA1',
    hash_function: (base, key) =>
      crypto.createHmac('sha1', key).update(base).digest('base64'),
  });

  const preAuthUrl = `${CONNECT_API}/oauth-service/oauth/preauthorized`;
  const preAuthParams = {
    ticket,
    'login-url': LOGIN_URL,
    'accepts-mfa-tokens': 'true',
  };
  const fullPreAuthUrl = `${preAuthUrl}?${new URLSearchParams(preAuthParams)}`;

  const preAuthHeader = oauth.toHeader(
    oauth.authorize({ url: fullPreAuthUrl, method: 'GET' })
  );

  const preAuthResp = await axios.get(fullPreAuthUrl, {
    headers: { ...preAuthHeader, 'User-Agent': MOBILE_UA },
    validateStatus: () => true,
  });

  if (preAuthResp.status !== 200) {
    throw new Error(
      `OAuth preauth failed (HTTP ${preAuthResp.status}).\n` +
      `  Ticket used: ${ticket}\n` +
      `  Response: ${JSON.stringify(preAuthResp.data).slice(0, 300)}`
    );
  }

  // Response is URL-encoded: oauth_token=...&oauth_token_secret=...&mfa_token=...
  const preAuthData = new URLSearchParams(preAuthResp.data);
  const oauth1Token = {
    oauth_token:        preAuthData.get('oauth_token'),
    oauth_token_secret: preAuthData.get('oauth_token_secret'),
    mfa_token:          preAuthData.get('mfa_token') || undefined,
  };

  if (!oauth1Token.oauth_token) {
    throw new Error(
      `OAuth preauth returned no token.\n` +
      `  Raw response: ${String(preAuthResp.data).slice(0, 300)}`
    );
  }

  // Step 5: exchange OAuth1 → OAuth2
  const exchangeUrl = `${CONNECT_API}/oauth-service/oauth/exchange/user/2.0`;

  // Body params must be passed to oauth.authorize() so they're included in the signature
  const exchangeBodyData = { audience: 'GARMIN_CONNECT_MOBILE_ANDROID_DI' };
  if (oauth1Token.mfa_token) exchangeBodyData.mfa_token = oauth1Token.mfa_token;

  const exchangeHeader = oauth.toHeader(
    oauth.authorize(
      { url: exchangeUrl, method: 'POST', data: exchangeBodyData },
      { key: oauth1Token.oauth_token, secret: oauth1Token.oauth_token_secret }
    )
  );

  const exchangeBody = new URLSearchParams(exchangeBodyData);

  const exchangeResp = await axios.post(exchangeUrl, exchangeBody.toString(), {
    headers: {
      ...exchangeHeader,
      'User-Agent': MOBILE_UA,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    validateStatus: () => true,
  });

  if (exchangeResp.status !== 200) {
    throw new Error(
      `OAuth exchange failed (HTTP ${exchangeResp.status}).\n` +
      `  Response: ${JSON.stringify(exchangeResp.data).slice(0, 300)}`
    );
  }

  const oauth2Token = exchangeResp.data;
  return { oauth1Token, oauth2Token };
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

  // Extract bare ticket from serviceTicketId (may be a plain string or contain ticket=)
  const ticketStr = serviceTicketUrl
    ? (String(serviceTicketUrl).match(/ticket=([^&\s"]+)/)?.[1] ?? String(serviceTicketUrl).trim())
    : null;

  let oauth1, oauth2;
  try {
    if (ticketStr) {
      // MFA path: use garth-style OAuth exchange with consumer key from S3
      const tokens = await exchangeTicketForTokens(ticketStr);
      oauth1 = tokens.oauth1Token;
      oauth2 = tokens.oauth2Token;
    } else {
      // No MFA: fall back to garmin-connect standard login
      await client.login();
      oauth1 = httpClient.oauth1Token;
      oauth2 = httpClient.oauth2Token;
    }
  } catch (err) {
    console.error('\n❌  Failed to obtain OAuth tokens:', err.message);
    process.exit(1);
  }

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
