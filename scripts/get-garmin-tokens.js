#!/usr/bin/env node
/**
 * Run this script ONCE locally to get long-lived Garmin OAuth tokens.
 * Supports accounts with MFA (email verification code) enabled.
 * Works on Mac, Linux, and Windows.
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

// ── Extract hidden input value from HTML ─────────────────────────────────────
function extractInput(html, name) {
  // Matches <input ... name="foo" ... value="bar"> in any attribute order
  const re = new RegExp(`<input[^>]+name=["']?${name}["']?[^>]*>`, 'i');
  const el = html.match(re);
  if (!el) return null;
  const val = el[0].match(/value=["']([^"']*)/i);
  return val ? val[1] : null;
}

// ── Full manual SSO login (handles MFA inline, before any failure) ───────────
async function ssoLogin(axiosInst, username, password) {
  const SSO = 'https://sso.garmin.com/sso';
  const QS = [
    'service=https%3A%2F%2Fconnect.garmin.com%2Fmodern%2F',
    'webhost=https%3A%2F%2Fconnect.garmin.com',
    'source=https%3A%2F%2Fconnect.garmin.com%2Fsignin',
    'redirectAfterAccountLoginUrl=https%3A%2F%2Fconnect.garmin.com%2Fmodern%2F',
    'redirectAfterAccountCreationUrl=https%3A%2F%2Fconnect.garmin.com%2Fmodern%2F',
    'gauthHost=https%3A%2F%2Fsso.garmin.com%2Fsso',
    'locale=en_US',
    'id=gauth-widget',
    'clientId=GarminConnect',
    'initialFocus=true',
    'embedWidget=false',
    'generateExtraServiceTicket=true',
    'generateTwoExtraServiceTickets=false',
    'generateNoServiceTicket=false',
    'connectLegalTerms=true',
  ].join('&');

  const signinUrl = `${SSO}/signin?${QS}`;
  const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';

  // Step 1: GET signin page — establishes session cookies + gets CSRF
  const page1 = await axiosInst.get(signinUrl, { headers: { 'User-Agent': UA } });
  const html1 = page1.data;

  const csrf1      = extractInput(html1, '_csrf');
  const lt         = extractInput(html1, 'lt');
  const execution  = extractInput(html1, 'execution');

  // Step 2: POST credentials
  const loginBody = new URLSearchParams();
  loginBody.set('username', username);
  loginBody.set('password', password);
  loginBody.set('embed', 'true');
  loginBody.set('_eventId', 'submit');
  loginBody.set('displayNameRequired', 'false');
  if (csrf1)     loginBody.set('_csrf', csrf1);
  if (lt)        loginBody.set('lt', lt);
  if (execution) loginBody.set('execution', execution);

  const page2 = await axiosInst.post(signinUrl, loginBody.toString(), {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Origin: 'https://sso.garmin.com',
      Referer: signinUrl,
      'User-Agent': UA,
    },
    maxRedirects: 5,
  });

  const html2 = typeof page2.data === 'string' ? page2.data : '';

  // Success without MFA — ticket in response
  const ticket2 = html2.match(/ticket=([^"&\s]+)/);
  if (ticket2) return ticket2[1];

  // Check for MFA page
  const isMfa = /MFA|verif|enter.*code|email.*code/i.test(html2);
  if (!isMfa) {
    throw new Error(
      'Login failed — please check your email and password.\n' +
      'If correct, Garmin may be rate-limiting your account. Wait 1-2 hours and try again.'
    );
  }

  // Step 3: MFA — we are still in the same session, so the code will be accepted
  console.log('  MFA required — check your email, a new code was just sent...');
  const csrf2   = extractInput(html2, '_csrf');
  const mfaCode = await prompt('\n📧  Enter the code from your email: ');
  if (!mfaCode) throw new Error('No code entered.');

  const mfaBody = new URLSearchParams();
  mfaBody.set('mfa', mfaCode.trim());
  mfaBody.set('embed', 'true');
  mfaBody.set('_eventId', 'submit');
  if (csrf2) mfaBody.set('_csrf', csrf2);

  const page3 = await axiosInst.post(
    `${SSO}/verifyMFA/loginEnterMfaCode`,
    mfaBody.toString(),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Origin: 'https://sso.garmin.com',
        Referer: signinUrl,
        'User-Agent': UA,
      },
      maxRedirects: 10,
    }
  );

  const html3 = typeof page3.data === 'string' ? page3.data : '';
  const ticket3 = html3.match(/ticket=([^"&\s]+)/);
  if (!ticket3) {
    throw new Error(
      'MFA code rejected or expired.\n' +
      '  • Make sure you enter the code that arrived AFTER starting the script\n' +
      '  • Enter it quickly — codes expire in ~5 minutes'
    );
  }

  return ticket3[1];
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

  // Create client to get its internal axios instance (already has cookie support)
  const client = new GarminConnect({ username: user, password: pass });
  const httpClient = client.client;
  const axiosInst = httpClient?.client;

  if (!axiosInst) {
    console.error('❌  Could not access internal HTTP client. Try updating garmin-connect: npm install garmin-connect@latest');
    process.exit(1);
  }

  let ticket;
  try {
    ticket = await ssoLogin(axiosInst, user, pass);
    console.log('  Login successful ✓');
  } catch (err) {
    console.error('\n❌ ', err.message);
    process.exit(1);
  }

  // Exchange ticket for OAuth tokens using garmin-connect internals
  try {
    const oauth1 = await httpClient.getOauth1Token(ticket);
    await httpClient.exchange(oauth1);
  } catch (err) {
    console.error('\n❌  Failed to exchange ticket for tokens:', err.message);
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
