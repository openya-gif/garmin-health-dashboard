/**
 * Push subscription store — persists to /tmp on Vercel.
 *
 * Why /tmp?
 *  Vercel serverless functions can write to /tmp. It's ephemeral across
 *  cold starts but persists within the same container session — much more
 *  reliable than a pure in-memory variable for the cron-check use case.
 *
 *  For full persistence across cold starts, replace with @vercel/kv.
 */

import * as fs   from 'fs';
import * as path from 'path';
import type { PushSubscription as WebPushSubscription } from 'web-push';

const STORE_PATH = '/tmp/garmin_push_store.json';

export interface StoredPushData {
  subscription: WebPushSubscription;
  threshold:    number;
  lastSentAt:   number;
}

/** Cooldown: don't send another notification within this window (ms). */
const COOLDOWN_MS = 3 * 60 * 60 * 1000; // 3 hours

// In-memory cache for fast reads within the same invocation
let memCache: StoredPushData | null = null;

function readStore(): StoredPushData | null {
  if (memCache) return memCache;
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf8');
    memCache = JSON.parse(raw) as StoredPushData;
    return memCache;
  } catch {
    return null;
  }
}

function writeStore(data: StoredPushData): void {
  memCache = data;
  try {
    fs.mkdirSync(path.dirname(STORE_PATH), { recursive: true });
    fs.writeFileSync(STORE_PATH, JSON.stringify(data), 'utf8');
  } catch {
    // /tmp not writable in some environments — in-memory fallback still works
  }
}

export function saveSubscription(sub: WebPushSubscription, threshold: number): void {
  const existing = readStore();
  writeStore({
    subscription: sub,
    threshold,
    lastSentAt: existing?.lastSentAt ?? 0,
  });
}

export function getStoredSubscription(): StoredPushData | null {
  return readStore();
}

export function markSent(): void {
  const existing = readStore();
  if (existing) writeStore({ ...existing, lastSentAt: Date.now() });
}

export function isCoolingDown(): boolean {
  const store = readStore();
  if (!store) return false;
  return Date.now() - store.lastSentAt < COOLDOWN_MS;
}

export function clearSubscription(): void {
  memCache = null;
  try { fs.unlinkSync(STORE_PATH); } catch { /* ignore */ }
}
