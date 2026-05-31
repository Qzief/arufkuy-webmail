import type { Env, SessionData } from "../index";
import { decryptString, encryptString, sha256Hex } from "./crypto";

const SESSION_COOKIE = "wm_session";
const DAY_SECONDS = 86_400;

export async function createSession(env: Env, email: string, password: string, ip: string | null) {
  const sessionId = crypto.randomUUID().replace(/-/g, "");
  const now = Math.floor(Date.now() / 1000);
  const ttlDays = Number.parseInt(env.SESSION_TTL_DAYS || "", 10) || 7;
  const expiresAt = now + ttlDays * DAY_SECONDS;
  const encryptedPassword = await encryptString(password, env);
  const ipHash = ip ? await sha256Hex(ip) : null;

  await env.DB.prepare(
    `INSERT INTO sessions (session_id, email, encrypted_password, ip_hash, created_at, expires_at, last_seen_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`
  )
    .bind(sessionId, email, encryptedPassword, ipHash, now, expiresAt, now)
    .run();

  return {
    cookie: serializeSessionCookie(sessionId, expiresAt),
    sessionId,
  };
}

export async function destroySession(env: Env, sessionId: string | null) {
  if (!sessionId) {
    return;
  }
  await env.DB.prepare("DELETE FROM sessions WHERE session_id = ?1").bind(sessionId).run();
}

export async function requireSession(request: Request, env: Env): Promise<{ session: SessionData; password: string }> {
  const sessionId = getSessionIdFromCookie(request);
  if (!sessionId) {
    throw new Error("Sesi tidak ditemukan.");
  }

  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= ?1").bind(now).run();

  const row = await env.DB.prepare(
    `SELECT session_id, email, encrypted_password, ip_hash, created_at, expires_at, last_seen_at
     FROM sessions
     WHERE session_id = ?1`
  )
    .bind(sessionId)
    .first<{
      session_id: string;
      email: string;
      encrypted_password: string;
      ip_hash: string | null;
      created_at: number;
      expires_at: number;
      last_seen_at: number;
    }>();

  if (!row || row.expires_at <= now) {
    throw new Error("Sesi sudah berakhir.");
  }

  await env.DB.prepare("UPDATE sessions SET last_seen_at = ?2 WHERE session_id = ?1").bind(sessionId, now).run();

  const password = await decryptString(row.encrypted_password, env);

  return {
    session: {
      sessionId: row.session_id,
      email: row.email,
      encryptedPassword: row.encrypted_password,
      ipHash: row.ip_hash,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      lastSeenAt: now,
    },
    password,
  };
}

export function getLogoutCookie() {
  return `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

export async function consumeRateLimit(env: Env, key: string, limit: number, windowSeconds: number) {
  const now = Math.floor(Date.now() / 1000);
  const existing = await env.DB.prepare("SELECT count, reset_at FROM rate_limits WHERE bucket_key = ?1").bind(key).first<{
    count: number;
    reset_at: number;
  }>();

  if (!existing || existing.reset_at <= now) {
    await env.DB.prepare(
      "INSERT OR REPLACE INTO rate_limits (bucket_key, count, reset_at) VALUES (?1, 1, ?2)"
    )
      .bind(key, now + windowSeconds)
      .run();
    return;
  }

  if (existing.count >= limit) {
    throw new Error("Terlalu banyak percobaan. Coba lagi sebentar.");
  }

  await env.DB.prepare("UPDATE rate_limits SET count = count + 1 WHERE bucket_key = ?1").bind(key).run();
}

export async function buildRateKey(prefix: string, request: Request, sessionId?: string) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const base = sessionId ? `${prefix}:${sessionId}:${ip}` : `${prefix}:${ip}`;
  return sha256Hex(base);
}

function serializeSessionCookie(sessionId: string, expiresAt: number) {
  const maxAge = Math.max(expiresAt - Math.floor(Date.now() / 1000), 0);
  return `${SESSION_COOKIE}=${sessionId}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function getSessionIdFromCookie(request: Request): string | null {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = cookieHeader.split(";").map((part) => part.trim());
  for (const cookie of cookies) {
    if (cookie.startsWith(`${SESSION_COOKIE}=`)) {
      return cookie.slice(SESSION_COOKIE.length + 1);
    }
  }
  return null;
}
