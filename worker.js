/**
 * Email Inbox Worker (KV) + Smart OTP extraction
 * + Firebase ID Token auth (no npm, pure WebCrypto)
 *
 * Bindings:
 * - KV: INBOX_KV
 * Vars/Secrets:
 * - FB_PROJECT_ID  (ex: "webmail-arufkuy")
 */

const TTL_3_DAYS = 3 * 24 * 60 * 60; // 259200
const MAX_STORED_BYTES = 350_000;

// Email spam guard (per inbox)
const EMAIL_RATE_LIMIT_PER_MINUTE = 30; // ubah sesuai kebutuhan (0 untuk disable)

// -------------------- CORS / Responses --------------------
function corsHeaders(origin = "*") {
  return {
    "Access-Control-Allow-Origin": origin,
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Max-Age": "86400",
  };
}
function json(data, { status = 200, origin = "*" } = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      ...corsHeaders(origin),
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}
function textResp(body, { status = 200, origin = "*" } = {}) {
  return new Response(body, {
    status,
    headers: {
      ...corsHeaders(origin),
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

// -------------------- KV keys --------------------
function kvKeyMsg(user, id) {
  return `msg:${user}:${id}`;
}
function kvKeyIndex(user) {
  return `idx:${user}`;
}

// uid -> inboxUser mapping
function kvKeyAllow(uid) {
  return `allow:${uid}`;
}

// inboxUser allowlist (anti catch-all abuse)
function kvKeyAllowInboxUser(inboxUser) {
  return `allowInboxUser:${inboxUser}`;
}

// rate limiter bucket
function kvKeyRateInbox(user, minuteBucket) {
  return `rate:inbox:${user}:${minuteBucket}`;
}

const KV_LAST_EMAIL = "debug:last_email";

// -------------------- Base64URL helpers --------------------
function b64urlToUint8Array(b64url) {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function b64urlToString(b64url) {
  const bytes = b64urlToUint8Array(b64url);
  return new TextDecoder().decode(bytes);
}

// -------------------- Firebase ID token verification (RS256) --------------------
const FIREBASE_CERTS_URL =
  "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

let CERT_CACHE = {
  fetchedAt: 0,
  maxAge: 0,
  certsByKid: null, // {kid: pem}
};

function parseCacheControlMaxAge(cacheControl) {
  if (!cacheControl) return 0;
  const m = cacheControl.match(/max-age=(\d+)/i);
  return m ? parseInt(m[1], 10) : 0;
}

async function getFirebaseCerts() {
  const now = Date.now();
  if (
    CERT_CACHE.certsByKid &&
    CERT_CACHE.maxAge > 0 &&
    now - CERT_CACHE.fetchedAt < CERT_CACHE.maxAge * 1000
  ) {
    return CERT_CACHE.certsByKid;
  }

  const res = await fetch(FIREBASE_CERTS_URL, { cf: { cacheTtl: 3600 } });
  if (!res.ok) throw new Error("Failed to fetch Firebase certs");

  const cacheControl = res.headers.get("cache-control") || "";
  const maxAge = parseCacheControlMaxAge(cacheControl) || 3600;

  const certsByKid = await res.json();

  CERT_CACHE = {
    fetchedAt: now,
    maxAge,
    certsByKid,
  };

  return certsByKid;
}

function pemToDer(pem) {
  const clean = pem
    .replace("-----BEGIN CERTIFICATE-----", "")
    .replace("-----END CERTIFICATE-----", "")
    .replace(/\s+/g, "");
  return b64urlToUint8Array(clean.replace(/\+/g, "-").replace(/\//g, "_")).buffer;
}

async function importRsaPublicKeyFromCertPem(pem) {
  const der = pemToDer(pem);
  const spki = extractSpkiFromX509Cert(der);
  return crypto.subtle.importKey(
    "spki",
    spki,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

function readAsn1Len(view, offset) {
  let len = view.getUint8(offset);
  if (len < 0x80) return { len, read: 1 };
  const bytes = len & 0x7f;
  let out = 0;
  for (let i = 0; i < bytes; i++) out = (out << 8) | view.getUint8(offset + 1 + i);
  return { len: out, read: 1 + bytes };
}
function readAsn1Tag(view, offset) {
  const tag = view.getUint8(offset);
  const { len, read } = readAsn1Len(view, offset + 1);
  const header = 1 + read;
  const start = offset + header;
  const end = start + len;
  return { tag, start, end, header };
}
function extractSpkiFromX509Cert(der) {
  const view = new DataView(der);
  const certSeq = readAsn1Tag(view, 0);
  if (certSeq.tag !== 0x30) throw new Error("Bad cert: not SEQUENCE");

  let off = certSeq.start;
  const tbs = readAsn1Tag(view, off);
  if (tbs.tag !== 0x30) throw new Error("Bad cert: tbs not SEQUENCE");

  off = tbs.start;
  const first = readAsn1Tag(view, off);
  if ((first.tag & 0xe0) === 0xa0) {
    off = first.end;
  }

  for (let i = 0; i < 5; i++) {
    const el = readAsn1Tag(view, off);
    off = el.end;
  }

  const spki = readAsn1Tag(view, off);
  if (spki.tag !== 0x30) throw new Error("Bad cert: SPKI not SEQUENCE");

  return der.slice(spki.start - spki.header, spki.end);
}

async function verifyFirebaseIdToken(request, env) {
  const projectId = env.FB_PROJECT_ID;
  if (!projectId) return { ok: false, status: 500, reason: "FB_PROJECT_ID not set" };

  const auth = request.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return { ok: false, status: 401, reason: "Missing Bearer token" };
  const token = m[1].trim();

  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, status: 401, reason: "Bad token format" };

  let header, payload;
  try {
    header = JSON.parse(b64urlToString(parts[0]));
    payload = JSON.parse(b64urlToString(parts[1]));
  } catch {
    return { ok: false, status: 401, reason: "Bad token encoding" };
  }

  const nowSec = Math.floor(Date.now() / 1000);
  if (payload.aud !== projectId) return { ok: false, status: 401, reason: "Bad aud" };
  if (payload.iss !== `https://securetoken.google.com/${projectId}`)
    return { ok: false, status: 401, reason: "Bad iss" };
  if (!payload.sub || typeof payload.sub !== "string")
    return { ok: false, status: 401, reason: "Missing sub" };
  if (payload.exp && payload.exp < nowSec) return { ok: false, status: 401, reason: "Token expired" };

  const kid = header.kid;
  if (!kid) return { ok: false, status: 401, reason: "Missing kid" };
  if (header.alg !== "RS256") return { ok: false, status: 401, reason: "Unsupported alg" };

  try {
    const certs = await getFirebaseCerts();
    const pem = certs[kid];
    if (!pem) return { ok: false, status: 401, reason: "Unknown kid" };

    const key = await importRsaPublicKeyFromCertPem(pem);

    const signingInput = new TextEncoder().encode(parts[0] + "." + parts[1]);
    const sig = b64urlToUint8Array(parts[2]);

    const ok = await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      key,
      sig,
      signingInput
    );
    if (!ok) return { ok: false, status: 401, reason: "Invalid signature" };

    return { ok: true, uid: payload.sub, claims: payload };
  } catch {
    return { ok: false, status: 401, reason: "Token verify failed" };
  }
}

// NOTE: ini masih allow-all seperti versi kamu.
// Minimal: kunci pakai secret admin token kalau dipakai publik.
function requireAdmin(request, env) {
  return { ok: true };
}

// -------------------- Parsing helpers --------------------
async function readEmailRaw(message) {
  const reader = message.raw.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;

    total += value.byteLength;
    if (total > MAX_STORED_BYTES) {
      const remaining = MAX_STORED_BYTES - (total - value.byteLength);
      if (remaining > 0) chunks.push(value.slice(0, remaining));
      break;
    }
    chunks.push(value);
  }

  const all = new Uint8Array(chunks.reduce((acc, c) => acc + c.byteLength, 0));
  let offset = 0;
  for (const c of chunks) {
    all.set(c, offset);
    offset += c.byteLength;
  }

  const raw = new TextDecoder().decode(all);
  return { raw, truncated: total > MAX_STORED_BYTES, storedBytes: all.byteLength };
}

function splitHeadersBody(raw) {
  let headerEnd = raw.indexOf("\r\n\r\n");
  let splitLen = 4;
  if (headerEnd < 0) {
    headerEnd = raw.indexOf("\n\n");
    splitLen = 2;
  }
  const headersPart = headerEnd >= 0 ? raw.slice(0, headerEnd) : raw;
  const bodyPart = headerEnd >= 0 ? raw.slice(headerEnd + splitLen) : "";
  return { headersPart, bodyPart };
}

function pickHeader(headersPart, name) {
  const unfolded = headersPart.replace(/\r?\n[ \t]+/g, " ");
  const re = new RegExp(`^${name}:\\s*(.*)$`, "im");
  const m = unfolded.match(re);
  return m ? m[1].trim() : "";
}

function extractRecipientFromHeaders(headersPart) {
  const candidates = ["Delivered-To", "X-Original-To", "Envelope-To", "To"];
  for (const h of candidates) {
    const re = new RegExp(`^${h}:\\s*(.+)$`, "im");
    const m = headersPart.match(re);
    if (!m) continue;
    const line = m[1].trim();
    const angle = line.match(/<([^>]+@[^>]+)>/);
    if (angle) return angle[1].trim();
    const bare = line.match(/([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i);
    if (bare) return bare[1].trim();
  }
  return "";
}

function normalizeUserFromRecipient(address) {
  const at = address.indexOf("@");
  const local = at >= 0 ? address.slice(0, at) : address;
  return local.toLowerCase().replace(/[^a-z0-9._-]/g, "") || "unknown";
}

function decodeQuotedPrintable(s) {
  const soft = s.replace(/=\r?\n/g, "");
  return soft.replace(/=([A-Fa-f0-9]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}
function decodeBase64(s) {
  const clean = s.replace(/\s+/g, "");
  try {
    const bin = atob(clean);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch {
    return "";
  }
}
function stripHtml(html) {
  let s = html.replace(/<script[\s\S]*?<\/script>/gi, " ");
  s = s.replace(/<style[\s\S]*?<\/style>/gi, " ");
  s = s.replace(/<(br|\/p|\/div|\/tr|\/li|\/h\d)\s*>/gi, "\n");
  s = s.replace(/<[^>]+>/g, " ");
  s = s
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
  s = s.replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
  return s;
}
function parseContentType(ctLine) {
  const lower = (ctLine || "").toLowerCase();
  const mime = lower.split(";")[0].trim();
  const charsetMatch = lower.match(/charset="?([^";]+)"?/i);
  return { mime, charset: charsetMatch ? charsetMatch[1] : "" };
}
function parseTransferEncoding(encLine) {
  return (encLine || "").toLowerCase().trim();
}
function extractBestTextFromRaw(raw) {
  const { headersPart, bodyPart } = splitHeadersBody(raw);

  const topCT = pickHeader(headersPart, "Content-Type");
  const topEnc = pickHeader(headersPart, "Content-Transfer-Encoding");

  const boundaryMatch = topCT.match(/boundary="?([^";]+)"?/i);
  const boundary = boundaryMatch ? boundaryMatch[1] : "";

  if (!boundary || !/multipart\//i.test(topCT)) {
    const enc = parseTransferEncoding(topEnc);
    let decoded = bodyPart;

    if (enc === "quoted-printable") decoded = decodeQuotedPrintable(decoded);
    else if (enc === "base64") decoded = decodeBase64(decoded);

    const { mime } = parseContentType(topCT);

    let text = "";
    let html = "";

    if (/text\/html/i.test(mime)) {
      html = decoded;
      text = stripHtml(decoded);
    } else {
      text = decoded.trim();
    }

    return { text, html, usedMime: mime || "unknown", hadMultipart: false };
  }

  const marker = `--${boundary}`;
  const endMarker = `--${boundary}--`;

  const parts = bodyPart.split(marker).slice(1);
  let bestPlain = "";
  let bestHtmlFull = "";
  let bestHtmlStripped = "";

  for (let part of parts) {
    if (part.includes(endMarker)) part = part.split(endMarker)[0];
    part = part.replace(/^\r?\n/, "").trim();
    if (!part) continue;

    const { headersPart: ph, bodyPart: pb } = splitHeadersBody(part);

    const ct = pickHeader(ph, "Content-Type");
    const enc = pickHeader(ph, "Content-Transfer-Encoding");
    const { mime } = parseContentType(ct);
    const encNorm = parseTransferEncoding(enc);

    let decoded = pb;
    if (encNorm === "quoted-printable") decoded = decodeQuotedPrintable(decoded);
    else if (encNorm === "base64") decoded = decodeBase64(decoded);

    if (/text\/plain/i.test(mime) && !bestPlain) {
      bestPlain = decoded.trim();
    } else if (/text\/html/i.test(mime) && !bestHtmlFull) {
      bestHtmlFull = decoded;
      bestHtmlStripped = stripHtml(decoded);
    }
  }

  const text = bestPlain || bestHtmlStripped || "";
  const html = bestHtmlFull || "";
  const usedMime = bestPlain ? "text/plain" : bestHtmlFull ? "text/html" : "unknown";

  return { text: text.trim(), html, usedMime, hadMultipart: true };
}

// -------------------- SMART OTP EXTRACTION --------------------
function extractSmartOtp(text, html) {
  const matches = [...text.matchAll(/\b\d{4,8}\b/g)];
  if (matches.length === 0) return { best: null, all: [] };

  const candidates = new Map();

  const positiveWords =
    /verification|verifikasi|code|kode|otp|auth|passcode|pin|secret|access|login/i;
  const strongPositive =
    /(is|adalah)\s+(your|ur|anda)?\s*(verification|verifikasi)?\s*(code|kode|otp)|use\s+(this|the)\s+code/i;
  const negativeWords =
    /zip|postal|post|address|alamat|jalan|street|ave|singapore|tel|fax|phone|copyright|reserved|ticket|order|invoice/i;

  for (const m of matches) {
    const num = m[0];
    const index = m.index;

    const start = Math.max(0, index - 60);
    const end = Math.min(text.length, index + num.length + 60);
    const context = text.slice(start, end);

    let score = 0;

    if (negativeWords.test(context)) score -= 50;
    if (positiveWords.test(context)) score += 10;
    if (strongPositive.test(context)) score += 20;

    if (html) {
      const visualRegex = new RegExp(
        `<(b|strong|span|div|p)[^>]*>\\s*${num}\\s*<\\/\\1>`,
        "i"
      );
      if (visualRegex.test(html)) score += 5;
    }

    if ((num.startsWith("19") || num.startsWith("20")) && num.length === 4) {
      score -= 5;
    }

    candidates.set(num, (candidates.get(num) || 0) + score);
  }

  const sorted = [...candidates.entries()].sort((a, b) => b[1] - a[1]);
  const valid = sorted.filter((x) => x[1] > -20);

  if (valid.length === 0) return { best: null, all: [] };

  return {
    best: valid[0][0],
    all: valid.map((x) => x[0]),
  };
}

function makeSnippet(text) {
  const firstLine =
    text
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l.length > 0) || "";
  return firstLine.slice(0, 180);
}

// -------------------- KV index helpers --------------------
async function loadIndex(env, user) {
  const raw = await env.INBOX_KV.get(kvKeyIndex(user));
  if (!raw) return [];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}
async function saveIndex(env, user, indexArr) {
  const trimmed = indexArr.slice(0, 200);
  await env.INBOX_KV.put(kvKeyIndex(user), JSON.stringify(trimmed), {
    expirationTtl: TTL_3_DAYS,
  });
}
async function messageExists(env, user, id) {
  const v = await env.INBOX_KV.get(kvKeyMsg(user, id));
  return v !== null;
}
async function getInboxUserForUid(env, uid) {
  const raw = await env.INBOX_KV.get(kvKeyAllow(uid));
  if (raw) {
    try {
      const obj = JSON.parse(raw);
      if (obj?.inboxUser) return String(obj.inboxUser).toLowerCase();
    } catch {}
  }
  return null;
}
async function isAllowedInboxUser(env, inboxUser) {
  const v = await env.INBOX_KV.get(kvKeyAllowInboxUser(inboxUser));
  return v !== null;
}

// -------------------- Worker --------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "*";

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(origin) });
    }

    if (url.pathname === "/health") {
      return json({ ok: true, now: Date.now() }, { origin });
    }

    // Admin endpoints
    if (url.pathname.startsWith("/admin/") || url.pathname.startsWith("/debug/")) {
      const adm = requireAdmin(request, env);
      if (!adm.ok) return json({ ok: false, error: adm.reason }, { status: adm.status, origin });

      // PUT /admin/allow?uid=...&inboxUser=...
      if (url.pathname === "/admin/allow" && request.method === "PUT") {
        const uid = url.searchParams.get("uid") || "";
        const inboxUser = (url.searchParams.get("inboxUser") || "").toLowerCase();
        if (!uid || !inboxUser) {
          return json({ ok: false, error: "Missing uid or inboxUser" }, { status: 400, origin });
        }

        // 1) uid -> inboxUser mapping (NO TTL)
        await env.INBOX_KV.put(kvKeyAllow(uid), JSON.stringify({ inboxUser }));

        // 2) allowlist inboxUser (NO TTL)
        await env.INBOX_KV.put(kvKeyAllowInboxUser(inboxUser), "1");

        return json({ ok: true, uid, inboxUser }, { origin });
      }

      // GET /admin/allow?uid=...
      if (url.pathname === "/admin/allow" && request.method === "GET") {
        const uid = url.searchParams.get("uid") || "";
        if (!uid) return json({ ok: false, error: "Missing uid" }, { status: 400, origin });
        const inboxUser = await getInboxUserForUid(env, uid);
        return json({ ok: true, uid, inboxUser }, { origin });
      }

      // DELETE /admin/allow?uid=...&inboxUser=...
      if (url.pathname === "/admin/allow" && request.method === "DELETE") {
        const uid = url.searchParams.get("uid") || "";
        const inboxUser = (url.searchParams.get("inboxUser") || "").toLowerCase();
        if (!uid || !inboxUser) {
          return json({ ok: false, error: "Missing uid or inboxUser" }, { status: 400, origin });
        }

        // 1) Delete uid -> inboxUser mapping
        await env.INBOX_KV.delete(kvKeyAllow(uid));

        // 2) Delete allowlist for inboxUser
        await env.INBOX_KV.delete(kvKeyAllowInboxUser(inboxUser));

        return json({ ok: true, uid, inboxUser, deleted: true }, { origin });
      }

      // PUT /admin/allowInboxUser?user=...
      if (url.pathname === "/admin/allowInboxUser" && request.method === "PUT") {
        const user = (url.searchParams.get("user") || "").toLowerCase();
        if (!user) return json({ ok: false, error: "Missing user" }, { status: 400, origin });
        await env.INBOX_KV.put(kvKeyAllowInboxUser(user), "1");
        return json({ ok: true, user }, { origin });
      }

      // DELETE /admin/allowInboxUser?user=...
      if (url.pathname === "/admin/allowInboxUser" && request.method === "DELETE") {
        const user = (url.searchParams.get("user") || "").toLowerCase();
        if (!user) return json({ ok: false, error: "Missing user" }, { status: 400, origin });
        await env.INBOX_KV.delete(kvKeyAllowInboxUser(user));
        return json({ ok: true, user, deleted: true }, { origin });
      }

      // Debug list
      if (url.pathname === "/debug/kv") {
        const listIdx = await env.INBOX_KV.list({ prefix: "idx:" });
        const listMsg = await env.INBOX_KV.list({ prefix: "msg:" });
        const listAllow = await env.INBOX_KV.list({ prefix: "allow:" });
        const listAllowInbox = await env.INBOX_KV.list({ prefix: "allowInboxUser:" });

        return json(
          {
            ok: true,
            idxKeys: listIdx.keys.map((k) => k.name),
            msgKeysSample: listMsg.keys.slice(0, 20).map((k) => k.name),
            msgCountApprox: listMsg.keys.length,
            allowKeys: listAllow.keys.map((k) => k.name),
            allowInboxUsers: listAllowInbox.keys.map((k) => k.name),
          },
          { origin }
        );
      }

      if (url.pathname === "/debug/last-email") {
        const raw = await env.INBOX_KV.get(KV_LAST_EMAIL);
        return json({ ok: true, lastEmail: raw ? JSON.parse(raw) : null }, { origin });
      }

      return textResp("Not found", { status: 404, origin });
    }

    // ---- User routes: require Firebase ID token ----
    const fb = await verifyFirebaseIdToken(request, env);
    if (!fb.ok) return json({ ok: false, error: fb.reason }, { status: fb.status, origin });

    const inboxUser = await getInboxUserForUid(env, fb.uid);
    if (!inboxUser) {
      return json(
        { ok: false, error: "No inbox assigned for this Firebase account (uid not allowed)" },
        { status: 403, origin }
      );
    }

    // GET /inbox
    if (url.pathname === "/inbox" && request.method === "GET") {
      const idx = await loadIndex(env, inboxUser);
      const filtered = [];
      for (const item of idx) {
        if (!item?.id) continue;
        if (await messageExists(env, inboxUser, item.id)) filtered.push(item);
      }
      if (filtered.length !== idx.length) await saveIndex(env, inboxUser, filtered);
      return json({ ok: true, uid: fb.uid, user: inboxUser, messages: filtered }, { origin });
    }

    // GET /message?id=...
    if (url.pathname === "/message" && request.method === "GET") {
      const id = url.searchParams.get("id") || "";
      const format = url.searchParams.get("format") || "html";
      if (!id) return json({ ok: false, error: "Missing ?id=" }, { status: 400, origin });

      const raw = await env.INBOX_KV.get(kvKeyMsg(inboxUser, id));
      if (!raw)
        return json({ ok: false, error: "Not found (expired or deleted)" }, { status: 404, origin });

      const msg = JSON.parse(raw);
      if (format === "json") {
        return json({ ok: true, uid: fb.uid, user: inboxUser, id, message: msg }, { origin });
      }

      const content =
        msg.html && msg.html.trim().length > 0
          ? msg.html
          : `<!DOCTYPE html><html><body><pre style="white-space: pre-wrap; word-wrap: break-word;">${(
              msg.text || ""
            ).replace(/</g, "&lt;")}</pre></body></html>`;

      return new Response(content, {
        status: 200,
        headers: {
          ...corsHeaders(origin),
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
        },
      });
    }

    // DELETE /message?id=...
    if (url.pathname === "/message" && request.method === "DELETE") {
      const id = url.searchParams.get("id") || "";
      if (!id) return json({ ok: false, error: "Missing ?id=" }, { status: 400, origin });

      await env.INBOX_KV.delete(kvKeyMsg(inboxUser, id));
      const idx = await loadIndex(env, inboxUser);
      await saveIndex(env, inboxUser, idx.filter((x) => x?.id !== id));

      return json({ ok: true, deleted: true, uid: fb.uid, user: inboxUser, id }, { origin });
    }

    // GET /otp/latest
    if (url.pathname === "/otp/latest" && request.method === "GET") {
      const idx = await loadIndex(env, inboxUser);
      const latest = idx[0];
      if (!latest?.id) return json({ ok: true, uid: fb.uid, user: inboxUser, latest: null }, { origin });

      const raw = await env.INBOX_KV.get(kvKeyMsg(inboxUser, latest.id));
      if (!raw) return json({ ok: true, uid: fb.uid, user: inboxUser, latest: null }, { origin });

      const msg = JSON.parse(raw);
      const bestOtp =
        msg.otpBest || (msg.otpCandidates && msg.otpCandidates.length ? msg.otpCandidates[0] : null);

      return json(
        {
          ok: true,
          uid: fb.uid,
          user: inboxUser,
          id: msg.id,
          subject: msg.subject || "",
          receivedAt: msg.receivedAt,
          otp: bestOtp,
          otpCandidates: msg.otpCandidates || [],
        },
        { origin }
      );
    }

    return textResp("Not found", { status: 404, origin });
  },

  async email(message, env, ctx) {
    try {
      const { raw, truncated, storedBytes } = await readEmailRaw(message);
      const { headersPart } = splitHeadersBody(raw);

      const headerTo = extractRecipientFromHeaders(headersPart);
      const sdkTo = message.to?.[0]?.address || "";
      const toAddr = headerTo || sdkTo || "unknown@unknown";
      const user = normalizeUserFromRecipient(toAddr);

      // ====== FILTER: hanya inboxUser yang di-allow yang boleh dibuat/simpan ======
      const allowedInbox = await isAllowedInboxUser(env, user);
      if (!allowedInbox) {
        // Tolak supaya tidak bikin idx/msg random dari catch-all
        // (kalau kamu mau silent drop, ganti jadi message.setDrop(); )
        message.setReject("Mailbox not found");
        return;
      }

      // ====== OPTIONAL rate limit per inbox ======
      if (EMAIL_RATE_LIMIT_PER_MINUTE > 0) {
        const bucket = Math.floor(Date.now() / 60000);
        const rkey = kvKeyRateInbox(user, bucket);
        const count = Number((await env.INBOX_KV.get(rkey)) || 0);

        if (count >= EMAIL_RATE_LIMIT_PER_MINUTE) {
          message.setReject("Too many requests");
          return;
        }
        // Use ctx.waitUntil for rate limit update
        ctx.waitUntil(env.INBOX_KV.put(rkey, String(count + 1), { expirationTtl: 70 }));
      }

      const subject = pickHeader(headersPart, "Subject");
      const from = pickHeader(headersPart, "From");
      const date = pickHeader(headersPart, "Date");

      const { text, html, usedMime, hadMultipart } = extractBestTextFromRaw(raw);
      const cleanedText = (text || "").trim();
      const snippet = makeSnippet(cleanedText || "(no text)");

      const { best, all } = extractSmartOtp(cleanedText, html);

      const id = `${Date.now()}-${crypto.randomUUID()}`;
      const receivedAt = Date.now();

      console.log("EMAIL EVENT CALLED", { toAddr, user, usedMime, otpBest: best });

      const record = {
        id,
        user,
        to: toAddr,
        subject,
        from,
        date,
        receivedAt,
        truncated,
        storedBytes,
        usedMime,
        hadMultipart,
        snippet,
        otpBest: best,
        otpCandidates: all,
        text: cleanedText,
        html: html || "",
      };

      // Parallelize KV writes using ctx.waitUntil
      const tasks = [
        env.INBOX_KV.put(
          KV_LAST_EMAIL,
          JSON.stringify({ user, to: toAddr, receivedAt, subject, usedMime }),
          { expirationTtl: TTL_3_DAYS }
        ),
        env.INBOX_KV.put(kvKeyMsg(user, id), JSON.stringify(record), {
          expirationTtl: TTL_3_DAYS,
        }),
        (async () => {
          const idx = await loadIndex(env, user);
          idx.unshift({ id, subject, from, date, snippet, receivedAt });
          await saveIndex(env, user, idx);
        })()
      ];

      ctx.waitUntil(Promise.all(tasks));

    } catch (e) {
      console.error("Email worker error:", e);
      message.setReject("Internal Worker Error");
    }
  },
};
