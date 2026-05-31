import type { Env } from "../index";
import { jsonError, jsonOk } from "../index";
import { testImapLogin } from "../lib/imapClient";
import { buildRateKey, consumeRateLimit, createSession, destroySession, getLogoutCookie } from "../lib/session";
import { parseJson, validateLoginPayload } from "../lib/validation";

export async function handleAuthRoute(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "POST" && url.pathname === "/api/auth/login") {
    return login(request, env);
  }

  if (request.method === "POST" && url.pathname === "/api/auth/logout") {
    return logout(request, env);
  }

  return jsonError(request, env, "Not found", 404);
}

async function login(request: Request, env: Env) {
  try {
    const rateKey = await buildRateKey("login", request);
    await consumeRateLimit(env, rateKey, 8, 300);

    const rawBody = await request.text();
    const payload = validateLoginPayload(parseJson(rawBody), env);
    await testImapLogin(payload.email, payload.password);

    const ip = request.headers.get("CF-Connecting-IP");
    const session = await createSession(env, payload.email, payload.password, ip);

    return jsonOk(request, env, { email: payload.email }, 200, {
      "Set-Cookie": session.cookie,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Login gagal.";
    console.error("Login failed:", message);

    if (/Email tidak valid|Domain email tidak diizinkan|Password wajib/i.test(message)) {
      return jsonError(request, env, message, 400);
    }

    if (/command failed|socket|login failed|authentication failed/i.test(message)) {
      return jsonError(request, env, "Email atau password tidak valid.", 401);
    }

    if (/D1_|no such table|database|session/i.test(message)) {
      return jsonError(request, env, "Backend session belum siap. Jalankan schema D1 lalu deploy ulang.", 500);
    }

    return jsonError(request, env, "Login gagal di server.", 500);
  }
}

async function logout(request: Request, env: Env) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const sessionId = cookieHeader
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith("wm_session="))
    ?.slice("wm_session=".length) || null;

  await destroySession(env, sessionId);
  return jsonOk(request, env, { loggedOut: true }, 200, {
    "Set-Cookie": getLogoutCookie(),
  });
}
