import { handleAuthRoute } from "./routes/auth";
import { handleMailRoute } from "./routes/mail";

export interface Env {
  DB: D1Database;
  MASTER_ENCRYPTION_KEY: string;
  ALLOWED_EMAIL_DOMAINS?: string;
  CORS_ORIGIN?: string;
  SESSION_TTL_DAYS?: string;
}

export interface SessionData {
  sessionId: string;
  email: string;
  encryptedPassword: string;
  ipHash: string | null;
  createdAt: number;
  expiresAt: number;
  lastSeenAt: number;
}

const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url);

      if (request.method === "OPTIONS") {
        return handleCorsPreflight(request, env);
      }

      if (url.pathname.startsWith("/api/auth/")) {
        return handleAuthRoute(request, env);
      }

      if (url.pathname.startsWith("/api/mail/") || url.pathname === "/api/me") {
        return handleMailRoute(request, env);
      }

      return jsonError(request, env, "Not found", 404);
    } catch (error) {
      console.error("Unhandled worker error", error instanceof Error ? error.message : error);
      return jsonError(request, env, "Internal server error", 500);
    }
  },
};

export function jsonOk(request: Request, env: Env, data: unknown, status = 200, extraHeaders?: HeadersInit) {
  return new Response(JSON.stringify({ ok: true, data }), {
    status,
    headers: {
      ...JSON_HEADERS,
      ...buildCorsHeaders(request, env),
      ...extraHeaders,
    },
  });
}

export function jsonError(request: Request, env: Env, error: string, status = 400, extraHeaders?: HeadersInit) {
  return new Response(JSON.stringify({ ok: false, error }), {
    status,
    headers: {
      ...JSON_HEADERS,
      ...buildCorsHeaders(request, env),
      ...extraHeaders,
    },
  });
}

export function buildCorsHeaders(request: Request, env: Env): HeadersInit {
  const origin = request.headers.get("Origin");
  const allowed = getAllowedOrigins(env);
  const headers: Record<string, string> = {
    Vary: "Origin",
  };

  if (!origin) {
    return headers;
  }

  if (allowed.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Credentials"] = "true";
  }

  return headers;
}

function handleCorsPreflight(request: Request, env: Env) {
  const origin = request.headers.get("Origin");
  const allowed = getAllowedOrigins(env);
  if (origin && !allowed.includes(origin)) {
    return new Response("Forbidden", { status: 403 });
  }

  return new Response(null, {
    status: 204,
    headers: {
      ...buildCorsHeaders(request, env),
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
    },
  });
}

function getAllowedOrigins(env: Env): string[] {
  return (env.CORS_ORIGIN || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}
