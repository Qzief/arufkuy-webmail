import type { Env } from "../index";
import { jsonError, jsonOk } from "../index";
import { deleteMessage, getMessage, listInbox, testImapLogin } from "../lib/imapClient";
import { requireSession, buildRateKey, consumeRateLimit } from "../lib/session";
import { testSmtpAuth, sendMail } from "../lib/smtpClient";
import { parseJson, parsePositiveInt, validateSendPayload } from "../lib/validation";

export async function handleMailRoute(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);

  try {
    if (request.method === "GET" && url.pathname === "/api/me") {
      const { session } = await requireSession(request, env);
      return jsonOk(request, env, { email: session.email });
    }

    if (request.method === "POST" && url.pathname === "/api/mail/test") {
      return await testConnections(request, env);
    }

    if (request.method === "GET" && url.pathname === "/api/mail/inbox") {
      return await inbox(request, env, url);
    }

    if (request.method === "GET" && url.pathname === "/api/mail/message") {
      return await message(request, env, url);
    }

    if (request.method === "DELETE" && url.pathname === "/api/mail/message") {
      return await removeMessage(request, env, url);
    }

    if (request.method === "POST" && url.pathname === "/api/mail/send") {
      return await send(request, env);
    }

    return jsonError(request, env, "Not found", 404);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Request gagal.";
    const status = /Sesi/i.test(message) ? 401 : 400;
    return jsonError(request, env, safeMailError(message), status);
  }
}

async function testConnections(request: Request, env: Env) {
  const { session, password } = await requireSession(request, env);
  const rateKey = await buildRateKey("mail-test", request, session.sessionId);
  await consumeRateLimit(env, rateKey, 10, 300);

  await testImapLogin(session.email, password);
  await testSmtpAuth(session.email, password);

  return jsonOk(request, env, {
    imap: "ok",
    smtp: "ok",
  });
}

async function inbox(request: Request, env: Env, url: URL) {
  const { session, password } = await requireSession(request, env);
  const rateKey = await buildRateKey("inbox", request, session.sessionId);
  await consumeRateLimit(env, rateKey, 60, 60);

  const limit = parsePositiveInt(url.searchParams.get("limit"), 20, 50);
  const offset = parsePositiveInt(url.searchParams.get("offset"), 0, 500);
  const messages = await listInbox(session.email, password, limit, offset);

  return jsonOk(request, env, {
    messages,
    limit,
    offset,
  });
}

async function message(request: Request, env: Env, url: URL) {
  const { session, password } = await requireSession(request, env);
  const uid = url.searchParams.get("id") || "";
  if (!uid) {
    throw new Error("UID email wajib diisi.");
  }

  const rateKey = await buildRateKey("message", request, session.sessionId);
  await consumeRateLimit(env, rateKey, 90, 60);
  const messageData = await getMessage(session.email, password, uid);
  return jsonOk(request, env, messageData);
}

async function removeMessage(request: Request, env: Env, url: URL) {
  const { session, password } = await requireSession(request, env);
  const uid = url.searchParams.get("id") || "";
  if (!uid) {
    throw new Error("UID email wajib diisi.");
  }

  const rateKey = await buildRateKey("delete", request, session.sessionId);
  await consumeRateLimit(env, rateKey, 20, 300);
  await deleteMessage(session.email, password, uid);
  return jsonOk(request, env, { deleted: true, uid });
}

async function send(request: Request, env: Env) {
  const { session, password } = await requireSession(request, env);
  const rateKey = await buildRateKey("send", request, session.sessionId);
  await consumeRateLimit(env, rateKey, 8, 600);

  const rawBody = await request.text();
  const payload = validateSendPayload(parseJson(rawBody));
  await sendMail(session.email, password, payload);

  return jsonOk(request, env, { sent: true });
}

function safeMailError(message: string) {
  if (/command failed|socket|imap|smtp/i.test(message)) {
    return "Koneksi ke mail server gagal.";
  }
  return message;
}
