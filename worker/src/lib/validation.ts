import type { Env } from "../index";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export interface SendPayload {
  to: string[];
  subject: string;
  body: string;
}

export function parseJson<T>(value: string): T {
  return JSON.parse(value) as T;
}

export function validateLoginPayload(payload: unknown, env: Env) {
  const body = asObject(payload);
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";

  if (!isValidEmail(email)) {
    throw new Error("Email tidak valid.");
  }
  if (!isAllowedEmailDomain(email, env)) {
    throw new Error("Domain email tidak diizinkan.");
  }
  if (!password) {
    throw new Error("Password wajib diisi.");
  }

  return { email, password };
}

export function validateSendPayload(payload: unknown): SendPayload {
  const body = asObject(payload);
  const toRaw = typeof body.to === "string" ? body.to : "";
  const subject = typeof body.subject === "string" ? body.subject.trim() : "";
  const messageBody = typeof body.body === "string" ? body.body : "";

  const recipients = toRaw
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);

  if (recipients.length === 0) {
    throw new Error("Penerima email wajib diisi.");
  }
  if (recipients.length > 3) {
    throw new Error("Maksimal 3 penerima.");
  }
  if (recipients.some((email) => !isValidEmail(email))) {
    throw new Error("Ada alamat tujuan yang tidak valid.");
  }
  if (subject.length > 150) {
    throw new Error("Subject maksimal 150 karakter.");
  }
  if (messageBody.length > 20_000) {
    throw new Error("Isi email maksimal 20.000 karakter.");
  }

  return {
    to: recipients,
    subject,
    body: messageBody,
  };
}

export function parsePositiveInt(value: string | null, fallback: number, max: number) {
  const numeric = Number.parseInt(value || "", 10);
  if (!Number.isFinite(numeric) || numeric < 0) {
    return fallback;
  }
  return Math.min(numeric, max);
}

export function isValidEmail(email: string): boolean {
  return EMAIL_RE.test(email);
}

export function isAllowedEmailDomain(email: string, env: Env): boolean {
  const domain = email.split("@")[1] || "";
  const allowedDomains = (env.ALLOWED_EMAIL_DOMAINS || "z.org")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  return allowedDomains.includes(domain);
}

function asObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object") {
    return {};
  }
  return value as Record<string, unknown>;
}
