import type { Env } from "../index";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export async function encryptString(plainText: string, env: Env): Promise<string> {
  const iv = new Uint8Array(crypto.getRandomValues(new Uint8Array(12)));
  const key = await getAesKey(env);
  const cipherBuffer = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(plainText));
  return `${toBase64(iv)}.${toBase64(new Uint8Array(cipherBuffer))}`;
}

export async function decryptString(cipherText: string, env: Env): Promise<string> {
  const [ivPart, dataPart] = cipherText.split(".");
  if (!ivPart || !dataPart) {
    throw new Error("Invalid cipher text format");
  }

  const key = await getAesKey(env);
  const iv = new Uint8Array(fromBase64(ivPart));
  const data = fromBase64(dataPart);
  const cipherBuffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  const plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipherBuffer);
  return decoder.decode(plainBuffer);
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function getAesKey(env: Env): Promise<CryptoKey> {
  if (!env.MASTER_ENCRYPTION_KEY) {
    throw new Error("MASTER_ENCRYPTION_KEY is not set");
  }

  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(env.MASTER_ENCRYPTION_KEY));
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}
