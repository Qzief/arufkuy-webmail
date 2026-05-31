import { connect } from "cloudflare:sockets";
import { ZORG_PROVIDER } from "./mailProvider";

interface InboxItem {
  uid: string;
  from: string;
  subject: string;
  date: string;
  preview: string;
  seen: boolean;
}

interface MessageItem {
  uid: string;
  from: string;
  to: string;
  subject: string;
  date: string;
  text: string;
  html: string;
  attachments: Array<Record<string, unknown>>;
  seen: boolean;
}

interface ParsedMimePart {
  headers: Record<string, string>;
  text: string;
  html: string;
}

export async function testImapLogin(email: string, password: string) {
  const client = await ImapClient.connect(email, password);
  await client.logout();
}

export async function listInbox(email: string, password: string, limit: number, offset: number): Promise<InboxItem[]> {
  const client = await ImapClient.connect(email, password);
  try {
    await client.selectInbox();
    const uids = await client.searchAllUids();
    const page = uids.reverse().slice(offset, offset + limit);
    const items: InboxItem[] = [];
    for (const uid of page) {
      items.push(await client.fetchInboxItem(uid));
    }
    return items;
  } finally {
    await client.logout();
  }
}

export async function getMessage(email: string, password: string, uid: string): Promise<MessageItem> {
  const client = await ImapClient.connect(email, password);
  try {
    await client.selectInbox();
    return await client.fetchMessage(uid);
  } finally {
    await client.logout();
  }
}

export async function deleteMessage(email: string, password: string, uid: string) {
  const client = await ImapClient.connect(email, password);
  try {
    await client.selectInbox();
    await client.exec(`UID STORE ${uid} +FLAGS.SILENT (\\Deleted)`);
    await client.exec("EXPUNGE");
  } finally {
    await client.logout();
  }
}

class ImapClient {
  private tagCounter = 1;
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  private buffer = "";

  private constructor(
    private socket: Socket,
    private email: string,
    private password: string,
  ) {
    this.reader = socket.readable.getReader();
    this.writer = socket.writable.getWriter();
  }

  static async connect(email: string, password: string) {
    const socket = connect(
      { hostname: ZORG_PROVIDER.imapHost, port: ZORG_PROVIDER.imapPort },
      { secureTransport: ZORG_PROVIDER.imapSecure ? "on" : "off", allowHalfOpen: false },
    );
    await socket.opened;
    const client = new ImapClient(socket, email, password);
    await client.readUntilLine();
    await client.exec(`LOGIN ${quoteImap(email)} ${quoteImap(password)}`);
    return client;
  }

  async selectInbox() {
    await this.exec('SELECT "INBOX"');
  }

  async searchAllUids(): Promise<string[]> {
    const response = await this.exec("UID SEARCH ALL");
    const match = response.match(/\* SEARCH([^\r\n]*)/);
    if (!match) {
      return [];
    }
    return match[1].trim().split(/\s+/).filter(Boolean);
  }

  async fetchInboxItem(uid: string): Promise<InboxItem> {
    const response = await this.exec(
      `UID FETCH ${uid} (UID FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)] BODY.PEEK[TEXT]<0.200>)`,
    );

    const header = extractLiteralAfter(response, "BODY[HEADER.FIELDS (FROM SUBJECT DATE)]");
    const previewRaw = extractLiteralAfter(response, "BODY[TEXT]<0>");
    const headers = parseHeaders(header);

    return {
      uid,
      from: decodeMimeWords(headers.from || ""),
      subject: decodeMimeWords(headers.subject || ""),
      date: normalizeDate(headers.date || ""),
      preview: buildPreview(previewRaw),
      seen: /FLAGS \([^\)]*\\Seen/i.test(response),
    };
  }

  async fetchMessage(uid: string): Promise<MessageItem> {
    const response = await this.exec(`UID FETCH ${uid} (UID FLAGS BODY.PEEK[])`);
    const raw = extractLiteralAfter(response, "BODY[]");
    const parsed = parseMimeMessage(raw);

    return {
      uid,
      from: parsed.headers.from || "",
      to: parsed.headers.to || "",
      subject: parsed.headers.subject || "",
      date: normalizeDate(parsed.headers.date || ""),
      text: parsed.text,
      html: parsed.html,
      attachments: [],
      seen: /FLAGS \([^\)]*\\Seen/i.test(response),
    };
  }

  async logout() {
    try {
      await this.exec("LOGOUT");
    } catch {
      await this.close();
    }
  }

  async exec(command: string): Promise<string> {
    const tag = `A${String(this.tagCounter).padStart(4, "0")}`;
    this.tagCounter += 1;

    await this.write(`${tag} ${command}\r\n`);
    const response = await this.readUntilTagged(tag);

    if (!new RegExp(`(?:^|\\r\\n)${tag} OK`, "i").test(response)) {
      throw new Error("IMAP command failed");
    }

    return response;
  }

  private async write(text: string) {
    await this.writer.write(new TextEncoder().encode(text));
  }

  private async readUntilLine() {
    while (!this.buffer.includes("\r\n")) {
      const { value, done } = await this.reader.read();
      if (done) {
        throw new Error("IMAP socket closed");
      }
      this.buffer += binaryString(value);
    }
    const lineEnd = this.buffer.indexOf("\r\n") + 2;
    const line = this.buffer.slice(0, lineEnd);
    this.buffer = this.buffer.slice(lineEnd);
    return line;
  }

  private async readUntilTagged(tag: string): Promise<string> {
    while (!new RegExp(`(?:^|\\r\\n)${tag} (OK|NO|BAD)`, "i").test(this.buffer)) {
      const { value, done } = await this.reader.read();
      if (done) {
        throw new Error("IMAP socket closed");
      }
      this.buffer += binaryString(value);
    }

    const response = this.buffer;
    this.buffer = "";
    return response;
  }

  private async close() {
    this.reader.releaseLock();
    this.writer.releaseLock();
    await this.socket.close();
  }
}

function binaryString(bytes: Uint8Array): string {
  let output = "";
  for (const byte of bytes) {
    output += String.fromCharCode(byte);
  }
  return output;
}

function quoteImap(value: string) {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function extractLiteralAfter(response: string, marker: string): string {
  const markerIndex = response.indexOf(marker);
  if (markerIndex === -1) {
    return "";
  }
  const lengthMatch = response.slice(markerIndex).match(/\{(\d+)\}\r\n/);
  if (!lengthMatch) {
    return "";
  }

  const lengthToken = lengthMatch[0];
  const length = Number.parseInt(lengthMatch[1], 10);
  const contentStart = markerIndex + response.slice(markerIndex).indexOf(lengthToken) + lengthToken.length;
  return response.slice(contentStart, contentStart + length);
}

function parseHeaders(rawHeaders: string): Record<string, string> {
  const unfolded = rawHeaders.replace(/\r?\n[ \t]+/g, " ");
  const lines = unfolded.split(/\r?\n/);
  const headers: Record<string, string> = {};

  for (const line of lines) {
    const separator = line.indexOf(":");
    if (separator === -1) {
      continue;
    }
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    headers[key] = decodeMimeWords(value);
  }

  return headers;
}

function buildPreview(text: string) {
  return text
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 220);
}

function normalizeDate(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toISOString();
}

function parseMimeMessage(raw: string): ParsedMimePart {
  const splitIndex = raw.search(/\r?\n\r?\n/);
  const rawHeaders = splitIndex === -1 ? raw : raw.slice(0, splitIndex);
  const body = splitIndex === -1 ? "" : raw.slice(splitIndex).replace(/^\r?\n\r?\n/, "");
  const headers = parseHeaders(rawHeaders);
  const contentType = headers["content-type"] || "text/plain";
  const transferEncoding = (headers["content-transfer-encoding"] || "").toLowerCase();

  if (/multipart\//i.test(contentType)) {
    const boundaryMatch = contentType.match(/boundary="?([^";]+)"?/i);
    if (!boundaryMatch) {
      return { headers, text: decodeBody(body, transferEncoding), html: "" };
    }

    const boundary = boundaryMatch[1];
    const parts: ParsedMimePart[] = splitMultipartBody(body, boundary).map((part) => parseMimeMessage(part));
    const htmlPart = parts.find((part) => part.html);
    const textPart = parts.find((part) => part.text);

    return {
      headers,
      text: textPart?.text || "",
      html: htmlPart?.html || "",
    };
  }

  const decoded = decodeBody(body, transferEncoding);
  if (/text\/html/i.test(contentType)) {
    return { headers, text: stripHtml(decoded), html: decoded };
  }

  return { headers, text: decoded, html: "" };
}

function splitMultipartBody(body: string, boundary: string) {
  const delimiter = `--${boundary}`;
  return body
    .split(delimiter)
    .slice(1)
    .map((part) => part.replace(/^\r?\n/, "").replace(/\r?\n--$/, "").trim())
    .filter((part) => part && part !== "--");
}

function decodeBody(body: string, encoding: string) {
  if (encoding.includes("base64")) {
    try {
      return decodeBinaryText(atob(body.replace(/\s+/g, "")));
    } catch {
      return body;
    }
  }
  if (encoding.includes("quoted-printable")) {
    return decodeQuotedPrintable(body);
  }
  return decodeBinaryText(body);
}

function decodeBinaryText(binary: string) {
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index) & 0xff;
  }
  return new TextDecoder().decode(bytes);
}

function decodeQuotedPrintable(input: string) {
  const normalized = input.replace(/=\r?\n/g, "");
  const bytes: number[] = [];
  for (let index = 0; index < normalized.length; index += 1) {
    if (normalized[index] === "=") {
      const hex = normalized.slice(index + 1, index + 3);
      if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
        bytes.push(Number.parseInt(hex, 16));
        index += 2;
        continue;
      }
    }
    bytes.push(normalized.charCodeAt(index));
  }
  return new TextDecoder().decode(new Uint8Array(bytes));
}

function stripHtml(html: string) {
  return html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

function decodeMimeWords(value: string) {
  return value.replace(/=\?([^?]+)\?([BQ])\?([^?]+)\?=/gi, (_full, charset, encoding, encodedText) => {
    try {
      let binary = "";
      if (encoding.toUpperCase() === "B") {
        binary = atob(encodedText);
      } else {
        binary = encodedText
          .replace(/_/g, " ")
          .replace(/=([0-9A-Fa-f]{2})/g, (_match: string, hex: string) => String.fromCharCode(Number.parseInt(hex, 16)));
      }

      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
      }
      return new TextDecoder(charset).decode(bytes);
    } catch {
      return encodedText;
    }
  });
}
