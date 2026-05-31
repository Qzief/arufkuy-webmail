import { connect } from "cloudflare:sockets";
import { ZORG_PROVIDER } from "./mailProvider";

export async function testSmtpAuth(email: string, password: string) {
  const client = await SmtpClient.connect(email, password);
  await client.quit();
}

export async function sendMail(
  email: string,
  password: string,
  payload: { to: string[]; subject: string; body: string },
) {
  const client = await SmtpClient.connect(email, password);
  try {
    await client.send(email, payload.to, payload.subject, payload.body);
  } finally {
    await client.quit();
  }
}

class SmtpClient {
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  private buffer = "";

  private constructor(private socket: Socket) {
    this.reader = socket.readable.getReader();
    this.writer = socket.writable.getWriter();
  }

  static async connect(email: string, password: string) {
    const socket = connect(
      { hostname: ZORG_PROVIDER.smtpHost, port: ZORG_PROVIDER.smtpPort },
      { secureTransport: ZORG_PROVIDER.smtpSecure ? "on" : "off", allowHalfOpen: false },
    );
    await socket.opened;
    const client = new SmtpClient(socket);
    await client.expect(220);
    await client.command(`EHLO worker.local`, 250);
    await client.command("AUTH LOGIN", 334);
    await client.command(btoa(email), 334);
    await client.command(btoa(password), 235);
    return client;
  }

  async send(from: string, to: string[], subject: string, body: string) {
    await this.command(`MAIL FROM:<${from}>`, 250);
    for (const recipient of to) {
      await this.command(`RCPT TO:<${recipient}>`, 250);
    }
    await this.command("DATA", 354);

    const lines = [
      `From: ${from}`,
      `To: ${to.join(", ")}`,
      `Subject: ${subject}`,
      `Date: ${new Date().toUTCString()}`,
      "MIME-Version: 1.0",
      'Content-Type: text/plain; charset="utf-8"',
      "Content-Transfer-Encoding: 8bit",
      "",
      dotStuff(body),
      ".",
    ];

    await this.write(`${lines.join("\r\n")}\r\n`);
    await this.expect(250);
  }

  async quit() {
    try {
      await this.command("QUIT", 221);
    } catch {
      await this.close();
    }
  }

  private async command(text: string, expectedCode: number) {
    await this.write(`${text}\r\n`);
    await this.expect(expectedCode);
  }

  private async expect(expectedCode: number) {
    while (true) {
      const complete = this.findCompleteResponse();
      if (complete) {
        if (!complete.startsWith(String(expectedCode))) {
          throw new Error("SMTP command failed");
        }
        return complete;
      }

      const { value, done } = await this.reader.read();
      if (done) {
        throw new Error("SMTP socket closed");
      }
      this.buffer += binaryString(value);
    }
  }

  private findCompleteResponse() {
    const lines = this.buffer.split("\r\n");
    if (lines.length < 2) {
      return "";
    }

    let lastCompleteIndex = -1;
    let response = "";
    for (let index = 0; index < lines.length - 1; index += 1) {
      const line = lines[index];
      if (!/^\d{3}[ -]/.test(line)) {
        continue;
      }
      response += `${line}\r\n`;
      if (/^\d{3} /.test(line)) {
        lastCompleteIndex = index;
        break;
      }
    }

    if (lastCompleteIndex === -1) {
      return "";
    }

    this.buffer = lines.slice(lastCompleteIndex + 1).join("\r\n");
    return response.trim();
  }

  private async write(text: string) {
    await this.writer.write(new TextEncoder().encode(text));
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

function dotStuff(text: string) {
  return text.replace(/\r?\n/g, "\r\n").replace(/^\./gm, "..");
}
