# Arufkuy Webmail Project Guide

## Ringkasan

Project ini adalah webmail berbasis frontend statis yang sudah direfaktor agar koneksi email tidak lagi dilakukan langsung dari browser. Semua akses email sekarang diarahkan ke Cloudflare Worker, lalu Worker tersebut yang berbicara ke server IMAP/SMTP provider.

Arsitektur saat ini:

```text
Frontend statis
-> Cloudflare Worker API
-> IMAP/SMTP mail.elektrine.com
```

## Tujuan Refactor

Refactor ini dibuat untuk:

- menghilangkan koneksi IMAP/SMTP langsung dari browser
- menghindari penyimpanan credential email di `localStorage`
- memindahkan autentikasi dan session ke backend Worker
- menjaga UI lama tetap utuh sebisa mungkin
- menyiapkan struktur backend yang lebih aman dan production-ready

## Struktur Project

Root project:

- [index.html](/D:/Program/Pyhton/arufkuy-webmail/index.html): frontend webmail utama
- [styles.css](/D:/Program/Pyhton/arufkuy-webmail/styles.css): styling UI lama
- [admin.html](/D:/Program/Pyhton/arufkuy-webmail/admin.html): panel admin lama berbasis Firebase
- [worker.js](/D:/Program/Pyhton/arufkuy-webmail/worker.js): Worker lama
- [worker/](/D:/Program/Pyhton/arufkuy-webmail/worker): Worker baru berbasis TypeScript

Struktur Worker baru:

- [worker/src/index.ts](/D:/Program/Pyhton/arufkuy-webmail/worker/src/index.ts): entry point Worker
- [worker/src/routes/auth.ts](/D:/Program/Pyhton/arufkuy-webmail/worker/src/routes/auth.ts): route login/logout
- [worker/src/routes/mail.ts](/D:/Program/Pyhton/arufkuy-webmail/worker/src/routes/mail.ts): route inbox, message, send, test, me
- [worker/src/lib/mailProvider.ts](/D:/Program/Pyhton/arufkuy-webmail/worker/src/lib/mailProvider.ts): konstanta provider z.org / Elektrine
- [worker/src/lib/imapClient.ts](/D:/Program/Pyhton/arufkuy-webmail/worker/src/lib/imapClient.ts): IMAP client minimal via `cloudflare:sockets`
- [worker/src/lib/smtpClient.ts](/D:/Program/Pyhton/arufkuy-webmail/worker/src/lib/smtpClient.ts): SMTP client TLS port 465
- [worker/src/lib/session.ts](/D:/Program/Pyhton/arufkuy-webmail/worker/src/lib/session.ts): session D1 + cookie
- [worker/src/lib/crypto.ts](/D:/Program/Pyhton/arufkuy-webmail/worker/src/lib/crypto.ts): AES-GCM encryption helper
- [worker/src/lib/validation.ts](/D:/Program/Pyhton/arufkuy-webmail/worker/src/lib/validation.ts): validasi input API
- [worker/wrangler.toml](/D:/Program/Pyhton/arufkuy-webmail/worker/wrangler.toml): config Worker
- [worker/schema.sql](/D:/Program/Pyhton/arufkuy-webmail/worker/schema.sql): schema D1

## Provider Email

Konfigurasi provider yang dipakai:

- IMAP host: `mail.elektrine.com`
- IMAP port: `993`
- IMAP secure: `TLS`
- SMTP host: `mail.elektrine.com`
- SMTP port: `465`
- SMTP secure: `SSL/TLS`
- username: email lengkap, contoh `user@z.org`

## Endpoint Worker

Format response sukses:

```json
{
  "ok": true,
  "data": {}
}
```

Format response gagal:

```json
{
  "ok": false,
  "error": "Pesan aman untuk frontend"
}
```

Endpoint utama:

- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/me`
- `POST /api/mail/test`
- `GET /api/mail/inbox`
- `GET /api/mail/message?id=UID`
- `DELETE /api/mail/message?id=UID`
- `POST /api/mail/send`

## Session dan Security

Sistem security saat ini:

- login divalidasi ke IMAP
- password email tidak dikirim balik ke frontend
- session disimpan di D1
- password email dienkripsi AES-GCM sebelum disimpan
- secret utama diambil dari `MASTER_ENCRYPTION_KEY`
- cookie session memakai:
  - `HttpOnly`
  - `Secure`
  - `SameSite=Lax`
  - `Path=/`

Rate limit sederhana sudah dipasang untuk:

- login
- inbox
- buka message
- delete message
- test mail
- send mail

## Perubahan Frontend

Frontend di [index.html](/D:/Program/Pyhton/arufkuy-webmail/index.html) sekarang:

- login via `fetch("/api/auth/login")`
- cek session via `GET /api/me`
- load inbox via `GET /api/mail/inbox`
- buka pesan via `GET /api/mail/message`
- delete pesan via `DELETE /api/mail/message`
- logout via `POST /api/auth/logout`

Hal yang sudah dihapus dari alur utama frontend:

- Firebase login untuk webmail user
- token auth Firebase di browser
- credential email di `localStorage`
- direct connection dari browser ke backend email

Hal yang sementara belum dilanjutkan:

- change password mailbox dari UI
- compose/send UI di frontend
- notification Firebase lama
- ads Firebase lama
- attachment parsing penuh

## Konfigurasi Frontend API

Saat ini frontend memakai fallback API ini:

```js
const WORKER_API = window.WEBMAIL_API_BASE || "https://arufkuy-webmail.arufcuy.workers.dev";
```

Artinya:

- kalau `window.WEBMAIL_API_BASE` tidak di-set, frontend otomatis memakai Worker production
- kalau ingin override untuk local testing, set `window.WEBMAIL_API_BASE` sebelum script utama

Contoh local:

```html
<script>
  window.WEBMAIL_API_BASE = "http://127.0.0.1:8787";
</script>
```

## Konfigurasi CORS

`CORS_ORIGIN` di [worker/wrangler.toml](/D:/Program/Pyhton/arufkuy-webmail/worker/wrangler.toml) harus berisi origin frontend yang diizinkan.

Contoh:

```toml
CORS_ORIGIN = "http://localhost:5000,http://127.0.0.1:5000,http://localhost:5500,http://127.0.0.1:5500,https://mail.arufkuy.me"
```

Aturan penting:

- origin harus lengkap dengan protocol
- jangan pakai slash di akhir
- kalau frontend dibuka dari port berbeda, origin itu harus ditambahkan
- wildcard `*` tidak boleh dipakai karena request memakai cookie

## Setup Worker

Masuk ke folder Worker:

```powershell
cd D:\Program\Pyhton\arufkuy-webmail\worker
```

Install dependency:

```powershell
npm install
```

Buat D1 database:

```powershell
npx wrangler d1 create arufkuy-webmail
```

Setelah keluar `database_id`, isi ke [worker/wrangler.toml](/D:/Program/Pyhton/arufkuy-webmail/worker/wrangler.toml).

## Setup Secret

Set secret enkripsi:

```powershell
npx wrangler secret put MASTER_ENCRYPTION_KEY
```

Isi dengan string acak yang panjang. Contoh:

```text
mK9x!2Qa7vN#pL4zT8rW1sY6uD@cF3hJpR5nB0eX
```

Secret ini dipakai untuk mengenkripsi password mailbox sebelum disimpan ke D1.

## Menjalankan Schema D1

Untuk database remote yang dipakai Worker hasil deploy:

```powershell
npx wrangler d1 execute arufkuy-webmail --remote --file=schema.sql
```

Kalau hanya untuk eksperimen lokal, bisa tanpa `--remote`, tapi untuk deploy nyata yang dipakai Worker production harus memakai `--remote`.

## Deploy Worker

Deploy:

```powershell
npx wrangler deploy
```

Catatan:

- `compatibility_date` tidak boleh tanggal masa depan
- saat ini project memakai `2026-05-31`

## Local Testing

Jalankan Worker lokal:

```powershell
npx wrangler dev
```

Lalu serve frontend statis, misalnya dari root project:

```powershell
python -m http.server 5000
```

Atau pakai server statis lain yang Anda suka.

Kalau frontend dibuka dari `http://localhost:5000`, pastikan origin itu ada di `CORS_ORIGIN`.

## Alur Troubleshooting

### 1. `wrangler` tidak dikenali

Gunakan:

```powershell
npx wrangler ...
```

bukan `wrangler ...`

### 2. Error `Can't set compatibility date in the future`

Turunkan `compatibility_date` di [worker/wrangler.toml](/D:/Program/Pyhton/arufkuy-webmail/worker/wrangler.toml) ke tanggal yang valid.

### 3. Error CORS

Kalau browser menampilkan:

```text
No 'Access-Control-Allow-Origin' header is present
```

cek:

- origin frontend yang sebenarnya, misal `http://localhost:5000`
- isi `CORS_ORIGIN`
- deploy ulang setelah mengubah `wrangler.toml`

### 4. `GET /api/me` status `401`

Sebelum login, ini normal. Artinya belum ada session cookie aktif.

### 5. `POST /api/auth/login` status `401`

Kemungkinan:

- email atau password mailbox salah
- username tidak memakai email lengkap
- backend menyamarkan kegagalan IMAP sebagai unauthorized

Lihat response JSON pada request login untuk pesan yang lebih spesifik.

### 6. Login gagal karena D1

Kalau backend mengembalikan pesan bahwa session/backend belum siap, jalankan:

```powershell
npx wrangler d1 execute arufkuy-webmail --remote --file=schema.sql
```

lalu deploy ulang:

```powershell
npx wrangler deploy
```

## Keterbatasan MVP Saat Ini

Implementasi sekarang sengaja dibuat minimal dan mudah diganti. Beberapa batasannya:

- IMAP client masih parser minimal
- attachment belum diproses
- HTML email masih diparsing sederhana
- belum ada endpoint ubah password mailbox
- belum ada UI compose yang terhubung ke endpoint send
- notifikasi/ads lama belum dipindah ke backend baru

## Saran Next Step

Tahap lanjutan yang paling masuk akal:

1. pastikan login IMAP + session D1 benar-benar lolos di environment real
2. tambahkan halaman/komponen compose agar `POST /api/mail/send` terpakai
3. tambahkan custom domain untuk Worker agar cookie lebih stabil dibanding `workers.dev`
4. perkuat parser MIME untuk multipart dan attachment
5. tambahkan observability yang lebih jelas untuk error IMAP/SMTP tanpa membocorkan credential

## Checklist Deploy

- [ ] `npm install`
- [ ] `npx wrangler d1 create arufkuy-webmail`
- [ ] `database_id` sudah diisi ke `wrangler.toml`
- [ ] `npx wrangler secret put MASTER_ENCRYPTION_KEY`
- [ ] `CORS_ORIGIN` sudah sesuai domain frontend
- [ ] `npx wrangler d1 execute arufkuy-webmail --remote --file=schema.sql`
- [ ] `npx wrangler deploy`
- [ ] frontend mengarah ke URL Worker yang benar
- [ ] login diuji dengan email penuh `user@z.org`

