### Arsitektur Baru
Frontend statis sekarang ditujukan untuk memanggil Cloudflare Worker API via cookie session.

### Deploy Worker
```bash
cd worker
npm install
wrangler d1 create arufkuy-webmail
wrangler d1 execute arufkuy-webmail --file=schema.sql
wrangler secret put MASTER_ENCRYPTION_KEY
wrangler deploy
```

### Konfigurasi Penting
- Set `database_id` di [worker/wrangler.toml](/D:/Program/Pyhton/arufkuy-webmail/worker/wrangler.toml)
- Set `CORS_ORIGIN` ke domain frontend webmail
- Pastikan frontend dan Worker berbagi origin `/api` atau set `window.WEBMAIL_API_BASE`

### Auto Fill Login
```text
user@z.org:password-email
```
