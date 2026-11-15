# Readiness assessment on Cloudflare (Worker + D1 + R2)

Same app and rules as `../live`, ported to Cloudflare:

| live (Node) | Cloudflare |
|---|---|
| SQLite file | **D1** (`readiness-db`) |
| `uploads/` folder | **R2** bucket (`readiness-files`) |
| scrypt | PBKDF2-SHA256 (Web Crypto) |
| in-memory login lockout | table in D1 (shared between instances) |

`public/index.html` and `src/generated/*` are produced by `npm run build` from `../live/source.html` and the patches in `../live/server.js`, so both versions stay in sync. The database starts with **only the `admin` user** and no demo data.

## Deploy (once)

```
cd cf
npm install
npx wrangler login
npx wrangler d1 create readiness-db          # copy the printed database_id into wrangler.toml
npx wrangler r2 bucket create readiness-files
npm run db:migrate:remote                    # creates the tables and the admin user
npm run deploy                               # builds and publishes; prints the https://readiness.<you>.workers.dev URL
npx wrangler secret put ADMIN_PASSWORD       # type the admin password
```

Log in as `admin` with the password you put in `ADMIN_PASSWORD`. On that first login it is stored hashed in D1; afterwards it can be changed from the «رمز» button, and the secret is no longer used.
New users get the default password shown on the users page.

## Local run and tests

```
echo ADMIN_PASSWORD=13741011 > .dev.vars     # local only, git-ignored
npm run dev                                  # http://localhost:8787 (local D1/R2 emulation)
npm test                                     # in another terminal; needs a fresh local database
```

## Notes

- PBKDF2 runs 100 000 iterations (the Workers maximum). On the **Workers Free** plan the 10 ms CPU limit can make logins fail with error 1102; the **Paid** plan ($5/month) avoids it. Lowering `PBKDF2_ITER` in `wrangler.toml` trades security for CPU.
- D1 limits: ~2 MB per stored value (one assessment's answers), so the Worker refuses larger saves. The Free plan allows 50 queries per request; the Worker writes only changed rows to stay under that.
- Evidence files go to R2 (≤ 50 MB each, ≤ 10 per question); R2 must be enabled on the account.
- The page viewer loads pdf.js/docx-preview from public CDNs, as in the live version.
- Concurrency is still last-write-wins per save.
