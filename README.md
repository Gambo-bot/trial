# NPP Constituency Register (backend + web app)

Node.js + Express + SQLite. One shared database, server-side login, roles, staff approval, per-staff record isolation and an audit log.

## Run it
```bash
npm install
npm start                 # http://localhost:3000
```
Requires Node 20+. First start creates `data/register.db` and two administrator accounts
(`admin`, `admin2`). Their one-time passwords were given to you separately; each must be changed at first sign-in.
Add more administrators any time: `node create-admin.js <username> "<Full name>"` (prints a one-time password).

## Deploy (production checklist)
1. Host on a small VPS (Ubuntu), Render, Railway, Fly.io, or with the included `Dockerfile` (mount `/app/data` as a persistent volume).
2. **Serve over HTTPS** (e.g. Caddy: `yourdomain.com { reverse_proxy localhost:3000 }` gives automatic certificates).
3. Set environment variables from `.env.example`: `COOKIE_SECURE=true`, `TRUST_PROXY=1`.
4. **Back up `data/register.db` daily** (copy the file while the app is idle, or use `sqlite3 data/register.db ".backup backup.db"`), and store copies off the server.
5. Keep the server, Node and npm packages updated (`npm audit`, `npm update`).
6. Restrict server access (SSH keys only, firewall open on 80/443 only).

## Who can do what
| | Staff | Administrator |
|---|---|---|
| Sign up | Request access; must be approved | Approves / rejects requests |
| Records | Add; view, edit and export **only their own** | View, edit, delete, import, export **all** |
| Users | - | Create, disable/enable, reset passwords |
| Audit log | - | Full log (sign-ins, record changes, exports, approvals) |

## Security built in
- Passwords hashed with bcrypt (cost 12); minimum 10 characters; forced change for new/reset accounts.
- Random session tokens in HttpOnly, SameSite=Strict cookies (Secure over HTTPS); 30-min idle and 8-hour absolute limits.
- Account lockout (5 failures, 15 min) plus per-IP rate limits on sign-in and registration.
- Staff isolation is enforced in the database queries, not just the screen.
- CSRF header check, strict Content-Security-Policy and other helmet headers, parameterised SQL, escaped output.
- CSV export neutralises spreadsheet formula injection.
- Audit log stores which fields changed, not the personal data itself.

## Data protection (Ghana)
This holds personal data of voters. Under the Data Protection Act, 2012 (Act 843), the organisation operating it is a data controller and should
register with the Data Protection Commission, collect only what it needs, tell people how their data is used, keep it secure and
delete it when no longer needed. Get legal advice on consent and retention for political data.

## Files
`server.js` API and security · `public/` web app (`index.html`, `app.js`, `style.css`) · `create-admin.js` add admins · `seed-admins.json` first-run admin hashes (hashes only, no passwords).
