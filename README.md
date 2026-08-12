# Google Workspace Security Posture Assessment

Client-facing checklist (CIS GWS Foundations v1.4.0 + Admin Security Health + Gemini controls) with optional cloud storage.

## Live

https://gws-security-assessment.vercel.app

- Assessment: `/` (`index.html`)
- Docs (two tabs): [`/levels.html`](https://gws-security-assessment.vercel.app/levels.html) — **Slim security levels** + **Full delivery playbook**

Repo: https://github.com/azibfikri/gws-security-assessment

Create a consultant account on the site (Sign in / Create account), then **Save to cloud**. Each auditor only sees their own companies.

## Local

Open `index.html`, or:

```bash
npx serve .
```

Cloud save requires the deployed Supabase function. `file://` drafts still work locally.

## Cloud data (Supabase)

Dedicated project (not the Study Desk DB): `dgkundohraqgdvctjonq` (ap-southeast-1)
Dashboard: https://supabase.com/dashboard/project/dgkundohraqgdvctjonq

| Table | Purpose |
|---|---|
| `gws_audit_users` | Consultant accounts (PBKDF2 hashes) |
| `gws_audit_companies` | Client company per auditor + domain |
| `gws_audit_assessments` | Checklist snapshots + scores |

RLS is on; `anon` / `authenticated` have no grants. The browser never talks to PostgREST. All reads/writes go through Edge Function `gws-audit-api` (service role, custom JWT, `verify_jwt: false`).

Each auditor only sees their own companies.

## Deploy

```bash
node scripts/write-config.js
npx vercel --prod --yes
```

Public env (optional overrides):

- `GWS_AUDIT_API_BASE`
- `GWS_SUPABASE_ANON_KEY` (anon / publishable only — never a service role)
