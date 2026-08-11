import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import * as jose from "npm:jose@5";

const USERNAME_RE = /^[a-zA-Z0-9_]{3,32}$/;
const TOKEN_TTL = "14d";
const EDITIONS = new Set(["starter", "standard", "plus", "entStd", "entPlus"]);
const STATUS_VAL = new Set(["pass", "fail", "na"]);
const CONTROL_ID = /^[A-D]\d{1,2}$/;

const ALLOWED_ORIGINS = new Set([
  "https://gws-security-assessment.vercel.app",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:4173",
]);

type JwtPayload = { sub: string; username: string };

function originAllowed(origin: string): boolean {
  if (!origin) return false;
  if (ALLOWED_ORIGINS.has(origin)) return true;
  try {
    const u = new URL(origin);
    return u.protocol === "https:" &&
      /^gws-security-assessment(-[a-z0-9-]+)?\.vercel\.app$/.test(u.hostname);
  } catch {
    return false;
  }
}

function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin") ?? "";
  const allow = originAllowed(origin) ? origin : "https://gws-security-assessment.vercel.app";
  return {
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

function json(req: Request, status: number, body: unknown) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders(req), "Content-Type": "application/json" },
  });
}

async function jwtKey() {
  const raw = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!raw) throw new Error("Missing service role");
  return new TextEncoder().encode(raw);
}

async function signToken(payload: JwtPayload) {
  const key = await jwtKey();
  return new jose.SignJWT({ username: payload.username })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(payload.sub)
    .setIssuedAt()
    .setExpirationTime(TOKEN_TTL)
    .sign(key);
}

async function verifyToken(token: string): Promise<JwtPayload | null> {
  try {
    const key = await jwtKey();
    const { payload } = await jose.jwtVerify(token, key);
    const sub = payload.sub;
    const username = payload.username;
    if (typeof sub !== "string" || typeof username !== "string") return null;
    return { sub, username };
  } catch {
    return null;
  }
}

async function hashPassword(password: string): Promise<string> {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 120_000, hash: "SHA-256" },
    keyMaterial,
    256,
  );
  const saltHex = [...salt].map((b) => b.toString(16).padStart(2, "0")).join("");
  const hashHex = [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `pbkdf2:${saltHex}:${hashHex}`;
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split(":");
  if (parts.length !== 3 || parts[0] !== "pbkdf2") return false;
  const salt = new Uint8Array(parts[1].match(/.{1,2}/g)!.map((h) => parseInt(h, 16)));
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 120_000, hash: "SHA-256" },
    keyMaterial,
    256,
  );
  const hashHex = [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return hashHex === parts[2];
}

function adminClient() {
  const url = Deno.env.get("SUPABASE_URL")!;
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  return createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } });
}

function bearer(req: Request): string | null {
  const h = req.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1].trim() : null;
}

async function requireUser(req: Request): Promise<JwtPayload | Response> {
  const token = bearer(req);
  if (!token) return json(req, 401, { error: "Not signed in." });
  const sess = await verifyToken(token);
  if (!sess) return json(req, 401, { error: "Session expired." });
  return sess;
}

function normalizeDomain(raw: string): string {
  let d = String(raw || "").trim().toLowerCase();
  d = d.replace(/^https?:\/\//, "").replace(/^www\./, "");
  d = d.split("/")[0].split("?")[0].replace(/\.$/, "");
  return d;
}

function cleanStatus(input: unknown): Record<string, string> {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
    if (!CONTROL_ID.test(k)) continue;
    if (typeof v !== "string" || !STATUS_VAL.has(v)) continue;
    out[k] = v;
    if (Object.keys(out).length >= 40) break;
  }
  return out;
}

function cleanEdition(raw: unknown, fallback = "entStd"): string {
  const v = String(raw || fallback);
  return EDITIONS.has(v) ? v : fallback;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(req) });
  }

  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "");
  const route = path.endsWith("/gws-audit-api") ? "" : path.split("/gws-audit-api").pop() ?? "";

  try {
    if (req.method === "POST" && (route === "" || route === "/register")) {
      const body = await req.json();
      const username = String(body.username ?? "").trim();
      const password = String(body.password ?? "");
      if (!USERNAME_RE.test(username)) {
        return json(req, 400, { error: "Username must be 3–32 characters: letters, numbers, underscore." });
      }
      if (password.length < 8) {
        return json(req, 400, { error: "Password must be at least 8 characters." });
      }
      const password_hash = await hashPassword(password);
      const db = adminClient();
      const { data, error } = await db
        .from("gws_audit_users")
        .insert({ username, password_hash })
        .select("id, username")
        .single();
      if (error) {
        if (error.code === "23505") return json(req, 409, { error: "That username is taken." });
        throw error;
      }
      const token = await signToken({ sub: data.id, username: data.username });
      return json(req, 200, { token, user: { id: data.id, username: data.username } });
    }

    if (req.method === "POST" && route === "/login") {
      const body = await req.json();
      const username = String(body.username ?? "").trim();
      const password = String(body.password ?? "");
      if (!username || !password) return json(req, 400, { error: "Username and password required." });
      const db = adminClient();
      const { data: user, error } = await db
        .from("gws_audit_users")
        .select("id, username, password_hash")
        .eq("username", username)
        .maybeSingle();
      if (error) throw error;
      if (!user || !(await verifyPassword(password, user.password_hash))) {
        return json(req, 401, { error: "Wrong username or password." });
      }
      const token = await signToken({ sub: user.id, username: user.username });
      return json(req, 200, { token, user: { id: user.id, username: user.username } });
    }

    if (req.method === "GET" && route === "/session") {
      const auth = await requireUser(req);
      if (auth instanceof Response) return auth;
      return json(req, 200, { user: { id: auth.sub, username: auth.username } });
    }

    if (req.method === "GET" && route === "/companies") {
      const auth = await requireUser(req);
      if (auth instanceof Response) return auth;
      const db = adminClient();
      const { data: companies, error } = await db
        .from("gws_audit_companies")
        .select("id, name, domain, edition, created_at, updated_at")
        .eq("owner_id", auth.sub)
        .order("updated_at", { ascending: false });
      if (error) throw error;
      const ids = (companies ?? []).map((c) => c.id);
      let latest: Record<string, { id: string; score_pct: number | null; assessment_date: string | null; updated_at: string }> = {};
      if (ids.length) {
        const { data: rows, error: aerr } = await db
          .from("gws_audit_assessments")
          .select("id, company_id, score_pct, assessment_date, updated_at")
          .eq("owner_id", auth.sub)
          .in("company_id", ids)
          .order("updated_at", { ascending: false });
        if (aerr) throw aerr;
        for (const row of rows ?? []) {
          if (!latest[row.company_id]) latest[row.company_id] = row;
        }
      }
      return json(req, 200, {
        companies: (companies ?? []).map((c) => ({
          ...c,
          latest: latest[c.id] ?? null,
        })),
      });
    }

    if (req.method === "POST" && route === "/companies") {
      const auth = await requireUser(req);
      if (auth instanceof Response) return auth;
      const body = await req.json();
      const name = String(body.name ?? "").trim();
      const domain = normalizeDomain(body.domain ?? "");
      const edition = cleanEdition(body.edition);
      if (!name || !domain) return json(req, 400, { error: "Client name and domain are required." });
      const db = adminClient();
      const { data, error } = await db
        .from("gws_audit_companies")
        .upsert(
          { owner_id: auth.sub, name, domain, edition, updated_at: new Date().toISOString() },
          { onConflict: "owner_id,domain" },
        )
        .select("id, name, domain, edition, created_at, updated_at")
        .single();
      if (error) throw error;
      return json(req, 200, { company: data });
    }

    if (req.method === "GET" && route === "/assessments") {
      const auth = await requireUser(req);
      if (auth instanceof Response) return auth;
      const companyId = url.searchParams.get("company_id") || "";
      if (!companyId) return json(req, 400, { error: "company_id required." });
      const db = adminClient();
      const { data, error } = await db
        .from("gws_audit_assessments")
        .select("id, company_id, auditor_name, assessment_date, edition, assess_gemini, score_pct, score_earned, score_possible, maturity_level, created_at, updated_at")
        .eq("owner_id", auth.sub)
        .eq("company_id", companyId)
        .order("updated_at", { ascending: false })
        .limit(50);
      if (error) throw error;
      return json(req, 200, { assessments: data ?? [] });
    }

    const one = /^\/assessments\/([0-9a-f-]{36})$/i.exec(route);

    if (req.method === "GET" && one) {
      const auth = await requireUser(req);
      if (auth instanceof Response) return auth;
      const db = adminClient();
      const { data, error } = await db
        .from("gws_audit_assessments")
        .select("*, gws_audit_companies!inner(id, name, domain, edition)")
        .eq("owner_id", auth.sub)
        .eq("id", one[1])
        .maybeSingle();
      if (error) throw error;
      if (!data) return json(req, 404, { error: "Assessment not found." });
      return json(req, 200, { assessment: data });
    }

    if (req.method === "DELETE" && one) {
      const auth = await requireUser(req);
      if (auth instanceof Response) return auth;
      const db = adminClient();
      const { error } = await db
        .from("gws_audit_assessments")
        .delete()
        .eq("owner_id", auth.sub)
        .eq("id", one[1]);
      if (error) throw error;
      return json(req, 200, { ok: true });
    }

    if (req.method === "PUT" && one) {
      const auth = await requireUser(req);
      if (auth instanceof Response) return auth;
      const body = await req.json();
      const db = adminClient();
      const patch: Record<string, unknown> = {
        auditor_name: String(body.auditor_name ?? "").trim().slice(0, 120) || null,
        assessment_date: body.assessment_date || null,
        edition: cleanEdition(body.edition),
        assess_gemini: !!body.assess_gemini,
        status: cleanStatus(body.status),
        score_pct: Number.isFinite(body.score_pct) ? Math.round(body.score_pct) : null,
        score_earned: Number.isFinite(body.score_earned) ? Math.round(body.score_earned) : null,
        score_possible: Number.isFinite(body.score_possible) ? Math.round(body.score_possible) : null,
        maturity_level: Number.isFinite(body.maturity_level) ? Math.round(body.maturity_level) : null,
        updated_at: new Date().toISOString(),
      };
      const { data, error } = await db
        .from("gws_audit_assessments")
        .update(patch)
        .eq("owner_id", auth.sub)
        .eq("id", one[1])
        .select("id, company_id, updated_at, score_pct")
        .maybeSingle();
      if (error) throw error;
      if (!data) return json(req, 404, { error: "Assessment not found." });
      if (data.company_id) {
        const companyPatch: Record<string, unknown> = {
          edition: cleanEdition(body.edition),
          updated_at: new Date().toISOString(),
        };
        const nextName = String(body.client_name ?? "").trim();
        if (nextName) companyPatch.name = nextName;
        await db.from("gws_audit_companies").update(companyPatch).eq("id", data.company_id).eq("owner_id", auth.sub);
      }
      return json(req, 200, { assessment: data });
    }

    if (req.method === "POST" && route === "/assessments") {
      const auth = await requireUser(req);
      if (auth instanceof Response) return auth;
      const body = await req.json();
      const name = String(body.client_name ?? "").trim();
      const domain = normalizeDomain(body.domain ?? "");
      const edition = cleanEdition(body.edition);
      if (!name || !domain) return json(req, 400, { error: "Client name and domain are required to save." });
      const db = adminClient();
      const { data: company, error: cerr } = await db
        .from("gws_audit_companies")
        .upsert(
          { owner_id: auth.sub, name, domain, edition, updated_at: new Date().toISOString() },
          { onConflict: "owner_id,domain" },
        )
        .select("id, name, domain, edition")
        .single();
      if (cerr) throw cerr;

      const row = {
        owner_id: auth.sub,
        company_id: company.id,
        auditor_name: String(body.auditor_name ?? "").trim().slice(0, 120) || null,
        assessment_date: body.assessment_date || null,
        edition,
        assess_gemini: body.assess_gemini !== false,
        status: cleanStatus(body.status),
        score_pct: Number.isFinite(body.score_pct) ? Math.round(body.score_pct) : null,
        score_earned: Number.isFinite(body.score_earned) ? Math.round(body.score_earned) : null,
        score_possible: Number.isFinite(body.score_possible) ? Math.round(body.score_possible) : null,
        maturity_level: Number.isFinite(body.maturity_level) ? Math.round(body.maturity_level) : null,
        updated_at: new Date().toISOString(),
      };

      if (body.assessment_id) {
        const { data, error } = await db
          .from("gws_audit_assessments")
          .update(row)
          .eq("owner_id", auth.sub)
          .eq("id", body.assessment_id)
          .select("id, company_id, updated_at, score_pct")
          .maybeSingle();
        if (error) throw error;
        if (!data) return json(req, 404, { error: "Assessment not found." });
        return json(req, 200, { company, assessment: data, updated: true });
      }

      const { data, error } = await db
        .from("gws_audit_assessments")
        .insert(row)
        .select("id, company_id, updated_at, score_pct")
        .single();
      if (error) throw error;
      return json(req, 200, { company, assessment: data, updated: false });
    }

    return json(req, 404, { error: "Not found." });
  } catch (e) {
    console.error(e);
    return json(req, 500, { error: "Server error." });
  }
});
