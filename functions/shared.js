// shared.js
// All shared helpers used by both app.js and exams.js
// Exported as a factory function that receives (request, env) and returns all helpers

export function createHelpers(request, env) {

  // ---------- Constants ----------
  const PEPPER = env.APP_SECRET || "";

  // ---------- Basic helpers ----------
  const nowISO = () => new Date().toISOString();
  const uuid = () => crypto.randomUUID();

  // ---------- HTML ----------
  function page(body, status = 200, headers = {}) {
    return new Response(
      `<!doctype html><html><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>QAcademy</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f8f7;color:#1f2a28}
  .wrap{max-width:980px;margin:0 auto;padding:18px}
  .card{background:#fff;border:1px solid rgba(0,0,0,.08);border-radius:14px;padding:16px;margin:12px 0}
  h1{font-size:20px;margin:0 0 8px}
  h2{font-size:16px;margin:14px 0 8px}
  label{display:block;font-size:13px;margin:10px 0 6px}
  input,select{width:100%;padding:10px;border:1px solid rgba(0,0,0,.14);border-radius:10px}
  button{padding:10px 14px;border:0;border-radius:10px;background:#0b7a75;color:#fff;font-weight:700;cursor:pointer}
  .muted{color:rgba(0,0,0,.6);font-size:13px}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
  @media(max-width:720px){.row{grid-template-columns:1fr}}
  .topbar{display:flex;gap:10px;align-items:center;justify-content:space-between;margin:6px 0 10px}
  a{color:#0b7a75;text-decoration:none}
  .pill{display:inline-block;padding:5px 10px;border-radius:999px;background:rgba(11,122,117,.10);color:#0b7a75;font-weight:700;font-size:12px}
  .err{background:#fff3f3;border:1px solid rgba(255,0,0,.18);padding:10px;border-radius:10px}
  .ok{background:#f0fff8;border:1px solid rgba(0,200,120,.18);padding:10px;border-radius:10px}
  .table{width:100%;border-collapse:collapse;font-size:14px}
  .table th,.table td{border-top:1px solid rgba(0,0,0,.08);padding:10px;vertical-align:top}
  .table th{font-size:12px;color:rgba(0,0,0,.55);text-transform:uppercase;letter-spacing:.04em}
  .small{font-size:12px}
  .actions{display:flex;gap:8px;flex-wrap:wrap}
  .btn2{background:#0b7a75;color:#fff;border-radius:10px;padding:8px 12px;border:0;font-weight:700;cursor:pointer}
  .btn3{background:#eaeef0;color:#1f2a28;border-radius:10px;padding:8px 12px;border:0;font-weight:700;cursor:pointer}
</style>
</head><body><div class="wrap">${body}</div></body></html>`,
      {
        status,
        headers: { "content-type": "text/html; charset=utf-8", ...headers },
      }
    );
  }

  const redirect = (to, headers = {}) =>
    new Response(null, { status: 302, headers: { Location: to, ...headers } });

  const escapeHtml = (s) =>
    String(s ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");

  const escapeAttr = (s) => escapeHtml(s).replaceAll("`", "&#096;");

  const roleLabel = (r) => {
    if (r === "SCHOOL_ADMIN") return "School Admin";
    if (r === "TEACHER") return "Teacher";
    if (r === "STUDENT") return "Student";
    return r || "";
  };

  const fmtISO = (iso) => {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString("en-GB", { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  };

  // Handles repeated field names like band_label[] correctly
  async function form() {
    const fd = await request.formData();
    const out = {};
    for (const [k] of fd.entries()) {
      if (out[k] !== undefined) continue;
      const vals = fd.getAll(k);
      out[k] = vals.length === 1 ? String(vals[0]).trim() : vals.map((v) => String(v).trim());
    }
    return out;
  }

  // ---------- Crypto ----------
  const toHex = (buf) =>
    [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

  const sha256Hex = async (text) => {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return toHex(digest);
  };

  const randomSaltHex = () => {
    const a = new Uint8Array(16);
    crypto.getRandomValues(a);
    return toHex(a.buffer);
  };

  const pbkdf2Hex = async (password, saltHex, iterations) => {
    const salt = Uint8Array.from(saltHex.match(/../g).map((x) => parseInt(x, 16)));
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      keyMaterial,
      256
    );
    return toHex(bits);
  };

  // ---------- Cookies ----------
  const cookieGet = (name) => {
    const raw = request.headers.get("Cookie") || "";
    for (const part of raw.split(";")) {
      const p = part.trim();
      const i = p.indexOf("=");
      if (i < 0) continue;
      if (p.slice(0, i) === name) return decodeURIComponent(p.slice(i + 1));
    }
    return null;
  };

  const cookieSet = (name, value, maxAgeSec) =>
    `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`;

  const cookieClear = (name) => `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

  // ---------- DB helpers ----------
  const first = async (sql, params = []) => await env.DB.prepare(sql).bind(...params).first();

  const all = async (sql, params = []) => {
    const res = await env.DB.prepare(sql).bind(...params).all();
    return res.results || [];
  };

  const run = async (sql, params = []) => await env.DB.prepare(sql).bind(...params).run();

  // ---------- Auth ----------
  async function loadAuth() {
    const token = cookieGet("qa_sess");
    if (!token) return { user: null, session: null, memberships: [] };

    const tokenHash = await sha256Hex(token);
    const session = await first(
      "SELECT token_hash, user_id, active_tenant_id, expires_at FROM sessions WHERE token_hash=?",
      [tokenHash]
    );
    if (!session) return { user: null, session: null, memberships: [] };

    if (Date.parse(session.expires_at) < Date.now()) {
      await run("DELETE FROM sessions WHERE token_hash=?", [tokenHash]);
      return { user: null, session: null, memberships: [] };
    }

    const user = await first(
      "SELECT id,email,name,is_system_admin FROM users WHERE id=? AND status='ACTIVE'",
      [session.user_id]
    );
    if (!user) return { user: null, session: null, memberships: [] };

    const memberships = await all(
      `SELECT m.tenant_id, m.role, t.name AS tenant_name
       FROM memberships m
       JOIN tenants t ON t.id = m.tenant_id
       WHERE m.user_id=? AND m.status='ACTIVE' AND t.status='ACTIVE'
       ORDER BY t.name ASC`,
      [user.id]
    );

    return { user, session, memberships };
  }

  async function requireLogin() {
    const a = await loadAuth();
    if (!a.user) return { ok: false, res: redirect("/login") };
    return { ok: true, ...a };
  }

  function pickActiveMembership(a) {
    const tid = a.session?.active_tenant_id;
    if (!tid) return null;
    return a.memberships.find((m) => m.tenant_id === tid) || null;
  }

  async function setActiveTenantForCurrentSession(tenantId) {
    const token = cookieGet("qa_sess");
    if (!token) return;
    const tokenHash = await sha256Hex(token);
    await run("UPDATE sessions SET active_tenant_id=? WHERE token_hash=?", [tenantId, tokenHash]);
  }

  async function createSessionForUser(userId) {
    const token = uuid() + "-" + uuid();
    const tokenHash = await sha256Hex(token);
    const ts = nowISO();
    const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString();
    await run(
      "INSERT INTO sessions (token_hash,user_id,active_tenant_id,expires_at,created_at) VALUES (?,?,?,?,?)",
      [tokenHash, userId, null, expires, ts]
    );
    return {
      token,
      headers: { "Set-Cookie": cookieSet("qa_sess", token, 60 * 60 * 24 * 7) },
    };
  }

  // ---------- Return everything ----------
  return {
    // constants
    PEPPER,
    // basic
    nowISO, uuid,
    // html
    page, redirect, escapeHtml, escapeAttr, roleLabel, fmtISO, form,
    // crypto
    toHex, sha256Hex, randomSaltHex, pbkdf2Hex,
    // cookies
    cookieGet, cookieSet, cookieClear,
    // db
    first, all, run,
    // auth
    loadAuth, requireLogin, pickActiveMembership,
    setActiveTenantForCurrentSession, createSessionForUser,
  };
}
