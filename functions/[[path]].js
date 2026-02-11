/* ============================================================
   Project Beta (Pages + D1) — Multi-school core + Join Codes
   BUILD: beta-joincodes-2026-02-11

   Routes:
   - /health
   - /setup
   - /login
   - /logout
   - /sys                 (System Admin)
   - /school               (School Admin)
   - /teacher              (Teacher)
   - /student              (Student)
   - /choose-school
   - /switch-school
   - /join                 (Public join)
   - /profile              (Account + change password)
   - /no-access
============================================================ */

const BUILD = "beta-joincodes-2026-02-11";

/** =========================
 *  Small helpers
 *  ========================= */

function nowISO() {
  return new Date().toISOString();
}
function addDaysISO(days) {
  return new Date(Date.now() + days * 86400000).toISOString();
}
function htmlEscape(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
function qs(url) {
  return new URL(url).searchParams;
}
function normalizePath(p) {
  if (!p) return "/";
  if (p.length > 1 && p.endsWith("/")) return p.slice(0, -1);
  return p;
}
function redirect(location, headers = new Headers()) {
  headers.set("Location", location);
  return new Response(null, { status: 302, headers });
}
function json(obj, status = 200, headers = new Headers()) {
  headers.set("Content-Type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(obj, null, 2), { status, headers });
}
function text(body, status = 200, headers = new Headers()) {
  headers.set("Content-Type", "text/plain; charset=utf-8");
  return new Response(body, { status, headers });
}
function page(title, bodyHtml, extraHead = "") {
  const css = `
    :root{--b:#0b7a75;--ink:#0f172a;--mut:#64748b;--bg:#f6f8f7;--card:#fff;--line:rgba(2,6,23,.10)}
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--ink)}
    a{color:var(--b);text-decoration:none}
    a:hover{text-decoration:underline}
    .wrap{max-width:980px;margin:0 auto;padding:18px}
    .top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}
    .brand{display:flex;align-items:center;gap:10px}
    .chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);background:#fff;padding:6px 10px;border-radius:999px;font-size:12px;color:var(--mut)}
    .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin:12px 0}
    .grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px}
    .col6{grid-column:span 6}
    .col12{grid-column:span 12}
    @media(max-width:820px){.col6{grid-column:span 12}}
    h1{font-size:20px;margin:0}
    h2{font-size:16px;margin:0 0 10px}
    .mut{color:var(--mut);font-size:13px}
    label{display:block;font-size:13px;color:var(--mut);margin-bottom:6px}
    input,select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:12px;background:#fff;font-size:14px}
    button{border:0;border-radius:12px;background:var(--b);color:#fff;padding:10px 12px;font-weight:600;cursor:pointer}
    button.secondary{background:#0f172a}
    button.ghost{background:#fff;color:var(--ink);border:1px solid var(--line)}
    button.danger{background:#b42318}
    .row{display:flex;gap:10px;flex-wrap:wrap}
    table{width:100%;border-collapse:collapse}
    th,td{padding:10px;border-top:1px solid var(--line);text-align:left;font-size:14px;vertical-align:top}
    th{font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
    .warn{background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;padding:10px;border-radius:12px}
    .ok{background:#ecfdf5;border:1px solid #a7f3d0;color:#065f46;padding:10px;border-radius:12px}
    .err{background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:10px;border-radius:12px}
    .hr{height:1px;background:var(--line);margin:10px 0}
  `;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${htmlEscape(title)}</title>
<style>${css}</style>
${extraHead}
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand">
      <div style="width:10px;height:10px;border-radius:3px;background:var(--b)"></div>
      <div>
        <div style="font-weight:800">Project Beta</div>
        <div class="mut">Build: ${htmlEscape(BUILD)}</div>
      </div>
    </div>
    <div class="row">
      <a class="chip" href="/health">/health</a>
      <a class="chip" href="/profile">Profile</a>
      <a class="chip" href="/logout">Logout</a>
    </div>
  </div>
  ${bodyHtml}
</div>
</body>
</html>`;
}

function parseCookies(cookieHeader) {
  const out = {};
  const s = cookieHeader || "";
  s.split(";").forEach(part => {
    const [k, ...rest] = part.trim().split("=");
    if (!k) return;
    out[k] = decodeURIComponent(rest.join("=") || "");
  });
  return out;
}

function setCookie(headers, name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || "/"}`);
  if (opts.httpOnly !== false) parts.push("HttpOnly");
  if (opts.secure !== false) parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite || "Lax"}`);
  if (opts.maxAge != null) parts.push(`Max-Age=${opts.maxAge}`);
  headers.append("Set-Cookie", parts.join("; "));
}

function clearCookie(headers, name) {
  headers.append("Set-Cookie", `${name}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
}

/** =========================
 *  DB helpers (D1)
 *  ========================= */
async function dbFirst(db, sql, params = []) {
  return await db.prepare(sql).bind(...params).first();
}
async function dbAll(db, sql, params = []) {
  const r = await db.prepare(sql).bind(...params).all();
  return r.results || [];
}
async function dbRun(db, sql, params = []) {
  return await db.prepare(sql).bind(...params).run();
}

/** =========================
 *  Password hashing (PBKDF2 SHA-256)
 *  Stored format:
 *  pbkdf2_sha256$40000$<saltB64>$<hashB64>
 *  ========================= */

function toB64(u8) {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function fromB64(b64) {
  const s = atob(b64);
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}
function timingSafeEqual(a, b) {
  if (!a || !b) return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function pbkdf2Sha256(password, saltU8, iterations, lengthBytes = 32) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltU8, iterations },
    keyMaterial,
    lengthBytes * 8
  );
  return new Uint8Array(bits);
}

async function hashPassword(password, env) {
  const pepper = env.APP_SECRET || "";
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iters = 40000;
  const derived = await pbkdf2Sha256(`${password}:${pepper}`, salt, iters, 32);
  return `pbkdf2_sha256$${iters}$${toB64(salt)}$${toB64(derived)}`;
}

async function verifyPassword(password, env, stored) {
  if (!stored || typeof stored !== "string") return false;
  const parts = stored.split("$");
  if (parts.length !== 4) return false;
  const [alg, itersStr, saltB64, hashB64] = parts;
  if (alg !== "pbkdf2_sha256") return false;

  const pepper = env.APP_SECRET || "";
  const iters = Number(itersStr);
  if (!Number.isFinite(iters) || iters < 10000) return false;

  const salt = fromB64(saltB64);
  const expected = fromB64(hashB64);
  const actual = await pbkdf2Sha256(`${password}:${pepper}`, salt, iters, expected.length);
  return timingSafeEqual(actual, expected);
}

/** =========================
 *  Session + auth
 *  ========================= */

const COOKIE_NAME = "sid";
const SESSION_MAX_AGE = 60 * 60 * 24 * 30; // 30 days

async function getSession(db, req) {
  const cookies = parseCookies(req.headers.get("Cookie") || "");
  const sid = cookies[COOKIE_NAME];
  if (!sid) return null;

  const sess = await dbFirst(
    db,
    `SELECT id, user_id, expires_at, active_school_id
     FROM sessions
     WHERE id = ?`,
    [sid]
  );
  if (!sess) return null;
  const exp = new Date(sess.expires_at).getTime();
  if (!Number.isFinite(exp) || exp <= Date.now()) return null;

  const user = await dbFirst(
    db,
    `SELECT id, email, name, is_system_admin, password_hash, created_at
     FROM users
     WHERE id = ?`,
    [sess.user_id]
  );
  if (!user) return null;

  return { sid, sess, user };
}

async function requireAuth(ctx) {
  const s = await getSession(ctx.env.DB, ctx.request);
  if (!s) {
    const u = new URL(ctx.request.url);
    const next = encodeURIComponent(u.pathname + u.search);
    return { ok: false, res: redirect(`/login?next=${next}`) };
  }
  return { ok: true, ...s };
}

async function setActiveSchool(db, sid, schoolId) {
  await dbRun(db, `UPDATE sessions SET active_school_id = ? WHERE id = ?`, [schoolId, sid]);
}

async function getMembership(db, userId, schoolId) {
  return await dbFirst(
    db,
    `SELECT m.id, m.role, m.school_id, s.name AS school_name
     FROM memberships m
     JOIN schools s ON s.id = m.school_id
     WHERE m.user_id = ? AND m.school_id = ?`,
    [userId, schoolId]
  );
}

async function listMemberships(db, userId) {
  return await dbAll(
    db,
    `SELECT m.school_id, m.role, s.name AS school_name
     FROM memberships m
     JOIN schools s ON s.id = m.school_id
     WHERE m.user_id = ?
     ORDER BY s.name ASC`,
    [userId]
  );
}

function dashPathForRole(role) {
  if (role === "school_admin") return "/school";
  if (role === "teacher") return "/teacher";
  if (role === "student") return "/student";
  return "/no-access";
}

async function landingForUser(db, sid, userId, activeSchoolId) {
  const ms = await listMemberships(db, userId);
  if (ms.length === 0) return { path: "/no-access" };

  if (activeSchoolId) {
    const m = ms.find(x => String(x.school_id) === String(activeSchoolId));
    if (m) return { path: dashPathForRole(m.role) };
  }

  if (ms.length === 1) {
    await setActiveSchool(db, sid, ms[0].school_id);
    return { path: dashPathForRole(ms[0].role) };
  }

  return { path: "/choose-school" };
}

/** =========================
 *  Join codes + requests
 *  ========================= */

function genJoinCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < 8; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
  return out;
}

async function loadJoinCode(db, codeStr) {
  const row = await dbFirst(
    db,
    `SELECT jc.*, s.name AS school_name
     FROM join_codes jc
     JOIN schools s ON s.id = jc.school_id
     WHERE jc.code = ?`,
    [codeStr]
  );
  if (!row) return { ok: false, reason: "Invalid code." };

  if (row.revoked_at) return { ok: false, reason: "This code has been revoked." };
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
    return { ok: false, reason: "This code has expired." };
  }
  if (row.max_uses != null && row.uses_count >= row.max_uses) {
    return { ok: false, reason: "This code has reached its maximum uses." };
  }
  return { ok: true, row };
}

async function createJoinRequest(db, userId, codeRow) {
  // If user already has membership, treat as "already in school" (still allow role-change via request)
  const existing = await dbFirst(
    db,
    `SELECT id, role FROM memberships WHERE user_id = ? AND school_id = ?`,
    [userId, codeRow.school_id]
  );

  // Prevent duplicate pending requests for same school/user
  const pending = await dbFirst(
    db,
    `SELECT id FROM join_requests
     WHERE user_id = ? AND school_id = ? AND status = 'pending'`,
    [userId, codeRow.school_id]
  );
  if (pending) {
    return { ok: true, status: "pending", message: "Request already pending." };
  }

  const createdAt = nowISO();

  // Insert request
  const ins = await dbRun(
    db,
    `INSERT INTO join_requests (school_id, user_id, code_id, role, status, created_at)
     VALUES (?, ?, ?, ?, 'pending', ?)`,
    [codeRow.school_id, userId, codeRow.id, codeRow.role, createdAt]
  );

  const reqId = ins.meta?.last_row_id;

  if (Number(codeRow.auto_approve) === 1) {
    // Auto-approve immediately
    const approved = await approveJoinRequest(db, reqId, null /* decided_by */, { allowRoleUpdate: true });
    return approved.ok
      ? { ok: true, status: "approved", message: existing ? "Role updated and approved." : "Approved and added to school.", school_id: codeRow.school_id }
      : { ok: false, reason: approved.reason || "Auto-approval failed." };
  }

  return { ok: true, status: "pending", message: "Request sent for approval." };
}

async function approveJoinRequest(db, requestId, decidedByUserId, opts = {}) {
  const req = await dbFirst(
    db,
    `SELECT jr.*, jc.max_uses, jc.uses_count, jc.school_id AS code_school_id, jc.role AS code_role
     FROM join_requests jr
     JOIN join_codes jc ON jc.id = jr.code_id
     WHERE jr.id = ?`,
    [requestId]
  );
  if (!req) return { ok: false, reason: "Request not found." };
  if (req.status !== "pending") return { ok: false, reason: "Request is not pending." };

  // Enforce max_uses at approval time
  if (req.max_uses != null && req.uses_count >= req.max_uses) {
    return { ok: false, reason: "Code has reached max uses; cannot approve." };
  }

  // Create or update membership
  const existing = await dbFirst(
    db,
    `SELECT id, role FROM memberships WHERE user_id = ? AND school_id = ?`,
    [req.user_id, req.school_id]
  );

  if (!existing) {
    await dbRun(
      db,
      `INSERT INTO memberships (user_id, school_id, role, created_at)
       VALUES (?, ?, ?, ?)`,
      [req.user_id, req.school_id, req.role, nowISO()]
    );
  } else if (opts.allowRoleUpdate) {
    await dbRun(
      db,
      `UPDATE memberships SET role = ? WHERE id = ?`,
      [req.role, existing.id]
    );
  }

  await dbRun(
    db,
    `UPDATE join_requests
     SET status = 'approved',
         decided_by = ?,
         decided_at = ?
     WHERE id = ?`,
    [decidedByUserId, nowISO(), requestId]
  );

  // Increment uses_count
  await dbRun(db, `UPDATE join_codes SET uses_count = uses_count + 1 WHERE id = ?`, [req.code_id]);

  return { ok: true, school_id: req.school_id, role: req.role };
}

async function rejectJoinRequest(db, requestId, decidedByUserId, note = "") {
  const req = await dbFirst(db, `SELECT id, status FROM join_requests WHERE id = ?`, [requestId]);
  if (!req) return { ok: false, reason: "Request not found." };
  if (req.status !== "pending") return { ok: false, reason: "Request is not pending." };

  await dbRun(
    db,
    `UPDATE join_requests
     SET status = 'rejected',
         note = ?,
         decided_by = ?,
         decided_at = ?
     WHERE id = ?`,
    [note || null, decidedByUserId, nowISO(), requestId]
  );
  return { ok: true };
}

/** =========================
 *  Route handlers
 *  ========================= */

async function handleHealth(ctx) {
  return json({ ok: true, build: BUILD, ts: nowISO() });
}

async function handleNoAccess(ctx) {
  const body = `
    <div class="card">
      <h1>No access</h1>
      <p class="mut">Your account is valid, but you currently have no school memberships.</p>
      <p class="mut">If you have a join code, go to <a href="/join">/join</a>.</p>
    </div>
  `;
  return new Response(page("No access", body), { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handleSetup(ctx) {
  const db = ctx.env.DB;

  const countRow = await dbFirst(db, `SELECT COUNT(*) AS c FROM users WHERE is_system_admin = 1`);
  const already = Number(countRow?.c || 0) > 0;

  if (ctx.request.method === "GET") {
    if (already) {
      const body = `
        <div class="card">
          <h1>Setup already completed</h1>
          <p class="mut">Go to <a href="/login">/login</a>.</p>
        </div>`;
      return new Response(page("Setup", body), { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }
    const body = `
      <div class="card">
        <h1>Initial setup</h1>
        <p class="mut">Create the first System Admin account.</p>
        <form method="post" class="grid">
          <div class="col6">
            <label>Email</label>
            <input name="email" type="email" required/>
          </div>
          <div class="col6">
            <label>Name</label>
            <input name="name" type="text" placeholder="Optional"/>
          </div>
          <div class="col6">
            <label>Password</label>
            <input name="password" type="password" required minlength="8"/>
          </div>
          <div class="col12">
            <button type="submit">Create System Admin</button>
          </div>
        </form>
      </div>`;
    return new Response(page("Setup", body), { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  if (already) return redirect("/login");

  const fd = await ctx.request.formData();
  const email = String(fd.get("email") || "").trim().toLowerCase();
  const name = String(fd.get("name") || "").trim();
  const password = String(fd.get("password") || "");

  if (!email || !password || password.length < 8) {
    return new Response(page("Setup", `<div class="card err"><b>Error:</b> invalid input.</div>`), {
      status: 400,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const exists = await dbFirst(db, `SELECT id FROM users WHERE email = ?`, [email]);
  if (exists) {
    return new Response(page("Setup", `<div class="card err"><b>Error:</b> email already exists.</div>`), {
      status: 400,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const password_hash = await hashPassword(password, ctx.env);

  await dbRun(
    db,
    `INSERT INTO users (email, name, password_hash, is_system_admin, created_at)
     VALUES (?, ?, ?, 1, ?)`,
    [email, name || null, password_hash, nowISO()]
  );

  const user = await dbFirst(db, `SELECT id FROM users WHERE email = ?`, [email]);
  const sid = crypto.randomUUID();
  const expires_at = new Date(Date.now() + SESSION_MAX_AGE * 1000).toISOString();

  await dbRun(
    db,
    `INSERT INTO sessions (id, user_id, expires_at, active_school_id)
     VALUES (?, ?, ?, NULL)`,
    [sid, user.id, expires_at]
  );

  const headers = new Headers();
  setCookie(headers, COOKIE_NAME, sid, { maxAge: SESSION_MAX_AGE });
  return redirect("/sys", headers);
}

async function handleLogin(ctx) {
  const db = ctx.env.DB;

  if (ctx.request.method === "GET") {
    const next = qs(ctx.request.url).get("next") || "";
    const body = `
      <div class="card">
        <h1>Login</h1>
        <form method="post" class="grid">
          <input type="hidden" name="next" value="${htmlEscape(next)}"/>
          <div class="col6">
            <label>Email</label>
            <input name="email" type="email" required/>
          </div>
          <div class="col6">
            <label>Password</label>
            <input name="password" type="password" required/>
          </div>
          <div class="col12 row">
            <button type="submit">Login</button>
            <a class="chip" href="/join">Have a join code?</a>
          </div>
        </form>
      </div>`;
    return new Response(page("Login", body), { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  const fd = await ctx.request.formData();
  const email = String(fd.get("email") || "").trim().toLowerCase();
  const password = String(fd.get("password") || "");
  const next = String(fd.get("next") || "").trim();

  const user = await dbFirst(
    db,
    `SELECT id, email, name, is_system_admin, password_hash
     FROM users
     WHERE email = ?`,
    [email]
  );

  if (!user) {
    return new Response(page("Login", `<div class="card err"><b>Invalid email/password.</b></div>`), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const ok = await verifyPassword(password, ctx.env, user.password_hash);
  if (!ok) {
    return new Response(page("Login", `<div class="card err"><b>Invalid email/password.</b></div>`), {
      status: 401,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const sid = crypto.randomUUID();
  const expires_at = new Date(Date.now() + SESSION_MAX_AGE * 1000).toISOString();

  await dbRun(
    db,
    `INSERT INTO sessions (id, user_id, expires_at, active_school_id)
     VALUES (?, ?, ?, NULL)`,
    [sid, user.id, expires_at]
  );

  // Determine landing and set active_school if only one membership
  const landing = await landingForUser(db, sid, user.id, null);

  const headers = new Headers();
  setCookie(headers, COOKIE_NAME, sid, { maxAge: SESSION_MAX_AGE });

  if (next && next.startsWith("/")) return redirect(next, headers);
  return redirect(landing.path, headers);
}

async function handleLogout(ctx) {
  const headers = new Headers();
  clearCookie(headers, COOKIE_NAME);
  return redirect("/login", headers);
}

async function handleChooseSchool(ctx, session) {
  const db = ctx.env.DB;
  const ms = await listMemberships(db, session.user.id);

  if (ms.length === 0) return redirect("/no-access");

  if (ctx.request.method === "POST") {
    const fd = await ctx.request.formData();
    const school_id = Number(fd.get("school_id"));
    const m = ms.find(x => Number(x.school_id) === school_id);
    if (!m) {
      return new Response(page("Choose school", `<div class="card err"><b>Invalid school.</b></div>`), {
        status: 400,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    await setActiveSchool(db, session.sid, school_id);
    return redirect(dashPathForRole(m.role));
  }

  const active = session.sess.active_school_id ? Number(session.sess.active_school_id) : null;

  const rows = ms
    .map(m => {
      const isActive = active && Number(m.school_id) === active;
      return `
        <tr>
          <td><b>${htmlEscape(m.school_name)}</b> ${isActive ? `<span class="chip">Current</span>` : ""}</td>
          <td>${htmlEscape(m.role)}</td>
          <td>
            <form method="post" style="margin:0">
              <input type="hidden" name="school_id" value="${htmlEscape(m.school_id)}"/>
              <button class="ghost" type="submit">Choose</button>
            </form>
          </td>
        </tr>`;
    })
    .join("");

  const body = `
    <div class="card">
      <h1>Choose school</h1>
      <p class="mut">You belong to multiple schools. Pick the one you want to work in right now.</p>
      <table>
        <thead><tr><th>School</th><th>Role</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
  return new Response(page("Choose school", body), { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handleSwitchSchool(ctx, session) {
  // GET: quick list; POST: same as choose-school
  return handleChooseSchool(ctx, session);
}

async function handleSys(ctx, session) {
  const db = ctx.env.DB;
  if (!session.user.is_system_admin) return redirect("/no-access");

  const url = new URL(ctx.request.url);
  const q = (url.searchParams.get("q") || "").trim().toLowerCase();

  if (ctx.request.method === "POST") {
    const fd = await ctx.request.formData();
    const action = String(fd.get("action") || "");

    if (action === "create_school") {
      const school_name = String(fd.get("school_name") || "").trim();
      const admin_email = String(fd.get("admin_email") || "").trim().toLowerCase();
      const admin_name = String(fd.get("admin_name") || "").trim();
      const admin_password = String(fd.get("admin_password") || "");

      if (!school_name || !admin_email) {
        return new Response(page("System Admin", `<div class="card err"><b>Error:</b> missing fields.</div>`), {
          status: 400,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      await dbRun(db, `INSERT INTO schools (name, created_at) VALUES (?, ?)`, [school_name, nowISO()]);
      const school = await dbFirst(db, `SELECT id, name FROM schools WHERE name = ? ORDER BY id DESC LIMIT 1`, [school_name]);

      let adminUser = await dbFirst(db, `SELECT id FROM users WHERE email = ?`, [admin_email]);

      if (!adminUser) {
        if (!admin_password || admin_password.length < 8) {
          return new Response(
            page(
              "System Admin",
              `<div class="card err"><b>Error:</b> new School Admin needs a password (min 8).</div>`
            ),
            { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } }
          );
        }
        const ph = await hashPassword(admin_password, ctx.env);
        await dbRun(
          db,
          `INSERT INTO users (email, name, password_hash, is_system_admin, created_at)
           VALUES (?, ?, ?, 0, ?)`,
          [admin_email, admin_name || null, ph, nowISO()]
        );
        adminUser = await dbFirst(db, `SELECT id FROM users WHERE email = ?`, [admin_email]);
      }

      // Upsert membership as school_admin
      const existingM = await dbFirst(
        db,
        `SELECT id FROM memberships WHERE user_id = ? AND school_id = ?`,
        [adminUser.id, school.id]
      );
      if (!existingM) {
        await dbRun(
          db,
          `INSERT INTO memberships (user_id, school_id, role, created_at)
           VALUES (?, ?, 'school_admin', ?)`,
          [adminUser.id, school.id, nowISO()]
        );
      } else {
        await dbRun(db, `UPDATE memberships SET role='school_admin' WHERE id=?`, [existingM.id]);
      }

      return redirect("/sys");
    }

    if (action === "add_user_to_school") {
      const user_id = Number(fd.get("user_id"));
      const school_id = Number(fd.get("school_id"));
      const role = String(fd.get("role") || "");
      if (!user_id || !school_id || !["school_admin", "teacher", "student"].includes(role)) {
        return new Response(page("System Admin", `<div class="card err"><b>Error:</b> invalid input.</div>`), {
          status: 400,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }

      const exists = await dbFirst(db, `SELECT id FROM memberships WHERE user_id=? AND school_id=?`, [user_id, school_id]);
      if (!exists) {
        await dbRun(db, `INSERT INTO memberships (user_id, school_id, role, created_at) VALUES (?, ?, ?, ?)`, [
          user_id,
          school_id,
          role,
          nowISO(),
        ]);
      } else {
        await dbRun(db, `UPDATE memberships SET role=? WHERE id=?`, [role, exists.id]);
      }

      return redirect(`/sys?q=${encodeURIComponent(q || "")}`);
    }

    return redirect("/sys");
  }

  const schools = await dbAll(db, `SELECT id, name FROM schools ORDER BY name ASC`);
  const schoolOptions = schools
    .map(s => `<option value="${htmlEscape(s.id)}">${htmlEscape(s.name)}</option>`)
    .join("");

  let usersHtml = "";
  if (q) {
    const users = await dbAll(
      db,
      `SELECT id, email, name, is_system_admin, created_at
       FROM users
       WHERE lower(email) LIKE ?
       ORDER BY id DESC
       LIMIT 25`,
      [`%${q}%`]
    );

    const userBlocks = [];
    for (const u of users) {
      const mem = await dbAll(
        db,
        `SELECT m.school_id, m.role, s.name AS school_name
         FROM memberships m JOIN schools s ON s.id=m.school_id
         WHERE m.user_id=? ORDER BY s.name ASC`,
        [u.id]
      );
      const memList = mem.length
        ? `<ul>${mem.map(m => `<li>${htmlEscape(m.school_name)} — <b>${htmlEscape(m.role)}</b></li>`).join("")}</ul>`
        : `<div class="mut">No memberships</div>`;

      userBlocks.push(`
        <div class="card">
          <div class="row" style="justify-content:space-between;align-items:flex-start">
            <div>
              <div><b>${htmlEscape(u.email)}</b> ${u.is_system_admin ? `<span class="chip">System Admin</span>` : ""}</div>
              <div class="mut">${htmlEscape(u.name || "")}</div>
            </div>
          </div>
          <div class="hr"></div>
          <div><b>Schools / Roles</b></div>
          ${memList}
          <div class="hr"></div>
          <form method="post" class="grid">
            <input type="hidden" name="action" value="add_user_to_school"/>
            <input type="hidden" name="user_id" value="${htmlEscape(u.id)}"/>
            <div class="col6">
              <label>Add to school</label>
              <select name="school_id" required>${schoolOptions}</select>
            </div>
            <div class="col6">
              <label>Role</label>
              <select name="role" required>
                <option value="student">student</option>
                <option value="teacher">teacher</option>
                <option value="school_admin">school_admin</option>
              </select>
            </div>
            <div class="col12"><button class="ghost" type="submit">Apply</button></div>
          </form>
        </div>
      `);
    }
    usersHtml = userBlocks.join("");
  }

  const body = `
    <div class="card">
      <h1>System Admin</h1>
      <p class="mut">Create schools + assign School Admins. Search users by email and add them to any school.</p>
    </div>

    <div class="card">
      <h2>Create school + first School Admin</h2>
      <form method="post" class="grid">
        <input type="hidden" name="action" value="create_school"/>
        <div class="col6">
          <label>School name</label>
          <input name="school_name" required/>
        </div>
        <div class="col6">
          <label>School Admin email</label>
          <input name="admin_email" type="email" required/>
        </div>
        <div class="col6">
          <label>School Admin name (optional)</label>
          <input name="admin_name"/>
        </div>
        <div class="col6">
          <label>Password (required if email is NEW)</label>
          <input name="admin_password" type="password" minlength="8"/>
        </div>
        <div class="col12">
          <button type="submit">Create</button>
        </div>
      </form>
    </div>

    <div class="card">
      <h2>User directory</h2>
      <form method="get" class="row" action="/sys" style="margin:0">
        <input name="q" placeholder="Search email (e.g. ama@...)" value="${htmlEscape(q)}" style="max-width:420px"/>
        <button class="ghost" type="submit">Search</button>
      </form>
      <div class="mut" style="margin-top:8px">Tip: searches by partial email.</div>
    </div>

    ${usersHtml || (q ? `<div class="card warn">No results.</div>` : ``)}
  `;

  return new Response(page("System Admin", body), { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handleSchool(ctx, session) {
  const db = ctx.env.DB;

  const activeSchoolId = session.sess.active_school_id ? Number(session.sess.active_school_id) : null;
  if (!activeSchoolId) return redirect("/choose-school");

  const mem = await getMembership(db, session.user.id, activeSchoolId);
  if (!mem || mem.role !== "school_admin") return redirect("/no-access");

  const url = new URL(ctx.request.url);
  const rosterCourseId = url.searchParams.get("course") ? Number(url.searchParams.get("course")) : null;

  if (ctx.request.method === "POST") {
    const fd = await ctx.request.formData();
    const action = String(fd.get("action") || "");

    if (action === "create_course") {
      const name = String(fd.get("course_name") || "").trim();
      if (!name) return redirect("/school");
      await dbRun(db, `INSERT INTO courses (school_id, name, created_at) VALUES (?, ?, ?)`, [activeSchoolId, name, nowISO()]);
      return redirect("/school");
    }

    if (action === "assign_teacher") {
      const course_id = Number(fd.get("course_id"));
      const teacher_id = Number(fd.get("teacher_id"));
      if (!course_id || !teacher_id) return redirect("/school");

      // ensure teacher in this school
      const tmem = await dbFirst(db, `SELECT id FROM memberships WHERE user_id=? AND school_id=? AND role='teacher'`, [
        teacher_id,
        activeSchoolId,
      ]);
      if (!tmem) return redirect("/school");

      // upsert
      const exists = await dbFirst(db, `SELECT 1 FROM course_teachers WHERE course_id=? AND user_id=?`, [course_id, teacher_id]);
      if (!exists) {
        await dbRun(db, `INSERT INTO course_teachers (course_id, user_id, created_at) VALUES (?, ?, ?)`, [
          course_id,
          teacher_id,
          nowISO(),
        ]);
      }
      return redirect("/school");
    }

    if (action === "unassign_teacher") {
      const course_id = Number(fd.get("course_id"));
      const teacher_id = Number(fd.get("teacher_id"));
      if (course_id && teacher_id) {
        await dbRun(
          db,
          `DELETE FROM course_teachers
           WHERE course_id=? AND user_id=?`,
          [course_id, teacher_id]
        );
      }
      return redirect(`/school?course=${encodeURIComponent(course_id)}`);
    }

    if (action === "enrol_student") {
      const course_id = Number(fd.get("course_id"));
      const student_id = Number(fd.get("student_id"));
      if (!course_id || !student_id) return redirect("/school");

      const smem = await dbFirst(db, `SELECT id FROM memberships WHERE user_id=? AND school_id=? AND role='student'`, [
        student_id,
        activeSchoolId,
      ]);
      if (!smem) return redirect("/school");

      const exists = await dbFirst(db, `SELECT 1 FROM enrolments WHERE course_id=? AND user_id=?`, [course_id, student_id]);
      if (!exists) {
        await dbRun(db, `INSERT INTO enrolments (course_id, user_id, created_at) VALUES (?, ?, ?)`, [course_id, student_id, nowISO()]);
      }
      return redirect("/school");
    }

    if (action === "unenrol_student") {
      const course_id = Number(fd.get("course_id"));
      const student_id = Number(fd.get("student_id"));
      if (course_id && student_id) {
        await dbRun(
          db,
          `DELETE FROM enrolments
           WHERE course_id=? AND user_id=?`,
          [course_id, student_id]
        );
      }
      return redirect(`/school?course=${encodeURIComponent(course_id)}`);
    }

    if (action === "create_join_code") {
      const role = String(fd.get("role") || "");
      const auto_approve = fd.get("auto_approve") ? 1 : 0;
      const expires_days = Number(fd.get("expires_days") || 0);
      const max_uses_raw = String(fd.get("max_uses") || "").trim();
      const max_uses = max_uses_raw ? Number(max_uses_raw) : null;

      if (!["teacher", "student"].includes(role)) return redirect("/school");
      const code = genJoinCode();
      const expires_at = expires_days > 0 ? addDaysISO(expires_days) : null;

      await dbRun(
        db,
        `INSERT INTO join_codes (school_id, code, role, auto_approve, expires_at, max_uses, uses_count, revoked_at, created_by, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 0, NULL, ?, ?)`,
        [activeSchoolId, code, role, auto_approve, expires_at, max_uses, session.user.id, nowISO()]
      );
      return redirect("/school");
    }

    if (action === "revoke_join_code") {
      const code_id = Number(fd.get("code_id"));
      if (code_id) {
        await dbRun(db, `UPDATE join_codes SET revoked_at=? WHERE id=? AND school_id=?`, [nowISO(), code_id, activeSchoolId]);
      }
      return redirect("/school");
    }

    if (action === "approve_join_request") {
      const request_id = Number(fd.get("request_id"));
      if (request_id) {
        // Ensure request is for this school
        const jr = await dbFirst(db, `SELECT id FROM join_requests WHERE id=? AND school_id=?`, [request_id, activeSchoolId]);
        if (jr) await approveJoinRequest(db, request_id, session.user.id, { allowRoleUpdate: true });
      }
      return redirect("/school");
    }

    if (action === "reject_join_request") {
      const request_id = Number(fd.get("request_id"));
      const note = String(fd.get("note") || "").trim();
      if (request_id) {
        const jr = await dbFirst(db, `SELECT id FROM join_requests WHERE id=? AND school_id=?`, [request_id, activeSchoolId]);
        if (jr) await rejectJoinRequest(db, request_id, session.user.id, note);
      }
      return redirect("/school");
    }

    if (action === "change_member_role") {
      const user_id = Number(fd.get("user_id"));
      const role = String(fd.get("role") || "");
      if (!user_id || !["teacher", "student", "school_admin"].includes(role)) return redirect("/school");

      // prevent self-demotion for safety
      if (user_id === session.user.id && role !== "school_admin") return redirect("/school");

      await dbRun(db, `UPDATE memberships SET role=? WHERE user_id=? AND school_id=?`, [role, user_id, activeSchoolId]);
      return redirect("/school");
    }

    if (action === "remove_member") {
      const user_id = Number(fd.get("user_id"));
      if (!user_id) return redirect("/school");

      // prevent self-removal
      if (user_id === session.user.id) return redirect("/school");

      // remove enrolments and teacher assignments for courses in this school
      await dbRun(
        db,
        `DELETE FROM enrolments
         WHERE user_id = ?
           AND course_id IN (SELECT id FROM courses WHERE school_id = ?)`,
        [user_id, activeSchoolId]
      );
      await dbRun(
        db,
        `DELETE FROM course_teachers
         WHERE user_id = ?
           AND course_id IN (SELECT id FROM courses WHERE school_id = ?)`,
        [user_id, activeSchoolId]
      );
      await dbRun(db, `DELETE FROM memberships WHERE user_id=? AND school_id=?`, [user_id, activeSchoolId]);
      return redirect("/school");
    }

    return redirect("/school");
  }

  // GET: render dashboard
  const school = await dbFirst(db, `SELECT id, name FROM schools WHERE id=?`, [activeSchoolId]);

  const joinCodes = await dbAll(
    db,
    `SELECT id, code, role, auto_approve, expires_at, max_uses, uses_count, revoked_at, created_at
     FROM join_codes
     WHERE school_id=?
     ORDER BY id DESC
     LIMIT 30`,
    [activeSchoolId]
  );

  const pendingRequests = await dbAll(
    db,
    `SELECT jr.id, jr.role, jr.created_at, u.email, u.name, jc.code
     FROM join_requests jr
     JOIN users u ON u.id = jr.user_id
     JOIN join_codes jc ON jc.id = jr.code_id
     WHERE jr.school_id=? AND jr.status='pending'
     ORDER BY jr.id DESC`,
    [activeSchoolId]
  );

  const members = await dbAll(
    db,
    `SELECT u.id AS user_id, u.email, u.name, m.role, m.created_at
     FROM memberships m
     JOIN users u ON u.id = m.user_id
     WHERE m.school_id=?
     ORDER BY m.role ASC, u.email ASC`,
    [activeSchoolId]
  );

  const courses = await dbAll(
    db,
    `SELECT c.id, c.name,
      (SELECT COUNT(*) FROM enrolments e WHERE e.course_id=c.id) AS students,
      (SELECT COUNT(*) FROM course_teachers t WHERE t.course_id=c.id) AS teachers
     FROM courses c
     WHERE c.school_id=?
     ORDER BY c.name ASC`,
    [activeSchoolId]
  );

  const teacherOptions = members
    .filter(m => m.role === "teacher")
    .map(m => `<option value="${htmlEscape(m.user_id)}">${htmlEscape(m.email)}</option>`)
    .join("");
  const studentOptions = members
    .filter(m => m.role === "student")
    .map(m => `<option value="${htmlEscape(m.user_id)}">${htmlEscape(m.email)}</option>`)
    .join("");
  const courseOptions = courses
    .map(c => `<option value="${htmlEscape(c.id)}">${htmlEscape(c.name)}</option>`)
    .join("");

  const joinCodeRows = joinCodes
    .map(jc => {
      const status = jc.revoked_at
        ? `<span class="chip">Revoked</span>`
        : (jc.expires_at && new Date(jc.expires_at).getTime() <= Date.now())
          ? `<span class="chip">Expired</span>`
          : `<span class="chip">Active</span>`;

      return `
        <tr>
          <td><b>${htmlEscape(jc.code)}</b><div class="mut">${status} • role=${htmlEscape(jc.role)} • auto=${jc.auto_approve ? "yes" : "no"}</div></td>
          <td class="mut">${jc.expires_at ? htmlEscape(jc.expires_at) : "—"}</td>
          <td class="mut">${jc.max_uses != null ? `${jc.uses_count}/${jc.max_uses}` : `${jc.uses_count}/∞`}</td>
          <td>
            <div class="row">
              <a class="chip" href="/join?code=${encodeURIComponent(jc.code)}">Join link</a>
              ${jc.revoked_at ? "" : `
                <form method="post" style="margin:0">
                  <input type="hidden" name="action" value="revoke_join_code"/>
                  <input type="hidden" name="code_id" value="${htmlEscape(jc.id)}"/>
                  <button class="danger" type="submit">Revoke</button>
                </form>
              `}
            </div>
          </td>
        </tr>`;
    })
    .join("");

  const requestRows = pendingRequests.length
    ? pendingRequests
        .map(r => `
          <tr>
            <td><b>${htmlEscape(r.email)}</b><div class="mut">${htmlEscape(r.name || "")}</div></td>
            <td>${htmlEscape(r.role)}</td>
            <td class="mut">code: ${htmlEscape(r.code)}<br/>${htmlEscape(r.created_at)}</td>
            <td>
              <div class="row">
                <form method="post" style="margin:0">
                  <input type="hidden" name="action" value="approve_join_request"/>
                  <input type="hidden" name="request_id" value="${htmlEscape(r.id)}"/>
                  <button type="submit">Approve</button>
                </form>
                <form method="post" style="margin:0">
                  <input type="hidden" name="action" value="reject_join_request"/>
                  <input type="hidden" name="request_id" value="${htmlEscape(r.id)}"/>
                  <input name="note" placeholder="Optional note" style="max-width:220px"/>
                  <button class="danger" type="submit">Reject</button>
                </form>
              </div>
            </td>
          </tr>`)
        .join("")
    : `<tr><td colspan="4" class="mut">No pending requests.</td></tr>`;

  const memberRows = members
    .map(m => `
      <tr>
        <td><b>${htmlEscape(m.email)}</b><div class="mut">${htmlEscape(m.name || "")}</div></td>
        <td>${htmlEscape(m.role)}</td>
        <td class="mut">${htmlEscape(m.created_at || "")}</td>
        <td>
          <div class="row">
            <form method="post" style="margin:0" class="row">
              <input type="hidden" name="action" value="change_member_role"/>
              <input type="hidden" name="user_id" value="${htmlEscape(m.user_id)}"/>
              <select name="role" style="max-width:180px">
                <option value="student" ${m.role === "student" ? "selected" : ""}>student</option>
                <option value="teacher" ${m.role === "teacher" ? "selected" : ""}>teacher</option>
                <option value="school_admin" ${m.role === "school_admin" ? "selected" : ""}>school_admin</option>
              </select>
              <button class="ghost" type="submit">Change</button>
            </form>
            ${m.user_id === session.user.id ? "" : `
              <form method="post" style="margin:0">
                <input type="hidden" name="action" value="remove_member"/>
                <input type="hidden" name="user_id" value="${htmlEscape(m.user_id)}"/>
                <button class="danger" type="submit">Remove</button>
              </form>
            `}
          </div>
        </td>
      </tr>
    `)
    .join("");

  const courseRows = courses
    .map(c => `
      <tr>
        <td><b>${htmlEscape(c.name)}</b></td>
        <td>${htmlEscape(c.teachers)}</td>
        <td>${htmlEscape(c.students)}</td>
        <td><a class="chip" href="/school?course=${encodeURIComponent(c.id)}">View roster</a></td>
      </tr>
    `)
    .join("");

  let rosterHtml = "";
  if (rosterCourseId) {
    const c = await dbFirst(db, `SELECT id, name FROM courses WHERE id=? AND school_id=?`, [rosterCourseId, activeSchoolId]);
    if (c) {
      const teachers = await dbAll(
        db,
        `SELECT u.id AS user_id, u.email, u.name
         FROM course_teachers t
         JOIN users u ON u.id = t.user_id
         WHERE t.course_id=?
         ORDER BY u.email ASC`,
        [rosterCourseId]
      );

      const students = await dbAll(
        db,
        `SELECT u.id AS user_id, u.email, u.name
         FROM enrolments e
         JOIN users u ON u.id = e.user_id
         WHERE e.course_id=?
         ORDER BY u.email ASC`,
        [rosterCourseId]
      );

      rosterHtml = `
        <div class="card">
          <h2>Roster — ${htmlEscape(c.name)}</h2>
          <div class="grid">
            <div class="col6">
              <b>Teachers (${teachers.length})</b>
              <ul>
                ${teachers
                  .map(
                    t => `
                    <li>
                      ${htmlEscape(t.email)}
                      <form method="post" style="display:inline;margin-left:8px">
                        <input type="hidden" name="action" value="unassign_teacher"/>
                        <input type="hidden" name="course_id" value="${htmlEscape(rosterCourseId)}"/>
                        <input type="hidden" name="teacher_id" value="${htmlEscape(t.user_id)}"/>
                        <button class="ghost" type="submit">Unassign</button>
                      </form>
                    </li>`
                  )
                  .join("")}
              </ul>
            </div>
            <div class="col6">
              <b>Students (${students.length})</b>
              <ul>
                ${students
                  .map(
                    s => `
                    <li>
                      ${htmlEscape(s.email)}
                      <form method="post" style="display:inline;margin-left:8px">
                        <input type="hidden" name="action" value="unenrol_student"/>
                        <input type="hidden" name="course_id" value="${htmlEscape(rosterCourseId)}"/>
                        <input type="hidden" name="student_id" value="${htmlEscape(s.user_id)}"/>
                        <button class="ghost" type="submit">Unenrol</button>
                      </form>
                    </li>`
                  )
                  .join("")}
              </ul>
            </div>
          </div>
        </div>
      `;
    }
  }

  const body = `
    <div class="card">
      <h1>School Admin — ${htmlEscape(school?.name || "")}</h1>
      <div class="row">
        <span class="chip">Active school</span>
        <a class="chip" href="/switch-school">Switch school</a>
      </div>
    </div>

    <div class="grid">
      <div class="card col6">
        <h2>Create join code</h2>
        <p class="mut">Users go to <b>/join</b>, enter code, then request approval.</p>
        <form method="post" class="grid">
          <input type="hidden" name="action" value="create_join_code"/>
          <div class="col6">
            <label>Role</label>
            <select name="role" required>
              <option value="student">student</option>
              <option value="teacher">teacher</option>
            </select>
          </div>
          <div class="col6">
            <label>Expires in days (0 = never)</label>
            <input name="expires_days" type="number" min="0" value="0"/>
          </div>
          <div class="col6">
            <label>Max uses (blank = unlimited)</label>
            <input name="max_uses" type="number" min="1" placeholder="e.g. 200"/>
          </div>
          <div class="col6">
            <label>&nbsp;</label>
            <label style="display:flex;gap:8px;align-items:center;color:var(--ink)">
              <input type="checkbox" name="auto_approve" style="width:auto"/> Auto-approve
            </label>
          </div>
          <div class="col12">
            <button type="submit">Create code</button>
          </div>
        </form>
      </div>

      <div class="card col6">
        <h2>Create course</h2>
        <form method="post" class="row" style="margin:0">
          <input type="hidden" name="action" value="create_course"/>
          <input name="course_name" placeholder="e.g. Biology 101" style="flex:1"/>
          <button type="submit">Add</button>
        </form>

        <div class="hr"></div>

        <h2>Assign teacher</h2>
        <form method="post" class="grid">
          <input type="hidden" name="action" value="assign_teacher"/>
          <div class="col6">
            <label>Course</label>
            <select name="course_id" required>${courseOptions || `<option value="">No courses yet</option>`}</select>
          </div>
          <div class="col6">
            <label>Teacher</label>
            <select name="teacher_id" required>${teacherOptions || `<option value="">No teachers yet</option>`}</select>
          </div>
          <div class="col12"><button class="ghost" type="submit">Assign</button></div>
        </form>

        <div class="hr"></div>

        <h2>Enrol student</h2>
        <form method="post" class="grid">
          <input type="hidden" name="action" value="enrol_student"/>
          <div class="col6">
            <label>Course</label>
            <select name="course_id" required>${courseOptions || `<option value="">No courses yet</option>`}</select>
          </div>
          <div class="col6">
            <label>Student</label>
            <select name="student_id" required>${studentOptions || `<option value="">No students yet</option>`}</select>
          </div>
          <div class="col12"><button class="ghost" type="submit">Enrol</button></div>
        </form>
      </div>
    </div>

    <div class="card">
      <h2>Join codes</h2>
      <table>
        <thead><tr><th>Code</th><th>Expiry</th><th>Uses</th><th>Actions</th></tr></thead>
        <tbody>${joinCodeRows || `<tr><td colspan="4" class="mut">No codes yet.</td></tr>`}</tbody>
      </table>
    </div>

    <div class="card">
      <h2>Join requests (pending)</h2>
      <table>
        <thead><tr><th>User</th><th>Requested role</th><th>Details</th><th>Actions</th></tr></thead>
        <tbody>${requestRows}</tbody>
      </table>
    </div>

    <div class="card">
      <h2>Members</h2>
      <table>
        <thead><tr><th>User</th><th>Role</th><th>Joined</th><th>Manage</th></tr></thead>
        <tbody>${memberRows}</tbody>
      </table>
    </div>

    <div class="card">
      <h2>Courses</h2>
      <table>
        <thead><tr><th>Course</th><th>Teachers</th><th>Students</th><th></th></tr></thead>
        <tbody>${courseRows || `<tr><td colspan="4" class="mut">No courses yet.</td></tr>`}</tbody>
      </table>
    </div>

    ${rosterHtml}
  `;

  return new Response(page("School Admin", body), { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handleTeacher(ctx, session) {
  const db = ctx.env.DB;
  const activeSchoolId = session.sess.active_school_id ? Number(session.sess.active_school_id) : null;
  if (!activeSchoolId) return redirect("/choose-school");

  const mem = await getMembership(db, session.user.id, activeSchoolId);
  if (!mem || mem.role !== "teacher") return redirect("/no-access");

  const courses = await dbAll(
    db,
    `SELECT c.id, c.name,
      (SELECT COUNT(*) FROM enrolments e WHERE e.course_id=c.id) AS students
     FROM course_teachers t
     JOIN courses c ON c.id = t.course_id
     WHERE t.user_id=? AND c.school_id=?
     ORDER BY c.name ASC`,
    [session.user.id, activeSchoolId]
  );

  const rows = courses
    .map(c => `<tr><td><b>${htmlEscape(c.name)}</b></td><td>${htmlEscape(c.students)}</td></tr>`)
    .join("");

  const body = `
    <div class="card">
      <h1>Teacher — ${htmlEscape(mem.school_name)}</h1>
      <div class="row">
        <span class="chip">Role: teacher</span>
        <a class="chip" href="/switch-school">Switch school</a>
      </div>
    </div>
    <div class="card">
      <h2>My courses</h2>
      <table>
        <thead><tr><th>Course</th><th>Students</th></tr></thead>
        <tbody>${rows || `<tr><td colspan="2" class="mut">No assigned courses yet.</td></tr>`}</tbody>
      </table>
    </div>
  `;
  return new Response(page("Teacher", body), { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handleStudent(ctx, session) {
  const db = ctx.env.DB;
  const activeSchoolId = session.sess.active_school_id ? Number(session.sess.active_school_id) : null;
  if (!activeSchoolId) return redirect("/choose-school");

  const mem = await getMembership(db, session.user.id, activeSchoolId);
  if (!mem || mem.role !== "student") return redirect("/no-access");

  const enrols = await dbAll(
    db,
    `SELECT c.name
     FROM enrolments e
     JOIN courses c ON c.id = e.course_id
     WHERE e.user_id=? AND c.school_id=?
     ORDER BY c.name ASC`,
    [session.user.id, activeSchoolId]
  );

  const body = `
    <div class="card">
      <h1>Student — ${htmlEscape(mem.school_name)}</h1>
      <div class="row">
        <span class="chip">Role: student</span>
        <a class="chip" href="/switch-school">Switch school</a>
      </div>
    </div>
    <div class="card">
      <h2>My enrolments</h2>
      <ul>
        ${enrols.map(e => `<li>${htmlEscape(e.name)}</li>`).join("") || `<li class="mut">No enrolments yet.</li>`}
      </ul>
    </div>
  `;
  return new Response(page("Student", body), { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function handleJoin(ctx) {
  const db = ctx.env.DB;
  const url = new URL(ctx.request.url);
  const codeInput = (url.searchParams.get("code") || "").trim().toUpperCase();

  const maybeSession = await getSession(db, ctx.request);

  if (ctx.request.method === "GET") {
    const body = `
      <div class="card">
        <h1>Join a school</h1>
        <p class="mut">Enter a join code from the School Admin. If you are not logged in, you can create an account here.</p>
        <form method="get" class="row" action="/join" style="margin:0">
          <input name="code" placeholder="Enter code (e.g. 8 chars)" value="${htmlEscape(codeInput)}" style="max-width:320px"/>
          <button class="ghost" type="submit">Continue</button>
        </form>
      </div>
    `;

    if (!codeInput) {
      return new Response(page("Join", body), { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    const codeCheck = await loadJoinCode(db, codeInput);
    if (!codeCheck.ok) {
      return new Response(page("Join", body + `<div class="card err"><b>${htmlEscape(codeCheck.reason)}</b></div>`), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    const codeRow = codeCheck.row;

    if (maybeSession) {
      // Logged-in: just request
      const extra = `
        <div class="card">
          <h2>Code found</h2>
          <p class="mut"><b>${htmlEscape(codeRow.school_name)}</b> • role requested: <b>${htmlEscape(codeRow.role)}</b> • auto-approve: <b>${codeRow.auto_approve ? "yes" : "no"}</b></p>
          <form method="post" class="row" style="margin:0">
            <input type="hidden" name="action" value="request"/>
            <input type="hidden" name="code" value="${htmlEscape(codeInput)}"/>
            <button type="submit">Request access</button>
          </form>
        </div>
      `;
      return new Response(page("Join", body + extra), { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    // Not logged in: show signup + login forms
    const forms = `
      <div class="grid">
        <div class="card col6">
          <h2>Create account + request</h2>
          <form method="post" class="grid">
            <input type="hidden" name="action" value="signup"/>
            <input type="hidden" name="code" value="${htmlEscape(codeInput)}"/>
            <div class="col12">
              <label>Email</label>
              <input name="email" type="email" required/>
            </div>
            <div class="col12">
              <label>Name (optional)</label>
              <input name="name"/>
            </div>
            <div class="col12">
              <label>Password</label>
              <input name="password" type="password" required minlength="8"/>
            </div>
            <div class="col12">
              <button type="submit">Create & Request</button>
            </div>
          </form>
        </div>

        <div class="card col6">
          <h2>Login + request</h2>
          <form method="post" class="grid">
            <input type="hidden" name="action" value="login"/>
            <input type="hidden" name="code" value="${htmlEscape(codeInput)}"/>
            <div class="col12">
              <label>Email</label>
              <input name="email" type="email" required/>
            </div>
            <div class="col12">
              <label>Password</label>
              <input name="password" type="password" required/>
            </div>
            <div class="col12">
              <button class="secondary" type="submit">Login & Request</button>
            </div>
          </form>
        </div>
      </div>

      <div class="card">
        <p class="mut"><b>Code details:</b> ${htmlEscape(codeRow.school_name)} • requested role: <b>${htmlEscape(codeRow.role)}</b> • auto-approve: <b>${codeRow.auto_approve ? "yes" : "no"}</b></p>
      </div>
    `;

    return new Response(page("Join", body + forms), { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  // POST
  const fd = await ctx.request.formData();
  const action = String(fd.get("action") || "");
  const codeStr = String(fd.get("code") || "").trim().toUpperCase();

  const codeCheck = await loadJoinCode(db, codeStr);
  if (!codeCheck.ok) {
    return new Response(page("Join", `<div class="card err"><b>${htmlEscape(codeCheck.reason)}</b></div><div class="card"><a href="/join">Back</a></div>`), {
      status: 400,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }
  const codeRow = codeCheck.row;

  let sid = null;
  let user = null;

  if (maybeSession && action === "request") {
    sid = maybeSession.sid;
    user = maybeSession.user;
  } else {
    const email = String(fd.get("email") || "").trim().toLowerCase();
    const password = String(fd.get("password") || "");
    const name = String(fd.get("name") || "").trim();

    if (!email || !password) {
      return new Response(page("Join", `<div class="card err"><b>Missing email/password.</b></div>`), {
        status: 400,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (action === "signup") {
      const exists = await dbFirst(db, `SELECT id FROM users WHERE email=?`, [email]);
      if (exists) {
        return new Response(page("Join", `<div class="card err"><b>Email already exists. Use Login + request.</b></div>`), {
          status: 400,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }
      if (password.length < 8) {
        return new Response(page("Join", `<div class="card err"><b>Password must be at least 8 characters.</b></div>`), {
          status: 400,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }
      const ph = await hashPassword(password, ctx.env);
      await dbRun(
        db,
        `INSERT INTO users (email, name, password_hash, is_system_admin, created_at)
         VALUES (?, ?, ?, 0, ?)`,
        [email, name || null, ph, nowISO()]
      );
      user = await dbFirst(db, `SELECT id, email, name, is_system_admin, password_hash FROM users WHERE email=?`, [email]);
    } else if (action === "login") {
      user = await dbFirst(db, `SELECT id, email, name, is_system_admin, password_hash FROM users WHERE email=?`, [email]);
      if (!user) {
        return new Response(page("Join", `<div class="card err"><b>Invalid email/password.</b></div>`), {
          status: 401,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }
      const ok = await verifyPassword(password, ctx.env, user.password_hash);
      if (!ok) {
        return new Response(page("Join", `<div class="card err"><b>Invalid email/password.</b></div>`), {
          status: 401,
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      }
    } else {
      return redirect("/join");
    }

    // Create session
    sid = crypto.randomUUID();
    const expires_at = new Date(Date.now() + SESSION_MAX_AGE * 1000).toISOString();
    await dbRun(db, `INSERT INTO sessions (id, user_id, expires_at, active_school_id) VALUES (?, ?, ?, NULL)`, [
      sid,
      user.id,
      expires_at,
    ]);
  }

  // Create join request (or auto-approve)
  const jr = await createJoinRequest(db, user.id, codeRow);

  const headers = new Headers();
  if (!maybeSession) {
    setCookie(headers, COOKIE_NAME, sid, { maxAge: SESSION_MAX_AGE });
  }

  if (!jr.ok) {
    return new Response(page("Join", `<div class="card err"><b>${htmlEscape(jr.reason || "Join failed")}</b></div><div class="card"><a href="/join">Back</a></div>`), {
      status: 400,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  if (jr.status === "approved" && jr.school_id) {
    await setActiveSchool(db, sid, jr.school_id);
    // redirect to correct dashboard
    const membership = await getMembership(db, user.id, jr.school_id);
    const path = membership ? dashPathForRole(membership.role) : "/choose-school";
    return redirect(path, headers);
  }

  // Pending
  const body = `
    <div class="card ok">
      <h1>Request sent</h1>
      <p>Your request has been sent to <b>${htmlEscape(codeRow.school_name)}</b>.</p>
      <p class="mut">Once approved, you can log in and access your dashboard.</p>
      <div class="row">
        <a class="chip" href="/login">Go to login</a>
        <a class="chip" href="/join?code=${encodeURIComponent(codeRow.code)}">Back to join</a>
      </div>
    </div>
  `;
  return new Response(page("Join", body), { headers: { "Content-Type": "text/html; charset=utf-8", ...Object.fromEntries(headers) } });
}

async function handleProfile(ctx, session) {
  const db = ctx.env.DB;

  if (ctx.request.method === "POST") {
    const fd = await ctx.request.formData();
    const action = String(fd.get("action") || "");
    if (action === "change_password") {
      const current = String(fd.get("current_password") || "");
      const next = String(fd.get("new_password") || "");
      const next2 = String(fd.get("new_password2") || "");

      if (!current || !next || next.length < 8 || next !== next2) {
        return new Response(
          page(
            "Profile",
            `<div class="card err"><b>Error:</b> invalid password input (min 8, and confirm must match).</div><div class="card"><a href="/profile">Back</a></div>`
          ),
          { status: 400, headers: { "Content-Type": "text/html; charset=utf-8" } }
        );
      }

      const u = await dbFirst(db, `SELECT id, password_hash FROM users WHERE id=?`, [session.user.id]);
      const ok = await verifyPassword(current, ctx.env, u.password_hash);
      if (!ok) {
        return new Response(
          page("Profile", `<div class="card err"><b>Error:</b> current password incorrect.</div><div class="card"><a href="/profile">Back</a></div>`),
          { status: 401, headers: { "Content-Type": "text/html; charset=utf-8" } }
        );
      }

      const ph = await hashPassword(next, ctx.env);
      await dbRun(db, `UPDATE users SET password_hash=? WHERE id=?`, [ph, session.user.id]);

      // Revoke other sessions for safety (keep current)
      await dbRun(db, `DELETE FROM sessions WHERE user_id=? AND id<>?`, [session.user.id, session.sid]);

      return redirect("/profile");
    }

    return redirect("/profile");
  }

  const ms = await listMemberships(db, session.user.id);

  const memList = ms.length
    ? `<ul>${ms.map(m => `<li>${htmlEscape(m.school_name)} — <b>${htmlEscape(m.role)}</b></li>`).join("")}</ul>`
    : `<div class="mut">No memberships yet. Use /join.</div>`;

  const body = `
    <div class="card">
      <h1>My profile</h1>
      <div class="mut">Email</div>
      <div><b>${htmlEscape(session.user.email)}</b></div>
      <div class="mut" style="margin-top:6px">Name</div>
      <div><b>${htmlEscape(session.user.name || "—")}</b></div>
      <div class="hr"></div>
      <div><b>Schools / Roles</b></div>
      ${memList}
    </div>

    <div class="card">
      <h2>Change password</h2>
      <form method="post" class="grid">
        <input type="hidden" name="action" value="change_password"/>
        <div class="col6">
          <label>Current password</label>
          <input name="current_password" type="password" required/>
        </div>
        <div class="col6"></div>
        <div class="col6">
          <label>New password</label>
          <input name="new_password" type="password" minlength="8" required/>
        </div>
        <div class="col6">
          <label>Confirm new password</label>
          <input name="new_password2" type="password" minlength="8" required/>
        </div>
        <div class="col12">
          <button type="submit">Update password</button>
        </div>
      </form>
    </div>
  `;

  return new Response(page("Profile", body), { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

/** =========================
 *  Main router
 *  ========================= */

export async function onRequest(ctx) {
  const url = new URL(ctx.request.url);
  const path = normalizePath(url.pathname);

  // Public endpoints
  if (path === "/health") return handleHealth(ctx);
  if (path === "/setup") return handleSetup(ctx);
  if (path === "/login") return handleLogin(ctx);
  if (path === "/logout") return handleLogout(ctx);
  if (path === "/join") return handleJoin(ctx);
  if (path === "/no-access") return handleNoAccess(ctx);

  // Everything else requires auth
  const auth = await requireAuth(ctx);
  if (!auth.ok) return auth.res;
  const session = { sid: auth.sid, sess: auth.sess, user: auth.user };

  if (path === "/" ) {
    // redirect to best landing
    const landing = await landingForUser(ctx.env.DB, session.sid, session.user.id, session.sess.active_school_id);
    return redirect(landing.path);
  }

  if (path === "/choose-school") return handleChooseSchool(ctx, session);
  if (path === "/switch-school") return handleSwitchSchool(ctx, session);
  if (path === "/sys") return handleSys(ctx, session);
  if (path === "/school") return handleSchool(ctx, session);
  if (path === "/teacher") return handleTeacher(ctx, session);
  if (path === "/student") return handleStudent(ctx, session);
  if (path === "/profile") return handleProfile(ctx, session);

  return new Response(page("Not found", `<div class="card err"><h1>404</h1><p class="mut">No route for ${htmlEscape(path)}</p></div>`), {
    status: 404,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
