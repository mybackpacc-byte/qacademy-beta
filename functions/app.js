export async function handleRequest(ctx) {
  try {
    const { request, env } = ctx;
    const url = new URL(request.url);
    const path = url.pathname;

    // If DB binding is missing, show a clear message (prevents Error 1101 mystery)
    if (!env.DB) {
      return page(
        `
        <div class="card err">
          <h1>DB not connected</h1>
          <p class="muted">Your Pages project does not have the D1 binding set.</p>
          <p class="muted">Fix: Pages → Settings → Functions → D1 bindings → add <b>DB</b> → select <b>beta_db</b> (for Production + Preview).</p>
        </div>
      `,
        500
      );
    }

    // =============================
    // Constants (easy to change)
    // =============================
    const JOIN_CODE_DEFAULT_EXP_DAYS = 14;
    const JOIN_CODE_DEFAULT_MAX_USES = 300;

    // Safety defaults (change later if you want)
    const ALLOW_SCHOOL_ADMIN_JOIN_CODES = false; // public escalation risk
    const JOIN_PREVENT_TEACHER_DEMOTION_ON_STUDENT_CODES = true; // avoids accidental staff lockouts

    // ---------- Helpers ----------
    const nowISO = () => new Date().toISOString();
    const uuid = () => crypto.randomUUID();

    // "pepper" (server secret)
    const PEPPER = env.APP_SECRET || "";

    function page(body, status = 200, headers = {}) {
      return new Response(
        `<!doctype html><html><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Beta</title>
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

    async function form() {
      const fd = await request.formData();
      const out = {};
      for (const [k, v] of fd.entries()) out[k] = String(v).trim();
      return out;
    }

    // --- crypto helpers ---
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

    // --- cookies ---
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

    // --- DB helpers ---
    const first = async (sql, params = []) => await env.DB.prepare(sql).bind(...params).first();

    const all = async (sql, params = []) => {
      const res = await env.DB.prepare(sql).bind(...params).all();
      return res.results || [];
    };

    const run = async (sql, params = []) => await env.DB.prepare(sql).bind(...params).run();

    // --- auth load ---
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

    // =============================
    // Join code helpers
    // =============================
    const CODE_ALPH = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // avoids O/0 and I/1 confusion
    function makeJoinCodePlain() {
      // 8 chars + dash for readability (e.g., 8PZK-4WQH)
      const rnd = (n) => {
        let s = "";
        const a = new Uint8Array(n);
        crypto.getRandomValues(a);
        for (let i = 0; i < n; i++) s += CODE_ALPH[a[i] % CODE_ALPH.length];
        return s;
      };
      return `${rnd(4)}-${rnd(4)}`;
    }

    async function joinCodeHash(codePlain) {
      // separate label helps avoid accidentally reusing same hash scheme elsewhere
      return await sha256Hex(`${codePlain}|${PEPPER}|JOINCODE`);
    }

    function isIsoInPast(iso) {
      if (!iso) return false;
      const t = Date.parse(iso);
      if (Number.isNaN(t)) return false;
      return t < Date.now();
    }

    function scopeLabel(scope) {
      if (scope === "TENANT_ROLE") return "School access";
      if (scope === "COURSE_ENROLL") return "Course enrol";
      if (scope === "COURSE_TEACHER") return "Course teacher";
      return scope || "";
    }

    function requestTypeFromScope(scope) {
      if (scope === "TENANT_ROLE") return "MEMBERSHIP";
      if (scope === "COURSE_ENROLL") return "COURSE_ENROLL";
      if (scope === "COURSE_TEACHER") return "COURSE_TEACHER";
      return "MEMBERSHIP";
    }

    async function loadJoinCodeByPlain(codePlain) {
      const h = await joinCodeHash(codePlain);
      const jc = await first(
        `SELECT jc.*, t.name AS tenant_name, c.title AS course_title
         FROM join_codes jc
         JOIN tenants t ON t.id = jc.tenant_id
         LEFT JOIN courses c ON c.id = jc.course_id
         WHERE jc.code_hash=?`,
        [h]
      );
      return jc || null;
    }

    function joinCodeIsValid(jc) {
      if (!jc) return { ok: false, why: "Invalid code." };
      if (Number(jc.revoked) === 1) return { ok: false, why: "This code was revoked." };
      if (isIsoInPast(jc.expires_at)) return { ok: false, why: "This code has expired." };
      if (Number(jc.uses_approved) >= Number(jc.max_uses)) return { ok: false, why: "This code has reached its maximum uses." };
      return { ok: true, why: "" };
    }

    async function reserveJoinCodeUse(joinCodeId) {
      // Reserve a use (prevents race-ish issues). If this fails, code is not usable now.
      const ts = nowISO();
      const res = await run(
        `UPDATE join_codes
         SET uses_approved = uses_approved + 1, updated_at=?
         WHERE id=? AND revoked=0 AND uses_approved < max_uses AND expires_at > ?`,
        [ts, joinCodeId, ts]
      );
      return Number(res?.meta?.changes || 0) > 0;
    }

    async function unreserveJoinCodeUse(joinCodeId) {
      // Best-effort rollback if something failed after reserving.
      await run(
        `UPDATE join_codes
         SET uses_approved = CASE WHEN uses_approved>0 THEN uses_approved-1 ELSE 0 END, updated_at=?
         WHERE id=?`,
        [nowISO(), joinCodeId]
      );
    }

    async function ensureMembership(tenantId, userId, roleWanted) {
      // Fetch current membership (if any)
      const m = await first(
        "SELECT id, role, status FROM memberships WHERE tenant_id=? AND user_id=? ORDER BY created_at ASC LIMIT 1",
        [tenantId, userId]
      );

      const ts = nowISO();

      if (!m) {
        // Create new membership
        const mid = uuid();
        await run(
          "INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,?,'ACTIVE',?,?)",
          [mid, userId, tenantId, roleWanted, ts, ts]
        );
        return { created: true, updated: false, role: roleWanted };
      }

      // If membership exists but inactive, reactivate + set role
      if (m.status !== "ACTIVE") {
        await run("UPDATE memberships SET status='ACTIVE', role=?, updated_at=? WHERE id=?", [roleWanted, ts, m.id]);
        return { created: false, updated: true, role: roleWanted };
      }

      // Active membership: update role if different (unless we decide to keep SCHOOL_ADMIN)
      if (m.role !== roleWanted) {
        await run("UPDATE memberships SET role=?, updated_at=? WHERE id=?", [roleWanted, ts, m.id]);
        return { created: false, updated: true, role: roleWanted };
      }

      return { created: false, updated: false, role: m.role };
    }

    async function applyJoinActionForUser(userId, jc) {
      // Validate scope/course existence
      if (jc.scope === "COURSE_ENROLL" || jc.scope === "COURSE_TEACHER") {
        if (!jc.course_id) return { ok: false, msg: "Code is missing course binding." };

        const c = await first("SELECT id, tenant_id, status FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [
          jc.course_id,
          jc.tenant_id,
        ]);
        if (!c) return { ok: false, msg: "Course not found or inactive." };
      }

      // Get current membership role (if any)
      const m = await first(
        "SELECT id, role, status FROM memberships WHERE tenant_id=? AND user_id=? ORDER BY created_at ASC LIMIT 1",
        [jc.tenant_id, userId]
      );
      const curRole = m && m.status === "ACTIVE" ? m.role : null;

      // Prevent accidental demotion of teachers using student-only codes (default safety)
      if (
        JOIN_PREVENT_TEACHER_DEMOTION_ON_STUDENT_CODES &&
        curRole === "TEACHER" &&
        jc.role === "STUDENT" &&
        (jc.scope === "TENANT_ROLE" || jc.scope === "COURSE_ENROLL")
      ) {
        return { ok: false, msg: "This code is for students. Ask the School Admin for the correct code." };
      }

      // 1) TENANT_ROLE: set membership role
      if (jc.scope === "TENANT_ROLE") {
        // Disallow SCHOOL_ADMIN join codes by default (safety)
        if (!ALLOW_SCHOOL_ADMIN_JOIN_CODES && jc.role === "SCHOOL_ADMIN") {
          return { ok: false, msg: "School Admin join codes are disabled." };
        }

        // If user is already SCHOOL_ADMIN, keep it (don’t auto-demote)
        const roleToSet = curRole === "SCHOOL_ADMIN" ? "SCHOOL_ADMIN" : jc.role;
        await ensureMembership(jc.tenant_id, userId, roleToSet);
        return { ok: true, msg: `School access updated: ${roleLabel(roleToSet)}.` };
      }

      // 2) COURSE_ENROLL: ensure student membership, then enroll
      if (jc.scope === "COURSE_ENROLL") {
        // If SCHOOL_ADMIN already, keep role; else set to STUDENT
        const roleToSet = curRole === "SCHOOL_ADMIN" ? "SCHOOL_ADMIN" : "STUDENT";
        if (!curRole) {
          await ensureMembership(jc.tenant_id, userId, roleToSet);
        } else if (curRole !== "SCHOOL_ADMIN" && curRole !== "STUDENT") {
          // If they were TEACHER, safety rule above likely blocks; otherwise update to STUDENT
          await ensureMembership(jc.tenant_id, userId, "STUDENT");
        }

        // Enroll (avoid duplicates)
        const ex = await first("SELECT 1 AS x FROM enrollments WHERE course_id=? AND user_id=? LIMIT 1", [
          jc.course_id,
          userId,
        ]);
        if (!ex) {
          await run("INSERT INTO enrollments (course_id,user_id,created_at) VALUES (?,?,?)", [
            jc.course_id,
            userId,
            nowISO(),
          ]);
        }
        return { ok: true, msg: `Enrolled into course: ${jc.course_title || "Course"}.` };
      }

      // 3) COURSE_TEACHER: ensure teacher membership, then assign teacher
      if (jc.scope === "COURSE_TEACHER") {
        const roleToSet = curRole === "SCHOOL_ADMIN" ? "SCHOOL_ADMIN" : "TEACHER";
        if (!curRole) {
          await ensureMembership(jc.tenant_id, userId, roleToSet);
        } else if (curRole !== "SCHOOL_ADMIN" && curRole !== "TEACHER") {
          // Promote student -> teacher if they used a teacher code (intentional)
          await ensureMembership(jc.tenant_id, userId, "TEACHER");
        }

        const ex = await first("SELECT 1 AS x FROM course_teachers WHERE course_id=? AND user_id=? LIMIT 1", [
          jc.course_id,
          userId,
        ]);
        if (!ex) {
          await run("INSERT INTO course_teachers (course_id,user_id,created_at) VALUES (?,?,?)", [
            jc.course_id,
            userId,
            nowISO(),
          ]);
        }
        return { ok: true, msg: `Assigned as teacher for: ${jc.course_title || "Course"}.` };
      }

      return { ok: false, msg: "Unknown join code scope." };
    }

    // Creates session + sets cookie
    async function createSessionForUser(userId) {
      const token = uuid() + "-" + uuid();
      const tokenHash = await sha256Hex(token);
      const ts = nowISO();
      const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString(); // 7 days

      await run(
        "INSERT INTO sessions (token_hash,user_id,active_tenant_id,expires_at,created_at) VALUES (?,?,?,?,?)",
        [tokenHash, userId, null, expires, ts]
      );

      return {
        token,
        headers: { "Set-Cookie": cookieSet("qa_sess", token, 60 * 60 * 24 * 7) },
      };
    }

    // ---------- Routes ----------

    if (path === "/health") {
      const row = await first("SELECT COUNT(*) AS n FROM users", []);
      return page(
        `<div class="card"><h1>OK</h1><p class="muted">Users count: ${escapeHtml(row?.n ?? 0)}</p></div>`
      );
    }

    if (path === "/") {
      const a = await loadAuth();
      if (!a.user) return redirect("/login");
      if (Number(a.user.is_system_admin) === 1) return redirect("/sys");
      if (!a.memberships.length) return redirect("/no-access");

      const active = pickActiveMembership(a);
      if (!active) {
        if (a.memberships.length === 1)
          return redirect(`/switch-school?tenant_id=${encodeURIComponent(a.memberships[0].tenant_id)}`);
        return redirect("/choose-school");
      }

      if (active.role === "SCHOOL_ADMIN") return redirect("/school");
      if (active.role === "TEACHER") return redirect("/teacher");
      if (active.role === "STUDENT") return redirect("/student");
      return redirect("/no-access");
    }

    if (path === "/no-access") {
      return page(`
        <div class="card">
          <h1>No access</h1>
          <p class="muted">Your account has no active school access yet.</p>
          <p class="muted">If you have a join code, go to <a href="/join">/join</a>.</p>
          <p><a href="/logout">Logout</a></p>
        </div>
      `);
    }

    // Setup (only if zero users exist)
    if (path === "/setup") {
      const countRow = await first("SELECT COUNT(*) AS n FROM users", []);
      const n = Number(countRow?.n || 0);

      if (request.method === "GET") {
        if (n > 0) {
          return page(`
            <div class="card">
              <h1>Setup already done</h1>
              <p><a href="/login">Go to login</a></p>
            </div>
          `);
        }
        return page(`
          <div class="card">
            <h1>First-time Setup</h1>
            <p class="muted">Create the System Admin account (only once).</p>
            <form method="post" action="/setup">
              <label>Full name</label><input name="name" required />
              <label>Email</label><input name="email" type="email" required />
              <label>Password (6+ characters)</label><input name="password" type="password" required />
              <button type="submit">Create System Admin</button>
            </form>
          </div>
        `);
      }

      if (request.method === "POST") {
        if (n > 0) return redirect("/login");
        const f = await form();
        const name = (f.name || "");
        const email = (f.email || "").toLowerCase();
        const password = (f.password || "");

        if (!name || !email || password.length < 6) {
          return page(
            `<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/setup">Back</a></p>`,
            400
          );
        }

        const saltHex = randomSaltHex();
        const iter = 40000;
        const hashHex = await pbkdf2Hex(password + "|" + PEPPER, saltHex, iter);
        const id = uuid();
        const ts = nowISO();

        await run(
          "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,1,'ACTIVE',?,?)",
          [id, email, name, saltHex, hashHex, iter, ts, ts]
        );

        return page(`
          <div class="card ok">
            <h1>System Admin created</h1>
            <p><a href="/login">Go to login</a></p>
          </div>
        `);
      }
    }

    // Login
    if (path === "/login") {
      if (request.method === "GET") {
        return page(`
          <div class="card">
            <h1>Login</h1>
            <form method="post" action="/login">
              <label>Email</label><input name="email" type="email" required />
              <label>Password</label><input name="password" type="password" required />
              <button type="submit">Login</button>
            </form>
            <p class="muted">Have a join code? Go to <a href="/join">/join</a>.</p>
            <p class="muted">First time? Go to <a href="/setup">/setup</a>.</p>
          </div>
        `);
      }

      if (request.method === "POST") {
        const f = await form();
        const email = (f.email || "").toLowerCase();
        const password = (f.password || "");

        const u = await first(
          "SELECT id,email,name,password_salt,password_hash,password_iter,is_system_admin FROM users WHERE email=? AND status='ACTIVE'",
          [email]
        );
        if (!u)
          return page(
            `<div class="card err"><b>Wrong email or password.</b></div><p><a href="/login">Try again</a></p>`,
            401
          );

        const check = await pbkdf2Hex(password + "|" + PEPPER, u.password_salt, Number(u.password_iter));
        if (check !== u.password_hash) {
          return page(
            `<div class="card err"><b>Wrong email or password.</b></div><p><a href="/login">Try again</a></p>`,
            401
          );
        }

        const token = uuid() + "-" + uuid();
        const tokenHash = await sha256Hex(token);
        const ts = nowISO();
        const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7).toISOString(); // 7 days

        await run(
          "INSERT INTO sessions (token_hash,user_id,active_tenant_id,expires_at,created_at) VALUES (?,?,?,?,?)",
          [tokenHash, u.id, null, expires, ts]
        );

        const headers = { "Set-Cookie": cookieSet("qa_sess", token, 60 * 60 * 24 * 7) };

        // System Admin: go straight to system dashboard
        if (Number(u.is_system_admin) === 1) return redirect("/sys", headers);

        // Non-system users: route smartly
        const mems = await all(
          `SELECT m.tenant_id, m.role, t.name AS tenant_name
           FROM memberships m
           JOIN tenants t ON t.id = m.tenant_id
           WHERE m.user_id=? AND m.status='ACTIVE' AND t.status='ACTIVE'
           ORDER BY t.name ASC`,
          [u.id]
        );

        if (!mems.length) return redirect("/no-access", headers);

        // If exactly 1 school, set active school immediately and go straight to the correct dashboard
        if (mems.length === 1) {
          await run("UPDATE sessions SET active_tenant_id=? WHERE token_hash=?", [mems[0].tenant_id, tokenHash]);

          if (mems[0].role === "SCHOOL_ADMIN") return redirect("/school", headers);
          if (mems[0].role === "TEACHER") return redirect("/teacher", headers);
          if (mems[0].role === "STUDENT") return redirect("/student", headers);
          return redirect("/no-access", headers);
        }

        // Multiple schools
        return redirect("/choose-school", headers);
      }
    }

    // Logout
    if (path === "/logout") {
      const token = cookieGet("qa_sess");
      if (token) {
        const tokenHash = await sha256Hex(token);
        await run("DELETE FROM sessions WHERE token_hash=?", [tokenHash]);
      }
      return redirect("/login", { "Set-Cookie": cookieClear("qa_sess") });
    }

    // Choose school
    if (path === "/choose-school") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      if (Number(r.user.is_system_admin) === 1) return redirect("/sys");
      if (!r.memberships.length) return redirect("/no-access");

      // If only one membership, no need for this page
      if (r.memberships.length === 1) {
        return redirect(`/switch-school?tenant_id=${encodeURIComponent(r.memberships[0].tenant_id)}`);
      }

      const activeNow = pickActiveMembership(r);
      const activeId = activeNow ? activeNow.tenant_id : null;

      const cards = r.memberships
        .map((m) => {
          const isCurrent = activeId && m.tenant_id === activeId;
          return `
            <div class="card">
              <div class="topbar">
                <div>
                  <div><b>${escapeHtml(m.tenant_name)}</b></div>
                  <div class="muted">
                    Role: <span class="pill">${escapeHtml(roleLabel(m.role))}</span>
                    ${isCurrent ? `<span class="pill">Current</span>` : ``}
                  </div>
                </div>
                <form method="post" action="/switch-school">
                  <input type="hidden" name="tenant_id" value="${escapeAttr(m.tenant_id)}"/>
                  <button type="submit">${isCurrent ? "Open" : "Switch"}</button>
                </form>
              </div>
            </div>
          `;
        })
        .join("");

      return page(`
        <div class="card">
          <h1>Choose School</h1>
          <p class="muted">Select which school you want to use right now.</p>
        </div>
        ${cards}
        <p class="actions"><a href="/profile">Profile</a> <a href="/logout">Logout</a></p>
      `);
    }

    // Switch school (set active tenant on session)
    if (path === "/switch-school") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      let tenantId = url.searchParams.get("tenant_id") || "";
      if (request.method === "POST") {
        const f = await form();
        tenantId = (f.tenant_id || tenantId).trim();
      }

      const membership = r.memberships.find((m) => m.tenant_id === tenantId);
      if (!membership) return redirect("/choose-school");

      await setActiveTenantForCurrentSession(tenantId);
      return redirect("/");
    }

    // =============================
    // Public Join
    // =============================
    if (path === "/join") {
      const a = await loadAuth();
      const isLoggedIn = !!a.user;

      if (request.method === "GET") {
        return page(`
          <div class="card">
            <div class="topbar">
              <h1>Join a school or course</h1>
              <div class="actions">
                ${isLoggedIn ? `<a href="/">Dashboard</a>` : `<a href="/login">Login</a>`}
              </div>
            </div>
            <p class="muted">Enter your join code. You can join a school role or a specific course.</p>
            <form method="post" action="/join">
              <label>Join code</label>
              <input name="code" placeholder="ABCD-EFGH" required />
              <button type="submit">Continue</button>
            </form>
          </div>
        `);
      }

      if (request.method === "POST") {
        const f = await form();
        const codePlain = (f.code || "").toUpperCase().replaceAll(" ", "");
        if (!codePlain) return redirect("/join");

        const jc = await loadJoinCodeByPlain(codePlain);
        const v = joinCodeIsValid(jc);
        if (!v.ok) {
          return page(`
            <div class="card err"><b>${escapeHtml(v.why)}</b></div>
            <p><a href="/join">Back</a></p>
          `, 400);
        }

        // If logged in, process immediately (auto-approve -> apply now; otherwise create request)
        if (isLoggedIn) {
          // If auto-approve, reserve a use now
          if (Number(jc.auto_approve) === 1) {
            const reserved = await reserveJoinCodeUse(jc.id);
            if (!reserved) {
              return page(`<div class="card err"><b>Code is no longer available (expired/used up/revoked).</b></div><p><a href="/join">Back</a></p>`, 400);
            }
            const applied = await applyJoinActionForUser(a.user.id, jc);
            if (!applied.ok) {
              await unreserveJoinCodeUse(jc.id);
              return page(`<div class="card err"><b>${escapeHtml(applied.msg)}</b></div><p><a href="/join">Back</a></p>`, 400);
            }

            // If they now have access to this tenant, set active tenant
            await setActiveTenantForCurrentSession(jc.tenant_id);

            return page(`
              <div class="card ok">
                <h1>Joined</h1>
                <p class="muted">${escapeHtml(applied.msg)}</p>
                <p class="actions"><a href="/">Go to dashboard</a> <a href="/join">Join another</a></p>
              </div>
            `);
          }

          // Not auto-approve => create join request (no use consumed yet)
          const exists = await first(
            `SELECT id FROM join_requests
             WHERE join_code_id=? AND user_id=? AND status='PENDING' LIMIT 1`,
            [jc.id, a.user.id]
          );
          if (!exists) {
            await run(
              `INSERT INTO join_requests
               (id,join_code_id,tenant_id,course_id,user_id,type,requested_role,status,reviewed_by_user_id,reviewed_at,created_at)
               VALUES (?,?,?,?,?,?,?,'PENDING',NULL,NULL,?)`,
              [
                uuid(),
                jc.id,
                jc.tenant_id,
                jc.course_id || null,
                a.user.id,
                requestTypeFromScope(jc.scope),
                jc.role,
                nowISO(),
              ]
            );
          }

          return page(`
            <div class="card ok">
              <h1>Request sent</h1>
              <p class="muted">School: <b>${escapeHtml(jc.tenant_name)}</b></p>
              <p class="muted">Request: <b>${escapeHtml(scopeLabel(jc.scope))}</b> (${escapeHtml(roleLabel(jc.role))}${jc.course_title ? ` • ${escapeHtml(jc.course_title)}` : ""})</p>
              <p class="muted">A School Admin must approve this request.</p>
              <p class="actions"><a href="/">Back</a> <a href="/join">Join another</a></p>
            </div>
          `);
        }

        // Not logged in => show login/create forms (both carry the code as hidden input)
        return page(`
          <div class="card">
            <h1>Join preview</h1>
            <p class="muted">School: <b>${escapeHtml(jc.tenant_name)}</b></p>
            <p class="muted">Action: <b>${escapeHtml(scopeLabel(jc.scope))}</b> • Role: <b>${escapeHtml(roleLabel(jc.role))}</b>${jc.course_title ? ` • Course: <b>${escapeHtml(jc.course_title)}</b>` : ""}</p>
            <p class="muted">Expires: ${escapeHtml(fmtISO(jc.expires_at))} • Uses: ${escapeHtml(jc.uses_approved)}/${escapeHtml(jc.max_uses)} • Auto-approve: ${Number(jc.auto_approve) === 1 ? "Yes" : "No"}</p>
          </div>

          <div class="row">
            <div class="card">
              <h2>Login</h2>
              <form method="post" action="/join-login">
                <input type="hidden" name="code" value="${escapeAttr(codePlain)}"/>
                <label>Email</label><input name="email" type="email" required />
                <label>Password</label><input name="password" type="password" required />
                <button type="submit">Login & join</button>
              </form>
            </div>

            <div class="card">
              <h2>Create account</h2>
              <form method="post" action="/join-create-account">
                <input type="hidden" name="code" value="${escapeAttr(codePlain)}"/>
                <label>Full name</label><input name="name" required />
                <label>Email</label><input name="email" type="email" required />
                <label>Password (6+ characters)</label><input name="password" type="password" required />
                <button type="submit">Create & join</button>
              </form>
              <p class="muted small">This creates your account and then completes the join request/approval flow.</p>
            </div>
          </div>

          <p><a href="/join">Back</a></p>
        `);
      }
    }

    // Join: login then continue
    if (path === "/join-login" && request.method === "POST") {
      const f = await form();
      const codePlain = (f.code || "").toUpperCase().replaceAll(" ", "");
      const email = (f.email || "").toLowerCase();
      const password = (f.password || "");

      const jc = await loadJoinCodeByPlain(codePlain);
      const v = joinCodeIsValid(jc);
      if (!v.ok) return page(`<div class="card err"><b>${escapeHtml(v.why)}</b></div><p><a href="/join">Back</a></p>`, 400);

      const u = await first(
        "SELECT id,email,name,password_salt,password_hash,password_iter,is_system_admin FROM users WHERE email=? AND status='ACTIVE'",
        [email]
      );
      if (!u) return page(`<div class="card err"><b>Wrong email or password.</b></div><p><a href="/join">Back</a></p>`, 401);

      const check = await pbkdf2Hex(password + "|" + PEPPER, u.password_salt, Number(u.password_iter));
      if (check !== u.password_hash) return page(`<div class="card err"><b>Wrong email or password.</b></div><p><a href="/join">Back</a></p>`, 401);

      // Create session cookie
      const s = await createSessionForUser(u.id);

      // System Admin accounts can still join schools via code if you want; we allow it.
      // Process join: auto-approve -> apply now; else create request.
      if (Number(jc.auto_approve) === 1) {
        const reserved = await reserveJoinCodeUse(jc.id);
        if (!reserved) return page(`<div class="card err"><b>Code is no longer available.</b></div><p><a href="/join">Back</a></p>`, 400);

        const applied = await applyJoinActionForUser(u.id, jc);
        if (!applied.ok) {
          await unreserveJoinCodeUse(jc.id);
          return page(`<div class="card err"><b>${escapeHtml(applied.msg)}</b></div><p><a href="/join">Back</a></p>`, 400);
        }

        // Set active tenant to the code’s tenant
        // (We have token in cookie, but the session row already exists with null active tenant.)
        // We can update by hashing the same token we just set.
        await (async () => {
          const tokenHash = await sha256Hex(s.token);
          await run("UPDATE sessions SET active_tenant_id=? WHERE token_hash=?", [jc.tenant_id, tokenHash]);
        })();

        return redirect("/", s.headers);
      }

      const exists = await first(
        `SELECT id FROM join_requests
         WHERE join_code_id=? AND user_id=? AND status='PENDING' LIMIT 1`,
        [jc.id, u.id]
      );
      if (!exists) {
        await run(
          `INSERT INTO join_requests
           (id,join_code_id,tenant_id,course_id,user_id,type,requested_role,status,reviewed_by_user_id,reviewed_at,created_at)
           VALUES (?,?,?,?,?,?,?,'PENDING',NULL,NULL,?)`,
          [
            uuid(),
            jc.id,
            jc.tenant_id,
            jc.course_id || null,
            u.id,
            requestTypeFromScope(jc.scope),
            jc.role,
            nowISO(),
          ]
        );
      }

      // Send them somewhere sensible; they may have access elsewhere already.
      return page(
        `<div class="card ok"><h1>Request sent</h1><p class="muted">A School Admin must approve this request.</p><p class="actions"><a href="/">Continue</a></p></div>`,
        200,
        s.headers
      );
    }

    // Join: create account then continue
    if (path === "/join-create-account" && request.method === "POST") {
      const f = await form();
      const codePlain = (f.code || "").toUpperCase().replaceAll(" ", "");
      const name = (f.name || "");
      const email = (f.email || "").toLowerCase();
      const password = (f.password || "");

      const jc = await loadJoinCodeByPlain(codePlain);
      const v = joinCodeIsValid(jc);
      if (!v.ok) return page(`<div class="card err"><b>${escapeHtml(v.why)}</b></div><p><a href="/join">Back</a></p>`, 400);

      if (!name || !email || password.length < 6) {
        return page(`<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/join">Back</a></p>`, 400);
      }

      const ts = nowISO();

      // Create user if not exists; if exists, we do NOT overwrite password here.
      let u = await first("SELECT id FROM users WHERE email=? AND status='ACTIVE'", [email]);
      let userId = u?.id;

      if (!userId) {
        const saltHex = randomSaltHex();
        const iter = 40000;
        const hashHex = await pbkdf2Hex(password + "|" + PEPPER, saltHex, iter);
        userId = uuid();
        await run(
          "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,0,'ACTIVE',?,?)",
          [userId, email, name, saltHex, hashHex, iter, ts, ts]
        );
      }

      const s = await createSessionForUser(userId);

      // Process join: auto-approve -> apply now; else create request.
      if (Number(jc.auto_approve) === 1) {
        const reserved = await reserveJoinCodeUse(jc.id);
        if (!reserved) return page(`<div class="card err"><b>Code is no longer available.</b></div><p><a href="/join">Back</a></p>`, 400);

        const applied = await applyJoinActionForUser(userId, jc);
        if (!applied.ok) {
          await unreserveJoinCodeUse(jc.id);
          return page(`<div class="card err"><b>${escapeHtml(applied.msg)}</b></div><p><a href="/join">Back</a></p>`, 400);
        }

        await (async () => {
          const tokenHash = await sha256Hex(s.token);
          await run("UPDATE sessions SET active_tenant_id=? WHERE token_hash=?", [jc.tenant_id, tokenHash]);
        })();

        return redirect("/", s.headers);
      }

      const exists = await first(
        `SELECT id FROM join_requests
         WHERE join_code_id=? AND user_id=? AND status='PENDING' LIMIT 1`,
        [jc.id, userId]
      );
      if (!exists) {
        await run(
          `INSERT INTO join_requests
           (id,join_code_id,tenant_id,course_id,user_id,type,requested_role,status,reviewed_by_user_id,reviewed_at,created_at)
           VALUES (?,?,?,?,?,?,?,'PENDING',NULL,NULL,?)`,
          [
            uuid(),
            jc.id,
            jc.tenant_id,
            jc.course_id || null,
            userId,
            requestTypeFromScope(jc.scope),
            jc.role,
            nowISO(),
          ]
        );
      }

      return page(
        `<div class="card ok"><h1>Request sent</h1><p class="muted">A School Admin must approve this request.</p><p class="actions"><a href="/">Continue</a></p></div>`,
        200,
        s.headers
      );
    }

    // =============================
    // Profile (basic)
    // =============================
    if (path === "/profile") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      if (request.method === "GET") {
        const mems = r.memberships || [];
        const rows = mems
          .map(
            (m) =>
              `<li><b>${escapeHtml(m.tenant_name)}</b> — <span class="pill">${escapeHtml(roleLabel(m.role))}</span></li>`
          )
          .join("");

        return page(`
          <div class="card">
            <div class="topbar">
              <h1>Profile</h1>
              <div class="actions">
                <a href="/">Dashboard</a>
                <a href="/logout">Logout</a>
              </div>
            </div>
            <p class="muted"><b>${escapeHtml(r.user.name)}</b> — ${escapeHtml(r.user.email)}</p>
            ${Number(r.user.is_system_admin) === 1 ? `<p><span class="pill">System Admin</span></p>` : ""}
          </div>

          <div class="card">
            <h2>My schools</h2>
            <ul>${rows || "<li class='muted'>None</li>"}</ul>
          </div>

          <div class="card">
            <h2>Change password</h2>
            <form method="post" action="/profile">
              <label>Current password</label><input name="old_password" type="password" required />
              <label>New password (6+ characters)</label><input name="new_password" type="password" required />
              <label>Confirm new password</label><input name="new_password2" type="password" required />
              <button type="submit">Update password</button>
            </form>
          </div>
        `);
      }

      if (request.method === "POST") {
        const f = await form();
        const oldPw = f.old_password || "";
        const newPw = f.new_password || "";
        const newPw2 = f.new_password2 || "";

        if (newPw.length < 6) return page(`<div class="card err"><b>New password must be 6+ characters.</b></div><p><a href="/profile">Back</a></p>`, 400);
        if (newPw !== newPw2) return page(`<div class="card err"><b>Passwords do not match.</b></div><p><a href="/profile">Back</a></p>`, 400);

        const u = await first(
          "SELECT id,password_salt,password_hash,password_iter FROM users WHERE id=? AND status='ACTIVE'",
          [r.user.id]
        );
        if (!u) return redirect("/logout");

        const check = await pbkdf2Hex(oldPw + "|" + PEPPER, u.password_salt, Number(u.password_iter));
        if (check !== u.password_hash) {
          return page(`<div class="card err"><b>Current password is incorrect.</b></div><p><a href="/profile">Back</a></p>`, 401);
        }

        const saltHex = randomSaltHex();
        const iter = 40000;
        const hashHex = await pbkdf2Hex(newPw + "|" + PEPPER, saltHex, iter);
        await run("UPDATE users SET password_salt=?, password_hash=?, password_iter=?, updated_at=? WHERE id=?", [
          saltHex,
          hashHex,
          iter,
          nowISO(),
          r.user.id,
        ]);

        return page(`<div class="card ok"><h1>Password updated</h1><p class="actions"><a href="/">Back to dashboard</a></p></div>`);
      }
    }

    // =============================
    // System Admin dashboard (+ user directory)
    // =============================
    if (path === "/sys") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) !== 1) return redirect("/");

      const tenants = await all("SELECT id,name,status FROM tenants ORDER BY name ASC", []);
      const list = tenants
        .map((t) => `<li>${escapeHtml(t.name)} <span class="muted">(${escapeHtml(t.status)})</span></li>`)
        .join("");

      // User directory search (GET ?q=email)
      const q = (url.searchParams.get("q") || "").trim().toLowerCase();
      let userSearchBlock = "";
      if (q) {
        const users = await all(
          "SELECT id,email,name,is_system_admin,status,created_at FROM users WHERE lower(email) LIKE ? ORDER BY email ASC LIMIT 25",
          [`%${q}%`]
        );

        const tenantOptions = tenants
          .filter((t) => t.status === "ACTIVE")
          .map((t) => `<option value="${escapeAttr(t.id)}">${escapeHtml(t.name)}</option>`)
          .join("");

        const rows = [];
        for (const u of users) {
          const mems = await all(
            `SELECT m.tenant_id, t.name AS tenant_name, m.role, m.status
             FROM memberships m JOIN tenants t ON t.id=m.tenant_id
             WHERE m.user_id=?
             ORDER BY t.name ASC`,
            [u.id]
          );

          const memList = mems
            .map((m) => `${escapeHtml(m.tenant_name)}: ${escapeHtml(m.role)} (${escapeHtml(m.status)})`)
            .join("<br/>");

          rows.push(`
            <tr>
              <td>
                <b>${escapeHtml(u.email)}</b><br/>
                <span class="muted">${escapeHtml(u.name)}</span>
                ${Number(u.is_system_admin) === 1 ? `<div class="pill">System Admin</div>` : ``}
              </td>
              <td class="small">${memList || `<span class="muted">No memberships</span>`}</td>
              <td>
                <form method="post" action="/sys-add-member">
                  <input type="hidden" name="user_id" value="${escapeAttr(u.id)}"/>
                  <label class="small">School</label>
                  <select name="tenant_id" required>${tenantOptions || "<option value=''>No schools</option>"}</select>
                  <label class="small">Role</label>
                  <select name="role" required>
                    <option value="STUDENT">Student</option>
                    <option value="TEACHER">Teacher</option>
                    <option value="SCHOOL_ADMIN">School Admin</option>
                  </select>
                  <button type="submit" style="margin-top:8px">Add / Update</button>
                </form>
              </td>
            </tr>
          `);
        }

        userSearchBlock = `
          <div class="card">
            <h2>User directory</h2>
            <p class="muted">Search: <b>${escapeHtml(q)}</b></p>
            <table class="table">
              <thead><tr><th>User</th><th>Schools / Roles</th><th>Add to school</th></tr></thead>
              <tbody>
                ${rows.join("") || `<tr><td colspan="3" class="muted">No users found</td></tr>`}
              </tbody>
            </table>
          </div>
        `;
      }

      return page(`
        <div class="card">
          <div class="topbar">
            <h1>System Admin</h1>
            <div class="actions">
              <a href="/profile">Profile</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
          <p class="muted">Create a school + its first School Admin in one step.</p>
        </div>

        <div class="card">
          <h2>Create School</h2>
          <form method="post" action="/sys-create-school">
            <label>School name</label><input name="tenant_name" required />
            <div class="row">
              <div>
                <label>School Admin full name</label><input name="admin_name" required />
              </div>
              <div>
                <label>School Admin email</label><input name="admin_email" type="email" required />
              </div>
            </div>
            <label>Temporary password (used only if this email is NEW)</label>
            <input name="admin_password" type="text" required />
            <button type="submit">Create school + admin</button>
          </form>
          <p class="muted">If the email already exists, we won’t change their password — we only add them to the school.</p>
        </div>

        <div class="card">
          <h2>Find user by email</h2>
          <form method="get" action="/sys">
            <label>Email contains</label>
            <input name="q" value="${escapeAttr(q)}" placeholder="e.g. ama@" required />
            <button type="submit">Search</button>
          </form>
        </div>

        ${userSearchBlock}

        <div class="card">
          <h2>Schools</h2>
          <ul>${list || "<li class='muted'>No schools yet</li>"}</ul>
        </div>
      `);
    }

    if (path === "/sys-add-member" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) !== 1) return redirect("/");

      const f = await form();
      const userId = (f.user_id || "").trim();
      const tenantId = (f.tenant_id || "").trim();
      const role = (f.role || "").trim();

      if (!userId || !tenantId || !["STUDENT", "TEACHER", "SCHOOL_ADMIN"].includes(role)) return redirect("/sys");

      const u = await first("SELECT id FROM users WHERE id=? AND status='ACTIVE'", [userId]);
      const t = await first("SELECT id FROM tenants WHERE id=? AND status='ACTIVE'", [tenantId]);
      if (!u || !t) return redirect("/sys");

      // Create membership if missing; otherwise update + reactivate
      const m = await first(
        "SELECT id,status FROM memberships WHERE user_id=? AND tenant_id=? ORDER BY created_at ASC LIMIT 1",
        [userId, tenantId]
      );
      const ts = nowISO();

      if (!m) {
        await run(
          "INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,?,'ACTIVE',?,?)",
          [uuid(), userId, tenantId, role, ts, ts]
        );
      } else {
        await run("UPDATE memberships SET role=?, status='ACTIVE', updated_at=? WHERE id=?", [role, ts, m.id]);
      }

      return redirect(`/sys?q=${encodeURIComponent((url.searchParams.get("q") || "").trim())}`);
    }

    if (path === "/sys-create-school" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) !== 1) return redirect("/");

      const f = await form();
      const tenantName = (f.tenant_name || "");
      const adminName = (f.admin_name || "");
      const adminEmail = (f.admin_email || "").toLowerCase();
      const adminPassword = (f.admin_password || "");

      if (!tenantName || !adminName || !adminEmail || adminPassword.length < 6) {
        return page(
          `<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/sys">Back</a></p>`,
          400
        );
      }

      const tenantId = uuid();
      const ts = nowISO();

      await run("INSERT INTO tenants (id,name,status,created_at,updated_at) VALUES (?,?, 'ACTIVE', ?, ?)", [
        tenantId,
        tenantName,
        ts,
        ts,
      ]);

      let u = await first("SELECT id FROM users WHERE email=? AND status='ACTIVE'", [adminEmail]);
      let userId = u?.id;

      if (!userId) {
        const saltHex = randomSaltHex();
        const iter = 40000;
        const hashHex = await pbkdf2Hex(adminPassword + "|" + PEPPER, saltHex, iter);
        userId = uuid();
        await run(
          "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,0,'ACTIVE',?,?)",
          [userId, adminEmail, adminName, saltHex, hashHex, iter, ts, ts]
        );
      }

      // Add membership as SCHOOL_ADMIN (avoid duplicates by checking first)
      const m = await first(
        "SELECT id FROM memberships WHERE user_id=? AND tenant_id=? ORDER BY created_at ASC LIMIT 1",
        [userId, tenantId]
      );
      if (!m) {
        await run(
          "INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,'SCHOOL_ADMIN','ACTIVE',?,?)",
          [uuid(), userId, tenantId, ts, ts]
        );
      } else {
        await run("UPDATE memberships SET role='SCHOOL_ADMIN', status='ACTIVE', updated_at=? WHERE id=?", [ts, m.id]);
      }

      return redirect("/sys");
    }

    // =============================
    // School Admin dashboard (expanded)
    // =============================
    if (path === "/school") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) === 1) return redirect("/sys");

      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;

      const members = await all(
        `SELECT u.id,u.name,u.email,m.id AS membership_id,m.role
         FROM memberships m JOIN users u ON u.id=m.user_id
         WHERE m.tenant_id=? AND m.status='ACTIVE' AND u.status='ACTIVE'
         ORDER BY m.role ASC, u.name ASC`,
        [tenantId]
      );

      const courses = await all("SELECT id,title,status FROM courses WHERE tenant_id=? ORDER BY title ASC", [tenantId]);

      // Teachers/students for existing forms
      const teachers = members.filter((x) => x.role === "TEACHER");
      const students = members.filter((x) => x.role === "STUDENT");

      const teacherOptions = teachers
        .map((t) => `<option value="${escapeAttr(t.id)}">${escapeHtml(t.name)} (${escapeHtml(t.email)})</option>`)
        .join("");

      const studentOptions = students
        .map((s) => `<option value="${escapeAttr(s.id)}">${escapeHtml(s.name)} (${escapeHtml(s.email)})</option>`)
        .join("");

      const courseOptions = courses
        .filter((c) => c.status === "ACTIVE")
        .map((c) => `<option value="${escapeAttr(c.id)}">${escapeHtml(c.title)}</option>`)
        .join("");

      // Join codes list
      const codes = await all(
        `SELECT jc.*, c.title AS course_title
         FROM join_codes jc
         LEFT JOIN courses c ON c.id=jc.course_id
         WHERE jc.tenant_id=?
         ORDER BY jc.created_at DESC`,
        [tenantId]
      );

      const codesRows = codes
        .map((c) => {
          const expired = isIsoInPast(c.expires_at);
          const status = Number(c.revoked) === 1 ? "Revoked" : expired ? "Expired" : "Active";
          return `
            <tr>
              <td>
                <b>${escapeHtml(scopeLabel(c.scope))}</b><br/>
                <span class="muted small">${escapeHtml(roleLabel(c.role))}${c.course_title ? ` • ${escapeHtml(c.course_title)}` : ""}</span>
              </td>
              <td class="small">
                ${escapeHtml(fmtISO(c.expires_at))}<br/>
                Uses: ${escapeHtml(c.uses_approved)}/${escapeHtml(c.max_uses)}<br/>
                Auto: ${Number(c.auto_approve) === 1 ? "Yes" : "No"}
              </td>
              <td>
                <span class="pill">${escapeHtml(status)}</span>
              </td>
              <td>
                ${
                  Number(c.revoked) === 1
                    ? `<span class="muted small">—</span>`
                    : `<form method="post" action="/school-revoke-code" onsubmit="return confirm('Revoke this code?')">
                        <input type="hidden" name="code_id" value="${escapeAttr(c.id)}"/>
                        <button type="submit" class="btn3">Revoke</button>
                      </form>`
                }
              </td>
            </tr>
          `;
        })
        .join("");

      // Join requests: pending + history
      const pending = await all(
        `SELECT jr.id, jr.type, jr.requested_role, jr.created_at,
                u.name AS user_name, u.email AS user_email,
                c.title AS course_title
         FROM join_requests jr
         JOIN users u ON u.id = jr.user_id
         LEFT JOIN courses c ON c.id = jr.course_id
         WHERE jr.tenant_id=? AND jr.status='PENDING'
         ORDER BY jr.created_at DESC`,
        [tenantId]
      );

      const history = await all(
        `SELECT jr.id, jr.type, jr.requested_role, jr.status, jr.created_at, jr.reviewed_at,
                u.name AS user_name, u.email AS user_email,
                c.title AS course_title
         FROM join_requests jr
         JOIN users u ON u.id = jr.user_id
         LEFT JOIN courses c ON c.id = jr.course_id
         WHERE jr.tenant_id=? AND jr.status IN ('APPROVED','REJECTED')
         ORDER BY jr.reviewed_at DESC, jr.created_at DESC
         LIMIT 50`,
        [tenantId]
      );

      const pendingRows = pending
        .map((x) => `
          <tr>
            <td><b>${escapeHtml(x.user_name)}</b><br/><span class="muted small">${escapeHtml(x.user_email)}</span></td>
            <td class="small">
              ${escapeHtml(x.type)} • ${escapeHtml(roleLabel(x.requested_role))}
              ${x.course_title ? `<br/>Course: ${escapeHtml(x.course_title)}` : ``}
              <br/><span class="muted">Requested: ${escapeHtml(fmtISO(x.created_at))}</span>
            </td>
            <td>
              <div class="actions">
                <form method="post" action="/school-approve-request" onsubmit="return confirm('Approve this request?')">
                  <input type="hidden" name="request_id" value="${escapeAttr(x.id)}"/>
                  <button class="btn2" type="submit">Approve</button>
                </form>
                <form method="post" action="/school-reject-request" onsubmit="return confirm('Reject this request?')">
                  <input type="hidden" name="request_id" value="${escapeAttr(x.id)}"/>
                  <button class="btn3" type="submit">Reject</button>
                </form>
              </div>
            </td>
          </tr>
        `)
        .join("");

      const historyRows = history
        .map((x) => `
          <tr>
            <td><b>${escapeHtml(x.user_name)}</b><br/><span class="muted small">${escapeHtml(x.user_email)}</span></td>
            <td class="small">
              ${escapeHtml(x.type)} • ${escapeHtml(roleLabel(x.requested_role))}
              ${x.course_title ? `<br/>Course: ${escapeHtml(x.course_title)}` : ``}
            </td>
            <td class="small">
              <span class="pill">${escapeHtml(x.status)}</span><br/>
              <span class="muted">Reviewed: ${escapeHtml(fmtISO(x.reviewed_at || ""))}</span>
            </td>
          </tr>
        `)
        .join("");

      // Members management table
      const memberRows = members
        .map((m) => {
          const self = m.id === r.user.id;
          return `
            <tr>
              <td><b>${escapeHtml(m.name)}</b><br/><span class="muted small">${escapeHtml(m.email)}</span>${self ? `<div class="pill">You</div>` : ``}</td>
              <td>
                <form method="post" action="/school-update-member-role" class="actions">
                  <input type="hidden" name="user_id" value="${escapeAttr(m.id)}"/>
                  <select name="role" required>
                    <option value="STUDENT" ${m.role === "STUDENT" ? "selected" : ""}>Student</option>
                    <option value="TEACHER" ${m.role === "TEACHER" ? "selected" : ""}>Teacher</option>
                    <option value="SCHOOL_ADMIN" ${m.role === "SCHOOL_ADMIN" ? "selected" : ""}>School Admin</option>
                  </select>
                  <button type="submit" class="btn2">Update</button>
                </form>
              </td>
              <td>
                <form method="post" action="/school-remove-member" onsubmit="return confirm('Remove this member from the school?')">
                  <input type="hidden" name="user_id" value="${escapeAttr(m.id)}"/>
                  <button type="submit" class="btn3" ${self ? "disabled title='Cannot remove yourself'" : ""}>Remove</button>
                </form>
              </td>
            </tr>
          `;
        })
        .join("");

      // Course rosters (simple readable lists)
      const rosterBlocks = [];
      for (const c of courses.filter((x) => x.status === "ACTIVE")) {
        const tRows = await all(
          `SELECT u.id,u.name,u.email
           FROM course_teachers ct JOIN users u ON u.id=ct.user_id
           WHERE ct.course_id=?
           ORDER BY u.name ASC`,
          [c.id]
        );
        const sRows = await all(
          `SELECT u.id,u.name,u.email
           FROM enrollments e JOIN users u ON u.id=e.user_id
           WHERE e.course_id=?
           ORDER BY u.name ASC`,
          [c.id]
        );

        const tList = tRows
          .map(
            (u) => `
              <li>${escapeHtml(u.name)} <span class="muted small">(${escapeHtml(u.email)})</span>
                <form style="display:inline" method="post" action="/school-unassign-teacher" onsubmit="return confirm('Unassign teacher from this course?')">
                  <input type="hidden" name="course_id" value="${escapeAttr(c.id)}"/>
                  <input type="hidden" name="user_id" value="${escapeAttr(u.id)}"/>
                  <button class="btn3" type="submit" style="margin-left:8px;padding:6px 10px">Remove</button>
                </form>
              </li>`
          )
          .join("");

        const sList = sRows
          .map(
            (u) => `
              <li>${escapeHtml(u.name)} <span class="muted small">(${escapeHtml(u.email)})</span>
                <form style="display:inline" method="post" action="/school-unenrol-student" onsubmit="return confirm('Remove student from this course?')">
                  <input type="hidden" name="course_id" value="${escapeAttr(c.id)}"/>
                  <input type="hidden" name="user_id" value="${escapeAttr(u.id)}"/>
                  <button class="btn3" type="submit" style="margin-left:8px;padding:6px 10px">Remove</button>
                </form>
              </li>`
          )
          .join("");

        rosterBlocks.push(`
          <div class="card">
            <h2>${escapeHtml(c.title)}</h2>
            <div class="row">
              <div>
                <h3 style="margin:0 0 6px;font-size:14px">Teachers (${tRows.length})</h3>
                <ul>${tList || `<li class="muted">None</li>`}</ul>
              </div>
              <div>
                <h3 style="margin:0 0 6px;font-size:14px">Students (${sRows.length})</h3>
                <ul>${sList || `<li class="muted">None</li>`}</ul>
              </div>
            </div>
          </div>
        `);
      }

      return page(`
        <div class="card">
          <div class="topbar">
            <div>
              <h1>School Admin</h1>
              <div class="muted">
                <span class="pill">${escapeHtml(active.tenant_name)}</span>
                <span class="pill">${escapeHtml(roleLabel(active.role))}</span>
              </div>
            </div>
            <div class="actions">
              ${r.memberships.length > 1 ? `<a href="/choose-school">Switch school</a>` : ``}
              <a href="/profile">Profile</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
        </div>

        <div class="card">
          <h2>Join Codes</h2>
          <p class="muted small">Codes are stored hashed; you’ll see the plaintext code only at creation time.</p>
          <form method="post" action="/school-create-code">
            <label>Code type</label>
            <select name="kind" required>
              <option value="TENANT_STUDENT">Student (school-wide access)</option>
              <option value="TENANT_TEACHER">Teacher (school-wide access)</option>
              <option value="COURSE_ENROLL">Student (course enrol)</option>
              <option value="COURSE_TEACHER">Teacher (course assignment)</option>
            </select>

            <label>Course (required for course codes)</label>
            <select name="course_id">${courseOptions || "<option value=''>Create a course first</option>"}</select>

            <div class="row">
              <div>
                <label>Auto-approve</label>
                <select name="auto_approve">
                  <option value="0">No (admin approval required)</option>
                  <option value="1">Yes (instant)</option>
                </select>
              </div>
              <div>
                <label>Expiry (days)</label>
                <input name="exp_days" type="number" min="1" value="${JOIN_CODE_DEFAULT_EXP_DAYS}" required />
              </div>
            </div>

            <label>Max uses</label>
            <input name="max_uses" type="number" min="1" value="${JOIN_CODE_DEFAULT_MAX_USES}" required />

            <button type="submit">Create code</button>
          </form>

          <h3 style="margin:14px 0 6px;font-size:14px">Existing codes</h3>
          <table class="table">
            <thead><tr><th>Type</th><th>Limits</th><th>Status</th><th></th></tr></thead>
            <tbody>
              ${codesRows || `<tr><td colspan="4" class="muted">No codes yet</td></tr>`}
            </tbody>
          </table>
        </div>

        <div class="card">
          <h2>Join Requests</h2>
          <h3 style="margin:10px 0 6px;font-size:14px">Pending</h3>
          <table class="table">
            <thead><tr><th>User</th><th>Request</th><th>Actions</th></tr></thead>
            <tbody>${pendingRows || `<tr><td colspan="3" class="muted">No pending requests</td></tr>`}</tbody>
          </table>

          <h3 style="margin:14px 0 6px;font-size:14px">History</h3>
          <table class="table">
            <thead><tr><th>User</th><th>Request</th><th>Status</th></tr></thead>
            <tbody>${historyRows || `<tr><td colspan="3" class="muted">No history yet</td></tr>`}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Add User (manual)</h2>
          <form method="post" action="/school-add-user">
            <label>Full name</label><input name="name" required />
            <label>Email</label><input name="email" type="email" required />
            <label>Role</label>
            <select name="role" required>
              <option value="TEACHER">Teacher</option>
              <option value="STUDENT">Student</option>
              <option value="SCHOOL_ADMIN">School Admin</option>
            </select>
            <label>Temporary password (used only if this email is NEW)</label>
            <input name="password" type="text" required />
            <button type="submit">Create user + add to this school</button>
          </form>
          <p class="muted">If the email already exists, we won’t change their password — we only add them to this school.</p>
        </div>

        <div class="card">
          <h2>Create Course</h2>
          <form method="post" action="/school-create-course">
            <label>Course title</label><input name="title" required />
            <button type="submit">Create course</button>
          </form>
        </div>

        <div class="card">
          <h2>Assign Teacher to Course (manual)</h2>
          <form method="post" action="/school-assign-teacher">
            <label>Course</label>
            <select name="course_id" required>${courseOptions || "<option value=''>Create a course first</option>"}</select>
            <label>Teacher</label>
            <select name="teacher_id" required>${teacherOptions || "<option value=''>Add a teacher first</option>"}</select>
            <button type="submit">Assign teacher</button>
          </form>
        </div>

        <div class="card">
          <h2>Enrol Student to Course (manual)</h2>
          <form method="post" action="/school-enrol-student">
            <label>Course</label>
            <select name="course_id" required>${courseOptions || "<option value=''>Create a course first</option>"}</select>
            <label>Student</label>
            <select name="student_id" required>${studentOptions || "<option value=''>Add a student first</option>"}</select>
            <button type="submit">Enrol student</button>
          </form>
        </div>

        <div class="card">
          <h2>Members (manage roles / remove)</h2>
          <table class="table">
            <thead><tr><th>Member</th><th>Role</th><th>Remove</th></tr></thead>
            <tbody>${memberRows || `<tr><td colspan="3" class="muted">No users yet</td></tr>`}</tbody>
          </table>
        </div>

        <div class="card">
          <h2>Courses</h2>
          <ul>${courses.map((c) => `<li><b>${escapeHtml(c.title)}</b> <span class="muted">(${escapeHtml(c.status)})</span></li>`).join("") || "<li class='muted'>No courses yet</li>"}</ul>
        </div>

        <div class="card">
          <h2>Course rosters</h2>
          <p class="muted small">Teachers assigned + students enrolled, per course.</p>
        </div>
        ${rosterBlocks.join("")}
      `);
    }

    // Create join code
    if (path === "/school-create-code" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const kind = (f.kind || "").trim();
      const courseId = (f.course_id || "").trim();
      const autoApprove = Number(f.auto_approve || "0") === 1 ? 1 : 0;
      const expDays = Math.max(1, parseInt(f.exp_days || `${JOIN_CODE_DEFAULT_EXP_DAYS}`, 10) || JOIN_CODE_DEFAULT_EXP_DAYS);
      const maxUses = Math.max(1, parseInt(f.max_uses || `${JOIN_CODE_DEFAULT_MAX_USES}`, 10) || JOIN_CODE_DEFAULT_MAX_USES);

      let scope = "";
      let role = "";
      let course_id = null;

      if (kind === "TENANT_STUDENT") { scope = "TENANT_ROLE"; role = "STUDENT"; }
      else if (kind === "TENANT_TEACHER") { scope = "TENANT_ROLE"; role = "TEACHER"; }
      else if (kind === "COURSE_ENROLL") { scope = "COURSE_ENROLL"; role = "STUDENT"; course_id = courseId || null; }
      else if (kind === "COURSE_TEACHER") { scope = "COURSE_TEACHER"; role = "TEACHER"; course_id = courseId || null; }
      else return redirect("/school");

      // Validate course if course-scoped
      if ((scope === "COURSE_ENROLL" || scope === "COURSE_TEACHER") && !course_id) {
        return page(`<div class="card err"><b>Please select a course for course codes.</b></div><p><a href="/school">Back</a></p>`, 400);
      }
      if (scope === "COURSE_ENROLL" || scope === "COURSE_TEACHER") {
        const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [course_id, active.tenant_id]);
        if (!c) return page(`<div class="card err"><b>Course not found or inactive.</b></div><p><a href="/school">Back</a></p>`, 400);
      }

      // Create code (hash-only). Show plaintext once.
      const expiresAt = new Date(Date.now() + expDays * 24 * 60 * 60 * 1000).toISOString();
      const ts = nowISO();

      let codePlain = "";
      let codeHash = "";
      let attempts = 0;
      while (attempts < 6) {
        attempts++;
        codePlain = makeJoinCodePlain();
        codeHash = await joinCodeHash(codePlain);
        const exists = await first("SELECT id FROM join_codes WHERE code_hash=? LIMIT 1", [codeHash]);
        if (!exists) break;
      }
      if (!codePlain) throw new Error("Failed to generate join code.");

      const id = uuid();
      await run(
        `INSERT INTO join_codes
         (id,tenant_id,scope,role,course_id,code_hash,auto_approve,expires_at,max_uses,uses_approved,revoked,created_by_user_id,created_at,updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,0,0,?,?,?)`,
        [id, active.tenant_id, scope, role, course_id, codeHash, autoApprove, expiresAt, maxUses, r.user.id, ts, ts]
      );

      return page(`
        <div class="card ok">
          <h1>Join code created</h1>
          <p class="muted">Copy and share this code (shown only once):</p>
          <div class="card" style="border:1px dashed rgba(0,0,0,.2);background:#fff;margin:10px 0">
            <div style="font-size:28px;font-weight:900;letter-spacing:.08em">${escapeHtml(codePlain)}</div>
          </div>
          <p class="muted">Users go to <b>/join</b>, enter the code, then login/create account.</p>
          <p class="actions"><a href="/school">Back to School Admin</a></p>
        </div>
      `);
    }

    if (path === "/school-revoke-code" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const codeId = (f.code_id || "").trim();
      if (!codeId) return redirect("/school");

      await run("UPDATE join_codes SET revoked=1, updated_at=? WHERE id=? AND tenant_id=?", [nowISO(), codeId, active.tenant_id]);
      return redirect("/school");
    }

    // Approve/reject join request
    if (path === "/school-approve-request" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const reqId = (f.request_id || "").trim();
      if (!reqId) return redirect("/school");

      const jr = await first(
        `SELECT * FROM join_requests
         WHERE id=? AND tenant_id=? AND status='PENDING'`,
        [reqId, active.tenant_id]
      );
      if (!jr) return redirect("/school");

      const jc = await first(
        `SELECT jc.*, t.name AS tenant_name, c.title AS course_title
         FROM join_codes jc
         JOIN tenants t ON t.id=jc.tenant_id
         LEFT JOIN courses c ON c.id=jc.course_id
         WHERE jc.id=? AND jc.tenant_id=?`,
        [jr.join_code_id, active.tenant_id]
      );
      const v = joinCodeIsValid(jc);
      if (!v.ok) {
        return page(`<div class="card err"><b>Cannot approve:</b> ${escapeHtml(v.why)}</div><p><a href="/school">Back</a></p>`, 400);
      }

      // Reserve use now
      const reserved = await reserveJoinCodeUse(jc.id);
      if (!reserved) {
        return page(`<div class="card err"><b>Cannot approve:</b> Code is no longer available.</div><p><a href="/school">Back</a></p>`, 400);
      }

      const applied = await applyJoinActionForUser(jr.user_id, jc);
      if (!applied.ok) {
        await unreserveJoinCodeUse(jc.id);
        return page(`<div class="card err"><b>Cannot approve:</b> ${escapeHtml(applied.msg)}</div><p><a href="/school">Back</a></p>`, 400);
      }

      await run(
        "UPDATE join_requests SET status='APPROVED', reviewed_by_user_id=?, reviewed_at=? WHERE id=?",
        [r.user.id, nowISO(), reqId]
      );

      return redirect("/school");
    }

    if (path === "/school-reject-request" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const reqId = (f.request_id || "").trim();
      if (!reqId) return redirect("/school");

      await run(
        "UPDATE join_requests SET status='REJECTED', reviewed_by_user_id=?, reviewed_at=? WHERE id=? AND tenant_id=? AND status='PENDING'",
        [r.user.id, nowISO(), reqId, active.tenant_id]
      );
      return redirect("/school");
    }

    // Member management: update role
    if (path === "/school-update-member-role" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const userId = (f.user_id || "").trim();
      const role = (f.role || "").trim();

      if (!userId || !["STUDENT", "TEACHER", "SCHOOL_ADMIN"].includes(role)) return redirect("/school");

      // Prevent locking yourself out
      if (userId === r.user.id && role !== "SCHOOL_ADMIN") {
        return page(`<div class="card err"><b>You cannot remove your own School Admin role.</b></div><p><a href="/school">Back</a></p>`, 400);
      }

      const m = await first(
        "SELECT id FROM memberships WHERE tenant_id=? AND user_id=? AND status='ACTIVE' ORDER BY created_at ASC LIMIT 1",
        [active.tenant_id, userId]
      );
      if (!m) return redirect("/school");

      await run("UPDATE memberships SET role=?, updated_at=? WHERE id=?", [role, nowISO(), m.id]);
      return redirect("/school");
    }

    // Member management: remove from school
    if (path === "/school-remove-member" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const userId = (f.user_id || "").trim();
      if (!userId) return redirect("/school");

      // Prevent removing yourself (simple safety)
      if (userId === r.user.id) {
        return page(`<div class="card err"><b>You cannot remove yourself.</b></div><p><a href="/school">Back</a></p>`, 400);
      }

      await run(
        "UPDATE memberships SET status='REMOVED', updated_at=? WHERE tenant_id=? AND user_id=? AND status='ACTIVE'",
        [nowISO(), active.tenant_id, userId]
      );

      // Optional cleanup: remove course assignments/enrolments for this tenant’s courses
      const courseIds = await all("SELECT id FROM courses WHERE tenant_id=?", [active.tenant_id]);
      for (const c of courseIds) {
        await run("DELETE FROM course_teachers WHERE course_id=? AND user_id=?", [c.id, userId]);
        await run("DELETE FROM enrollments WHERE course_id=? AND user_id=?", [c.id, userId]);
      }

      return redirect("/school");
    }

    // Course roster actions
    if (path === "/school-unassign-teacher" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const courseId = (f.course_id || "").trim();
      const userId = (f.user_id || "").trim();
      if (!courseId || !userId) return redirect("/school");

      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=?", [courseId, active.tenant_id]);
      if (!c) return redirect("/school");

      await run("DELETE FROM course_teachers WHERE course_id=? AND user_id=?", [courseId, userId]);
      return redirect("/school");
    }

    if (path === "/school-unenrol-student" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const courseId = (f.course_id || "").trim();
      const userId = (f.user_id || "").trim();
      if (!courseId || !userId) return redirect("/school");

      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=?", [courseId, active.tenant_id]);
      if (!c) return redirect("/school");

      await run("DELETE FROM enrollments WHERE course_id=? AND user_id=?", [courseId, userId]);
      return redirect("/school");
    }

    // Manual add user (now includes SCHOOL_ADMIN too)
    if (path === "/school-add-user" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;
      const f = await form();
      const name = (f.name || "");
      const email = (f.email || "").toLowerCase();
      const role = (f.role || "");
      const password = (f.password || "");

      if (!name || !email || !["TEACHER", "STUDENT", "SCHOOL_ADMIN"].includes(role) || password.length < 6) {
        return page(
          `<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/school">Back</a></p>`,
          400
        );
      }

      const ts = nowISO();

      let u = await first("SELECT id FROM users WHERE email=? AND status='ACTIVE'", [email]);
      let userId = u?.id;

      if (!userId) {
        const saltHex = randomSaltHex();
        const iter = 40000;
        const hashHex = await pbkdf2Hex(password + "|" + PEPPER, saltHex, iter);
        userId = uuid();
        await run(
          "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,0,'ACTIVE',?,?)",
          [userId, email, name, saltHex, hashHex, iter, ts, ts]
        );
      }

      // Upsert membership
      const m = await first(
        "SELECT id,status FROM memberships WHERE user_id=? AND tenant_id=? ORDER BY created_at ASC LIMIT 1",
        [userId, tenantId]
      );
      if (!m) {
        await run(
          "INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,?,'ACTIVE',?,?)",
          [uuid(), userId, tenantId, role, ts, ts]
        );
      } else {
        await run("UPDATE memberships SET role=?, status='ACTIVE', updated_at=? WHERE id=?", [role, ts, m.id]);
      }

      return redirect("/school");
    }

    if (path === "/school-create-course" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const title = (f.title || "");
      if (!title) return redirect("/school");

      const ts = nowISO();
      await run("INSERT INTO courses (id,tenant_id,title,status,created_at,updated_at) VALUES (?,?,?,'ACTIVE',?,?)", [
        uuid(),
        active.tenant_id,
        title,
        ts,
        ts,
      ]);

      return redirect("/school");
    }

    if (path === "/school-assign-teacher" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const courseId = (f.course_id || "");
      const teacherId = (f.teacher_id || "");

      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [
        courseId,
        active.tenant_id,
      ]);
      if (!c) return redirect("/school");

      const m = await first(
        "SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role IN ('TEACHER','SCHOOL_ADMIN') AND status='ACTIVE' ORDER BY created_at ASC LIMIT 1",
        [teacherId, active.tenant_id]
      );
      if (!m) return redirect("/school");

      const ex = await first("SELECT 1 AS x FROM course_teachers WHERE course_id=? AND user_id=? LIMIT 1", [
        courseId,
        teacherId,
      ]);
      if (!ex) {
        await run("INSERT INTO course_teachers (course_id,user_id,created_at) VALUES (?,?,?)", [
          courseId,
          teacherId,
          nowISO(),
        ]);
      }
      return redirect("/school");
    }

    if (path === "/school-enrol-student" && request.method === "POST") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active || active.role !== "SCHOOL_ADMIN") return redirect("/");

      const f = await form();
      const courseId = (f.course_id || "");
      const studentId = (f.student_id || "");

      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [
        courseId,
        active.tenant_id,
      ]);
      if (!c) return redirect("/school");

      const m = await first(
        "SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role IN ('STUDENT','SCHOOL_ADMIN') AND status='ACTIVE' ORDER BY created_at ASC LIMIT 1",
        [studentId, active.tenant_id]
      );
      if (!m) return redirect("/school");

      const ex = await first("SELECT 1 AS x FROM enrollments WHERE course_id=? AND user_id=? LIMIT 1", [
        courseId,
        studentId,
      ]);
      if (!ex) {
        await run("INSERT INTO enrollments (course_id,user_id,created_at) VALUES (?,?,?)", [
          courseId,
          studentId,
          nowISO(),
        ]);
      }
      return redirect("/school");
    }

    // =============================
    // Teacher dashboard (read-only)
    // =============================
    if (path === "/teacher") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "TEACHER") return redirect("/");

      const rows = await all(
        `SELECT c.title
         FROM course_teachers ct
         JOIN courses c ON c.id = ct.course_id
         WHERE ct.user_id=? AND c.tenant_id=? AND c.status='ACTIVE'
         ORDER BY c.title ASC`,
        [r.user.id, active.tenant_id]
      );

      return page(`
        <div class="card">
          <div class="topbar">
            <div>
              <h1>Teacher</h1>
              <div class="muted">
                <span class="pill">${escapeHtml(active.tenant_name)}</span>
                <span class="pill">${escapeHtml(roleLabel(active.role))}</span>
              </div>
            </div>
            <div class="actions">
              ${r.memberships.length > 1 ? `<a href="/choose-school">Switch school</a>` : ``}
              <a href="/profile">Profile</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
        </div>
        <div class="card">
          <h2>My assigned courses</h2>
          <ul>${rows.map((x) => `<li>${escapeHtml(x.title)}</li>`).join("") || "<li class='muted'>None yet</li>"}</ul>
        </div>
      `);
    }

    // =============================
    // Student dashboard (read-only)
    // =============================
    if (path === "/student") {
      const r = await requireLogin();
      if (!r.ok) return r.res;

      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "STUDENT") return redirect("/");

      const rows = await all(
        `SELECT c.title
         FROM enrollments e
         JOIN courses c ON c.id = e.course_id
         WHERE e.user_id=? AND c.tenant_id=? AND c.status='ACTIVE'
         ORDER BY c.title ASC`,
        [r.user.id, active.tenant_id]
      );

      return page(`
        <div class="card">
          <div class="topbar">
            <div>
              <h1>Student</h1>
              <div class="muted">
                <span class="pill">${escapeHtml(active.tenant_name)}</span>
                <span class="pill">${escapeHtml(roleLabel(active.role))}</span>
              </div>
            </div>
            <div class="actions">
              ${r.memberships.length > 1 ? `<a href="/choose-school">Switch school</a>` : ``}
              <a href="/profile">Profile</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
        </div>
        <div class="card">
          <h2>My enrolled courses</h2>
          <ul>${rows.map((x) => `<li>${escapeHtml(x.title)}</li>`).join("") || "<li class='muted'>None yet</li>"}</ul>
        </div>
      `);
    }

    return page(
      `
      <div class="card">
        <h1>Not found</h1>
        <p class="muted">Try <a href="/setup">/setup</a> or <a href="/login">/login</a>.</p>
        <p class="muted">Have a join code? Try <a href="/join">/join</a>.</p>
      </div>
    `,
      404
    );
  } catch (err) {
    console.error("FATAL", err);
    const msg = err && err.stack ? err.stack : String(err);
    return new Response("FATAL ERROR:\n\n" + msg, { status: 500 });
  }
}
