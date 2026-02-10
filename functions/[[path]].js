export async function onRequest(ctx) {
  try {
    const { request, env } = ctx;
    const url = new URL(request.url);
    const path = url.pathname;

    // If DB binding is missing, show a clear message (prevents Error 1101 mystery)
    if (!env.DB) {
      return page(`
        <div class="card err">
          <h1>DB not connected</h1>
          <p class="muted">Your Pages project does not have the D1 binding set.</p>
          <p class="muted">Fix: Pages → Settings → Functions → D1 bindings → add <b>DB</b> → select <b>beta_db</b> (for Production + Preview).</p>
        </div>
      `, 500);
    }

    // ---------- Helpers ----------
    const nowISO = () => new Date().toISOString();
    const uuid = () => crypto.randomUUID();

    function page(body, status = 200, headers = {}) {
      return new Response(`<!doctype html><html><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Beta</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f8f7;color:#1f2a28}
  .wrap{max-width:920px;margin:0 auto;padding:18px}
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
</style>
</head><body><div class="wrap">${body}</div></body></html>`, {
        status,
        headers: { "content-type": "text/html; charset=utf-8", ...headers },
      });
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

    async function form() {
      const fd = await request.formData();
      const out = {};
      for (const [k, v] of fd.entries()) out[k] = String(v).trim();
      return out;
    }

    // --- crypto helpers ---
    const toHex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
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
      const salt = Uint8Array.from(saltHex.match(/../g).map(x => parseInt(x, 16)));
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
    const cookieClear = (name) =>
      `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

    // --- DB helpers ---
    const first = async (sql, params = []) =>
      await env.DB.prepare(sql).bind(...params).first();

    const all = async (sql, params = []) => {
      const res = await env.DB.prepare(sql).bind(...params).all();
      return res.results || [];
    };

    const run = async (sql, params = []) =>
      await env.DB.prepare(sql).bind(...params).run();

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
      return a.memberships.find(m => m.tenant_id === tid) || null;
    }

    // ---------- Routes ----------
    if (path === "/health") {
      // quick test that DB works
      const row = await first("SELECT COUNT(*) AS n FROM users", []);
      return page(`<div class="card"><h1>OK</h1><p class="muted">Users count: ${escapeHtml(row?.n ?? 0)}</p></div>`);
    }

    if (path === "/") {
      const a = await loadAuth();
      if (!a.user) return redirect("/login");
      if (Number(a.user.is_system_admin) === 1) return redirect("/sys");
      if (!a.memberships.length) return redirect("/no-access");

      const active = pickActiveMembership(a);
      if (!active) {
        if (a.memberships.length === 1) return redirect(`/switch-school?tenant_id=${encodeURIComponent(a.memberships[0].tenant_id)}`);
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
          return page(`<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/setup">Back</a></p>`, 400);
        }

        const saltHex = randomSaltHex();
        const iter = 150000;
        const hashHex = await pbkdf2Hex(password, saltHex, iter);
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
        if (!u) return page(`<div class="card err"><b>Wrong email or password.</b></div><p><a href="/login">Try again</a></p>`, 401);

        const check = await pbkdf2Hex(password, u.password_salt, Number(u.password_iter));
        if (check !== u.password_hash) {
          return page(`<div class="card err"><b>Wrong email or password.</b></div><p><a href="/login">Try again</a></p>`, 401);
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

        if (Number(u.is_system_admin) === 1) return redirect("/sys", headers);
        return redirect("/", headers);
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
      if (r.memberships.length === 1) {
        return redirect(`/switch-school?tenant_id=${encodeURIComponent(r.memberships[0].tenant_id)}`);
      }

      const cards = r.memberships.map(m => `
        <div class="card">
          <div class="topbar">
            <div>
              <div><b>${escapeHtml(m.tenant_name)}</b></div>
              <div class="muted">Role: <span class="pill">${escapeHtml(m.role)}</span></div>
            </div>
            <form method="post" action="/switch-school">
              <input type="hidden" name="tenant_id" value="${escapeAttr(m.tenant_id)}"/>
              <button type="submit">Open</button>
            </form>
          </div>
        </div>
      `).join("");

      return page(`
        <div class="card">
          <h1>Choose School</h1>
          <p class="muted">Select which school you want to use right now.</p>
        </div>
        ${cards}
        <p><a href="/logout">Logout</a></p>
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

      const membership = r.memberships.find(m => m.tenant_id === tenantId);
      if (!membership) return redirect("/choose-school");

      const token = cookieGet("qa_sess");
      const tokenHash = await sha256Hex(token);
      await run("UPDATE sessions SET active_tenant_id=? WHERE token_hash=?", [tenantId, tokenHash]);

      return redirect("/");
    }

    // System Admin dashboard
    if (path === "/sys") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) !== 1) return redirect("/");

      const tenants = await all("SELECT id,name,status FROM tenants ORDER BY name ASC", []);
      const list = tenants.map(t => `<li>${escapeHtml(t.name)} <span class="muted">(${escapeHtml(t.status)})</span></li>`).join("");

      return page(`
        <div class="card">
          <div class="topbar">
            <h1>System Admin</h1>
            <div><a href="/logout">Logout</a></div>
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
          <h2>Schools</h2>
          <ul>${list || "<li class='muted'>No schools yet</li>"}</ul>
        </div>
      `);
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
        return page(`<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/sys">Back</a></p>`, 400);
      }

      const tenantId = uuid();
      const ts = nowISO();

      await run("INSERT INTO tenants (id,name,status,created_at,updated_at) VALUES (?,?, 'ACTIVE', ?, ?)", [tenantId, tenantName, ts, ts]);

      let u = await first("SELECT id FROM users WHERE email=? AND status='ACTIVE'", [adminEmail]);
      let userId = u?.id;

      if (!userId) {
        const saltHex = randomSaltHex();
        const iter = 150000;
        const hashHex = await pbkdf2Hex(adminPassword, saltHex, iter);
        userId = uuid();
        await run(
          "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,0,'ACTIVE',?,?)",
          [userId, adminEmail, adminName, saltHex, hashHex, iter, ts, ts]
        );
      }

      await run(
        "INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,'SCHOOL_ADMIN','ACTIVE',?,?)",
        [uuid(), userId, tenantId, ts, ts]
      );

      return redirect("/sys");
    }

    // School Admin dashboard (manage users + courses + assign/enrol)
    if (path === "/school") {
      const r = await requireLogin();
      if (!r.ok) return r.res;
      if (Number(r.user.is_system_admin) === 1) return redirect("/sys");

      const active = pickActiveMembership(r);
      if (!active) return redirect("/choose-school");
      if (active.role !== "SCHOOL_ADMIN") return redirect("/");

      const tenantId = active.tenant_id;

      const members = await all(
        `SELECT u.id,u.name,u.email,m.role
         FROM memberships m JOIN users u ON u.id=m.user_id
         WHERE m.tenant_id=? AND m.status='ACTIVE' AND u.status='ACTIVE'
         ORDER BY m.role ASC, u.name ASC`,
        [tenantId]
      );

      const courses = await all("SELECT id,title,status FROM courses WHERE tenant_id=? ORDER BY title ASC", [tenantId]);

      const teachers = members.filter(x => x.role === "TEACHER");
      const students = members.filter(x => x.role === "STUDENT");

      const memberList = members.map(x => `<li><b>${escapeHtml(x.name)}</b> — ${escapeHtml(x.email)} <span class="pill">${escapeHtml(x.role)}</span></li>`).join("");
      const courseList = courses.map(c => `<li><b>${escapeHtml(c.title)}</b> <span class="muted">(${escapeHtml(c.status)})</span></li>`).join("");

      const teacherOptions = teachers.map(t => `<option value="${escapeAttr(t.id)}">${escapeHtml(t.name)} (${escapeHtml(t.email)})</option>`).join("");
      const studentOptions = students.map(s => `<option value="${escapeAttr(s.id)}">${escapeHtml(s.name)} (${escapeHtml(s.email)})</option>`).join("");
      const courseOptions = courses.map(c => `<option value="${escapeAttr(c.id)}">${escapeHtml(c.title)}</option>`).join("");

      return page(`
        <div class="card">
          <div class="topbar">
            <div>
              <h1>School Admin</h1>
              <div class="muted">${escapeHtml(active.tenant_name)}</div>
            </div>
            <div style="display:flex;gap:10px;align-items:center">
              <a href="/choose-school">Switch school</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
        </div>

        <div class="card">
          <h2>Add User (Teacher or Student)</h2>
          <form method="post" action="/school-add-user">
            <label>Full name</label><input name="name" required />
            <label>Email</label><input name="email" type="email" required />
            <label>Role</label>
            <select name="role" required>
              <option value="TEACHER">Teacher</option>
              <option value="STUDENT">Student</option>
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
          <h2>Assign Teacher to Course</h2>
          <form method="post" action="/school-assign-teacher">
            <label>Course</label>
            <select name="course_id" required>${courseOptions || "<option value=''>Create a course first</option>"}</select>
            <label>Teacher</label>
            <select name="teacher_id" required>${teacherOptions || "<option value=''>Add a teacher first</option>"}</select>
            <button type="submit">Assign teacher</button>
          </form>
        </div>

        <div class="card">
          <h2>Enrol Student to Course</h2>
          <form method="post" action="/school-enrol-student">
            <label>Course</label>
            <select name="course_id" required>${courseOptions || "<option value=''>Create a course first</option>"}</select>
            <label>Student</label>
            <select name="student_id" required>${studentOptions || "<option value=''>Add a student first</option>"}</select>
            <button type="submit">Enrol student</button>
          </form>
        </div>

        <div class="card">
          <h2>Users in this school</h2>
          <ul>${memberList || "<li class='muted'>No users yet</li>"}</ul>
        </div>

        <div class="card">
          <h2>Courses</h2>
          <ul>${courseList || "<li class='muted'>No courses yet</li>"}</ul>
        </div>
      `);
    }

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

      if (!name || !email || !["TEACHER", "STUDENT"].includes(role) || password.length < 6) {
        return page(`<div class="card err"><b>Check inputs.</b> Password must be 6+ characters.</div><p><a href="/school">Back</a></p>`, 400);
      }

      const ts = nowISO();

      let u = await first("SELECT id FROM users WHERE email=? AND status='ACTIVE'", [email]);
      let userId = u?.id;

      if (!userId) {
        const saltHex = randomSaltHex();
        const iter = 150000;
        const hashHex = await pbkdf2Hex(password, saltHex, iter);
        userId = uuid();
        await run(
          "INSERT INTO users (id,email,name,password_salt,password_hash,password_iter,is_system_admin,status,created_at,updated_at) VALUES (?,?,?,?,?,?,0,'ACTIVE',?,?)",
          [userId, email, name, saltHex, hashHex, iter, ts, ts]
        );
      }

      // add membership (ignore if already exists)
      try {
        await run(
          "INSERT INTO memberships (id,user_id,tenant_id,role,status,created_at,updated_at) VALUES (?,?,?,?,'ACTIVE',?,?)",
          [uuid(), userId, tenantId, role, ts, ts]
        );
      } catch (e) {}

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
      await run(
        "INSERT INTO courses (id,tenant_id,title,status,created_at,updated_at) VALUES (?,?,?,'ACTIVE',?,?)",
        [uuid(), active.tenant_id, title, ts, ts]
      );

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

      // course must belong to this tenant
      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [courseId, active.tenant_id]);
      if (!c) return redirect("/school");

      // user must be a TEACHER in this tenant
      const m = await first("SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role='TEACHER' AND status='ACTIVE'", [teacherId, active.tenant_id]);
      if (!m) return redirect("/school");

      try { await run("INSERT INTO course_teachers (course_id,user_id,created_at) VALUES (?,?,?)", [courseId, teacherId, nowISO()]); } catch (e) {}
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

      const c = await first("SELECT id FROM courses WHERE id=? AND tenant_id=? AND status='ACTIVE'", [courseId, active.tenant_id]);
      if (!c) return redirect("/school");

      const m = await first("SELECT id FROM memberships WHERE user_id=? AND tenant_id=? AND role='STUDENT' AND status='ACTIVE'", [studentId, active.tenant_id]);
      if (!m) return redirect("/school");

      try { await run("INSERT INTO enrollments (course_id,user_id,created_at) VALUES (?,?,?)", [courseId, studentId, nowISO()]); } catch (e) {}
      return redirect("/school");
    }

    // Teacher dashboard (read-only for now)
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
              <div class="muted">${escapeHtml(active.tenant_name)}</div>
            </div>
            <div style="display:flex;gap:10px;align-items:center">
              <a href="/choose-school">Switch school</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
        </div>
        <div class="card">
          <h2>My assigned courses</h2>
          <ul>${rows.map(x => `<li>${escapeHtml(x.title)}</li>`).join("") || "<li class='muted'>None yet</li>"}</ul>
        </div>
      `);
    }

    // Student dashboard (read-only for now)
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
              <div class="muted">${escapeHtml(active.tenant_name)}</div>
            </div>
            <div style="display:flex;gap:10px;align-items:center">
              <a href="/choose-school">Switch school</a>
              <a href="/logout">Logout</a>
            </div>
          </div>
        </div>
        <div class="card">
          <h2>My enrolled courses</h2>
          <ul>${rows.map(x => `<li>${escapeHtml(x.title)}</li>`).join("") || "<li class='muted'>None yet</li>"}</ul>
        </div>
      `);
    }

    return page(`
      <div class="card">
        <h1>Not found</h1>
        <p class="muted">Try <a href="/setup">/setup</a> or <a href="/login">/login</a>.</p>
      </div>
    `, 404);

  } catch (err) {
    console.error("FATAL", err);
    return new Response("Worker error. Check Functions logs for details.", { status: 500 });
  }
}
